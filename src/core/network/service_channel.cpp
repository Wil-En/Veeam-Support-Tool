// The Veeam Service Channel test: the service, its pipe, an HTTP/2 handshake and one gRPC health
// check on the pipe, and the gRPC lines the product logged (support_assist/service_channel.hpp). The
// health check reads the service's state and changes nothing.
#include "support_assist/service_channel.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <iterator>
#include <map>
#include <set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace support_assist {

namespace {

struct Pattern {
  std::string id;
  std::string name;
  std::vector<std::string> all_of; // lower case
  std::string status;              // Fail, Attention, Info
  std::string reading;
  std::string url;
  bool observed = true;
};

struct ChannelData {
  int hours = 24;
  int timeout_ms = 5000;
  std::string health_url; // the gRPC health checking protocol
  std::vector<ServiceChannelProduct> products;
  std::vector<Pattern> patterns;
};

const ChannelData& channel_data() {
  static const ChannelData data = [] {
    ChannelData parsed;
    const JsonValue& value = data_file("grpc.json");
    parsed.hours = static_cast<int>(value["hours"].as_number(24.0));
    parsed.timeout_ms = static_cast<int>(value["timeout_ms"].as_number(5000.0));
    std::map<std::string, std::string> urls;
    for (const auto& [key, source] : value["sources"].members())
      urls[key] = source["url"].as_string();
    const auto health_url = urls.find("grpc-health");
    parsed.health_url = health_url == urls.end() ? std::string() : health_url->second;
    for (const JsonValue& item : value["products"].items()) {
      parsed.products.push_back({item["id"].as_string(), item["name"].as_string(), item["service"].as_string(),
                                 item["pipe"].as_string(), item["log_folder"].as_string(),
                                 item["log_files"].string_items(), item["observed_on"].as_string()});
    }
    for (const JsonValue& item : value["patterns"].items()) {
      Pattern pattern;
      pattern.id = item["id"].as_string();
      pattern.name = item["name"].as_string();
      for (const std::string& part : item["all_of"].string_items())
        pattern.all_of.push_back(ascii_lower(part));
      const std::string status = item["status"].as_string("info");
      pattern.status = status == "fail" ? "Fail" : status == "attention" ? "Attention" : "Info";
      pattern.reading = item["reading"].as_string();
      const auto url = urls.find(item["source"].as_string());
      pattern.url = url == urls.end() ? std::string() : url->second;
      pattern.observed = item["observed"].as_bool(true);
      if (!pattern.all_of.empty())
        parsed.patterns.push_back(std::move(pattern));
    }
    return parsed;
  }();
  return data;
}

std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) {
  year -= month <= 2 ? 1 : 0;
  const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
  const auto year_of_era = static_cast<unsigned>(year - era * 400);
  const unsigned day_of_year = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
  const unsigned day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

std::string time_text(std::int64_t seconds) {
  std::int64_t days = seconds / 86400;
  std::int64_t of_day = seconds % 86400;
  if (of_day < 0) {
    of_day += 86400;
    --days;
  }
  const std::int64_t shifted = days + 719468;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096) / 146097;
  const std::int64_t day_of_era = shifted - era * 146097;
  const std::int64_t year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
  const std::int64_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  const std::int64_t month_index = (5 * day_of_year + 2) / 153;
  const std::int64_t day = day_of_year - (153 * month_index + 2) / 5 + 1;
  const std::int64_t month = month_index < 10 ? month_index + 3 : month_index - 9;
  const std::int64_t year = year_of_era + era * 400 + (month <= 2 ? 1 : 0);
  char buffer[64];
  std::snprintf(buffer, sizeof(buffer), "%04lld-%02lld-%02lld %02lld:%02lld:%02lld", static_cast<long long>(year),
                static_cast<long long>(month), static_cast<long long>(day), static_cast<long long>(of_day / 3600),
                static_cast<long long>(of_day / 60 % 60), static_cast<long long>(of_day % 60));
  return buffer;
}

std::int64_t local_now_seconds() {
  const std::time_t now = std::time(nullptr);
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &now);
#else
  localtime_r(&now, &local);
#endif
  return days_from_civil(local.tm_year + 1900, static_cast<unsigned>(local.tm_mon + 1), static_cast<unsigned>(local.tm_mday)) *
             86400 +
         local.tm_hour * 3600 + local.tm_min * 60 + local.tm_sec;
}

bool wildcard_match(std::string_view pattern, std::string_view text) {
  // '*' only, case-insensitive.
  std::size_t p = 0;
  std::size_t t = 0;
  std::size_t star = std::string_view::npos;
  std::size_t mark = 0;
  auto same = [](char left, char right) {
    return std::tolower(static_cast<unsigned char>(left)) == std::tolower(static_cast<unsigned char>(right));
  };
  while (t < text.size()) {
    if (p < pattern.size() && pattern[p] == '*') {
      star = p++;
      mark = t;
    } else if (p < pattern.size() && same(pattern[p], text[t])) {
      ++p;
      ++t;
    } else if (star != std::string_view::npos) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.size() && pattern[p] == '*')
    ++p;
  return p == pattern.size();
}

// The last 16 MB of a log as lines; UTF-16 logs are read as their ASCII text.
std::vector<std::string> read_tail_lines(const std::filesystem::path& path) {
  constexpr std::uintmax_t kTail = 16U * 1024U * 1024U;
  std::vector<std::string> lines;
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error)
    return lines;
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return lines;
  const std::uintmax_t start = size > kTail ? size - kTail : 0U;
  input.seekg(static_cast<std::streamoff>(start));
  std::string bytes(static_cast<std::size_t>(size - start), '\0');
  input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  bytes.resize(static_cast<std::size_t>(input.gcount()));
  if (start == 0U && bytes.size() >= 2U && static_cast<unsigned char>(bytes[0]) == 0xFF &&
      static_cast<unsigned char>(bytes[1]) == 0xFE) {
    std::string narrow;
    for (std::size_t index = 2; index + 1U < bytes.size(); index += 2)
      narrow += bytes[index + 1U] == '\0' ? bytes[index] : '?';
    bytes.swap(narrow);
  }
  std::size_t begin = 0;
  if (start != 0U) {
    const std::size_t first = bytes.find('\n');
    begin = first == std::string::npos ? bytes.size() : first + 1U;
  }
  while (begin < bytes.size()) {
    std::size_t end = bytes.find('\n', begin);
    if (end == std::string::npos)
      end = bytes.size();
    std::string line = bytes.substr(begin, end - begin);
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    lines.push_back(std::move(line));
    begin = end + 1U;
  }
  return lines;
}

std::filesystem::path expanded_folder(const std::string& folder) {
#ifdef _WIN32
  const std::wstring wide = wide_from_utf8(folder);
  wchar_t buffer[MAX_PATH * 2]{};
  if (ExpandEnvironmentStringsW(wide.c_str(), buffer, static_cast<DWORD>(std::size(buffer))) != 0)
    return std::filesystem::path(buffer);
  return std::filesystem::path(wide);
#else
  if (folder.find('%') != std::string::npos)
    return {};
  return path_from_utf8(folder);
#endif
}

#ifdef _WIN32

std::string win_error_text(DWORD code) {
  wchar_t* buffer = nullptr;
  const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
  std::string text = length != 0U && buffer != nullptr ? std::string(trim(utf8_from_wide(buffer))) : std::string();
  if (buffer != nullptr)
    LocalFree(buffer);
  return text + " (error " + std::to_string(code) + ")";
}

std::string current_account() {
  wchar_t user[256]{};
  DWORD size = static_cast<DWORD>(std::size(user));
  std::string name = GetUserNameW(user, &size) != FALSE ? utf8_from_wide(user) : std::string("this account");
  wchar_t domain[256]{};
  if (GetEnvironmentVariableW(L"USERDOMAIN", domain, static_cast<DWORD>(std::size(domain))) != 0)
    name = utf8_from_wide(domain) + "\\" + name;
  return name;
}

// Overlapped pipe I/O with a time limit; a timed-out request is cancelled before it returns.
bool pipe_write(HANDLE pipe, HANDLE event, const std::string& data, DWORD timeout, DWORD& error) {
  OVERLAPPED overlapped{};
  overlapped.hEvent = event;
  ResetEvent(event);
  DWORD written = 0;
  if (WriteFile(pipe, data.data(), static_cast<DWORD>(data.size()), nullptr, &overlapped) == FALSE) {
    error = GetLastError();
    if (error != ERROR_IO_PENDING)
      return false;
    if (WaitForSingleObject(event, timeout) != WAIT_OBJECT_0) {
      CancelIoEx(pipe, &overlapped);
      GetOverlappedResult(pipe, &overlapped, &written, TRUE);
      error = WAIT_TIMEOUT;
      return false;
    }
  }
  if (GetOverlappedResult(pipe, &overlapped, &written, FALSE) == FALSE) {
    error = GetLastError();
    return false;
  }
  error = 0;
  return written == data.size();
}

// Bytes read; 0 when the server closed the pipe; -1 on a timeout or an error (in error).
long pipe_read(HANDLE pipe, HANDLE event, char* buffer, DWORD size, DWORD timeout, DWORD& error) {
  OVERLAPPED overlapped{};
  overlapped.hEvent = event;
  ResetEvent(event);
  DWORD read = 0;
  if (ReadFile(pipe, buffer, size, nullptr, &overlapped) == FALSE) {
    error = GetLastError();
    if (error == ERROR_BROKEN_PIPE)
      return 0;
    if (error != ERROR_IO_PENDING)
      return -1;
    if (WaitForSingleObject(event, timeout) != WAIT_OBJECT_0) {
      CancelIoEx(pipe, &overlapped);
      GetOverlappedResult(pipe, &overlapped, &read, TRUE);
      error = WAIT_TIMEOUT;
      return -1;
    }
  }
  if (GetOverlappedResult(pipe, &overlapped, &read, FALSE) == FALSE) {
    error = GetLastError();
    if (error == ERROR_BROKEN_PIPE)
      return 0;
    if (error != ERROR_MORE_DATA)
      return -1;
  }
  error = 0;
  return static_cast<long>(read);
}

std::string hex_bytes(std::string_view bytes, std::size_t limit = 16) {
  std::string text;
  char buffer[4];
  for (std::size_t index = 0; index < bytes.size() && index < limit; ++index) {
    std::snprintf(buffer, sizeof(buffer), "%02X", static_cast<unsigned int>(static_cast<unsigned char>(bytes[index])));
    text += (text.empty() ? "" : " ") + std::string(buffer);
  }
  return text;
}

struct Handshake {
  bool opened = false;
  bool passed = false;
  bool access_denied = false;
  bool timed_out = false;
  std::string stage;
  std::string detail;
  bool health_ran = false;
  service_channel_detail::HealthExchange health;
};

// The handshake: the HTTP/2 client preface and SETTINGS, the server's SETTINGS and its ACK, one PING and its
// ACK. When that passes, one gRPC health check follows on the same connection (a read of the service's
// state), then GOAWAY, waiting for the server to close first.
Handshake pipe_handshake(const std::string& pipe_name, DWORD timeout, const std::string& account) {
  Handshake result;
  const std::wstring name = wide_from_utf8(pipe_name);
  HANDLE pipe = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    result.access_denied = code == ERROR_ACCESS_DENIED;
    result.stage = "open";
    result.detail = result.access_denied ? account + " cannot open the service pipe: " + win_error_text(code)
                    : code == ERROR_PIPE_BUSY ? "Every instance of the pipe is busy: " + win_error_text(code)
                                              : "The pipe did not open: " + win_error_text(code);
    return result;
  }
  result.opened = true;
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  DWORD error = 0;
  std::string inbox;
  std::string first_bytes;
  DWORD read_limit = timeout;
  std::uint32_t frame_stream = 0;
  auto fail = [&](std::string stage, std::string detail) {
    result.stage = std::move(stage);
    result.detail = std::move(detail);
    result.timed_out = error == WAIT_TIMEOUT;
  };
  // The next frame: its type, flags and payload; false on a timeout, a close or bytes that are not HTTP/2.
  auto next_frame = [&](std::uint8_t& type, std::uint8_t& flags, std::string& payload) {
    for (;;) {
      if (inbox.size() >= 9U) {
        const std::uint32_t length = (static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[0])) << 16) |
                                     (static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[1])) << 8) |
                                     static_cast<unsigned char>(inbox[2]);
        type = static_cast<std::uint8_t>(inbox[3]);
        if (length > (1U << 20) || type > 0x0AU) {
          error = ERROR_INVALID_DATA;
          return false;
        }
        if (inbox.size() >= 9U + length) {
          flags = static_cast<std::uint8_t>(inbox[4]);
          frame_stream = ((static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[5])) & 0x7FU) << 24) |
                         (static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[6])) << 16) |
                         (static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[7])) << 8) |
                         static_cast<std::uint32_t>(static_cast<unsigned char>(inbox[8]));
          payload = inbox.substr(9, length);
          inbox.erase(0, 9U + length);
          return true;
        }
      }
      char buffer[4096];
      const long count = pipe_read(pipe, event, buffer, sizeof(buffer), read_limit, error);
      if (count <= 0) {
        if (count == 0)
          error = ERROR_BROKEN_PIPE;
        return false;
      }
      if (first_bytes.size() < 16U)
        first_bytes.append(buffer, static_cast<std::size_t>(std::min<long>(count, 16 - static_cast<long>(first_bytes.size()))));
      inbox.append(buffer, static_cast<std::size_t>(count));
    }
  };
  auto read_failure = [&](const std::string& waiting_for) {
    if (error == WAIT_TIMEOUT)
      return "No " + waiting_for + " within " + std::to_string(timeout / 1000U) + " seconds.";
    if (error == ERROR_BROKEN_PIPE)
      return "The service closed the pipe before its " + waiting_for + ".";
    if (error == ERROR_INVALID_DATA)
      return "The service answered with bytes that are not HTTP/2: " + hex_bytes(first_bytes) + ".";
    return "Reading the " + waiting_for + " failed: " + win_error_text(error);
  };

  // One gRPC health check on stream 1 of the open connection: the request, then the service's frames until
  // the stream ends, the service resets it or sends GOAWAY, the pipe closes or the time limit passes.
  auto health_call = [&]() {
    service_channel_detail::HealthCall call;
    service_channel_detail::HealthExchange& exchange = call.exchange();
    exchange.timeout_seconds = static_cast<int>(timeout / 1000U);
    std::uint8_t reply_type = 0;
    std::uint8_t reply_flags = 0;
    std::string reply_payload;
    if (!pipe_write(pipe, event, service_channel_detail::health_request(static_cast<int>(timeout)), timeout, error)) {
      exchange.failure = "Sending the health call failed: " + win_error_text(error);
      return exchange;
    }
    const ULONGLONG deadline = GetTickCount64() + timeout;
    while (!call.finished()) {
      const ULONGLONG now = GetTickCount64();
      if (now >= deadline) {
        exchange.timed_out = true;
        break;
      }
      read_limit = static_cast<DWORD>(deadline - now);
      if (!next_frame(reply_type, reply_flags, reply_payload)) {
        if (error == WAIT_TIMEOUT)
          exchange.timed_out = true;
        else if (error == ERROR_BROKEN_PIPE)
          exchange.pipe_closed = true;
        else
          exchange.failure = read_failure("health answer");
        break;
      }
      const std::string acknowledgement = call.accept(reply_type, reply_flags, frame_stream, reply_payload);
      if (!acknowledgement.empty() && !pipe_write(pipe, event, acknowledgement, timeout, error)) {
        exchange.failure = "Answering the service during the health call failed: " + win_error_text(error);
        break;
      }
    }
    read_limit = timeout;
    return exchange;
  };

  const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + service_channel_detail::http2_frame(0x4, 0x0, {});
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::string payload;
  if (!pipe_write(pipe, event, preface, timeout, error)) {
    fail("preface", "Sending the HTTP/2 preface failed: " + win_error_text(error));
  } else {
    bool settings = false;
    std::size_t settings_count = 0;
    while (!settings && next_frame(type, flags, payload)) {
      if (type == 0x4 && (flags & 0x1U) == 0U) {
        settings = true;
        settings_count = payload.size() / 6U;
      } else if (type == 0x7) {
        break;
      }
    }
    if (!settings) {
      fail("SETTINGS", type == 0x7 && error == 0 ? "The service sent GOAWAY instead of its SETTINGS." : read_failure("SETTINGS"));
    } else if (!pipe_write(pipe, event, service_channel_detail::http2_frame(0x4, 0x1, {}), timeout, error)) {
      fail("SETTINGS ACK", "Acknowledging the server's SETTINGS failed: " + win_error_text(error));
    } else {
      const std::string token = "SATPING1";
      const auto started = GetTickCount64();
      if (!pipe_write(pipe, event, service_channel_detail::http2_frame(0x6, 0x0, token), timeout, error)) {
        fail("PING", "Sending PING failed: " + win_error_text(error));
      } else {
        bool answered = false;
        while (!answered && next_frame(type, flags, payload)) {
          if (type == 0x6 && (flags & 0x1U) != 0U && payload == token)
            answered = true;
          else if (type == 0x7)
            break;
        }
        if (!answered) {
          fail("PING", type == 0x7 && error == 0 ? "The service sent GOAWAY instead of answering PING." : read_failure("PING answer"));
        } else {
          const auto elapsed = GetTickCount64() - started;
          result.passed = true;
          result.stage = "done";
          result.detail = "The pipe accepted " + account + ", answered the HTTP/2 preface with SETTINGS (" +
                          std::to_string(settings_count) + (settings_count == 1U ? " setting" : " settings") +
                          ") and a PING in " + std::to_string(elapsed) + " ms. SAT closed with GOAWAY.";
          result.health = health_call();
          result.health_ran = true;
          // GOAWAY: last stream 0, NO_ERROR; then wait briefly for the service to close first.
          std::string goaway(8, '\0');
          static_cast<void>(pipe_write(pipe, event, service_channel_detail::http2_frame(0x7, 0x0, goaway), timeout, error));
          char drain[512];
          for (int attempt = 0; attempt < 4 && pipe_read(pipe, event, drain, sizeof(drain), 250, error) > 0; ++attempt) {
          }
        }
      }
    }
  }
  CloseHandle(event);
  CloseHandle(pipe);
  return result;
}

std::string service_state_name(unsigned long state) {
  switch (state) {
  case SERVICE_RUNNING:
    return "running";
  case SERVICE_STOPPED:
    return "stopped";
  case SERVICE_START_PENDING:
    return "starting";
  case SERVICE_STOP_PENDING:
    return "stopping";
  case SERVICE_PAUSED:
    return "paused";
  default:
    return "in state " + std::to_string(state);
  }
}

#endif

} // namespace

namespace service_channel_detail {

namespace {

struct HuffmanCode {
  std::uint32_t code;
  std::uint8_t bits;
};

// RFC 7541 Appendix B: the code and its length in bits for each byte value, then the end-of-string symbol.
constexpr HuffmanCode kHuffman[257] = {
    {0x1ff8, 13}, {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28}, {0xfffffe4, 28}, {0xfffffe5, 28},
    {0xfffffe6, 28}, {0xfffffe7, 28}, {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
    {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28}, {0xfffffed, 28}, {0xfffffee, 28},
    {0xfffffef, 28}, {0xffffff0, 28}, {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28}, {0xffffff8, 28}, {0xffffff9, 28},
    {0xffffffa, 28}, {0xffffffb, 28}, {0x14, 6}, {0x3f8, 10}, {0x3f9, 10}, {0xffa, 12},
    {0x1ff9, 13}, {0x15, 6}, {0xf8, 8}, {0x7fa, 11}, {0x3fa, 10}, {0x3fb, 10},
    {0xf9, 8}, {0x7fb, 11}, {0xfa, 8}, {0x16, 6}, {0x17, 6}, {0x18, 6},
    {0x0, 5}, {0x1, 5}, {0x2, 5}, {0x19, 6}, {0x1a, 6}, {0x1b, 6},
    {0x1c, 6}, {0x1d, 6}, {0x1e, 6}, {0x1f, 6}, {0x5c, 7}, {0xfb, 8},
    {0x7ffc, 15}, {0x20, 6}, {0xffb, 12}, {0x3fc, 10}, {0x1ffa, 13}, {0x21, 6},
    {0x5d, 7}, {0x5e, 7}, {0x5f, 7}, {0x60, 7}, {0x61, 7}, {0x62, 7},
    {0x63, 7}, {0x64, 7}, {0x65, 7}, {0x66, 7}, {0x67, 7}, {0x68, 7},
    {0x69, 7}, {0x6a, 7}, {0x6b, 7}, {0x6c, 7}, {0x6d, 7}, {0x6e, 7},
    {0x6f, 7}, {0x70, 7}, {0x71, 7}, {0x72, 7}, {0xfc, 8}, {0x73, 7},
    {0xfd, 8}, {0x1ffb, 13}, {0x7fff0, 19}, {0x1ffc, 13}, {0x3ffc, 14}, {0x22, 6},
    {0x7ffd, 15}, {0x3, 5}, {0x23, 6}, {0x4, 5}, {0x24, 6}, {0x5, 5},
    {0x25, 6}, {0x26, 6}, {0x27, 6}, {0x6, 5}, {0x74, 7}, {0x75, 7},
    {0x28, 6}, {0x29, 6}, {0x2a, 6}, {0x7, 5}, {0x2b, 6}, {0x76, 7},
    {0x2c, 6}, {0x8, 5}, {0x9, 5}, {0x2d, 6}, {0x77, 7}, {0x78, 7},
    {0x79, 7}, {0x7a, 7}, {0x7b, 7}, {0x7ffe, 15}, {0x7fc, 11}, {0x3ffd, 14},
    {0x1ffd, 13}, {0xffffffc, 28}, {0xfffe6, 20}, {0x3fffd2, 22}, {0xfffe7, 20}, {0xfffe8, 20},
    {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23}, {0x3fffd6, 22}, {0x7fffda, 23},
    {0x7fffdb, 23}, {0x7fffdc, 23}, {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
    {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23}, {0xffffee, 24}, {0x7fffe1, 23},
    {0x7fffe2, 23}, {0x7fffe3, 23}, {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
    {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24}, {0x3fffda, 22}, {0x1fffdd, 21},
    {0xfffe9, 20}, {0x3fffdb, 22}, {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
    {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24}, {0x1fffdf, 21}, {0x3fffdf, 22},
    {0x7fffeb, 23}, {0x7fffec, 23}, {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
    {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23}, {0xfffea, 20}, {0x3fffe2, 22},
    {0x3fffe3, 22}, {0x3fffe4, 22}, {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
    {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19}, {0x3fffe7, 22}, {0x7ffff2, 23},
    {0x3fffe8, 22}, {0x1ffffec, 25}, {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
    {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25}, {0x7fff2, 19}, {0x1fffe3, 21},
    {0x3ffffe6, 26}, {0x7ffffe0, 27}, {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
    {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26}, {0xffffffd, 28}, {0x7ffffe3, 27},
    {0x7ffffe4, 27}, {0x7ffffe5, 27}, {0xfffec, 20}, {0xfffff3, 24}, {0xfffed, 20}, {0x1fffe6, 21},
    {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23}, {0x3fffea, 22}, {0x3fffeb, 22},
    {0x1ffffee, 25}, {0x1ffffef, 25}, {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26}, {0x7ffffe7, 27}, {0x7ffffe8, 27},
    {0x7ffffe9, 27}, {0x7ffffea, 27}, {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
    {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26}, {0x3fffffff, 30},
};

struct StaticField {
  const char* name;
  const char* value;
};

// RFC 7541 Appendix A: entries 1 to 61.
constexpr StaticField kStaticTable[61] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""},
};

constexpr std::size_t kStaticCount = 61U;

const std::map<std::uint64_t, int>& huffman_lookup() {
  static const std::map<std::uint64_t, int> table = [] {
    std::map<std::uint64_t, int> built;
    for (std::size_t symbol = 0; symbol < 257U; ++symbol)
      built[(static_cast<std::uint64_t>(kHuffman[symbol].bits) << 32) | kHuffman[symbol].code] = static_cast<int>(symbol);
    return built;
  }();
  return table;
}

// An integer with an N bit prefix (RFC 7541 section 5.1); flags are the bits above the prefix.
void put_integer(std::string& out, unsigned flags, unsigned prefix, std::uint64_t value) {
  const std::uint64_t limit = (1ULL << prefix) - 1ULL;
  if (value < limit) {
    out += static_cast<char>(flags | static_cast<unsigned>(value));
    return;
  }
  out += static_cast<char>(flags | static_cast<unsigned>(limit));
  value -= limit;
  while (value >= 128U) {
    out += static_cast<char>(0x80U | static_cast<unsigned>(value & 0x7FU));
    value >>= 7U;
  }
  out += static_cast<char>(value);
}

// A string without Huffman coding.
void put_string(std::string& out, std::string_view text) {
  put_integer(out, 0U, 7U, text.size());
  out.append(text);
}

// A field as a literal without indexing: its name from the static table (name_index) or as a new string.
void put_literal(std::string& out, std::uint64_t name_index, std::string_view name, std::string_view value) {
  put_integer(out, 0U, 4U, name_index);
  if (name_index == 0U)
    put_string(out, name);
  put_string(out, value);
}

bool read_integer(std::string_view block, std::size_t& at, unsigned prefix, std::uint64_t& value) {
  if (at >= block.size())
    return false;
  const std::uint64_t limit = (1ULL << prefix) - 1ULL;
  value = static_cast<unsigned char>(block[at++]) & limit;
  if (value < limit)
    return true;
  unsigned shift = 0;
  for (;;) {
    if (at >= block.size() || shift > 28U)
      return false;
    const auto next = static_cast<unsigned char>(block[at++]);
    value += static_cast<std::uint64_t>(next & 0x7FU) << shift;
    shift += 7U;
    if ((next & 0x80U) == 0U)
      return true;
  }
}

bool read_string(std::string_view block, std::size_t& at, std::string& out, std::string& error) {
  if (at >= block.size()) {
    error = "The header block ends before a string.";
    return false;
  }
  const bool huffman = (static_cast<unsigned char>(block[at]) & 0x80U) != 0U;
  std::uint64_t length = 0;
  if (!read_integer(block, at, 7U, length)) {
    error = "The header block ends inside a number, or the number is too large.";
    return false;
  }
  if (length > block.size() - at) {
    error = "A string is longer than the rest of the header block.";
    return false;
  }
  const std::string_view raw = block.substr(at, static_cast<std::size_t>(length));
  at += static_cast<std::size_t>(length);
  if (!huffman) {
    out.assign(raw);
    return true;
  }
  std::optional<std::string> decoded = huffman_decode(raw);
  if (!decoded) {
    error = "A Huffman-coded string is not valid.";
    return false;
  }
  out = std::move(*decoded);
  return true;
}

std::uint32_t big_endian(std::string_view bytes, std::size_t at) {
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < 4U; ++index)
    value = (value << 8) | static_cast<unsigned char>(bytes[at + index]);
  return value;
}

bool read_varint(std::string_view data, std::size_t& at, std::uint64_t& value) {
  value = 0;
  for (unsigned shift = 0; shift < 70U && at < data.size(); shift += 7U) {
    const auto byte = static_cast<unsigned char>(data[at++]);
    value |= static_cast<std::uint64_t>(byte & 0x7FU) << shift;
    if ((byte & 0x80U) == 0U)
      return true;
  }
  return false;
}

std::string grpc_status_name(int code) {
  static const char* const names[] = {"OK",
                                      "CANCELLED",
                                      "UNKNOWN",
                                      "INVALID_ARGUMENT",
                                      "DEADLINE_EXCEEDED",
                                      "NOT_FOUND",
                                      "ALREADY_EXISTS",
                                      "PERMISSION_DENIED",
                                      "RESOURCE_EXHAUSTED",
                                      "FAILED_PRECONDITION",
                                      "ABORTED",
                                      "OUT_OF_RANGE",
                                      "UNIMPLEMENTED",
                                      "INTERNAL",
                                      "UNAVAILABLE",
                                      "DATA_LOSS",
                                      "UNAUTHENTICATED"};
  return code >= 0 && code < static_cast<int>(std::size(names)) ? names[code] : "unknown status";
}

std::string http2_error_text(std::uint32_t code) {
  static const char* const names[] = {"NO_ERROR",         "PROTOCOL_ERROR",     "INTERNAL_ERROR",   "FLOW_CONTROL_ERROR",
                                      "SETTINGS_TIMEOUT", "STREAM_CLOSED",      "FRAME_SIZE_ERROR", "REFUSED_STREAM",
                                      "CANCEL",           "COMPRESSION_ERROR",  "CONNECT_ERROR",    "ENHANCE_YOUR_CALM",
                                      "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED"};
  return (code < std::size(names) ? std::string(names[code]) + ", " : std::string()) + "code " + std::to_string(code);
}

std::string health_status_name(int status) {
  switch (status) {
  case 0:
    return "UNKNOWN";
  case 1:
    return "SERVING";
  case 2:
    return "NOT_SERVING";
  case 3:
    return "SERVICE_UNKNOWN";
  default:
    return "status " + std::to_string(status);
  }
}

// grpc-message is percent-encoded.
std::string percent_decoded(std::string_view text) {
  auto digit_value = [](char digit) {
    return digit >= '0' && digit <= '9'   ? digit - '0'
           : digit >= 'a' && digit <= 'f' ? digit - 'a' + 10
           : digit >= 'A' && digit <= 'F' ? digit - 'A' + 10
                                          : -1;
  };
  std::string out;
  for (std::size_t at = 0; at < text.size(); ++at) {
    if (text[at] == '%' && at + 2U < text.size()) {
      const int high = digit_value(text[at + 1U]);
      const int low = digit_value(text[at + 2U]);
      if (high >= 0 && low >= 0) {
        out += static_cast<char>(high * 16 + low);
        at += 2U;
        continue;
      }
    }
    out += text[at];
  }
  return out;
}

// The value of the last field with this name, or nullptr.
const std::string* last_header(const std::vector<HeaderField>& headers, std::string_view name) {
  const std::string* found = nullptr;
  for (const HeaderField& field : headers) {
    if (field.name == name)
      found = &field.value;
  }
  return found;
}

} // namespace

std::string http2_frame(std::uint8_t type, std::uint8_t flags, std::string_view payload, std::uint32_t stream) {
  std::string bytes;
  const auto length = static_cast<std::uint32_t>(payload.size());
  bytes += static_cast<char>((length >> 16) & 0xFFU);
  bytes += static_cast<char>((length >> 8) & 0xFFU);
  bytes += static_cast<char>(length & 0xFFU);
  bytes += static_cast<char>(type);
  bytes += static_cast<char>(flags);
  bytes += static_cast<char>((stream >> 24) & 0x7FU);
  bytes += static_cast<char>((stream >> 16) & 0xFFU);
  bytes += static_cast<char>((stream >> 8) & 0xFFU);
  bytes += static_cast<char>(stream & 0xFFU);
  bytes.append(payload);
  return bytes;
}

std::string hpack_encode_request(std::string_view path, std::string_view authority, int timeout_ms) {
  std::string block;
  block += static_cast<char>(0x83); // :method POST, static entry 3
  block += static_cast<char>(0x86); // :scheme http, static entry 6
  put_literal(block, 4U, {}, path);
  put_literal(block, 1U, {}, authority);
  put_literal(block, 31U, {}, "application/grpc");
  put_literal(block, 0U, "te", "trailers");
  // grpc-timeout is at most 8 digits and a unit: whole seconds when they divide evenly, else milliseconds.
  const int milliseconds = timeout_ms > 0 ? timeout_ms : 1;
  put_literal(block, 0U, "grpc-timeout",
              milliseconds % 1000 == 0 ? std::to_string(milliseconds / 1000) + "S" : std::to_string(milliseconds) + "m");
  return block;
}

std::string health_request(int timeout_ms) {
  const std::string block = hpack_encode_request(kHealthPath, "localhost", timeout_ms);
  return http2_frame(0x1, 0x4, block, 1U) + http2_frame(0x0, 0x1, std::string(5U, '\0'), 1U);
}

std::optional<std::string> huffman_decode(std::string_view bytes) {
  const std::map<std::uint64_t, int>& table = huffman_lookup();
  std::string out;
  std::uint32_t code = 0;
  unsigned bits = 0;
  for (const char byte : bytes) {
    for (int shift = 7; shift >= 0; --shift) {
      code = (code << 1) | ((static_cast<unsigned char>(byte) >> shift) & 1U);
      ++bits;
      if (bits >= 5U) {
        const auto found = table.find((static_cast<std::uint64_t>(bits) << 32) | code);
        if (found != table.end()) {
          if (found->second == 256)
            return std::nullopt;
          out += static_cast<char>(found->second);
          code = 0;
          bits = 0;
          continue;
        }
      }
      if (bits >= 30U)
        return std::nullopt;
    }
  }
  // What is left is padding: fewer than 8 bits, all ones (the start of the end-of-string code).
  if (bits > 7U || code != (1U << bits) - 1U)
    return std::nullopt;
  return out;
}

bool HpackDecoder::lookup(std::size_t index, HeaderField& field) const {
  if (index >= 1U && index <= kStaticCount) {
    field.name = kStaticTable[index - 1U].name;
    field.value = kStaticTable[index - 1U].value;
    return true;
  }
  if (index > kStaticCount && index - kStaticCount - 1U < table_.size()) {
    field = table_[index - kStaticCount - 1U];
    return true;
  }
  return false;
}

void HpackDecoder::shrink(std::size_t target) {
  while (bytes_ > target && !table_.empty()) {
    bytes_ -= table_.back().name.size() + table_.back().value.size() + 32U;
    table_.pop_back();
  }
}

void HpackDecoder::insert(HeaderField field) {
  const std::size_t size = field.name.size() + field.value.size() + 32U;
  if (size > max_) {
    // An entry larger than the table empties it and is not added.
    table_.clear();
    bytes_ = 0;
    return;
  }
  shrink(max_ - size);
  bytes_ += size;
  table_.push_front(std::move(field));
}

std::string HpackDecoder::decode(std::string_view block, std::vector<HeaderField>& fields) {
  // The table changes as the block is read, so a block that fails leaves it half updated and the caller
  // stops using the decoder after an error.
  std::vector<HeaderField> decoded;
  std::size_t at = 0;
  while (at < block.size()) {
    const auto first = static_cast<unsigned char>(block[at]);
    if ((first & 0x80U) != 0U) {
      std::uint64_t index = 0;
      if (!read_integer(block, at, 7U, index))
        return "The header block ends inside a number, or the number is too large.";
      HeaderField field;
      if (index == 0U || !lookup(static_cast<std::size_t>(index), field))
        return "A header field refers to table entry " + std::to_string(index) + ", which does not exist.";
      decoded.push_back(std::move(field));
      continue;
    }
    if ((first & 0xE0U) == 0x20U) {
      std::uint64_t size = 0;
      if (!read_integer(block, at, 5U, size))
        return "The header block ends inside a number, or the number is too large.";
      if (size > limit_)
        return "A dynamic table size update asks for " + std::to_string(size) + " bytes, more than the " +
               std::to_string(limit_) + " allowed.";
      max_ = static_cast<std::size_t>(size);
      shrink(max_);
      continue;
    }
    const bool indexing = (first & 0xC0U) == 0x40U;
    std::uint64_t name_index = 0;
    if (!read_integer(block, at, indexing ? 6U : 4U, name_index))
      return "The header block ends inside a number, or the number is too large.";
    HeaderField field;
    std::string error;
    if (name_index == 0U) {
      if (!read_string(block, at, field.name, error))
        return error;
    } else {
      HeaderField named;
      if (!lookup(static_cast<std::size_t>(name_index), named))
        return "A header field refers to table entry " + std::to_string(name_index) + ", which does not exist.";
      field.name = std::move(named.name);
    }
    if (!read_string(block, at, field.value, error))
      return error;
    if (indexing)
      insert(field);
    decoded.push_back(std::move(field));
  }
  for (HeaderField& field : decoded)
    fields.push_back(std::move(field));
  return {};
}

bool headers_fragment(std::uint8_t flags, std::string_view payload, std::string_view& fragment) {
  std::size_t begin = 0;
  std::size_t padding = 0;
  if ((flags & 0x8U) != 0U) {
    if (payload.empty())
      return false;
    padding = static_cast<unsigned char>(payload[0]);
    begin = 1U;
  }
  if ((flags & 0x20U) != 0U)
    begin += 5U;
  if (begin + padding > payload.size())
    return false;
  fragment = payload.substr(begin, payload.size() - begin - padding);
  return true;
}

HealthMessage parse_health_response(std::string_view data) {
  HealthMessage result;
  if (data.empty()) {
    result.error = "The service sent no message.";
    return result;
  }
  if (data.size() < 5U) {
    result.error = "The message is shorter than its 5 byte prefix.";
    return result;
  }
  if (data[0] != '\0') {
    result.error = "The message is compressed or has an unknown prefix.";
    return result;
  }
  const std::uint32_t length = big_endian(data, 1U);
  if (data.size() - 5U < length) {
    result.error = "The message is shorter than the " + std::to_string(length) + " bytes its prefix states.";
    return result;
  }
  const std::string_view message = data.substr(5U, length);
  std::size_t at = 0;
  while (at < message.size()) {
    std::uint64_t tag = 0;
    if (!read_varint(message, at, tag)) {
      result.error = "The message ends inside a field tag.";
      return result;
    }
    const std::uint64_t field = tag >> 3U;
    const std::uint64_t wire = tag & 7U;
    std::uint64_t value = 0;
    if (wire == 0U) {
      if (!read_varint(message, at, value)) {
        result.error = "The message ends inside a number.";
        return result;
      }
      if (field == 1U)
        result.status = static_cast<int>(std::min<std::uint64_t>(value, 1000U));
    } else if (field == 1U) {
      result.error = "The status field is not a number.";
      return result;
    } else if (wire == 1U || wire == 5U) {
      const std::size_t size = wire == 1U ? 8U : 4U;
      if (message.size() - at < size) {
        result.error = "The message ends inside a field.";
        return result;
      }
      at += size;
    } else if (wire == 2U) {
      if (!read_varint(message, at, value) || value > message.size() - at) {
        result.error = "The message ends inside a field.";
        return result;
      }
      at += static_cast<std::size_t>(value);
    } else {
      result.error = "The message holds a field type this reader does not know.";
      return result;
    }
  }
  result.ok = true;
  return result;
}

void HealthCall::header_block_complete() {
  collecting_ = false;
  if (!decoding_failed_) {
    std::vector<HeaderField> fields;
    const std::string error = decoder_.decode(block_, fields);
    if (!error.empty()) {
      decoding_failed_ = true;
      exchange_.header_error = error;
    } else {
      for (HeaderField& field : fields)
        exchange_.headers.push_back(std::move(field));
    }
  }
  block_.clear();
  if (block_ends_stream_) {
    exchange_.stream_ended = true;
    finished_ = true;
  }
}

std::string HealthCall::accept(std::uint8_t type, std::uint8_t flags, std::uint32_t stream, std::string_view payload) {
  std::string reply;
  if (collecting_ && (type != 0x9 || stream != 1U)) {
    collecting_ = false;
    block_.clear();
    decoding_failed_ = true;
    exchange_.header_error = "A header block was not completed by CONTINUATION frames.";
  }
  switch (type) {
  case 0x0: // DATA
    if (stream == 1U) {
      std::string_view body;
      if (!headers_fragment(static_cast<std::uint8_t>(flags & 0x8U), payload, body)) {
        exchange_.failure = "The service sent a DATA frame whose padding is longer than the frame.";
        finished_ = true;
      } else {
        exchange_.data.append(body);
        if ((flags & 0x1U) != 0U) {
          exchange_.stream_ended = true;
          finished_ = true;
        }
      }
    }
    break;
  case 0x1: // HEADERS
  case 0x9: // CONTINUATION
    if (stream == 1U && (type == 0x1 || collecting_)) {
      std::string_view fragment;
      if (!headers_fragment(type == 0x1 ? flags : static_cast<std::uint8_t>(0), payload, fragment)) {
        exchange_.failure = "The service sent a header frame that is shorter than its own fields.";
        finished_ = true;
        break;
      }
      if (type == 0x1) {
        block_.assign(fragment);
        block_ends_stream_ = (flags & 0x1U) != 0U;
      } else {
        block_.append(fragment);
      }
      if (block_.size() > (1U << 20)) {
        exchange_.failure = "The service sent a header block larger than 1 MB.";
        finished_ = true;
        break;
      }
      if ((flags & 0x4U) != 0U)
        header_block_complete();
      else
        collecting_ = true;
    }
    break;
  case 0x3: // RST_STREAM
    if (stream == 1U) {
      exchange_.reset = true;
      exchange_.error_code = payload.size() >= 4U ? big_endian(payload, 0U) : 0U;
      finished_ = true;
    }
    break;
  case 0x7: // GOAWAY
    exchange_.goaway = true;
    exchange_.error_code = payload.size() >= 8U ? big_endian(payload, 4U) : 0U;
    finished_ = true;
    break;
  case 0x4: // SETTINGS
    if ((flags & 0x1U) == 0U)
      reply = http2_frame(0x4, 0x1, {});
    break;
  case 0x6: // PING
    if ((flags & 0x1U) == 0U)
      reply = http2_frame(0x6, 0x1, payload);
    break;
  default:
    break;
  }
  return reply;
}

HealthReading read_health_exchange(const HealthExchange& exchange) {
  const auto reading = [](std::string detail, const char* status) { return HealthReading{std::move(detail), status}; };
  if (!exchange.failure.empty())
    return reading(exchange.failure, "Attention");
  if (exchange.reset)
    return reading("The service reset the health call (HTTP/2 error " + http2_error_text(exchange.error_code) + ").",
                   "Attention");
  if (exchange.goaway)
    return reading("The service sent GOAWAY instead of answering the health call (HTTP/2 error " +
                       http2_error_text(exchange.error_code) + ").",
                   "Attention");
  const std::string* grpc_status = last_header(exchange.headers, "grpc-status");
  if (grpc_status == nullptr) {
    if (!exchange.header_error.empty()) {
      std::string detail = "The service answered the health call, but its headers could not be decoded: " + exchange.header_error;
      const HealthMessage message = parse_health_response(exchange.data);
      if (message.ok)
        detail += " The message itself read " + health_status_name(message.status) + ".";
      return reading(detail, "Attention");
    }
    if (exchange.timed_out)
      return reading("The service did not answer the health call within " + std::to_string(exchange.timeout_seconds) + " seconds.",
                     "Attention");
    if (exchange.pipe_closed)
      return reading("The service closed the pipe before it answered the health call.", "Attention");
    const std::string* http_status = last_header(exchange.headers, ":status");
    if (http_status != nullptr && *http_status != "200")
      return reading("The service answered the health call with HTTP status " + *http_status + ".", "Attention");
    return reading("The service ended the health call without a grpc-status.", "Attention");
  }
  int code = -1;
  if (!grpc_status->empty() && grpc_status->size() <= 3U &&
      std::all_of(grpc_status->begin(), grpc_status->end(), [](char digit) { return digit >= '0' && digit <= '9'; }))
    code = std::stoi(*grpc_status);
  if (code < 0)
    return reading("The service sent grpc-status \"" + *grpc_status + "\", which is not a number.", "Attention");
  if (code == 12) {
    return reading(
        "The service does not offer the standard gRPC health service (grpc-status 12, UNIMPLEMENTED), so it has no "
        "health answer to give. The HTTP/2 handshake row is the evidence that the channel works.",
        "Info");
  }
  if (code != 0) {
    const std::string* raw_message = last_header(exchange.headers, "grpc-message");
    const std::string message = raw_message == nullptr ? std::string() : percent_decoded(*raw_message);
    std::string detail = "The service answered the gRPC health check with grpc-status " + std::to_string(code) + " (" +
                         grpc_status_name(code) + ")";
    if (!message.empty())
      detail += ": " + message;
    if (detail.back() != '.')
      detail += '.';
    return reading(detail, "Attention");
  }
  const HealthMessage health = parse_health_response(exchange.data);
  if (!health.ok)
    return reading("The service answered grpc-status 0 (OK), but its health message could not be read: " + health.error,
                   "Attention");
  return reading("The service answered the gRPC health check: " + health_status_name(health.status) + ".",
                 health.status == 1 ? "Pass" : health.status == 2 ? "Fail" : "Attention");
}

} // namespace service_channel_detail

const std::vector<ServiceChannelProduct>& service_channel_products() {
  return channel_data().products;
}

std::int64_t service_channel_line_time(std::string_view line) {
  // "[dd.MM.yyyy HH:mm:ss"
  if (line.size() < 20U || line[0] != '[' || line[3] != '.' || line[6] != '.' || line[11] != ' ' || line[14] != ':' ||
      line[17] != ':')
    return 0;
  auto number = [&line](std::size_t at, std::size_t count) {
    int value = 0;
    for (std::size_t index = at; index < at + count; ++index) {
      if (std::isdigit(static_cast<unsigned char>(line[index])) == 0)
        return -1;
      value = value * 10 + (line[index] - '0');
    }
    return value;
  };
  const int day = number(1, 2);
  const int month = number(4, 2);
  const int year = number(7, 4);
  const int hour = number(12, 2);
  const int minute = number(15, 2);
  const int second = number(18, 2);
  if (day < 1 || month < 1 || month > 12 || year < 1970 || hour < 0 || minute < 0 || second < 0)
    return 0;
  return days_from_civil(year, static_cast<unsigned>(month), static_cast<unsigned>(day)) * 86400 + hour * 3600 +
         minute * 60 + second;
}

std::vector<ServiceChannelRow> read_service_channel_lines(const std::vector<std::string>& lines,
                                                          std::int64_t now_seconds, int hours) {
  const ChannelData& data = channel_data();
  struct Found {
    std::uint64_t count = 0;
    std::int64_t first = 0;
    std::int64_t last = 0;
    std::set<std::string> methods;
  };
  std::vector<Found> found(data.patterns.size());
  const std::int64_t from = hours > 0 ? now_seconds - static_cast<std::int64_t>(hours) * 3600 : 0;
  std::int64_t current = 0;
  std::string method;
  for (const std::string& line : lines) {
    if (const std::int64_t stamp = service_channel_line_time(line); stamp != 0)
      current = stamp;
    if (hours > 0 && (current == 0 || current < from))
      continue;
    const std::string lower = ascii_lower(line);
    if (const std::size_t at = lower.find("execution failed ["); at != std::string::npos) {
      const std::size_t end = line.find(']', at + 18U);
      if (end != std::string::npos) {
        method = line.substr(at + 18U, end - at - 18U);
        const std::size_t dot = method.rfind('.');
        const std::size_t interface_dot = dot == std::string::npos ? std::string::npos : method.rfind('.', dot - 1U);
        if (interface_dot != std::string::npos)
          method = method.substr(interface_dot + 1U); // "IReportGrpcService.GetEpJobModels"
      }
    }
    for (std::size_t index = 0; index < data.patterns.size(); ++index) {
      const Pattern& pattern = data.patterns[index];
      if (!std::all_of(pattern.all_of.begin(), pattern.all_of.end(),
                       [&lower](const std::string& part) { return lower.find(part) != std::string::npos; }))
        continue;
      Found& entry = found[index];
      ++entry.count;
      if (entry.first == 0 || (current != 0 && current < entry.first))
        entry.first = current;
      entry.last = std::max(entry.last, current);
      if (!method.empty() && (pattern.id == "deadline" || pattern.id == "connect_timeout" || pattern.id == "unavailable"))
        entry.methods.insert(method);
    }
  }
  std::vector<ServiceChannelRow> rows;
  for (std::size_t index = 0; index < data.patterns.size(); ++index) {
    const Found& entry = found[index];
    if (entry.count == 0U)
      continue;
    const Pattern& pattern = data.patterns[index];
    std::string detail = pattern.reading + " " + std::to_string(entry.count) + (entry.count == 1U ? " line" : " lines");
    if (entry.first != 0)
      detail += ", " + time_text(entry.first) + (entry.last != entry.first ? " to " + time_text(entry.last) : std::string());
    detail += ".";
    if (!entry.methods.empty()) {
      std::string methods;
      for (const std::string& name : entry.methods)
        methods += (methods.empty() ? "" : ", ") + name;
      detail += " Calls: " + methods + ".";
    }
    if (!pattern.url.empty())
      detail += "  " + pattern.url;
    rows.push_back({kChannelLogs, pattern.name, detail, pattern.status});
  }
  if (rows.empty()) {
    rows.push_back({kChannelLogs, "gRPC lines",
                    hours > 0 ? "No gRPC lines in the last " + std::to_string(hours) + " hours." : "No gRPC lines.", "Info"});
  }
  return rows;
}

ServiceChannelReport run_service_channel_test(const ServiceChannelOptions& options, const CancellationToken& cancel,
                                              const ProgressCallback& progress) {
  ServiceChannelReport report;
  const auto layer = [&progress](const char* name, std::uint64_t index) {
    if (!progress)
      return;
    ProgressEvent event;
    event.phase = "Veeam Service Channel";
    event.current_scope = name;
    event.processed = index;
    event.total = 4;
    progress(event);
  };
  const ChannelData& data = channel_data();
  const auto product = std::find_if(data.products.begin(), data.products.end(),
                                    [&](const ServiceChannelProduct& entry) { return entry.id == options.product; });
  if (product == data.products.end()) {
    report.rows.push_back({"Product", "Product", "Unknown product: " + options.product + ".", "Could not check"});
    report.summary = "Unknown product.";
    return report;
  }
  const int hours = options.hours > 0 ? options.hours : data.hours;
  std::string service_state;
  bool service_running = false;
  bool pipe_present = false;
  bool handshake_passed = false;
  bool handshake_denied = false;
  bool handshake_timeout = false;
  std::string health_status; // the health row's status; empty when no health call was made
  bool live_ran = false;

#ifdef _WIN32
  if (options.live) {
    live_ran = true;
    // The service.
    layer(kChannelService, 0);
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager == nullptr ? nullptr
                                           : OpenServiceW(manager, wide_from_utf8(product->service).c_str(),
                                                          SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (service == nullptr) {
      const DWORD code = GetLastError();
      service_state = code == ERROR_SERVICE_DOES_NOT_EXIST ? "not installed" : "not readable";
      report.rows.push_back({kChannelService, product->service,
                             code == ERROR_SERVICE_DOES_NOT_EXIST ? product->name + " is not installed on this machine (no " +
                                                                        product->service + " service)."
                                                                  : "The service was not read: " + win_error_text(code),
                             code == ERROR_SERVICE_DOES_NOT_EXIST ? "Not applicable" : "Could not check"});
    } else {
      SERVICE_STATUS_PROCESS status{};
      DWORD needed = 0;
      QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed);
      QueryServiceConfigW(service, nullptr, 0, &needed);
      std::vector<unsigned char> buffer(needed == 0U ? 1U : needed);
      auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
      std::string account;
      std::string start = "unknown start type";
      if (needed != 0U && QueryServiceConfigW(service, config, needed, &needed) != FALSE) {
        account = config->lpServiceStartName == nullptr ? std::string() : utf8_from_wide(config->lpServiceStartName);
        start = config->dwStartType == SERVICE_AUTO_START     ? "automatic start"
                : config->dwStartType == SERVICE_DEMAND_START ? "manual start"
                : config->dwStartType == SERVICE_DISABLED     ? "disabled"
                                                              : "start type " + std::to_string(config->dwStartType);
      }
      service_state = service_state_name(status.dwCurrentState);
      service_running = status.dwCurrentState == SERVICE_RUNNING;
      std::string detail = product->service + " is " + service_state + " (" + start +
                           (account.empty() ? std::string() : ", as " + account) + ")";
      if (service_running && status.dwProcessId != 0U) {
        detail += ", process " + std::to_string(status.dwProcessId);
        if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, status.dwProcessId)) {
          FILETIME created{};
          FILETIME exited{};
          FILETIME kernel{};
          FILETIME user{};
          FILETIME local{};
          SYSTEMTIME time{};
          if (GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE &&
              FileTimeToLocalFileTime(&created, &local) != FALSE && FileTimeToSystemTime(&local, &time) != FALSE) {
            char text[64];
            std::snprintf(text, sizeof(text), " started %04u-%02u-%02u %02u:%02u", time.wYear, time.wMonth, time.wDay,
                          time.wHour, time.wMinute);
            detail += text;
          }
          CloseHandle(process);
        }
      }
      report.rows.push_back({kChannelService, product->service, detail + ".", service_running ? "Pass" : "Fail"});
      CloseServiceHandle(service);
    }
    if (manager != nullptr)
      CloseServiceHandle(manager);

    // The pipe, by its known name; the pipe namespace is not listed.
    layer(kChannelPipe, 1);
    if (!service_running) {
      report.rows.push_back({kChannelPipe, "Service pipe", "Not tried: the service is not running.", "Not applicable"});
    } else if (product->pipe.empty()) {
      report.rows.push_back({kChannelPipe, "Service pipe",
                             "The pipe " + product->name + " uses is not known yet; only the logs are read.",
                             "Not applicable"});
    } else {
      const std::wstring pipe = wide_from_utf8(product->pipe);
      if (WaitNamedPipeW(pipe.c_str(), 1) != FALSE) {
        pipe_present = true;
        report.rows.push_back({kChannelPipe, product->pipe, "Present, and an instance is free.", "Pass"});
      } else {
        const DWORD code = GetLastError();
        pipe_present = code == ERROR_SEM_TIMEOUT;
        report.rows.push_back({kChannelPipe, product->pipe,
                               code == ERROR_SEM_TIMEOUT ? "Present, but every instance was busy."
                               : code == ERROR_FILE_NOT_FOUND ? "Not present: the service is running but has not created its pipe."
                                                              : "Not read: " + win_error_text(code),
                               code == ERROR_SEM_TIMEOUT ? "Attention" : "Fail"});
      }
    }

    // The HTTP/2 handshake on the pipe, then the health call on the same connection.
    layer(kChannelHandshake, 2);
    if (pipe_present && !cancel.is_cancelled()) {
      const Handshake handshake = pipe_handshake(product->pipe, static_cast<DWORD>(data.timeout_ms), current_account());
      handshake_passed = handshake.passed;
      handshake_denied = handshake.access_denied;
      handshake_timeout = handshake.timed_out;
      report.rows.push_back({kChannelHandshake, handshake.passed ? "HTTP/2 on the pipe" : "Stage: " + handshake.stage,
                             handshake.detail, handshake.passed ? "Pass" : "Fail"});

      // The gRPC health check, made on the handshake's connection.
      if (handshake.health_ran) {
        service_channel_detail::HealthReading health = service_channel_detail::read_health_exchange(handshake.health);
        health_status = health.status;
        if (health.status != "Pass" && !data.health_url.empty())
          health.detail += "  " + data.health_url;
        report.rows.push_back({kChannelHealth, service_channel_detail::kHealthCheckName, health.detail, health.status});
      } else {
        report.rows.push_back({kChannelHealth, service_channel_detail::kHealthCheckName,
                               "Not tried: the HTTP/2 handshake did not pass.", "Not applicable"});
      }
    } else if (service_running && !product->pipe.empty()) {
      report.rows.push_back({kChannelHandshake, "HTTP/2 on the pipe", "Not tried: the pipe is not present.", "Not applicable"});
      report.rows.push_back({kChannelHealth, service_channel_detail::kHealthCheckName,
                             "Not tried: the pipe is not present.", "Not applicable"});
    }
  }
#else
  if (options.live) {
    report.rows.push_back({"Live test", "Service, pipe and handshake",
                           "The service, its pipe and the handshake are tested on Windows; here only the logs are read.",
                           "Not applicable"});
  }
#endif

  // The logs.
  layer(kChannelLogs, 3);
  const std::filesystem::path folder = options.log_folder.empty() ? expanded_folder(product->log_folder) : options.log_folder;
  std::vector<std::string> lines;
  std::size_t files_read = 0;
  std::error_code error;
  if (folder.empty() || !std::filesystem::is_directory(folder, error)) {
    report.rows.push_back({kChannelLogs, "Log folder",
                           (folder.empty() ? std::string("No log folder.") : "Not found: " + path_to_utf8(folder) + "."),
                           "Could not check"});
  } else {
    const auto window_start = std::filesystem::file_time_type::clock::now() - std::chrono::hours(hours + 1);
    auto consider = [&](const std::filesystem::directory_entry& entry) {
      if (!entry.is_regular_file(error))
        return;
      const std::string name = path_to_utf8(entry.path().filename());
      if (std::none_of(product->log_files.begin(), product->log_files.end(),
                       [&name](const std::string& pattern) { return wildcard_match(pattern, name); }))
        return;
      if (entry.last_write_time(error) < window_start)
        return;
      std::vector<std::string> read = read_tail_lines(entry.path());
      lines.insert(lines.end(), std::make_move_iterator(read.begin()), std::make_move_iterator(read.end()));
      ++files_read;
    };
    for (std::filesystem::directory_iterator entry(folder, error), end; !error && entry != end; entry.increment(error)) {
      if (cancel.is_cancelled())
        break;
      if (entry->is_directory(error)) {
        std::error_code inner;
        for (std::filesystem::directory_iterator child(entry->path(), inner), child_end; !inner && child != child_end;
             child.increment(inner))
          consider(*child);
      } else {
        consider(*entry);
      }
    }
    report.rows.push_back({kChannelLogs, "Logs read",
                           std::to_string(files_read) + (files_read == 1U ? " log" : " logs") + " in " + path_to_utf8(folder) +
                               " written in the last " + std::to_string(hours) + " hours" +
                               (product->observed_on.empty() ? std::string() : "; readings from " + product->observed_on) + ".",
                           "Info"});
    for (ServiceChannelRow& row : read_service_channel_lines(lines, local_now_seconds(), hours))
      report.rows.push_back(std::move(row));
  }

  // The summary sentence.
  bool connect_failures = false;
  bool log_errors = false;
  for (const ServiceChannelRow& row : report.rows) {
    if (row.layer == kChannelLogs && row.status == "Fail")
      log_errors = true;
    if (row.layer == kChannelLogs && row.check == "Failed to connect with the backup service")
      connect_failures = true;
  }
  const std::string window = "in the last " + std::to_string(hours) + " hours";
  if (!live_ran) {
    report.summary = "Log reading only: " + std::string(log_errors ? "the product logged gRPC errors " : "no gRPC errors ") +
                     window + ". No live test was run on this machine.";
  } else if (!service_running) {
    report.summary = product->name + "'s service is " + (service_state.empty() ? std::string("not running") : service_state) + "." +
                     (connect_failures ? " Clients logged Failed to connect with the backup service " + window + "."
                                       : std::string());
  } else if (product->pipe.empty()) {
    report.summary = product->name + "'s service is running; its pipe is not known yet, so the channel was read from the logs " +
                     std::string(log_errors ? "(gRPC errors logged " : "(no gRPC errors ") + window + ").";
  } else if (!pipe_present) {
    report.summary = "The service is running but its pipe is not present.";
  } else if (handshake_denied) {
    report.summary = "This account cannot open the service pipe.";
  } else if (handshake_timeout) {
    report.summary = "The pipe is present but the service did not answer the HTTP/2 handshake within " +
                     std::to_string(data.timeout_ms / 1000) + " seconds.";
  } else if (!handshake_passed) {
    report.summary = "The pipe is present but the HTTP/2 handshake failed.";
  } else {
    report.summary = product->name + "'s service is running, its pipe accepts this account and speaks HTTP/2, and " +
                     (log_errors ? "the product logged gRPC errors " + window + "." : "the product logged no gRPC errors " + window + ".");
    if (health_status == "Pass")
      report.summary += " The gRPC health check answered SERVING.";
    else if (health_status == "Fail")
      report.summary += " The gRPC health check answered NOT_SERVING.";
    else if (health_status == "Attention")
      report.summary += " The gRPC health check was not answered cleanly; see the gRPC health row.";
  }
  return report;
}

} // namespace support_assist
