#include "support_assist/support_tools.hpp"
#include "support_assist/network.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/security.hpp"

#include <chrono>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>



#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winnetwk.h>
#ifdef _MSC_VER
#pragma comment(lib, "Mpr.lib")
#endif
#endif

namespace support_assist {
namespace {
std::string state_escape(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  for (char c : value) {
    if (c == '\\') output += "\\\\";
    else if (c == '\n') output += "\\n";
    else if (c == '\r') output += "\\r";
    else if (c == '=') output += "\\=";
    else output.push_back(c);
  }
  return output;
}

std::string state_unescape(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  bool escaped = false;
  for (char c : value) {
    if (!escaped && c == '\\') { escaped = true; continue; }
    if (escaped) {
      if (c == 'n') output.push_back('\n');
      else if (c == 'r') output.push_back('\r');
      else output.push_back(c);
      escaped = false;
    } else output.push_back(c);
  }
  if (escaped) output.push_back('\\');
  return output;
}

std::size_t state_separator(std::string_view line) {
  bool escaped = false;
  for (std::size_t index = 0; index < line.size(); ++index) {
    if (!escaped && line[index] == '\\') { escaped = true; continue; }
    if (!escaped && line[index] == '=') return index;
    escaped = false;
  }
  return std::string_view::npos;
}

#ifdef _WIN32
bool capture_status_inactive(std::string_view text) {
  const std::string folded = ascii_lower(text);
  return folded.find("not running") != std::string::npos ||
         folded.find("not started") != std::string::npos ||
         folded.find("no trace session") != std::string::npos ||
         folded.find("there is no trace") != std::string::npos ||
         folded.find("stopped") != std::string::npos;
}

// netsh trace says "Status: Running"; pktmon lists the capture's sections and its log file instead.
bool capture_status_active(std::string_view text) {
  const std::string folded = ascii_lower(text);
  if (capture_status_inactive(text)) return false;
  return folded.find("running") != std::string::npos ||
         folded.find("capture is active") != std::string::npos ||
         folded.find("trace is active") != std::string::npos ||
         folded.find("collected data") != std::string::npos ||
         folded.find("capture type") != std::string::npos ||
         folded.find("logging mode") != std::string::npos ||
         folded.find("log file") != std::string::npos;
}

// pktmon and netsh trace answer this to an account that is not elevated.
bool capture_access_denied(std::string_view text) {
  return ascii_lower(text).find("access is denied") != std::string::npos;
}

std::string normalized_capture_output(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
  while (!value.empty() && (value.back() == '\n' || value.back() == ' ' || value.back() == '\t'))
    value.pop_back();
  return value;
}

std::string normalized_windows_path(std::filesystem::path path) {
  std::string value = ascii_lower(path_to_utf8(path.lexically_normal()));
  std::replace(value.begin(), value.end(), '/', '\\');
  return value;
}

bool capture_status_matches_output(std::string_view text, const std::filesystem::path& output) {
  std::string folded = ascii_lower(text);
  std::replace(folded.begin(), folded.end(), '/', '\\');
  const std::string expected = normalized_windows_path(output);
  return !expected.empty() && folded.find(expected) != std::string::npos;
}

// The status names a capture file that is not SAT's. A status that names no file says nothing
// against SAT's capture.
bool capture_status_names_other_file(std::string_view text, const std::filesystem::path& output) {
  return !capture_status_matches_output(text, output) && ascii_lower(text).find(".etl") != std::string::npos;
}

// What the backend's status said, for a refusal: the first 300 characters on one line.
std::string capture_status_quote(std::string_view text) {
  std::string quoted(text);
  quoted.erase(std::remove(quoted.begin(), quoted.end(), '\r'), quoted.end());
  std::replace(quoted.begin(), quoted.end(), '\n', ' ');
  quoted = trim(quoted);
  if (quoted.empty())
    return {};
  if (quoted.size() > 300U)
    quoted = quoted.substr(0, 300U) + "...";
  return " Its status read: \"" + quoted + "\"";
}

std::vector<std::uint32_t> running_procmon_processes() {
  std::vector<std::uint32_t> result;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    return result;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      const std::string name = ascii_lower(utf8_from_wide(entry.szExeFile));
      if (name == "procmon.exe" || name == "procmon64.exe" || name == "procmon64a.exe")
        result.push_back(static_cast<std::uint32_t>(entry.th32ProcessID));
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }
  CloseHandle(snapshot);
  return result;
}

std::filesystem::path process_image_path(std::uint32_t process_id) {
  HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
  if (process == nullptr)
    return {};
  std::wstring buffer(32768, L'\0');
  DWORD length = static_cast<DWORD>(buffer.size());
  if (QueryFullProcessImageNameW(process, 0, buffer.data(), &length) == FALSE) {
    CloseHandle(process);
    return {};
  }
  CloseHandle(process);
  buffer.resize(length);
  return std::filesystem::path(buffer);
}

// The image name the process list gives an id, lower case; empty when the id is not running.
std::string process_snapshot_name(std::uint32_t process_id) {
  std::string name;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    return name;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      if (entry.th32ProcessID == process_id) {
        name = ascii_lower(utf8_from_wide(entry.szExeFile));
        break;
      }
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }
  CloseHandle(snapshot);
  return name;
}

// The Win32 file API refuses a path of MAX_PATH (260) characters or more unless the path is
// absolute and carries the \\?\ prefix (\\?\UNC\ for a share). A capture state file in a deep case
// or tools folder passes that length, so the state readers and writers open it in this form.
std::wstring long_path(const std::filesystem::path& input) {
  const std::wstring& raw = input.native();
  if (raw.rfind(L"\\\\?\\", 0) == 0 || raw.rfind(L"\\\\.\\", 0) == 0)
    return raw;
  const DWORD required = GetFullPathNameW(raw.c_str(), 0, nullptr, nullptr);
  if (required == 0)
    return raw;
  std::wstring full(static_cast<std::size_t>(required), L'\0');
  const DWORD written = GetFullPathNameW(raw.c_str(), required, full.data(), nullptr);
  if (written == 0 || written >= required)
    return raw;
  full.resize(written);
  if (full.rfind(L"\\\\", 0) == 0)
    return L"\\\\?\\UNC\\" + full.substr(2);
  return L"\\\\?\\" + full;
}

// Creates each missing folder of a \\?\ path below its drive or share. CreateDirectoryW fails
// harmlessly on a folder that exists, or on a parent this account may not create in; the result is
// whether the whole path is a folder at the end.
bool create_long_directories(const std::wstring& path) {
  std::size_t next = std::wstring::npos;
  if (path.rfind(L"\\\\?\\UNC\\", 0) == 0) {
    const std::size_t server_end = path.find(L'\\', 8);
    if (server_end != std::wstring::npos)
      next = path.find(L'\\', server_end + 1);
  } else if (path.rfind(L"\\\\?\\", 0) == 0) {
    next = path.find(L'\\', 4);
  }
  while (next != std::wstring::npos) {
    next = path.find(L'\\', next + 1);
    static_cast<void>(CreateDirectoryW(path.substr(0, next).c_str(), nullptr));
  }
  const DWORD attributes = GetFileAttributesW(path.c_str());
  return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

#endif

// The path a capture state file is written through, with its folder created: the \\?\ form on
// Windows, so a state file past MAX_PATH saves. Empty, with `problem` set, when the folder cannot be
// created.
std::filesystem::path state_file_for_writing(const std::filesystem::path& state_path, std::string& problem) {
#ifdef _WIN32
  const std::wstring file = long_path(state_path);
  const std::size_t folder_end = file.find_last_of(L'\\');
  std::wstring folder = folder_end == std::wstring::npos ? std::wstring() : file.substr(0, folder_end);
  if (!folder.empty() && folder.back() == L':')
    folder += L'\\';  // a drive root keeps its separator
  if (folder.empty() || !create_long_directories(folder)) {
    problem = "Unable to create the state folder";
    return {};
  }
  return std::filesystem::path(file);
#else
  std::error_code error;
  std::filesystem::create_directories(state_path.parent_path(), error);
  if (error) {
    problem = error.message();
    return {};
  }
  return state_path;
#endif
}

// The path a capture state file is read through: the \\?\ form on Windows.
std::filesystem::path state_file_for_reading(const std::filesystem::path& state_path) {
#ifdef _WIN32
  return std::filesystem::path(long_path(state_path));
#else
  return state_path;
#endif
}

Error tool_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "SupportTools";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

Result<ProcessResult> run_tool(std::string_view tool_id,
                               std::vector<std::string> arguments,
                               const std::filesystem::path& third_party_directory,
                               const CancellationToken& cancel,
                               ProgressCallback progress,
                               std::chrono::milliseconds timeout = std::chrono::minutes(2)) {
  auto executable = resolve_external_tool(tool_id, third_party_directory);
  if (!executable.ok())
    return Result<ProcessResult>::failure(executable.error());
  ProcessOptions process;
  process.executable = std::move(executable.value());
  process.arguments = std::move(arguments);
  process.timeout = timeout;
  return run_process_capture(process, cancel, std::move(progress));
}

#ifdef _WIN32
std::filesystem::path system_executable(std::wstring_view name) {
  wchar_t buffer[MAX_PATH]{};
  const UINT length = GetSystemDirectoryW(buffer, MAX_PATH);
  if (length == 0 || length >= MAX_PATH)
    return {};
  const auto path = std::filesystem::path(buffer) / name;
  std::error_code error;
  if (!std::filesystem::is_regular_file(path, error) || error)
    return {};
  return path;
}

Result<ProcessResult> run_system_tool(std::wstring_view name,
                                      std::vector<std::string> arguments,
                                      const CancellationToken& cancel,
                                      ProgressCallback progress,
                                      std::chrono::milliseconds timeout = std::chrono::minutes(2)) {
  ProcessOptions process;
  process.executable = system_executable(name);
  if (process.executable.empty())
    // Use the project's UTF-8 converter. Constructing a narrow std::string from wide iterators
    // narrows each wchar_t to char, which MSVC reports as C4244 under /WX and which silently
    // mangles any non-ASCII executable name in the diagnostic.
    return Result<ProcessResult>::failure(tool_error(
        "launch system tool", utf8_from_wide(name),
        "Trusted Windows system executable was not found"));
  process.arguments = std::move(arguments);
  process.timeout = timeout;
  return run_process_capture(process, cancel, std::move(progress));
}

bool running_elevated() {
  auto context = current_security_context();
  return context.ok() && context.value().elevated;
}

std::wstring quoted_argument(std::wstring_view value) {
  std::wstring result = L"\"";
  std::size_t slashes = 0;
  for (const wchar_t ch : value) {
    if (ch == L'\\') {
      ++slashes;
      continue;
    }
    if (ch == L'"') {
      result.append(slashes * 2 + 1, L'\\');
      result.push_back(ch);
      slashes = 0;
      continue;
    }
    result.append(slashes, L'\\');
    slashes = 0;
    result.push_back(ch);
  }
  result.append(slashes * 2, L'\\');
  result.push_back(L'"');
  return result;
}

// Starts a program through the administrator prompt and hands back its process. The id is the
// elevated process's own; a program that elevates itself starts a second process instead.
Result<HANDLE> start_elevated(const std::filesystem::path& program,
                              const std::vector<std::string>& arguments,
                              int show) {
  std::wstring parameters;
  for (const auto& argument : arguments) {
    if (!parameters.empty())
      parameters.push_back(L' ');
    parameters += quoted_argument(wide_from_utf8(argument));
  }
  const std::wstring file = program.wstring();
  const std::wstring folder = program.parent_path().wstring();
  SHELLEXECUTEINFOW execute{};
  execute.cbSize = sizeof(execute);
  execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
  execute.lpVerb = L"runas";
  execute.lpFile = file.c_str();
  execute.lpParameters = parameters.c_str();
  execute.lpDirectory = folder.empty() ? nullptr : folder.c_str();
  execute.nShow = show;
  if (ShellExecuteExW(&execute) == FALSE || execute.hProcess == nullptr) {
    const DWORD code = GetLastError();
    Error error = tool_error("start as administrator", path_to_utf8(program),
                             code == ERROR_CANCELLED ? "The administrator prompt was declined"
                                                     : "ShellExecuteExW failed");
    error.native_code = static_cast<std::int64_t>(code);
    error.elevation_may_help = true;
    return Result<HANDLE>::failure(std::move(error));
  }
  return Result<HANDLE>::success(execute.hProcess);
}

// Procmon's /Terminate with the program the session started, through the administrator prompt
// when SAT is not elevated. Procmon finishes writing the backing file before it exits.
Result<ProcessResult> procmon_terminate(const std::filesystem::path& program,
                                        const CancellationToken& cancel,
                                        ProgressCallback progress) {
  if (running_elevated()) {
    ProcessOptions process;
    process.executable = program;
    process.arguments = {"/Terminate"};
    process.timeout = std::chrono::seconds(60);
    return run_process_capture(process, cancel, std::move(progress));
  }
  static_cast<void>(cancel);
  static_cast<void>(progress);
  auto elevated = start_elevated(program, {"/Terminate"}, SW_HIDE);
  if (!elevated.ok())
    return Result<ProcessResult>::failure(elevated.error());
  const DWORD wait = WaitForSingleObject(elevated.value(), 60000);
  DWORD code = 1;
  if (wait == WAIT_OBJECT_0)
    GetExitCodeProcess(elevated.value(), &code);
  CloseHandle(elevated.value());
  if (wait != WAIT_OBJECT_0)
    return Result<ProcessResult>::failure(tool_error("stop Process Monitor", path_to_utf8(program),
                                                     "Process Monitor did not finish within 60 seconds"));
  ProcessResult result;
  result.launched = true;
  result.exit_code = static_cast<int>(code);
  return Result<ProcessResult>::success(std::move(result));
}

PacketCaptureBackend choose_capture_backend(PacketCaptureBackend requested) {
  if (requested != PacketCaptureBackend::automatic)
    return requested;
  return resolve_external_tool("pktmon").ok() ? PacketCaptureBackend::pktmon
                                              : PacketCaptureBackend::netsh;
}
#endif

} // namespace

namespace {
// A counter as pktmon prints it, thousands grouped with the locale's separator.
std::optional<std::uint64_t> counter_value(std::string_view token) {
  std::uint64_t value = 0;
  bool digits = false;
  for (const char c : token) {
    if (c >= '0' && c <= '9') {
      value = value * 10U + static_cast<std::uint64_t>(c - '0');
      digits = true;
    } else if (c != ',' && c != '.' && c != '\'') {
      return std::nullopt;
    }
  }
  return digits ? std::optional<std::uint64_t>(value) : std::nullopt;
}

std::string grouped_count(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (std::size_t at = digits.size(); at > 3U; at -= 3U)
    digits.insert(at - 3U, ",");
  return digits;
}

std::string megabytes_text(std::uint64_t bytes) {
  const std::uint64_t tenths = (bytes * 10U + 524288U) / 1048576U;
  return std::to_string(tenths / 10U) + "." + std::to_string(tenths % 10U) + " MB";
}
} // namespace

std::string pktmon_counters_summary(std::string_view counters_output) {
  struct Totals {
    std::uint64_t rx_packets = 0;
    std::uint64_t rx_bytes = 0;
    std::uint64_t tx_packets = 0;
    std::uint64_t tx_bytes = 0;
  };
  Totals sum;
  Totals group;
  bool any = false;
  const auto close_group = [&]() {
    sum.rx_packets += group.rx_packets;
    sum.rx_bytes += group.rx_bytes;
    sum.tx_packets += group.tx_packets;
    sum.tx_bytes += group.tx_bytes;
    group = Totals{};
  };
  std::istringstream lines{std::string(counters_output)};
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (trim(line).empty())
      continue;
    std::istringstream words(line);
    std::vector<std::string> tokens;
    for (std::string word; words >> word;)
      tokens.push_back(word);
    bool counted = false;
    for (std::size_t index = 0; index + 2U < tokens.size(); ++index) {
      const std::string direction = ascii_lower(tokens[index]);
      if (direction != "rx" && direction != "tx")
        continue;
      const auto packets = counter_value(tokens[index + 1U]);
      const auto bytes = counter_value(tokens[index + 2U]);
      if (!packets || !bytes)
        continue;
      counted = true;
      if (direction == "rx") {
        group.rx_packets = std::max(group.rx_packets, *packets);
        group.rx_bytes = std::max(group.rx_bytes, *bytes);
      } else {
        group.tx_packets = std::max(group.tx_packets, *packets);
        group.tx_bytes = std::max(group.tx_bytes, *bytes);
      }
    }
    // An adapter's own line, not indented and without counts, starts its group.
    if (!counted && line.front() != ' ' && line.front() != '\t')
      close_group();
    any = any || counted;
  }
  close_group();
  if (!any)
    return {};
  return "Received " + grouped_count(sum.rx_packets) + " packets (" + megabytes_text(sum.rx_bytes) + "), sent " +
         grouped_count(sum.tx_packets) + " packets (" + megabytes_text(sum.tx_bytes) + ")";
}

std::string packet_capture_progress_text(const PacketCaptureSession& session, const CancellationToken& cancel) {
  std::string text;
#ifdef _WIN32
  if (session.backend == PacketCaptureBackend::pktmon) {
    auto counters = run_tool("pktmon", {"counters"}, {}, cancel, {}, std::chrono::seconds(20));
    if (counters.ok())
      text = pktmon_counters_summary(counters.value().output);
  }
#else
  static_cast<void>(cancel);
#endif
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(session.output_etl, error);
  if (!error)
    text += (text.empty() ? std::string("Capture file ") : std::string("; capture file ")) +
            megabytes_text(static_cast<std::uint64_t>(size));
  return text.empty() ? std::string("No packets counted yet") : text;
}

bool pktmon_filter_list_empty(std::string_view text) {
  const std::string folded = ascii_lower(text);
  if (folded.find("no filters") != std::string::npos || folded.find("no packet filters") != std::string::npos ||
      folded.find("filter list is empty") != std::string::npos)
    return true;
  constexpr std::string_view heading = "packet filters:";
  const std::size_t found = folded.find(heading);
  if (found == std::string::npos)
    return false;
  const std::size_t first = folded.find_first_not_of(" \t\r\n", found + heading.size());
  const std::size_t last = folded.find_last_not_of(" \t\r\n");
  return first != std::string::npos && folded.substr(first, last - first + 1) == "none";
}

std::string to_string(PacketCaptureBackend backend) {
  switch (backend) {
  case PacketCaptureBackend::automatic:
    return "auto";
  case PacketCaptureBackend::pktmon:
    return "pktmon";
  case PacketCaptureBackend::netsh:
    return "netsh";
  }
  return "auto";
}

Result<PacketCaptureBackend> parse_packet_capture_backend(std::string_view value) {
  const std::string folded = ascii_lower(value);
  if (folded.empty() || folded == "auto" || folded == "automatic") {
    return Result<PacketCaptureBackend>::success(PacketCaptureBackend::automatic);
  }
  if (folded == "pktmon") {
    return Result<PacketCaptureBackend>::success(PacketCaptureBackend::pktmon);
  }
  if (folded == "netsh") {
    return Result<PacketCaptureBackend>::success(PacketCaptureBackend::netsh);
  }
  return Result<PacketCaptureBackend>::failure(tool_error(
      "parse packet capture backend", std::string(value), "Expected auto, pktmon, or netsh"));
}

Status save_packet_capture_session(const PacketCaptureSession& session) {
  if (session.state_path.empty())
    return Status::failure(tool_error("save packet capture session", {}, "A state path is required"));
  std::string problem;
  const std::filesystem::path state_file = state_file_for_writing(session.state_path, problem);
  if (state_file.empty())
    return Status::failure(tool_error("save packet capture session", path_to_utf8(session.state_path), problem));
  std::ofstream output(state_file, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(tool_error("save packet capture session", path_to_utf8(session.state_path), "Unable to create state file"));
  output << "schema=1\n"
         << "session_id=" << state_escape(session.session_id) << "\n"
         << "backend=" << to_string(session.backend) << "\n"
         << "output_etl=" << state_escape(path_to_utf8(session.output_etl)) << "\n"
         << "started_utc=" << state_escape(session.started_utc) << "\n"
         << "stopped_utc=" << state_escape(session.stopped_utc) << "\n"
         << "active=" << (session.active ? "1" : "0") << "\n"
         << "ip_filter=" << state_escape(session.ip_filter.value_or("")) << "\n"
         << "port_filter=" << (session.port_filter ? std::to_string(*session.port_filter) : std::string{}) << "\n"
         << "pktmon_filter_owned=" << (session.pktmon_filter_owned ? "1" : "0") << "\n"
         << "pktmon_filter_name=" << state_escape(session.pktmon_filter_name) << "\n"
         << "pktmon_owned_filter_snapshot=" << state_escape(session.pktmon_owned_filter_snapshot) << "\n";
  output.flush();
  if (!output)
    return Status::failure(tool_error("save packet capture session", path_to_utf8(session.state_path), "State write failed"));
  return Status::success();
}

Result<PacketCaptureSession> load_packet_capture_session(const std::filesystem::path& state_path) {
  std::ifstream input(state_file_for_reading(state_path), std::ios::binary);
  if (!input)
    return Result<PacketCaptureSession>::failure(
        tool_error("load packet capture session", path_to_utf8(state_path), "Unable to open state file"));
  PacketCaptureSession session;
  session.state_path = state_path;
  std::string line;
  int schema = 0;
  while (std::getline(input, line)) {
    const std::size_t split = state_separator(line);
    if (split == std::string::npos) continue;
    const std::string key = line.substr(0, split);
    const std::string value = state_unescape(std::string_view(line).substr(split + 1U));
    if (key == "schema") {
      try {
        schema = std::stoi(value);
      } catch (...) {
        return Result<PacketCaptureSession>::failure(
            tool_error("load packet capture session", path_to_utf8(state_path), "Persisted schema is invalid"));
      }
    }
    else if (key == "session_id") session.session_id = value;
    else if (key == "backend") {
      auto parsed = parse_packet_capture_backend(value);
      if (!parsed.ok() || parsed.value() == PacketCaptureBackend::automatic)
        return Result<PacketCaptureSession>::failure(
            tool_error("load packet capture session", path_to_utf8(state_path), "Persisted backend is invalid"));
      session.backend = parsed.value();
    } else if (key == "output_etl") session.output_etl = path_from_utf8(value);
    else if (key == "started_utc") session.started_utc = value;
    else if (key == "stopped_utc") session.stopped_utc = value;
    else if (key == "active") session.active = value == "1";
    else if (key == "ip_filter" && !value.empty()) session.ip_filter = value;
    else if (key == "port_filter" && !value.empty()) {
      try {
        const unsigned long port = std::stoul(value);
        if (port == 0UL || port > 65535UL)
          throw std::out_of_range("port");
        session.port_filter = static_cast<std::uint16_t>(port);
      } catch (...) {
        return Result<PacketCaptureSession>::failure(
            tool_error("load packet capture session", path_to_utf8(state_path), "Persisted port is invalid"));
      }
    } else if (key == "pktmon_filter_owned") session.pktmon_filter_owned = value == "1";
    else if (key == "pktmon_filter_name") session.pktmon_filter_name = value;
    else if (key == "pktmon_owned_filter_snapshot") session.pktmon_owned_filter_snapshot = value;
  }
  if (schema != 1 || session.session_id.empty() || session.backend == PacketCaptureBackend::automatic ||
      session.output_etl.empty()) {
    return Result<PacketCaptureSession>::failure(
        tool_error("load packet capture session", path_to_utf8(state_path), "Capture session state is incomplete"));
  }
  return Result<PacketCaptureSession>::success(std::move(session));
}

// The operation a failure of the backend's own start command carries: pktmon not starting is when
// netsh trace takes over.
constexpr std::string_view kBackendStartFailed = "start capture backend";

static Result<PacketCaptureSession> start_owned_capture(const PacketCaptureOptions& options,
                                                        PacketCaptureBackend backend,
                                                        const std::filesystem::path& state_directory,
                                                        const CancellationToken& cancel,
                                                        ProgressCallback progress) {
#ifdef _WIN32
  if (options.output_etl.empty())
    return Result<PacketCaptureSession>::failure(
        tool_error("start owned packet capture", {}, "An ETL output path is required"));
  if (state_directory.empty())
    return Result<PacketCaptureSession>::failure(
        tool_error("start owned packet capture", {}, "A capture state directory is required"));

  PacketCaptureSession session;
  session.session_id = make_uuid_v4();
  session.backend = backend;
  session.output_etl = options.output_etl;
  session.state_path = state_directory / ("pc-" + session.session_id.substr(0, 8) + ".state");
  session.started_utc = utc_now_iso8601();
  session.ip_filter = options.ip_filter;
  session.port_filter = options.port_filter;

  // Refuse to claim an already-running global capture. Unknown/localized status
  // is treated conservatively rather than risking another owner's trace.
  Result<ProcessResult> before = session.backend == PacketCaptureBackend::netsh
      ? run_system_tool(L"netsh.exe", {"trace", "show", "status"}, cancel, progress, std::chrono::seconds(30))
      : run_tool("pktmon", {"status"}, {}, cancel, progress, std::chrono::seconds(30));
  if (!before.ok())
    return Result<PacketCaptureSession>::failure(before.error());
  if (capture_access_denied(before.value().output)) {
    Error error = tool_error("start owned packet capture", to_string(session.backend),
                             std::string("Packet capture needs administrator: ") +
                                 (session.backend == PacketCaptureBackend::netsh ? "netsh trace" : "pktmon") +
                                 " answered \"Access is denied\" for this account.");
    error.elevation_may_help = true;
    return Result<PacketCaptureSession>::failure(std::move(error));
  }
  if (capture_status_active(before.value().output))
    return Result<PacketCaptureSession>::failure(
        tool_error("start owned packet capture", to_string(session.backend),
                   "A packet capture is already active. SAT will not replace or stop an unowned capture."));
  if (!capture_status_inactive(before.value().output) && !trim(before.value().output).empty())
    return Result<PacketCaptureSession>::failure(
        tool_error("start owned packet capture", to_string(session.backend),
                   "Unable to prove that the global capture backend is idle. SAT will not take ownership."));

  PacketCaptureOptions concrete = options;
  concrete.backend = session.backend;
  if (session.backend == PacketCaptureBackend::pktmon && (options.ip_filter || options.port_filter)) {
    auto listed = run_tool("pktmon", {"filter", "list"}, {}, cancel, progress, std::chrono::seconds(30));
    if (!listed.ok())
      return Result<PacketCaptureSession>::failure(listed.error());
    if (!pktmon_filter_list_empty(listed.value().output))
      return Result<PacketCaptureSession>::failure(
          tool_error("start owned packet capture", "pktmon filters",
                     "Existing or unrecognized global pktmon filters are present. SAT will not remove or replace them."));
    session.pktmon_filter_name = "SAT-" + session.session_id.substr(0, 8U);
    std::vector<std::string> filter{"filter", "add", session.pktmon_filter_name};
    if (options.ip_filter) { filter.push_back("-i"); filter.push_back(*options.ip_filter); }
    if (options.port_filter) { filter.push_back("-p"); filter.push_back(std::to_string(*options.port_filter)); }
    auto added = run_tool("pktmon", std::move(filter), {}, cancel, progress, std::chrono::seconds(30));
    if (!added.ok() || added.value().exit_code != 0)
      return added.ok() ? Result<PacketCaptureSession>::failure(
                              tool_error("add pktmon filter", session.pktmon_filter_name, added.value().output))
                        : Result<PacketCaptureSession>::failure(added.error());
    auto owned_snapshot = run_tool("pktmon", {"filter", "list"}, {}, cancel, progress, std::chrono::seconds(30));
    if (!owned_snapshot.ok())
      return Result<PacketCaptureSession>::failure(owned_snapshot.error());
    session.pktmon_filter_owned = true;
    session.pktmon_owned_filter_snapshot = normalized_capture_output(owned_snapshot.value().output);
    // The legacy start helper would remove filters. Start pktmon directly now.
    concrete.ip_filter.reset();
    concrete.port_filter.reset();
  }

  auto started = packet_capture_start(concrete, cancel, progress);
  if (!started.ok() || started.value().exit_code != 0) {
    if (session.pktmon_filter_owned) {
      auto current = run_tool("pktmon", {"filter", "list"}, {}, cancel, {}, std::chrono::seconds(30));
      if (current.ok() && normalized_capture_output(current.value().output) == session.pktmon_owned_filter_snapshot)
        static_cast<void>(run_tool("pktmon", {"filter", "remove"}, {}, cancel, {}, std::chrono::seconds(30)));
    }
    Error error = started.ok() ? tool_error(std::string(kBackendStartFailed), to_string(session.backend),
                                            started.value().output)
                               : started.error();
    error.operation = std::string(kBackendStartFailed);
    return Result<PacketCaptureSession>::failure(std::move(error));
  }
  session.active = true;
  auto saved = save_packet_capture_session(session);
  if (!saved.ok()) {
    static_cast<void>(session.backend == PacketCaptureBackend::netsh
                          ? run_system_tool(L"netsh.exe", {"trace", "stop"}, cancel, {}, std::chrono::minutes(3))
                          : run_tool("pktmon", {"stop"}, {}, cancel, {}, std::chrono::seconds(30)));
    if (session.backend == PacketCaptureBackend::pktmon && session.pktmon_filter_owned) {
      auto current = run_tool("pktmon", {"filter", "list"}, {}, cancel, {}, std::chrono::seconds(30));
      if (current.ok() &&
          normalized_capture_output(current.value().output) == session.pktmon_owned_filter_snapshot) {
        static_cast<void>(run_tool("pktmon", {"filter", "remove"}, {}, cancel, {},
                                   std::chrono::seconds(30)));
      }
    }
    return Result<PacketCaptureSession>::failure(saved.error());
  }
  return Result<PacketCaptureSession>::success(std::move(session));
#else
  static_cast<void>(options); static_cast<void>(backend); static_cast<void>(state_directory);
  static_cast<void>(cancel); static_cast<void>(progress);
  return Result<PacketCaptureSession>::failure(
      tool_error("start owned packet capture", {}, "Packet capture requires Windows"));
#endif
}

Result<PacketCaptureSession>
packet_capture_start_owned(const PacketCaptureOptions& options,
                           const std::filesystem::path& state_directory,
                           const CancellationToken& cancel,
                           ProgressCallback progress) {
#ifdef _WIN32
  if (options.backend != PacketCaptureBackend::automatic)
    return start_owned_capture(options, options.backend, state_directory, cancel, std::move(progress));
  if (!resolve_external_tool("pktmon").ok())
    return start_owned_capture(options, PacketCaptureBackend::netsh, state_directory, cancel, std::move(progress));
  auto started = start_owned_capture(options, PacketCaptureBackend::pktmon, state_directory, cancel, progress);
  // netsh trace is Windows' other packet capture: it takes over when pktmon's own start fails. It has
  // no port filter, and a refusal before the start (a capture running, no administrator) holds for it.
  if (started.ok() || options.port_filter || started.error().operation != kBackendStartFailed)
    return started;
  auto fallback = start_owned_capture(options, PacketCaptureBackend::netsh, state_directory, cancel, std::move(progress));
  if (fallback.ok())
    return fallback;
  return started;
#else
  return start_owned_capture(options, options.backend, state_directory, cancel, std::move(progress));
#endif
}

Result<ProcessResult> packet_capture_status_owned(const PacketCaptureSession& session,
                                                  const CancellationToken& cancel,
                                                  ProgressCallback progress) {
  if (!session.active)
    return Result<ProcessResult>::failure(
        tool_error("owned packet capture status", session.session_id, "The SAT capture session is not active"));
  if (session.backend == PacketCaptureBackend::automatic)
    return Result<ProcessResult>::failure(
        tool_error("owned packet capture status", session.session_id, "Persisted backend is missing"));
  auto status = packet_capture_status(cancel, std::move(progress), session.backend);
  if (!status.ok() || status.value().exit_code != 0)
    return status;
#ifdef _WIN32
  if (!capture_status_active(status.value().output)) {
    return Result<ProcessResult>::failure(tool_error(
        "owned packet capture status", session.session_id,
        "The persisted SAT session says the capture is active, but the backend is not active. SAT will not claim ownership of a replacement trace." +
            capture_status_quote(status.value().output)));
  }
  if (capture_status_names_other_file(status.value().output, session.output_etl)) {
    return Result<ProcessResult>::failure(tool_error(
        "owned packet capture status", session.session_id,
        "The active capture output does not match the SAT-owned ETL path. SAT will not claim or stop this global capture." +
            capture_status_quote(status.value().output)));
  }
  if (session.backend == PacketCaptureBackend::pktmon && session.pktmon_filter_owned) {
    auto current = run_tool("pktmon", {"filter", "list"}, {}, cancel, {}, std::chrono::seconds(30));
    if (!current.ok() ||
        normalized_capture_output(current.value().output) != session.pktmon_owned_filter_snapshot) {
      return Result<ProcessResult>::failure(tool_error(
          "owned packet capture status", session.session_id,
          "The global pktmon filter set changed after SAT started the capture. SAT will not claim ownership."));
    }
  }
#endif
  return status;
}

Result<ProcessResult> packet_capture_stop_owned(PacketCaptureSession& session,
                                                const CancellationToken& cancel,
                                                ProgressCallback progress) {
#ifdef _WIN32
  // A capture that already ended, or that another capture replaced, ends SAT's session: nothing of
  // SAT's is left to stop, and the session must not hold the tab or SAT open.
  if (session.active && session.backend != PacketCaptureBackend::automatic) {
    auto status = packet_capture_status(cancel, {}, session.backend);
    if (status.ok() && !capture_access_denied(status.value().output) &&
        (!capture_status_active(status.value().output) ||
         capture_status_names_other_file(status.value().output, session.output_etl))) {
      const bool replaced = capture_status_active(status.value().output);
      ProcessResult ended;
      ended.launched = true;
      ended.exit_code = 0;
      ended.output = replaced ? "Another packet capture is running, not SAT's; SAT left it running. SAT's capture had "
                                "already ended."
                              : "The capture had already stopped. Its file is kept.";
      if (!replaced && session.backend == PacketCaptureBackend::pktmon && session.pktmon_filter_owned) {
        auto current = run_tool("pktmon", {"filter", "list"}, {}, cancel, {}, std::chrono::seconds(30));
        if (current.ok() && normalized_capture_output(current.value().output) == session.pktmon_owned_filter_snapshot)
          static_cast<void>(run_tool("pktmon", {"filter", "remove"}, {}, cancel, {}, std::chrono::seconds(30)));
      }
      session.active = false;
      session.stopped_utc = utc_now_iso8601();
      auto saved = save_packet_capture_session(session);
      if (!saved.ok())
        ended.output += "\nSAT warning: session state could not be updated: " + saved.error().message;
      return Result<ProcessResult>::success(std::move(ended));
    }
  }
#endif
  // Verify the concrete backend, active state, output file and any owned pktmon
  // filter snapshot before invoking a global stop command. If another actor has
  // replaced the trace, SAT refuses to stop it.
  auto ownership = packet_capture_status_owned(session, cancel, {});
  if (!ownership.ok())
    return Result<ProcessResult>::failure(ownership.error());
  auto stopped = packet_capture_stop(cancel, progress, session.backend);
  if (!stopped.ok() || stopped.value().exit_code != 0)
    return stopped;
#ifdef _WIN32
  if (session.backend == PacketCaptureBackend::pktmon && session.pktmon_filter_owned) {
    auto current = run_tool("pktmon", {"filter", "list"}, {}, cancel, {}, std::chrono::seconds(30));
    if (current.ok() && normalized_capture_output(current.value().output) == session.pktmon_owned_filter_snapshot) {
      auto removed = run_tool("pktmon", {"filter", "remove"}, {}, cancel, {}, std::chrono::seconds(30));
      if (!removed.ok() || removed.value().exit_code != 0)
        stopped.value().output += "\nSAT warning: capture stopped but the owned pktmon filter could not be removed safely.";
    } else {
      stopped.value().output += "\nSAT warning: pktmon filters changed while capture was active; SAT left the global filter set untouched.";
    }
  }
#endif
  session.active = false;
  session.stopped_utc = utc_now_iso8601();
  auto saved = save_packet_capture_session(session);
  if (!saved.ok())
    stopped.value().output += "\nSAT warning: capture stopped but session state could not be updated: " + saved.error().message;
  return stopped;
}

Result<ProcessResult> packet_capture_start(const PacketCaptureOptions& options,
                                           const CancellationToken& cancel,
                                           ProgressCallback progress) {
#ifdef _WIN32
  if (options.output_etl.empty()) {
    return Result<ProcessResult>::failure(
        tool_error("start packet capture", {}, "An ETL output path is required"));
  }

  const PacketCaptureBackend backend = choose_capture_backend(options.backend);
  if (backend == PacketCaptureBackend::netsh) {
    if (options.port_filter) {
      return Result<ProcessResult>::failure(
          tool_error("start packet capture",
                     std::to_string(*options.port_filter),
                     "Netsh capture filters do not support a TCP/UDP port. Use an IP filter "
                     "or install/use pktmon on a supported Windows build."));
    }
    std::vector<std::string> arguments{"trace",
                                       "start",
                                       "capture=yes",
                                       "protocol=TCP",
                                       "report=no",
                                       "persistent=no",
                                       "tracefile=" + path_to_utf8(options.output_etl)};
    if (options.ip_filter && !options.ip_filter->empty()) {
      const bool ipv6 = options.ip_filter->find(':') != std::string::npos;
      arguments.push_back(std::string(ipv6 ? "IPv6.Address=" : "IPv4.Address=") +
                          *options.ip_filter);
    }
    arguments.insert(arguments.end(),
                     options.custom_start_arguments.begin(),
                     options.custom_start_arguments.end());
    return run_system_tool(
        L"netsh.exe", std::move(arguments), cancel, std::move(progress), std::chrono::seconds(45));
  }

  if (options.ip_filter || options.port_filter) {
    return Result<ProcessResult>::failure(
        tool_error("start packet capture",
                   "pktmon filters",
                   "Filtered pktmon capture must use packet_capture_start_owned so SAT can verify and preserve the global filter state."));
  }
  std::vector<std::string> arguments{
      "start", "--capture", "--pkt-size", "0", "--file-name", path_to_utf8(options.output_etl)};
  arguments.insert(arguments.end(),
                   options.custom_start_arguments.begin(),
                   options.custom_start_arguments.end());
  return run_tool(
      "pktmon", std::move(arguments), {}, cancel, std::move(progress), std::chrono::seconds(30));
#else
  static_cast<void>(options);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<ProcessResult>::failure(
      tool_error("start packet capture", {}, "Packet capture requires Windows"));
#endif
}

Result<ProcessResult> packet_capture_stop(const CancellationToken& cancel,
                                          ProgressCallback progress,
                                          PacketCaptureBackend backend) {
#ifdef _WIN32
  if (backend == PacketCaptureBackend::automatic) {
    return Result<ProcessResult>::failure(tool_error(
        "stop packet capture", "auto",
        "Auto backend is unsafe for stop. Use the persisted SAT capture session/backend."));
  }
  const PacketCaptureBackend selected = backend;
  if (selected == PacketCaptureBackend::netsh) {
    return run_system_tool(
        L"netsh.exe", {"trace", "stop"}, cancel, std::move(progress), std::chrono::minutes(3));
  }
  return run_tool("pktmon", {"stop"}, {}, cancel, std::move(progress), std::chrono::seconds(30));
#else
  static_cast<void>(cancel);
  static_cast<void>(progress);
  static_cast<void>(backend);
  return Result<ProcessResult>::failure(
      tool_error("stop packet capture", {}, "Packet capture requires Windows"));
#endif
}

Result<ProcessResult> packet_capture_status(const CancellationToken& cancel,
                                            ProgressCallback progress,
                                            PacketCaptureBackend backend) {
#ifdef _WIN32
  if (backend == PacketCaptureBackend::automatic) {
    return Result<ProcessResult>::failure(tool_error(
        "packet capture status", "auto",
        "Auto backend is unsafe for status. Use the persisted SAT capture session/backend."));
  }
  const PacketCaptureBackend selected = backend;
  if (selected == PacketCaptureBackend::netsh) {
    return run_system_tool(L"netsh.exe",
                           {"trace", "show", "status"},
                           cancel,
                           std::move(progress),
                           std::chrono::seconds(30));
  }
  return run_tool("pktmon", {"status"}, {}, cancel, std::move(progress), std::chrono::seconds(30));
#else
  static_cast<void>(cancel);
  static_cast<void>(progress);
  static_cast<void>(backend);
  return Result<ProcessResult>::failure(
      tool_error("packet capture status", {}, "Packet capture requires Windows"));
#endif
}

Result<ProcessResult> packet_capture_text(const std::filesystem::path& input_etl,
                                          const std::filesystem::path& output_text,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress) {
#ifdef _WIN32
  return run_tool("pktmon",
                  {"etl2txt", path_to_utf8(input_etl), "--out", path_to_utf8(output_text)},
                  {},
                  cancel,
                  std::move(progress),
                  std::chrono::minutes(10));
#else
  static_cast<void>(cancel);
  static_cast<void>(progress);
  static_cast<void>(output_text);
  return Result<ProcessResult>::failure(
      tool_error("packet capture text", path_to_utf8(input_etl), "pktmon is part of Windows"));
#endif
}

Result<ProcessResult> convert_packet_capture_native(const std::filesystem::path& input_etl,
                                                    const std::filesystem::path& output_pcapng,
                                                    const CancellationToken& cancel,
                                                    ProgressCallback progress) {
#ifdef _WIN32
  return run_tool("pktmon",
                  {"etl2pcap", path_to_utf8(input_etl), "--out", path_to_utf8(output_pcapng)},
                  {},
                  cancel,
                  std::move(progress),
                  std::chrono::minutes(10));
#else
  static_cast<void>(output_pcapng);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<ProcessResult>::failure(
      tool_error("convert packet capture", path_to_utf8(input_etl), "pktmon is part of Windows"));
#endif
}

Result<ProcessResult> convert_packet_capture(const std::filesystem::path& input_etl,
                                             const std::filesystem::path& output_pcapng,
                                             const std::filesystem::path& third_party_directory,
                                             const CancellationToken& cancel,
                                             ProgressCallback progress) {
  if (input_etl.empty() || output_pcapng.empty()) {
    return Result<ProcessResult>::failure(
        tool_error("convert packet capture",
                   path_to_utf8(input_etl),
                   "Both input ETL and output PCAPNG paths are required"));
  }
#ifdef _WIN32
  // Current Windows builds can convert pktmon ETL files without an extra
  // download. Keep the Microsoft etl2pcapng utility only as a compatibility
  // fallback for captures that pktmon cannot read.
  auto native = convert_packet_capture_native(input_etl, output_pcapng, cancel, progress);
  if (native.ok() && native.value().exit_code == 0)
    return native;

  auto fallback = run_tool("etl2pcapng",
                           {path_to_utf8(input_etl), path_to_utf8(output_pcapng)},
                           third_party_directory,
                           cancel,
                           std::move(progress),
                           std::chrono::minutes(10));
  if (fallback.ok())
    return fallback;
  if (native.ok()) {
    Error error = fallback.error();
    error.message = "The in-box pktmon converter rejected the ETL file and the optional "
                    "etl2pcapng fallback was not available. pktmon output: " +
                    native.value().output;
    return Result<ProcessResult>::failure(std::move(error));
  }
  return fallback;
#else
  return run_tool("etl2pcapng",
                  {path_to_utf8(input_etl), path_to_utf8(output_pcapng)},
                  third_party_directory,
                  cancel,
                  std::move(progress),
                  std::chrono::minutes(10));
#endif
}

Status save_procmon_session(const ProcmonSession& session) {
  if (session.state_path.empty())
    return Status::failure(tool_error("save Process Monitor session", {}, "A state path is required"));
  std::string problem;
  const std::filesystem::path state_file = state_file_for_writing(session.state_path, problem);
  if (state_file.empty())
    return Status::failure(tool_error("save Process Monitor session", path_to_utf8(session.state_path), problem));
  std::ofstream output(state_file, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(tool_error("save Process Monitor session", path_to_utf8(session.state_path), "Unable to create state file"));
  output << "schema=1\n"
         << "session_id=" << state_escape(session.session_id) << "\n"
         << "executable_path=" << state_escape(path_to_utf8(session.executable_path)) << "\n"
         << "output_pml=" << state_escape(path_to_utf8(session.output_pml)) << "\n"
         << "process_id=" << session.process_id << "\n"
         << "started_utc=" << state_escape(session.started_utc) << "\n"
         << "stopped_utc=" << state_escape(session.stopped_utc) << "\n"
         << "active=" << (session.active ? "1" : "0") << "\n";
  output.flush();
  if (!output)
    return Status::failure(tool_error("save Process Monitor session", path_to_utf8(session.state_path), "State write failed"));
  return Status::success();
}

Result<ProcmonSession> load_procmon_session(const std::filesystem::path& state_path) {
  std::ifstream input(state_file_for_reading(state_path), std::ios::binary);
  if (!input)
    return Result<ProcmonSession>::failure(
        tool_error("load Process Monitor session", path_to_utf8(state_path), "Unable to open state file"));
  ProcmonSession session;
  session.state_path = state_path;
  std::string line;
  int schema = 0;
  while (std::getline(input, line)) {
    const std::size_t split = state_separator(line);
    if (split == std::string::npos)
      continue;
    const std::string key = line.substr(0, split);
    const std::string value = state_unescape(std::string_view(line).substr(split + 1U));
    if (key == "schema") {
      try { schema = std::stoi(value); }
      catch (...) {
        return Result<ProcmonSession>::failure(
            tool_error("load Process Monitor session", path_to_utf8(state_path), "Persisted schema is invalid"));
      }
    } else if (key == "session_id") session.session_id = value;
    else if (key == "executable_path") session.executable_path = value;
    else if (key == "output_pml") session.output_pml = path_from_utf8(value);
    else if (key == "process_id") {
      try { session.process_id = static_cast<std::uint32_t>(std::stoul(value)); }
      catch (...) {
        return Result<ProcmonSession>::failure(
            tool_error("load Process Monitor session", path_to_utf8(state_path), "Persisted process id is invalid"));
      }
    } else if (key == "started_utc") session.started_utc = value;
    else if (key == "stopped_utc") session.stopped_utc = value;
    else if (key == "active") session.active = value == "1";
  }
  if (schema != 1 || session.session_id.empty() || session.executable_path.empty() ||
      session.output_pml.empty() || session.process_id == 0U) {
    return Result<ProcmonSession>::failure(
        tool_error("load Process Monitor session", path_to_utf8(state_path), "Process Monitor session state is incomplete"));
  }
  return Result<ProcmonSession>::success(std::move(session));
}

Result<ProcmonSession> procmon_start_owned(const ProcmonOptions& options,
                                           const std::filesystem::path& state_directory) {
#ifdef _WIN32
  if (options.output_pml.empty())
    return Result<ProcmonSession>::failure(
        tool_error("start owned Process Monitor", {}, "A PML output path is required"));
  if (state_directory.empty())
    return Result<ProcmonSession>::failure(
        tool_error("start owned Process Monitor", {}, "A session state directory is required"));
  const auto existing = running_procmon_processes();
  if (!existing.empty())
    return Result<ProcmonSession>::failure(tool_error(
        "start owned Process Monitor", "Procmon",
        "Process Monitor is already running. SAT will not replace or later terminate an unowned capture."));
  auto executable = resolve_external_tool("procmon", options.third_party_directory);
  if (!executable.ok())
    return Result<ProcmonSession>::failure(executable.error());

  // On 64-bit Windows Procmon.exe starts Procmon64.exe and exits, so the process SAT later proves it
  // owns must be the native one: start it directly when it sits beside Procmon.exe.
  std::filesystem::path program = executable.value();
  {
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    const wchar_t* native = system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64   ? L"Procmon64a.exe"
                            : system.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ? L"Procmon64.exe"
                                                                                           : nullptr;
    std::error_code ignored;
    if (native != nullptr && std::filesystem::is_regular_file(program.parent_path() / native, ignored))
      program = program.parent_path() / native;
  }

  std::vector<std::string> arguments{"/AcceptEula", "/Quiet", "/Minimized", "/BackingFile",
                                     path_to_utf8(options.output_pml)};
  if (!options.filter_file.empty()) {
    arguments.push_back("/LoadConfig");
    arguments.push_back(path_to_utf8(options.filter_file));
  }
  arguments.insert(arguments.end(), options.custom_arguments.begin(), options.custom_arguments.end());
  std::uint32_t process_id = 0;
  if (running_elevated()) {
    ProcessOptions process;
    process.executable = program;
    process.arguments = std::move(arguments);
    process.create_no_window = true;
    auto launched = launch_process_detached_owned(process);
    if (!launched.ok())
      return Result<ProcmonSession>::failure(launched.error());
    process_id = launched.value().process_id;
  } else {
    // Process Monitor needs administrator. Started without it, it starts a second, elevated copy of
    // itself and the first stays, so SAT starts the elevated one through the prompt.
    auto elevated = start_elevated(program, arguments, SW_SHOWMINNOACTIVE);
    if (!elevated.ok())
      return Result<ProcmonSession>::failure(elevated.error());
    process_id = static_cast<std::uint32_t>(GetProcessId(elevated.value()));
    CloseHandle(elevated.value());
  }

  ProcmonSession session;
  session.session_id = make_uuid_v4();
  session.executable_path = program;
  session.output_pml = options.output_pml;
  session.process_id = process_id;
  session.started_utc = utc_now_iso8601();
  session.active = true;
  // A short name: the state folder can already be deep in a case or tools tree.
  session.state_path = state_directory / ("pm-" + session.session_id.substr(0, 8) + ".state");

  auto saved = save_procmon_session(session);
  if (!saved.ok()) {
    // Only issue Procmon's global terminate when SAT can still prove it is the
    // sole Procmon process and that process is the one SAT just launched.
    const auto current = running_procmon_processes();
    if (current.size() == 1U && current.front() == session.process_id) {
      support_assist::CancellationToken no_cancel;
      static_cast<void>(procmon_stop(options.third_party_directory, no_cancel));
    }
    return Result<ProcmonSession>::failure(saved.error());
  }
  return Result<ProcmonSession>::success(std::move(session));
#else
  static_cast<void>(options);
  static_cast<void>(state_directory);
  return Result<ProcmonSession>::failure(
      tool_error("start owned Process Monitor", {}, "Process Monitor requires Windows"));
#endif
}

Result<ProcessResult> procmon_status_owned(const ProcmonSession& session) {
  if (!session.active)
    return Result<ProcessResult>::failure(
        tool_error("owned Process Monitor status", session.session_id, "The SAT Process Monitor session is not active"));
#ifdef _WIN32
  const auto current = running_procmon_processes();
  if (current.size() != 1U || current.front() != session.process_id) {
    return Result<ProcessResult>::failure(tool_error(
        "owned Process Monitor status", session.session_id,
        "SAT cannot prove that the running Process Monitor instance is the one this session started."));
  }
  // An elevated Procmon may not give its full image path to SAT without administrator; the process
  // list's name for the same id stands in then.
  const std::filesystem::path image = process_image_path(session.process_id);
  const bool image_matches =
      image.empty() ? !process_snapshot_name(session.process_id).empty() &&
                          process_snapshot_name(session.process_id) ==
                              ascii_lower(path_to_utf8(session.executable_path.filename()))
                    : normalized_windows_path(image) == normalized_windows_path(session.executable_path);
  if (!image_matches) {
    return Result<ProcessResult>::failure(tool_error(
        "owned Process Monitor status", session.session_id,
        "The running Process Monitor image does not match the executable recorded by the SAT session."));
  }
  ProcessResult result;
  result.launched = true;
  result.exit_code = 0;
  result.output = "SAT-owned Process Monitor session is active. PID=" + std::to_string(session.process_id) +
                  " PML=" + path_to_utf8(session.output_pml);
  return Result<ProcessResult>::success(std::move(result));
#else
  return Result<ProcessResult>::failure(
      tool_error("owned Process Monitor status", {}, "Process Monitor requires Windows"));
#endif
}

Result<ProcessResult> procmon_stop_owned(ProcmonSession& session,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress) {
  auto ownership = procmon_status_owned(session);
  if (!ownership.ok())
    return Result<ProcessResult>::failure(ownership.error());
#ifdef _WIN32
  auto stopped = procmon_terminate(session.executable_path, cancel, std::move(progress));
#else
  auto stopped = procmon_stop(session.executable_path.parent_path(), cancel, std::move(progress));
#endif
  if (!stopped.ok() || stopped.value().exit_code != 0)
    return stopped;
  session.active = false;
  session.stopped_utc = utc_now_iso8601();
  auto saved = save_procmon_session(session);
  if (!saved.ok())
    stopped.value().output += "\nSAT warning: Process Monitor stopped but session state could not be updated: " + saved.error().message;
  return stopped;
}

Status procmon_start(const ProcmonOptions& options) {
#ifdef _WIN32
  if (options.output_pml.empty()) {
    return Status::failure(
        tool_error("start Process Monitor", {}, "A PML output path is required"));
  }
  auto executable = resolve_external_tool("procmon", options.third_party_directory);
  if (!executable.ok())
    return Status::failure(executable.error());
  ProcessOptions process;
  process.executable = std::move(executable.value());
  process.arguments = {
      "/AcceptEula", "/Quiet", "/Minimized", "/BackingFile", path_to_utf8(options.output_pml)};
  if (!options.filter_file.empty()) {
    process.arguments.push_back("/LoadConfig");
    process.arguments.push_back(path_to_utf8(options.filter_file));
  }
  process.arguments.insert(
      process.arguments.end(), options.custom_arguments.begin(), options.custom_arguments.end());
  process.create_no_window = true;
  return launch_process_detached(process);
#else
  static_cast<void>(options);
  return Status::failure(
      tool_error("start Process Monitor", {}, "Process Monitor requires Windows"));
#endif
}

Result<ProcessResult> procmon_stop(const std::filesystem::path& third_party_directory,
                                   const CancellationToken& cancel,
                                   ProgressCallback progress) {
#ifdef _WIN32
  return run_tool("procmon",
                  {"/Terminate"},
                  third_party_directory,
                  cancel,
                  std::move(progress),
                  std::chrono::seconds(30));
#else
  static_cast<void>(third_party_directory);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<ProcessResult>::failure(
      tool_error("stop Process Monitor", {}, "Process Monitor requires Windows"));
#endif
}

Result<ProcessResult>
run_iperf(const IperfOptions& options, const CancellationToken& cancel, ProgressCallback progress) {
  std::vector<std::string> arguments;
  if (options.server) {
    arguments = {"-s", "-1", "-p", std::to_string(options.port)};
  } else {
    if (options.host.empty()) {
      return Result<ProcessResult>::failure(
          tool_error("run iPerf", {}, "A server address is required in client mode"));
    }
    arguments = {"-c", options.host, "-p", std::to_string(options.port)};
    if (!options.payload.empty()) {
      arguments.push_back("-n");
      arguments.push_back(options.payload);
    }
  }
  arguments.insert(
      arguments.end(), options.custom_arguments.begin(), options.custom_arguments.end());
  return run_tool("iperf3",
                  std::move(arguments),
                  options.third_party_directory,
                  cancel,
                  std::move(progress),
                  options.timeout);
}


namespace {

#ifdef _WIN32
bool valid_guid_text(std::string_view value) {
  if (value.size() != 36U)
    return false;
  constexpr std::size_t hyphens[] = {8U, 13U, 18U, 23U};
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (std::find(std::begin(hyphens), std::end(hyphens), index) != std::end(hyphens)) {
      if (value[index] != '-') return false;
      continue;
    }
    if (std::isxdigit(static_cast<unsigned char>(value[index])) == 0)
      return false;
  }
  return true;
}

std::vector<std::string> split_tab_record(std::string_view line) {
  std::vector<std::string> fields;
  std::size_t start = 0;
  while (start <= line.size()) {
    const std::size_t separator = line.find('\t', start);
    if (separator == std::string_view::npos) {
      fields.emplace_back(line.substr(start));
      break;
    }
    fields.emplace_back(line.substr(start, separator - start));
    start = separator + 1U;
  }
  return fields;
}

std::vector<std::filesystem::path> vbr_powershell_candidates() {
  std::vector<std::filesystem::path> candidates;
  // Veeam PowerShell v13 requires PowerShell 7. Prefer its standard Program Files
  // installation and fall back only to the trusted Windows system PowerShell.
  // Do not resolve PowerShell hosts through PATH.
  wchar_t program_files[32768]{};
  const DWORD length = GetEnvironmentVariableW(L"ProgramFiles", program_files,
                                                static_cast<DWORD>(std::size(program_files)));
  if (length > 0 && length < std::size(program_files)) {
    const auto ps7 = std::filesystem::path(program_files) / L"PowerShell" / L"7" / L"pwsh.exe";
    if (std::filesystem::exists(ps7)) candidates.push_back(ps7);
  }
  const auto legacy = system_executable(L"WindowsPowerShell\\v1.0\\powershell.exe");
  if (!legacy.empty() && std::filesystem::is_regular_file(legacy)) candidates.push_back(legacy);
  return candidates;
}

Result<std::filesystem::path> select_vbr_powershell_host(const CancellationToken& cancel) {
  std::string failures;
  for (const auto& candidate : vbr_powershell_candidates()) {
    if (cancel.is_cancelled())
      return Result<std::filesystem::path>::failure(
          tool_error("select Veeam PowerShell host", path_to_utf8(candidate), "Operation cancelled"));
    ProcessOptions probe;
    probe.executable = candidate;
    probe.arguments = {"-NoProfile", "-NonInteractive", "-Command",
                       "$ErrorActionPreference='Stop'; Import-Module Veeam.Backup.PowerShell -ErrorAction Stop; Connect-VBRServer -Server 'localhost' -ErrorAction Stop | Out-Null; "
                       "'SATVBRPS\t' + $PSVersionTable.PSVersion.ToString()"};
    probe.timeout = std::chrono::seconds(20);
    probe.merge_standard_error = false;
    probe.maximum_output_bytes = 64U * 1024U;
    probe.maximum_standard_error_bytes = 256U * 1024U;
    auto checked = run_process_capture(probe, cancel, {});
    if (checked.ok() && checked.value().exit_code == 0 &&
        checked.value().output.find("SATVBRPS\t") != std::string::npos)
      return Result<std::filesystem::path>::success(candidate);
    if (!failures.empty()) failures += " | ";
    failures += path_to_utf8(candidate) + ": ";
    if (!checked.ok()) failures += checked.error().message;
    else if (!checked.value().standard_error.empty()) failures += checked.value().standard_error;
    else failures += checked.value().output;
    if (failures.size() > 4096U) failures.resize(4096U);
  }
  return Result<std::filesystem::path>::failure(tool_error(
      "select Veeam PowerShell host", "Veeam.Backup.PowerShell",
      failures.empty() ? "No compatible PowerShell host with the Veeam Backup PowerShell module was found"
                       : "No compatible PowerShell host could import the Veeam module. " + failures));
}

Result<ProcessResult> run_vbr_powershell(std::string script,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress,
                                         std::chrono::milliseconds timeout = std::chrono::seconds(45)) {
  auto host = select_vbr_powershell_host(cancel);
  if (!host.ok()) return Result<ProcessResult>::failure(host.error());
  ProcessOptions process;
  process.executable = host.value();
  process.arguments = {"-NoProfile", "-NonInteractive", "-Command", std::move(script)};
  process.timeout = timeout;
  process.merge_standard_error = false;
  process.maximum_output_bytes = 4U * 1024U * 1024U;
  process.maximum_standard_error_bytes = 1U * 1024U * 1024U;
  return run_process_capture(process, cancel, std::move(progress));
}
#endif

} // namespace

Result<std::vector<VbrRunningJob>> list_vbr_running_jobs(
    const CancellationToken& cancel,
    ProgressCallback progress) {
#ifdef _WIN32
  if (progress)
    progress(ProgressEvent{"vbr-running-jobs", {}, 0, 0, 0.0, 0.0});

  // Keep the script self-contained and return only bounded tab-delimited data.
  // No credentials or case data enter this PowerShell process.
  const std::string script = R"PS(
$ErrorActionPreference = 'Stop'
Import-Module Veeam.Backup.PowerShell -ErrorAction Stop
Connect-VBRServer -Server 'localhost' -ErrorAction Stop | Out-Null
function Clean([object]$v) {
  if ($null -eq $v) { return '' }
  return ([string]$v).Replace("`t",' ').Replace("`r",' ').Replace("`n",' ').Trim()
}
function IdText([object]$v) {
  if ($null -eq $v) { return '' }
  try { return ([Guid]$v).ToString() } catch { return (Clean $v) }
}
function PutJob([hashtable]$map,[object]$job,[string]$kind,[bool]$stoppable) {
  if ($null -eq $job) { return }
  $id = IdText $job.Id
  if ([string]::IsNullOrWhiteSpace($id)) { return }
  $map[$id] = [pscustomobject]@{ Kind=$kind; Name=(Clean $job.Name); Stoppable=$stoppable }
}
function IsActive([object]$session) {
  if ($null -eq $session) { return $false }
  $state = Clean $session.State
  return -not [string]::IsNullOrWhiteSpace($state) -and $state -notin @('Stopped','Idle')
}
function Emit([hashtable]$jobs,[hashtable]$seen,[object]$session,[string]$fallbackKind,[string]$fallbackName,[bool]$fallbackStop) {
  if (-not (IsActive $session)) { return }
  $sid = IdText $session.Id
  if ([string]::IsNullOrWhiteSpace($sid)) { return }
  if ($seen.ContainsKey($sid)) { return }
  $seen[$sid] = $true
  $jid = IdText $session.JobId
  $meta = $null
  if (-not [string]::IsNullOrWhiteSpace($jid) -and $jobs.ContainsKey($jid)) { $meta = $jobs[$jid] }
  $kind = if ($null -ne $meta) { $meta.Kind } else { $fallbackKind }
  $name = if ($null -ne $meta) { $meta.Name } else { $fallbackName }
  $stoppable = if ($null -ne $meta) { $meta.Stoppable } else { $fallbackStop }
  if ([string]::IsNullOrWhiteSpace($name)) {
    if ($session.PSObject.Properties['Name']) { $name = Clean $session.Name }
    if ([string]::IsNullOrWhiteSpace($name)) { $name = '(unnamed session)' }
  }
  $started = ''
  if ($session.PSObject.Properties['CreationTime'] -and $null -ne $session.CreationTime) {
    try { $started = ([DateTime]$session.CreationTime).ToString('yyyy-MM-dd HH:mm:ss zzz') } catch { $started = Clean $session.CreationTime }
  }
  $progress = ''
  if ($session.PSObject.Properties['Progress'] -and $null -ne $session.Progress) { $progress = Clean $session.Progress }
  $result = if ($session.PSObject.Properties['Result']) { Clean $session.Result } else { '' }
  $initiator = ''
  foreach ($prop in @('Initiator','UserName','InitiatedBy')) {
    if ($session.PSObject.Properties[$prop]) { $initiator = Clean $session.$prop; if ($initiator) { break } }
  }
  $detailParts = New-Object System.Collections.Generic.List[string]
  if ($session.PSObject.Properties['RunManually']) { $detailParts.Add(('RunManually=' + (Clean $session.RunManually))) }
  if ($session.PSObject.Properties['Type']) { $detailParts.Add(('SessionType=' + (Clean $session.Type))) }
  if ($session.PSObject.Properties['JobType']) { $detailParts.Add(('JobType=' + (Clean $session.JobType))) }
  $details = $detailParts -join '; '
  @('SATJOB',$kind,(Clean $name),$jid,$sid,(Clean $session.State),$result,$started,$progress,$initiator,$details,($(if($stoppable){'1'}else{'0'}))) -join "`t"
}

$jobs = @{}
$seen = @{}
if (Get-Command Get-VBRJob -ErrorAction SilentlyContinue) {
  Get-VBRJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'backup-replication' $true }
}
if (Get-Command Get-VBRBackupCopyJob -ErrorAction SilentlyContinue) {
  Get-VBRBackupCopyJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'backup-copy' $true }
}
if (Get-Command Get-VBRComputerBackupJob -ErrorAction SilentlyContinue) {
  Get-VBRComputerBackupJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'agent' $true }
}
if (Get-Command Get-VBRTapeJob -ErrorAction SilentlyContinue) {
  Get-VBRTapeJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'tape' $true }
}
if (Get-Command Get-VBRSureBackupJob -ErrorAction SilentlyContinue) {
  Get-VBRSureBackupJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'surebackup' $true }
}
if (Get-Command Get-VBRApplicationBackupJob -ErrorAction SilentlyContinue) {
  Get-VBRApplicationBackupJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'application' $true }
}
if (Get-Command Get-VBRUnstructuredBackupJob -ErrorAction SilentlyContinue) {
  Get-VBRUnstructuredBackupJob -ErrorAction SilentlyContinue | ForEach-Object { PutJob $jobs $_ 'unstructured' $false }
}

# Get-VBRBackupSession documents backup, replication, backup-copy, file and cloud
# job sessions. State-filtered queries avoid loading the entire historical DB.
if (Get-Command Get-VBRBackupSession -ErrorAction SilentlyContinue) {
  foreach ($state in @('Starting','Stopping','Working','Pausing','Resuming','WaitingTape','Postprocessing','WaitingRepository','Pending','WaitingSlot','ActionRequired')) {
    try { Get-VBRBackupSession -State $state -ErrorAction Stop | ForEach-Object { Emit $jobs $seen $_ 'backup-replication' '' $true } } catch { }
  }
}
# Dedicated families are queried as well because they are not guaranteed to be
# represented by the generic backup-session command on every supported VBR build.
if (Get-Command Get-VBRComputerBackupJobSession -ErrorAction SilentlyContinue) {
  try { Get-VBRComputerBackupJobSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'agent' '' $true } } catch { }
}
if (Get-Command Get-VBRTapeBackupSession -ErrorAction SilentlyContinue) {
  try { Get-VBRTapeBackupSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'tape' '' $true } } catch { }
}
if (Get-Command Get-VBRSureBackupSession -ErrorAction SilentlyContinue) {
  try { Get-VBRSureBackupSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'surebackup' '' $true } } catch { }
}
if (Get-Command Get-VBRApplicationBackupJobSession -ErrorAction SilentlyContinue) {
  try { Get-VBRApplicationBackupJobSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'application' '' $true } } catch { }
}
# Some active VBR work has a readable documented session surface but no matching
# documented stop cmdlet for the job object. Surface it as read-only instead of
# hiding it or guessing an unsupported termination path.
if (Get-Command Get-VBRUnstructuredBackupSession -ErrorAction SilentlyContinue) {
  try { Get-VBRUnstructuredBackupSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'unstructured' '' $false } } catch { }
}
if (Get-Command Get-VBRPluginBackupSession -ErrorAction SilentlyContinue) {
  try { Get-VBRPluginBackupSession -ErrorAction Stop | Where-Object { IsActive $_ } | ForEach-Object { Emit $jobs $seen $_ 'plugin-session' '' $false } } catch { }
}
)PS";

  auto process = run_vbr_powershell(script, cancel, std::move(progress), std::chrono::seconds(60));
  if (!process.ok())
    return Result<std::vector<VbrRunningJob>>::failure(process.error());
  if (process.value().exit_code != 0) {
    std::string detail = process.value().standard_error.empty() ? process.value().output
                                                                : process.value().standard_error;
    return Result<std::vector<VbrRunningJob>>::failure(
        tool_error("list running VBR jobs", "Veeam.Backup.PowerShell",
                   detail.empty() ? "Veeam PowerShell returned a non-zero exit code" : detail));
  }

  std::vector<VbrRunningJob> jobs;
  std::istringstream lines(process.value().output);
  std::string line;
  while (std::getline(lines, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.rfind("SATJOB\t", 0) != 0) continue;
    auto fields = split_tab_record(line);
    if (fields.size() < 12U) continue;
    VbrRunningJob job;
    job.kind = fields[1];
    job.name = fields[2];
    job.job_id = fields[3];
    job.session_id = fields[4];
    job.state = fields[5];
    job.result = fields[6];
    job.started = fields[7];
    job.progress = fields[8];
    job.initiated_by = fields[9];
    job.details = fields[10];
    job.stoppable = fields[11] == "1";
    jobs.push_back(std::move(job));
  }
  std::stable_sort(jobs.begin(), jobs.end(), [](const VbrRunningJob& left, const VbrRunningJob& right) {
    if (left.started != right.started) return left.started > right.started;
    return ascii_lower(left.name) < ascii_lower(right.name);
  });
  return Result<std::vector<VbrRunningJob>>::success(std::move(jobs));
#else
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<std::vector<VbrRunningJob>>::failure(
      tool_error("list running VBR jobs", {}, "Running VBR Jobs requires Windows and the local Veeam PowerShell module"));
#endif
}

Result<VbrStopJobResult> stop_vbr_running_job(
    const VbrStopJobRequest& request,
    const CancellationToken& cancel,
    ProgressCallback progress) {
#ifdef _WIN32
  static const std::vector<std::string> allowed_kinds{
      "backup-replication", "backup-copy", "agent", "tape", "surebackup", "application"};
  if (std::find(allowed_kinds.begin(), allowed_kinds.end(), request.kind) == allowed_kinds.end())
    return Result<VbrStopJobResult>::failure(tool_error("stop VBR job", request.kind, "Unsupported running-job family"));
  if (!valid_guid_text(request.job_id))
    return Result<VbrStopJobResult>::failure(tool_error("stop VBR job", request.job_id, "Job ID is not a valid GUID"));
  if (!request.session_id.empty() && !valid_guid_text(request.session_id))
    return Result<VbrStopJobResult>::failure(tool_error("stop VBR job", request.session_id, "Session ID is not a valid GUID"));

  const std::string job_id = request.job_id;
  const std::string session_id = request.session_id;
  const std::string kind = request.kind;
  std::ostringstream ps;
  ps << "$ErrorActionPreference='Stop'; Import-Module Veeam.Backup.PowerShell -ErrorAction Stop; "
     << "$jid=[Guid]::Parse('" << job_id << "'); ";
  if (kind == "backup-replication") {
    // Get-VBRJob has no -Id parameter in the current v13 reference. Resolve
    // the returned object by its GUID without interpolating the human job name.
    ps << "$job=Get-VBRJob -ErrorAction Stop | Where-Object {$_.Id -eq $jid} | Select-Object -First 1; "
       << "if($null -eq $job){throw 'Job no longer exists'}; "
       << "Stop-VBRJob -Job $job -Gracefully -RunAsync -Confirm:$false -ErrorAction Stop;";
  } else if (kind == "backup-copy") {
    ps << "$job=Get-VBRBackupCopyJob -Id $jid -ErrorAction Stop; if($null -eq $job){throw 'Backup copy job no longer exists'}; "
       << "Stop-VBRBackupCopyJob -Job $job -RunAsync -Confirm:$false -ErrorAction Stop;";
  } else if (kind == "agent") {
    ps << "$job=Get-VBRComputerBackupJob -Id $jid -ErrorAction Stop; if($null -eq $job){throw 'Agent job no longer exists'}; "
       << "Stop-VBRComputerBackupJob -Job $job -RunAsync -Confirm:$false -ErrorAction Stop;";
  } else if (kind == "surebackup") {
    ps << "$job=Get-VBRSureBackupJob -Id $jid -ErrorAction Stop; if($null -eq $job){throw 'SureBackup job no longer exists'}; "
       << "Stop-VBRSureBackupJob -Job $job -RunAsync -Confirm:$false -ErrorAction Stop;";
  } else if (kind == "application") {
    ps << "$job=Get-VBRApplicationBackupJob -Id $jid -ErrorAction Stop; if($null -eq $job){throw 'Application backup policy no longer exists'}; "
       << "$cmd=Get-Command Stop-VBRApplicationBackupJob -ErrorAction Stop; "
       << "$params=@{Job=$job; ErrorAction='Stop'}; if($cmd.Parameters.ContainsKey('RunAsync')){$params.RunAsync=$true}; "
       << "if($cmd.Parameters.ContainsKey('Confirm')){$params.Confirm=$false}; Stop-VBRApplicationBackupJob @params;";
  } else { // tape: stop the exact active session, not a similarly named job.
    if (session_id.empty())
      return Result<VbrStopJobResult>::failure(tool_error("stop VBR tape session", request.job_id, "Tape stop requires the active session ID"));
    // Get-VBRTapeJob also has no -Id parameter. Veeam's documented tape-stop
    // flow is job -> Get-VBRSession -> Stop-VBRSession, so resolve both objects
    // by the GUIDs SAT already captured from the live inventory.
    ps << "$sid=[Guid]::Parse('" << session_id << "'); "
       << "$job=Get-VBRTapeJob -ErrorAction Stop | Where-Object {$_.Id -eq $jid} | Select-Object -First 1; "
       << "if($null -eq $job){throw 'Tape job no longer exists'}; "
       << "$session=Get-VBRSession -Job $job -ErrorAction Stop | Where-Object {$_.Id -eq $sid} | Select-Object -First 1; "
       << "if($null -eq $session){throw 'Tape session no longer exists'}; "
       << "Stop-VBRSession -Session $session -ErrorAction Stop;";
  }
  ps << "'SATSTOP\tSENT'";

  if (progress)
    progress(ProgressEvent{"vbr-stop-request", {}, 0, 0, 0.0, 0.0});
  auto process = run_vbr_powershell(ps.str(), cancel, std::move(progress), std::chrono::seconds(30));
  if (!process.ok())
    return Result<VbrStopJobResult>::failure(process.error());
  if (process.value().exit_code != 0 || process.value().output.find("SATSTOP\tSENT") == std::string::npos) {
    std::string detail = process.value().standard_error.empty() ? process.value().output
                                                                : process.value().standard_error;
    return Result<VbrStopJobResult>::failure(
        tool_error("send VBR stop request", request.job_id,
                   detail.empty() ? "The Veeam stop cmdlet did not confirm submission" : detail));
  }
  VbrStopJobResult result;
  result.request_sent = true;
  result.kind = request.kind;
  result.job_id = request.job_id;
  result.session_id = request.session_id;
  result.detail = "Stop request accepted by Veeam PowerShell; refresh running jobs to confirm the session leaves the active list.";
  return Result<VbrStopJobResult>::success(std::move(result));
#else
  static_cast<void>(request);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<VbrStopJobResult>::failure(
      tool_error("stop VBR job", {}, "Running VBR Jobs requires Windows and the local Veeam PowerShell module"));
#endif
}

Result<SmbConnectivityResult> test_smb_connectivity(
    const SmbConnectivityOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress) {
#ifdef _WIN32
  SmbConnectivityResult result;
  result.target = options.target;
  const auto valid_target = [](std::string_view value) {
    if (value.empty() || value.size() > 255U) return false;
    for (const char ch : value) {
      const unsigned char u = static_cast<unsigned char>(ch);
      if (std::isalnum(u) != 0 || ch == '.' || ch == '-' || ch == '_') continue;
      return false;
    }
    return true;
  };
  if (!valid_target(options.target))
    return Result<SmbConnectivityResult>::failure(
        tool_error("validate SMB target", options.target,
                   "Use a Windows hostname, FQDN, or IPv4 address; UNC prefixes and paths belong in the path field"));
  if (options.relative_path.empty() || options.relative_path.size() > 1024U ||
      options.relative_path.rfind("C$", 0) != 0 || options.relative_path.find("..") != std::string::npos)
    return Result<SmbConnectivityResult>::failure(
        tool_error("validate SMB test path", options.relative_path,
                   "The bounded SMB test path must remain under C$ and cannot contain parent traversal"));

  if (progress) progress(ProgressEvent{"SMB TCP/445", options.target, 0, 0, 0.0, 0.0});
  TcpPortTestOptions tcp;
  tcp.host = options.target;
  tcp.port = 445;
  tcp.timeout = options.timeout;
  tcp.detect_sat_listener = false;
  tcp.sat_payload_bytes = 0;
  auto tcp_result = test_tcp_port(tcp, cancel, {});
  if (!tcp_result.ok())
    return Result<SmbConnectivityResult>::failure(tcp_result.error());
  result.tcp_445_connected = tcp_result.value().connected;
  result.resolved_address = tcp_result.value().connected_address;
  if (!result.tcp_445_connected) {
    result.failure_stage = "TCP/445";
    result.detail = "TCP port 445 could not be reached";
    if (!tcp_result.value().attempts.empty()) {
      const auto& attempt = tcp_result.value().attempts.back();
      if (!attempt.message.empty()) {
        result.detail += ": " + attempt.message;
      }
      if (attempt.native_code != 0) {
        result.detail += " (native=" + std::to_string(attempt.native_code) + ")";
      }
    }
    return Result<SmbConnectivityResult>::success(std::move(result));
  }
  if (cancel.is_cancelled())
    return Result<SmbConnectivityResult>::failure(tool_error("SMB connectivity", options.target, "Operation cancelled"));

  const std::wstring target = wide_from_utf8(options.target);
  const std::wstring relative = wide_from_utf8(options.relative_path);
  const std::size_t slash = relative.find(L'\\');
  const std::wstring share_component = slash == std::wstring::npos ? relative : relative.substr(0, slash);
  const std::wstring share = L"\\\\" + target + L"\\" + share_component;
  const std::wstring full_path = L"\\\\" + target + L"\\" + relative;
  result.unc_share = utf8_from_wide(share);
  result.test_path = utf8_from_wide(full_path);

  NETRESOURCEW resource{};
  resource.dwType = RESOURCETYPE_DISK;
  resource.lpRemoteName = const_cast<LPWSTR>(share.c_str());
  const DWORD flags = CONNECT_TEMPORARY |
      (options.prompt_for_alternate_credentials ? (CONNECT_INTERACTIVE | CONNECT_PROMPT) : 0U);
  if (progress) progress(ProgressEvent{"SMB session", result.unc_share, 0, 0, 0.0, 0.0});
  const DWORD connected = WNetAddConnection2W(&resource, nullptr, nullptr, flags);
  bool use_existing_connection = false;
  if (connected == NO_ERROR) {
    result.smb_session_available = true;
    result.temporary_session_created = true;
  } else if (!options.prompt_for_alternate_credentials &&
             (connected == ERROR_ALREADY_ASSIGNED || connected == ERROR_DEVICE_ALREADY_REMEMBERED)) {
    result.smb_session_available = true;
    use_existing_connection = true;
  } else {
    result.failure_stage = "SMB authentication/session";
    result.native_code = static_cast<std::int64_t>(connected);
    if (connected == ERROR_SESSION_CREDENTIAL_CONFLICT)
      result.detail = "Windows already has a connection to this server using different credentials. SAT did not disconnect that existing session.";
    else if (connected == ERROR_CANCELLED)
      result.detail = "The Windows credential/network prompt was cancelled.";
    else {
      LPWSTR message = nullptr;
      const DWORD chars = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                             FORMAT_MESSAGE_IGNORE_INSERTS,
                                         nullptr, connected, 0,
                                         reinterpret_cast<LPWSTR>(&message), 0, nullptr);
      if (chars != 0 && message != nullptr) {
        result.detail = utf8_from_wide(message);
        LocalFree(message);
      } else {
        result.detail = "Windows could not establish the SMB session";
      }
    }
    return Result<SmbConnectivityResult>::success(std::move(result));
  }

  struct DisconnectGuard {
    std::wstring share;
    SmbConnectivityResult* result = nullptr;
    bool owned = false;

    void disconnect_now() {
      if (!owned || share.empty() || result == nullptr) return;
      owned = false;
      const DWORD code = WNetCancelConnection2W(share.c_str(), 0, FALSE);
      result->temporary_session_disconnected = code == NO_ERROR || code == ERROR_NOT_CONNECTED;
      if (!result->temporary_session_disconnected && result->detail.empty()) {
        result->detail = "SMB test completed, but Windows reported that the SAT-created temporary session could not be disconnected cleanly (native=" +
                         std::to_string(code) + ")";
      }
    }

    ~DisconnectGuard() { disconnect_now(); }
  } disconnect{share, &result, result.temporary_session_created};

  std::error_code path_error;
  result.path_accessible = std::filesystem::is_directory(std::filesystem::path(full_path), path_error);
  if (!result.path_accessible) {
    result.failure_stage = "SMB path access";
    result.native_code = static_cast<std::int64_t>(path_error.value());
    result.detail = path_error ? path_error.message() : "Target directory does not exist or is not accessible";
    disconnect.disconnect_now();
    return Result<SmbConnectivityResult>::success(std::move(result));
  }

  // Query the negotiated SMB connection after the Windows redirector has a live
  // handle. No credential text is passed to PowerShell.
  if (progress) progress(ProgressEvent{"SMB dialect", options.target, 0, 0, 0.0, 0.0});
  std::ostringstream dialect_script;
  dialect_script << "$ErrorActionPreference='SilentlyContinue'; "
                 << "$c=Get-SmbConnection -ServerName '" << options.target
                 << "' | Where-Object {$_.ShareName -eq '" << utf8_from_wide(share_component)
                 << "'} | Select-Object -First 1; if($null -ne $c){ "
                 << "'SATSMB' + \"`t\" + [string]$c.Dialect + \"`t\" + [string]$c.UserName + \"`t\" + [string]$c.Signed + \"`t\" + [string]$c.Encrypted }";
  ProcessOptions ps;
  ps.executable = system_executable(L"WindowsPowerShell\\v1.0\\powershell.exe");
  ps.arguments = {"-NoProfile", "-NonInteractive", "-Command", dialect_script.str()};
  ps.timeout = std::chrono::seconds(10);
  ps.merge_standard_error = false;
  ps.maximum_output_bytes = 64U * 1024U;
  // run_process_capture returns Result<ProcessResult>; both ternary branches must agree.
  auto dialect = ps.executable.empty()
                     ? Result<ProcessResult>::failure(
                           tool_error("query SMB dialect", options.target,
                                      "Trusted Windows PowerShell executable was not found under the Windows system directory"))
                     : run_process_capture(ps, cancel, {});
  if (dialect.ok()) {
    std::istringstream lines(dialect.value().output);
    std::string line;
    while (std::getline(lines, line)) {
      if (!line.empty() && line.back() == '\r') line.pop_back();
      if (line.rfind("SATSMB\t", 0) != 0) continue;
      auto fields = split_tab_record(line);
      if (fields.size() >= 5U) {
        result.dialect = fields[1];
        result.username = fields[2];
        result.signing = fields[3];
        result.encryption = fields[4];
      }
      break;
    }
  }

  if (cancel.is_cancelled())
    return Result<SmbConnectivityResult>::failure(tool_error("SMB connectivity", options.target, "Operation cancelled"));
  if (progress) progress(ProgressEvent{"SMB write/read/delete", result.test_path, 0, 0, 0.0, 0.0});
  const std::string payload = "SAT SMB independent validation\r\nTest-ID: " + make_uuid_v4() +
                              "\r\nCreated-UTC: " + utc_now_iso8601() + "\r\n";
  const std::string filename = "SAT-SMB-" + make_uuid_v4() + ".tmp";
  const std::filesystem::path payload_path = std::filesystem::path(full_path) / wide_from_utf8(filename);
  result.payload_name = filename;
  {
    std::ofstream output(payload_path, std::ios::binary | std::ios::trunc);
    if (!output) {
      result.failure_stage = "SMB payload create";
      result.native_code = static_cast<std::int64_t>(GetLastError());
      result.detail = "The target directory is readable but SAT could not create the bounded test payload";
      disconnect.disconnect_now();
      return Result<SmbConnectivityResult>::success(std::move(result));
    }
    output.write(payload.data(), static_cast<std::streamsize>(payload.size()));
    output.flush();
    result.payload_created = output.good();
  }
  if (!result.payload_created) {
    result.failure_stage = "SMB payload write";
    result.detail = "Windows opened the payload but the write did not complete";
  } else {
    std::ifstream input(payload_path, std::ios::binary);
    std::ostringstream contents;
    contents << input.rdbuf();
    result.payload_verified = input.good() || input.eof();
    result.payload_verified = result.payload_verified && contents.str() == payload;
    if (!result.payload_verified) {
      result.failure_stage = "SMB payload verification";
      result.detail = "The test file was created but its read-back content did not match";
    }
  }
  std::error_code remove_error;
  result.payload_deleted = std::filesystem::remove(payload_path, remove_error);
  if (!result.payload_deleted) {
    if (result.failure_stage.empty()) result.failure_stage = "SMB payload cleanup";
    if (result.detail.empty()) result.detail = remove_error ? remove_error.message() : "The test payload could not be removed";
  }
  if (result.payload_verified && result.payload_deleted && result.failure_stage.empty()) {
    result.detail = "TCP/445, Windows SMB session, target-path access, write/read verification, and payload cleanup succeeded";
  }
  static_cast<void>(use_existing_connection);
  disconnect.disconnect_now();
  return Result<SmbConnectivityResult>::success(std::move(result));
#else
  static_cast<void>(options);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<SmbConnectivityResult>::failure(
      tool_error("SMB connectivity", {}, "SMB connectivity validation requires Windows"));
#endif
}

} // namespace support_assist
