#include "support_assist/collected_evidence.hpp"

#include "support_assist/archive_browser.hpp"
#include "support_assist/secure_temp.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <map>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <sstream>
#include <system_error>

namespace support_assist {
namespace {

Error evidence_error(std::string operation, std::string message) {
  Error error;
  error.component = "CollectedEvidence";
  error.operation = std::move(operation);
  error.message = std::move(message);
  return error;
}

std::string read_file(const std::filesystem::path& path, std::size_t maximum_bytes) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  if (text.size() > maximum_bytes)
    text.resize(maximum_bytes);
  return text;
}

// `reg export` writes UTF-16LE. Appending such a file verbatim leaves NUL bytes in the middle of a
// document that is otherwise UTF-8, which makes every strict reader fail on the whole file rather
// than the one section. universal_collection.cpp transcodes for the same reason.
//
// Decoded by hand rather than through utf8_from_wide(), which is Windows-only and would anyway be
// wrong on Linux, where wchar_t is 32-bit and a UTF-16 code unit is not a wchar_t. A collection
// gathered on Windows is very often read on a Linux workstation, so this path has to be portable.
void append_utf8(std::string& output, std::uint32_t code_point) {
  if (code_point < 0x80U) {
    output.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800U) {
    output.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else if (code_point < 0x10000U) {
    output.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else {
    output.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
    output.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    output.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  }
}

std::string transcode_if_utf16(std::string text) {
  if (text.size() < 2U)
    return text;
  const auto first = static_cast<unsigned char>(text[0]);
  const auto second = static_cast<unsigned char>(text[1]);
  if (first != 0xFF || second != 0xFE)
    return text;

  const auto unit_at = [&text](std::size_t index) {
    return static_cast<std::uint32_t>(static_cast<unsigned char>(text[index])) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(text[index + 1U])) << 8U);
  };

  std::string output;
  output.reserve(text.size() / 2U);
  for (std::size_t index = 2U; index + 1U < text.size(); index += 2U) {
    std::uint32_t unit = unit_at(index);
    if (unit >= 0xD800U && unit <= 0xDBFFU && index + 3U < text.size()) {
      const std::uint32_t low = unit_at(index + 2U);
      if (low >= 0xDC00U && low <= 0xDFFFU) {
        unit = 0x10000U + ((unit - 0xD800U) << 10U) + (low - 0xDC00U);
        index += 2U;
      }
    }
    // An unpaired surrogate is not a character. Substituting keeps the readable remainder rather
    // than emitting bytes that make the whole document invalid UTF-8.
    if (unit >= 0xD800U && unit <= 0xDFFFU)
      unit = 0xFFFDU;
    append_utf8(output, unit);
  }
  return output;
}

std::string strip_utf8_bom(std::string text) {
  if (text.size() >= 3U && static_cast<unsigned char>(text[0]) == 0xEF &&
      static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF) {
    text.erase(0, 3U);
  }
  return text;
}

std::vector<std::string> split_lines(std::string_view text) {
  std::vector<std::string> lines;
  std::string current;
  for (const char character : text) {
    if (character == '\n') {
      if (!current.empty() && current.back() == '\r')
        current.pop_back();
      lines.push_back(current);
      current.clear();
      continue;
    }
    current.push_back(character);
  }
  if (!current.empty()) {
    if (current.back() == '\r')
      current.pop_back();
    lines.push_back(current);
  }
  return lines;
}

bool parse_bool_word(std::string_view value) {
  return ascii_lower(value) == "true";
}

// systeminfo.exe writes `Key:<padding>Value`, and both the key and the value may contain a colon
// ("Virtual Memory: Max Size:      66,892 MB", "System Boot Time: 8/12/2026, 8:18:05 PM"). The
// separator is the last colon followed by padding, which distinguishes it from a colon inside a
// clock time, where the next character is a digit.
std::optional<std::pair<std::string, std::string>> split_padded_field(std::string_view line) {
  std::size_t separator = std::string_view::npos;
  for (std::size_t index = 0; index + 2U < line.size(); ++index) {
    if (line[index] == ':' && line[index + 1U] == ' ' && line[index + 2U] == ' ')
      separator = index;
  }
  if (separator == std::string_view::npos) {
    const std::size_t plain = line.find(':');
    if (plain == std::string_view::npos)
      return std::nullopt;
    separator = plain;
  }
  std::string key = trim(line.substr(0, separator));
  std::string value = trim(line.substr(separator + 1U));
  if (key.empty())
    return std::nullopt;
  return std::make_pair(std::move(key), std::move(value));
}

// "65,292 MB" -> bytes. Also accepts a bare byte count.
std::optional<std::uint64_t> parse_quantity(std::string_view text, std::uint64_t default_multiplier) {
  std::string digits;
  std::string unit;
  for (const char character : text) {
    if (std::isdigit(static_cast<unsigned char>(character)) != 0)
      digits.push_back(character);
    else if (character == ',' || character == ' ')
      continue;
    else if (std::isalpha(static_cast<unsigned char>(character)) != 0)
      unit.push_back(character);
  }
  if (digits.empty())
    return std::nullopt;
  std::uint64_t value = 0;
  for (const char digit : digits) {
    const auto next = static_cast<std::uint64_t>(digit - '0');
    if (value > (UINT64_MAX - next) / 10U)
      return std::nullopt;
    value = value * 10U + next;
  }
  const std::string folded = ascii_lower(unit);
  std::uint64_t multiplier = default_multiplier;
  if (folded == "kb" || folded == "k")
    multiplier = 1024U;
  else if (folded == "mb" || folded == "m")
    multiplier = 1024U * 1024U;
  else if (folded == "gb" || folded == "g")
    multiplier = 1024U * 1024U * 1024U;
  else if (folded == "b" || folded == "bytes")
    multiplier = 1U;
  if (multiplier != 0U && value > UINT64_MAX / multiplier)
    return std::nullopt;
  return value * multiplier;
}

// "1 Gbps", "3 Mbps", "0 bps" -> bits per second.
std::uint64_t parse_link_speed(std::string_view text) {
  std::string digits;
  std::string unit;
  bool seen_digit = false;
  for (const char character : text) {
    if (std::isdigit(static_cast<unsigned char>(character)) != 0) {
      digits.push_back(character);
      seen_digit = true;
    } else if (character == '.' && seen_digit) {
      continue;
    } else if (std::isalpha(static_cast<unsigned char>(character)) != 0) {
      unit.push_back(character);
    }
  }
  if (digits.empty())
    return 0U;
  std::uint64_t value = 0;
  for (const char digit : digits) {
    const auto next = static_cast<std::uint64_t>(digit - '0');
    if (value > (UINT64_MAX - next) / 10U)
      return 0U;
    value = value * 10U + next;
  }
  const std::string folded = ascii_lower(unit);
  std::uint64_t multiplier = 1U;
  if (folded == "kbps")
    multiplier = 1000U;
  else if (folded == "mbps")
    multiplier = 1000U * 1000U;
  else if (folded == "gbps")
    multiplier = 1000U * 1000U * 1000U;
  else if (folded == "tbps")
    multiplier = 1000ULL * 1000ULL * 1000ULL * 1000ULL;
  if (value > UINT64_MAX / multiplier)
    return 0U;
  return value * multiplier;
}

double percent_of(std::uint64_t part, std::uint64_t whole) {
  if (whole == 0U)
    return 0.0;
  return static_cast<double>(part) * 100.0 / static_cast<double>(whole);
}

std::string json_string_field(std::string_view text, std::string_view key) {
  const std::string needle = "\"" + std::string(key) + "\"";
  const std::size_t at = text.find(needle);
  if (at == std::string_view::npos)
    return {};
  const std::size_t colon = text.find(':', at + needle.size());
  if (colon == std::string_view::npos)
    return {};
  const std::size_t open = text.find('"', colon);
  if (open == std::string_view::npos)
    return {};
  const std::size_t close = text.find('"', open + 1U);
  if (close == std::string_view::npos)
    return {};
  return std::string(text.substr(open + 1U, close - open - 1U));
}

// The collection's own manifest records the products it was told to gather, in the same fields
// environment.log's [Products] section carries. Reading them back is a transcription, not a
// re-detection: SAT must never re-run product discovery here, because discovery would report what
// is installed on the ENGINEER's machine rather than the customer's.
std::string products_section_from_manifest(std::string_view manifest) {
  const std::size_t array_start = manifest.find("\"products\"");
  if (array_start == std::string_view::npos)
    return {};
  const std::size_t open = manifest.find('[', array_start);
  if (open == std::string_view::npos)
    return {};
  // Find the array's own closing bracket, not the first one encountered. Each product entry
  // carries "evidence":[...], whose ']' would otherwise end the scan and drop every product.
  std::size_t close = std::string_view::npos;
  {
    int depth = 0;
    bool in_string = false;
    bool escaped = false;
    for (std::size_t index = open; index < manifest.size(); ++index) {
      const char character = manifest[index];
      if (in_string) {
        if (escaped)
          escaped = false;
        else if (character == '\\')
          escaped = true;
        else if (character == '"')
          in_string = false;
        continue;
      }
      if (character == '"') {
        in_string = true;
      } else if (character == '[') {
        ++depth;
      } else if (character == ']') {
        --depth;
        if (depth == 0) {
          close = index;
          break;
        }
      }
    }
  }
  if (close == std::string_view::npos)
    return {};
  const std::string_view body = manifest.substr(open + 1U, close - open - 1U);

  std::ostringstream output;
  std::size_t cursor = 0;
  while (cursor < body.size()) {
    const std::size_t entry_open = body.find('{', cursor);
    if (entry_open == std::string_view::npos)
      break;
    const std::size_t entry_close = body.find('}', entry_open);
    if (entry_close == std::string_view::npos)
      break;
    const std::string_view entry = body.substr(entry_open, entry_close - entry_open + 1U);
    const std::string id = json_string_field(entry, "id");
    if (!id.empty()) {
      output << id << '\t' << json_string_field(entry, "name") << '\t'
             << json_string_field(entry, "role") << '\t'
             << (entry.find("\"signature_detected\":true") != std::string_view::npos ||
                         entry.find("\"signature_detected\": true") != std::string_view::npos
                     ? "detected"
                     : "selected")
             << '\t';
      // The evidence paths are a JSON array of strings; join them the way the collector does.
      const std::size_t evidence = entry.find("\"evidence\"");
      if (evidence != std::string_view::npos) {
        const std::size_t list_open = entry.find('[', evidence);
        const std::size_t list_close = entry.find(']', list_open == std::string_view::npos ? evidence
                                                                                           : list_open);
        if (list_open != std::string_view::npos && list_close != std::string_view::npos) {
          std::string_view list = entry.substr(list_open + 1U, list_close - list_open - 1U);
          std::size_t at = 0;
          bool first = true;
          while (at < list.size()) {
            const std::size_t quote_open = list.find('"', at);
            if (quote_open == std::string_view::npos)
              break;
            std::string value;
            std::size_t index = quote_open + 1U;
            for (; index < list.size() && list[index] != '"'; ++index) {
              if (list[index] == '\\' && index + 1U < list.size()) {
                ++index;
                value.push_back(list[index]);
                continue;
              }
              value.push_back(list[index]);
            }
            if (!first)
              output << ';';
            output << value;
            first = false;
            at = index + 1U;
          }
        }
      }
      output << '\n';
    }
    cursor = entry_close + 1U;
  }
  return output.str();
}

} // namespace

std::optional<CollectedCommand> parse_collected_command(std::string_view text) {
  const auto lines = split_lines(strip_utf8_bom(std::string(text)));
  if (lines.empty() || !lines.front().starts_with("Command:"))
    return std::nullopt;

  CollectedCommand command;
  command.command = trim(std::string_view(lines.front()).substr(std::string_view("Command:").size()));

  std::size_t index = 1U;
  for (; index < lines.size(); ++index) {
    const std::string& line = lines[index];
    if (line.empty()) {
      ++index;
      break;
    }
    const auto field = split_padded_field(line);
    if (!field)
      break;
    if (field->first == "ExitCode")
      command.exit_code = std::atoi(field->second.c_str());
    else if (field->first == "TimedOut")
      command.timed_out = parse_bool_word(field->second);
    else if (field->first == "Cancelled")
      command.cancelled = parse_bool_word(field->second);
    else
      break;
  }

  std::ostringstream body;
  for (std::size_t rest = index; rest < lines.size(); ++rest) {
    body << lines[rest];
    if (rest + 1U < lines.size())
      body << '\n';
  }
  command.body = body.str();
  return command;
}

std::vector<EvidenceRecord> parse_format_list(std::string_view body) {
  std::vector<EvidenceRecord> records;
  EvidenceRecord current;
  for (const auto& line : split_lines(body)) {
    if (trim(line).empty()) {
      if (!current.empty()) {
        records.push_back(std::move(current));
        current.clear();
      }
      continue;
    }
    const std::size_t colon = line.find(':');
    const bool indented = !line.empty() && (line.front() == ' ' || line.front() == '\t');
    if (colon == std::string::npos || (indented && !current.empty())) {
      // A wrapped value continues the previous field rather than starting a new one.
      if (!current.empty())
        current.back().second += " " + trim(line);
      continue;
    }
    std::string key = trim(line.substr(0, colon));
    std::string value = trim(line.substr(colon + 1U));
    if (key.empty())
      continue;
    current.emplace_back(std::move(key), std::move(value));
  }
  if (!current.empty())
    records.push_back(std::move(current));
  return records;
}

std::optional<std::string> record_value(const EvidenceRecord& record, std::string_view key) {
  for (const auto& [name, value] : record) {
    if (name == key)
      return value;
  }
  return std::nullopt;
}

const std::vector<CollectedEnvironmentSection>& environment_sections() {
  // The environment.log section table. universal_collection.cpp writes the file from this table and
  // reconstruct_collected_evidence() reads it back through it, keeping the collector and the
  // reconstruction on one definition of the section set.
  static const std::vector<CollectedEnvironmentSection> sections = {
      {"SystemInfo", "WindowsSupport/SystemInfo/systeminfo.log", 1024U * 1024U, true},
      // Veeam has no Get-ComputerInfo file of that name; its Get-ComputerInfo output is SysInfo.log.
      {"ComputerInfo", "WindowsSupport/SystemInfo/computer_info.log", 1024U * 1024U, true, {"SysInfo.log"}},
      {"WindowsMaintenancePackages", "WindowsSupport/SystemInfo/dism_packages.log", 2U * 1024U * 1024U, true, {"dism_pack.log"}},
      {"WindowsHotfixes", "WindowsSupport/SystemInfo/windows_updates.log", 2U * 1024U * 1024U, true},
      {"InstalledSoftware", "WindowsSupport/SystemInfo/installed_software.log", 2U * 1024U * 1024U, true},
      {"Services", "WindowsSupport/SystemInfo/services.log", 2U * 1024U * 1024U, true},
      {"IPConfiguration", "WindowsSupport/SystemInfo/ipconfig.log", 1024U * 1024U, true},
      {"ListeningPorts", "WindowsSupport/SystemInfo/netstat.log", 2U * 1024U * 1024U, true},
      {"Routes", "WindowsSupport/SystemInfo/route.log", 1024U * 1024U, true},
      {"NetworkAdapterBindings", "WindowsSupport/SystemInfo/file_and_printer_sharing.log", 2U * 1024U * 1024U, true},
      {"NetworkAdapters", "WindowsSupport/SystemInfo/network_adapters.log", 2U * 1024U * 1024U, true},
      {"NetworkIpInterfaces", "WindowsSupport/SystemInfo/network_ip_interfaces.log", 2U * 1024U * 1024U, true},
      {"NetworkRoutesDetailed", "WindowsSupport/SystemInfo/network_routes.log", 2U * 1024U * 1024U, true},
      {"NetworkAdvancedProperties", "WindowsSupport/SystemInfo/network_advanced_properties.log", 2U * 1024U * 1024U, true},
      {"TlsProtocols", "WindowsSupport/SystemInfo/tls_protocols.log", 1024U * 1024U, true},
      {"TlsCipherSuites", "WindowsSupport/SystemInfo/tls_ciphers.log", 2U * 1024U * 1024U, true, {"ciphers.txt"}},
      {"VeeamCertificates", "WindowsSupport/SystemInfo/veeam_certificates.log", 1024U * 1024U, true, {"VAW_cert.log"}},
      {"VeeamRegistrySafe", "WindowsSupport/Registry/veeam_registry_safe_inventory.log", 2U * 1024U * 1024U, true},
      {"SchannelRegistry", "WindowsSupport/SystemInfo/network_customizations.reg", 2U * 1024U * 1024U, true, {"network_customizations.log"}},
      {"Storage", "WindowsSupport/SystemInfo/fsutil_sectorinfo.log", 1024U * 1024U, true, {"fsutil_info.log"}},
      {"FilesystemFilters", "WindowsSupport/SystemInfo/minifilters.log", 1024U * 1024U, true, {"filter.log"}},
      {"OSRelease", "PlatformContext/os-release.txt", 1024U * 1024U, false},
      {"NetworkAddresses", "PlatformContext/network-addresses.txt", 1024U * 1024U, false},
      {"NetworkLinks", "PlatformContext/network-links.txt", 2U * 1024U * 1024U, false},
      {"ListeningPorts", "PlatformContext/listening-ports.txt", 2U * 1024U * 1024U, false},
      {"Routes", "PlatformContext/routes.txt", 1024U * 1024U, false},
      {"RoutingRules", "PlatformContext/routing-rules.txt", 1024U * 1024U, false},
      {"Services", "PlatformContext/services.txt", 2U * 1024U * 1024U, false},
      {"ServiceFiles", "PlatformContext/service-files.txt", 2U * 1024U * 1024U, false},
      {"InstalledSoftware", "PlatformContext/installed-software.txt", 2U * 1024U * 1024U, false},
      {"TlsCipherSuites", "PlatformContext/tls-ciphers.txt", 2U * 1024U * 1024U, false},
      {"Storage", "PlatformContext/filesystems.txt", 1024U * 1024U, false},
  };
  return sections;
}

std::filesystem::path existing_environment_log(const std::filesystem::path& root) {
  std::error_code error;
  const auto candidate = root / "environment.log";
  if (std::filesystem::is_regular_file(candidate, error))
    return candidate;
  return {};
}

std::filesystem::path existing_health_report(const std::filesystem::path& root) {
  std::error_code error;
  if (!std::filesystem::is_directory(root, error))
    return {};
  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error)
      break;
    if (!entry.is_regular_file(error))
      continue;
    const std::string name = path_to_utf8(entry.path().filename());
    if (name.size() > std::string_view("-SystemHealth.txt").size() &&
        name.ends_with("-SystemHealth.txt")) {
      return entry.path();
    }
  }
  return {};
}

namespace {

// Whether a directory is a Veeam log collection - SAT's own or the Veeam Agent collector's.
//
// A Veeam Agent bundle carries directories such as Backup, Endpoint, Events, RegVal, Setup, SysInfo
// and VSS and none of SAT's own markers, so recognition is by evidence rather than by one
// collector's layout: a SAT marker file, two or more known collector directories, or any directory
// that holds log files.
bool looks_like_collection(const std::filesystem::path& directory) {
  std::error_code error;
  if (!std::filesystem::is_directory(directory, error))
    return false;

  if (std::filesystem::exists(directory / "WindowsSupport", error) ||
      std::filesystem::exists(directory / "PlatformContext", error) ||
      std::filesystem::exists(directory / "collection-manifest.json", error) ||
      std::filesystem::exists(directory / "universal-support-manifest.json", error)) {
    return true;
  }

  // Directory names the Veeam collectors use, matched case-insensitively. Two or more together
  // identify a collection; a single one is too common to be conclusive.
  static const std::array<std::string, 12> known{
      {"backup", "endpoint", "events", "regval", "setup", "sysinfo", "vss", "systeminfo",
       "registry", "logs", "platformcontext", "windowssupport"}};
  std::size_t hits = 0;
  for (const auto& entry : std::filesystem::directory_iterator(directory, error)) {
    if (error)
      break;
    if (!entry.is_directory(error))
      continue;
    const std::string name = ascii_lower(path_to_utf8(entry.path().filename()));
    if (std::find(known.begin(), known.end(), name) != known.end())
      ++hits;
  }
  return hits >= 2U;
}

// Read a collected file's payload.
//
// SAT prefixes its own captures with a "Command:/ExitCode:/TimedOut:/Cancelled:" envelope; a file
// from another collector is the raw output. Both forms are read, so evidence from either source is
// available to the reconstruction.
std::string evidence_payload(const std::filesystem::path& path, std::size_t maximum_bytes) {
  const std::string raw = transcode_if_utf16(strip_utf8_bom(read_file(path, maximum_bytes)));
  if (raw.empty())
    return raw;
  if (const auto capture = parse_collected_command(raw)) {
    // A command that failed carries no facts, only the reason it failed.
    return capture->succeeded() ? capture->body : std::string();
  }
  return raw;
}

// Walk a collection looking for a file whose content matches. Bounded so a bundle with a very large
// tree cannot turn a button press into a directory crawl.
std::filesystem::path find_evidence_by_content(
    const std::filesystem::path& root,
    const std::function<bool(const std::string&)>& matches,
    std::size_t maximum_bytes) {
  constexpr std::size_t kMaximumFilesInspected = 4000U;
  constexpr std::uintmax_t kMaximumFileSize = 8U * 1024U * 1024U;

  std::error_code error;
  std::size_t inspected = 0;
  std::filesystem::recursive_directory_iterator iterator(
      root, std::filesystem::directory_options::skip_permission_denied, error);
  if (error)
    return {};

  for (const auto& entry : iterator) {
    if (inspected >= kMaximumFilesInspected)
      break;
    std::error_code entry_error;
    if (!entry.is_regular_file(entry_error) || entry_error)
      continue;
    // Only text-shaped evidence. An .evtx or a .zip cannot be scanned this way and reading them
    // would be most of the time budget.
    const std::string extension = ascii_lower(path_to_utf8(entry.path().extension()));
    if (extension != ".log" && extension != ".txt" && extension != ".csv" && extension != ".nfo" &&
        extension != ".reg" && !extension.empty()) {
      continue;
    }
    const auto size = entry.file_size(entry_error);
    if (entry_error || size == 0U || size > kMaximumFileSize)
      continue;
    ++inspected;
    const std::string payload = evidence_payload(entry.path(), maximum_bytes);
    if (!payload.empty() && matches(payload))
      return entry.path();
  }
  return {};
}

// Every file in a collection, keyed by lower-cased basename, in one bounded walk. The environment
// section table maps each section to SAT's own path; a Veeam Agent bundle carries the same evidence
// under SysInfo/ with a different basename, so resolving twenty sections by name is one crawl here
// rather than twenty. First occurrence of a basename wins - a collection does not repeat them.
std::map<std::string, std::filesystem::path> index_evidence_by_basename(
    const std::filesystem::path& root) {
  constexpr std::size_t kMaximumFilesInspected = 8000U;
  std::map<std::string, std::filesystem::path> index;
  std::error_code error;
  std::filesystem::recursive_directory_iterator iterator(
      root, std::filesystem::directory_options::skip_permission_denied, error);
  if (error)
    return index;
  std::size_t inspected = 0;
  for (const auto& entry : iterator) {
    if (inspected >= kMaximumFilesInspected)
      break;
    std::error_code entry_error;
    if (!entry.is_regular_file(entry_error) || entry_error)
      continue;
    ++inspected;
    index.emplace(ascii_lower(path_to_utf8(entry.path().filename())), entry.path());
  }
  return index;
}

// Content signatures. Each names two independent markers, so an unrelated file mentioning one of
// them in passing is not mistaken for the evidence.
bool looks_like_systeminfo(const std::string& text) {
  return text.find("Host Name:") != std::string::npos && text.find("OS Name:") != std::string::npos;
}
bool looks_like_computer_info(const std::string& text) {
  return text.find("CsTotalPhysicalMemory") != std::string::npos ||
         text.find("OsTotalVisibleMemorySize") != std::string::npos;
}
bool looks_like_net_adapters(const std::string& text) {
  // LinkSpeed is the distinctive marker; the second is whichever companion field the collector
  // happened to select. Requiring InterfaceDescription specifically rejected real Get-NetAdapter
  // output that had been narrowed to Name/Status/LinkSpeed.
  if (text.find("LinkSpeed") == std::string::npos)
    return false;
  return text.find("InterfaceDescription") != std::string::npos ||
         text.find("MacAddress") != std::string::npos ||
         text.find("Status") != std::string::npos ||
         text.find("ifIndex") != std::string::npos;
}

// Prefer the path SAT would have written, then fall back to searching for the shape.
std::string evidence_for(const std::filesystem::path& root,
                         const std::filesystem::path& preferred,
                         const std::function<bool(const std::string&)>& matches,
                         std::size_t maximum_bytes,
                         std::filesystem::path& found_at) {
  std::error_code error;
  if (std::filesystem::is_regular_file(preferred, error) && !error) {
    const std::string payload = evidence_payload(preferred, maximum_bytes);
    if (!payload.empty() && matches(payload)) {
      found_at = preferred;
      return payload;
    }
  }
  const auto located = find_evidence_by_content(root, matches, maximum_bytes);
  if (located.empty())
    return {};
  found_at = located;
  return evidence_payload(located, maximum_bytes);
}

std::filesystem::path locate_collection_root(const std::filesystem::path& root) {
  std::error_code error;
  if (!std::filesystem::is_directory(root, error))
    return {};

  // A sub-directory of a collection, so an engineer can point at the folder they are looking at
  // rather than having to find the top of it.
  const std::string folded = ascii_lower(path_to_utf8(root.filename()));
  if (folded == "windowssupport" || folded == "sysinfo" || folded == "systeminfo") {
    if (looks_like_collection(root.parent_path()))
      return root.parent_path();
  }

  if (looks_like_collection(root))
    return root;

  // A directory holding exactly one collection.
  std::filesystem::path only;
  std::size_t matches = 0;
  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error)
      break;
    if (!entry.is_directory(error))
      continue;
    if (looks_like_collection(entry.path())) {
      only = entry.path();
      ++matches;
    }
  }
  if (matches == 1U)
    return only;
  return {};
}

void rebuild_memory(SystemHealthSnapshot& snapshot,
                    const EvidenceRecord& computer_info,
                    const std::vector<std::pair<std::string, std::string>>& system_info,
                    std::vector<std::string>& recovered,
                    std::vector<std::string>& unavailable) {
  const auto system_field = [&](std::string_view key) -> std::optional<std::string> {
    for (const auto& [name, value] : system_info) {
      if (name == key)
        return value;
    }
    return std::nullopt;
  };

  std::uint64_t physical_total = 0;
  std::uint64_t physical_available = 0;
  std::uint64_t commit_limit = 0;
  std::uint64_t commit_used = 0;
  std::string source;

  // Get-ComputerInfo carries exact byte and kilobyte counts, so it is preferred over systeminfo,
  // which rounds to whole megabytes.
  if (const auto total = record_value(computer_info, "CsTotalPhysicalMemory")) {
    if (const auto parsed = parse_quantity(*total, 1U)) {
      physical_total = *parsed;
      source = "SystemInfo/computer_info.log";
    }
  }
  if (physical_total == 0U) {
    if (const auto visible = record_value(computer_info, "OsTotalVisibleMemorySize")) {
      if (const auto parsed = parse_quantity(*visible, 1024U)) {
        physical_total = *parsed;
        source = "SystemInfo/computer_info.log";
      }
    }
  }
  if (const auto free_physical = record_value(computer_info, "OsFreePhysicalMemory")) {
    if (const auto parsed = parse_quantity(*free_physical, 1024U))
      physical_available = *parsed;
  }
  if (const auto virtual_total = record_value(computer_info, "OsTotalVirtualMemorySize")) {
    if (const auto parsed = parse_quantity(*virtual_total, 1024U))
      commit_limit = *parsed;
  }
  if (const auto virtual_used = record_value(computer_info, "OsInUseVirtualMemory")) {
    if (const auto parsed = parse_quantity(*virtual_used, 1024U))
      commit_used = *parsed;
  }

  if (physical_total == 0U) {
    if (const auto total = system_field("Total Physical Memory")) {
      if (const auto parsed = parse_quantity(*total, 1024U * 1024U)) {
        physical_total = *parsed;
        source = "SystemInfo/systeminfo.log";
      }
    }
    if (const auto available = system_field("Available Physical Memory")) {
      if (const auto parsed = parse_quantity(*available, 1024U * 1024U))
        physical_available = *parsed;
    }
    if (const auto limit = system_field("Virtual Memory: Max Size")) {
      if (const auto parsed = parse_quantity(*limit, 1024U * 1024U))
        commit_limit = *parsed;
    }
    if (const auto used = system_field("Virtual Memory: In Use")) {
      if (const auto parsed = parse_quantity(*used, 1024U * 1024U))
        commit_used = *parsed;
    }
  }

  if (physical_total == 0U) {
    unavailable.emplace_back(
        "Physical memory - neither systeminfo.log nor computer_info.log carried a usable total");
    return;
  }

  snapshot.memory.physical_total_bytes = physical_total;
  snapshot.memory.physical_available_bytes = physical_available;
  snapshot.memory.physical_used_bytes =
      physical_available <= physical_total ? physical_total - physical_available : 0U;
  snapshot.memory.physical_load_percent =
      percent_of(snapshot.memory.physical_used_bytes, physical_total);
  snapshot.memory_total_bytes = snapshot.memory.physical_total_bytes;
  snapshot.memory_used_bytes = snapshot.memory.physical_used_bytes;
  snapshot.memory_load_percent = snapshot.memory.physical_load_percent;
  if (commit_limit != 0U) {
    snapshot.memory.commit_limit_bytes = commit_limit;
    snapshot.memory.commit_total_bytes = commit_used;
    snapshot.memory.commit_load_percent = percent_of(commit_used, commit_limit);
  }
  recovered.push_back("Memory (" + source + ")");

  // Paging RATES are live performance counters. A collection captures a moment, not an interval,
  // so they are absent rather than zero - reporting 0 pages/sec would read as "no paging".
  unavailable.emplace_back(
      "Paging rates - pages/sec counters are sampled over an interval and a collection is a "
      "single point in time");
}

void rebuild_adapters(SystemHealthSnapshot& snapshot,
                      const std::vector<EvidenceRecord>& adapters,
                      std::vector<std::string>& recovered,
                      std::vector<std::string>& unavailable) {
  std::size_t added = 0;
  for (const auto& record : adapters) {
    const auto name = record_value(record, "Name");
    if (!name || name->empty())
      continue;
    NetworkAdapterHealth adapter;
    adapter.name = *name;
    adapter.key = *name;
    adapter.description = record_value(record, "InterfaceDescription").value_or("");
    adapter.operational_status = record_value(record, "Status").value_or("Unknown");
    const std::uint64_t speed = parse_link_speed(record_value(record, "LinkSpeed").value_or(""));
    adapter.receive_link_speed_bits = speed;
    adapter.transmit_link_speed_bits = speed;

    // Only from what the record actually says. Guessing from a name would be inference.
    const std::string media = ascii_lower(record_value(record, "MediaType").value_or(""));
    const std::string physical = ascii_lower(record_value(record, "PhysicalMediaType").value_or(""));
    adapter.virtual_adapter = media == "tunnel" || physical == "unspecified";

    snapshot.network_adapters.push_back(std::move(adapter));
    ++added;
  }
  if (added == 0U) {
    unavailable.emplace_back("Network adapters - no Get-NetAdapter output in the collection");
    return;
  }
  recovered.push_back("Network adapters, " + std::to_string(added) +
                      " (SystemInfo/network_adapters.log)");
  unavailable.emplace_back(
      "Network throughput, errors and discards - Get-NetAdapter reports configuration, not the "
      "live counters the health monitor samples");
}

} // namespace

// The machine an evidence rebuild describes.
//
// Order matters: the health snapshot states it, the environment document states it, and the folder
// name only suggests it. A folder called "Logs" would otherwise become a machine called "Logs" and
// sit in the case index next to real ones.
void resolve_machine_name(EvidenceReconstruction& rebuilt) {
  if (!rebuilt.health.machine_name.empty()) {
    rebuilt.machine_name = rebuilt.health.machine_name;
    return;
  }
  // "Machine=NAME" on its own line in SAT_ENVIRONMENT_V1/V2.
  std::istringstream environment(rebuilt.environment_text);
  std::string line;
  while (std::getline(environment, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    constexpr std::string_view key = "Machine=";
    if (line.rfind(key, 0) == 0) {
      const std::string value = trim(line.substr(key.size()));
      if (!value.empty()) {
        rebuilt.machine_name = value;
        return;
      }
    }
    // The header block ends at the first section; nothing below it is the machine name.
    if (!line.empty() && line.front() == '[')
      break;
  }
  if (!rebuilt.collection_root.empty()) {
    rebuilt.machine_name = path_to_utf8(rebuilt.collection_root.filename());
    rebuilt.machine_name_inferred = true;
  }
}

// A machine name as a directory name. Not the case-id sanitiser: this keeps the name recognisable
// in a folder listing, and only removes what a path cannot hold.
std::string machine_directory_name(std::string_view machine) {
  std::string output;
  output.reserve(machine.size());
  for (const char raw : machine) {
    const unsigned char c = static_cast<unsigned char>(raw);
    if (std::isalnum(c) != 0 || raw == '-' || raw == '_' || raw == '.')
      output.push_back(raw);
    else if (!output.empty() && output.back() != '-')
      output.push_back('-');
  }
  while (!output.empty() && output.back() == '-')
    output.pop_back();
  if (output.size() > 64U)
    output.resize(64U);
  return output.empty() ? std::string("Unknown") : output;
}

std::filesystem::path imported_machine_index_path(const std::filesystem::path& case_root) {
  return reconstructed_evidence_directory(case_root) / "index.tsv";
}

// Tabs separate the fields, so a machine name with spaces in it survives the round trip.
std::string encode_index_field(std::string_view value) {
  std::string output;
  output.reserve(value.size());
  for (const char c : value) {
    if (c == '\t' || c == '\n' || c == '\r')
      output.push_back(' ');
    else
      output.push_back(c);
  }
  return output;
}

namespace {

// A .zip unpacked into a temporary directory that removes itself.
//
// Only the members a reconstruction can actually use are written: text-shaped and under the same
// size ceiling the content search applies. Directory structure is preserved, because
// looks_like_collection() reads folder names to recognise a collection.
class UnpackedArchive {
public:
  explicit UnpackedArchive(const std::filesystem::path& archive) {
    auto temporary = secure_temp_directory();
    if (!temporary.ok())
      return;
    auto suffix = secure_random_hex(8U);
    if (!suffix.ok())
      return;
    std::error_code error;
    root_ = temporary.value() / ("collection-" + suffix.value());
    std::filesystem::create_directories(root_, error);
    if (error) {
      root_.clear();
      return;
    }
    owned_ = true;
    unpack(archive, {});
  }

  UnpackedArchive(const UnpackedArchive&) = delete;
  UnpackedArchive& operator=(const UnpackedArchive&) = delete;

  // Removed even when the rebuild above threw: customer log content does not outlive the import
  // that needed it.
  ~UnpackedArchive() {
    if (!owned_ || root_.empty())
      return;
    std::error_code error;
    static_cast<void>(std::filesystem::remove_all(root_, error));
  }

  [[nodiscard]] const std::filesystem::path& root() const { return root_; }
  [[nodiscard]] bool ok() const { return owned_ && !root_.empty() && wrote_something_; }

private:
  void unpack(const std::filesystem::path& archive, const std::string& directory) {
    if (depth_guard_ > 24U)
      return;
    auto listing = archive_list_directory(archive, directory);
    if (!listing.ok())
      return;
    for (const auto& entry : listing.value()) {
      if (inspected_ >= kMaximumMembers)
        return;
      if (entry.directory) {
        ++depth_guard_;
        unpack(archive, entry.path);
        --depth_guard_;
        continue;
      }
      ++inspected_;
      if (entry.size == 0U || entry.size > kMaximumMemberBytes)
        continue;
      const std::string extension =
          ascii_lower(path_to_utf8(path_from_utf8(entry.path).extension()));
      if (extension != ".log" && extension != ".txt" && extension != ".csv" &&
          extension != ".nfo" && extension != ".reg" && !extension.empty()) {
        continue;
      }
      auto body = archive_read_member_text(archive, entry.path,
                                           static_cast<std::size_t>(kMaximumMemberBytes));
      if (!body.ok())
        continue;

      // archive_list_directory() already drops absolute and traversing members, so the relative
      // path can be joined - but the join is still checked, because a path that escapes the
      // temporary root would be writing somewhere nobody asked for.
      const auto destination = root_ / path_from_utf8(entry.path);
      const auto normalised = destination.lexically_normal();
      const auto base = root_.lexically_normal();
      if (path_to_utf8(normalised).rfind(path_to_utf8(base), 0) != 0)
        continue;

      std::error_code error;
      std::filesystem::create_directories(normalised.parent_path(), error);
      if (error)
        continue;
      std::ofstream out(normalised, std::ios::binary | std::ios::trunc);
      if (!out)
        continue;
      out << body.value();
      if (out)
        wrote_something_ = true;
    }
  }

  static constexpr std::size_t kMaximumMembers = 6000U;
  static constexpr std::uint64_t kMaximumMemberBytes = 8U * 1024U * 1024U;

  std::filesystem::path root_;
  bool owned_ = false;
  bool wrote_something_ = false;
  std::size_t inspected_ = 0;
  std::size_t depth_guard_ = 0;
};

bool path_is_archive(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(path_to_utf8(path.extension()));
  return extension == ".zip";
}

// Declared here because the two are mutually recursive: an archive holds collections,
// and a collection can itself be an archive. Defined further down, beside the
// multi-collection entry point it delegates to.
Result<std::vector<EvidenceReconstruction>> reconstruct_from_archive(
    const std::filesystem::path& archive);

} // namespace

Result<EvidenceReconstruction> reconstruct_collected_evidence(const std::filesystem::path& root) {
  // A .zip is read through a temporary unpack of its useful members. Handled here rather than in
  // every caller, so "point SAT at whatever the customer sent" stays true.
  std::error_code archive_error;
  if (path_is_archive(root) && std::filesystem::is_regular_file(root, archive_error)) {
    auto all = reconstruct_from_archive(root);
    if (!all.ok())
      return Result<EvidenceReconstruction>::failure(all.error());
    if (all.value().empty()) {
      return Result<EvidenceReconstruction>::failure(evidence_error(
          "rebuild", "No collection was found inside " + path_to_utf8(root.filename()) + "."));
    }
    return Result<EvidenceReconstruction>::success(std::move(all.value().front()));
  }

  EvidenceReconstruction output;

  // Accept whatever the engineer selected.
  //
  // A file resolves to the folder holding it, and a folder that is not itself a collection is
  // searched for one. Selection is accepted by evidence rather than by a required layout, so a
  // Veeam Agent bundle is read as readily as SAT's own.
  std::error_code selection_error;
  std::filesystem::path selected = root;
  if (std::filesystem::is_regular_file(selected, selection_error) && !selection_error)
    selected = selected.parent_path();

  output.collection_root = locate_collection_root(selected);
  if (output.collection_root.empty()) {
    // Last resort: does this tree contain evidence at all? If it does, it is a collection whatever
    // its folders are called.
    std::filesystem::path witness;
    if (!find_evidence_by_content(selected, looks_like_systeminfo, 1024U * 1024U).empty() ||
        !find_evidence_by_content(selected, looks_like_computer_info, 1024U * 1024U).empty() ||
        !find_evidence_by_content(selected, looks_like_net_adapters, 1024U * 1024U).empty()) {
      output.collection_root = selected;
    }
  }
  if (output.collection_root.empty()) {
    return Result<EvidenceReconstruction>::failure(evidence_error(
        "reconstruct",
        "Nothing in that folder could be read as collected evidence. SAT searched it and its "
        "sub-folders for systeminfo, Get-ComputerInfo or Get-NetAdapter output and found none. "
        "Selected: " + path_to_utf8(selected) +
            ". Select the collection folder, any folder inside it, or a file from it."));
  }

  const auto& sections = environment_sections();

  // --- environment.log ---------------------------------------------------------------------
  //
  // Rebuilt through the same section table the collector writes from, in the same order, so an
  // engineer reading a reconstructed snapshot sees the document they already know.
  std::error_code error;
  // A collection is Windows if it carries SAT's own WindowsSupport tree, the Veeam Agent's SysInfo
  // tree, or - for a collector that used neither name - Windows systeminfo or Get-ComputerInfo
  // content anywhere in it. Recognising SysInfo and content, not only WindowsSupport, is what lets
  // a Veeam Agent bundle be read as the Windows collection it is.
  bool windows_collection =
      std::filesystem::exists(output.collection_root / "WindowsSupport", error) ||
      std::filesystem::exists(output.collection_root / "SysInfo", error);
  if (!windows_collection) {
    windows_collection =
        !find_evidence_by_content(output.collection_root, looks_like_systeminfo, 1024U * 1024U)
             .empty() ||
        !find_evidence_by_content(output.collection_root, looks_like_computer_info, 1024U * 1024U)
             .empty();
  }

  // Resolve each section by SAT's own path first, then by basename anywhere in the tree. Built once.
  const auto evidence_by_basename = index_evidence_by_basename(output.collection_root);

  std::ostringstream environment;
  std::size_t present_sections = 0;
  std::size_t missing_sections = 0;
  std::ostringstream section_text;
  for (const auto& section : sections) {
    if (section.windows != windows_collection)
      continue;
    const auto native_path =
        output.collection_root / std::filesystem::path(std::string(section.relative_path));
    std::filesystem::path path;
    if (std::filesystem::is_regular_file(native_path, error)) {
      path = native_path;
    } else {
      // Not at SAT's own path: try the basename SAT would use, then each Veeam alias.
      std::vector<std::string> names;
      names.push_back(ascii_lower(path_to_utf8(
          std::filesystem::path(std::string(section.relative_path)).filename())));
      for (const auto& alt : section.alt_basenames)
        names.push_back(ascii_lower(std::string(alt)));
      for (const auto& name : names) {
        const auto found = evidence_by_basename.find(name);
        if (found != evidence_by_basename.end()) {
          path = found->second;
          break;
        }
      }
    }
    std::string body;
    if (!path.empty())
      body = evidence_payload(path, section.maximum_bytes);
    if (body.empty()) {
      // Empty covers absent, a zero-byte capture, and a collected command that recorded only a
      // failure - none of which is evidence, so the section reads NotCollected rather than blank.
      section_text << "\n[" << section.name << "]\nNotCollected="
                   << path_to_utf8(native_path) << "\n\n";
      ++missing_sections;
      continue;
    }
    section_text << "\n[" << section.name << "]\n" << body << "\n";
    ++present_sections;
  }

  // Header facts come from the evidence, never from the machine doing the reconstruction. Reading
  // the local host name here would silently label a customer's snapshot with the engineer's
  // workstation.
  std::string machine_name;
  std::string os_name;
  std::string os_version;
  std::string architecture;
  std::string captured_utc;

  std::vector<std::pair<std::string, std::string>> system_info_fields;
  std::filesystem::path system_info_source;
  {
    const std::string payload = evidence_for(
        output.collection_root,
        output.collection_root / "WindowsSupport" / "SystemInfo" / "systeminfo.log",
        looks_like_systeminfo, 1024U * 1024U, system_info_source);
    for (const auto& line : split_lines(payload)) {
      if (auto field = split_padded_field(line))
        system_info_fields.push_back(std::move(*field));
    }
  }
  for (const auto& [key, value] : system_info_fields) {
    if (key == "Host Name")
      machine_name = value;
    else if (key == "OS Name")
      os_name = value;
    else if (key == "OS Version")
      os_version = value;
    else if (key == "System Type")
      architecture = value;
  }

  EvidenceRecord computer_info;
  std::filesystem::path computer_info_source;
  {
    const std::string payload = evidence_for(
        output.collection_root,
        output.collection_root / "WindowsSupport" / "SystemInfo" / "computer_info.log",
        looks_like_computer_info, 4U * 1024U * 1024U, computer_info_source);
    auto records = parse_format_list(payload);
    if (!records.empty())
      computer_info = std::move(records.front());
  }
  if (machine_name.empty())
    machine_name = record_value(computer_info, "CsName").value_or("");
  if (os_name.empty())
    os_name = record_value(computer_info, "OsName").value_or("");
  if (os_version.empty())
    os_version = record_value(computer_info, "OsVersion").value_or("");
  if (architecture.empty())
    architecture = record_value(computer_info, "OsArchitecture").value_or("");

  // The collection's own index records when it ran. That is the capture time - not now.
  const auto index_path = output.collection_root / "WindowsSupport" / "windows-support-index.json";
  const std::string index_text = read_file(index_path, 4U * 1024U * 1024U);
  if (!index_text.empty()) {
    captured_utc = json_string_field(index_text, "created_utc");
    if (machine_name.empty())
      machine_name = json_string_field(index_text, "collector_machine");
  }

  if (machine_name.empty())
    machine_name = "Unknown";

  environment << "SAT_ENVIRONMENT_V2\n"
              << "CapturedUTC=" << (captured_utc.empty() ? "Unknown" : captured_utc) << "\n"
              << "Machine=" << machine_name << "\n"
              << "Platform=" << (windows_collection ? "windows" : "linux") << "\n"
              << "OS=" << (os_name.empty() ? "Unknown" : os_name) << "\n"
              << "OSVersion=" << (os_version.empty() ? "Unknown" : os_version) << "\n"
              << "Architecture=" << (architecture.empty() ? "Unknown" : architecture) << "\n"
              // Elevation is a property of the process that collected, and the collection does not
              // record it. Claiming either value would be inventing evidence.
              << "Elevated=unknown\n"
              << "Reconstructed=true\n"
              << "ReconstructedFrom=" << path_to_utf8(output.collection_root) << "\n";
  const std::string manifest_text =
      read_file(output.collection_root / "universal-support-manifest.json", 4U * 1024U * 1024U);
  const std::string products = products_section_from_manifest(manifest_text);
  environment << "\n[Products]\n" << products;
  if (products.empty()) {
    output.unavailable.emplace_back(
        "Detected products - the collection carries no universal-support-manifest.json to read "
        "them from, and re-running discovery here would report this machine, not the customer's");
  } else {
    output.recovered.emplace_back("Detected products (universal-support-manifest.json)");
  }
  environment << "\n[BundlePaths]\nWindowsSupport=WindowsSupport\nPlatformContext=PlatformContext\n"
                 "Tools=Tools\nApplicationLogs=ApplicationLogs\n";
  environment << section_text.str();

  output.environment_text = environment.str();
  output.environment_reconstructed = present_sections > 0U;
  if (present_sections > 0U) {
    output.recovered.push_back("Environment sections, " + std::to_string(present_sections) +
                               " of " + std::to_string(present_sections + missing_sections));
  }
  if (missing_sections > 0U) {
    output.unavailable.push_back(
        std::to_string(missing_sections) +
        " environment section(s) were not in the collection and are marked NotCollected");
  }

  // --- health snapshot ---------------------------------------------------------------------
  output.health.machine_name = machine_name;
  output.health.captured_utc = captured_utc;

  rebuild_memory(output.health, computer_info, system_info_fields, output.recovered,
                 output.unavailable);

  std::vector<EvidenceRecord> adapter_records;
  std::filesystem::path adapters_source;
  {
    const std::string payload = evidence_for(
        output.collection_root,
        output.collection_root / "WindowsSupport" / "SystemInfo" / "network_adapters.log",
        looks_like_net_adapters, 4U * 1024U * 1024U, adapters_source);
    adapter_records = parse_format_list(payload);
  }
  rebuild_adapters(output.health, adapter_records, output.recovered, output.unavailable);

  // These three are not gaps in the reconstruction - they are gaps in the collection. Naming the
  // missing command is what lets the collector be fixed rather than the reader blamed.
  output.unavailable.emplace_back(
      "Volumes and free space - the collection runs no Get-Volume or Win32_LogicalDisk capture");
  output.unavailable.emplace_back(
      "Storage devices and predictive failure - the collection runs no Get-PhysicalDisk capture");
  output.unavailable.emplace_back(
      "Top processes - the collection captures no process list");
  output.unavailable.emplace_back(
      "CPU utilization and temperature - both are live counters, absent from any collection");

  // The same evaluator the live samplers use, so a reconstructed snapshot is never judged by
  // different thresholds than a sampled one.
  evaluate_system_health(output.health);

  for (const auto& gap : output.unavailable)
    output.health.warnings.push_back("Not reconstructed: " + gap);
  output.health.warnings.push_back("This snapshot was rebuilt from collected evidence in " +
                                   path_to_utf8(output.collection_root) +
                                   ". It is not a live sample.");

  output.health_reconstructed =
      output.health.memory.physical_total_bytes != 0U || !output.health.network_adapters.empty();

  if (!output.health_reconstructed && !output.environment_reconstructed) {
    return Result<EvidenceReconstruction>::failure(evidence_error(
        "reconstruct",
        "The collection was found but carried no readable Windows support evidence: "
        "systeminfo.log, computer_info.log and network_adapters.log are all absent or failed."));
  }
  resolve_machine_name(output);
  return Result<EvidenceReconstruction>::success(std::move(output));
}


std::filesystem::path reconstructed_evidence_directory(const std::filesystem::path& case_root) {
  return case_root / "reconstructed";
}

std::vector<ImportedMachine> load_imported_machines(const std::filesystem::path& case_root) {
  std::vector<ImportedMachine> machines;
  if (case_root.empty())
    return machines;

  const auto index = imported_machine_index_path(case_root);
  std::error_code error;
  if (std::filesystem::is_regular_file(index, error)) {
    std::ifstream input(index, std::ios::binary);
    std::string line;
    while (std::getline(input, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      if (line.empty() || line.front() == '#')
        continue;
      std::vector<std::string> fields;
      std::string field;
      std::istringstream row(line);
      while (std::getline(row, field, '\t'))
        fields.push_back(field);
      if (fields.size() < 6U)
        continue;                     // a short row is a hand-edit mistake, not a machine
      ImportedMachine entry;
      entry.machine_name = fields[0];
      entry.directory = std::filesystem::path(fields[1]);
      if (!fields[2].empty())
        entry.environment_log = std::filesystem::path(fields[2]);
      if (!fields[3].empty())
        entry.health_report = std::filesystem::path(fields[3]);
      entry.source_collection = fields[4];
      entry.imported_utc = fields[5];
      machines.push_back(std::move(entry));
    }
    return machines;
  }

  // No index: a case written before the index existed, with the two documents sitting directly in
  // reconstructed/. Read them as one unnamed machine rather than reporting the case as empty.
  const auto directory = reconstructed_evidence_directory(case_root);
  if (!std::filesystem::is_directory(directory, error))
    return machines;
  ImportedMachine legacy;
  legacy.directory = directory;
  legacy.environment_log = existing_environment_log(directory);
  legacy.health_report = existing_health_report(directory);
  if (legacy.environment_log.empty() && legacy.health_report.empty())
    return machines;
  if (!legacy.health_report.empty()) {
    // "<MACHINE>-SystemHealth.txt" carries the name in the filename.
    const std::string name = path_to_utf8(legacy.health_report.filename());
    constexpr std::string_view suffix = "-SystemHealth.txt";
    if (name.size() > suffix.size())
      legacy.machine_name = name.substr(0, name.size() - suffix.size());
  }
  if (legacy.machine_name.empty())
    legacy.machine_name = "Imported";
  machines.push_back(std::move(legacy));
  return machines;
}

bool collected_evidence_archive_supported() noexcept { return archive_browser_available(); }

bool importable_collection_path(const std::filesystem::path& path) {
  std::error_code error;
  if (std::filesystem::is_directory(path, error))
    return true;
  return path_is_archive(path) && collected_evidence_archive_supported();
}

namespace {

// Rebuild everything inside one archive. The unpacked directory lives only for this call.
Result<std::vector<EvidenceReconstruction>> reconstruct_from_archive(
    const std::filesystem::path& archive) {
  using ResultType = Result<std::vector<EvidenceReconstruction>>;
  if (!collected_evidence_archive_supported()) {
    return ResultType::failure(evidence_error(
        "rebuild", "This build cannot read archives, so " + path_to_utf8(archive.filename()) +
                       " has to be extracted before it can be imported."));
  }

  UnpackedArchive unpacked(archive);
  if (!unpacked.ok()) {
    return ResultType::failure(evidence_error(
        "rebuild", "Nothing readable was found in " + path_to_utf8(archive.filename()) +
                       ". A collection archive should carry the collector's .log and .txt output."));
  }

  auto rebuilt = reconstruct_all_collected_evidence(unpacked.root());
  if (!rebuilt.ok()) {
    // The inner reason is the useful half, but it talks about a collection - the engineer picked a
    // FILE, and needs to know which one was rejected.
    return ResultType::failure(evidence_error(
        "rebuild", path_to_utf8(archive.filename()) + " could not be imported. " +
                       rebuilt.error().message));
  }
  // Provenance is the ARCHIVE. The directory this was read through is about to be deleted, and a
  // saved README naming it would point at nothing.
  for (auto& one : rebuilt.value())
    one.collection_root = archive;
  return rebuilt;
}

} // namespace

Result<std::vector<EvidenceReconstruction>> reconstruct_all_collected_evidence(
    const std::filesystem::path& root) {
  using ResultType = Result<std::vector<EvidenceReconstruction>>;

  std::error_code error;
  if (!std::filesystem::is_directory(root, error)) {
    // An archive holds its own collections, so it can yield several machines.
    if (path_is_archive(root))
      return reconstruct_from_archive(root);
    // A file, or one collection: the single-collection path already resolves either.
    auto single = reconstruct_collected_evidence(root);
    if (!single.ok())
      return ResultType::failure(single.error());
    return ResultType::success({std::move(single.value())});
  }

  // Every immediate child that is itself a collection. Checked before the root is treated as one,
  // because a folder holding three collections also "looks like" a collection from above.
  std::vector<std::filesystem::path> candidates;
  std::vector<std::filesystem::path> archives;
  for (const auto& entry : std::filesystem::directory_iterator(root, error)) {
    if (error)
      break;
    std::error_code entry_error;
    if (entry.is_directory(entry_error)) {
      if (looks_like_collection(entry.path()))
        candidates.push_back(entry.path());
      continue;
    }
    // A folder of zipped collections is how a set of machines usually arrives, now that a
    // collection removes its own staging directory once the zip is written.
    if (path_is_archive(entry.path()) && collected_evidence_archive_supported())
      archives.push_back(entry.path());
  }

  std::vector<EvidenceReconstruction> rebuilt;
  std::vector<std::string> failures;
  for (const auto& candidate : candidates) {
    auto one = reconstruct_collected_evidence(candidate);
    if (one.ok())
      rebuilt.push_back(std::move(one.value()));
    else
      failures.push_back(path_to_utf8(candidate.filename()) + ": " + one.error().message);
  }
  for (const auto& archive : archives) {
    auto inside = reconstruct_from_archive(archive);
    if (inside.ok()) {
      for (auto& one : inside.value())
        rebuilt.push_back(std::move(one));
    } else {
      failures.push_back(path_to_utf8(archive.filename()) + ": " + inside.error().message);
    }
  }

  if (!rebuilt.empty()) {
    // Two collections of the same machine - a first capture and a later one - are not two machines.
    // The later import wins, which is the same rule the case index applies.
    return ResultType::success(std::move(rebuilt));
  }

  // Nothing under it was a collection, so the folder itself has to be one.
  auto single = reconstruct_collected_evidence(root);
  if (single.ok())
    return ResultType::success({std::move(single.value())});

  std::string message = single.error().message;
  if (!failures.empty()) {
    message += " Collections found under it that could not be rebuilt: ";
    for (std::size_t index = 0; index < failures.size(); ++index) {
      if (index != 0U)
        message += "; ";
      message += failures[index];
    }
  }
  return ResultType::failure(evidence_error("rebuild", message));
}

Result<SavedEvidencePaths> save_reconstructed_evidence(const EvidenceReconstruction& rebuilt,
                                                       const std::filesystem::path& case_root) {
  if (case_root.empty()) {
    return Result<SavedEvidencePaths>::failure(evidence_error(
        "save", "Open a case first. The rebuilt reports are saved into the case so they can be "
                "reopened without walking the collection again."));
  }

  SavedEvidencePaths saved;
  // One folder per machine, so importing a second machine does not overwrite the first.
  saved.directory = reconstructed_evidence_directory(case_root) /
                    machine_directory_name(rebuilt.machine_name);
  std::error_code error;
  std::filesystem::create_directories(saved.directory, error);
  if (error) {
    return Result<SavedEvidencePaths>::failure(evidence_error(
        "save", "Could not create " + path_to_utf8(saved.directory) + ": " + error.message()));
  }

  if (rebuilt.environment_reconstructed) {
    saved.environment_log = saved.directory / "environment.log";
    std::ofstream output(saved.environment_log, std::ios::binary | std::ios::trunc);
    output << rebuilt.environment_text;
    output.flush();
    if (!output) {
      return Result<SavedEvidencePaths>::failure(evidence_error(
          "save", "Could not write " + path_to_utf8(saved.environment_log)));
    }
  }

  if (rebuilt.health_reconstructed) {
    const std::string machine =
        rebuilt.health.machine_name.empty() ? "Unknown" : rebuilt.health.machine_name;
    saved.health_report = saved.directory / (machine + "-SystemHealth.txt");
    std::ofstream output(saved.health_report, std::ios::binary | std::ios::trunc);
    output << format_system_health_report(rebuilt.health);
    output.flush();
    if (!output) {
      return Result<SavedEvidencePaths>::failure(evidence_error(
          "save", "Could not write " + path_to_utf8(saved.health_report)));
    }
  }

  // A note beside them, because in six months nobody will remember which collection these came
  // from or that they are a reconstruction rather than a live capture.
  {
    std::ofstream note(saved.directory / "README.txt", std::ios::binary | std::ios::trunc);
    note << "Rebuilt by Support Assist Tool from collected evidence.\n\n"
         << "Machine: " << (rebuilt.machine_name.empty() ? "Unknown" : rebuilt.machine_name)
         << (rebuilt.machine_name_inferred
                 ? "  (taken from the collection folder name - the evidence did not state it)"
                 : "")
         << "\n"
         << "Source collection: " << path_to_utf8(rebuilt.collection_root) << "\n"
         << "These are NOT a live capture of this machine. They were reconstructed from the files\n"
         << "in that collection, and the following could not be recovered from it:\n\n";
    for (const auto& gap : rebuilt.unavailable)
      note << "  - " << gap << "\n";
  }

  // The index is what lets a reopened case find this again, and what keeps two machines apart.
  // A machine already listed is REPLACED rather than added, so re-importing a newer collection
  // updates that machine instead of producing a second row for it.
  {
    auto machines = load_imported_machines(case_root);
    ImportedMachine row;
    row.machine_name = rebuilt.machine_name.empty() ? "Unknown" : rebuilt.machine_name;
    row.directory = saved.directory;
    row.environment_log = saved.environment_log;
    row.health_report = saved.health_report;
    row.source_collection = path_to_utf8(rebuilt.collection_root);
    row.imported_utc = utc_now_iso8601();

    const auto existing = std::find_if(machines.begin(), machines.end(), [&](const auto& entry) {
      return entry.machine_name == row.machine_name;
    });
    if (existing == machines.end())
      machines.push_back(std::move(row));
    else
      *existing = std::move(row);

    const auto index = imported_machine_index_path(case_root);
    std::ofstream out(index, std::ios::binary | std::ios::trunc);
    out << "# Support Assist Tool - machines imported into this case.\n"
        << "# machine\tdirectory\tenvironment.log\thealth report\tsource collection\timported (UTC)\n";
    for (const auto& entry : machines) {
      out << encode_index_field(entry.machine_name) << '\t'
          << encode_index_field(path_to_utf8(entry.directory)) << '\t'
          << encode_index_field(path_to_utf8(entry.environment_log)) << '\t'
          << encode_index_field(path_to_utf8(entry.health_report)) << '\t'
          << encode_index_field(entry.source_collection) << '\t'
          << encode_index_field(entry.imported_utc) << '\n';
    }
    out.flush();
    if (!out) {
      return Result<SavedEvidencePaths>::failure(evidence_error(
          "save", "The documents were written, but the case index could not be updated: " +
                      path_to_utf8(index)));
    }
  }

  return Result<SavedEvidencePaths>::success(std::move(saved));
}

} // namespace support_assist
