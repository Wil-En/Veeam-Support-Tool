// WMI health: the Winmgmt service, the repository, a timed probe of each namespace and the recent WMI
// faults, as rows of Stage, Finding, Detail and Status. Read-only: services are opened for query,
// the repository is verified (never salvaged or reset) and only while SAT is elevated, and the event
// logs are read. The rows, the data file and the decoding are shared by every platform; the checks
// themselves are Windows only.
#include "support_assist/wmi_health.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "support_assist/log_search.hpp"
#include "support_assist/process.hpp"
#include "support_assist/security.hpp"
#include "support_assist/wmi.hpp"

#include <windows.h>

#include <chrono>
#include <filesystem>
#include <system_error>
#endif

namespace support_assist {

namespace wmi_health_detail {

namespace {

constexpr std::uint32_t kAccessDenied = 0x80041003U;
constexpr std::uint32_t kInvalidNamespace = 0x8004100EU;
constexpr std::uint32_t kDcomAccessDenied = 0x80070005U;
constexpr std::uint32_t kRpcServerUnavailable = 0x800706BAU;

std::uint32_t code_of(std::int64_t hresult) {
  return static_cast<std::uint32_t>(hresult);
}

const HealthError* find_error(std::uint32_t code, const HealthData& data) {
  for (const HealthError& error : data.errors) {
    if (error.code == code)
      return &error;
  }
  return nullptr;
}

bool is_hex_digit(char character) {
  return std::isxdigit(static_cast<unsigned char>(character)) != 0;
}

// The position of the value after a field name: past spaces, '=', ':', quotes and '>'.
std::size_t value_start(std::string_view text, std::size_t after_name) {
  std::size_t index = after_name;
  while (index < text.size() && (text[index] == ' ' || text[index] == '=' || text[index] == ':' ||
                                 text[index] == '\'' || text[index] == '"' || text[index] == '>'))
    ++index;
  return index;
}

std::string with_thousands(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (std::size_t position = digits.size(); position > 3U; position -= 3U)
    digits.insert(position - 3U, ",");
  return digits;
}

std::string event_label(const HealthEvent& event) {
  return "Event " + std::to_string(event.id) + " (" + event.log + ")";
}

std::string newest_text(std::int64_t unix_millis) {
  return unix_millis > 0 ? readable_utc_from_unix_millis(unix_millis - unix_millis % 1000) : std::string("unknown");
}

} // namespace

HealthData parse_health_data(const JsonValue& value) {
  HealthData data;
  data.repository_limit_gb = value["repository_limit_gb"].as_number(4.0);
  data.slow_probe_ms = static_cast<std::int64_t>(value["slow_probe_ms"].as_number(2000.0));
  data.event_days = static_cast<int>(value["event_days"].as_number(7.0));
  for (const JsonValue& item : value["namespaces"].items()) {
    HealthNamespace entry;
    entry.name_space = item["namespace"].as_string();
    entry.role = item["role"].as_string();
    entry.why = item["why"].as_string();
    entry.probe = item["probe"].as_string();
    entry.absent_means = item["absent_means"].as_string();
    if (!entry.name_space.empty() && !entry.probe.empty())
      data.namespaces.push_back(std::move(entry));
  }
  for (const JsonValue& item : value["errors"].items()) {
    const auto code = parse_hex_code(item["code"].as_string());
    if (!code)
      continue;
    data.errors.push_back(
        {*code, item["name"].as_string(), item["meaning"].as_string(), item["routine"].as_bool(false)});
  }
  for (const JsonValue& item : value["events"].items()) {
    HealthEvent event;
    event.log = item["log"].as_string();
    event.provider = item["provider"].as_string();
    event.id = static_cast<std::uint32_t>(item["id"].as_number());
    event.meaning = item["meaning"].as_string();
    if (!event.log.empty() && event.id != 0U)
      data.events.push_back(std::move(event));
  }
  return data;
}

const HealthData& health_data() {
  static const HealthData data = parse_health_data(data_file("wmi-health.json"));
  return data;
}

std::string hresult_text(std::int64_t hresult) {
  char buffer[16];
  std::snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<unsigned int>(code_of(hresult)));
  return buffer;
}

std::optional<std::uint32_t> parse_hex_code(std::string_view text) {
  const std::string trimmed = trim(text);
  if (trimmed.size() < 3U || trimmed[0] != '0' || (trimmed[1] != 'x' && trimmed[1] != 'X'))
    return std::nullopt;
  std::uint64_t value = 0;
  std::size_t digits = 0;
  for (std::size_t index = 2; index < trimmed.size(); ++index) {
    const char character = trimmed[index];
    if (!is_hex_digit(character) || ++digits > 8U)
      return std::nullopt;
    value = value * 16U + static_cast<std::uint64_t>(std::isdigit(static_cast<unsigned char>(character)) != 0
                                                          ? character - '0'
                                                          : std::toupper(static_cast<unsigned char>(character)) - 'A' + 10);
  }
  return static_cast<std::uint32_t>(value);
}

std::string decode_wmi_error(std::int64_t hresult, const HealthData& data) {
  const std::string code = hresult_text(hresult);
  if (const HealthError* known = find_error(code_of(hresult), data))
    return code + " " + known->name + ": " + known->meaning;
  return code;
}

std::optional<std::uint32_t> result_code_from_message(std::string_view message) {
  constexpr std::string_view kName = "ResultCode";
  for (std::size_t at = message.find(kName); at != std::string_view::npos; at = message.find(kName, at + 1U)) {
    const std::size_t start = value_start(message, at + kName.size());
    if (start + 2U >= message.size() || message[start] != '0' || (message[start + 1U] != 'x' && message[start + 1U] != 'X'))
      continue;
    std::size_t end = start + 2U;
    while (end < message.size() && is_hex_digit(message[end]))
      ++end;
    if (const auto code = parse_hex_code(message.substr(start, end - start)))
      return code;
  }
  return std::nullopt;
}

std::optional<std::uint32_t> client_process_from_message(std::string_view message) {
  constexpr std::string_view kName = "ClientProcessId";
  for (std::size_t at = message.find(kName); at != std::string_view::npos; at = message.find(kName, at + 1U)) {
    const std::size_t start = value_start(message, at + kName.size());
    std::uint64_t value = 0;
    std::size_t end = start;
    while (end < message.size() && message[end] >= '0' && message[end] <= '9' && end - start < 10U) {
      value = value * 10U + static_cast<std::uint64_t>(message[end] - '0');
      ++end;
    }
    if (end > start && value <= 0xFFFFFFFFULL)
      return static_cast<std::uint32_t>(value);
  }
  return std::nullopt;
}

std::string first_line(std::string_view text) {
  const std::size_t end = text.find_first_of("\r\n");
  return trim(text.substr(0, end));
}

std::vector<FaultGroup> group_by_result_code(const std::vector<FaultEvent>& events) {
  std::map<std::uint32_t, FaultGroup> coded;
  FaultGroup uncoded;
  for (const FaultEvent& event : events) {
    const auto code = result_code_from_message(event.message);
    FaultGroup& group = code ? coded[*code] : uncoded;
    group.result_code = code;
    ++group.count;
    if (group.count == 1U || event.time_unix_millis > group.newest_unix_millis) {
      group.newest_unix_millis = event.time_unix_millis;
      group.newest_message = event.message;
    }
  }
  std::vector<FaultGroup> groups;
  for (auto& [code, group] : coded)
    groups.push_back(std::move(group));
  std::stable_sort(groups.begin(), groups.end(),
                   [](const FaultGroup& left, const FaultGroup& right) { return left.count > right.count; });
  if (uncoded.count != 0U)
    groups.push_back(std::move(uncoded));
  return groups;
}

std::vector<WmiHealthRow> fault_rows(const HealthEvent& event, const std::vector<FaultEvent>& events,
                                     std::size_t left_out, const HealthData& data) {
  const std::string window = "in the last " + std::to_string(data.event_days) + " days";
  const std::string left_out_text =
      left_out == 0U ? std::string()
                     : " Left out: " + std::to_string(left_out) + " from this SAT process's own WMI queries.";
  std::vector<WmiHealthRow> rows;
  if (events.empty()) {
    rows.push_back({"Recent faults", event_label(event), "None " + window + "." + left_out_text, kWmiHealthPass});
    return rows;
  }
  for (const FaultGroup& group : group_by_result_code(events)) {
    WmiHealthRow row;
    row.stage = "Recent faults";
    row.status = kWmiHealthFinding;
    std::string meaning = event.meaning;
    if (group.result_code) {
      const std::int64_t code = static_cast<std::int64_t>(*group.result_code);
      row.finding = "Event " + std::to_string(event.id) + ", ResultCode " + hresult_text(code);
      if (const HealthError* known = find_error(*group.result_code, data)) {
        row.finding += " " + known->name;
        meaning = known->meaning;
        if (known->routine)
          row.status = kWmiHealthRoutine;
      }
    } else {
      row.finding = event_label(event);
    }
    row.detail = with_thousands(group.count) + " " + window + ", newest " + newest_text(group.newest_unix_millis) +
                 ". " + meaning + (rows.empty() ? left_out_text : std::string()) +
                 " Newest: " + first_line(group.newest_message);
    rows.push_back(std::move(row));
  }
  return rows;
}

bool signature_has_provider(std::string_view signature, std::string_view provider) {
  constexpr std::string_view kKey = "provider:";
  const std::size_t at = signature.find(kKey);
  if (at == std::string_view::npos)
    return false;
  std::string_view named = signature.substr(at + kKey.size());
  named = named.substr(0, named.find(';'));
  return ascii_lower(named) == ascii_lower(provider);
}

std::string size_text(std::uint64_t bytes) {
  constexpr double kKilobyte = 1024.0;
  const double value = static_cast<double>(bytes);
  char buffer[32];
  if (value >= kKilobyte * kKilobyte * kKilobyte)
    std::snprintf(buffer, sizeof(buffer), "%.2f GB", value / (kKilobyte * kKilobyte * kKilobyte));
  else if (value >= kKilobyte * kKilobyte)
    std::snprintf(buffer, sizeof(buffer), "%.1f MB", value / (kKilobyte * kKilobyte));
  else if (value >= kKilobyte)
    std::snprintf(buffer, sizeof(buffer), "%.1f KB", value / kKilobyte);
  else
    std::snprintf(buffer, sizeof(buffer), "%llu bytes", static_cast<unsigned long long>(bytes));
  return buffer;
}

WmiHealthRow repository_size_row(std::uint64_t bytes, double limit_gb) {
  const double limit_bytes = limit_gb * 1024.0 * 1024.0 * 1024.0;
  const double share = limit_bytes > 0.0 ? static_cast<double>(bytes) / limit_bytes : 0.0;
  char limit[32];
  std::snprintf(limit, sizeof(limit), "%g GB", limit_gb);
  WmiHealthRow row;
  row.stage = "Repository";
  row.finding = "Size";
  row.detail = size_text(bytes) + " of the " + limit + " limit (" +
               std::to_string(static_cast<long long>(std::floor(share * 100.0))) + "%).";
  if (share >= 0.9) {
    row.status = kWmiHealthFinding;
    row.detail += " At the limit WMI returns WBEM_E_OUT_OF_DISK_SPACE (0x8004103B).";
  } else {
    row.status = kWmiHealthPass;
  }
  return row;
}

WmiHealthRow probe_row(const HealthNamespace& name_space, bool succeeded, std::int64_t hresult,
                       std::string_view operation, std::string_view error_text, std::int64_t elapsed_ms,
                       const HealthData& data) {
  WmiHealthRow row;
  row.stage = "Namespaces";
  row.finding = name_space.name_space + (name_space.role.empty() ? std::string() : " (" + name_space.role + ")");
  if (succeeded) {
    if (elapsed_ms > data.slow_probe_ms) {
      row.status = kWmiHealthFinding;
      row.detail = "Answered in " + milliseconds_text(elapsed_ms) + ", slower than " +
                   milliseconds_text(data.slow_probe_ms) + ". " + name_space.why;
    } else {
      row.status = kWmiHealthPass;
      row.detail = "Answered in " + milliseconds_text(elapsed_ms) + ". " + name_space.why;
    }
    return row;
  }
  const std::uint32_t code = code_of(hresult);
  if (code == kInvalidNamespace) {
    row.status = kWmiHealthNotPresent;
    row.detail = name_space.absent_means.empty() ? "The namespace is not on the machine." : name_space.absent_means;
    return row;
  }
  const std::string where = operation.empty() ? std::string() : "The " + std::string(operation) + " step failed: ";
  if (code == kAccessDenied || code == kDcomAccessDenied) {
    row.status = kWmiHealthNeedsAdministrator;
    row.detail = where + decode_wmi_error(hresult, data);
    return row;
  }
  row.status = kWmiHealthFinding;
  if (hresult == 0) {
    row.detail = std::string(error_text);
  } else if (find_error(code, data) != nullptr) {
    row.detail = where + decode_wmi_error(hresult, data);
  } else {
    row.detail = std::string(error_text);
  }
  return row;
}

bool stops_probes(std::int64_t hresult) {
  return code_of(hresult) == kRpcServerUnavailable;
}

std::string milliseconds_text(std::int64_t milliseconds) {
  return with_thousands(static_cast<std::uint64_t>(std::max<std::int64_t>(milliseconds, 0))) + " ms";
}

std::string service_state_text(unsigned long state) {
  switch (state) {
  case 1: return "Stopped";
  case 2: return "Starting";
  case 3: return "Stopping";
  case 4: return "Running";
  case 5: return "Continuing";
  case 6: return "Pausing";
  case 7: return "Paused";
  default: return "State " + std::to_string(state);
  }
}

std::string start_type_text(unsigned long start_type, bool delayed) {
  switch (start_type) {
  case 0: return "Boot";
  case 1: return "System";
  case 2: return delayed ? "Automatic (Delayed Start)" : "Automatic";
  case 3: return "Manual";
  case 4: return "Disabled";
  default: return "Start type " + std::to_string(start_type);
  }
}

bool service_is_finding(unsigned long state, unsigned long start_type) {
  return state != 4UL || start_type == 4UL;
}

bool is_this_machine(std::string_view machine, const std::vector<std::string>& own_names) {
  std::string name = ascii_lower(trim(machine));
  while (!name.empty() && (name.front() == '\\' || name.front() == '/'))
    name.erase(name.begin());
  if (name.empty() || name == "." || name == "localhost" || name == "127.0.0.1" || name == "::1")
    return true;
  return std::any_of(own_names.begin(), own_names.end(),
                     [&](const std::string& own) { return !own.empty() && ascii_lower(own) == name; });
}

} // namespace wmi_health_detail

std::string wmi_error_meaning(std::int64_t hresult) {
  const auto& data = wmi_health_detail::health_data();
  for (const auto& error : data.errors) {
    if (error.code == static_cast<std::uint32_t>(hresult))
      return error.name + ": " + error.meaning;
  }
  return {};
}

bool wmi_health_has_finding(const WmiHealthReport& report) {
  return std::any_of(report.rows.begin(), report.rows.end(),
                     [](const WmiHealthRow& row) { return row.status == kWmiHealthFinding; });
}

std::string wmi_health_summary(const WmiHealthReport& report) {
  std::string summary = "WMI health on " + (report.this_machine ? std::string("this machine") : report.machine) + ":";
  bool first = true;
  for (const char* status : {kWmiHealthPass, kWmiHealthFinding, kWmiHealthRoutine, kWmiHealthNotPresent,
                             kWmiHealthNeedsAdministrator, kWmiHealthThisMachineOnly}) {
    const auto count = std::count_if(report.rows.begin(), report.rows.end(),
                                     [&](const WmiHealthRow& row) { return row.status == status; });
    if (count == 0)
      continue;
    summary += (first ? " " : ", ") + std::to_string(count) + " " + status;
    first = false;
  }
  if (first)
    summary += " nothing checked";
  if (report.cancelled)
    summary += " (stopped before the end)";
  return summary + ".";
}

#ifdef _WIN32

namespace {

using namespace wmi_health_detail;

std::string system_message(DWORD code) {
  wchar_t* buffer = nullptr;
  const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                          FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
  std::string text;
  if (length != 0U && buffer != nullptr)
    text = trim(utf8_from_wide(std::wstring_view(buffer, length)));
  if (buffer != nullptr)
    LocalFree(buffer);
  while (!text.empty() && text.back() == '.')
    text.pop_back();
  return text.empty() ? "Windows error " + std::to_string(code) : text + " (error " + std::to_string(code) + ")";
}

std::vector<std::string> own_computer_names() {
  std::vector<std::string> names;
  for (const COMPUTER_NAME_FORMAT format : {ComputerNameNetBIOS, ComputerNameDnsHostname, ComputerNameDnsFullyQualified}) {
    wchar_t buffer[256]{};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));
    if (GetComputerNameExW(format, buffer, &size) != FALSE && size != 0U)
      names.push_back(utf8_from_wide(std::wstring_view(buffer, size)));
  }
  return names;
}

// A console program's text: UTF-8 when it is valid, else the OEM code page; one line per line.
std::string console_text(const std::string& bytes) {
  std::wstring wide;
  const int strict = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, bytes.data(), static_cast<int>(bytes.size()),
                                         nullptr, 0);
  const UINT page = strict > 0 ? CP_UTF8 : CP_OEMCP;
  const int length = MultiByteToWideChar(page, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
  if (length > 0) {
    wide.resize(static_cast<std::size_t>(length));
    MultiByteToWideChar(page, 0, bytes.data(), static_cast<int>(bytes.size()), wide.data(), length);
  }
  std::string joined;
  for (std::string line : split(utf8_from_wide(wide), '\n')) {
    std::replace(line.begin(), line.end(), '\t', ' ');
    line = trim(line);
    if (line.empty())
      continue;
    joined += (joined.empty() ? "" : "; ") + line;
  }
  return joined;
}

struct ServiceReading {
  DWORD error = ERROR_SUCCESS;
  DWORD state = 0;
  DWORD start_type = 0;
  bool delayed = false;
  std::string display_name;
  std::vector<std::wstring> dependencies; // a load order group starts with SC_GROUP_IDENTIFIER
};

ServiceReading read_service(SC_HANDLE manager, const std::wstring& name) {
  ServiceReading reading;
  SC_HANDLE service = OpenServiceW(manager, name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  if (service == nullptr) {
    reading.error = GetLastError();
    return reading;
  }
  SERVICE_STATUS_PROCESS status{};
  DWORD needed = 0;
  if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status),
                           &needed) == FALSE) {
    reading.error = GetLastError();
    CloseServiceHandle(service);
    return reading;
  }
  reading.state = status.dwCurrentState;
  needed = 0;
  QueryServiceConfigW(service, nullptr, 0, &needed);
  if (needed != 0U) {
    std::vector<std::uint8_t> buffer(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (QueryServiceConfigW(service, config, needed, &needed) != FALSE) {
      reading.start_type = config->dwStartType;
      if (config->lpDisplayName != nullptr)
        reading.display_name = utf8_from_wide(config->lpDisplayName);
      for (const wchar_t* entry = config->lpDependencies; entry != nullptr && *entry != L'\0';
           entry += wcslen(entry) + 1U)
        reading.dependencies.emplace_back(entry);
    } else {
      reading.error = GetLastError();
    }
  }
  SERVICE_DELAYED_AUTO_START_INFO delayed{};
  if (QueryServiceConfig2W(service, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, reinterpret_cast<LPBYTE>(&delayed),
                           sizeof(delayed), &needed) != FALSE)
    reading.delayed = delayed.fDelayedAutostart != FALSE;
  CloseServiceHandle(service);
  return reading;
}

std::string service_finding(const std::wstring& name, const ServiceReading& reading) {
  const std::string service = utf8_from_wide(name);
  return reading.display_name.empty() || reading.display_name == service ? service
                                                                          : service + " (" + reading.display_name + ")";
}

WmiHealthRow service_row(const std::wstring& name, const ServiceReading& reading, const std::string& needed_by,
                         const std::string& where) {
  WmiHealthRow row;
  row.stage = "Service";
  row.finding = service_finding(name, reading);
  if (reading.error != ERROR_SUCCESS) {
    row.status = reading.error == ERROR_ACCESS_DENIED ? kWmiHealthNeedsAdministrator : kWmiHealthFinding;
    row.detail = reading.error == ERROR_SERVICE_DOES_NOT_EXIST
                     ? "The service is not registered on " + where + "."
                     : "The service could not be read: " + system_message(reading.error) + ".";
    return row;
  }
  row.status = service_is_finding(reading.state, reading.start_type) ? kWmiHealthFinding : kWmiHealthPass;
  row.detail = service_state_text(reading.state) + ". Start type: " + start_type_text(reading.start_type, reading.delayed) + ".";
  if (!needed_by.empty())
    row.detail += " " + needed_by + " depends on it.";
  return row;
}

void service_stage(WmiHealthReport& report, const std::string& machine, const std::string& where) {
  const std::wstring target = wide_from_utf8(machine);
  SC_HANDLE manager = OpenSCManagerW(report.this_machine ? nullptr : target.c_str(), nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    const DWORD code = GetLastError();
    report.rows.push_back({"Service", "Service manager",
                           "The service manager on " + where + " did not open: " + system_message(code) + ".",
                           code == ERROR_ACCESS_DENIED ? kWmiHealthNeedsAdministrator : kWmiHealthFinding});
    return;
  }
  const ServiceReading winmgmt = read_service(manager, L"Winmgmt");
  WmiHealthRow first = service_row(L"Winmgmt", winmgmt, {}, where);
  std::vector<std::wstring> services;
  std::vector<std::string> named;
  for (const std::wstring& dependency : winmgmt.dependencies) {
    if (!dependency.empty() && dependency.front() == SC_GROUP_IDENTIFIERW) {
      named.push_back("the " + utf8_from_wide(std::wstring_view(dependency).substr(1)) + " group");
    } else {
      services.push_back(dependency);
      named.push_back(utf8_from_wide(dependency));
    }
  }
  if (winmgmt.error == ERROR_SUCCESS) {
    std::string list;
    for (const std::string& name : named)
      list += (list.empty() ? "" : ", ") + name;
    first.detail += named.empty() ? " It depends on no other service." : " It depends on " + list + ".";
  }
  report.rows.push_back(std::move(first));
  for (const std::wstring& dependency : services)
    report.rows.push_back(service_row(dependency, read_service(manager, dependency), "Winmgmt", where));
  CloseServiceHandle(manager);
}

std::filesystem::path windows_directory() {
  wchar_t buffer[MAX_PATH]{};
  const UINT length = GetSystemWindowsDirectoryW(buffer, MAX_PATH);
  if (length == 0U || length >= MAX_PATH)
    return std::filesystem::path(L"C:\\Windows");
  return std::filesystem::path(std::wstring(buffer, length));
}

void repository_stage(WmiHealthReport& report, const HealthData& data, const CancellationToken& cancel) {
  const std::filesystem::path wbem = windows_directory() / L"System32" / L"wbem";
  if (report.elevated) {
    ProcessOptions options;
    options.executable = wbem / L"winmgmt.exe";
    options.arguments = {"/verifyrepository"};
    options.timeout = std::chrono::milliseconds(60000);
    options.merge_standard_error = true;
    WmiHealthRow row{"Repository", "Consistency", {}, kWmiHealthFinding};
    const std::string repair = " For an inconsistent repository Microsoft documents winmgmt /salvagerepository, "
                               "then winmgmt /resetrepository.";
    auto ran = run_process_capture(options, cancel);
    if (!ran.ok()) {
      row.detail = "winmgmt /verifyrepository did not start: " + describe_error(ran.error());
    } else if (ran.value().cancelled) {
      report.cancelled = true;
      return;
    } else if (ran.value().timed_out) {
      row.detail = "winmgmt /verifyrepository did not finish within 60 seconds.";
    } else {
      const std::string said = console_text(ran.value().output);
      if (ran.value().exit_code == 0) {
        row.status = kWmiHealthPass;
        row.detail = "winmgmt /verifyrepository exited with 0, consistent." + (said.empty() ? "" : " It said: " + said);
      } else {
        row.detail = "winmgmt /verifyrepository exited with " + std::to_string(ran.value().exit_code) + "." +
                     (said.empty() ? "" : " It said: " + said) + repair;
      }
    }
    report.rows.push_back(std::move(row));
  } else {
    report.rows.push_back({"Repository", "Consistency",
                           "winmgmt /verifyrepository needs administrator. Run SAT as administrator to include it.",
                           kWmiHealthNeedsAdministrator});
  }

  const std::filesystem::path repository = wbem / L"Repository";
  std::error_code error;
  std::uint64_t bytes = 0;
  std::filesystem::recursive_directory_iterator walk(repository, std::filesystem::directory_options::skip_permission_denied,
                                                     error);
  const std::filesystem::recursive_directory_iterator end{};
  if (error && walk == end) {
    const bool denied = error == std::errc::permission_denied || error.value() == ERROR_ACCESS_DENIED;
    report.rows.push_back({"Repository", "Size",
                           path_to_utf8(repository) + " could not be read: " +
                               system_message(static_cast<DWORD>(error.value())) + ".",
                           denied ? kWmiHealthNeedsAdministrator : kWmiHealthFinding});
    return;
  }
  for (; walk != end; walk.increment(error)) {
    if (error)
      break;
    std::error_code entry_error;
    if (walk->is_regular_file(entry_error)) {
      // file_size gives (uintmax_t)-1 on failure.
      const std::uintmax_t file_bytes = walk->file_size(entry_error);
      if (file_bytes != static_cast<std::uintmax_t>(-1))
        bytes += file_bytes;
    }
  }
  WmiHealthRow size = repository_size_row(bytes, data.repository_limit_gb);
  size.detail = path_to_utf8(repository) + ": " + size.detail;
  report.rows.push_back(std::move(size));
}

void namespace_stage(WmiHealthReport& report, const std::string& machine, const HealthData& data,
                     const CancellationToken& cancel) {
  for (std::size_t index = 0; index < data.namespaces.size(); ++index) {
    if (cancel.is_cancelled()) {
      report.cancelled = true;
      return;
    }
    const HealthNamespace& entry = data.namespaces[index];
    WmiQueryOptions options;
    options.machine = report.this_machine ? std::string(".") : machine;
    options.name_space = entry.name_space;
    options.query = entry.probe;
    options.maximum_rows = 1;
    const auto started = std::chrono::steady_clock::now();
    auto probed = query_wmi(options, cancel);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    if (!probed.ok()) {
      const Error& failure = probed.error();
      WmiHealthRow row = probe_row(entry, false, failure.hresult, failure.operation, describe_error(failure),
                                   elapsed.count(), data);
      if (stops_probes(failure.hresult) && index + 1U < data.namespaces.size()) {
        row.detail += " The other namespaces were not probed.";
        report.rows.push_back(std::move(row));
        return;
      }
      report.rows.push_back(std::move(row));
      continue;
    }
    report.rows.push_back(probe_row(entry, true, 0, {}, {}, elapsed.count(), data));
  }
}

void faults_stage(WmiHealthReport& report, const HealthData& data, const CancellationToken& cancel) {
  const std::int64_t now = unix_millis_now();
  const std::int64_t from = now - static_cast<std::int64_t>(data.event_days) * 86400000LL;
  const std::uint32_t own_process = GetCurrentProcessId();
  for (const HealthEvent& event : data.events) {
    if (cancel.is_cancelled()) {
      report.cancelled = true;
      return;
    }
    WindowsEventLogSearchOptions options;
    options.channel = event.log;
    options.event_ids = {event.id};
    options.from_utc_ms = from;
    std::vector<FaultEvent> found;
    std::size_t left_out = 0;
    auto searched = search_windows_event_log(options, cancel, {}, [&](const LogMatch& match) {
      if (!event.provider.empty() && !signature_has_provider(match.signature, event.provider))
        return Status::success();
      if (client_process_from_message(match.matching_line) == own_process) {
        ++left_out;
        return Status::success();
      }
      found.push_back({match.timestamp_utc_ms.value_or(0), match.matching_line});
      return Status::success();
    });
    if (!searched.ok()) {
      const auto code = static_cast<DWORD>(searched.error().native_code);
      const std::string label = "Event " + std::to_string(event.id) + " (" + event.log + ")";
      if (code == ERROR_ACCESS_DENIED)
        report.rows.push_back({"Recent faults", label, "This account cannot read the " + event.log + " log.",
                               kWmiHealthNeedsAdministrator});
      else if (code == ERROR_EVT_CHANNEL_NOT_FOUND)
        report.rows.push_back({"Recent faults", label, "The " + event.log + " log is not on this machine.",
                               kWmiHealthNotPresent});
      else
        report.rows.push_back({"Recent faults", label, describe_error(searched.error()), kWmiHealthFinding});
      continue;
    }
    for (WmiHealthRow& row : fault_rows(event, found, left_out, data))
      report.rows.push_back(std::move(row));
  }
}

// The machine itself, as the host test read it: its name, its Windows and its last start. A
// machine WMI does not answer for fails here first.
void host_stage(WmiHealthReport& report, const std::string& machine, const CancellationToken& cancel) {
  WmiQueryOptions query = make_host_wmi_preset(machine);
  query.maximum_rows = 1;
  auto rows = query_wmi(query, cancel);
  if (!rows.ok()) {
    WmiHealthRow row{"Host", "Windows", describe_error(rows.error()), kWmiHealthFinding};
    if (const std::string meaning = wmi_error_meaning(rows.error().hresult); !meaning.empty())
      row.detail += " " + meaning;
    report.rows.push_back(std::move(row));
    return;
  }
  if (rows.value().empty()) {
    report.rows.push_back({"Host", "Windows", "WMI returned no operating system.", kWmiHealthFinding});
    return;
  }
  const auto& values = rows.value().front().values;
  const auto value = [&values](const char* key) {
    const auto found = values.find(key);
    return found == values.end() ? std::string() : found->second;
  };
  report.rows.push_back({"Host", "Name", value("CSName"), kWmiHealthPass});
  report.rows.push_back({"Host", "Windows",
                         value("Caption") + ", version " + value("Version") + " (build " + value("BuildNumber") +
                             "), " + value("OSArchitecture"),
                         kWmiHealthPass});
  report.rows.push_back({"Host", "Last start", value("LastBootUpTime"), kWmiHealthPass});
}

void stage_progress(const ProgressCallback& progress, const char* stage, std::uint64_t index) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = "WMI health";
  event.current_scope = stage;
  event.processed = index;
  event.total = 5;
  progress(event);
}

} // namespace

bool is_this_computer(std::string_view machine) {
  return is_this_machine(machine, own_computer_names());
}

Result<WmiHealthReport> run_wmi_health(const WmiHealthOptions& options, const CancellationToken& cancel,
                                       ProgressCallback progress) {
  const HealthData& data = health_data();
  WmiHealthReport report;
  report.machine = trim(options.machine);
  while (!report.machine.empty() && (report.machine.front() == '\\' || report.machine.front() == '/'))
    report.machine.erase(report.machine.begin());
  if (report.machine.empty())
    report.machine = ".";
  report.this_machine = is_this_machine(report.machine, own_computer_names());
  const auto context = current_security_context();
  report.elevated = context.ok() && context.value().elevated;
  const std::string where = report.this_machine ? std::string("this machine") : report.machine;

  stage_progress(progress, "Host", 1);
  host_stage(report, report.machine, cancel);
  if (cancel.is_cancelled()) {
    report.cancelled = true;
    return Result<WmiHealthReport>::success(std::move(report));
  }

  stage_progress(progress, "Service", 2);
  service_stage(report, report.machine, where);
  if (cancel.is_cancelled()) {
    report.cancelled = true;
    return Result<WmiHealthReport>::success(std::move(report));
  }

  stage_progress(progress, "Repository", 3);
  if (report.this_machine)
    repository_stage(report, data, cancel);
  else
    report.rows.push_back({"Repository", "Consistency and size",
                           "The repository is read on the machine itself. Run WMI health on " + report.machine +
                               " to include it.",
                           kWmiHealthThisMachineOnly});
  if (cancel.is_cancelled() || report.cancelled) {
    report.cancelled = true;
    return Result<WmiHealthReport>::success(std::move(report));
  }

  stage_progress(progress, "Namespaces", 4);
  namespace_stage(report, report.machine, data, cancel);
  if (cancel.is_cancelled() || report.cancelled) {
    report.cancelled = true;
    return Result<WmiHealthReport>::success(std::move(report));
  }

  stage_progress(progress, "Recent faults", 5);
  if (report.this_machine)
    faults_stage(report, data, cancel);
  else
    report.rows.push_back({"Recent faults", "WMI events",
                           "The event logs are read on the machine itself. Run WMI health on " + report.machine +
                               " to include them.",
                           kWmiHealthThisMachineOnly});
  if (cancel.is_cancelled())
    report.cancelled = true;
  return Result<WmiHealthReport>::success(std::move(report));
}

#else

bool is_this_computer(std::string_view machine) {
  return wmi_health_detail::is_this_machine(machine, {});
}

Result<WmiHealthReport> run_wmi_health(const WmiHealthOptions& options, const CancellationToken& cancel,
                                       ProgressCallback progress) {
  static_cast<void>(options);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  Error error;
  error.component = "WMI";
  error.operation = "health";
  error.message = "WMI health is a Windows check: it reads the WMI service, repository, namespaces and event logs of a "
                  "Windows machine.";
  return Result<WmiHealthReport>::failure(std::move(error));
}

#endif

} // namespace support_assist
