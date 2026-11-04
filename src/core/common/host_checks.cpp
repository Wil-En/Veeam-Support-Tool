// Host Checks: read-only checks of what most often explains a failed snapshot or backup, as rows of
// Group, Check, Detail and Status. The data file, the rows and the plain readings are shared; the
// Windows groups read the event logs, the service manager, WMI and the registry, and the Linux
// groups read /proc, /sys, /lib/modules, /var/lib/dkms and the kernel log file.
#include "support_assist/host_checks.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <utility>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "support_assist/log_search.hpp"
#include "support_assist/wmi.hpp"

#include <windows.h>
#else
#include <sys/utsname.h>
#endif

namespace support_assist {

namespace {

struct HostEvent {
  std::string log;
  std::vector<std::string> providers;
  std::uint32_t id = 0;
  std::vector<std::string> levels; // empty counts every level
  std::string meaning;
  std::string source;
};

struct Signature {
  std::string text;
  std::string meaning;
};

struct HostData {
  std::vector<HostCheckGroup> groups;
  int event_days = 7;
  std::vector<HostEvent> events;
  std::string driver_prefix = "Veeam";
  std::string cbt_store;
  std::vector<std::string> linux_modules;
  std::uint32_t dotnet_minimum = 0;
  std::string dotnet_minimum_name;
  std::string dotnet_source;
  std::vector<std::pair<std::uint32_t, std::string>> dotnet_releases; // newest first
  std::vector<std::string> tls_protocols;
  std::string tls_required;
  std::vector<std::string> kernel_logs;
  std::uint64_t kernel_log_bytes = 16U * 1024U * 1024U;
  std::vector<Signature> kernel_signatures;
};

HostData parse_data(const JsonValue& value) {
  HostData data;
  for (const JsonValue& item : value["groups"].items()) {
    data.groups.push_back({item["id"].as_string(), item["title"].as_string(), item["description"].as_string(),
                           item["platform"].as_string(), item["needs_admin"].as_bool(false)});
  }
  data.event_days = static_cast<int>(value["event_days"].as_number(7.0));
  for (const JsonValue& item : value["events"].items()) {
    HostEvent event;
    event.log = item["log"].as_string();
    event.providers = item["providers"].string_items();
    event.id = static_cast<std::uint32_t>(item["id"].as_number());
    event.levels = item["levels"].string_items();
    event.meaning = item["meaning"].as_string();
    event.source = item["source"].as_string();
    data.events.push_back(std::move(event));
  }
  data.driver_prefix = value["windows_driver_prefix"].as_string();
  data.cbt_store = value["windows_cbt_store"].as_string();
  data.linux_modules = value["linux_modules"].string_items();
  data.dotnet_minimum = static_cast<std::uint32_t>(value["dotnet_minimum"]["release"].as_number());
  data.dotnet_minimum_name = value["dotnet_minimum"]["name"].as_string();
  data.dotnet_source = value["dotnet_minimum"]["source"].as_string();
  for (const JsonValue& item : value["dotnet_releases"].items())
    data.dotnet_releases.emplace_back(static_cast<std::uint32_t>(item["release"].as_number()), item["name"].as_string());
  std::sort(data.dotnet_releases.begin(), data.dotnet_releases.end(),
            [](const auto& left, const auto& right) { return left.first > right.first; });
  data.tls_protocols = value["tls_protocols"].string_items();
  data.tls_required = value["tls_required"].as_string();
  data.kernel_logs = value["kernel_logs"].string_items();
  data.kernel_log_bytes = static_cast<std::uint64_t>(value["kernel_log_bytes"].as_number(16777216.0));
  for (const JsonValue& item : value["kernel_signatures"].items())
    data.kernel_signatures.push_back({item["text"].as_string(), item["meaning"].as_string()});
  return data;
}

const HostData& host_data() {
  static const HostData data = parse_data(data_file("host-checks.json"));
  return data;
}

void report_progress(const ProgressCallback& progress, const std::string& group, std::uint64_t index,
                     std::uint64_t total) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = "Host Checks";
  event.current_scope = group;
  event.processed = index;
  event.total = total;
  progress(event);
}

std::string with_thousands(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (std::size_t position = digits.size(); position > 3U; position -= 3U)
    digits.insert(position - 3U, ",");
  return digits;
}

bool platform_matches(const std::string& platform) {
#ifdef _WIN32
  return platform == "windows" || platform == "both";
#else
  return platform == "linux" || platform == "both";
#endif
}

#ifdef _WIN32

std::string utc_text(std::int64_t millis) {
  return millis > 0 ? readable_utc_from_unix_millis(millis - millis % 1000) : std::string("an unknown time");
}

void events_group(const HostData& data, int days, const std::string& title, const CancellationToken& cancel,
                  std::vector<HostCheckRow>& rows) {
  struct Count {
    std::uint64_t count = 0;
    std::int64_t first = 0;
    std::int64_t newest = 0;
    std::string newest_text;
  };
  std::vector<Count> counts(data.events.size());
  const std::int64_t from = unix_millis_now() - static_cast<std::int64_t>(days) * 86400000LL;
  std::vector<std::string> logs;
  for (const HostEvent& event : data.events) {
    if (std::find(logs.begin(), logs.end(), event.log) == logs.end())
      logs.push_back(event.log);
  }
  std::vector<std::string> unread;
  for (const std::string& log : logs) {
    WindowsEventLogSearchOptions options;
    options.channel = log;
    options.from_utc_ms = from;
    for (const HostEvent& event : data.events) {
      if (event.log == log)
        options.event_ids.push_back(event.id);
    }
    auto searched = search_windows_event_log(options, cancel, {}, [&](const LogMatch& match) {
      // The signature is "event-id:N;provider:NAME".
      const std::size_t id_at = match.signature.find("event-id:");
      const std::size_t provider_at = match.signature.find("provider:");
      if (id_at == std::string::npos)
        return Status::success();
      const auto id = static_cast<std::uint32_t>(std::strtoul(match.signature.c_str() + id_at + 9, nullptr, 10));
      const std::string provider =
          provider_at == std::string::npos ? std::string() : ascii_lower(match.signature.substr(provider_at + 9));
      const std::int64_t at = match.timestamp_utc_ms.value_or(0);
      for (std::size_t index = 0; index < data.events.size(); ++index) {
        const HostEvent& event = data.events[index];
        if (event.log != log || event.id != id)
          continue;
        if (!event.providers.empty() &&
            std::none_of(event.providers.begin(), event.providers.end(),
                         [&](const std::string& name) { return ascii_lower(name) == provider; }))
          continue;
        if (!event.levels.empty() &&
            std::none_of(event.levels.begin(), event.levels.end(),
                         [&](const std::string& level) { return ascii_lower(match.severity) == level; }))
          continue;
        Count& count = counts[index];
        ++count.count;
        if (count.first == 0 || (at > 0 && at < count.first))
          count.first = at;
        if (at >= count.newest) {
          count.newest = at;
          count.newest_text = match.matching_line;
        }
      }
      return Status::success();
    });
    // A stopped search has counted only part of the log, so no row is made from it.
    if (cancel.is_cancelled())
      return;
    if (!searched.ok())
      unread.push_back(log + ": " + describe_error(searched.error()));
  }
  const std::string window = "the last " + std::to_string(days) + (days == 1 ? " day" : " days");
  for (std::size_t index = 0; index < data.events.size(); ++index) {
    const HostEvent& event = data.events[index];
    const std::string provider = event.providers.empty() ? std::string("Event") : event.providers.front();
    const std::string check = provider + " " + std::to_string(event.id) + " (" + event.log + ")";
    const Count& count = counts[index];
    if (count.count == 0) {
      rows.push_back({title, check, "None in " + window + ". " + event.meaning, kHostCheckPass, event.source});
      continue;
    }
    std::string detail = with_thousands(count.count) + " in " + window + ", from " + utc_text(count.first) +
                         " to " + utc_text(count.newest) + ". " + event.meaning;
    if (!count.newest_text.empty())
      detail += " Newest: " + host_checks_detail::shortened(count.newest_text);
    rows.push_back({title, check, detail, kHostCheckFinding, event.source});
  }
  for (const std::string& log : unread)
    rows.push_back({title, "Event log", "Not read. " + log, kHostCheckInformation, ""});
}

std::string start_type_text(DWORD start) {
  switch (start) {
  case SERVICE_BOOT_START: return "starts at boot";
  case SERVICE_SYSTEM_START: return "starts with the system";
  case SERVICE_AUTO_START: return "starts automatically";
  case SERVICE_DEMAND_START: return "starts on demand";
  case SERVICE_DISABLED: return "disabled";
  default: return "start type " + std::to_string(start);
  }
}

std::uint64_t folder_size(const std::filesystem::path& folder, std::uint64_t& files) {
  std::uint64_t bytes = 0;
  std::error_code error;
  for (std::filesystem::recursive_directory_iterator it(folder, std::filesystem::directory_options::skip_permission_denied,
                                                       error),
       end;
       !error && it != end; it.increment(error)) {
    std::error_code size_error;
    if (it->is_regular_file(size_error)) {
      ++files;
      const auto size = it->file_size(size_error);
      if (!size_error)
        bytes += size;
    }
  }
  return bytes;
}

void drivers_group(const HostData& data, const std::string& title, std::vector<HostCheckRow>& rows) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr) {
    rows.push_back({title, "Service manager", "Not read: Windows error " + std::to_string(GetLastError()) + ".",
                    kHostCheckInformation, ""});
    return;
  }
  // The list can grow between two calls, so a buffer that is too small is enlarged and the read
  // repeated from the start.
  DWORD needed = 0;
  DWORD returned = 0;
  DWORD resume = 0;
  DWORD read_error = ERROR_SUCCESS;
  bool listed = false;
  std::vector<BYTE> buffer(64U * 1024U);
  for (int attempt = 0; attempt < 8 && !listed; ++attempt) {
    needed = 0;
    returned = 0;
    resume = 0;
    if (EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER, SERVICE_STATE_ALL, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed, &returned, &resume, nullptr)) {
      listed = true;
      break;
    }
    read_error = GetLastError();
    if (read_error != ERROR_MORE_DATA)
      break;
    buffer.resize(buffer.size() + static_cast<std::size_t>(needed) + 4096U);
  }
  std::size_t found = 0;
  if (listed) {
    const auto* services = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
    const std::string prefix = ascii_lower(data.driver_prefix);
    for (DWORD index = 0; index < returned; ++index) {
      const std::string name = utf8_from_wide(services[index].lpServiceName);
      const std::string display = utf8_from_wide(services[index].lpDisplayName);
      if (ascii_lower(name).rfind(prefix, 0) != 0 && ascii_lower(display).rfind(prefix, 0) != 0)
        continue;
      ++found;
      std::string detail = services[index].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING ? "Running" : "Stopped";
      if (SC_HANDLE service = OpenServiceW(manager, services[index].lpServiceName, SERVICE_QUERY_CONFIG)) {
        DWORD config_needed = 0;
        QueryServiceConfigW(service, nullptr, 0, &config_needed);
        if (config_needed > 0) {
          std::vector<BYTE> config_buffer(config_needed);
          auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config_buffer.data());
          if (QueryServiceConfigW(service, config, config_needed, &config_needed)) {
            detail += ", " + start_type_text(config->dwStartType);
            if (config->lpBinaryPathName != nullptr && *config->lpBinaryPathName != L'\0')
              detail += ", " + utf8_from_wide(config->lpBinaryPathName);
          }
        }
        CloseServiceHandle(service);
      }
      rows.push_back({title, display == name ? name : display + " (" + name + ")", detail + ".",
                      kHostCheckInformation, ""});
    }
  }
  CloseServiceHandle(manager);
  if (!listed)
    rows.push_back({title, "Service manager", "Not read: Windows error " + std::to_string(read_error) + ".",
                    kHostCheckInformation, ""});
  else if (found == 0)
    rows.push_back({title, "Veeam drivers", "No Veeam driver is installed on this machine.", kHostCheckNotPresent, ""});

  if (!data.cbt_store.empty()) {
    const std::filesystem::path store = path_from_utf8(data.cbt_store);
    std::error_code error;
    if (std::filesystem::is_directory(store, error)) {
      std::uint64_t files = 0;
      const std::uint64_t bytes = folder_size(store, files);
      rows.push_back({title, "Change tracking store",
                      data.cbt_store + " holds " + with_thousands(files) + (files == 1 ? " file, " : " files, ") +
                          host_checks_detail::storage_size_text(bytes) + ".",
                      kHostCheckInformation, ""});
    } else {
      rows.push_back({title, "Change tracking store", "No folder at " + data.cbt_store + ".", kHostCheckNotPresent, ""});
    }
  }
}

bool access_denied(const Error& error) {
  const auto code = static_cast<std::uint32_t>(error.hresult);
  return code == 0x80041003U || code == 0x80070005U || error.native_code == ERROR_ACCESS_DENIED;
}

std::uint64_t to_uint64(const std::string& text) {
  return std::strtoull(text.c_str(), nullptr, 10);
}

// "Volume{guid}" from a device id or a Win32_Volume reference; empty when there is none.
std::string volume_key(const std::string& text) {
  const std::string lower = ascii_lower(text);
  const std::size_t start = lower.find("volume{");
  if (start == std::string::npos)
    return {};
  const std::size_t end = lower.find('}', start);
  return end == std::string::npos ? std::string() : lower.substr(start, end - start + 1);
}

void shadow_storage_group(const std::string& title, bool elevated, const CancellationToken& cancel,
                          std::vector<HostCheckRow>& rows) {
  WmiQueryOptions volumes_query;
  volumes_query.query = "SELECT DeviceID, Name FROM Win32_Volume";
  std::map<std::string, std::string> names;
  if (auto volumes = query_wmi(volumes_query, cancel); volumes.ok()) {
    for (const WmiRow& row : volumes.value()) {
      const auto device = row.values.find("DeviceID");
      const auto name = row.values.find("Name");
      if (device != row.values.end() && name != row.values.end())
        names[volume_key(device->second)] = name->second;
    }
  }
  const auto name_of = [&](const std::string& reference) {
    const auto found = names.find(volume_key(reference));
    return found != names.end() && !found->second.empty() ? found->second : reference;
  };

  WmiQueryOptions storage_query;
  storage_query.query = "SELECT Volume, DiffVolume, UsedSpace, AllocatedSpace, MaxSpace FROM Win32_ShadowStorage";
  auto storage = query_wmi(storage_query, cancel);
  if (cancel.is_cancelled())
    return;
  if (!storage.ok()) {
    rows.push_back({title, "Shadow storage",
                    access_denied(storage.error()) ? "Windows lets only an administrator read it."
                                                   : "Not read: " + describe_error(storage.error()),
                    access_denied(storage.error()) ? kHostCheckNeedsAdministrator : kHostCheckInformation, ""});
    return;
  }

  struct Copies {
    std::uint64_t count = 0;
    std::string oldest;
  };
  std::map<std::string, Copies> copies;
  WmiQueryOptions copies_query;
  copies_query.query = "SELECT VolumeName, InstallDate FROM Win32_ShadowCopy";
  copies_query.maximum_rows = 10000;
  if (auto listed = query_wmi(copies_query, cancel); listed.ok()) {
    for (const WmiRow& row : listed.value()) {
      const auto volume = row.values.find("VolumeName");
      if (volume == row.values.end())
        continue;
      Copies& entry = copies[volume_key(volume->second)];
      ++entry.count;
      const auto date = row.values.find("InstallDate");
      if (date != row.values.end() && (entry.oldest.empty() || date->second < entry.oldest))
        entry.oldest = date->second;
    }
  }
  if (cancel.is_cancelled())
    return;

  if (storage.value().empty()) {
    // Without administrator Windows answers with an empty list, not a refusal.
    if (!elevated)
      rows.push_back({title, "Shadow storage", "Windows lists shadow storage only to an administrator.",
                      kHostCheckNeedsAdministrator, ""});
    else
      rows.push_back({title, "Shadow storage", "No volume has shadow storage set up.", kHostCheckInformation, ""});
    return;
  }
  for (const WmiRow& row : storage.value()) {
    const auto value_of = [&row](const char* key) {
      const auto found = row.values.find(key);
      return found == row.values.end() ? std::string() : found->second;
    };
    const std::string volume = value_of("Volume");
    const std::uint64_t used = to_uint64(value_of("UsedSpace"));
    const std::uint64_t allocated = to_uint64(value_of("AllocatedSpace"));
    const std::uint64_t maximum = to_uint64(value_of("MaxSpace"));
    const bool unlimited = maximum == std::numeric_limits<std::uint64_t>::max();
    std::string detail = "Used " + host_checks_detail::storage_size_text(used) + ", allocated " +
                         host_checks_detail::storage_size_text(allocated) + ", maximum " +
                         (unlimited ? std::string("no limit") : host_checks_detail::storage_size_text(maximum)) +
                         ". Kept on " + name_of(value_of("DiffVolume")) + ".";
    const auto listed = copies.find(volume_key(volume));
    if (listed != copies.end()) {
      detail += " " + with_thousands(listed->second.count) +
                (listed->second.count == 1 ? " shadow copy" : " shadow copies");
      if (!listed->second.oldest.empty())
        detail += ", the oldest from " + host_checks_detail::cim_date_text(listed->second.oldest);
      detail += ".";
    } else {
      detail += " No shadow copies.";
    }
    const bool full = !unlimited && maximum > 0 && used >= maximum;
    if (full)
      detail += " Used has reached the maximum: Windows deletes older shadow copies, and a new one can be aborted "
                "(volsnap 36).";
    rows.push_back({title, "Shadow storage for " + name_of(volume), detail, full ? kHostCheckFinding : kHostCheckPass,
                    full ? "https://www.veeam.com/kb4573" : ""});
  }
}

std::optional<std::uint32_t> registry_dword(const std::wstring& key, const wchar_t* value) {
  DWORD data = 0;
  DWORD size = sizeof(data);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), value, RRF_RT_REG_DWORD, nullptr, &data, &size) != ERROR_SUCCESS)
    return std::nullopt;
  return static_cast<std::uint32_t>(data);
}

void dotnet_tls_group(const HostData& data, const std::string& title, std::vector<HostCheckRow>& rows) {
  const auto release = registry_dword(L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", L"Release");
  if (!release) {
    rows.push_back({title, ".NET Framework", ".NET Framework 4.5 or later is not installed.",
                    data.dotnet_minimum > 0 ? kHostCheckFinding : kHostCheckInformation, data.dotnet_source});
  } else {
    const bool below = host_checks_detail::dotnet_below_minimum(*release);
    std::string detail = host_checks_detail::dotnet_name(*release) + ".";
    if (below)
      detail += " Veeam Backup & Replication needs " + data.dotnet_minimum_name + " or later.";
    rows.push_back({title, ".NET Framework", detail, below ? kHostCheckFinding : kHostCheckPass,
                    below ? data.dotnet_source : std::string()});
  }

  const std::pair<const wchar_t*, const char*> views[] = {
      {L"SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319", "64-bit"},
      {L"SOFTWARE\\WOW6432Node\\Microsoft\\.NETFramework\\v4.0.30319", "32-bit"}};
  for (const auto& [key, view] : views) {
    for (const wchar_t* name : {L"SchUseStrongCrypto", L"SystemDefaultTlsVersions"}) {
      const auto value = registry_dword(key, name);
      rows.push_back({title, utf8_from_wide(name) + " (" + view + ")", host_checks_detail::switch_text(value) + ".",
                      value && *value == 0 ? kHostCheckFinding : kHostCheckInformation, ""});
    }
  }

  for (const std::string& protocol : data.tls_protocols) {
    for (const char* side : {"Client", "Server"}) {
      const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\" +
                               wide_from_utf8(protocol) + L"\\" + wide_from_utf8(side);
      const auto reading = host_checks_detail::tls_reading(registry_dword(key, L"Enabled"),
                                                           registry_dword(key, L"DisabledByDefault"));
      const bool required = protocol == data.tls_required;
      rows.push_back({title, protocol + " " + ascii_lower(side), reading.text,
                      required && reading.off ? kHostCheckFinding : kHostCheckInformation, ""});
    }
  }
}

#else

std::string read_first_line(const std::filesystem::path& path) {
  std::ifstream file(path);
  std::string line;
  std::getline(file, line);
  return trim(line);
}

void modules_group(const HostData& data, const std::string& title, std::vector<HostCheckRow>& rows) {
  struct utsname name {};
  const std::string release = uname(&name) == 0 ? std::string(name.release) : std::string();
  std::string loaded_modules;
  {
    std::ifstream modules("/proc/modules");
    std::string line;
    while (std::getline(modules, line))
      loaded_modules += line.substr(0, line.find(' ')) + "\n";
  }
  std::string dependencies;
  if (!release.empty()) {
    std::ifstream file("/lib/modules/" + release + "/modules.dep");
    std::string line;
    while (std::getline(file, line))
      dependencies += line.substr(0, line.find(':')) + "\n";
  }
  bool any = false;
  bool any_dkms = false;
  for (const std::string& module : data.linux_modules) {
    const bool loaded = loaded_modules.find(module + "\n") != std::string::npos &&
                        (loaded_modules.rfind(module + "\n", 0) == 0 ||
                         loaded_modules.find("\n" + module + "\n") != std::string::npos);
    const bool installed = dependencies.find("/" + module + ".ko") != std::string::npos;
    std::vector<std::string> dkms_versions;
    bool dkms_built_here = false;
    std::error_code error;
    const std::filesystem::path dkms = "/var/lib/dkms/" + module;
    if (std::filesystem::is_directory(dkms, error)) {
      for (std::filesystem::directory_iterator it(dkms, error), end; !error && it != end; it.increment(error)) {
        const std::string version = it->path().filename().string();
        std::error_code kind_error;
        if (version == "source" || !it->is_directory(kind_error))
          continue;
        dkms_versions.push_back(version);
        std::error_code built_error;
        if (!release.empty() && std::filesystem::exists(it->path() / release, built_error))
          dkms_built_here = true;
      }
    }
    if (!loaded && !installed && dkms_versions.empty())
      continue;
    any = true;
    any_dkms = any_dkms || !dkms_versions.empty();
    std::string detail = loaded ? "Loaded" : "Not loaded";
    if (loaded) {
      const std::string version = read_first_line("/sys/module/" + module + "/version");
      if (!version.empty())
        detail += ", version " + version;
    }
    detail += installed ? "; installed for this kernel (" + release + ")" : "; not installed for this kernel (" + release + ")";
    if (!dkms_versions.empty()) {
      std::string versions;
      for (const std::string& version : dkms_versions)
        versions += (versions.empty() ? "" : ", ") + version;
      detail += "; DKMS holds " + versions + (dkms_built_here ? ", built for this kernel" : ", not built for this kernel");
    }
    const bool stranded = !loaded && !installed && !dkms_versions.empty() && !dkms_built_here;
    if (stranded)
      detail += ". DKMS has not built it for the running kernel, which is how the module goes missing after a "
                "kernel update";
    rows.push_back({title, module, detail + ".", stranded ? kHostCheckFinding : kHostCheckInformation,
                    stranded ? "https://www.veeam.com/kb4695" : ""});
  }
  if (!any) {
    rows.push_back({title, "Veeam snapshot module", "No Veeam snapshot module is loaded, installed or registered with DKMS.",
                    kHostCheckNotPresent, ""});
    return;
  }
  if (any_dkms && !release.empty()) {
    std::error_code error;
    const bool headers = std::filesystem::exists("/lib/modules/" + release + "/build", error);
    rows.push_back({title, "Kernel headers",
                    headers ? "Present for " + release + "."
                            : "Not present for " + release + ". DKMS needs them to build a module for this kernel.",
                    kHostCheckInformation, ""});
  }
}

void kernel_log_group(const HostData& data, const std::string& title, std::vector<HostCheckRow>& rows) {
  std::string chosen;
  bool unreadable = false;
  for (const std::string& path : data.kernel_logs) {
    std::error_code error;
    if (!std::filesystem::exists(path, error))
      continue;
    std::ifstream probe(path, std::ios::binary);
    if (!probe) {
      unreadable = true;
      continue;
    }
    chosen = path;
    break;
  }
  if (chosen.empty()) {
    if (unreadable)
      rows.push_back({title, "Kernel log", "The kernel log file is readable by root only.", kHostCheckNeedsAdministrator, ""});
    else
      rows.push_back({title, "Kernel log", "No kernel log file (kern.log or messages); this system may keep it in the journal only.",
                      kHostCheckNotPresent, ""});
    return;
  }
  std::ifstream file(chosen, std::ios::binary);
  file.seekg(0, std::ios::end);
  const auto size = static_cast<std::uint64_t>(std::max<std::streamoff>(0, file.tellg()));
  const std::uint64_t start = size > data.kernel_log_bytes ? size - data.kernel_log_bytes : 0;
  file.seekg(static_cast<std::streamoff>(start));
  std::vector<std::uint64_t> counts(data.kernel_signatures.size(), 0);
  std::vector<std::string> newest(data.kernel_signatures.size());
  std::string line;
  if (start > 0)
    std::getline(file, line); // a partial first line
  while (std::getline(file, line)) {
    for (const std::size_t index : host_checks_detail::kernel_signatures_in(line)) {
      ++counts[index];
      newest[index] = line;
    }
  }
  for (std::size_t index = 0; index < data.kernel_signatures.size(); ++index) {
    const Signature& signature = data.kernel_signatures[index];
    if (counts[index] == 0) {
      rows.push_back({title, signature.text, "None in " + chosen + ". " + signature.meaning, kHostCheckPass, ""});
      continue;
    }
    rows.push_back({title, signature.text,
                    with_thousands(counts[index]) + (counts[index] == 1 ? " line" : " lines") + " in " + chosen + ". " +
                        signature.meaning + " Newest: " + host_checks_detail::shortened(newest[index]),
                    kHostCheckFinding, ""});
  }
}

#endif

} // namespace

const std::vector<HostCheckGroup>& host_check_groups() {
  return host_data().groups;
}

std::vector<HostCheckGroup> host_check_groups_here() {
  std::vector<HostCheckGroup> here;
  for (const HostCheckGroup& group : host_check_groups()) {
    if (platform_matches(group.platform))
      here.push_back(group);
  }
  return here;
}

Result<HostChecksReport> run_host_checks(const HostChecksOptions& options, const CancellationToken& cancel,
                                         ProgressCallback progress) {
  const HostData& data = host_data();
  HostChecksReport report;
  report.days = options.days > 0 ? options.days : data.event_days;
  const auto context = current_security_context();
  report.elevated = context.ok() && context.value().elevated;

  std::vector<HostCheckGroup> chosen;
  for (const HostCheckGroup& group : host_check_groups_here()) {
    if (options.groups.empty() ||
        std::find(options.groups.begin(), options.groups.end(), group.id) != options.groups.end())
      chosen.push_back(group);
  }
  for (const std::string& id : options.groups) {
    const auto named = std::find_if(data.groups.begin(), data.groups.end(),
                                    [&id](const HostCheckGroup& group) { return group.id == id; });
    if (named == data.groups.end()) {
      Error error;
      error.component = "Host Checks";
      error.operation = "choose checks";
      error.message = "No check named " + id + ". The checks are: " + [&]() {
        std::string names;
        for (const HostCheckGroup& group : host_check_groups_here())
          names += (names.empty() ? "" : ", ") + group.id;
        return names;
      }() + ".";
      return Result<HostChecksReport>::failure(std::move(error));
    }
    if (!platform_matches(named->platform)) {
      Error error;
      error.component = "Host Checks";
      error.operation = "choose checks";
      error.message = "The " + id + " check runs on " + (named->platform == "windows" ? "Windows" : "Linux") +
                      " only.";
      return Result<HostChecksReport>::failure(std::move(error));
    }
  }

  std::uint64_t index = 0;
  for (const HostCheckGroup& group : chosen) {
    if (cancel.is_cancelled()) {
      report.cancelled = true;
      break;
    }
    report_progress(progress, group.title, ++index, chosen.size());
    report.groups_run.push_back(group.title);
#ifdef _WIN32
    if (group.id == "events")
      events_group(data, report.days, group.title, cancel, report.rows);
    else if (group.id == "drivers")
      drivers_group(data, group.title, report.rows);
    else if (group.id == "shadow-storage")
      shadow_storage_group(group.title, report.elevated, cancel, report.rows);
    else if (group.id == "dotnet-tls")
      dotnet_tls_group(data, group.title, report.rows);
#else
    if (group.id == "drivers")
      modules_group(data, group.title, report.rows);
    else if (group.id == "kernel-log")
      kernel_log_group(data, group.title, report.rows);
#endif
    if (cancel.is_cancelled())
      report.cancelled = true;
  }
  return Result<HostChecksReport>::success(std::move(report));
}

std::string host_checks_summary(const HostChecksReport& report) {
  std::map<std::string, std::size_t> counts;
  for (const HostCheckRow& row : report.rows)
    ++counts[row.status];
  std::string text = "Host Checks";
  if (!report.groups_run.empty()) {
    text += " (";
    for (std::size_t index = 0; index < report.groups_run.size(); ++index)
      text += (index == 0 ? "" : ", ") + report.groups_run[index];
    text += ")";
  }
  text += ":";
  bool first = true;
  for (const char* status : {kHostCheckFinding, kHostCheckNeedsAdministrator, kHostCheckPass, kHostCheckInformation,
                             kHostCheckNotPresent}) {
    const auto found = counts.find(status);
    if (found == counts.end())
      continue;
    text += std::string(first ? " " : ", ") + std::to_string(found->second) + " " + status;
    first = false;
  }
  text += first ? " nothing to report." : ".";
  if (report.cancelled)
    text += " Cancelled before every check finished.";
  return text;
}

bool host_checks_has_finding(const HostChecksReport& report) {
  return std::any_of(report.rows.begin(), report.rows.end(),
                     [](const HostCheckRow& row) { return row.status == kHostCheckFinding; });
}

namespace host_checks_detail {

std::string dotnet_version(std::uint32_t release) {
  for (const auto& [minimum, name] : host_data().dotnet_releases) {
    if (release >= minimum)
      return name;
  }
  return {};
}

std::string dotnet_name(std::uint32_t release) {
  const std::string version = dotnet_version(release);
  if (!version.empty())
    return ".NET Framework " + version + " (release " + std::to_string(release) + ")";
  return ".NET Framework release " + std::to_string(release);
}

std::string dotnet_minimum_version() {
  return host_data().dotnet_minimum_name;
}

bool dotnet_below_minimum(std::uint32_t release) {
  return host_data().dotnet_minimum > 0 && release < host_data().dotnet_minimum;
}

TlsReading tls_reading(std::optional<std::uint32_t> enabled, std::optional<std::uint32_t> disabled_by_default) {
  TlsReading reading;
  if (!enabled && !disabled_by_default) {
    reading.text = "Not set (Windows default).";
    return reading;
  }
  reading.off = (enabled && *enabled == 0) || (disabled_by_default && *disabled_by_default != 0);
  reading.text = std::string("Enabled ") + (enabled ? std::to_string(*enabled) : std::string("not set")) +
                 ", DisabledByDefault " +
                 (disabled_by_default ? std::to_string(*disabled_by_default) : std::string("not set")) +
                 (reading.off ? ": turned off." : ": on.");
  return reading;
}

std::string switch_text(std::optional<std::uint32_t> value) {
  if (!value)
    return "Not set (Windows default)";
  return *value == 0 ? "Off (set to 0)" : "On (set to " + std::to_string(*value) + ")";
}

std::vector<std::size_t> kernel_signatures_in(std::string_view line) {
  std::vector<std::size_t> found;
  const auto& signatures = host_data().kernel_signatures;
  for (std::size_t index = 0; index < signatures.size(); ++index) {
    if (!signatures[index].text.empty() && line.find(signatures[index].text) != std::string_view::npos)
      found.push_back(index);
  }
  return found;
}

std::string storage_size_text(std::uint64_t bytes) {
  char text[48] = {};
  const double value = static_cast<double>(bytes);
  if (bytes >= 1024ULL * 1024ULL * 1024ULL)
    std::snprintf(text, sizeof(text), "%.1f GB", value / (1024.0 * 1024.0 * 1024.0));
  else if (bytes >= 1024ULL * 1024ULL)
    std::snprintf(text, sizeof(text), "%.1f MB", value / (1024.0 * 1024.0));
  else
    std::snprintf(text, sizeof(text), "%llu bytes", static_cast<unsigned long long>(bytes));
  return text;
}

std::string cim_date_text(const std::string& value) {
  // query_wmi already gives "2026-10-16 12:34:56 (UTC-05:00)".
  if (value.size() >= 16 && value[4] == '-' && value[7] == '-' && value[10] == ' ')
    return value.substr(0, 16);
  if (value.size() < 12)
    return value;
  return value.substr(0, 4) + "-" + value.substr(4, 2) + "-" + value.substr(6, 2) + " " + value.substr(8, 2) + ":" +
         value.substr(10, 2);
}

std::string shortened(std::string text, std::size_t limit) {
  for (char& character : text) {
    if (character == '\r' || character == '\n' || character == '\t')
      character = ' ';
  }
  text = trim(text);
  if (text.size() > limit) {
    // A byte of the form 10xxxxxx continues a character, so the cut moves back to where one starts.
    std::size_t cut = limit;
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0U) == 0x80U)
      --cut;
    text = text.substr(0, cut) + "...";
  }
  return text;
}

} // namespace host_checks_detail

} // namespace support_assist
