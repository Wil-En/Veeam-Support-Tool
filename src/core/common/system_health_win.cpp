#include "support_assist/system_health.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/log_search.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/wmi.hpp"

#include "system_health_windows_sdk.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iterator>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

std::uint64_t file_time_value(const FILETIME& value) {
  ULARGE_INTEGER converted{};
  converted.LowPart = value.dwLowDateTime;
  converted.HighPart = value.dwHighDateTime;
  return converted.QuadPart;
}

Error health_error(std::string operation, std::string message, std::int64_t native_code = 0) {
  Error error;
  error.component = "SystemHealth";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.native_code = native_code;
  error.timestamp_utc = utc_now_iso8601();
  return error;
}

std::string drive_type_name(UINT type) {
  switch (type) {
  case DRIVE_FIXED:
    return "Fixed";
  case DRIVE_REMOVABLE:
    return "Removable";
  case DRIVE_REMOTE:
    return "Network";
  case DRIVE_CDROM:
    return "Optical";
  case DRIVE_RAMDISK:
    return "RAM disk";
  case DRIVE_NO_ROOT_DIR:
    return "Unavailable";
  default:
    return "Unknown";
  }
}

std::string oper_status_name(IF_OPER_STATUS status) {
  switch (status) {
  case IfOperStatusUp:
    return "Up";
  case IfOperStatusDown:
    return "Down";
  case IfOperStatusTesting:
    return "Testing";
  case IfOperStatusDormant:
    return "Dormant";
  case IfOperStatusNotPresent:
    return "Not present";
  case IfOperStatusLowerLayerDown:
    return "Lower layer down";
  case IfOperStatusUnknown:
  default:
    return "Unknown";
  }
}

std::optional<double> parse_double(std::string_view text) {
  double value = 0.0;
  const auto [position, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || position != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::optional<std::uint64_t> parse_uint64(std::string_view text) {
  std::uint64_t value = 0;
  const auto [position, error] =
      std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || position != text.data() + text.size())
    return std::nullopt;
  return value;
}

std::string row_value(const WmiRow& row, std::string_view key) {
  const auto found = row.values.find(std::string(key));
  return found == row.values.end() ? std::string{} : found->second;
}

bool text_is_true(std::string_view value) {
  std::string normalized(value);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return normalized == "true" || normalized == "1" || normalized == "yes";
}

std::optional<double> temperature_from_raw(double raw) {
  double celsius = raw;
  if (raw > 1000.0)
    celsius = (raw / 10.0) - 273.15;
  else if (raw > 200.0)
    celsius = raw - 273.15;
  if (!std::isfinite(celsius) || celsius < -30.0 || celsius > 160.0)
    return std::nullopt;
  return celsius;
}

std::optional<double> query_temperature(std::string& source) {
  CancellationToken cancel;
  WmiQueryOptions options;
  options.name_space = "root\\WMI";
  options.query = "SELECT CurrentTemperature FROM MSAcpi_ThermalZoneTemperature";
  options.maximum_rows = 32;
  options.maximum_properties = 8;
  auto result = query_wmi(options, cancel);
  if (result.ok()) {
    std::optional<double> highest;
    for (const auto& row : result.value()) {
      const auto raw = parse_double(row_value(row, "CurrentTemperature"));
      const auto value = raw ? temperature_from_raw(*raw) : std::nullopt;
      if (value && (!highest || *value > *highest))
        highest = value;
    }
    if (highest) {
      source = "Windows ACPI thermal zone estimate";
      return highest;
    }
  }

  options.name_space = "root\\cimv2";
  options.query =
      "SELECT Temperature FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation";
  result = query_wmi(options, cancel);
  if (!result.ok())
    return std::nullopt;
  std::optional<double> highest;
  for (const auto& row : result.value()) {
    const auto raw = parse_double(row_value(row, "Temperature"));
    const auto value = raw ? temperature_from_raw(*raw) : std::nullopt;
    if (value && (!highest || *value > *highest))
      highest = value;
  }
  if (highest)
    source = "Windows thermal-zone performance counter estimate";
  return highest;
}

std::string storage_health_name(std::string_view value) {
  if (value == "0")
    return "Healthy";
  if (value == "1")
    return "Warning";
  if (value == "2")
    return "Unhealthy";
  if (value == "5")
    return "Unknown";
  return value.empty() ? "Unknown" : std::string(value);
}

std::string storage_media_name(std::string_view value) {
  if (value == "3")
    return "HDD";
  if (value == "4")
    return "SSD";
  if (value == "5")
    return "SCM";
  return value.empty() || value == "0" ? "Unspecified" : std::string(value);
}

std::string storage_bus_name(std::string_view value) {
  static const std::map<std::string, std::string> names{
      {"1", "SCSI"}, {"2", "ATAPI"}, {"3", "ATA"}, {"7", "USB"},
      {"8", "RAID"}, {"11", "SATA"}, {"12", "SAS"}, {"17", "NVMe"}};
  const auto found = names.find(std::string(value));
  return found == names.end() ? (value.empty() ? "Unknown" : std::string(value))
                              : found->second;
}

std::string storage_operational_name(std::string value) {
  if (value == "2" || value == "{2}")
    return "OK";
  if (value == "3" || value == "{3}")
    return "Degraded";
  if (value == "6" || value == "{6}")
    return "Error";
  return value.empty() ? "Unknown" : value;
}

std::vector<StorageDeviceHealth> query_storage_health(std::vector<std::string>& warnings) {
  CancellationToken cancel;
  WmiQueryOptions options;
  options.name_space = "root\\Microsoft\\Windows\\Storage";
  options.query =
      "SELECT FriendlyName,HealthStatus,OperationalStatus,MediaType,BusType,Size FROM MSFT_PhysicalDisk";
  options.maximum_rows = 128;
  options.maximum_properties = 16;
  auto result = query_wmi(options, cancel);
  std::vector<StorageDeviceHealth> devices;
  if (result.ok()) {
    for (const auto& row : result.value()) {
      StorageDeviceHealth device;
      device.name = row_value(row, "FriendlyName");
      device.health_status = storage_health_name(row_value(row, "HealthStatus"));
      device.operational_status = storage_operational_name(row_value(row, "OperationalStatus"));
      device.media_type = storage_media_name(row_value(row, "MediaType"));
      device.bus_type = storage_bus_name(row_value(row, "BusType"));
      device.size_bytes = parse_uint64(row_value(row, "Size")).value_or(0U);
      device.health_available = !device.name.empty();
      if (device.name.empty())
        device.name = "Physical disk";
      devices.push_back(std::move(device));
    }
  } else {
    warnings.push_back(
        "Storage Management health is unavailable; the controller or Windows edition may not expose it.");
  }

  options.name_space = "root\\WMI";
  options.query =
      "SELECT InstanceName,PredictFailure,Reason FROM MSStorageDriver_FailurePredictStatus";
  options.maximum_rows = 128;
  auto predictive = query_wmi(options, cancel);
  if (predictive.ok()) {
    for (const auto& row : predictive.value()) {
      if (!text_is_true(row_value(row, "PredictFailure")))
        continue;
      StorageDeviceHealth device;
      device.name = row_value(row, "InstanceName");
      if (device.name.empty())
        device.name = "Storage device reported by SMART";
      device.health_available = true;
      device.health_status = "Unhealthy";
      device.predictive_failure = true;
      device.predictive_failure_reason = row_value(row, "Reason");
      devices.push_back(std::move(device));
    }
  }
  return devices;
}

std::optional<double> formatted_counter(PDH_HCOUNTER counter) {
  if (counter == nullptr)
    return std::nullopt;
  PDH_FMT_COUNTERVALUE value{};
  DWORD type = 0;
  if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, &type, &value) != ERROR_SUCCESS ||
      (value.CStatus != PDH_CSTATUS_VALID_DATA && value.CStatus != PDH_CSTATUS_NEW_DATA)) {
    return std::nullopt;
  }
  return value.doubleValue;
}

struct PdhVolumeCounters {
  PDH_HCOUNTER read = nullptr;
  PDH_HCOUNTER write = nullptr;
  PDH_HCOUNTER active = nullptr;
  PDH_HCOUNTER read_latency = nullptr;
  PDH_HCOUNTER write_latency = nullptr;
  PDH_HCOUNTER queue = nullptr;
};

struct PdhMemoryCounters {
  PDH_HCOUNTER pages_input = nullptr;
  PDH_HCOUNTER page_reads = nullptr;
  PDH_HCOUNTER page_writes = nullptr;
  PDH_HCOUNTER page_faults = nullptr;
  PDH_HCOUNTER pagefile_percent = nullptr;
  PDH_HCOUNTER processor_queue = nullptr;
};

struct NetworkCounterSnapshot {
  std::uint64_t in_octets = 0;
  std::uint64_t out_octets = 0;
  std::uint64_t in_discards = 0;
  std::uint64_t out_discards = 0;
  std::uint64_t in_errors = 0;
  std::uint64_t out_errors = 0;
};

struct ProcessCounterSnapshot {
  std::uint64_t cpu_time_100ns = 0;
  std::uint64_t read_bytes = 0;
  std::uint64_t write_bytes = 0;
};

// The event-log checks (health-events.json): one search of each log for all its IDs, counted per
// check by provider and by window (the last days, or since the restart).
std::vector<HealthEventCount> read_health_events(std::vector<std::string>& warnings) {
  const std::vector<HealthEventCheck>& checks = health_event_checks();
  std::vector<HealthEventCount> counts;
  for (const HealthEventCheck& check : checks)
    counts.push_back({check, 0U, 0});
  const std::int64_t now = unix_millis_now();
  const std::int64_t days_from = now - static_cast<std::int64_t>(health_event_days()) * 86400000LL;
  const std::int64_t restart_from = now - static_cast<std::int64_t>(GetTickCount64());
  std::vector<std::string> logs;
  for (const HealthEventCheck& check : checks) {
    if (std::find(logs.begin(), logs.end(), check.log) == logs.end())
      logs.push_back(check.log);
  }
  const CancellationToken never;
  for (const std::string& log : logs) {
    WindowsEventLogSearchOptions options;
    options.channel = log;
    std::int64_t from = now;
    for (const HealthEventCheck& check : checks) {
      if (check.log != log)
        continue;
      options.event_ids.push_back(check.id);
      from = std::min(from, check.since_restart ? restart_from : days_from);
    }
    options.from_utc_ms = from;
    auto searched = search_windows_event_log(options, never, {}, [&](const LogMatch& match) {
      // The signature is "event-id:N;provider:NAME".
      const std::string& signature = match.signature;
      const std::size_t id_at = signature.find("event-id:");
      const std::size_t provider_at = signature.find("provider:");
      if (id_at == std::string::npos)
        return Status::success();
      const auto id = static_cast<std::uint32_t>(std::strtoul(signature.c_str() + id_at + 9, nullptr, 10));
      const std::string provider =
          provider_at == std::string::npos ? std::string() : ascii_lower(signature.substr(provider_at + 9));
      const std::int64_t at = match.timestamp_utc_ms.value_or(0);
      for (HealthEventCount& count : counts) {
        const HealthEventCheck& check = count.check;
        if (check.log != log || check.id != id || at < (check.since_restart ? restart_from : days_from))
          continue;
        if (!check.providers.empty() &&
            std::none_of(check.providers.begin(), check.providers.end(),
                         [&](const std::string& name) { return ascii_lower(name) == provider; }))
          continue;
        ++count.count;
        count.newest_unix_millis = std::max(count.newest_unix_millis, at);
      }
      return Status::success();
    });
    if (!searched.ok())
      warnings.push_back("The " + log + " event log was not read: " + describe_error(searched.error()));
  }
  return counts;
}

} // namespace

struct SystemHealthSampler::Impl {
  std::uint64_t previous_idle = 0;
  std::uint64_t previous_kernel = 0;
  std::uint64_t previous_user = 0;
  bool cpu_seeded = false;

  PDH_HQUERY disk_query = nullptr;
  bool disk_query_seeded = false;
  std::map<std::string, PdhVolumeCounters> disk_counters;
  std::vector<VolumeHealth> cached_volumes;

  PDH_HQUERY memory_query = nullptr;
  bool memory_query_seeded = false;
  PdhMemoryCounters memory_counters;

  std::optional<double> cached_temperature;
  std::string cached_temperature_source;
  std::vector<StorageDeviceHealth> cached_storage_devices;
  std::vector<HealthEventCount> cached_events;
  bool events_read = false;

  std::unordered_map<std::uint64_t, NetworkCounterSnapshot> previous_network;
  std::chrono::steady_clock::time_point previous_network_time{};
  bool network_seeded = false;

  std::unordered_map<std::uint32_t, ProcessCounterSnapshot> previous_processes;
  std::chrono::steady_clock::time_point previous_process_time{};
  bool processes_seeded = false;

  Impl() {
    rebuild_memory_query();
  }

  ~Impl() {
    close_disk_query();
    close_memory_query();
  }

  void close_disk_query() {
    if (disk_query != nullptr)
      PdhCloseQuery(disk_query);
    disk_query = nullptr;
    disk_query_seeded = false;
    disk_counters.clear();
  }

  void close_memory_query() {
    if (memory_query != nullptr)
      PdhCloseQuery(memory_query);
    memory_query = nullptr;
    memory_query_seeded = false;
    memory_counters = {};
  }

  void add_memory_counter(const wchar_t* path, PDH_HCOUNTER& counter) {
    if (PdhAddEnglishCounterW(memory_query, path, 0, &counter) != ERROR_SUCCESS)
      counter = nullptr;
  }

  void rebuild_memory_query() {
    close_memory_query();
    if (PdhOpenQueryW(nullptr, 0, &memory_query) != ERROR_SUCCESS) {
      memory_query = nullptr;
      return;
    }
    add_memory_counter(L"\\Memory\\Pages Input/sec", memory_counters.pages_input);
    add_memory_counter(L"\\Memory\\Page Reads/sec", memory_counters.page_reads);
    add_memory_counter(L"\\Memory\\Page Writes/sec", memory_counters.page_writes);
    add_memory_counter(L"\\Memory\\Page Faults/sec", memory_counters.page_faults);
    add_memory_counter(L"\\Paging File(_Total)\\% Usage", memory_counters.pagefile_percent);
    add_memory_counter(L"\\System\\Processor Queue Length", memory_counters.processor_queue);
    if (PdhCollectQueryData(memory_query) == ERROR_SUCCESS)
      memory_query_seeded = true;
  }

  void add_disk_counter(const std::wstring& path, PDH_HCOUNTER& counter) {
    if (PdhAddEnglishCounterW(disk_query, path.c_str(), 0, &counter) != ERROR_SUCCESS)
      counter = nullptr;
  }

  void rebuild_disk_query() {
    close_disk_query();
    if (PdhOpenQueryW(nullptr, 0, &disk_query) != ERROR_SUCCESS) {
      disk_query = nullptr;
      return;
    }
    for (const auto& volume : cached_volumes) {
      if (volume.root_path.size() < 2U || volume.root_path[1] != ':' ||
          volume.drive_type == "Network" || volume.drive_type == "Optical") {
        continue;
      }
      const std::wstring instance = wide_from_utf8(volume.root_path.substr(0, 2));
      const std::wstring prefix = L"\\LogicalDisk(" + instance + L")\\";
      PdhVolumeCounters counters;
      add_disk_counter(prefix + L"Disk Read Bytes/sec", counters.read);
      add_disk_counter(prefix + L"Disk Write Bytes/sec", counters.write);
      add_disk_counter(prefix + L"% Disk Time", counters.active);
      add_disk_counter(prefix + L"Avg. Disk sec/Read", counters.read_latency);
      add_disk_counter(prefix + L"Avg. Disk sec/Write", counters.write_latency);
      add_disk_counter(prefix + L"Current Disk Queue Length", counters.queue);
      if (counters.read != nullptr || counters.write != nullptr || counters.active != nullptr ||
          counters.read_latency != nullptr || counters.write_latency != nullptr ||
          counters.queue != nullptr) {
        disk_counters.emplace(volume.root_path, counters);
      }
    }
    if (disk_counters.empty()) {
      close_disk_query();
      return;
    }
    if (PdhCollectQueryData(disk_query) == ERROR_SUCCESS)
      disk_query_seeded = true;
  }

  void refresh_volumes() {
    std::vector<VolumeHealth> volumes;
    const DWORD mask = GetLogicalDrives();
    for (int index = 0; index < 26; ++index) {
      if ((mask & (1UL << static_cast<unsigned int>(index))) == 0)
        continue;
      std::wstring root;
      root.push_back(static_cast<wchar_t>(L'A' + index));
      root += L":\\";
      const UINT type = GetDriveTypeW(root.c_str());
      VolumeHealth volume;
      volume.root_path = utf8_from_wide(root);
      volume.drive_type = drive_type_name(type);

      if (type != DRIVE_REMOTE && type != DRIVE_CDROM) {
        wchar_t label[256]{};
        wchar_t filesystem[64]{};
        DWORD serial = 0;
        DWORD maximum_component = 0;
        DWORD flags = 0;
        if (GetVolumeInformationW(root.c_str(), label, static_cast<DWORD>(std::size(label)),
                                  &serial, &maximum_component, &flags, filesystem,
                                  static_cast<DWORD>(std::size(filesystem))) != FALSE) {
          volume.label = utf8_from_wide(label);
          volume.filesystem = utf8_from_wide(filesystem);
        }

        ULARGE_INTEGER available{};
        ULARGE_INTEGER total{};
        ULARGE_INTEGER free{};
        if (GetDiskFreeSpaceExW(root.c_str(), &available, &total, &free) != FALSE) {
          volume.total_bytes = total.QuadPart;
          volume.free_bytes = free.QuadPart;
          volume.capacity_available = true;
        }
      }
      volumes.push_back(std::move(volume));
    }
    attach_volume_layout(volumes);
    cached_volumes = std::move(volumes);
    rebuild_disk_query();
  }

  void sample_disk(std::vector<VolumeHealth>& volumes) {
    if (disk_query == nullptr || !disk_query_seeded)
      return;
    if (PdhCollectQueryData(disk_query) != ERROR_SUCCESS)
      return;
    for (auto& volume : volumes) {
      const auto found = disk_counters.find(volume.root_path);
      if (found == disk_counters.end())
        continue;
      volume.read_bytes_per_second = formatted_counter(found->second.read);
      volume.write_bytes_per_second = formatted_counter(found->second.write);
      volume.active_percent = formatted_counter(found->second.active);
      if (volume.active_percent)
        volume.active_percent = std::clamp(*volume.active_percent, 0.0, 100.0);
      if (const auto value = formatted_counter(found->second.read_latency))
        volume.average_read_latency_ms = std::max(0.0, *value * 1000.0);
      if (const auto value = formatted_counter(found->second.write_latency))
        volume.average_write_latency_ms = std::max(0.0, *value * 1000.0);
      volume.queue_length = formatted_counter(found->second.queue);
    }
  }

  void sample_memory_counters(SystemHealthSnapshot& snapshot) {
    if (memory_query == nullptr || !memory_query_seeded)
      return;
    if (PdhCollectQueryData(memory_query) != ERROR_SUCCESS)
      return;
    snapshot.memory.pages_input_per_second = formatted_counter(memory_counters.pages_input);
    snapshot.memory.page_reads_per_second = formatted_counter(memory_counters.page_reads);
    snapshot.memory.page_writes_per_second = formatted_counter(memory_counters.page_writes);
    snapshot.memory.page_faults_per_second = formatted_counter(memory_counters.page_faults);
    snapshot.processor_queue_length = formatted_counter(memory_counters.processor_queue);
    if (const auto pagefile_percent = formatted_counter(memory_counters.pagefile_percent)) {
      snapshot.memory.pagefile_load_percent = std::clamp(*pagefile_percent, 0.0, 100.0);
      snapshot.memory.pagefile_used_bytes = static_cast<std::uint64_t>(
          static_cast<double>(snapshot.memory.pagefile_limit_bytes) *
          snapshot.memory.pagefile_load_percent / 100.0);
    }
  }

  std::vector<NetworkAdapterHealth> sample_network() {
    PMIB_IF_TABLE2 table = nullptr;
    if (GetIfTable2(&table) != NO_ERROR || table == nullptr)
      return {};
    const auto now = std::chrono::steady_clock::now();
    const double elapsed = network_seeded
                               ? std::chrono::duration<double>(now - previous_network_time).count()
                               : 0.0;
    std::unordered_map<std::uint64_t, NetworkCounterSnapshot> next;
    std::vector<NetworkAdapterHealth> adapters;
    adapters.reserve(table->NumEntries);
    for (ULONG index = 0; index < table->NumEntries; ++index) {
      const MIB_IF_ROW2& row = table->Table[index];
      // A filter driver (WFP, QoS, Npcap) is a layer over an adapter listed in its own right and
      // repeats that adapter's counters.
      if (row.InterfaceAndOperStatusFlags.FilterInterface)
        continue;
      NetworkAdapterHealth adapter;
      const std::uint64_t key = row.InterfaceLuid.Value;
      adapter.key = std::to_string(key);
      adapter.name = utf8_from_wide(row.Alias);
      adapter.description = utf8_from_wide(row.Description);
      adapter.operational_status = oper_status_name(row.OperStatus);
      adapter.receive_link_speed_bits = row.ReceiveLinkSpeed;
      adapter.transmit_link_speed_bits = row.TransmitLinkSpeed;
      adapter.mtu = row.Mtu == 0xFFFFFFFFUL ? 0U : static_cast<std::uint32_t>(row.Mtu);
      adapter.receive_discards = row.InDiscards;
      adapter.transmit_discards = row.OutDiscards;
      adapter.receive_errors = row.InErrors;
      adapter.transmit_errors = row.OutErrors;
      adapter.virtual_adapter = row.Type == IF_TYPE_SOFTWARE_LOOPBACK ||
                                row.Type == IF_TYPE_TUNNEL || row.PhysicalAddressLength == 0U;
      next.emplace(key,
                   NetworkCounterSnapshot{row.InOctets,
                                          row.OutOctets,
                                          row.InDiscards,
                                          row.OutDiscards,
                                          row.InErrors,
                                          row.OutErrors});
      const auto previous = previous_network.find(key);
      if (previous != previous_network.end() && elapsed > 0.0 &&
          row.InOctets >= previous->second.in_octets &&
          row.OutOctets >= previous->second.out_octets) {
        adapter.receive_bytes_per_second =
            static_cast<double>(row.InOctets - previous->second.in_octets) / elapsed;
        adapter.transmit_bytes_per_second =
            static_cast<double>(row.OutOctets - previous->second.out_octets) / elapsed;
        if (row.InDiscards >= previous->second.in_discards)
          adapter.receive_discards_delta = row.InDiscards - previous->second.in_discards;
        if (row.OutDiscards >= previous->second.out_discards)
          adapter.transmit_discards_delta = row.OutDiscards - previous->second.out_discards;
        if (row.InErrors >= previous->second.in_errors)
          adapter.receive_errors_delta = row.InErrors - previous->second.in_errors;
        if (row.OutErrors >= previous->second.out_errors)
          adapter.transmit_errors_delta = row.OutErrors - previous->second.out_errors;
        const std::uint64_t link_speed =
            std::max(row.ReceiveLinkSpeed, row.TransmitLinkSpeed);
        if (link_speed != 0U) {
          const double total_bits =
              (*adapter.receive_bytes_per_second + *adapter.transmit_bytes_per_second) * 8.0;
          adapter.utilization_percent =
              std::clamp(total_bits * 100.0 / static_cast<double>(link_speed), 0.0, 100.0);
        }
      }
      if (adapter.name.empty())
        adapter.name = adapter.description.empty() ? "Network adapter " + adapter.key
                                                   : adapter.description;
      adapters.push_back(std::move(adapter));
    }
    FreeMibTable(table);
    previous_network = std::move(next);
    previous_network_time = now;
    network_seeded = true;
    std::stable_sort(adapters.begin(), adapters.end(), [](const auto& left, const auto& right) {
      if (left.operational_status != right.operational_status)
        return left.operational_status == "Up";
      return left.name < right.name;
    });
    return adapters;
  }

  std::vector<ProcessHealth> sample_processes() {
    const auto now = std::chrono::steady_clock::now();
    const double elapsed = processes_seeded
                               ? std::chrono::duration<double>(now - previous_process_time).count()
                               : 0.0;
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const double processors = static_cast<double>(std::max<DWORD>(1U, system_info.dwNumberOfProcessors));
    std::unordered_map<std::uint32_t, ProcessCounterSnapshot> next;
    std::vector<ProcessHealth> processes;

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
      return processes;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry) != FALSE) {
      do {
        ProcessHealth process;
        process.process_id = entry.th32ProcessID;
        process.name = utf8_from_wide(entry.szExeFile);
        process.thread_count = entry.cntThreads;
        const HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                              PROCESS_VM_READ,
                                          FALSE, entry.th32ProcessID);
        if (handle != nullptr) {
          FILETIME creation{};
          FILETIME exit{};
          FILETIME kernel{};
          FILETIME user{};
          IO_COUNTERS io{};
          PROCESS_MEMORY_COUNTERS_EX memory{};
          memory.cb = sizeof(memory);
          DWORD handle_count = 0;
          wchar_t image[MAX_PATH * 4]{};
          DWORD image_length = static_cast<DWORD>(std::size(image));
          if (QueryFullProcessImageNameW(handle, 0, image, &image_length) != FALSE)
            process.image_path = utf8_from_wide(std::wstring_view(image, image_length));
          if (GetProcessMemoryInfo(handle,
                                   reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory),
                                   static_cast<DWORD>(sizeof(memory))) != FALSE) {
            process.private_bytes = memory.PrivateUsage;
            process.working_set_bytes = memory.WorkingSetSize;
          }
          if (GetProcessHandleCount(handle, &handle_count) != FALSE)
            process.handle_count = handle_count;
          if (GetProcessTimes(handle, &creation, &exit, &kernel, &user) != FALSE &&
              GetProcessIoCounters(handle, &io) != FALSE) {
            const std::uint64_t cpu = file_time_value(kernel) + file_time_value(user);
            next.emplace(process.process_id,
                         ProcessCounterSnapshot{cpu, io.ReadTransferCount, io.WriteTransferCount});
            const auto previous = previous_processes.find(process.process_id);
            if (previous != previous_processes.end() && elapsed > 0.0 &&
                cpu >= previous->second.cpu_time_100ns) {
              const double wall_100ns = elapsed * 10000000.0 * processors;
              process.cpu_percent = std::clamp(
                  static_cast<double>(cpu - previous->second.cpu_time_100ns) * 100.0 /
                      wall_100ns,
                  0.0, 100.0);
              if (io.ReadTransferCount >= previous->second.read_bytes) {
                process.read_bytes_per_second =
                    static_cast<double>(io.ReadTransferCount - previous->second.read_bytes) /
                    elapsed;
              }
              if (io.WriteTransferCount >= previous->second.write_bytes) {
                process.write_bytes_per_second =
                    static_cast<double>(io.WriteTransferCount - previous->second.write_bytes) /
                    elapsed;
              }
            }
          }
          CloseHandle(handle);
        }
        processes.push_back(std::move(process));
      } while (Process32NextW(snapshot, &entry) != FALSE);
    }
    CloseHandle(snapshot);
    previous_processes = std::move(next);
    previous_process_time = now;
    processes_seeded = true;

    std::stable_sort(processes.begin(), processes.end(), [](const auto& left, const auto& right) {
      const double left_cpu = left.cpu_percent.value_or(0.0);
      const double right_cpu = right.cpu_percent.value_or(0.0);
      if (left_cpu != right_cpu)
        return left_cpu > right_cpu;
      const double left_io = left.read_bytes_per_second.value_or(0.0) +
                             left.write_bytes_per_second.value_or(0.0);
      const double right_io = right.read_bytes_per_second.value_or(0.0) +
                              right.write_bytes_per_second.value_or(0.0);
      if (left_io != right_io)
        return left_io > right_io;
      return left.private_bytes > right.private_bytes;
    });
    if (processes.size() > 25U)
      processes.resize(25U);
    return processes;
  }
};

SystemHealthSampler::SystemHealthSampler() : impl_(std::make_unique<Impl>()) {}
SystemHealthSampler::~SystemHealthSampler() = default;
SystemHealthSampler::SystemHealthSampler(SystemHealthSampler&&) noexcept = default;
SystemHealthSampler& SystemHealthSampler::operator=(SystemHealthSampler&&) noexcept = default;

Result<SystemHealthSnapshot>
SystemHealthSampler::sample(const SystemHealthSampleOptions& options) {
  if (!impl_)
    return Result<SystemHealthSnapshot>::failure(
        health_error("sample", "System health sampler is not initialized"));

  SystemHealthSnapshot snapshot;
  snapshot.captured_utc = utc_now_iso8601();
  {
    wchar_t name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = static_cast<DWORD>(std::size(name));
    if (GetComputerNameW(name, &size) != FALSE)
      snapshot.machine_name = utf8_from_wide(std::wstring_view(name, size));
  }

  FILETIME idle{};
  FILETIME kernel{};
  FILETIME user{};
  if (GetSystemTimes(&idle, &kernel, &user) != FALSE) {
    const std::uint64_t idle_value = file_time_value(idle);
    const std::uint64_t kernel_value = file_time_value(kernel);
    const std::uint64_t user_value = file_time_value(user);
    if (impl_->cpu_seeded && kernel_value >= impl_->previous_kernel &&
        user_value >= impl_->previous_user && idle_value >= impl_->previous_idle) {
      const std::uint64_t idle_delta = idle_value - impl_->previous_idle;
      const std::uint64_t kernel_delta = kernel_value - impl_->previous_kernel;
      const std::uint64_t user_delta = user_value - impl_->previous_user;
      const std::uint64_t total = kernel_delta + user_delta;
      if (total != 0U) {
        const std::uint64_t busy = total > idle_delta ? total - idle_delta : 0U;
        snapshot.cpu_load_percent =
            std::clamp(static_cast<double>(busy) * 100.0 / static_cast<double>(total), 0.0, 100.0);
        snapshot.cpu_load_available = true;
      }
    }
    impl_->previous_idle = idle_value;
    impl_->previous_kernel = kernel_value;
    impl_->previous_user = user_value;
    impl_->cpu_seeded = true;
  } else {
    snapshot.warnings.push_back("CPU load is unavailable from GetSystemTimes.");
  }

  MEMORYSTATUSEX memory{};
  memory.dwLength = sizeof(memory);
  if (GlobalMemoryStatusEx(&memory) != FALSE) {
    snapshot.memory_total_bytes = memory.ullTotalPhys;
    snapshot.memory_used_bytes = memory.ullTotalPhys - memory.ullAvailPhys;
    snapshot.memory_load_percent = static_cast<double>(memory.dwMemoryLoad);
    snapshot.memory.physical_total_bytes = memory.ullTotalPhys;
    snapshot.memory.physical_available_bytes = memory.ullAvailPhys;
    snapshot.memory.physical_used_bytes = snapshot.memory_used_bytes;
    snapshot.memory.physical_load_percent = snapshot.memory_load_percent;
    snapshot.memory.commit_limit_bytes = memory.ullTotalPageFile;
    snapshot.memory.commit_total_bytes = memory.ullTotalPageFile - memory.ullAvailPageFile;
    if (snapshot.memory.commit_limit_bytes != 0U) {
      snapshot.memory.commit_load_percent =
          static_cast<double>(snapshot.memory.commit_total_bytes) * 100.0 /
          static_cast<double>(snapshot.memory.commit_limit_bytes);
    }
    snapshot.memory.pagefile_limit_bytes =
        memory.ullTotalPageFile > memory.ullTotalPhys
            ? memory.ullTotalPageFile - memory.ullTotalPhys
            : 0U;
  } else {
    snapshot.warnings.push_back("Memory load is unavailable from GlobalMemoryStatusEx.");
  }
  impl_->sample_memory_counters(snapshot);

  if (options.refresh_volumes || impl_->cached_volumes.empty())
    impl_->refresh_volumes();
  snapshot.volumes = impl_->cached_volumes;
  impl_->sample_disk(snapshot.volumes);

  if (options.refresh_temperature) {
    std::string source;
    impl_->cached_temperature = query_temperature(source);
    impl_->cached_temperature_source = std::move(source);
  }
  snapshot.cpu_temperature_celsius = impl_->cached_temperature;
  snapshot.temperature_source = impl_->cached_temperature_source;
  if (!snapshot.cpu_temperature_celsius) {
    snapshot.warnings.push_back(
        "CPU temperature is not exposed by a reliable in-box Windows thermal source.");
  }

  if (options.refresh_storage_health || impl_->cached_storage_devices.empty())
    impl_->cached_storage_devices = query_storage_health(snapshot.warnings);
  snapshot.storage_devices = impl_->cached_storage_devices;
  if (options.refresh_storage_health) {
    impl_->cached_events = read_health_events(snapshot.warnings);
    impl_->events_read = true;
  }
  snapshot.event_counts = impl_->cached_events;
  snapshot.events_read = impl_->events_read;
  snapshot.network_adapters = impl_->sample_network();
  if (options.refresh_processes)
    snapshot.top_processes = impl_->sample_processes();

  evaluate_system_health(snapshot);
  return Result<SystemHealthSnapshot>::success(std::move(snapshot));
}

} // namespace support_assist
