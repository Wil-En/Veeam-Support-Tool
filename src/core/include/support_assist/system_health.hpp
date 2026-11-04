#pragma once

#include "support_assist/error.hpp"

#include <cstdint>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class HealthSeverity {
  unknown,
  healthy,
  informational,
  warning,
  critical
};

std::string to_string(HealthSeverity severity);

struct HealthFinding {
  HealthSeverity severity = HealthSeverity::unknown;
  std::string component;
  std::string metric;
  std::string summary;
  std::string observed_value;
  std::string threshold;
};

struct MemoryHealth {
  std::uint64_t physical_total_bytes = 0;
  std::uint64_t physical_used_bytes = 0;
  std::uint64_t physical_available_bytes = 0;
  double physical_load_percent = 0.0;
  std::uint64_t commit_total_bytes = 0;
  std::uint64_t commit_limit_bytes = 0;
  double commit_load_percent = 0.0;
  std::uint64_t pagefile_used_bytes = 0;
  std::uint64_t pagefile_limit_bytes = 0;
  double pagefile_load_percent = 0.0;
  std::optional<double> pages_input_per_second;
  std::optional<double> page_reads_per_second;
  std::optional<double> page_writes_per_second;
  std::optional<double> page_faults_per_second;
};

struct NetworkAdapterHealth {
  std::string key;
  std::string name;
  std::string description;
  std::string operational_status;
  std::uint64_t receive_link_speed_bits = 0;
  std::uint64_t transmit_link_speed_bits = 0;
  std::uint32_t mtu = 0; // bytes; 0 when not read
  std::optional<double> receive_bytes_per_second;
  std::optional<double> transmit_bytes_per_second;
  std::uint64_t receive_discards = 0;
  std::uint64_t transmit_discards = 0;
  std::uint64_t receive_errors = 0;
  std::uint64_t transmit_errors = 0;
  std::uint64_t receive_discards_delta = 0;
  std::uint64_t transmit_discards_delta = 0;
  std::uint64_t receive_errors_delta = 0;
  std::uint64_t transmit_errors_delta = 0;
  std::optional<double> utilization_percent;
  bool virtual_adapter = false;
};

struct ProcessHealth {
  std::uint32_t process_id = 0;
  std::string name;
  std::string image_path;
  std::optional<double> cpu_percent;
  std::uint64_t private_bytes = 0;
  std::uint64_t working_set_bytes = 0;
  std::optional<double> read_bytes_per_second;
  std::optional<double> write_bytes_per_second;
  std::uint32_t thread_count = 0;
  std::uint32_t handle_count = 0;
};

struct StorageDeviceHealth {
  std::string name;
  std::string media_type;
  std::string bus_type;
  std::string health_status;
  std::string operational_status;
  std::uint64_t size_bytes = 0;
  bool health_available = false;
  bool predictive_failure = false;
  std::string predictive_failure_reason;
};

struct VolumeHealth {
  std::string root_path;
  std::string label;
  std::string filesystem;
  std::string drive_type;
  std::uint64_t total_bytes = 0;
  std::uint64_t free_bytes = 0;
  std::optional<double> read_bytes_per_second;
  std::optional<double> write_bytes_per_second;
  std::optional<double> active_percent;
  std::optional<double> average_read_latency_ms;
  std::optional<double> average_write_latency_ms;
  std::optional<double> queue_length;
  bool capacity_available = false;
  // As Volume Check reads them (attach_volume_layout).
  std::uint32_t logical_sector_bytes = 0;
  std::uint32_t physical_sector_bytes = 0;
  std::string partition_style; // "GPT", "MBR"
  std::string storage_driver;  // "stornvme 10.0.26100.1150"; Linux: "nvme", "ahci"
};

// An event-log check from config/checks/health-events.json: disk problems in the last days, and
// events counted since the last restart (a desktop heap allocation failure).
struct HealthEventCheck {
  std::string log;                    // "System", "Application"
  std::vector<std::string> providers; // any of them; empty for any provider
  std::uint32_t id = 0;
  bool since_restart = false;         // else the last event_days days
  HealthSeverity severity = HealthSeverity::warning;
  std::string meaning;
};

struct HealthEventCount {
  HealthEventCheck check;
  std::uint64_t count = 0;
  std::int64_t newest_unix_millis = 0;
};

struct SystemHealthSnapshot {
  std::string machine_name;
  double cpu_load_percent = 0.0;
  bool cpu_load_available = false;
  std::optional<double> cpu_temperature_celsius;
  std::string temperature_source;
  std::uint64_t memory_total_bytes = 0;
  std::uint64_t memory_used_bytes = 0;
  double memory_load_percent = 0.0;
  MemoryHealth memory;
  std::optional<double> processor_queue_length;
  std::vector<VolumeHealth> volumes;
  std::vector<StorageDeviceHealth> storage_devices;
  std::vector<NetworkAdapterHealth> network_adapters;
  std::vector<ProcessHealth> top_processes;
  std::vector<HealthFinding> findings;
  std::vector<std::string> warnings;
  std::string captured_utc;
  // The event-log checks that found events (Windows), read with the storage health.
  std::vector<HealthEventCount> event_counts;
  bool events_read = false;
};

struct SystemHealthSampleOptions {
  bool refresh_volumes = false;
  bool refresh_temperature = false;
  bool refresh_storage_health = false;
  bool refresh_network_adapters = false;
  bool refresh_processes = true;
};

class SystemHealthSampler {
public:
  SystemHealthSampler();
  ~SystemHealthSampler();
  SystemHealthSampler(const SystemHealthSampler&) = delete;
  SystemHealthSampler& operator=(const SystemHealthSampler&) = delete;
  SystemHealthSampler(SystemHealthSampler&&) noexcept;
  SystemHealthSampler& operator=(SystemHealthSampler&&) noexcept;

  Result<SystemHealthSnapshot> sample(const SystemHealthSampleOptions& options = {});

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

std::string format_health_bytes(std::uint64_t bytes);
std::string format_health_rate(double bytes_per_second);
std::string format_system_health_report(const SystemHealthSnapshot& snapshot);
Result<SystemHealthSnapshot> parse_system_health_report(std::string_view text);
void evaluate_system_health(SystemHealthSnapshot& snapshot);

// The event-log checks and the days a disk event counts for, from health-events.json.
const std::vector<HealthEventCheck>& health_event_checks();
int health_event_days();

// "10 Gb/s, MTU 1500"; empty when neither is known.
std::string health_link_text(const NetworkAdapterHealth& adapter);
// "GPT, 512 B sectors (4 KB physical), stornvme 10.0.26100.1150"; empty when none is known.
std::string health_volume_layout_text(const VolumeHealth& volume);
// Fills each volume's sector sizes, partition style and driver from Volume Check, which is read
// again only for a volume it has not seen.
void attach_volume_layout(std::vector<VolumeHealth>& volumes);

} // namespace support_assist
