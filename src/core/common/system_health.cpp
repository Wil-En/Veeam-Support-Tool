#include "support_assist/system_health.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/json.hpp"
#include "support_assist/time.hpp"
#include "support_assist/volume_check.hpp"

#include <array>
#include <map>
#include <mutex>
#include <cmath>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <vector>
#include <type_traits>

namespace support_assist {
namespace {

std::string format_scaled(double value, const std::array<const char*, 5>& units) {
  std::size_t unit = 0;
  while (value >= 1024.0 && unit + 1U < units.size()) {
    value /= 1024.0;
    ++unit;
  }
  std::ostringstream output;
  if (value >= 100.0 || unit == 0U)
    output << std::fixed << std::setprecision(0);
  else if (value >= 10.0)
    output << std::fixed << std::setprecision(1);
  else
    output << std::fixed << std::setprecision(2);
  output << value << ' ' << units[unit];
  return output.str();
}


std::string percent_text(double value) {
  std::ostringstream output;
  output << std::fixed << std::setprecision(1) << value << '%';
  return output.str();
}

void add_finding(SystemHealthSnapshot& snapshot,
                 HealthSeverity severity,
                 std::string component,
                 std::string metric,
                 std::string summary,
                 std::string observed,
                 std::string threshold) {
  snapshot.findings.push_back(HealthFinding{severity,
                                            std::move(component),
                                            std::move(metric),
                                            std::move(summary),
                                            std::move(observed),
                                            std::move(threshold)});
}

std::string health_escape(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  for (const char ch : value) {
    switch (ch) {
    case '\\': result += "\\\\"; break;
    case '\t': result += "\\t"; break;
    case '\r': result += "\\r"; break;
    case '\n': result += "\\n"; break;
    default: result.push_back(ch); break;
    }
  }
  return result;
}

std::string health_unescape(std::string_view value) {
  std::string result;
  result.reserve(value.size());
  bool escape = false;
  for (const char ch : value) {
    if (!escape) {
      if (ch == '\\') escape = true;
      else result.push_back(ch);
      continue;
    }
    switch (ch) {
    case 't': result.push_back('\t'); break;
    case 'r': result.push_back('\r'); break;
    case 'n': result.push_back('\n'); break;
    case '\\': result.push_back('\\'); break;
    default: result.push_back(ch); break;
    }
    escape = false;
  }
  if (escape) result.push_back('\\');
  return result;
}

std::vector<std::string> health_fields(std::string_view line) {
  std::vector<std::string> result;
  std::size_t start = 0;
  while (start <= line.size()) {
    const std::size_t tab = line.find('\t', start);
    const std::size_t end = tab == std::string_view::npos ? line.size() : tab;
    result.push_back(health_unescape(line.substr(start, end - start)));
    if (tab == std::string_view::npos) break;
    start = tab + 1U;
  }
  return result;
}

template <typename T>
T health_number(std::string_view value, T fallback = {}) {
  try {
    if constexpr (std::is_integral_v<T>)
      return static_cast<T>(std::stoull(std::string(value)));
    else
      return static_cast<T>(std::stod(std::string(value)));
  } catch (...) {
    return fallback;
  }
}

std::optional<double> health_optional_double(std::string_view value) {
  if (value.empty()) return std::nullopt;
  try { return std::stod(std::string(value)); } catch (...) { return std::nullopt; }
}

std::string health_optional_text(const std::optional<double>& value) {
  if (!value) return {};
  std::ostringstream output;
  output << std::setprecision(17) << *value;
  return output.str();
}

HealthSeverity health_severity(std::string_view value) {
  if (value == "healthy") return HealthSeverity::healthy;
  if (value == "information") return HealthSeverity::informational;
  if (value == "warning") return HealthSeverity::warning;
  if (value == "critical") return HealthSeverity::critical;
  return HealthSeverity::unknown;
}

} // namespace

std::string format_health_bytes(std::uint64_t bytes) {
  constexpr std::array<const char*, 5> units{"B", "KiB", "MiB", "GiB", "TiB"};
  return format_scaled(static_cast<double>(bytes), units);
}

std::string format_health_rate(double bytes_per_second) {
  if (!std::isfinite(bytes_per_second) || bytes_per_second < 0.0)
    bytes_per_second = 0.0;
  constexpr std::array<const char*, 5> units{"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"};
  return format_scaled(bytes_per_second, units);
}




std::string format_system_health_report(const SystemHealthSnapshot& snapshot) {
  std::ostringstream output;
  output << "Support Assist Tool - System Health Snapshot\n"
         << "Format Version: 1\n"
         << "Machine: " << (snapshot.machine_name.empty() ? "Unknown" : snapshot.machine_name) << "\n"
         << "Captured UTC: " << (snapshot.captured_utc.empty() ? "Unknown" : snapshot.captured_utc) << "\n\n";
  if (snapshot.cpu_load_available)
    output << "CPU utilization: " << percent_text(snapshot.cpu_load_percent) << "\n";
  else
    output << "CPU utilization: unavailable\n";
  if (snapshot.cpu_temperature_celsius)
    output << "CPU temperature: " << std::fixed << std::setprecision(1)
           << *snapshot.cpu_temperature_celsius << " C"
           << (snapshot.temperature_source.empty() ? "" : " (" + snapshot.temperature_source + ")") << "\n";
  output << "Physical memory: " << percent_text(snapshot.memory.physical_load_percent != 0.0
                                                    ? snapshot.memory.physical_load_percent
                                                    : snapshot.memory_load_percent)
         << " | Used " << format_health_bytes(snapshot.memory.physical_used_bytes != 0U
                                                   ? snapshot.memory.physical_used_bytes
                                                   : snapshot.memory_used_bytes)
         << " / " << format_health_bytes(snapshot.memory.physical_total_bytes != 0U
                                               ? snapshot.memory.physical_total_bytes
                                               : snapshot.memory_total_bytes) << "\n";
  if (snapshot.memory.commit_limit_bytes != 0U)
    output << "Committed memory: " << percent_text(snapshot.memory.commit_load_percent)
           << " | " << format_health_bytes(snapshot.memory.commit_total_bytes)
           << " / " << format_health_bytes(snapshot.memory.commit_limit_bytes) << "\n";
  if (snapshot.memory.pages_input_per_second)
    output << "Pages input/sec: " << *snapshot.memory.pages_input_per_second << "\n";

  output << "\nFindings (" << snapshot.findings.size() << "):\n";
  if (snapshot.findings.empty())
    output << "- No threshold findings in this snapshot.\n";
  for (const auto& finding : snapshot.findings) {
    output << "- [" << to_string(finding.severity) << "] " << finding.component << " / "
           << finding.metric << ": " << finding.summary;
    if (!finding.observed_value.empty())
      output << " | Observed: " << finding.observed_value;
    if (!finding.threshold.empty())
      output << " | Threshold: " << finding.threshold;
    output << "\n";
  }

  output << "\nVolumes (" << snapshot.volumes.size() << "):\n";
  for (const auto& volume : snapshot.volumes) {
    output << "- " << volume.root_path;
    if (!volume.label.empty()) output << " [" << volume.label << "]";
    if (!volume.filesystem.empty()) output << " " << volume.filesystem;
    if (volume.capacity_available && volume.total_bytes != 0U)
      output << " | Free " << format_health_bytes(volume.free_bytes) << " / "
             << format_health_bytes(volume.total_bytes);
    if (volume.active_percent) output << " | Active " << percent_text(*volume.active_percent);
    if (volume.average_read_latency_ms) output << " | Read " << *volume.average_read_latency_ms << " ms";
    if (volume.average_write_latency_ms) output << " | Write " << *volume.average_write_latency_ms << " ms";
    output << "\n";
  }

  output << "\nStorage devices (" << snapshot.storage_devices.size() << "):\n";
  for (const auto& device : snapshot.storage_devices) {
    output << "- " << device.name << " | Health: "
           << (device.health_status.empty() ? "Unknown" : device.health_status);
    if (!device.operational_status.empty()) output << " | Operational: " << device.operational_status;
    if (!device.media_type.empty()) output << " | Media: " << device.media_type;
    if (!device.bus_type.empty()) output << " | Bus: " << device.bus_type;
    if (device.size_bytes != 0U) output << " | Size: " << format_health_bytes(device.size_bytes);
    if (device.predictive_failure) output << " | PREDICTIVE FAILURE";
    output << "\n";
  }

  output << "\nNetwork adapters (" << snapshot.network_adapters.size() << "):\n";
  for (const auto& adapter : snapshot.network_adapters) {
    output << "- " << adapter.name << " | " << adapter.operational_status;
    if (adapter.receive_bytes_per_second) output << " | RX " << format_health_rate(*adapter.receive_bytes_per_second);
    if (adapter.transmit_bytes_per_second) output << " | TX " << format_health_rate(*adapter.transmit_bytes_per_second);
    if (adapter.utilization_percent) output << " | Utilization " << percent_text(*adapter.utilization_percent);
    output << " | Errors RX/TX " << adapter.receive_errors << "/" << adapter.transmit_errors
           << " | Discards RX/TX " << adapter.receive_discards << "/" << adapter.transmit_discards << "\n";
  }

  output << "\nTop processes (" << snapshot.top_processes.size() << "):\n";
  for (const auto& process : snapshot.top_processes) {
    output << "- " << process.name << " (PID " << process.process_id << ")";
    if (process.cpu_percent) output << " | CPU " << percent_text(*process.cpu_percent);
    output << " | Private " << format_health_bytes(process.private_bytes)
           << " | Working set " << format_health_bytes(process.working_set_bytes)
           << " | Threads " << process.thread_count;
    if (process.read_bytes_per_second) output << " | Read " << format_health_rate(*process.read_bytes_per_second);
    if (process.write_bytes_per_second) output << " | Write " << format_health_rate(*process.write_bytes_per_second);
    output << "\n";
  }

  if (!snapshot.warnings.empty()) {
    output << "\nSampler warnings:\n";
    for (const auto& warning : snapshot.warnings) output << "- " << warning << "\n";
  }

  // The structured appendix keeps the text file readable while allowing SAT to
  // faithfully reopen the saved dashboard without reverse-engineering prose.
  output << "\n[SupportAssistHealthDataV1]\n";
  output << "META\t" << health_escape(snapshot.machine_name) << "\t"
         << health_escape(snapshot.captured_utc) << "\n";
  output << "CPU\t" << (snapshot.cpu_load_available ? "1" : "0") << "\t"
         << std::setprecision(17) << snapshot.cpu_load_percent << "\t"
         << health_optional_text(snapshot.cpu_temperature_celsius) << "\t"
         << health_escape(snapshot.temperature_source) << "\t"
         << health_optional_text(snapshot.processor_queue_length) << "\n";
  output << "MEM\t" << snapshot.memory.physical_total_bytes << "\t"
         << snapshot.memory.physical_used_bytes << "\t"
         << snapshot.memory.physical_available_bytes << "\t"
         << std::setprecision(17) << snapshot.memory.physical_load_percent << "\t"
         << snapshot.memory.commit_total_bytes << "\t" << snapshot.memory.commit_limit_bytes << "\t"
         << snapshot.memory.commit_load_percent << "\t" << snapshot.memory.pagefile_used_bytes << "\t"
         << snapshot.memory.pagefile_limit_bytes << "\t" << snapshot.memory.pagefile_load_percent << "\t"
         << health_optional_text(snapshot.memory.pages_input_per_second) << "\t"
         << health_optional_text(snapshot.memory.page_reads_per_second) << "\t"
         << health_optional_text(snapshot.memory.page_writes_per_second) << "\t"
         << health_optional_text(snapshot.memory.page_faults_per_second) << "\n";
  for (const auto& finding : snapshot.findings)
    output << "FINDING\t" << to_string(finding.severity) << "\t" << health_escape(finding.component)
           << "\t" << health_escape(finding.metric) << "\t" << health_escape(finding.summary)
           << "\t" << health_escape(finding.observed_value) << "\t" << health_escape(finding.threshold) << "\n";
  for (const auto& volume : snapshot.volumes)
    output << "VOLUME\t" << health_escape(volume.root_path) << "\t" << health_escape(volume.label)
           << "\t" << health_escape(volume.filesystem) << "\t" << health_escape(volume.drive_type)
           << "\t" << volume.total_bytes << "\t" << volume.free_bytes << "\t"
           << health_optional_text(volume.read_bytes_per_second) << "\t"
           << health_optional_text(volume.write_bytes_per_second) << "\t"
           << health_optional_text(volume.active_percent) << "\t"
           << health_optional_text(volume.average_read_latency_ms) << "\t"
           << health_optional_text(volume.average_write_latency_ms) << "\t"
           << health_optional_text(volume.queue_length) << "\t" << (volume.capacity_available ? "1" : "0") << "\n";
  for (const auto& device : snapshot.storage_devices)
    output << "STORAGE\t" << health_escape(device.name) << "\t" << health_escape(device.media_type)
           << "\t" << health_escape(device.bus_type) << "\t" << health_escape(device.health_status)
           << "\t" << health_escape(device.operational_status) << "\t" << device.size_bytes
           << "\t" << (device.health_available ? "1" : "0") << "\t"
           << (device.predictive_failure ? "1" : "0") << "\t"
           << health_escape(device.predictive_failure_reason) << "\n";
  for (const auto& adapter : snapshot.network_adapters)
    output << "NIC\t" << health_escape(adapter.key) << "\t" << health_escape(adapter.name)
           << "\t" << health_escape(adapter.description) << "\t" << health_escape(adapter.operational_status)
           << "\t" << adapter.receive_link_speed_bits << "\t" << adapter.transmit_link_speed_bits
           << "\t" << health_optional_text(adapter.receive_bytes_per_second) << "\t"
           << health_optional_text(adapter.transmit_bytes_per_second) << "\t" << adapter.receive_discards
           << "\t" << adapter.transmit_discards << "\t" << adapter.receive_errors << "\t"
           << adapter.transmit_errors << "\t" << adapter.receive_discards_delta << "\t"
           << adapter.transmit_discards_delta << "\t" << adapter.receive_errors_delta << "\t"
           << adapter.transmit_errors_delta << "\t" << health_optional_text(adapter.utilization_percent)
           << "\t" << (adapter.virtual_adapter ? "1" : "0") << "\n";
  for (const auto& process : snapshot.top_processes)
    output << "PROCESS\t" << process.process_id << "\t" << health_escape(process.name)
           << "\t" << health_escape(process.image_path) << "\t" << health_optional_text(process.cpu_percent)
           << "\t" << process.private_bytes << "\t" << process.working_set_bytes << "\t"
           << health_optional_text(process.read_bytes_per_second) << "\t"
           << health_optional_text(process.write_bytes_per_second) << "\t" << process.thread_count
           << "\t" << process.handle_count << "\n";
  for (const auto& warning : snapshot.warnings)
    output << "WARNING\t" << health_escape(warning) << "\n";
  output << "[/SupportAssistHealthDataV1]\n";
  return output.str();
}

Result<SystemHealthSnapshot> parse_system_health_report(std::string_view text) {
  constexpr std::string_view begin_marker = "[SupportAssistHealthDataV1]";
  constexpr std::string_view end_marker = "[/SupportAssistHealthDataV1]";
  const std::size_t begin = text.find(begin_marker);
  if (begin == std::string_view::npos) {
    Error error;
    error.component = "SystemHealth";
    error.operation = "load saved snapshot";
    error.message = "The selected file does not contain a reloadable Support Assist health snapshot.";
    return Result<SystemHealthSnapshot>::failure(std::move(error));
  }
  const std::size_t data_start = begin + begin_marker.size();
  const std::size_t end = text.find(end_marker, data_start);
  if (end == std::string_view::npos) {
    Error error;
    error.component = "SystemHealth";
    error.operation = "load saved snapshot";
    error.message = "The saved health snapshot is incomplete.";
    return Result<SystemHealthSnapshot>::failure(std::move(error));
  }

  SystemHealthSnapshot snapshot;
  std::istringstream input(std::string(text.substr(data_start, end - data_start)));
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    auto fields = health_fields(line);
    if (fields.empty()) continue;
    const std::string& tag = fields[0];
    if (tag == "META" && fields.size() >= 3U) {
      snapshot.machine_name = fields[1];
      snapshot.captured_utc = fields[2];
    } else if (tag == "CPU" && fields.size() >= 6U) {
      snapshot.cpu_load_available = fields[1] == "1";
      snapshot.cpu_load_percent = health_number<double>(fields[2]);
      snapshot.cpu_temperature_celsius = health_optional_double(fields[3]);
      snapshot.temperature_source = fields[4];
      snapshot.processor_queue_length = health_optional_double(fields[5]);
    } else if (tag == "MEM" && fields.size() >= 15U) {
      snapshot.memory.physical_total_bytes = health_number<std::uint64_t>(fields[1]);
      snapshot.memory.physical_used_bytes = health_number<std::uint64_t>(fields[2]);
      snapshot.memory.physical_available_bytes = health_number<std::uint64_t>(fields[3]);
      snapshot.memory.physical_load_percent = health_number<double>(fields[4]);
      snapshot.memory.commit_total_bytes = health_number<std::uint64_t>(fields[5]);
      snapshot.memory.commit_limit_bytes = health_number<std::uint64_t>(fields[6]);
      snapshot.memory.commit_load_percent = health_number<double>(fields[7]);
      snapshot.memory.pagefile_used_bytes = health_number<std::uint64_t>(fields[8]);
      snapshot.memory.pagefile_limit_bytes = health_number<std::uint64_t>(fields[9]);
      snapshot.memory.pagefile_load_percent = health_number<double>(fields[10]);
      snapshot.memory.pages_input_per_second = health_optional_double(fields[11]);
      snapshot.memory.page_reads_per_second = health_optional_double(fields[12]);
      snapshot.memory.page_writes_per_second = health_optional_double(fields[13]);
      snapshot.memory.page_faults_per_second = health_optional_double(fields[14]);
      snapshot.memory_total_bytes = snapshot.memory.physical_total_bytes;
      snapshot.memory_used_bytes = snapshot.memory.physical_used_bytes;
      snapshot.memory_load_percent = snapshot.memory.physical_load_percent;
    } else if (tag == "FINDING" && fields.size() >= 7U) {
      snapshot.findings.push_back(HealthFinding{health_severity(fields[1]), fields[2], fields[3],
                                                fields[4], fields[5], fields[6]});
    } else if (tag == "VOLUME" && fields.size() >= 14U) {
      VolumeHealth value;
      value.root_path = fields[1]; value.label = fields[2]; value.filesystem = fields[3];
      value.drive_type = fields[4]; value.total_bytes = health_number<std::uint64_t>(fields[5]);
      value.free_bytes = health_number<std::uint64_t>(fields[6]);
      value.read_bytes_per_second = health_optional_double(fields[7]);
      value.write_bytes_per_second = health_optional_double(fields[8]);
      value.active_percent = health_optional_double(fields[9]);
      value.average_read_latency_ms = health_optional_double(fields[10]);
      value.average_write_latency_ms = health_optional_double(fields[11]);
      value.queue_length = health_optional_double(fields[12]); value.capacity_available = fields[13] == "1";
      snapshot.volumes.push_back(std::move(value));
    } else if (tag == "STORAGE" && fields.size() >= 10U) {
      StorageDeviceHealth value;
      value.name = fields[1]; value.media_type = fields[2]; value.bus_type = fields[3];
      value.health_status = fields[4]; value.operational_status = fields[5];
      value.size_bytes = health_number<std::uint64_t>(fields[6]); value.health_available = fields[7] == "1";
      value.predictive_failure = fields[8] == "1"; value.predictive_failure_reason = fields[9];
      snapshot.storage_devices.push_back(std::move(value));
    } else if (tag == "NIC" && fields.size() >= 19U) {
      NetworkAdapterHealth value;
      value.key = fields[1]; value.name = fields[2]; value.description = fields[3]; value.operational_status = fields[4];
      value.receive_link_speed_bits = health_number<std::uint64_t>(fields[5]);
      value.transmit_link_speed_bits = health_number<std::uint64_t>(fields[6]);
      value.receive_bytes_per_second = health_optional_double(fields[7]);
      value.transmit_bytes_per_second = health_optional_double(fields[8]);
      value.receive_discards = health_number<std::uint64_t>(fields[9]);
      value.transmit_discards = health_number<std::uint64_t>(fields[10]);
      value.receive_errors = health_number<std::uint64_t>(fields[11]); value.transmit_errors = health_number<std::uint64_t>(fields[12]);
      value.receive_discards_delta = health_number<std::uint64_t>(fields[13]); value.transmit_discards_delta = health_number<std::uint64_t>(fields[14]);
      value.receive_errors_delta = health_number<std::uint64_t>(fields[15]); value.transmit_errors_delta = health_number<std::uint64_t>(fields[16]);
      value.utilization_percent = health_optional_double(fields[17]); value.virtual_adapter = fields[18] == "1";
      snapshot.network_adapters.push_back(std::move(value));
    } else if (tag == "PROCESS" && fields.size() >= 11U) {
      ProcessHealth value;
      value.process_id = health_number<std::uint32_t>(fields[1]); value.name = fields[2]; value.image_path = fields[3];
      value.cpu_percent = health_optional_double(fields[4]); value.private_bytes = health_number<std::uint64_t>(fields[5]);
      value.working_set_bytes = health_number<std::uint64_t>(fields[6]);
      value.read_bytes_per_second = health_optional_double(fields[7]); value.write_bytes_per_second = health_optional_double(fields[8]);
      value.thread_count = health_number<std::uint32_t>(fields[9]); value.handle_count = health_number<std::uint32_t>(fields[10]);
      snapshot.top_processes.push_back(std::move(value));
    } else if (tag == "WARNING" && fields.size() >= 2U) {
      snapshot.warnings.push_back(fields[1]);
    }
  }
  return Result<SystemHealthSnapshot>::success(std::move(snapshot));
}

std::string to_string(HealthSeverity severity) {
  switch (severity) {
  case HealthSeverity::healthy:
    return "healthy";
  case HealthSeverity::informational:
    return "information";
  case HealthSeverity::warning:
    return "warning";
  case HealthSeverity::critical:
    return "critical";
  case HealthSeverity::unknown:
  default:
    return "unknown";
  }
}

void evaluate_system_health(SystemHealthSnapshot& snapshot) {
  snapshot.findings.clear();

  if (snapshot.cpu_load_available) {
    if (snapshot.cpu_load_percent >= 95.0) {
      add_finding(snapshot, HealthSeverity::critical, "CPU", "Utilization",
                  "CPU utilization is critically high and may be delaying all workloads.",
                  percent_text(snapshot.cpu_load_percent), "Critical at 95% or higher");
    } else if (snapshot.cpu_load_percent >= 85.0) {
      add_finding(snapshot, HealthSeverity::warning, "CPU", "Utilization",
                  "CPU utilization is high; review the top process list.",
                  percent_text(snapshot.cpu_load_percent), "Warning at 85% or higher");
    }
  }

  if (snapshot.cpu_temperature_celsius) {
    const double temperature = *snapshot.cpu_temperature_celsius;
    std::ostringstream observed;
    observed << std::fixed << std::setprecision(1) << temperature << " C";
    if (temperature >= 95.0) {
      add_finding(snapshot, HealthSeverity::critical, "Temperature", "CPU thermal zone",
                  "The available Windows thermal reading is critically high.",
                  observed.str(), "Critical at 95 C or higher");
    } else if (temperature >= 85.0) {
      add_finding(snapshot, HealthSeverity::warning, "Temperature", "CPU thermal zone",
                  "The available Windows thermal reading is high.",
                  observed.str(), "Warning at 85 C or higher");
    }
  }

  const double physical = snapshot.memory.physical_load_percent != 0.0
                              ? snapshot.memory.physical_load_percent
                              : snapshot.memory_load_percent;
  if (physical >= 95.0) {
    add_finding(snapshot, HealthSeverity::critical, "Memory", "Physical memory",
                "Physical memory pressure is critical and paging is likely.",
                percent_text(physical), "Critical at 95% or higher");
  } else if (physical >= 85.0) {
    add_finding(snapshot, HealthSeverity::warning, "Memory", "Physical memory",
                "Physical memory use is high.",
                percent_text(physical), "Warning at 85% or higher");
  }

  if (snapshot.memory.commit_limit_bytes != 0U) {
    if (snapshot.memory.commit_load_percent >= 95.0) {
      add_finding(snapshot, HealthSeverity::critical, "Memory", "Committed memory",
                  "Committed memory is close to the system commit limit.",
                  percent_text(snapshot.memory.commit_load_percent),
                  "Critical at 95% or higher");
    } else if (snapshot.memory.commit_load_percent >= 85.0) {
      add_finding(snapshot, HealthSeverity::warning, "Memory", "Committed memory",
                  "Committed memory is high relative to the commit limit.",
                  percent_text(snapshot.memory.commit_load_percent),
                  "Warning at 85% or higher");
    }
  }

  // Pages input are hard faults: pages read back from disk. They point to a memory shortage only
  // while memory is short; with memory free they are file reads through mapped I/O (a large copy, a
  // ZIP, a scan). Page faults/sec counts soft faults as well and is never a finding.
  const bool commit_short =
      snapshot.memory.commit_limit_bytes != 0U && snapshot.memory.commit_load_percent >= 90.0;
  if ((physical >= 90.0 || commit_short) && snapshot.memory.pages_input_per_second &&
      *snapshot.memory.pages_input_per_second >= 100.0) {
    add_finding(snapshot, physical >= 95.0 || commit_short ? HealthSeverity::critical : HealthSeverity::warning,
                "Memory", "Pages input/sec",
                "Memory is short and pages are being read back from disk, which slows the machine.",
                std::to_string(static_cast<std::uint64_t>(*snapshot.memory.pages_input_per_second)) +
                    " pages/sec with " + percent_text(physical) + " of physical memory in use",
                "A finding at 100 pages/sec while 90% or more of physical memory or of the commit limit is in "
                "use; critical at 95% physical or 90% committed");
  }

  for (const auto& volume : snapshot.volumes) {
    if (volume.capacity_available && volume.total_bytes != 0U) {
      const double free_percent =
          static_cast<double>(volume.free_bytes) * 100.0 /
          static_cast<double>(volume.total_bytes);
      if (free_percent < 5.0) {
        add_finding(snapshot, HealthSeverity::critical, "Storage", volume.root_path,
                    "The volume is critically low on free space.",
                    percent_text(free_percent) + " free", "Critical below 5% free");
      } else if (free_percent < 15.0) {
        add_finding(snapshot, HealthSeverity::warning, "Storage", volume.root_path,
                    "The volume is low on free space.",
                    percent_text(free_percent) + " free", "Warning below 15% free");
      }
    }
    const double latency = std::max(volume.average_read_latency_ms.value_or(0.0),
                                    volume.average_write_latency_ms.value_or(0.0));
    if (volume.active_percent && *volume.active_percent >= 98.0 && latency >= 50.0) {
      add_finding(snapshot, HealthSeverity::critical, "Storage", volume.root_path,
                  "The volume is saturated with severe I/O latency.",
                  percent_text(*volume.active_percent) + ", " +
                      std::to_string(static_cast<std::uint64_t>(latency)) + " ms",
                  "Critical at 98% active and 50 ms latency");
    } else if (volume.active_percent && *volume.active_percent >= 90.0 &&
               latency >= 20.0) {
      add_finding(snapshot, HealthSeverity::warning, "Storage", volume.root_path,
                  "The volume is busy and responding slowly.",
                  percent_text(*volume.active_percent) + ", " +
                      std::to_string(static_cast<std::uint64_t>(latency)) + " ms",
                  "Warning at 90% active and 20 ms latency");
    }
  }

  for (const auto& device : snapshot.storage_devices) {
    if (device.predictive_failure) {
      add_finding(snapshot, HealthSeverity::critical, "Storage hardware", device.name,
                  "The storage device reports a predictive failure condition.",
                  device.predictive_failure_reason.empty() ? "Predictive failure"
                                                           : device.predictive_failure_reason,
                  "Any predictive-failure report is critical");
    } else if (device.health_available && device.health_status != "Healthy" &&
               device.health_status != "Unknown") {
      add_finding(snapshot,
                  device.health_status == "Unhealthy" ? HealthSeverity::critical
                                                       : HealthSeverity::warning,
                  "Storage hardware", device.name,
                  "The storage device health state is not healthy.",
                  device.health_status, "Expected Healthy");
    }
  }

  for (const auto& adapter : snapshot.network_adapters) {
    const std::uint64_t errors =
        adapter.receive_errors_delta + adapter.transmit_errors_delta;
    const std::uint64_t drops =
        adapter.receive_discards_delta + adapter.transmit_discards_delta;
    if (errors != 0U) {
      add_finding(snapshot, HealthSeverity::warning, "Network", adapter.name,
                  "The network adapter reports packet errors.",
                  std::to_string(errors) + " new error(s) since the previous sample",
                  "Expected no increasing errors");
    } else if (drops != 0U) {
      add_finding(snapshot, HealthSeverity::informational, "Network", adapter.name,
                  "The network adapter reports discarded packets.",
                  std::to_string(drops) + " new discard(s) since the previous sample",
                  "Investigate when the count is increasing");
    }
    if (adapter.utilization_percent && *adapter.utilization_percent >= 95.0) {
      add_finding(snapshot, HealthSeverity::critical, "Network", adapter.name,
                  "The network link is close to saturation.",
                  percent_text(*adapter.utilization_percent),
                  "Critical at 95% or higher");
    } else if (adapter.utilization_percent && *adapter.utilization_percent >= 80.0) {
      add_finding(snapshot, HealthSeverity::warning, "Network", adapter.name,
                  "The network link is heavily utilized.",
                  percent_text(*adapter.utilization_percent),
                  "Warning at 80% or higher");
    }
  }

  // The event-log checks that found events: disk problems in the last days, and since the restart.
  for (const HealthEventCount& found : snapshot.event_counts) {
    if (found.count == 0U)
      continue;
    const HealthEventCheck& check = found.check;
    const std::string window = check.since_restart ? std::string("since the last restart")
                                                   : "in the last " + std::to_string(health_event_days()) + " days";
    std::string providers;
    for (const std::string& provider : check.providers)
      providers += (providers.empty() ? "" : ", ") + provider;
    std::string observed = std::to_string(found.count) + (found.count == 1U ? " event " : " events ") + window;
    if (found.newest_unix_millis > 0)
      observed += ", newest " + readable_utc_from_unix_millis(found.newest_unix_millis - found.newest_unix_millis % 1000);
    add_finding(snapshot, check.severity, check.since_restart ? "Session" : "Storage",
                "Event " + std::to_string(check.id) + (providers.empty() ? "" : " (" + providers + ")"), check.meaning,
                observed, "Any event " + window + " in the " + check.log + " log");
  }

  std::stable_sort(snapshot.findings.begin(), snapshot.findings.end(),
                   [](const auto& left, const auto& right) {
    const auto rank = [](HealthSeverity severity) {
      switch (severity) {
      case HealthSeverity::critical:
        return 0;
      case HealthSeverity::warning:
        return 1;
      case HealthSeverity::informational:
        return 2;
      case HealthSeverity::unknown:
        return 3;
      case HealthSeverity::healthy:
      default:
        return 4;
      }
    };
    if (rank(left.severity) != rank(right.severity))
      return rank(left.severity) < rank(right.severity);
    if (left.component != right.component)
      return left.component < right.component;
    return left.metric < right.metric;
  });
}

namespace {

struct HealthEventData {
  int days = 7;
  std::vector<HealthEventCheck> checks;
};

const HealthEventData& health_event_data() {
  static const HealthEventData data = [] {
    HealthEventData parsed;
    const JsonValue& value = data_file("health-events.json");
    parsed.days = static_cast<int>(value["event_days"].as_number(7.0));
    for (const JsonValue& item : value["checks"].items()) {
      HealthEventCheck check;
      check.log = item["log"].as_string();
      check.providers = item["providers"].string_items();
      check.id = static_cast<std::uint32_t>(item["id"].as_number());
      check.since_restart = item["since_restart"].as_bool(false);
      const std::string severity = item["severity"].as_string("warning");
      check.severity = severity == "critical" ? HealthSeverity::critical
                       : severity == "informational" ? HealthSeverity::informational
                                                     : HealthSeverity::warning;
      check.meaning = item["meaning"].as_string();
      if (!check.log.empty() && check.id != 0U)
        parsed.checks.push_back(std::move(check));
    }
    return parsed;
  }();
  return data;
}

std::string sector_text(std::uint32_t bytes) {
  return bytes % 1024U == 0U ? std::to_string(bytes / 1024U) + " KB" : std::to_string(bytes) + " B";
}

} // namespace

const std::vector<HealthEventCheck>& health_event_checks() {
  return health_event_data().checks;
}

int health_event_days() {
  return health_event_data().days;
}

std::string health_link_text(const NetworkAdapterHealth& adapter) {
  const std::uint64_t speed = std::max(adapter.receive_link_speed_bits, adapter.transmit_link_speed_bits);
  std::string text = speed != 0U ? link_speed_text(static_cast<double>(speed)) : std::string();
  if (adapter.mtu != 0U)
    text += (text.empty() ? "" : ", ") + std::string("MTU ") + std::to_string(adapter.mtu);
  return text;
}

std::string health_volume_layout_text(const VolumeHealth& volume) {
  std::string text = volume.partition_style;
  if (volume.logical_sector_bytes != 0U) {
    std::string sectors = sector_text(volume.logical_sector_bytes) + " sectors";
    if (volume.physical_sector_bytes != 0U && volume.physical_sector_bytes != volume.logical_sector_bytes)
      sectors += " (" + sector_text(volume.physical_sector_bytes) + " physical)";
    text += (text.empty() ? "" : ", ") + sectors;
  }
  if (!volume.storage_driver.empty())
    text += (text.empty() ? "" : ", ") + volume.storage_driver;
  return text;
}

void attach_volume_layout(std::vector<VolumeHealth>& volumes) {
  static std::mutex lock;
  static std::map<std::string, VolumeInfo> known; // by mount point, as Volume Check read it
  const std::lock_guard<std::mutex> guard(lock);
  const bool missing = std::any_of(volumes.begin(), volumes.end(), [](const VolumeHealth& volume) {
    return known.find(volume.root_path) == known.end();
  });
  if (missing) {
    if (auto listed = list_volumes(); listed.ok()) {
      for (const VolumeInfo& info : listed.value()) {
        for (const std::string& point : info.mount_points.empty() ? std::vector<std::string>{info.mount_point}
                                                                  : info.mount_points)
          if (!point.empty())
            known[point] = info;
      }
    }
    for (const VolumeHealth& volume : volumes)
      known.emplace(volume.root_path, VolumeInfo{}); // read once, even when Volume Check has nothing
  }
  for (VolumeHealth& volume : volumes) {
    const auto found = known.find(volume.root_path);
    if (found == known.end())
      continue;
    volume.logical_sector_bytes = found->second.logical_sector_bytes;
    volume.physical_sector_bytes = found->second.physical_sector_bytes;
    volume.partition_style = found->second.partition_style;
    volume.storage_driver = found->second.driver;
  }
}

} // namespace support_assist
