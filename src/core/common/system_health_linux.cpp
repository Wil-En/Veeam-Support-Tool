#include "support_assist/system_health.hpp"

#include "support_assist/time.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include "support_assist/debug_log.hpp"
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <unistd.h>

namespace support_assist {
namespace {

struct CpuTimes {
  std::uint64_t idle = 0;
  std::uint64_t total = 0;
  bool valid = false;
};

struct NetworkCounters {
  std::uint64_t receive_bytes = 0;
  std::uint64_t transmit_bytes = 0;
  std::uint64_t receive_drops = 0;
  std::uint64_t transmit_drops = 0;
  std::uint64_t receive_errors = 0;
  std::uint64_t transmit_errors = 0;
};

struct VmCounters {
  std::uint64_t page_in = 0;
  std::uint64_t page_out = 0;
  std::uint64_t faults = 0;
  bool valid = false;
};

struct ProcessCounters {
  std::uint64_t cpu_ticks = 0;
  std::uint64_t read_bytes = 0;
  std::uint64_t write_bytes = 0;
};

std::optional<std::uint64_t> read_u64(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::uint64_t value = 0;
  if (input >> value)
    return value;
  return std::nullopt;
}

std::string read_first_line(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::string line;
  std::getline(input, line);
  return line;
}

CpuTimes read_cpu_times() {
  std::ifstream input("/proc/stat");
  std::string name;
  std::uint64_t user = 0, nice = 0, system = 0, idle = 0, iowait = 0, irq = 0, softirq = 0,
                steal = 0;
  if (!(input >> name >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal) ||
      name != "cpu")
    return {};
  return {idle + iowait, user + nice + system + idle + iowait + irq + softirq + steal, true};
}

VmCounters read_vm_counters() {
  std::ifstream input("/proc/vmstat");
  std::string key;
  std::uint64_t value = 0;
  VmCounters counters;
  while (input >> key >> value) {
    if (key == "pgpgin") counters.page_in = value * 1024U;
    else if (key == "pgpgout") counters.page_out = value * 1024U;
    else if (key == "pgfault") counters.faults = value;
  }
  counters.valid = counters.faults != 0U || counters.page_in != 0U || counters.page_out != 0U;
  return counters;
}

void read_memory(SystemHealthSnapshot& snapshot) {
  std::ifstream input("/proc/meminfo");
  std::string line;
  std::unordered_map<std::string, std::uint64_t> values;
  while (std::getline(input, line)) {
    std::istringstream parser(line);
    std::string key, unit;
    std::uint64_t value = 0;
    if (parser >> key >> value >> unit)
      values[key] = value * 1024U;
  }
  const std::uint64_t total = values["MemTotal:"];
  const std::uint64_t available = values["MemAvailable:"];
  const std::uint64_t swap_total = values["SwapTotal:"];
  const std::uint64_t swap_free = values["SwapFree:"];
  snapshot.memory_total_bytes = total;
  snapshot.memory_used_bytes = total > available ? total - available : 0U;
  snapshot.memory_load_percent = total == 0U ? 0.0 :
      static_cast<double>(snapshot.memory_used_bytes) * 100.0 / static_cast<double>(total);
  snapshot.memory.physical_total_bytes = total;
  snapshot.memory.physical_available_bytes = available;
  snapshot.memory.physical_used_bytes = snapshot.memory_used_bytes;
  snapshot.memory.physical_load_percent = snapshot.memory_load_percent;
  snapshot.memory.pagefile_limit_bytes = swap_total;
  snapshot.memory.pagefile_used_bytes = swap_total > swap_free ? swap_total - swap_free : 0U;
  snapshot.memory.pagefile_load_percent = swap_total == 0U ? 0.0 :
      static_cast<double>(snapshot.memory.pagefile_used_bytes) * 100.0 / static_cast<double>(swap_total);
  snapshot.memory.commit_total_bytes = snapshot.memory_used_bytes + snapshot.memory.pagefile_used_bytes;
  snapshot.memory.commit_limit_bytes = total + swap_total;
  snapshot.memory.commit_load_percent = snapshot.memory.commit_limit_bytes == 0U ? 0.0 :
      static_cast<double>(snapshot.memory.commit_total_bytes) * 100.0 /
          static_cast<double>(snapshot.memory.commit_limit_bytes);
}

std::unordered_map<std::string, NetworkCounters> read_network_counters() {
  std::ifstream input("/proc/net/dev");
  std::string line;
  std::unordered_map<std::string, NetworkCounters> result;
  while (std::getline(input, line)) {
    const auto colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string name = line.substr(0, colon);
    const auto first = name.find_first_not_of(" \t");
    if (first == std::string::npos) continue;
    name.erase(0, first);
    const auto last = name.find_last_not_of(" \t");
    if (last != std::string::npos) name.erase(last + 1U);
    std::istringstream parser(line.substr(colon + 1U));
    std::uint64_t receive_packets = 0, receive_fifo = 0, receive_frame = 0,
                  receive_compressed = 0, receive_multicast = 0, transmit_packets = 0,
                  transmit_fifo = 0, transmit_collisions = 0, transmit_carrier = 0,
                  transmit_compressed = 0;
    NetworkCounters counters;
    if (parser >> counters.receive_bytes >> receive_packets >> counters.receive_errors >>
            counters.receive_drops >> receive_fifo >> receive_frame >> receive_compressed >>
            receive_multicast >> counters.transmit_bytes >> transmit_packets >>
            counters.transmit_errors >> counters.transmit_drops >> transmit_fifo >>
            transmit_collisions >> transmit_carrier >> transmit_compressed)
      result.emplace(std::move(name), counters);
  }
  return result;
}

std::optional<double> read_temperature() {
  std::error_code error;
  const std::filesystem::path root("/sys/class/thermal");
  if (!std::filesystem::exists(root, error)) return std::nullopt;
  for (std::filesystem::directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) {
    if (!it->path().filename().string().starts_with("thermal_zone")) continue;
    const auto raw = read_u64(it->path() / "temp");
    if (raw && *raw > 0U) {
      const double value = *raw > 1000U ? static_cast<double>(*raw) / 1000.0 : static_cast<double>(*raw);
      if (value > 0.0 && value < 150.0) return value;
    }
  }
  return std::nullopt;
}

// Mounts that hold no storage a backup lands on: the kernel's own, memory (tmpfs, ramfs), container
// layers (overlay), snap images (squashfs), the desktop's FUSE helpers and WSL's 9p shares of the
// host. Disks, /boot/efi, NFS, CIFS and fuseblk (NTFS) stay.
bool pseudo_filesystem(std::string_view fs) {
  static const std::set<std::string> ignored = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2",
      "securityfs", "pstore", "debugfs", "tracefs", "configfs", "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc",
      "tmpfs", "ramfs", "overlay", "squashfs", "nsfs", "bpf", "efivarfs", "rpc_pipefs", "nfsd", "selinuxfs", "9p",
      "fuse.gvfsd-fuse", "fuse.portal", "fuse.snapfuse", "fuse.lxcfs"};
  return ignored.contains(std::string(fs));
}

// /proc/mounts separates its fields with spaces, so the kernel escapes anything that would break
// that as a three-digit octal sequence: \040 space, \011 tab, \012 newline, \134 backslash.
// Fields have to be decoded before use - a mount path still carrying them is not a path that
// exists, and every filesystem call made with it fails.
std::string decode_mount_escapes(const std::string& value) {
  std::string decoded;
  decoded.reserve(value.size());
  for (std::size_t index = 0; index < value.size(); ++index) {
    const bool escape = value[index] == '\\' && index + 3U < value.size() &&
                        value[index + 1U] >= '0' && value[index + 1U] <= '3' &&
                        value[index + 2U] >= '0' && value[index + 2U] <= '7' &&
                        value[index + 3U] >= '0' && value[index + 3U] <= '7';
    if (!escape) {
      decoded.push_back(value[index]);
      continue;
    }
    const int code = (value[index + 1U] - '0') * 64 + (value[index + 2U] - '0') * 8 +
                     (value[index + 3U] - '0');
    decoded.push_back(static_cast<char>(code));
    index += 3U;
  }
  return decoded;
}

void read_volumes(SystemHealthSnapshot& snapshot) {
  std::ifstream input("/proc/mounts");
  std::string device, mount, filesystem, options;
  int dump = 0, pass = 0;
  std::set<std::string> seen;
  while (input >> device >> mount >> filesystem >> options >> dump >> pass) {
    // Decode before anything else looks at them, including the duplicate check - two mounts that
    // differ only in an escape are still two different mounts.
    mount = decode_mount_escapes(mount);
    device = decode_mount_escapes(device);
    if (pseudo_filesystem(filesystem) || !seen.insert(mount).second) continue;
    VolumeHealth volume;
    volume.root_path = mount;
    volume.label = device;
    volume.filesystem = filesystem;
    volume.drive_type = (filesystem == "nfs" || filesystem == "nfs4" || filesystem == "cifs") ? "Network" : "Local";
    std::error_code error;
    const auto space = std::filesystem::space(mount, error);
    if (!error) {
      volume.total_bytes = space.capacity;
      volume.free_bytes = space.available;
      volume.capacity_available = true;
    }
    snapshot.volumes.push_back(std::move(volume));
  }
  if (snapshot.volumes.empty()) {
    VolumeHealth root;
    root.root_path = "/";
    root.drive_type = "Local";
    std::error_code error;
    const auto space = std::filesystem::space("/", error);
    if (!error) { root.total_bytes = space.capacity; root.free_bytes = space.available; root.capacity_available = true; }
    snapshot.volumes.push_back(std::move(root));
  }
}

void read_storage_devices(SystemHealthSnapshot& snapshot) {
  std::error_code error;
  const std::filesystem::path root("/sys/block");
  if (!std::filesystem::exists(root, error)) return;
  for (std::filesystem::directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) {
    const std::string name = it->path().filename().string();
    if (name.starts_with("loop") || name.starts_with("ram") || name.starts_with("zram")) continue;
    StorageDeviceHealth device;
    device.name = name;
    const std::string model = read_first_line(it->path() / "device/model");
    if (!model.empty()) device.name += " (" + model + ")";
    if (const auto sectors = read_u64(it->path() / "size")) device.size_bytes = *sectors * 512U;
    const std::string state = read_first_line(it->path() / "device/state");
    device.operational_status = state.empty() ? "Unknown" : state;
    if (const auto rotational = read_u64(it->path() / "queue/rotational"))
      device.media_type = *rotational == 0U ? "SSD/Non-rotational" : "HDD/Rotational";
    device.health_status = "Not queried";
    device.health_available = false;
    snapshot.storage_devices.push_back(std::move(device));
  }
}

std::optional<ProcessHealth> read_process(std::uint32_t pid, ProcessCounters& counters) {
  const std::filesystem::path base = std::filesystem::path("/proc") / std::to_string(pid);
  std::ifstream stat(base / "stat");
  std::string stat_line;
  if (!std::getline(stat, stat_line)) return std::nullopt;
  const auto lparen = stat_line.find('(');
  const auto rparen = stat_line.rfind(')');
  if (lparen == std::string::npos || rparen == std::string::npos || rparen + 2U >= stat_line.size()) return std::nullopt;
  ProcessHealth process;
  process.process_id = pid;
  process.name = stat_line.substr(lparen + 1U, rparen - lparen - 1U);
  std::istringstream fields(stat_line.substr(rparen + 2U));
  std::vector<std::string> values;
  std::string value;
  while (fields >> value) values.push_back(value);
  // values[0] is field 3 (state); utime/stime are fields 14/15 -> indexes 11/12.
  if (values.size() > 17U) {
    try {
      counters.cpu_ticks = std::stoull(values[11]) + std::stoull(values[12]);
      process.thread_count = static_cast<std::uint32_t>(std::stoul(values[17]));
    } catch (const std::exception& error) {
      // Previously swallowed in silence. A health probe that quietly gives up looks identical to a
      // machine with nothing to report, which is the worst possible ambiguity in a support tool.
      write_debug_exception("SystemHealth", "sampling a health counter", error.what());
    } catch (...) {
      write_debug_exception("SystemHealth", "sampling a health counter", "unknown exception");
    }
  }
  std::ifstream status(base / "status");
  std::string line;
  while (std::getline(status, line)) {
    auto parse_kb = [&](std::string_view prefix, std::uint64_t& target) {
      if (!line.starts_with(prefix)) return;
      std::istringstream parser(line.substr(prefix.size()));
      std::uint64_t kb = 0;
      if (parser >> kb) target = kb * 1024U;
    };
    parse_kb("VmRSS:", process.working_set_bytes);
    parse_kb("VmSize:", process.private_bytes);
  }
  std::ifstream io(base / "io");
  std::string key;
  std::uint64_t io_value = 0;
  while (io >> key >> io_value) {
    if (key == "read_bytes:") counters.read_bytes = io_value;
    else if (key == "write_bytes:") counters.write_bytes = io_value;
  }
  std::error_code error;
  const auto exe = std::filesystem::read_symlink(base / "exe", error);
  if (!error) process.image_path = exe.string();
  return process;
}

} // namespace

struct SystemHealthSampler::Impl {
  CpuTimes previous_cpu;
  VmCounters previous_vm;
  std::unordered_map<std::string, NetworkCounters> previous_network;
  std::unordered_map<std::uint32_t, ProcessCounters> previous_processes;
  std::chrono::steady_clock::time_point previous_time{};
  bool seeded = false;
};

SystemHealthSampler::SystemHealthSampler() : impl_(std::make_unique<Impl>()) {}
SystemHealthSampler::~SystemHealthSampler() = default;
SystemHealthSampler::SystemHealthSampler(SystemHealthSampler&&) noexcept = default;
SystemHealthSampler& SystemHealthSampler::operator=(SystemHealthSampler&&) noexcept = default;

Result<SystemHealthSnapshot> SystemHealthSampler::sample(const SystemHealthSampleOptions& options) {
  SystemHealthSnapshot snapshot;
  snapshot.captured_utc = utc_now_iso8601();
  char hostname[256]{};
  if (gethostname(hostname, sizeof(hostname) - 1U) == 0) snapshot.machine_name = hostname;

  const auto now = std::chrono::steady_clock::now();
  const double elapsed = impl_->seeded ? std::chrono::duration<double>(now - impl_->previous_time).count() : 0.0;
  const CpuTimes current_cpu = read_cpu_times();
  std::uint64_t cpu_delta = 0;
  if (current_cpu.valid && impl_->previous_cpu.valid && current_cpu.total >= impl_->previous_cpu.total) {
    cpu_delta = current_cpu.total - impl_->previous_cpu.total;
    const std::uint64_t idle_delta = current_cpu.idle >= impl_->previous_cpu.idle ? current_cpu.idle - impl_->previous_cpu.idle : 0U;
    if (cpu_delta != 0U) {
      snapshot.cpu_load_percent = std::clamp(static_cast<double>(cpu_delta - std::min(cpu_delta, idle_delta)) * 100.0 /
                                             static_cast<double>(cpu_delta), 0.0, 100.0);
      snapshot.cpu_load_available = true;
    }
  }
  impl_->previous_cpu = current_cpu;
  read_memory(snapshot);

  const VmCounters vm = read_vm_counters();
  if (elapsed > 0.0 && vm.valid && impl_->previous_vm.valid) {
    if (vm.page_in >= impl_->previous_vm.page_in)
      snapshot.memory.pages_input_per_second = static_cast<double>(vm.page_in - impl_->previous_vm.page_in) / elapsed;
    if (vm.page_out >= impl_->previous_vm.page_out)
      snapshot.memory.page_writes_per_second = static_cast<double>(vm.page_out - impl_->previous_vm.page_out) / elapsed;
    if (vm.faults >= impl_->previous_vm.faults)
      snapshot.memory.page_faults_per_second = static_cast<double>(vm.faults - impl_->previous_vm.faults) / elapsed;
  }
  impl_->previous_vm = vm;

  if (options.refresh_temperature || !impl_->seeded) {
    snapshot.cpu_temperature_celsius = read_temperature();
    if (snapshot.cpu_temperature_celsius) snapshot.temperature_source = "Linux thermal_zone";
  }
  read_volumes(snapshot);
  attach_volume_layout(snapshot.volumes);
  if (options.refresh_storage_health || !impl_->seeded) read_storage_devices(snapshot);

  auto current_network = read_network_counters();
  for (const auto& [name, counters] : current_network) {
    NetworkAdapterHealth adapter;
    adapter.key = name;
    adapter.name = name;
    adapter.description = read_first_line(std::filesystem::path("/sys/class/net") / name / "device/uevent");
    adapter.operational_status = read_first_line(std::filesystem::path("/sys/class/net") / name / "operstate");
    if (adapter.operational_status.empty()) adapter.operational_status = name == "lo" ? "loopback" : "unknown";
    std::error_code link_error;
    adapter.virtual_adapter = name == "lo" || !std::filesystem::exists(std::filesystem::path("/sys/class/net") / name / "device", link_error);
    if (const auto speed = read_u64(std::filesystem::path("/sys/class/net") / name / "speed"); speed && *speed < 1000000U) {
      adapter.receive_link_speed_bits = *speed * 1000U * 1000U;
      adapter.transmit_link_speed_bits = adapter.receive_link_speed_bits;
    }
    if (const auto mtu = read_u64(std::filesystem::path("/sys/class/net") / name / "mtu"); mtu && *mtu < 1000000U)
      adapter.mtu = static_cast<std::uint32_t>(*mtu);
    adapter.receive_discards = counters.receive_drops;
    adapter.transmit_discards = counters.transmit_drops;
    adapter.receive_errors = counters.receive_errors;
    adapter.transmit_errors = counters.transmit_errors;
    const auto previous = impl_->previous_network.find(name);
    if (previous != impl_->previous_network.end() && elapsed > 0.0) {
      if (counters.receive_bytes >= previous->second.receive_bytes)
        adapter.receive_bytes_per_second = static_cast<double>(counters.receive_bytes - previous->second.receive_bytes) / elapsed;
      if (counters.transmit_bytes >= previous->second.transmit_bytes)
        adapter.transmit_bytes_per_second = static_cast<double>(counters.transmit_bytes - previous->second.transmit_bytes) / elapsed;
      if (counters.receive_drops >= previous->second.receive_drops) adapter.receive_discards_delta = counters.receive_drops - previous->second.receive_drops;
      if (counters.transmit_drops >= previous->second.transmit_drops) adapter.transmit_discards_delta = counters.transmit_drops - previous->second.transmit_drops;
      if (counters.receive_errors >= previous->second.receive_errors) adapter.receive_errors_delta = counters.receive_errors - previous->second.receive_errors;
      if (counters.transmit_errors >= previous->second.transmit_errors) adapter.transmit_errors_delta = counters.transmit_errors - previous->second.transmit_errors;
    }
    const double combined_rate = adapter.receive_bytes_per_second.value_or(0.0) + adapter.transmit_bytes_per_second.value_or(0.0);
    if (adapter.receive_link_speed_bits != 0U)
      adapter.utilization_percent = std::min(100.0, combined_rate * 8.0 * 100.0 / static_cast<double>(adapter.receive_link_speed_bits));
    snapshot.network_adapters.push_back(std::move(adapter));
  }
  impl_->previous_network = std::move(current_network);

  if (options.refresh_processes) {
    std::unordered_map<std::uint32_t, ProcessCounters> current_processes;
    std::error_code error;
    for (std::filesystem::directory_iterator it("/proc", std::filesystem::directory_options::skip_permission_denied, error), end;
         !error && it != end; it.increment(error)) {
      const std::string name = it->path().filename().string();
      if (name.empty() || !std::all_of(name.begin(), name.end(), [](char ch) { return std::isdigit(static_cast<unsigned char>(ch)) != 0; })) continue;
      std::uint32_t pid = 0;
      try { pid = static_cast<std::uint32_t>(std::stoul(name)); } catch (...) { continue; }
      ProcessCounters counters;
      auto process = read_process(pid, counters);
      if (!process) continue;
      const auto previous = impl_->previous_processes.find(pid);
      if (previous != impl_->previous_processes.end() && elapsed > 0.0) {
        if (counters.cpu_ticks >= previous->second.cpu_ticks && cpu_delta != 0U)
          process->cpu_percent = std::min(100.0, static_cast<double>(counters.cpu_ticks - previous->second.cpu_ticks) * 100.0 /
                                                   static_cast<double>(cpu_delta));
        if (counters.read_bytes >= previous->second.read_bytes)
          process->read_bytes_per_second = static_cast<double>(counters.read_bytes - previous->second.read_bytes) / elapsed;
        if (counters.write_bytes >= previous->second.write_bytes)
          process->write_bytes_per_second = static_cast<double>(counters.write_bytes - previous->second.write_bytes) / elapsed;
      }
      current_processes.emplace(pid, counters);
      snapshot.top_processes.push_back(std::move(*process));
    }
    std::sort(snapshot.top_processes.begin(), snapshot.top_processes.end(), [](const auto& left, const auto& right) {
      const double left_cpu = left.cpu_percent.value_or(0.0);
      const double right_cpu = right.cpu_percent.value_or(0.0);
      if (left_cpu != right_cpu) return left_cpu > right_cpu;
      return left.working_set_bytes > right.working_set_bytes;
    });
    if (snapshot.top_processes.size() > 25U) snapshot.top_processes.resize(25U);
    impl_->previous_processes = std::move(current_processes);
  }

  if (!snapshot.cpu_temperature_celsius)
    snapshot.warnings.push_back("CPU temperature is unavailable from Linux thermal_zone interfaces on this host.");
  snapshot.warnings.push_back("Drive SMART predictive status is not auto-invoked on Linux; SAT reports block-device state without requiring smartctl/root device access.");
  impl_->previous_time = now;
  impl_->seeded = true;
  evaluate_system_health(snapshot);
  return Result<SystemHealthSnapshot>::success(std::move(snapshot));
}

} // namespace support_assist
