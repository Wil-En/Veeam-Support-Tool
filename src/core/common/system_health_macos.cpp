#include "support_assist/system_health.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ifaddrs.h>
#include <libproc.h>
#include <mach/mach.h>
#include <memory>
#include <net/if.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace support_assist {
namespace {

struct CpuCounters { std::uint64_t user=0, system=0, idle=0, nice=0; bool valid=false; };
struct ProcessCounters { std::uint64_t cpu_ns=0, read_bytes=0, write_bytes=0; };

CpuCounters cpu_counters() {
  host_cpu_load_info_data_t info{};
  mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
  if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, reinterpret_cast<host_info_t>(&info), &count) != KERN_SUCCESS)
    return {};
  return {info.cpu_ticks[CPU_STATE_USER], info.cpu_ticks[CPU_STATE_SYSTEM], info.cpu_ticks[CPU_STATE_IDLE],
          info.cpu_ticks[CPU_STATE_NICE], true};
}

std::uint64_t total_ticks(const CpuCounters& c) { return c.user + c.system + c.idle + c.nice; }

std::uint64_t sysctl_u64(const char* name) {
  std::uint64_t value = 0; size_t size = sizeof(value);
  return sysctlbyname(name, &value, &size, nullptr, 0) == 0 ? value : 0U;
}

void memory_snapshot(SystemHealthSnapshot& snapshot) {
  const std::uint64_t total = sysctl_u64("hw.memsize");
  vm_statistics64_data_t vm{};
  mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
  if (host_statistics64(mach_host_self(), HOST_VM_INFO64, reinterpret_cast<host_info64_t>(&vm), &count) != KERN_SUCCESS)
    return;
  vm_size_t page_size = 0;
  host_page_size(mach_host_self(), &page_size);
  const std::uint64_t free_bytes = static_cast<std::uint64_t>(vm.free_count + vm.inactive_count) * page_size;
  snapshot.memory_total_bytes = total;
  snapshot.memory_used_bytes = total > free_bytes ? total - free_bytes : 0U;
  snapshot.memory_load_percent = total == 0U ? 0.0 : static_cast<double>(snapshot.memory_used_bytes) * 100.0 / total;
  snapshot.memory.physical_total_bytes = total;
  snapshot.memory.physical_available_bytes = free_bytes;
  snapshot.memory.physical_used_bytes = snapshot.memory_used_bytes;
  snapshot.memory.physical_load_percent = snapshot.memory_load_percent;
  struct xsw_usage swap{}; size_t swap_size = sizeof(swap);
  if (sysctlbyname("vm.swapusage", &swap, &swap_size, nullptr, 0) == 0) {
    snapshot.memory.pagefile_limit_bytes = swap.xsu_total;
    snapshot.memory.pagefile_used_bytes = swap.xsu_used;
    snapshot.memory.pagefile_load_percent = swap.xsu_total == 0U ? 0.0 : static_cast<double>(swap.xsu_used) * 100.0 / swap.xsu_total;
  }
  snapshot.memory.commit_total_bytes = snapshot.memory_used_bytes + snapshot.memory.pagefile_used_bytes;
  snapshot.memory.commit_limit_bytes = total + snapshot.memory.pagefile_limit_bytes;
  snapshot.memory.commit_load_percent = snapshot.memory.commit_limit_bytes == 0U ? 0.0 :
      static_cast<double>(snapshot.memory.commit_total_bytes) * 100.0 / snapshot.memory.commit_limit_bytes;
  snapshot.memory.page_faults_per_second = std::nullopt;
}

void volumes(SystemHealthSnapshot& snapshot) {
  struct statfs* mounts = nullptr;
  const int count = getmntinfo(&mounts, MNT_NOWAIT);
  for (int index = 0; index < count; ++index) {
    const auto& m = mounts[index];
    VolumeHealth volume;
    volume.root_path = m.f_mntonname;
    volume.label = m.f_mntfromname;
    volume.filesystem = m.f_fstypename;
    volume.drive_type = (m.f_flags & MNT_LOCAL) != 0 ? "Local" : "Network";
    volume.total_bytes = static_cast<std::uint64_t>(m.f_blocks) * m.f_bsize;
    volume.free_bytes = static_cast<std::uint64_t>(m.f_bavail) * m.f_bsize;
    volume.capacity_available = true;
    snapshot.volumes.push_back(std::move(volume));
  }
}

void network(SystemHealthSnapshot& snapshot,
             std::unordered_map<std::string, std::pair<std::uint64_t,std::uint64_t>>& current,
             const std::unordered_map<std::string, std::pair<std::uint64_t,std::uint64_t>>& previous,
             double elapsed) {
  ifaddrs* addresses = nullptr;
  if (getifaddrs(&addresses) != 0) return;
  for (ifaddrs* item = addresses; item != nullptr; item = item->ifa_next) {
    if (item->ifa_addr == nullptr || item->ifa_addr->sa_family != AF_LINK || item->ifa_data == nullptr) continue;
    const auto* data = static_cast<const if_data*>(item->ifa_data);
    const std::string name = item->ifa_name;
    if (current.contains(name)) continue;
    current[name] = {data->ifi_ibytes, data->ifi_obytes};
    NetworkAdapterHealth adapter;
    adapter.key = name; adapter.name = name;
    adapter.operational_status = (item->ifa_flags & IFF_UP) != 0 ? "up" : "down";
    adapter.virtual_adapter = name == "lo0" || name.starts_with("utun") || name.starts_with("bridge") || name.starts_with("awdl");
    adapter.receive_errors = data->ifi_ierrors; adapter.transmit_errors = data->ifi_oerrors;
    adapter.receive_discards = data->ifi_iqdrops;
    adapter.receive_link_speed_bits = data->ifi_baudrate; adapter.transmit_link_speed_bits = data->ifi_baudrate;
    adapter.mtu = static_cast<std::uint32_t>(data->ifi_mtu);
    const auto prior = previous.find(name);
    if (prior != previous.end() && elapsed > 0.0) {
      if (data->ifi_ibytes >= prior->second.first) adapter.receive_bytes_per_second = static_cast<double>(data->ifi_ibytes-prior->second.first)/elapsed;
      if (data->ifi_obytes >= prior->second.second) adapter.transmit_bytes_per_second = static_cast<double>(data->ifi_obytes-prior->second.second)/elapsed;
    }
    snapshot.network_adapters.push_back(std::move(adapter));
  }
  freeifaddrs(addresses);
}

std::vector<ProcessHealth> processes(std::unordered_map<std::uint32_t, ProcessCounters>& current,
                                     const std::unordered_map<std::uint32_t, ProcessCounters>& previous,
                                     double elapsed) {
  std::vector<ProcessHealth> result;
  // libproc returns a PID count, not a byte count. Allocate some headroom
  // because processes may appear between the sizing and fill calls.
  const int suggested_count = proc_listallpids(nullptr, 0);
  if (suggested_count <= 0) return result;
  std::vector<pid_t> pids(static_cast<std::size_t>(suggested_count) + 64U);
  const int used = proc_listallpids(pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
  const std::size_t count = used > 0 ? std::min<std::size_t>(static_cast<std::size_t>(used), pids.size()) : 0U;
  for (std::size_t index=0; index<count; ++index) {
    const pid_t pid = pids[index]; if (pid <= 0) continue;
    proc_taskinfo task{};
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task, sizeof(task)) != sizeof(task)) continue;
    char name_buffer[PROC_PIDPATHINFO_MAXSIZE]{};
    proc_name(pid, name_buffer, sizeof(name_buffer));
    ProcessHealth process;
    process.process_id = static_cast<std::uint32_t>(pid);
    process.name = name_buffer[0] ? name_buffer : "process";
    char path_buffer[PROC_PIDPATHINFO_MAXSIZE]{};
    if (proc_pidpath(pid, path_buffer, sizeof(path_buffer)) > 0) process.image_path = path_buffer;
    process.working_set_bytes = task.pti_resident_size;
    process.private_bytes = task.pti_virtual_size;
    process.thread_count = task.pti_threadnum;
    rusage_info_current usage{};
    ProcessCounters counters;
    counters.cpu_ns = task.pti_total_user + task.pti_total_system;
    if (proc_pid_rusage(pid, RUSAGE_INFO_CURRENT, reinterpret_cast<rusage_info_t*>(&usage)) == 0) {
      counters.read_bytes = usage.ri_diskio_bytesread;
      counters.write_bytes = usage.ri_diskio_byteswritten;
    }
    const auto prior = previous.find(process.process_id);
    if (prior != previous.end() && elapsed > 0.0) {
      if (counters.cpu_ns >= prior->second.cpu_ns) process.cpu_percent = std::min(100.0, static_cast<double>(counters.cpu_ns-prior->second.cpu_ns)/1.0e9/elapsed*100.0);
      if (counters.read_bytes >= prior->second.read_bytes) process.read_bytes_per_second = static_cast<double>(counters.read_bytes-prior->second.read_bytes)/elapsed;
      if (counters.write_bytes >= prior->second.write_bytes) process.write_bytes_per_second = static_cast<double>(counters.write_bytes-prior->second.write_bytes)/elapsed;
    }
    current.emplace(process.process_id, counters);
    result.push_back(std::move(process));
  }
  std::sort(result.begin(), result.end(), [](const auto& a, const auto& b) {
    if (a.cpu_percent.value_or(0.0) != b.cpu_percent.value_or(0.0)) return a.cpu_percent.value_or(0.0) > b.cpu_percent.value_or(0.0);
    return a.working_set_bytes > b.working_set_bytes;
  });
  if (result.size() > 25U) result.resize(25U);
  return result;
}

} // namespace

struct SystemHealthSampler::Impl {
  CpuCounters previous_cpu;
  std::unordered_map<std::string, std::pair<std::uint64_t,std::uint64_t>> previous_network;
  std::unordered_map<std::uint32_t, ProcessCounters> previous_processes;
  std::chrono::steady_clock::time_point previous_time{};
  bool seeded=false;
};
SystemHealthSampler::SystemHealthSampler():impl_(std::make_unique<Impl>()){}
SystemHealthSampler::~SystemHealthSampler()=default;
SystemHealthSampler::SystemHealthSampler(SystemHealthSampler&&) noexcept=default;
SystemHealthSampler& SystemHealthSampler::operator=(SystemHealthSampler&&) noexcept=default;

Result<SystemHealthSnapshot> SystemHealthSampler::sample(const SystemHealthSampleOptions& options) {
  SystemHealthSnapshot snapshot; snapshot.captured_utc=utc_now_iso8601();
  char host[256]{}; if (gethostname(host,sizeof(host)-1U)==0) snapshot.machine_name=host;
  const auto now=std::chrono::steady_clock::now();
  const double elapsed=impl_->seeded?std::chrono::duration<double>(now-impl_->previous_time).count():0.0;
  const auto current_cpu=cpu_counters();
  if (current_cpu.valid && impl_->previous_cpu.valid) {
    const auto total=total_ticks(current_cpu)-total_ticks(impl_->previous_cpu);
    const auto idle=current_cpu.idle-impl_->previous_cpu.idle;
    if (total!=0U) { snapshot.cpu_load_percent=std::clamp(static_cast<double>(total-std::min(total,idle))*100.0/total,0.0,100.0); snapshot.cpu_load_available=true; }
  }
  impl_->previous_cpu=current_cpu;
  memory_snapshot(snapshot); volumes(snapshot);
  std::unordered_map<std::string,std::pair<std::uint64_t,std::uint64_t>> current_network;
  network(snapshot,current_network,impl_->previous_network,elapsed); impl_->previous_network=std::move(current_network);
  if (options.refresh_processes) { std::unordered_map<std::uint32_t,ProcessCounters> current; snapshot.top_processes=processes(current,impl_->previous_processes,elapsed); impl_->previous_processes=std::move(current); }
  snapshot.warnings.push_back("CPU temperature is not exposed through a stable public macOS API and is not fabricated by SAT.");
  snapshot.warnings.push_back("Drive SMART/predictive-failure status is not auto-invoked in the macOS sampler; filesystem capacity and process/network health remain available.");
  impl_->previous_time=now; impl_->seeded=true;
  evaluate_system_health(snapshot);
  return Result<SystemHealthSnapshot>::success(std::move(snapshot));
}

} // namespace support_assist
