// Service and Process Watch on Linux: systemd service units from their unit files, running when
// their cgroup holds a process, and the processes from /proc; both filtered. systemctl is not run.
#include "support_assist/veeam_watch.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <set>

#include <unistd.h>

namespace support_assist {
namespace {

std::uint32_t first_process_in_cgroup(const std::string& unit) {
  for (const std::string& path : {"/sys/fs/cgroup/system.slice/" + unit + "/cgroup.procs",
                                  "/sys/fs/cgroup/systemd/system.slice/" + unit + "/cgroup.procs"}) {
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
      const unsigned long pid = std::strtoul(line.c_str(), nullptr, 10);
      if (pid != 0)
        return static_cast<std::uint32_t>(pid);
    }
  }
  return 0;
}

} // namespace

WatchSnapshot take_watch_snapshot(const std::string& filter) {
  WatchSnapshot snapshot;
  snapshot.taken_unix_millis = unix_millis_now();
  const std::string lowered = ascii_lower(trim(filter));
  const ProcessDirectory processes = ProcessDirectory::capture();

  std::set<std::string> units;
  for (const char* folder : {"/etc/systemd/system", "/run/systemd/system", "/usr/lib/systemd/system",
                             "/lib/systemd/system"}) {
    std::error_code error;
    for (std::filesystem::directory_iterator it(folder, error), end; !error && it != end; it.increment(error)) {
      const std::string name = it->path().filename().string();
      if (name.size() > 8 && name.compare(name.size() - 8, 8, ".service") == 0 && name.find('@') == std::string::npos &&
          (lowered.empty() || ascii_lower(name).find(lowered) != std::string::npos))
        units.insert(name);
    }
  }
  for (const std::string& unit : units) {
    WatchItem item;
    item.kind = WatchKind::service;
    item.name = unit;
    item.pid = first_process_in_cgroup(unit);
    item.state = item.pid != 0 ? "running" : "not running";
    if (const ProcessIdentity* identity = item.pid != 0 ? processes.find(item.pid) : nullptr) {
      item.started_unix_millis = identity->started_unix_millis;
      item.path = identity->path;
    }
    snapshot.items.push_back(std::move(item));
  }

  // SAT itself is left out: it often runs from a folder whose name holds "Veeam".
  const auto self = static_cast<std::uint32_t>(getpid());
  for (const ProcessIdentity& process : processes.all()) {
    WatchItem item;
    item.kind = WatchKind::process;
    item.name = process.name;
    item.state = "running";
    item.pid = process.pid;
    item.started_unix_millis = process.started_unix_millis;
    item.path = process.path;
    if (process.pid != self && watch_detail::matches(item, lowered))
      snapshot.items.push_back(std::move(item));
  }
  watch_detail::add_listening_ports(snapshot);
  return snapshot;
}

} // namespace support_assist
