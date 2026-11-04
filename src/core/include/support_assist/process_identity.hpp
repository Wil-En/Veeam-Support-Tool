#pragma once

// Who a process is: its name, program path and the services it hosts, read once for every process
// so the local port, file lock and watch engines name owners the same way.

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace support_assist {

struct ProcessIdentity {
  std::uint32_t pid = 0;
  std::uint32_t parent_pid = 0;
  std::string name;     // "VeeamTransportSvc.exe", "veeamtransport"
  std::string path;     // empty when the account cannot read it
  std::string services; // Windows services in the process, or the Linux systemd unit, comma separated
  std::int64_t started_unix_millis = 0; // 0 when not readable
};

class ProcessDirectory {
public:
  // Every process on the machine now. Paths and start times are best effort: a process of another
  // account (or a protected one) keeps its name and loses the rest.
  static ProcessDirectory capture();

  [[nodiscard]] const ProcessIdentity* find(std::uint32_t pid) const;
  [[nodiscard]] const std::vector<ProcessIdentity>& all() const { return processes_; }

private:
  std::vector<ProcessIdentity> processes_;
  std::unordered_map<std::uint32_t, std::size_t> by_pid_;
  friend ProcessDirectory make_process_directory(std::vector<ProcessIdentity> processes);
};

ProcessDirectory make_process_directory(std::vector<ProcessIdentity> processes);

} // namespace support_assist
