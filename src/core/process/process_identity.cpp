#include "support_assist/process_identity.hpp"

namespace support_assist {

ProcessDirectory make_process_directory(std::vector<ProcessIdentity> processes) {
  ProcessDirectory directory;
  directory.processes_ = std::move(processes);
  for (std::size_t i = 0; i < directory.processes_.size(); ++i)
    directory.by_pid_.emplace(directory.processes_[i].pid, i);
  return directory;
}

const ProcessIdentity* ProcessDirectory::find(std::uint32_t pid) const {
  const auto found = by_pid_.find(pid);
  return found == by_pid_.end() ? nullptr : &processes_[found->second];
}

} // namespace support_assist
