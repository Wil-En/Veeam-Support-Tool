// Linux process identities from /proc: the name from comm, the parent and start time from stat, the
// program path where the account may read it, and the systemd unit from the cgroup (the Linux
// counterpart of the Windows services a process hosts). Read-only throughout.
#include "support_assist/process_identity.hpp"

#include <dirent.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace support_assist {
namespace {

std::string read_first_line(const std::string& path) {
  std::ifstream input(path);
  std::string line;
  std::getline(input, line);
  return line;
}

std::string read_link(const std::string& path) {
  std::string buffer(PATH_MAX, '\0');
  const ssize_t length = readlink(path.c_str(), buffer.data(), buffer.size() - 1);
  if (length <= 0)
    return {};
  buffer.resize(static_cast<std::size_t>(length));
  return buffer;
}

std::int64_t boot_time_seconds() {
  std::ifstream input("/proc/stat");
  std::string line;
  while (std::getline(input, line)) {
    if (line.rfind("btime ", 0) == 0)
      return std::strtoll(line.c_str() + 6, nullptr, 10);
  }
  return 0;
}

std::string systemd_unit(const std::string& pid) {
  std::ifstream input("/proc/" + pid + "/cgroup");
  std::string line;
  while (std::getline(input, line)) {
    const std::size_t service = line.rfind(".service");
    if (service == std::string::npos)
      continue;
    const std::size_t slash = line.rfind('/', service);
    if (slash == std::string::npos)
      continue;
    return line.substr(slash + 1, service + 8 - slash - 1);
  }
  return {};
}

} // namespace

ProcessDirectory ProcessDirectory::capture() {
  std::vector<ProcessIdentity> processes;
  const std::int64_t boot = boot_time_seconds();
  const long ticks = sysconf(_SC_CLK_TCK);
  DIR* proc = opendir("/proc");
  if (proc == nullptr)
    return make_process_directory(std::move(processes));
  while (const dirent* entry = readdir(proc)) {
    const std::string pid = entry->d_name;
    if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
      continue;
    ProcessIdentity identity;
    identity.pid = static_cast<std::uint32_t>(std::strtoul(pid.c_str(), nullptr, 10));
    identity.name = read_first_line("/proc/" + pid + "/comm");
    if (identity.name.empty())
      continue; // the process ended while the list was read
    identity.path = read_link("/proc/" + pid + "/exe");
    if (identity.path.empty()) {
      // Another account's process: the command line is readable where the executable link is not.
      std::ifstream cmdline("/proc/" + pid + "/cmdline");
      std::string first;
      std::getline(cmdline, first, '\0');
      if (!first.empty() && first.front() == '/')
        identity.path = first;
    }
    // stat: "pid (comm) state ppid ...", with starttime the 22nd field. comm may hold spaces and
    // parentheses, so the fields are counted from the last ')'.
    const std::string stat = read_first_line("/proc/" + pid + "/stat");
    const std::size_t close = stat.rfind(')');
    if (close != std::string::npos) {
      std::istringstream fields(stat.substr(close + 1));
      std::string field;
      for (int index = 3; fields >> field; ++index) {
        if (index == 4)
          identity.parent_pid = static_cast<std::uint32_t>(std::strtoul(field.c_str(), nullptr, 10));
        if (index == 22) {
          if (ticks > 0 && boot > 0) {
            const long long start_ticks = std::strtoll(field.c_str(), nullptr, 10);
            identity.started_unix_millis = boot * 1000 + start_ticks * 1000 / ticks;
          }
          break;
        }
      }
    }
    identity.services = systemd_unit(pid);
    processes.push_back(std::move(identity));
  }
  closedir(proc);
  return make_process_directory(std::move(processes));
}

} // namespace support_assist
