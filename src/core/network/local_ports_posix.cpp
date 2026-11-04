// Linux socket tables: /proc/net/tcp, tcp6, udp and udp6, owners through each process's open file
// descriptors. Any account reads the tables; only root reads every other account's descriptors, so
// without root the owners of other accounts' sockets are counted as not readable and said so.
#include "support_assist/local_ports.hpp"

#include "support_assist/process_identity.hpp"

#include <dirent.h>
#include <unistd.h>

#include <climits>
#include <cstdlib>
#include <fstream>
#include <unordered_map>

namespace support_assist {
namespace {

void read_table(const char* path, bool ipv6, PortProtocol protocol, std::vector<LocalSocket>& sockets,
                std::vector<unsigned long long>& inodes) {
  std::ifstream input(path);
  std::string line;
  while (std::getline(input, line)) {
    LocalSocket socket;
    unsigned long long inode = 0;
    if (local_ports_detail::parse_proc_net_line(line, ipv6, protocol, socket, inode)) {
      sockets.push_back(std::move(socket));
      inodes.push_back(inode);
    }
  }
}

// socket inode -> pid, from /proc/<pid>/fd/* links that read "socket:[<inode>]".
std::unordered_map<unsigned long long, std::uint32_t> socket_owners() {
  std::unordered_map<unsigned long long, std::uint32_t> owners;
  DIR* proc = opendir("/proc");
  if (proc == nullptr)
    return owners;
  while (const dirent* entry = readdir(proc)) {
    const std::string pid = entry->d_name;
    if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
      continue;
    const std::string fd_path = "/proc/" + pid + "/fd";
    DIR* fds = opendir(fd_path.c_str());
    if (fds == nullptr)
      continue; // another account's process without root
    while (const dirent* fd = readdir(fds)) {
      if (fd->d_name[0] == '.')
        continue;
      char target[128] = {};
      const std::string link = fd_path + "/" + fd->d_name;
      const ssize_t length = readlink(link.c_str(), target, sizeof(target) - 1);
      if (length <= 8)
        continue;
      const std::string text(target, static_cast<std::size_t>(length));
      if (text.rfind("socket:[", 0) != 0 || text.back() != ']')
        continue;
      const unsigned long long inode = std::strtoull(text.c_str() + 8, nullptr, 10);
      owners.emplace(inode, static_cast<std::uint32_t>(std::strtoul(pid.c_str(), nullptr, 10)));
    }
    closedir(fds);
  }
  closedir(proc);
  return owners;
}

} // namespace

Result<LocalSocketTable> list_local_sockets() {
  LocalSocketTable table;
  std::vector<unsigned long long> inodes;
  read_table("/proc/net/tcp", false, PortProtocol::tcp, table.sockets, inodes);
  read_table("/proc/net/tcp6", true, PortProtocol::tcp, table.sockets, inodes);
  read_table("/proc/net/udp", false, PortProtocol::udp, table.sockets, inodes);
  read_table("/proc/net/udp6", true, PortProtocol::udp, table.sockets, inodes);
  if (table.sockets.empty()) {
    Error error;
    error.component = "network";
    error.operation = "read the socket tables";
    error.source = "/proc/net";
    error.message = "no socket table could be read";
    return Result<LocalSocketTable>::failure(error);
  }

  const auto owners = socket_owners();
  const ProcessDirectory processes = ProcessDirectory::capture();
  for (std::size_t i = 0; i < table.sockets.size(); ++i) {
    LocalSocket& socket = table.sockets[i];
    const unsigned long long inode = inodes[i];
    if (inode == 0)
      continue; // TIME_WAIT and similar states belong to no process
    const auto owner = owners.find(inode);
    if (owner == owners.end()) {
      ++table.owners_not_readable;
      continue;
    }
    socket.pid = owner->second;
    if (const ProcessIdentity* identity = processes.find(socket.pid)) {
      socket.process_name = identity->name;
      socket.process_path = identity->path;
      socket.services = identity->services;
    }
  }
  if (table.owners_not_readable > 0 && geteuid() != 0) {
    table.note = std::to_string(table.owners_not_readable) +
                 " sockets belong to processes of other accounts; their owners are readable as root.";
  }
  return Result<LocalSocketTable>::success(std::move(table));
}

} // namespace support_assist
