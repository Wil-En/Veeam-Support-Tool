// Windows socket tables: GetExtendedTcpTable and GetExtendedUdpTable for IPv4 and IPv6, owners from
// the process directory. The tables are readable by any account; only a process's path and start
// time depend on being allowed to open it.
#include "support_assist/local_ports.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winsvc.h>

#include <array>
#include <map>
#include <string>
#include <vector>

namespace support_assist {
namespace {

using local_ports_detail::format_ipv4;
using local_ports_detail::format_ipv6;

std::string tcp_state_name(DWORD state) {
  switch (state) {
  case MIB_TCP_STATE_CLOSED: return "CLOSED";
  case MIB_TCP_STATE_LISTEN: return "LISTEN";
  case MIB_TCP_STATE_SYN_SENT: return "SYN_SENT";
  case MIB_TCP_STATE_SYN_RCVD: return "SYN_RECV";
  case MIB_TCP_STATE_ESTAB: return "ESTABLISHED";
  case MIB_TCP_STATE_FIN_WAIT1: return "FIN_WAIT1";
  case MIB_TCP_STATE_FIN_WAIT2: return "FIN_WAIT2";
  case MIB_TCP_STATE_CLOSE_WAIT: return "CLOSE_WAIT";
  case MIB_TCP_STATE_CLOSING: return "CLOSING";
  case MIB_TCP_STATE_LAST_ACK: return "LAST_ACK";
  case MIB_TCP_STATE_TIME_WAIT: return "TIME_WAIT";
  case MIB_TCP_STATE_DELETE_TCB: return "DELETE_TCB";
  default: return "UNKNOWN";
  }
}

std::string ipv4_text(DWORD network_order) {
  const auto* b = reinterpret_cast<const std::uint8_t*>(&network_order);
  return format_ipv4(b[0], b[1], b[2], b[3]);
}

std::string ipv6_text(const UCHAR* address) {
  std::array<std::uint8_t, 16> bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i)
    bytes[i] = address[i];
  return format_ipv6(bytes);
}

std::uint16_t port_of(DWORD network_order) {
  return ntohs(static_cast<u_short>(network_order & 0xFFFFU));
}

template <typename Fetch> bool fetch_table(std::vector<unsigned char>& buffer, Fetch fetch) {
  DWORD size = 0;
  DWORD status = fetch(nullptr, &size);
  for (int attempt = 0; attempt < 4 && status == ERROR_INSUFFICIENT_BUFFER; ++attempt) {
    buffer.resize(size + 4096U);
    size = static_cast<DWORD>(buffer.size());
    status = fetch(buffer.data(), &size);
  }
  return status == NO_ERROR && !buffer.empty();
}

Error table_error(const std::string& what, DWORD code) {
  Error error;
  error.component = "network";
  error.operation = "read the " + what + " table";
  error.native_code = static_cast<std::int64_t>(code);
  error.message = "the system did not return its " + what + " table";
  return error;
}

// The program of the first service in `services` (comma separated) from its configuration, when
// its file name is the process's; empty otherwise. Reads the service manager only.
std::string service_program_for(const std::string& services, const std::string& process_name) {
  const std::string first = trim(services.substr(0, services.find(',')));
  if (first.empty())
    return {};
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr)
    return {};
  std::string program;
  if (SC_HANDLE service = OpenServiceW(manager, wide_from_utf8(first).c_str(), SERVICE_QUERY_CONFIG)) {
    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    std::vector<unsigned char> buffer(needed == 0U ? 1U : needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (needed != 0U && QueryServiceConfigW(service, config, needed, &needed) != FALSE &&
        config->lpBinaryPathName != nullptr) {
      const std::string command = trim(utf8_from_wide(config->lpBinaryPathName));
      if (!command.empty() && command.front() == '"') {
        const std::size_t close = command.find('"', 1);
        program = close == std::string::npos ? std::string() : command.substr(1, close - 1);
      } else {
        const std::size_t exe = ascii_lower(command).find(".exe");
        program = exe == std::string::npos ? command : command.substr(0, exe + 4);
      }
    }
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
  const std::size_t slash = program.find_last_of("\\/");
  const std::string file = slash == std::string::npos ? program : program.substr(slash + 1);
  return !process_name.empty() && ascii_lower(file) == ascii_lower(process_name) ? program : std::string();
}

} // namespace

Result<LocalSocketTable> list_local_sockets() {
  LocalSocketTable table;
  std::vector<unsigned char> buffer;

  if (fetch_table(buffer, [](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
      })) {
    const auto* rows = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      LocalSocket socket;
      socket.protocol = PortProtocol::tcp;
      socket.local_address = ipv4_text(row.dwLocalAddr);
      socket.local_port = port_of(row.dwLocalPort);
      socket.state = tcp_state_name(row.dwState);
      if (row.dwState != MIB_TCP_STATE_LISTEN) {
        socket.remote_address = ipv4_text(row.dwRemoteAddr);
        socket.remote_port = port_of(row.dwRemotePort);
      }
      socket.pid = row.dwOwningPid;
      table.sockets.push_back(std::move(socket));
    }
  } else {
    return Result<LocalSocketTable>::failure(table_error("TCP", GetLastError()));
  }

  buffer.clear();
  if (fetch_table(buffer, [](void* data, DWORD* size) {
        return GetExtendedTcpTable(data, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
      })) {
    const auto* rows = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      LocalSocket socket;
      socket.protocol = PortProtocol::tcp;
      socket.ipv6 = true;
      socket.local_address = ipv6_text(row.ucLocalAddr);
      socket.local_port = port_of(row.dwLocalPort);
      socket.state = tcp_state_name(row.dwState);
      if (row.dwState != MIB_TCP_STATE_LISTEN) {
        socket.remote_address = ipv6_text(row.ucRemoteAddr);
        socket.remote_port = port_of(row.dwRemotePort);
      }
      socket.pid = row.dwOwningPid;
      table.sockets.push_back(std::move(socket));
    }
  }

  buffer.clear();
  if (fetch_table(buffer, [](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
      })) {
    const auto* rows = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      LocalSocket socket;
      socket.protocol = PortProtocol::udp;
      socket.local_address = ipv4_text(row.dwLocalAddr);
      socket.local_port = port_of(row.dwLocalPort);
      socket.state = "BOUND";
      socket.pid = row.dwOwningPid;
      table.sockets.push_back(std::move(socket));
    }
  }

  buffer.clear();
  if (fetch_table(buffer, [](void* data, DWORD* size) {
        return GetExtendedUdpTable(data, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
      })) {
    const auto* rows = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(buffer.data());
    for (DWORD i = 0; i < rows->dwNumEntries; ++i) {
      const auto& row = rows->table[i];
      LocalSocket socket;
      socket.protocol = PortProtocol::udp;
      socket.ipv6 = true;
      socket.local_address = ipv6_text(row.ucLocalAddr);
      socket.local_port = port_of(row.dwLocalPort);
      socket.state = "BOUND";
      socket.pid = row.dwOwningPid;
      table.sockets.push_back(std::move(socket));
    }
  }

  const ProcessDirectory processes = ProcessDirectory::capture();
  std::map<std::uint32_t, std::string> service_paths; // per PID, read once
  for (auto& socket : table.sockets) {
    if (socket.pid == 4) {
      // Kernel-mode listeners report the System process: the SMB server on 445 and 139, and
      // HTTP.SYS for the services that register addresses with it, whose name the socket table
      // does not hold.
      socket.process_name = socket.local_port == 445 || socket.local_port == 139
                                ? "System (the SMB server in the kernel)"
                                : "System (kernel listener, such as HTTP.SYS)";
      // Windows Defender Firewall names the kernel's program "System" (File and Printer Sharing).
      socket.process_path = "System";
      continue;
    }
    if (const ProcessIdentity* identity = processes.find(socket.pid)) {
      socket.process_name = identity->name;
      socket.process_path = identity->path;
      socket.services = identity->services;
      // A service's process path is often unreadable without administrator, and a firewall rule
      // for a program can then never match it. The service's own program path is readable.
      if (socket.process_path.empty() && !socket.services.empty()) {
        auto cached = service_paths.find(socket.pid);
        if (cached == service_paths.end())
          cached = service_paths.emplace(socket.pid, service_program_for(socket.services, socket.process_name)).first;
        socket.process_path = cached->second;
      }
    }
  }
  return Result<LocalSocketTable>::success(std::move(table));
}

} // namespace support_assist
