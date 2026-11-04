#pragma once

// This machine's own ports: which sockets hold them, on which address, for which process. The
// engine behind the Local Port Checker (docs/PROPOSAL_5.x_CHECKS.md section 5.10) and its command
// line twin. It reads the operating system's socket tables and sends nothing.

#include "support_assist/error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class PortProtocol { tcp, udp };

std::string to_string(PortProtocol protocol);

// "999,123,22-23": ports and ranges separated by commas or spaces. Duplicates collapse and the list
// comes back sorted. A list of more than max_ports ports is refused.
Result<std::vector<std::uint16_t>> parse_port_list(std::string_view text, std::size_t max_ports = 1024);

struct LocalSocket {
  PortProtocol protocol = PortProtocol::tcp;
  bool ipv6 = false;
  std::string local_address;  // "0.0.0.0", "::", "127.0.0.1", "10.0.4.10"
  std::uint16_t local_port = 0;
  std::string remote_address; // TCP connections only
  std::uint16_t remote_port = 0;
  std::string state;          // TCP state ("LISTEN", "ESTABLISHED", ...); "BOUND" for UDP
  std::uint32_t pid = 0;      // 0 when the owner could not be read
  std::string process_name;
  std::string process_path;
  std::string services;       // Windows services hosted by the PID, comma separated
};

struct LocalSocketTable {
  std::vector<LocalSocket> sockets;
  // Sockets whose owner could not be read (on Linux without root, other accounts' sockets).
  std::size_t owners_not_readable = 0;
  std::string note;
};

// Every TCP and UDP socket on this machine, IPv4 and IPv6.
Result<LocalSocketTable> list_local_sockets();

enum class ListenScope { none, all_addresses, loopback_only, specific_addresses };

std::string to_string(ListenScope scope);

struct LocalPortState {
  std::uint16_t port = 0;
  PortProtocol protocol = PortProtocol::tcp;
  bool found = false;      // any socket holds the port
  bool listening = false;  // a TCP socket listening, or a UDP socket bound
  ListenScope scope = ListenScope::none;
  std::vector<std::string> listen_addresses;
  std::size_t connections = 0; // TCP connections on the port, in any state other than LISTEN
  std::vector<LocalSocket> owners; // the listening or bound sockets, one per address
};

// The ports asked for, per protocol asked for, from a socket table.
std::vector<LocalPortState> summarize_local_ports(const std::vector<LocalSocket>& sockets,
                                                  const std::vector<std::uint16_t>& ports,
                                                  bool tcp,
                                                  bool udp);

// Every TCP port listening and UDP port bound, for the "by process" view: the ports a process
// holds, with its connections counted.
std::vector<LocalPortState> ports_held_by_process(const std::vector<LocalSocket>& sockets,
                                                  std::string_view process_name_or_pid);

// Internal parsers and formatters, shared by the platform readers and exposed for the unit tests.
namespace local_ports_detail {
// One line of /proc/net/tcp, tcp6, udp or udp6. Returns false for the header or a malformed line.
bool parse_proc_net_line(std::string_view line, bool ipv6, PortProtocol protocol, LocalSocket& socket,
                         unsigned long long& inode);
std::string format_ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d);
// RFC 5952 text; an IPv4-mapped address keeps its dotted tail ("::ffff:10.0.4.21").
std::string format_ipv6(const std::array<std::uint8_t, 16>& bytes);
} // namespace local_ports_detail

} // namespace support_assist
