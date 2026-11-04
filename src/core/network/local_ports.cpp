// The parts of the local port engine that do not depend on the operating system: the port list the
// engineer types, the per-port summary, and the /proc/net line parser (kept here so the unit tests
// cover it on every platform).
#include "support_assist/local_ports.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <set>

namespace support_assist {
namespace {

Error port_list_error(const std::string& message) {
  Error error;
  error.component = "network";
  error.operation = "read the port list";
  error.message = message;
  return error;
}

bool parse_port_number(std::string_view text, std::uint16_t& port) {
  if (text.empty() || text.size() > 5)
    return false;
  unsigned long value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9')
      return false;
    value = value * 10U + static_cast<unsigned long>(c - '0');
  }
  if (value == 0U || value > 65535U)
    return false;
  port = static_cast<std::uint16_t>(value);
  return true;
}

bool is_loopback(const std::string& address) {
  return address.rfind("127.", 0) == 0 || address == "::1" || address.rfind("::ffff:127.", 0) == 0;
}

bool is_any(const std::string& address) {
  return address == "0.0.0.0" || address == "::" || address == "*";
}

int hex_digit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

bool parse_hex(std::string_view text, unsigned long long& value) {
  if (text.empty() || text.size() > 16)
    return false;
  value = 0;
  for (const char c : text) {
    const int digit = hex_digit(c);
    if (digit < 0)
      return false;
    value = (value << 4U) | static_cast<unsigned long long>(digit);
  }
  return true;
}

std::vector<std::string_view> fields_of(std::string_view line) {
  std::vector<std::string_view> fields;
  std::size_t at = 0;
  while (at < line.size()) {
    while (at < line.size() && std::isspace(static_cast<unsigned char>(line[at])) != 0)
      ++at;
    const std::size_t start = at;
    while (at < line.size() && std::isspace(static_cast<unsigned char>(line[at])) == 0)
      ++at;
    if (at > start)
      fields.push_back(line.substr(start, at - start));
  }
  return fields;
}

std::string tcp_state_from_proc(unsigned long long code) {
  switch (code) {
  case 0x01: return "ESTABLISHED";
  case 0x02: return "SYN_SENT";
  case 0x03: return "SYN_RECV";
  case 0x04: return "FIN_WAIT1";
  case 0x05: return "FIN_WAIT2";
  case 0x06: return "TIME_WAIT";
  case 0x07: return "CLOSE";
  case 0x08: return "CLOSE_WAIT";
  case 0x09: return "LAST_ACK";
  case 0x0A: return "LISTEN";
  case 0x0B: return "CLOSING";
  default: return "UNKNOWN";
  }
}

} // namespace

namespace local_ports_detail {

std::string format_ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return std::to_string(a) + "." + std::to_string(b) + "." + std::to_string(c) + "." + std::to_string(d);
}

// RFC 5952 text: the longest run of two or more zero groups becomes "::", and an IPv4-mapped
// address keeps its dotted tail.
std::string format_ipv6(const std::array<std::uint8_t, 16>& bytes) {
  bool mapped = true;
  for (std::size_t i = 0; i < 10; ++i)
    mapped = mapped && bytes[i] == 0;
  mapped = mapped && bytes[10] == 0xFF && bytes[11] == 0xFF;
  if (mapped)
    return "::ffff:" + format_ipv4(bytes[12], bytes[13], bytes[14], bytes[15]);

  std::array<unsigned, 8> groups{};
  for (std::size_t i = 0; i < 8; ++i)
    groups[i] = (static_cast<unsigned>(bytes[2 * i]) << 8U) | bytes[2 * i + 1];
  std::size_t best_start = 8;
  std::size_t best_length = 0;
  for (std::size_t i = 0; i < 8;) {
    if (groups[i] != 0) {
      ++i;
      continue;
    }
    std::size_t j = i;
    while (j < 8 && groups[j] == 0)
      ++j;
    if (j - i > best_length && j - i >= 2) {
      best_start = i;
      best_length = j - i;
    }
    i = j;
  }
  std::string text;
  char buffer[8];
  for (std::size_t i = 0; i < 8; ++i) {
    if (i == best_start) {
      text += "::";
      i += best_length - 1;
      continue;
    }
    if (!text.empty() && text.back() != ':')
      text += ':';
    std::snprintf(buffer, sizeof(buffer), "%x", groups[i]);
    text += buffer;
  }
  return text.empty() ? "::" : text;
}

bool parse_proc_net_line(std::string_view line, bool ipv6, PortProtocol protocol, LocalSocket& socket,
                         unsigned long long& inode) {
  const auto fields = fields_of(line);
  if (fields.size() < 10 || fields[0].empty() || fields[0].back() != ':')
    return false;
  const auto endpoint = [ipv6](std::string_view text, std::string& address, std::uint16_t& port) {
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos)
      return false;
    const std::string_view hex_address = text.substr(0, colon);
    unsigned long long port_value = 0;
    if (!parse_hex(text.substr(colon + 1), port_value) || port_value > 65535U)
      return false;
    port = static_cast<std::uint16_t>(port_value);
    // The kernel prints each 32-bit word of the address in the host's byte order (little-endian
    // on the x86-64 and ARM64 machines SAT runs on), so each word's bytes are reversed here.
    if (!ipv6) {
      unsigned long long word = 0;
      if (hex_address.size() != 8 || !parse_hex(hex_address, word))
        return false;
      address = format_ipv4(static_cast<std::uint8_t>(word & 0xFFU), static_cast<std::uint8_t>((word >> 8U) & 0xFFU),
                            static_cast<std::uint8_t>((word >> 16U) & 0xFFU),
                            static_cast<std::uint8_t>((word >> 24U) & 0xFFU));
      return true;
    }
    if (hex_address.size() != 32)
      return false;
    std::array<std::uint8_t, 16> bytes{};
    for (std::size_t w = 0; w < 4; ++w) {
      unsigned long long word = 0;
      if (!parse_hex(hex_address.substr(w * 8, 8), word))
        return false;
      for (std::size_t b = 0; b < 4; ++b)
        bytes[w * 4 + b] = static_cast<std::uint8_t>((word >> (8U * b)) & 0xFFU);
    }
    address = format_ipv6(bytes);
    return true;
  };

  socket = LocalSocket{};
  socket.protocol = protocol;
  socket.ipv6 = ipv6;
  if (!endpoint(fields[1], socket.local_address, socket.local_port) ||
      !endpoint(fields[2], socket.remote_address, socket.remote_port))
    return false;
  unsigned long long state = 0;
  if (!parse_hex(fields[3], state))
    return false;
  socket.state = protocol == PortProtocol::udp ? "BOUND" : tcp_state_from_proc(state);
  if (protocol == PortProtocol::udp) {
    socket.remote_address.clear();
    socket.remote_port = 0;
  }
  inode = 0;
  for (const char c : fields[9]) {
    if (c < '0' || c > '9')
      return false;
    inode = inode * 10U + static_cast<unsigned long long>(c - '0');
  }
  return true;
}

} // namespace local_ports_detail

std::string to_string(PortProtocol protocol) {
  return protocol == PortProtocol::tcp ? "TCP" : "UDP";
}

std::string to_string(ListenScope scope) {
  switch (scope) {
  case ListenScope::all_addresses: return "all addresses";
  case ListenScope::loopback_only: return "loopback only";
  case ListenScope::specific_addresses: return "specific addresses";
  case ListenScope::none: break;
  }
  return "not listening";
}

Result<std::vector<std::uint16_t>> parse_port_list(std::string_view text, std::size_t max_ports) {
  std::set<std::uint16_t> ports;
  std::string item;
  const auto flush = [&]() -> Status {
    if (item.empty())
      return Status::success();
    const std::size_t dash = item.find('-');
    std::uint16_t first = 0;
    std::uint16_t last = 0;
    if (dash == std::string::npos) {
      if (!parse_port_number(item, first))
        return Status::failure(port_list_error("\"" + item + "\" is not a port from 1 to 65535"));
      last = first;
    } else if (!parse_port_number(item.substr(0, dash), first) ||
               !parse_port_number(item.substr(dash + 1), last) || last < first) {
      return Status::failure(port_list_error("\"" + item + "\" is not a range such as 22-23"));
    }
    if (static_cast<std::size_t>(last - first) + 1U + ports.size() > max_ports)
      return Status::failure(port_list_error("more than " + std::to_string(max_ports) +
                                             " ports; check a smaller range"));
    for (unsigned port = first; port <= last; ++port)
      ports.insert(static_cast<std::uint16_t>(port));
    item.clear();
    return Status::success();
  };
  for (const char c : text) {
    if (c == ',' || c == ';' || std::isspace(static_cast<unsigned char>(c)) != 0) {
      if (auto flushed = flush(); !flushed.ok())
        return Result<std::vector<std::uint16_t>>::failure(flushed.error());
    } else {
      item.push_back(c);
    }
  }
  if (auto flushed = flush(); !flushed.ok())
    return Result<std::vector<std::uint16_t>>::failure(flushed.error());
  if (ports.empty())
    return Result<std::vector<std::uint16_t>>::failure(port_list_error("no port was given"));
  return Result<std::vector<std::uint16_t>>::success(std::vector<std::uint16_t>(ports.begin(), ports.end()));
}

std::vector<LocalPortState> summarize_local_ports(const std::vector<LocalSocket>& sockets,
                                                  const std::vector<std::uint16_t>& ports,
                                                  bool tcp,
                                                  bool udp) {
  std::vector<LocalPortState> states;
  for (const std::uint16_t port : ports) {
    for (const PortProtocol protocol : {PortProtocol::tcp, PortProtocol::udp}) {
      if ((protocol == PortProtocol::tcp && !tcp) || (protocol == PortProtocol::udp && !udp))
        continue;
      LocalPortState state;
      state.port = port;
      state.protocol = protocol;
      std::set<std::string> addresses;
      std::set<std::string> owner_keys;
      for (const auto& socket : sockets) {
        if (socket.protocol != protocol || socket.local_port != port)
          continue;
        state.found = true;
        const bool listening = protocol == PortProtocol::udp || socket.state == "LISTEN";
        if (!listening) {
          ++state.connections;
          continue;
        }
        state.listening = true;
        addresses.insert(socket.local_address);
        const std::string key = std::to_string(socket.pid) + "|" + socket.local_address;
        if (owner_keys.insert(key).second)
          state.owners.push_back(socket);
      }
      state.listen_addresses.assign(addresses.begin(), addresses.end());
      if (state.listening) {
        const bool any = std::any_of(addresses.begin(), addresses.end(), is_any);
        const bool loopback = std::all_of(addresses.begin(), addresses.end(), is_loopback);
        state.scope = any ? ListenScope::all_addresses
                          : loopback ? ListenScope::loopback_only : ListenScope::specific_addresses;
      }
      states.push_back(std::move(state));
    }
  }
  return states;
}

std::vector<LocalPortState> ports_held_by_process(const std::vector<LocalSocket>& sockets,
                                                  std::string_view process_name_or_pid) {
  const std::string wanted = ascii_lower(trim(process_name_or_pid));
  const bool by_pid = !wanted.empty() && std::all_of(wanted.begin(), wanted.end(),
                                                     [](char c) { return c >= '0' && c <= '9'; });
  const auto matches = [&](const LocalSocket& socket) {
    if (wanted.empty())
      return false;
    if (by_pid)
      return std::to_string(socket.pid) == wanted;
    const std::string name = ascii_lower(socket.process_name);
    return name == wanted || name == wanted + ".exe";
  };
  std::set<std::pair<int, std::uint16_t>> seen;
  std::vector<std::uint16_t> tcp_ports;
  std::vector<std::uint16_t> udp_ports;
  for (const auto& socket : sockets) {
    if (!matches(socket))
      continue;
    const bool held = socket.protocol == PortProtocol::udp || socket.state == "LISTEN";
    if (!held)
      continue;
    const int kind = socket.protocol == PortProtocol::tcp ? 0 : 1;
    if (seen.insert({kind, socket.local_port}).second)
      (kind == 0 ? tcp_ports : udp_ports).push_back(socket.local_port);
  }
  std::vector<LocalSocket> owned;
  for (const auto& socket : sockets) {
    if (matches(socket))
      owned.push_back(socket);
  }
  std::sort(tcp_ports.begin(), tcp_ports.end());
  std::sort(udp_ports.begin(), udp_ports.end());
  auto states = summarize_local_ports(owned, tcp_ports, true, false);
  auto udp_states = summarize_local_ports(owned, udp_ports, false, true);
  states.insert(states.end(), udp_states.begin(), udp_states.end());
  return states;
}

} // namespace support_assist
