#include "support_assist/network.hpp"
#include "support_assist/https_request.hpp"
#include "support_assist/name_check.hpp"

#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/strings.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <map>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <wincrypt.h>
#else
#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace support_assist {
namespace {
// "50 MiB", "1024 MiB", "8192 MiB". MiB throughout, because that is the unit the tester's own field
// is labelled in and a message that changes unit under the reader is worse than a large number.
std::string describe_payload_size(std::uint64_t bytes) {
  const std::uint64_t mib = bytes / (1024ULL * 1024ULL);
  if (mib == 0U)
    return std::to_string(bytes) + " bytes";
  return std::to_string(mib) + " MiB";
}


#ifdef _WIN32
using SocketHandle = SOCKET;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
using SocketLength = int;
#else
using SocketHandle = int;
constexpr SocketHandle kInvalidSocket = -1;
// On POSIX a send to a peer that has closed raises SIGPIPE, whose default action ends the process.
// TCP sends pass MSG_NOSIGNAL and get EPIPE instead; a client that only checks the port closes
// before the listener's banner is sent.
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif
using SocketLength = socklen_t;
#endif

class SocketRuntime {
public:
  SocketRuntime() {
#ifdef _WIN32
    WSADATA data{};
    status_ = WSAStartup(MAKEWORD(2, 2), &data);
#endif
  }
  ~SocketRuntime() {
#ifdef _WIN32
    if (status_ == 0)
      WSACleanup();
#endif
  }
  [[nodiscard]] bool ok() const noexcept {
#ifdef _WIN32
    return status_ == 0;
#else
    return true;
#endif
  }
  [[nodiscard]] int error_code() const noexcept {
#ifdef _WIN32
    return status_;
#else
    return 0;
#endif
  }

private:
#ifdef _WIN32
  int status_ = 0;
#endif
};

class SocketOwner {
public:
  SocketOwner() = default;
  explicit SocketOwner(SocketHandle handle) : handle_(handle) {}
  ~SocketOwner() {
    reset();
  }
  SocketOwner(const SocketOwner&) = delete;
  SocketOwner& operator=(const SocketOwner&) = delete;
  SocketOwner(SocketOwner&& other) noexcept : handle_(other.release()) {}
  SocketOwner& operator=(SocketOwner&& other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  [[nodiscard]] SocketHandle get() const noexcept {
    return handle_;
  }
  [[nodiscard]] bool valid() const noexcept {
    return handle_ != kInvalidSocket;
  }
  SocketHandle release() noexcept {
    const SocketHandle value = handle_;
    handle_ = kInvalidSocket;
    return value;
  }
  void reset(SocketHandle replacement = kInvalidSocket) noexcept {
    if (valid()) {
#ifdef _WIN32
      closesocket(handle_);
#else
      close(handle_);
#endif
    }
    handle_ = replacement;
  }

private:
  SocketHandle handle_ = kInvalidSocket;
};

// Binds every SAT listener's port. On Windows SO_REUSEADDR would let a socket share a port another
// program of the same account holds, so the port is taken with SO_EXCLUSIVEADDRUSE. On POSIX
// SO_REUSEADDR only allows binding over TIME_WAIT connections of an earlier run; a port another
// program listens on still refuses the bind.
void claim_listener_port(SocketHandle socket) {
  int enable = 1;
#ifdef _WIN32
  static_cast<void>(setsockopt(socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                               reinterpret_cast<const char*>(&enable),
                               static_cast<SocketLength>(sizeof(enable))));
#else
  static_cast<void>(setsockopt(socket, SOL_SOCKET, SO_REUSEADDR,
                               reinterpret_cast<const char*>(&enable),
                               static_cast<SocketLength>(sizeof(enable))));
#endif
}

int last_socket_error() noexcept {
#ifdef _WIN32
  return WSAGetLastError();
#else
  return errno;
#endif
}

bool would_block(int error_code) noexcept {
#ifdef _WIN32
  return error_code == WSAEWOULDBLOCK || error_code == WSAEINPROGRESS || error_code == WSAEINVAL;
#else
  return error_code == EINPROGRESS || error_code == EWOULDBLOCK || error_code == EAGAIN;
#endif
}

Status set_nonblocking(SocketHandle socket) {
#ifdef _WIN32
  u_long mode = 1;
  if (ioctlsocket(socket, FIONBIO, &mode) != 0) {
    Error error;
    error.component = "Network";
    error.operation = "set nonblocking mode";
    error.native_code = last_socket_error();
    error.message = "ioctlsocket(FIONBIO) failed";
    return Status::failure(std::move(error));
  }
#else
  const int flags = fcntl(socket, F_GETFL, 0);
  if (flags < 0 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
    Error error;
    error.component = "Network";
    error.operation = "set nonblocking mode";
    error.native_code = last_socket_error();
    error.message = "fcntl(O_NONBLOCK) failed";
    return Status::failure(std::move(error));
  }
#endif
  return Status::success();
}

std::string
endpoint_text(const sockaddr* address, SocketLength length, std::uint16_t* port = nullptr) {
  std::array<char, NI_MAXHOST> host{};
  std::array<char, NI_MAXSERV> service{};
  const int result = getnameinfo(address,
                                 length,
                                 host.data(),
                                 static_cast<socklen_t>(host.size()),
                                 service.data(),
                                 static_cast<socklen_t>(service.size()),
                                 NI_NUMERICHOST | NI_NUMERICSERV);
  if (result != 0)
    return "unknown";
  if (port != nullptr) {
    unsigned long parsed = 0;
    try {
      parsed = std::stoul(service.data());
    } catch (...) {
      parsed = 0;
    }
    if (parsed <= static_cast<unsigned long>(std::numeric_limits<std::uint16_t>::max())) {
      *port = static_cast<std::uint16_t>(parsed);
    }
  }
  return host.data();
}

std::string address_info_error_text(int error_code) {
#ifdef _WIN32
  const char* text = gai_strerrorA(error_code);
#else
  const char* text = gai_strerror(error_code);
#endif
  return text == nullptr ? "Address resolution failed" : std::string(text);
}

std::string socket_error_text(int error_code) {
  if (error_code == 0)
    return "Connected";
#ifdef _WIN32
  char* raw = nullptr;
  const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                      FORMAT_MESSAGE_IGNORE_INSERTS;
  const DWORD length = FormatMessageA(flags, nullptr, static_cast<DWORD>(error_code), 0,
                                      reinterpret_cast<char*>(&raw), 0, nullptr);
  if (length == 0 || raw == nullptr)
    return "Socket error " + std::to_string(error_code);
  std::string text(raw, length);
  LocalFree(raw);
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
    text.pop_back();
  return text;
#else
  return std::strerror(error_code);
#endif
}

std::string address_family_name(int family) {
  if (family == AF_INET)
    return "IPv4";
  if (family == AF_INET6)
    return "IPv6";
  return "Other";
}

Error network_error(std::string operation,
                    std::string source,
                    std::string message,
                    std::int64_t native_code = 0) {
  Error error;
  error.component = "Network";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  error.native_code = native_code;
  return error;
}

void report(const ProgressCallback& progress,
            std::string phase,
            std::string scope,
            std::uint64_t processed = 0) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = std::move(phase);
  event.current_scope = std::move(scope);
  event.processed = processed;
  progress(event);
}

int select_socket(SocketHandle socket, bool read, std::chrono::milliseconds duration) {
  fd_set read_set;
  fd_set write_set;
  FD_ZERO(&read_set);
  FD_ZERO(&write_set);
  if (read)
    FD_SET(socket, &read_set);
  else
    FD_SET(socket, &write_set);
  timeval timeout{};
  const auto milliseconds = std::max<std::int64_t>(0, duration.count());
  timeout.tv_sec = static_cast<long>(milliseconds / 1000);
  timeout.tv_usec = static_cast<long>((milliseconds % 1000) * 1000);
#ifdef _WIN32
  // Winsock reports a failed non-blocking connect in the except set only, never as writable.
  fd_set except_set;
  FD_ZERO(&except_set);
  if (!read)
    FD_SET(socket, &except_set);
  return select(0, read ? &read_set : nullptr, read ? nullptr : &write_set, read ? nullptr : &except_set,
                &timeout);
#else
  return select(socket + 1,
                read ? &read_set : nullptr,
                read ? nullptr : &write_set,
                nullptr,
                &timeout);
#endif
}


unsigned int prefix_length_from_mask(const sockaddr* mask) {
  if (mask == nullptr)
    return 0;
  unsigned int bits = 0;
  if (mask->sa_family == AF_INET) {
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(mask);
    std::uint32_t value = ntohl(ipv4->sin_addr.s_addr);
    while (value != 0U) {
      bits += value & 1U;
      value >>= 1U;
    }
  } else if (mask->sa_family == AF_INET6) {
    const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(mask);
    for (const unsigned char byte : ipv6->sin6_addr.s6_addr) {
      unsigned char value = byte;
      while (value != 0U) {
        bits += value & 1U;
        value = static_cast<unsigned char>(value >> 1U);
      }
    }
  }
  return bits;
}

bool is_link_local_address(std::string_view address) {
  return address.rfind("169.254.", 0) == 0 ||
         address.rfind("fe80:", 0) == 0 || address.rfind("FE80:", 0) == 0;
}

bool name_contains(std::string_view text, std::string_view token) {
  std::string lower(text);
  std::string lower_token(token);
  std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  std::transform(lower_token.begin(), lower_token.end(), lower_token.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return lower.find(lower_token) != std::string::npos;
}

#ifndef _WIN32
std::string linux_default_gateway_for(std::string_view interface_name) {
#if defined(__linux__)
  std::ifstream input("/proc/net/route");
  std::string line;
  std::getline(input, line);
  while (std::getline(input, line)) {
    std::istringstream fields(line);
    std::string iface;
    std::string destination;
    std::string gateway_hex;
    unsigned long flags = 0;
    if (!(fields >> iface >> destination >> gateway_hex >> std::hex >> flags))
      continue;
    if (iface != interface_name || destination != "00000000" || (flags & 0x1UL) == 0)
      continue;
    unsigned long raw = 0;
    try {
      raw = std::stoul(gateway_hex, nullptr, 16);
    } catch (...) {
      continue;
    }
    in_addr gateway{};
    gateway.s_addr = static_cast<in_addr_t>(raw);
    char buffer[INET_ADDRSTRLEN]{};
    if (inet_ntop(AF_INET, &gateway, buffer, sizeof(buffer)) != nullptr)
      return buffer;
  }
#else
  static_cast<void>(interface_name);
#endif
  return {};
}

std::vector<std::string> linux_bond_members(std::string_view interface_name) {
  std::vector<std::string> members;
#if defined(__linux__)
  const auto path = std::filesystem::path("/sys/class/net") / std::string(interface_name) /
                    "bonding" / "slaves";
  std::ifstream input(path);
  std::string member;
  while (input >> member)
    members.push_back(member);
#else
  static_cast<void>(interface_name);
#endif
  return members;
}

bool linux_vlan_interface(std::string_view interface_name) {
#if defined(__linux__)
  std::error_code error;
  return std::filesystem::exists(std::filesystem::path("/proc/net/vlan") /
                                     std::string(interface_name),
                                 error) &&
         !error;
#else
  static_cast<void>(interface_name);
  return false;
#endif
}

bool posix_virtual_interface(std::string_view interface_name) {
#if defined(__linux__)
  const std::filesystem::path base = std::filesystem::path("/sys/class/net") /
                                     std::string(interface_name);
  std::error_code error;
  const bool has_device = std::filesystem::exists(base / "device", error) && !error;
  if (!has_device)
    return true;
#endif
  return name_contains(interface_name, "docker") || name_contains(interface_name, "veth") ||
         name_contains(interface_name, "virbr") || name_contains(interface_name, "bridge") ||
         name_contains(interface_name, "utun") || name_contains(interface_name, "tun") ||
         name_contains(interface_name, "tap") || name_contains(interface_name, "wg") ||
         name_contains(interface_name, "tailscale");
}
#endif

// An IPv6 address with its zone split off: "fe80::1%16" (Windows names the zone by its index) or
// "fe80::1%eth0". inet_pton takes no zone, and a link-local address cannot be used without one.
bool parse_ipv6(std::string_view value, in6_addr& address, std::uint32_t& scope_id) {
  scope_id = 0;
  const std::size_t percent = value.find('%');
  const std::string text(value.substr(0, percent));
  if (inet_pton(AF_INET6, text.c_str(), &address) != 1)
    return false;
  if (percent == std::string_view::npos)
    return true;
  const std::string zone(value.substr(percent + 1));
  if (zone.empty())
    return false;
  std::uint32_t index = 0;
  const auto parsed = std::from_chars(zone.data(), zone.data() + zone.size(), index);
  if (parsed.ec == std::errc() && parsed.ptr == zone.data() + zone.size()) {
    scope_id = index;
    return true;
  }
#ifdef _WIN32
  return false;
#else
  scope_id = if_nametoindex(zone.c_str());
  return scope_id != 0;
#endif
}

bool numeric_ip_address(std::string_view value) {
  if (value.empty())
    return false;
  in_addr ipv4{};
  in6_addr ipv6{};
  std::uint32_t scope_id = 0;
  const std::string text(value);
  return inet_pton(AF_INET, text.c_str(), &ipv4) == 1 || parse_ipv6(value, ipv6, scope_id);
}

int numeric_ip_family(std::string_view value) {
  if (value.empty())
    return AF_UNSPEC;
  in_addr ipv4{};
  in6_addr ipv6{};
  std::uint32_t scope_id = 0;
  const std::string text(value);
  if (inet_pton(AF_INET, text.c_str(), &ipv4) == 1)
    return AF_INET;
  if (parse_ipv6(value, ipv6, scope_id))
    return AF_INET6;
  return AF_UNSPEC;
}

Status bind_source_address(SocketHandle socket, int family, std::string_view source_address) {
  if (source_address.empty())
    return Status::success();
  if (family == AF_INET) {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    if (inet_pton(AF_INET, std::string(source_address).c_str(), &local.sin_addr) != 1) {
      return Status::failure(network_error("bind source interface", std::string(source_address),
                                           "Source address is not IPv4 for an IPv4 destination"));
    }
    if (bind(socket, reinterpret_cast<const sockaddr*>(&local),
             static_cast<SocketLength>(sizeof(local))) != 0) {
      return Status::failure(network_error("bind source interface", std::string(source_address),
                                           "bind() failed", last_socket_error()));
    }
    return Status::success();
  }
  if (family == AF_INET6) {
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_port = 0;
    std::uint32_t scope_id = 0;
    if (!parse_ipv6(source_address, local.sin6_addr, scope_id)) {
      return Status::failure(network_error("bind source interface", std::string(source_address),
                                           "Source address is not IPv6 for an IPv6 destination"));
    }
    // A link-local source is bound on its own interface.
    local.sin6_scope_id = scope_id;
    if (bind(socket, reinterpret_cast<const sockaddr*>(&local),
             static_cast<SocketLength>(sizeof(local))) != 0) {
      return Status::failure(network_error("bind source interface", std::string(source_address),
                                           "bind() failed", last_socket_error()));
    }
    return Status::success();
  }
  return Status::failure(network_error("bind source interface", std::string(source_address),
                                       "Unsupported source address family"));
}

std::string socket_local_address(SocketHandle socket) {
  sockaddr_storage local{};
  SocketLength length = static_cast<SocketLength>(sizeof(local));
  if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &length) != 0)
    return {};
  return endpoint_text(reinterpret_cast<const sockaddr*>(&local), length);
}

Result<SocketOwner> connect_tcp_socket(std::string_view host,
                                      std::uint16_t port,
                                      std::chrono::milliseconds timeout,
                                      const CancellationToken& cancel,
                                      const ProgressCallback& progress,
                                      std::string& connected_address,
                                      std::string_view source_address = {}) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_CANONNAME;
  addrinfo* raw_results = nullptr;
  const std::string service = std::to_string(port);
  const std::string host_text(host);
  const int resolve_result = getaddrinfo(host_text.c_str(), service.c_str(), &hints, &raw_results);
  if (resolve_result != 0) {
    return Result<SocketOwner>::failure(
        network_error("resolve", host_text, address_info_error_text(resolve_result), resolve_result));
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> results(raw_results, freeaddrinfo);
  const int source_family = numeric_ip_family(source_address);
  for (addrinfo* current = results.get(); current != nullptr; current = current->ai_next) {
    if (source_family != AF_UNSPEC && current->ai_family != source_family)
      continue;
    if (cancel.is_cancelled()) {
      return Result<SocketOwner>::failure(
          network_error("connect", host_text + ":" + service, "Operation cancelled"));
    }
    const std::string address =
        endpoint_text(current->ai_addr, static_cast<SocketLength>(current->ai_addrlen));
    report(progress, "Connecting", address);
    SocketOwner socket(::socket(current->ai_family, current->ai_socktype, current->ai_protocol));
    if (!socket.valid())
      continue;
    if (!source_address.empty()) {
      auto bound = bind_source_address(socket.get(), current->ai_family, source_address);
      if (!bound.ok())
        continue;
    }
    if (auto status = set_nonblocking(socket.get()); !status.ok())
      continue;
    const int result =
        connect(socket.get(), current->ai_addr, static_cast<SocketLength>(current->ai_addrlen));
    if (result == 0) {
      connected_address = address;
      return Result<SocketOwner>::success(std::move(socket));
    }
    const int connect_error = last_socket_error();
    if (!would_block(connect_error))
      continue;
    const auto started = std::chrono::steady_clock::now();
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() - started < timeout) {
      const int selected = select_socket(socket.get(), false, std::chrono::milliseconds(100));
      if (selected < 0)
        break;
      if (selected == 0)
        continue;
      int pending_error = 0;
      SocketLength pending_length = static_cast<SocketLength>(sizeof(pending_error));
      if (getsockopt(socket.get(),
                     SOL_SOCKET,
                     SO_ERROR,
                     reinterpret_cast<char*>(&pending_error),
                     &pending_length) == 0 &&
          pending_error == 0) {
        connected_address = address;
        return Result<SocketOwner>::success(std::move(socket));
      }
      break;
    }
  }
  return Result<SocketOwner>::failure(
      network_error("connect", host_text + ":" + service,
                    "Nothing accepted a connection on port " + service + " at any address of " + host_text));
}

Status send_control_text(SocketHandle socket,
                         std::string_view text,
                         std::chrono::milliseconds timeout,
                         const CancellationToken& cancel,
                         std::string_view peer) {
  std::size_t sent_total = 0;
  const auto started = std::chrono::steady_clock::now();
  while (sent_total < text.size()) {
    if (cancel.is_cancelled())
      return Status::failure(network_error("TCP throughput handshake", std::string(peer), "Operation cancelled"));
    if (std::chrono::steady_clock::now() - started >= timeout)
      return Status::failure(network_error("TCP throughput handshake", std::string(peer), "Handshake send timed out"));
    const int selected = select_socket(socket, false, std::chrono::milliseconds(100));
    if (selected < 0)
      return Status::failure(network_error("TCP throughput handshake", std::string(peer),
                                           "select() failed", last_socket_error()));
    if (selected == 0)
      continue;
    const std::size_t remaining = text.size() - sent_total;
#ifdef _WIN32
    const int sent = send(socket, text.data() + sent_total, static_cast<int>(remaining), 0);
#else
    const ssize_t sent = send(socket, text.data() + sent_total, remaining, kSendFlags);
#endif
    if (sent > 0) {
      sent_total += static_cast<std::size_t>(sent);
      continue;
    }
    if (sent == 0)
      return Status::failure(network_error("TCP throughput handshake", std::string(peer),
                                           "Peer closed during handshake"));
    const int code = last_socket_error();
    if (!would_block(code))
      return Status::failure(network_error("TCP throughput handshake", std::string(peer),
                                           "send() failed", code));
  }
  return Status::success();
}

Result<std::string> receive_control_line(SocketHandle socket,
                                         std::chrono::milliseconds timeout,
                                         const CancellationToken& cancel,
                                         std::string_view peer) {
  std::string line;
  line.reserve(128);
  const auto started = std::chrono::steady_clock::now();
  while (line.size() < 512U) {
    if (cancel.is_cancelled())
      return Result<std::string>::failure(
          network_error("TCP throughput handshake", std::string(peer), "Operation cancelled"));
    if (std::chrono::steady_clock::now() - started >= timeout)
      return Result<std::string>::failure(
          network_error("TCP throughput handshake", std::string(peer), "Handshake receive timed out"));
    const int selected = select_socket(socket, true, std::chrono::milliseconds(100));
    if (selected < 0)
      return Result<std::string>::failure(network_error(
          "TCP throughput handshake", std::string(peer), "select() failed", last_socket_error()));
    if (selected == 0)
      continue;
    char c = '\0';
#ifdef _WIN32
    const int received = recv(socket, &c, 1, 0);
#else
    const ssize_t received = recv(socket, &c, 1, 0);
#endif
    if (received == 1) {
      if (c == '\n')
        return Result<std::string>::success(std::move(line));
      if (c != '\r')
        line.push_back(c);
      continue;
    }
    if (received == 0)
      return Result<std::string>::failure(network_error(
          "TCP throughput handshake", std::string(peer), "Peer closed during handshake"));
    const int code = last_socket_error();
    if (!would_block(code))
      return Result<std::string>::failure(network_error(
          "TCP throughput handshake", std::string(peer), "recv() failed", code));
  }
  return Result<std::string>::failure(network_error(
      "TCP throughput handshake", std::string(peer), "Handshake line exceeded 512 bytes"));
}


Status send_protocol_text(SocketHandle socket,
                          std::string_view text,
                          std::chrono::milliseconds timeout,
                          const CancellationToken& cancel,
                          std::string_view operation,
                          std::string_view peer) {
  std::size_t sent_total = 0;
  const auto started = std::chrono::steady_clock::now();
  while (sent_total < text.size()) {
    if (cancel.is_cancelled())
      return Status::failure(network_error(std::string(operation), std::string(peer), "Operation cancelled"));
    if (std::chrono::steady_clock::now() - started >= timeout)
      return Status::failure(network_error(std::string(operation), std::string(peer), "Send timed out"));
    const int selected = select_socket(socket, false, std::chrono::milliseconds(100));
    if (selected < 0) {
#ifndef _WIN32
      if (last_socket_error() == EINTR)
        continue;
#endif
      return Status::failure(network_error(std::string(operation), std::string(peer),
                                           "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    const std::size_t remaining = text.size() - sent_total;
#ifdef _WIN32
    const int sent = send(socket, text.data() + sent_total, static_cast<int>(remaining), 0);
#else
    const ssize_t sent = send(socket, text.data() + sent_total, remaining, kSendFlags);
#endif
    if (sent > 0) {
      sent_total += static_cast<std::size_t>(sent);
      continue;
    }
    if (sent == 0)
      return Status::failure(network_error(std::string(operation), std::string(peer), "Peer closed during send"));
    const int code = last_socket_error();
    if (!would_block(code))
      return Status::failure(network_error(std::string(operation), std::string(peer), "send() failed", code));
  }
  return Status::success();
}

Result<std::string> receive_protocol_line(SocketHandle socket,
                                          std::chrono::milliseconds timeout,
                                          const CancellationToken& cancel,
                                          std::string_view operation,
                                          std::string_view peer,
                                          bool allow_clean_close = false) {
  std::string line;
  line.reserve(192);
  const auto started = std::chrono::steady_clock::now();
  while (line.size() < 1024U) {
    if (cancel.is_cancelled())
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "Operation cancelled"));
    if (std::chrono::steady_clock::now() - started >= timeout)
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "Receive timed out"));
    const int selected = select_socket(socket, true, std::chrono::milliseconds(100));
    if (selected < 0) {
#ifndef _WIN32
      if (last_socket_error() == EINTR)
        continue;
#endif
      return Result<std::string>::failure(network_error(
          std::string(operation), std::string(peer), "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    char c = '\0';
#ifdef _WIN32
    const int received = recv(socket, &c, 1, 0);
#else
    const ssize_t received = recv(socket, &c, 1, 0);
#endif
    if (received == 1) {
      if (c == '\n')
        return Result<std::string>::success(std::move(line));
      if (c != '\r')
        line.push_back(c);
      continue;
    }
    if (received == 0) {
      if (allow_clean_close)
        return Result<std::string>::success(std::move(line));
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "Peer closed during receive"));
    }
    const int code = last_socket_error();
    if (!would_block(code))
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "recv() failed", code));
  }
  return Result<std::string>::failure(
      network_error(std::string(operation), std::string(peer), "Protocol line exceeded 1024 bytes"));
}

class Sha256Accumulator {
public:
  Sha256Accumulator() : context_(EVP_MD_CTX_new()) {
    if (context_ != nullptr)
      valid_ = EVP_DigestInit_ex(context_, EVP_sha256(), nullptr) == 1;
  }
  ~Sha256Accumulator() {
    EVP_MD_CTX_free(context_);
  }
  Sha256Accumulator(const Sha256Accumulator&) = delete;
  Sha256Accumulator& operator=(const Sha256Accumulator&) = delete;

  [[nodiscard]] bool valid() const noexcept { return valid_; }

  bool update(const void* data, std::size_t bytes) {
    return valid_ && EVP_DigestUpdate(context_, data, bytes) == 1;
  }

  Result<std::string> finish(std::string_view operation, std::string_view peer) {
    if (!valid_)
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "Unable to initialize SHA-256"));
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int digest_length = 0;
    if (EVP_DigestFinal_ex(context_, digest.data(), &digest_length) != 1) {
      return Result<std::string>::failure(
          network_error(std::string(operation), std::string(peer), "Unable to finalize SHA-256"));
    }
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digest_length; ++index)
      output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    valid_ = false;
    return Result<std::string>::success(output.str());
  }

private:
  EVP_MD_CTX* context_ = nullptr;
  bool valid_ = false;
};

std::string normalize_fingerprint(std::string_view input) {
  std::string output;
  output.reserve(input.size());
  for (const unsigned char c : input) {
    if (std::isxdigit(c) != 0)
      output.push_back(static_cast<char>(std::toupper(c)));
  }
  return output;
}

std::string openssl_error_text() {
  const unsigned long code = ERR_get_error();
  if (code == 0)
    return "OpenSSL did not provide an error detail";
  std::array<char, 256> buffer{};
  ERR_error_string_n(code, buffer.data(), buffer.size());
  return buffer.data();
}

std::string x509_name_text(X509_NAME* name) {
  if (name == nullptr)
    return {};
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == nullptr)
    return {};
  X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253);
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio, &data);
  std::string output;
  if (length > 0 && data != nullptr)
    output.assign(data, static_cast<std::size_t>(length));
  BIO_free(bio);
  return output;
}

std::string asn1_time_text(const ASN1_TIME* time) {
  if (time == nullptr)
    return {};
  BIO* bio = BIO_new(BIO_s_mem());
  if (bio == nullptr)
    return {};
  if (ASN1_TIME_print(bio, time) != 1) {
    BIO_free(bio);
    return {};
  }
  char* data = nullptr;
  const long length = BIO_get_mem_data(bio, &data);
  std::string output;
  if (length > 0 && data != nullptr)
    output.assign(data, static_cast<std::size_t>(length));
  BIO_free(bio);
  return output;
}

std::string x509_digest_text(X509* certificate, const EVP_MD* digest) {
  if (certificate == nullptr || digest == nullptr)
    return {};
  std::array<unsigned char, EVP_MAX_MD_SIZE> bytes{};
  unsigned int length = 0;
  if (X509_digest(certificate, digest, bytes.data(), &length) != 1)
    return {};
  std::ostringstream output;
  output << std::hex << std::uppercase << std::setfill('0');
  for (unsigned int index = 0; index < length; ++index) {
    if (index != 0)
      output << ':';
    output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
  }
  return output.str();
}

std::vector<std::string> certificate_sans(X509* certificate) {
  std::vector<std::string> output;
  if (certificate == nullptr)
    return output;
  GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
      X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr));
  if (names == nullptr)
    return output;
  const int count = sk_GENERAL_NAME_num(names);
  for (int index = 0; index < count; ++index) {
    const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, index);
    if (name == nullptr)
      continue;
    if (name->type == GEN_DNS) {
      const ASN1_STRING* value = name->d.dNSName;
      const unsigned char* data = ASN1_STRING_get0_data(value);
      const int length = ASN1_STRING_length(value);
      if (data != nullptr && length > 0)
        output.emplace_back(reinterpret_cast<const char*>(data), static_cast<std::size_t>(length));
    } else if (name->type == GEN_IPADD) {
      const ASN1_STRING* value = name->d.iPAddress;
      const unsigned char* data = ASN1_STRING_get0_data(value);
      const int length = ASN1_STRING_length(value);
      char buffer[INET6_ADDRSTRLEN]{};
      if (data != nullptr && length == 4 && inet_ntop(AF_INET, data, buffer, sizeof(buffer)) != nullptr)
        output.emplace_back(buffer);
      else if (data != nullptr && length == 16 && inet_ntop(AF_INET6, data, buffer, sizeof(buffer)) != nullptr)
        output.emplace_back(buffer);
    }
  }
  GENERAL_NAMES_free(names);
  return output;
}

struct HandshakeTrace {
  bool client_hello = false;
  bool server_hello = false;
  bool certificate_request = false;
  std::size_t client_hello_bytes = 0;
  std::size_t server_hello_bytes = 0;
};

void tls_message_callback(int write_p,
                          int /*version*/,
                          int content_type,
                          const void* buffer,
                          std::size_t length,
                          SSL* /*ssl*/,
                          void* argument) {
  if (argument == nullptr || content_type != SSL3_RT_HANDSHAKE || buffer == nullptr || length == 0)
    return;
  auto* trace = static_cast<HandshakeTrace*>(argument);
  const auto* bytes = static_cast<const unsigned char*>(buffer);
  const unsigned char type = bytes[0];
  if (write_p != 0 && type == SSL3_MT_CLIENT_HELLO) {
    trace->client_hello = true;
    trace->client_hello_bytes = length;
  } else if (write_p == 0 && type == SSL3_MT_SERVER_HELLO) {
    trace->server_hello = true;
    trace->server_hello_bytes = length;
  } else if (write_p == 0 && type == SSL3_MT_CERTIFICATE_REQUEST) {
    trace->certificate_request = true;
  }
}

std::vector<std::string> ssl_cipher_names(SSL* ssl) {
  std::vector<std::string> output;
  if (ssl == nullptr)
    return output;
  STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);
  const int count = ciphers == nullptr ? 0 : sk_SSL_CIPHER_num(ciphers);
  output.reserve(static_cast<std::size_t>(std::max(count, 0)));
  for (int index = 0; index < count; ++index) {
    const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, index);
    if (cipher != nullptr && SSL_CIPHER_get_name(cipher) != nullptr)
      output.emplace_back(SSL_CIPHER_get_name(cipher));
  }
  return output;
}

void configure_tls_version(SSL_CTX* context, TlsProbeVersion version) {
  if (context == nullptr)
    return;
  switch (version) {
  case TlsProbeVersion::tls12_only:
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION);
    break;
  case TlsProbeVersion::tls13_only:
#ifdef TLS1_3_VERSION
    SSL_CTX_set_min_proto_version(context, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION);
#endif
    break;
  case TlsProbeVersion::automatic:
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
#ifdef TLS1_3_VERSION
    SSL_CTX_set_max_proto_version(context, TLS1_3_VERSION);
#endif
    break;
  }
}

void add_offered_versions(TlsProbeVersion version, std::vector<std::string>& versions) {
  if (version == TlsProbeVersion::automatic || version == TlsProbeVersion::tls12_only)
    versions.emplace_back("TLS 1.2");
#ifdef TLS1_3_VERSION
  if (version == TlsProbeVersion::automatic || version == TlsProbeVersion::tls13_only)
    versions.emplace_back("TLS 1.3");
#else
  if (version == TlsProbeVersion::tls13_only)
    versions.emplace_back("TLS 1.3 unavailable in local TLS library");
#endif
}

TlsCertificateInfo inspect_peer_certificate(SSL* ssl,
                                            const TlsProbeOptions& options) {
  TlsCertificateInfo output;
  if (ssl == nullptr)
    return output;
  X509* certificate = SSL_get1_peer_certificate(ssl);
  if (certificate == nullptr)
    return output;

  output.subject = x509_name_text(X509_get_subject_name(certificate));
  output.issuer = x509_name_text(X509_get_issuer_name(certificate));
  output.subject_alt_names = certificate_sans(certificate);
  output.valid_from = asn1_time_text(X509_get0_notBefore(certificate));
  output.valid_until = asn1_time_text(X509_get0_notAfter(certificate));
  output.sha1_thumbprint = x509_digest_text(certificate, EVP_sha1());
  output.sha256_fingerprint = x509_digest_text(certificate, EVP_sha256());

  const std::string expected_name = options.server_name.empty() ? options.host : options.server_name;
  if (!expected_name.empty()) {
    output.hostname_checked = true;
    output.hostname_matches =
        X509_check_host(certificate, expected_name.c_str(), expected_name.size(), 0, nullptr) == 1;
  }

  if (!options.expected_fingerprint.empty()) {
    output.expected_fingerprint_provided = true;
    const std::string expected = normalize_fingerprint(options.expected_fingerprint);
    const std::string sha1 = normalize_fingerprint(output.sha1_thumbprint);
    const std::string sha256 = normalize_fingerprint(output.sha256_fingerprint);
    output.expected_fingerprint_matches = expected == sha1 || expected == sha256;
  }

  if (options.check_system_trust) {
    output.system_trust_checked = true;
    X509_STORE* store = X509_STORE_new();
    X509_STORE_CTX* store_context = X509_STORE_CTX_new();
    if (store != nullptr && store_context != nullptr && X509_STORE_set_default_paths(store) == 1) {
      STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl);
      if (X509_STORE_CTX_init(store_context, store, certificate, chain) == 1) {
        const int verified = X509_verify_cert(store_context);
        output.system_trusted = verified == 1;
        if (verified == 1) {
          output.system_trust_detail = "Certificate chain validated against the local trust store";
        } else {
          const int verify_error = X509_STORE_CTX_get_error(store_context);
          output.system_trust_detail = X509_verify_cert_error_string(verify_error);
        }
      } else {
        output.system_trust_detail = "Unable to initialize certificate verification context";
      }
    } else {
      output.system_trust_detail = "Unable to load the local TLS trust store";
    }
    X509_STORE_CTX_free(store_context);
    X509_STORE_free(store);
  }

  X509_free(certificate);
  return output;
}

Result<std::uint64_t> parse_throughput_request(std::string_view line) {
  std::istringstream input{std::string(line)};
  std::string protocol;
  std::string direction;
  std::uint64_t bytes = 0;
  std::string trailing;
  if (!(input >> protocol >> direction >> bytes) || (input >> trailing) ||
      protocol != "SAT-THROUGHPUT/1" || direction != "SEND" || bytes == 0U) {
    return Result<std::uint64_t>::failure(
        network_error("TCP throughput handshake", std::string(line),
                      "Peer did not send a valid SAT-THROUGHPUT/1 SEND handshake"));
  }
  return Result<std::uint64_t>::success(bytes);
}

Result<std::uint64_t> parse_throughput_ack(std::string_view line) {
  std::istringstream input{std::string(line)};
  std::string protocol;
  std::string status;
  std::uint64_t bytes = 0;
  std::string trailing;
  if (!(input >> protocol >> status >> bytes) || (input >> trailing) ||
      protocol != "SAT-THROUGHPUT/1" || status != "OK" || bytes == 0U) {
    return Result<std::uint64_t>::failure(
        network_error("TCP throughput handshake", std::string(line),
                      "Peer did not acknowledge the SAT throughput protocol"));
  }
  return Result<std::uint64_t>::success(bytes);
}


double rate_for(std::uint64_t bytes, double seconds);

Status run_sat_connectivity_probe(SocketHandle socket,
                                  const TcpPortTestOptions& options,
                                  TcpEndpointAttempt& attempt,
                                  const CancellationToken& cancel,
                                  const ProgressCallback& progress,
                                  std::string_view peer) {
  if (!options.detect_sat_listener)
    return Status::success();

  auto hello = receive_protocol_line(socket,
                                     std::chrono::milliseconds(400),
                                     cancel,
                                     "SAT connectivity handshake",
                                     peer,
                                     true);
  if (cancel.is_cancelled())
    return Status::failure(network_error("SAT connectivity handshake", std::string(peer),
                                         "Operation cancelled"));
  if (!hello.ok())
    return Status::success();
  if (hello.value().rfind("SAT-CONNECT/2 HELLO ", 0) != 0) {
    attempt.peer_banner = trim(hello.value());
    return Status::success();
  }

  attempt.sat_listener_detected = true;
  attempt.sat_test_id = make_uuid_v4();
  const std::uint64_t requested_bytes = options.sat_payload_bytes;
  const std::string request = "SAT-CONNECT/2 TEST " + attempt.sat_test_id + " " +
                              std::to_string(requested_bytes) + "\n";
  auto sent_request = send_protocol_text(socket,
                                         request,
                                         std::chrono::seconds(3),
                                         cancel,
                                         "SAT connectivity handshake",
                                         peer);
  if (!sent_request.ok())
    return sent_request;

  auto ready = receive_protocol_line(socket,
                                     std::chrono::seconds(3),
                                     cancel,
                                     "SAT connectivity handshake",
                                     peer);
  if (!ready.ok())
    return Status::failure(ready.error());
  {
    std::istringstream input{ready.value()};
    std::string protocol;
    std::string state;
    std::string test_id;
    std::uint64_t bytes = 0;
    std::string trailing;
    if (!(input >> protocol >> state >> test_id >> bytes) || (input >> trailing) ||
        protocol != "SAT-CONNECT/2" || state != "READY" ||
        test_id != attempt.sat_test_id || bytes != requested_bytes) {
      return Status::failure(network_error("SAT connectivity handshake",
                                           std::string(peer),
                                           "SAT listener returned an invalid READY response"));
    }
  }
  attempt.sat_handshake_completed = true;
  attempt.sat_payload_bytes = requested_bytes;
  if (requested_bytes == 0) {
    auto banner = receive_protocol_line(socket, std::chrono::milliseconds(750), cancel,
                                        "TCP listener banner", peer, true);
    if (banner.ok())
      attempt.peer_banner = trim(banner.value());
    return Status::success();
  }

  Sha256Accumulator digest;
  if (!digest.valid()) {
    return Status::failure(network_error("SAT connectivity payload",
                                         std::string(peer),
                                         "Unable to initialize SHA-256"));
  }

  std::vector<unsigned char> buffer(256U * 1024U);
  for (std::size_t index = 0; index < buffer.size(); ++index)
    buffer[index] = static_cast<unsigned char>((index * 131U + 17U) & 0xffU);

  const auto started = std::chrono::steady_clock::now();
  // Scale the budget with the payload, keeping the configured value as a floor. At a
  // deliberately pessimistic 10 Mbit/s a gigabyte needs about fourteen minutes; a flat sixty
  // seconds would have failed every large run as a timeout rather than reporting its rate.
  const auto size_budget = std::chrono::milliseconds(
      static_cast<std::int64_t>(requested_bytes / (10ULL * 1024ULL * 1024ULL / 8ULL)) * 1000);
  const auto deadline = started + std::max(options.sat_payload_timeout, size_budget);
  std::uint64_t sent_total = 0;
  while (sent_total < requested_bytes) {
    if (cancel.is_cancelled())
      return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                           "Operation cancelled"));
    if (std::chrono::steady_clock::now() >= deadline)
      return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                           describe_payload_size(requested_bytes) +
                                               " payload validation timed out"));
    const std::size_t remaining = static_cast<std::size_t>(
        std::min<std::uint64_t>(requested_bytes - sent_total,
                                static_cast<std::uint64_t>(buffer.size())));
    const int selected = select_socket(socket, false, std::chrono::milliseconds(100));
    if (selected < 0) {
#ifndef _WIN32
      if (last_socket_error() == EINTR)
        continue;
#endif
      return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                           "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
#ifdef _WIN32
    const int sent = send(socket,
                          reinterpret_cast<const char*>(buffer.data()),
                          static_cast<int>(remaining),
                          0);
#else
    const ssize_t sent = send(socket, buffer.data(), remaining, kSendFlags);
#endif
    if (sent > 0) {
      const auto sent_size = static_cast<std::size_t>(sent);
      if (!digest.update(buffer.data(), sent_size)) {
        return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                             "SHA-256 update failed"));
      }
      sent_total += static_cast<std::uint64_t>(sent_size);
      report(progress, "Validating payload", std::string(peer), sent_total);
      continue;
    }
    if (sent == 0) {
      return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                           "Peer closed during payload transfer"));
    }
    const int code = last_socket_error();
    if (!would_block(code)) {
      return Status::failure(network_error("SAT connectivity payload", std::string(peer),
                                           "send() failed", code));
    }
  }

  auto sha256 = digest.finish("SAT connectivity payload", peer);
  if (!sha256.ok())
    return Status::failure(sha256.error());
  const std::string done = "SAT-CONNECT/2 DONE " + attempt.sat_test_id + " " +
                           sha256.value() + "\n";
  auto sent_done = send_protocol_text(socket,
                                      done,
                                      std::chrono::seconds(3),
                                      cancel,
                                      "SAT connectivity payload",
                                      peer);
  if (!sent_done.ok())
    return sent_done;

  auto result = receive_protocol_line(socket,
                                      std::chrono::seconds(5),
                                      cancel,
                                      "SAT connectivity payload",
                                      peer);
  if (!result.ok())
    return Status::failure(result.error());
  std::istringstream input{result.value()};
  std::string protocol;
  std::string state;
  std::string test_id;
  std::string status;
  std::uint64_t bytes = 0;
  std::string peer_sha256;
  std::string trailing;
  if (!(input >> protocol >> state >> test_id >> status >> bytes >> peer_sha256) ||
      (input >> trailing) || protocol != "SAT-CONNECT/2" || state != "RESULT" ||
      test_id != attempt.sat_test_id || status != "OK" || bytes != requested_bytes ||
      normalize_fingerprint(peer_sha256) != normalize_fingerprint(sha256.value())) {
    return Status::failure(network_error("SAT connectivity payload",
                                         std::string(peer),
                                         "SAT listener did not validate the payload SHA-256"));
  }

  const double seconds = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - started)
                             .count();
  attempt.sat_payload_seconds = seconds;
  attempt.sat_payload_bits_per_second = rate_for(requested_bytes, seconds);
  attempt.sat_payload_sha256 = sha256.value();
  attempt.sat_payload_validated = true;
  auto banner = receive_protocol_line(socket, std::chrono::milliseconds(750), cancel,
                                      "TCP listener banner", peer, true);
  if (banner.ok())
    attempt.peer_banner = trim(banner.value());
  return Status::success();
}

// The File Transfer Calculator's test on a SAT listener's port: the bytes are counted and timed, not
// hashed, so the figure is the network's and not the hash's. DONE tells the sender every byte is here.
Status service_sat_throughput(SocketHandle socket,
                              const TcpListenerOptions& options,
                              TcpAcceptedConnection& connection,
                              const std::string& request,
                              const CancellationToken& cancel,
                              const ProgressCallback& progress,
                              const std::string& peer) {
  auto requested = parse_throughput_request(request);
  if (!requested.ok())
    return Status::failure(requested.error());
  if (requested.value() > options.max_sat_payload_bytes) {
    static_cast<void>(send_protocol_text(socket, "SAT-THROUGHPUT/1 ERR 0\n", std::chrono::seconds(2), cancel,
                                         "SAT listener throughput", peer));
    return Status::failure(network_error("SAT listener throughput", peer,
                                         "The largest transfer this listener accepts is " +
                                             describe_payload_size(options.max_sat_payload_bytes) + "."));
  }
  const std::uint64_t expected = requested.value();
  connection.sat_probe = true;
  connection.sat_throughput = true;
  connection.sat_payload_bytes = expected;
  auto sent_ok = send_protocol_text(socket, "SAT-THROUGHPUT/1 OK " + std::to_string(expected) + "\n",
                                    std::chrono::seconds(2), cancel, "SAT listener throughput", peer);
  if (!sent_ok.ok())
    return sent_ok;

  std::vector<char> buffer(256U * 1024U);
  std::uint64_t received_total = 0;
  const auto started = std::chrono::steady_clock::now();
  auto last_activity = started;
  while (received_total < expected) {
    if (cancel.is_cancelled())
      return Status::failure(network_error("SAT listener throughput", peer, "Operation cancelled"));
    if (std::chrono::steady_clock::now() - last_activity >= std::chrono::seconds(30))
      return Status::failure(network_error("SAT listener throughput", peer, "Transfer timed out with no progress"));
    const int selected = select_socket(socket, true, std::chrono::milliseconds(100));
    if (selected < 0) {
#ifndef _WIN32
      if (last_socket_error() == EINTR)
        continue;
#endif
      return Status::failure(network_error("SAT listener throughput", peer, "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    const std::size_t count = static_cast<std::size_t>(
        std::min<std::uint64_t>(expected - received_total, static_cast<std::uint64_t>(buffer.size())));
#ifdef _WIN32
    const int received = recv(socket, buffer.data(), static_cast<int>(count), 0);
#else
    const ssize_t received = recv(socket, buffer.data(), count, 0);
#endif
    if (received > 0) {
      received_total += static_cast<std::uint64_t>(received);
      last_activity = std::chrono::steady_clock::now();
      report(progress, "Receiving the transfer test", peer, received_total);
      continue;
    }
    if (received == 0)
      return Status::failure(network_error("SAT listener throughput", peer, "Peer closed before the transfer completed"));
    const int code = last_socket_error();
    if (!would_block(code))
      return Status::failure(network_error("SAT listener throughput", peer, "recv() failed", code));
  }
  const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  connection.sat_payload_seconds = seconds;
  connection.sat_payload_validated = received_total == expected;
  const auto micros = static_cast<long long>(std::llround(seconds * 1e6));
  static_cast<void>(send_protocol_text(socket,
                                       "SAT-THROUGHPUT/1 DONE " + std::to_string(received_total) + " " +
                                           std::to_string(micros) + "\n",
                                       std::chrono::seconds(3), cancel, "SAT listener throughput", peer));
  return Status::success();
}

Status service_sat_listener_connection(SocketHandle socket,
                                       const TcpListenerOptions& options,
                                       TcpAcceptedConnection& connection,
                                       const CancellationToken& cancel,
                                       const ProgressCallback& progress) {
  if (!options.enable_sat_protocol)
    return Status::success();

  const std::string listener_id = make_uuid_v4();
  const std::string peer = connection.remote_address + ":" +
                           std::to_string(connection.remote_port);
  const std::string hello = "SAT-CONNECT/2 HELLO " + listener_id +
                            " PAYLOAD_SHA256\n";
  auto sent_hello = send_protocol_text(socket,
                                       hello,
                                       std::chrono::seconds(2),
                                       cancel,
                                       "SAT listener handshake",
                                       peer);
  if (!sent_hello.ok())
    return sent_hello;

  auto request = receive_protocol_line(socket,
                                       std::chrono::milliseconds(750),
                                       cancel,
                                       "SAT listener handshake",
                                       peer,
                                       true);
  if (cancel.is_cancelled())
    return Status::failure(network_error("SAT listener handshake", peer, "Operation cancelled"));
  // The File Transfer Calculator's test, on the same port.
  if (request.ok() && request.value().rfind("SAT-THROUGHPUT/1 ", 0) == 0)
    return service_sat_throughput(socket, options, connection, request.value(), cancel, progress, peer);
  if (!request.ok() || request.value().rfind("SAT-CONNECT/2 TEST ", 0) != 0)
    return Status::success();

  std::istringstream input{request.value()};
  std::string protocol;
  std::string action;
  std::string test_id;
  std::uint64_t requested_bytes = 0;
  std::string trailing;
  if (!(input >> protocol >> action >> test_id >> requested_bytes) || (input >> trailing) ||
      protocol != "SAT-CONNECT/2" || action != "TEST" || test_id.empty() ||
      requested_bytes > options.max_sat_payload_bytes) {
    // Name the cap. A refusal that says only "invalid" sends the engineer looking at the
    // network for a limit that is ours.
    return Status::failure(network_error(
        "SAT listener handshake", peer,
        "Invalid SAT connectivity TEST request. The largest payload this listener accepts is " +
            describe_payload_size(options.max_sat_payload_bytes) + "."));
  }

  connection.sat_probe = true;
  connection.sat_test_id = test_id;
  connection.sat_payload_bytes = requested_bytes;
  const std::string ready = "SAT-CONNECT/2 READY " + test_id + " " +
                            std::to_string(requested_bytes) + "\n";
  auto sent_ready = send_protocol_text(socket,
                                       ready,
                                       std::chrono::seconds(2),
                                       cancel,
                                       "SAT listener handshake",
                                       peer);
  if (!sent_ready.ok())
    return sent_ready;
  if (requested_bytes == 0)
    return Status::success();

  Sha256Accumulator digest;
  if (!digest.valid()) {
    return Status::failure(network_error("SAT listener payload", peer,
                                         "Unable to initialize SHA-256"));
  }
  std::vector<unsigned char> buffer(256U * 1024U);
  std::uint64_t received_total = 0;
  const auto started = std::chrono::steady_clock::now();
  const auto deadline = started + std::chrono::seconds(60);
  while (received_total < requested_bytes) {
    if (cancel.is_cancelled())
      return Status::failure(network_error("SAT listener payload", peer, "Operation cancelled"));
    if (std::chrono::steady_clock::now() >= deadline)
      return Status::failure(network_error("SAT listener payload", peer,
                                           "Payload receive timed out"));
    const int selected = select_socket(socket, true, std::chrono::milliseconds(100));
    if (selected < 0) {
#ifndef _WIN32
      if (last_socket_error() == EINTR)
        continue;
#endif
      return Status::failure(network_error("SAT listener payload", peer,
                                           "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    const std::size_t remaining = static_cast<std::size_t>(
        std::min<std::uint64_t>(requested_bytes - received_total,
                                static_cast<std::uint64_t>(buffer.size())));
#ifdef _WIN32
    const int received = recv(socket,
                              reinterpret_cast<char*>(buffer.data()),
                              static_cast<int>(remaining),
                              0);
#else
    const ssize_t received = recv(socket, buffer.data(), remaining, 0);
#endif
    if (received > 0) {
      const auto received_size = static_cast<std::size_t>(received);
      if (!digest.update(buffer.data(), received_size)) {
        return Status::failure(network_error("SAT listener payload", peer,
                                             "SHA-256 update failed"));
      }
      received_total += static_cast<std::uint64_t>(received_size);
      report(progress, "Receiving payload", peer, received_total);
      continue;
    }
    if (received == 0) {
      return Status::failure(network_error("SAT listener payload", peer,
                                           "Peer closed before payload completed"));
    }
    const int code = last_socket_error();
    if (!would_block(code)) {
      return Status::failure(network_error("SAT listener payload", peer,
                                           "recv() failed", code));
    }
  }

  auto sha256 = digest.finish("SAT listener payload", peer);
  if (!sha256.ok())
    return Status::failure(sha256.error());
  auto done = receive_protocol_line(socket,
                                    std::chrono::seconds(5),
                                    cancel,
                                    "SAT listener payload",
                                    peer);
  if (!done.ok())
    return Status::failure(done.error());
  std::istringstream done_input{done.value()};
  std::string done_protocol;
  std::string done_action;
  std::string done_test_id;
  std::string client_sha256;
  std::string done_trailing;
  const bool done_valid =
      (done_input >> done_protocol >> done_action >> done_test_id >> client_sha256) &&
      !(done_input >> done_trailing) && done_protocol == "SAT-CONNECT/2" &&
      done_action == "DONE" && done_test_id == test_id;
  const bool hash_match = done_valid &&
                          normalize_fingerprint(client_sha256) ==
                              normalize_fingerprint(sha256.value());
  const std::string response = "SAT-CONNECT/2 RESULT " + test_id + " " +
                               (hash_match ? "OK " : "FAIL ") +
                               std::to_string(received_total) + " " + sha256.value() + "\n";
  auto sent_result = send_protocol_text(socket,
                                        response,
                                        std::chrono::seconds(3),
                                        cancel,
                                        "SAT listener payload",
                                        peer);
  if (!sent_result.ok())
    return sent_result;

  connection.sat_payload_sha256 = sha256.value();
  connection.sat_payload_seconds = std::chrono::duration<double>(
                                       std::chrono::steady_clock::now() - started)
                                       .count();
  connection.sat_payload_validated = hash_match && received_total == requested_bytes;
  if (!connection.sat_payload_validated) {
    return Status::failure(network_error("SAT listener payload", peer,
                                         "Payload byte count or SHA-256 did not match"));
  }
  return Status::success();
}

double rate_for(std::uint64_t bytes, double seconds) {
  if (seconds <= 0.0)
    return 0.0;
  return static_cast<double>(bytes) * 8.0 / seconds;
}

} // namespace

Result<std::vector<NetworkInterfaceInfo>> enumerate_network_interfaces() {
  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<std::vector<NetworkInterfaceInfo>>::failure(
        network_error("enumerate network interfaces", {},
                      "Socket runtime initialization failed", runtime.error_code()));
  }

  std::vector<NetworkInterfaceInfo> output;
#ifdef _WIN32
  ULONG size = 16U * 1024U;
  std::vector<unsigned char> buffer(size);
  IP_ADAPTER_ADDRESSES* adapters =
      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  ULONG result = GetAdaptersAddresses(AF_UNSPEC,
                                      GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                                      nullptr,
                                      adapters,
                                      &size);
  if (result == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC,
                                  GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                                  nullptr,
                                  adapters,
                                  &size);
  }
  if (result != NO_ERROR) {
    return Result<std::vector<NetworkInterfaceInfo>>::failure(
        network_error("enumerate network interfaces", {},
                      "GetAdaptersAddresses failed", static_cast<std::int64_t>(result)));
  }

  for (const IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    const std::string name = adapter->FriendlyName == nullptr
                                 ? std::string(adapter->AdapterName == nullptr ? "adapter" : adapter->AdapterName)
                                 : utf8_from_wide(adapter->FriendlyName);
    const std::string description = adapter->Description == nullptr
                                        ? std::string{}
                                        : utf8_from_wide(adapter->Description);
    const bool loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    const bool up = adapter->OperStatus == IfOperStatusUp;
    const bool team = name_contains(name, "team") || name_contains(description, "team") ||
                      name_contains(description, "multiplexor");
    const bool vlan = name_contains(name, "vlan") || name_contains(description, "vlan");
    const bool virtual_interface = !team && !vlan &&
        (adapter->IfType == IF_TYPE_TUNNEL || name_contains(name, "vethernet") ||
         name_contains(description, "virtual") || name_contains(description, "hyper-v") ||
         name_contains(description, "vpn") || name_contains(name, "vpn"));

    std::string gateway;
    for (const IP_ADAPTER_GATEWAY_ADDRESS_LH* current = adapter->FirstGatewayAddress;
         current != nullptr; current = current->Next) {
      if (current->Address.lpSockaddr == nullptr)
        continue;
      gateway = endpoint_text(current->Address.lpSockaddr,
                              static_cast<SocketLength>(current->Address.iSockaddrLength));
      if (!gateway.empty() && gateway != "unknown")
        break;
    }

    for (const IP_ADAPTER_UNICAST_ADDRESS_LH* address = adapter->FirstUnicastAddress;
         address != nullptr; address = address->Next) {
      if (address->Address.lpSockaddr == nullptr ||
          (address->Address.lpSockaddr->sa_family != AF_INET &&
           address->Address.lpSockaddr->sa_family != AF_INET6))
        continue;
      NetworkInterfaceInfo item;
      item.name = name;
      item.description = description;
      item.address = endpoint_text(address->Address.lpSockaddr,
                                   static_cast<SocketLength>(address->Address.iSockaddrLength));
      item.address_family = address_family_name(address->Address.lpSockaddr->sa_family);
      item.prefix_length = static_cast<unsigned int>(address->OnLinkPrefixLength);
      item.gateway = gateway;
      item.up = up;
      item.loopback = loopback;
      item.virtual_interface = virtual_interface;
      item.vlan_interface = vlan;
      item.team_or_bond = team;
      item.diagnostic_default = item.up && !item.loopback && !item.address.empty() &&
                                item.address != "unknown" && !is_link_local_address(item.address) &&
                                (!item.virtual_interface || item.vlan_interface || item.team_or_bond);
      output.push_back(std::move(item));
    }
  }
#else
  ifaddrs* raw = nullptr;
  if (getifaddrs(&raw) != 0) {
    return Result<std::vector<NetworkInterfaceInfo>>::failure(
        network_error("enumerate network interfaces", {}, "getifaddrs() failed", last_socket_error()));
  }
  std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(raw, freeifaddrs);
  for (const ifaddrs* current = interfaces.get(); current != nullptr; current = current->ifa_next) {
    if (current->ifa_addr == nullptr || current->ifa_name == nullptr ||
        (current->ifa_addr->sa_family != AF_INET && current->ifa_addr->sa_family != AF_INET6))
      continue;
    NetworkInterfaceInfo item;
    item.name = current->ifa_name;
    item.description = current->ifa_name;
    item.address = endpoint_text(current->ifa_addr,
                                 current->ifa_addr->sa_family == AF_INET
                                     ? static_cast<SocketLength>(sizeof(sockaddr_in))
                                     : static_cast<SocketLength>(sizeof(sockaddr_in6)));
    item.address_family = address_family_name(current->ifa_addr->sa_family);
    item.prefix_length = prefix_length_from_mask(current->ifa_netmask);
    item.gateway = current->ifa_addr->sa_family == AF_INET
                       ? linux_default_gateway_for(item.name)
                       : std::string{};
    item.up = (current->ifa_flags & IFF_UP) != 0;
    item.loopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
    item.members = linux_bond_members(item.name);
    item.team_or_bond = !item.members.empty() || name_contains(item.name, "bond");
    item.vlan_interface = linux_vlan_interface(item.name) ||
                          (item.name.find('.') != std::string::npos && !item.loopback);
    item.virtual_interface = !item.team_or_bond && !item.vlan_interface &&
                             posix_virtual_interface(item.name);
    item.diagnostic_default = item.up && !item.loopback && !item.address.empty() &&
                              item.address != "unknown" && !is_link_local_address(item.address) &&
                              (!item.virtual_interface || item.vlan_interface || item.team_or_bond);
    output.push_back(std::move(item));
  }
#endif

  std::sort(output.begin(), output.end(), [](const auto& left, const auto& right) {
    if (left.name != right.name)
      return left.name < right.name;
    if (left.address_family != right.address_family)
      return left.address_family < right.address_family;
    return left.address < right.address;
  });
  output.erase(std::unique(output.begin(), output.end(), [](const auto& left, const auto& right) {
                 return left.name == right.name && left.address == right.address;
               }),
               output.end());
  return Result<std::vector<NetworkInterfaceInfo>>::success(std::move(output));
}

Result<std::vector<InterfaceTcpTestResult>> test_tcp_across_interfaces(
    const TcpPortTestOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress,
    bool include_virtual_or_special) {
  auto interfaces = enumerate_network_interfaces();
  if (!interfaces.ok())
    return Result<std::vector<InterfaceTcpTestResult>>::failure(interfaces.error());

  std::vector<InterfaceTcpTestResult> output;
  for (const auto& interface : interfaces.value()) {
    if (cancel.is_cancelled()) {
      return Result<std::vector<InterfaceTcpTestResult>>::failure(
          network_error("TCP interface matrix", options.host, "Operation cancelled"));
    }
    if (!interface.up || interface.loopback || interface.address.empty())
      continue;
    if (!include_virtual_or_special && !interface.diagnostic_default)
      continue;
    TcpPortTestOptions one = options;
    one.source_address = interface.address;
    one.source_interface = interface.name;
    one.describe_name_source = options.describe_name_source && output.empty();
    report(progress, "Testing interface", interface.name + " " + interface.address,
           static_cast<std::uint64_t>(output.size()));
    auto tested = test_tcp_port(one, cancel, progress);
    if (!tested.ok()) {
      // A source-address family can legitimately be incompatible with all
      // resolved target addresses. Preserve a structured row instead of
      // aborting the entire matrix.
      TcpPortTestResult failed;
      failed.host = options.host;
      failed.port = options.port;
      TcpEndpointAttempt attempt;
      attempt.source_address = interface.address;
      attempt.source_interface = interface.name;
      attempt.address_family = interface.address_family;
      attempt.message = tested.error().message;
      attempt.native_code = tested.error().native_code;
      failed.attempts.push_back(std::move(attempt));
      output.push_back(InterfaceTcpTestResult{interface, std::move(failed)});
      continue;
    }
    output.push_back(InterfaceTcpTestResult{interface, std::move(tested.value())});
  }
  return Result<std::vector<InterfaceTcpTestResult>>::success(std::move(output));
}

Result<UdpPortTestResult> test_udp_port(const UdpPortTestOptions& options,
                                        const CancellationToken& cancel,
                                        ProgressCallback progress) {
  if (options.host.empty() || options.port == 0) {
    return Result<UdpPortTestResult>::failure(
        network_error("UDP port test", options.host, "A host and non-zero port are required"));
  }
  if (cancel.is_cancelled()) {
    return Result<UdpPortTestResult>::failure(
        network_error("UDP port test", options.host, "Operation cancelled"));
  }
  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<UdpPortTestResult>::failure(
        network_error("initialize sockets", options.host,
                      "Socket runtime initialization failed", runtime.error_code()));
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_CANONNAME;
  addrinfo* raw_results = nullptr;
  const std::string service = std::to_string(options.port);
  report(progress, "Resolving", options.host);
  const int resolve_result = getaddrinfo(options.host.c_str(), service.c_str(), &hints, &raw_results);
  if (resolve_result != 0) {
    return Result<UdpPortTestResult>::failure(
        network_error("resolve host", options.host,
                      address_info_error_text(resolve_result), resolve_result));
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> results(raw_results, freeaddrinfo);

  UdpPortTestResult output;
  output.host = options.host;
  output.port = options.port;
  output.dns_lookup_required = !numeric_ip_address(options.host);
  if (results.get() != nullptr && results.get()->ai_canonname != nullptr)
    output.canonical_name = results.get()->ai_canonname;
  std::set<std::string> unique_addresses;
  const int source_family = numeric_ip_family(options.source_address);
  for (addrinfo* current = results.get(); current != nullptr; current = current->ai_next) {
    if (cancel.is_cancelled()) {
      return Result<UdpPortTestResult>::failure(
          network_error("UDP port test", options.host, "Operation cancelled"));
    }
    UdpEndpointAttempt attempt;
    attempt.address = endpoint_text(current->ai_addr,
                                    static_cast<SocketLength>(current->ai_addrlen));
    attempt.address_family = address_family_name(current->ai_family);
    attempt.source_address = options.source_address;
    attempt.source_interface = options.source_interface;
    if (unique_addresses.insert(attempt.address).second)
      output.resolved_addresses.push_back(attempt.address);
    if (source_family != AF_UNSPEC && current->ai_family != source_family)
      continue;

    SocketOwner socket(::socket(current->ai_family, current->ai_socktype, current->ai_protocol));
    if (!socket.valid()) {
      attempt.native_code = last_socket_error();
      attempt.message = "socket() failed";
      output.attempts.push_back(std::move(attempt));
      continue;
    }
    if (!options.source_address.empty()) {
      auto bound = bind_source_address(socket.get(), current->ai_family, options.source_address);
      if (!bound.ok()) {
        attempt.native_code = bound.error().native_code;
        attempt.message = bound.error().message;
        output.attempts.push_back(std::move(attempt));
        continue;
      }
    }
    if (auto status = set_nonblocking(socket.get()); !status.ok()) {
      attempt.native_code = status.error().native_code;
      attempt.message = status.error().message;
      output.attempts.push_back(std::move(attempt));
      continue;
    }

    std::string payload;
    if (options.mode == UdpProbeMode::sat_listener) {
      attempt.sat_test_id = make_uuid_v4();
      payload = "SAT-UDP/1 TEST " + attempt.sat_test_id + "\n";
    } else {
      payload.assign(1, '?');
    }

    const auto started = std::chrono::steady_clock::now();
    report(progress, "Sending UDP", attempt.address,
           static_cast<std::uint64_t>(output.attempts.size()));
    bool sent = false;
    while (!cancel.is_cancelled() &&
           std::chrono::steady_clock::now() - started < options.timeout) {
#ifdef _WIN32
      const int written = sendto(socket.get(), payload.data(), static_cast<int>(payload.size()), 0,
                                 current->ai_addr,
                                 static_cast<SocketLength>(current->ai_addrlen));
#else
      const ssize_t written = sendto(socket.get(), payload.data(), payload.size(), 0,
                                     current->ai_addr,
                                     static_cast<SocketLength>(current->ai_addrlen));
#endif
      if (written >= 0 && static_cast<std::size_t>(written) == payload.size()) {
        sent = true;
        break;
      }
      if (written >= 0) {
        attempt.message = "UDP datagram was only partially sent";
        break;
      }
      const int code = last_socket_error();
      if (!would_block(code)) {
        attempt.native_code = code;
        attempt.message = socket_error_text(code);
        break;
      }
      const int ready = select_socket(socket.get(), false, std::chrono::milliseconds(50));
      if (ready < 0) {
        attempt.native_code = last_socket_error();
        attempt.message = "select() failed while sending UDP datagram";
        break;
      }
    }
    attempt.datagram_sent = sent;
    attempt.local_address = socket_local_address(socket.get());
    if (!sent) {
      if (attempt.message.empty())
        attempt.message = cancel.is_cancelled() ? "Operation cancelled" : "UDP send timed out";
      attempt.elapsed_ms = std::chrono::duration<double, std::milli>(
                               std::chrono::steady_clock::now() - started)
                               .count();
      output.attempts.push_back(std::move(attempt));
      continue;
    }

    if (options.mode == UdpProbeMode::generic_datagram) {
      attempt.message = "Datagram sent; UDP reachability is indeterminate without an application acknowledgement";
      attempt.elapsed_ms = std::chrono::duration<double, std::milli>(
                               std::chrono::steady_clock::now() - started)
                               .count();
      output.attempts.push_back(std::move(attempt));
      continue;
    }

    const auto deadline = started + options.timeout;
    std::array<char, 512> receive_buffer{};
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < deadline) {
      const int ready = select_socket(socket.get(), true, std::chrono::milliseconds(100));
      if (ready < 0) {
#ifndef _WIN32
        if (last_socket_error() == EINTR)
          continue;
#endif
        attempt.native_code = last_socket_error();
        attempt.message = "select() failed while waiting for UDP acknowledgement";
        break;
      }
      if (ready == 0)
        continue;
      sockaddr_storage remote{};
      SocketLength remote_length = static_cast<SocketLength>(sizeof(remote));
#ifdef _WIN32
      const int received = recvfrom(socket.get(), receive_buffer.data(),
                                    static_cast<int>(receive_buffer.size()), 0,
                                    reinterpret_cast<sockaddr*>(&remote), &remote_length);
#else
      const ssize_t received = recvfrom(socket.get(), receive_buffer.data(), receive_buffer.size(), 0,
                                        reinterpret_cast<sockaddr*>(&remote), &remote_length);
#endif
      if (received > 0) {
        attempt.response_received = true;
        std::string response(receive_buffer.data(), static_cast<std::size_t>(received));
        response = trim(response);
        const std::string expected = "SAT-UDP/1 ACK " + attempt.sat_test_id;
        if (response == expected) {
          attempt.sat_acknowledged = true;
          attempt.message = "SAT UDP listener acknowledged the probe";
        } else {
          attempt.message = "UDP response received, but it was not the expected SAT acknowledgement";
        }
        break;
      }
      if (received < 0) {
        const int code = last_socket_error();
        if (would_block(code))
          continue;
        attempt.native_code = code;
        attempt.message = socket_error_text(code);
        break;
      }
    }
    if (attempt.message.empty())
      attempt.message = "No SAT UDP acknowledgement was received before timeout";
    attempt.elapsed_ms = std::chrono::duration<double, std::milli>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    output.attempts.push_back(std::move(attempt));
  }
  if (output.dns_lookup_required && options.describe_name_source && !cancel.is_cancelled())
    output.name_source = describe_name_source(options.host, output.resolved_addresses);
  return Result<UdpPortTestResult>::success(std::move(output));
}

Result<UdpListenerResult> listen_udp(const UdpListenerOptions& options,
                                     const CancellationToken& cancel,
                                     ProgressCallback progress,
                                     UdpListenerEventCallback event_callback) {
  if (options.port == 0) {
    return Result<UdpListenerResult>::failure(
        network_error("UDP listener", {}, "A non-zero port is required"));
  }
  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<UdpListenerResult>::failure(
        network_error("initialize sockets", {},
                      "Socket runtime initialization failed", runtime.error_code()));
  }

  std::vector<SocketOwner> listeners;
  const auto add_listener = [&](int family) -> Status {
    SocketOwner socket(::socket(family, SOCK_DGRAM, IPPROTO_UDP));
    if (!socket.valid())
      return Status::failure(network_error("create UDP listener", std::to_string(options.port),
                                           "socket() failed", last_socket_error()));
    claim_listener_port(socket.get());
    if (family == AF_INET6) {
      int v6_only = 1;
      static_cast<void>(setsockopt(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                                   reinterpret_cast<const char*>(&v6_only),
                                   static_cast<SocketLength>(sizeof(v6_only))));
      sockaddr_in6 local{};
      local.sin6_family = AF_INET6;
      local.sin6_addr = in6addr_any;
      local.sin6_port = htons(options.port);
      if (bind(socket.get(), reinterpret_cast<const sockaddr*>(&local),
               static_cast<SocketLength>(sizeof(local))) != 0) {
        return Status::failure(network_error("bind UDP listener", std::to_string(options.port),
                                             "IPv6 bind() failed", last_socket_error()));
      }
    } else {
      sockaddr_in local{};
      local.sin_family = AF_INET;
      local.sin_addr.s_addr = htonl(INADDR_ANY);
      local.sin_port = htons(options.port);
      if (bind(socket.get(), reinterpret_cast<const sockaddr*>(&local),
               static_cast<SocketLength>(sizeof(local))) != 0) {
        return Status::failure(network_error("bind UDP listener", std::to_string(options.port),
                                             "IPv4 bind() failed", last_socket_error()));
      }
    }
    if (auto nonblocking = set_nonblocking(socket.get()); !nonblocking.ok())
      return nonblocking;
    listeners.push_back(std::move(socket));
    return Status::success();
  };

  auto ipv4 = add_listener(AF_INET);
  auto ipv6 = add_listener(AF_INET6);
  if (!ipv4.ok() && !ipv6.ok())
    return Result<UdpListenerResult>::failure(ipv4.error());

  UdpListenerResult output;
  output.port = options.port;
  const auto deadline = std::chrono::steady_clock::now() + options.duration;
  report(progress, "Listening UDP", "* :" + std::to_string(options.port));

  while (std::chrono::steady_clock::now() < deadline) {
    if (cancel.is_cancelled()) {
      output.cancelled = true;
      break;
    }
    fd_set read_set;
    FD_ZERO(&read_set);
#ifndef _WIN32
    SocketHandle max_socket = 0;
#endif
    for (const auto& listener : listeners) {
      FD_SET(listener.get(), &read_set);
#ifndef _WIN32
      max_socket = std::max(max_socket, listener.get());
#endif
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;
#ifdef _WIN32
    const int selected = select(0, &read_set, nullptr, nullptr, &timeout);
#else
    const int selected = select(max_socket + 1, &read_set, nullptr, nullptr, &timeout);
#endif
    if (selected < 0) {
#ifndef _WIN32
      if (errno == EINTR) {
        if (cancel.is_cancelled()) {
          output.cancelled = true;
          break;
        }
        continue;
      }
#endif
      return Result<UdpListenerResult>::failure(
          network_error("wait for UDP datagram", std::to_string(options.port),
                        "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;

    for (auto& listener : listeners) {
      if (!FD_ISSET(listener.get(), &read_set))
        continue;
      std::array<char, 2048> buffer{};
      sockaddr_storage remote{};
      SocketLength remote_length = static_cast<SocketLength>(sizeof(remote));
#ifdef _WIN32
      const int received = recvfrom(listener.get(), buffer.data(), static_cast<int>(buffer.size()), 0,
                                    reinterpret_cast<sockaddr*>(&remote), &remote_length);
#else
      const ssize_t received = recvfrom(listener.get(), buffer.data(), buffer.size(), 0,
                                        reinterpret_cast<sockaddr*>(&remote), &remote_length);
#endif
      if (received < 0)
        continue;
      UdpReceivedDatagram datagram;
      datagram.remote_address = endpoint_text(reinterpret_cast<const sockaddr*>(&remote),
                                              remote_length, &datagram.remote_port);
      datagram.local_address = socket_local_address(listener.get());
      datagram.local_port = options.port;
      datagram.received_utc = utc_now_iso8601();
      datagram.bytes = static_cast<std::uint64_t>(received);

      if (options.enable_sat_protocol && received > 0) {
        std::string text(buffer.data(), static_cast<std::size_t>(received));
        text = trim(text);
        std::istringstream input(text);
        std::string protocol;
        std::string action;
        std::string test_id;
        std::string trailing;
        if ((input >> protocol >> action >> test_id) && !(input >> trailing) &&
            protocol == "SAT-UDP/1" && action == "TEST" && !test_id.empty()) {
          datagram.sat_probe = true;
          datagram.sat_test_id = test_id;
          const std::string ack = "SAT-UDP/1 ACK " + test_id + "\n";
#ifdef _WIN32
          const int sent = sendto(listener.get(), ack.data(), static_cast<int>(ack.size()), 0,
                                  reinterpret_cast<const sockaddr*>(&remote), remote_length);
#else
          const ssize_t sent = sendto(listener.get(), ack.data(), ack.size(), 0,
                                      reinterpret_cast<const sockaddr*>(&remote), remote_length);
#endif
          datagram.sat_ack_sent = sent >= 0 && static_cast<std::size_t>(sent) == ack.size();
        }
      }
      output.datagrams.push_back(std::move(datagram));
      if (event_callback)
        event_callback(output.datagrams.back());
      report(progress,
             output.datagrams.back().sat_probe ? "SAT UDP probe" : "UDP datagram",
             output.datagrams.back().remote_address,
             static_cast<std::uint64_t>(output.datagrams.size()));
      if (!options.accept_multiple)
        break;
    }
    if (!options.accept_multiple && !output.datagrams.empty())
      break;
  }
  output.timed_out = !output.cancelled && output.datagrams.empty() &&
                     std::chrono::steady_clock::now() >= deadline;
  return Result<UdpListenerResult>::success(std::move(output));
}

Result<std::vector<InterfaceUdpTestResult>> test_udp_across_interfaces(
    const UdpPortTestOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress,
    bool include_virtual_or_special) {
  auto interfaces = enumerate_network_interfaces();
  if (!interfaces.ok())
    return Result<std::vector<InterfaceUdpTestResult>>::failure(interfaces.error());
  std::vector<InterfaceUdpTestResult> output;
  for (const auto& interface : interfaces.value()) {
    if (cancel.is_cancelled()) {
      return Result<std::vector<InterfaceUdpTestResult>>::failure(
          network_error("UDP interface matrix", options.host, "Operation cancelled"));
    }
    if (!interface.up || interface.loopback || interface.address.empty())
      continue;
    if (!include_virtual_or_special && !interface.diagnostic_default)
      continue;
    UdpPortTestOptions one = options;
    one.source_address = interface.address;
    one.source_interface = interface.name;
    one.describe_name_source = options.describe_name_source && output.empty();
    report(progress, "Testing UDP interface", interface.name + " " + interface.address,
           static_cast<std::uint64_t>(output.size()));
    auto tested = test_udp_port(one, cancel, progress);
    if (!tested.ok()) {
      UdpPortTestResult failed;
      failed.host = options.host;
      failed.port = options.port;
      UdpEndpointAttempt attempt;
      attempt.source_address = interface.address;
      attempt.source_interface = interface.name;
      attempt.address_family = interface.address_family;
      attempt.message = tested.error().message;
      attempt.native_code = tested.error().native_code;
      failed.attempts.push_back(std::move(attempt));
      output.push_back(InterfaceUdpTestResult{interface, std::move(failed)});
      continue;
    }
    output.push_back(InterfaceUdpTestResult{interface, std::move(tested.value())});
  }
  return Result<std::vector<InterfaceUdpTestResult>>::success(std::move(output));
}

Result<std::uint64_t> parse_transfer_size(std::string_view value) {
  std::string text(value);
  text.erase(text.begin(), std::find_if(text.begin(), text.end(), [](unsigned char c) {
               return std::isspace(c) == 0;
             }));
  text.erase(std::find_if(text.rbegin(), text.rend(), [](unsigned char c) {
               return std::isspace(c) == 0;
             }).base(),
             text.end());
  if (text.empty()) {
    return Result<std::uint64_t>::failure(
        network_error("parse transfer size", {}, "A transfer size is required"));
  }
  std::size_t numeric_end = 0;
  while (numeric_end < text.size() && std::isdigit(static_cast<unsigned char>(text[numeric_end])))
    ++numeric_end;
  if (numeric_end == 0) {
    return Result<std::uint64_t>::failure(
        network_error("parse transfer size", text, "Transfer size must begin with an integer"));
  }
  std::uint64_t number = 0;
  const auto [position, error] =
      std::from_chars(text.data(), text.data() + numeric_end, number);
  if (error != std::errc{} || position != text.data() + numeric_end) {
    return Result<std::uint64_t>::failure(
        network_error("parse transfer size", text, "Invalid transfer size"));
  }
  std::string suffix = text.substr(numeric_end);
  suffix.erase(suffix.begin(), std::find_if(suffix.begin(), suffix.end(), [](unsigned char c) {
                 return std::isspace(c) == 0;
               }));
  std::transform(suffix.begin(), suffix.end(), suffix.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  std::uint64_t multiplier = 1;
  if (suffix.empty() || suffix == "B") {
    multiplier = 1;
  } else if (suffix == "K" || suffix == "KB" || suffix == "KIB") {
    multiplier = 1024ULL;
  } else if (suffix == "M" || suffix == "MB" || suffix == "MIB") {
    multiplier = 1024ULL * 1024ULL;
  } else if (suffix == "G" || suffix == "GB" || suffix == "GIB") {
    multiplier = 1024ULL * 1024ULL * 1024ULL;
  } else if (suffix == "T" || suffix == "TB" || suffix == "TIB") {
    multiplier = 1024ULL * 1024ULL * 1024ULL * 1024ULL;
  } else {
    return Result<std::uint64_t>::failure(network_error(
        "parse transfer size", text, "Supported suffixes are B, K, M, G, T, KB, MB, GB, TB or KiB/MiB/GiB/TiB"));
  }
  if (number > std::numeric_limits<std::uint64_t>::max() / multiplier) {
    return Result<std::uint64_t>::failure(
        network_error("parse transfer size", text, "Transfer size is too large"));
  }
  return Result<std::uint64_t>::success(number * multiplier);
}

std::string format_transfer_rate(double bits_per_second) {
  const std::array<std::string_view, 4> units{"bit/s", "Kbit/s", "Mbit/s", "Gbit/s"};
  std::size_t unit = 0;
  double value = std::max(0.0, bits_per_second);
  while (value >= 1000.0 && unit + 1U < units.size()) {
    value /= 1000.0;
    ++unit;
  }
  std::ostringstream output;
  output << std::fixed << std::setprecision(value >= 100.0 ? 1 : 2) << value << ' ' << units[unit];
  return output.str();
}

Result<TcpPortTestResult> test_tcp_port(const TcpPortTestOptions& options,
                                        const CancellationToken& cancel,
                                        ProgressCallback progress) {
  if (options.host.empty() || options.port == 0) {
    return Result<TcpPortTestResult>::failure(
        network_error("TCP port test", options.host, "A host and non-zero port are required"));
  }
  if (cancel.is_cancelled()) {
    return Result<TcpPortTestResult>::failure(
        network_error("TCP port test", options.host, "Operation cancelled"));
  }
  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<TcpPortTestResult>::failure(network_error("initialize sockets",
                                                            options.host,
                                                            "Socket runtime initialization failed",
                                                            runtime.error_code()));
  }

  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  hints.ai_flags = AI_CANONNAME;
  addrinfo* raw_results = nullptr;
  const std::string service = std::to_string(options.port);
  report(progress, "Resolving", options.host);
  const int resolve_result =
      getaddrinfo(options.host.c_str(), service.c_str(), &hints, &raw_results);
  if (resolve_result != 0) {
    return Result<TcpPortTestResult>::failure(
        network_error("resolve host", options.host, address_info_error_text(resolve_result), resolve_result));
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> results(raw_results, freeaddrinfo);
  if (cancel.is_cancelled()) {
    return Result<TcpPortTestResult>::failure(
        network_error("TCP port test", options.host, "Operation cancelled"));
  }

  TcpPortTestResult output;
  output.host = options.host;
  output.port = options.port;
  output.dns_lookup_required = !numeric_ip_address(options.host);
  if (results.get() != nullptr && results.get()->ai_canonname != nullptr)
    output.canonical_name = results.get()->ai_canonname;
  std::set<std::string> unique_addresses;
  const int source_family = numeric_ip_family(options.source_address);
  const auto overall_start = std::chrono::steady_clock::now();
  bool connected_ipv4 = false;
  bool connected_ipv6 = false;
  TcpPortTestOptions without_payload = options;
  without_payload.sat_payload_bytes = 0;

  for (addrinfo* current = results.get(); current != nullptr; current = current->ai_next) {
    if (cancel.is_cancelled()) {
      return Result<TcpPortTestResult>::failure(
          network_error("TCP port test", options.host, "Operation cancelled"));
    }
    const std::string address =
        endpoint_text(current->ai_addr, static_cast<SocketLength>(current->ai_addrlen));
    if (unique_addresses.insert(address).second)
      output.resolved_addresses.push_back(address);
    if (source_family != AF_UNSPEC && current->ai_family != source_family)
      continue;
    const bool ipv6 = current->ai_family == AF_INET6;
    if (ipv6 ? connected_ipv6 : connected_ipv4)
      continue; // this family already connected

    TcpEndpointAttempt attempt;
    attempt.address = address;
    attempt.address_family = address_family_name(current->ai_family);
    attempt.source_address = options.source_address;
    attempt.source_interface = options.source_interface;
    const auto attempt_start = std::chrono::steady_clock::now();
    report(progress, "Connecting", address, static_cast<std::uint64_t>(output.attempts.size()));

    SocketOwner socket(::socket(current->ai_family, current->ai_socktype, current->ai_protocol));
    if (!socket.valid()) {
      attempt.native_code = last_socket_error();
      attempt.message = "socket() failed";
      output.attempts.push_back(std::move(attempt));
      continue;
    }
    if (!options.source_address.empty()) {
      auto bound = bind_source_address(socket.get(), current->ai_family, options.source_address);
      if (!bound.ok()) {
        attempt.native_code = bound.error().native_code;
        attempt.message = bound.error().message;
        output.attempts.push_back(std::move(attempt));
        continue;
      }
    }
    if (auto status = set_nonblocking(socket.get()); !status.ok()) {
      attempt.native_code = status.error().native_code;
      attempt.message = status.error().message;
      output.attempts.push_back(std::move(attempt));
      continue;
    }

    const int connect_result =
        connect(socket.get(), current->ai_addr, static_cast<SocketLength>(current->ai_addrlen));
    bool connected = connect_result == 0;
    int socket_error = connected ? 0 : last_socket_error();
    if (!connected && would_block(socket_error)) {
      // Poll in short slices rather than blocking in select() for the entire
      // requested timeout. This makes immediate GUI cancellation deterministic
      // and keeps the socket owned by this stack frame until the operation has
      // fully unwound.
      const auto deadline = std::chrono::steady_clock::now() + options.timeout;
      bool wait_complete = false;
      while (!wait_complete) {
        if (cancel.is_cancelled()) {
          return Result<TcpPortTestResult>::failure(
              network_error("TCP port test", options.host, "Operation cancelled"));
        }
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
#ifdef _WIN32
          socket_error = WSAETIMEDOUT;
#else
          socket_error = ETIMEDOUT;
#endif
          break;
        }
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        const auto slice = std::min<std::chrono::milliseconds>(remaining,
                                                               std::chrono::milliseconds(100));
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(socket.get(), &write_set);
        const auto slice_count = slice.count();
        timeval timeout{};
        timeout.tv_sec = static_cast<long>(slice_count / 1000);
        timeout.tv_usec = static_cast<long>((slice_count % 1000) * 1000);
#ifdef _WIN32
        // A refused connect shows in the except set only; watching the write set alone turned every
        // refusal into a timeout.
        fd_set except_set;
        FD_ZERO(&except_set);
        FD_SET(socket.get(), &except_set);
        const int selected = select(0, nullptr, &write_set, &except_set, &timeout);
        const bool signalled = selected > 0 && (FD_ISSET(socket.get(), &write_set) ||
                                                FD_ISSET(socket.get(), &except_set));
#else
        const int selected = select(socket.get() + 1, nullptr, &write_set, nullptr, &timeout);
        const bool signalled = selected > 0 && FD_ISSET(socket.get(), &write_set);
#endif
        if (selected == 0)
          continue;
        wait_complete = true;
        if (signalled) {
          int pending_error = 0;
          SocketLength pending_length = static_cast<SocketLength>(sizeof(pending_error));
          if (getsockopt(socket.get(),
                         SOL_SOCKET,
                         SO_ERROR,
                         reinterpret_cast<char*>(&pending_error),
                         &pending_length) == 0) {
            connected = pending_error == 0;
            socket_error = pending_error;
          } else {
            socket_error = last_socket_error();
          }
        } else {
          socket_error = last_socket_error();
        }
      }
    }

    const auto attempt_end = std::chrono::steady_clock::now();
    attempt.elapsed_ms =
        std::chrono::duration<double, std::milli>(attempt_end - attempt_start).count();
    attempt.connected = connected;
    attempt.native_code = socket_error;
    attempt.message = socket_error_text(socket_error);
    if (connected)
      attempt.local_address = socket_local_address(socket.get());
    if (connected && options.detect_sat_listener) {
      auto sat_probe = run_sat_connectivity_probe(
          socket.get(), output.connected ? without_payload : options, attempt, cancel, progress, address);
      if (!sat_probe.ok()) {
        attempt.message += "; SAT validation: " + sat_probe.error().message;
      } else if (attempt.sat_listener_detected && attempt.sat_payload_validated) {
        attempt.message += "; SAT handshake and payload verified";
      } else if (attempt.sat_listener_detected && attempt.sat_handshake_completed) {
        attempt.message += "; SAT handshake verified";
      }
    }
    output.attempts.push_back(attempt);
    if (connected) {
      if (!output.connected) {
        output.connected = true;
        output.connected_address = address;
        output.elapsed_ms = attempt.elapsed_ms;
      }
      (ipv6 ? connected_ipv6 : connected_ipv4) = true;
      if (!options.both_families)
        break;
    }
  }
  if (output.dns_lookup_required && options.describe_name_source && !cancel.is_cancelled())
    output.name_source = describe_name_source(options.host, output.resolved_addresses);

  if (!output.connected) {
    output.elapsed_ms =
        std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - overall_start)
            .count();
  }
  report(progress,
         output.connected ? "Connected" : "Failed",
         output.connected ? output.connected_address : options.host,
         static_cast<std::uint64_t>(output.attempts.size()));
  return Result<TcpPortTestResult>::success(std::move(output));
}

std::string expand_listener_banner(std::string_view banner, std::uint16_t port) {
  static constexpr std::string_view token = "%port%";
  const std::string value = std::to_string(port);
  std::string text(banner);
  for (std::size_t at = text.find(token); at != std::string::npos;
       at = text.find(token, at + value.size()))
    text.replace(at, token.size(), value);
  return text;
}

Result<TcpListenerResult> listen_tcp(const TcpListenerOptions& options,
                                     const CancellationToken& cancel,
                                     ProgressCallback progress,
                                     TcpListenerEventCallback event_callback) {
  if (options.port == 0) {
    return Result<TcpListenerResult>::failure(
        network_error("TCP listener", {}, "A non-zero port is required"));
  }
  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<TcpListenerResult>::failure(network_error(
        "initialize sockets", {}, "Socket runtime initialization failed", runtime.error_code()));
  }

  // One socket per address family, as the UDP listener has: IPv4 on every address, and IPv6 on every
  // address where the system offers IPv6. IPv4 must bind, so a port another program holds refuses the
  // listener outright; IPv6 is added when it binds and skipped when the system has no IPv6.
  std::vector<SocketOwner> listeners;
  for (const int family : {AF_INET, AF_INET6}) {
    const bool ipv6 = family == AF_INET6;
    SocketOwner socket(::socket(family, SOCK_STREAM, IPPROTO_TCP));
    if (!socket.valid()) {
      if (ipv6)
        continue;
      return Result<TcpListenerResult>::failure(network_error(
          "create listener", std::to_string(options.port), "socket() failed", last_socket_error()));
    }
    claim_listener_port(socket.get());
    int bound = -1;
    if (ipv6) {
      int v6_only = 1;
      static_cast<void>(setsockopt(socket.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                                   reinterpret_cast<const char*>(&v6_only),
                                   static_cast<SocketLength>(sizeof(v6_only))));
      sockaddr_in6 local{};
      local.sin6_family = AF_INET6;
      local.sin6_addr = in6addr_any;
      local.sin6_port = htons(options.port);
      bound = bind(socket.get(), reinterpret_cast<const sockaddr*>(&local),
                   static_cast<SocketLength>(sizeof(local)));
    } else {
      sockaddr_in local{};
      local.sin_family = AF_INET;
      local.sin_addr.s_addr = htonl(INADDR_ANY);
      local.sin_port = htons(options.port);
      bound = bind(socket.get(), reinterpret_cast<const sockaddr*>(&local),
                   static_cast<SocketLength>(sizeof(local)));
    }
    if (bound != 0) {
      if (ipv6)
        continue;
      return Result<TcpListenerResult>::failure(network_error(
          "bind listener", std::to_string(options.port), "bind() failed", last_socket_error()));
    }
    if (listen(socket.get(), SOMAXCONN) != 0) {
      if (ipv6)
        continue;
      return Result<TcpListenerResult>::failure(network_error(
          "listen", std::to_string(options.port), "listen() failed", last_socket_error()));
    }
    listeners.push_back(std::move(socket));
  }

  TcpListenerResult output;
  output.port = options.port;
  const auto deadline = std::chrono::steady_clock::now() + options.duration;
  report(progress, "Listening",
         std::string(listeners.size() > 1 ? "all IPv4 and IPv6 addresses" : "all IPv4 addresses") +
             ", port " + std::to_string(options.port));

  while (std::chrono::steady_clock::now() < deadline) {
    if (cancel.is_cancelled()) {
      output.cancelled = true;
      break;
    }
    fd_set read_set;
    FD_ZERO(&read_set);
#ifndef _WIN32
    int highest = 0;
#endif
    for (const auto& listener : listeners) {
      FD_SET(listener.get(), &read_set);
#ifndef _WIN32
      highest = std::max(highest, static_cast<int>(listener.get()));
#endif
    }
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = 200000;
#ifdef _WIN32
    const int selected = select(0, &read_set, nullptr, nullptr, &timeout);
#else
    const int selected = select(highest + 1, &read_set, nullptr, nullptr, &timeout);
#endif
    if (selected < 0) {
#ifndef _WIN32
      if (errno == EINTR) {
        if (cancel.is_cancelled()) {
          output.cancelled = true;
          break;
        }
        continue;
      }
#endif
      return Result<TcpListenerResult>::failure(network_error("wait for connection",
                                                              std::to_string(options.port),
                                                              "select() failed",
                                                              last_socket_error()));
    }
    if (selected == 0)
      continue;
    const SocketOwner* ready = nullptr;
    for (const auto& listener : listeners) {
      if (FD_ISSET(listener.get(), &read_set)) {
        ready = &listener;
        break;
      }
    }
    if (ready == nullptr)
      continue;

    sockaddr_storage remote{};
    SocketLength remote_length = static_cast<SocketLength>(sizeof(remote));
    SocketOwner accepted(
        accept(ready->get(), reinterpret_cast<sockaddr*>(&remote), &remote_length));
    if (!accepted.valid())
      continue;

    TcpAcceptedConnection connection;
    connection.remote_address = endpoint_text(
        reinterpret_cast<const sockaddr*>(&remote), remote_length, &connection.remote_port);
    sockaddr_storage local_endpoint{};
    SocketLength local_length = static_cast<SocketLength>(sizeof(local_endpoint));
    if (getsockname(accepted.get(), reinterpret_cast<sockaddr*>(&local_endpoint), &local_length) == 0) {
      connection.local_address = endpoint_text(
          reinterpret_cast<const sockaddr*>(&local_endpoint), local_length, &connection.local_port);
    }
    connection.accepted_utc = utc_now_iso8601();
    if (event_callback)
      event_callback(TcpListenerEventKind::accepted, connection);

    if (auto nonblocking = set_nonblocking(accepted.get()); nonblocking.ok()) {
      auto sat_service = service_sat_listener_connection(
          accepted.get(), options, connection, cancel, progress);
      if (!sat_service.ok() && cancel.is_cancelled()) {
        output.cancelled = true;
      }
    }

    const std::string banner = expand_listener_banner(options.banner, options.port);
    if (!banner.empty()) {
      std::string line = banner;
      if (line.back() != '\n')
        line.push_back('\n');
      const auto sent_banner = send_protocol_text(accepted.get(),
                                                  line,
                                                  std::chrono::seconds(1),
                                                  cancel,
                                                  "TCP listener banner",
                                                  connection.remote_address);
      connection.banner = banner;
      connection.banner_sent = sent_banner.ok();
    }

    if (event_callback)
      event_callback(TcpListenerEventKind::updated, connection);
    output.connections.push_back(connection);
    report(progress,
           connection.sat_probe ? "SAT probe accepted" : "Accepted",
           connection.remote_address,
           static_cast<std::uint64_t>(output.connections.size()));
    if (output.cancelled || !options.accept_multiple)
      break;
  }

  output.timed_out = !output.cancelled && output.connections.empty() &&
                     std::chrono::steady_clock::now() >= deadline;
  return Result<TcpListenerResult>::success(std::move(output));
}


Result<TlsProbeResult> test_tls_handshake(const TlsProbeOptions& options,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress) {
  if (options.host.empty() || options.port == 0) {
    return Result<TlsProbeResult>::failure(
        network_error("TLS handshake test", options.host, "A host and non-zero port are required"));
  }
  if (cancel.is_cancelled()) {
    return Result<TlsProbeResult>::failure(
        network_error("TLS handshake test", options.host, "Operation cancelled"));
  }

  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<TlsProbeResult>::failure(network_error(
        "initialize sockets", options.host, "Socket runtime initialization failed", runtime.error_code()));
  }

  TlsProbeResult output;
  output.host = options.host;
  output.port = options.port;
  output.source_address = options.source_address;
  output.source_interface = options.source_interface;
  output.requested_server_name = options.server_name.empty() ? options.host : options.server_name;
  add_offered_versions(options.version, output.offered_versions);

  report(progress, "TCP connect", options.host);
  const auto tcp_started = std::chrono::steady_clock::now();
  std::string connected_address;
  auto connected = connect_tcp_socket(options.host,
                                      options.port,
                                      options.timeout,
                                      cancel,
                                      progress,
                                      connected_address,
                                      options.source_address);
  output.tcp_elapsed_ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - tcp_started)
                              .count();
  if (!connected.ok())
    return Result<TlsProbeResult>::failure(connected.error());
  output.tcp_connected = true;
  output.connected_address = connected_address;
  output.local_address = socket_local_address(connected.value().get());

  SSL_CTX* raw_context = SSL_CTX_new(TLS_client_method());
  if (raw_context == nullptr) {
    return Result<TlsProbeResult>::failure(
        network_error("TLS handshake test", options.host, "SSL_CTX_new failed: " + openssl_error_text()));
  }
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(raw_context, SSL_CTX_free);
  configure_tls_version(context.get(), options.version);
  SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);

  HandshakeTrace trace;
  SSL_CTX_set_msg_callback(context.get(), tls_message_callback);
  SSL_CTX_set_msg_callback_arg(context.get(), &trace);

  SSL* raw_ssl = SSL_new(context.get());
  if (raw_ssl == nullptr) {
    return Result<TlsProbeResult>::failure(
        network_error("TLS handshake test", options.host, "SSL_new failed: " + openssl_error_text()));
  }
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);
  if (!output.requested_server_name.empty()) {
    static_cast<void>(SSL_set_tlsext_host_name(ssl.get(), output.requested_server_name.c_str()));
  }
  output.offered_cipher_suites = ssl_cipher_names(ssl.get());

  if (SSL_set_fd(ssl.get(), static_cast<int>(connected.value().get())) != 1) {
    return Result<TlsProbeResult>::failure(
        network_error("TLS handshake test", options.host, "SSL_set_fd failed: " + openssl_error_text()));
  }

  report(progress, "TLS handshake", output.connected_address);
  ERR_clear_error();
  const auto tls_started = std::chrono::steady_clock::now();
  const auto deadline = tls_started + options.timeout;
  int final_ssl_error = SSL_ERROR_NONE;
  while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < deadline) {
    const int result = SSL_connect(ssl.get());
    if (result == 1) {
      output.handshake_completed = true;
      break;
    }
    final_ssl_error = SSL_get_error(ssl.get(), result);
    if (final_ssl_error == SSL_ERROR_WANT_READ || final_ssl_error == SSL_ERROR_WANT_WRITE) {
      const bool want_read = final_ssl_error == SSL_ERROR_WANT_READ;
      const int selected = select_socket(connected.value().get(), want_read, std::chrono::milliseconds(100));
      if (selected < 0) {
#ifndef _WIN32
        if (last_socket_error() == EINTR)
          continue;
#endif
        output.failure_reason = "Socket wait failed: " + socket_error_text(last_socket_error());
        break;
      }
      continue;
    }
    output.failure_reason = openssl_error_text();
    if (output.failure_reason.empty())
      output.failure_reason = "TLS handshake failed with OpenSSL error " + std::to_string(final_ssl_error);
    break;
  }

  output.tls_elapsed_ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - tls_started)
                              .count();
  output.client_hello_observed = trace.client_hello;
  output.server_hello_observed = trace.server_hello;
  output.server_requested_client_certificate = trace.certificate_request;
  output.client_hello_bytes = trace.client_hello_bytes;
  output.server_hello_bytes = trace.server_hello_bytes;

  if (cancel.is_cancelled()) {
    output.failure_stage = "Cancelled";
    output.failure_reason = "Operation cancelled";
  } else if (!output.handshake_completed && output.failure_reason.empty()) {
    output.failure_reason = "TLS handshake timed out";
  }

  if (trace.client_hello && !trace.server_hello)
    output.failure_stage = "ServerHello negotiation";
  else if (trace.certificate_request && !output.handshake_completed)
    output.failure_stage = "Client certificate authentication";
  else if (trace.server_hello && !output.handshake_completed)
    output.failure_stage = "TLS handshake after ServerHello";
  else if (!output.handshake_completed && output.failure_stage.empty())
    output.failure_stage = "TLS initialization/negotiation";

  if (trace.server_hello) {
    const char* version = SSL_get_version(ssl.get());
    if (version != nullptr)
      output.negotiated_version = version;
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl.get());
    if (cipher != nullptr && SSL_CIPHER_get_name(cipher) != nullptr)
      output.negotiated_cipher_suite = SSL_CIPHER_get_name(cipher);
    output.negotiated_cipher_was_offered =
        !output.negotiated_cipher_suite.empty() &&
        std::find(output.offered_cipher_suites.begin(),
                  output.offered_cipher_suites.end(),
                  output.negotiated_cipher_suite) != output.offered_cipher_suites.end();
  }

  output.certificate = inspect_peer_certificate(ssl.get(), options);
  if (output.handshake_completed)
    report(progress, "TLS complete", output.negotiated_version + " / " + output.negotiated_cipher_suite);
  else
    report(progress, "TLS incomplete", output.failure_stage);

  return Result<TlsProbeResult>::success(std::move(output));
}

Result<std::vector<InterfaceTlsTestResult>> test_tls_across_interfaces(
    const TlsProbeOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress,
    bool include_virtual_or_special) {
  auto interfaces = enumerate_network_interfaces();
  if (!interfaces.ok())
    return Result<std::vector<InterfaceTlsTestResult>>::failure(interfaces.error());

  std::vector<InterfaceTlsTestResult> output;
  for (const auto& interface : interfaces.value()) {
    if (cancel.is_cancelled()) {
      return Result<std::vector<InterfaceTlsTestResult>>::failure(
          network_error("TLS interface matrix", options.host, "Operation cancelled"));
    }
    if (!interface.up || interface.loopback || interface.address.empty())
      continue;
    if (!include_virtual_or_special && !interface.diagnostic_default)
      continue;

    TlsProbeOptions one = options;
    one.source_address = interface.address;
    one.source_interface = interface.name;
    report(progress, "Testing TLS interface", interface.name + " " + interface.address,
           static_cast<std::uint64_t>(output.size()));
    auto tested = test_tls_handshake(one, cancel, progress);
    if (!tested.ok()) {
      TlsProbeResult failed;
      failed.host = options.host;
      failed.port = options.port;
      failed.source_address = interface.address;
      failed.source_interface = interface.name;
      failed.requested_server_name = options.server_name.empty() ? options.host : options.server_name;
      failed.failure_stage = "TCP/TLS connection";
      failed.failure_reason = tested.error().message;
      output.push_back(InterfaceTlsTestResult{interface, std::move(failed)});
      continue;
    }
    output.push_back(InterfaceTlsTestResult{interface, std::move(tested.value())});
  }
  return Result<std::vector<InterfaceTlsTestResult>>::success(std::move(output));
}

Result<TcpThroughputResult> run_tcp_throughput(const TcpThroughputOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress) {
  if (options.port == 0) {
    return Result<TcpThroughputResult>::failure(
        network_error("TCP throughput", {}, "A non-zero port is required"));
  }
  if (!options.server && options.host.empty()) {
    return Result<TcpThroughputResult>::failure(
        network_error("TCP throughput client", {}, "A server address is required"));
  }
  if (!options.server && options.transfer_bytes == 0) {
    return Result<TcpThroughputResult>::failure(
        network_error("TCP throughput client", options.host, "Transfer size must be greater than zero"));
  }
  if (options.buffer_bytes < 4096U || options.buffer_bytes > 4U * 1024U * 1024U) {
    return Result<TcpThroughputResult>::failure(network_error(
        "TCP throughput", {}, "Buffer size must be between 4 KiB and 4 MiB"));
  }

  SocketRuntime runtime;
  if (!runtime.ok()) {
    return Result<TcpThroughputResult>::failure(network_error(
        "initialize sockets", {}, "Socket runtime initialization failed", runtime.error_code()));
  }

  TcpThroughputResult output;
  output.server = options.server;
  output.port = options.port;
  std::vector<char> buffer(options.buffer_bytes);
  for (std::size_t index = 0; index < buffer.size(); ++index)
    buffer[index] = static_cast<char>(index & 0xFFU);

  if (!options.server) {
    std::string address;
    auto connected = connect_tcp_socket(options.host,
                                        options.port,
                                        options.connect_timeout,
                                        cancel,
                                        progress,
                                        address);
    if (!connected.ok())
      return Result<TcpThroughputResult>::failure(connected.error());
    SocketOwner socket = std::move(connected.value());
    output.peer_address = address;
    output.direction = "send";
    const std::string request =
        "SAT-THROUGHPUT/1 SEND " + std::to_string(options.transfer_bytes) + "\n";
    auto sent_handshake = send_control_text(
        socket.get(), request, options.connect_timeout, cancel, output.peer_address);
    if (!sent_handshake.ok())
      return Result<TcpThroughputResult>::failure(sent_handshake.error());
    auto ack_line = receive_control_line(
        socket.get(), options.connect_timeout, cancel, output.peer_address);
    if (!ack_line.ok())
      return Result<TcpThroughputResult>::failure(ack_line.error());
    auto acknowledged = parse_throughput_ack(ack_line.value());
    if (!acknowledged.ok())
      return Result<TcpThroughputResult>::failure(acknowledged.error());
    if (acknowledged.value() != options.transfer_bytes)
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput client", output.peer_address,
          "Peer acknowledged a different transfer size than requested"));
    output.protocol_verified = true;
    const auto started = std::chrono::steady_clock::now();
    auto last_activity = started;
    while (output.transferred_bytes < options.transfer_bytes) {
      if (cancel.is_cancelled()) {
        output.cancelled = true;
        break;
      }
      if (std::chrono::steady_clock::now() - last_activity >= options.idle_timeout) {
        return Result<TcpThroughputResult>::failure(
            network_error("TCP throughput client", address, "Transfer timed out with no progress"));
      }
      const int selected = select_socket(socket.get(), false, std::chrono::milliseconds(100));
      if (selected < 0) {
        return Result<TcpThroughputResult>::failure(network_error(
            "TCP throughput client", address, "select() failed", last_socket_error()));
      }
      if (selected == 0)
        continue;
      const std::uint64_t remaining = options.transfer_bytes - output.transferred_bytes;
      const std::size_t count = static_cast<std::size_t>(
          std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size())));
#ifdef _WIN32
      const int sent = send(socket.get(), buffer.data(), static_cast<int>(count), 0);
#else
      const ssize_t sent = send(socket.get(), buffer.data(), count, kSendFlags);
#endif
      if (sent > 0) {
        output.transferred_bytes += static_cast<std::uint64_t>(sent);
        last_activity = std::chrono::steady_clock::now();
        report(progress, "Sending", address, output.transferred_bytes);
        continue;
      }
      if (sent == 0)
        break;
      const int error_code = last_socket_error();
      if (!would_block(error_code)) {
        return Result<TcpThroughputResult>::failure(
            network_error("TCP throughput client", address, "send() failed", error_code));
      }
    }
#ifdef _WIN32
    static_cast<void>(shutdown(socket.get(), SD_SEND));
#else
    static_cast<void>(shutdown(socket.get(), SHUT_WR));
#endif
    output.elapsed_seconds =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    output.bits_per_second = rate_for(output.transferred_bytes, output.elapsed_seconds);
    return Result<TcpThroughputResult>::success(std::move(output));
  }

  int listener_family = AF_INET6;
  SocketOwner listener(::socket(listener_family, SOCK_STREAM, IPPROTO_TCP));
  if (!listener.valid()) {
    listener_family = AF_INET;
    listener.reset(::socket(listener_family, SOCK_STREAM, IPPROTO_TCP));
  }
  if (!listener.valid()) {
    return Result<TcpThroughputResult>::failure(
        network_error("TCP throughput server", {}, "socket() failed", last_socket_error()));
  }
  claim_listener_port(listener.get());
  if (listener_family == AF_INET6) {
    int dual_stack = 0;
    static_cast<void>(setsockopt(listener.get(),
                                 IPPROTO_IPV6,
                                 IPV6_V6ONLY,
                                 reinterpret_cast<const char*>(&dual_stack),
                                 static_cast<SocketLength>(sizeof(dual_stack))));
  }

  sockaddr_storage local{};
  SocketLength local_length = 0;
  if (listener_family == AF_INET6) {
    sockaddr_in6 address6{};
    address6.sin6_family = AF_INET6;
    address6.sin6_addr = in6addr_any;
    address6.sin6_port = htons(options.port);
    std::memcpy(&local, &address6, sizeof(address6));
    local_length = static_cast<SocketLength>(sizeof(address6));
  } else {
    sockaddr_in address4{};
    address4.sin_family = AF_INET;
    address4.sin_addr.s_addr = htonl(INADDR_ANY);
    address4.sin_port = htons(options.port);
    std::memcpy(&local, &address4, sizeof(address4));
    local_length = static_cast<SocketLength>(sizeof(address4));
  }
  if (bind(listener.get(), reinterpret_cast<const sockaddr*>(&local), local_length) != 0) {
    listener.reset(::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (!listener.valid()) {
      return Result<TcpThroughputResult>::failure(
          network_error("TCP throughput server", {}, "socket() failed", last_socket_error()));
    }
    claim_listener_port(listener.get());
    sockaddr_in address4{};
    address4.sin_family = AF_INET;
    address4.sin_addr.s_addr = htonl(INADDR_ANY);
    address4.sin_port = htons(options.port);
    if (bind(listener.get(),
             reinterpret_cast<const sockaddr*>(&address4),
             static_cast<SocketLength>(sizeof(address4))) != 0) {
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput server", std::to_string(options.port), "bind() failed", last_socket_error()));
    }
  }
  if (listen(listener.get(), 1) != 0) {
    return Result<TcpThroughputResult>::failure(network_error(
        "TCP throughput server", std::to_string(options.port), "listen() failed", last_socket_error()));
  }
  report(progress, "Waiting", "0.0.0.0:" + std::to_string(options.port));
  const auto wait_started = std::chrono::steady_clock::now();
  SocketOwner accepted;
  while (!cancel.is_cancelled() &&
         std::chrono::steady_clock::now() - wait_started < options.connect_timeout) {
    const int selected = select_socket(listener.get(), true, std::chrono::milliseconds(100));
    if (selected < 0) {
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput server", std::to_string(options.port), "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    sockaddr_storage remote{};
    SocketLength remote_length = static_cast<SocketLength>(sizeof(remote));
    accepted.reset(accept(listener.get(), reinterpret_cast<sockaddr*>(&remote), &remote_length));
    if (accepted.valid()) {
      output.peer_address =
          endpoint_text(reinterpret_cast<const sockaddr*>(&remote), remote_length);
      break;
    }
  }
  if (cancel.is_cancelled()) {
    output.cancelled = true;
    return Result<TcpThroughputResult>::success(std::move(output));
  }
  if (!accepted.valid()) {
    return Result<TcpThroughputResult>::failure(network_error(
        "TCP throughput server", std::to_string(options.port), "No client connected before the timeout"));
  }
  if (auto status = set_nonblocking(accepted.get()); !status.ok())
    return Result<TcpThroughputResult>::failure(status.error());

  output.direction = "receive";
  auto request_line = receive_control_line(
      accepted.get(), options.connect_timeout, cancel, output.peer_address);
  if (!request_line.ok())
    return Result<TcpThroughputResult>::failure(request_line.error());
  auto requested_bytes = parse_throughput_request(request_line.value());
  if (!requested_bytes.ok())
    return Result<TcpThroughputResult>::failure(requested_bytes.error());
  if (options.transfer_bytes > 0U && requested_bytes.value() > options.transfer_bytes) {
    static_cast<void>(send_control_text(accepted.get(), "SAT-THROUGHPUT/1 ERR 0\n",
                                        options.connect_timeout, cancel, output.peer_address));
    return Result<TcpThroughputResult>::failure(network_error(
        "TCP throughput server", output.peer_address,
        "Client requested more data than the configured server transfer limit"));
  }
  const std::uint64_t expected_bytes = requested_bytes.value();
  const std::string acknowledgement =
      "SAT-THROUGHPUT/1 OK " + std::to_string(expected_bytes) + "\n";
  auto sent_ack = send_control_text(
      accepted.get(), acknowledgement, options.connect_timeout, cancel, output.peer_address);
  if (!sent_ack.ok())
    return Result<TcpThroughputResult>::failure(sent_ack.error());
  output.protocol_verified = true;

  const auto started = std::chrono::steady_clock::now();
  auto last_activity = started;
  while (output.transferred_bytes < expected_bytes) {
    if (cancel.is_cancelled()) {
      output.cancelled = true;
      break;
    }
    if (std::chrono::steady_clock::now() - last_activity >= options.idle_timeout) {
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput server", output.peer_address, "Transfer timed out with no progress"));
    }
    const int selected = select_socket(accepted.get(), true, std::chrono::milliseconds(100));
    if (selected < 0) {
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput server", output.peer_address, "select() failed", last_socket_error()));
    }
    if (selected == 0)
      continue;
    const std::uint64_t remaining = expected_bytes - output.transferred_bytes;
    const std::size_t receive_size = static_cast<std::size_t>(
        std::min<std::uint64_t>(remaining, static_cast<std::uint64_t>(buffer.size())));
#ifdef _WIN32
    const int received = recv(accepted.get(), buffer.data(), static_cast<int>(receive_size), 0);
#else
    const ssize_t received = recv(accepted.get(), buffer.data(), receive_size, 0);
#endif
    if (received > 0) {
      output.transferred_bytes += static_cast<std::uint64_t>(received);
      last_activity = std::chrono::steady_clock::now();
      report(progress, "Receiving", output.peer_address, output.transferred_bytes);
      continue;
    }
    if (received == 0) {
      return Result<TcpThroughputResult>::failure(network_error(
          "TCP throughput server", output.peer_address,
          "Peer closed before sending the transfer size declared in the SAT handshake"));
    }
    const int error_code = last_socket_error();
    if (!would_block(error_code)) {
      return Result<TcpThroughputResult>::failure(
          network_error("TCP throughput server", output.peer_address, "recv() failed", error_code));
    }
  }
  output.elapsed_seconds =
      std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  output.bits_per_second = rate_for(output.transferred_bytes, output.elapsed_seconds);
  // The File Transfer Calculator stops its clock on this line; an older client has closed already.
  if (!output.cancelled) {
    static_cast<void>(send_control_text(
        accepted.get(),
        "SAT-THROUGHPUT/1 DONE " + std::to_string(output.transferred_bytes) + " " +
            std::to_string(static_cast<long long>(std::llround(output.elapsed_seconds * 1e6))) + "\n",
        std::chrono::milliseconds(2000), cancel, output.peer_address));
  }
  return Result<TcpThroughputResult>::success(std::move(output));
}


namespace {

class BinaryProtocolChannel {
public:
  BinaryProtocolChannel(SocketHandle socket, SSL* ssl = nullptr) : socket_(socket), ssl_(ssl) {}

  Status send_bytes(const unsigned char* data,
                    std::size_t bytes,
                    std::chrono::milliseconds timeout,
                    const CancellationToken& cancel,
                    std::string_view operation,
                    std::string_view peer) {
    std::size_t sent_total = 0;
    const auto started = std::chrono::steady_clock::now();
    while (sent_total < bytes) {
      if (cancel.is_cancelled())
        return Status::failure(network_error(std::string(operation), std::string(peer), "Operation cancelled"));
      if (std::chrono::steady_clock::now() - started >= timeout)
        return Status::failure(network_error(std::string(operation), std::string(peer), "Send timed out"));

      if (ssl_ != nullptr) {
        ERR_clear_error();
        const int count = static_cast<int>(std::min<std::size_t>(bytes - sent_total,
                                                                 static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int written = SSL_write(ssl_, data + sent_total, count);
        if (written > 0) {
          sent_total += static_cast<std::size_t>(written);
          continue;
        }
        const int ssl_error = SSL_get_error(ssl_, written);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          const int selected = select_socket(socket_, ssl_error == SSL_ERROR_WANT_READ,
                                             std::chrono::milliseconds(100));
          if (selected < 0)
            return Status::failure(network_error(std::string(operation), std::string(peer),
                                                 "Socket wait failed", last_socket_error()));
          continue;
        }
        return Status::failure(network_error(std::string(operation), std::string(peer),
                                             "TLS write failed: " + openssl_error_text()));
      }

      const int selected = select_socket(socket_, false, std::chrono::milliseconds(100));
      if (selected < 0)
        return Status::failure(network_error(std::string(operation), std::string(peer),
                                             "select() failed", last_socket_error()));
      if (selected == 0)
        continue;
#ifdef _WIN32
      const int written = send(socket_, reinterpret_cast<const char*>(data + sent_total),
                               static_cast<int>(bytes - sent_total), 0);
#else
      const ssize_t written = send(socket_, data + sent_total, bytes - sent_total, kSendFlags);
#endif
      if (written > 0) {
        sent_total += static_cast<std::size_t>(written);
        continue;
      }
      if (written == 0)
        return Status::failure(network_error(std::string(operation), std::string(peer), "Peer closed during send"));
      const int code = last_socket_error();
      if (!would_block(code))
        return Status::failure(network_error(std::string(operation), std::string(peer), "send() failed", code));
    }
    return Status::success();
  }

  Result<std::vector<unsigned char>> receive_exact(std::size_t bytes,
                                                   std::chrono::milliseconds timeout,
                                                   const CancellationToken& cancel,
                                                   std::string_view operation,
                                                   std::string_view peer) {
    std::vector<unsigned char> output(bytes);
    std::size_t received_total = 0;
    const auto started = std::chrono::steady_clock::now();
    while (received_total < bytes) {
      if (cancel.is_cancelled())
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer), "Operation cancelled"));
      if (std::chrono::steady_clock::now() - started >= timeout)
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer), "Receive timed out"));

      if (ssl_ != nullptr) {
        ERR_clear_error();
        const int count = static_cast<int>(std::min<std::size_t>(bytes - received_total,
                                                                 static_cast<std::size_t>(std::numeric_limits<int>::max())));
        const int read = SSL_read(ssl_, output.data() + received_total, count);
        if (read > 0) {
          received_total += static_cast<std::size_t>(read);
          continue;
        }
        const int ssl_error = SSL_get_error(ssl_, read);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
          const int selected = select_socket(socket_, ssl_error == SSL_ERROR_WANT_READ,
                                             std::chrono::milliseconds(100));
          if (selected < 0)
            return Result<std::vector<unsigned char>>::failure(
                network_error(std::string(operation), std::string(peer),
                              "Socket wait failed", last_socket_error()));
          continue;
        }
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer),
                          "TLS read failed: " + openssl_error_text()));
      }

      const int selected = select_socket(socket_, true, std::chrono::milliseconds(100));
      if (selected < 0)
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer), "select() failed", last_socket_error()));
      if (selected == 0)
        continue;
#ifdef _WIN32
      const int read = recv(socket_, reinterpret_cast<char*>(output.data() + received_total),
                            static_cast<int>(bytes - received_total), 0);
#else
      const ssize_t read = recv(socket_, output.data() + received_total, bytes - received_total, 0);
#endif
      if (read > 0) {
        received_total += static_cast<std::size_t>(read);
        continue;
      }
      if (read == 0)
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer), "Peer closed during receive"));
      const int code = last_socket_error();
      if (!would_block(code))
        return Result<std::vector<unsigned char>>::failure(
            network_error(std::string(operation), std::string(peer), "recv() failed", code));
    }
    return Result<std::vector<unsigned char>>::success(std::move(output));
  }

private:
  SocketHandle socket_ = kInvalidSocket;
  SSL* ssl_ = nullptr;
};

struct Http2Frame {
  std::uint8_t type = 0;
  std::uint8_t flags = 0;
  std::uint32_t stream_id = 0;
  std::vector<unsigned char> payload;
};

std::vector<unsigned char> make_http2_frame(std::uint8_t type,
                                            std::uint8_t flags,
                                            std::uint32_t stream_id,
                                            const std::vector<unsigned char>& payload = {}) {
  std::vector<unsigned char> frame(9U + payload.size());
  const std::uint32_t length = static_cast<std::uint32_t>(payload.size());
  frame[0] = static_cast<unsigned char>((length >> 16) & 0xFFU);
  frame[1] = static_cast<unsigned char>((length >> 8) & 0xFFU);
  frame[2] = static_cast<unsigned char>(length & 0xFFU);
  frame[3] = type;
  frame[4] = flags;
  const std::uint32_t stream = stream_id & 0x7FFFFFFFU;
  frame[5] = static_cast<unsigned char>((stream >> 24) & 0x7FU);
  frame[6] = static_cast<unsigned char>((stream >> 16) & 0xFFU);
  frame[7] = static_cast<unsigned char>((stream >> 8) & 0xFFU);
  frame[8] = static_cast<unsigned char>(stream & 0xFFU);
  std::copy(payload.begin(), payload.end(), frame.begin() + 9);
  return frame;
}

Result<Http2Frame> receive_http2_frame(BinaryProtocolChannel& channel,
                                       std::chrono::milliseconds timeout,
                                       const CancellationToken& cancel,
                                       std::string_view operation,
                                       std::string_view peer,
                                       std::string* header_bytes = nullptr) {
  auto header = channel.receive_exact(9U, timeout, cancel, operation, peer);
  if (!header.ok())
    return Result<Http2Frame>::failure(header.error());
  const auto& bytes = header.value();
  if (header_bytes != nullptr)
    header_bytes->assign(bytes.begin(), bytes.end());
  const std::uint32_t length = (static_cast<std::uint32_t>(bytes[0]) << 16) |
                               (static_cast<std::uint32_t>(bytes[1]) << 8) |
                               static_cast<std::uint32_t>(bytes[2]);
  if (length > 1024U * 1024U)
    return Result<Http2Frame>::failure(network_error(std::string(operation), std::string(peer),
                                                     "HTTP/2 frame exceeded the 1 MiB diagnostic bound"));
  Http2Frame frame;
  frame.type = bytes[3];
  frame.flags = bytes[4];
  frame.stream_id = ((static_cast<std::uint32_t>(bytes[5]) & 0x7FU) << 24) |
                    (static_cast<std::uint32_t>(bytes[6]) << 16) |
                    (static_cast<std::uint32_t>(bytes[7]) << 8) |
                    static_cast<std::uint32_t>(bytes[8]);
  if (length != 0U) {
    auto payload = channel.receive_exact(length, timeout, cancel, operation, peer);
    if (!payload.ok())
      return Result<Http2Frame>::failure(payload.error());
    frame.payload = std::move(payload.value());
  }
  return Result<Http2Frame>::success(std::move(frame));
}

constexpr std::uint16_t kSatHttp2SettingId = 0xFA57U;
constexpr std::uint32_t kSatHttp2SettingValue = 0x53415431U; // "SAT1"

std::vector<unsigned char> sat_http2_settings_payload() {
  return {static_cast<unsigned char>((kSatHttp2SettingId >> 8) & 0xFFU),
          static_cast<unsigned char>(kSatHttp2SettingId & 0xFFU),
          static_cast<unsigned char>((kSatHttp2SettingValue >> 24) & 0xFFU),
          static_cast<unsigned char>((kSatHttp2SettingValue >> 16) & 0xFFU),
          static_cast<unsigned char>((kSatHttp2SettingValue >> 8) & 0xFFU),
          static_cast<unsigned char>(kSatHttp2SettingValue & 0xFFU)};
}

bool contains_sat_http2_setting(const std::vector<unsigned char>& payload) {
  for (std::size_t offset = 0; offset + 6U <= payload.size(); offset += 6U) {
    const std::uint16_t id = (static_cast<std::uint16_t>(payload[offset]) << 8) |
                             static_cast<std::uint16_t>(payload[offset + 1]);
    const std::uint32_t value = (static_cast<std::uint32_t>(payload[offset + 2]) << 24) |
                                (static_cast<std::uint32_t>(payload[offset + 3]) << 16) |
                                (static_cast<std::uint32_t>(payload[offset + 4]) << 8) |
                                static_cast<std::uint32_t>(payload[offset + 5]);
    if (id == kSatHttp2SettingId && value == kSatHttp2SettingValue)
      return true;
  }
  return false;
}

std::array<unsigned char, 8> make_sat_ping_payload() {
  std::array<unsigned char, 8> output{'S', 'A', 'T', 'G', '0', '0', '0', '0'};
  std::string id = make_uuid_v4();
  id.erase(std::remove(id.begin(), id.end(), '-'), id.end());
  for (std::size_t index = 0; index < 4U && index < id.size(); ++index)
    output[4U + index] = static_cast<unsigned char>(id[index]);
  return output;
}

std::string ping_test_id(const std::array<unsigned char, 8>& payload) {
  return std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
}

bool bind_probe_family(int family, std::uint16_t port, int& native_code) {
  SocketOwner probe(::socket(family, SOCK_STREAM, IPPROTO_TCP));
  if (!probe.valid()) {
    native_code = last_socket_error();
    return false;
  }
#ifdef _WIN32
  BOOL exclusive = TRUE;
  static_cast<void>(setsockopt(probe.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)));
#endif
  if (family == AF_INET6) {
    int v6_only = 1;
    static_cast<void>(setsockopt(probe.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                                 reinterpret_cast<const char*>(&v6_only), sizeof(v6_only)));
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    local.sin6_port = htons(port);
    if (bind(probe.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
      native_code = last_socket_error();
      return false;
    }
    return true;
  }
  sockaddr_in local{};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = htonl(INADDR_ANY);
  local.sin_port = htons(port);
  if (bind(probe.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
    native_code = last_socket_error();
    return false;
  }
  return true;
}

#ifdef _WIN32
void populate_tcp_owner(LocalTcpPortState& state) {
  DWORD bytes = 0;
  if (GetExtendedTcpTable(nullptr, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != ERROR_INSUFFICIENT_BUFFER || bytes == 0)
    return;
  std::vector<unsigned char> buffer(bytes);
  auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
  if (GetExtendedTcpTable(table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) != NO_ERROR)
    return;
  for (DWORD index = 0; index < table->dwNumEntries; ++index) {
    const auto& row = table->table[index];
    if (ntohs(static_cast<u_short>(row.dwLocalPort)) != state.port)
      continue;
    state.owner_process_id = row.dwOwningPid;
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, row.dwOwningPid);
    if (process != nullptr) {
      std::wstring path(32768, L'\0');
      DWORD chars = static_cast<DWORD>(path.size());
      if (QueryFullProcessImageNameW(process, 0, path.data(), &chars) && chars != 0) {
        path.resize(chars);
        state.owner_process_name = utf8_from_wide(std::filesystem::path(path).filename().wstring());
      }
      CloseHandle(process);
    }
    break;
  }
}
#endif

std::vector<unsigned char> rpc_endpoint_mapper_bind_pdu() {
  // DCE/RPC v5 connection-oriented BIND for the Endpoint Mapper interface
  // e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0 using NDR v2.0.
  return {
      0x05,0x00,0x0B,0x03,0x10,0x00,0x00,0x00,0x48,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
      0xB8,0x10,0xB8,0x10,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,
      0x00,0x00,0x01,0x00,
      0x08,0x83,0xAF,0xE1,0x1F,0x5D,0xC9,0x11,0x91,0xA4,0x08,0x00,0x2B,0x14,0xA0,0xFA,
      0x03,0x00,0x00,0x00,
      0x04,0x5D,0x88,0x8A,0xEB,0x1C,0xC9,0x11,0x9F,0xE8,0x08,0x00,0x2B,0x10,0x48,0x60,
      0x02,0x00,0x00,0x00};
}

bool parse_rpc_bind_ack(const std::vector<unsigned char>& pdu,
                        std::uint16_t& context_result,
                        std::uint16_t& reject_reason) {
  if (pdu.size() < 30U || pdu[0] != 5U || pdu[2] != 12U)
    return false;
  const std::size_t body = 16U;
  const std::uint16_t secondary_length = static_cast<std::uint16_t>(pdu[body + 8]) |
                                         (static_cast<std::uint16_t>(pdu[body + 9]) << 8);
  std::size_t offset = body + 10U + secondary_length;
  offset = (offset + 3U) & ~std::size_t(3U);
  if (offset + 8U > pdu.size())
    return false;
  const std::uint8_t result_count = pdu[offset];
  offset += 4U;
  if (result_count == 0U || offset + 4U > pdu.size())
    return false;
  context_result = static_cast<std::uint16_t>(pdu[offset]) |
                   (static_cast<std::uint16_t>(pdu[offset + 1]) << 8);
  reject_reason = static_cast<std::uint16_t>(pdu[offset + 2]) |
                  (static_cast<std::uint16_t>(pdu[offset + 3]) << 8);
  return true;
}

} // namespace

Result<LocalTcpPortState> inspect_local_tcp_listener_port(std::uint16_t port) {
  if (port == 0)
    return Result<LocalTcpPortState>::failure(network_error("inspect local TCP port", {}, "A non-zero port is required"));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<LocalTcpPortState>::failure(network_error("initialize sockets", {}, "Socket runtime initialization failed", runtime.error_code()));
  LocalTcpPortState state;
  state.port = port;
  int ipv4_error = 0;
  int ipv6_error = 0;
  const bool ipv4_free = bind_probe_family(AF_INET, port, ipv4_error);
  const bool ipv6_free = bind_probe_family(AF_INET6, port, ipv6_error);
  state.available = ipv4_free && ipv6_free;
  if (state.available) {
    state.detail = "No IPv4 or IPv6 TCP listener currently owns the requested port";
    return Result<LocalTcpPortState>::success(std::move(state));
  }
  state.native_code = ipv4_free ? ipv6_error : ipv4_error;
  state.detail = "The requested port is already bound, reserved, or unavailable; SAT will not start a temporary listener";
#ifdef _WIN32
  populate_tcp_owner(state);
#endif
  return Result<LocalTcpPortState>::success(std::move(state));
}

Result<RpcConnectivityResult> test_rpc_endpoint_mapper(const RpcConnectivityOptions& options,
                                                       const CancellationToken& cancel,
                                                       ProgressCallback progress) {
  if (options.host.empty() || options.port == 0)
    return Result<RpcConnectivityResult>::failure(network_error("RPC Endpoint Mapper test", options.host, "A host and non-zero port are required"));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<RpcConnectivityResult>::failure(network_error("initialize sockets", options.host, "Socket runtime initialization failed", runtime.error_code()));
  RpcConnectivityResult output;
  output.host = options.host;
  output.port = options.port;
  output.source_interface = options.source_interface;
  const auto started = std::chrono::steady_clock::now();
  report(progress, "RPC TCP connect", options.host + ":" + std::to_string(options.port));
  std::string connected_address;
  auto socket = connect_tcp_socket(options.host, options.port, options.timeout, cancel, progress,
                                   connected_address, options.source_address);
  if (!socket.ok()) {
    output.failure_stage = "TCP connect";
    output.detail = socket.error().message;
    output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return Result<RpcConnectivityResult>::success(std::move(output));
  }
  output.tcp_connected = true;
  output.connected_address = connected_address;
  output.local_address = socket_local_address(socket.value().get());
  BinaryProtocolChannel channel(socket.value().get());
  const auto bind = rpc_endpoint_mapper_bind_pdu();
  report(progress, "DCE/RPC bind", connected_address);
  auto sent = channel.send_bytes(bind.data(), bind.size(), options.timeout, cancel,
                                 "RPC Endpoint Mapper bind", connected_address);
  if (!sent.ok()) {
    output.failure_stage = "DCE/RPC bind send";
    output.detail = sent.error().message;
  } else {
    output.rpc_bind_sent = true;
    auto header = channel.receive_exact(16U, options.timeout, cancel,
                                        "RPC Endpoint Mapper bind", connected_address);
    if (!header.ok()) {
      output.failure_stage = "DCE/RPC bind response";
      output.detail = header.error().message;
    } else {
      const std::uint16_t fragment_length = static_cast<std::uint16_t>(header.value()[8]) |
                                            (static_cast<std::uint16_t>(header.value()[9]) << 8);
      if (fragment_length < 16U) {
        output.failure_stage = "DCE/RPC bind response";
        output.detail = "Peer returned an invalid DCE/RPC fragment length";
      } else {
        std::vector<unsigned char> pdu = header.value();
        if (fragment_length > 16U) {
          auto body = channel.receive_exact(fragment_length - 16U, options.timeout, cancel,
                                            "RPC Endpoint Mapper bind", connected_address);
          if (!body.ok()) {
            output.failure_stage = "DCE/RPC bind response";
            output.detail = body.error().message;
          } else {
            pdu.insert(pdu.end(), body.value().begin(), body.value().end());
          }
        }
        if (pdu.size() == fragment_length) {
          output.bind_ack_received = pdu[2] == 12U;
          if (output.bind_ack_received) {
            if (parse_rpc_bind_ack(pdu, output.rpc_context_result, output.rpc_reject_reason)) {
              output.endpoint_mapper_accepted = output.rpc_context_result == 0U;
              output.detail = output.endpoint_mapper_accepted
                                  ? "DCE/RPC Endpoint Mapper accepted the EPM v3 bind over TCP"
                                  : "Endpoint Mapper replied but rejected the requested presentation context";
              output.failure_stage = output.endpoint_mapper_accepted ? std::string{} : "DCE/RPC presentation context";
            } else {
              output.failure_stage = "DCE/RPC bind acknowledgement";
              output.detail = "Endpoint Mapper returned a bind acknowledgement that SAT could not parse safely";
            }
          } else {
            output.failure_stage = "DCE/RPC bind acknowledgement";
            output.detail = "TCP/135 responded, but the peer did not return a DCE/RPC BIND_ACK";
          }
        }
      }
    }
  }
  output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  return Result<RpcConnectivityResult>::success(std::move(output));
}

Result<GrpcConnectivityResult> test_grpc_connectivity(const GrpcConnectivityOptions& options,
                                                      const CancellationToken& cancel,
                                                      ProgressCallback progress) {
  if (options.host.empty() || options.port == 0)
    return Result<GrpcConnectivityResult>::failure(network_error("gRPC connectivity test", options.host, "A host and non-zero port are required"));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<GrpcConnectivityResult>::failure(network_error("initialize sockets", options.host, "Socket runtime initialization failed", runtime.error_code()));

  GrpcConnectivityResult output;
  output.host = options.host;
  output.port = options.port;
  output.source_interface = options.source_interface;
  output.tls_requested = options.use_tls;
  const auto started = std::chrono::steady_clock::now();
  std::string connected_address;
  report(progress, "gRPC TCP connect", options.host + ":" + std::to_string(options.port));
  auto connected = connect_tcp_socket(options.host, options.port, options.timeout, cancel, progress,
                                      connected_address, options.source_address);
  if (!connected.ok()) {
    output.failure_stage = "TCP connect";
    output.detail = connected.error().message;
    output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return Result<GrpcConnectivityResult>::success(std::move(output));
  }
  output.tcp_connected = true;
  output.connected_address = connected_address;
  output.local_address = socket_local_address(connected.value().get());

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(nullptr, SSL_CTX_free);
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(nullptr, SSL_free);
  if (options.use_tls) {
    SSL_CTX* raw_context = SSL_CTX_new(TLS_client_method());
    if (raw_context == nullptr) {
      output.failure_stage = "TLS initialization";
      output.detail = openssl_error_text();
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
    context.reset(raw_context);
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
    SSL* raw_ssl = SSL_new(context.get());
    if (raw_ssl == nullptr) {
      output.failure_stage = "TLS initialization";
      output.detail = openssl_error_text();
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
    ssl.reset(raw_ssl);
    const std::string server_name = options.server_name.empty() ? options.host : options.server_name;
    if (!server_name.empty())
      static_cast<void>(SSL_set_tlsext_host_name(ssl.get(), server_name.c_str()));
    const unsigned char protocols[] = {2U, 'h', '2'};
    static_cast<void>(SSL_set_alpn_protos(ssl.get(), protocols, sizeof(protocols)));
    if (SSL_set_fd(ssl.get(), static_cast<int>(connected.value().get())) != 1) {
      output.failure_stage = "TLS initialization";
      output.detail = openssl_error_text();
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
    report(progress, "gRPC TLS / ALPN", connected_address);
    const auto deadline = std::chrono::steady_clock::now() + options.timeout;
    while (!cancel.is_cancelled() && std::chrono::steady_clock::now() < deadline) {
      const int result = SSL_connect(ssl.get());
      if (result == 1) {
        output.tls_completed = true;
        break;
      }
      const int ssl_error = SSL_get_error(ssl.get(), result);
      if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
        const int selected = select_socket(connected.value().get(), ssl_error == SSL_ERROR_WANT_READ,
                                           std::chrono::milliseconds(100));
        if (selected < 0)
          break;
        continue;
      }
      output.detail = openssl_error_text();
      break;
    }
    if (!output.tls_completed) {
      output.failure_stage = "TLS handshake";
      if (output.detail.empty()) output.detail = "TLS handshake did not complete before the timeout";
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
    output.tls_version = SSL_get_version(ssl.get()) == nullptr ? std::string{} : SSL_get_version(ssl.get());
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl.get());
    if (cipher != nullptr && SSL_CIPHER_get_name(cipher) != nullptr)
      output.tls_cipher = SSL_CIPHER_get_name(cipher);
    {
      TlsProbeOptions certificate_options;
      certificate_options.host = options.host;
      certificate_options.server_name = options.server_name;
      output.certificate = inspect_peer_certificate(ssl.get(), certificate_options);
      output.certificate_read = !output.certificate.sha256_fingerprint.empty();
    }
    const unsigned char* selected_protocol = nullptr;
    unsigned int selected_length = 0;
    SSL_get0_alpn_selected(ssl.get(), &selected_protocol, &selected_length);
    if (selected_protocol != nullptr && selected_length != 0U)
      output.alpn_protocol.assign(reinterpret_cast<const char*>(selected_protocol), selected_length);
    if (output.alpn_protocol != "h2") {
      output.failure_stage = "HTTP/2 ALPN";
      output.detail = output.alpn_protocol.empty()
                          ? "TLS completed, but the server did not negotiate ALPN h2"
                          : "TLS completed, but the server negotiated ALPN " + output.alpn_protocol + " instead of h2";
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
  }

  BinaryProtocolChannel channel(connected.value().get(), ssl.get());
  static constexpr std::string_view preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  report(progress, "HTTP/2 preface", connected_address);
  auto preface_status = channel.send_bytes(reinterpret_cast<const unsigned char*>(preface.data()), preface.size(),
                                           options.timeout, cancel, "gRPC HTTP/2 preface", connected_address);
  if (!preface_status.ok()) {
    output.failure_stage = "HTTP/2 client preface";
    output.detail = preface_status.error().message;
    output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return Result<GrpcConnectivityResult>::success(std::move(output));
  }
  output.http2_preface_sent = true;
  const auto settings = make_http2_frame(4U, 0U, 0U);
  auto settings_status = channel.send_bytes(settings.data(), settings.size(), options.timeout, cancel,
                                            "gRPC HTTP/2 SETTINGS", connected_address);
  if (!settings_status.ok()) {
    output.failure_stage = "HTTP/2 client SETTINGS";
    output.detail = settings_status.error().message;
    output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return Result<GrpcConnectivityResult>::success(std::move(output));
  }

  // What the peer's first bytes look like when they are not HTTP/2.
  const auto describe_first = [&output](const std::string& header) {
    if (header.empty())
      return;
    std::string hex;
    char buffer[4];
    for (const char byte : header) {
      std::snprintf(buffer, sizeof(buffer), "%02X", static_cast<unsigned int>(static_cast<unsigned char>(byte)));
      hex += (hex.empty() ? "" : " ") + std::string(buffer);
    }
    output.first_bytes = hex;
    const auto first = static_cast<unsigned char>(header[0]);
    output.first_bytes_look =
        header.rfind("HTTP/", 0) == 0                                        ? "an HTTP/1.x response: the port speaks HTTP/1, not HTTP/2"
        : header.rfind("SSH-", 0) == 0                                       ? "an SSH banner"
        : (first == 0x15U || first == 0x16U) && header.size() > 1U && header[1] == '\x03' ? "a TLS record: the port expects TLS"
                                                                             : "binary data that is not HTTP/2, such as Veeam's own transport on a data port";
    output.detail += " First bytes: " + output.first_bytes + " (" + output.first_bytes_look + ").";
  };
  for (int index = 0; index < 8 && !output.server_settings_received; ++index) {
    std::string header;
    auto frame = receive_http2_frame(channel, options.timeout, cancel, "gRPC HTTP/2 SETTINGS", connected_address,
                                     index == 0 ? &header : nullptr);
    if (!frame.ok()) {
      output.failure_stage = "HTTP/2 server SETTINGS";
      output.detail = frame.error().message;
      describe_first(header);
      output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
      return Result<GrpcConnectivityResult>::success(std::move(output));
    }
    if (index == 0 && (frame.value().type != 4U || frame.value().stream_id != 0U))
      describe_first(header);
    if (frame.value().type == 4U && frame.value().stream_id == 0U && (frame.value().flags & 0x1U) == 0U) {
      output.server_settings_received = true;
      output.sat_peer_verified = contains_sat_http2_setting(frame.value().payload);
    }
  }
  if (!output.server_settings_received) {
    output.failure_stage = "HTTP/2 server SETTINGS";
    output.detail = "The peer did not provide an HTTP/2 SETTINGS frame";
    output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return Result<GrpcConnectivityResult>::success(std::move(output));
  }
  const auto settings_ack = make_http2_frame(4U, 0x1U, 0U);
  static_cast<void>(channel.send_bytes(settings_ack.data(), settings_ack.size(), options.timeout, cancel,
                                       "gRPC HTTP/2 SETTINGS ACK", connected_address));

  const auto ping_payload = make_sat_ping_payload();
  const std::vector<unsigned char> ping_vector(ping_payload.begin(), ping_payload.end());
  const auto ping = make_http2_frame(6U, 0U, 0U, ping_vector);
  output.sat_test_id = ping_test_id(ping_payload);
  report(progress, "HTTP/2 PING", output.sat_test_id);
  auto ping_sent = channel.send_bytes(ping.data(), ping.size(), options.timeout, cancel,
                                      "gRPC HTTP/2 PING", connected_address);
  if (ping_sent.ok()) {
    for (int index = 0; index < 8 && !output.http2_ping_acknowledged; ++index) {
      auto frame = receive_http2_frame(channel, options.timeout, cancel, "gRPC HTTP/2 PING", connected_address);
      if (!frame.ok())
        break;
      if (frame.value().type == 6U && frame.value().stream_id == 0U && (frame.value().flags & 0x1U) != 0U &&
          frame.value().payload == ping_vector) {
        output.http2_ping_acknowledged = true;
        break;
      }
    }
  }
  if (!output.http2_ping_acknowledged) {
    output.failure_stage = "HTTP/2 PING";
    output.detail = "HTTP/2 SETTINGS succeeded, but the peer did not acknowledge the bounded HTTP/2 PING";
  } else {
    output.detail = output.sat_peer_verified
                        ? "HTTP/2 transport completed and the peer advertised the SAT gRPC transport marker"
                        : "HTTP/2 transport completed. This validates gRPC transport compatibility; no application method was invoked";
  }
  output.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  return Result<GrpcConnectivityResult>::success(std::move(output));
}

Result<GrpcListenerResult> listen_grpc_transport(const GrpcListenerOptions& options,
                                                 const CancellationToken& cancel,
                                                 ProgressCallback progress,
                                                 GrpcListenerEventCallback event_callback) {
  if (options.port == 0)
    return Result<GrpcListenerResult>::failure(network_error("gRPC transport listener", {}, "A non-zero port is required"));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<GrpcListenerResult>::failure(network_error("initialize sockets", {}, "Socket runtime initialization failed", runtime.error_code()));

  int listener_family = AF_INET6;
  SocketOwner listener(::socket(listener_family, SOCK_STREAM, IPPROTO_TCP));
  if (listener.valid()) {
    int dual_stack = 0;
    static_cast<void>(setsockopt(listener.get(), IPPROTO_IPV6, IPV6_V6ONLY,
                                 reinterpret_cast<const char*>(&dual_stack), sizeof(dual_stack)));
  } else {
    listener_family = AF_INET;
    listener.reset(::socket(listener_family, SOCK_STREAM, IPPROTO_TCP));
  }
  if (!listener.valid())
    return Result<GrpcListenerResult>::failure(network_error("create gRPC transport listener", {}, "socket() failed", last_socket_error()));
#ifdef _WIN32
  BOOL exclusive = TRUE;
  static_cast<void>(setsockopt(listener.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                               reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)));
#endif
  int bind_result = -1;
  if (listener_family == AF_INET6) {
    sockaddr_in6 local{};
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    local.sin6_port = htons(options.port);
    bind_result = bind(listener.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local));
  } else {
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(options.port);
    bind_result = bind(listener.get(), reinterpret_cast<const sockaddr*>(&local), sizeof(local));
  }
  if (bind_result != 0)
    return Result<GrpcListenerResult>::failure(network_error("bind gRPC transport listener", std::to_string(options.port), "bind() failed", last_socket_error()));
  if (listen(listener.get(), SOMAXCONN) != 0)
    return Result<GrpcListenerResult>::failure(network_error("listen gRPC transport", std::to_string(options.port), "listen() failed", last_socket_error()));

  GrpcListenerResult output;
  output.port = options.port;
  const auto deadline = std::chrono::steady_clock::now() + options.duration;
  report(progress, "Listening", "gRPC/HTTP2 0.0.0.0:" + std::to_string(options.port));
  while (std::chrono::steady_clock::now() < deadline) {
    if (cancel.is_cancelled()) { output.cancelled = true; break; }
    const int selected = select_socket(listener.get(), true, std::chrono::milliseconds(200));
    if (selected < 0)
      return Result<GrpcListenerResult>::failure(network_error("wait for gRPC connection", std::to_string(options.port), "select() failed", last_socket_error()));
    if (selected == 0)
      continue;
    sockaddr_storage remote{};
    SocketLength remote_length = static_cast<SocketLength>(sizeof(remote));
    SocketOwner accepted(accept(listener.get(), reinterpret_cast<sockaddr*>(&remote), &remote_length));
    if (!accepted.valid())
      continue;
    static_cast<void>(set_nonblocking(accepted.get()));
    GrpcAcceptedConnection connection;
    connection.remote_address = endpoint_text(reinterpret_cast<const sockaddr*>(&remote), remote_length, &connection.remote_port);
    sockaddr_storage local_endpoint{};
    SocketLength local_length = static_cast<SocketLength>(sizeof(local_endpoint));
    if (getsockname(accepted.get(), reinterpret_cast<sockaddr*>(&local_endpoint), &local_length) == 0)
      connection.local_address = endpoint_text(reinterpret_cast<const sockaddr*>(&local_endpoint), local_length, &connection.local_port);
    connection.accepted_utc = utc_now_iso8601();
    if (event_callback) event_callback(GrpcListenerEventKind::accepted, connection);

    BinaryProtocolChannel channel(accepted.get());
    static constexpr std::string_view expected_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    auto preface = channel.receive_exact(expected_preface.size(), std::chrono::seconds(3), cancel,
                                         "gRPC listener preface", connection.remote_address);
    if (preface.ok() && std::equal(preface.value().begin(), preface.value().end(), expected_preface.begin(), expected_preface.end())) {
      connection.http2_preface_received = true;
      auto client_settings = receive_http2_frame(channel, std::chrono::seconds(3), cancel,
                                                  "gRPC listener SETTINGS", connection.remote_address);
      if (client_settings.ok() && client_settings.value().type == 4U && client_settings.value().stream_id == 0U) {
        connection.client_settings_received = true;
        const auto server_settings = make_http2_frame(4U, 0U, 0U, sat_http2_settings_payload());
        auto sent_settings = channel.send_bytes(server_settings.data(), server_settings.size(), std::chrono::seconds(3), cancel,
                                                "gRPC listener SETTINGS", connection.remote_address);
        connection.server_settings_sent = sent_settings.ok();
        if (sent_settings.ok()) {
          for (int index = 0; index < 8; ++index) {
            auto frame = receive_http2_frame(channel, std::chrono::seconds(3), cancel,
                                             "gRPC listener frame", connection.remote_address);
            if (!frame.ok()) break;
            if (frame.value().type == 6U && frame.value().stream_id == 0U && frame.value().payload.size() == 8U &&
                (frame.value().flags & 0x1U) == 0U) {
              connection.ping_received = true;
              connection.sat_test_id.assign(reinterpret_cast<const char*>(frame.value().payload.data()), frame.value().payload.size());
              const auto ack = make_http2_frame(6U, 0x1U, 0U, frame.value().payload);
              auto sent_ack = channel.send_bytes(ack.data(), ack.size(), std::chrono::seconds(3), cancel,
                                                 "gRPC listener PING ACK", connection.remote_address);
              connection.ping_ack_sent = sent_ack.ok();
              connection.sat_peer_verified = connection.ping_ack_sent && connection.sat_test_id.rfind("SATG", 0) == 0;
              break;
            }
          }
        }
      }
    }
    connection.detail = connection.sat_peer_verified
                            ? "SAT gRPC transport peer verified through HTTP/2 SETTINGS and PING"
                            : connection.http2_preface_received
                                  ? "HTTP/2 client reached the listener; SAT peer verification was incomplete"
                                  : "TCP connected, but the HTTP/2 client preface was not received";
    if (event_callback) event_callback(GrpcListenerEventKind::updated, connection);
    output.connections.push_back(connection);
    report(progress, connection.sat_peer_verified ? "gRPC SAT peer verified" : "gRPC connection observed",
           connection.remote_address, static_cast<std::uint64_t>(output.connections.size()));
    if (!options.accept_multiple)
      break;
  }
  output.timed_out = !output.cancelled && output.connections.empty() && std::chrono::steady_clock::now() >= deadline;
  return Result<GrpcListenerResult>::success(std::move(output));
}

// ------------------------------------------------------------------------------ HTTPS requests

namespace {

#ifdef _WIN32
std::string windows_trust_error_text(DWORD code) {
  switch (code) {
  case static_cast<DWORD>(CERT_E_UNTRUSTEDROOT): return "Its root certificate is not trusted on this machine";
  case static_cast<DWORD>(CERT_E_CHAINING): return "Its chain does not reach a trusted root";
  case static_cast<DWORD>(CERT_E_CN_NO_MATCH): return "It does not carry the name asked for";
  case static_cast<DWORD>(CERT_E_EXPIRED): return "It has expired, or is not valid yet";
  case static_cast<DWORD>(CERT_E_WRONG_USAGE): return "It is not for a TLS server";
  case static_cast<DWORD>(CRYPT_E_REVOKED): return "It has been revoked";
  case static_cast<DWORD>(TRUST_E_CERT_SIGNATURE): return "Its signature does not check out";
  default: break;
  }
  char text[64] = {};
  std::snprintf(text, sizeof(text), "Windows does not trust it (0x%08lX)", static_cast<unsigned long>(code));
  return text;
}

// The peer's chain checked by Windows itself: its certificate store, its policy for a TLS server,
// and the name asked for.
bool system_trusts_chain(SSL* ssl, const std::string& server_name, std::string& detail) {
  X509* leaf = SSL_get1_peer_certificate(ssl);
  if (leaf == nullptr) {
    detail = "The server sent no certificate";
    return false;
  }
  HCERTSTORE memory = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr);
  PCCERT_CONTEXT leaf_context = nullptr;
  const auto add = [&](X509* certificate, PCCERT_CONTEXT* added) {
    unsigned char* der = nullptr;
    const int length = i2d_X509(certificate, &der);
    if (length > 0 && der != nullptr && memory != nullptr)
      CertAddEncodedCertificateToStore(memory, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, der,
                                       static_cast<DWORD>(length), CERT_STORE_ADD_ALWAYS, added);
    OPENSSL_free(der);
  };
  add(leaf, &leaf_context);
  if (STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl)) {
    for (int index = 0; index < sk_X509_num(chain); ++index)
      add(sk_X509_value(chain, index), nullptr);
  }
  X509_free(leaf);
  bool trusted = false;
  detail = "Windows could not read the certificate";
  if (leaf_context != nullptr) {
    char server_auth[] = szOID_PKIX_KP_SERVER_AUTH;
    LPSTR usages[] = {server_auth};
    CERT_CHAIN_PARA chain_para{};
    chain_para.cbSize = sizeof(chain_para);
    chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    chain_para.RequestedUsage.Usage.cUsageIdentifier = 1;
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = usages;
    PCCERT_CHAIN_CONTEXT chain_context = nullptr;
    if (CertGetCertificateChain(nullptr, leaf_context, nullptr, memory, &chain_para, 0, nullptr, &chain_context) !=
        FALSE) {
      std::wstring name = wide_from_utf8(server_name);
      HTTPSPolicyCallbackData https{};
      https.cbStruct = sizeof(https);
      https.dwAuthType = AUTHTYPE_SERVER;
      https.pwszServerName = name.data();
      CERT_CHAIN_POLICY_PARA policy{};
      policy.cbSize = sizeof(policy);
      policy.pvExtraPolicyPara = &https;
      CERT_CHAIN_POLICY_STATUS status{};
      status.cbSize = sizeof(status);
      if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain_context, &policy, &status) != FALSE) {
        trusted = status.dwError == 0;
        detail = trusted ? "Trusted by Windows' certificate store" : windows_trust_error_text(status.dwError);
      } else {
        detail = "Windows could not check the certificate chain";
      }
      CertFreeCertificateChain(chain_context);
    } else {
      detail = "Windows could not build the certificate chain";
    }
    CertFreeCertificateContext(leaf_context);
  }
  if (memory != nullptr)
    CertCloseStore(memory, 0);
  return trusted;
}
#else
// The peer's chain checked against the system's certificate store, as a TLS server, for the name
// asked for.
bool system_trusts_chain(SSL* ssl, const std::string& server_name, std::string& detail) {
  X509* leaf = SSL_get1_peer_certificate(ssl);
  if (leaf == nullptr) {
    detail = "The server sent no certificate";
    return false;
  }
  bool trusted = false;
  X509_STORE* store = X509_STORE_new();
  X509_STORE_CTX* context = X509_STORE_CTX_new();
  if (store != nullptr && context != nullptr && X509_STORE_set_default_paths(store) == 1 &&
      X509_STORE_CTX_init(context, store, leaf, SSL_get_peer_cert_chain(ssl)) == 1) {
    X509_VERIFY_PARAM* parameters = X509_STORE_CTX_get0_param(context);
    X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_SSL_SERVER);
    in6_addr ip6{};
    in_addr ip4{};
    if (inet_pton(AF_INET, server_name.c_str(), &ip4) == 1 || inet_pton(AF_INET6, server_name.c_str(), &ip6) == 1)
      X509_VERIFY_PARAM_set1_ip_asc(parameters, server_name.c_str());
    else
      X509_VERIFY_PARAM_set1_host(parameters, server_name.c_str(), server_name.size());
    trusted = X509_verify_cert(context) == 1;
    detail = trusted ? "Trusted by the system's certificate store"
                     : X509_verify_cert_error_string(X509_STORE_CTX_get_error(context));
  } else {
    detail = "The system's certificate store could not be read";
  }
  X509_STORE_CTX_free(context);
  X509_STORE_free(store);
  X509_free(leaf);
  return trusted;
}
#endif

bool is_address_literal(const std::string& name) {
  in6_addr ip6{};
  in_addr ip4{};
  return inet_pton(AF_INET, name.c_str(), &ip4) == 1 || inet_pton(AF_INET6, name.c_str(), &ip6) == 1;
}

// The certificates in a file the engineer chose: PEM, one or more, or a single DER certificate.
std::vector<X509*> read_certificates(const std::string& contents) {
  std::vector<X509*> certificates;
  if (contents.empty() || contents.size() > 4U * 1024U * 1024U)
    return certificates;
  if (BIO* bio = BIO_new_mem_buf(contents.data(), static_cast<int>(contents.size()))) {
    while (X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr))
      certificates.push_back(certificate);
    BIO_free(bio);
  }
  ERR_clear_error(); // the end of the PEM data is reported as an error
  if (certificates.empty()) {
    const auto* data = reinterpret_cast<const unsigned char*>(contents.data());
    if (X509* certificate = d2i_X509(nullptr, &data, static_cast<long>(contents.size())))
      certificates.push_back(certificate);
    ERR_clear_error();
  }
  return certificates;
}

// The peer's chain checked against the certificates in a file: the server's own certificate, or a CA
// that issued it (an intermediate in the file counts), as a TLS server, for the name asked for.
bool file_trusts_chain(SSL* ssl, const std::string& server_name, const std::string& contents, std::string& detail) {
  std::vector<X509*> certificates = read_certificates(contents);
  if (certificates.empty()) {
    detail = "the file holds no certificate SAT can read (PEM or DER)";
    return false;
  }
  bool trusted = false;
  X509* leaf = SSL_get1_peer_certificate(ssl);
  if (leaf == nullptr) {
    detail = "the server sent no certificate";
  } else {
    for (X509* certificate : certificates) {
      if (X509_cmp(certificate, leaf) == 0) {
        trusted = true;
        detail = "the server's own certificate is in the file";
        break;
      }
    }
    if (!trusted) {
      X509_STORE* store = X509_STORE_new();
      X509_STORE_CTX* context = X509_STORE_CTX_new();
      if (store != nullptr && context != nullptr) {
        for (X509* certificate : certificates)
          X509_STORE_add_cert(store, certificate);
        if (X509_STORE_CTX_init(context, store, leaf, SSL_get_peer_cert_chain(ssl)) == 1) {
          X509_VERIFY_PARAM* parameters = X509_STORE_CTX_get0_param(context);
          X509_VERIFY_PARAM_set_purpose(parameters, X509_PURPOSE_SSL_SERVER);
          X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_PARTIAL_CHAIN);
          if (is_address_literal(server_name))
            X509_VERIFY_PARAM_set1_ip_asc(parameters, server_name.c_str());
          else
            X509_VERIFY_PARAM_set1_host(parameters, server_name.c_str(), server_name.size());
          trusted = X509_verify_cert(context) == 1;
          detail = trusted ? "its chain leads to a certificate in the file"
                           : X509_verify_cert_error_string(X509_STORE_CTX_get_error(context));
        } else {
          detail = "the chain could not be checked against the file";
        }
      }
      X509_STORE_CTX_free(context);
      X509_STORE_free(store);
    }
    X509_free(leaf);
  }
  for (X509* certificate : certificates)
    X509_free(certificate);
  return trusted;
}

Error https_error(const std::string& name, std::string message) {
  return network_error("HTTPS request", name, std::move(message));
}

} // namespace

std::string HttpsResponse::header(std::string_view name) const {
  const std::string wanted = ascii_lower(std::string(name));
  for (const auto& [key, value] : headers) {
    if (key == wanted)
      return value;
  }
  return {};
}

Result<HttpsResponse> https_request(const HttpsRequest& request, const CancellationToken& cancel) {
  const std::string name = request.server_name.empty() ? request.host : request.server_name;
  if (request.host.empty() || request.port == 0)
    return Result<HttpsResponse>::failure(https_error(name, "A host and a port are required"));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<HttpsResponse>::failure(network_error(
        "initialize sockets", request.host, "Socket runtime initialization failed", runtime.error_code()));

  HttpsResponse output;
  const auto started = std::chrono::steady_clock::now();
  const auto deadline = started + request.timeout;
  std::string connected_address;
  auto connected = connect_tcp_socket(request.host, request.port, request.timeout, cancel, {}, connected_address);
  output.connect_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
  if (!connected.ok())
    return Result<HttpsResponse>::failure(connected.error());
  output.connected_address = connected_address;
  const SocketHandle socket = connected.value().get();

  SSL_CTX* raw_context = SSL_CTX_new(TLS_client_method());
  if (raw_context == nullptr)
    return Result<HttpsResponse>::failure(https_error(name, "SSL_CTX_new failed: " + openssl_error_text()));
  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(raw_context, SSL_CTX_free);
  SSL_CTX_set_min_proto_version(context.get(), TLS1_2_VERSION);
  // The chain is checked below by the system's own store, with the name asked for.
  SSL_CTX_set_verify(context.get(), SSL_VERIFY_NONE, nullptr);
  SSL* raw_ssl = SSL_new(context.get());
  if (raw_ssl == nullptr)
    return Result<HttpsResponse>::failure(https_error(name, "SSL_new failed: " + openssl_error_text()));
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(raw_ssl, SSL_free);
  if (!is_address_literal(name))
    static_cast<void>(SSL_set_tlsext_host_name(ssl.get(), name.c_str()));
  if (SSL_set_fd(ssl.get(), static_cast<int>(socket)) != 1)
    return Result<HttpsResponse>::failure(https_error(name, "SSL_set_fd failed: " + openssl_error_text()));

  // Waits for the socket while OpenSSL asks to read or write; false on a timeout or a stop.
  const auto wait_for = [&](int ssl_error) {
    if (cancel.is_cancelled() || std::chrono::steady_clock::now() >= deadline)
      return false;
    static_cast<void>(select_socket(socket, ssl_error == SSL_ERROR_WANT_READ, std::chrono::milliseconds(100)));
    return true;
  };

  const auto tls_started = std::chrono::steady_clock::now();
  ERR_clear_error();
  while (true) {
    const int result = SSL_connect(ssl.get());
    if (result == 1)
      break;
    const int ssl_error = SSL_get_error(ssl.get(), result);
    if ((ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) && wait_for(ssl_error))
      continue;
    std::string reason = openssl_error_text();
    if (cancel.is_cancelled())
      reason = "Operation cancelled";
    else if (reason.empty())
      reason = std::chrono::steady_clock::now() >= deadline ? "timed out"
                                                            : "OpenSSL error " + std::to_string(ssl_error);
    return Result<HttpsResponse>::failure(https_error(name, "The TLS handshake did not complete: " + reason));
  }
  output.tls_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - tls_started).count();
  if (const char* version = SSL_get_version(ssl.get()))
    output.tls_version = version;

  TlsProbeOptions probe;
  probe.host = request.host;
  probe.server_name = name;
  probe.check_system_trust = false;
  probe.expected_fingerprint = request.pinned_sha256;
  output.certificate = inspect_peer_certificate(ssl.get(), probe);
  output.name_matches = output.certificate.hostname_matches;
  if (is_address_literal(name)) {
    X509* leaf = SSL_get1_peer_certificate(ssl.get());
    output.name_matches = leaf != nullptr && X509_check_ip_asc(leaf, name.c_str(), 0) == 1;
    X509_free(leaf);
  }
  const bool system_trusted = system_trusts_chain(ssl.get(), name, output.trust_detail);
  output.certificate.system_trust_checked = true;
  output.certificate.system_trusted = system_trusted;
  output.certificate.system_trust_detail = output.trust_detail;
  output.pinned = !request.pinned_sha256.empty() && output.certificate.expected_fingerprint_matches;
  std::string file_detail;
  if (!request.trusted_certificates.empty())
    output.file_trusted = file_trusts_chain(ssl.get(), name, request.trusted_certificates, file_detail);
  output.trusted = system_trusted || output.pinned || output.file_trusted;
  if (output.file_trusted && !system_trusted)
    output.trust_detail =
        "Trusted by the certificate file chosen (" + file_detail + "); not by this machine's store: " + output.trust_detail;
  else if (output.pinned && !system_trusted)
    output.trust_detail = "Accepted by its fingerprint for this session; not by this machine's store: " + output.trust_detail;
  else if (!request.trusted_certificates.empty() && !system_trusted)
    output.trust_detail += "; nor by the certificate file chosen: " + file_detail;
  if (request.handshake_only) {
    static_cast<void>(SSL_shutdown(ssl.get()));
    return Result<HttpsResponse>::success(std::move(output));
  }
  if (!output.trusted)
    return Result<HttpsResponse>::failure(https_error(
        name, "The certificate is not trusted (" + output.trust_detail +
                  "). A request needs a trusted certificate: by this machine's certificate store, by a certificate "
                  "file chosen, or by its SHA-256 fingerprint accepted for the session."));

  // The request.
  std::string host_header = name.find(':') != std::string::npos ? "[" + name + "]" : name;
  if (request.port != 443)
    host_header += ":" + std::to_string(request.port);
  std::string text = request.method + " " + request.target + " HTTP/1.1\r\nHost: " + host_header + "\r\n";
  for (const auto& [key, value] : request.headers)
    text += key + ": " + value + "\r\n";
  text += "User-Agent: SupportAssistTool\r\nConnection: close\r\n\r\n";
  const auto request_started = std::chrono::steady_clock::now();
  std::size_t written = 0;
  while (written < text.size()) {
    const int result = SSL_write(ssl.get(), text.data() + written, static_cast<int>(text.size() - written));
    if (result > 0) {
      written += static_cast<std::size_t>(result);
      continue;
    }
    const int ssl_error = SSL_get_error(ssl.get(), result);
    if ((ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) && wait_for(ssl_error))
      continue;
    return Result<HttpsResponse>::failure(https_error(name, "The request could not be sent: " + openssl_error_text()));
  }
  output.request_sent = true;

  // The response: headers, then the body by its length, its chunks or the end of the connection.
  std::string raw;
  const std::size_t limit = request.max_body_bytes + 64U * 1024U;
  bool closed = false;
  std::size_t header_end = std::string::npos;
  std::optional<std::size_t> content_length;
  bool chunked = false;
  const auto complete = [&]() {
    if (header_end == std::string::npos)
      return false;
    const std::size_t body = raw.size() - (header_end + 4U);
    if (request.method == "HEAD" || output.status == 204 || output.status == 304)
      return true;
    if (content_length)
      return body >= *content_length;
    if (chunked)
      return raw.size() >= 5U && raw.compare(raw.size() - 5U, 5U, "0\r\n\r\n") == 0;
    return false;
  };
  char buffer[16384];
  while (!closed && !complete() && raw.size() < limit) {
    const int got = SSL_read(ssl.get(), buffer, static_cast<int>(sizeof(buffer)));
    if (got > 0) {
      raw.append(buffer, static_cast<std::size_t>(got));
      output.bytes_received += static_cast<std::uint64_t>(got);
      if (header_end == std::string::npos) {
        header_end = raw.find("\r\n\r\n");
        if (header_end != std::string::npos) {
          const auto lines = split(raw.substr(0, header_end), '\n');
          if (!lines.empty()) {
            const auto status_parts = split(trim(lines.front()), ' ');
            if (status_parts.size() >= 2U)
              output.status = std::atoi(status_parts[1].c_str());
          }
          for (std::size_t index = 1; index < lines.size(); ++index) {
            const std::string line = trim(lines[index]);
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos)
              continue;
            output.headers.emplace_back(ascii_lower(trim(line.substr(0, colon))), trim(line.substr(colon + 1U)));
          }
          const std::string length = output.header("content-length");
          if (!length.empty())
            content_length = static_cast<std::size_t>(std::strtoull(length.c_str(), nullptr, 10));
          chunked = ascii_lower(output.header("transfer-encoding")).find("chunked") != std::string::npos;
        }
      }
      continue;
    }
    const int ssl_error = SSL_get_error(ssl.get(), got);
    if (ssl_error == SSL_ERROR_ZERO_RETURN || (ssl_error == SSL_ERROR_SYSCALL && ERR_peek_error() == 0)) {
      closed = true;
      break;
    }
    if ((ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) && wait_for(ssl_error))
      continue;
    if (header_end != std::string::npos)
      break;
    return Result<HttpsResponse>::failure(https_error(
        name, cancel.is_cancelled() ? "Operation cancelled" : "No answer to the request: " + openssl_error_text()));
  }
  output.request_ms =
      std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - request_started).count();
  if (header_end == std::string::npos)
    return Result<HttpsResponse>::failure(https_error(name, "The answer had no complete HTTP headers"));

  std::string body = raw.substr(header_end + 4U);
  if (chunked) {
    std::string decoded;
    std::size_t at = 0;
    while (at < body.size()) {
      const std::size_t line_end = body.find("\r\n", at);
      if (line_end == std::string::npos)
        break;
      const std::size_t size = static_cast<std::size_t>(std::strtoull(body.substr(at, line_end - at).c_str(), nullptr, 16));
      if (size == 0U)
        break;
      decoded += body.substr(line_end + 2U, size);
      at = line_end + 2U + size + 2U;
    }
    body = std::move(decoded);
  } else if (content_length && body.size() > *content_length) {
    body.resize(*content_length);
  }
  if (body.size() > request.max_body_bytes) {
    body.resize(request.max_body_bytes);
    output.body_truncated = true;
  }
  output.body = std::move(body);
  static_cast<void>(SSL_shutdown(ssl.get()));
  return Result<HttpsResponse>::success(std::move(output));
}

std::string describe_listener_connection(const TcpAcceptedConnection& connection) {
  if (connection.sat_throughput) {
    if (!connection.sat_payload_validated)
      return "Throughput test, " + describe_payload_size(connection.sat_payload_bytes) + " not completed";
    char seconds[32] = {};
    std::snprintf(seconds, sizeof(seconds), "%.1f s", connection.sat_payload_seconds);
    return "Throughput test, " + describe_payload_size(connection.sat_payload_bytes) + " in " + seconds + " (" +
           format_transfer_rate(rate_for(connection.sat_payload_bytes, connection.sat_payload_seconds)) + ")";
  }
  if (connection.sat_probe)
    return "SAT probe, test " + connection.sat_test_id;
  return "Connection";
}

Result<TransferTestResult> run_transfer_test(const TransferTestOptions& options, const CancellationToken& cancel,
                                             ProgressCallback progress) {
  if (options.host.empty() || options.port == 0)
    return Result<TransferTestResult>::failure(
        network_error("File transfer test", options.host, "Enter the other machine's name or address and the port."));
  if (options.bytes < 1024ULL * 1024ULL || options.bytes > kTransferTestMaxBytes)
    return Result<TransferTestResult>::failure(
        network_error("File transfer test", options.host, "The test sends from 1 MiB to 8 GiB."));
  SocketRuntime runtime;
  if (!runtime.ok())
    return Result<TransferTestResult>::failure(network_error(
        "initialize sockets", options.host, "Socket runtime initialization failed", runtime.error_code()));

  TransferTestResult output;
  output.host = options.host;
  std::string address;
  auto connected = connect_tcp_socket(options.host, options.port, options.connect_timeout, cancel, progress, address);
  if (!connected.ok())
    return Result<TransferTestResult>::failure(connected.error());
  SocketOwner socket = std::move(connected.value());
  output.ipv6 = address.find(':') != std::string::npos;
  output.peer_address = (output.ipv6 ? "[" + address + "]" : address) + ":" + std::to_string(options.port);
  const std::string peer = output.peer_address;

  // A SAT listener speaks first; Network Tools' throughput server waits for the request.
  bool listener = false;
  const int greeting = select_socket(socket.get(), true, std::chrono::milliseconds(1500));
  if (greeting > 0) {
    auto hello = receive_protocol_line(socket.get(), std::chrono::seconds(2), cancel, "File transfer test", peer, true);
    if (!hello.ok())
      return Result<TransferTestResult>::failure(hello.error());
    listener = hello.value().rfind("SAT-CONNECT/2 HELLO ", 0) == 0;
    if (!listener)
      return Result<TransferTestResult>::failure(network_error(
          "File transfer test", peer,
          hello.value().empty() ? std::string("The service on that port closed the connection: it is not SAT's listener.")
                                : "The service on that port is not SAT's listener. It answered: " + hello.value()));
  }
  output.answered_by = listener ? "SAT listener" : "SAT throughput server";
  auto sent_request = send_control_text(socket.get(), "SAT-THROUGHPUT/1 SEND " + std::to_string(options.bytes) + "\n",
                                        options.connect_timeout, cancel, peer);
  if (!sent_request.ok())
    return Result<TransferTestResult>::failure(sent_request.error());
  auto answer = receive_protocol_line(socket.get(), options.connect_timeout, cancel, "File transfer test", peer, true);
  if (!answer.ok())
    return Result<TransferTestResult>::failure(answer.error());
  auto accepted = parse_throughput_ack(answer.value());
  if (!accepted.ok() || accepted.value() != options.bytes) {
    if (listener)
      return Result<TransferTestResult>::failure(network_error(
          "File transfer test", peer,
          answer.value().rfind("SAT-THROUGHPUT/1 ERR", 0) == 0
              ? std::string("The listener refused the size: send less.")
              : std::string("The listener there is an older SAT, without the throughput test. Start the listener "
                            "from this SAT on that machine, or choose iPerf3.")));
    return Result<TransferTestResult>::failure(network_error(
        "File transfer test", peer, "Nothing on that port answered SAT's throughput test. Start SAT's listener there first."));
  }

  std::vector<char> buffer(256U * 1024U);
  for (std::size_t index = 0; index < buffer.size(); ++index)
    buffer[index] = static_cast<char>(index & 0xFFU);
  const auto started = std::chrono::steady_clock::now();
  auto last_activity = started;
  while (output.bytes < options.bytes) {
    if (cancel.is_cancelled()) {
      output.cancelled = true;
      return Result<TransferTestResult>::success(std::move(output));
    }
    if (std::chrono::steady_clock::now() - last_activity >= options.idle_timeout)
      return Result<TransferTestResult>::failure(
          network_error("File transfer test", peer, "The transfer stopped moving for 30 seconds."));
    const int writable = select_socket(socket.get(), false, std::chrono::milliseconds(100));
    if (writable < 0)
      return Result<TransferTestResult>::failure(
          network_error("File transfer test", peer, "select() failed", last_socket_error()));
    if (writable == 0)
      continue;
    const std::size_t count = static_cast<std::size_t>(
        std::min<std::uint64_t>(options.bytes - output.bytes, static_cast<std::uint64_t>(buffer.size())));
#ifdef _WIN32
    const int sent = send(socket.get(), buffer.data(), static_cast<int>(count), 0);
#else
    const ssize_t sent = send(socket.get(), buffer.data(), count, kSendFlags);
#endif
    if (sent > 0) {
      output.bytes += static_cast<std::uint64_t>(sent);
      last_activity = std::chrono::steady_clock::now();
      report(progress, "Sending", peer, output.bytes);
      continue;
    }
    const int code = last_socket_error();
    if (sent == 0 || !would_block(code))
      return Result<TransferTestResult>::failure(network_error("File transfer test", peer, "send() failed", code));
  }
  // The clock stops when the other end has every byte: its DONE line, or its close.
  auto done = receive_protocol_line(socket.get(), options.idle_timeout, cancel, "File transfer test", peer, true);
  if (!done.ok() && cancel.is_cancelled()) {
    output.cancelled = true;
    return Result<TransferTestResult>::success(std::move(output));
  }
  if (!done.ok())
    return Result<TransferTestResult>::failure(done.error());
  output.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  output.bytes_per_second = output.seconds > 0.0 ? static_cast<double>(output.bytes) / output.seconds : 0.0;
  return Result<TransferTestResult>::success(std::move(output));
}

namespace {

#if defined(__linux__)
std::string read_sys_line(const std::filesystem::path& path) {
  std::ifstream input(path);
  std::string line;
  std::getline(input, line);
  return trim(line);
}

std::uint64_t read_sys_number(const std::filesystem::path& path) {
  const std::string text = read_sys_line(path);
  std::uint64_t value = 0;
  const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
  return parsed.ec == std::errc() ? value : 0U;
}
#endif

std::string link_text(std::uint64_t bits_per_second) {
  if (bits_per_second == 0U)
    return "speed not reported";
  char text[32] = {};
  if (bits_per_second >= 1000000000ULL)
    std::snprintf(text, sizeof(text), "%g Gb/s", static_cast<double>(bits_per_second) / 1e9);
  else
    std::snprintf(text, sizeof(text), "%g Mb/s", static_cast<double>(bits_per_second) / 1e6);
  return text;
}

} // namespace

std::string network_adapter_label(const NetworkAdapter& adapter) {
  std::string label = adapter.name + " \xC2\xB7 " +
                      (adapter.virtual_adapter && adapter.link_bits_per_second == 0U ? std::string("virtual")
                                                                                     : link_text(adapter.link_bits_per_second));
  if (adapter.mtu != 0U)
    label += " \xC2\xB7 MTU " + std::to_string(adapter.mtu);
  if (!adapter.addresses.empty())
    label += " \xC2\xB7 " + adapter.addresses.front();
  if (!adapter.up)
    label += " \xC2\xB7 down";
  return label;
}

Result<std::vector<NetworkAdapter>> list_network_adapters() {
  SocketRuntime runtime; // getnameinfo needs it on Windows
  if (!runtime.ok())
    return Result<std::vector<NetworkAdapter>>::failure(network_error(
        "list network adapters", {}, "Socket runtime initialization failed", runtime.error_code()));
  std::vector<NetworkAdapter> output;
#ifdef _WIN32
  ULONG size = 16U * 1024U;
  std::vector<unsigned char> buffer(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, adapters, &size);
  if (result == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr, adapters, &size);
  }
  if (result != NO_ERROR)
    return Result<std::vector<NetworkAdapter>>::failure(
        network_error("list network adapters", {}, "GetAdaptersAddresses failed", static_cast<std::int64_t>(result)));
  for (const IP_ADAPTER_ADDRESSES* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    NetworkAdapter item;
    item.name = adapter->FriendlyName == nullptr ? std::string(adapter->AdapterName == nullptr ? "adapter" : adapter->AdapterName)
                                                 : utf8_from_wide(adapter->FriendlyName);
    item.description = adapter->Description == nullptr ? std::string() : utf8_from_wide(adapter->Description);
    item.up = adapter->OperStatus == IfOperStatusUp;
    item.loopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    item.virtual_adapter = adapter->IfType == IF_TYPE_TUNNEL || name_contains(item.name, "vethernet") ||
                           name_contains(item.description, "virtual") || name_contains(item.description, "hyper-v") ||
                           name_contains(item.description, "vpn");
    item.mtu = adapter->Mtu == 0xFFFFFFFFUL ? 0U : static_cast<std::uint32_t>(adapter->Mtu);
    const ULONG64 speed = std::min(adapter->TransmitLinkSpeed, adapter->ReceiveLinkSpeed);
    item.link_bits_per_second = speed == static_cast<ULONG64>(-1) ? 0U : static_cast<std::uint64_t>(speed);
    for (const IP_ADAPTER_UNICAST_ADDRESS_LH* address = adapter->FirstUnicastAddress; address != nullptr;
         address = address->Next) {
      if (address->Address.lpSockaddr == nullptr)
        continue;
      const std::string text = endpoint_text(address->Address.lpSockaddr,
                                             static_cast<SocketLength>(address->Address.iSockaddrLength));
      if (text.empty() || text == "unknown")
        continue;
      // IPv4 first, then the addresses that are not link-local.
      if (address->Address.lpSockaddr->sa_family == AF_INET)
        item.addresses.insert(item.addresses.begin(), text);
      else if (!is_link_local_address(text))
        item.addresses.push_back(text);
    }
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = adapter->Luid;
    if (GetIfEntry2(&row) == NO_ERROR) {
      item.receive_errors = row.InErrors;
      item.send_errors = row.OutErrors;
      item.receive_discards = row.InDiscards;
      item.send_discards = row.OutDiscards;
    }
    output.push_back(std::move(item));
  }
#else
  ifaddrs* raw = nullptr;
  if (getifaddrs(&raw) != 0)
    return Result<std::vector<NetworkAdapter>>::failure(
        network_error("list network adapters", {}, "getifaddrs() failed", last_socket_error()));
  std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> interfaces(raw, freeifaddrs);
  for (const ifaddrs* current = interfaces.get(); current != nullptr; current = current->ifa_next) {
    if (current->ifa_name == nullptr)
      continue;
    auto found = std::find_if(output.begin(), output.end(),
                              [&](const NetworkAdapter& item) { return item.name == current->ifa_name; });
    if (found == output.end()) {
      NetworkAdapter item;
      item.name = current->ifa_name;
      item.up = (current->ifa_flags & IFF_UP) != 0 && (current->ifa_flags & IFF_RUNNING) != 0;
      item.loopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
      item.virtual_adapter = posix_virtual_interface(item.name);
#if defined(__linux__)
      const std::filesystem::path base = std::filesystem::path("/sys/class/net") / item.name;
      // speed is in Mb/s, and -1 or absent when the driver does not say.
      const std::string speed = read_sys_line(base / "speed");
      long long megabits = 0;
      const auto parsed = std::from_chars(speed.data(), speed.data() + speed.size(), megabits);
      if (parsed.ec == std::errc() && megabits > 0)
        item.link_bits_per_second = static_cast<std::uint64_t>(megabits) * 1000000ULL;
      item.mtu = static_cast<std::uint32_t>(read_sys_number(base / "mtu"));
      item.receive_errors = read_sys_number(base / "statistics" / "rx_errors");
      item.send_errors = read_sys_number(base / "statistics" / "tx_errors");
      item.receive_discards = read_sys_number(base / "statistics" / "rx_dropped");
      item.send_discards = read_sys_number(base / "statistics" / "tx_dropped");
      std::error_code ignored;
      const auto driver = std::filesystem::read_symlink(base / "device" / "driver", ignored);
      if (!ignored)
        item.description = driver.filename().string();
#endif
      output.push_back(std::move(item));
      found = output.end() - 1;
    }
    if (current->ifa_addr == nullptr ||
        (current->ifa_addr->sa_family != AF_INET && current->ifa_addr->sa_family != AF_INET6))
      continue;
    const std::string text = endpoint_text(current->ifa_addr, current->ifa_addr->sa_family == AF_INET
                                                                  ? static_cast<SocketLength>(sizeof(sockaddr_in))
                                                                  : static_cast<SocketLength>(sizeof(sockaddr_in6)));
    if (text.empty() || text == "unknown")
      continue;
    if (current->ifa_addr->sa_family == AF_INET)
      found->addresses.insert(found->addresses.begin(), text);
    else if (!is_link_local_address(text))
      found->addresses.push_back(text);
  }
#endif
  // Up adapters with an address first, the loopback last.
  std::stable_sort(output.begin(), output.end(), [](const NetworkAdapter& left, const NetworkAdapter& right) {
    const auto rank = [](const NetworkAdapter& item) {
      return item.loopback ? 3 : !item.up ? 2 : item.addresses.empty() || item.virtual_adapter ? 1 : 0;
    };
    return rank(left) < rank(right);
  });
  return Result<std::vector<NetworkAdapter>>::success(std::move(output));
}

} // namespace support_assist
