// One UDP question and its answer, on a connected socket so that only the server asked can reply,
// and an ICMP "port unreachable" from it ends the wait at once.
#include "support_assist/udp_exchange.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#endif

#include <memory>

namespace support_assist {
namespace {

#ifdef _WIN32
using SocketHandle = SOCKET;
using SocketLength = int;
constexpr SocketHandle kNoSocket = INVALID_SOCKET;
void close_socket(SocketHandle handle) { closesocket(handle); }
int last_error() { return WSAGetLastError(); }
bool refused(int code) { return code == WSAECONNRESET || code == WSAECONNREFUSED; }
#else
using SocketHandle = int;
using SocketLength = socklen_t;
constexpr SocketHandle kNoSocket = -1;
void close_socket(SocketHandle handle) { close(handle); }
int last_error() { return errno; }
bool refused(int code) { return code == ECONNREFUSED; }
#endif

class Runtime {
public:
  Runtime() {
#ifdef _WIN32
    WSADATA data{};
    ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
#endif
  }
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  ~Runtime() {
#ifdef _WIN32
    if (ok_)
      WSACleanup();
#endif
  }
  [[nodiscard]] bool ok() const { return ok_; }

private:
  bool ok_ = true;
};

class Closer {
public:
  explicit Closer(SocketHandle handle) : handle_(handle) {}
  Closer(const Closer&) = delete;
  Closer& operator=(const Closer&) = delete;
  ~Closer() {
    if (handle_ != kNoSocket)
      close_socket(handle_);
  }

private:
  SocketHandle handle_;
};

} // namespace

UdpExchange udp_exchange(const std::string& host, std::uint16_t port, bool numeric_only,
                         const std::function<std::vector<std::uint8_t>()>& request,
                         const std::function<bool(const std::vector<std::uint8_t>&)>& accept,
                         std::chrono::milliseconds timeout) {
  UdpExchange exchange;
  Runtime runtime;
  if (!runtime.ok()) {
    exchange.error = "sockets could not be started";
    return exchange;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = numeric_only ? AI_NUMERICHOST : 0;
  addrinfo* raw = nullptr;
  const std::string service = std::to_string(port);
  if (getaddrinfo(host.c_str(), service.c_str(), &hints, &raw) != 0 || raw == nullptr) {
    exchange.error = numeric_only ? "\"" + host + "\" is not an IP address" : "\"" + host + "\" did not resolve";
    return exchange;
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> target(raw, freeaddrinfo);
  char numeric[NI_MAXHOST] = {};
  if (getnameinfo(target->ai_addr, static_cast<SocketLength>(target->ai_addrlen), numeric, sizeof(numeric), nullptr, 0,
                  NI_NUMERICHOST) == 0)
    exchange.address = numeric;

  const SocketHandle handle = socket(target->ai_family, SOCK_DGRAM, IPPROTO_UDP);
  if (handle == kNoSocket) {
    exchange.error = "a UDP socket could not be opened (error " + std::to_string(last_error()) + ")";
    return exchange;
  }
  Closer closer(handle);
  if (connect(handle, target->ai_addr, static_cast<SocketLength>(target->ai_addrlen)) != 0) {
    exchange.error = "no route to " + host + " (error " + std::to_string(last_error()) + ")";
    return exchange;
  }

  const std::vector<std::uint8_t> bytes = request();
  const auto started = std::chrono::steady_clock::now();
  const auto finish = [&]() {
    exchange.elapsed_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - started).count();
    return exchange;
  };
#ifdef _WIN32
  const int sent = send(handle, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
#else
  const ssize_t sent = send(handle, bytes.data(), bytes.size(), 0);
#endif
  if (sent < 0 || static_cast<std::size_t>(sent) != bytes.size()) {
    exchange.error = "the request could not be sent (error " + std::to_string(last_error()) + ")";
    return finish();
  }

  std::vector<std::uint8_t> buffer(4096);
  for (;;) {
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (elapsed >= timeout) {
      exchange.error = "no answer within " + std::to_string(timeout.count()) + " ms";
      return finish();
    }
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(timeout - elapsed).count();
    fd_set read_set;
    FD_ZERO(&read_set);
    FD_SET(handle, &read_set);
    timeval wait{};
    wait.tv_sec = static_cast<long>(remaining / 1000);
    wait.tv_usec = static_cast<long>((remaining % 1000) * 1000);
#ifdef _WIN32
    const int ready = select(0, &read_set, nullptr, nullptr, &wait);
#else
    const int ready = select(handle + 1, &read_set, nullptr, nullptr, &wait);
#endif
    if (ready == 0)
      continue;
    if (ready < 0) {
      exchange.error = "waiting for the answer failed (error " + std::to_string(last_error()) + ")";
      return finish();
    }
#ifdef _WIN32
    const int received = recv(handle, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
#else
    const ssize_t received = recv(handle, buffer.data(), buffer.size(), 0);
#endif
    const auto received_at = std::chrono::system_clock::now();
    if (received < 0) {
      const int code = last_error();
      exchange.error = refused(code) ? "nothing answers on " + host + " port " + service + " (port unreachable)"
                                     : "the answer could not be read (error " + std::to_string(code) + ")";
      return finish();
    }
    std::vector<std::uint8_t> response(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(received));
    if (accept(response)) {
      exchange.answered = true;
      exchange.received_at = received_at;
      exchange.response = std::move(response);
      return finish();
    }
  }
}

} // namespace support_assist
