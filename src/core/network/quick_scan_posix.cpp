// Quick scan on Linux: a packet socket per IP version, filtered in the kernel to the port (TCP SYN
// without ACK, or UDP), read on a worker. Packets leaving this machine are not counted. Needs root
// or CAP_NET_RAW. Other POSIX systems have no packet socket and report the scan as unavailable.

#include "support_assist/quick_scan.hpp"

#include <atomic>
#include <mutex>
#include <thread>

#ifdef __linux__
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace support_assist {
namespace {

Error scan_error(std::string message, bool elevation_may_help) {
  Error error;
  error.component = "Quick scan";
  error.operation = "start quick scan";
  error.message = std::move(message);
  error.elevation_may_help = elevation_may_help;
  return error;
}

} // namespace

#ifdef __linux__
namespace {

// The classic BPF programs, run on the packet from its network header on (SOCK_DGRAM).
std::vector<sock_filter> port_filter(bool ipv6, PortProtocol protocol, std::uint16_t port) {
  const auto op = [](std::uint16_t code, std::uint8_t jt, std::uint8_t jf, std::uint32_t k) {
    sock_filter instruction{};
    instruction.code = code;
    instruction.jt = jt;
    instruction.jf = jf;
    instruction.k = k;
    return instruction;
  };
  constexpr std::uint16_t ld_b = BPF_LD | BPF_B | BPF_ABS;
  constexpr std::uint16_t ld_h = BPF_LD | BPF_H | BPF_ABS;
  constexpr std::uint16_t ld_h_ind = BPF_LD | BPF_H | BPF_IND;
  constexpr std::uint16_t ld_b_ind = BPF_LD | BPF_B | BPF_IND;
  constexpr std::uint16_t ldx_msh = BPF_LDX | BPF_B | BPF_MSH;
  constexpr std::uint16_t jeq = BPF_JMP | BPF_JEQ | BPF_K;
  constexpr std::uint16_t jset = BPF_JMP | BPF_JSET | BPF_K;
  constexpr std::uint16_t and_k = BPF_ALU | BPF_AND | BPF_K;
  constexpr std::uint16_t ret = BPF_RET | BPF_K;
  constexpr std::uint32_t accept = 0x40000;
  const bool tcp = protocol == PortProtocol::tcp;
  if (!ipv6 && tcp) {
    return {op(ld_b, 0, 0, 9),        op(jeq, 0, 9, 6),         op(ld_h, 0, 0, 6),
            op(jset, 7, 0, 0x1FFF),   op(ldx_msh, 0, 0, 0),     op(ld_h_ind, 0, 0, 2),
            op(jeq, 0, 4, port),      op(ld_b_ind, 0, 0, 13),   op(and_k, 0, 0, 0x12),
            op(jeq, 0, 1, 0x02),      op(ret, 0, 0, accept),    op(ret, 0, 0, 0)};
  }
  if (!ipv6) {
    return {op(ld_b, 0, 0, 9),      op(jeq, 0, 6, 17),       op(ld_h, 0, 0, 6),
            op(jset, 4, 0, 0x1FFF), op(ldx_msh, 0, 0, 0),    op(ld_h_ind, 0, 0, 2),
            op(jeq, 0, 1, port),    op(ret, 0, 0, accept),   op(ret, 0, 0, 0)};
  }
  if (tcp) {
    return {op(ld_b, 0, 0, 6),     op(jeq, 0, 6, 6),      op(ld_h, 0, 0, 42),
            op(jeq, 0, 4, port),   op(ld_b, 0, 0, 53),    op(and_k, 0, 0, 0x12),
            op(jeq, 0, 1, 0x02),   op(ret, 0, 0, accept), op(ret, 0, 0, 0)};
  }
  return {op(ld_b, 0, 0, 6),   op(jeq, 0, 3, 17),     op(ld_h, 0, 0, 42),
          op(jeq, 0, 1, port), op(ret, 0, 0, accept), op(ret, 0, 0, 0)};
}

int open_packet_socket(bool ipv6, PortProtocol protocol, std::uint16_t port, std::string& error) {
  const int handle = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ipv6 ? ETH_P_IPV6 : ETH_P_IP));
  if (handle < 0) {
    error = std::strerror(errno);
    return -1;
  }
  std::vector<sock_filter> program = port_filter(ipv6, protocol, port);
  sock_fprog filter{};
  filter.len = static_cast<unsigned short>(program.size());
  filter.filter = program.data();
  if (setsockopt(handle, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) != 0) {
    error = std::strerror(errno);
    close(handle);
    return -1;
  }
  return handle;
}

} // namespace

struct QuickScan::Impl {
  quick_scan_detail::AttemptCounter counter;
  mutable std::mutex mutex;
  std::atomic<bool> stopping{false};
  int sockets[2] = {-1, -1};
  std::thread reader;

  Impl(std::uint16_t port, PortProtocol protocol) : counter(port, protocol) {}

  void run() {
    std::vector<std::uint8_t> buffer(65536);
    pollfd waits[2] = {};
    for (int index = 0; index < 2; ++index) {
      waits[index].fd = sockets[index];
      waits[index].events = POLLIN;
    }
    while (!stopping.load()) {
      if (poll(waits, 2, 200) <= 0)
        continue;
      for (const pollfd& wait : waits) {
        if ((wait.revents & POLLIN) == 0)
          continue;
        sockaddr_ll from{};
        socklen_t length = sizeof(from);
        const ssize_t received = recvfrom(wait.fd, buffer.data(), buffer.size(), MSG_DONTWAIT,
                                          reinterpret_cast<sockaddr*>(&from), &length);
        if (received <= 0)
          continue;
        auto packet = quick_scan_detail::parse_ip_packet(buffer.data(), static_cast<std::size_t>(received));
        if (!packet)
          continue;
        packet->inbound = from.sll_pkttype != PACKET_OUTGOING;
        std::scoped_lock lock(mutex);
        counter.add(*packet);
      }
    }
  }

  void close_all() {
    for (int& handle : sockets) {
      if (handle >= 0)
        close(handle);
      handle = -1;
    }
  }
};

QuickScanSupport quick_scan_support() {
  QuickScanSupport support;
  const int probe = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IP));
  if (probe < 0) {
    support.reason = errno == EPERM || errno == EACCES
                         ? "Quick scan needs SAT running as root: a packet capture on Linux needs root or the "
                           "CAP_NET_RAW capability."
                         : std::string("A packet socket could not be opened: ") + std::strerror(errno) + ".";
    return support;
  }
  close(probe);
  support.available = true;
  return support;
}

Result<std::unique_ptr<QuickScan>> QuickScan::start(std::uint16_t port, PortProtocol protocol) {
  const QuickScanSupport support = quick_scan_support();
  if (!support.available)
    return Result<std::unique_ptr<QuickScan>>::failure(scan_error(support.reason, true));
  auto impl = std::make_unique<Impl>(port, protocol);
  std::string reason;
  for (int index = 0; index < 2; ++index) {
    impl->sockets[index] = open_packet_socket(index == 1, protocol, port, reason);
    if (impl->sockets[index] < 0) {
      impl->close_all();
      return Result<std::unique_ptr<QuickScan>>::failure(
          scan_error("The packet socket could not be set up: " + reason + ".", false));
    }
  }
  Impl* raw = impl.get();
  impl->reader = std::thread([raw]() { raw->run(); });
  return Result<std::unique_ptr<QuickScan>>::success(std::unique_ptr<QuickScan>(new QuickScan(std::move(impl))));
}

QuickScanCounts QuickScan::counts() const {
  std::scoped_lock lock(impl_->mutex);
  return impl_->counter.counts();
}

void QuickScan::stop() {
  if (!impl_ || impl_->stopping.exchange(true))
    return;
  if (impl_->reader.joinable())
    impl_->reader.join();
  impl_->close_all();
}

#else

struct QuickScan::Impl {
  quick_scan_detail::AttemptCounter counter{0, PortProtocol::tcp};
};

QuickScanSupport quick_scan_support() {
  return {false, "Quick scan reads a packet socket, which this system does not have."};
}

Result<std::unique_ptr<QuickScan>> QuickScan::start(std::uint16_t, PortProtocol) {
  return Result<std::unique_ptr<QuickScan>>::failure(scan_error(quick_scan_support().reason, false));
}

QuickScanCounts QuickScan::counts() const { return impl_->counter.counts(); }

void QuickScan::stop() {}

#endif

QuickScan::QuickScan(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

QuickScan::~QuickScan() { stop(); }

} // namespace support_assist
