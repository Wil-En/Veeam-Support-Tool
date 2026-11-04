#pragma once

// Quick scan: while the Local Port Checker's listener runs, the connection attempts that arrive at
// its port, counted in memory with no capture file (docs/PROPOSAL_5.x_CHECKS.md section 5.10,
// pairing 1). An attempt is a TCP SYN without ACK, or a UDP datagram, addressed to the port; a
// retransmission from the same source address and port counts once. The window compares the count
// with the connections the listener accepted: what arrived and never reached the listener was
// stopped on this machine.
//
// Windows reads Packet Monitor in its real-time mode (pktmon start --capture --log-mode real-time),
// which writes no file, with a pktmon filter on the port; the filter is SAT's only while the scan
// runs, and a scan does not start when other pktmon filters or a capture exist. Linux reads a packet
// socket filtered to the port in the kernel. Both need administrator or root.

#include "support_assist/error.hpp"
#include "support_assist/local_ports.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct QuickScanSupport {
  bool available = false;
  std::string reason; // why not, in a sentence, when not available
};

// Whether a scan can run here: the rights, and on Windows a pktmon with the real-time mode.
QuickScanSupport quick_scan_support();

struct QuickScanSource {
  std::string address;
  std::size_t attempts = 0;
};

inline constexpr std::size_t kQuickScanMaxSources = 20;

struct QuickScanCounts {
  std::size_t attempts = 0;             // connection attempts that arrived
  std::vector<QuickScanSource> sources; // up to kQuickScanMaxSources, most attempts first
  bool more_sources = false;            // attempts came from more addresses than are kept
  std::string note;                     // a reading problem, in a sentence; empty when none
};

class QuickScan {
public:
  // Starts counting attempts to `port`. Fails with the reason when quick_scan_support() says no,
  // or when the capture cannot start.
  static Result<std::unique_ptr<QuickScan>> start(std::uint16_t port, PortProtocol protocol);

  QuickScan(const QuickScan&) = delete;
  QuickScan& operator=(const QuickScan&) = delete;
  ~QuickScan();

  // The counts so far; safe from any thread.
  QuickScanCounts counts() const;
  // Ends the capture and, on Windows, removes SAT's pktmon filter. Safe to call more than once.
  void stop();

  struct Impl;

private:
  explicit QuickScan(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

namespace quick_scan_detail {

// One packet as a capture reports it.
struct Packet {
  std::string source;
  std::uint16_t source_port = 0;
  std::string destination;
  std::uint16_t destination_port = 0;
  bool tcp = false;
  bool syn = false;
  bool ack = false;
  bool inbound = true;
};

// The counter both captures feed: attempts by source address and port, sources ranked.
class AttemptCounter {
public:
  AttemptCounter(std::uint16_t port, PortProtocol protocol) : port_(port), protocol_(protocol) {}
  // Counts `packet` when it is an attempt to the port; returns whether it counted.
  bool add(const Packet& packet);
  QuickScanCounts counts() const;

private:
  std::uint16_t port_;
  PortProtocol protocol_;
  std::set<std::pair<std::string, std::uint16_t>> seen_;
  std::vector<QuickScanSource> sources_;
  std::size_t attempts_ = 0;
};

// pktmon's real-time text: a header line per packet appearance ("PktGroupId 1, PktNumber 1,
// Appearance 1, Direction Rx , ...") and the decoded packet under it ("10.0.4.21.51022 >
// 10.0.4.10.999: Flags [S], ..."). A packet appears once per component it passes, and on some
// machines each appearance has its own PktGroupId, so the reader counts a packet once by its group
// and number and by its decoded text seen again within a moment.
class PktmonReader {
public:
  // Feeds one line; returns a packet once when the line decodes one.
  std::optional<Packet> line(std::string_view text);

private:
  bool header_seen_ = false;
  bool inbound_ = true;
  std::string key_;
  std::set<std::string> seen_;
  // The current header's time of day in nanoseconds; -1 when it carries none.
  std::int64_t time_ns_ = -1;
  // Decoded packets seen in the last moment, and when.
  std::vector<std::pair<std::string, std::int64_t>> recent_;
  std::string last_identity_;
};

// Splits "10.0.4.21.51022" or "fe80::1.51022" into the address and the port.
std::optional<std::pair<std::string, std::uint16_t>> split_address_port(std::string_view text);

// An IPv4 or IPv6 packet from its network header on (a Linux packet socket's SOCK_DGRAM view).
std::optional<Packet> parse_ip_packet(const std::uint8_t* data, std::size_t size);

} // namespace quick_scan_detail

} // namespace support_assist
