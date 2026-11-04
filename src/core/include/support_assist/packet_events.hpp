#pragma once

// The notable events in a packet capture (.pcapng or .pcap), with their times: TCP retransmissions,
// duplicate ACKs, keep-alives, resets, zero windows, segments the capture is missing, and TLS
// (SCHANNEL) handshake messages and alerts. Not a full analyzer: TCP is followed in each direction
// from the headers alone, and TLS only where a record starts a segment. pktmon logs one packet once
// at every component it passes; those copies are counted once. The keep-alives of one connection
// direction are listed as one event. The event names, the TLS names and the limits are data
// (config/checks/packet-events.json).

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <istream>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {

enum class PacketEventKind {
  retransmission,
  fast_retransmission,
  spurious_retransmission,
  out_of_order,
  previous_segment_lost,
  duplicate_ack,
  keep_alive,
  reset,
  zero_window,
  tls_handshake,
  tls_alert,
};

inline constexpr std::size_t kPacketEventKinds = 11;

struct PacketEvent {
  std::int64_t time_micros = 0; // UTC, microseconds since 1970; for a keep-alive row the first probe's
  PacketEventKind kind = PacketEventKind::retransmission;
  std::string connection; // "10.0.0.5:52114 -> 10.0.0.9:9392", the packet's sender first
  std::string detail;     // a keep-alive row: the count and the times of the first and last probe
};

struct PacketEventReport {
  std::uint64_t packets = 0;       // records read
  std::uint64_t copies = 0;        // the same packet logged again at another component
  std::uint64_t tcp_packets = 0;   // after the copies
  std::uint64_t other_packets = 0; // not TCP over IPv4 or IPv6
  std::uint64_t connections = 0;
  std::int64_t first_micros = 0;
  std::int64_t last_micros = 0;
  std::array<std::uint64_t, kPacketEventKinds> counts{};
  std::uint64_t keep_alive_connections = 0; // connections that carried keep-alives
  std::uint64_t keep_alive_groups = 0;      // connection directions that sent keep-alives
  std::vector<PacketEvent> events; // in time order, at most events_shown_per_kind of each kind
  std::vector<std::string> warnings;
};

// The event's name and meaning from the data file ("Retransmission").
std::string packet_event_name(PacketEventKind kind);
std::string packet_event_meaning(PacketEventKind kind);

// "2026-10-14 12:00:01.123"
std::string packet_event_time(std::int64_t time_micros);

Result<PacketEventReport> analyze_packet_capture(const std::filesystem::path& capture,
                                                 const CancellationToken& cancel = {});
Result<PacketEventReport> analyze_packet_stream(std::istream& input, const CancellationToken& cancel = {});

// The report's summary as label and value pairs, shared by the CLI and the GUI: packets, the time
// span, connections and the count of each kind found.
std::vector<std::pair<std::string, std::string>> packet_event_summary(const PacketEventReport& report);

} // namespace support_assist
