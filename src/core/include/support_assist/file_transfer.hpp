#pragma once

// The File Transfer Calculator: how long a transfer takes over a network link, worked out one step at
// a time. Arithmetic on the figures given; the adapters and the network test are in network.hpp.
//
// Link speeds are decimal bits (10 Gb/s = 10,000,000,000 bits per second). Sizes and rates are shown
// as Windows counts them: 1 MB = 1,048,576 bytes, 1 TB = 1,024 GB.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

inline constexpr double kTransferMiB = 1024.0 * 1024.0;
inline constexpr double kTransferGiB = kTransferMiB * 1024.0;
inline constexpr double kTransferTiB = kTransferGiB * 1024.0;
inline constexpr double kTransferPiB = kTransferTiB * 1024.0;

// The units the calculator's size takes, as Windows counts them; TB is the one chosen first.
inline constexpr const char* kTransferSizeUnits[] = {"MB", "GB", "TB", "PB"};
inline constexpr int kTransferSizeUnitChosen = 2;

// Ethernet adds 38 bytes to each packet on the wire: its header 14, the frame check 4, the preamble 8
// and the gap between frames 12.
inline constexpr int kEthernetFrameBytes = 38;
inline constexpr int kStandardMtu = 1500;
inline constexpr int kJumboMtu = 9000;

enum class TransferIp { ipv4, ipv6 };

// A speed the time can be set by: the link for data, the network's speed and the storage's, typed in
// (Manual) or measured (Live test).
struct TransferSpeed {
  std::string name;   // "Network test to repo01"
  std::string detail; // "SAT listener, one connection"
  double bytes_per_second = 0.0;
  std::string phrase; // in a sentence: "the network test to repo01", "the storage's write speed"
};

struct TransferInputs {
  double size_bytes = 0.0;
  double link_bits_per_second = 0.0;
  int mtu = kStandardMtu;
  TransferIp ip = TransferIp::ipv4;
  bool tcp_timestamps = false;
  double share_percent = 100.0;      // the share of the link this transfer gets
  double reduced_to_percent = 100.0; // the share of the data left to send after Veeam's reduction
  // Manual: the speeds the live test would measure, typed in. Each sets the time when it is the lowest.
  std::optional<double> network_bytes_per_second;
  std::optional<double> storage_bytes_per_second;
  std::string link_name;                         // the adapter the link speed came from, if any
  std::vector<TransferSpeed> measured;           // a network test, a storage result
};

struct TransferRow {
  std::string label;
  std::string value;
};

struct TransferSpeedRow {
  TransferSpeed speed;
  double seconds = 0.0;
  bool lowest = false;
};

struct TransferEstimate {
  TransferInputs inputs;
  double line_bytes_per_second = 0.0; // the link in bytes
  double efficiency = 0.0;            // the share of the wire that carries data
  double data_bytes_per_second = 0.0; // the link for data, after overhead and the share
  double moved_bytes = 0.0;           // the size after the reduction
  double rate_bytes_per_second = 0.0; // the lowest speed, which sets the time
  double seconds = 0.0;
  std::optional<double> jumbo_seconds; // the time at MTU 9000, when the link sets the time
  std::vector<TransferSpeedRow> speeds;
  std::string lowest_name;
  std::string lowest_phrase; // the lowest speed in a sentence; empty when the link sets the time
  std::string headline;
  std::string summary;
  std::vector<TransferRow> simple;
  std::vector<TransferRow> steps;
  std::vector<TransferRow> other_sizes;
  std::string jumbo_note;
  std::vector<TransferRow> terms;
};

struct TransferEmail {
  std::string subject;
  std::string body;
};

// "20TB", "20 TB", "1.5T", "500 GB", or a number in default_unit ("TB", "GB").
Result<double> parse_data_size(std::string_view text, std::string_view default_unit = "TB");
// "10G", "10 Gb/s", "10Gbps", "2.5G", "1000M", "100 Mb/s", or a number in default_unit ("Gb/s").
Result<double> parse_link_speed(std::string_view text, std::string_view default_unit = "Gb/s");
// "520MB/s", "520 MB/s", "1.2 GB/s", "6 Gb/s", or a number in default_unit (MB/s).
Result<double> parse_byte_rate(std::string_view text, std::string_view default_unit = "MB/s");
// "1500", "9000", "Standard, 1500", "Jumbo, 9000": the MTU from 576 to 9216.
Result<int> parse_mtu(std::string_view text);
// "100", "60 %", "60%": from 1 to 100.
Result<double> parse_percent(std::string_view text, std::string_view what);

// The share of the wire that carries data: (MTU - IP and TCP headers) / (MTU + 38).
double packet_efficiency(int mtu, TransferIp ip = TransferIp::ipv4, bool tcp_timestamps = false);

Result<TransferEstimate> estimate_transfer(const TransferInputs& inputs);

std::string transfer_duration_text(double seconds);      // "5 h 9 min", "15 min", "under a minute"
std::string transfer_duration_words(double seconds);     // "5 hours 9 minutes"
std::string transfer_rate_text(double bytes_per_second); // "1,132 MB/s (1.11 GB/s)"
std::string transfer_rate_figure(double bytes_per_second);     // "1,132": the MB/s, for a speed field
std::string transfer_size_text(double bytes);            // "20 TB", "1.5 TB", "500 GB"
std::string link_speed_text(double bits_per_second);     // "10 Gb/s", "2.5 Gb/s", "100 Mb/s"

// A storage figure from a saved Disk Speed Test result.json: the write speed for a repository (the
// data lands there), the read speed for a source, and for any other test the slower it measured.
Result<TransferSpeed> storage_speed_from_result(std::string_view json_text);

// The network test's fallback: iPerf3 as a client to an iPerf3 server the engineer started on the
// other machine, with -J, read as the bits per second that server received.
struct IperfTransferOptions {
  std::string host;
  std::uint16_t port = 5201;
  int streams = 1;
  int seconds = 10;
  std::filesystem::path tools_folder; // where SAT keeps iperf3; the PATH is searched as well on Linux
};

Result<TransferSpeed> iperf3_speed_from_json(std::string_view json_text, std::string_view host, int streams);
Result<TransferSpeed> run_iperf3_transfer_test(const IperfTransferOptions& options, const CancellationToken& cancel);

TransferEmail transfer_email(const TransferEstimate& estimate);
// The estimate as plain text, for the CLI and Copy.
std::string transfer_text(const TransferEstimate& estimate);

} // namespace support_assist
