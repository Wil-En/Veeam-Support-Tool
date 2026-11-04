#pragma once

// The Veeam Service Channel test: the channel Veeam's own processes use to reach their service,
// tested in layers, stopping at the first that fails: the service that hosts the gRPC server, its
// named pipe, an HTTP/2 handshake on the pipe as the current user (preface, SETTINGS, PING), one
// standard gRPC health check on the same connection (grpc.health.v1.Health/Check, then GOAWAY), and
// the gRPC lines the product logged. The health check reads the service's state and changes nothing;
// no job or configuration is touched. The first four layers are Windows only; the logs are read from
// any log folder, on both editions. The products, pipe names, logs and line readings are data
// (config/checks/grpc.json).

#include "support_assist/cancellation.hpp"
#include "support_assist/progress.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct ServiceChannelProduct {
  std::string id;   // "agent", "vbr"
  std::string name;
  std::string service;
  std::string pipe; // empty when not known for the product
  std::string log_folder;
  std::vector<std::string> log_files; // name patterns with *
  std::string observed_on;
};

const std::vector<ServiceChannelProduct>& service_channel_products();

// The layers, in the order they are tested.
inline constexpr const char* kChannelService = "Service";
inline constexpr const char* kChannelPipe = "Named pipe";
inline constexpr const char* kChannelHandshake = "HTTP/2 handshake";
inline constexpr const char* kChannelHealth = "gRPC health";
inline constexpr const char* kChannelLogs = "Logs";

struct ServiceChannelRow {
  std::string layer;  // one of the layers above, or "Live test"
  std::string check;
  std::string detail;
  std::string status; // Pass, Fail, Attention, Info, Not applicable, Could not check
};

struct ServiceChannelOptions {
  std::string product = "agent";
  std::filesystem::path log_folder; // empty: the product's own folder
  int hours = 24;
  bool live = true;                 // the service, pipe, handshake and health check on this machine; false reads the logs only
};

struct ServiceChannelReport {
  std::vector<ServiceChannelRow> rows;
  std::string summary; // one plain sentence for the status line and a case note
};

// `progress` receives one event as each layer starts (Service, Named pipe, HTTP/2 handshake with
// the health call, Logs), for a live row per layer.
ServiceChannelReport run_service_channel_test(const ServiceChannelOptions& options, const CancellationToken& cancel,
                                              const ProgressCallback& progress = {});

// The Logs layer over log lines already read: one row per pattern found in the window, with its count, first
// and last time and the methods named in failed calls. now_seconds and the window are wall-clock
// seconds as the log's own timestamps read them ([dd.MM.yyyy HH:mm:ss]); hours 0 reads every line.
std::vector<ServiceChannelRow> read_service_channel_lines(const std::vector<std::string>& lines,
                                                          std::int64_t now_seconds, int hours);

// "[28.08.2026 15:00:52.123] ..." as seconds; 0 when the line does not start with a timestamp.
std::int64_t service_channel_line_time(std::string_view line);

// The parts of the health check that need no pipe: HTTP/2 framing, HPACK (RFC 7541), the health messages
// and the reading of the answer. They are declared here so the tests reach them.
namespace service_channel_detail {

inline constexpr const char* kHealthPath = "/grpc.health.v1.Health/Check";
inline constexpr const char* kHealthCheckName = "grpc.health.v1.Health/Check";

struct HeaderField {
  std::string name;
  std::string value;
};

// One HTTP/2 frame: the 9 byte header (length, type, flags, stream), then the payload.
std::string http2_frame(std::uint8_t type, std::uint8_t flags, std::string_view payload, std::uint32_t stream = 0);

// The header block of a gRPC request: :method POST, :scheme http, :path, :authority, content-type
// application/grpc, te trailers and grpc-timeout. Every string is literal (no Huffman coding) and no field
// is added to the dynamic table.
std::string hpack_encode_request(std::string_view path, std::string_view authority, int timeout_ms);

// The health request on stream 1: a HEADERS frame (END_HEADERS) and a DATA frame (END_STREAM) holding the
// 5 byte gRPC prefix of an empty HealthCheckRequest, which asks for the server's overall state.
std::string health_request(int timeout_ms);

// The bytes of a Huffman-coded string (RFC 7541 Appendix B); nothing when the code or its padding is not valid.
std::optional<std::string> huffman_decode(std::string_view bytes);

// An HPACK decoder with its dynamic table (RFC 7541), one per connection.
class HpackDecoder {
public:
  explicit HpackDecoder(std::size_t table_limit = 4096U) : limit_(table_limit), max_(table_limit) {}

  // Decodes one complete header block and appends its fields. Returns an empty text on success, else why
  // the block could not be decoded; the fields of a block that fails are not appended.
  std::string decode(std::string_view block, std::vector<HeaderField>& fields);

  std::size_t table_entries() const { return table_.size(); }
  std::size_t table_bytes() const { return bytes_; }
  // Entry 0 is the newest.
  const HeaderField& table_entry(std::size_t index) const { return table_[index]; }

private:
  bool lookup(std::size_t index, HeaderField& field) const;
  void insert(HeaderField field);
  void shrink(std::size_t target);

  std::deque<HeaderField> table_;
  std::size_t bytes_ = 0;
  std::size_t limit_;
  std::size_t max_;
};

// The header block of a HEADERS or CONTINUATION frame without its padding and priority fields.
bool headers_fragment(std::uint8_t flags, std::string_view payload, std::string_view& fragment);

struct HealthMessage {
  bool ok = false;
  int status = 0;     // 0 UNKNOWN, 1 SERVING, 2 NOT_SERVING, 3 SERVICE_UNKNOWN
  std::string error;  // why the message could not be read
};

// The DATA payload of a health answer: the gRPC message prefix (a compression flag and a 4 byte big-endian
// length) and a HealthCheckResponse whose field 1 is the status. A message without the field reads UNKNOWN.
HealthMessage parse_health_response(std::string_view data);

// What came back on stream 1.
struct HealthExchange {
  std::string data;                  // the DATA payload, in order
  std::vector<HeaderField> headers;  // the decoded header fields, in order
  std::string header_error;          // why a header block could not be decoded
  bool stream_ended = false;
  bool timed_out = false;
  bool pipe_closed = false;
  bool reset = false;                // RST_STREAM
  bool goaway = false;
  std::uint32_t error_code = 0;      // of the RST_STREAM or GOAWAY
  std::string failure;               // anything else that stopped the exchange
  int timeout_seconds = 5;
};

// The frames of an answer, one at a time. accept() returns the frames to send back (SETTINGS and PING
// acknowledgements).
class HealthCall {
public:
  std::string accept(std::uint8_t type, std::uint8_t flags, std::uint32_t stream, std::string_view payload);
  bool finished() const { return finished_; }
  HealthExchange& exchange() { return exchange_; }

private:
  void header_block_complete();

  HealthExchange exchange_;
  HpackDecoder decoder_;
  std::string block_;
  bool collecting_ = false;
  bool block_ends_stream_ = false;
  bool decoding_failed_ = false;
  bool finished_ = false;
};

struct HealthReading {
  std::string detail;
  std::string status; // Pass, Fail, Attention, Info
};

// The row for what came back: SERVING Pass, NOT_SERVING Fail, UNIMPLEMENTED Info, anything else Attention.
HealthReading read_health_exchange(const HealthExchange& exchange);

} // namespace service_channel_detail

} // namespace support_assist
