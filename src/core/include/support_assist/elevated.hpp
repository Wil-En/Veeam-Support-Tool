#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/support_tools.hpp"
#include "support_assist/universal_collection.hpp"
#include "support_assist/vss.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct ElevatedVssResult {
  VssSessionDetails details;
  bool backup_succeeded = false;
  std::string diagnostic_message;
};

Result<ElevatedVssResult> run_vss_test_elevated(const VssTestOptions& options,
                                                const CancellationToken& cancel,
                                                ProgressCallback progress);
Result<std::vector<VssWriterInfo>> run_vss_writer_health_elevated(
    const CancellationToken& cancel,
    ProgressCallback progress);

// Packet capture's start and stop in the elevated helper, for a SAT that is not elevated: one
// administrator prompt each. Stop also writes the .pcapng and the .txt beside the ETL with Windows'
// own pktmon; the caller converts with etl2pcapng from the Tools folder only when one is missing.
Result<PacketCaptureSession> packet_capture_start_owned_elevated(const PacketCaptureOptions& options,
                                                                 const std::filesystem::path& state_directory,
                                                                 const CancellationToken& cancel,
                                                                 ProgressCallback progress = {});
Result<ProcessResult> packet_capture_stop_owned_elevated(PacketCaptureSession& session,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress = {});

// A Universal Log Collection run by the elevated helper: the same collection the window runs, its
// progress through `progress` as it goes, and the result as the rows the window shows.
struct ElevatedCollectionResult {
  std::vector<std::array<std::string, 4>> rows;
  std::filesystem::path result_path;
};
Result<ElevatedCollectionResult> run_universal_collection_elevated(const UniversalCollectionOptions& options,
                                                                   const CancellationToken& cancel,
                                                                   ProgressCallback progress = {});

// A System Differences files capture taken by the elevated helper, for a SAT that is not elevated:
// the same capture, with administrator rights, so it reads the folder from the NTFS master file
// table and records the change journal. Windows asks for approval first; declining fails with
// native_code ERROR_CANCELLED (1223). The helper writes the capture file; progress arrives as it goes.
Result<FilesystemBaselineResult> capture_filesystem_baseline_elevated(const std::filesystem::path& snapshot_path,
                                                                      const FilesystemScanOptions& options,
                                                                      const CancellationToken& cancel,
                                                                      ProgressCallback progress = {},
                                                                      std::string_view options_json = "{}");

// A SAT-owned packet capture while it runs: its counts every 5 seconds through `on_counts` (called on
// another thread), and its stop. Without administrator the elevated helper holds the capture, so the
// one approval at the start covers the stop. Dropped without stop(), the capture keeps running.
class PacketCaptureMonitor {
public:
  using CountsCallback = std::function<void(const std::string& counts)>;
  static Result<std::shared_ptr<PacketCaptureMonitor>> start(const PacketCaptureOptions& options,
                                                             const std::filesystem::path& state_directory,
                                                             CountsCallback on_counts,
                                                             const CancellationToken& cancel,
                                                             ProgressCallback progress = {});
  virtual ~PacketCaptureMonitor() = default;
  PacketCaptureMonitor() = default;
  PacketCaptureMonitor(const PacketCaptureMonitor&) = delete;
  PacketCaptureMonitor& operator=(const PacketCaptureMonitor&) = delete;
  [[nodiscard]] virtual PacketCaptureSession session() const = 0;
  [[nodiscard]] virtual std::string last_counts() const = 0;
  virtual Result<ProcessResult> stop(const CancellationToken& cancel, ProgressCallback progress = {}) = 0;
};

#ifdef _WIN32
namespace elevated_protocol {

constexpr std::uint32_t kMagic = 0x53534350U; // "SSCP"
constexpr std::uint32_t kProtocolVersion = 6;
constexpr std::uint32_t kCommandVssTest = 1;
constexpr std::uint32_t kCommandVssWriterHealth = 2;
constexpr std::uint32_t kCommandPacketCaptureStart = 3;
constexpr std::uint32_t kCommandPacketCaptureStop = 4;
constexpr std::uint32_t kCommandUniversalCollection = 5;
constexpr std::uint32_t kCommandFilesCapture = 6;
constexpr std::uint32_t kMaximumStringBytes = 1024U * 1024U;
constexpr std::uint32_t kMaximumVolumes = 64;
constexpr std::uint32_t kMaximumWriters = 512;

struct Request {
  std::string nonce;
  VssTestOptions options;
  bool writer_health_only = false;
  // Zero for the VSS commands (writer_health_only picks one); otherwise a packet capture command.
  std::uint32_t command = 0;
  // Packet capture: the ETL and the state folder to start, or the session's state file to stop.
  std::string capture_output;
  std::string capture_state;
  std::string capture_backend;
  std::string capture_ip_filter;
  std::uint32_t capture_port = 0;
  // Universal Log Collection: its options as encode_universal_options writes them.
  std::string collection_options;
  // A files capture: the folder, the capture file, the hash mode as to_string(HashMode) writes it,
  // the capture's options JSON and whether alternate data streams are recorded.
  std::string files_root;
  std::string files_output;
  std::string files_hash;
  std::string files_options_json;
  bool files_streams = false;
};

// UniversalCollectionOptions as "key=value" lines for the helper request, and back.
std::string encode_universal_options(const UniversalCollectionOptions& options);
UniversalCollectionOptions decode_universal_options(std::string_view text);
// Rows of four cells as text for the helper's answer: one row a line, cells separated by tabs (a tab
// or a line break inside a cell becomes a space); and back.
std::string encode_rows(const std::vector<std::array<std::string, 4>>& rows);
std::vector<std::array<std::string, 4>> decode_rows(std::string_view text);

struct Response {
  // Protocol v4 is framed: helpers may emit zero or more progress responses before
  // one final response. This keeps long VSS operations observable while the main
  // SAT process remains non-elevated.
  bool final = true;
  bool success = false;
  std::string phase;
  std::string current_scope;
  std::uint64_t current = 0;
  std::uint64_t total = 0;
  std::int64_t native_code = 0;
  std::int64_t hresult = 0;
  std::string message;
  ElevatedVssResult result;
};

Status write_request(void* handle, const Request& request);
Result<Request> read_request(void* handle);
Status write_response(void* handle, const Response& response);
Result<Response> read_response(void* handle);

} // namespace elevated_protocol
#endif

} // namespace support_assist
