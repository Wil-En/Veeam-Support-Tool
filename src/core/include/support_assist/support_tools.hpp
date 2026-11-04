#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/process.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class PacketCaptureBackend { automatic, pktmon, netsh };

std::string to_string(PacketCaptureBackend backend);
Result<PacketCaptureBackend> parse_packet_capture_backend(std::string_view value);

struct PacketCaptureOptions {
  std::filesystem::path output_etl;
  std::optional<std::string> ip_filter;
  std::optional<std::uint16_t> port_filter;
  std::vector<std::string> custom_start_arguments;
  std::filesystem::path third_party_directory;
  PacketCaptureBackend backend = PacketCaptureBackend::automatic;
};

// SAT-owned capture state. Start resolves Auto once and persists that concrete
// backend. Status/stop must use this record instead of re-resolving Auto later.
struct PacketCaptureSession {
  std::string session_id;
  PacketCaptureBackend backend = PacketCaptureBackend::automatic;
  std::filesystem::path output_etl;
  std::filesystem::path state_path;
  std::string started_utc;
  std::string stopped_utc;
  std::optional<std::string> ip_filter;
  std::optional<std::uint16_t> port_filter;
  bool active = false;
  bool pktmon_filter_owned = false;
  std::string pktmon_filter_name;
  // Snapshot immediately after SAT added its filter. SAT removes the global
  // pktmon filter set only when the stop-time snapshot is unchanged.
  std::string pktmon_owned_filter_snapshot;
};

Status save_packet_capture_session(const PacketCaptureSession& session);
Result<PacketCaptureSession> load_packet_capture_session(const std::filesystem::path& state_path);

Result<PacketCaptureSession>
packet_capture_start_owned(const PacketCaptureOptions& options,
                           const std::filesystem::path& state_directory,
                           const CancellationToken& cancel,
                           ProgressCallback progress = {});
Result<ProcessResult> packet_capture_status_owned(const PacketCaptureSession& session,
                                                  const CancellationToken& cancel,
                                                  ProgressCallback progress = {});
Result<ProcessResult> packet_capture_stop_owned(PacketCaptureSession& session,
                                                const CancellationToken& cancel,
                                                ProgressCallback progress = {});

// Legacy stateless entry points remain for CLI/source compatibility. Auto is
// accepted for start only. Status/stop reject Auto because it cannot prove
// ownership of a running backend.
Result<ProcessResult> packet_capture_start(const PacketCaptureOptions& options,
                                           const CancellationToken& cancel,
                                           ProgressCallback progress = {});
Result<ProcessResult>
packet_capture_stop(const CancellationToken& cancel,
                    ProgressCallback progress = {},
                    PacketCaptureBackend backend = PacketCaptureBackend::automatic);
Result<ProcessResult>
packet_capture_status(const CancellationToken& cancel,
                      ProgressCallback progress = {},
                      PacketCaptureBackend backend = PacketCaptureBackend::automatic);
// A pktmon capture as text (one block per packet, its headers decoded) with Windows' own
// `pktmon etl2txt`. Windows only.
Result<ProcessResult> packet_capture_text(const std::filesystem::path& input_etl,
                                          const std::filesystem::path& output_text,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress = {});
Result<ProcessResult> convert_packet_capture(const std::filesystem::path& input_etl,
                                             const std::filesystem::path& output_pcapng,
                                             const std::filesystem::path& third_party_directory,
                                             const CancellationToken& cancel,
                                             ProgressCallback progress = {});
// The pktmon half of convert_packet_capture: Windows' own converter only, nothing from the Tools
// folder. Windows only.
Result<ProcessResult> convert_packet_capture_native(const std::filesystem::path& input_etl,
                                                    const std::filesystem::path& output_pcapng,
                                                    const CancellationToken& cancel,
                                                    ProgressCallback progress = {});

// pktmon's "filter list" names no filter: a "Packet Filters:" heading followed by "None", or a
// sentence on some builds.
bool pktmon_filter_list_empty(std::string_view text);

// `pktmon counters` summed per adapter (the highest count among each adapter's components):
// "Received 1,234 packets (2.1 MB), sent 980 packets (0.4 MB)". Empty when no counter row is read.
std::string pktmon_counters_summary(std::string_view counters_output);
// One line for a capture in progress: pktmon's counts when it gives them, and the capture file's
// size. Needs administrator for the counts. Windows only for the counts.
std::string packet_capture_progress_text(const PacketCaptureSession& session, const CancellationToken& cancel);

struct ProcmonOptions {
  std::filesystem::path output_pml;
  std::filesystem::path filter_file;
  std::vector<std::string> custom_arguments;
  std::filesystem::path third_party_directory;
};

struct ProcmonSession {
  std::string session_id;
  std::filesystem::path executable_path;
  std::filesystem::path output_pml;
  std::filesystem::path state_path;
  std::uint32_t process_id = 0;
  std::string started_utc;
  std::string stopped_utc;
  bool active = false;
};

Status save_procmon_session(const ProcmonSession& session);
Result<ProcmonSession> load_procmon_session(const std::filesystem::path& state_path);
Result<ProcmonSession> procmon_start_owned(const ProcmonOptions& options,
                                           const std::filesystem::path& state_directory);
Result<ProcessResult> procmon_status_owned(const ProcmonSession& session);
Result<ProcessResult> procmon_stop_owned(ProcmonSession& session,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress = {});

// Stateless helpers remain for compatibility, but GUI/CLI stop workflows should
// use the owned-session APIs so SAT never sends Procmon's global /Terminate to
// an unrelated capture.
Status procmon_start(const ProcmonOptions& options);
Result<ProcessResult> procmon_stop(const std::filesystem::path& third_party_directory,
                                   const CancellationToken& cancel,
                                   ProgressCallback progress = {});

struct IperfOptions {
  bool server = false;
  std::string host;
  std::uint16_t port = 2500;
  std::string payload;
  std::vector<std::string> custom_arguments;
  std::chrono::milliseconds timeout{120000};
  std::filesystem::path third_party_directory;
};

Result<ProcessResult> run_iperf(const IperfOptions& options,
                                const CancellationToken& cancel,
                                ProgressCallback progress = {});

// A normalized, read-only view of active Veeam Backup & Replication work.
// The PowerShell implementation queries documented VBR cmdlets and emits only
// non-secret operational metadata. Job/session IDs are retained so a later stop
// request never has to interpolate a job name into PowerShell code.
struct VbrRunningJob {
  std::string kind;
  std::string name;
  std::string job_id;
  std::string session_id;
  std::string state;
  std::string result;
  std::string started;
  std::string progress;
  std::string initiated_by;
  std::string details;
  bool stoppable = false;
};

Result<std::vector<VbrRunningJob>> list_vbr_running_jobs(
    const CancellationToken& cancel,
    ProgressCallback progress = {});

struct VbrStopJobRequest {
  std::string kind;
  std::string job_id;
  std::string session_id;
};

struct VbrStopJobResult {
  bool request_sent = false;
  std::string kind;
  std::string job_id;
  std::string session_id;
  std::string detail;
};

Result<VbrStopJobResult> stop_vbr_running_job(
    const VbrStopJobRequest& request,
    const CancellationToken& cancel,
    ProgressCallback progress = {});

// Independent Windows SMB validation. SAT never receives alternate-credential
// password text: when prompt_for_alternate_credentials is true the Windows
// network provider owns the credential UI and authentication exchange.
struct SmbConnectivityOptions {
  std::string target;
  std::string relative_path = R"(C$\Windows\Veeam)";
  bool prompt_for_alternate_credentials = false;
  std::chrono::milliseconds timeout{5000};
};

struct SmbConnectivityResult {
  std::string target;
  std::string resolved_address;
  std::string unc_share;
  std::string test_path;
  bool tcp_445_connected = false;
  bool smb_session_available = false;
  bool temporary_session_created = false;
  bool path_accessible = false;
  bool payload_created = false;
  bool payload_verified = false;
  bool payload_deleted = false;
  bool temporary_session_disconnected = false;
  std::string dialect;
  std::string username;
  std::string signing;
  std::string encryption;
  std::string payload_name;
  std::string failure_stage;
  std::int64_t native_code = 0;
  std::string detail;
};

Result<SmbConnectivityResult> test_smb_connectivity(
    const SmbConnectivityOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {});

} // namespace support_assist
