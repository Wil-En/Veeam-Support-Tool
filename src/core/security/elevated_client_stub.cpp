#include "support_assist/elevated.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

namespace support_assist {
Result<ElevatedVssResult>
run_vss_test_elevated(const VssTestOptions&, const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "VSS test";
  error.message = "The elevated VSS helper is available only in Windows builds";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<ElevatedVssResult>::failure(std::move(error));
}

Result<std::vector<VssWriterInfo>>
run_vss_writer_health_elevated(const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "VSS writer health";
  error.message = "The elevated VSS helper is available only in Windows builds";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<std::vector<VssWriterInfo>>::failure(std::move(error));
}

Result<PacketCaptureSession> packet_capture_start_owned_elevated(const PacketCaptureOptions&,
                                                                 const std::filesystem::path&,
                                                                 const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "start packet capture";
  error.message = "Packet capture requires Windows";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<PacketCaptureSession>::failure(std::move(error));
}

Result<FilesystemBaselineResult> capture_filesystem_baseline_elevated(const std::filesystem::path&,
                                                                      const FilesystemScanOptions&,
                                                                      const CancellationToken&, ProgressCallback,
                                                                      std::string_view) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "capture as administrator";
  error.message = "The elevated helper is available only in Windows builds";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<FilesystemBaselineResult>::failure(std::move(error));
}

Result<ElevatedCollectionResult> run_universal_collection_elevated(const UniversalCollectionOptions&,
                                                                   const CancellationToken&, ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "Universal log collection";
  error.message = "The elevated helper is available only in Windows builds";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<ElevatedCollectionResult>::failure(std::move(error));
}

Result<std::shared_ptr<PacketCaptureMonitor>> PacketCaptureMonitor::start(const PacketCaptureOptions&,
                                                                         const std::filesystem::path&,
                                                                         CountsCallback, const CancellationToken&,
                                                                         ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "start packet capture";
  error.message = "Packet capture requires Windows";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<std::shared_ptr<PacketCaptureMonitor>>::failure(std::move(error));
}

Result<ProcessResult> packet_capture_stop_owned_elevated(PacketCaptureSession&, const CancellationToken&,
                                                         ProgressCallback) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = "stop packet capture";
  error.message = "Packet capture requires Windows";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<ProcessResult>::failure(std::move(error));
}
} // namespace support_assist
