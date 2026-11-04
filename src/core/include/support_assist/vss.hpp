#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace support_assist {

enum class VssBackupType { copy, full };

struct VssWriterInfo {
  std::string writer_class_id;
  std::string writer_instance_id;
  std::string name;
  int state = 0;
  std::string state_name;
  std::int64_t failure_hresult = 0;
  bool selected = false;
};

struct VssSnapshotInfo {
  std::string snapshot_id;
  std::string snapshot_set_id;
  std::string original_volume;
  std::string device_object;
  std::string provider_id;
  std::uint32_t attributes = 0;
  std::string status;
};

struct VssTestOptions {
  std::vector<std::string> volumes;
  std::vector<std::string> enabled_writer_class_ids;
  VssBackupType backup_type = VssBackupType::copy;
  bool component_mode = false;
  bool select_all_components = false;
  bool backup_bootable_system_state = false;
  bool partial_file_support = false;
  // The portable interface stores the native VSS context as an integer. The application
  // currently permits only the normal writer-participating backup context
  // VSS_CTX_BACKUP (zero). Non-writer contexts are intentionally separate future work.
  std::int32_t context = 0;
  std::uint32_t hold_seconds = 0;
};

struct VssSessionDetails {
  std::string session_id;
  std::string snapshot_set_id;
  std::string started_utc;
  std::string released_utc;
  std::vector<VssWriterInfo> writers;
  std::vector<VssSnapshotInfo> snapshots;
  std::string consistency_label;
  // Host classification is informational. SAT uses the same native, writer-aware
  // requester workflow on Windows client and Windows Server; it does not swap to
  // a weaker no-writer context merely because the host is a workstation.
  std::string windows_product_type;
  std::string context_description;
  VssBackupType backup_type = VssBackupType::copy;
  bool component_mode = false;
  std::int32_t context = 0;
  bool active = false;
  bool cleanup_succeeded = false;
  bool cleanup_verified = false;
  std::uint32_t cleanup_deleted_snapshots = 0;
  std::uint32_t cleanup_verification_seconds = 0;
  std::uint32_t cleanup_remaining_snapshots = 0;
};

class VssSession {
public:
  virtual ~VssSession() = default;
  virtual const VssSessionDetails& details() const noexcept = 0;
  virtual Status release(bool backup_succeeded, ProgressCallback progress = {}) = 0;
};

Result<std::vector<VssWriterInfo>> enumerate_vss_writers();
Result<std::unique_ptr<VssSession>> create_vss_test_session(const VssTestOptions& options,
                                                            const CancellationToken& cancel,
                                                            ProgressCallback progress);

} // namespace support_assist
