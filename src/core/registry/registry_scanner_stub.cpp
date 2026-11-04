#include "support_assist/registry.hpp"
namespace support_assist {
Result<ScanSummary> scan_registry(SnapshotStore&,
                                  std::string_view,
                                  const RegistryScanOptions&,
                                  const CancellationToken&,
                                  ProgressCallback) {
  Error e;
  e.component = "Registry";
  e.operation = "scan";
  e.message = "Registry scanning requires a Windows build.";
  return Result<ScanSummary>::failure(std::move(e));
}
} // namespace support_assist
