#pragma once
#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/models.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/snapshot_store.hpp"
#include <filesystem>
#include <functional>
#include <string>
#include <vector>
namespace support_assist {
struct RegistryScope {
  std::string hive;
  std::string subkey;
  RegistryView view = RegistryView::both;
};
Result<RegistryScope> parse_registry_scope(std::string_view text, RegistryView view);
struct RegistryScanOptions {
  std::vector<RegistryScope> scopes;
  std::size_t batch_size = 1000;
  std::size_t display_limit = 4096;
  bool include_security = false;
};
struct ScanSummary {
  std::uint64_t objects = 0;
  std::uint64_t errors = 0;
  bool cancelled = false;
  // A files scan on Windows: how it read the folder (kCaptureSourceMft or kCaptureSourceListing),
  // and why the master file table was not used when it was tried. Empty elsewhere.
  std::string source;
  std::string source_note;
};
Result<ScanSummary> scan_registry(SnapshotStore& store,
                                  std::string_view snapshot_id,
                                  const RegistryScanOptions& options,
                                  const CancellationToken& cancel,
                                  ProgressCallback progress);
using DiffCallback = std::function<Status(const DiffRecord&)>;
// Cancel stops the statement running; the failure then reads "Cancelled".
Result<std::uint64_t> compare_registry(const std::filesystem::path& before,
                                       std::string_view before_id,
                                       const std::filesystem::path& after,
                                       std::string_view after_id,
                                       const DiffCallback& callback,
                                       const CancellationToken& cancel = CancellationToken{});
} // namespace support_assist
