// The filesystem baseline/compare sequence, owned by the core.
//
// This file exists because the sequence below was written three times - once in the Windows GUI,
// once in the CLI, and once more when the Qt GUI needed it. Three copies of an ordering constraint
// (persist the scan configuration BEFORE scanning, finish the snapshot with the state the scan
// actually reached, never leave a half-written snapshot behind) is three chances to get it wrong,
// and no way for a fix in one to reach the others. A frontend should be able to ask for a baseline
// and be handed one.

#include "support_assist/filesystem.hpp"

#include "support_assist/change_journal.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_info.hpp"

#include <system_error>
#include <utility>

namespace support_assist {
namespace {

Error baseline_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "Filesystem";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

FilesystemScanConfig configuration_from_options(std::string_view snapshot_id,
                                                const FilesystemScanOptions& options) {
  FilesystemScanConfig config;
  config.snapshot_id = std::string(snapshot_id);
  config.root_path = support_assist::generic_path_to_utf8(options.root);
  config.exclusions = options.exclusions;
  config.follow_reparse_points = options.follow_reparse_points;
  config.maximum_depth = options.maximum_depth;
  config.maximum_objects = options.maximum_objects;
  config.hash_mode = to_string(options.hash_mode);
  config.hash_size_limit = options.hash_size_limit;
  config.hash_extensions = options.hash_extensions;
  config.capture_streams = options.capture_streams;
  config.capture_file_identity = options.capture_file_identity;
  config.hydrate_cloud_files = options.hydrate_cloud_files;
  return config;
}

} // namespace

std::string to_string(HashMode mode) {
  switch (mode) {
  case HashMode::all:
    return "all";
  case HashMode::below_size:
    return "below-size";
  case HashMode::extensions:
    return "extensions";
  case HashMode::none:
    break;
  }
  return "none";
}

HashMode parse_hash_mode(std::string_view value) {
  // "small" is accepted because baselines written by earlier builds use it for below_size. A
  // baseline that can be read but not reproduced is worse than no baseline.
  if (value == "all") {
    return HashMode::all;
  }
  if (value == "below-size" || value == "small") {
    return HashMode::below_size;
  }
  if (value == "extensions") {
    return HashMode::extensions;
  }
  return HashMode::none;
}

Result<FilesystemBaselineResult> capture_filesystem_baseline(
    const std::filesystem::path& snapshot_path,
    const FilesystemScanOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress,
    std::string_view options_json) {
  if (snapshot_path.empty()) {
    return Result<FilesystemBaselineResult>::failure(
        baseline_error("capture filesystem baseline", {}, "A baseline file path is required"));
  }
  if (options.root.empty()) {
    return Result<FilesystemBaselineResult>::failure(baseline_error(
        "capture filesystem baseline", support_assist::generic_path_to_utf8(snapshot_path),
        "A root path to baseline is required"));
  }

  if (snapshot_path.has_parent_path()) {
    std::error_code directory_error;
    std::filesystem::create_directories(snapshot_path.parent_path(), directory_error);
    if (directory_error) {
      return Result<FilesystemBaselineResult>::failure(
          baseline_error("create baseline folder", support_assist::generic_path_to_utf8(snapshot_path.parent_path()),
                         directory_error.message()));
    }
  }

  auto store = SnapshotStore::create(snapshot_path);
  if (!store.ok()) {
    return Result<FilesystemBaselineResult>::failure(store.error());
  }

  auto metadata = make_snapshot_metadata(SnapshotKind::filesystem, support_assist::generic_path_to_utf8(options.root),
                                         std::string(options_json));
  if (auto status = store.value().begin_snapshot(metadata); !status.ok()) {
    return Result<FilesystemBaselineResult>::failure(status.error());
  }
  // Written BEFORE the scan. A snapshot that is interrupted still describes what it was trying to
  // capture, which is what makes a partial baseline diagnosable instead of opaque.
  if (auto status =
          store.value().set_filesystem_scan_config(configuration_from_options(metadata.id, options));
      !status.ok()) {
    return Result<FilesystemBaselineResult>::failure(status.error());
  }

  auto summary = scan_filesystem(store.value(), metadata.id, options, cancel, std::move(progress));
  if (!summary.ok()) {
    static_cast<void>(store.value().finish_snapshot(metadata.id, SnapshotState::failed, 0, 1));
    return Result<FilesystemBaselineResult>::failure(summary.error());
  }

  FilesystemBaselineResult result;
  result.snapshot_id = metadata.id;
  result.state = summary.value().cancelled ? SnapshotState::cancelled : SnapshotState::complete;
  result.objects = summary.value().objects;
  result.errors = summary.value().errors;
  result.source = summary.value().source;
  result.source_note = summary.value().source_note;
  if (!result.source.empty())
    static_cast<void>(store.value().set_capture_source(metadata.id, {result.source, result.source_note}));
  // Where the change journal stands now, so a later compare can read what happened after this
  // capture. Taken after the scan, so everything the journal records after the mark came after the
  // capture. A capture that cannot be marked (another system, no administrator rights, a volume
  // without a journal) is still a complete capture.
  if (result.state == SnapshotState::complete) {
    const ChangeJournalProbe probe = probe_change_journal(options.root);
    if (probe.available)
      static_cast<void>(store.value().set_change_journal_mark(metadata.id, probe.mark));
  }
  if (auto status = store.value().finish_snapshot(metadata.id, result.state, result.objects,
                                                  result.errors);
      !status.ok()) {
    return Result<FilesystemBaselineResult>::failure(status.error());
  }
  return Result<FilesystemBaselineResult>::success(std::move(result));
}

Result<FilesystemScanOptions> load_filesystem_baseline_options(
    const std::filesystem::path& snapshot_path,
    std::string& snapshot_id) {
  auto store = SnapshotStore::open(snapshot_path, true);
  if (!store.ok()) {
    return Result<FilesystemScanOptions>::failure(store.error());
  }
  if (auto status = store.value().validate(); !status.ok()) {
    return Result<FilesystemScanOptions>::failure(status.error());
  }
  auto id = store.value().latest_complete_snapshot_id(SnapshotKind::filesystem);
  if (!id.ok()) {
    return Result<FilesystemScanOptions>::failure(id.error());
  }
  auto metadata = store.value().metadata(id.value());
  if (!metadata.ok()) {
    return Result<FilesystemScanOptions>::failure(metadata.error());
  }
  if (metadata.value().kind != SnapshotKind::filesystem ||
      metadata.value().state != SnapshotState::complete) {
    return Result<FilesystemScanOptions>::failure(
        baseline_error("load filesystem baseline", support_assist::generic_path_to_utf8(snapshot_path),
                       "The selected file must contain a complete filesystem baseline"));
  }
  auto config = store.value().filesystem_scan_config(id.value());
  if (!config.ok()) {
    return Result<FilesystemScanOptions>::failure(config.error());
  }

  FilesystemScanOptions options;
  options.root = support_assist::path_from_utf8(config.value().root_path);
  options.exclusions = config.value().exclusions;
  options.follow_reparse_points = config.value().follow_reparse_points;
  options.maximum_depth = config.value().maximum_depth;
  options.maximum_objects = config.value().maximum_objects;
  options.hash_mode = parse_hash_mode(config.value().hash_mode);
  options.hash_size_limit = config.value().hash_size_limit;
  options.hash_extensions = config.value().hash_extensions;
  options.capture_streams = config.value().capture_streams;
  options.capture_file_identity = config.value().capture_file_identity;
  options.hydrate_cloud_files = config.value().hydrate_cloud_files;
  // Read now the way the capture was read, so both sides of a compare come from the same source.
  if (auto source = store.value().capture_source(id.value()); source.ok())
    options.try_mft = source.value() && source.value()->source == kCaptureSourceMft;
  snapshot_id = id.value();
  return Result<FilesystemScanOptions>::success(std::move(options));
}

} // namespace support_assist
