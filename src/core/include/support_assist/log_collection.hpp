#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/product_discovery.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace support_assist {

enum class LogCollectionProfile { universal, vaw, vbr, sql_plugin, rman_plugin, custom };

std::string to_string(LogCollectionProfile profile);
Result<LogCollectionProfile> parse_log_collection_profile(std::string_view value);

struct LogSourceCandidate {
  std::filesystem::path path;
  std::string label;
  bool inferred = true;
};

struct LogCollectionOptions {
  // Names the bundle after the product it is about: SAT-<product>-<host>-<timestamp>. The lower
  // collection layer does not detect products, so the universal layer supplies the token. Empty
  // falls back to the collection profile, which is what a custom-path collection has instead of a
  // product.
  std::string bundle_product_token;
  LogCollectionProfile profile = LogCollectionProfile::custom;
  std::vector<std::filesystem::path> sources;
  std::filesystem::path output_root;
  std::optional<std::int64_t> from_utc_ms;
  std::optional<std::int64_t> to_utc_ms;
  bool recursive = true;
  bool follow_directory_symlinks = false;
  bool create_archive = true;
  // On Windows, collect bounded OS/VSS/network/Event Log and additional Veeam
  // support context inspired by the established guest-machine collection workflow.
  // The structured Veeam parser treats this subtree as raw evidence until dedicated
  // parsers are added.
  bool include_windows_support_context = true;
  // Optional point-in-time Support Assist health snapshot supplied by the GUI.
  // When present it is written beside collected logs and included in the archive.
  std::string system_health_report;
  // Transient output logs produced by Customer / Lab tools. When collection
  // successfully creates its ZIP, only files copied from this directory are
  // removed. A failed/cancelled archive preserves the originals.
  std::filesystem::path tool_output_directory;
  bool include_tool_output_logs = true;
  bool cleanup_tool_output_after_archive = true;
  // SAT application state/logging root. This is distinct from collected tool
  // evidence. Customer/Lab may archive and remove it only after a successful
  // bundle; Engineer Review must leave destructive cleanup disabled.
  std::filesystem::path sat_logs_directory;
  bool include_sat_logs = false;
  bool cleanup_sat_logs_after_archive = false;
  // Customer/Lab uses a transient uncompressed staging directory. Remove it
  // only after the ZIP is complete; the sibling archive is never removed.
  bool cleanup_collection_directory_after_archive = false;
  // User-selected files/folders marked from the Explorer workspace. These are
  // copied read-only under Additional/Local while preserving their source path
  // below the drive/root. They never replace or expand the normal product log
  // discovery roots.
  std::vector<std::filesystem::path> additional_sources;
  std::uint64_t maximum_files = 500000;
  std::uint64_t maximum_bytes = 100ULL * 1024ULL * 1024ULL * 1024ULL;
};

struct LogCollectionResult {
  LogCollectionProfile profile = LogCollectionProfile::custom;
  std::filesystem::path collection_directory;
  std::filesystem::path archive_path;
  std::filesystem::path manifest_path;
  std::filesystem::path health_report_path;
  std::filesystem::path windows_support_directory;
  std::filesystem::path windows_support_index_path;
  std::uint64_t copied_files = 0;
  std::uint64_t skipped_files = 0;
  std::uint64_t error_count = 0;
  std::uint64_t copied_bytes = 0;
  std::uint64_t windows_support_files = 0;
  std::uint64_t tool_output_files = 0;
  std::uint64_t tool_output_files_cleaned = 0;
  std::uint64_t sat_log_files = 0;
  std::uint64_t additional_files = 0;
  bool tool_output_copy_complete = true;
  bool sat_logs_copy_complete = true;
  bool sat_logs_directory_cleaned = false;
  bool collection_directory_cleaned = false;
  std::vector<std::string> warnings;
};

// Product-neutral Veeam roots that may contain evidence from multiple products.
// These are collection sources only and must never be used as installation identity.
std::vector<LogSourceCandidate> discover_shared_veeam_log_sources(
    const ProductDiscoveryContext& context);

std::vector<LogSourceCandidate> discover_log_collection_sources(LogCollectionProfile profile);

Result<LogCollectionResult> collect_logs(const LogCollectionOptions& options,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress = {});

// The \\?\ form of an absolute Windows path, so a file deeper than MAX_PATH (260 characters) can
// still be read, copied and removed; the path unchanged elsewhere.
std::filesystem::path long_path_form(const std::filesystem::path& path);

Status create_zip_archive(const std::filesystem::path& source_directory,
                          const std::filesystem::path& archive_path);

} // namespace support_assist
