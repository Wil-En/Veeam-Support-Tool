#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/log_collection.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/time_check.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace support_assist {

struct ThirdPartyDiagnosticFinding {
  std::string product;
  std::filesystem::path source;
  std::filesystem::path collected_copy;
  std::string policy;
};

struct OfficialExporterRun {
  std::string product_id;
  std::string product_name;
  std::filesystem::path executable;
  std::filesystem::path output_directory;
  int exit_code = -1;
  bool launched = false;
  bool succeeded = false;
  bool may_include_configuration = false;
};

struct UniversalCollectionOptions {
  std::filesystem::path output_root;
  // Optional time boundary for collected log files and exported event logs.
  // The GUI exposes this as Last X days; unset means all available.
  std::optional<std::int64_t> from_utc_ms;
  std::optional<std::int64_t> to_utc_ms;
  // Optional SAT-owned transient General Tools output. This preserves the
  // Windows Gather Logs behavior while keeping the cross-platform collector
  // explicit about what it owns and may clean after successful archival.
  std::filesystem::path tool_output_directory;
  bool include_tool_output_logs = true;
  bool cleanup_tool_output_after_archive = true;
  std::filesystem::path sat_logs_directory;
  bool include_sat_logs = false;
  bool cleanup_sat_logs_after_archive = false;
  bool cleanup_collection_directory_after_archive = false;
  std::vector<std::filesystem::path> additional_sources;
  bool create_archive = true;
  bool include_third_party_error_logs = true;
  bool include_platform_context = true;
  bool include_official_product_exporters = false;
  // When true, selected_product_ids is an exact GUI/CLI checklist. An empty
  // explicit selection means collect no Veeam product roots; it must not fall
  // back to generic discovery behind the engineer's back.
  bool product_selection_explicit = false;
  std::vector<std::string> selected_product_ids;
  std::uint64_t maximum_files = 500000;
  std::uint64_t maximum_bytes = 100ULL * 1024ULL * 1024ULL * 1024ULL;
};

struct UniversalCollectionResult {
  LogCollectionResult logs;
  HostPlatform platform = HostPlatform::unknown;
  std::vector<DetectedProduct> detected_products;
  std::vector<ThirdPartyDiagnosticFinding> third_party_files;
  std::vector<OfficialExporterRun> official_exporter_runs;
  std::filesystem::path universal_manifest_path;
  std::filesystem::path platform_context_directory;
  std::filesystem::path environment_log_path;
  std::vector<std::string> privacy_notes;
  std::vector<std::string> warnings;
  // The machine's clock when the collection started: zone, time source and one reading of it.
  std::optional<TimeCheckResult> time_base;
};

Result<UniversalCollectionResult> collect_universal_support_bundle(
    const UniversalCollectionOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {});

std::string redact_third_party_log_line(std::string_view line);

} // namespace support_assist
