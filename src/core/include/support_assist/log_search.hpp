#pragma once
#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/models.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/time.hpp"
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>
namespace support_assist {
enum class SearchMode { literal, regular_expression };
struct LogSearchOptions {
  std::vector<std::filesystem::path> sources;
  std::string query;
  SearchMode mode = SearchMode::literal;
  bool case_sensitive = false;
  bool recursive = true;
  bool search_archives = true;
  std::vector<std::string> filename_patterns;
  std::vector<std::string> severities;
  std::optional<std::int64_t> from_utc_ms;
  std::optional<std::int64_t> to_utc_ms;
  bool inclusive_start = true;
  bool inclusive_end = true;
  DateOrder date_order = DateOrder::automatic;
  int assumed_timezone_offset_minutes = 0;
  std::size_t context_before = 4;
  std::size_t context_after = 4;
  std::size_t maximum_results = 100000;
  std::size_t maximum_line_bytes = 4 * 1024 * 1024;
  std::uint64_t maximum_archive_expanded_bytes = 4ULL * 1024ULL * 1024ULL * 1024ULL;
  std::uint64_t maximum_archive_entries = 100000;
  std::uint32_t maximum_archive_depth = 2;
};
using LogMatchCallback = std::function<Status(const LogMatch&)>;
Result<std::uint64_t> search_logs(const LogSearchOptions& options,
                                  const CancellationToken& cancel,
                                  ProgressCallback progress,
                                  const LogMatchCallback& callback);
std::vector<std::filesystem::path> discover_veeam_sources();

struct WindowsEventLogSearchOptions {
  std::string channel = "Veeam Agent";
  std::string query;
  bool case_sensitive = false;
  std::vector<std::uint32_t> event_ids;
  std::vector<std::string> severities;
  std::optional<std::int64_t> from_utc_ms;
  std::optional<std::int64_t> to_utc_ms;
  std::size_t maximum_results = 100000;
};
Result<std::uint64_t> search_windows_event_log(const WindowsEventLogSearchOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress,
                                               const LogMatchCallback& callback);
} // namespace support_assist
