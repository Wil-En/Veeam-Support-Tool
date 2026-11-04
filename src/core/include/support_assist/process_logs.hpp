#pragma once

// The Veeam logs written when a process ended, for Service and Process Watch's Its log: the files in
// the Veeam log folders last written near that moment, newest first, and the line in one of them
// written nearest before it, read from the lines' own time prefixes. Veeam names its logs by job,
// task and service rather than by program, so the files are offered for the engineer to choose.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace support_assist {

struct LogWrittenNear {
  std::filesystem::path path;
  std::int64_t written_unix_millis = 0;
};

// This machine's Veeam log folders that exist: the product-neutral roots and each detected product's.
std::vector<std::filesystem::path> veeam_log_folders();

// How far before the moment a log's last write counts as near it, and after it.
inline constexpr std::int64_t kLogNearBeforeMillis = 2LL * 60LL * 1000LL;
inline constexpr std::int64_t kLogNearAfterMillis = 10LL * 1000LL;

// Logs (.log and .txt) under the folders last written from kLogNearBeforeMillis before `at` to
// kLogNearAfterMillis after it, newest first, at most `limit`. Reads the folders' listings only.
std::vector<LogWrittenNear> logs_written_near(const std::vector<std::filesystem::path>& folders,
                                              std::int64_t at_unix_millis, std::size_t limit = 20);

// The 1-based line of a log written nearest before `at` (one second later still counts), by the lines'
// own time prefixes read at utc_offset_minutes; 1 when no line before it carries a time. Reads at most
// the file's last 32 MB, counting the lines before them.
std::uint64_t log_line_before(const std::filesystem::path& path, std::int64_t at_unix_millis, int utc_offset_minutes);

} // namespace support_assist
