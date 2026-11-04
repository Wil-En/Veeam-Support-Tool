#pragma once

// activity.tsv, the record of what SAT ran on a machine: time, tool, result, details and case, one
// tab-separated line each, oldest first. Recent Activity opens one collected from another machine
// read-only, from the file, a folder holding it or an archive holding it, without extracting it.

#include "support_assist/error.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct ActivityEntry {
  std::string time;
  std::string tool;
  std::string result;
  std::string detail;
  std::string case_id;
};

// The entries newest first; a record longer than kActivityEntryLimit keeps its newest entries.
inline constexpr std::size_t kActivityEntryLimit = 100000;
std::vector<ActivityEntry> parse_activity_record(std::string_view text);

struct ArchivedActivity {
  std::filesystem::path source; // the activity.tsv, or the archive holding it
  std::string member;           // inside an archive: the member read; empty otherwise
  std::vector<ActivityEntry> entries;
};

// `path` is an activity.tsv, a folder holding one (a collected bundle: its ApplicationLogs copy
// first, the one SAT writes) or an archive holding one, read in memory.
Result<ArchivedActivity> open_archived_activity(const std::filesystem::path& path);

} // namespace support_assist
