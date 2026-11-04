#pragma once

// The cases an engineer opened, most recent first, for Home's Recent cases on both editions:
// recent-cases.txt beside the case catalog, one line per case, "<opened unix ms>\t<case root>".

#include "support_assist/case_workspace.hpp"
#include "support_assist/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace support_assist {

struct RecentCase {
  std::filesystem::path root;
  std::int64_t opened_unix_ms = 0;
};

inline constexpr std::size_t kRecentCasesKept = 50;

// Most recently opened first; a line that does not read is skipped.
std::vector<RecentCase> read_recent_cases(const std::filesystem::path& file);

// Moves the case to the front with this time, keeping at most kRecentCasesKept.
Status record_case_opened(const std::filesystem::path& file, const std::filesystem::path& root,
                          std::int64_t opened_unix_ms);

// Drops a deleted case from the list.
Status forget_recent_case(const std::filesystem::path& file, const std::filesystem::path& root);

// Home's order: the cases opened, most recently first, then the others in the order given.
std::vector<const CaseWorkspace*> recent_case_order(const std::vector<CaseWorkspace>& cases,
                                                    const std::vector<RecentCase>& recent);

} // namespace support_assist
