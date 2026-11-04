#pragma once

// Host Checks on Host Diagnostics, for both editions: a check box per group this system runs, the
// rows the result table shows, and Show CLI's arguments. The checks are core host_checks.hpp.

#include "support_assist/host_checks.hpp"
#include "support_assist/strings.hpp"

#include <string>
#include <vector>

namespace support_assist::gui {

inline constexpr int kHostChecksMode = 28;

struct HostChecksTableRow {
  std::string group;
  std::string check;
  std::string detail;
  std::string status;
};

// The ticked groups' ids, given the ticks in host_check_groups_here() order.
inline std::vector<std::string> host_checks_chosen(const std::vector<bool>& ticked) {
  std::vector<std::string> ids;
  const auto groups = host_check_groups_here();
  for (std::size_t index = 0; index < groups.size() && index < ticked.size(); ++index) {
    if (ticked[index])
      ids.push_back(groups[index].id);
  }
  return ids;
}

// "Backup events: System and Application events that ..." for a group's check box.
inline std::string host_check_label(const HostCheckGroup& group) {
  return group.title + (group.needs_admin ? "  (administrator)" : "");
}

inline std::vector<HostChecksTableRow> host_checks_table(const HostChecksReport& report) {
  std::vector<HostChecksTableRow> rows;
  for (const HostCheckRow& row : report.rows)
    rows.push_back({row.group, row.check, row.source.empty() ? row.detail : row.detail + "  " + row.source, row.status});
  return rows;
}

inline std::vector<std::string> host_checks_cli_arguments(const std::vector<std::string>& ids, const std::string& days) {
  std::vector<std::string> arguments{"system", "host-checks"};
  const auto all = host_check_groups_here();
  if (!ids.empty() && ids.size() < all.size()) {
    std::string joined;
    for (const std::string& id : ids)
      joined += (joined.empty() ? "" : ",") + id;
    arguments.insert(arguments.end(), {"--checks", joined});
  }
  if (!trim(days).empty())
    arguments.insert(arguments.end(), {"--days", trim(days)});
  return arguments;
}

} // namespace support_assist::gui
