#pragma once

// Recent Activity on both editions: what SAT ran on this machine, newest first. activity.tsv keeps
// each result as it was written; the page shows a short form of it in its outcome's colour, and
// tiles above the table count the outcomes and show only those entries when clicked.

#include "home_board.hpp"
#include "quick_tool_reports.hpp"

#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

// The newest entries of this machine's record the page shows; an opened record shows all of it.
inline constexpr std::size_t kRecentActivityShown = 500;

enum class ActivityOutcome { started, completed, finding, failed, cancelled };

// The tiles, in their order on the page. Each but the first shows only its outcome.
enum class ActivityFilter { all, findings, failed, cancelled };

namespace activity_detail {

inline std::string folded(std::string_view text) {
  std::string lowered(text);
  for (char& character : lowered)
    character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  return lowered;
}

inline bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

constexpr std::string_view kExecution = "Execution: ";
constexpr std::string_view kDiagnostic = " | Diagnostic: ";

} // namespace activity_detail

// A Tools run writes "Execution: Completed | Diagnostic: Finding"; the other entries write a word or
// two ("Started", "Listener failed", "Cancel requested", "Uploaded").
inline ActivityOutcome activity_outcome(std::string_view result) {
  const std::string text = activity_detail::folded(result);
  const auto has = [&](std::string_view token) { return text.find(token) != std::string::npos; };
  if (has("cancel"))
    return ActivityOutcome::cancelled;
  if (has("fail") || has("not read") || has("unavailable"))
    return ActivityOutcome::failed;
  if (has("diagnostic: finding"))
    return ActivityOutcome::finding;
  if (text == "started" || activity_detail::ends_with(text, " started"))
    return ActivityOutcome::started;
  return ActivityOutcome::completed;
}

// "Execution: Completed | Diagnostic: Pass" reads "Completed, passed" and a finding "Completed, with
// findings"; a diagnostic that says nothing either way (Neutral, Not Applicable, Unknown) is left
// out. Every other result reads as written.
inline std::string activity_result_text(std::string_view result) {
  using activity_detail::kDiagnostic;
  using activity_detail::kExecution;
  if (result.substr(0, kExecution.size()) != kExecution)
    return std::string(result);
  const std::size_t bar = result.find(kDiagnostic);
  const std::string_view run = result.substr(kExecution.size(), bar == std::string_view::npos
                                                                    ? std::string_view::npos
                                                                    : bar - kExecution.size());
  const std::string_view found =
      bar == std::string_view::npos ? std::string_view() : result.substr(bar + kDiagnostic.size());
  if (found == "Pass")
    return std::string(run) + ", passed";
  if (found == "Finding")
    return std::string(run) + ", with findings";
  return std::string(run);
}

// The page is a history, not a diagnosis: results read in the table's own colour, with starts and
// cancels quieter. No warning colours.
inline ReportTone activity_tone(std::string_view result) {
  switch (activity_outcome(result)) {
  case ActivityOutcome::started:
  case ActivityOutcome::cancelled:
    return ReportTone::quiet;
  case ActivityOutcome::failed:
  case ActivityOutcome::finding:
  case ActivityOutcome::completed:
    break;
  }
  return ReportTone::normal;
}

inline bool activity_shown(ActivityFilter filter, std::string_view result) {
  switch (filter) {
  case ActivityFilter::findings:
    return activity_outcome(result) == ActivityOutcome::finding;
  case ActivityFilter::failed:
    return activity_outcome(result) == ActivityOutcome::failed;
  case ActivityFilter::cancelled:
    return activity_outcome(result) == ActivityOutcome::cancelled;
  case ActivityFilter::all:
    break;
  }
  return true;
}

struct ActivityCounts {
  std::size_t entries = 0;
  std::size_t findings = 0;
  std::size_t failed = 0;
  std::size_t cancelled = 0;
};

inline ActivityCounts activity_counts(const std::vector<std::string>& results) {
  ActivityCounts counts;
  for (const std::string& result : results) {
    ++counts.entries;
    switch (activity_outcome(result)) {
    case ActivityOutcome::finding: ++counts.findings; break;
    case ActivityOutcome::failed: ++counts.failed; break;
    case ActivityOutcome::cancelled: ++counts.cancelled; break;
    case ActivityOutcome::started:
    case ActivityOutcome::completed: break;
    }
  }
  return counts;
}

// The tile at this index on the page (the board reports tiles in this order).
inline ActivityFilter activity_filter_at(int index) {
  switch (index) {
  case 1: return ActivityFilter::findings;
  case 2: return ActivityFilter::failed;
  case 3: return ActivityFilter::cancelled;
  default: return ActivityFilter::all;
  }
}

// The tiles: the entries, then the findings, failures and cancels, the one in use pressed in. A
// second click on a pressed tile shows every entry again (the page does that).
inline BoardSection activity_board(const ActivityCounts& counts, ActivityFilter filter) {
  BoardSection section{"", 4, true, {}};
  // A history, so every tile is drawn alike; a count of none is quieter.
  const auto tile = [&](const char* caption, std::size_t count, const char* detail, ActivityFilter shows) {
    BoardTile made;
    made.caption = caption;
    made.value = std::to_string(count);
    made.detail = detail;
    made.tone = count == 0U && shows != ActivityFilter::all ? ReportTone::quiet : ReportTone::normal;
    made.selected = filter == shows;
    // A board takes a click only on a tile with an action; the page's own handler filters by the
    // tile's position, so the action only marks the tile as clickable.
    made.action = BoardAction::open_page;
    made.page = WorkspacePage::recent_activity;
    section.tiles.push_back(std::move(made));
  };
  tile("ALL ENTRIES", counts.entries, "Everything recorded, newest first", ActivityFilter::all);
  tile("FINDINGS", counts.findings, "Checks that reported something to review", ActivityFilter::findings);
  tile("FAILED", counts.failed, "Runs and actions that ended with an error", ActivityFilter::failed);
  tile("CANCELLED", counts.cancelled, "Stopped on request before completing", ActivityFilter::cancelled);
  return section;
}

// The line under the page title. `archived_source` names an opened record; empty for this machine's.
inline std::string activity_description(std::string_view archived_source) {
  if (!archived_source.empty())
    return "A record opened read-only from " + std::string(archived_source) +
           ". This machine's own history is unchanged; Show live activity returns to it.";
  return "The history of what SAT has run on this machine, newest first: when each run or action took place, "
         "what it was and how it ended. Choose a tile to list only those entries.";
}

// The caption over the table.
inline std::string activity_caption(bool archived, ActivityFilter filter) {
  std::string caption = archived ? "ARCHIVED ACTIVITY" : "RECENT ACTIVITY";
  switch (filter) {
  case ActivityFilter::findings: caption += ": FINDINGS"; break;
  case ActivityFilter::failed: caption += ": FAILED"; break;
  case ActivityFilter::cancelled: caption += ": CANCELLED"; break;
  case ActivityFilter::all: break;
  }
  return caption;
}

} // namespace support_assist::gui
