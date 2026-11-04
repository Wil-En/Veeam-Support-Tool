#pragma once

// Home as a status board in both roles, and the Tools categories, drawn by both editions. Each tile
// carries one number or state and opens what is behind it; the link rows under the tiles open
// pages, quick tools and actions. Each edition gathers the inputs from its own state and draws the
// board; the words, the numbers, the grouping and the order are decided here.

#include "keyboard_shortcuts.hpp"
#include "quick_tool_reports.hpp"
#include "workspace_view_model.hpp"

#include "support_assist/case_workspace.hpp"
#include "support_assist/pending_restart.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/veeam_log_review.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

// ------------------------------------------------------------------------------- the board

enum class BoardAction {
  none,
  open_page,         // `page`
  open_dashboard,    // the active case's Case Dashboard
  open_saved_review, // the active case's saved review
  open_note_review,  // the active case's Note Review
  open_case,         // `target`, a case folder: it becomes the active case and its dashboard opens
  new_case,          // Case Manager's new-case form
  open_running_jobs,
  collect_logs,      // Universal Veeam Log Collection
  prepare_output,    // the last tool output
  delete_output,
  restart_details,   // the pending restart report
  products_details,  // the Veeam products installed, as a report
  services_details,  // the Veeam services, as a report
  quick_tool,        // `tool`
  switch_role,       // the other workspace role; Engineer Review needs the licence
};

struct BoardTile {
  std::string caption; // "ACTIVE CASE"
  std::string value;   // "SPECTR-VAW-004", "12", "Attention"
  std::string detail;  // one or two short lines
  std::string pill;    // a case status drawn as a pill; empty for none
  ReportTone tone = ReportTone::normal; // the value's colour
  bool highlight = false;               // drawn with the accent border
  bool selected = false;                // a filter tile that is on: drawn pressed in
  std::string link;                     // "Dashboard"; empty when the tile opens nothing
  BoardAction action = BoardAction::none;
  WorkspacePage page = WorkspacePage::home;
  ShortcutCommand tool = ShortcutCommand::help;
  std::string target; // open_case: the case folder
};

// A group of tiles under an optional caption.
struct BoardSection {
  std::string caption;  // "THIS MACHINE'S HEALTH"; empty for none
  int columns = 3;      // fewer when the tiles would be too narrow to read
  bool compact = false; // caption, value and one line, with the pill beside the caption
  std::vector<BoardTile> tiles;
  // Drawn compact while the board is taller than its window, the lowest such section first, so
  // Home fits the window it opens in.
  bool compact_when_short = false;
};

// A link under the tiles. Links run left to right and wrap when a row is full; `new_row` starts a
// row, with `row_caption` above it, and `right` puts a link at the right end of its row.
struct BoardLink {
  std::string label;
  std::string key; // drawn in a key cap after the label: "F6"
  BoardAction action = BoardAction::open_page;
  WorkspacePage page = WorkspacePage::home;
  ShortcutCommand tool = ShortcutCommand::help;
  std::string note; // drawn after a primary link
  bool primary = false;
  bool right = false;
  bool new_row = false;
  std::string row_caption;
};

struct HomeBoard {
  std::vector<BoardSection> sections;
  std::vector<BoardLink> links;
};

// The tiles in reading order: the index a renderer reports for a tile, before the links.
inline std::vector<BoardTile> board_tiles(const HomeBoard& board) {
  std::vector<BoardTile> tiles;
  for (const BoardSection& section : board.sections)
    tiles.insert(tiles.end(), section.tiles.begin(), section.tiles.end());
  return tiles;
}

namespace board_detail {

inline std::string count_text(std::size_t count, const char* one, const char* many) {
  return std::to_string(count) + " " + (count == 1U ? one : many);
}

inline std::string percent_text(double value) {
  char text[24] = {};
  std::snprintf(text, sizeof(text), "%.0f%%", value);
  return text;
}

inline std::string one_decimal_percent(double value) {
  char text[24] = {};
  std::snprintf(text, sizeof(text), "%.1f%%", value);
  return text;
}

inline std::string rate_text(double bytes_per_second) {
  const char* units[] = {"B/s", "KB/s", "MB/s", "GB/s"};
  std::size_t unit = 0;
  while (bytes_per_second >= 1024.0 && unit + 1U < std::size(units)) {
    bytes_per_second /= 1024.0;
    ++unit;
  }
  char text[32] = {};
  std::snprintf(text, sizeof(text), unit == 0U ? "%.0f %s" : "%.1f %s", bytes_per_second, units[unit]);
  return text;
}

// "27 Sep 18:40" in UTC, the board's short date.
inline std::string short_time(std::int64_t unix_millis) {
  const std::string full = time_check_detail::format_unix_millis(unix_millis, 0); // 2026-09-27 18:40:00.000
  if (full.size() < 16)
    return full;
  static const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                 "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  const int month = std::atoi(full.substr(5, 2).c_str());
  const int day = std::atoi(full.substr(8, 2).c_str());
  if (month < 1 || month > 12)
    return full;
  return std::to_string(day) + " " + months[month - 1] + " " + full.substr(11, 5);
}

// "18:40" in UTC.
inline std::string clock_time(std::int64_t unix_millis) {
  const std::string full = time_check_detail::format_unix_millis(unix_millis, 0);
  return full.size() >= 16 ? full.substr(11, 5) : full;
}

// "Last at 18:40 UTC", for a count made this session.
inline std::string last_at(std::int64_t unix_millis) {
  return unix_millis > 0 ? "Last at " + clock_time(unix_millis) + " UTC" : std::string();
}

// "40 min", "5 h 12 min", "3 days": how long the machine has been up.
inline std::string uptime_text(std::int64_t millis) {
  const std::int64_t minutes = std::max<std::int64_t>(0, millis / 60000);
  if (minutes < 60)
    return std::to_string(minutes) + " min";
  if (minutes < 48 * 60)
    return std::to_string(minutes / 60) + " h " + std::to_string(minutes % 60) + " min";
  return std::to_string(minutes / (24 * 60)) + " days";
}

// The last part of a path, whichever separator it uses.
inline std::string file_name(std::string path) {
  while (!path.empty() && (path.back() == '\\' || path.back() == '/'))
    path.pop_back();
  const auto slash = path.find_last_of("\\/");
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

// A product name without the vendor in front: "Backup & Replication".
inline std::string short_product_name(const std::string& name) {
  constexpr std::string_view vendor = "Veeam ";
  return name.rfind(vendor.data(), 0) == 0 ? name.substr(vendor.size()) : name;
}

inline std::string joined(const std::vector<std::string>& items, std::string_view separator = ", ") {
  std::string text;
  for (const std::string& item : items)
    text += (text.empty() ? "" : std::string(separator)) + item;
  return text;
}

// The lines of a free-text field that say something.
inline std::vector<std::string> text_lines(const std::string& text) {
  std::vector<std::string> lines;
  std::string line;
  const auto flush = [&]() {
    const auto first = line.find_first_not_of(" \t-*\r");
    const auto last = line.find_last_not_of(" \t\r");
    if (first != std::string::npos && last != std::string::npos && last >= first)
      lines.push_back(line.substr(first, last - first + 1));
    line.clear();
  };
  for (const char character : text) {
    if (character == '\n')
      flush();
    else
      line.push_back(character);
  }
  flush();
  return lines;
}

inline bool is_problem(const VeeamIncident& incident) {
  if (incident.story_stage != VeeamStoryStage::none)
    return false;
  std::string severity;
  for (const char character : incident.severity)
    severity.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
  return severity.find("err") != std::string::npos || severity.find("warn") != std::string::npos ||
         severity.find("crit") != std::string::npos || severity.find("fail") != std::string::npos;
}

inline int severity_rank(const VeeamIncident& incident) {
  std::string severity;
  for (const char character : incident.severity)
    severity.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
  if (severity.find("crit") != std::string::npos || severity.find("fail") != std::string::npos)
    return 3;
  if (severity.find("err") != std::string::npos)
    return 2;
  return 1;
}

inline std::int64_t unix_millis_of(std::filesystem::file_time_type time) {
  const auto system = std::chrono::clock_cast<std::chrono::system_clock>(time);
  return std::chrono::duration_cast<std::chrono::milliseconds>(system.time_since_epoch()).count();
}

} // namespace board_detail

// ------------------------------------------------------------------------ Engineer Review Home

// What a saved review says, for the board: read once per review file, not per repaint.
struct CaseReviewSummary {
  bool saved = false;
  std::size_t findings = 0; // errors and warnings, not story events
  std::string top_finding;  // the worst, then the most frequent
  std::size_t machines = 0;
  std::size_t runs = 0;
  std::size_t collections = 0;
  std::int64_t reviewed_unix_millis = 0;
  std::vector<std::string> machine_names; // offered in the forms' host fields
};

inline CaseReviewSummary summarize_case_review(const VeeamLogReviewResult& review, std::int64_t reviewed_unix_millis) {
  CaseReviewSummary summary;
  summary.saved = true;
  summary.machines = review.machines.size();
  for (const VeeamMachineRecord& machine : review.machines)
    summary.machine_names.push_back(machine.display_name.empty() ? machine.key : machine.display_name);
  summary.runs = review.job_sessions.size();
  summary.collections = review.bundles.size();
  summary.reviewed_unix_millis = reviewed_unix_millis;
  const VeeamIncident* top = nullptr;
  for (const VeeamIncident& incident : review.incidents) {
    if (!board_detail::is_problem(incident))
      continue;
    ++summary.findings;
    if (top == nullptr || board_detail::severity_rank(incident) > board_detail::severity_rank(*top) ||
        (board_detail::severity_rank(incident) == board_detail::severity_rank(*top) &&
         incident.occurrences > top->occurrences))
      top = &incident;
  }
  if (top != nullptr)
    summary.top_finding = top->summary.empty() ? top->signature : top->summary;
  return summary;
}

// What the active case holds beyond its saved review: its Log Review sources, the collections
// imported into its logs folder, the #note snapshots saved and the evidence marked for the note.
struct CaseHoldings {
  std::size_t sources = 0;
  std::string last_source; // the newest source's file or folder name
  std::size_t imported = 0;
  std::string last_imported; // the newest item in the logs folder
  std::size_t notes_saved = 0;
  std::int64_t note_saved_unix_millis = 0;
  std::size_t marked_for_note = 0;
  std::size_t evidence = 0; // log lines kept as evidence: bookmarked or marked for the note
};

// Read on a worker with the saved review; every part that cannot be read stays empty.
inline CaseHoldings read_case_holdings(const CaseWorkspace& workspace) {
  CaseHoldings holdings;
  if (auto state = load_case_review_state(workspace); state.ok()) {
    std::vector<std::string> sources;
    for (const CaseReviewSource& source : state.value().source_profiles)
      sources.push_back(source.path);
    if (sources.empty())
      sources = state.value().sources;
    holdings.sources = sources.size();
    if (!sources.empty())
      holdings.last_source = board_detail::file_name(sources.back());
  }
  std::error_code error;
  std::int64_t newest = -1;
  for (std::filesystem::directory_iterator entry(workspace.logs, error), end; !error && entry != end;
       entry.increment(error)) {
    ++holdings.imported;
    std::error_code time_error;
    const auto written = entry->last_write_time(time_error);
    const std::int64_t millis = time_error ? 0 : board_detail::unix_millis_of(written);
    if (millis > newest) {
      newest = millis;
      holdings.last_imported = board_detail::file_name(path_to_utf8(entry->path()));
    }
  }
  error.clear();
  for (std::filesystem::directory_iterator entry(workspace.notes, error), end; !error && entry != end;
       entry.increment(error)) {
    if (entry->path().extension() != ".txt")
      continue;
    ++holdings.notes_saved;
    std::error_code time_error;
    const auto written = entry->last_write_time(time_error);
    if (!time_error)
      holdings.note_saved_unix_millis =
          std::max(holdings.note_saved_unix_millis, board_detail::unix_millis_of(written));
  }
  if (auto bookmarks = load_case_evidence_bookmarks(workspace); bookmarks.ok()) {
    holdings.marked_for_note = static_cast<std::size_t>(
        std::count_if(bookmarks.value().begin(), bookmarks.value().end(),
                      [](const CaseEvidenceBookmark& bookmark) { return bookmark.include_in_note; }));
    holdings.evidence = static_cast<std::size_t>(
        std::count_if(bookmarks.value().begin(), bookmarks.value().end(), [](const CaseEvidenceBookmark& bookmark) {
          return bookmark.bookmarked || bookmark.include_in_note;
        }));
  }
  return holdings;
}

struct CaseStatusCount {
  std::string status;
  std::size_t count = 0;
};

// A case in the Recent cases row.
struct RecentCase {
  std::string root; // the case folder, which identifies it
  std::string case_id;
  std::string title;
  std::string status;
  bool active = false;
};

struct EngineerBoardInput {
  bool has_case = false;
  std::string case_id;
  std::string case_title;
  std::string case_status;
  std::string next_steps; // the case's Next Steps text, one step per line
  CaseReviewSummary review;
  CaseHoldings holdings;
  std::size_t running_jobs = 0;
  std::string running_job; // the newest job and its progress: "Log Review parse, 64%"
  std::size_t cases = 0;
  std::vector<CaseStatusCount> statuses; // every case SAT can see, counted by status, in list order
  std::vector<RecentCase> recent;        // newest first
};

inline constexpr std::size_t kRecentCases = 5;

// The case flow, the work in progress and the recent cases, with the links an engineer moves
// between: the case first.
inline HomeBoard engineer_home(const EngineerBoardInput& input) {
  using board_detail::count_text;
  HomeBoard board;

  // The case flow: the case, its logs, its evidence, its note.
  BoardSection flow{"CASE FLOW", 4, false, {}};
  flow.compact_when_short = true;
  BoardTile active;
  active.caption = "1  CASE";
  if (input.has_case) {
    active.value = input.case_id;
    active.detail = input.case_title;
    active.pill = input.case_status;
    active.tone = ReportTone::good;
    active.highlight = true;
    active.link = "Dashboard";
    active.action = BoardAction::open_dashboard;
    active.page = WorkspacePage::case_dashboard;
  } else {
    active.value = "None";
    active.detail = input.recent.empty() ? "Start a case to keep its logs, review and note together."
                                         : "Pick a recent case below, or start a new one.";
    active.tone = ReportTone::quiet;
    active.link = "New case";
    active.action = BoardAction::new_case;
  }
  flow.tiles.push_back(active);

  BoardTile logs;
  logs.caption = "2  LOGS";
  BoardTile evidence;
  evidence.caption = "3  EVIDENCE";
  BoardTile note;
  note.caption = "4  NOTE";
  if (!input.has_case) {
    for (BoardTile* tile : {&logs, &evidence, &note}) {
      tile->value = "—";
      tile->detail = "No active case.";
      tile->tone = ReportTone::quiet;
    }
  } else {
    // Log Review's sources, the collections the review found, or those imported into the case's
    // logs folder, whichever is more.
    const std::size_t sources =
        std::max({input.holdings.sources, input.review.collections, input.holdings.imported});
    logs.value = sources == 0U ? "None" : count_text(sources, "source", "sources");
    if (input.review.saved) {
      logs.detail = "Reviewed " +
                    (input.review.reviewed_unix_millis > 0 ? board_detail::short_time(input.review.reviewed_unix_millis)
                                                           : std::string("and saved")) +
                    ": " + count_text(input.review.machines, "machine", "machines") + ", " +
                    count_text(input.review.runs, "run", "runs");
    } else if (!input.holdings.last_source.empty()) {
      logs.detail = "Not reviewed yet. Last added: " + input.holdings.last_source;
    } else if (!input.holdings.last_imported.empty()) {
      logs.detail = "Not reviewed yet. Imported: " + input.holdings.last_imported;
    } else {
      logs.detail = "Add the customer's logs in Log Review.";
    }
    logs.tone = sources == 0U ? ReportTone::quiet : ReportTone::normal;
    logs.link = sources == 0U ? "Add logs" : "Log Review";
    logs.action = BoardAction::open_page;
    logs.page = WorkspacePage::log_review;

    // The log lines the engineer kept, not the review's error and warning count, which runs to
    // thousands for one bundle.
    const std::size_t kept = input.holdings.evidence;
    evidence.value = kept == 0U ? "None" : count_text(kept, "line", "lines");
    if (kept > 0U) {
      evidence.detail = count_text(input.holdings.marked_for_note, "line", "lines") + " marked for the note";
      evidence.tone = ReportTone::normal;
    } else if (input.review.saved) {
      evidence.detail = input.review.top_finding.empty()
                            ? "Bookmark the log lines that matter in the saved review."
                            : "None kept yet. Top in the review: " + input.review.top_finding;
      evidence.tone = ReportTone::quiet;
    } else {
      evidence.detail = "Review the logs, then bookmark the lines that matter.";
      evidence.tone = ReportTone::quiet;
    }
    if (input.review.saved) {
      evidence.link = "Saved review";
      evidence.action = BoardAction::open_saved_review;
    } else {
      evidence.link = "Log Review";
      evidence.action = BoardAction::open_page;
      evidence.page = WorkspacePage::log_review;
    }

    if (input.holdings.notes_saved > 0U) {
      note.value = "Saved";
      note.detail = input.holdings.note_saved_unix_millis > 0
                        ? "Last saved " + board_detail::short_time(input.holdings.note_saved_unix_millis) + " UTC"
                        : count_text(input.holdings.notes_saved, "note saved", "notes saved");
      note.tone = ReportTone::good;
    } else {
      note.value = input.holdings.marked_for_note > 0U ? "Draft" : "Not written";
      note.detail = input.holdings.marked_for_note > 0U
                        ? count_text(input.holdings.marked_for_note, "line marked for the note",
                                     "lines marked for the note")
                        : "Mark findings with Add to #note, then read the note through.";
      note.tone = input.holdings.marked_for_note > 0U ? ReportTone::normal : ReportTone::quiet;
    }
    note.link = "Note Review";
    note.action = BoardAction::open_note_review;
    note.page = WorkspacePage::note_review;
  }
  flow.tiles.push_back(logs);
  flow.tiles.push_back(evidence);
  flow.tiles.push_back(note);

  // Work in progress: next steps, running jobs and the case list's counts.
  BoardSection progress{"IN PROGRESS", 3, false, {}};
  progress.compact_when_short = true;
  BoardTile steps;
  steps.caption = "NEXT STEPS";
  const auto lines = board_detail::text_lines(input.next_steps);
  if (!input.has_case) {
    steps.value = "—";
    steps.detail = "No active case.";
    steps.tone = ReportTone::quiet;
  } else if (lines.empty()) {
    steps.value = "None";
    steps.detail = "Write the next steps on the Case Dashboard.";
    steps.tone = ReportTone::quiet;
    steps.link = "Case Dashboard";
    steps.action = BoardAction::open_dashboard;
    steps.page = WorkspacePage::case_dashboard;
  } else {
    steps.value = std::to_string(lines.size()) + " open";
    std::string joined;
    for (std::size_t index = 0; index < lines.size() && index < 2U; ++index)
      joined += (index == 0U ? "" : "; ") + lines[index];
    steps.detail = joined;
    steps.link = "Case Dashboard";
    steps.action = BoardAction::open_dashboard;
    steps.page = WorkspacePage::case_dashboard;
  }
  progress.tiles.push_back(steps);

  BoardTile jobs;
  jobs.caption = "RUNNING JOBS";
  jobs.value = std::to_string(input.running_jobs);
  jobs.detail = input.running_jobs == 0U ? "Nothing is running." : input.running_job;
  jobs.tone = input.running_jobs == 0U ? ReportTone::quiet : ReportTone::good;
  jobs.link = "Running Jobs";
  jobs.action = BoardAction::open_running_jobs;
  progress.tiles.push_back(jobs);

  BoardTile cases;
  cases.caption = "CASES";
  cases.value = std::to_string(input.cases);
  std::string counts;
  for (const CaseStatusCount& status : input.statuses) {
    if (status.count == 0U)
      continue;
    std::string name;
    for (const char character : status.status)
      name.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    counts += (counts.empty() ? "" : ", ") + std::to_string(status.count) + " " + name;
  }
  cases.detail = input.cases == 0U ? "No cases in the case folder yet." : counts;
  cases.tone = input.cases == 0U ? ReportTone::quiet : ReportTone::normal;
  cases.link = "Case Manager";
  cases.action = BoardAction::open_page;
  cases.page = WorkspacePage::case_manager;
  progress.tiles.push_back(cases);

  // The newest cases, each opening its dashboard.
  BoardSection recent{"RECENT CASES", static_cast<int>(kRecentCases), true, {}};
  for (std::size_t index = 0; index < input.recent.size() && index < kRecentCases; ++index) {
    const RecentCase& item = input.recent[index];
    BoardTile tile;
    tile.caption = item.active ? "ACTIVE" : "";
    tile.value = item.case_id;
    tile.detail = item.title.empty() ? "No title" : item.title;
    tile.pill = item.status;
    tile.highlight = item.active;
    tile.action = BoardAction::open_case;
    tile.page = WorkspacePage::case_dashboard;
    tile.target = item.root;
    recent.tiles.push_back(std::move(tile));
  }

  // Without an active case, picking one comes first.
  if (!input.has_case && !recent.tiles.empty()) {
    board.sections = {recent, flow, progress};
  } else {
    board.sections = {flow, progress};
    if (!recent.tiles.empty())
      board.sections.push_back(recent);
  }

  const auto link = [](std::string label, WorkspacePage page) {
    BoardLink made;
    made.label = std::move(label);
    made.page = page;
    return made;
  };
  BoardLink new_case;
  new_case.label = "New case";
  new_case.action = BoardAction::new_case;
  new_case.primary = true;
  board.links.push_back(new_case);
  board.links.push_back(link("Case Manager", WorkspacePage::case_manager));
  board.links.push_back(link("Log Review", WorkspacePage::log_review));
  board.links.push_back(link("Environment Review", WorkspacePage::environment_review));
  board.links.push_back(link("Health snapshot", WorkspacePage::health_monitor));
  board.links.push_back(link("Integrations", WorkspacePage::tool_manager));
  BoardLink role;
  role.label = "Switch to Customer / Lab";
  role.action = BoardAction::switch_role;
  role.right = true;
  board.links.push_back(role);
  return board;
}

// ------------------------------------------------------------------------- Customer / Lab Home

// The six health tiles: overall, CPU, memory, paging, storage, network.
inline std::vector<BoardTile> health_tiles(const SystemHealthSnapshot& snapshot, bool sampled) {
  using board_detail::count_text;
  std::vector<BoardTile> tiles(6);
  const char* captions[] = {"OVERALL", "CPU", "MEMORY", "PAGING", "STORAGE", "NETWORK"};
  for (std::size_t index = 0; index < tiles.size(); ++index) {
    tiles[index].caption = captions[index];
    tiles[index].action = BoardAction::open_page;
    tiles[index].page = WorkspacePage::health_monitor;
    tiles[index].link = "Health Monitor";
  }
  if (!sampled) {
    for (BoardTile& tile : tiles) {
      tile.value = "Sampling";
      tile.tone = ReportTone::quiet;
    }
    return tiles;
  }

  HealthSeverity worst = HealthSeverity::healthy;
  for (const HealthFinding& finding : snapshot.findings) {
    if (static_cast<int>(finding.severity) > static_cast<int>(worst))
      worst = finding.severity;
  }
  tiles[0].value = worst == HealthSeverity::critical  ? "Critical"
                   : worst == HealthSeverity::warning ? "Attention"
                                                       : "Healthy";
  tiles[0].tone = worst == HealthSeverity::critical  ? ReportTone::problem
                  : worst == HealthSeverity::warning ? ReportTone::attention
                                                      : ReportTone::good;
  tiles[0].detail = count_text(snapshot.findings.size(), "finding", "findings");

  tiles[1].value = snapshot.cpu_load_available ? board_detail::percent_text(snapshot.cpu_load_percent) : "Sampling";
  if (snapshot.cpu_temperature_celsius) {
    char temperature[24] = {};
    std::snprintf(temperature, sizeof(temperature), "%.0f °C", *snapshot.cpu_temperature_celsius);
    tiles[1].detail = temperature;
  } else {
    tiles[1].detail = "temperature not exposed";
  }
  tiles[1].tone = snapshot.cpu_load_percent >= 90.0 ? ReportTone::attention : ReportTone::normal;

  tiles[2].value = board_detail::percent_text(snapshot.memory_load_percent);
  tiles[2].detail = format_health_bytes(snapshot.memory_used_bytes) + " of " +
                    format_health_bytes(snapshot.memory_total_bytes);
  tiles[2].tone = snapshot.memory_load_percent >= 90.0 ? ReportTone::attention : ReportTone::normal;

  tiles[3].value = board_detail::one_decimal_percent(snapshot.memory.pagefile_load_percent);
  const double pages_in = snapshot.memory.pages_input_per_second.value_or(0.0);
  tiles[3].detail = pages_in < 0.5 ? "no hard faults"
                                   : std::to_string(static_cast<long long>(pages_in + 0.5)) + " pages in/s";

  // The fullest local volume, and how many are low (under 10% free).
  const VolumeHealth* fullest = nullptr;
  double fullest_used = -1.0;
  std::size_t low = 0;
  for (const VolumeHealth& volume : snapshot.volumes) {
    if (!volume.capacity_available || volume.total_bytes == 0U)
      continue;
    const double used = 100.0 * static_cast<double>(volume.total_bytes - std::min(volume.free_bytes, volume.total_bytes)) /
                        static_cast<double>(volume.total_bytes);
    if (used >= 90.0)
      ++low;
    if (used > fullest_used) {
      fullest_used = used;
      fullest = &volume;
    }
  }
  if (fullest == nullptr) {
    tiles[4].value = "—";
    tiles[4].detail = "no local volume read";
    tiles[4].tone = ReportTone::quiet;
  } else {
    std::string name = fullest->root_path;
    while (name.size() > 1U && (name.back() == '\\' || name.back() == '/'))
      name.pop_back();
    tiles[4].value = name + " " + board_detail::percent_text(fullest_used);
    tiles[4].detail = low == 0U ? count_text(snapshot.volumes.size(), "volume", "volumes")
                                : count_text(low, "volume low", "volumes low");
    tiles[4].tone = fullest_used >= 95.0 ? ReportTone::problem
                    : fullest_used >= 90.0 ? ReportTone::attention
                                           : ReportTone::normal;
  }

  double traffic = 0.0;
  std::size_t adapters = 0;
  for (const NetworkAdapterHealth& adapter : snapshot.network_adapters) {
    // Physical adapters that are up; Windows also lists miniports and disconnected cards.
    std::string status;
    for (const char character : adapter.operational_status)
      status.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    if (adapter.virtual_adapter || (!status.empty() && status != "up"))
      continue;
    ++adapters;
    traffic += adapter.receive_bytes_per_second.value_or(0.0) + adapter.transmit_bytes_per_second.value_or(0.0);
  }
  tiles[5].value = board_detail::rate_text(traffic);
  tiles[5].detail = count_text(adapters, "adapter", "adapters");
  return tiles;
}

// A detected Veeam product: its name and the role the catalogue gives it.
struct FoundProduct {
  std::string name; // "Veeam Backup & Replication"
  std::string role; // "Backup Server / Infrastructure"
};

struct LabBoardInput {
  SystemHealthSnapshot health;
  bool sampled = false;
  // This machine, read once.
  bool machine_read = false;
  std::string machine_name;
  std::string os_text; // "Windows 10.0.26200 x64", "Ubuntu 24.04.1 LTS"
  bool windows = true; // words the account line for the platform
  bool elevated = false;
  int utc_offset_minutes = 0;
  std::int64_t boot_unix_millis = 0; // 0 when not known
  std::int64_t now_unix_millis = 0;
  // Found on this machine.
  bool products_read = false;
  std::vector<FoundProduct> products;
  std::vector<std::string> guided; // the guided diagnostics that apply here
  bool services_read = false;
  std::size_t services_running = 0;
  std::vector<std::string> services_stopped; // Veeam services not running (stopped, starting, paused)
  // This session.
  std::size_t collections = 0;  // log collections made this session
  std::string last_collection;  // where the newest went, or its time
  bool has_output = false;
  std::string output_completed_utc; // ISO 8601, as the tool output's manifest records it
  std::string output_text;          // "Packet capture, 38 MB"
  bool restart_read = false;
  PendingRestartResult restart;
};

// The quick tools in the order the Tools menu lists them, by key.
inline constexpr ShortcutCommand kHomeQuickTools[] = {
    ShortcutCommand::name_check,      ShortcutCommand::local_port_checker, ShortcutCommand::time_check,
    ShortcutCommand::file_lock_check, ShortcutCommand::volume_check,       ShortcutCommand::file_transfer_calculator,
    ShortcutCommand::service_watch};

// The machine first: its health, what is on it, this session, then the quick
// tools and the pages behind them.
inline HomeBoard lab_home(const LabBoardInput& input) {
  using board_detail::count_text;
  HomeBoard board;
  board.sections.push_back({"THIS MACHINE'S HEALTH", 6, true, health_tiles(input.health, input.sampled)});

  BoardSection found{"FOUND ON THIS MACHINE", 4, false, {}};
  found.compact_when_short = true;
  BoardTile machine;
  machine.caption = "THIS MACHINE";
  if (!input.machine_read) {
    machine.value = "Reading";
    machine.tone = ReportTone::quiet;
  } else {
    machine.value = input.machine_name.empty() ? "This machine" : input.machine_name;
    std::string detail = input.os_text;
    if (input.boot_unix_millis > 0 && input.now_unix_millis > input.boot_unix_millis)
      detail += (detail.empty() ? "Up " : ", up ") + board_detail::uptime_text(input.now_unix_millis - input.boot_unix_millis);
    detail += (detail.empty() ? "" : ". ") + format_utc_offset(input.utc_offset_minutes) + ", ";
    detail += input.windows ? (input.elevated ? "administrator" : "not administrator")
                            : (input.elevated ? "root" : "not root");
    machine.detail = detail;
  }
  machine.link = "Environment Review";
  machine.action = BoardAction::open_page;
  machine.page = WorkspacePage::environment_review;
  found.tiles.push_back(machine);

  BoardTile products;
  products.caption = "VEEAM PRODUCTS";
  if (!input.products_read) {
    products.value = "Reading";
    products.tone = ReportTone::quiet;
  } else {
    products.value = std::to_string(input.products.size());
    if (input.products.empty()) {
      products.detail = "None found. Custom Paths still collects the files you choose.";
      products.tone = ReportTone::quiet;
    } else if (input.products.size() == 1U) {
      products.detail = input.products.front().name +
                        (input.products.front().role.empty() ? std::string() : ", " + input.products.front().role);
      products.tone = ReportTone::good;
    } else {
      std::vector<std::string> names;
      for (const FoundProduct& product : input.products)
        names.push_back(board_detail::short_product_name(product.name));
      products.detail = board_detail::joined(names);
      products.tone = ReportTone::good;
    }
  }
  products.link = "Details";
  products.action = BoardAction::products_details;
  found.tiles.push_back(products);

  BoardTile guided;
  guided.caption = "GUIDED DIAGNOSTICS";
  if (!input.products_read) {
    guided.value = "Reading";
    guided.tone = ReportTone::quiet;
  } else {
    guided.value = std::to_string(input.guided.size());
    guided.detail = input.guided.empty() ? "None apply to the products found here." : board_detail::joined(input.guided);
    guided.tone = input.guided.empty() ? ReportTone::quiet : ReportTone::normal;
  }
  guided.link = "Guided Diagnostics";
  guided.action = BoardAction::open_page;
  guided.page = WorkspacePage::guided_diagnostics;
  found.tiles.push_back(guided);

  BoardTile services;
  services.caption = "VEEAM SERVICES";
  if (!input.services_read) {
    services.value = "Reading";
    services.tone = ReportTone::quiet;
  } else if (input.services_running == 0U && input.services_stopped.empty()) {
    services.value = "None";
    services.detail = "No Veeam service on this machine.";
    services.tone = ReportTone::quiet;
  } else {
    services.value = std::to_string(input.services_running) + " running";
    services.detail = input.services_stopped.empty()
                          ? "All running."
                          : count_text(input.services_stopped.size(), "not running", "not running") + ": " +
                                board_detail::joined(input.services_stopped);
  }
  services.link = "Details";
  services.action = BoardAction::services_details;
  services.tool = ShortcutCommand::service_watch;
  found.tiles.push_back(services);
  board.sections.push_back(std::move(found));

  BoardSection session{"THIS SESSION", 3, false, {}};
  session.compact_when_short = true;
  BoardTile collected;
  collected.caption = "COLLECTED";
  if (input.collections == 0U) {
    collected.value = "Not yet";
    collected.detail = input.products.size() > 1U ? "Log Collection gathers every product found."
                                                  : "Log Collection gathers the logs support asks for.";
    collected.tone = ReportTone::attention;
  } else {
    collected.value = count_text(input.collections, "collection", "collections");
    collected.detail = input.last_collection;
    collected.tone = ReportTone::good;
  }
  collected.link = "Collect logs";
  collected.action = BoardAction::collect_logs;
  session.tiles.push_back(collected);

  BoardTile output;
  output.caption = "LAST OUTPUT";
  if (input.has_output) {
    // "2026-09-29T14:05:12Z" -> "14:05"
    output.value = input.output_completed_utc.size() >= 16U ? input.output_completed_utc.substr(11, 5) : "Ready";
    output.detail = input.output_text;
    output.link = "Prepare";
    output.action = BoardAction::prepare_output;
  } else {
    output.value = "None";
    output.detail = "Tools write their output here until it is prepared or deleted.";
    output.tone = ReportTone::quiet;
  }
  session.tiles.push_back(output);

  BoardTile restart;
  restart.caption = "PENDING RESTART";
  if (!input.restart_read) {
    restart.value = "Checking";
    restart.tone = ReportTone::quiet;
  } else {
    restart.value = input.restart.restart_needed ? "Waiting"
                    : input.restart.markers.empty() ? "None"
                                                     : "Files only";
    restart.tone = input.restart.restart_needed ? ReportTone::attention : ReportTone::good;
    std::string reasons;
    for (const RestartMarker& marker : input.restart.markers)
      reasons += (reasons.empty() ? "" : ", ") + marker.name;
    restart.detail = input.restart.markers.empty() ? "Nothing waits for the next start." : reasons;
    restart.link = "Details";
    restart.action = BoardAction::restart_details;
  }
  session.tiles.push_back(restart);
  board.sections.push_back(std::move(session));

  BoardLink collect;
  collect.label = "Collect logs";
  collect.action = BoardAction::collect_logs;
  collect.note = "Universal Veeam Log Collection, into Log-Collections";
  collect.primary = true;
  board.links.push_back(collect);
  if (input.has_output) {
    BoardLink prepare;
    prepare.label = "Prepare output";
    prepare.action = BoardAction::prepare_output;
    board.links.push_back(prepare);
    BoardLink remove;
    remove.label = "Delete output";
    remove.action = BoardAction::delete_output;
    board.links.push_back(remove);
  }
  bool first_tool = true;
  for (const ShortcutCommand tool : kHomeQuickTools) {
    const KeyboardShortcut* shortcut = shortcut_for(tool);
    if (shortcut == nullptr)
      continue;
    BoardLink link;
    link.label = std::string(shortcut->label);
    link.key = shortcut_text(tool);
    link.action = BoardAction::quick_tool;
    link.tool = tool;
    if (first_tool) {
      link.new_row = true;
      link.row_caption = "QUICK TOOLS";
      first_tool = false;
    }
    board.links.push_back(std::move(link));
  }
  const auto page_link = [](std::string label, WorkspacePage page) {
    BoardLink made;
    made.label = std::move(label);
    made.page = page;
    return made;
  };
  BoardLink tools = page_link("Tools", WorkspacePage::tools);
  tools.new_row = true;
  tools.row_caption = "OPEN";
  board.links.push_back(tools);
  board.links.push_back(page_link("Environment Review", WorkspacePage::environment_review));
  board.links.push_back(page_link("Log Review", WorkspacePage::log_review));
  board.links.push_back(page_link("Health Monitor", WorkspacePage::health_monitor));
  board.links.push_back(page_link("Recent Activity", WorkspacePage::recent_activity));
  BoardLink role;
  role.label = "Switch to Engineer Review";
  role.action = BoardAction::switch_role;
  role.right = true;
  board.links.push_back(role);
  return board;
}

// ------------------------------------------------------------------------------ Tools categories
//
// The categories themselves are the table in workspace_view_model.hpp (kToolCategoryTable). VBR
// Diagnostics shows with a local backup server, and Last Tool Output once a tool has produced
// output.

// The category of a Tools card, by the page it opens: the Linux host diagnostics open
// general_tools, and Prepare and Delete the last output open Home's modes 8 and 9.
inline ToolCategory tool_category_for(WorkspacePage page) {
  if (page == WorkspacePage::home)
    return ToolCategory::last_output;
  return tool_category_of_page(page).value_or(ToolCategory::host_diagnostics);
}

// Where the quick tools sit: Local Port Checker, Name Check and the File Transfer Calculator in
// Network Tools, after the card for network mode kNetworkQuickToolsFollowMode (the Remote Port
// Checker); the other four open Host Diagnostics under kQuickChecksSection.
inline ToolCategory quick_tool_category(ShortcutCommand tool) {
  switch (tool) {
  case ShortcutCommand::local_port_checker:
  case ShortcutCommand::name_check:
  case ShortcutCommand::file_transfer_calculator: return ToolCategory::network_tools;
  default: return ToolCategory::host_diagnostics;
  }
}

inline constexpr int kNetworkQuickToolsFollowMode = 0;
inline constexpr std::string_view kQuickChecksSection = "QUICK CHECKS";

// One category tile: its count and the names of its tools, in card order.
struct CategoryTile {
  ToolCategory category = ToolCategory::log_collection;
  std::size_t count = 0;
  std::string names;
};

// The tiles for the categories an edition lists, counted from the titles of its tool cards.
inline std::vector<CategoryTile> category_tiles(const std::vector<std::pair<ToolCategory, std::string>>& cards,
                                                const std::vector<ToolCategory>& listed) {
  std::vector<CategoryTile> tiles;
  for (const ToolCategory category : kToolCategories) {
    if (std::find(listed.begin(), listed.end(), category) == listed.end())
      continue;
    CategoryTile tile;
    tile.category = category;
    for (const auto& [card_category, title] : cards) {
      if (card_category != category)
        continue;
      ++tile.count;
      tile.names += (tile.names.empty() ? "" : ", ") + title;
    }
    tiles.push_back(std::move(tile));
  }
  return tiles;
}

inline std::string category_tile_text(const CategoryTile& tile) {
  if (tile.count > 0U)
    return tile.names;
  switch (tile.category) {
  case ToolCategory::guided_diagnostics: return "None apply to the products found here.";
  case ToolCategory::last_output: return "Shown once a tool has produced output.";
  default: return "Nothing to run on this machine.";
  }
}

// The Tools board: a compact tile per category, the one whose page shows drawn pressed in.
inline BoardSection tools_board(const std::vector<CategoryTile>& tiles, std::optional<ToolCategory> chosen) {
  BoardSection section{"", 4, true, {}};
  for (const CategoryTile& tile : tiles) {
    BoardTile board_tile;
    std::string caption(tool_category_title(tile.category));
    for (char& character : caption)
      character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
    board_tile.caption = caption;
    board_tile.value = std::to_string(tile.count);
    board_tile.detail = category_tile_text(tile);
    board_tile.selected = chosen && *chosen == tile.category;
    board_tile.tone = tile.count == 0U ? ReportTone::quiet : ReportTone::normal;
    board_tile.action = BoardAction::open_page;
    board_tile.page = tool_category_page(tile.category);
    section.tiles.push_back(std::move(board_tile));
  }
  return section;
}

// The quick tools as Tools cards: badge, title and description.
struct QuickToolCard {
  ShortcutCommand tool = ShortcutCommand::help;
  std::string badge;
  std::string title;
  std::string description;
};

inline std::vector<QuickToolCard> quick_tool_cards() {
  const auto card = [](ShortcutCommand tool, const char* badge) {
    QuickToolCard made;
    made.tool = tool;
    made.badge = badge;
    if (const KeyboardShortcut* shortcut = shortcut_for(tool)) {
      made.title = std::string(shortcut->label);
      made.description = std::string(shortcut->detail);
    }
    return made;
  };
  return {card(ShortcutCommand::local_port_checker, "PORTS"), card(ShortcutCommand::name_check, "DNS"),
          card(ShortcutCommand::file_transfer_calculator, "CALC"),
          card(ShortcutCommand::time_check, "TIME"),         card(ShortcutCommand::file_lock_check, "LOCK"),
          card(ShortcutCommand::volume_check, "VOL"),        card(ShortcutCommand::service_watch, "WATCH")};
}

} // namespace support_assist::gui
