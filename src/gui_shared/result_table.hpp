#pragma once

// The result tables of the Tools pages that keep runs or repeat a group, for both editions. A run
// opens with a RUN row (the tool, its target, the UTC time and the run's outcome); the newest run is
// first and the earlier ones stay under it, dimmed. Guided Diagnostics shows a row per step, and the
// RESULT and CASE NOTE rows close the run. A grouped table shows each group once, as a section row
// with its count, and the group's checks under it. The editions keep the rows they were given (the
// tool output and the exports read those) and show the table built here from them.

#include "host_checks_form.hpp"
#include "tool_output.hpp"
#include "workspace_view_model.hpp"
#include "support_assist/sql_check.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

enum class ResultLayout { plain, run_history, guided, grouped, query };

enum class ResultRowKind { data, run, section };

using RawResultRow = std::array<std::string, 4>;

struct ResultTableRow {
  ResultRowKind kind = ResultRowKind::data;
  std::array<std::string, 4> cells{}; // in the shown column order; a section row's text is in cells[1]
  std::vector<std::string> extra_cells; // a query grid's columns after the fourth
  bool earlier = false;               // a row of an earlier run, shown dimmed
  std::string detail;                 // the detail pane's text when it is not the cells
};

struct ResultTable {
  std::array<std::string, 4> headings{}; // an empty heading is a column not shown
  std::vector<std::string> extra_headings; // a query grid's columns after the fourth
  std::vector<ResultTableRow> rows;
};

// SQL Tools' Read-only query mode: its results show as a grid.
inline constexpr int kSqlQueryResultMode = 4;

// The number of columns a table shows: four, or a query grid's own count.
inline std::size_t result_table_column_count(const ResultTable& table) {
  if (table.extra_headings.empty()) {
    std::size_t count = 4;
    while (count > 1U && table.headings[count - 1U].empty())
      --count;
    return count;
  }
  return 4U + table.extra_headings.size();
}

inline constexpr const char* kRunRowArea = "RUN";
inline constexpr const char* kStopRowArea = "STOP";
inline constexpr const char* kRunRowRunning = "Running";

// Modes that are tables of their own on the pages that otherwise keep runs.
inline constexpr int kProcessInventoryResultMode = 13;
inline constexpr int kInstallerCacheResultMode = 25;
inline constexpr int kWmiHealthResultMode = 26;
inline constexpr int kNamedPipesResultMode = 29;

inline ResultLayout result_layout_for(WorkspacePage page, int mode) {
  switch (page) {
  case WorkspacePage::network_tools:
    return ResultLayout::run_history;
  case WorkspacePage::guided_diagnostics:
    return ResultLayout::guided;
  case WorkspacePage::general_tools:
    if (mode == kHostChecksMode)
      return ResultLayout::grouped;
    if (mode == kInstallerCacheResultMode || mode == kNamedPipesResultMode || mode == kProcessInventoryResultMode)
      return ResultLayout::plain;
    return ResultLayout::run_history;
  case WorkspacePage::wmi_diagnostics:
    if (mode == kWmiHealthResultMode)
      return ResultLayout::grouped;
    if (mode == kProcessInventoryResultMode)
      return ResultLayout::plain;
    return ResultLayout::run_history;
  case WorkspacePage::sql_tools:
    return mode == kSqlQueryResultMode ? ResultLayout::query : ResultLayout::plain;
  default:
    return ResultLayout::plain;
  }
}

// A layout that keeps the earlier runs under the newest one.
inline bool result_layout_keeps_runs(ResultLayout layout) {
  return layout == ResultLayout::run_history || layout == ResultLayout::guided;
}

inline bool is_run_row(const RawResultRow& row) { return row[0] == kRunRowArea || row[0] == kStopRowArea; }

namespace result_table_detail {

inline std::string lower(std::string_view text) {
  std::string folded(text);
  for (char& character : folded) {
    if (character >= 'A' && character <= 'Z')
      character = static_cast<char>(character - 'A' + 'a');
  }
  return folded;
}

inline std::string upper(std::string_view text) {
  std::string raised(text);
  for (char& character : raised) {
    if (character >= 'a' && character <= 'z')
      character = static_cast<char>(character - 'a' + 'A');
  }
  return raised;
}

inline bool has(const std::string& folded, std::string_view token) { return folded.find(token) != std::string::npos; }

inline std::string renamed(std::string_view heading) {
  if (heading == "Protocol")
    return "Check";
  if (heading == "IP Address")
    return "Address";
  if (heading == "Result")
    return "Status";
  return std::string(heading);
}

// A guided step's Found text and what follows it (the meaning, the next step, the sources).
inline constexpr std::array<std::string_view, 3> kStepParts{"  Meaning: ", "  Next: ", "  Sources: "};

inline std::pair<std::string, std::string> split_step_detail(const std::string& detail) {
  std::size_t cut = std::string::npos;
  for (std::string_view part : kStepParts)
    cut = std::min(cut, detail.find(part));
  if (cut == std::string::npos)
    return {detail, {}};
  std::string rest = detail.substr(cut + 2U);
  for (std::string_view part : kStepParts) {
    const std::string marker(part);
    for (std::size_t at = rest.find(marker); at != std::string::npos; at = rest.find(marker, at + 1U))
      rest.replace(at, 2U, "\n");
  }
  return {detail.substr(0, cut), rest};
}

} // namespace result_table_detail

// "2026-10-22T14:32:45Z" as the RUN row shows it: "2026-10-22 14:32:45 UTC".
inline std::string run_time_text(std::string_view iso) {
  std::string text(iso);
  if (const auto t = text.find('T'); t != std::string::npos)
    text[t] = ' ';
  if (const auto dot = text.find('.'); dot != std::string::npos) {
    const auto zone = text.find('Z', dot);
    text.erase(dot, zone == std::string::npos ? std::string::npos : zone - dot);
  }
  if (!text.empty() && text.back() == 'Z')
    text.back() = ' ';
  else
    text += ' ';
  return text + "UTC";
}

// What a run was pointed at: "localhost : 2500 / TCP" when the form has a Host, else the machine.
inline std::string run_target_text(std::string_view tool, const std::vector<FormSummaryField>& fields,
                                   std::string_view machine) {
  std::string host;
  std::string port;
  for (const FormSummaryField& field : fields) {
    const std::string label = result_table_detail::lower(field.label);
    if (host.empty() && (label == "host" || label == "target" || label == "target host"))
      host = std::string(trim(field.value));
    else if (port.empty() && label == "port")
      port = std::string(trim(field.value));
  }
  if (host.empty())
    return std::string(machine);
  std::string target = host + (port.empty() ? std::string() : " : " + port);
  const std::string title(tool);
  if (title.find("TCP") != std::string::npos)
    target += " / TCP";
  else if (title.find("UDP") != std::string::npos)
    target += " / UDP";
  return target;
}

// A time as run_row takes it: "2026-10-22T14:32:45Z".
inline std::string utc_iso_of(std::chrono::system_clock::time_point when) {
  const std::time_t seconds = std::chrono::system_clock::to_time_t(when);
  std::tm parts{};
#ifdef _WIN32
  gmtime_s(&parts, &seconds);
#else
  gmtime_r(&seconds, &parts);
#endif
  char text[32]{};
  std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &parts);
  return text;
}

// How long a run took: "2.1 s", "1 min 05 s", "1 h 02 min".
inline std::string run_runtime_text(std::chrono::milliseconds runtime) {
  const long long millis = std::max<long long>(0, runtime.count());
  char text[32]{};
  if (millis < 60000)
    std::snprintf(text, sizeof(text), "%lld.%lld s", millis / 1000, (millis % 1000) / 100);
  else if (millis < 3600000)
    std::snprintf(text, sizeof(text), "%lld min %02lld s", millis / 60000, (millis % 60000) / 1000);
  else
    std::snprintf(text, sizeof(text), "%lld h %02lld min", millis / 3600000, (millis % 3600000) / 60000);
  return text;
}

// The row a run starts with: the tool, its target, the UTC start and, once it ends, its runtime and
// outcome. The outcome reads Running until the run ends.
inline RawResultRow run_row(std::string_view tool, std::string_view target, std::string_view utc_iso,
                            std::string_view outcome = kRunRowRunning, bool stop = false,
                            std::string_view runtime = {}) {
  std::string when = run_time_text(utc_iso);
  if (!runtime.empty())
    when += "  |  " + std::string(runtime);
  return {stop ? kStopRowArea : kRunRowArea, std::string(tool),
          target.empty() ? when : std::string(target) + "  |  " + when, std::string(outcome)};
}

enum class StatusTone { other, fail, attention, pass };

// The tone of a status cell, by the words the tools write.
inline StatusTone status_tone(std::string_view status) {
  using result_table_detail::has;
  const std::string state = result_table_detail::lower(status);
  if (has(state, "fail") || has(state, "error") || has(state, "blocked") || has(state, "mismatch") ||
      has(state, "timed out") || has(state, "refused") || has(state, "closed"))
    return StatusTone::fail;
  if (has(state, "warning") || has(state, "finding") || has(state, "partial") || has(state, "indeterminate") ||
      has(state, "no ack") || has(state, "review") || has(state, "attention") || has(state, "could not check") ||
      has(state, "needs administrator"))
    return StatusTone::attention;
  if (has(state, "pass") || has(state, "connected") || has(state, "verified") || has(state, "resolved") ||
      has(state, "received") || has(state, "listening") || has(state, "ack sent") || has(state, "trusted") ||
      state == "open" || state == "ok")
    return StatusTone::pass;
  return StatusTone::other;
}

// The group row's window on a table whose form has Days ("last 7 days"); empty without one.
inline std::string result_group_note(const std::vector<FormSummaryField>& fields) {
  for (const FormSummaryField& field : fields) {
    const std::string value(trim(field.value));
    if (result_table_detail::lower(field.label) == "days" && !value.empty())
      return "last " + value + (value == "1" ? " day" : " days");
  }
  return {};
}

// A finished run's outcome for its RUN row: the scenario's result when it has one, else the tool's
// own words from its status line ("TCP diagnostic completed: no tested path connected" gives "no
// tested path connected"), else the rows counted by tone ("2 failed, 1 to look at, 5 passed").
inline std::string run_outcome(const std::vector<RawResultRow>& rows, std::string_view message = {}) {
  for (const RawResultRow& row : rows) {
    if (row[0] == "Result" && !row[2].empty())
      return row[2];
  }
  std::string own(trim(message));
  if (const auto colon = own.find(": "); colon != std::string::npos)
    own = std::string(trim(own.substr(colon + 2U)));
  while (!own.empty() && own.back() == '.')
    own.pop_back();
  if (!own.empty())
    return own;
  std::size_t failed = 0;
  std::size_t attention = 0;
  std::size_t passed = 0;
  std::size_t counted = 0;
  for (const RawResultRow& row : rows) {
    if (is_run_row(row) || is_live_progress_row(row[0]) || row[0] == "Case note" || row[0] == "DONE" ||
        row[3].empty())
      continue;
    ++counted;
    switch (status_tone(row[3])) {
    case StatusTone::fail:
      ++failed;
      break;
    case StatusTone::attention:
      ++attention;
      break;
    case StatusTone::pass:
      ++passed;
      break;
    case StatusTone::other:
      break;
    }
  }
  if (counted == 0U)
    return "no rows";
  std::string outcome;
  const auto add = [&](std::size_t count, const char* words) {
    if (count == 0U)
      return;
    outcome += (outcome.empty() ? "" : ", ") + std::to_string(count) + " " + words;
  };
  add(failed, "failed");
  add(attention, "to look at");
  add(passed, "passed");
  if (outcome.empty())
    outcome = std::to_string(counted) + (counted == 1U ? " row" : " rows");
  return outcome;
}

namespace result_table_detail {

inline ResultTableRow run_header(const RawResultRow& row) {
  ResultTableRow shown;
  shown.kind = ResultRowKind::run;
  shown.cells[0] = row[0] + " " + row[1];
  shown.cells[1] = row[2] + (row[3].empty() ? std::string() : "  |  " + row[3]);
  shown.detail = shown.cells[0] + "\n" + shown.cells[1];
  return shown;
}

inline ResultTableRow section(std::string label, std::string text, std::string detail = {}) {
  ResultTableRow shown;
  shown.kind = ResultRowKind::section;
  shown.cells[0] = std::move(label);
  shown.cells[1] = std::move(text);
  shown.detail = detail.empty() ? shown.cells[0] + "\n" + shown.cells[1] : std::move(detail);
  return shown;
}

inline ResultTableRow reordered(const RawResultRow& row) {
  ResultTableRow shown;
  shown.cells = {row[0], row[1], row[3], row[2]};
  return shown;
}

inline void add_guided(std::vector<ResultTableRow>& out, const std::vector<RawResultRow>& body) {
  std::string note;
  for (const RawResultRow& row : body) {
    if (row[0] == "Case note") {
      note += (note.empty() ? "" : "\n") + row[2];
      continue;
    }
    if (row[0] == "Result") {
      out.push_back(section("RESULT", row[2].empty() ? row[3] : row[2]));
      continue;
    }
    if (row[0].rfind("Step ", 0) == 0U) {
      auto [found, rest] = split_step_detail(row[2]);
      ResultTableRow shown;
      shown.cells = {row[0].substr(5), row[1], row[3], found};
      shown.detail = row[0] + ": " + row[1] + (row[3].empty() ? "" : "  " + row[3]) + "\n" + found +
                     (rest.empty() ? "" : "\n" + rest);
      out.push_back(std::move(shown));
      continue;
    }
    out.push_back(reordered(row));
  }
  if (!note.empty())
    out.push_back(section("CASE NOTE", "ready to copy: select this row", note));
}

inline void add_grouped(std::vector<ResultTableRow>& out, const std::vector<RawResultRow>& body,
                        const std::string& event_window) {
  for (std::size_t index = 0; index < body.size();) {
    const std::string& group = body[index][0];
    std::size_t end = index;
    while (end < body.size() && body[end][0] == group)
      ++end;
    const std::size_t count = end - index;
    // An events group reads its window too ("8 checks, last 7 days").
    const bool events = !event_window.empty() && lower(group).find("event") != std::string::npos;
    if (!group.empty())
      out.push_back(section(upper(group), std::to_string(count) + (count == 1U ? " check" : " checks") +
                                              (events ? ", " + event_window : std::string())));
    for (; index < end; ++index) {
      const RawResultRow& row = body[index];
      ResultTableRow shown;
      shown.cells = {(group.empty() ? "" : "    ") + row[1], row[2], row[3], std::string()};
      shown.detail = (group.empty() ? std::string() : group + ": ") + row[1] + (row[3].empty() ? "" : "  " + row[3]) +
                     "\n" + row[2];
      out.push_back(std::move(shown));
    }
  }
}

} // namespace result_table_detail

// A read-only query's rows (SQL Tools) as a grid: the row's name, then the columns the grid shows (all
// of them up to seven, else the query's main columns); the selected row's every column goes to the
// detail pane, one "name<TAB>value" line each. A result with no rows, an error or a cut-off list reads as
// a section row.
inline ResultTable query_result_table(const std::vector<RawResultRow>& rows) {
  ResultTable table;
  std::vector<std::array<std::string, 3>> triples;
  triples.reserve(rows.size());
  for (const RawResultRow& row : rows) {
    // A query shows its newest result only: the RUN row an edition adds is not part of it.
    if (!is_run_row(row))
      triples.push_back({row[0], row[1], row[2]});
  }
  // A result set starts with its Columns row; rows without one are a query that did not run, saying why.
  const bool result = std::any_of(triples.begin(), triples.end(),
                                  [](const auto& triple) { return triple[0] == kSqlQueryColumnsArea; });
  const auto grids = result ? sql_query_grids(triples) : std::vector<SqlQueryGrid>{};
  if (grids.empty()) {
    if (triples.empty())
      return table;
    // No result set: a query that did not run, whose rows say why.
    table.headings = {"Query", "Result", "Details", "Status"};
    for (const RawResultRow& row : rows) {
      if (is_run_row(row))
        continue;
      ResultTableRow shown;
      shown.cells = row;
      table.rows.push_back(std::move(shown));
    }
    return table;
  }
  const SqlQueryGrid& grid = grids.front();
  const auto shown = sql_query_shown_columns(grid, sql_query_main_columns(grid));
  std::vector<std::string> headings{grid.label_heading.empty() ? std::string("Row") : grid.label_heading};
  for (const std::size_t column : shown)
    headings.push_back(grid.columns[column]);
  for (std::size_t index = 0; index < headings.size(); ++index) {
    if (index < 4U)
      table.headings[index] = headings[index];
    else
      table.extra_headings.push_back(headings[index]);
  }
  for (std::size_t row = 0; row < grid.labels.size(); ++row) {
    ResultTableRow shown_row;
    std::vector<std::string> cells{grid.labels[row]};
    for (const std::size_t column : shown)
      cells.push_back(grid.cells[row][column]);
    for (std::size_t index = 0; index < cells.size(); ++index) {
      if (index < 4U)
        shown_row.cells[index] = cells[index];
      else
        shown_row.extra_cells.push_back(cells[index]);
    }
    shown_row.detail = headings.front() + "\t" + grid.labels[row];
    for (std::size_t column = 0; column < grid.columns.size(); ++column)
      shown_row.detail += "\n" + grid.columns[column] + "\t" + grid.cells[row][column];
    table.rows.push_back(std::move(shown_row));
  }
  const auto note_row = [&table](const std::string& text) {
    ResultTableRow note;
    note.kind = ResultRowKind::section;
    note.cells[1] = text;
    note.detail = text;
    table.rows.push_back(std::move(note));
  };
  for (const std::string& note : grid.notes)
    note_row(note);
  for (std::size_t set = 1; set < grids.size(); ++set)
    note_row("Result set " + std::to_string(set + 1U) + ": " + std::to_string(grids[set].labels.size()) +
             " rows. sql query on the command line lists every set.");
  return table;
}

// A query's result as tab-separated text, a header line and a line per row, kept as query.tsv beside
// result.tsv so a spreadsheet opens it as rows and columns; empty for rows that are not a query's.
inline std::string query_tsv_text(const std::vector<RawResultRow>& rows) {
  std::vector<std::array<std::string, 3>> triples;
  bool query = false;
  for (const RawResultRow& row : rows) {
    query = query || row[0] == kSqlQueryColumnsArea;
    if (!is_run_row(row))
      triples.push_back({row[0], row[1], row[2]});
  }
  if (!query)
    return {};
  const auto grids = sql_query_grids(triples);
  return grids.empty() ? std::string() : sql_query_tsv(grids.front());
}

// The table to show for a session's rows: runs split at their RUN rows, the newest first.
inline ResultTable result_table(ResultLayout layout, const std::vector<std::string>& columns,
                                const std::vector<RawResultRow>& rows, const std::string& event_window = {}) {
  using namespace result_table_detail;
  if (layout == ResultLayout::query)
    return query_result_table(rows);
  ResultTable table;
  const auto column = [&](std::size_t index) { return index < columns.size() ? columns[index] : std::string(); };
  switch (layout) {
  case ResultLayout::plain:
    table.headings = {column(0), column(1), column(2), column(3)};
    break;
  case ResultLayout::run_history:
    table.headings = {renamed(column(0)), renamed(column(1)), renamed(column(3)), renamed(column(2))};
    break;
  case ResultLayout::guided:
    table.headings = {"Step", "Check", "Status", "Found"};
    break;
  case ResultLayout::grouped:
    table.headings = {column(1), column(2), column(3), std::string()};
    break;
  case ResultLayout::query:
    break;
  }
  if (layout == ResultLayout::plain) {
    for (const RawResultRow& row : rows) {
      ResultTableRow shown;
      shown.cells = row;
      table.rows.push_back(std::move(shown));
    }
    return table;
  }

  struct Run {
    const RawResultRow* header = nullptr;
    std::vector<RawResultRow> body;
  };
  std::vector<Run> runs;
  for (const RawResultRow& row : rows) {
    if (is_run_row(row) || runs.empty())
      runs.push_back({});
    if (is_run_row(row))
      runs.back().header = &row;
    else
      runs.back().body.push_back(row);
  }
  for (std::size_t index = runs.size(); index > 0U; --index) {
    const Run& run = runs[index - 1U];
    const std::size_t first = table.rows.size();
    if (run.header != nullptr)
      table.rows.push_back(run_header(*run.header));
    if (layout == ResultLayout::guided) {
      add_guided(table.rows, run.body);
    } else if (layout == ResultLayout::grouped) {
      add_grouped(table.rows, run.body, event_window);
    } else {
      for (const RawResultRow& row : run.body)
        table.rows.push_back(reordered(row));
    }
    if (index != runs.size()) {
      for (std::size_t shown = first; shown < table.rows.size(); ++shown)
        table.rows[shown].earlier = true;
    }
  }
  return table;
}

// The newest run's RUN row, taken out of the table to show as the line above it; the earlier runs
// keep theirs in the table. Nothing when the table does not start with the newest run's RUN row.
inline std::optional<ResultTableRow> take_current_run(ResultTable& table) {
  if (table.rows.empty() || table.rows.front().kind != ResultRowKind::run || table.rows.front().earlier)
    return std::nullopt;
  ResultTableRow run = std::move(table.rows.front());
  table.rows.erase(table.rows.begin());
  return run;
}

// That line: "RUN Remote Port Checker    localhost : 2500 / TCP  |  ...  |  no tested path connected".
inline std::string run_header_text(const ResultTableRow& run) { return run.cells[0] + "    " + run.cells[1]; }

// The selected row in the detail pane: its own text when it has one, else each column in full.
inline std::string result_table_row_detail(const ResultTable& table, const ResultTableRow& row) {
  if (!row.detail.empty())
    return row.detail;
  std::vector<std::string> headings;
  std::vector<std::string> cells;
  for (std::size_t index = 0; index < row.cells.size(); ++index) {
    if (table.headings[index].empty() && row.cells[index].empty())
      continue;
    headings.push_back(table.headings[index]);
    cells.push_back(row.cells[index]);
  }
  return result_row_detail(headings, cells);
}

} // namespace support_assist::gui
