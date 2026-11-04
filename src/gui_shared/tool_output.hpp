#pragma once

// A Tools operation's output on both editions. While it runs, its table shows live rows: one per step
// the run reaches, the step in hand updating in place. When it ends, the results replace them and the
// form folds to one summary line; a selected row shows in full in the detail pane.

#include "progress_list.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

// The first cell of a live progress row; the results that follow a run replace these rows.
inline constexpr const char* kLiveProgressArea = "Progress";
inline constexpr const char* kLiveProgressRunning = "Running";

using LiveRow = std::array<std::string, 4>; // area, step, count, state

struct LiveProgressRows {
  std::optional<LiveRow> finished; // the step before, now Done: it replaces the running row
  std::optional<LiveRow> current;  // the step in hand
  bool current_replaces = false;   // true: the running row shown already takes these values
};

// Turns progress events into live rows. A new step shows at once; the running row's count updates in
// place at most once per interval, so a fast loop does not flood the window.
class LiveProgress {
public:
  explicit LiveProgress(std::chrono::milliseconds interval = std::chrono::milliseconds(250)) : interval_(interval) {}

  LiveProgressRows add(const ProgressEvent& event, std::chrono::steady_clock::time_point now) {
    LiveProgressRows out;
    const ProgressChange change = list_.add(event);
    if (change == ProgressChange::none)
      return out;
    const auto& rows = list_.rows();
    if (change == ProgressChange::advanced && rows.size() >= 2U) {
      out.finished = row_of(rows[rows.size() - 2U]);
      out.current = row_of(rows.back());
      last_shown_ = now;
      return out;
    }
    if (!shown_any_) {
      shown_any_ = true;
      out.current = row_of(rows.back());
      last_shown_ = now;
      return out;
    }
    if (now - last_shown_ < interval_)
      return out;
    out.current = row_of(rows.back());
    out.current_replaces = true;
    last_shown_ = now;
    return out;
  }

  static LiveRow row_of(const ProgressListRow& row) {
    return {kLiveProgressArea, row.what, row.extent,
            row.state == kProgressCurrent ? std::string(kLiveProgressRunning) : row.state};
  }

private:
  ProgressList list_;
  std::chrono::milliseconds interval_;
  std::chrono::steady_clock::time_point last_shown_{};
  bool shown_any_ = false;
};

inline bool is_live_progress_row(std::string_view first_cell) { return first_cell == kLiveProgressArea; }

struct FormSummaryField {
  std::string label;
  std::string value;
};

namespace tool_output_detail {
inline std::string one_line(std::string_view text, std::size_t limit) {
  std::string line(text.substr(0, text.find_first_of("\r\n")));
  if (line.size() > limit)
    line = line.substr(0, limit) + "...";
  return line;
}
} // namespace tool_output_detail

// The form in one line after a run: the operation, each field with a value, then the ticked options.
inline std::string folded_form_summary(std::string_view operation, const std::vector<FormSummaryField>& fields,
                                       const std::vector<std::string>& ticked) {
  std::string summary(operation);
  for (const FormSummaryField& field : fields) {
    const std::string value = tool_output_detail::one_line(field.value, 80);
    if (value.empty())
      continue;
    if (!summary.empty())
      summary += "  |  ";
    summary += field.label.empty() ? value : field.label + ": " + value;
  }
  std::string options;
  for (const std::string& option : ticked) {
    if (option.empty())
      continue;
    if (!options.empty())
      options += ", ";
    options += option;
  }
  if (!options.empty())
    summary += (summary.empty() ? "" : "  |  ") + options;
  return summary;
}

// A result row in full for the detail pane: each column as "Heading: value", the longest value last
// on its own lines, so a long detail reads without the table cutting it.
inline std::string result_row_detail(const std::vector<std::string>& headings, const std::vector<std::string>& cells) {
  std::size_t longest = cells.size();
  for (std::size_t index = 0; index < cells.size(); ++index) {
    if (cells[index].size() > 60U && (longest == cells.size() || cells[index].size() > cells[longest].size()))
      longest = index;
  }
  std::string detail;
  for (std::size_t index = 0; index < cells.size(); ++index) {
    if (index == longest || cells[index].empty())
      continue;
    const std::string heading = index < headings.size() ? headings[index] : std::string();
    detail += (heading.empty() ? std::string() : heading + ": ") + cells[index] + "\n";
  }
  if (longest < cells.size()) {
    const std::string heading = longest < headings.size() ? headings[longest] : std::string();
    detail += "\n" + (heading.empty() ? std::string() : heading + "\n") + cells[longest] + "\n";
  }
  return detail;
}

} // namespace support_assist::gui
