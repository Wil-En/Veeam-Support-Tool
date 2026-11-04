#pragma once

// A long run's progress as a list, on both editions: one row for each file (or each step without
// a file) the run reaches, the one in hand marked Current and each before it Done, instead of one
// line rewritten. Log Review shows it in its table while the parse runs.

#include "support_assist/progress.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace support_assist::gui {

inline constexpr const char* kProgressCurrent = "Current";
inline constexpr const char* kProgressDone = "Done";

struct ProgressListRow {
  std::string state;  // Current or Done
  std::string what;   // the step, and the file when the step names one
  std::string extent; // "3 / 20", "12 processed", or empty
};

enum class ProgressChange {
  none,     // nothing to show
  updated,  // the current row changed in place
  advanced, // the previous row is Done and a new current row follows it
};

class ProgressList {
public:
  ProgressChange add(const ProgressEvent& event) {
    std::string key = event.current_scope.empty() ? event.phase : event.current_scope;
    if (key.empty())
      key = "Working";
    std::string scope = event.current_scope;
    std::string extent;
    // The parser starts its scope with the count, "3/20 | <file> | 972 line(s)": the count is the
    // extent, the rest says what.
    const std::size_t slash = scope.find('/');
    const std::size_t bar = scope.find(" | ");
    if (slash != std::string::npos && bar != std::string::npos && slash < bar && slash != 0U &&
        scope.find_first_not_of("0123456789") == slash &&
        scope.find_first_not_of("0123456789", slash + 1U) == bar && bar > slash + 1U) {
      extent = scope.substr(0, slash) + " / " + scope.substr(slash + 1U, bar - slash - 1U);
      scope.erase(0, bar + 3U);
    } else if (event.total != 0U) {
      extent = std::to_string(event.processed) + " / " + std::to_string(event.total);
    } else if (event.processed != 0U) {
      extent = std::to_string(event.processed) + " processed";
    }
    std::string what = event.phase.empty() ? std::string("Working") : event.phase;
    if (!scope.empty())
      what += " | " + scope;

    if (!rows_.empty() && key == current_key_) {
      ProgressListRow& current = rows_.back();
      if (current.what == what && current.extent == extent)
        return ProgressChange::none;
      current.what = std::move(what);
      current.extent = std::move(extent);
      return ProgressChange::updated;
    }
    const bool had_current = !rows_.empty();
    if (had_current)
      rows_.back().state = kProgressDone;
    current_key_ = std::move(key);
    rows_.push_back({kProgressCurrent, std::move(what), std::move(extent)});
    return had_current ? ProgressChange::advanced : ProgressChange::updated;
  }

  // The run ended: the last row is Done too.
  void finish() {
    if (!rows_.empty())
      rows_.back().state = kProgressDone;
  }

  const std::vector<ProgressListRow>& rows() const { return rows_; }

private:
  std::string current_key_;
  std::vector<ProgressListRow> rows_;
};

} // namespace support_assist::gui
