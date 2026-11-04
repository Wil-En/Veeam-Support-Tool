#pragma once

// What to prepare before a Tools operation runs, and on which machine, for the hint card
// (operation_guide.hpp). The lines are data, config/checks/operation-setup.json, found by the
// operation's title as its form shows it. An entry can be for one edition, and can add lines for
// Windows or for Linux after its common ones. An operation that needs nothing prepared has no entry.
// A Guided Diagnostics scenario carries its own setup (support_assist/scenarios.hpp).

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"

#include <string>
#include <vector>

namespace support_assist::gui {

#ifdef _WIN32
inline constexpr bool kSetupHostIsWindows = true;
#else
inline constexpr bool kSetupHostIsWindows = false;
#endif

namespace operation_setup_detail {

// Whether the entry is for this edition: no platform, "both", or the edition's own.
inline bool entry_applies(const JsonValue& entry, bool on_windows) {
  const std::string platform = entry["platform"].as_string();
  return platform.empty() || platform == "both" || platform == (on_windows ? "windows" : "linux");
}

inline bool entry_is_named(const JsonValue& entry, const std::string& title) {
  for (const std::string& name : entry["titles"].string_items()) {
    if (name == title)
      return true;
  }
  return false;
}

} // namespace operation_setup_detail

// The setup lines for the operation with this title, in order: the lines of every entry that names it
// and applies to this edition, each entry's common lines and then its Windows or Linux ones. Empty
// when nothing has to be prepared.
inline std::vector<std::string> operation_setup_steps(const std::string& title, bool on_windows = kSetupHostIsWindows) {
  std::vector<std::string> steps;
  const JsonValue& file = data_file("operation-setup.json");
  for (const JsonValue& entry : file["operations"].items()) {
    if (!operation_setup_detail::entry_applies(entry, on_windows) || !operation_setup_detail::entry_is_named(entry, title))
      continue;
    for (const std::string& line : entry["setup"].string_items())
      steps.push_back(line);
    for (const std::string& line : entry[on_windows ? "setup_windows" : "setup_linux"].string_items())
      steps.push_back(line);
  }
  return steps;
}

} // namespace support_assist::gui
