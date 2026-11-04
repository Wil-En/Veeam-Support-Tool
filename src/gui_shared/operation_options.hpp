#pragma once

// What each field, path and tick box of a Tools operation does, and whether it is required, for the
// OPTIONS section of the hint card (operation_guide.hpp). The words are data,
// config/checks/operation-options.json, found by the operation's title as its form shows it and by
// the option's label. An option can be for one edition. tools/test_operation_options.py checks that
// every shared operation's fields have an entry. A Guided Diagnostics scenario's inputs carry their
// own words (support_assist/scenarios.hpp).

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"

#include <optional>
#include <string>

namespace support_assist::gui {

#ifdef _WIN32
inline constexpr bool kOptionsHostIsWindows = true;
#else
inline constexpr bool kOptionsHostIsWindows = false;
#endif

struct OperationOptionHelp {
  std::string label;
  std::string kind; // field, path or tick box
  bool required = false;
  std::string text;
};

// The option with this label on the operation with this title, for this edition; empty when the
// file has none.
inline std::optional<OperationOptionHelp> operation_option(const std::string& title, const std::string& label,
                                                       bool on_windows = kOptionsHostIsWindows) {
  const JsonValue& file = data_file("operation-options.json");
  for (const JsonValue& entry : file["operations"].items()) {
    bool named = false;
    for (const std::string& name : entry["titles"].string_items())
      named = named || name == title;
    if (!named)
      continue;
    for (const JsonValue& item : entry["options"].items()) {
      const std::string platform = item["platform"].as_string();
      if (!platform.empty() && platform != "both" && platform != (on_windows ? "windows" : "linux"))
        continue;
      if (item["label"].as_string() != label)
        continue;
      return OperationOptionHelp{label, item["kind"].as_string(), item["need"].as_string() == "required",
                             item["text"].as_string()};
    }
  }
  return std::nullopt;
}

} // namespace support_assist::gui
