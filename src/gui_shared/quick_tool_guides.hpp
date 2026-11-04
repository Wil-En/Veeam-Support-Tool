#pragma once

// A quick tool's guide, shown in its window until the first result on both editions and drawn as a
// report, in the same cards as a result: what the tool checks, then one short line for each way to use
// it. The full instructions are the tool's Help article (quick_tool_help.hpp), which F1 opens.

#include "keyboard_shortcuts.hpp"
#include "quick_tool_help.hpp"
#include "quick_tool_reports.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace support_assist::gui {

// A tool with modes (the File Transfer Calculator's Manual and Live test) shows the entries of the mode
// in use and those for every mode; an empty mode shows them all.
inline QuickToolReport quick_tool_guide_report(ShortcutCommand tool, std::string_view mode = {}) {
  QuickToolReport report;
  const QuickToolGuide guide = quick_tool_guide(tool);
  if (const KeyboardShortcut* shortcut = shortcut_for(tool)) {
    report.tool = std::string(shortcut->label);
    report.headline = std::string(shortcut->label) + ": " + std::string(shortcut->detail);
  } else if (tool == ShortcutCommand::object_storage_check) {
    report.tool = "Object Storage Check";
    report.headline = "Object Storage Check (experimental): a bucket as Veeam reaches it.";
  }
  report.headline_tone = ReportTone::normal;
  report.notes.push_back(guide.what);
  ReportSection uses;
  uses.title = "HOW TO USE IT";
  for (const QuickToolGuideEntry& entry : guide.entries) {
    if (!mode.empty() && !entry.mode.empty() && entry.mode != mode)
      continue;
    uses.rows.push_back({entry.label, entry.snippet, ReportTone::normal});
  }
  uses.note = guide.tip.empty() ? std::string("F1 opens the full instructions.")
                                : guide.tip + " F1 opens the full instructions.";
  report.sections.push_back(std::move(uses));
  return report;
}

} // namespace support_assist::gui
