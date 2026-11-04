#pragma once

// The Help window's page on both editions, drawn as the cards are: sections of label and value
// rows. An article's rows (workspace_cards.hpp) keep their sections. A Tools operation and a Guided
// Diagnostics scenario have an article of their own, built from the card their form shows
// (operation_guide.hpp), which F1 opens from that form.

#include "operation_guide.hpp"
#include "quick_tool_reports.hpp"
#include "workspace_cards.hpp"

#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

// An article as a report: its title, its summary as the first note, then a section for each run of
// rows with the same section, each row's heading beside its explanation and its note.
inline QuickToolReport help_article_report(const std::string& title, const std::string& summary,
                                           const std::vector<ArticleRow>& rows) {
  QuickToolReport report;
  report.tool = title;
  report.headline = title;
  report.headline_tone = ReportTone::normal;
  if (!summary.empty())
    report.notes.push_back(summary);
  for (const ArticleRow& row : rows) {
    if (report.sections.empty() || report.sections.back().title != row.section) {
      ReportSection section;
      section.title = row.section;
      report.sections.push_back(std::move(section));
    }
    std::string value = row.explanation;
    if (!row.note.empty())
      value += (value.empty() ? std::string() : std::string(" ")) + "Note: " + row.note;
    report.sections.back().rows.push_back({row.heading, std::move(value), ReportTone::normal});
  }
  return report;
}

// The article of one Tools operation or scenario: its card, with the page article's row for it
// (the row headed by its title) under ABOUT, and without the card's pointer to F1.
inline QuickToolReport operation_help_report(const OperationGuideInput& input,
                                             const std::vector<ArticleRow>& page_article = {}) {
  QuickToolReport report = operation_guide_report(input);
  if (scenario_with_title(input.title) == nullptr) {
    for (const ArticleRow& row : page_article) {
      if (row.heading != input.title)
        continue;
      ReportSection about;
      about.title = "ABOUT";
      std::string value = row.explanation;
      if (!row.note.empty())
        value += (value.empty() ? std::string() : std::string(" ")) + row.note;
      about.rows.push_back({"", std::move(value), ReportTone::normal});
      report.sections.insert(report.sections.begin(), std::move(about));
      break;
    }
  }
  for (ReportSection& section : report.sections) {
    if (section.title == "OPTIONS")
      section.note = input.action.empty() ? std::string() : input.action + " runs it.";
  }
  return report;
}

// A report as plain text, for Copy and for reading it back: the title, the notes, then each
// section's title and its rows, a label and its value on a line.
inline std::string help_report_text(const QuickToolReport& report) {
  std::string text = report.headline + "\n\n";
  for (const std::string& note : report.notes)
    text += note + "\n\n";
  for (const ReportSection& section : report.sections) {
    if (!section.title.empty())
      text += section.title + "\n";
    for (const ReportRow& row : section.rows) {
      if (!row.label.empty())
        text += row.label + "\n";
      if (!row.value.empty())
        text += "    " + row.value + "\n";
    }
    if (!section.note.empty())
      text += "    " + section.note + "\n";
    text += "\n";
  }
  return text;
}

} // namespace support_assist::gui
