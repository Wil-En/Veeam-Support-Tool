#pragma once

// A Tools operation's hint before it runs, on both editions: the Object Storage Check's guide card
// for every operation form. What the operation does, then OPTIONS: each field and tick box shown,
// whether it is required, and what it does (operation_options.hpp). The full instructions, with what
// to prepare for each tool, are the page's Help article and the User Guide. A Guided Diagnostics
// scenario gets a longer card: what it is for, the machine to run it on, what to set up first, what
// each step checks and what the results mean, then its OPTIONS.

#include "operation_options.hpp"
#include "quick_tool_reports.hpp"
#include "scenario_form.hpp"

#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

struct OperationGuideField {
  std::string label;
  std::string help; // its tooltip, or the example its empty field shows
};

struct OperationGuideInput {
  std::string title; // the operation
  std::string intro; // what it does
  std::vector<OperationGuideField> fields;
  std::vector<std::string> options; // the check boxes, as labelled
  std::string action;               // the run button
};

namespace operation_guide_detail {

// The first sentence, for a one-line hint.
inline std::string first_sentence(std::string text) {
  const std::size_t stop = text.find(". ");
  if (stop != std::string::npos)
    text.erase(stop + 1U);
  return text;
}

} // namespace operation_guide_detail

// The SETUP section: each prerequisite on a line of its own, with no label.
inline ReportSection setup_section(const std::vector<std::string>& lines) {
  ReportSection setup;
  setup.title = "SETUP";
  for (const std::string& line : lines)
    setup.rows.push_back({"", line, ReportTone::normal});
  return setup;
}

// The sections that describe a scenario before it runs, in reading order: the machine to run it on,
// what to set up first, what each step checks, and what the results mean.
inline std::vector<ReportSection> scenario_guide_sections(const ScenarioDefinition& scenario) {
  std::vector<ReportSection> sections;
  if (!scenario.run_on.empty()) {
    ReportSection run_on;
    run_on.title = "RUN IT ON";
    run_on.rows.push_back({"", scenario.run_on, ReportTone::normal});
    sections.push_back(std::move(run_on));
  }
  sections.push_back(setup_section(scenario_setup_lines(scenario)));
  ReportSection checks;
  checks.title = "WHAT IT CHECKS";
  for (std::size_t index = 0; index < scenario.steps.size(); ++index) {
    const ScenarioStepInfo& step = scenario.steps[index];
    checks.rows.push_back({std::to_string(index + 1U) + ". " + step.title, scenario_step_text(step), ReportTone::normal});
  }
  sections.push_back(std::move(checks));
  ReportSection results;
  results.title = "WHAT THE RESULTS MEAN";
  for (const auto& [status, meaning] : scenario_status_meanings()) {
    const ReportTone tone = status == "Pass"        ? ReportTone::good
                            : status == "Attention" ? ReportTone::attention
                            : status == "Fail"      ? ReportTone::problem
                                                    : ReportTone::normal;
    results.rows.push_back({status, meaning, tone});
  }
  for (std::size_t index = 0; index < scenario.steps.size(); ++index) {
    const ScenarioStepInfo& step = scenario.steps[index];
    const std::string text = scenario_step_meaning_text(step);
    if (!text.empty())
      results.rows.push_back({std::to_string(index + 1U) + ". " + step.title, text, ReportTone::normal});
  }
  sections.push_back(std::move(results));
  return sections;
}

inline QuickToolReport operation_guide_report(const OperationGuideInput& input) {
  QuickToolReport report;
  report.tool = input.title;
  report.headline = input.title;
  report.headline_tone = ReportTone::normal;
  // A scenario is recognised by its title; what it is for is its symptom, and the steps are listed
  // in a section of their own.
  const ScenarioDefinition* scenario = scenario_with_title(input.title);
  if (scenario != nullptr) {
    report.notes.push_back(scenario->symptom);
    for (ReportSection& section : scenario_guide_sections(*scenario))
      report.sections.push_back(std::move(section));
  } else if (!input.intro.empty()) {
    report.notes.push_back(input.intro);
  }
  // OPTIONS: each field and tick box the form shows, whether it is required, and what it does.
  ReportSection options;
  options.title = "OPTIONS";
  const auto described = [](bool required, const std::string& text) {
    return std::string(required ? "Required." : "Optional.") + (text.empty() ? std::string() : " " + text);
  };
  for (const auto& field : input.fields) {
    if (field.label.empty())
      continue;
    std::string value;
    if (scenario != nullptr) {
      for (const ScenarioInput& item : scenario->inputs) {
        if (item.label != field.label)
          continue;
        const bool required = !item.optional && item.default_value.empty();
        value = described(required, item.about.empty() ? operation_guide_detail::first_sentence(field.help) : item.about);
        if (!item.default_value.empty())
          value += " Default " + item.default_value + ".";
      }
    } else if (const auto option = operation_option(input.title, field.label)) {
      value = described(option->required, option->text);
    }
    if (value.empty())
      value = field.help.empty() ? std::string("Fill this in before running.") : operation_guide_detail::first_sentence(field.help);
    options.rows.push_back({field.label, value, ReportTone::normal});
  }
  for (const auto& box : input.options) {
    if (box.empty())
      continue;
    std::string value;
    if (scenario != nullptr && box == kScenarioKeepGoingLabel)
      value = described(false, kScenarioKeepGoingText);
    else if (const auto option = operation_option(input.title, box))
      value = described(option->required, option->text);
    else
      value = "Optional. A tick box.";
    options.rows.push_back({box, value, ReportTone::normal});
  }
  if (!input.action.empty())
    options.note = input.action + " runs it, and the results show here. F1 opens the full instructions.";
  else
    options.note = "F1 opens the full instructions.";
  report.sections.push_back(std::move(options));
  return report;
}

} // namespace support_assist::gui
