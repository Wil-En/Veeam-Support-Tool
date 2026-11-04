#pragma once

// Guided Diagnostics' scenario forms for both editions: the fields to the scenario's inputs, the
// result as table rows (each step, the result, the case note's lines), and the CLI's arguments. The
// words that describe a scenario before it runs (the machine to run it on, what to set up first,
// what each step checks, what each result means) are built here once, for the hint card and the
// Help article.

#include "support_assist/product_discovery.hpp"
#include "support_assist/scenarios.hpp"
#include "support_assist/strings.hpp"

#include <cstdlib>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

// Guided Diagnostics' scenarios for this machine, read once: the products found do not change while
// SAT runs.
inline const std::vector<ScenarioDefinition>& guided_scenarios_here() {
  static const std::vector<ScenarioDefinition> scenarios = [] {
#ifdef SUPPORT_ASSIST_UI_SELFCHECK
    // SAT_UI_SHOT_ALL_SCENARIOS: the figure harness lists this edition's every scenario, those for
    // products not installed here among them.
#ifdef _WIN32
    char* value = nullptr;
    std::size_t length = 0;
    const bool every_scenario = _dupenv_s(&value, &length, "SAT_UI_SHOT_ALL_SCENARIOS") == 0 && value != nullptr;
    std::free(value);
#else
    const bool every_scenario = std::getenv("SAT_UI_SHOT_ALL_SCENARIOS") != nullptr;
#endif
    if (every_scenario) {
      std::vector<ScenarioDefinition> every;
      for (const ScenarioDefinition& definition : scenario_catalog()) {
#ifndef _WIN32
        if (definition.windows_only)
          continue;
#endif
        every.push_back(definition);
        for (ScenarioInput& input : every.back().inputs) {
          if (!input.default_by_vbr.empty())
            input.default_value = scenarios_detail::input_default(input, local_vbr_major_version());
        }
      }
      return every;
    }
#endif
    return available_scenarios(native_product_discovery_context());
  }();
  return scenarios;
}

// The scenario's symptom and its steps, for the line above the form.
inline std::string scenario_intro(const ScenarioDefinition& scenario) {
  std::string text = scenario.symptom + " Steps:";
  for (std::size_t index = 0; index < scenario.step_titles.size(); ++index)
    text += (index == 0U ? " " : "; ") + std::to_string(index + 1U) + " " + scenario.step_titles[index];
  return text + ".";
}

// The scenario in the catalog with this title; nullptr for any other operation. The hint card
// recognises a scenario by the title its form carries.
inline const ScenarioDefinition* scenario_with_title(const std::string& title) {
  for (const ScenarioDefinition& scenario : scenario_catalog()) {
    if (scenario.title == title)
      return &scenario;
  }
  return nullptr;
}

#ifdef _WIN32
inline constexpr bool kScenarioHostIsWindows = true;
#else
inline constexpr bool kScenarioHostIsWindows = false;
#endif

// What a step checks, as the hint card and the Help article word it: the scenario data's sentence,
// that the step belongs to Windows when this edition is not Windows, and that its failure ends the run.
inline std::string scenario_step_text(const ScenarioStepInfo& step, bool on_windows = kScenarioHostIsWindows) {
  const bool applies = on_windows || !step.windows_only;
  std::string text = applies ? std::string() : std::string("Windows only: this edition reads Not applicable for it. ");
  text += step.does;
  if (step.decisive && applies)
    text += " A failure here stops the run.";
  return text;
}

// What a failure of the step, and an attention where the scenario words one, mean; empty when the
// scenario words neither.
inline std::string scenario_step_meaning_text(const ScenarioStepInfo& step) {
  std::string text;
  if (!step.fail.meaning.empty())
    text = "Fail: " + step.fail.meaning;
  if (!step.attention.meaning.empty())
    text += (text.empty() ? "" : " ") + std::string("Attention: ") + step.attention.meaning;
  return text;
}

// The statuses a step row can show, in plain words.
inline const std::vector<std::pair<std::string, std::string>>& scenario_status_meanings() {
  static const std::vector<std::pair<std::string, std::string>> meanings{
      {"Pass", "The step found nothing wrong. The row says what was read."},
      {"Attention", "The step found something to look at. The run goes on, and the result counts it."},
      {"Fail", "The step found a problem. The row says what was found, what it means and what to do next."},
      {"Stops the run",
       "A step marked above as stopping the run ends it when it fails, and the steps after it read Not run. "
       "Keep going after a failure runs every step and lists each failure, the first one first."},
      {"Not applicable",
       "The step does not apply here, such as a Windows step on Linux or a SQL Server that is another machine."},
      {"Could not check",
       "The step could not read what it needs, such as a server that does not answer or a right SAT lacks. The row "
       "says why."}};
  return meanings;
}

// What has to be in place before a run, each line a prerequisite naming the machine it is on: the
// lines for every edition, then this edition's. One line saying so when the scenario needs nothing.
inline std::vector<std::string> scenario_setup_lines(const ScenarioDefinition& scenario,
                                                     bool on_windows = kScenarioHostIsWindows) {
  std::vector<std::string> lines = scenario.setup;
  for (const std::string& line : on_windows ? scenario.setup_windows : scenario.setup_linux)
    lines.push_back(line);
  if (lines.empty())
    lines.push_back("Nothing has to be set up before running.");
  return lines;
}

// The scenario form's one tick box, on the card's OPTIONS.
inline constexpr const char* kScenarioKeepGoingLabel = "Keep going after a failure";
inline constexpr const char* kScenarioKeepGoingText =
    "Ticked, every step runs and each failure is listed. Cleared, the run stops at the first failure of a "
    "step marked as stopping the run, and the steps after it read Not run.";

// A scenario in the Help article: its symptom, the machine to run it on, what to set up first, then
// each step and what it checks, one to a line.
inline std::string scenario_article_text(const ScenarioDefinition& scenario, bool on_windows = kScenarioHostIsWindows) {
  const std::string indent = "\n    ";
  std::string text = scenario.symptom;
  if (!scenario.run_on.empty())
    text += indent + "Run it on: " + scenario.run_on;
  text += indent + "Set up first:";
  for (const std::string& line : scenario_setup_lines(scenario, on_windows))
    text += indent + line;
  text += indent + "What it checks:";
  for (std::size_t index = 0; index < scenario.steps.size(); ++index) {
    const ScenarioStepInfo& step = scenario.steps[index];
    text += indent + std::to_string(index + 1U) + ". " + step.title + ": " + scenario_step_text(step, on_windows);
  }
  return text;
}

inline std::map<std::string, std::string> scenario_inputs(const ScenarioDefinition& scenario,
                                                          const std::vector<std::string>& fields) {
  std::map<std::string, std::string> inputs;
  for (std::size_t index = 0; index < scenario.inputs.size() && index < fields.size(); ++index)
    inputs[scenario.inputs[index].id] = std::string(trim(fields[index]));
  return inputs;
}

// The form's refusal when an input the scenario needs is empty ("Server name or address is
// needed."); empty when every needed input has a value.
inline std::string scenario_missing_input(const ScenarioDefinition& scenario, const std::vector<std::string>& fields) {
  for (std::size_t index = 0; index < scenario.inputs.size(); ++index) {
    const ScenarioInput& input = scenario.inputs[index];
    if (!input.optional && (index >= fields.size() || trim(fields[index]).empty()))
      return input.label + " is needed.";
  }
  return {};
}

struct ScenarioRow {
  std::string area;
  std::string check;
  std::string detail;
  std::string status;
};

inline std::vector<ScenarioRow> scenario_rows(const ScenarioResult& result) {
  std::vector<ScenarioRow> rows;
  for (const ScenarioStepResult& step : result.steps) {
    // What was found, then the parts the result table shows in the detail pane (result_table.hpp).
    std::string detail = step.found;
    if (!step.meaning.empty())
      detail += "  Meaning: " + step.meaning;
    if (!step.next.empty())
      detail += "  Next: " + step.next;
    for (std::size_t index = 0; index < step.links.size(); ++index)
      detail += (index == 0U ? "  Sources: " : "  ") + step.links[index];
    rows.push_back({"Step " + std::to_string(step.number), step.title, detail, step.status});
  }
  rows.push_back({"Result", result.title, result.result, result.overall});
  for (const std::string& line : split(result.case_note, '\n')) {
    if (!trim(line).empty())
      rows.push_back({"Case note", "", line, ""});
  }
  return rows;
}

inline std::vector<std::string> scenario_cli_arguments(const ScenarioDefinition& scenario,
                                                       const std::vector<std::string>& fields, bool keep_going) {
  std::vector<std::string> arguments{"guided", "run", "--scenario", scenario.id};
  for (const auto& [id, value] : scenario_inputs(scenario, fields)) {
    if (!value.empty()) {
      arguments.push_back("--input");
      arguments.push_back(id + "=" + value);
    }
  }
  if (keep_going)
    arguments.push_back("--continue");
  return arguments;
}

} // namespace support_assist::gui
