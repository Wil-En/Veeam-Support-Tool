#pragma once

// Diagnostics as one page on both editions: what SAT reads about this machine, the Veeam products
// and integrations it finds, SAT's self-test and what the tools need on this machine, in one report
// rather than separate sub-pages. Each edition reads the rows its own way; this lays them out the same.

#include "integration_state.hpp"
#include "quick_tool_reports.hpp"

#include "support_assist/tool_catalog.hpp"
#include "support_assist/tool_requirements.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

struct DiagnosticsInput {
  std::vector<ReportRow> system;    // this machine and this copy of SAT
  std::vector<ReportRow> products;  // Veeam products found, then the integrations SAT knows
  std::vector<ReportRow> self_test; // one row per check; a failed one has the problem tone
  std::vector<ReportRow> requirements; // what the tools need on this machine; not part of the self-test result
  std::int64_t read_unix_millis = 0;
};

// What each tool needs, one row per requirement: the name, what was found and the tools that use it.
// A missing requirement or one that needs attention has the attention tone and one that does not
// apply here has the quiet tone; none of them is a self-test problem.
inline std::vector<ReportRow> requirement_report_rows(const std::vector<ToolRequirement>& requirements) {
  std::vector<ReportRow> rows;
  for (const ToolRequirement& requirement : requirements) {
    ReportTone tone = ReportTone::normal;
    if (requirement.status == kRequirementAttention || requirement.status == kRequirementMissing)
      tone = ReportTone::attention;
    else if (requirement.status == kRequirementNotApplicable)
      tone = ReportTone::quiet;
    rows.push_back({requirement.name, requirement.found + " | Used by: " + requirement.used_by, tone});
  }
  return rows;
}

// The integrations SAT knows on this platform, each with the state the Integrations page shows and
// where it was found. The other platform's tools are left out.
inline std::vector<ReportRow> integration_report_rows(const std::vector<ExternalToolStatus>& tools,
                                                      const std::filesystem::path& managed_root) {
  std::vector<ReportRow> rows;
  for (const ExternalToolStatus& tool : tools) {
    const IntegrationState state = integration_state(tool, managed_root);
    if (state == IntegrationState::not_applicable)
      continue;
    std::string value = integration_state_text(state);
    if (!tool.resolved_path.empty())
      value += " | " + path_to_utf8(tool.resolved_path);
    rows.push_back({tool.definition.name, value,
                    state == IntegrationState::not_present ? ReportTone::quiet : ReportTone::normal});
  }
  return rows;
}

inline QuickToolReport diagnostics_report(DiagnosticsInput input) {
  QuickToolReport report;
  report.tool = "Diagnostics";
  int problems = 0;
  for (const ReportRow& row : input.self_test)
    if (row.tone == ReportTone::problem)
      ++problems;
  if (input.self_test.empty()) {
    report.headline = "SAT Self-Test did not run";
    report.headline_tone = ReportTone::attention;
  } else if (problems == 0) {
    report.headline = "SAT Self-Test passed";
    report.headline_tone = ReportTone::good;
  } else {
    report.headline = "SAT Self-Test: " + std::to_string(problems) + (problems == 1 ? " problem" : " problems");
    report.headline_tone = ReportTone::problem;
  }
  report.notes.push_back("This machine, the Veeam products and integrations found on it, and whether this copy of "
                         "SAT works as it should. Run again reads them again.");
  report.checked_unix_millis = input.read_unix_millis;
  const auto section = [&report](const char* title, std::vector<ReportRow> rows, const char* none) {
    ReportSection added;
    added.title = title;
    added.rows = std::move(rows);
    if (added.rows.empty())
      added.rows.push_back({"None", none, ReportTone::quiet});
    report.sections.push_back(std::move(added));
  };
  section("SYSTEM INFORMATION", std::move(input.system), "Nothing could be read.");
  section("PRODUCTS AND INTEGRATIONS", std::move(input.products), "No Veeam product or integration was found.");
  section("SAT SELF-TEST", std::move(input.self_test), "The self-test did not run.");
  section("REQUIREMENTS", std::move(input.requirements), "Nothing was read.");
  return report;
}

} // namespace support_assist::gui
