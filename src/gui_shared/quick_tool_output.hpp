#pragma once

// A quick tool run's output on a Customer / Lab machine: an execution artifact like each Tools run
// leaves, grouped per tool, holding result.json (the raw result, as the command line prints it
// with --json) and report.txt (what the window showed). Prepare output carries it with the rest of
// the tool output, so a later import can bring the machine's checks into a case.

#include "quick_tool_reports.hpp"

#include "support_assist/case_workspace.hpp"
#include "support_assist/execution_artifact.hpp"
#include "support_assist/tool_evidence.hpp"

#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

inline DiagnosticStatus diagnostic_of(ReportTone tone) {
  switch (tone) {
  case ReportTone::good: return DiagnosticStatus::pass;
  case ReportTone::attention:
  case ReportTone::problem: return DiagnosticStatus::finding;
  case ReportTone::normal:
  case ReportTone::quiet: break;
  }
  return DiagnosticStatus::neutral;
}

struct QuickToolOutput {
  std::string tool;        // "Volume Check": the artifact's tool and the folder its runs are kept in
  std::string result_json; // the raw result
  std::string report;      // the text the window showed
  std::string summary;     // the headline
  ReportTone tone = ReportTone::normal;
  std::vector<ToolResultRow> rows{}; // result.tsv, for Tool Evidence in a case; none for a watch or a listener
};

// A row's status in result.tsv: Tool Evidence lists Warning and Finding rows as what the run found.
inline std::string result_status_of(ReportTone tone) {
  switch (tone) {
  case ReportTone::problem: return "Finding";
  case ReportTone::attention: return "Warning";
  case ReportTone::good: return "OK";
  case ReportTone::normal:
  case ReportTone::quiet: break;
  }
  return {};
}

// A report as result.tsv's rows: the headline, then each section's rows under the section's title.
inline std::vector<ToolResultRow> quick_tool_result_rows(const QuickToolReport& report) {
  std::vector<ToolResultRow> rows;
  if (!report.headline.empty())
    rows.push_back({"Result", report.headline, report.subject, result_status_of(report.headline_tone)});
  for (const ReportSection& section : report.sections) {
    for (const ReportRow& row : section.rows)
      rows.push_back({section.title, row.label, row.value, result_status_of(row.tone)});
  }
  return rows;
}

// A run kept from its report: the text the window showed, its headline and tone, and its rows.
inline QuickToolOutput quick_tool_output_of(std::string tool, std::string result_json, const QuickToolReport& report) {
  return {std::move(tool), std::move(result_json), report_text(report), report.headline, report.headline_tone,
          quick_tool_result_rows(report)};
}

// Writes one run under tools_directory/<Tool>/.
inline Result<ExecutionArtifactManifest> write_quick_tool_output(const std::filesystem::path& tools_directory,
                                                                 const QuickToolOutput& output) {
  const std::string folder = tool_folder_name(output.tool);
  auto artifact = begin_execution_artifact(tools_directory / folder, output.tool);
  if (!artifact.ok())
    return artifact;
  if (const Status written = write_execution_artifact_text(artifact.value(), "result.json", output.result_json + "\n");
      !written.ok())
    return Result<ExecutionArtifactManifest>::failure(written.error());
  if (!output.report.empty()) {
    if (const Status written = write_execution_artifact_text(artifact.value(), "report.txt", output.report);
        !written.ok())
      return Result<ExecutionArtifactManifest>::failure(written.error());
  }
  if (!output.rows.empty()) {
    if (const Status written = write_execution_artifact_text(
            artifact.value(), "result.tsv",
            format_tool_result_tsv(output.tool, ExecutionStatus::completed, diagnostic_of(output.tone), output.summary,
                                   output.rows));
        !written.ok())
      return Result<ExecutionArtifactManifest>::failure(written.error());
  }
  if (const Status finalized = finalize_execution_artifact(artifact.value(), ExecutionStatus::completed,
                                                           diagnostic_of(output.tone), output.summary);
      !finalized.ok())
    return Result<ExecutionArtifactManifest>::failure(finalized.error());
  return artifact;
}

} // namespace support_assist::gui
