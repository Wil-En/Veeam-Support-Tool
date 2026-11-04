#pragma once

#include "support_assist/error.hpp"
#include "support_assist/execution_artifact.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// Customer/Lab tool output as reviewable case evidence.
//
// SAT's tools have always written structured, self-describing artifacts to disk, and Log Collection
// has always packaged them into the bundle under [BundlePaths] Tools=. Nothing ever read them back,
// so an engineer retyped tool results into the case note by hand. This turns that output into
// first-class evidence: identified by machine, ordered in time, and carrying its own findings.
//
// Timestamps come from the artifact manifest and are already UTC, so tool evidence needs none of
// the per-file offset reconstruction that product logs require. It can be merged directly into a
// cross-machine timeline.

// One row of a tool's result.tsv: category / item / details / status.
struct ToolResultRow {
  std::string category;
  std::string item;
  std::string details;
  std::string status;
};

struct ToolEvidence {
  ExecutionArtifactManifest manifest;
  std::vector<ToolResultRow> rows;
  // Milliseconds since the Unix epoch, parsed from manifest.started_utc. 0 when unparseable.
  std::int64_t started_utc_ms = 0;
  std::int64_t completed_utc_ms = 0;

  const std::string& tool() const { return manifest.tool_name; }
  const std::string& host() const { return manifest.host_name; }
  bool has_finding() const { return manifest.diagnostic_status == DiagnosticStatus::finding; }
  // Rows whose status reads as a problem. Used to surface what the tool actually found without
  // making the engineer read every row.
  std::vector<ToolResultRow> finding_rows() const;
};

// result.tsv as a Tools run writes it and load_tool_evidence reads it back: a short key=value
// header, a blank line, the column row, then one row per result. A tab or line break in a cell
// becomes a space.
std::string format_tool_result_tsv(std::string_view tool, ExecutionStatus execution, DiagnosticStatus diagnostic,
                                   std::string_view summary, const std::vector<ToolResultRow>& rows);

// All tool evidence beneath `root`, oldest first. `root` may be a bundle's Tools directory, a
// Log-Collections tree, or any parent of them - discovery is recursive and tolerant of unrelated
// directories.
Result<std::vector<ToolEvidence>> load_tool_evidence(const std::filesystem::path& root);

// Tool evidence grouped by the machine it was collected from, machines ordered by first activity.
struct ToolEvidenceByMachine {
  std::string host;
  std::vector<ToolEvidence> evidence;
  std::int64_t first_activity_utc_ms = 0;
  std::int64_t last_activity_utc_ms = 0;
  std::size_t finding_count = 0;
};

std::vector<ToolEvidenceByMachine> group_tool_evidence_by_machine(std::vector<ToolEvidence> evidence);

// A single chronological line across every machine and tool - the "one view arranged by time"
// an engineer needs to see what happened in what order on which host.
struct ToolTimelineEntry {
  std::int64_t utc_ms = 0;
  std::string utc_text;
  std::string host;
  std::string tool;
  std::string status;      // execution status
  std::string diagnostic;  // diagnostic status
  std::string summary;
  std::size_t finding_count = 0;
  // The rows that actually reported a problem. A count alone forces the reader back to the raw
  // artifact to learn what was found, which is the retyping this whole path exists to remove.
  std::vector<ToolResultRow> findings;
  std::filesystem::path source;
};

std::vector<ToolTimelineEntry> build_tool_timeline(const std::vector<ToolEvidence>& evidence);

// Renders the timeline as the padded, attributed text SAT already uses for note evidence, so tool
// results can be appended to a case note in the same shape as log evidence.
std::string render_tool_timeline_note(const std::vector<ToolEvidence>& evidence,
                                      std::string_view machine_filter = {});

} // namespace support_assist
