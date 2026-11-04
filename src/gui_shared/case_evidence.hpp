#pragma once

// Evidence both GUIs write into a case, built once so a case written on one edition reads the same
// on the other: a tool run added to #note, a review finding bookmarked or added to #note, a Health
// Monitor row added to #note, and a result-table row added to #note. The Windows functions
// add_tool_evidence_entry_to_note(), bookmark_review_evidence(), toggle_health_row_note() and the
// grid menu's Add to #note were the reference, and now call these.

#include "support_assist/case_workspace.hpp"
#include "support_assist/error.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/tool_evidence.hpp"
#include "support_assist/veeam_log_review.hpp"

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace support_assist::gui {

// ------------------------------------------------------------------------------ tool evidence

// The whole loaded timeline, kept with the case; #note carries only the runs the engineer picks.
inline std::filesystem::path tool_evidence_reference_path(const CaseWorkspace& workspace) {
  return workspace.root / "notes" / "tool-evidence-reference.txt";
}

// The runs picked for #note.
inline std::filesystem::path tool_evidence_note_path(const CaseWorkspace& workspace) {
  return workspace.root / "notes" / "tool-evidence.txt";
}

// One tool run as it reads in #note: what ran, on which host and when, and what it returned.
inline std::string tool_evidence_note_block(const ToolTimelineEntry& entry) {
  std::ostringstream block;
  block << "  [" << entry.utc_text << "] " << entry.tool << "  |  " << entry.host << "\n"
        << "    Result: " << entry.status << "  |  Diagnostic: " << entry.diagnostic << "\n";
  if (!entry.summary.empty()) {
    block << "    Summary: " << entry.summary << "\n";
  }
  if (entry.finding_count > 0U) {
    block << "    Findings: " << entry.finding_count << "\n";
  }
  block << "    Source: " << path_to_utf8(entry.source) << "\n\n";
  return block.str();
}

enum class NoteWrite { added, already_there, failed };

// Appends the run to the case's #note file. The same run twice is a no-op rather than a duplicate
// paragraph in the ticket.
inline NoteWrite add_tool_evidence_to_note(const CaseWorkspace& workspace,
                                           const ToolTimelineEntry& entry) {
  const std::string text = tool_evidence_note_block(entry);
  const std::filesystem::path destination = tool_evidence_note_path(workspace);
  {
    std::ifstream existing(destination, std::ios::binary);
    if (existing) {
      std::ostringstream buffer;
      buffer << existing.rdbuf();
      if (buffer.str().find(text) != std::string::npos) {
        return NoteWrite::already_there;
      }
    }
  }
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  std::ofstream output(destination, std::ios::binary | std::ios::app);
  if (!output) {
    return NoteWrite::failed;
  }
  output << text;
  return output ? NoteWrite::added : NoteWrite::failed;
}

// Writes the loaded timeline to the reference file, replacing the previous one.
inline bool write_tool_evidence_reference(const CaseWorkspace& workspace,
                                          const std::vector<ToolEvidence>& evidence) {
  const std::filesystem::path destination = tool_evidence_reference_path(workspace);
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  std::ofstream output(destination, std::ios::binary | std::ios::trunc);
  if (!output) {
    return false;
  }
  output << render_tool_timeline_note(evidence);
  return static_cast<bool>(output);
}

// ------------------------------------------------------------------------- flag toggles

enum class EvidenceFlag { bookmark, note };

// The outcome of flipping one flag on a record: kept with its flags, or deleted when neither flag
// remains.
struct EvidenceToggle {
  bool ok = true;
  std::string error;
  bool removed = false;
  bool bookmarked = false;
  bool in_note = false;
};

namespace case_evidence_detail {

inline EvidenceToggle save_or_remove(const CaseWorkspace& workspace, CaseEvidenceBookmark record) {
  EvidenceToggle result;
  result.bookmarked = record.bookmarked;
  result.in_note = record.include_in_note;
  if (!record.bookmarked && !record.include_in_note) {
    if (!record.evidence_id.empty()) {
      const Status removed = delete_case_evidence_bookmark(workspace, record.evidence_id);
      if (!removed.ok()) {
        result.ok = false;
        result.error = describe_error(removed.error());
        return result;
      }
    }
    result.removed = true;
    return result;
  }
  const auto saved = save_case_evidence_bookmark(workspace, std::move(record));
  if (!saved.ok()) {
    result.ok = false;
    result.error = describe_error(saved.error());
  }
  return result;
}

}  // namespace case_evidence_detail

// --------------------------------------------------------------------------- review findings

// The source line a finding is recorded with: within the selected machine and run, the run's
// earliest line, or the latest line when no run is selected. Null when no retained location
// matches the selection.
inline const VeeamIncidentLocation* evidence_location(const VeeamIncident& incident,
                                                      const std::string& machine_key,
                                                      const VeeamJobSession* run) {
  const VeeamIncidentLocation* chosen = nullptr;
  for (const auto& location : incident.locations) {
    if (!machine_key.empty() && location.machine_key != machine_key) {
      continue;
    }
    if (run != nullptr && !veeam_location_matches_run(location, *run)) {
      continue;
    }
    if (chosen == nullptr ||
        (location.timestamp_utc_ms && chosen->timestamp_utc_ms &&
         (run != nullptr ? *location.timestamp_utc_ms < *chosen->timestamp_utc_ms
                         : *location.timestamp_utc_ms > *chosen->timestamp_utc_ms)) ||
        (!chosen->timestamp_utc_ms && location.timestamp_utc_ms)) {
      chosen = &location;
    }
  }
  return chosen;
}

// The record a finding is saved as: scoped to the selected run, else the selected machine, else
// the case, with the source line and the lines around it. Both flags start clear.
inline CaseEvidenceBookmark review_evidence_bookmark(const VeeamIncident& incident,
                                                     const VeeamIncidentLocation& chosen,
                                                     const std::string& machine_key,
                                                     const VeeamJobSession* run,
                                                     const std::string& case_id) {
  CaseEvidenceBookmark bookmark;
  bookmark.bookmarked = false;
  bookmark.include_in_note = false;
  bookmark.title = incident.summary.empty() ? incident.signature : incident.summary;
  bookmark.machine_name = chosen.machine_name;
  bookmark.source_path = chosen.source_path;
  bookmark.line_number = chosen.line_number;
  bookmark.timestamp_original = chosen.timestamp_original;
  bookmark.timestamp_utc_ms = chosen.timestamp_utc_ms.value_or(0);
  for (const std::vector<std::string>* lines : {&chosen.before, &chosen.lines, &chosen.after}) {
    for (const auto& line : *lines) {
      if (!bookmark.raw_text.empty()) {
        bookmark.raw_text += "\n";
      }
      bookmark.raw_text += line;
    }
  }
  if (run != nullptr) {
    bookmark.scope_type = "job-run";
    bookmark.scope_key = run->run_key;
    bookmark.job_name = run->job_name;
  } else if (!machine_key.empty()) {
    bookmark.scope_type = "machine";
    bookmark.scope_key = machine_key;
  } else {
    bookmark.scope_type = "case";
    bookmark.scope_key = case_id;
  }
  return bookmark;
}

// The case's saved record for the same finding: same scope, source line and title.
inline std::optional<CaseEvidenceBookmark> saved_review_evidence(
    const CaseWorkspace& workspace, const CaseEvidenceBookmark& bookmark) {
  auto loaded = load_case_evidence_bookmarks(workspace);
  if (!loaded.ok()) {
    return std::nullopt;
  }
  for (const auto& item : loaded.value()) {
    if (item.scope_type == bookmark.scope_type && item.scope_key == bookmark.scope_key &&
        item.source_path == bookmark.source_path && item.line_number == bookmark.line_number &&
        item.title == bookmark.title) {
      return item;
    }
  }
  return std::nullopt;
}

// Flips the bookmark or the #note flag on a finding's record, keeping the other flag.
inline EvidenceToggle toggle_review_evidence(const CaseWorkspace& workspace,
                                             CaseEvidenceBookmark bookmark, EvidenceFlag flag) {
  if (const auto existing = saved_review_evidence(workspace, bookmark)) {
    bookmark.evidence_id = existing->evidence_id;
    bookmark.created_utc = existing->created_utc;
    bookmark.bookmarked = existing->bookmarked;
    bookmark.include_in_note = existing->include_in_note;
  }
  if (flag == EvidenceFlag::note) {
    bookmark.include_in_note = !bookmark.include_in_note;
  } else {
    bookmark.bookmarked = !bookmark.bookmarked;
  }
  return case_evidence_detail::save_or_remove(workspace, std::move(bookmark));
}

// Whether any record on this source line is bookmarked, and whether any is in #note: what the
// result menu offers to add or remove.
struct EvidenceState {
  bool bookmarked = false;
  bool in_note = false;
};

inline EvidenceState source_line_evidence_state(const CaseWorkspace& workspace,
                                                const std::string& source_path,
                                                std::uint64_t line_number) {
  EvidenceState state;
  auto loaded = load_case_evidence_bookmarks(workspace);
  if (!loaded.ok()) {
    return state;
  }
  for (const auto& item : loaded.value()) {
    if (item.source_path == source_path && item.line_number == line_number) {
      state.bookmarked = state.bookmarked || item.bookmarked;
      state.in_note = state.in_note || item.include_in_note;
    }
  }
  return state;
}

// ----------------------------------------------------------------------- Health Monitor rows

// One Health Monitor row: the table it is in (Finding, Storage, Network, Process, Volume) and its
// cells, with the snapshot it was read from.
struct HealthNoteRow {
  std::string category;
  std::vector<std::string> values;
  std::string machine_name;
  std::string captured_utc;
  std::string source_path;
};

// A row is keyed by its table and its first two cells, so the same row read again is the same
// record.
inline std::string health_note_scope_key(const HealthNoteRow& row) {
  return row.category + ":" + (row.values.empty() ? std::string("row") : row.values[0]) +
         (row.values.size() > 1 ? ":" + row.values[1] : std::string());
}

inline bool health_row_in_note(const CaseWorkspace& workspace, const HealthNoteRow& row) {
  auto loaded = load_case_evidence_bookmarks(workspace);
  if (!loaded.ok()) {
    return false;
  }
  const std::string key = health_note_scope_key(row);
  return std::any_of(loaded.value().begin(), loaded.value().end(), [&](const auto& item) {
    return item.scope_type == "health" && item.scope_key == key && item.include_in_note;
  });
}

// Adds the row to #note, or takes it out when it is there already.
inline EvidenceToggle toggle_health_row_note(const CaseWorkspace& workspace,
                                             const HealthNoteRow& row) {
  const std::string key = health_note_scope_key(row);
  auto loaded = load_case_evidence_bookmarks(workspace);
  if (loaded.ok()) {
    for (const auto& item : loaded.value()) {
      if (item.scope_type == "health" && item.scope_key == key && item.include_in_note) {
        CaseEvidenceBookmark removed = item;
        removed.bookmarked = false;
        removed.include_in_note = false;
        return case_evidence_detail::save_or_remove(workspace, std::move(removed));
      }
    }
  }
  std::string raw = row.category + ": ";
  for (std::size_t index = 0; index < row.values.size(); ++index) {
    if (index != 0U) {
      raw += " | ";
    }
    raw += row.values[index];
  }
  CaseEvidenceBookmark item;
  item.scope_type = "health";
  item.scope_key = key;
  item.title = row.category;
  item.machine_name = row.machine_name;
  item.timestamp_original = row.captured_utc;
  item.source_path = row.source_path;
  item.raw_text = std::move(raw);
  item.bookmarked = false;
  item.include_in_note = true;
  return case_evidence_detail::save_or_remove(workspace, std::move(item));
}

// ------------------------------------------------------------------------ result-table rows

// A result-table row added to #note: the row's text, scoped to the selected machine when a review
// has one, else to the case.
inline CaseEvidenceBookmark table_row_bookmark(std::string text, const std::string& source_path,
                                               const std::string& machine_key,
                                               const std::string& case_id) {
  CaseEvidenceBookmark bookmark;
  bookmark.bookmarked = true;
  bookmark.include_in_note = true;
  if (text.size() > 2000U) {
    text.resize(2000U);
  }
  bookmark.title = text.size() > 120U ? text.substr(0, 120U) + "..." : text;
  bookmark.raw_text = std::move(text);
  bookmark.source_path = source_path;
  if (!machine_key.empty()) {
    bookmark.scope_type = "machine";
    bookmark.scope_key = machine_key;
  } else {
    bookmark.scope_type = "case";
    bookmark.scope_key = case_id;
  }
  return bookmark;
}

}  // namespace support_assist::gui
