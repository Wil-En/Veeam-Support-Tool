// Assembling a case report from a parser model plus the engineer's bookmarks.
//
// See the header for why this is core rather than frontend code. In short: the run-retention rules
// below decide what a customer-facing report contains, and two copies of them would eventually
// disagree about what evidence a case actually holds.

#include "support_assist/case_report.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <set>
#include <sstream>
#include <utility>

namespace support_assist {
namespace {

std::string report_timestamp(std::int64_t utc_ms, const std::string& original) {
  if (utc_ms != 0) {
    return readable_utc_from_unix_millis(utc_ms);
  }
  return original;
}

} // namespace

PdfReportDocument build_case_report_document(std::string_view case_id,
                                             const VeeamLogReviewResult& review,
                                             const std::vector<CaseEvidenceBookmark>& evidence,
                                             const CaseReportScope& scope,
                                             std::vector<std::string> environment_lines,
                                             std::vector<std::string> note_lines) {
  PdfReportDocument document;
  document.title = "Support Assist Tool Case Report - " + std::string(case_id);
  document.subtitle = scope.master
                          ? "Master case report"
                          : "Selected environment/run report - " + scope.scope_name;
  document.sections.push_back({"Environment", std::move(environment_lines)});
  document.sections.push_back({"Case Note", std::move(note_lines)});

  // A PDF is an engineer-selected evidence report, not a second unfiltered parser dump. The
  // detailed timeline stays bound to bookmark/note evidence and to the structured runs that
  // evidence actually correlates to.
  std::set<std::string> retained_run_keys;
  if (!scope.selected_run_key.empty()) {
    retained_run_keys.insert(scope.selected_run_key);
  }

  PdfReportSection timeline{"Bookmarked / Note Evidence Timeline - Newest First", {}};
  std::vector<CaseEvidenceBookmark> ordered = evidence;
  std::stable_sort(ordered.begin(), ordered.end(),
                   [](const CaseEvidenceBookmark& left, const CaseEvidenceBookmark& right) {
                     if (left.timestamp_utc_ms != 0 && right.timestamp_utc_ms != 0 &&
                         left.timestamp_utc_ms != right.timestamp_utc_ms) {
                       return left.timestamp_utc_ms > right.timestamp_utc_ms;
                     }
                     if ((left.timestamp_utc_ms != 0) != (right.timestamp_utc_ms != 0)) {
                       return left.timestamp_utc_ms != 0;
                     }
                     if (left.source_path != right.source_path) {
                       return left.source_path < right.source_path;
                     }
                     return left.line_number < right.line_number;
                   });

  for (const auto& item : ordered) {
    if (!item.bookmarked && !item.include_in_note) {
      continue;
    }
    if (!scope.master && !scope.scope_key.empty() && !item.machine_name.empty() &&
        ascii_lower(item.machine_name) != ascii_lower(scope.scope_name) &&
        item.scope_key != scope.scope_key && item.scope_key != scope.selected_run_key) {
      continue;
    }
    if (!scope.selected_run_key.empty() && item.scope_type == "job-run" &&
        item.scope_key != scope.selected_run_key) {
      continue;
    }

    if ((item.scope_type == "job-run" || item.scope_type == "note-run") &&
        !item.scope_key.empty()) {
      retained_run_keys.insert(item.scope_key);
    }

    // Older bookmarks may carry only source+line. Reuse the parser's exact incident-location
    // correlation rather than guessing the run from a filename.
    if (!item.source_path.empty()) {
      for (const auto& incident : review.incidents) {
        for (const auto& location : incident.locations) {
          if (location.source_path != item.source_path ||
              location.line_number != item.line_number) {
            continue;
          }
          if (!location.explicit_job_run_key.empty()) {
            retained_run_keys.insert(location.explicit_job_run_key);
          }
          for (const auto& run_key : location.correlated_job_run_keys) {
            retained_run_keys.insert(run_key);
          }
        }
      }
    }

    std::ostringstream line;
    const std::string when = report_timestamp(item.timestamp_utc_ms, item.timestamp_original);
    if (!when.empty()) {
      line << when << " | ";
    }
    if (!item.machine_name.empty()) {
      line << item.machine_name << " | ";
    }
    if (!item.job_name.empty()) {
      line << item.job_name << " | ";
    }
    line << (item.title.empty() ? "Selected evidence" : item.title);
    timeline.lines.push_back(line.str());
    if (!item.source_path.empty()) {
      std::string source = veeam_ticket_evidence_path(item.source_path);
      if (item.line_number != 0U) {
        source += ":" + std::to_string(item.line_number);
      }
      timeline.lines.push_back("  Source: " + source);
    }
    if (!item.raw_text.empty()) {
      timeline.lines.push_back("  Evidence: " + item.raw_text);
    }
  }
  if (timeline.lines.empty()) {
    timeline.lines.push_back(
        "No bookmarked or note-selected evidence is retained for this report scope.");
  }
  document.sections.push_back(std::move(timeline));

  PdfReportSection runs{"Structured Timeline - Newest First", {}};
  for (const auto& run : review.job_sessions) {
    if (retained_run_keys.find(run.run_key) == retained_run_keys.end()) {
      continue;
    }
    if (!scope.master && !scope.scope_key.empty() && run.machine_key != scope.scope_key &&
        ascii_lower(run.machine_name) != ascii_lower(scope.scope_name)) {
      continue;
    }
    if (!scope.selected_run_key.empty() && run.run_key != scope.selected_run_key) {
      continue;
    }
    std::ostringstream line;
    line << report_timestamp(run.start_utc_ms.value_or(0), run.start_timestamp_original) << " | "
         << (run.machine_name.empty() ? "Unassigned system" : run.machine_name) << " | "
         << (run.job_name.empty() ? run.job_type : run.job_name) << " | "
         << (run.status.empty() ? "Unknown" : run.status);
    runs.lines.push_back(line.str());
  }
  if (runs.lines.empty()) {
    runs.lines.push_back("No structured run is directly retained by the selected evidence.");
  }
  document.sections.push_back(std::move(runs));
  return document;
}

} // namespace support_assist
