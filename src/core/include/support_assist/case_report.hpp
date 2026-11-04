#pragma once

#include "support_assist/case_workspace.hpp"
#include "support_assist/error.hpp"
#include "support_assist/veeam_log_review.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace support_assist {

struct PdfReportSection {
  std::string heading;
  std::vector<std::string> lines;
};

struct PdfReportDocument {
  std::string title;
  std::string subtitle;
  std::vector<PdfReportSection> sections;
};

// What the report is ABOUT. A master report covers the whole case; a selected report narrows to
// one system and optionally one run, which is what an engineer attaches when the ticket is about a
// single failure rather than the whole environment.
struct CaseReportScope {
  bool master = true;
  std::string scope_key;
  std::string scope_name = "ALL Systems / Components";
  std::string selected_run_key;
};

// Builds the evidence sections of a case report.
//
// The hard part of this is not formatting - it is deciding WHICH structured runs a piece of
// bookmarked evidence retains. A bookmark may carry only a source path and a line number, so the
// parser's own incident-location correlation has to be replayed to find the runs that line belongs
// to. Getting that wrong produces a report that omits the run the engineer is writing about. It is
// exactly the kind of logic that must not exist twice, so it lives here and each frontend supplies
// only its own prose (the environment summary and the case note) and its own file dialog.
PdfReportDocument build_case_report_document(std::string_view case_id,
                                             const VeeamLogReviewResult& review,
                                             const std::vector<CaseEvidenceBookmark>& evidence,
                                             const CaseReportScope& scope,
                                             std::vector<std::string> environment_lines,
                                             std::vector<std::string> note_lines);

// Writes a self-contained PDF using only the PDF base fonts. The writer is
// intentionally dependency-free so the customer package remains one EXE.
Status write_pdf_report(const std::filesystem::path& output_path,
                        const PdfReportDocument& document);

} // namespace support_assist
