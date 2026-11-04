#pragma once

#include "support_assist/case_workspace.hpp"
#include "support_assist/veeam_log_review.hpp"

#include <filesystem>
#include <optional>

namespace support_assist {

// Persists the review model required to reopen a case without re-reading raw logs.
// The on-disk format is private, versioned SAT data and is not intended as a customer report.
Status save_case_review_model(const CaseWorkspace& workspace,
                              const VeeamLogReviewResult& review);
Result<VeeamLogReviewResult> load_case_review_model(const CaseWorkspace& workspace);

// When the model load_case_review_model reads was last written; nothing when the case has none.
// A page keeping a loaded model compares it to tell whether the model changed since.
std::optional<std::filesystem::file_time_type> case_review_model_written(const CaseWorkspace& workspace);

// Merge a newly reviewed evidence set into the accumulated case model. Existing
// machine facts are retained unless the new model fills a blank; job runs and
// evidence locations are deduplicated by stable source/run identity.
VeeamLogReviewResult merge_case_review_models(const VeeamLogReviewResult& existing,
                                              const VeeamLogReviewResult& incoming);

// Returns an empty string when a fresh full re-analysis is safe to replace the
// saved case model. A non-empty reason means the incoming model has collapsed
// enough that SAT should preserve the richer saved review rather than silently
// committing a likely wrong-source or partial-source scan.
std::string case_review_regression_reason(const VeeamLogReviewResult& existing,
                                          const VeeamLogReviewResult& incoming);

} // namespace support_assist
