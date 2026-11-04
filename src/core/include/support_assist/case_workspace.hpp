#pragma once

#include "support_assist/error.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct CaseWorkspaceOptions {
  std::filesystem::path parent_directory;
  std::string case_id;
  std::string title;
  std::string engineer;
  std::string notes;
};

struct CaseWorkspace {
  std::filesystem::path root;
  std::filesystem::path logs;
  std::filesystem::path captures;
  std::filesystem::path reports;
  std::filesystem::path baselines;
  std::filesystem::path third_party;
  std::filesystem::path notes;
  std::filesystem::path evidence;
  // Case-owned parsed data. Parser reports, private review state/model, and cache
  // live here so opening/deleting a case has one authoritative parsed-data root.
  std::filesystem::path parsed;
  std::filesystem::path parser_cache;
  std::filesystem::path manifest;
  std::string case_id;
  std::string title;
  std::string engineer;
  std::string created_utc;
  // Workflow state, stored as its own text rather than an enum ordinal so a case written by a
  // build that knows a status this one does not stays readable. Empty means the first option.
  std::string status;
  // What the engineer decided to do next. Distinct from a review note's next_action: this one is
  // about the case, survives re-analysis, and is what someone picking the case up reads first.
  std::string next_steps;
  // Free-text case notes. Named apart from the `notes` PATH above, which is the notes folder.
  std::string notes_text;
};

struct CaseReviewSource {
  std::string path;
  // Profile explicitly selected by the engineer for this source. New sources
  // default to automatic so a mixed-product case does not inherit the profile
  // of whichever bundle happened to be reviewed first.
  std::string requested_profile = "automatic";
  // Profile/product observed after parsing. These are descriptive provenance;
  // they do not override an explicit requested_profile on re-analysis.
  std::string detected_profile;
  std::string product_type;
  std::string product_version;
  std::string source_owner;
};

struct CaseReviewState {
  // Legacy case-wide profile retained for schema-1 compatibility and simple
  // single-source callers. Mixed cases use source_profiles as authority.
  std::string profile;
  std::vector<std::string> sources;
  std::vector<CaseReviewSource> source_profiles;
  bool fast_index = true;
  std::string selected_machine_key;
  std::string selected_job_name;
  std::string selected_run_key;
  bool rescans_only = false;
  std::string updated_utc;
};

struct CaseEvidenceBookmark {
  std::string evidence_id;
  std::string scope_type;
  std::string scope_key;
  std::string title;
  std::string machine_name;
  std::string job_name;
  std::string source_path;
  std::uint64_t line_number = 0;
  std::string timestamp_original;
  std::int64_t timestamp_utc_ms = 0;
  std::string raw_text;
  bool bookmarked = true;
  bool include_in_note = false;
  std::string created_utc;
};

struct CaseReviewNote {
  std::string scope_type;
  std::string scope_key;
  std::string machine_name;
  std::string job_name;
  std::string observations;
  std::string hypothesis;
  std::string next_action;
  std::string engineer_notes;
  std::string evidence_ids;
  std::string updated_utc;
};

Result<CaseWorkspace> create_case_workspace(const CaseWorkspaceOptions& options);
Result<CaseWorkspace> open_case_workspace(const std::filesystem::path& root);
Result<std::vector<CaseWorkspace>> discover_case_workspaces(const std::filesystem::path& parent);
Status delete_case_workspace(const std::filesystem::path& root);
// Rewrites case.json from the workspace, so title, engineer, status, next steps and notes can be
// edited after the case exists. Paths and created_utc are not editable and are preserved.
Status save_case_workspace_metadata(const CaseWorkspace& workspace);
// The selectable case statuses, in order. ONE list, read by every frontend - adding a status here
// is the whole change.
// The colour a status carries in the case list. Seven named colours and a grey default, so a
// status file that names no colour still renders, and an unrecognised name is grey rather than an
// error - a case list is not worth refusing to draw over a misspelled word.
enum class CaseStatusColor {
  grey, green, yellow, orange, red, blue, purple, teal,
  // The expanded palette. Grey stays the default; the rest are drawn with a dark fill and
  // a light label chosen for the dark theme (see case_status_badge_colours).
  pink, cyan, magenta, lime, olive, navy, maroon, brown, gold, indigo, coral, slate, rose, mint,
  lavender, amber
};

// Parses one colour word, case-insensitively. Returns nothing when the word is not a colour, which
// is what lets "Priority: 1" stay a status name rather than becoming a bad colour.
std::optional<CaseStatusColor> parse_case_status_color(std::string_view name);

// The colour's own name, as it is written in the file.
std::string case_status_color_name(CaseStatusColor color);

// The full palette in display order (grey first), for the settings colour picker.
const std::vector<CaseStatusColor>& case_status_color_palette();

// A status and the colour it asked for.
struct CaseStatusOption {
  std::string name;
  CaseStatusColor color = CaseStatusColor::grey;
};

// The selectable statuses with their colours, in file order.
const std::vector<CaseStatusOption>& case_status_entries();

// The colour for a status by name, or grey when the status is not in the list - which is normal:
// a case keeps a status that has since been removed from the file.
CaseStatusColor case_status_color(std::string_view status);

const std::vector<std::string>& case_status_options();

// Replace the status list from a text file, so statuses can be added without a rebuild.
//
// One status per line; blank lines and lines starting with '#' are ignored. A missing file is not
// an error - it just leaves the built-in list in place. Statuses are stored on a case as TEXT, so
// a case carrying a status that is later removed from the file keeps it rather than being silently
// rewritten.
//
// Called once at startup by each frontend with the file beside SAT's own state.
Status load_case_status_options(const std::filesystem::path& file);

// The same, from text already in memory. A session without an engineer licence keeps the statuses
// it edits in Settings this way: they apply until SAT closes and are never written. `source` names
// the text in a failure message.
Status load_case_status_options_text(std::string_view text, std::string_view source);

// Where that file lives relative to a state directory, and the text written when creating a
// starter copy for an engineer to edit.
std::filesystem::path case_status_options_path(const std::filesystem::path& state_directory);
std::string default_case_status_file_contents();
// The stored status, or the first option when a case has none.
std::string case_status_or_default(const CaseWorkspace& workspace);
Status save_case_review_note(const CaseWorkspace& workspace, CaseReviewNote note);
Result<std::vector<CaseReviewNote>> load_case_review_notes(const CaseWorkspace& workspace);
Status save_case_review_state(const CaseWorkspace& workspace, CaseReviewState state);
Result<CaseReviewState> load_case_review_state(const CaseWorkspace& workspace);
Result<std::string> save_case_evidence_bookmark(const CaseWorkspace& workspace,
                                                CaseEvidenceBookmark bookmark);
Result<std::vector<CaseEvidenceBookmark>> load_case_evidence_bookmarks(
    const CaseWorkspace& workspace);
Status delete_case_evidence_bookmark(const CaseWorkspace& workspace, std::string_view evidence_id);
Result<std::filesystem::path> save_case_ticket_note(const CaseWorkspace& workspace,
                                                    std::string_view note_text,
                                                    std::string_view name_hint = "log-review");
Status copy_case_artifact(const CaseWorkspace& workspace,
                          const std::filesystem::path& source,
                          std::string_view category);
std::string sanitize_case_identifier(std::string_view value);

} // namespace support_assist
