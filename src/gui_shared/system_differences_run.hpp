#pragma once

// System Differences for both editions: capture a folder, then compare that capture with this
// machine now or with a second capture. Windows and Linux pass their field text and get the same
// rows and result line back; core filesystem.hpp does the work. The Windows registry operations
// use the result line, the counts and the capture-file handling here as well. On Windows a files
// capture also records the NTFS change journal's position (core change_journal.hpp), and a compare
// reads the journal from there to add what a snapshot compare cannot see.

#include "support_assist/cancellation.hpp"
#include "support_assist/change_journal.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

inline constexpr int kDifferencesCapture = 0;
inline constexpr int kDifferencesCompare = 1;
inline constexpr const char* kCompareWithNow = "Now";
inline constexpr const char* kContentsNever = "Never";
inline constexpr const char* kContentsUpTo64 = "Files up to 64 MB";
inline constexpr const char* kContentsAll = "All files";
inline constexpr std::uint64_t kContentsSizeLimit = 64ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t kDifferencesShownRows = 100000;
inline constexpr std::size_t kSkippedShownRows = 200;

struct DifferencesRow {
  std::string change;
  std::string path;
  std::string reason;
  std::string detail;
};

struct DifferencesOutcome {
  bool ok = false;
  std::string summary; // the result line, or why it did not run
  std::vector<DifferencesRow> rows;
};

// "Compare file contents": Never, Files up to 64 MB, All files. The words earlier builds used
// (none, below-size, small, all) still read.
inline bool contents_choice(std::string_view text, HashMode& mode) {
  const std::string value = ascii_lower(trim(text));
  if (value.empty() || value == "never" || value == "none") {
    mode = HashMode::none;
    return true;
  }
  if (value == ascii_lower(kContentsUpTo64) || value == "below-size" || value == "small") {
    mode = HashMode::below_size;
    return true;
  }
  if (value == ascii_lower(kContentsAll) || value == "all") {
    mode = HashMode::all;
    return true;
  }
  return false;
}

inline bool compares_with_now(std::string_view text) {
  const std::string value = ascii_lower(trim(text));
  return value.empty() || value == "now";
}

// A change kind in words.
inline std::string grouped_number(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (int index = static_cast<int>(digits.size()) - 3; index > 0; index -= 3)
    digits.insert(static_cast<std::size_t>(index), ",");
  return digits;
}

inline std::string counted_text(std::uint64_t value, const char* one, const char* many) {
  return grouped_number(value) + " " + (value == 1 ? one : many);
}

inline std::string seconds_text(double value) {
  char text[32] = {};
  std::snprintf(text, sizeof(text), value < 10.0 ? "%.1f s" : "%.0f s", value);
  return text;
}

// A compare's counts by kind, for its result line.
struct DifferenceCounts {
  std::uint64_t added = 0;
  std::uint64_t removed = 0;
  std::uint64_t changed = 0;
  std::uint64_t moved = 0;

  void count(ChangeKind kind) {
    switch (kind) {
    case ChangeKind::added: ++added; break;
    case ChangeKind::removed: ++removed; break;
    case ChangeKind::moved:
    case ChangeKind::renamed:
    case ChangeKind::inferred_rename: ++moved; break;
    default: ++changed; break;
    }
  }

  std::string text() const {
    if (added + removed + changed + moved == 0)
      return "no differences.";
    return grouped_number(added) + " added, " + grouped_number(removed) + " removed, " + grouped_number(changed) +
           " changed, " + grouped_number(moved) + " moved or renamed.";
  }
};

// A result row for one compare record.
// The row a compare shows and keeps in the capture file (core stored_comparison_row words it).
inline DifferencesRow difference_row(const DiffRecord& change) {
  StoredComparisonRow row = stored_comparison_row(change);
  return {std::move(row.change), std::move(row.path), std::move(row.reason), std::move(row.detail)};
}

// A capture file and its SQLite companions.
inline void remove_capture_file(const std::filesystem::path& path) {
  std::error_code ignored;
  for (const char* suffix : {"", "-wal", "-shm", "-journal"}) {
    std::filesystem::path companion = path;
    companion += suffix;
    std::filesystem::remove(companion, ignored);
  }
}

// "taken 2026-10-16 19:00:01 UTC on SPECTR", from the capture's own record.
inline std::string capture_taken_text(const std::filesystem::path& file, const std::string& id) {
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return {};
  auto metadata = store.value().metadata(id);
  if (!metadata.ok())
    return {};
  std::string when = metadata.value().created_start_utc.substr(0, 19);
  if (const auto t = when.find('T'); t != std::string::npos)
    when[t] = ' ';
  std::string text = "taken " + when + " UTC";
  if (!metadata.value().machine_name.empty())
    text += " on " + metadata.value().machine_name;
  return text;
}

// The newest completed capture of a kind in a file.
inline Result<std::string> capture_id(const std::filesystem::path& file, SnapshotKind kind) {
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return Result<std::string>::failure(store.error());
  return store.value().latest_complete_snapshot_id(kind);
}

// The rows and result line of a finished capture: what was captured, where it was saved, and the
// places skipped for want of administrator rights.
// How a files capture read its folder, for the result line: the table, or folder by folder with the
// reason the table was not read. Empty when nothing was tried (another system, a registry capture).
inline std::string capture_source_sentence(const std::string& source, const std::string& note) {
  if (source == kCaptureSourceMft)
    return " Read from the NTFS master file table.";
  if (source == kCaptureSourceListing && !note.empty())
    return " Read folder by folder. The NTFS master file table was not read: " + note + ".";
  return {};
}

inline DifferencesOutcome capture_outcome(const std::string& from, const std::filesystem::path& file,
                                          const std::string& snapshot_id, std::uint64_t objects,
                                          std::uint64_t errors, double seconds) {
  std::vector<std::string> skipped;
  if (auto store = SnapshotStore::open(file, true); store.ok()) {
    if (auto sources = store.value().elevation_skipped_sources(snapshot_id); sources.ok())
      skipped = std::move(sources.value());
  }
  DifferencesOutcome outcome;
  outcome.ok = true;
  outcome.rows.push_back({"Captured", from, counted_text(objects, "object", "objects"), seconds_text(seconds)});
  outcome.rows.push_back({"Saved", path_to_utf8(file), "Capture file", ""});
  for (std::size_t index = 0; index < skipped.size() && index < kSkippedShownRows; ++index)
    outcome.rows.push_back({"Skipped", skipped[index], "Needs administrator rights", ""});

  outcome.summary =
      "Captured " + counted_text(objects, "object", "objects") + " from " + from + " in " + seconds_text(seconds) + ".";
  if (objects <= 1)
    outcome.summary += " Nothing is under it.";
  if (!skipped.empty())
    outcome.summary += " Skipped " + counted_text(skipped.size(), "place", "places") +
                       " that need administrator rights; run SAT as administrator to include them.";
  const std::uint64_t other_errors = errors > skipped.size() ? errors - skipped.size() : 0;
  if (other_errors > 0)
    outcome.summary += " " + counted_text(other_errors, "object", "objects") + " could not be read.";
  return outcome;
}

// The result line of a finished compare.
inline std::string compare_summary(bool now, const std::filesystem::path& other, const DifferenceCounts& counts,
                                   std::uint64_t total, const std::string& taken) {
  std::string summary = (now ? std::string("Compared with now") : "Compared with " + path_to_utf8(other.filename())) +
                        ": " + counts.text();
  if (!taken.empty())
    summary += " The capture was " + taken + ".";
  if (total > kDifferencesShownRows)
    summary += " The first " + grouped_number(kDifferencesShownRows) + " are listed.";
  return summary;
}

// ---- Change journal --------------------------------------------------------------------------
//
// A snapshot compare cannot see a file that was created and removed between the two captures. On
// Windows the NTFS change journal can: a capture records where the journal stood, and a compare
// reads the records written after that position.

inline constexpr std::size_t kJournalShownRows = 20000;
inline constexpr const char* kJournalRowReason = "Recorded by the NTFS change journal";

// The change journal's position recorded in a capture, if it has one.
inline std::optional<ChangeJournalMark> capture_journal_mark(const std::filesystem::path& file, const std::string& id) {
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return std::nullopt;
  auto mark = store.value().change_journal_mark(id);
  if (!mark.ok())
    return std::nullopt;
  return mark.value();
}

// Whether SAT was running as administrator when the capture was taken.
inline bool capture_was_elevated(const std::filesystem::path& file, const std::string& id) {
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return false;
  auto metadata = store.value().metadata(id);
  return metadata.ok() && metadata.value().elevated;
}

// What only the change journal can show: files and folders created and removed inside the window,
// and renames with the names before and after.
inline std::vector<DifferencesRow> journal_rows(const std::vector<JournalChange>& changes,
                                                std::size_t limit = kJournalShownRows) {
  std::vector<DifferencesRow> rows;
  for (const JournalChange& change : changes) {
    if (rows.size() >= limit)
      break;
    if (change.created_and_deleted()) {
      std::string detail = std::string(change.directory ? "Folder created " : "Created ") +
                           journal_time_text(change.created_time) + ", deleted " +
                           journal_time_text(change.deleted_time);
      if (change.renamed() && !change.renamed_from.empty())
        detail += ", renamed from " + change.renamed_from;
      rows.push_back({"Created and deleted", change.path, kJournalRowReason, detail});
    } else if (change.renamed()) {
      const std::string from = change.renamed_from.empty() ? std::string("outside the folder") : change.renamed_from;
      rows.push_back({"Renamed", change.renamed_to, kJournalRowReason,
                      from + " -> " + change.renamed_to + ", renamed " + journal_time_text(change.renamed_time)});
    }
  }
  return rows;
}

// The sentence a compare adds after reading the change journal.
inline std::string journal_result_text(const ChangeJournalReadout& readout) {
  std::uint64_t made_and_removed = 0;
  std::uint64_t renamed = 0;
  for (const JournalChange& change : readout.changes) {
    if (change.created_and_deleted())
      ++made_and_removed;
    else if (change.renamed())
      ++renamed;
  }
  std::string text;
  if (readout.changes.empty()) {
    text = " The change journal recorded no changes under the folder.";
  } else {
    text = " The change journal recorded " + counted_text(readout.records_inside, "change", "changes") + " to " +
           counted_text(readout.changes.size(), "file or folder", "files and folders") + " under the folder; ";
    std::vector<std::string> parts;
    if (made_and_removed > 0)
      parts.push_back(grouped_number(made_and_removed) + (made_and_removed == 1 ? " was" : " were") +
                      " created and deleted in between");
    if (renamed > 0)
      parts.push_back(grouped_number(renamed) + (renamed == 1 ? " was" : " were") + " renamed");
    if (parts.empty())
      text += "none were created and deleted in between.";
    else
      text += parts.front() + (parts.size() > 1 ? " and " + parts[1] : std::string()) + ".";
  }
  if (readout.unplaced > 0) {
    text += " Journal entries that could not be matched to a folder are not counted (" +
            grouped_number(readout.unplaced) + " on the volume).";
  }
  if (readout.cut_short) {
    text += " The read stopped at " + readout.cut_short_reason;
    if (readout.reached_time > 0)
      text += ", at " + journal_time_text(readout.reached_time);
    text += "; later changes are not included.";
  }
  if (readout.dropped > 0)
    text += " " + counted_text(readout.dropped, "more file or folder is", "more files and folders are") + " not listed.";
  return text;
}

// The sentence for a capture that has no change journal mark.
inline std::string journal_no_mark_text(bool elevated_at_capture) {
  if (!elevated_at_capture)
    return " No change journal position was recorded for this capture because SAT was not running as administrator. "
           "Capture again as administrator to list files created and removed in between.";
  return " No change journal position was recorded for this capture, so files created and removed in between are not "
         "listed.";
}

struct JournalFindings {
  std::vector<DifferencesRow> rows;
  std::string sentence; // added to the result line, starts with a space
  bool cancelled = false;
};

// Reads the change journal between the earlier capture and now, or the second capture. SAT's own
// temporary capture of this machine is left out of the list.
inline JournalFindings journal_findings(const std::filesystem::path& before, const std::string& before_id, bool now,
                                        const std::filesystem::path& after, const std::string& after_id,
                                        const std::filesystem::path& folder, const CancellationToken& token) {
  JournalFindings findings;
  const std::optional<ChangeJournalMark> start = capture_journal_mark(before, before_id);
  if (!start) {
    findings.sentence = journal_no_mark_text(capture_was_elevated(before, before_id));
    return findings;
  }
  ChangeJournalWindow window;
  window.folder = folder;
  window.start = *start;
  if (!now) {
    const std::optional<ChangeJournalMark> end = capture_journal_mark(after, after_id);
    if (!end) {
      findings.sentence = " No change journal position was recorded for the second capture, so files created and "
                          "removed between the two captures are not listed.";
      return findings;
    }
    if (end->journal_id != start->journal_id || !journal_path_equal(end->volume, start->volume)) {
      findings.sentence = " The two captures were not taken from the same change journal, so files created and "
                          "removed between them are not listed.";
      return findings;
    }
    if (end->next_usn <= start->next_usn) {
      findings.sentence = " The second capture was taken before the first, so no change journal records lie between "
                          "them.";
      return findings;
    }
    window.end_usn = end->next_usn;
  }
  auto readout = read_change_journal(window, token);
  if (!readout.ok()) {
    findings.sentence = " " + readout.error().message;
    return findings;
  }
  if (readout.value().cancelled) {
    findings.cancelled = true;
    return findings;
  }
  if (now) {
    const std::string own_name = path_to_utf8(after.filename());
    std::vector<std::string> own;
    for (const char* suffix : {"", "-wal", "-shm", "-journal"})
      own.push_back(own_name + suffix);
    auto& changes = readout.value().changes;
    changes.erase(std::remove_if(changes.begin(), changes.end(),
                                 [&](const JournalChange& change) {
                                   const auto slash = change.path.find_last_of('\\');
                                   const std::string_view leaf =
                                       slash == std::string::npos ? std::string_view(change.path)
                                                                  : std::string_view(change.path).substr(slash + 1);
                                   return std::any_of(own.begin(), own.end(), [&](const std::string& name) {
                                     return journal_path_equal(leaf, name);
                                   });
                                 }),
                  changes.end());
  }
  findings.rows = journal_rows(readout.value().changes);
  findings.sentence = journal_result_text(readout.value());
  return findings;
}

// Adds the change journal's position to a finished capture's result: a row when it was recorded,
// otherwise the reason when it is something the engineer can act on.
inline void note_capture_journal(DifferencesOutcome& outcome, const std::filesystem::path& folder,
                                 const std::filesystem::path& file, const std::string& snapshot_id) {
  if (!kChangeJournalSystem)
    return;
  if (const std::optional<ChangeJournalMark> mark = capture_journal_mark(file, snapshot_id)) {
    outcome.rows.push_back({"Change journal", path_to_utf8(folder), "Position recorded for a later compare",
                            "USN " + std::to_string(mark->next_usn) + " at " + mark->recorded_utc});
    return;
  }
  const std::string sentence = journal_mark_missing_sentence(probe_change_journal(folder));
  if (!sentence.empty())
    outcome.summary += " " + sentence;
}

// The row a compare shows when it found nothing, so the result is a table and not the hint card.
inline DifferencesRow no_differences_row(bool now, const std::filesystem::path& other) {
  return {"No differences", now ? std::string("Now") : path_to_utf8(other.filename()),
          "Nothing was added, removed, changed or moved since the capture.", ""};
}

// Keeps a finished compare in the capture compared (the first capture file): its header, every row
// and the counts. A file that cannot be written (read-only media) leaves the compare as it was.
inline std::string keep_comparison(const std::filesystem::path& file, const std::string& snapshot_id,
                                   const std::string& kind, bool now, const std::filesystem::path& other,
                                   const std::string& other_id, const std::vector<StoredComparisonRow>& rows,
                                   const StoredComparisonCounts& counts, const std::string& summary) {
  auto store = SnapshotStore::open(file, false);
  if (!store.ok())
    return " The compare was not kept in the capture file: " + store.error().message + ".";
  StoredComparison header;
  header.snapshot_id = snapshot_id;
  header.kind = kind;
  header.against = now ? std::string("now") : path_to_utf8(other);
  header.against_snapshot_id = other_id;
  auto id = store.value().begin_comparison(header);
  if (!id.ok())
    return " The compare was not kept in the capture file: " + id.error().message + ".";
  if (auto added = store.value().add_comparison_rows(id.value(), rows); !added.ok())
    return " The compare was not kept in the capture file: " + added.error().message + ".";
  if (auto finished = store.value().finish_comparison(id.value(), counts, summary); !finished.ok())
    return " The compare was not kept in the capture file: " + finished.error().message + ".";
  return " The compare is kept in the capture file.";
}

// The compares kept in a capture file, newest first, each with its rows, for Open. Returns how many
// compares the file keeps.
inline std::size_t add_kept_comparison_rows(DifferencesOutcome& outcome, SnapshotStore& store, const std::string& id,
                                            std::size_t limit) {
  auto kept = store.comparisons(id);
  if (!kept.ok())
    return 0;
  std::size_t added = 0;
  for (const StoredComparison& comparison : kept.value()) {
    std::string when = comparison.created_utc.substr(0, 19);
    if (const auto t_at = when.find('T'); t_at != std::string::npos)
      when[t_at] = ' ';
    outcome.rows.push_back({"Compare", comparison.against == "now" ? std::string("With now") : "With " + comparison.against,
                            when + " UTC", comparison_counts_text(comparison)});
    ++added;
    static_cast<void>(store.visit_comparison_rows(comparison.id, [&](const StoredComparisonRow& row) {
      if (added >= limit)
        return false;
      outcome.rows.push_back({row.change, row.path, row.reason, row.detail});
      ++added;
      return true;
    }));
  }
  return kept.value().size();
}

// How a page takes a files capture: capture_filesystem_baseline, or on Windows the elevated helper
// when the engineer chose to capture as administrator. Empty is capture_filesystem_baseline.
using CaptureRunner = std::function<Result<FilesystemBaselineResult>(
    const std::filesystem::path&, const FilesystemScanOptions&, const CancellationToken&, ProgressCallback,
    std::string_view)>;

inline Result<FilesystemBaselineResult> take_capture(const CaptureRunner& runner, const std::filesystem::path& file,
                                                     const FilesystemScanOptions& options,
                                                     const CancellationToken& token, ProgressCallback progress,
                                                     std::string_view options_json = "{}") {
  if (runner)
    return runner(file, options, token, std::move(progress), options_json);
  return capture_filesystem_baseline(file, options, token, std::move(progress), options_json);
}

// A progress callback that names its work: `phase` for the scanner's own reports, and `total` (when
// known) so the line shows the percent and the time left.
inline ProgressCallback named_progress(ProgressCallback forward, std::string phase, std::uint64_t total = 0) {
  if (!forward)
    return {};
  return [forward = std::move(forward), phase = std::move(phase), total](const ProgressEvent& event) {
    ProgressEvent copy = event;
    if (copy.phase == "filesystem-scan" || copy.phase.empty())
      copy.phase = phase;
    if (total != 0U && copy.total == 0U)
      copy.total = total;
    forward(copy);
  };
}

// Whether the capture file a form names is there yet: Compare captures first when it is not.
inline bool capture_file_exists(const std::string& file_text) {
  const std::string name = trim(file_text);
  std::error_code error;
  return !name.empty() && std::filesystem::is_regular_file(path_from_utf8(name), error);
}

// Whether a capture was read from the NTFS master file table, so a compare with now reads this
// machine the same way.
inline bool capture_read_from_mft(const std::string& file_text) {
  if (!capture_file_exists(file_text))
    return false;
  auto store = SnapshotStore::open(path_from_utf8(trim(file_text)), true);
  if (!store.ok())
    return false;
  auto id = store.value().latest_complete_snapshot_id(SnapshotKind::filesystem);
  if (!id.ok())
    return false;
  auto source = store.value().capture_source(id.value());
  return source.ok() && source.value() && source.value()->source == kCaptureSourceMft;
}

// Captures one folder into a capture file. A capture file holds one capture: an existing file is
// replaced (each GUI asks first). A cancelled capture is removed, as it cannot be compared.
inline DifferencesOutcome run_files_capture(const std::string& folder_text, const std::string& file_text,
                                            const std::string& contents_text, bool streams,
                                            const CancellationToken& token, ProgressCallback progress = {},
                                            const CaptureRunner& runner = {}) {
  const std::string folder = trim(folder_text);
  const std::string file_name = trim(file_text);
  if (folder.empty())
    return {false, "Choose the folder to look at.", {}};
  if (file_name.empty())
    return {false, "Choose where to save the capture.", {}};
  FilesystemScanOptions options;
  if (!contents_choice(contents_text, options.hash_mode))
    return {false,
            std::string("Compare file contents takes ") + kContentsNever + ", " + kContentsUpTo64 + " or " +
                kContentsAll + ".",
            {}};
  options.root = path_from_utf8(folder);
  options.hash_size_limit = kContentsSizeLimit;
  options.capture_streams = streams;
  std::error_code error;
  if (!std::filesystem::is_directory(options.root, error))
    return {false, "No folder at " + folder + ".", {}};
  const std::filesystem::path file = path_from_utf8(file_name);
  remove_capture_file(file);

  const auto started = std::chrono::steady_clock::now();
  auto captured = take_capture(runner, file, options, token, named_progress(std::move(progress), "Capturing"),
                               "{\"hash\":\"" + to_string(options.hash_mode) + "\"}");
  if (!captured.ok()) {
    if (token.is_cancelled()) {
      remove_capture_file(file);
      return {false, "Capture cancelled. A cancelled capture cannot be compared, so it was not kept.", {}};
    }
    return {false, describe_error(captured.error()), {}};
  }
  const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
  if (captured.value().state != SnapshotState::complete) {
    remove_capture_file(file);
    return {false, "Capture cancelled. A cancelled capture cannot be compared, so it was not kept.", {}};
  }
  DifferencesOutcome outcome = capture_outcome(folder, file, captured.value().snapshot_id, captured.value().objects,
                                               captured.value().errors, seconds);
  outcome.summary += capture_source_sentence(captured.value().source, captured.value().source_note);
  note_capture_journal(outcome, options.root, file, captured.value().snapshot_id);
  return outcome;
}

// Compares a capture with this machine now, or with a second capture of the same folder.
inline DifferencesOutcome run_files_compare(const std::string& file_text, const std::string& with_text,
                                            const CancellationToken& token, ProgressCallback progress = {},
                                            const CaptureRunner& runner = {}) {
  const std::string file_name = trim(file_text);
  if (file_name.empty())
    return {false, "Choose the capture file to compare.", {}};
  const std::filesystem::path before = path_from_utf8(file_name);
  std::string before_id;
  auto options = load_filesystem_baseline_options(before, before_id);
  if (!options.ok())
    return {false, describe_error(options.error()), {}};

  const bool now = compares_with_now(with_text);
  std::filesystem::path after;
  std::string after_id;
  std::string source_sentence;
  if (now) {
    after = std::filesystem::temp_directory_path() / ("sat-live-" + make_uuid_v4() + ".satsnap");
    // The capture's own object count is about what this machine holds now, so the read shows a percent.
    std::uint64_t expected = 0;
    if (auto store = SnapshotStore::open(before, true); store.ok()) {
      if (auto metadata = store.value().metadata(before_id); metadata.ok())
        expected = metadata.value().object_count;
    }
    auto live = take_capture(runner, after, options.value(), token,
                             named_progress(progress, "Reading this machine", expected));
    if (!live.ok()) {
      remove_capture_file(after);
      if (token.is_cancelled())
        return {false, "Compare cancelled while reading this machine.", {}};
      return {false, describe_error(live.error()), {}};
    }
    if (live.value().state != SnapshotState::complete) {
      remove_capture_file(after);
      return {false, "Compare cancelled while reading this machine.", {}};
    }
    after_id = live.value().snapshot_id;
    if (options.value().try_mft && live.value().source == kCaptureSourceListing)
      source_sentence = " The capture was read from the NTFS master file table and this machine folder by folder (" +
                        live.value().source_note + "), so sizes on disk and folders SAT could not open can differ "
                        "for that reason alone.";
  } else {
    after = path_from_utf8(trim(with_text));
    auto id = capture_id(after, SnapshotKind::filesystem);
    if (!id.ok())
      return {false, describe_error(id.error()), {}};
    after_id = id.value();
  }

  DifferencesOutcome outcome;
  DifferenceCounts counts;
  StoredComparisonCounts kept_counts;
  std::vector<StoredComparisonRow> kept_rows;
  auto compared = compare_filesystem(before, before_id, after, after_id, FilesystemCompareOptions{},
                                     [&](const DiffRecord& change) {
                                       counts.count(change.kind);
                                       kept_counts.count(change.kind);
                                       kept_rows.push_back(stored_comparison_row(change));
                                       if (outcome.rows.size() < kDifferencesShownRows)
                                         outcome.rows.push_back(difference_row(change));
                                       return Status::success();
                                     },
                                     token, progress);
  const std::string taken = capture_taken_text(before, before_id);
  if (!compared.ok()) {
    if (now)
      remove_capture_file(after);
    if (token.is_cancelled())
      return {false, "Compare cancelled.", {}};
    return {false, describe_error(compared.error()), {}};
  }

  // What the snapshots cannot show, from the change journal. The compare stands without it.
  JournalFindings journal;
  if (kChangeJournalSystem) {
    if (progress)
      progress(ProgressEvent{"Reading the NTFS change journal", path_to_utf8(options.value().root), 0, 0, 0.0, 0.0, 0});
    journal = journal_findings(before, before_id, now, after, after_id, options.value().root, token);
  }
  if (now)
    remove_capture_file(after);
  if (journal.cancelled)
    return {false, "Compare cancelled while reading the change journal.", {}};
  for (DifferencesRow& row : journal.rows) {
    kept_rows.push_back({row.change, row.path, row.reason, row.detail});
    if (outcome.rows.size() < kDifferencesShownRows)
      outcome.rows.push_back(std::move(row));
  }
  if (outcome.rows.empty())
    outcome.rows.push_back(no_differences_row(now, after));
  outcome.ok = true;
  outcome.summary = compare_summary(now, after, counts, compared.value(), taken) + journal.sentence + source_sentence;
  outcome.summary += keep_comparison(before, before_id, "filesystem", now, after, after_id, kept_rows, kept_counts,
                                     outcome.summary);
  return outcome;
}

// ---- Open ------------------------------------------------------------------------------------
//
// Open reads a capture file and lists what it holds: when and where it was taken and what it
// covers, then each object in path order, the first kDifferencesShownRows of them.

inline constexpr int kDifferencesLoad = 4;
inline constexpr int kDifferencesRegistryLoad = 5;

// A capture's time as text. Windows records 100 ns ticks since 1601, the other systems since 1970.
inline std::string capture_time_text(std::int64_t ticks, bool windows_capture) {
  if (ticks <= 0)
    return {};
  return journal_time_text(windows_capture ? ticks : ticks + 116444736000000000LL);
}

// The capture's own rows: what it covers, when and where it was taken, and its object count.
inline void add_capture_rows(DifferencesOutcome& outcome, SnapshotStore& store, const std::string& id,
                             const std::string& covered) {
  auto metadata = store.metadata(id);
  if (!metadata.ok())
    return;
  const SnapshotMetadata& value = metadata.value();
  std::string taken = value.created_start_utc.substr(0, 19);
  if (const auto t = taken.find('T'); t != std::string::npos)
    taken[t] = ' ';
  outcome.rows.push_back({"Capture", covered, "Taken " + taken + " UTC" + (value.machine_name.empty() ? std::string() : " on " + value.machine_name),
                          counted_text(value.object_count, "object", "objects")});
  const bool windows = value.os_name.find("Windows") != std::string::npos;
  outcome.rows.push_back({"Taken as", value.elevated ? (windows ? "Administrator" : "Root") : "Standard user",
                          value.os_name + " " + value.os_version, ""});
  if (auto source = store.capture_source(id); source.ok() && source.value())
    outcome.rows.push_back({"Read from",
                            source.value()->source == kCaptureSourceMft ? "NTFS master file table" : "Folder by folder",
                            source.value()->detail, ""});
  if (auto skipped = store.elevation_skipped_sources(id); skipped.ok()) {
    for (std::size_t index = 0; index < skipped.value().size() && index < kSkippedShownRows; ++index)
      outcome.rows.push_back({"Skipped", skipped.value()[index], "Needs administrator rights", ""});
  }
}

inline std::string kept_compares_sentence(std::size_t compares) {
  if (compares == 0)
    return " No compares are kept in it yet.";
  return " " + counted_text(compares, "compare is", "compares are") + " kept in it, newest first.";
}

inline DifferencesOutcome run_files_load(const std::string& file_text, const CancellationToken& token) {
  const std::string file_name = trim(file_text);
  if (file_name.empty())
    return {false, "Choose the capture file to open.", {}};
  const std::filesystem::path file = path_from_utf8(file_name);
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return {false, describe_error(store.error()), {}};
  if (auto valid = store.value().validate(); !valid.ok())
    return {false, describe_error(valid.error()), {}};
  auto id = store.value().latest_complete_snapshot_id(SnapshotKind::filesystem);
  if (!id.ok())
    return {false, describe_error(id.error()), {}};
  auto metadata = store.value().metadata(id.value());
  if (!metadata.ok())
    return {false, describe_error(metadata.error()), {}};
  const bool windows_capture = metadata.value().os_name.find("Windows") != std::string::npos;
  std::string folder;
  std::string contents = kContentsNever;
  if (auto config = store.value().filesystem_scan_config(id.value()); config.ok()) {
    folder = config.value().root_path;
    const HashMode mode = parse_hash_mode(config.value().hash_mode);
    contents = mode == HashMode::all ? kContentsAll : mode == HashMode::below_size ? kContentsUpTo64 : kContentsNever;
  }

  DifferencesOutcome outcome;
  add_capture_rows(outcome, store.value(), id.value(), folder);
  outcome.rows.push_back({"Compare file contents", contents, "", ""});
  if (auto mark = store.value().change_journal_mark(id.value()); mark.ok() && mark.value())
    outcome.rows.push_back({"Change journal", mark.value()->volume, "Position recorded for a later compare",
                            "USN " + std::to_string(mark.value()->next_usn) + " at " + mark.value()->recorded_utc});
  const std::size_t compares = add_kept_comparison_rows(outcome, store.value(), id.value(), kDifferencesShownRows / 2);
  const std::size_t header = outcome.rows.size();

  std::uint64_t objects = 0;
  std::uint64_t files = 0;
  std::uint64_t folders = 0;
  std::uint64_t bytes = 0;
  bool cancelled = false;
  auto visited = store.value().visit_filesystem_objects(id.value(), [&](const SnapshotStore::CapturedObject& object) {
    if (token.is_cancelled()) {
      cancelled = true;
      return false;
    }
    ++objects;
    const bool is_file = object.object_type == "file";
    files += is_file ? 1U : 0U;
    folders += object.object_type == "directory" ? 1U : 0U;
    bytes += is_file ? object.size : 0U;
    if (outcome.rows.size() - header >= kDifferencesShownRows)
      return true;
    std::string kind = is_file ? "File" : object.object_type == "directory" ? "Folder" : "Link";
    std::string detail = capture_time_text(object.write_100ns, windows_capture);
    if (!object.content_hash.empty())
      detail += (detail.empty() ? "" : "; ") + std::string("SHA-256 ") + object.content_hash;
    if (object.access_result != 0)
      detail += (detail.empty() ? "" : "; ") + std::string("not read: error ") + std::to_string(object.access_result);
    outcome.rows.push_back({std::move(kind), object.relative_path,
                            is_file ? counted_text(object.size, "byte", "bytes") : std::string(), std::move(detail)});
    return true;
  });
  if (cancelled)
    return {false, "Open cancelled.", {}};
  if (!visited.ok())
    return {false, describe_error(visited.error()), {}};
  outcome.ok = true;
  outcome.summary = "Opened " + path_to_utf8(file.filename()) + ": " + counted_text(files, "file", "files") + " and " +
                    counted_text(folders, "folder", "folders") + " under " + folder + ", " +
                    counted_text(bytes, "byte", "bytes") + ".";
  outcome.summary += kept_compares_sentence(compares);
  if (objects > kDifferencesShownRows)
    outcome.summary += " The first " + grouped_number(kDifferencesShownRows) + " are listed.";
  return outcome;
}

inline DifferencesOutcome run_registry_load(const std::string& file_text, const CancellationToken& token) {
  const std::string file_name = trim(file_text);
  if (file_name.empty())
    return {false, "Choose the capture file to open.", {}};
  const std::filesystem::path file = path_from_utf8(file_name);
  auto store = SnapshotStore::open(file, true);
  if (!store.ok())
    return {false, describe_error(store.error()), {}};
  if (auto valid = store.value().validate(); !valid.ok())
    return {false, describe_error(valid.error()), {}};
  auto id = store.value().latest_complete_snapshot_id(SnapshotKind::registry);
  if (!id.ok())
    return {false, describe_error(id.error()), {}};
  std::string scope;
  if (auto configs = store.value().registry_scope_configs(id.value()); configs.ok()) {
    for (const RegistryScopeConfig& config : configs.value())
      scope += (scope.empty() ? "" : "; ") + config.hive + (config.subkey.empty() ? "" : "\\" + config.subkey) +
               " (" + to_string(config.view) + ")";
  }
  DifferencesOutcome outcome;
  add_capture_rows(outcome, store.value(), id.value(), scope);
  const std::size_t compares = add_kept_comparison_rows(outcome, store.value(), id.value(), kDifferencesShownRows / 2);
  const std::size_t header = outcome.rows.size();
  std::uint64_t keys = 0;
  std::uint64_t values = 0;
  bool cancelled = false;
  auto visited = store.value().visit_registry_items(id.value(), [&](const SnapshotStore::CapturedRegistryItem& item) {
    if (token.is_cancelled()) {
      cancelled = true;
      return false;
    }
    (item.is_value ? values : keys) += 1U;
    if (outcome.rows.size() - header >= kDifferencesShownRows)
      return true;
    const std::string key = item.hive + (item.relative_path.empty() ? "" : "\\" + item.relative_path);
    if (item.is_value)
      outcome.rows.push_back({"Value", key, item.value_name.empty() ? "(Default)" : item.value_name, item.data});
    else
      outcome.rows.push_back({"Key", key, item.registry_view, capture_time_text(item.last_write_100ns, true)});
    return true;
  });
  if (cancelled)
    return {false, "Open cancelled.", {}};
  if (!visited.ok())
    return {false, describe_error(visited.error()), {}};
  outcome.ok = true;
  outcome.summary = "Opened " + path_to_utf8(file.filename()) + ": " + counted_text(keys, "key", "keys") + " and " +
                    counted_text(values, "value", "values") + " under " + scope + ".";
  outcome.summary += kept_compares_sentence(compares);
  if (keys + values > kDifferencesShownRows)
    outcome.summary += " The first " + grouped_number(kDifferencesShownRows) + " are listed.";
  return outcome;
}

// The command line for Show CLI, the same on both editions.
inline std::vector<std::string> files_differences_cli_arguments(int mode, const std::string& first,
                                                                const std::string& second,
                                                                const std::string& contents) {
  if (mode == kDifferencesCapture) {
    if (trim(first).empty() || trim(second).empty())
      return {};
    std::vector<std::string> arguments{"files", "baseline", "--path", trim(first), "--output", trim(second)};
    HashMode hash = HashMode::none;
    if (contents_choice(contents, hash) && hash != HashMode::none)
      arguments.insert(arguments.end(), {"--hash", to_string(hash)});
    return arguments;
  }
  if (trim(first).empty())
    return {};
  if (mode == kDifferencesLoad || mode == kDifferencesRegistryLoad)
    return {"baseline", "inspect", "--file", trim(first)};
  // The page keeps every compare in the capture file, as --keep does.
  std::vector<std::string> arguments{"files", "compare", "--baseline", trim(first), "--keep"};
  if (compares_with_now(second))
    arguments.push_back("--live");
  else
    arguments.insert(arguments.end(), {"--other", trim(second)});
  return arguments;
}

} // namespace support_assist::gui
