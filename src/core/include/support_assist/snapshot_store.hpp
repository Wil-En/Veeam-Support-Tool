#pragma once
#include "support_assist/change_journal.hpp"
#include "support_assist/error.hpp"
#include "support_assist/models.hpp"
#include "support_assist/sqlite.hpp"
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
namespace support_assist {
std::string_view snapshot_schema_sql();
// The tables that keep compares inside a capture file, as CREATE TABLE IF NOT EXISTS statements.
std::string_view snapshot_comparison_schema_sql();
std::string_view snapshot_capture_source_schema_sql();

// How a files capture read its folder: from the NTFS master file table, or folder by folder.
inline constexpr const char* kCaptureSourceMft = "mft";
inline constexpr const char* kCaptureSourceListing = "listing";
struct CaptureSource {
  std::string source;  // kCaptureSourceMft or kCaptureSourceListing
  std::string detail;  // why the master file table was not used, when it was tried
};

// What a compare found, by kind: moved includes renamed and renamed by content.
struct StoredComparisonCounts {
  std::uint64_t added = 0;
  std::uint64_t removed = 0;
  std::uint64_t changed = 0;
  std::uint64_t moved = 0;
  void count(ChangeKind kind) noexcept;
  std::uint64_t total() const noexcept {
    return added + removed + changed + moved;
  }
};
// "no differences." or "3 added, 1 removed, 2 changed, 0 moved or renamed."
std::string comparison_counts_text(const StoredComparisonCounts& counts);
// A change kind in words: Added, Removed, Changed, Renamed, Moved and so on.
std::string comparison_change_words(ChangeKind kind);

// A compare kept in a capture file. A comparison that was begun and never finished has an empty
// summary.
struct StoredComparison : StoredComparisonCounts {
  std::int64_t id = 0;
  std::string snapshot_id;          // the capture that was compared
  std::string created_utc;          // filled in by begin_comparison when empty
  std::string kind;                 // "filesystem" or "registry"
  std::string against = "now";      // "now" or the second file's path
  std::string against_snapshot_id;  // the capture compared with
  std::string summary;
};
// One row of a stored comparison, as the Differences list shows it.
struct StoredComparisonRow {
  std::string change;  // Added, Removed, Changed, ...
  std::string path;
  std::string reason;
  std::string detail;  // "before -> after"
};
// The row a compare record becomes: its kind in words, identity, reason and "before -> after".
StoredComparisonRow stored_comparison_row(const DiffRecord& record);

class SnapshotStore {
public:
  SnapshotStore() = default;
  static Result<SnapshotStore> create(const std::filesystem::path& path);
  static Result<SnapshotStore> open(const std::filesystem::path& path, bool read_only = false);
  Status initialize_schema();
  Status begin_snapshot(const SnapshotMetadata& metadata);
  Status finish_snapshot(std::string_view id,
                         SnapshotState state,
                         std::uint64_t objects,
                         std::uint64_t errors);
  Status add_error(std::string_view snapshot_id, const Error& error);
  Status add_registry_scope_config(const RegistryScopeConfig& config);
  Status set_filesystem_scan_config(const FilesystemScanConfig& config);
  Result<std::vector<RegistryScopeConfig>> registry_scope_configs(std::string_view snapshot_id);
  Result<FilesystemScanConfig> filesystem_scan_config(std::string_view snapshot_id);
  Status add_registry_key(const RegistryKeyRecord& record);
  Status add_registry_value(const RegistryValueRecord& record);
  Status add_filesystem_object(const FilesystemRecord& record);
  Result<SnapshotMetadata> metadata(std::string_view id);
  Result<std::string> latest_complete_snapshot_id();
  // The newest completed capture of one kind: one file can hold a files and a registry capture.
  Result<std::string> latest_complete_snapshot_id(SnapshotKind kind);
  // The places a capture could not read without administrator rights, in the order met.
  Result<std::vector<std::string>> elevation_skipped_sources(std::string_view snapshot_id);
  // Where the NTFS change journal stood when a capture finished. A capture without one (an older
  // file, another system, no administrator rights) is valid, and change_journal_mark answers
  // an empty optional for it.
  Status set_change_journal_mark(std::string_view snapshot_id, const ChangeJournalMark& mark);
  Result<std::optional<ChangeJournalMark>> change_journal_mark(std::string_view snapshot_id);
  // How a files capture was read. A capture file made before this was recorded answers an empty
  // optional; it was read folder by folder.
  Status set_capture_source(std::string_view snapshot_id, const CaptureSource& source);
  Result<std::optional<CaptureSource>> capture_source(std::string_view snapshot_id);
  // What a capture holds, in path order, each item passed to visit until it returns false.
  struct CapturedObject {
    std::string relative_path;
    std::string object_type;  // file, directory or reparse
    std::uint64_t size = 0;
    std::int64_t write_100ns = 0;
    std::string content_hash;
    int access_result = 0;    // the system error that kept it from being read, 0 when read
  };
  struct CapturedRegistryItem {
    std::string hive;
    std::string relative_path;
    std::string registry_view;
    bool is_value = false;    // a value of the key, else the key itself
    std::string value_name;   // empty with is_value for the key's default value
    std::string data;         // a value's data as text; for a key, empty
    std::int64_t last_write_100ns = 0;  // a key's last write time
  };
  Status visit_filesystem_objects(std::string_view snapshot_id,
                                  const std::function<bool(const CapturedObject&)>& visit);
  Status visit_registry_items(std::string_view snapshot_id,
                              const std::function<bool(const CapturedRegistryItem&)>& visit);
  // Compares kept in the capture file. The store has to be open for writing to begin one; a file
  // made before they existed gains the tables then. Rows go in as they are found: begin, add rows
  // in batches (each call is one transaction and continues the numbering), then finish with the
  // counts and the result line. A file opened read-only, or one without the tables, answers an
  // empty list or no rows.
  Result<std::int64_t> begin_comparison(const StoredComparison& header);
  Status add_comparison_rows(std::int64_t id, const std::vector<StoredComparisonRow>& rows);
  Status finish_comparison(std::int64_t id, const StoredComparisonCounts& counts, std::string_view summary);
  // Removes a comparison and its rows, for one that was cancelled or failed part way.
  Status delete_comparison(std::int64_t id);
  // The comparisons of one capture, newest first; an empty snapshot_id lists every capture's.
  Result<std::vector<StoredComparison>> comparisons(std::string_view snapshot_id);
  // The rows of one comparison in the order they were added, each passed to visit until it returns
  // false.
  Status visit_comparison_rows(std::int64_t id, const std::function<bool(const StoredComparisonRow&)>& visit);
  Status validate();
  Database& db() noexcept {
    return db_;
  }
  const std::filesystem::path& path() const noexcept {
    return path_;
  }

private:
  SnapshotStore(Database db, std::filesystem::path path)
      : db_(std::move(db)), path_(std::move(path)) {}
  Database db_;
  std::filesystem::path path_;
};
class SnapshotBatchWriter {
public:
  SnapshotBatchWriter() = default;
  ~SnapshotBatchWriter();
  SnapshotBatchWriter(const SnapshotBatchWriter&) = delete;
  SnapshotBatchWriter& operator=(const SnapshotBatchWriter&) = delete;
  SnapshotBatchWriter(SnapshotBatchWriter&& other) noexcept;
  SnapshotBatchWriter& operator=(SnapshotBatchWriter&& other) noexcept;
  static Result<SnapshotBatchWriter> create(SnapshotStore& store, std::size_t batch_size = 1000);
  Status add_error(std::string_view snapshot_id, const Error& error);
  Status add_registry_scope_config(const RegistryScopeConfig& config);
  Status set_filesystem_scan_config(const FilesystemScanConfig& config);
  Result<std::vector<RegistryScopeConfig>> registry_scope_configs(std::string_view snapshot_id);
  Result<FilesystemScanConfig> filesystem_scan_config(std::string_view snapshot_id);
  Status add_registry_key(const RegistryKeyRecord& record);
  Status add_registry_value(const RegistryValueRecord& record);
  Status add_filesystem_object(const FilesystemRecord& record);
  Status flush();
  Status finish();

private:
  Status after_row();
  Database* db_ = nullptr;
  Statement error_;
  Statement registry_key_;
  Statement registry_value_;
  Statement filesystem_object_;
  std::size_t batch_size_ = 1000;
  std::size_t pending_ = 0;
  bool transaction_active_ = false;
};

} // namespace support_assist
