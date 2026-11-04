#include "support_assist/filesystem.hpp"
#include "support_assist/sqlite.hpp"
#include "support_assist/strings.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

// The compare's own capture files, when they lie in the folder that was captured: the capture and
// SQLite's journal files beside it, as paths relative to that folder. Writing them moves the
// last-write time of the folder that holds them, so that alone is not reported either.
struct OwnFiles {
  std::vector<std::string> files;
  std::vector<std::string> folders;
};

// A relative path in one form for matching: '/' between parts, and case folded on Windows.
std::string match_form(std::string text) {
  std::replace(text.begin(), text.end(), '\\', '/');
#ifdef _WIN32
  std::transform(text.begin(), text.end(), text.begin(),
                 [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
#endif
  return text;
}

void add_own_file(OwnFiles& own, const std::filesystem::path& root, const std::filesystem::path& capture) {
  if (root.empty() || capture.empty())
    return;
  std::error_code error;
  const std::filesystem::path base = std::filesystem::weakly_canonical(root, error);
  if (error)
    return;
  const std::filesystem::path file = std::filesystem::weakly_canonical(std::filesystem::absolute(capture, error), error);
  if (error)
    return;
  const std::string relative = match_form(path_to_utf8(file.lexically_relative(base)));
  if (relative.empty() || relative == "." || relative.rfind("..", 0) == 0)
    return;
  for (const char* suffix : {"", "-wal", "-shm", "-journal"})
    own.files.push_back(relative + suffix);
  const std::size_t slash = relative.find_last_of('/');
  own.folders.push_back(slash == std::string::npos ? std::string(".") : relative.substr(0, slash));
}

bool is_own_change(const OwnFiles& own, const DiffRecord& difference) {
  const auto listed = [](const std::vector<std::string>& paths, const std::string& path) {
    return std::find(paths.begin(), paths.end(), match_form(path)) != paths.end();
  };
  for (const std::string* path : {&difference.old_path, &difference.new_path}) {
    if (!path->empty() && listed(own.files, *path))
      return true;
  }
  if (difference.kind == ChangeKind::metadata_changed && difference.reason == "Last-write time changed") {
    const std::string& path = difference.new_path.empty() ? difference.old_path : difference.new_path;
    return listed(own.folders, path);
  }
  return false;
}

Status attach_filesystem_snapshot(Database& database, const std::filesystem::path& path) {
  auto prepared = database.prepare("ATTACH DATABASE ? AS rhs;");
  if (!prepared.ok())
    return Status::failure(prepared.error());
  const auto utf8 = path.u8string();
  const std::string value(reinterpret_cast<const char*>(utf8.data()), utf8.size());
  if (auto status = prepared.value().bind(1, value); !status.ok())
    return status;
  auto row = prepared.value().step();
  return row.ok() ? Status::success() : Status::failure(row.error());
}

ChangeKind parse_change_kind(std::string_view value) {
  if (value == "added")
    return ChangeKind::added;
  if (value == "removed")
    return ChangeKind::removed;
  if (value == "moved")
    return ChangeKind::moved;
  if (value == "inferred_rename")
    return ChangeKind::inferred_rename;
  if (value == "type_changed")
    return ChangeKind::type_changed;
  if (value == "access_changed")
    return ChangeKind::access_changed;
  if (value == "metadata_changed")
    return ChangeKind::metadata_changed;
  return ChangeKind::modified;
}

Status stream_rows(Database& database,
                   std::string_view sql,
                   const OwnFiles& own,
                   const DiffCallback& callback,
                   std::uint64_t& count) {
  auto prepared = database.prepare(sql);
  if (!prepared.ok())
    return Status::failure(prepared.error());
  for (;;) {
    auto row = prepared.value().step();
    if (!row.ok())
      return Status::failure(row.error());
    if (!row.value())
      break;

    DiffRecord difference;
    difference.kind = parse_change_kind(prepared.value().column_text(0));
    difference.category = "filesystem";
    difference.identity = prepared.value().column_text(1);
    difference.old_path = prepared.value().column_text(2);
    difference.new_path = prepared.value().column_text(3);
    difference.before_summary = prepared.value().column_text(4);
    difference.after_summary = prepared.value().column_text(5);
    difference.reason = prepared.value().column_text(6);
    difference.confidence = prepared.value().column_double(7);
    if (is_own_change(own, difference))
      continue;
    if (auto status = callback(difference); !status.ok())
      return status;
    ++count;
  }
  return Status::success();
}

// Each capture's stable identities and content hashes, counted, with the row of an identity or hash
// that one object holds. They are built once per compare and keyed, so the queries below find an
// object by its key or its row; joined unkeyed, SQLite scans one capture's list for each entry of the
// other, which is hours of work at 300,000 objects.
constexpr std::string_view kCompareKeysSql = R"SQL(
CREATE TEMP TABLE left_ids(volume_serial INTEGER,file_id_hex TEXT,count INTEGER,object_id INTEGER,
  PRIMARY KEY(volume_serial,file_id_hex));
CREATE TEMP TABLE right_ids(volume_serial INTEGER,file_id_hex TEXT,count INTEGER,object_id INTEGER,
  PRIMARY KEY(volume_serial,file_id_hex));
CREATE TEMP TABLE left_hashes(content_hash TEXT,size INTEGER,count INTEGER,object_id INTEGER,
  PRIMARY KEY(content_hash,size));
CREATE TEMP TABLE right_hashes(content_hash TEXT,size INTEGER,count INTEGER,object_id INTEGER,
  PRIMARY KEY(content_hash,size));
INSERT INTO left_ids
  SELECT volume_serial,file_id_hex,COUNT(*),MIN(id) FROM main.filesystem_objects
  WHERE snapshot_id=(SELECT before_id FROM compare_ids) AND file_id_hex<>''
  GROUP BY volume_serial,file_id_hex;
INSERT INTO right_ids
  SELECT volume_serial,file_id_hex,COUNT(*),MIN(id) FROM rhs.filesystem_objects
  WHERE snapshot_id=(SELECT after_id FROM compare_ids) AND file_id_hex<>''
  GROUP BY volume_serial,file_id_hex;
INSERT INTO left_hashes
  SELECT content_hash,size,COUNT(*),MIN(id) FROM main.filesystem_objects
  WHERE snapshot_id=(SELECT before_id FROM compare_ids) AND object_type='file' AND content_hash<>''
  GROUP BY content_hash,size;
INSERT INTO right_hashes
  SELECT content_hash,size,COUNT(*),MIN(id) FROM rhs.filesystem_objects
  WHERE snapshot_id=(SELECT after_id FROM compare_ids) AND object_type='file' AND content_hash<>''
  GROUP BY content_hash,size;
)SQL";

// An object whose stable identity one object holds in each capture, at another path. CROSS JOIN keeps
// SQLite to this order: each identity of the first capture, then lookups by key and by row.
constexpr std::string_view kExactMovesSql = R"SQL(
SELECT 'moved',l.volume_serial||':'||l.file_id_hex,l.relative_path,r.relative_path,
       'type='||l.object_type||'; size='||l.size||'; write='||l.write_100ns,
       'type='||r.object_type||'; size='||r.size||'; write='||r.write_100ns,
       'Unique stable file identity matched on the same volume',1.0
FROM compare_ids ids
CROSS JOIN left_ids lc
CROSS JOIN right_ids rc
CROSS JOIN main.filesystem_objects l
CROSS JOIN rhs.filesystem_objects r
WHERE ids.detect_moves=1 AND lc.count=1
  AND rc.volume_serial=lc.volume_serial AND rc.file_id_hex=lc.file_id_hex AND rc.count=1
  AND l.id=lc.object_id AND r.id=rc.object_id
  AND l.relative_path<>r.relative_path;
)SQL";

// A file whose size and SHA-256 one file holds in each capture, at another path, when the stable
// identity did not match them and nothing in the second capture is at the old path.
constexpr std::string_view kInferredMovesSql = R"SQL(
SELECT 'inferred_rename',l.content_hash,l.relative_path,r.relative_path,
       'size='||l.size||'; hash='||l.content_hash,
       'size='||r.size||'; hash='||r.content_hash,
       'Unique size and SHA-256 match; stable identity was unavailable or changed',0.75
FROM compare_ids ids
CROSS JOIN left_hashes lc
CROSS JOIN right_hashes rc
CROSS JOIN main.filesystem_objects l
CROSS JOIN rhs.filesystem_objects r
WHERE ids.infer_moves=1 AND lc.count=1
  AND rc.content_hash=lc.content_hash AND rc.size=lc.size AND rc.count=1
  AND l.id=lc.object_id AND r.id=rc.object_id
  AND l.relative_path<>r.relative_path
  AND (l.file_id_hex='' OR r.file_id_hex='' OR
       l.volume_serial<>r.volume_serial OR l.file_id_hex<>r.file_id_hex)
  AND NOT EXISTS (
      SELECT 1 FROM rhs.filesystem_objects same_path
      WHERE same_path.snapshot_id=ids.after_id
        AND same_path.relative_path=l.relative_path
  );
)SQL";

// An object at the same path in both captures whose recorded state differs. A hard-link count of 0
// was not read (a file taken from its folder's listing), so it is compared only when both were read.
constexpr std::string_view kModifiedSql = R"SQL(
WITH ids AS (SELECT before_id,after_id,tolerance,access_tolerance FROM compare_ids)
SELECT CASE
         WHEN l.object_type<>r.object_type THEN 'type_changed'
         WHEN l.access_result<>r.access_result THEN 'access_changed'
         WHEN l.content_hash<>'' AND r.content_hash<>'' AND l.content_hash<>r.content_hash
           THEN 'modified'
         WHEN l.size<>r.size THEN 'modified'
         ELSE 'metadata_changed'
       END,
       l.relative_path,l.relative_path,r.relative_path,
       'type='||l.object_type||'; size='||l.size||'; allocation='||l.allocation_size
         ||'; create='||l.creation_100ns||'; access='||l.access_100ns
         ||'; write='||l.write_100ns||'; change='||l.change_100ns
         ||'; attrs='||l.attributes||'; links='||l.hard_link_count
         ||'; access_result='||l.access_result||'; hash='||l.content_hash,
       'type='||r.object_type||'; size='||r.size||'; allocation='||r.allocation_size
         ||'; create='||r.creation_100ns||'; access='||r.access_100ns
         ||'; write='||r.write_100ns||'; change='||r.change_100ns
         ||'; attrs='||r.attributes||'; links='||r.hard_link_count
         ||'; access_result='||r.access_result||'; hash='||r.content_hash,
       CASE
         WHEN l.object_type<>r.object_type THEN 'Object type changed'
         WHEN l.access_result<>r.access_result THEN 'Access state changed'
         WHEN l.content_hash<>'' AND r.content_hash<>'' AND l.content_hash<>r.content_hash
           THEN 'Content hash changed'
         WHEN l.size<>r.size THEN 'Logical size changed'
         WHEN l.allocation_size<>r.allocation_size THEN 'Allocation size changed'
         WHEN abs(l.write_100ns-r.write_100ns)>ids.tolerance THEN 'Last-write time changed'
         WHEN abs(l.creation_100ns-r.creation_100ns)>ids.tolerance THEN 'Creation time changed'
         WHEN abs(l.access_100ns-r.access_100ns)>ids.access_tolerance THEN 'Last-access time changed'
         WHEN abs(l.change_100ns-r.change_100ns)>ids.tolerance THEN 'Filesystem change time changed'
         WHEN l.attributes<>r.attributes THEN 'File attributes changed'
         WHEN l.reparse_tag<>r.reparse_tag OR l.reparse_point<>r.reparse_point
           THEN 'Reparse metadata changed'
         WHEN l.hard_link_count<>r.hard_link_count AND l.hard_link_count>0 AND r.hard_link_count>0
           THEN 'Hard-link count changed'
         WHEN l.streams_json<>r.streams_json THEN 'Alternate data stream summary changed'
         WHEN l.case_sensitive_directory<>r.case_sensitive_directory
           THEN 'Directory case-sensitivity flag changed'
         WHEN l.enumeration_error<>r.enumeration_error THEN 'Enumeration error state changed'
         ELSE 'Captured metadata changed'
       END,1.0
FROM filesystem_objects l
JOIN ids
JOIN rhs.filesystem_objects r
  ON r.snapshot_id=ids.after_id AND r.relative_path=l.relative_path
WHERE l.snapshot_id=ids.before_id
  AND (
    l.object_type<>r.object_type OR l.size<>r.size OR
    l.allocation_size<>r.allocation_size OR
    abs(l.creation_100ns-r.creation_100ns)>ids.tolerance OR
    abs(l.access_100ns-r.access_100ns)>ids.access_tolerance OR
    abs(l.write_100ns-r.write_100ns)>ids.tolerance OR
    abs(l.change_100ns-r.change_100ns)>ids.tolerance OR
    l.attributes<>r.attributes OR l.reparse_point<>r.reparse_point OR
    l.reparse_tag<>r.reparse_tag OR
    (l.hard_link_count<>r.hard_link_count AND l.hard_link_count>0 AND r.hard_link_count>0) OR
    l.streams_json<>r.streams_json OR l.access_result<>r.access_result OR
    l.enumeration_error<>r.enumeration_error OR
    l.case_sensitive_directory<>r.case_sensitive_directory OR
    (l.content_hash<>'' AND r.content_hash<>'' AND l.content_hash<>r.content_hash)
  );
)SQL";

// An object of the first capture with nothing at its path in the second, unless it moved: its stable
// identity, or its size and SHA-256, is held by one object in each capture, at another path.
constexpr std::string_view kRemovedSql = R"SQL(
SELECT 'removed',l.relative_path,l.relative_path,'',
       'type='||l.object_type||'; size='||l.size||'; hash='||l.content_hash,
       '','Directory entry is absent from the after snapshot',1.0
FROM compare_ids ids
CROSS JOIN main.filesystem_objects l
LEFT JOIN rhs.filesystem_objects same_path
  ON same_path.snapshot_id=ids.after_id AND same_path.relative_path=l.relative_path
WHERE l.snapshot_id=ids.before_id
  AND same_path.id IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM left_ids lc
    CROSS JOIN right_ids rc
    CROSS JOIN rhs.filesystem_objects moved
    WHERE ids.detect_moves=1 AND l.file_id_hex<>''
      AND lc.volume_serial=l.volume_serial AND lc.file_id_hex=l.file_id_hex AND lc.count=1
      AND rc.volume_serial=l.volume_serial AND rc.file_id_hex=l.file_id_hex AND rc.count=1
      AND moved.id=rc.object_id
      AND moved.relative_path<>l.relative_path
  )
  AND NOT EXISTS (
    SELECT 1
    FROM left_hashes lc
    CROSS JOIN right_hashes rc
    CROSS JOIN rhs.filesystem_objects inferred
    WHERE ids.infer_moves=1 AND l.object_type='file' AND l.content_hash<>''
      AND lc.content_hash=l.content_hash AND lc.size=l.size AND lc.count=1
      AND rc.content_hash=l.content_hash AND rc.size=l.size AND rc.count=1
      AND inferred.id=rc.object_id
      AND inferred.relative_path<>l.relative_path
      AND (l.file_id_hex='' OR inferred.file_id_hex='' OR
           l.volume_serial<>inferred.volume_serial OR l.file_id_hex<>inferred.file_id_hex)
  );
)SQL";

// An object of the second capture with nothing at its path in the first, unless it moved there.
constexpr std::string_view kAddedSql = R"SQL(
SELECT 'added',r.relative_path,'',r.relative_path,'',
       'type='||r.object_type||'; size='||r.size||'; hash='||r.content_hash,
       'Directory entry is absent from the before snapshot',1.0
FROM compare_ids ids
CROSS JOIN rhs.filesystem_objects r
LEFT JOIN main.filesystem_objects same_path
  ON same_path.snapshot_id=ids.before_id AND same_path.relative_path=r.relative_path
WHERE r.snapshot_id=ids.after_id
  AND same_path.id IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM right_ids rc
    CROSS JOIN left_ids lc
    CROSS JOIN main.filesystem_objects moved
    WHERE ids.detect_moves=1 AND r.file_id_hex<>''
      AND rc.volume_serial=r.volume_serial AND rc.file_id_hex=r.file_id_hex AND rc.count=1
      AND lc.volume_serial=r.volume_serial AND lc.file_id_hex=r.file_id_hex AND lc.count=1
      AND moved.id=lc.object_id
      AND moved.relative_path<>r.relative_path
  )
  AND NOT EXISTS (
    SELECT 1
    FROM right_hashes rc
    CROSS JOIN left_hashes lc
    CROSS JOIN main.filesystem_objects inferred
    WHERE ids.infer_moves=1 AND r.object_type='file' AND r.content_hash<>''
      AND rc.content_hash=r.content_hash AND rc.size=r.size AND rc.count=1
      AND lc.content_hash=r.content_hash AND lc.size=r.size AND lc.count=1
      AND inferred.id=lc.object_id
      AND inferred.relative_path<>r.relative_path
      AND (inferred.file_id_hex='' OR r.file_id_hex='' OR
           inferred.volume_serial<>r.volume_serial OR inferred.file_id_hex<>r.file_id_hex)
  );
)SQL";

} // namespace

Result<std::uint64_t> compare_filesystem(const std::filesystem::path& before,
                                         std::string_view before_id,
                                         const std::filesystem::path& after,
                                         std::string_view after_id,
                                         const FilesystemCompareOptions& options,
                                         const DiffCallback& callback,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress) {
  const auto started = std::chrono::steady_clock::now();
  std::uint64_t stage = 0;
  const auto report = [&](const char* name, std::uint64_t found) {
    ++stage;
    if (!progress)
      return;
    ProgressEvent event;
    event.phase = "Comparing";
    event.current_scope = std::string(name) + ", " + std::to_string(found) +
                          (found == 1 ? " difference so far" : " differences so far");
    event.processed = stage;
    event.total = kCompareStages;
    event.elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    progress(event);
  };
  auto opened = Database::open(before, true);
  if (!opened.ok())
    return Result<std::uint64_t>::failure(opened.error());
  auto& database = opened.value();
  // Cancel interrupts the statement running: SQLite asks every 10,000 steps.
  sqlite3_progress_handler(
      database.native(), 10000,
      [](void* token) { return static_cast<const CancellationToken*>(token)->is_cancelled() ? 1 : 0; },
      const_cast<CancellationToken*>(&cancel));
  const auto failed = [&cancel](const Error& error) {
    if (!cancel.is_cancelled())
      return Result<std::uint64_t>::failure(error);
    Error cancelled = error;
    cancelled.message = "Cancelled";
    return Result<std::uint64_t>::failure(std::move(cancelled));
  };
  if (auto status = attach_filesystem_snapshot(database, after); !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  OwnFiles own;
  if (auto root = database.prepare("SELECT root_path FROM main.filesystem_scan_config WHERE snapshot_id=?;");
      root.ok() && root.value().bind(1, before_id).ok()) {
    if (auto row = root.value().step(); row.ok() && row.value()) {
      const std::filesystem::path folder = path_from_utf8(root.value().column_text(0));
      add_own_file(own, folder, before);
      add_own_file(own, folder, after);
    }
  }

  auto created = database.execute("CREATE TEMP TABLE compare_ids("
                                  "before_id TEXT,after_id TEXT,tolerance INTEGER,"
                                  "detect_moves INTEGER,infer_moves INTEGER,access_tolerance INTEGER);");
  if (!created.ok())
    return Result<std::uint64_t>::failure(created.error());
  auto insert = database.prepare("INSERT INTO compare_ids VALUES(?,?,?,?,?,?);");
  if (!insert.ok())
    return Result<std::uint64_t>::failure(insert.error());
  if (auto status = insert.value().bind(1, before_id); !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  if (auto status = insert.value().bind(2, after_id); !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  if (auto status = insert.value().bind(3, options.timestamp_tolerance_100ns); !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  if (auto status = insert.value().bind(4, static_cast<std::int64_t>(options.detect_moves ? 1 : 0));
      !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  if (auto status =
          insert.value().bind(5, static_cast<std::int64_t>(options.infer_moves_by_hash ? 1 : 0));
      !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  const std::int64_t access_tolerance =
      options.ignore_access_time ? std::numeric_limits<std::int64_t>::max() : options.timestamp_tolerance_100ns;
  if (auto status = insert.value().bind(6, access_tolerance); !status.ok()) {
    return Result<std::uint64_t>::failure(status.error());
  }
  auto inserted = insert.value().step();
  if (!inserted.ok())
    return Result<std::uint64_t>::failure(inserted.error());
  report("matching file identities", 0);
  if (auto keys = database.execute(kCompareKeysSql); !keys.ok())
    return failed(keys.error());

  std::uint64_t count = 0;
  report("moved and renamed", count);
  if (options.detect_moves) {
    if (auto status = stream_rows(database, kExactMovesSql, own, callback, count); !status.ok()) {
      return failed(status.error());
    }
  }
  report("moved with the same contents", count);
  if (options.infer_moves_by_hash) {
    if (auto status = stream_rows(database, kInferredMovesSql, own, callback, count); !status.ok()) {
      return failed(status.error());
    }
  }
  const std::pair<const char*, std::string_view> stages[] = {
      {"changed", kModifiedSql}, {"removed", kRemovedSql}, {"added", kAddedSql}};
  for (const auto& [name, sql] : stages) {
    report(name, count);
    if (auto status = stream_rows(database, sql, own, callback, count); !status.ok()) {
      return failed(status.error());
    }
  }
  sqlite3_progress_handler(database.native(), 0, nullptr, nullptr);
  return Result<std::uint64_t>::success(count);
}

} // namespace support_assist
