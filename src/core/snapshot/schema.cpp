#include "support_assist/snapshot_store.hpp"
#include "support_assist/version.hpp"
#include <string>
namespace support_assist {
namespace {
std::string_view base_schema_sql() {
  return R"SQL(
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS application_metadata(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS snapshots(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('creating','complete','cancelled','failed')),
  application_version TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  created_start_utc TEXT NOT NULL,
  created_end_utc TEXT,
  machine_name TEXT,
  os_name TEXT,
  os_version TEXT,
  architecture TEXT,
  timezone TEXT,
  user_scope TEXT,
  elevated INTEGER NOT NULL DEFAULT 0 CHECK(elevated IN (0,1)),
  enabled_privileges TEXT NOT NULL DEFAULT '',
  options_json TEXT NOT NULL DEFAULT '{}',
  source_filesystem TEXT NOT NULL DEFAULT '',
  object_count INTEGER NOT NULL DEFAULT 0,
  error_count INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE IF NOT EXISTS scan_errors(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  component TEXT NOT NULL,
  operation TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  native_code INTEGER NOT NULL DEFAULT 0,
  hresult INTEGER NOT NULL DEFAULT 0,
  sqlite_code INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL,
  severity TEXT NOT NULL,
  recoverable INTEGER NOT NULL DEFAULT 0,
  elevation_may_help INTEGER NOT NULL DEFAULT 0,
  skipped INTEGER NOT NULL DEFAULT 0,
  timestamp_utc TEXT NOT NULL,
  correlation_id TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS registry_scope_config(
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  hive TEXT NOT NULL,
  subkey TEXT NOT NULL,
  registry_view TEXT NOT NULL,
  PRIMARY KEY(snapshot_id,ordinal)
) STRICT;
CREATE TABLE IF NOT EXISTS filesystem_scan_config(
  snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
  root_path TEXT NOT NULL,
  follow_reparse_points INTEGER NOT NULL DEFAULT 0 CHECK(follow_reparse_points IN (0,1)),
  maximum_depth INTEGER NOT NULL,
  maximum_objects INTEGER NOT NULL,
  hash_mode TEXT NOT NULL,
  hash_size_limit INTEGER NOT NULL,
  capture_streams INTEGER NOT NULL DEFAULT 0 CHECK(capture_streams IN (0,1)),
  capture_file_identity INTEGER NOT NULL DEFAULT 1 CHECK(capture_file_identity IN (0,1)),
  hydrate_cloud_files INTEGER NOT NULL DEFAULT 0 CHECK(hydrate_cloud_files IN (0,1)),
  from_vss INTEGER NOT NULL DEFAULT 0 CHECK(from_vss IN (0,1))
 ) STRICT;
CREATE TABLE IF NOT EXISTS filesystem_scan_exclusions(
  snapshot_id TEXT NOT NULL REFERENCES filesystem_scan_config(snapshot_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  pattern TEXT NOT NULL,
  PRIMARY KEY(snapshot_id,ordinal)
) STRICT;
CREATE TABLE IF NOT EXISTS filesystem_scan_hash_extensions(
  snapshot_id TEXT NOT NULL REFERENCES filesystem_scan_config(snapshot_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  extension TEXT NOT NULL,
  PRIMARY KEY(snapshot_id,ordinal)
) STRICT;
CREATE TABLE IF NOT EXISTS change_journal_marks(
  snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
  volume TEXT NOT NULL,
  journal_id INTEGER NOT NULL,
  next_usn INTEGER NOT NULL,
  recorded_utc TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS registry_keys(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  hive TEXT NOT NULL,
  relative_path TEXT NOT NULL COLLATE WINDOWS_ORDINAL_NOCASE,
  registry_view TEXT NOT NULL,
  key_name TEXT NOT NULL,
  last_write_100ns INTEGER NOT NULL DEFAULT 0,
  class_name TEXT NOT NULL DEFAULT '',
  access_result INTEGER NOT NULL DEFAULT 0,
  enumeration_error TEXT NOT NULL DEFAULT '',
  UNIQUE(snapshot_id,hive,relative_path,registry_view)
) STRICT;
-- The UNIQUE constraint's index serves every lookup the compare makes by key or value; a second index on
-- the same columns held each path a third time.
CREATE TABLE IF NOT EXISTS registry_values(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  hive TEXT NOT NULL,
  relative_path TEXT NOT NULL COLLATE WINDOWS_ORDINAL_NOCASE,
  registry_view TEXT NOT NULL,
  value_name TEXT NOT NULL COLLATE WINDOWS_ORDINAL_NOCASE,
  is_default INTEGER NOT NULL DEFAULT 0 CHECK(is_default IN (0,1)),
  value_type INTEGER NOT NULL,
  raw_data BLOB NOT NULL,
  display_data TEXT NOT NULL DEFAULT '',
  data_hash TEXT NOT NULL DEFAULT '',
  display_truncated INTEGER NOT NULL DEFAULT 0 CHECK(display_truncated IN (0,1)),
  UNIQUE(snapshot_id,hive,relative_path,registry_view,value_name)
) STRICT;
CREATE TABLE IF NOT EXISTS filesystem_objects(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  relative_path TEXT NOT NULL,
  source_path TEXT NOT NULL,
  object_type TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  allocation_size INTEGER NOT NULL DEFAULT 0,
  attributes INTEGER NOT NULL DEFAULT 0,
  creation_100ns INTEGER NOT NULL DEFAULT 0,
  access_100ns INTEGER NOT NULL DEFAULT 0,
  write_100ns INTEGER NOT NULL DEFAULT 0,
  change_100ns INTEGER NOT NULL DEFAULT 0,
  volume_serial INTEGER NOT NULL DEFAULT 0,
  file_id_hex TEXT NOT NULL DEFAULT '',
  reparse_point INTEGER NOT NULL DEFAULT 0 CHECK(reparse_point IN (0,1)),
  reparse_tag INTEGER NOT NULL DEFAULT 0,
  hard_link_count INTEGER NOT NULL DEFAULT 0,
  streams_json TEXT NOT NULL DEFAULT '[]',
  access_result INTEGER NOT NULL DEFAULT 0,
  enumeration_error TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL DEFAULT '',
  hash_algorithm TEXT NOT NULL DEFAULT '',
  hash_status TEXT NOT NULL DEFAULT '',
  from_vss INTEGER NOT NULL DEFAULT 0 CHECK(from_vss IN (0,1)),
  case_sensitive_directory INTEGER NOT NULL DEFAULT 0 CHECK(case_sensitive_directory IN (0,1)),
  UNIQUE(snapshot_id,relative_path)
) STRICT;
CREATE INDEX IF NOT EXISTS idx_filesystem_identity ON filesystem_objects(snapshot_id,relative_path);
CREATE INDEX IF NOT EXISTS idx_filesystem_file_id ON filesystem_objects(snapshot_id,volume_serial,file_id_hex);
CREATE TABLE IF NOT EXISTS vss_sessions(
  id TEXT PRIMARY KEY,
  snapshot_set_id TEXT NOT NULL DEFAULT '',
  started_utc TEXT NOT NULL,
  completed_utc TEXT,
  state TEXT NOT NULL,
  requested_context INTEGER NOT NULL,
  backup_type INTEGER NOT NULL,
  component_mode INTEGER NOT NULL,
  writer_mode TEXT NOT NULL,
  hold_requested_seconds INTEGER NOT NULL DEFAULT 0,
  cleanup_result TEXT NOT NULL DEFAULT '',
  owner_pid INTEGER NOT NULL,
  owner_session_id INTEGER NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vss_snapshots(
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES vss_sessions(id) ON DELETE CASCADE,
  snapshot_id TEXT NOT NULL,
  snapshot_set_id TEXT NOT NULL,
  original_volume TEXT NOT NULL,
  device_object TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  attributes INTEGER NOT NULL,
  status TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS vss_writers(
  id INTEGER PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES vss_sessions(id) ON DELETE CASCADE,
  writer_class_id TEXT NOT NULL,
  writer_instance_id TEXT NOT NULL,
  writer_name TEXT NOT NULL,
  state INTEGER NOT NULL,
  failure_hresult INTEGER NOT NULL,
  selected INTEGER NOT NULL DEFAULT 0,
  metadata_json TEXT NOT NULL DEFAULT '{}'
) STRICT;
CREATE TABLE IF NOT EXISTS log_matches(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT REFERENCES snapshots(id) ON DELETE CASCADE,
  source_path TEXT NOT NULL,
  line_number INTEGER NOT NULL,
  severity TEXT NOT NULL DEFAULT '',
  timestamp_original TEXT NOT NULL DEFAULT '',
  timestamp_utc_ms INTEGER,
  timestamp_format TEXT NOT NULL DEFAULT '',
  timestamp_ambiguous INTEGER NOT NULL DEFAULT 0,
  timestamp_confidence REAL NOT NULL DEFAULT 0.0,
  context_before_json TEXT NOT NULL DEFAULT '[]',
  matching_line TEXT NOT NULL,
  context_after_json TEXT NOT NULL DEFAULT '[]',
  signature TEXT NOT NULL DEFAULT ''
) STRICT;
PRAGMA user_version=1;
)SQL";
}
} // namespace

// Comparisons stored in a capture file. CREATE TABLE IF NOT EXISTS lets a capture file made before
// they existed gain them when it is opened for writing.
std::string_view snapshot_comparison_schema_sql() {
  return R"SQL(
CREATE TABLE IF NOT EXISTS comparisons(
  id INTEGER PRIMARY KEY,
  snapshot_id TEXT NOT NULL,
  created_utc TEXT NOT NULL,
  kind TEXT NOT NULL,
  against TEXT NOT NULL DEFAULT 'now',
  against_snapshot_id TEXT NOT NULL DEFAULT '',
  added INTEGER NOT NULL DEFAULT 0,
  removed INTEGER NOT NULL DEFAULT 0,
  changed INTEGER NOT NULL DEFAULT 0,
  moved INTEGER NOT NULL DEFAULT 0,
  summary TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX IF NOT EXISTS idx_comparisons_snapshot ON comparisons(snapshot_id,created_utc,id);
CREATE TABLE IF NOT EXISTS comparison_rows(
  comparison_id INTEGER NOT NULL REFERENCES comparisons(id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  change TEXT NOT NULL,
  path TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(comparison_id,ordinal)
) STRICT;
)SQL";
}

// How each files capture was read. Added the same way as the comparisons.
std::string_view snapshot_capture_source_schema_sql() {
  return R"SQL(
CREATE TABLE IF NOT EXISTS capture_sources(
  snapshot_id TEXT PRIMARY KEY REFERENCES snapshots(id) ON DELETE CASCADE,
  source TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
) STRICT;
)SQL";
}

std::string_view snapshot_schema_sql() {
  static const std::string full = std::string(base_schema_sql()) + std::string(snapshot_comparison_schema_sql()) +
                                  std::string(snapshot_capture_source_schema_sql());
  return full;
}
} // namespace support_assist
