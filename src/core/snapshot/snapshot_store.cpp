#include "support_assist/snapshot_store.hpp"
#include "support_assist/time.hpp"
#include "support_assist/version.hpp"
#include <array>
namespace support_assist {
std::string to_string(SnapshotKind v) {
  switch (v) {
  case SnapshotKind::registry:
    return "registry";
  case SnapshotKind::filesystem:
    return "filesystem";
  case SnapshotKind::logs:
    return "logs";
  case SnapshotKind::combined:
    return "combined";
  }
  return "combined";
}
std::string to_string(SnapshotState v) {
  switch (v) {
  case SnapshotState::creating:
    return "creating";
  case SnapshotState::complete:
    return "complete";
  case SnapshotState::cancelled:
    return "cancelled";
  case SnapshotState::failed:
    return "failed";
  }
  return "failed";
}
std::string to_string(RegistryView v) {
  switch (v) {
  case RegistryView::native:
    return "native";
  case RegistryView::view32:
    return "32";
  case RegistryView::view64:
    return "64";
  case RegistryView::both:
    return "both";
  }
  return "native";
}
std::string to_string(ChangeKind v) {
  switch (v) {
  case ChangeKind::added:
    return "added";
  case ChangeKind::removed:
    return "removed";
  case ChangeKind::modified:
    return "modified";
  case ChangeKind::renamed:
    return "renamed";
  case ChangeKind::moved:
    return "moved";
  case ChangeKind::metadata_changed:
    return "metadata_changed";
  case ChangeKind::access_changed:
    return "access_changed";
  case ChangeKind::inferred_rename:
    return "inferred_rename";
  case ChangeKind::type_changed:
    return "type_changed";
  }
  return "modified";
}
Result<SnapshotStore> SnapshotStore::create(const std::filesystem::path& p) {
  auto d = Database::open(p, false);
  if (!d.ok())
    return Result<SnapshotStore>::failure(d.error());
  SnapshotStore s(std::move(d.value()), p);
  auto st = s.initialize_schema();
  if (!st.ok())
    return Result<SnapshotStore>::failure(st.error());
  return Result<SnapshotStore>::success(std::move(s));
}
Result<SnapshotStore> SnapshotStore::open(const std::filesystem::path& p, bool ro) {
  auto d = Database::open(p, ro);
  if (!d.ok())
    return Result<SnapshotStore>::failure(d.error());
  return Result<SnapshotStore>::success(SnapshotStore(std::move(d.value()), p));
}
Status SnapshotStore::initialize_schema() {
  auto s = db_.execute("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA "
                       "foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;");
  if (!s.ok())
    return s;
  s = db_.execute(snapshot_schema_sql());
  if (!s.ok())
    return s;
  auto q = db_.prepare("INSERT OR REPLACE INTO application_metadata(key,value) "
                       "VALUES('schema_version',?),('application_version',?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& st = q.value();
  if (auto x = st.bind(1, static_cast<std::int64_t>(kSnapshotSchemaVersion)); !x.ok())
    return x;
  if (auto x = st.bind(2, kVersion); !x.ok())
    return x;
  auto r = st.step();
  return r.ok() ? Status::success() : Status::failure(r.error());
}
Status SnapshotStore::begin_snapshot(const SnapshotMetadata& m) {
  auto q = db_.prepare(
      "INSERT INTO "
      "snapshots(id,kind,state,application_version,schema_version,created_start_utc,machine_name,"
      "os_name,os_version,architecture,timezone,user_scope,elevated,enabled_privileges,options_"
      "json,source_filesystem) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& s = q.value();
  int i = 1;
  for (auto v : {m.id, to_string(m.kind), to_string(m.state), m.application_version}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, static_cast<std::int64_t>(m.schema_version)); !x.ok())
    return x;
  for (auto v : {m.created_start_utc,
                 m.machine_name,
                 m.os_name,
                 m.os_version,
                 m.architecture,
                 m.timezone,
                 m.user_scope}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, static_cast<std::int64_t>(m.elevated ? 1 : 0)); !x.ok())
    return x;
  for (auto v : {m.enabled_privileges, m.options_json, m.source_filesystem}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  auto r = s.step();
  return r.ok() ? Status::success() : Status::failure(r.error());
}
Status SnapshotStore::finish_snapshot(std::string_view id,
                                      SnapshotState state,
                                      std::uint64_t objects,
                                      std::uint64_t errors) {
  {
    auto prepared = db_.prepare(
        "UPDATE snapshots SET state=?,created_end_utc=?,object_count=?,error_count=? WHERE id=?;");
    if (!prepared.ok())
      return Status::failure(prepared.error());
    auto& statement = prepared.value();
    if (auto status = statement.bind(1, to_string(state)); !status.ok())
      return status;
    if (auto status = statement.bind(2, utc_now_iso8601()); !status.ok())
      return status;
    if (auto status = statement.bind(3, static_cast<std::int64_t>(objects)); !status.ok())
      return status;
    if (auto status = statement.bind(4, static_cast<std::int64_t>(errors)); !status.ok())
      return status;
    if (auto status = statement.bind(5, id); !status.ok())
      return status;
    auto row = statement.step();
    if (!row.ok())
      return Status::failure(row.error());
  }

  // Scans use WAL for write throughput. A completed baseline must remain a
  // self-contained file that can be copied without SQLite sidecars.
  if (auto status = db_.execute("PRAGMA wal_checkpoint(TRUNCATE);"); !status.ok())
    return status;
  if (auto status = db_.execute("PRAGMA journal_mode=DELETE;"); !status.ok())
    return status;
  // Rows arrive in the order the scan finds them, which leaves the indexes' pages part empty; written
  // again in order, a registry capture takes about two thirds of the room. The data is unchanged.
  if (state == SnapshotState::complete)
    return db_.execute("VACUUM;");
  return Status::success();
}
Status SnapshotStore::add_error(std::string_view sid, const Error& e) {
  auto q = db_.prepare("INSERT INTO "
                       "scan_errors(snapshot_id,component,operation,source,native_code,hresult,"
                       "sqlite_code,message,severity,recoverable,elevation_may_help,skipped,"
                       "timestamp_utc,correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& s = q.value();
  int i = 1;
  for (auto v : {sid,
                 std::string_view(e.component),
                 std::string_view(e.operation),
                 std::string_view(e.source)}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  for (auto v : {e.native_code, e.hresult, static_cast<std::int64_t>(e.sqlite_code)}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, e.message); !x.ok())
    return x;
  if (auto x = s.bind(i++, to_string(e.severity)); !x.ok())
    return x;
  for (auto v : {e.recoverable, e.elevation_may_help, e.skipped}) {
    auto x = s.bind(i++, static_cast<std::int64_t>(v ? 1 : 0));
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, e.timestamp_utc); !x.ok())
    return x;
  if (auto x = s.bind(i++, e.correlation_id); !x.ok())
    return x;
  auto r = s.step();
  return r.ok() ? Status::success() : Status::failure(r.error());
}
Status SnapshotStore::add_registry_scope_config(const RegistryScopeConfig& config) {
  auto prepared = db_.prepare(
      "INSERT OR REPLACE INTO registry_scope_config(snapshot_id,ordinal,hive,subkey,registry_view) "
      "VALUES(?,?,?,?,?);");
  if (!prepared.ok())
    return Status::failure(prepared.error());
  auto& statement = prepared.value();
  if (auto status = statement.bind(1, config.snapshot_id); !status.ok())
    return status;
  if (auto status = statement.bind(2, static_cast<std::int64_t>(config.ordinal)); !status.ok())
    return status;
  if (auto status = statement.bind(3, config.hive); !status.ok())
    return status;
  if (auto status = statement.bind(4, config.subkey); !status.ok())
    return status;
  if (auto status = statement.bind(5, to_string(config.view)); !status.ok())
    return status;
  auto row = statement.step();
  return row.ok() ? Status::success() : Status::failure(row.error());
}

Status SnapshotStore::set_filesystem_scan_config(const FilesystemScanConfig& config) {
  auto prepared =
      db_.prepare("INSERT OR REPLACE INTO "
                  "filesystem_scan_config(snapshot_id,root_path,follow_reparse_points,maximum_"
                  "depth,maximum_objects,hash_mode,hash_size_limit,capture_streams,capture_file_"
                  "identity,hydrate_cloud_files,from_vss) VALUES(?,?,?,?,?,?,?,?,?,?,?);");
  if (!prepared.ok())
    return Status::failure(prepared.error());
  auto& statement = prepared.value();
  int index = 1;
  if (auto status = statement.bind(index++, config.snapshot_id); !status.ok())
    return status;
  if (auto status = statement.bind(index++, config.root_path); !status.ok())
    return status;
  if (auto status =
          statement.bind(index++, static_cast<std::int64_t>(config.follow_reparse_points));
      !status.ok())
    return status;
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(config.maximum_depth));
      !status.ok())
    return status;
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(config.maximum_objects));
      !status.ok())
    return status;
  if (auto status = statement.bind(index++, config.hash_mode); !status.ok())
    return status;
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(config.hash_size_limit));
      !status.ok())
    return status;
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(config.capture_streams));
      !status.ok())
    return status;
  if (auto status =
          statement.bind(index++, static_cast<std::int64_t>(config.capture_file_identity));
      !status.ok())
    return status;
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(config.hydrate_cloud_files));
      !status.ok())
    return status;
  // The v0.1 schema contained this provenance flag. v0.2 keeps the column for
  // file compatibility but baseline capture is always a direct scan; VSS is a
  // separate diagnostic laboratory.
  if (auto status = statement.bind(index++, static_cast<std::int64_t>(0)); !status.ok())
    return status;
  auto row = statement.step();
  if (!row.ok())
    return Status::failure(row.error());
  for (const auto sql : {"DELETE FROM filesystem_scan_exclusions WHERE snapshot_id=?;",
                         "DELETE FROM filesystem_scan_hash_extensions WHERE snapshot_id=?;"}) {
    auto deletion = db_.prepare(sql);
    if (!deletion.ok())
      return Status::failure(deletion.error());
    if (auto status = deletion.value().bind(1, config.snapshot_id); !status.ok())
      return status;
    auto deleted = deletion.value().step();
    if (!deleted.ok())
      return Status::failure(deleted.error());
  }
  auto exclusion = db_.prepare(
      "INSERT INTO filesystem_scan_exclusions(snapshot_id,ordinal,pattern) VALUES(?,?,?);");
  if (!exclusion.ok())
    return Status::failure(exclusion.error());
  for (std::size_t ordinal = 0; ordinal < config.exclusions.size(); ++ordinal) {
    if (auto status = exclusion.value().bind(1, config.snapshot_id); !status.ok())
      return status;
    if (auto status = exclusion.value().bind(2, static_cast<std::int64_t>(ordinal)); !status.ok())
      return status;
    if (auto status = exclusion.value().bind(3, config.exclusions[ordinal]); !status.ok())
      return status;
    auto inserted = exclusion.value().step();
    if (!inserted.ok())
      return Status::failure(inserted.error());
    if (auto status = exclusion.value().reset(); !status.ok())
      return status;
  }
  auto extension = db_.prepare(
      "INSERT INTO filesystem_scan_hash_extensions(snapshot_id,ordinal,extension) VALUES(?,?,?);");
  if (!extension.ok())
    return Status::failure(extension.error());
  for (std::size_t ordinal = 0; ordinal < config.hash_extensions.size(); ++ordinal) {
    if (auto status = extension.value().bind(1, config.snapshot_id); !status.ok())
      return status;
    if (auto status = extension.value().bind(2, static_cast<std::int64_t>(ordinal)); !status.ok())
      return status;
    if (auto status = extension.value().bind(3, config.hash_extensions[ordinal]); !status.ok())
      return status;
    auto inserted = extension.value().step();
    if (!inserted.ok())
      return Status::failure(inserted.error());
    if (auto status = extension.value().reset(); !status.ok())
      return status;
  }
  return Status::success();
}

Result<std::vector<RegistryScopeConfig>>
SnapshotStore::registry_scope_configs(std::string_view snapshot_id) {
  auto prepared = db_.prepare("SELECT ordinal,hive,subkey,registry_view FROM registry_scope_config "
                              "WHERE snapshot_id=? ORDER BY ordinal;");
  if (!prepared.ok())
    return Result<std::vector<RegistryScopeConfig>>::failure(prepared.error());
  if (auto status = prepared.value().bind(1, snapshot_id); !status.ok()) {
    return Result<std::vector<RegistryScopeConfig>>::failure(status.error());
  }
  std::vector<RegistryScopeConfig> output;
  for (;;) {
    auto row = prepared.value().step();
    if (!row.ok())
      return Result<std::vector<RegistryScopeConfig>>::failure(row.error());
    if (!row.value())
      break;
    RegistryScopeConfig config;
    config.snapshot_id = std::string(snapshot_id);
    config.ordinal = static_cast<std::uint32_t>(prepared.value().column_int64(0));
    config.hive = prepared.value().column_text(1);
    config.subkey = prepared.value().column_text(2);
    const auto view = prepared.value().column_text(3);
    config.view = view == "32"       ? RegistryView::view32
                  : view == "64"     ? RegistryView::view64
                  : view == "native" ? RegistryView::native
                                     : RegistryView::both;
    output.push_back(std::move(config));
  }
  if (output.empty()) {
    Error error;
    error.component = "SnapshotStore";
    error.operation = "load Registry scan configuration";
    error.source = std::string(snapshot_id);
    error.message = "The snapshot does not contain normalized Registry scope configuration";
    return Result<std::vector<RegistryScopeConfig>>::failure(std::move(error));
  }
  return Result<std::vector<RegistryScopeConfig>>::success(std::move(output));
}

Result<FilesystemScanConfig> SnapshotStore::filesystem_scan_config(std::string_view snapshot_id) {
  auto prepared =
      db_.prepare("SELECT "
                  "root_path,follow_reparse_points,maximum_depth,maximum_objects,hash_mode,hash_"
                  "size_limit,capture_streams,capture_file_identity,hydrate_cloud_files,from_vss "
                  "FROM filesystem_scan_config WHERE snapshot_id=?;");
  if (!prepared.ok())
    return Result<FilesystemScanConfig>::failure(prepared.error());
  if (auto status = prepared.value().bind(1, snapshot_id); !status.ok()) {
    return Result<FilesystemScanConfig>::failure(status.error());
  }
  auto row = prepared.value().step();
  if (!row.ok())
    return Result<FilesystemScanConfig>::failure(row.error());
  if (!row.value()) {
    Error error;
    error.component = "SnapshotStore";
    error.operation = "load filesystem scan configuration";
    error.source = std::string(snapshot_id);
    error.message = "The snapshot does not contain normalized filesystem scan configuration";
    return Result<FilesystemScanConfig>::failure(std::move(error));
  }
  FilesystemScanConfig config;
  config.snapshot_id = std::string(snapshot_id);
  config.root_path = prepared.value().column_text(0);
  config.follow_reparse_points = prepared.value().column_int(1) != 0;
  config.maximum_depth = static_cast<std::uint32_t>(prepared.value().column_int64(2));
  config.maximum_objects = static_cast<std::uint64_t>(prepared.value().column_int64(3));
  config.hash_mode = prepared.value().column_text(4);
  config.hash_size_limit = static_cast<std::uint64_t>(prepared.value().column_int64(5));
  config.capture_streams = prepared.value().column_int(6) != 0;
  config.capture_file_identity = prepared.value().column_int(7) != 0;
  config.hydrate_cloud_files = prepared.value().column_int(8) != 0;
  static_cast<void>(prepared.value().column_int(9)); // legacy v0.1 column
  auto load_values = [&](std::string_view sql, std::vector<std::string>& values) -> Status {
    auto query = db_.prepare(sql);
    if (!query.ok())
      return Status::failure(query.error());
    if (auto status = query.value().bind(1, snapshot_id); !status.ok())
      return status;
    for (;;) {
      auto value_row = query.value().step();
      if (!value_row.ok())
        return Status::failure(value_row.error());
      if (!value_row.value())
        break;
      values.push_back(query.value().column_text(0));
    }
    return Status::success();
  };
  if (auto status = load_values(
          "SELECT pattern FROM filesystem_scan_exclusions WHERE snapshot_id=? ORDER BY ordinal;",
          config.exclusions);
      !status.ok()) {
    return Result<FilesystemScanConfig>::failure(status.error());
  }
  if (auto status = load_values("SELECT extension FROM filesystem_scan_hash_extensions WHERE "
                                "snapshot_id=? ORDER BY ordinal;",
                                config.hash_extensions);
      !status.ok()) {
    return Result<FilesystemScanConfig>::failure(status.error());
  }
  return Result<FilesystemScanConfig>::success(std::move(config));
}

Status SnapshotStore::add_registry_key(const RegistryKeyRecord& r) {
  auto q =
      db_.prepare("INSERT OR REPLACE INTO "
                  "registry_keys(snapshot_id,hive,relative_path,registry_view,key_name,last_write_"
                  "100ns,class_name,access_result,enumeration_error) VALUES(?,?,?,?,?,?,?,?,?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& s = q.value();
  int i = 1;
  for (auto v : {r.snapshot_id, r.hive, r.relative_path, to_string(r.view), r.key_name}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, r.last_write_100ns); !x.ok())
    return x;
  if (auto x = s.bind(i++, r.class_name); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.access_result)); !x.ok())
    return x;
  if (auto x = s.bind(i++, r.enumeration_error); !x.ok())
    return x;
  auto z = s.step();
  return z.ok() ? Status::success() : Status::failure(z.error());
}
Status SnapshotStore::add_registry_value(const RegistryValueRecord& r) {
  auto q = db_.prepare(
      "INSERT OR REPLACE INTO "
      "registry_values(snapshot_id,hive,relative_path,registry_view,value_name,is_default,value_"
      "type,raw_data,display_data,data_hash,display_truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& s = q.value();
  int i = 1;
  for (auto v : {r.snapshot_id, r.hive, r.relative_path, to_string(r.view), r.value_name}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.is_default ? 1 : 0)); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.type)); !x.ok())
    return x;
  if (auto x = s.bind(i++, std::span<const std::byte>(r.raw_data.data(), r.raw_data.size()));
      !x.ok())
    return x;
  if (auto x = s.bind(i++, r.display_data); !x.ok())
    return x;
  if (auto x = s.bind(i++, r.data_hash); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.display_truncated ? 1 : 0)); !x.ok())
    return x;
  auto z = s.step();
  return z.ok() ? Status::success() : Status::failure(z.error());
}
Status SnapshotStore::add_filesystem_object(const FilesystemRecord& r) {
  auto q = db_.prepare(
      "INSERT OR REPLACE INTO "
      "filesystem_objects(snapshot_id,relative_path,source_path,object_type,size,allocation_size,"
      "attributes,creation_100ns,access_100ns,write_100ns,change_100ns,volume_serial,file_id_hex,"
      "reparse_point,reparse_tag,hard_link_count,streams_json,access_result,enumeration_error,"
      "content_hash,hash_algorithm,hash_status,from_vss,case_sensitive_directory) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
  if (!q.ok())
    return Status::failure(q.error());
  auto& s = q.value();
  int i = 1;
  for (auto v : {r.snapshot_id, r.relative_path, r.source_path, r.object_type}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  for (auto v : {r.size,
                 r.allocation_size,
                 static_cast<std::uint64_t>(r.attributes),
                 static_cast<std::uint64_t>(r.creation_100ns),
                 static_cast<std::uint64_t>(r.access_100ns),
                 static_cast<std::uint64_t>(r.write_100ns),
                 static_cast<std::uint64_t>(r.change_100ns),
                 r.volume_serial}) {
    auto x = s.bind(i++, static_cast<std::int64_t>(v));
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, r.file_id_hex); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.reparse_point ? 1 : 0)); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.reparse_tag)); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.hard_link_count)); !x.ok())
    return x;
  for (auto v : {r.streams_json}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.access_result)); !x.ok())
    return x;
  for (auto v : {r.enumeration_error, r.content_hash, r.hash_algorithm, r.hash_status}) {
    auto x = s.bind(i++, v);
    if (!x.ok())
      return x;
  }
  if (auto x = s.bind(i++, static_cast<std::int64_t>(0)); !x.ok())
    return x;
  if (auto x = s.bind(i++, static_cast<std::int64_t>(r.case_sensitive_directory ? 1 : 0)); !x.ok())
    return x;
  auto z = s.step();
  return z.ok() ? Status::success() : Status::failure(z.error());
}
// The newest capture that completed: a file collects every attempt, and a cancelled or failed one
// has nothing whole to compare.
Result<std::string> SnapshotStore::latest_complete_snapshot_id() {
  auto q = db_.prepare("SELECT id FROM snapshots WHERE state='complete' ORDER BY created_start_utc DESC LIMIT 1;");
  if (!q.ok())
    return Result<std::string>::failure(q.error());
  auto r = q.value().step();
  if (!r.ok())
    return Result<std::string>::failure(r.error());
  if (!r.value()) {
    Error e;
    e.component = "SnapshotStore";
    e.operation = "latest_complete_snapshot_id";
    e.message = "No completed capture in this file: every capture in it was cancelled or failed";
    return Result<std::string>::failure(std::move(e));
  }
  return Result<std::string>::success(q.value().column_text(0));
}
Result<std::string> SnapshotStore::latest_complete_snapshot_id(SnapshotKind kind) {
  auto q = db_.prepare("SELECT id FROM snapshots WHERE state='complete' AND kind=? "
                       "ORDER BY created_start_utc DESC LIMIT 1;");
  if (!q.ok())
    return Result<std::string>::failure(q.error());
  const std::string kind_text = to_string(kind);
  q.value().bind(1, std::string_view(kind_text));
  auto r = q.value().step();
  if (!r.ok())
    return Result<std::string>::failure(r.error());
  if (!r.value()) {
    Error e;
    e.component = "SnapshotStore";
    e.operation = "latest_complete_snapshot_id";
    e.message = "No completed " + kind_text + " capture in this file";
    return Result<std::string>::failure(std::move(e));
  }
  return Result<std::string>::success(q.value().column_text(0));
}
Result<std::vector<std::string>> SnapshotStore::elevation_skipped_sources(std::string_view snapshot_id) {
  auto q = db_.prepare("SELECT source FROM scan_errors WHERE snapshot_id=? AND elevation_may_help=1 ORDER BY id;");
  if (!q.ok())
    return Result<std::vector<std::string>>::failure(q.error());
  q.value().bind(1, snapshot_id);
  std::vector<std::string> sources;
  for (;;) {
    auto r = q.value().step();
    if (!r.ok())
      return Result<std::vector<std::string>>::failure(r.error());
    if (!r.value())
      break;
    sources.push_back(q.value().column_text(0));
  }
  return Result<std::vector<std::string>>::success(std::move(sources));
}
Status SnapshotStore::visit_filesystem_objects(std::string_view snapshot_id,
                                               const std::function<bool(const CapturedObject&)>& visit) {
  auto q = db_.prepare("SELECT relative_path,object_type,size,write_100ns,content_hash,access_result "
                       "FROM filesystem_objects WHERE snapshot_id=? ORDER BY relative_path;");
  if (!q.ok())
    return Status::failure(q.error());
  if (auto bound = q.value().bind(1, snapshot_id); !bound.ok())
    return bound;
  for (;;) {
    auto r = q.value().step();
    if (!r.ok())
      return Status::failure(r.error());
    if (!r.value())
      break;
    CapturedObject object;
    object.relative_path = q.value().column_text(0);
    object.object_type = q.value().column_text(1);
    object.size = static_cast<std::uint64_t>(q.value().column_int64(2));
    object.write_100ns = q.value().column_int64(3);
    object.content_hash = q.value().column_text(4);
    object.access_result = static_cast<int>(q.value().column_int64(5));
    if (!visit(object))
      break;
  }
  return Status::success();
}
Status SnapshotStore::visit_registry_items(std::string_view snapshot_id,
                                           const std::function<bool(const CapturedRegistryItem&)>& visit) {
  // Each key, then its values, in path order: the default value first, then the rest by name.
  auto q = db_.prepare(
      "SELECT hive,relative_path,registry_view,0,'','',last_write_100ns FROM registry_keys WHERE snapshot_id=?1 "
      "UNION ALL "
      "SELECT hive,relative_path,registry_view,1,value_name,display_data,0 FROM registry_values WHERE snapshot_id=?1 "
      "ORDER BY 1,3,2,4,5;");
  if (!q.ok())
    return Status::failure(q.error());
  if (auto bound = q.value().bind(1, snapshot_id); !bound.ok())
    return bound;
  for (;;) {
    auto r = q.value().step();
    if (!r.ok())
      return Status::failure(r.error());
    if (!r.value())
      break;
    CapturedRegistryItem item;
    item.hive = q.value().column_text(0);
    item.relative_path = q.value().column_text(1);
    item.registry_view = q.value().column_text(2);
    item.is_value = q.value().column_int64(3) != 0;
    item.value_name = q.value().column_text(4);
    item.data = q.value().column_text(5);
    item.last_write_100ns = q.value().column_int64(6);
    if (!visit(item))
      break;
  }
  return Status::success();
}
Status SnapshotStore::set_change_journal_mark(std::string_view snapshot_id, const ChangeJournalMark& mark) {
  auto prepared = db_.prepare("INSERT OR REPLACE INTO "
                              "change_journal_marks(snapshot_id,volume,journal_id,next_usn,recorded_utc) "
                              "VALUES(?,?,?,?,?);");
  if (!prepared.ok())
    return Status::failure(prepared.error());
  auto& statement = prepared.value();
  if (auto status = statement.bind(1, snapshot_id); !status.ok())
    return status;
  if (auto status = statement.bind(2, mark.volume); !status.ok())
    return status;
  // The journal id is an unsigned 64-bit value; SQLite keeps the same 64 bits as a signed integer.
  if (auto status = statement.bind(3, static_cast<std::int64_t>(mark.journal_id)); !status.ok())
    return status;
  if (auto status = statement.bind(4, mark.next_usn); !status.ok())
    return status;
  if (auto status = statement.bind(5, mark.recorded_utc); !status.ok())
    return status;
  auto row = statement.step();
  return row.ok() ? Status::success() : Status::failure(row.error());
}

Status SnapshotStore::set_capture_source(std::string_view snapshot_id, const CaptureSource& source) {
  if (auto status = db_.execute(snapshot_capture_source_schema_sql()); !status.ok())
    return status;
  auto prepared = db_.prepare("INSERT OR REPLACE INTO capture_sources(snapshot_id,source,detail) VALUES(?,?,?);");
  if (!prepared.ok())
    return Status::failure(prepared.error());
  auto& statement = prepared.value();
  if (auto status = statement.bind(1, snapshot_id); !status.ok())
    return status;
  if (auto status = statement.bind(2, source.source); !status.ok())
    return status;
  if (auto status = statement.bind(3, source.detail); !status.ok())
    return status;
  auto row = statement.step();
  return row.ok() ? Status::success() : Status::failure(row.error());
}

Result<std::optional<CaptureSource>> SnapshotStore::capture_source(std::string_view snapshot_id) {
  using SourceResult = Result<std::optional<CaptureSource>>;
  auto exists = db_.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='capture_sources';");
  if (!exists.ok())
    return SourceResult::failure(exists.error());
  auto present = exists.value().step();
  if (!present.ok())
    return SourceResult::failure(present.error());
  if (!present.value())
    return SourceResult::success(std::nullopt);
  auto prepared = db_.prepare("SELECT source,detail FROM capture_sources WHERE snapshot_id=?;");
  if (!prepared.ok())
    return SourceResult::failure(prepared.error());
  if (auto status = prepared.value().bind(1, snapshot_id); !status.ok())
    return SourceResult::failure(status.error());
  auto row = prepared.value().step();
  if (!row.ok())
    return SourceResult::failure(row.error());
  if (!row.value())
    return SourceResult::success(std::nullopt);
  CaptureSource source;
  source.source = prepared.value().column_text(0);
  source.detail = prepared.value().column_text(1);
  return SourceResult::success(std::move(source));
}

Result<std::optional<ChangeJournalMark>> SnapshotStore::change_journal_mark(std::string_view snapshot_id) {
  using MarkResult = Result<std::optional<ChangeJournalMark>>;
  // A capture file made before marks existed has no such table.
  auto exists = db_.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='change_journal_marks';");
  if (!exists.ok())
    return MarkResult::failure(exists.error());
  auto present = exists.value().step();
  if (!present.ok())
    return MarkResult::failure(present.error());
  if (!present.value())
    return MarkResult::success(std::nullopt);

  auto prepared = db_.prepare("SELECT volume,journal_id,next_usn,recorded_utc FROM change_journal_marks "
                              "WHERE snapshot_id=?;");
  if (!prepared.ok())
    return MarkResult::failure(prepared.error());
  if (auto status = prepared.value().bind(1, snapshot_id); !status.ok())
    return MarkResult::failure(status.error());
  auto row = prepared.value().step();
  if (!row.ok())
    return MarkResult::failure(row.error());
  if (!row.value())
    return MarkResult::success(std::nullopt);
  ChangeJournalMark mark;
  mark.volume = prepared.value().column_text(0);
  mark.journal_id = static_cast<std::uint64_t>(prepared.value().column_int64(1));
  mark.next_usn = prepared.value().column_int64(2);
  mark.recorded_utc = prepared.value().column_text(3);
  return MarkResult::success(std::move(mark));
}

Result<SnapshotMetadata> SnapshotStore::metadata(std::string_view id) {
  auto q = db_.prepare("SELECT "
                       "id,kind,state,application_version,schema_version,created_start_utc,"
                       "COALESCE(created_end_utc,''),machine_name,os_name,os_version,architecture,"
                       "timezone,user_scope,elevated,enabled_privileges,options_json,source_"
                       "filesystem,object_count,error_count FROM snapshots WHERE id=?;");
  if (!q.ok())
    return Result<SnapshotMetadata>::failure(q.error());
  q.value().bind(1, id);
  auto r = q.value().step();
  if (!r.ok())
    return Result<SnapshotMetadata>::failure(r.error());
  if (!r.value()) {
    Error e;
    e.component = "SnapshotStore";
    e.operation = "metadata";
    e.message = "Snapshot not found";
    return Result<SnapshotMetadata>::failure(std::move(e));
  }
  SnapshotMetadata m;
  auto& s = q.value();
  m.id = s.column_text(0);
  auto kind = s.column_text(1);
  m.kind = kind == "registry"     ? SnapshotKind::registry
           : kind == "filesystem" ? SnapshotKind::filesystem
           : kind == "logs"       ? SnapshotKind::logs
                                  : SnapshotKind::combined;
  auto state = s.column_text(2);
  m.state = state == "complete"    ? SnapshotState::complete
            : state == "cancelled" ? SnapshotState::cancelled
            : state == "failed"    ? SnapshotState::failed
                                   : SnapshotState::creating;
  m.application_version = s.column_text(3);
  m.schema_version = s.column_int(4);
  m.created_start_utc = s.column_text(5);
  m.created_end_utc = s.column_text(6);
  m.machine_name = s.column_text(7);
  m.os_name = s.column_text(8);
  m.os_version = s.column_text(9);
  m.architecture = s.column_text(10);
  m.timezone = s.column_text(11);
  m.user_scope = s.column_text(12);
  m.elevated = s.column_int(13) != 0;
  m.enabled_privileges = s.column_text(14);
  m.options_json = s.column_text(15);
  m.source_filesystem = s.column_text(16);
  m.object_count = static_cast<std::uint64_t>(s.column_int64(17));
  m.error_count = static_cast<std::uint64_t>(s.column_int64(18));
  return Result<SnapshotMetadata>::success(std::move(m));
}
Status SnapshotStore::validate() {
  auto q = db_.prepare("PRAGMA quick_check;");
  if (!q.ok())
    return Status::failure(q.error());
  auto r = q.value().step();
  if (!r.ok())
    return Status::failure(r.error());
  if (!r.value() || q.value().column_text(0) != "ok") {
    Error e;
    e.component = "SnapshotStore";
    e.operation = "quick_check";
    e.message = r.value() ? q.value().column_text(0) : "No result";
    return Status::failure(std::move(e));
  }
  auto uv = db_.prepare("PRAGMA user_version;");
  if (!uv.ok())
    return Status::failure(uv.error());
  auto x = uv.value().step();
  if (!x.ok() || !x.value() || uv.value().column_int(0) != kSnapshotSchemaVersion) {
    Error e;
    e.component = "SnapshotStore";
    e.operation = "schema version";
    e.message = "Unsupported snapshot schema";
    return Status::failure(std::move(e));
  }
  return Status::success();
}

namespace {
std::string grouped_count(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (int index = static_cast<int>(digits.size()) - 3; index > 0; index -= 3)
    digits.insert(static_cast<std::size_t>(index), ",");
  return digits;
}
// A capture file made before compares were kept has no such table.
Result<bool> comparison_tables_present(Database& db) {
  auto exists = db.prepare("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND "
                           "name IN ('comparisons','comparison_rows');");
  if (!exists.ok())
    return Result<bool>::failure(exists.error());
  auto row = exists.value().step();
  if (!row.ok())
    return Result<bool>::failure(row.error());
  return Result<bool>::success(row.value() && exists.value().column_int64(0) == 2);
}
Error comparison_error(std::string operation, std::string message) {
  Error e;
  e.component = "SnapshotStore";
  e.operation = std::move(operation);
  e.message = std::move(message);
  e.timestamp_utc = utc_now_iso8601();
  return e;
}
} // namespace

void StoredComparisonCounts::count(ChangeKind kind) noexcept {
  switch (kind) {
  case ChangeKind::added:
    ++added;
    break;
  case ChangeKind::removed:
    ++removed;
    break;
  case ChangeKind::moved:
  case ChangeKind::renamed:
  case ChangeKind::inferred_rename:
    ++moved;
    break;
  default:
    ++changed;
    break;
  }
}
std::string comparison_counts_text(const StoredComparisonCounts& counts) {
  if (counts.total() == 0)
    return "no differences.";
  return grouped_count(counts.added) + " added, " + grouped_count(counts.removed) + " removed, " +
         grouped_count(counts.changed) + " changed, " + grouped_count(counts.moved) + " moved or renamed.";
}
std::string comparison_change_words(ChangeKind kind) {
  switch (kind) {
  case ChangeKind::added:
    return "Added";
  case ChangeKind::removed:
    return "Removed";
  case ChangeKind::modified:
    return "Changed";
  case ChangeKind::renamed:
    return "Renamed";
  case ChangeKind::moved:
    return "Moved";
  case ChangeKind::metadata_changed:
    return "Times or attributes";
  case ChangeKind::access_changed:
    return "Access";
  case ChangeKind::inferred_rename:
    return "Renamed (same content)";
  case ChangeKind::type_changed:
    return "Type";
  }
  return "Changed";
}
StoredComparisonRow stored_comparison_row(const DiffRecord& record) {
  StoredComparisonRow row;
  row.change = comparison_change_words(record.kind);
  row.path = record.identity;
  row.reason = record.reason;
  row.detail = record.before_summary;
  if (!record.before_summary.empty() || !record.after_summary.empty())
    row.detail += " -> ";
  row.detail += record.after_summary;
  return row;
}

Result<std::int64_t> SnapshotStore::begin_comparison(const StoredComparison& header) {
  using IdResult = Result<std::int64_t>;
  if (header.kind != "filesystem" && header.kind != "registry") {
    return IdResult::failure(
        comparison_error("begin comparison", "A comparison is of kind filesystem or registry."));
  }
  if (auto status = db_.execute(snapshot_comparison_schema_sql()); !status.ok())
    return IdResult::failure(status.error());
  {
    auto insert = db_.prepare("INSERT INTO comparisons(snapshot_id,created_utc,kind,against,"
                              "against_snapshot_id,added,removed,changed,moved,summary) "
                              "VALUES(?,?,?,?,?,?,?,?,?,?);");
    if (!insert.ok())
      return IdResult::failure(insert.error());
    auto& statement = insert.value();
    const std::string created = header.created_utc.empty() ? utc_now_iso8601() : header.created_utc;
    const std::string against = header.against.empty() ? std::string("now") : header.against;
    const std::array<std::string_view, 5> text_values{
        header.snapshot_id, created, header.kind, against, header.against_snapshot_id};
    int index = 1;
    for (const std::string_view text : text_values) {
      if (auto status = statement.bind(index++, text); !status.ok())
        return IdResult::failure(status.error());
    }
    for (const std::uint64_t value : {header.added, header.removed, header.changed, header.moved}) {
      if (auto status = statement.bind(index++, static_cast<std::int64_t>(value)); !status.ok())
        return IdResult::failure(status.error());
    }
    if (auto status = statement.bind(index, header.summary); !status.ok())
      return IdResult::failure(status.error());
    auto stepped = statement.step();
    if (!stepped.ok())
      return IdResult::failure(stepped.error());
  }
  auto last = db_.prepare("SELECT last_insert_rowid();");
  if (!last.ok())
    return IdResult::failure(last.error());
  auto row = last.value().step();
  if (!row.ok())
    return IdResult::failure(row.error());
  return IdResult::success(last.value().column_int64(0));
}

Status SnapshotStore::add_comparison_rows(std::int64_t id, const std::vector<StoredComparisonRow>& rows) {
  if (rows.empty())
    return Status::success();
  std::int64_t ordinal = 0;
  {
    auto next = db_.prepare("SELECT COALESCE(MAX(ordinal)+1,0) FROM comparison_rows WHERE comparison_id=?;");
    if (!next.ok())
      return Status::failure(next.error());
    if (auto status = next.value().bind(1, id); !status.ok())
      return status;
    auto row = next.value().step();
    if (!row.ok())
      return Status::failure(row.error());
    if (row.value())
      ordinal = next.value().column_int64(0);
  }
  auto insert = db_.prepare("INSERT INTO comparison_rows(comparison_id,ordinal,change,path,reason,detail) "
                            "VALUES(?,?,?,?,?,?);");
  if (!insert.ok())
    return Status::failure(insert.error());
  auto& statement = insert.value();
  if (auto status = db_.execute("SAVEPOINT sat_comparison_rows;"); !status.ok())
    return status;
  const auto abandon = [&](const Error& error) {
    static_cast<void>(statement.reset());
    static_cast<void>(db_.execute("ROLLBACK TO sat_comparison_rows; RELEASE sat_comparison_rows;"));
    return Status::failure(error);
  };
  for (const StoredComparisonRow& row : rows) {
    if (auto status = statement.bind(1, id); !status.ok())
      return abandon(status.error());
    if (auto status = statement.bind(2, ordinal++); !status.ok())
      return abandon(status.error());
    if (auto status = statement.bind(3, row.change); !status.ok())
      return abandon(status.error());
    if (auto status = statement.bind(4, row.path); !status.ok())
      return abandon(status.error());
    if (auto status = statement.bind(5, row.reason); !status.ok())
      return abandon(status.error());
    if (auto status = statement.bind(6, row.detail); !status.ok())
      return abandon(status.error());
    auto stepped = statement.step();
    if (!stepped.ok())
      return abandon(stepped.error());
    if (auto status = statement.reset(); !status.ok())
      return abandon(status.error());
  }
  return db_.execute("RELEASE sat_comparison_rows;");
}

Status SnapshotStore::finish_comparison(std::int64_t id,
                                        const StoredComparisonCounts& counts,
                                        std::string_view summary) {
  {
    auto update = db_.prepare("UPDATE comparisons SET added=?,removed=?,changed=?,moved=?,summary=? WHERE id=?;");
    if (!update.ok())
      return Status::failure(update.error());
    auto& statement = update.value();
    int index = 1;
    for (const std::uint64_t value : {counts.added, counts.removed, counts.changed, counts.moved}) {
      if (auto status = statement.bind(index++, static_cast<std::int64_t>(value)); !status.ok())
        return status;
    }
    if (auto status = statement.bind(index++, summary); !status.ok())
      return status;
    if (auto status = statement.bind(index, id); !status.ok())
      return status;
    auto stepped = statement.step();
    if (!stepped.ok())
      return Status::failure(stepped.error());
  }
  // A capture file stays one self-contained file: fold a write-ahead log back in when the file was
  // left in that mode.
  static_cast<void>(db_.execute("PRAGMA wal_checkpoint(TRUNCATE);"));
  return Status::success();
}

Status SnapshotStore::delete_comparison(std::int64_t id) {
  auto present = comparison_tables_present(db_);
  if (!present.ok())
    return Status::failure(present.error());
  if (!present.value())
    return Status::success();
  auto remove = db_.prepare("DELETE FROM comparisons WHERE id=?;");
  if (!remove.ok())
    return Status::failure(remove.error());
  if (auto status = remove.value().bind(1, id); !status.ok())
    return status;
  auto stepped = remove.value().step();
  return stepped.ok() ? Status::success() : Status::failure(stepped.error());
}

Result<std::vector<StoredComparison>> SnapshotStore::comparisons(std::string_view snapshot_id) {
  using ListResult = Result<std::vector<StoredComparison>>;
  auto present = comparison_tables_present(db_);
  if (!present.ok())
    return ListResult::failure(present.error());
  std::vector<StoredComparison> output;
  if (!present.value())
    return ListResult::success(std::move(output));
  auto query = db_.prepare("SELECT id,snapshot_id,created_utc,kind,against,against_snapshot_id,added,removed,"
                           "changed,moved,summary FROM comparisons WHERE (?1='' OR snapshot_id=?1) "
                           "ORDER BY created_utc DESC,id DESC;");
  if (!query.ok())
    return ListResult::failure(query.error());
  if (auto status = query.value().bind(1, snapshot_id); !status.ok())
    return ListResult::failure(status.error());
  for (;;) {
    auto row = query.value().step();
    if (!row.ok())
      return ListResult::failure(row.error());
    if (!row.value())
      break;
    StoredComparison comparison;
    comparison.id = query.value().column_int64(0);
    comparison.snapshot_id = query.value().column_text(1);
    comparison.created_utc = query.value().column_text(2);
    comparison.kind = query.value().column_text(3);
    comparison.against = query.value().column_text(4);
    comparison.against_snapshot_id = query.value().column_text(5);
    comparison.added = static_cast<std::uint64_t>(query.value().column_int64(6));
    comparison.removed = static_cast<std::uint64_t>(query.value().column_int64(7));
    comparison.changed = static_cast<std::uint64_t>(query.value().column_int64(8));
    comparison.moved = static_cast<std::uint64_t>(query.value().column_int64(9));
    comparison.summary = query.value().column_text(10);
    output.push_back(std::move(comparison));
  }
  return ListResult::success(std::move(output));
}

Status SnapshotStore::visit_comparison_rows(std::int64_t id,
                                            const std::function<bool(const StoredComparisonRow&)>& visit) {
  auto present = comparison_tables_present(db_);
  if (!present.ok())
    return Status::failure(present.error());
  if (!present.value())
    return Status::success();
  auto query = db_.prepare("SELECT change,path,reason,detail FROM comparison_rows WHERE comparison_id=? "
                           "ORDER BY ordinal;");
  if (!query.ok())
    return Status::failure(query.error());
  if (auto status = query.value().bind(1, id); !status.ok())
    return status;
  for (;;) {
    auto row = query.value().step();
    if (!row.ok())
      return Status::failure(row.error());
    if (!row.value())
      break;
    StoredComparisonRow item;
    item.change = query.value().column_text(0);
    item.path = query.value().column_text(1);
    item.reason = query.value().column_text(2);
    item.detail = query.value().column_text(3);
    if (!visit(item))
      break;
  }
  return Status::success();
}
} // namespace support_assist

namespace support_assist {
namespace {
Status bind_bool(Statement& s, int index, bool value) {
  return s.bind(index, static_cast<std::int64_t>(value ? 1 : 0));
}
Status reset_after_step(Statement& s) {
  auto row = s.step();
  if (!row.ok())
    return Status::failure(row.error());
  return s.reset();
}
} // namespace

SnapshotBatchWriter::~SnapshotBatchWriter() {
  if (transaction_active_ && db_) {
    db_->rollback();
  }
}
SnapshotBatchWriter::SnapshotBatchWriter(SnapshotBatchWriter&& other) noexcept
    : db_(other.db_), error_(std::move(other.error_)),
      registry_key_(std::move(other.registry_key_)),
      registry_value_(std::move(other.registry_value_)),
      filesystem_object_(std::move(other.filesystem_object_)), batch_size_(other.batch_size_),
      pending_(other.pending_), transaction_active_(other.transaction_active_) {
  other.db_ = nullptr;
  other.transaction_active_ = false;
  other.pending_ = 0;
}
SnapshotBatchWriter& SnapshotBatchWriter::operator=(SnapshotBatchWriter&& other) noexcept {
  if (this != &other) {
    if (transaction_active_ && db_)
      db_->rollback();
    db_ = other.db_;
    error_ = std::move(other.error_);
    registry_key_ = std::move(other.registry_key_);
    registry_value_ = std::move(other.registry_value_);
    filesystem_object_ = std::move(other.filesystem_object_);
    batch_size_ = other.batch_size_;
    pending_ = other.pending_;
    transaction_active_ = other.transaction_active_;
    other.db_ = nullptr;
    other.transaction_active_ = false;
    other.pending_ = 0;
  }
  return *this;
}
Result<SnapshotBatchWriter> SnapshotBatchWriter::create(SnapshotStore& store,
                                                        std::size_t batch_size) {
  SnapshotBatchWriter writer;
  writer.db_ = &store.db();
  writer.batch_size_ = batch_size == 0 ? 1000 : batch_size;
  auto e =
      writer.db_->prepare("INSERT INTO "
                          "scan_errors(snapshot_id,component,operation,source,native_code,hresult,"
                          "sqlite_code,message,severity,recoverable,elevation_may_help,skipped,"
                          "timestamp_utc,correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
  if (!e.ok())
    return Result<SnapshotBatchWriter>::failure(e.error());
  writer.error_ = std::move(e.value());
  auto k = writer.db_->prepare(
      "INSERT OR REPLACE INTO "
      "registry_keys(snapshot_id,hive,relative_path,registry_view,key_name,last_write_100ns,class_"
      "name,access_result,enumeration_error) VALUES(?,?,?,?,?,?,?,?,?);");
  if (!k.ok())
    return Result<SnapshotBatchWriter>::failure(k.error());
  writer.registry_key_ = std::move(k.value());
  auto v = writer.db_->prepare(
      "INSERT OR REPLACE INTO "
      "registry_values(snapshot_id,hive,relative_path,registry_view,value_name,is_default,value_"
      "type,raw_data,display_data,data_hash,display_truncated) VALUES(?,?,?,?,?,?,?,?,?,?,?);");
  if (!v.ok())
    return Result<SnapshotBatchWriter>::failure(v.error());
  writer.registry_value_ = std::move(v.value());
  auto f = writer.db_->prepare(
      "INSERT OR REPLACE INTO "
      "filesystem_objects(snapshot_id,relative_path,source_path,object_type,size,allocation_size,"
      "attributes,creation_100ns,access_100ns,write_100ns,change_100ns,volume_serial,file_id_hex,"
      "reparse_point,reparse_tag,hard_link_count,streams_json,access_result,enumeration_error,"
      "content_hash,hash_algorithm,hash_status,from_vss,case_sensitive_directory) "
      "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);");
  if (!f.ok())
    return Result<SnapshotBatchWriter>::failure(f.error());
  writer.filesystem_object_ = std::move(f.value());
  auto begin = writer.db_->begin();
  if (!begin.ok())
    return Result<SnapshotBatchWriter>::failure(begin.error());
  writer.transaction_active_ = true;
  return Result<SnapshotBatchWriter>::success(std::move(writer));
}
Status SnapshotBatchWriter::after_row() {
  ++pending_;
  if (pending_ < batch_size_)
    return Status::success();
  auto committed = db_->commit();
  if (!committed.ok())
    return committed;
  transaction_active_ = false;
  auto begun = db_->begin();
  if (!begun.ok())
    return begun;
  transaction_active_ = true;
  pending_ = 0;
  return Status::success();
}
Status SnapshotBatchWriter::add_error(std::string_view sid, const Error& e) {
  int i = 1;
  for (auto v : {sid,
                 std::string_view(e.component),
                 std::string_view(e.operation),
                 std::string_view(e.source)}) {
    auto s = error_.bind(i++, v);
    if (!s.ok())
      return s;
  }
  for (auto v : {e.native_code, e.hresult, static_cast<std::int64_t>(e.sqlite_code)}) {
    auto s = error_.bind(i++, v);
    if (!s.ok())
      return s;
  }
  if (auto s = error_.bind(i++, e.message); !s.ok())
    return s;
  if (auto s = error_.bind(i++, to_string(e.severity)); !s.ok())
    return s;
  for (bool v : {e.recoverable, e.elevation_may_help, e.skipped}) {
    auto s = bind_bool(error_, i++, v);
    if (!s.ok())
      return s;
  }
  if (auto s = error_.bind(i++, e.timestamp_utc); !s.ok())
    return s;
  if (auto s = error_.bind(i++, e.correlation_id); !s.ok())
    return s;
  if (auto s = reset_after_step(error_); !s.ok())
    return s;
  return after_row();
}
Status SnapshotBatchWriter::add_registry_key(const RegistryKeyRecord& r) {
  int i = 1;
  const std::string view = to_string(r.view);
  const std::array<std::string_view, 5> text_values{
      r.snapshot_id, r.hive, r.relative_path, view, r.key_name};
  for (const auto value : text_values) {
    if (auto status = registry_key_.bind(i++, value); !status.ok())
      return status;
  }
  if (auto status = registry_key_.bind(i++, r.last_write_100ns); !status.ok())
    return status;
  if (auto status = registry_key_.bind(i++, r.class_name); !status.ok())
    return status;
  if (auto status = registry_key_.bind(i++, static_cast<std::int64_t>(r.access_result));
      !status.ok())
    return status;
  if (auto status = registry_key_.bind(i++, r.enumeration_error); !status.ok())
    return status;
  if (auto status = reset_after_step(registry_key_); !status.ok())
    return status;
  return after_row();
}

Status SnapshotBatchWriter::add_registry_value(const RegistryValueRecord& r) {
  int i = 1;
  const std::string view = to_string(r.view);
  const std::array<std::string_view, 5> text_values{
      r.snapshot_id, r.hive, r.relative_path, view, r.value_name};
  for (const auto value : text_values) {
    if (auto status = registry_value_.bind(i++, value); !status.ok())
      return status;
  }
  if (auto status = bind_bool(registry_value_, i++, r.is_default); !status.ok())
    return status;
  if (auto status = registry_value_.bind(i++, static_cast<std::int64_t>(r.type)); !status.ok())
    return status;
  if (auto status = registry_value_.bind(
          i++, std::span<const std::byte>(r.raw_data.data(), r.raw_data.size()));
      !status.ok())
    return status;
  if (auto status = registry_value_.bind(i++, r.display_data); !status.ok())
    return status;
  if (auto status = registry_value_.bind(i++, r.data_hash); !status.ok())
    return status;
  if (auto status = bind_bool(registry_value_, i++, r.display_truncated); !status.ok())
    return status;
  if (auto status = reset_after_step(registry_value_); !status.ok())
    return status;
  return after_row();
}
Status SnapshotBatchWriter::add_filesystem_object(const FilesystemRecord& r) {
  int i = 1;
  for (auto v : {std::string_view(r.snapshot_id),
                 std::string_view(r.relative_path),
                 std::string_view(r.source_path),
                 std::string_view(r.object_type)}) {
    auto s = filesystem_object_.bind(i++, v);
    if (!s.ok())
      return s;
  }
  for (auto v : {r.size,
                 r.allocation_size,
                 static_cast<std::uint64_t>(r.attributes),
                 static_cast<std::uint64_t>(r.creation_100ns),
                 static_cast<std::uint64_t>(r.access_100ns),
                 static_cast<std::uint64_t>(r.write_100ns),
                 static_cast<std::uint64_t>(r.change_100ns),
                 r.volume_serial}) {
    auto s = filesystem_object_.bind(i++, static_cast<std::int64_t>(v));
    if (!s.ok())
      return s;
  }
  if (auto s = filesystem_object_.bind(i++, r.file_id_hex); !s.ok())
    return s;
  if (auto s = bind_bool(filesystem_object_, i++, r.reparse_point); !s.ok())
    return s;
  if (auto s = filesystem_object_.bind(i++, static_cast<std::int64_t>(r.reparse_tag)); !s.ok())
    return s;
  if (auto s = filesystem_object_.bind(i++, static_cast<std::int64_t>(r.hard_link_count)); !s.ok())
    return s;
  if (auto s = filesystem_object_.bind(i++, r.streams_json); !s.ok())
    return s;
  if (auto s = filesystem_object_.bind(i++, static_cast<std::int64_t>(r.access_result)); !s.ok())
    return s;
  for (auto v : {std::string_view(r.enumeration_error),
                 std::string_view(r.content_hash),
                 std::string_view(r.hash_algorithm),
                 std::string_view(r.hash_status)}) {
    auto s = filesystem_object_.bind(i++, v);
    if (!s.ok())
      return s;
  }
  if (auto s = bind_bool(filesystem_object_, i++, false); !s.ok())
    return s;
  if (auto s = bind_bool(filesystem_object_, i++, r.case_sensitive_directory); !s.ok())
    return s;
  if (auto s = reset_after_step(filesystem_object_); !s.ok())
    return s;
  return after_row();
}
Status SnapshotBatchWriter::flush() {
  if (!transaction_active_)
    return Status::success();
  auto committed = db_->commit();
  if (!committed.ok())
    return committed;
  transaction_active_ = false;
  pending_ = 0;
  auto begun = db_->begin();
  if (!begun.ok())
    return begun;
  transaction_active_ = true;
  return Status::success();
}
Status SnapshotBatchWriter::finish() {
  if (!transaction_active_)
    return Status::success();
  auto committed = db_->commit();
  if (!committed.ok())
    return committed;
  transaction_active_ = false;
  pending_ = 0;
  return Status::success();
}
} // namespace support_assist
