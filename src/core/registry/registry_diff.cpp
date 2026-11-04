#include "support_assist/registry.hpp"
#include "support_assist/sqlite.hpp"
#include "support_assist/strings.hpp"

#include <sqlite3.h>

#include <string>
#include <string_view>
#include <utility>
namespace support_assist {
namespace {
Status attach(Database& db, const std::filesystem::path& p) {
  auto q = db.prepare("ATTACH DATABASE ? AS rhs;");
  if (!q.ok())
    return Status::failure(q.error());
  auto u = p.u8string();
  std::string x(reinterpret_cast<const char*>(u.data()), u.size());
  if (auto s = q.value().bind(1, x); !s.ok())
    return s;
  auto r = q.value().step();
  return r.ok() ? Status::success() : Status::failure(r.error());
}
Status emit_rows(Database& db, std::string_view sql, const DiffCallback& cb, std::uint64_t& count) {
  auto q = db.prepare(sql);
  if (!q.ok())
    return Status::failure(q.error());
  for (;;) {
    auto r = q.value().step();
    if (!r.ok())
      return Status::failure(r.error());
    if (!r.value())
      break;
    DiffRecord d;
    auto k = q.value().column_text(0);
    d.kind = k == "added"            ? ChangeKind::added
             : k == "removed"        ? ChangeKind::removed
             : k == "access_changed" ? ChangeKind::access_changed
                                     : ChangeKind::modified;
    d.category = q.value().column_text(1);
    d.identity = q.value().column_text(2);
    d.old_path = q.value().column_text(3);
    d.new_path = q.value().column_text(4);
    d.before_summary = q.value().column_text(5);
    d.after_summary = q.value().column_text(6);
    d.reason = q.value().column_text(7);
    auto s = cb(d);
    if (!s.ok())
      return s;
    ++count;
  }
  return Status::success();
}
// How a row names a key: the hive and view, then the key's path. A hive's own root has no path,
// so nothing follows the view for it. @L@ and @R@ stand for the before and after side.
std::string replace_all(std::string text, std::string_view token, const std::string& replacement) {
  for (auto position = text.find(token); position != std::string::npos;
       position = text.find(token, position + replacement.size()))
    text.replace(position, token.size(), replacement);
  return text;
}
std::string with_key_names(std::string sql) {
  const auto name = [](const char* side) {
    const std::string s = side;
    return s + ".hive||'['||" + s + ".registry_view||']'||CASE WHEN " + s + ".relative_path='' THEN '' ELSE '\\'||" + s +
           ".relative_path END";
  };
  sql = replace_all(std::move(sql), "@L@", name("l"));
  return replace_all(std::move(sql), "@R@", name("r"));
}
} // namespace
Result<std::uint64_t> compare_registry(const std::filesystem::path& before,
                                       std::string_view before_id,
                                       const std::filesystem::path& after,
                                       std::string_view after_id,
                                       const DiffCallback& callback,
                                       const CancellationToken& cancel) {
  auto op = Database::open(before, true);
  if (!op.ok())
    return Result<std::uint64_t>::failure(op.error());
  auto& db = op.value();
  // Cancel interrupts the statement running: SQLite asks every 10,000 steps.
  sqlite3_progress_handler(
      db.native(), 10000,
      [](void* token) { return static_cast<const CancellationToken*>(token)->is_cancelled() ? 1 : 0; },
      const_cast<CancellationToken*>(&cancel));
  const auto failed = [&cancel](const Error& error) {
    if (!cancel.is_cancelled())
      return Result<std::uint64_t>::failure(error);
    Error cancelled = error;
    cancelled.message = "Cancelled";
    return Result<std::uint64_t>::failure(std::move(cancelled));
  };
  auto a = attach(db, after);
  if (!a.ok())
    return Result<std::uint64_t>::failure(a.error());
  auto c = db.execute("CREATE TEMP TABLE compare_ids(before_id TEXT,after_id TEXT);");
  if (!c.ok())
    return Result<std::uint64_t>::failure(c.error());
  auto ins = db.prepare("INSERT INTO compare_ids VALUES(?,?);");
  if (!ins.ok())
    return Result<std::uint64_t>::failure(ins.error());
  ins.value().bind(1, before_id);
  ins.value().bind(2, after_id);
  auto ir = ins.value().step();
  if (!ir.ok())
    return Result<std::uint64_t>::failure(ir.error());
  std::uint64_t count = 0;
  const char* keys = R"SQL(
WITH ids AS (SELECT before_id b,after_id a FROM compare_ids),
left_rows AS (
 SELECT CASE WHEN r.id IS NULL THEN 'removed' WHEN l.access_result<>r.access_result THEN 'access_changed' ELSE 'modified' END kind,
 'registry_key' category,@L@ identity,l.relative_path old_path,COALESCE(r.relative_path,'') new_path,
 'last_write='||l.last_write_100ns||'; access='||l.access_result,
 COALESCE('last_write='||r.last_write_100ns||'; access='||r.access_result,''),
 CASE WHEN r.id IS NULL THEN 'Key absent from after snapshot'
      WHEN l.access_result<>r.access_result THEN 'Access state changed'
      WHEN (l.relative_path COLLATE BINARY)<>(r.relative_path COLLATE BINARY) THEN 'Key path case or representation changed'
      WHEN l.class_name<>r.class_name THEN 'Key class changed'
      ELSE 'Key last-write time changed' END reason
 FROM registry_keys l CROSS JOIN ids LEFT JOIN rhs.registry_keys r ON r.snapshot_id=ids.a AND r.hive=l.hive AND r.registry_view=l.registry_view AND r.relative_path=l.relative_path
 WHERE l.snapshot_id=ids.b AND (r.id IS NULL OR l.last_write_100ns<>r.last_write_100ns OR l.access_result<>r.access_result OR l.class_name<>r.class_name OR (l.relative_path COLLATE BINARY)<>(r.relative_path COLLATE BINARY))
), added AS (
 SELECT 'added','registry_key',@R@,'',r.relative_path,'','last_write='||r.last_write_100ns||'; access='||r.access_result,'Key absent from before snapshot'
 FROM rhs.registry_keys r CROSS JOIN ids LEFT JOIN registry_keys l ON l.snapshot_id=ids.b AND l.hive=r.hive AND l.registry_view=r.registry_view AND l.relative_path=r.relative_path
 WHERE r.snapshot_id=ids.a AND l.id IS NULL)
SELECT * FROM left_rows UNION ALL SELECT * FROM added ORDER BY 3;
)SQL";
  auto s = emit_rows(db, with_key_names(keys), callback, count);
  if (!s.ok())
    return failed(s.error());
  const char* values = R"SQL(
WITH ids AS (SELECT before_id b,after_id a FROM compare_ids),
left_rows AS (
 SELECT CASE WHEN r.id IS NULL THEN 'removed' ELSE 'modified' END,'registry_value',@L@||'::'||l.value_name,l.relative_path,l.relative_path,
 'type='||l.value_type||'; data='||substr(l.display_data,1,512),COALESCE('type='||r.value_type||'; data='||substr(r.display_data,1,512),''),
 CASE WHEN r.id IS NULL THEN 'Value absent from after snapshot'
      WHEN (l.relative_path COLLATE BINARY)<>(r.relative_path COLLATE BINARY) OR (l.value_name COLLATE BINARY)<>(r.value_name COLLATE BINARY) THEN 'Value name or parent path case representation changed'
      WHEN l.value_type<>r.value_type THEN 'Value type changed'
      ELSE 'Value data changed' END
 FROM registry_values l CROSS JOIN ids LEFT JOIN rhs.registry_values r ON r.snapshot_id=ids.a AND r.hive=l.hive AND r.registry_view=l.registry_view AND r.relative_path=l.relative_path AND r.value_name=l.value_name
 WHERE l.snapshot_id=ids.b AND (r.id IS NULL OR l.value_type<>r.value_type OR l.raw_data<>r.raw_data OR (l.relative_path COLLATE BINARY)<>(r.relative_path COLLATE BINARY) OR (l.value_name COLLATE BINARY)<>(r.value_name COLLATE BINARY))
),added AS (
 SELECT 'added','registry_value',@R@||'::'||r.value_name,'',r.relative_path,'','type='||r.value_type||'; data='||substr(r.display_data,1,512),'Value absent from before snapshot'
 FROM rhs.registry_values r CROSS JOIN ids LEFT JOIN registry_values l ON l.snapshot_id=ids.b AND l.hive=r.hive AND l.registry_view=r.registry_view AND l.relative_path=r.relative_path AND l.value_name=r.value_name
 WHERE r.snapshot_id=ids.a AND l.id IS NULL)
SELECT * FROM left_rows UNION ALL SELECT * FROM added ORDER BY 3;
)SQL";
  s = emit_rows(db, with_key_names(values), callback, count);
  if (!s.ok())
    return failed(s.error());
  sqlite3_progress_handler(db.native(), 0, nullptr, nullptr);
  return Result<std::uint64_t>::success(count);
}
} // namespace support_assist
