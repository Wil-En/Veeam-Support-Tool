#include "support_assist/sqlite.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <sqlite3.h>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
namespace support_assist {
namespace {
Error sqlite_error(sqlite3* db, std::string op, int code = 0) {
  Error e;
  e.component = "SQLite";
  e.operation = std::move(op);
  e.sqlite_code = code ? code : (db ? sqlite3_errcode(db) : SQLITE_ERROR);
  e.message = db ? sqlite3_errmsg(db) : "SQLite error";
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return e;
}

#ifdef _WIN32
int binary_compare(const void* left, int left_size, const void* right, int right_size) {
  const int common = std::min(left_size, right_size);
  const int compared = common > 0 ? std::memcmp(left, right, static_cast<std::size_t>(common)) : 0;
  if (compared < 0)
    return -1;
  if (compared > 0)
    return 1;
  return left_size < right_size ? -1 : (left_size > right_size ? 1 : 0);
}

std::wstring utf8_to_wide_noexcept(const void* data, int size) {
  if (size <= 0)
    return {};
  const auto* text = static_cast<const char*>(data);
  const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, size, nullptr, 0);
  if (required <= 0)
    return {};
  std::wstring result(static_cast<std::size_t>(required), L'\0');
  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, size, result.data(), required) ==
      0) {
    return {};
  }
  return result;
}
#endif

int registry_identity_collation(
    void*, int left_size, const void* left, int right_size, const void* right) noexcept {
#ifdef _WIN32
  const auto left_wide = utf8_to_wide_noexcept(left, left_size);
  const auto right_wide = utf8_to_wide_noexcept(right, right_size);
  if ((left_size > 0 && left_wide.empty()) || (right_size > 0 && right_wide.empty())) {
    return binary_compare(left, left_size, right, right_size);
  }
  const int result = CompareStringOrdinal(left_wide.data(),
                                          static_cast<int>(left_wide.size()),
                                          right_wide.data(),
                                          static_cast<int>(right_wide.size()),
                                          TRUE);
  if (result == CSTR_LESS_THAN)
    return -1;
  if (result == CSTR_GREATER_THAN)
    return 1;
  if (result == CSTR_EQUAL)
    return 0;
  return binary_compare(left, left_size, right, right_size);
#else
  const auto* lhs = static_cast<const unsigned char*>(left);
  const auto* rhs = static_cast<const unsigned char*>(right);
  const int common = std::min(left_size, right_size);
  for (int index = 0; index < common; ++index) {
    const int a = std::tolower(lhs[index]);
    const int b = std::tolower(rhs[index]);
    if (a < b)
      return -1;
    if (a > b)
      return 1;
  }
  return left_size < right_size ? -1 : (left_size > right_size ? 1 : 0);
#endif
}
} // namespace
Database::~Database() {
  if (db_)
    sqlite3_close_v2(db_);
}
Database::Database(Database&& o) noexcept : db_(o.db_) {
  o.db_ = nullptr;
}
Database& Database::operator=(Database&& o) noexcept {
  if (this != &o) {
    if (db_)
      sqlite3_close_v2(db_);
    db_ = o.db_;
    o.db_ = nullptr;
  }
  return *this;
}
Result<Database> Database::open(const std::filesystem::path& path, bool read_only) {
  sqlite3* db = nullptr;
  const int flags =
      (read_only ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE)) |
      SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_URI;
  const auto utf8_path = path.u8string();
  const std::string native_path(reinterpret_cast<const char*>(utf8_path.data()), utf8_path.size());
  const int open_result = sqlite3_open_v2(native_path.c_str(), &db, flags, nullptr);
  if (open_result != SQLITE_OK) {
    auto error = sqlite_error(db, "open", open_result);
    if (db)
      sqlite3_close_v2(db);
    return Result<Database>::failure(std::move(error));
  }

  const int collation_result = sqlite3_create_collation_v2(
      db, "WINDOWS_ORDINAL_NOCASE", SQLITE_UTF8, nullptr, registry_identity_collation, nullptr);
  if (collation_result != SQLITE_OK) {
    auto error = sqlite_error(db, "register Registry identity collation", collation_result);
    sqlite3_close_v2(db);
    return Result<Database>::failure(std::move(error));
  }

  sqlite3_extended_result_codes(db, 1);
  sqlite3_busy_timeout(db, 5000);
  sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
  sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, nullptr);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 512 * 1024 * 1024);
  sqlite3_limit(db, SQLITE_LIMIT_SQL_LENGTH, 1024 * 1024);
  sqlite3_limit(db, SQLITE_LIMIT_COLUMN, 2000);
  sqlite3_limit(db, SQLITE_LIMIT_COMPOUND_SELECT, 100);
  sqlite3_limit(db, SQLITE_LIMIT_ATTACHED, 2);

  Database database(db);
  auto pragmas = database.execute("PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON;");
  if (!pragmas.ok())
    return Result<Database>::failure(pragmas.error());
  return Result<Database>::success(std::move(database));
}
Status Database::execute(std::string_view sql) {
  char* msg = nullptr;
  int rc = sqlite3_exec(db_, std::string(sql).c_str(), nullptr, nullptr, &msg);
  if (rc != SQLITE_OK) {
    auto e = sqlite_error(db_, "execute", rc);
    if (msg) {
      e.message = msg;
      sqlite3_free(msg);
    }
    return Status::failure(std::move(e));
  }
  return Status::success();
}
Result<Statement> Database::prepare(std::string_view sql) {
  sqlite3_stmt* st = nullptr;
  int rc = sqlite3_prepare_v3(
      db_, sql.data(), static_cast<int>(sql.size()), SQLITE_PREPARE_PERSISTENT, &st, nullptr);
  if (rc != SQLITE_OK)
    return Result<Statement>::failure(sqlite_error(db_, "prepare", rc));
  return Result<Statement>::success(Statement(db_, st));
}
std::string Database::last_error() const {
  return db_ ? sqlite3_errmsg(db_) : "database closed";
}
Status Database::begin() {
  return execute("BEGIN IMMEDIATE;");
}
Status Database::commit() {
  return execute("COMMIT;");
}
Status Database::rollback() {
  return execute("ROLLBACK;");
}
Statement::~Statement() {
  if (stmt_)
    sqlite3_finalize(stmt_);
}
Statement::Statement(Statement&& o) noexcept : db_(o.db_), stmt_(o.stmt_) {
  o.db_ = nullptr;
  o.stmt_ = nullptr;
}
Statement& Statement::operator=(Statement&& o) noexcept {
  if (this != &o) {
    if (stmt_)
      sqlite3_finalize(stmt_);
    db_ = o.db_;
    stmt_ = o.stmt_;
    o.db_ = nullptr;
    o.stmt_ = nullptr;
  }
  return *this;
}
Error Statement::error(std::string op) const {
  return sqlite_error(db_, std::move(op));
}
Status Statement::bind(int i, std::string_view v) {
  int rc = sqlite3_bind_text(stmt_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("bind text"));
}
Status Statement::bind(int i, std::int64_t v) {
  int rc = sqlite3_bind_int64(stmt_, i, v);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("bind int64"));
}
Status Statement::bind(int i, double v) {
  int rc = sqlite3_bind_double(stmt_, i, v);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("bind double"));
}
Status Statement::bind(int i, std::span<const std::byte> v) {
  // An empty span's data() may be null, which SQLite binds as NULL; an empty value is a zero-length
  // blob (a registry value with no data).
  int rc = v.empty() ? sqlite3_bind_zeroblob(stmt_, i, 0)
                     : sqlite3_bind_blob64(stmt_, i, v.data(), static_cast<sqlite3_uint64>(v.size()),
                                           SQLITE_TRANSIENT);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("bind blob"));
}
Status Statement::bind_null(int i) {
  int rc = sqlite3_bind_null(stmt_, i);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("bind null"));
}
Result<bool> Statement::step() {
  int rc = sqlite3_step(stmt_);
  if (rc == SQLITE_ROW)
    return Result<bool>::success(true);
  if (rc == SQLITE_DONE)
    return Result<bool>::success(false);
  return Result<bool>::failure(error("step"));
}
Status Statement::reset() {
  int rc = sqlite3_reset(stmt_);
  sqlite3_clear_bindings(stmt_);
  return rc == SQLITE_OK ? Status::success() : Status::failure(error("reset"));
}
std::int64_t Statement::column_int64(int i) const {
  return sqlite3_column_int64(stmt_, i);
}
int Statement::column_int(int i) const {
  return sqlite3_column_int(stmt_, i);
}
double Statement::column_double(int i) const {
  return sqlite3_column_double(stmt_, i);
}
std::string Statement::column_text(int i) const {
  const auto* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt_, i));
  int n = sqlite3_column_bytes(stmt_, i);
  return p ? std::string(p, static_cast<std::size_t>(n)) : std::string();
}
std::vector<std::byte> Statement::column_blob(int i) const {
  const auto* p = static_cast<const std::byte*>(sqlite3_column_blob(stmt_, i));
  int n = sqlite3_column_bytes(stmt_, i);
  return p ? std::vector<std::byte>(p, p + n) : std::vector<std::byte>();
}
} // namespace support_assist
