#pragma once
#include "support_assist/error.hpp"
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>
struct sqlite3;
struct sqlite3_stmt;
namespace support_assist {
class Statement;
class Database {
public:
  Database() = default;
  ~Database();
  Database(const Database&) = delete;
  Database& operator=(const Database&) = delete;
  Database(Database&& other) noexcept;
  Database& operator=(Database&& other) noexcept;
  static Result<Database> open(const std::filesystem::path& path, bool read_only = false);
  Status execute(std::string_view sql);
  Result<Statement> prepare(std::string_view sql);
  [[nodiscard]] sqlite3* native() const noexcept {
    return db_;
  }
  [[nodiscard]] std::string last_error() const;
  Status begin();
  Status commit();
  Status rollback();

private:
  explicit Database(sqlite3* db) : db_(db) {}
  sqlite3* db_ = nullptr;
};
class Statement {
public:
  Statement() = default;
  ~Statement();
  Statement(const Statement&) = delete;
  Statement& operator=(const Statement&) = delete;
  Statement(Statement&& other) noexcept;
  Statement& operator=(Statement&& other) noexcept;
  Status bind(int index, std::string_view value);
  Status bind(int index, std::int64_t value);
  Status bind(int index, double value);
  Status bind(int index, std::span<const std::byte> value);
  Status bind_null(int index);
  Result<bool> step();
  Status reset();
  [[nodiscard]] std::int64_t column_int64(int index) const;
  [[nodiscard]] int column_int(int index) const;
  [[nodiscard]] double column_double(int index) const;
  [[nodiscard]] std::string column_text(int index) const;
  [[nodiscard]] std::vector<std::byte> column_blob(int index) const;

private:
  friend class Database;
  Statement(sqlite3* db, sqlite3_stmt* stmt) : db_(db), stmt_(stmt) {}
  Error error(std::string operation) const;
  sqlite3* db_ = nullptr;
  sqlite3_stmt* stmt_ = nullptr;
};
} // namespace support_assist
