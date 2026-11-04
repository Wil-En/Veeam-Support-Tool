#pragma once

// The read-only statement runner behind SQL Tools' checks, written once over an ODBC entry-point
// table: Windows passes the ODBC functions themselves, POSIX the table it loads with dlopen. One
// connection runs every statement in turn; a statement that fails records its error and the next
// one still runs. Only statements SAT composes, or the read-only query guard passed, reach it.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/version.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::sql_batch_detail {

inline std::string escape_connection_value(std::string_view value) {
  if (value.find_first_of(";{}=") == std::string_view::npos)
    return std::string(value);
  std::string output{"{"};
  for (const char c : value) {
    output.push_back(c);
    if (c == '}')
      output.push_back('}');
  }
  output.push_back('}');
  return output;
}

// The connection strings to try, newest driver first. The password is only ever in this string,
// in memory, for the connect call.
inline std::vector<std::string> connection_strings(const SqlConnection& connection) {
  const std::string authentication =
      connection.integrated ? std::string("Trusted_Connection=Yes;")
                            : "UID=" + escape_connection_value(connection.login) +
                                  ";PWD=" + escape_connection_value(connection.password) + ";";
  const std::array<std::string_view, 3> drivers{"ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server",
                                                "SQL Server"};
  std::vector<std::string> output;
  for (const std::string_view driver : drivers) {
    std::string text = "Driver={" + std::string(driver) + "};Server=" + escape_connection_value(connection.server) +
                       ";Database=" + escape_connection_value(connection.database.empty() ? "master" : connection.database) +
                       ";" + authentication;
    if (driver == "ODBC Driver 18 for SQL Server")
      text += "Encrypt=Optional;";
    if (connection.trust_server_certificate)
      text += "TrustServerCertificate=Yes;";
    text += "Application Name=" + std::string(kProductName) + ";";
    output.push_back(std::move(text));
  }
  return output;
}

template <typename Api>
class Handle {
public:
  Handle(const Api& api, SQLSMALLINT type) : api_(api), type_(type) {}
  ~Handle() {
    if (value_ != SQL_NULL_HANDLE)
      static_cast<void>(api_.free_handle(type_, value_));
  }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  bool allocate(SQLHANDLE parent) {
    const SQLRETURN result = api_.alloc_handle(type_, parent, &value_);
    return result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO;
  }
  SQLHANDLE get() const noexcept { return value_; }

private:
  const Api& api_;
  SQLSMALLINT type_;
  SQLHANDLE value_ = SQL_NULL_HANDLE;
};

inline bool ok(SQLRETURN result) {
  return result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO;
}

template <typename Api>
std::string diagnostics(const Api& api, SQLSMALLINT type, SQLHANDLE handle) {
  std::string output;
  std::array<SQLCHAR, 6> state{};
  std::array<SQLCHAR, 2048> message{};
  SQLINTEGER native_code = 0;
  SQLSMALLINT length = 0;
  for (SQLSMALLINT record = 1; record < 16; ++record) {
    const SQLRETURN result = api.get_diag_rec_a(type, handle, record, state.data(), &native_code, message.data(),
                                                static_cast<SQLSMALLINT>(message.size()), &length);
    if (!ok(result))
      break;
    if (!output.empty())
      output += " | ";
    output += std::string(reinterpret_cast<const char*>(state.data())) + " (" + std::to_string(native_code) +
              "): " + reinterpret_cast<const char*>(message.data());
  }
  return output;
}

template <typename Api>
std::optional<std::string> read_value(const Api& api, SQLHSTMT statement, SQLUSMALLINT column) {
  std::string output;
  std::array<char, 4096> buffer{};
  SQLLEN indicator = 0;
  for (;;) {
    const SQLRETURN result = api.get_data(statement, column, SQL_C_CHAR, buffer.data(),
                                          static_cast<SQLLEN>(buffer.size()), &indicator);
    if (result == SQL_NO_DATA)
      break;
    if (!ok(result))
      return std::string("<read error>");
    if (indicator == SQL_NULL_DATA)
      return std::nullopt;
    output.append(buffer.data(), std::char_traits<char>::length(buffer.data()));
    if (result == SQL_SUCCESS)
      break;
    if (output.size() >= 1024U * 1024U)
      break;
  }
  return output;
}

inline constexpr std::size_t kMaximumRows = 20000;

template <typename Api>
SqlStatementResult run_one(const Api& api, SQLHDBC connection, const std::string& text, const CancellationToken& cancel) {
  SqlStatementResult result;
  Handle<Api> statement(api, SQL_HANDLE_STMT);
  if (!statement.allocate(connection)) {
    result.error = "The statement could not be prepared (SQLAllocHandle).";
    return result;
  }
  SQLHSTMT handle = static_cast<SQLHSTMT>(statement.get());
  SQLRETURN status = api.exec_direct_a(handle, reinterpret_cast<SQLCHAR*>(const_cast<char*>(text.c_str())), SQL_NTS);
  if (!ok(status) && status != SQL_NO_DATA) {
    result.error = diagnostics(api, SQL_HANDLE_STMT, statement.get());
    return result;
  }
  std::size_t rows = 0;
  for (;;) {
    SQLSMALLINT columns = 0;
    if (ok(api.num_result_cols(handle, &columns)) && columns > 0) {
      SqlResultSet set;
      for (SQLUSMALLINT column = 1; column <= static_cast<SQLUSMALLINT>(columns); ++column) {
        std::array<SQLCHAR, 256> name{};
        SQLSMALLINT name_length = 0;
        SQLSMALLINT data_type = 0;
        SQLULEN size = 0;
        SQLSMALLINT digits = 0;
        SQLSMALLINT nullable = 0;
        if (ok(api.describe_col_a(handle, column, name.data(), static_cast<SQLSMALLINT>(name.size()), &name_length,
                                  &data_type, &size, &digits, &nullable)))
          set.columns.emplace_back(reinterpret_cast<const char*>(name.data()));
        else
          set.columns.push_back("column " + std::to_string(column));
      }
      while ((status = api.fetch(handle)) != SQL_NO_DATA) {
        if (!ok(status)) {
          result.error = diagnostics(api, SQL_HANDLE_STMT, statement.get());
          break;
        }
        std::vector<std::optional<std::string>> row;
        for (SQLUSMALLINT column = 1; column <= static_cast<SQLUSMALLINT>(columns); ++column)
          row.push_back(read_value(api, handle, column));
        set.rows.push_back(std::move(row));
        if (++rows >= kMaximumRows || cancel.is_cancelled()) {
          set.truncated = true;
          break;
        }
      }
      result.sets.push_back(std::move(set));
    }
    if (rows >= kMaximumRows || cancel.is_cancelled())
      break;
    status = api.more_results(handle);
    if (status == SQL_NO_DATA)
      break;
    if (!ok(status)) {
      result.error = diagnostics(api, SQL_HANDLE_STMT, statement.get());
      break;
    }
  }
  if (cancel.is_cancelled())
    static_cast<void>(api.cancel(handle));
  result.ok = result.error.empty();
  return result;
}

template <typename Api>
Result<SqlBatchResult> run_batch(const Api& api, const SqlConnection& connection, const std::vector<std::string>& statements,
                                 const CancellationToken& cancel, const ProgressCallback& progress) {
  auto failure = [&connection](std::string operation, std::string message) {
    Error error;
    error.component = "SQL ODBC";
    error.operation = std::move(operation);
    error.source = connection.server;
    error.message = std::move(message);
    return Result<SqlBatchResult>::failure(std::move(error));
  };
  if (connection.server.empty())
    return failure("connect", "A SQL Server name is required.");
  Handle<Api> environment(api, SQL_HANDLE_ENV);
  if (!environment.allocate(SQL_NULL_HANDLE))
    return failure("connect", "The ODBC environment could not be created.");
  static_cast<void>(api.set_env_attr(static_cast<SQLHENV>(environment.get()), SQL_ATTR_ODBC_VERSION,
                                     reinterpret_cast<SQLPOINTER>(static_cast<std::uintptr_t>(SQL_OV_ODBC3)), 0));
  Handle<Api> link(api, SQL_HANDLE_DBC);
  if (!link.allocate(environment.get()))
    return failure("connect", "The ODBC connection could not be created.");
  static_cast<void>(api.set_connect_attr(static_cast<SQLHDBC>(link.get()), SQL_LOGIN_TIMEOUT,
                                         reinterpret_cast<SQLPOINTER>(static_cast<std::uintptr_t>(15)), 0));
  if (progress) {
    ProgressEvent event;
    event.phase = "Connecting";
    event.current_scope = connection.server;
    progress(event);
  }
  SqlBatchResult batch;
  std::string failures;
  std::vector<std::string> drivers_tried;
  std::vector<std::string> candidates = connection_strings(connection);
  for (std::string& text : candidates) {
    if (cancel.is_cancelled())
      break;
    // "Driver={NAME};..." names the driver this attempt uses.
    const std::size_t close = text.find('}');
    const std::string driver = close == std::string::npos ? std::string() : text.substr(8, close - 8);
    drivers_tried.push_back(driver);
    const SQLRETURN result =
        api.driver_connect_a(static_cast<SQLHDBC>(link.get()), nullptr, reinterpret_cast<SQLCHAR*>(text.data()),
                             SQL_NTS, nullptr, 0, nullptr, SQL_DRIVER_NOPROMPT);
    std::fill(text.begin(), text.end(), '\0');
    if (ok(result)) {
      batch.driver = driver;
      batch.connected = true;
      break;
    }
    if (!failures.empty())
      failures += " | ";
    failures += diagnostics(api, SQL_HANDLE_DBC, link.get());
  }
  for (std::string& text : candidates)
    std::fill(text.begin(), text.end(), '\0');
  if (cancel.is_cancelled())
    return failure("connect", "Cancelled.");
  if (!batch.connected) {
    // One plain sentence from the diagnostics, then the drivers' own text. The instance list is read
    // only for a server that is this machine.
    std::optional<std::vector<std::string>> local_instances;
    if (sql_server_is_this_host(connection.server))
      local_instances = sql_local_instances_listed();
    return failure("connect", sql_connect_failure_text(connection.server, failures, drivers_tried, local_instances));
  }
  for (std::size_t index = 0; index < statements.size(); ++index) {
    if (cancel.is_cancelled())
      break;
    if (progress) {
      ProgressEvent event;
      event.phase = "Reading";
      event.processed = index + 1U;
      event.total = statements.size();
      event.current_scope = connection.server;
      progress(event);
    }
    batch.statements.push_back(run_one(api, static_cast<SQLHDBC>(link.get()), statements[index], cancel));
  }
  static_cast<void>(api.disconnect(static_cast<SQLHDBC>(link.get())));
  batch.cancelled = cancel.is_cancelled();
  return Result<SqlBatchResult>::success(std::move(batch));
}

} // namespace support_assist::sql_batch_detail
