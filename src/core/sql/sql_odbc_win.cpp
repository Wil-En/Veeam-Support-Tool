#include "sql_odbc.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/version.hpp"

#include <windows.h>
#include <sql.h>
#include <sqlext.h>

#include "sql_batch.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

class OdbcHandle {
public:
  OdbcHandle() = default;
  OdbcHandle(SQLSMALLINT type, SQLHANDLE value) : type_(type), value_(value) {}
  ~OdbcHandle() {
    reset();
  }
  OdbcHandle(const OdbcHandle&) = delete;
  OdbcHandle& operator=(const OdbcHandle&) = delete;
  OdbcHandle(OdbcHandle&& other) noexcept : type_(other.type_), value_(other.release()) {}
  OdbcHandle& operator=(OdbcHandle&& other) noexcept {
    if (this != &other) {
      reset();
      type_ = other.type_;
      value_ = other.release();
    }
    return *this;
  }
  SQLHANDLE get() const noexcept {
    return value_;
  }
  SQLHANDLE release() noexcept {
    SQLHANDLE value = value_;
    value_ = SQL_NULL_HANDLE;
    return value;
  }
  void reset(SQLHANDLE replacement = SQL_NULL_HANDLE) noexcept {
    if (value_ != SQL_NULL_HANDLE)
      SQLFreeHandle(type_, value_);
    value_ = replacement;
  }

private:
  SQLSMALLINT type_ = 0;
  SQLHANDLE value_ = SQL_NULL_HANDLE;
};

bool succeeded(SQLRETURN result) noexcept {
  return result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO;
}

std::string diagnostics(SQLSMALLINT type, SQLHANDLE handle) {
  std::ostringstream output;
  std::array<SQLCHAR, 6> state{};
  std::array<SQLCHAR, 2048> message{};
  SQLINTEGER native_code = 0;
  SQLSMALLINT length = 0;
  for (SQLSMALLINT record = 1;; ++record) {
    const SQLRETURN result = SQLGetDiagRecA(type,
                                            handle,
                                            record,
                                            state.data(),
                                            &native_code,
                                            message.data(),
                                            static_cast<SQLSMALLINT>(message.size()),
                                            &length);
    if (result == SQL_NO_DATA)
      break;
    if (!succeeded(result))
      break;
    if (record > 1)
      output << " | ";
    output << reinterpret_cast<const char*>(state.data()) << " (" << native_code << "): "
           << reinterpret_cast<const char*>(message.data());
  }
  return output.str();
}

Error odbc_error(std::string operation,
                 std::string source,
                 std::string message,
                 SQLSMALLINT type = 0,
                 SQLHANDLE handle = SQL_NULL_HANDLE) {
  Error error;
  error.component = "SQL ODBC";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  if (type != 0 && handle != SQL_NULL_HANDLE) {
    const std::string detail = diagnostics(type, handle);
    if (!detail.empty())
      error.message += ": " + detail;
  }
  return error;
}

std::string escape_connection_value(std::string_view value) {
  if (value.find_first_of(";{}") == std::string_view::npos)
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

std::vector<std::string> connection_candidates(const SqlPermissionOptions& options) {
  if (!options.connection_string.empty())
    return {options.connection_string};

  const std::string server = escape_connection_value(options.server);
  const std::string database = escape_connection_value(options.database);
  const std::string authentication =
      options.trusted_connection ? "Trusted_Connection=Yes;" : std::string();
  const std::string certificate =
      options.trust_server_certificate ? "TrustServerCertificate=Yes;" : std::string();
  const std::array<std::string_view, 3> drivers{
      "ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server", "SQL Server"};
  std::vector<std::string> output;
  output.reserve(drivers.size());
  for (const std::string_view driver : drivers) {
    std::string connection = "Driver={" + std::string(driver) + "};Server=" + server +
                             ";Database=" + database + ";" + authentication;
    if (driver == "ODBC Driver 18 for SQL Server")
      connection += "Encrypt=Optional;";
    connection += certificate;
    connection += "Application Name=" + std::string(kProductName) + ";";
    output.push_back(std::move(connection));
  }
  return output;
}

std::string read_column(SQLHSTMT statement, SQLUSMALLINT column) {
  std::string output;
  std::array<char, 4096> buffer{};
  SQLLEN indicator = 0;
  for (;;) {
    const SQLRETURN result = SQLGetData(statement,
                                        column,
                                        SQL_C_CHAR,
                                        buffer.data(),
                                        static_cast<SQLLEN>(buffer.size()),
                                        &indicator);
    if (indicator == SQL_NULL_DATA)
      return "<NULL>";
    if (result == SQL_NO_DATA)
      break;
    if (!succeeded(result))
      return "<ODBC read error>";
    const std::size_t length = std::char_traits<char>::length(buffer.data());
    output.append(buffer.data(), length);
    if (result == SQL_SUCCESS)
      break;
    if (output.size() >= 1024U * 1024U) {
      output += "<truncated>";
      break;
    }
  }
  return output;
}

void publish(const ProgressCallback& progress,
             std::string phase,
             std::string scope,
             std::uint64_t processed = 0) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = std::move(phase);
  event.current_scope = std::move(scope);
  event.processed = processed;
  progress(event);
}

Result<OdbcHandle> allocate_handle(SQLSMALLINT type,
                                   SQLHANDLE parent,
                                   std::string_view operation) {
  SQLHANDLE raw = SQL_NULL_HANDLE;
  const SQLRETURN result = SQLAllocHandle(type, parent, &raw);
  if (!succeeded(result)) {
    return Result<OdbcHandle>::failure(
        odbc_error(std::string(operation), {}, "SQLAllocHandle failed"));
  }
  return Result<OdbcHandle>::success(OdbcHandle(type, raw));
}

} // namespace

Result<ProcessResult> run_sql_permission_diagnostic_odbc(const SqlPermissionOptions& options,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress) {
  if (options.server.empty()) {
    return Result<ProcessResult>::failure(
        odbc_error("connect", {}, "A SQL Server instance is required"));
  }
  if (options.principal.empty()) {
    return Result<ProcessResult>::failure(
        odbc_error("permission diagnostic", options.server, "A principal name is required"));
  }
  if (!options.trusted_connection && options.connection_string.empty()) {
    return Result<ProcessResult>::failure(odbc_error(
        "connect",
        options.server,
        "Non-integrated authentication requires an explicit ODBC connection string"));
  }

  auto environment_result =
      allocate_handle(SQL_HANDLE_ENV, SQL_NULL_HANDLE, "allocate environment");
  if (!environment_result.ok())
    return Result<ProcessResult>::failure(environment_result.error());
  OdbcHandle environment = std::move(environment_result.value());
  if (!succeeded(SQLSetEnvAttr(static_cast<SQLHENV>(environment.get()),
                               SQL_ATTR_ODBC_VERSION,
                               reinterpret_cast<SQLPOINTER>(static_cast<UINT_PTR>(SQL_OV_ODBC3)),
                               0))) {
    return Result<ProcessResult>::failure(odbc_error("configure environment",
                                                     options.server,
                                                     "SQLSetEnvAttr failed",
                                                     SQL_HANDLE_ENV,
                                                     environment.get()));
  }

  auto connection_result =
      allocate_handle(SQL_HANDLE_DBC, environment.get(), "allocate connection");
  if (!connection_result.ok())
    return Result<ProcessResult>::failure(connection_result.error());
  OdbcHandle connection = std::move(connection_result.value());
  static_cast<void>(SQLSetConnectAttr(static_cast<SQLHDBC>(connection.get()),
                                      SQL_LOGIN_TIMEOUT,
                                      reinterpret_cast<SQLPOINTER>(static_cast<UINT_PTR>(15)),
                                      0));

  std::string failures;
  bool connected = false;
  for (const std::string& candidate : connection_candidates(options)) {
    if (cancel.is_cancelled()) {
      return Result<ProcessResult>::failure(
          odbc_error("connect", options.server, "Operation cancelled"));
    }
    publish(progress, "Connecting through ODBC", options.server);
    const SQLRETURN result = SQLDriverConnectA(static_cast<SQLHDBC>(connection.get()),
                                               nullptr,
                                               reinterpret_cast<SQLCHAR*>(
                                                   const_cast<char*>(candidate.c_str())),
                                               SQL_NTS,
                                               nullptr,
                                               0,
                                               nullptr,
                                               SQL_DRIVER_NOPROMPT);
    if (succeeded(result)) {
      connected = true;
      break;
    }
    if (!failures.empty())
      failures += " | ";
    failures += diagnostics(SQL_HANDLE_DBC, connection.get());
  }
  if (!connected) {
    return Result<ProcessResult>::failure(odbc_error(
        "connect", options.server, "No installed SQL Server ODBC driver connected: " + failures));
  }

  auto statement_result =
      allocate_handle(SQL_HANDLE_STMT, connection.get(), "allocate statement");
  if (!statement_result.ok())
    return Result<ProcessResult>::failure(statement_result.error());
  OdbcHandle statement = std::move(statement_result.value());
  const std::string script = make_sql_permission_diagnostic_script(
      options.principal, options.include_database_permissions);
  publish(progress, "Executing permission diagnostic", options.principal);
  SQLRETURN result = SQLExecDirectA(static_cast<SQLHSTMT>(statement.get()),
                                    reinterpret_cast<SQLCHAR*>(const_cast<char*>(script.c_str())),
                                    SQL_NTS);
  if (!succeeded(result)) {
    return Result<ProcessResult>::failure(odbc_error("execute permission diagnostic",
                                                     options.server,
                                                     "SQLExecDirect failed",
                                                     SQL_HANDLE_STMT,
                                                     statement.get()));
  }

  ProcessResult output;
  output.launched = true;
  output.exit_code = 0;
  output.command_display = "Native ODBC permission diagnostic against " + options.server;
  std::ostringstream text;
  text << "Connection: native ODBC\n"
       << "Server: " << options.server << "\n"
       << "Database: " << options.database << "\n"
       << "Principal: " << options.principal << "\n\n";

  std::uint64_t total_rows = 0;
  std::uint32_t result_set = 0;
  for (;;) {
    if (cancel.is_cancelled()) {
      static_cast<void>(SQLCancel(static_cast<SQLHSTMT>(statement.get())));
      output.cancelled = true;
      output.exit_code = 130;
      break;
    }
    SQLSMALLINT column_count = 0;
    result = SQLNumResultCols(static_cast<SQLHSTMT>(statement.get()), &column_count);
    if (!succeeded(result)) {
      return Result<ProcessResult>::failure(odbc_error("inspect result set",
                                                       options.server,
                                                       "SQLNumResultCols failed",
                                                       SQL_HANDLE_STMT,
                                                       statement.get()));
    }
    ++result_set;
    if (column_count > 0) {
      text << "Result set " << result_set << '\n';
      std::vector<std::string> column_names;
      column_names.reserve(static_cast<std::size_t>(column_count));
      for (SQLUSMALLINT column = 1; column <= static_cast<SQLUSMALLINT>(column_count); ++column) {
        std::array<SQLCHAR, 256> name{};
        SQLSMALLINT name_length = 0;
        SQLSMALLINT data_type = 0;
        SQLULEN column_size = 0;
        SQLSMALLINT decimal_digits = 0;
        SQLSMALLINT nullable = 0;
        const SQLRETURN describe = SQLDescribeColA(static_cast<SQLHSTMT>(statement.get()),
                                                   column,
                                                   name.data(),
                                                   static_cast<SQLSMALLINT>(name.size()),
                                                   &name_length,
                                                   &data_type,
                                                   &column_size,
                                                   &decimal_digits,
                                                   &nullable);
        if (!succeeded(describe))
          column_names.push_back("column_" + std::to_string(column));
        else
          column_names.emplace_back(reinterpret_cast<const char*>(name.data()),
                                    static_cast<std::size_t>(std::max<SQLSMALLINT>(0, name_length)));
      }
      for (std::size_t index = 0; index < column_names.size(); ++index) {
        if (index != 0)
          text << " | ";
        text << column_names[index];
      }
      text << '\n';
      while ((result = SQLFetch(static_cast<SQLHSTMT>(statement.get()))) != SQL_NO_DATA) {
        if (!succeeded(result)) {
          return Result<ProcessResult>::failure(odbc_error("fetch result row",
                                                           options.server,
                                                           "SQLFetch failed",
                                                           SQL_HANDLE_STMT,
                                                           statement.get()));
        }
        for (SQLUSMALLINT column = 1; column <= static_cast<SQLUSMALLINT>(column_count); ++column) {
          if (column != 1)
            text << " | ";
          text << read_column(static_cast<SQLHSTMT>(statement.get()), column);
        }
        text << '\n';
        ++total_rows;
        if (total_rows >= 10000U ||
            text.tellp() >= static_cast<std::streampos>(16 * 1024 * 1024)) {
          text << "<output truncated by safety limit>\n";
          break;
        }
        publish(progress, "Reading SQL results", options.server, total_rows);
        if (cancel.is_cancelled())
          break;
      }
      text << '\n';
    }
    if (total_rows >= 10000U || cancel.is_cancelled())
      break;
    result = SQLMoreResults(static_cast<SQLHSTMT>(statement.get()));
    if (result == SQL_NO_DATA)
      break;
    if (!succeeded(result)) {
      return Result<ProcessResult>::failure(odbc_error("advance result set",
                                                       options.server,
                                                       "SQLMoreResults failed",
                                                       SQL_HANDLE_STMT,
                                                       statement.get()));
    }
  }

  output.output = text.str();
  static_cast<void>(SQLDisconnect(static_cast<SQLHDBC>(connection.get())));
  return Result<ProcessResult>::success(std::move(output));
}

namespace {

// The ODBC entry points SQL Tools' statement runner calls, here the functions themselves.
struct WindowsOdbcApi {
  decltype(&::SQLAllocHandle) alloc_handle = &::SQLAllocHandle;
  decltype(&::SQLFreeHandle) free_handle = &::SQLFreeHandle;
  decltype(&::SQLGetDiagRecA) get_diag_rec_a = &::SQLGetDiagRecA;
  decltype(&::SQLGetData) get_data = &::SQLGetData;
  decltype(&::SQLSetEnvAttr) set_env_attr = &::SQLSetEnvAttr;
  decltype(&::SQLSetConnectAttr) set_connect_attr = &::SQLSetConnectAttr;
  decltype(&::SQLDriverConnectA) driver_connect_a = &::SQLDriverConnectA;
  decltype(&::SQLExecDirectA) exec_direct_a = &::SQLExecDirectA;
  decltype(&::SQLCancel) cancel = &::SQLCancel;
  decltype(&::SQLNumResultCols) num_result_cols = &::SQLNumResultCols;
  decltype(&::SQLDescribeColA) describe_col_a = &::SQLDescribeColA;
  decltype(&::SQLFetch) fetch = &::SQLFetch;
  decltype(&::SQLMoreResults) more_results = &::SQLMoreResults;
  decltype(&::SQLDisconnect) disconnect = &::SQLDisconnect;
};

} // namespace

Result<SqlBatchResult> run_sql_statements(const SqlConnection& connection, const std::vector<std::string>& statements,
                                          const CancellationToken& cancel, ProgressCallback progress) {
  static const WindowsOdbcApi api;
  return sql_batch_detail::run_batch(api, connection, statements, cancel, progress);
}

} // namespace support_assist
