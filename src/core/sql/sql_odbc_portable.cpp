#include "sql_odbc.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/version.hpp"

#include <sql.h>
#include <sqlext.h>

#include "sql_batch.hpp"

#include <dlfcn.h>

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

// ODBC is an optional runtime capability on POSIX platforms.
// Compile against the ODBC headers when a developer SDK is present, but resolve
// the driver-manager entry points with dlopen/dlsym only when SQL Tools is used.
// This keeps libodbc out of the executable's ELF/Mach-O hard dependency set so
// a Linux/macOS engineer can launch SAT without installing an ODBC runtime.
struct OdbcApi {
  void* library = nullptr;
  std::string library_name;
  std::string load_error;

  decltype(&::SQLAllocHandle) alloc_handle = nullptr;
  decltype(&::SQLFreeHandle) free_handle = nullptr;
  decltype(&::SQLGetDiagRecA) get_diag_rec_a = nullptr;
  decltype(&::SQLGetData) get_data = nullptr;
  decltype(&::SQLSetEnvAttr) set_env_attr = nullptr;
  decltype(&::SQLSetConnectAttr) set_connect_attr = nullptr;
  decltype(&::SQLDriverConnectA) driver_connect_a = nullptr;
  decltype(&::SQLExecDirectA) exec_direct_a = nullptr;
  decltype(&::SQLCancel) cancel = nullptr;
  decltype(&::SQLNumResultCols) num_result_cols = nullptr;
  decltype(&::SQLDescribeColA) describe_col_a = nullptr;
  decltype(&::SQLFetch) fetch = nullptr;
  decltype(&::SQLMoreResults) more_results = nullptr;
  decltype(&::SQLDisconnect) disconnect = nullptr;

  [[nodiscard]] bool loaded() const noexcept {
    return library != nullptr && alloc_handle != nullptr && free_handle != nullptr &&
           get_diag_rec_a != nullptr && get_data != nullptr && set_env_attr != nullptr &&
           set_connect_attr != nullptr && driver_connect_a != nullptr && exec_direct_a != nullptr &&
           cancel != nullptr && num_result_cols != nullptr && describe_col_a != nullptr &&
           fetch != nullptr && more_results != nullptr && disconnect != nullptr;
  }
};

template <typename T>
bool resolve_symbol(void* library, const char* name, T& output, std::string& error) {
  dlerror();
  void* symbol = dlsym(library, name);
  const char* lookup_error = dlerror();
  if (lookup_error != nullptr || symbol == nullptr) {
    error = std::string("Missing ODBC entry point ") + name;
    if (lookup_error != nullptr)
      error += std::string(": ") + lookup_error;
    return false;
  }
  output = reinterpret_cast<T>(symbol);
  return true;
}

const OdbcApi& odbc_api() {
  // Process-lifetime allocation is intentional. Keeping the driver manager
  // loaded avoids invalidating ODBC handles while tool results unwind.
  static const OdbcApi* api = [] {
    auto* value = new OdbcApi();
#if defined(__APPLE__)
    constexpr std::array<const char*, 4> candidates{
        "libodbc.2.dylib", "libodbc.dylib", "libiodbc.2.dylib", "libiodbc.dylib"};
#else
    constexpr std::array<const char*, 2> candidates{"libodbc.so.2", "libodbc.so"};
#endif
    for (const char* candidate : candidates) {
      dlerror();
      value->library = dlopen(candidate, RTLD_NOW | RTLD_LOCAL);
      if (value->library != nullptr) {
        value->library_name = candidate;
        break;
      }
      if (const char* error = dlerror(); error != nullptr)
        value->load_error = error;
    }
    if (value->library == nullptr) {
      if (value->load_error.empty())
        value->load_error = "No supported ODBC driver-manager library was found";
      return value;
    }

#define SAT_ODBC_SYMBOL(member, symbol)                                                        \
  if (!resolve_symbol(value->library, #symbol, value->member, value->load_error)) {             \
    dlclose(value->library);                                                                    \
    value->library = nullptr;                                                                   \
    return value;                                                                               \
  }
    SAT_ODBC_SYMBOL(alloc_handle, SQLAllocHandle)
    SAT_ODBC_SYMBOL(free_handle, SQLFreeHandle)
    SAT_ODBC_SYMBOL(get_diag_rec_a, SQLGetDiagRecA)
    SAT_ODBC_SYMBOL(get_data, SQLGetData)
    SAT_ODBC_SYMBOL(set_env_attr, SQLSetEnvAttr)
    SAT_ODBC_SYMBOL(set_connect_attr, SQLSetConnectAttr)
    SAT_ODBC_SYMBOL(driver_connect_a, SQLDriverConnectA)
    SAT_ODBC_SYMBOL(exec_direct_a, SQLExecDirectA)
    SAT_ODBC_SYMBOL(cancel, SQLCancel)
    SAT_ODBC_SYMBOL(num_result_cols, SQLNumResultCols)
    SAT_ODBC_SYMBOL(describe_col_a, SQLDescribeColA)
    SAT_ODBC_SYMBOL(fetch, SQLFetch)
    SAT_ODBC_SYMBOL(more_results, SQLMoreResults)
    SAT_ODBC_SYMBOL(disconnect, SQLDisconnect)
#undef SAT_ODBC_SYMBOL
    return value;
  }();
  return *api;
}

class OdbcHandle {
public:
  OdbcHandle() = default;
  OdbcHandle(const OdbcApi* api, SQLSMALLINT type, SQLHANDLE value)
      : api_(api), type_(type), value_(value) {}
  ~OdbcHandle() {
    reset();
  }
  OdbcHandle(const OdbcHandle&) = delete;
  OdbcHandle& operator=(const OdbcHandle&) = delete;
  OdbcHandle(OdbcHandle&& other) noexcept
      : api_(other.api_), type_(other.type_), value_(other.release()) {}
  OdbcHandle& operator=(OdbcHandle&& other) noexcept {
    if (this != &other) {
      reset();
      api_ = other.api_;
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
    if (value_ != SQL_NULL_HANDLE && api_ != nullptr && api_->free_handle != nullptr)
      static_cast<void>(api_->free_handle(type_, value_));
    value_ = replacement;
  }

private:
  const OdbcApi* api_ = nullptr;
  SQLSMALLINT type_ = 0;
  SQLHANDLE value_ = SQL_NULL_HANDLE;
};

bool succeeded(SQLRETURN result) noexcept {
  return result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO;
}

std::string diagnostics(const OdbcApi& api, SQLSMALLINT type, SQLHANDLE handle) {
  std::ostringstream output;
  std::array<SQLCHAR, 6> state{};
  std::array<SQLCHAR, 2048> message{};
  SQLINTEGER native_code = 0;
  SQLSMALLINT length = 0;
  for (SQLSMALLINT record = 1;; ++record) {
    const SQLRETURN result = api.get_diag_rec_a(type,
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

Error odbc_error(const OdbcApi* api,
                 std::string operation,
                 std::string source,
                 std::string message,
                 SQLSMALLINT type = 0,
                 SQLHANDLE handle = SQL_NULL_HANDLE) {
  Error error;
  error.component = "SQL ODBC";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  if (api != nullptr && api->loaded() && type != 0 && handle != SQL_NULL_HANDLE) {
    const std::string detail = diagnostics(*api, type, handle);
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

std::string read_column(const OdbcApi& api, SQLHSTMT statement, SQLUSMALLINT column) {
  std::string output;
  std::array<char, 4096> buffer{};
  SQLLEN indicator = 0;
  for (;;) {
    const SQLRETURN result = api.get_data(statement,
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

Result<OdbcHandle> allocate_handle(const OdbcApi& api,
                                   SQLSMALLINT type,
                                   SQLHANDLE parent,
                                   std::string_view operation) {
  SQLHANDLE raw = SQL_NULL_HANDLE;
  const SQLRETURN result = api.alloc_handle(type, parent, &raw);
  if (!succeeded(result)) {
    return Result<OdbcHandle>::failure(
        odbc_error(&api, std::string(operation), {}, "SQLAllocHandle failed"));
  }
  return Result<OdbcHandle>::success(OdbcHandle(&api, type, raw));
}

} // namespace

Result<ProcessResult> run_sql_permission_diagnostic_odbc(const SqlPermissionOptions& options,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress) {
  const OdbcApi& api = odbc_api();
  if (!api.loaded()) {
    return Result<ProcessResult>::failure(odbc_error(
        nullptr,
        "load runtime",
        {},
        "ODBC is optional and its driver manager is not available. SAT remains usable; "
        "install or place a compatible unixODBC/iODBC runtime beside SAT only when SQL Tools "
        "are required. Loader detail: " +
            api.load_error));
  }

  if (options.server.empty()) {
    return Result<ProcessResult>::failure(
        odbc_error(&api, "connect", {}, "A SQL Server instance is required"));
  }
  if (options.principal.empty()) {
    return Result<ProcessResult>::failure(
        odbc_error(&api, "permission diagnostic", options.server, "A principal name is required"));
  }
  if (!options.trusted_connection && options.connection_string.empty()) {
    return Result<ProcessResult>::failure(odbc_error(
        &api,
        "connect",
        options.server,
        "Non-integrated authentication requires an explicit ODBC connection string"));
  }

  auto environment_result =
      allocate_handle(api, SQL_HANDLE_ENV, SQL_NULL_HANDLE, "allocate environment");
  if (!environment_result.ok())
    return Result<ProcessResult>::failure(environment_result.error());
  OdbcHandle environment = std::move(environment_result.value());
  if (!succeeded(api.set_env_attr(static_cast<SQLHENV>(environment.get()),
                                  SQL_ATTR_ODBC_VERSION,
                                  reinterpret_cast<SQLPOINTER>(
                                      static_cast<std::uintptr_t>(SQL_OV_ODBC3)),
                                  0))) {
    return Result<ProcessResult>::failure(odbc_error(&api,
                                                     "configure environment",
                                                     options.server,
                                                     "SQLSetEnvAttr failed",
                                                     SQL_HANDLE_ENV,
                                                     environment.get()));
  }

  auto connection_result =
      allocate_handle(api, SQL_HANDLE_DBC, environment.get(), "allocate connection");
  if (!connection_result.ok())
    return Result<ProcessResult>::failure(connection_result.error());
  OdbcHandle connection = std::move(connection_result.value());
  static_cast<void>(api.set_connect_attr(
      static_cast<SQLHDBC>(connection.get()),
      SQL_LOGIN_TIMEOUT,
      reinterpret_cast<SQLPOINTER>(static_cast<std::uintptr_t>(15)),
      0));

  std::string failures;
  bool connected = false;
  for (const std::string& candidate : connection_candidates(options)) {
    if (cancel.is_cancelled()) {
      return Result<ProcessResult>::failure(
          odbc_error(&api, "connect", options.server, "Operation cancelled"));
    }
    publish(progress, "Connecting through ODBC", options.server);
    const SQLRETURN result = api.driver_connect_a(
        static_cast<SQLHDBC>(connection.get()),
        nullptr,
        reinterpret_cast<SQLCHAR*>(const_cast<char*>(candidate.c_str())),
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
    failures += diagnostics(api, SQL_HANDLE_DBC, connection.get());
  }
  if (!connected) {
    return Result<ProcessResult>::failure(odbc_error(
        &api, "connect", options.server, "No installed SQL Server ODBC driver connected: " + failures));
  }

  auto statement_result =
      allocate_handle(api, SQL_HANDLE_STMT, connection.get(), "allocate statement");
  if (!statement_result.ok())
    return Result<ProcessResult>::failure(statement_result.error());
  OdbcHandle statement = std::move(statement_result.value());
  const std::string script = make_sql_permission_diagnostic_script(
      options.principal, options.include_database_permissions);
  publish(progress, "Executing permission diagnostic", options.principal);
  SQLRETURN result = api.exec_direct_a(static_cast<SQLHSTMT>(statement.get()),
                                       reinterpret_cast<SQLCHAR*>(
                                           const_cast<char*>(script.c_str())),
                                       SQL_NTS);
  if (!succeeded(result)) {
    return Result<ProcessResult>::failure(odbc_error(&api,
                                                     "execute permission diagnostic",
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
  text << "Connection: native ODBC (runtime loaded: " << api.library_name << ")\n"
       << "Server: " << options.server << "\n"
       << "Database: " << options.database << "\n"
       << "Principal: " << options.principal << "\n\n";

  std::uint64_t total_rows = 0;
  std::uint32_t result_set = 0;
  for (;;) {
    if (cancel.is_cancelled()) {
      static_cast<void>(api.cancel(static_cast<SQLHSTMT>(statement.get())));
      output.cancelled = true;
      output.exit_code = 130;
      break;
    }
    SQLSMALLINT column_count = 0;
    result = api.num_result_cols(static_cast<SQLHSTMT>(statement.get()), &column_count);
    if (!succeeded(result)) {
      return Result<ProcessResult>::failure(odbc_error(&api,
                                                       "inspect result set",
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
        const SQLRETURN describe = api.describe_col_a(static_cast<SQLHSTMT>(statement.get()),
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
      while ((result = api.fetch(static_cast<SQLHSTMT>(statement.get()))) != SQL_NO_DATA) {
        if (!succeeded(result)) {
          return Result<ProcessResult>::failure(odbc_error(&api,
                                                           "fetch result row",
                                                           options.server,
                                                           "SQLFetch failed",
                                                           SQL_HANDLE_STMT,
                                                           statement.get()));
        }
        for (SQLUSMALLINT column = 1; column <= static_cast<SQLUSMALLINT>(column_count); ++column) {
          if (column != 1)
            text << " | ";
          text << read_column(api, static_cast<SQLHSTMT>(statement.get()), column);
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
    result = api.more_results(static_cast<SQLHSTMT>(statement.get()));
    if (result == SQL_NO_DATA)
      break;
    if (!succeeded(result)) {
      return Result<ProcessResult>::failure(odbc_error(&api,
                                                       "advance result set",
                                                       options.server,
                                                       "SQLMoreResults failed",
                                                       SQL_HANDLE_STMT,
                                                       statement.get()));
    }
  }

  output.output = text.str();
  static_cast<void>(api.disconnect(static_cast<SQLHDBC>(connection.get())));
  return Result<ProcessResult>::success(std::move(output));
}

Result<SqlBatchResult> run_sql_statements(const SqlConnection& connection, const std::vector<std::string>& statements,
                                          const CancellationToken& cancel, ProgressCallback progress) {
  const OdbcApi& api = odbc_api();
  if (!api.loaded()) {
    Error error;
    error.component = "SQL ODBC";
    error.operation = "connect";
    error.source = connection.server;
    error.message = "The ODBC driver manager was not loaded (" + api.load_error +
                    "). Install unixODBC and Microsoft's ODBC Driver for SQL Server.";
    return Result<SqlBatchResult>::failure(std::move(error));
  }
  return sql_batch_detail::run_batch(api, connection, statements, cancel, progress);
}

} // namespace support_assist
