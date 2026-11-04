#include "support_assist/sql_tools.hpp"
#include "support_assist/secure_temp.hpp"

#include "sql_odbc.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/uuid.hpp"

#include <fstream>
#include <optional>
#include <sstream>

namespace support_assist {
namespace {

Error sql_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "SQL";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

std::string sql_literal(std::string_view value) {
  std::string output;
  output.reserve(value.size() + 2U);
  output.push_back('N');
  output.push_back('\'');
  for (const char c : value) {
    if (c == '\'')
      output += "''";
    else
      output.push_back(c);
  }
  output.push_back('\'');
  return output;
}

} // namespace

std::string make_sql_permission_diagnostic_script(std::string_view principal,
                                                  bool include_database_permissions) {
  const std::string principal_literal = sql_literal(principal);
  std::ostringstream script;
  script << "SET NOCOUNT ON;\n"
         << "DECLARE @Principal sysname = " << principal_literal << ";\n"
         << "SELECT @@SERVERNAME AS server_name, DB_NAME() AS database_name, "
            "SUSER_SNAME() AS connected_login, ORIGINAL_LOGIN() AS original_login;\n"
         << "SELECT sp.name, sp.type_desc, sp.is_disabled, sp.default_database_name\n"
         << "FROM sys.server_principals AS sp WHERE sp.name = @Principal;\n"
         << "SELECT role_name = rp.name, member_name = mp.name\n"
         << "FROM sys.server_role_members AS srm\n"
         << "JOIN sys.server_principals AS rp ON rp.principal_id = srm.role_principal_id\n"
         << "JOIN sys.server_principals AS mp ON mp.principal_id = srm.member_principal_id\n"
         << "WHERE mp.name = @Principal ORDER BY rp.name;\n"
         << "SELECT permission_scope = 'SERVER', permission_name = perm.permission_name, "
            "state_desc = perm.state_desc, securable = COALESCE(OBJECT_NAME(perm.major_id), '')\n"
         << "FROM sys.server_permissions AS perm\n"
         << "JOIN sys.server_principals AS sp ON sp.principal_id = perm.grantee_principal_id\n"
         << "WHERE sp.name = @Principal ORDER BY perm.permission_name;\n";
  if (include_database_permissions) {
    script << "SELECT dp.name, dp.type_desc, dp.authentication_type_desc\n"
           << "FROM sys.database_principals AS dp WHERE dp.name = @Principal;\n"
           << "SELECT role_name = rp.name, member_name = mp.name\n"
           << "FROM sys.database_role_members AS drm\n"
           << "JOIN sys.database_principals AS rp ON rp.principal_id = drm.role_principal_id\n"
           << "JOIN sys.database_principals AS mp ON mp.principal_id = drm.member_principal_id\n"
           << "WHERE mp.name = @Principal ORDER BY rp.name;\n"
           << "SELECT permission_scope = perm.class_desc, permission_name = perm.permission_name, "
              "state_desc = perm.state_desc, securable = "
              "CASE WHEN perm.major_id = 0 THEN DB_NAME() ELSE OBJECT_SCHEMA_NAME(perm.major_id) + "
              "'.' + OBJECT_NAME(perm.major_id) END\n"
           << "FROM sys.database_permissions AS perm\n"
           << "JOIN sys.database_principals AS dp ON dp.principal_id = perm.grantee_principal_id\n"
           << "WHERE dp.name = @Principal ORDER BY perm.class_desc, perm.permission_name;\n";
  }
  script << "SELECT permission_name, result = HAS_PERMS_BY_NAME(NULL, 'SERVER', permission_name)\n"
         << "FROM (VALUES ('CONNECT SQL'), ('VIEW SERVER STATE'), ('ALTER ANY DATABASE'), "
            "('CONTROL SERVER')) AS checks(permission_name);\n";
  return script.str();
}

Result<std::filesystem::path> write_sql_permission_script(const SqlPermissionOptions& options) {
  if (options.principal.empty()) {
    return Result<std::filesystem::path>::failure(
        sql_error("write permission script", {}, "A principal name is required"));
  }
  std::filesystem::path output = options.output_file;
  if (output.empty()) {
    // SAT-SEC-03: owner-only, exclusively created, in the SAT-owned temporary directory.
    auto script_file = create_secure_temp_file("support-assist-sql-permissions", ".sql");
    if (!script_file.ok())
      return Result<std::filesystem::path>::failure(script_file.error());
    // The caller keeps this script, so release ownership instead of deleting on scope exit.
    output = script_file.value().release();
  }
  std::ofstream file(output, std::ios::binary | std::ios::trunc);
  if (!file) {
    return Result<std::filesystem::path>::failure(
        sql_error("write permission script", path_to_utf8(output), "Could not create SQL script"));
  }
  file << make_sql_permission_diagnostic_script(options.principal,
                                                options.include_database_permissions);
  if (!file) {
    return Result<std::filesystem::path>::failure(
        sql_error("write permission script", path_to_utf8(output), "Failed while writing SQL script"));
  }
  return Result<std::filesystem::path>::success(output);
}

Result<ProcessResult> run_sql_permission_diagnostic(const SqlPermissionOptions& options,
                                                    const CancellationToken& cancel,
                                                    ProgressCallback progress) {
  if (options.server.empty()) {
    return Result<ProcessResult>::failure(
        sql_error("run permission diagnostic", {}, "A SQL Server instance is required"));
  }

  std::optional<Error> native_error;
  if (options.prefer_native_odbc && options.sqlcmd_path.empty()) {
    auto native = run_sql_permission_diagnostic_odbc(options, cancel, progress);
    if (native.ok())
      return native;
    // An explicit connection string means the caller selected ODBC and should
    // receive the ODBC diagnostic instead of silently changing transports.
    if (!options.connection_string.empty())
      return native;
    native_error = native.error();
  }

  auto script = write_sql_permission_script(options);
  if (!script.ok())
    return Result<ProcessResult>::failure(script.error());

  std::filesystem::path sqlcmd = options.sqlcmd_path;
  if (sqlcmd.empty()) {
    auto resolved = resolve_external_tool("sqlcmd", options.third_party_directory);
    if (!resolved.ok()) {
      if (native_error) {
        native_error->message +=
            ". The optional SQLCMD fallback was also unavailable: " + resolved.error().message;
        return Result<ProcessResult>::failure(std::move(*native_error));
      }
      return Result<ProcessResult>::failure(resolved.error());
    }
    sqlcmd = std::move(resolved.value());
  }

  ProcessOptions process;
  process.executable = sqlcmd;
  process.arguments = {"-S",
                       options.server,
                       "-d",
                       options.database,
                       "-i",
                       path_to_utf8(script.value()),
                       "-W",
                       "-w",
                       "65535"};
  if (options.trusted_connection)
    process.arguments.push_back("-E");
  process.timeout = std::chrono::minutes(5);
  auto result = run_process_capture(process, cancel, std::move(progress));
  if (options.output_file.empty()) {
    std::error_code ignored;
    std::filesystem::remove(script.value(), ignored);
  }
  return result;
}

} // namespace support_assist
