#pragma once

// SQL Tools for PostgreSQL: the same five read-only checks as SQL Server (permissions, server shape,
// backups and the log chain, database files, a read-only query), run through psql. The statements
// are SELECTs over the system catalogs and statistics views. Every psql run starts by making the
// session read only and confirming it. The password goes to psql only in its environment
// (PGPASSWORD), never on the command line. The requirements Veeam's pages state, the sources and the
// named queries are data (config/checks/postgres-checks.json). Results use the types of
// support_assist/sql_check.hpp, so both engines share the report rows and the result table.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/sql_check.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct PostgresConnection {
  std::string host = "localhost";
  int port = 5432;
  std::string database = "postgres";
  bool integrated = true;           // no password: psql uses the account running SAT, as pg_hba.conf allows
  std::string user;                 // the role to connect as; empty with integrated lets psql choose
  std::string password;             // in memory for the run only; passed as PGPASSWORD
  std::filesystem::path tools_folder; // where SAT keeps psql; the PATH and install folders are searched too
};

// A connection from the server field ("host" or "host:port"), the login choice and the database
// ("postgres" when empty). The failure says what to enter.
Result<PostgresConnection> make_postgres_connection(std::string_view server, bool use_logged_in_user,
                                                    const std::string& login, const std::string& password,
                                                    const std::string& database,
                                                    const std::filesystem::path& tools_folder = {});
// Why a connection cannot be used (control characters, a database name psql would read as a
// connection string, no login without Use logged-in user), or nullopt.
std::optional<std::string> postgres_connection_problem(const PostgresConnection& connection);
// The role psql connects as. With Use logged-in user and no role given, a Windows host connects as
// the role Veeam's installer maps its Windows accounts to; elsewhere psql's own default applies.
std::string postgres_role_for(const PostgresConnection& connection, bool windows);

// ------------------------------------------------------------------------------------- running psql

// Runs the statements over one psql session per attempt. A statement that fails records its error
// and the rest run again in a new session. A missing psql or a connection that cannot be made is a
// failure that says so in plain words.
Result<SqlBatchResult> run_postgres_statements(const PostgresConnection& connection,
                                               const std::vector<std::string>& statements,
                                               const CancellationToken& cancel, ProgressCallback progress = {});

// The psql arguments for the statements from first_statement on: no startup file, unaligned
// output with 0x1F between fields, a zero byte after each record, column headers, no footer, NULL
// shown as 0x1A, stop at the first error, never ask for a password. The session is made read only
// and confirmed before the first statement, and each statement follows a marker that names it.
std::vector<std::string> postgres_psql_arguments(const PostgresConnection& connection,
                                                 const std::vector<std::string>& statements, std::string_view token,
                                                 std::size_t first_statement, bool windows);
// The environment for psql: PGPASSWORD (empty for the logged-in user, so none inherited is used),
// UTF-8 output, the connect timeout and the application name.
std::vector<std::pair<std::string, std::string>> postgres_psql_environment(const PostgresConnection& connection);

// What psql printed, split by the markers. The statements are in the order their markers appeared;
// each holds one result set (columns, rows, NULL as nullopt) or none.
struct PostgresParsedOutput {
  std::vector<std::pair<std::size_t, SqlStatementResult>> statements; // statement index, result
  bool read_only_confirmed = false;
  bool truncated = false; // the output ended inside a record or a set passed the row limit
};
PostgresParsedOutput parse_postgres_output(std::string_view output, std::string_view token);

// The error lines of psql's standard error (ERROR, FATAL, DETAIL, HINT) without the statement echo
// and the caret line, joined with " | ".
std::string postgres_error_text(std::string_view standard_error);
// A plain sentence for a connection that was not made, with psql's own line after it.
std::string postgres_connection_failure(std::string_view standard_error, const PostgresConnection& connection);

// PostgreSQL text for a statement: 'text' with quotes and backslashes doubled, so it reads the same
// whatever standard_conforming_strings is. Control characters are left out.
std::string postgres_string_literal(std::string_view text);

// ------------------------------------------------------------------------------------- checks

struct PostgresPermissionOptions {
  std::string another_account;        // empty: the connected role
  std::string configuration_database; // empty: the name Veeam uses unless told otherwise
};
// The configuration database's name when none is given: the Veeam registry's, when this is the
// backup server and it uses PostgreSQL, else the default in the data file.
std::string postgres_default_configuration_database();
std::vector<std::string> postgres_permission_statements(const PostgresPermissionOptions& options);
SqlCheckReport evaluate_postgres_permissions(const SqlBatchResult& batch, const PostgresConnection& connection,
                                             const PostgresPermissionOptions& options);

std::vector<std::string> postgres_shape_statements();
SqlCheckReport evaluate_postgres_shape(const SqlBatchResult& batch);

std::vector<std::string> postgres_backup_statements();
SqlCheckReport evaluate_postgres_backups(const SqlBatchResult& batch);

// Where the data directory, the tablespaces and the databases are. When SAT runs on the PostgreSQL
// host, each path's volume is classified with Volume Check.
std::vector<std::string> postgres_files_statements();
SqlCheckReport evaluate_postgres_files(const SqlBatchResult& batch, bool on_this_host);

// The read-only query: sql_query_refusal's rules, plus the PostgreSQL functions that act on the
// server (ending sessions, reloading, switching WAL, large objects, reading files) and the
// quoting forms whose reading differs from a plain string (E'...' and $$...$$). The reason it is
// refused, or nullopt. The session is read only as well.
std::optional<std::string> postgres_query_refusal(std::string_view text);
const std::vector<SqlNamedQuery>& postgres_named_queries();

} // namespace support_assist
