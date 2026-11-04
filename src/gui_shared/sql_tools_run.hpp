#pragma once

// SQL Tools' operations for both editions: the form's fields to a connection and a check, the
// check run, and the rows the result table shows. Windows and Linux pass their field text and
// get the same rows back (support_assist/sql_check.hpp does the work for SQL Server over ODBC,
// support_assist/postgres_check.hpp for PostgreSQL through psql).

#include "field_choices.hpp"
#include "support_assist/cancellation.hpp"
#include "support_assist/postgres_check.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/sql_catalog.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

namespace support_assist::gui {

// The operations' modes, the same on both editions.
inline constexpr int kSqlPermissionCheck = 0;
inline constexpr int kSqlServerShape = 1;
inline constexpr int kSqlBackups = 2;
inline constexpr int kSqlFiles = 3;
inline constexpr int kSqlQuery = 4;

inline constexpr const char* kSqlGuestProcessing = "Guest processing";
inline constexpr const char* kSqlConfigurationDatabase = "Configuration database";

struct SqlToolsForm {
  int mode = kSqlPermissionCheck;
  // SQL Server: the server or "HOST\INSTANCE". PostgreSQL: "host" or "host:port".
  std::string server;
  // Permission check: check against, configuration database, another account.
  // Backups: database, days. Query: database, query.
  // PostgreSQL: the permission check takes the configuration database in third and another role in
  // fourth (second is not used), and the query takes the database in second and the text in third.
  std::string second;
  std::string third;
  std::string fourth;
  bool use_logged_in_user = true;
  bool trust_server_certificate = false; // SQL Server only
  std::string login;
  std::string password;
  SqlEngine engine = SqlEngine::sql_server;
  std::filesystem::path tools_folder; // PostgreSQL: where SAT keeps psql, searched before the PATH
};

struct SqlToolsRow {
  std::string area;
  std::string check;
  std::string detail;
  std::string status;
};

struct SqlToolsOutcome {
  bool ok = false;
  std::string summary; // the status line
  std::string error;   // why it did not run
  std::vector<SqlToolsRow> rows;
};

namespace sql_tools_detail {

// A Read-only query the guard refused: the output names the query, says it did not run and why, and the
// status line carries the reason.
inline SqlToolsOutcome refused_query(std::string_view statement, const std::string& reason) {
  SqlToolsOutcome outcome;
  outcome.error = reason;
  std::string why = reason;
  if (why.rfind("Not run: ", 0) == 0) {
    why = why.substr(9);
    if (!why.empty())
      why[0] = static_cast<char>(std::toupper(static_cast<unsigned char>(why[0])));
  }
  outcome.rows.push_back({sql_query_one_line(statement), "Not run", why, "Fail"});
  return outcome;
}

inline std::vector<SqlToolsRow> rows_of(const SqlCheckReport& report) {
  std::vector<SqlToolsRow> rows;
  for (const SqlCheckRow& row : report.rows) {
    std::string detail = row.detail;
    if (!row.source.empty())
      detail += "  " + row.source;
    rows.push_back({row.area, row.check, detail, to_string(row.status)});
  }
  return rows;
}

inline std::string summary_of(const SqlCheckReport& report, const std::string& name) {
  std::size_t failed = 0;
  std::size_t attention = 0;
  for (const SqlCheckRow& row : report.rows) {
    failed += row.status == SqlCheckStatus::fail ? 1U : 0U;
    attention += row.status == SqlCheckStatus::attention ? 1U : 0U;
  }
  if (failed == 0U && attention == 0U)
    return name + ": nothing to act on";
  return name + ": " + std::to_string(failed) + " failed, " + std::to_string(attention) + " to look at";
}

} // namespace sql_tools_detail

// The statement a Query field names: a named query of the engine by its name, else the text as typed.
// The field keeps the name, so it reads as the name; the command line takes the name as well.
inline std::string sql_query_statement(std::string_view field, SqlEngine engine) {
  const std::string text(trim(field));
  const auto& named = engine == SqlEngine::postgresql ? postgres_named_queries() : sql_named_queries();
  for (const SqlNamedQuery& query : named) {
    if (query.name == text)
      return query.text;
  }
  return text;
}

// The Edit query window's example: rows from the database chosen in the form, in an order, each part
// on its own line so the columns, the table and the order are easy to change. It runs as it is.
inline std::string sql_query_example(SqlEngine engine) {
  if (engine == SqlEngine::postgresql)
    return "SELECT table_schema, table_name\n"
           "FROM information_schema.tables\n"
           "WHERE table_schema NOT IN ('pg_catalog', 'information_schema')\n"
           "ORDER BY table_schema, table_name\n"
           "LIMIT 50";
  return "SELECT TOP (50) name, create_date, modify_date\n"
         "FROM sys.tables\n"
         "ORDER BY modify_date DESC";
}

// What the Edit query window shows first: the example while the Query field is empty or holds the
// form's starting query, otherwise the field's own statement (a named query's SQL, or what was typed).
inline std::string sql_query_editor_text(std::string_view field, SqlEngine engine) {
  const std::string text(trim(field));
  if (text.empty() || text == sql_default_query(engine))
    return sql_query_example(engine);
  return sql_query_statement(text, engine);
}

// The statements the form's operation runs, in order, for the form's engine: the same lists the
// runner and the CLI build. A Read-only query is the engine's statement for a named query, or the
// text as typed.
inline std::vector<std::string> sql_tools_cli_statements(const SqlToolsForm& form) {
  if (form.mode == kSqlQuery) {
    const std::string text = sql_query_statement(form.third, form.engine);
    return text.empty() ? std::vector<std::string>{} : std::vector<std::string>{text};
  }
  if (form.engine == SqlEngine::postgresql) {
    switch (form.mode) {
    case kSqlPermissionCheck: {
      PostgresPermissionOptions permissions;
      permissions.configuration_database = std::string(trim(form.third));
      permissions.another_account = std::string(trim(form.fourth));
      return postgres_permission_statements(permissions);
    }
    case kSqlServerShape:
      return postgres_shape_statements();
    case kSqlBackups:
      return postgres_backup_statements();
    case kSqlFiles:
      return postgres_files_statements();
    default:
      return {};
    }
  }
  switch (form.mode) {
  case kSqlPermissionCheck: {
    SqlPermissionCheckOptions permissions;
    permissions.target = form.second == kSqlConfigurationDatabase ? SqlPermissionTarget::configuration_database
                                                                  : SqlPermissionTarget::guest_processing;
    permissions.configuration_database = std::string(trim(form.third));
    permissions.another_account = std::string(trim(form.fourth));
    return sql_permission_statements(permissions);
  }
  case kSqlServerShape:
    return sql_shape_statements();
  case kSqlBackups: {
    SqlBackupOptions backups;
    backups.database = std::string(trim(form.second));
    backups.days = std::atoi(std::string(trim(form.third)).c_str());
    if (backups.days <= 0)
      backups.days = 14;
    backups.veeam_on_sql_host = veeam_installed_on_sql_host(trim(form.server));
    return sql_backup_statements(backups);
  }
  case kSqlFiles:
    return sql_files_statements();
  default:
    return {};
  }
}

// Show CLI's SQL section: the statements the command runs, under the engine's name, each as it is
// sent, so they can be read or pasted into SSMS, sqlcmd or psql. A query that would not run says
// why at the end. Lines end in '\n'.
inline std::string sql_tools_cli_sql_text(const SqlToolsForm& form) {
  const std::vector<std::string> statements = sql_tools_cli_statements(form);
  if (statements.empty())
    return {};
  const std::string heading = "SQL IT RUNS (" + sql_engine_name(form.engine) + ")";
  std::string text = heading + "\n" + std::string(heading.size(), '=') + "\n";
  for (std::size_t index = 0; index < statements.size(); ++index) {
    if (statements.size() > 1U)
      text += "-- " + std::to_string(index + 1U) + "\n";
    text += statements[index] + "\n";
    if (index + 1U < statements.size())
      text += "\n";
  }
  if (form.mode == kSqlQuery) {
    const auto refusal = form.engine == SqlEngine::postgresql ? postgres_query_refusal(statements.front())
                                                              : sql_query_refusal(statements.front());
    if (refusal)
      text += "\n" + *refusal + "\n";
  }
  return text;
}

// The CLI's arguments for the form, for Show CLI ("sql check --server ..."), with --show-sql so the
// command also prints the SQL it runs. A Read-only query goes on the command line as the engine's
// statement on one line, not by a named query's name. The password never appears: the CLI reads it
// from SQLCMDPASSWORD (SQL Server) or PGPASSWORD (PostgreSQL).
inline std::vector<std::string> sql_tools_cli_arguments(const SqlToolsForm& form) {
  std::vector<std::string> arguments;
  if (trim(form.server).empty())
    return arguments;
  const char* verbs[] = {"check", "shape", "backups", "files", "query"};
  arguments = {"sql", verbs[std::clamp(form.mode, 0, 4)], "--server", std::string(trim(form.server))};
  auto add = [&arguments](const char* option, const std::string& value) {
    if (!trim(value).empty()) {
      arguments.push_back(option);
      arguments.push_back(std::string(trim(value)));
    }
  };
  if (form.engine == SqlEngine::postgresql) {
    arguments.push_back("--engine");
    arguments.push_back("postgres");
    if (form.mode == kSqlPermissionCheck) {
      add("--config-database", form.third);
      add("--account", form.fourth);
    } else if (form.mode == kSqlQuery) {
      add("--database", form.second);
      add("--query", sql_query_one_line(sql_query_statement(form.third, form.engine)));
    }
    if (!form.use_logged_in_user)
      add("--login", form.login.empty() ? std::string("LOGIN") : form.login);
    arguments.push_back("--show-sql");
    return arguments;
  }
  if (form.mode == kSqlPermissionCheck) {
    if (form.second == kSqlConfigurationDatabase) {
      arguments.push_back("--against");
      arguments.push_back("config");
      add("--config-database", form.third);
    }
    add("--account", form.fourth);
  } else if (form.mode == kSqlBackups) {
    add("--database", form.second);
    add("--days", form.third);
  } else if (form.mode == kSqlQuery) {
    add("--database", form.second);
    add("--query", sql_query_one_line(sql_query_statement(form.third, form.engine)));
  }
  if (!form.use_logged_in_user)
    add("--login", form.login.empty() ? std::string("LOGIN") : form.login);
  if (form.trust_server_certificate)
    arguments.push_back("--trust-certificate");
  arguments.push_back("--show-sql");
  return arguments;
}

// The PostgreSQL branch of the form: the same five operations through psql.
inline SqlToolsOutcome run_postgres_tools_form(const SqlToolsForm& form, const CancellationToken& cancel,
                                               ProgressCallback progress = {}) {
  SqlToolsOutcome outcome;
  if (trim(form.server).empty()) {
    outcome.error = "Enter the PostgreSQL server (host or host:port), or choose one of this machine's instances.";
    return outcome;
  }
  const std::string database = form.mode == kSqlQuery ? std::string(trim(form.second)) : std::string();
  auto made = make_postgres_connection(form.server, form.use_logged_in_user, form.login, form.password, database,
                                       form.tools_folder);
  if (!made.ok()) {
    outcome.error = made.error().message;
    return outcome;
  }
  PostgresConnection connection = std::move(made.value());

  std::vector<std::string> statements;
  PostgresPermissionOptions permissions;
  std::string name;
  switch (form.mode) {
  case kSqlPermissionCheck:
    permissions.configuration_database = std::string(trim(form.third));
    permissions.another_account = std::string(trim(form.fourth));
    statements = postgres_permission_statements(permissions);
    name = "Permission check";
    break;
  case kSqlServerShape:
    statements = postgres_shape_statements();
    name = "Server shape";
    break;
  case kSqlBackups:
    statements = postgres_backup_statements();
    name = "Backups and log chain";
    break;
  case kSqlFiles:
    statements = postgres_files_statements();
    name = "Database files";
    break;
  case kSqlQuery: {
    const std::string text = sql_query_statement(form.third, SqlEngine::postgresql);
    if (text.empty()) {
      outcome.error = "Enter a query, or choose one of the named queries.";
      return outcome;
    }
    if (const auto refusal = postgres_query_refusal(text))
      return sql_tools_detail::refused_query(text, *refusal);
    statements = {text};
    name = "Query";
    break;
  }
  default:
    outcome.error = "Unknown SQL Tools operation.";
    return outcome;
  }

  auto batch = run_postgres_statements(connection, statements, cancel, std::move(progress));
  std::fill(connection.password.begin(), connection.password.end(), '\0');
  if (!batch.ok()) {
    outcome.error = describe_error(batch.error());
    return outcome;
  }
  SqlCheckReport report;
  switch (form.mode) {
  case kSqlPermissionCheck:
    report = evaluate_postgres_permissions(batch.value(), connection, permissions);
    break;
  case kSqlServerShape:
    report = evaluate_postgres_shape(batch.value());
    break;
  case kSqlBackups:
    report = evaluate_postgres_backups(batch.value());
    break;
  case kSqlFiles:
    report = evaluate_postgres_files(batch.value(), sql_server_is_this_host(connection.host));
    break;
  default:
    report = sql_query_rows(batch.value());
    break;
  }
  outcome.ok = true;
  outcome.rows = sql_tools_detail::rows_of(report);
  outcome.summary = form.mode == kSqlQuery
                        ? "Query: " + std::to_string(report.rows.size()) + " values read through " + batch.value().driver
                        : sql_tools_detail::summary_of(report, name);
  if (batch.value().cancelled)
    outcome.summary += " (cancelled)";
  return outcome;
}

inline SqlToolsOutcome run_sql_tools_form(const SqlToolsForm& form, const CancellationToken& cancel,
                                          ProgressCallback progress = {}) {
  // A Read-only query that is refused says so before anything else is asked of the form: it never
  // connects, so the server and the login do not matter.
  if (form.mode == kSqlQuery) {
    const std::string text = sql_query_statement(form.third, form.engine);
    if (!text.empty()) {
      const auto refusal = form.engine == SqlEngine::postgresql ? postgres_query_refusal(text) : sql_query_refusal(text);
      if (refusal)
        return sql_tools_detail::refused_query(text, *refusal);
    }
  }
  if (form.engine == SqlEngine::postgresql)
    return run_postgres_tools_form(form, cancel, std::move(progress));
  SqlToolsOutcome outcome;
  SqlConnection connection;
  connection.server = std::string(trim(form.server));
  if (connection.server.empty()) {
    outcome.error = "Enter the SQL Server, or choose one of this machine's instances.";
    return outcome;
  }
  connection.integrated = form.use_logged_in_user;
  connection.login = form.login;
  connection.password = form.password;
  connection.trust_server_certificate = form.trust_server_certificate;
  if (!connection.integrated && connection.login.empty()) {
    outcome.error = "Enter the SQL login, or tick Use logged-in user.";
    return outcome;
  }

  std::vector<std::string> statements;
  SqlPermissionCheckOptions permissions;
  SqlBackupOptions backups;
  std::string name;
  switch (form.mode) {
  case kSqlPermissionCheck:
    permissions.target = form.second == kSqlConfigurationDatabase ? SqlPermissionTarget::configuration_database
                                                                  : SqlPermissionTarget::guest_processing;
    permissions.configuration_database = std::string(trim(form.third));
    permissions.another_account = std::string(trim(form.fourth));
    statements = sql_permission_statements(permissions);
    name = "Permission check";
    break;
  case kSqlServerShape:
    statements = sql_shape_statements();
    name = "Server shape";
    break;
  case kSqlBackups:
    backups.database = std::string(trim(form.second));
    backups.days = std::atoi(std::string(trim(form.third)).c_str());
    if (backups.days <= 0)
      backups.days = 14;
    backups.veeam_on_sql_host = veeam_installed_on_sql_host(connection.server);
    statements = sql_backup_statements(backups);
    connection.database = "msdb";
    name = "Backups and log chain";
    break;
  case kSqlFiles:
    statements = sql_files_statements();
    name = "Database files";
    break;
  case kSqlQuery: {
    const std::string text = sql_query_statement(form.third, SqlEngine::sql_server);
    if (text.empty()) {
      outcome.error = "Enter a query, or choose one of the named queries.";
      return outcome;
    }
    if (const auto refusal = sql_query_refusal(text))
      return sql_tools_detail::refused_query(text, *refusal);
    if (!trim(form.second).empty())
      connection.database = std::string(trim(form.second));
    statements = {text};
    name = "Query";
    break;
  }
  default:
    outcome.error = "Unknown SQL Tools operation.";
    return outcome;
  }

  auto batch = run_sql_statements(connection, statements, cancel, std::move(progress));
  std::fill(connection.password.begin(), connection.password.end(), '\0');
  if (!batch.ok()) {
    outcome.error = describe_error(batch.error());
    return outcome;
  }
  SqlCheckReport report;
  switch (form.mode) {
  case kSqlPermissionCheck:
    report = evaluate_sql_permissions(batch.value(), connection, permissions);
    break;
  case kSqlServerShape:
    report = evaluate_sql_shape(batch.value());
    break;
  case kSqlBackups:
    report = evaluate_sql_backups(batch.value(), backups);
    break;
  case kSqlFiles:
    report = evaluate_sql_files(batch.value(), sql_server_is_this_host(connection.server));
    break;
  default:
    report = sql_query_rows(batch.value());
    break;
  }
  outcome.ok = true;
  outcome.rows = sql_tools_detail::rows_of(report);
  outcome.summary = form.mode == kSqlQuery
                        ? "Query: " + std::to_string(report.rows.size()) + " values read through " + batch.value().driver
                        : sql_tools_detail::summary_of(report, name);
  if (batch.value().cancelled)
    outcome.summary += " (cancelled)";
  return outcome;
}

} // namespace support_assist::gui
