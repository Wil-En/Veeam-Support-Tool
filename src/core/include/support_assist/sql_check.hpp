#pragma once

// SQL Tools: read-only checks of a SQL Server instance against Veeam's guides, over ODBC, on both
// editions. Permissions (the connected account, or another account's catalog rows), the server's
// shape (Always On, failover cluster), the databases' backup history and log chain, where the
// database files are, and a read-only query. Every statement is a SELECT, a system function or a
// fixed SELECT inside a named database; nothing is written. The lists Veeam's pages give, the shape
// notes and the named queries are data (config/checks/sql-*.json).

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct SqlConnection {
  std::string server;              // "SQLHOST01", "SQLHOST01\VEEAMSQL2016", "tcp:10.0.0.5,1433"
  std::string database = "master";
  bool integrated = true;          // the account running SAT; else login and password
  std::string login;
  std::string password;            // in memory for the connect only; never written or shown
  bool trust_server_certificate = false;
};

struct SqlResultSet {
  std::vector<std::string> columns;
  std::vector<std::vector<std::optional<std::string>>> rows; // nullopt is NULL
  bool truncated = false;
};

struct SqlStatementResult {
  bool ok = false;
  std::string error;
  std::vector<SqlResultSet> sets;
};

struct SqlBatchResult {
  bool connected = false;
  bool cancelled = false;
  std::string driver;
  std::vector<SqlStatementResult> statements; // one per statement, in order
};

// Runs the statements over one connection. A statement that fails records its error; the rest run.
Result<SqlBatchResult> run_sql_statements(const SqlConnection& connection, const std::vector<std::string>& statements,
                                          const CancellationToken& cancel, ProgressCallback progress = {});

// The text for a connection that no driver could make. `diagnostics` is what the drivers reported,
// one "SQLSTATE (native code): message" record per entry joined with " | ", and `drivers_tried` the
// driver names in the order they were tried. One plain sentence leads, chosen from the records:
// no driver installed (every record IM002), the server refused the sign-in (28000, 18456), nothing
// answered at the server (08001 with a network-level code or message), or no answer in time
// (HYT00, login timeout). `local_instances` is this machine's SQL Server instances where the
// platform lists them, and nullopt where it does not; an empty list for a server that is this
// machine says no instance is installed. The drivers' own text follows the sentence. Records that
// fit none of these keep the plain "No SQL Server ODBC driver connected: ..." text.
std::string sql_connect_failure_text(std::string_view server, std::string_view diagnostics,
                                     const std::vector<std::string>& drivers_tried,
                                     const std::optional<std::vector<std::string>>& local_instances);

// The last group are the log chain rows of Backups and log chain, one per backup: they describe the
// chain and are not findings (the findings above them carry Fail and Attention). `section` is a
// heading row: the area holds the heading and the other columns are empty.
enum class SqlCheckStatus {
  pass, attention, fail, not_applicable, could_not_check, info,
  chain_ok, chain_base, chain_base_changed, chain_lost, chain_after_loss, chain_new_chain, chain_gap_before,
  section
};
// "Pass", "Attention", "Fail", "Not applicable", "Could not check", "Info"; the chain rows "OK", "Base",
// "Base changed", "Lost", "After loss", "New chain", "Gap before"; a section row "".
std::string to_string(SqlCheckStatus status);

struct SqlCheckRow {
  std::string area;   // "Connection", "Guest processing", "Availability group AG1", "msdb backups"
  std::string check;  // what was compared
  std::string detail; // one plain sentence with the facts read
  SqlCheckStatus status = SqlCheckStatus::info;
  std::string source; // the Veeam or Microsoft page the comparison follows, when there is one
};

struct SqlCheckReport {
  std::vector<SqlCheckRow> rows;
};

// T-SQL quoting for text SAT puts into a statement: N'...' with quotes doubled, and [name].
// Control characters are left out.
std::string sql_string_literal(std::string_view text);
std::string sql_quote_name(std::string_view name);

// Permissions. This account: the permission functions over the connected token, which counts group
// membership as SQL Server does. Another account: the catalog rows for that name, which the
// connected account sees only with VIEW ANY DEFINITION or sysadmin; groups are not expanded.
enum class SqlPermissionTarget { guest_processing, configuration_database };
struct SqlPermissionCheckOptions {
  SqlPermissionTarget target = SqlPermissionTarget::guest_processing;
  std::string another_account;        // empty: the connected account
  std::string configuration_database; // for the configuration database target
};
std::vector<std::string> sql_permission_statements(const SqlPermissionCheckOptions& options);
SqlCheckReport evaluate_sql_permissions(const SqlBatchResult& batch, const SqlConnection& connection,
                                        const SqlPermissionCheckOptions& options);

// The server's shape: availability groups, listeners, the cluster, the preferred backup replica,
// failover cluster nodes and disks, with the guide's sentence for a shape that is present. Each
// availability group gets a Type row (cluster type WSFC, NONE for a clusterless group, EXTERNAL;
// distributed, Basic, contained, DTC support) and a distributed group a Member row for the groups
// it joins. The statement reads the group's own catalog columns with `ag.*`, so a column that the
// version lacks is simply absent from the rows and is reported as not reported by that version.
std::vector<std::string> sql_shape_statements();
SqlCheckReport evaluate_sql_shape(const SqlBatchResult& batch);

// Backups and the log chain over msdb (KB2117): full, differential and log backups in the last
// days, who took each (Veeam by the software, vendor id or device name it records; a VSS snapshot
// full as likely Veeam's when Veeam is installed on the SQL host or the database has Veeam rows),
// gaps, log backups to NUL, a full that moves the base of the logs, restarts, forks, and databases
// that cannot take a log backup. After the findings, a section row and the log chain itself: one
// row per backup, oldest first, with the chain statuses.
struct SqlBackupOptions {
  std::string database; // empty: every database except tempdb
  int days = 14;
  bool veeam_on_sql_host = false; // the caller found a Veeam product installed on the SQL host
};
std::vector<std::string> sql_backup_statements(const SqlBackupOptions& options);
SqlCheckReport evaluate_sql_backups(const SqlBatchResult& batch, const SqlBackupOptions& options);
// For SqlBackupOptions::veeam_on_sql_host: the server is this machine and a Veeam product is installed here.
bool veeam_installed_on_sql_host(std::string_view server);

// Where the database files are. When SAT runs on the SQL host, each file's volume is classified
// with Volume Check (kind, bus, file system, sector size).
std::vector<std::string> sql_files_statements();
SqlCheckReport evaluate_sql_files(const SqlBatchResult& batch, bool on_this_host);
// Whether a server name points at this machine ("localhost", ".", this computer's name).
bool sql_server_is_this_host(std::string_view server);

// The read-only query: one SELECT or WITH statement. The reason it is refused, or nullopt. A guard
// against slips, not a security boundary: the connected account's rights are the boundary.
std::optional<std::string> sql_query_refusal(std::string_view text);
// A typed query on one line, for the Query field and its command line: each run of spaces, tabs and
// line breaks outside quoted text ('...', "...", [...], $tag$...$tag$) becomes one space, and the
// ends are trimmed. Quoted text is kept as typed.
std::string sql_query_one_line(std::string_view text);
// A query's result sets as Row, Column, Value rows, at most max_rows rows.
SqlCheckReport sql_query_rows(const SqlBatchResult& batch, std::size_t max_rows = 500);

struct SqlNamedQuery {
  std::string name;
  std::string text;
  // For a query wider than a grid shows: the columns the grid shows (the rest are in the row's detail).
  std::vector<std::string> main_columns;
};
const std::vector<SqlNamedQuery>& sql_named_queries();

// sql_query_rows starts each result set with this row: check is the column that names each row ("Row"
// when the rows are numbered), detail every other column, tab separated, in the query's order.
inline constexpr const char* kSqlQueryColumnsArea = "Columns";

// One result set of a read-only query as a grid, rebuilt from sql_query_rows' rows.
struct SqlQueryGrid {
  std::string label_heading;                    // the column that names each row, or "Row"
  std::vector<std::string> columns;             // the other columns, in the query's order
  std::vector<std::string> labels;              // each result row's name
  std::vector<std::vector<std::string>> cells;  // each result row's values, in the order of columns
  std::vector<std::string> notes;               // "No rows.", "N rows; the first 500 are listed.", an error
};
// The result sets in rows given as (area, check, detail), one grid each, in order.
std::vector<SqlQueryGrid> sql_query_grids(const std::vector<std::array<std::string, 3>>& rows);
// The columns a grid shows, as indexes into grid.columns: all of them when there are max_shown or
// fewer, else the main columns the grid has, else the first max_shown.
std::vector<std::size_t> sql_query_shown_columns(const SqlQueryGrid& grid, const std::vector<std::string>& main_columns,
                                                 std::size_t max_shown = 7);
// The named query, of either engine, whose text or name the query is; nullptr for a query typed.
const SqlNamedQuery* sql_named_query_for(std::string_view query);
// The main columns of the named query, of either engine, whose main columns the grid has; none when no
// named query's main columns are all in it.
std::vector<std::string> sql_query_main_columns(const SqlQueryGrid& grid);
// For the command line: a text table of the shown columns, a block per row with every column, and
// tab-separated text (a header line, then a line per row).
std::string sql_query_text_table(const SqlQueryGrid& grid, const std::vector<std::size_t>& shown);
std::string sql_query_text_records(const SqlQueryGrid& grid);
std::string sql_query_tsv(const SqlQueryGrid& grid);

// For the form's lists: this machine's SQL Server instances (Windows registry: "HOST" for the
// default instance, "HOST\NAME" for a named one), and the accounts worth checking (the Veeam Backup
// Service's logon account, NT AUTHORITY\SYSTEM). Empty where there is nothing to read.
std::vector<std::string> sql_local_instances();
// The same list where the platform can read it (Windows), and nullopt where it cannot, so that an
// empty list on Windows means "none installed" and never "not readable here".
std::optional<std::vector<std::string>> sql_local_instances_listed();
std::vector<std::string> sql_accounts_to_check();

} // namespace support_assist
