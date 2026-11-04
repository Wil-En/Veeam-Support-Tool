#pragma once

// SQL Tools' lists for the forms' drop-downs: the database servers on this machine (SQL Server and
// PostgreSQL), and the databases of one server. Also the pieces that tell the two engines apart
// from a name: which engine a listed name belongs to, and a PostgreSQL "host:port" split into its
// parts.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

enum class SqlEngine { sql_server, postgresql };

// "SQL Server" or "PostgreSQL".
std::string sql_engine_name(SqlEngine engine);

struct SqlInstanceChoice {
  std::string name; // what goes in the server field: "HOST", "HOST\NAME" or "localhost:5432"
  SqlEngine engine = SqlEngine::sql_server;
  std::string detail; // version and data directory, when known
};

// The database servers on this machine. SQL Server instances come from sql_local_instances().
// PostgreSQL instances come from the PostgreSQL entries in the Windows registry and the program
// folder, or on Linux from /etc/postgresql and the sockets in /var/run/postgresql, and are named
// by the address psql connects to ("localhost:5432"). Empty where there is nothing to read.
std::vector<SqlInstanceChoice> local_database_instances();

// A PostgreSQL server field: "host", "host:port", "[::1]" or "[::1]:5433". The port is 5432 when
// none is given. Nothing is returned for an empty host or a port that is not 1 to 65535.
struct PostgresAddress {
  std::string host;
  int port = 5432;
};
std::optional<PostgresAddress> parse_postgres_server(std::string_view text);

// Which engine a name from the instance list belongs to. A name ending in ":port" (host or
// bracketed address) is PostgreSQL; everything else, including "HOST\NAME" and "host,1433", is
// SQL Server.
SqlEngine sql_engine_of(std::string_view name);

// The port a postgresql.conf sets: the last "port = N" line that is not a comment.
std::optional<int> postgres_conf_port(std::string_view text);

// The databases a server holds that accept connections. SQL Server: the online databases, through
// ODBC. PostgreSQL: through psql, which is found in tools_folder, on the PATH or in the PostgreSQL
// install folders. With use_logged_in_user the account running SAT connects and no password is
// used.
Result<std::vector<std::string>> list_databases(SqlEngine engine, const std::string& server, bool use_logged_in_user,
                                                const std::string& login, const std::string& password,
                                                const CancellationToken& cancel, bool trust_server_certificate = false,
                                                const std::filesystem::path& tools_folder = {});

} // namespace support_assist
