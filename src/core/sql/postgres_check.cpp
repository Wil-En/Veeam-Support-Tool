// SQL Tools' PostgreSQL checks: how psql is run, the statements each check sends, and the rows made of
// what comes back. The statements are SELECTs over the system catalogs and statistics views; the
// requirements and sources they are held against are data (config/checks/postgres-checks.json).
#include "support_assist/postgres_check.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/json.hpp"
#include "support_assist/process.hpp"
#include "support_assist/sql_catalog.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"
#include "support_assist/volume_check.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <map>
#include <set>

namespace support_assist {

namespace {

constexpr char kUnitSeparator = '\x1F';
constexpr char kNullMarker = '\x1A';
constexpr std::size_t kMaximumRows = 20000;
constexpr int kStatementTimeoutMilliseconds = 120000;
constexpr std::size_t kMaximumArgumentCharacters = 30000;
constexpr std::size_t kMaximumOutputBytes = 64U * 1024U * 1024U;

#ifdef _WIN32
constexpr bool kOnWindows = true;
#else
constexpr bool kOnWindows = false;
#endif

// ------------------------------------------------------------------------------------- data

struct Requirement {
  std::string attribute; // a pg_roles column: "rolsuper"
  std::string label;     // "Superuser"
  std::string text;      // what the page says
  std::string source;    // the page's address
  SqlCheckStatus if_missing = SqlCheckStatus::attention;
};

struct Note {
  std::string text;
  std::string source;
};

struct PostgresData {
  std::string default_database = "VeeamBackup";
  std::string integrated_role = "postgres";
  std::vector<Requirement> requirements;
  std::map<std::string, Note> notes;
  std::map<std::string, std::string> sources; // id -> address
};

SqlCheckStatus status_named(const std::string& name) {
  if (name == "pass")
    return SqlCheckStatus::pass;
  if (name == "fail")
    return SqlCheckStatus::fail;
  if (name == "info")
    return SqlCheckStatus::info;
  return SqlCheckStatus::attention;
}

const PostgresData& postgres_data() {
  static const PostgresData data = [] {
    PostgresData parsed;
    const JsonValue& value = data_file("postgres-checks.json");
    for (const auto& [key, source] : value["sources"].members())
      parsed.sources[key] = source["url"].as_string();
    auto url_of = [&parsed](const std::string& id) {
      const auto found = parsed.sources.find(id);
      return found == parsed.sources.end() ? std::string() : found->second;
    };
    parsed.default_database = value["configuration_database"]["default_name"].as_string("VeeamBackup");
    parsed.integrated_role = value["authentication"]["windows_integrated_role"].as_string("postgres");
    for (const JsonValue& item : value["requirements"].items()) {
      Requirement requirement;
      requirement.attribute = item["attribute"].as_string();
      requirement.label = item["label"].as_string();
      requirement.text = item["text"].as_string();
      requirement.source = url_of(item["source"].as_string());
      requirement.if_missing = status_named(item["status_if_missing"].as_string("attention"));
      if (!requirement.attribute.empty())
        parsed.requirements.push_back(std::move(requirement));
    }
    for (const JsonValue& item : value["notes"].items())
      parsed.notes[item["id"].as_string()] = {item["text"].as_string(), url_of(item["source"].as_string())};
    return parsed;
  }();
  return data;
}

// ------------------------------------------------------------------------------------- reading

const SqlResultSet* first_set(const SqlBatchResult& batch, std::size_t statement) {
  if (statement >= batch.statements.size() || !batch.statements[statement].ok ||
      batch.statements[statement].sets.empty())
    return nullptr;
  return &batch.statements[statement].sets.front();
}

std::string statement_error(const SqlBatchResult& batch, std::size_t statement) {
  if (statement >= batch.statements.size())
    return "The statement did not run.";
  return batch.statements[statement].error.empty() ? std::string("No result.") : batch.statements[statement].error;
}

std::optional<std::size_t> column_of(const SqlResultSet& set, std::string_view name) {
  for (std::size_t index = 0; index < set.columns.size(); ++index) {
    if (ascii_lower(set.columns[index]) == ascii_lower(name))
      return index;
  }
  return std::nullopt;
}

std::string cell(const SqlResultSet& set, std::size_t row, std::string_view name) {
  const auto column = column_of(set, name);
  if (!column || row >= set.rows.size() || *column >= set.rows[row].size() || !set.rows[row][*column])
    return {};
  return *set.rows[row][*column];
}

bool is_null(const SqlResultSet& set, std::size_t row, std::string_view name) {
  const auto column = column_of(set, name);
  return !column || row >= set.rows.size() || *column >= set.rows[row].size() || !set.rows[row][*column];
}

// psql prints a boolean as t or f.
bool truthy(const std::string& value) {
  const std::string folded = ascii_lower(value);
  return folded == "t" || folded == "true" || folded == "on" || folded == "yes" || folded == "1";
}

std::string yes_no(bool value) {
  return value ? "yes" : "no";
}

std::string joined(const std::vector<std::string>& items, const std::string& separator = ", ") {
  std::string text;
  for (const std::string& item : items)
    text += (text.empty() ? "" : separator) + item;
  return text;
}

std::uint64_t number_of(const std::string& text) {
  try {
    return text.empty() ? 0U : std::stoull(text);
  } catch (...) {
    return 0U;
  }
}

// name -> value of the rows of a "name, setting" result; a NULL setting (hidden from this role) is left out.
std::map<std::string, std::string> settings_of(const SqlResultSet* set) {
  std::map<std::string, std::string> settings;
  if (set == nullptr)
    return settings;
  for (std::size_t row = 0; row < set->rows.size(); ++row) {
    if (!is_null(*set, row, "setting"))
      settings[cell(*set, row, "name")] = cell(*set, row, "setting");
  }
  return settings;
}

std::string setting_or(const std::map<std::string, std::string>& settings, const std::string& name,
                       const std::string& fallback) {
  const auto found = settings.find(name);
  return found == settings.end() ? fallback : found->second;
}

std::string port_text(const PostgresConnection& connection) {
  return connection.host + ":" + std::to_string(connection.port);
}

bool has_control_character(std::string_view text) {
  return std::any_of(text.begin(), text.end(), [](char character) {
    const auto code = static_cast<unsigned char>(character);
    return code < 0x20U || code == 0x7FU;
  });
}

Error postgres_error(std::string operation, const PostgresConnection& connection, std::string message) {
  Error error;
  error.component = "PostgreSQL";
  error.operation = std::move(operation);
  error.source = port_text(connection);
  error.message = std::move(message);
  return error;
}

// ------------------------------------------------------------------------------------- volumes

std::string volume_facts(const std::string& path, std::map<std::string, std::string>& cache) {
  if (const auto found = cache.find(path); found != cache.end())
    return found->second;
  std::string native = path;
#ifdef _WIN32
  std::replace(native.begin(), native.end(), '/', '\\');
#endif
  std::string facts;
  const auto checked = check_volume(native);
  if (!checked.ok()) {
    facts = "the volume was not read";
  } else {
    const VolumeInfo& info = checked.value();
    facts = info.kind.empty() ? std::string("volume") : info.kind;
    if (!info.bus.empty())
      facts += ", " + info.bus;
    if (!info.file_system.empty())
      facts += ", " + info.file_system;
    if (info.logical_sector_bytes != 0U)
      facts += ", " + std::to_string(info.logical_sector_bytes) + "-byte sectors";
    if (info.network_share)
      facts += ", network share";
    if (info.total_bytes != 0U)
      facts += ", " + volume_detail::format_bytes(info.free_bytes) + " free of " + volume_detail::format_bytes(info.total_bytes);
  }
  cache[path] = facts;
  return facts;
}

// ------------------------------------------------------------------------------------- archive command

// The program an archive_command runs, without its arguments, which may carry credentials.
std::string describe_archive_command(const std::string& command) {
  const std::string text = trim(command);
  if (text.empty())
    return "not set";
  std::string program;
  if (text.front() == '"' || text.front() == '\'') {
    const std::size_t close = text.find(text.front(), 1U);
    program = text.substr(1U, close == std::string::npos ? std::string::npos : close - 1U);
  } else {
    program = text.substr(0U, text.find_first_of(" \t"));
  }
  const std::size_t slash = program.find_last_of("/\\");
  if (slash != std::string::npos)
    program = program.substr(slash + 1U);
  if (program.empty() || program.find_first_of("=@") != std::string::npos)
    return "set (" + std::to_string(text.size()) + " characters; the program and arguments are not shown)";
  return "set (" + std::to_string(text.size()) + " characters); it runs " + program + ", arguments not shown";
}

// ------------------------------------------------------------------------------------- query guard

bool is_word_character(char character) {
  return std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_';
}

const std::set<std::string>& refused_functions() {
  static const std::set<std::string> words{
      "pg_terminate_backend", "pg_cancel_backend", "pg_reload_conf", "pg_rotate_logfile", "pg_switch_wal",
      "pg_switch_xlog", "pg_create_restore_point", "pg_promote", "pg_start_backup", "pg_stop_backup",
      "pg_backup_start", "pg_backup_stop", "set_config", "nextval", "setval", "txid_current", "pg_current_xact_id",
      "pg_logical_emit_message", "pg_import_system_collations", "pg_stat_statements_reset", "pg_read_file",
      "pg_read_binary_file", "pg_file_write", "pg_file_rename", "pg_file_unlink", "pg_logdir_ls"};
  return words;
}

const std::vector<std::string>& refused_prefixes() {
  static const std::vector<std::string> prefixes{"pg_create_", "pg_drop_", "pg_replication_origin_", "pg_advisory_",
                                                  "pg_stat_reset", "pg_wal_replay_", "lo_", "dblink"};
  return prefixes;
}

}  // namespace

// ------------------------------------------------------------------------------------- connection

std::optional<std::string> postgres_connection_problem(const PostgresConnection& connection) {
  if (has_control_character(connection.host) || has_control_character(connection.database) ||
      has_control_character(connection.user) || has_control_character(connection.password))
    return std::string("The server, database, login and password cannot contain control characters.");
  if (connection.port < 1 || connection.port > 65535)
    return std::string("The PostgreSQL port must be a number from 1 to 65535.");
  if (connection.database.find('=') != std::string::npos || connection.database.rfind("postgresql://", 0) == 0 ||
      connection.database.rfind("postgres://", 0) == 0)
    return std::string("The database name cannot contain '=' or start with postgresql://.");
  if (!connection.integrated && connection.user.empty())
    return std::string("Enter the PostgreSQL login, or tick Use logged-in user.");
  return std::nullopt;
}

Result<PostgresConnection> make_postgres_connection(std::string_view server, bool use_logged_in_user,
                                                    const std::string& login, const std::string& password,
                                                    const std::string& database,
                                                    const std::filesystem::path& tools_folder) {
  PostgresConnection connection;
  const auto address = parse_postgres_server(server);
  if (!address) {
    Error error;
    error.component = "PostgreSQL";
    error.operation = "connect";
    error.source = trim(server);
    error.message = "Enter the PostgreSQL server as a host name or address, with the port after a colon if it is "
                    "not 5432.";
    return Result<PostgresConnection>::failure(std::move(error));
  }
  connection.host = address->host;
  connection.port = address->port;
  const std::string name = trim(database);
  connection.database = name.empty() ? std::string("postgres") : name;
  connection.integrated = use_logged_in_user;
  connection.user = use_logged_in_user ? std::string() : trim(login);
  connection.password = use_logged_in_user ? std::string() : password;
  connection.tools_folder = tools_folder;
  if (const auto problem = postgres_connection_problem(connection))
    return Result<PostgresConnection>::failure(postgres_error("connect", connection, *problem));
  return Result<PostgresConnection>::success(std::move(connection));
}

std::string postgres_role_for(const PostgresConnection& connection, bool windows) {
  if (!connection.integrated || !connection.user.empty())
    return connection.user;
  return windows ? postgres_data().integrated_role : std::string();
}

std::string postgres_string_literal(std::string_view text) {
  std::string literal = "E'";
  for (const char character : text) {
    if (static_cast<unsigned char>(character) < 0x20U)
      continue;
    if (character == '\'')
      literal += "''";
    else if (character == '\\')
      literal += "\\\\";
    else
      literal += character;
  }
  return literal + "'";
}

// ------------------------------------------------------------------------------------- psql

namespace {

std::string marker_name(std::string_view token, std::string_view suffix) {
  return "satmark_" + std::string(token) + "_" + std::string(suffix);
}

std::string new_token() {
  std::string token;
  for (const char character : make_uuid_v4()) {
    if (std::isalnum(static_cast<unsigned char>(character)) != 0)
      token += static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    if (token.size() == 12U)
      break;
  }
  return token.empty() ? std::string("0") : token;
}

std::optional<std::string> field_value(std::string_view piece) {
  if (piece.size() == 1U && piece.front() == kNullMarker)
    return std::nullopt;
  std::string text(piece);
  // A value with a line break reaches a Windows pipe as CR LF.
  for (std::size_t at = text.find("\r\n"); at != std::string::npos; at = text.find("\r\n", at))
    text.erase(at, 1U);
  return text;
}

std::vector<std::optional<std::string>> read_fields(std::string_view record) {
  std::vector<std::optional<std::string>> fields;
  std::size_t start = 0;
  for (;;) {
    const std::size_t end = record.find(kUnitSeparator, start);
    fields.push_back(field_value(record.substr(start, end == std::string_view::npos ? end : end - start)));
    if (end == std::string_view::npos)
      break;
    start = end + 1U;
  }
  return fields;
}

bool all_digits(std::string_view text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](char character) {
           return std::isdigit(static_cast<unsigned char>(character)) != 0;
         });
}

bool looks_like_connection_failure(const std::string& lowered) {
  for (const char* phrase : {"connection to server", "could not connect", "could not translate host name",
                             "connection refused", "no pg_hba.conf entry", "password authentication failed",
                             "no password supplied", "sspi authentication", "timeout expired",
                             "name or service not known", "no such host is known"}) {
    if (lowered.find(phrase) != std::string::npos)
      return true;
  }
  return false;
}

}  // namespace

std::vector<std::string> postgres_psql_arguments(const PostgresConnection& connection,
                                                 const std::vector<std::string>& statements, std::string_view token,
                                                 std::size_t first_statement, bool windows) {
  std::vector<std::string> arguments{"-X", "-q", "-A", "-0", "-F", std::string(1U, kUnitSeparator), "-P", "footer=off",
                                     "-P", std::string("null=") + kNullMarker, "-v", "ON_ERROR_STOP=1", "-w"};
  if (!connection.host.empty()) {
    arguments.push_back("-h");
    arguments.push_back(connection.host);
  }
  arguments.push_back("-p");
  arguments.push_back(std::to_string(connection.port));
  arguments.push_back("-d");
  arguments.push_back(connection.database.empty() ? std::string("postgres") : connection.database);
  const std::string role = postgres_role_for(connection, windows);
  if (!role.empty()) {
    arguments.push_back("-U");
    arguments.push_back(role);
  }
  auto add_statement = [&arguments](std::string text) {
    arguments.push_back("-c");
    arguments.push_back(std::move(text));
  };
  add_statement("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY");
  add_statement("SET statement_timeout = " + std::to_string(kStatementTimeoutMilliseconds));
  // The proof is marked like every statement: the marker's header, then the setting's own header and
  // its value, which is what parse_postgres_output reads.
  add_statement("SELECT 1 AS " + marker_name(token, "ro") + " WHERE false");
  add_statement("SELECT current_setting('default_transaction_read_only') AS default_transaction_read_only");
  for (std::size_t index = first_statement; index < statements.size(); ++index) {
    add_statement("SELECT 1 AS " + marker_name(token, std::to_string(index)) + " WHERE false");
    add_statement(statements[index]);
  }
  return arguments;
}

std::vector<std::pair<std::string, std::string>> postgres_psql_environment(const PostgresConnection& connection) {
  return {{"PGPASSWORD", connection.integrated ? std::string() : connection.password},
          {"PGCLIENTENCODING", "UTF8"},
          {"PGCONNECT_TIMEOUT", "15"},
          {"PGAPPNAME", std::string(kProductName)}};
}

PostgresParsedOutput parse_postgres_output(std::string_view output, std::string_view token) {
  PostgresParsedOutput parsed;
  std::vector<std::string> records;
  std::size_t position = 0;
  while (position < output.size()) {
    const std::size_t end = output.find('\0', position);
    if (end == std::string_view::npos) {
      parsed.truncated = true; // the output ended inside a record
      break;
    }
    records.emplace_back(output.substr(position, end - position));
    position = end + 1U;
  }

  struct Group {
    bool proof = false;
    std::size_t index = 0;
    std::vector<std::string> records;
  };
  std::vector<Group> groups;
  const std::string prefix = marker_name(token, "");
  for (std::string& record : records) {
    if (record.rfind(prefix, 0) == 0) {
      const std::string suffix = record.substr(prefix.size());
      if (suffix == "ro") {
        groups.push_back({true, 0U, {}});
        continue;
      }
      if (all_digits(suffix) && suffix.size() < 10U) {
        groups.push_back({false, static_cast<std::size_t>(std::stoul(suffix)), {}});
        continue;
      }
    }
    if (!groups.empty())
      groups.back().records.push_back(std::move(record));
  }

  for (Group& group : groups) {
    if (group.proof) {
      parsed.read_only_confirmed = group.records.size() >= 2U && group.records[1] == "on";
      continue;
    }
    SqlStatementResult result;
    result.ok = true;
    if (!group.records.empty()) {
      SqlResultSet set;
      for (const auto& name : read_fields(group.records.front()))
        set.columns.push_back(name.value_or(std::string()));
      for (std::size_t row = 1; row < group.records.size(); ++row) {
        if (set.rows.size() >= kMaximumRows) {
          set.truncated = true;
          parsed.truncated = true;
          break;
        }
        set.rows.push_back(read_fields(group.records[row]));
      }
      result.sets.push_back(std::move(set));
    }
    parsed.statements.emplace_back(group.index, std::move(result));
  }
  if (parsed.truncated && !parsed.statements.empty() && !parsed.statements.back().second.sets.empty())
    parsed.statements.back().second.sets.back().truncated = true;
  return parsed;
}

std::string postgres_error_text(std::string_view standard_error) {
  std::string output;
  std::size_t start = 0;
  while (start <= standard_error.size()) {
    const std::size_t end = standard_error.find('\n', start);
    std::string line = trim(standard_error.substr(start, end == std::string_view::npos ? end : end - start));
    start = end == std::string_view::npos ? standard_error.size() + 1U : end + 1U;
    if (line.empty() || (line.rfind("LINE ", 0) == 0 && line.find(':') != std::string::npos) ||
        line.find_first_not_of(" ^") == std::string::npos)
      continue; // the statement echo and its caret
    if (line.rfind("psql: error: ", 0) == 0)
      line.erase(0, 13U);
    else if (line.rfind("psql: ", 0) == 0)
      line.erase(0, 6U);
    for (std::size_t at = line.find(":  "); at != std::string::npos && at < 12U; at = line.find(":  ", at + 1U))
      line.erase(at + 1U, 1U);
    if (!output.empty())
      output += " | ";
    output += line;
  }
  if (output.size() > 700U)
    output = output.substr(0U, 700U) + "...";
  return output;
}

std::string postgres_connection_failure(std::string_view standard_error, const PostgresConnection& connection) {
  const std::string text = postgres_error_text(standard_error);
  const std::string lowered = ascii_lower(text);
  const std::string address = port_text(connection);
  const std::string role = postgres_role_for(connection, kOnWindows);
  auto has = [&lowered](const char* phrase) { return lowered.find(phrase) != std::string::npos; };
  auto sspi_page = []() {
    const auto found = postgres_data().sources.find("kb4542");
    return found == postgres_data().sources.end() ? std::string() : ", " + found->second;
  };
  std::string plain;
  if (has("could not translate host name") || has("name or service not known") || has("no such host is known") ||
      has("temporary failure in name resolution"))
    plain = "The server name " + connection.host + " did not resolve to an address.";
  else if (has("connection refused") || has("is the server running") || has("actively refused"))
    plain = "No PostgreSQL server answered at " + address +
            ". Check the server name and port, and that the PostgreSQL service is running.";
  else if (has("timeout expired") || has("timed out"))
    plain = "The PostgreSQL server at " + address +
            " did not answer in time. Check the server name, the port and any firewall between this machine and the "
            "server.";
  else if (has("sspi authentication failed") || has("no match in usermap"))
    plain = "The server did not accept the logged-in Windows account. PostgreSQL maps Windows accounts to roles in "
            "pg_ident.conf (Veeam KB4542" + sspi_page() + ").";
  else if (has("password authentication failed"))
    plain = "The server refused the login or the password" + (role.empty() ? std::string() : " for " + role) + ".";
  else if (has("no password supplied") || has("fe_sendauth"))
    plain = "The server asks for a password. Clear Use logged-in user, then enter the login and the password.";
  else if (has("no pg_hba.conf entry"))
    plain = "The server has no pg_hba.conf entry for this machine, role and database.";
  else if (has("database \"") && has("does not exist"))
    plain = "The database " + connection.database + " does not exist on this server.";
  else if (has("role \"") && has("does not exist"))
    plain = "The role " + role + " does not exist on this server.";
  if (plain.empty())
    return text.empty() ? std::string("psql could not connect to ") + address + "." : text;
  return text.empty() ? plain : plain + " (" + text + ")";
}

Result<SqlBatchResult> run_postgres_statements(const PostgresConnection& connection,
                                               const std::vector<std::string>& statements,
                                               const CancellationToken& cancel, ProgressCallback progress) {
  auto failure = [&connection](std::string operation, std::string message) {
    return Result<SqlBatchResult>::failure(postgres_error(std::move(operation), connection, std::move(message)));
  };
  if (const auto problem = postgres_connection_problem(connection))
    return failure("connect", *problem);
  if (statements.empty())
    return failure("run", "There is no statement to run.");
  std::size_t characters = 0;
  for (const std::string& statement : statements)
    characters += statement.size() + 64U;
  if (characters > kMaximumArgumentCharacters)
    return failure("run", "The statements are too long to pass to psql (the limit is about 30,000 characters).");

  const auto psql = resolve_external_tool("psql", connection.tools_folder);
  if (!psql.ok())
    return failure("find psql", "psql was not found. Place psql in the Tools folder on the Integrations page, or install "
                                "the PostgreSQL client tools, then run the check again.");

  if (progress) {
    ProgressEvent event;
    event.phase = "Connecting";
    event.current_scope = port_text(connection);
    progress(event);
  }

  SqlBatchResult batch;
  batch.driver = "psql";
  batch.statements.resize(statements.size());
  std::vector<bool> settled(statements.size(), false);
  const std::string token = new_token();
  std::size_t next = 0;
  bool connected = false;
  for (std::size_t attempt = 0; attempt <= statements.size() && next < statements.size(); ++attempt) {
    if (cancel.is_cancelled()) {
      batch.cancelled = true;
      break;
    }
    ProcessOptions options;
    options.executable = psql.value();
    options.arguments = postgres_psql_arguments(connection, statements, token, next, kOnWindows);
    options.environment_overrides = postgres_psql_environment(connection);
    options.merge_standard_error = false;
    options.timeout = std::chrono::minutes(10);
    options.maximum_output_bytes = kMaximumOutputBytes;
    auto ran = run_process_capture(options, cancel);
    for (auto& entry : options.environment_overrides)
      std::fill(entry.second.begin(), entry.second.end(), '\0');
    if (!ran.ok())
      return failure("run psql", describe_error(ran.error()));
    const ProcessResult& process = ran.value();
    if (process.cancelled || cancel.is_cancelled()) {
      batch.cancelled = true;
      break;
    }

    PostgresParsedOutput parsed = parse_postgres_output(process.output, token);
    const bool failed_run = process.exit_code != 0 || process.timed_out;
    if (!failed_run && !parsed.read_only_confirmed) {
      // psql can exit 0 after refusing the connection; its own words come first when it said any.
      const std::string said = postgres_error_text(process.standard_error);
      if (looks_like_connection_failure(ascii_lower(said)))
        return failure("connect", postgres_connection_failure(process.standard_error, connection));
      if (!said.empty())
        return failure("start session", "The read-only session could not be started: " + said);
      return failure("start session", "psql did not confirm a read-only session, so nothing was run. psql 9.6 or later "
                                      "is needed.");
    }
    if (failed_run && !parsed.read_only_confirmed) {
      const std::string lowered = ascii_lower(postgres_error_text(process.standard_error));
      if (process.timed_out)
        return failure("connect", "psql did not finish within 10 minutes.");
      if (process.exit_code == 2 || looks_like_connection_failure(lowered))
        return failure("connect", postgres_connection_failure(process.standard_error, connection));
      return failure("start session", "The read-only session could not be started: " +
                                          postgres_error_text(process.standard_error));
    }
    connected = true;

    // The statement named by the last marker is the one that failed; the ones before it finished.
    const std::size_t failed_statement =
        failed_run && !parsed.statements.empty() ? parsed.statements.back().first : statements.size();
    for (auto& [index, result] : parsed.statements) {
      if (index >= statements.size() || index < next || index == failed_statement)
        continue;
      batch.statements[index] = std::move(result);
      settled[index] = true;
    }
    if (!failed_run)
      break;

    std::string reason = process.timed_out ? std::string("psql did not finish within 10 minutes.")
                                           : postgres_error_text(process.standard_error);
    if (reason.empty())
      reason = "The statement failed.";
    if (failed_statement >= statements.size())
      return failure("run", reason);
    if (process.exit_code == 2 || process.timed_out) {
      // The session is gone: this statement and the ones after it did not run.
      for (std::size_t index = failed_statement; index < statements.size(); ++index) {
        batch.statements[index].error = postgres_connection_failure(process.standard_error, connection);
        settled[index] = true;
      }
      break;
    }
    batch.statements[failed_statement].error = reason;
    settled[failed_statement] = true;
    next = failed_statement + 1U;
    if (progress) {
      ProgressEvent event;
      event.phase = "Reading";
      event.processed = next;
      event.total = statements.size();
      event.current_scope = port_text(connection);
      progress(event);
    }
  }
  for (std::size_t index = 0; index < statements.size(); ++index) {
    if (!settled[index] && batch.statements[index].error.empty())
      batch.statements[index].error = batch.cancelled ? std::string("Cancelled.") : std::string("No result.");
  }
  batch.connected = connected;
  if (progress && !batch.cancelled) {
    ProgressEvent event;
    event.phase = "Reading";
    event.processed = statements.size();
    event.total = statements.size();
    event.current_scope = port_text(connection);
    progress(event);
  }
  return Result<SqlBatchResult>::success(std::move(batch));
}

// ------------------------------------------------------------------------------------- permissions

std::string postgres_default_configuration_database() {
  if (const auto databases = identify_configuration_databases(); databases.ok()) {
    for (const ConfigurationDatabaseInfo& item : databases.value()) {
      if (item.found && ascii_lower(item.engine) == "postgresql" && !item.database.empty())
        return item.database;
    }
  }
  return postgres_data().default_database;
}

namespace {

// Statement order: who, the role, its memberships, the configuration database, the databases.
constexpr std::size_t kWho = 0;
constexpr std::size_t kRole = 1;
constexpr std::size_t kMemberships = 2;
constexpr std::size_t kConfiguration = 3;
constexpr std::size_t kDatabases = 4;

std::string subject_of(const PostgresPermissionOptions& options) {
  return options.another_account.empty() ? std::string("current_user")
                                         : postgres_string_literal(options.another_account) + "::name";
}

}  // namespace

std::vector<std::string> postgres_permission_statements(const PostgresPermissionOptions& options) {
  const std::string subject = subject_of(options);
  const std::string database = postgres_string_literal(
      options.configuration_database.empty() ? postgres_default_configuration_database() : options.configuration_database);
  return {
      "SELECT current_user AS role_name, session_user AS session_name, current_database() AS database_name, "
      "current_setting('server_version') AS server_version, pg_is_in_recovery() AS in_recovery",
      "SELECT r.rolname AS role_name, r.rolsuper, r.rolcreatedb, r.rolcreaterole, r.rolcanlogin, r.rolinherit, "
      "r.rolreplication, r.rolbypassrls, r.rolconnlimit, r.rolvaliduntil::text AS valid_until FROM pg_roles r "
      "WHERE r.rolname = " + subject,
      "WITH RECURSIVE tree(roleid, depth) AS (SELECT m.roleid, 1 FROM pg_auth_members m JOIN pg_roles u ON u.oid = "
      "m.member WHERE u.rolname = " + subject +
          " UNION SELECT m.roleid, t.depth + 1 FROM pg_auth_members m JOIN tree t ON m.member = t.roleid) "
          "SELECT g.rolname AS member_of, min(t.depth) AS depth, g.rolsuper FROM tree t JOIN pg_roles g ON g.oid = "
          "t.roleid GROUP BY g.rolname, g.rolsuper ORDER BY min(t.depth), g.rolname",
      "SELECT d.datname AS database_name, pg_get_userbyid(d.datdba) AS owner, d.datallowconn AS allow_connections, "
      "d.datconnlimit AS connection_limit, has_database_privilege(" + subject +
          ", d.oid, 'CONNECT') AS can_connect, has_database_privilege(" + subject +
          ", d.oid, 'CREATE') AS can_create, pg_has_role(" + subject +
          ", d.datdba, 'MEMBER') AS member_of_owner FROM pg_database d WHERE d.datname = " + database,
      "SELECT d.datname AS database_name, has_database_privilege(" + subject +
          ", d.oid, 'CONNECT') AS can_connect FROM pg_database d WHERE NOT d.datistemplate ORDER BY d.datname"};
}

SqlCheckReport evaluate_postgres_permissions(const SqlBatchResult& batch, const PostgresConnection& connection,
                                             const PostgresPermissionOptions& options) {
  SqlCheckReport report;
  const PostgresData& data = postgres_data();
  const SqlResultSet* who = first_set(batch, kWho);
  if (who == nullptr || who->rows.empty()) {
    report.rows.push_back({"Connection", "Who is connected", statement_error(batch, kWho), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  const std::string connected_role = cell(*who, 0, "role_name");
  const std::string session = cell(*who, 0, "session_name");
  const std::string database = cell(*who, 0, "database_name");
  report.rows.push_back(
      {"Connection", "Who is connected",
       "Connected as " + connected_role + (session != connected_role && !session.empty() ? " (session user " + session + ")" : std::string()) +
           " to database " + database + " on " + port_text(connection) + ", PostgreSQL " + cell(*who, 0, "server_version") +
           (truthy(cell(*who, 0, "in_recovery")) ? ", a standby" : std::string()) +
           (connection.integrated ? ", with the logged-in account" : ", with a login and password") +
           (batch.driver.empty() ? std::string() : ", through " + batch.driver) + ".",
       SqlCheckStatus::info, ""});
  if (connection.integrated) {
    if (const auto note = data.notes.find("sspi_default"); note != data.notes.end())
      report.rows.push_back({"Guide", "Windows login", note->second.text, SqlCheckStatus::info, note->second.source});
  }

  const bool other = !options.another_account.empty();
  const std::string subject = other ? options.another_account : connected_role;
  if (other)
    report.rows.push_back({"Account", "Account checked", options.another_account + ", from the catalog.", SqlCheckStatus::info, ""});

  const std::string roles_url = [&data] {
    const auto found = data.sources.find("postgresql-roles");
    return found == data.sources.end() ? std::string() : found->second;
  }();
  const SqlResultSet* role = first_set(batch, kRole);
  if (role == nullptr) {
    report.rows.push_back({"Role", "Role attributes", statement_error(batch, kRole), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  if (role->rows.empty()) {
    report.rows.push_back({"Role", "Role attributes", "No role named " + subject + " on this server.",
                           other ? SqlCheckStatus::fail : SqlCheckStatus::could_not_check, ""});
    return report;
  }
  const std::string limit = cell(*role, 0, "rolconnlimit");
  report.rows.push_back(
      {"Role", "Role attributes",
       subject + ": can log in " + yes_no(truthy(cell(*role, 0, "rolcanlogin"))) + ", superuser " +
           yes_no(truthy(cell(*role, 0, "rolsuper"))) + ", create databases " + yes_no(truthy(cell(*role, 0, "rolcreatedb"))) +
           ", create roles " + yes_no(truthy(cell(*role, 0, "rolcreaterole"))) + ", replication " +
           yes_no(truthy(cell(*role, 0, "rolreplication"))) + ", bypass row security " +
           yes_no(truthy(cell(*role, 0, "rolbypassrls"))) + ", connection limit " +
           (limit.empty() || limit == "-1" ? std::string("none") : limit) + ", password valid until " +
           (cell(*role, 0, "valid_until").empty() ? std::string("no limit") : cell(*role, 0, "valid_until")) + ".",
       SqlCheckStatus::info, roles_url});

  std::vector<std::string> superuser_groups;
  if (const SqlResultSet* groups = first_set(batch, kMemberships)) {
    std::vector<std::string> names;
    for (std::size_t row = 0; row < groups->rows.size(); ++row) {
      const bool direct = cell(*groups, row, "depth") == "1";
      const bool super = truthy(cell(*groups, row, "rolsuper"));
      names.push_back(cell(*groups, row, "member_of") + " (" + (direct ? "direct" : "indirect") + (super ? ", superuser" : "") + ")");
      if (super)
        superuser_groups.push_back(cell(*groups, row, "member_of"));
    }
    report.rows.push_back({"Role", "Memberships",
                           names.empty() ? subject + " is not a member of any role." : subject + " is a member of " + joined(names) + ".",
                           SqlCheckStatus::info, ""});
  } else {
    report.rows.push_back({"Role", "Memberships", statement_error(batch, kMemberships), SqlCheckStatus::could_not_check, ""});
  }

  for (const Requirement& requirement : data.requirements) {
    const bool held = truthy(cell(*role, 0, requirement.attribute));
    std::string detail = subject + (held ? " is a " : " is not a ") + ascii_lower(requirement.label) + ". " + requirement.text;
    if (!held && !superuser_groups.empty())
      detail += " " + subject + " is a member of " + joined(superuser_groups) +
                ", but the superuser attribute is not inherited through membership.";
    report.rows.push_back({"Configuration database", requirement.label, detail,
                           held ? SqlCheckStatus::pass : requirement.if_missing, requirement.source});
  }

  const std::string wanted =
      options.configuration_database.empty() ? postgres_default_configuration_database() : options.configuration_database;
  const SqlResultSet* configuration = first_set(batch, kConfiguration);
  if (configuration == nullptr) {
    report.rows.push_back({"Configuration database", "Database " + wanted, statement_error(batch, kConfiguration),
                           SqlCheckStatus::could_not_check, ""});
  } else if (configuration->rows.empty()) {
    std::vector<std::string> others;
    if (const SqlResultSet* databases = first_set(batch, kDatabases)) {
      for (std::size_t row = 0; row < databases->rows.size(); ++row)
        others.push_back(cell(*databases, row, "database_name"));
    }
    report.rows.push_back({"Configuration database", "Database " + wanted,
                           "No database named " + wanted + " on this server." +
                               (others.empty() ? std::string() : " Databases here: " + joined(others) + "."),
                           SqlCheckStatus::attention, ""});
  } else {
    const std::string owner = cell(*configuration, 0, "owner");
    const std::string relation = owner == subject                              ? subject + " owns it"
                                 : truthy(cell(*configuration, 0, "member_of_owner")) ? subject + " is a member of the owner role " + owner
                                                                                      : subject + " is neither the owner (" + owner + ") nor a member of the owner role";
    const std::string connection_limit = cell(*configuration, 0, "connection_limit");
    report.rows.push_back(
        {"Configuration database", "Database " + wanted,
         wanted + ": " + relation + "; connect privilege " + yes_no(truthy(cell(*configuration, 0, "can_connect"))) +
             ", create privilege " + yes_no(truthy(cell(*configuration, 0, "can_create"))) + "; connections " +
             (truthy(cell(*configuration, 0, "allow_connections")) ? "allowed" : "not allowed") + ", limit " +
             (connection_limit.empty() || connection_limit == "-1" ? std::string("none") : connection_limit) + ".",
         SqlCheckStatus::info, ""});
  }
  return report;
}

// ------------------------------------------------------------------------------------- shape

std::vector<std::string> postgres_shape_statements() {
  return {
      "SELECT version() AS version_text, current_setting('server_version') AS server_version, "
      "pg_is_in_recovery() AS in_recovery, pg_postmaster_start_time()::text AS started, current_user AS role_name, "
      "current_database() AS database_name",
      "SELECT name, setting FROM pg_settings WHERE name IN ('data_directory', 'listen_addresses', 'port', "
      "'wal_level', 'max_wal_senders', 'max_replication_slots', 'synchronous_standby_names', 'synchronous_commit', "
      "'hot_standby', 'max_connections') ORDER BY name",
      "SELECT application_name, usename, client_addr::text AS client_addr, state, sync_state, sync_priority, "
      "CASE WHEN pg_is_in_recovery() THEN NULL ELSE pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) END AS "
      "replay_lag_bytes FROM pg_stat_replication ORDER BY application_name, client_addr::text",
      "SELECT status, sender_host, sender_port, slot_name FROM pg_stat_wal_receiver"};
}

SqlCheckReport evaluate_postgres_shape(const SqlBatchResult& batch) {
  SqlCheckReport report;
  const PostgresData& data = postgres_data();
  const SqlResultSet* instance = first_set(batch, 0);
  if (instance == nullptr || instance->rows.empty()) {
    report.rows.push_back({"Instance", "Version", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  const bool standby = truthy(cell(*instance, 0, "in_recovery"));
  report.rows.push_back({"Instance", "Version",
                         cell(*instance, 0, "version_text") + ". Started " + cell(*instance, 0, "started") + ".",
                         SqlCheckStatus::info, ""});

  const auto settings = settings_of(first_set(batch, 1));
  if (standby) {
    std::string detail = "Standby: this server is in recovery.";
    if (const SqlResultSet* receiver = first_set(batch, 3); receiver != nullptr && !receiver->rows.empty()) {
      detail += " It receives from " + cell(*receiver, 0, "sender_host") + ":" + cell(*receiver, 0, "sender_port") +
                " (status " + cell(*receiver, 0, "status") + ")" +
                (cell(*receiver, 0, "slot_name").empty() ? std::string() : ", replication slot " + cell(*receiver, 0, "slot_name")) + ".";
    } else if (first_set(batch, 3) != nullptr) {
      detail += " No WAL receiver is running, so it is restoring from an archive or the stream has stopped.";
    }
    report.rows.push_back({"Instance", "Role of this server", detail, SqlCheckStatus::info, ""});
  } else {
    report.rows.push_back({"Instance", "Role of this server", "Primary: this server is not in recovery.", SqlCheckStatus::info, ""});
  }

  std::vector<std::string> replication;
  for (const char* name : {"wal_level", "max_wal_senders", "max_replication_slots", "hot_standby", "synchronous_commit"}) {
    if (const auto found = settings.find(name); found != settings.end())
      replication.push_back(std::string(name) + " = " + found->second);
  }
  const auto synchronous = settings.find("synchronous_standby_names");
  replication.push_back("synchronous_standby_names = " +
                        (synchronous == settings.end() ? std::string("not shown")
                         : synchronous->second.empty() ? std::string("none")
                                                       : synchronous->second));
  report.rows.push_back({"Replication", "Replication settings", joined(replication) + ".", SqlCheckStatus::info, ""});

  if (const SqlResultSet* standbys = first_set(batch, 2)) {
    if (standbys->rows.empty()) {
      report.rows.push_back({"Replication", "Connected standbys",
                             standby ? "No server is receiving from this standby." : "No standby is connected to this server.",
                             SqlCheckStatus::info, ""});
    }
    for (std::size_t row = 0; row < standbys->rows.size(); ++row) {
      const std::string state = cell(*standbys, row, "state");
      const std::string name = cell(*standbys, row, "application_name");
      std::string detail = (name.empty() ? std::string("A standby") : name) + " at " +
                           (cell(*standbys, row, "client_addr").empty() ? std::string("a local connection") : cell(*standbys, row, "client_addr")) +
                           ": " + (state.empty() ? std::string("state not shown") : state) + ", " +
                           (cell(*standbys, row, "sync_state").empty() ? std::string("sync state not shown") : cell(*standbys, row, "sync_state"));
      if (!is_null(*standbys, row, "replay_lag_bytes"))
        detail += ", " + volume_detail::format_bytes(number_of(cell(*standbys, row, "replay_lag_bytes"))) + " behind";
      detail += ".";
      const bool normal = state.empty() || state == "streaming" || state == "backup";
      report.rows.push_back({"Replication", "Standby " + std::to_string(row + 1U), detail,
                             normal ? SqlCheckStatus::info : SqlCheckStatus::attention, ""});
    }
  } else {
    report.rows.push_back({"Replication", "Connected standbys", statement_error(batch, 2), SqlCheckStatus::could_not_check, ""});
  }

  const auto listen = settings.find("listen_addresses");
  const auto port = settings.find("port");
  if (listen == settings.end() && port == settings.end()) {
    report.rows.push_back({"Network", "Listening", "listen_addresses and port are not shown to this role.",
                           SqlCheckStatus::could_not_check, ""});
  } else {
    report.rows.push_back({"Network", "Listening",
                           "listen_addresses = " + (listen == settings.end() ? std::string("not shown") : listen->second) +
                               ", port = " + (port == settings.end() ? std::string("not shown") : port->second) + ".",
                           SqlCheckStatus::info, ""});
  }
  const auto directory = settings.find("data_directory");
  report.rows.push_back({"Files", "Data directory",
                         directory == settings.end() ? std::string("Not shown to this role; the setting needs a superuser or pg_read_all_settings.")
                                                     : directory->second,
                         directory == settings.end() ? SqlCheckStatus::could_not_check : SqlCheckStatus::info, ""});
  if (const auto note = data.notes.find("listen_default"); note != data.notes.end() && listen != settings.end())
    report.rows.push_back({"Guide", "What the guide says", note->second.text, SqlCheckStatus::info, note->second.source});
  return report;
}

// ------------------------------------------------------------------------------------- backups

std::vector<std::string> postgres_backup_statements() {
  return {
      "SELECT name, setting FROM pg_settings WHERE name IN ('archive_mode', 'archive_command', 'archive_library', "
      "'archive_timeout', 'wal_level') ORDER BY name",
      "SELECT archived_count, last_archived_wal, last_archived_time::text AS last_archived_time, failed_count, "
      "last_failed_wal, last_failed_time::text AS last_failed_time, stats_reset::text AS stats_reset, "
      "(last_failed_time IS NOT NULL AND (last_archived_time IS NULL OR last_failed_time > last_archived_time)) AS "
      "failing, pg_is_in_recovery() AS in_recovery FROM pg_stat_archiver"};
}

SqlCheckReport evaluate_postgres_backups(const SqlBatchResult& batch) {
  SqlCheckReport report;
  const PostgresData& data = postgres_data();
  const std::string archiver_url = [&data] {
    const auto found = data.sources.find("postgresql-archiver");
    return found == data.sources.end() ? std::string() : found->second;
  }();
  const SqlResultSet* archiver = first_set(batch, 1);
  const SqlResultSet* settings_set = first_set(batch, 0);
  const auto settings = settings_of(settings_set);
  std::string mode = "off";
  if (settings_set == nullptr) {
    report.rows.push_back({"Archiving", "WAL archiving", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
  } else {
    mode = setting_or(settings, "archive_mode", "off");
    std::string detail = "archive_mode is " + mode + ".";
    if (mode != "off") {
      detail += " archive_command is " + (settings.count("archive_command") == 0U ? std::string("not shown to this role")
                                                                                 : describe_archive_command(settings.at("archive_command"))) + ".";
      if (const auto library = settings.find("archive_library"); library != settings.end() && !library->second.empty())
        detail += " archive_library is " + library->second + ".";
      detail += " wal_level is " + setting_or(settings, "wal_level", "not shown") + ".";
    } else {
      detail += " Archived WAL, which a log chain needs, is not being kept.";
    }
    report.rows.push_back({"Archiving", "WAL archiving", detail, SqlCheckStatus::info, ""});
  }

  if (archiver == nullptr || archiver->rows.empty()) {
    report.rows.push_back({"Archiver", "Archiver statistics",
                           archiver == nullptr ? statement_error(batch, 1) : std::string("The archiver view returned no row."),
                           SqlCheckStatus::could_not_check, ""});
  } else {
    const std::string archived = cell(*archiver, 0, "archived_count");
    const std::string failed = cell(*archiver, 0, "failed_count");
    std::string detail = archived + " WAL files archived";
    if (!is_null(*archiver, 0, "last_archived_wal"))
      detail += ", the last " + cell(*archiver, 0, "last_archived_wal") + " at " + cell(*archiver, 0, "last_archived_time");
    detail += ". Statistics since " + (cell(*archiver, 0, "stats_reset").empty() ? std::string("the server started") : cell(*archiver, 0, "stats_reset")) + ".";
    const bool never = number_of(archived) == 0U;
    report.rows.push_back({"Archiver", "Archived WAL", detail,
                           never && mode != "off" ? SqlCheckStatus::attention : SqlCheckStatus::info, archiver_url});

    const bool failing = truthy(cell(*archiver, 0, "failing"));
    if (failing) {
      report.rows.push_back(
          {"Archiver", "Archive failures",
           "The archiver is failing. " + failed + " failures so far; the last was " + cell(*archiver, 0, "last_failed_wal") + " at " +
               cell(*archiver, 0, "last_failed_time") + (is_null(*archiver, 0, "last_archived_time")
                                                            ? std::string(", and nothing has been archived since the statistics began.")
                                                            : ", after the last success at " + cell(*archiver, 0, "last_archived_time") + "."),
           SqlCheckStatus::fail, archiver_url});
    } else if (number_of(failed) != 0U) {
      report.rows.push_back({"Archiver", "Archive failures",
                             failed + " failures are recorded, the last " + cell(*archiver, 0, "last_failed_wal") + " at " +
                                 cell(*archiver, 0, "last_failed_time") + "; a later archive succeeded.",
                             SqlCheckStatus::attention, archiver_url});
    } else {
      report.rows.push_back({"Archiver", "Archive failures", "No failure is recorded.",
                             mode == "off" ? SqlCheckStatus::info : SqlCheckStatus::pass, archiver_url});
    }
  }
  return report;
}

// ------------------------------------------------------------------------------------- files

std::vector<std::string> postgres_files_statements() {
  return {
      "SELECT name, setting FROM pg_settings WHERE name IN ('data_directory', 'config_file', 'hba_file', "
      "'ident_file', 'log_directory') ORDER BY name",
      "SELECT spcname, pg_get_userbyid(spcowner) AS owner, pg_tablespace_location(oid) AS location FROM "
      "pg_tablespace ORDER BY spcname",
      "SELECT d.datname, pg_get_userbyid(d.datdba) AS owner, t.spcname AS default_tablespace, "
      "pg_database_size(d.oid) AS size_bytes FROM pg_database d JOIN pg_tablespace t ON t.oid = d.dattablespace "
      "WHERE has_database_privilege(d.oid, 'CONNECT') ORDER BY d.datname"};
}

SqlCheckReport evaluate_postgres_files(const SqlBatchResult& batch, bool on_this_host) {
  SqlCheckReport report;
  const SqlResultSet* settings_set = first_set(batch, 0);
  if (settings_set == nullptr) {
    report.rows.push_back({"Files", "Data directory", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
  }
  if (!on_this_host) {
    report.rows.push_back({"Files", "Volumes",
                           "SAT is not running on the PostgreSQL host, so the volumes are not classified. Run SQL Tools on "
                           "the PostgreSQL host for each path's volume.",
                           SqlCheckStatus::not_applicable, ""});
  }
  std::map<std::string, std::string> volumes;
  auto with_volume = [&](const std::string& path) {
    return on_this_host ? path + " (" + volume_facts(path, volumes) + ")" : path;
  };

  const auto settings = settings_of(settings_set);
  if (settings_set != nullptr) {
    const auto directory = settings.find("data_directory");
    if (directory == settings.end()) {
      report.rows.push_back({"Files", "Data directory",
                             "Not shown to this role; the setting needs a superuser or pg_read_all_settings.",
                             SqlCheckStatus::could_not_check, ""});
    } else {
      report.rows.push_back({"Files", "Data directory", with_volume(directory->second) + ".", SqlCheckStatus::info, ""});
    }
    std::vector<std::string> files;
    static const std::pair<const char*, const char*> kFiles[] = {{"config_file", "postgresql.conf"},
                                                                  {"hba_file", "pg_hba.conf"},
                                                                  {"ident_file", "pg_ident.conf"},
                                                                  {"log_directory", "log directory"}};
    for (const auto& [name, label] : kFiles) {
      if (const auto found = settings.find(name); found != settings.end())
        files.push_back(std::string(label) + ": " + found->second);
    }
    if (!files.empty())
      report.rows.push_back({"Files", "Configuration files", joined(files, "; ") + ".", SqlCheckStatus::info, ""});
  }

  if (const SqlResultSet* tablespaces = first_set(batch, 1)) {
    for (std::size_t row = 0; row < tablespaces->rows.size(); ++row) {
      const std::string location = cell(*tablespaces, row, "location");
      report.rows.push_back({"Tablespace " + cell(*tablespaces, row, "spcname"), "Location",
                             (location.empty() ? std::string("Inside the data directory") : with_volume(location)) +
                                 "; owner " + cell(*tablespaces, row, "owner") + ".",
                             SqlCheckStatus::info, ""});
    }
  } else {
    report.rows.push_back({"Tablespaces", "Locations", statement_error(batch, 1), SqlCheckStatus::could_not_check, ""});
  }

  if (const SqlResultSet* databases = first_set(batch, 2)) {
    std::uint64_t total = 0;
    for (std::size_t row = 0; row < databases->rows.size(); ++row) {
      const std::uint64_t bytes = number_of(cell(*databases, row, "size_bytes"));
      total += bytes;
      report.rows.push_back({cell(*databases, row, "datname"), "Size",
                             volume_detail::format_bytes(bytes) + " (" + std::to_string(bytes) + " bytes); owner " +
                                 cell(*databases, row, "owner") + ", default tablespace " +
                                 cell(*databases, row, "default_tablespace") + ".",
                             SqlCheckStatus::info, ""});
    }
    report.rows.push_back({"Databases", "Total size",
                           volume_detail::format_bytes(total) + " in " + std::to_string(databases->rows.size()) +
                               " databases this role can connect to.",
                           SqlCheckStatus::info, ""});
  } else {
    report.rows.push_back({"Databases", "Sizes", statement_error(batch, 2), SqlCheckStatus::could_not_check, ""});
  }
  return report;
}

// ------------------------------------------------------------------------------------- query

std::optional<std::string> postgres_query_refusal(std::string_view text) {
  if (auto refusal = sql_query_refusal(text))
    return refusal;
  // Quoted text is skipped as sql_query_refusal does; what stays is code. The quoting forms whose
  // reading differs from a plain string are refused, so the two readings of a quote cannot disagree.
  std::string word;
  auto check_word = [&word]() -> std::optional<std::string> {
    if (word.empty())
      return std::nullopt;
    const std::string folded = ascii_lower(word);
    word.clear();
    bool refused = refused_functions().count(folded) != 0U;
    for (const std::string& prefix : refused_prefixes())
      refused = refused || folded.rfind(prefix, 0) == 0;
    if (refused)
      return "Not run: this query uses " + folded +
             ", which can make changes. Only queries that read data run here. To change data, use the database console.";
    return std::nullopt;
  };
  for (std::size_t index = 0; index < text.size(); ++index) {
    const char character = text[index];
    if (character == '\'' || character == '"') {
      if (character == '\'' && word.size() == 1U && (word == "e" || word == "E"))
        return std::string("Not run: use plain quotes ('...') instead of an escape string (E'...').");
      if (const auto refusal = check_word())
        return refusal;
      ++index;
      while (index < text.size()) {
        if (text[index] == character) {
          if (index + 1U < text.size() && text[index + 1U] == character) {
            index += 2U;
            continue;
          }
          break;
        }
        ++index;
      }
      continue;
    }
    if (character == '$' && index + 1U < text.size() &&
        (text[index + 1U] == '$' || std::isalpha(static_cast<unsigned char>(text[index + 1U])) != 0 || text[index + 1U] == '_'))
      return std::string("Not run: use plain quotes ('...') instead of dollar quotes ($$...$$).");
    if (is_word_character(character)) {
      word += character;
      continue;
    }
    if (const auto refusal = check_word())
      return refusal;
  }
  return check_word();
}

const std::vector<SqlNamedQuery>& postgres_named_queries() {
  static const std::vector<SqlNamedQuery> queries = [] {
    std::vector<SqlNamedQuery> parsed;
    for (const JsonValue& item : data_file("postgres-checks.json")["queries"].items()) {
      SqlNamedQuery query{item["name"].as_string(), item["sql"].as_string(), {}};
      for (const JsonValue& column : item["main_columns"].items())
        query.main_columns.push_back(column.as_string());
      parsed.push_back(std::move(query));
    }
    return parsed;
  }();
  return queries;
}

}  // namespace support_assist
