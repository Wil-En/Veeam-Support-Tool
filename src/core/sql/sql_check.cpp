// SQL Tools' checks: the statements each check sends and the rows it makes of what comes back. The
// statements are SELECTs, system functions and fixed SELECTs inside a named database; the lists
// they are held against are data (config/checks/sql-permissions.json, sql-shape-notes.json,
// sql-queries.json).
#include "support_assist/sql_check.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/installed_products.hpp"
#include "support_assist/postgres_check.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/volume_check.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdlib>
#include <initializer_list>
#include <iterator>
#include <map>
#include <optional>
#include <set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace support_assist {

namespace {

// ------------------------------------------------------------------------------------- data

struct NamedSource {
  std::string title;
  std::string url;
};

std::map<std::string, NamedSource> read_sources(const JsonValue& value) {
  std::map<std::string, NamedSource> sources;
  for (const auto& [key, source] : value["sources"].members())
    sources[key] = {source["title"].as_string(), source["url"].as_string()};
  return sources;
}

struct PermissionData {
  std::string guest_url;
  std::string guest_section;
  std::vector<std::string> full_roles;
  std::vector<std::string> minimal_roles;
  std::vector<std::string> minimal_securables;
  std::vector<std::pair<std::string, std::vector<std::string>>> minimal_databases;
  std::string config_url;
  std::string config_section;
  std::string config_default_name = "VeeamBackup";
  std::vector<std::string> install_securables;
  std::vector<std::string> operation_roles;
  std::vector<std::string> operation_permissions;
  std::string operation_alternative = "db_owner";
  std::string upgrade_role = "db_owner";
};

const PermissionData& permission_data() {
  static const PermissionData data = [] {
    PermissionData parsed;
    const JsonValue& value = data_file("sql-permissions.json");
    const auto sources = read_sources(value);
    auto url_of = [&sources](const std::string& id) {
      const auto found = sources.find(id);
      return found == sources.end() ? std::string() : found->second.url;
    };
    const JsonValue& guest = value["guest_processing"];
    parsed.guest_url = url_of(guest["source"].as_string());
    parsed.guest_section = guest["section"].as_string();
    parsed.full_roles = guest["full_server_roles"].string_items();
    parsed.minimal_roles = guest["minimal"]["server_roles"].string_items();
    parsed.minimal_securables = guest["minimal"]["securables"].string_items();
    for (const auto& [database, roles] : guest["minimal"]["databases"].members())
      parsed.minimal_databases.emplace_back(database, roles.string_items());
    const JsonValue& config = value["configuration_database"];
    parsed.config_url = url_of(config["source"].as_string());
    parsed.config_section = config["section"].as_string();
    parsed.config_default_name = config["default_name"].as_string("VeeamBackup");
    parsed.install_securables = config["install_securables"].string_items();
    parsed.operation_roles = config["operation_roles"].string_items();
    parsed.operation_permissions = config["operation_permissions"].string_items();
    parsed.operation_alternative = config["operation_alternative_role"].as_string("db_owner");
    parsed.upgrade_role = config["upgrade_role"].as_string("db_owner");
    return parsed;
  }();
  return data;
}

struct ShapeNote {
  std::string text;
  std::string url;
};

// A shape can carry several notes, one per Veeam page that speaks to it, in the file's order.
const std::map<std::string, std::vector<ShapeNote>>& shape_notes() {
  static const std::map<std::string, std::vector<ShapeNote>> notes = [] {
    std::map<std::string, std::vector<ShapeNote>> parsed;
    const JsonValue& value = data_file("sql-shape-notes.json");
    const auto sources = read_sources(value);
    for (const JsonValue& item : value["notes"].items()) {
      const auto source = sources.find(item["source"].as_string());
      parsed[item["shape"].as_string()].push_back(
          {item["text"].as_string(), source == sources.end() ? std::string() : source->second.url});
    }
    return parsed;
  }();
  return notes;
}

void add_note(SqlCheckReport& report, const std::string& shape, std::set<std::string>& shown) {
  if (!shown.insert(shape).second)
    return;
  const auto found = shape_notes().find(shape);
  if (found == shape_notes().end())
    return;
  for (const ShapeNote& note : found->second)
    report.rows.push_back({"Guide", "What the guide says", note.text, SqlCheckStatus::info, note.url});
}

// The Microsoft page that describes a kind of availability group ("distributed", "clusterless",
// "external", "basic", "contained", else "default"), from the file's topology table.
std::string topology_url(const std::string& kind) {
  static const std::map<std::string, std::string> urls = [] {
    std::map<std::string, std::string> parsed;
    const JsonValue& value = data_file("sql-shape-notes.json");
    const auto sources = read_sources(value);
    for (const auto& [name, source] : value["topology"].members()) {
      const auto found = sources.find(source.as_string());
      if (found != sources.end())
        parsed[name] = found->second.url;
    }
    return parsed;
  }();
  const auto found = urls.find(kind);
  return found != urls.end() ? found->second : std::string();
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
    if (ascii_lower(set.columns[index]) == ascii_lower(std::string(name)))
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

bool truthy(const std::string& value) {
  return value == "1" || ascii_lower(value) == "true";
}

std::string joined(const std::vector<std::string>& items, const std::string& separator = ", ") {
  std::string text;
  for (const std::string& item : items)
    text += (text.empty() ? "" : separator) + item;
  return text;
}

bool starts_with_ci(std::string_view text, std::string_view prefix) {
  return text.size() >= prefix.size() && ascii_lower(std::string(text.substr(0, prefix.size()))) ==
                                             ascii_lower(std::string(prefix));
}

// ------------------------------------------------------------------------------------- permissions

std::vector<std::string> permission_databases(const SqlPermissionCheckOptions& options) {
  const PermissionData& data = permission_data();
  if (options.target == SqlPermissionTarget::configuration_database)
    return {options.configuration_database.empty() ? data.config_default_name : options.configuration_database};
  std::vector<std::string> databases;
  for (const auto& [database, roles] : data.minimal_databases)
    databases.push_back(database);
  return databases;
}

std::vector<std::string> server_roles_checked() {
  const PermissionData& data = permission_data();
  std::vector<std::string> roles = data.full_roles;
  for (const std::string& role : data.minimal_roles) {
    if (std::find(roles.begin(), roles.end(), role) == roles.end())
      roles.push_back(role);
  }
  return roles;
}

std::vector<std::string> securables_checked() {
  const PermissionData& data = permission_data();
  std::vector<std::string> securables = data.minimal_securables;
  for (const std::string& securable : data.install_securables) {
    if (std::find(securables.begin(), securables.end(), securable) == securables.end())
      securables.push_back(securable);
  }
  return securables;
}

// Statement order: P1, P2, then P3 for each database; with another account, its principal, server
// roles, server permissions, then its users and roles in each database.
constexpr std::size_t kWho = 0;
constexpr std::size_t kServerRights = 1;
constexpr std::size_t kDatabaseRights = 2;

std::string database_rights_statement(const std::string& database) {
  std::string inner = "SELECT DB_NAME() AS db";
  for (const char* role : {"db_owner", "db_backupoperator", "db_datareader", "db_datawriter", "db_denydatareader", "public"})
    inner += std::string(", IS_MEMBER(''") + role + "'') AS [" + role + "]";
  inner += ", HAS_PERMS_BY_NAME(DB_NAME(), ''DATABASE'', ''EXECUTE'') AS [EXECUTE]";
  return "EXEC " + sql_quote_name(database) + ".sys.sp_executesql N'" + inner + "'";
}

struct Rights {
  bool read = false;          // the rows were read
  bool visible = true;        // another account: the catalog rows can be seen
  bool exists = true;         // another account: a login of that name
  std::set<std::string> server_roles;
  std::set<std::string> securables;
  std::map<std::string, std::set<std::string>> database_roles; // database: roles and permissions held
  std::map<std::string, std::string> database_errors;           // database: why it was not read
};

Rights this_account_rights(const SqlBatchResult& batch, const std::vector<std::string>& databases) {
  Rights rights;
  if (const SqlResultSet* set = first_set(batch, kServerRights); set != nullptr && !set->rows.empty()) {
    rights.read = true;
    for (const std::string& role : server_roles_checked()) {
      if (truthy(cell(*set, 0, "role:" + role)))
        rights.server_roles.insert(role);
    }
    for (const std::string& securable : securables_checked()) {
      if (truthy(cell(*set, 0, "perm:" + securable)))
        rights.securables.insert(securable);
    }
  }
  for (std::size_t index = 0; index < databases.size(); ++index) {
    const SqlResultSet* set = first_set(batch, kDatabaseRights + index);
    if (set == nullptr || set->rows.empty()) {
      rights.database_errors[databases[index]] = statement_error(batch, kDatabaseRights + index);
      continue;
    }
    auto& held = rights.database_roles[databases[index]];
    for (const char* role : {"db_owner", "db_backupoperator", "db_datareader", "db_datawriter", "db_denydatareader", "public"}) {
      if (truthy(cell(*set, 0, role)))
        held.insert(role);
    }
    if (truthy(cell(*set, 0, "EXECUTE")))
      held.insert("EXECUTE");
  }
  return rights;
}

Rights other_account_rights(const SqlBatchResult& batch, const std::vector<std::string>& databases, bool can_see) {
  Rights rights;
  const std::size_t base = kDatabaseRights + databases.size();
  const SqlResultSet* principal = first_set(batch, base);
  if (principal == nullptr)
    return rights;
  rights.read = true;
  rights.visible = can_see;
  rights.exists = !principal->rows.empty();
  if (const SqlResultSet* roles = first_set(batch, base + 1)) {
    for (std::size_t row = 0; row < roles->rows.size(); ++row)
      rights.server_roles.insert(cell(*roles, row, "role_name"));
  }
  if (rights.exists)
    rights.server_roles.insert("public");
  if (const SqlResultSet* granted = first_set(batch, base + 2)) {
    for (std::size_t row = 0; row < granted->rows.size(); ++row) {
      const std::string state = cell(*granted, row, "state_desc");
      if (state == "GRANT" || state == "GRANT_WITH_GRANT_OPTION")
        rights.securables.insert(cell(*granted, row, "permission_name"));
    }
  }
  for (std::size_t index = 0; index < databases.size(); ++index) {
    const SqlResultSet* users = first_set(batch, base + 3 + index);
    if (users == nullptr) {
      rights.database_errors[databases[index]] = statement_error(batch, base + 3 + index);
      continue;
    }
    if (users->rows.empty())
      continue; // no user for that account in the database
    auto& held = rights.database_roles[databases[index]];
    held.insert("public");
    for (std::size_t row = 0; row < users->rows.size(); ++row) {
      const std::string role = cell(*users, row, "role_name");
      if (!role.empty())
        held.insert(role);
      const std::string permission = cell(*users, row, "permission_name");
      const std::string state = cell(*users, row, "state_desc");
      if (!permission.empty() && (state == "GRANT" || state == "GRANT_WITH_GRANT_OPTION"))
        held.insert(permission);
    }
  }
  return rights;
}

std::vector<std::string> missing_from(const std::vector<std::string>& wanted, const std::set<std::string>& held) {
  std::vector<std::string> missing;
  for (const std::string& item : wanted) {
    if (held.count(item) == 0U)
      missing.push_back(item);
  }
  return missing;
}

} // namespace

// ------------------------------------------------------------------------------------- public

std::string to_string(SqlCheckStatus status) {
  switch (status) {
  case SqlCheckStatus::pass:
    return "Pass";
  case SqlCheckStatus::attention:
    return "Attention";
  case SqlCheckStatus::fail:
    return "Fail";
  case SqlCheckStatus::not_applicable:
    return "Not applicable";
  case SqlCheckStatus::could_not_check:
    return "Could not check";
  case SqlCheckStatus::chain_ok:
    return "OK";
  case SqlCheckStatus::chain_base:
    return "Base";
  case SqlCheckStatus::chain_base_changed:
    return "Base changed";
  case SqlCheckStatus::chain_lost:
    return "Lost";
  case SqlCheckStatus::chain_after_loss:
    return "After loss";
  case SqlCheckStatus::chain_new_chain:
    return "New chain";
  case SqlCheckStatus::chain_gap_before:
    return "Gap before";
  case SqlCheckStatus::section:
    return "";
  case SqlCheckStatus::info:
  default:
    return "Info";
  }
}

std::string sql_string_literal(std::string_view text) {
  std::string literal = "N'";
  for (const char character : text) {
    if (static_cast<unsigned char>(character) < 0x20U)
      continue;
    literal += character;
    if (character == '\'')
      literal += '\'';
  }
  return literal + "'";
}

std::string sql_quote_name(std::string_view name) {
  std::string quoted = "[";
  for (const char character : name) {
    if (static_cast<unsigned char>(character) < 0x20U)
      continue;
    quoted += character;
    if (character == ']')
      quoted += ']';
  }
  return quoted + "]";
}

std::vector<std::string> sql_permission_statements(const SqlPermissionCheckOptions& options) {
  std::vector<std::string> statements;
  statements.push_back(
      "SELECT SUSER_SNAME() AS login_name, ORIGINAL_LOGIN() AS original_login, "
      "CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) AS server_name, "
      "CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(128)) AS version, "
      "CAST(SERVERPROPERTY('ProductLevel') AS nvarchar(128)) AS level, "
      "CAST(SERVERPROPERTY('Edition') AS nvarchar(128)) AS edition, "
      "CAST(SERVERPROPERTY('IsClustered') AS int) AS is_clustered, "
      "CAST(SERVERPROPERTY('IsHadrEnabled') AS int) AS is_hadr_enabled");
  std::string rights = "SELECT 1 AS checked";
  for (const std::string& role : server_roles_checked())
    rights += ", IS_SRVROLEMEMBER(" + sql_string_literal(role) + ") AS " + sql_quote_name("role:" + role);
  for (const std::string& securable : securables_checked())
    rights += ", HAS_PERMS_BY_NAME(NULL, NULL, " + sql_string_literal(securable) + ") AS " +
              sql_quote_name("perm:" + securable);
  statements.push_back(rights);
  const std::vector<std::string> databases = permission_databases(options);
  for (const std::string& database : databases)
    statements.push_back(database_rights_statement(database));
  if (!options.another_account.empty()) {
    const std::string name = sql_string_literal(options.another_account);
    statements.push_back("SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE name = " + name);
    statements.push_back(
        "SELECT r.name AS role_name FROM sys.server_role_members m "
        "JOIN sys.server_principals r ON r.principal_id = m.role_principal_id "
        "JOIN sys.server_principals u ON u.principal_id = m.member_principal_id WHERE u.name = " + name);
    statements.push_back(
        "SELECT p.permission_name, p.state_desc FROM sys.server_permissions p "
        "JOIN sys.server_principals u ON u.principal_id = p.grantee_principal_id WHERE u.name = " + name);
    for (const std::string& database : databases) {
      const std::string db = sql_quote_name(database);
      statements.push_back(
          "SELECT u.name AS user_name, r.name AS role_name, p.permission_name, p.state_desc FROM " + db +
          ".sys.database_principals u LEFT JOIN " + db +
          ".sys.database_role_members m ON m.member_principal_id = u.principal_id LEFT JOIN " + db +
          ".sys.database_principals r ON r.principal_id = m.role_principal_id LEFT JOIN " + db +
          ".sys.database_permissions p ON p.grantee_principal_id = u.principal_id AND p.class = 0 "
          "WHERE u.sid = SUSER_SID(" + name + ")");
    }
  }
  return statements;
}

SqlCheckReport evaluate_sql_permissions(const SqlBatchResult& batch, const SqlConnection& connection,
                                        const SqlPermissionCheckOptions& options) {
  SqlCheckReport report;
  const PermissionData& data = permission_data();
  const SqlResultSet* who = first_set(batch, kWho);
  if (who == nullptr || who->rows.empty()) {
    report.rows.push_back({"Connection", "Who is connected", statement_error(batch, kWho), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  const std::string login = cell(*who, 0, "login_name");
  const std::string server = cell(*who, 0, "server_name");
  report.rows.push_back(
      {"Connection", "Who is connected",
       "Connected as " + login + (connection.integrated ? " (Windows authentication)" : " (SQL login)") + " to " +
           server + ", SQL Server " + cell(*who, 0, "version") + " " + cell(*who, 0, "level") + ", " +
           cell(*who, 0, "edition") + (batch.driver.empty() ? std::string() : ", through " + batch.driver) + ".",
       SqlCheckStatus::info, ""});

  const std::vector<std::string> databases = permission_databases(options);
  const Rights mine = this_account_rights(batch, databases);
  const bool other = !options.another_account.empty();
  const bool can_see = mine.server_roles.count("sysadmin") != 0U || mine.securables.count("VIEW ANY DEFINITION") != 0U;
  const Rights rights = other ? other_account_rights(batch, databases, can_see) : mine;
  const std::string subject = other ? options.another_account : login;

  if (other) {
    report.rows.push_back({"Account", "Account checked",
                           options.another_account +
                               ", from its catalog rows. Rights it gets through a Windows group are not counted.",
                           SqlCheckStatus::info, ""});
    if (!rights.read) {
      report.rows.push_back({"Account", "Catalog rows", statement_error(batch, kDatabaseRights + databases.size()),
                             SqlCheckStatus::could_not_check, ""});
      return report;
    }
    if (!rights.exists) {
      report.rows.push_back(
          {"Account", "Login", can_see ? "No login named " + options.another_account + " on " + server + "."
                                       : login + " cannot see other logins (it needs VIEW ANY DEFINITION or sysadmin), "
                                                 "so " + options.another_account + " could not be looked up.",
           can_see ? SqlCheckStatus::fail : SqlCheckStatus::could_not_check, ""});
      return report;
    }
  } else if (!rights.read) {
    report.rows.push_back({"Account", "Server rights", statement_error(batch, kServerRights), SqlCheckStatus::could_not_check, ""});
    return report;
  }

  const bool sysadmin = rights.server_roles.count("sysadmin") != 0U;
  if (options.target == SqlPermissionTarget::guest_processing) {
    const std::string area = "Guest processing";
    const std::vector<std::string> full_missing = missing_from(data.full_roles, rights.server_roles);
    report.rows.push_back({area, "Full permissions (" + joined(data.full_roles) + ")",
                           full_missing.empty()
                               ? subject + " is a member of " + joined(data.full_roles) + " on " + server +
                                     ", which meets the guest processing requirement (" + data.guest_section + ")."
                               : subject + " is not a member of " + joined(full_missing) +
                                     ". The minimal permissions below are the alternative the guide lists.",
                           full_missing.empty() ? SqlCheckStatus::pass : SqlCheckStatus::attention, data.guest_url});
    auto minimal_row = [&](const std::string& check, const std::vector<std::string>& missing, const std::string& extra) {
      if (sysadmin) {
        report.rows.push_back({area, check, "Covered by sysadmin.", SqlCheckStatus::pass, data.guest_url});
        return;
      }
      report.rows.push_back({area, check,
                             missing.empty() ? "All held." + extra : "Missing: " + joined(missing) + "." + extra,
                             missing.empty() ? SqlCheckStatus::pass : SqlCheckStatus::fail, data.guest_url});
    };
    minimal_row("Minimal: server roles (" + joined(data.minimal_roles) + ")",
                missing_from(data.minimal_roles, rights.server_roles), "");
    minimal_row("Minimal: securables (" + joined(data.minimal_securables) + ")",
                missing_from(data.minimal_securables, rights.securables), "");
    for (const auto& [database, roles] : data.minimal_databases) {
      const auto error = rights.database_errors.find(database);
      const auto held = rights.database_roles.find(database);
      std::string extra;
      std::vector<std::string> missing = roles;
      if (held != rights.database_roles.end())
        missing = missing_from(roles, held->second);
      else if (error != rights.database_errors.end())
        extra = " " + subject + " could not open " + database + ": " + error->second;
      else if (other)
        extra = " " + subject + " has no user in " + database + ".";
      minimal_row("Minimal: " + database + " (" + joined(roles) + ")", missing, extra);
    }
  } else {
    const std::string area = "Configuration database";
    const std::string database = databases.front();
    const std::vector<std::string> install_missing = missing_from(data.install_securables, rights.securables);
    report.rows.push_back({area, "Installation (" + joined(data.install_securables) + ")",
                           sysadmin || install_missing.empty()
                               ? subject + " can create databases on " + server + "."
                               : subject + " lacks " + joined(install_missing) + ", needed to create the configuration database.",
                           sysadmin || install_missing.empty() ? SqlCheckStatus::pass : SqlCheckStatus::attention,
                           data.config_url});
    const auto held = rights.database_roles.find(database);
    const auto error = rights.database_errors.find(database);
    if (held == rights.database_roles.end()) {
      report.rows.push_back({area, "Operation on " + database,
                             error != rights.database_errors.end()
                                 ? subject + " could not open " + database + ": " + error->second
                                 : subject + " has no user in " + database + ".",
                             sysadmin ? SqlCheckStatus::pass : SqlCheckStatus::fail, data.config_url});
    } else {
      std::vector<std::string> wanted = data.operation_roles;
      wanted.insert(wanted.end(), data.operation_permissions.begin(), data.operation_permissions.end());
      const std::vector<std::string> missing = missing_from(wanted, held->second);
      const bool owner = held->second.count(data.operation_alternative) != 0U;
      report.rows.push_back(
          {area, "Operation on " + database + " (" + joined(wanted) + ", or " + data.operation_alternative + ")",
           owner ? subject + " holds " + data.operation_alternative + " in " + database + "."
                 : missing.empty() ? subject + " holds " + joined(wanted) + " in " + database + "."
                                   : subject + " lacks " + joined(missing) + " in " + database + ".",
           owner || missing.empty() || sysadmin ? SqlCheckStatus::pass : SqlCheckStatus::fail, data.config_url});
      report.rows.push_back({area, "Upgrade (" + data.upgrade_role + " recommended)",
                             held->second.count(data.upgrade_role) != 0U || sysadmin
                                 ? subject + " holds " + data.upgrade_role + " in " + database + "."
                                 : subject + " does not hold " + data.upgrade_role + " in " + database +
                                       "; the guide recommends it for an upgrade.",
                             held->second.count(data.upgrade_role) != 0U || sysadmin ? SqlCheckStatus::pass
                                                                                     : SqlCheckStatus::attention,
                             data.config_url});
    }
  }
  return report;
}

// ------------------------------------------------------------------------------------- shape

// The group statement selects `ag.*`: sys.availability_groups gains columns with the version
// (basic_features, dtc_support and is_distributed in SQL Server 2016, cluster_type_desc in 2017,
// is_contained in 2022), and `*` returns exactly the columns the server has, so the statement runs on
// every version and the evaluation reads a missing column as not reported. A distributed group's
// replica rows name the member groups in replica_server_name, with their listener endpoints.
std::vector<std::string> sql_shape_statements() {
  return {
      "SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(256)) AS server_name, "
      "CAST(SERVERPROPERTY('MachineName') AS nvarchar(128)) AS machine, "
      "CAST(SERVERPROPERTY('ComputerNamePhysicalNetBIOS') AS nvarchar(128)) AS physical_node, "
      "CAST(SERVERPROPERTY('IsClustered') AS int) AS is_clustered, "
      "CAST(SERVERPROPERTY('IsHadrEnabled') AS int) AS is_hadr_enabled",
      "SELECT ag.*, ar.replica_server_name, ar.endpoint_url, ar.availability_mode_desc, ar.failover_mode_desc, "
      "ar.backup_priority, rs.role_desc, rs.synchronization_health_desc, rs.is_local FROM sys.availability_groups ag "
      "JOIN sys.availability_replicas ar ON ar.group_id = ag.group_id "
      "LEFT JOIN sys.dm_hadr_availability_replica_states rs ON rs.replica_id = ar.replica_id AND rs.group_id = ag.group_id "
      "ORDER BY ag.name, ar.replica_server_name",
      "SELECT ag.name AS ag_name, l.dns_name, l.port FROM sys.availability_group_listeners l "
      "JOIN sys.availability_groups ag ON ag.group_id = l.group_id",
      "SELECT cluster_name, quorum_type_desc, quorum_state_desc FROM sys.dm_hadr_cluster",
      "SELECT d.name, sys.fn_hadr_backup_is_preferred_replica(d.name) AS preferred FROM sys.databases d "
      "WHERE d.replica_id IS NOT NULL ORDER BY d.name",
      "SELECT NodeName, status_description, is_current_owner FROM sys.dm_os_cluster_nodes",
      "SELECT DriveName FROM sys.dm_io_cluster_shared_drives"};
}

namespace {

// How an availability group is managed, from its catalog row.
enum class GroupKind {
  distributed,      // is_distributed: a group of availability groups
  wsfc,             // cluster_type_desc WSFC
  clusterless,      // NONE: no cluster manager, as in a read-scale group
  external_manager, // EXTERNAL: a cluster manager outside SQL Server, such as Pacemaker
  other,            // a cluster type this code does not know
  unreported        // the version or the row carries no cluster type
};

// A bit column of the group's row: nullopt when the version has no such column or the value is NULL.
std::optional<bool> group_flag(const SqlResultSet& set, std::size_t row, std::string_view name) {
  if (is_null(set, row, name))
    return std::nullopt;
  return truthy(cell(set, row, name));
}

bool flag_set(const std::optional<bool>& flag) {
  return flag.has_value() && *flag;
}

GroupKind group_kind(const SqlResultSet& set, std::size_t row) {
  if (flag_set(group_flag(set, row, "is_distributed")))
    return GroupKind::distributed;
  const std::string type = ascii_upper(cell(set, row, "cluster_type_desc"));
  if (type == "WSFC")
    return GroupKind::wsfc;
  if (type == "NONE")
    return GroupKind::clusterless;
  if (type == "EXTERNAL")
    return GroupKind::external_manager;
  return type.empty() ? GroupKind::unreported : GroupKind::other;
}

std::string cluster_type_sentence(const SqlResultSet& set, std::size_t row, GroupKind kind) {
  switch (kind) {
  case GroupKind::wsfc:
    return "Cluster type WSFC: a Windows Server Failover Cluster manages failover.";
  case GroupKind::clusterless:
    return "Cluster type NONE: a clusterless (read-scale) availability group. No cluster manages failover, so a "
           "failover is done by hand.";
  case GroupKind::external_manager:
    return "Cluster type EXTERNAL: an external cluster manager, such as Pacemaker on Linux, manages failover.";
  case GroupKind::other:
    return "Cluster type " + cell(set, row, "cluster_type_desc") + ".";
  case GroupKind::distributed:
  case GroupKind::unreported:
    break;
  }
  if (column_of(set, "cluster_type_desc"))
    return "The cluster type was not read.";
  return "This SQL Server version does not report the cluster type (SQL Server 2017 added it). Before then an "
         "availability group always runs on a Windows Server Failover Cluster.";
}

// Distributed, Basic, contained and DTC support as yes or no; a column the version lacks is named
// as not reported.
std::string group_flags_sentence(const SqlResultSet& set, std::size_t row) {
  struct Flag {
    const char* column;
    const char* label;
    const char* plain;
  };
  static const Flag flags[] = {{"is_distributed", "Distributed", "distributed"},
                               {"basic_features", "Basic", "Basic"},
                               {"is_contained", "Contained", "contained"},
                               {"dtc_support", "DTC support", "DTC support"}};
  std::string text;
  std::vector<std::string> missing;
  for (const Flag& flag : flags) {
    const std::optional<bool> value = group_flag(set, row, flag.column);
    if (!value) {
      missing.emplace_back(flag.plain);
      continue;
    }
    text += std::string(text.empty() ? "" : " ") + flag.label + ": " + (*value ? "yes." : "no.");
  }
  if (!missing.empty())
    text += std::string(text.empty() ? "" : " ") + "Not reported by this SQL Server version: " + joined(missing) + ".";
  return text;
}

// What a Basic or a contained group is, as Microsoft describes them.
std::string group_extra_sentences(const SqlResultSet& set, std::size_t row) {
  std::string text;
  if (flag_set(group_flag(set, row, "basic_features")))
    text += " A Basic availability group is limited to one database and two replicas, with no read access or "
            "backups on the secondary replica.";
  if (flag_set(group_flag(set, row, "is_contained")))
    text += " A contained availability group carries its own master and msdb contents (logins, permissions and "
            "Agent jobs) with the group.";
  return text;
}

// The Microsoft page behind the Type row.
std::string type_source(const SqlResultSet& set, std::size_t row, GroupKind kind) {
  if (flag_set(group_flag(set, row, "is_contained")))
    return topology_url("contained");
  if (flag_set(group_flag(set, row, "basic_features")))
    return topology_url("basic");
  if (kind == GroupKind::clusterless)
    return topology_url("clusterless");
  if (kind == GroupKind::external_manager)
    return topology_url("external");
  return topology_url("default");
}

} // namespace

SqlCheckReport evaluate_sql_shape(const SqlBatchResult& batch) {
  SqlCheckReport report;
  std::set<std::string> shown;
  const SqlResultSet* instance = first_set(batch, 0);
  if (instance == nullptr || instance->rows.empty()) {
    report.rows.push_back({"Instance", "Instance", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  const std::string server = cell(*instance, 0, "server_name");
  const bool clustered = truthy(cell(*instance, 0, "is_clustered"));
  const bool hadr = truthy(cell(*instance, 0, "is_hadr_enabled"));
  if (clustered) {
    std::vector<std::string> nodes;
    if (const SqlResultSet* set = first_set(batch, 5)) {
      for (std::size_t row = 0; row < set->rows.size(); ++row)
        nodes.push_back(cell(*set, row, "NodeName") + " (" + cell(*set, row, "status_description") +
                        (truthy(cell(*set, row, "is_current_owner")) ? ", owner)" : ")"));
    }
    std::vector<std::string> drives;
    if (const SqlResultSet* set = first_set(batch, 6)) {
      for (std::size_t row = 0; row < set->rows.size(); ++row)
        drives.push_back(cell(*set, row, "DriveName"));
    }
    report.rows.push_back({"Instance", "Failover cluster instance",
                           server + " runs on node " + cell(*instance, 0, "physical_node") + ". Nodes: " +
                               (nodes.empty() ? std::string("not read") : joined(nodes)) +
                               (drives.empty() ? std::string() : ". Cluster disks: " + joined(drives)) + ".",
                           SqlCheckStatus::info, ""});
    add_note(report, "fci", shown);
  } else {
    report.rows.push_back({"Instance", "Standalone instance",
                           server + " on " + cell(*instance, 0, "machine") + " is not a failover cluster instance.",
                           SqlCheckStatus::info, ""});
  }
  if (!hadr) {
    report.rows.push_back({"Always On", "Availability groups", "Always On availability groups are not enabled on " + server + ".",
                           SqlCheckStatus::not_applicable, ""});
    return report;
  }
  const SqlResultSet* replicas = first_set(batch, 1);
  if (replicas == nullptr) {
    report.rows.push_back({"Always On", "Availability groups", statement_error(batch, 1), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  if (replicas->rows.empty()) {
    report.rows.push_back({"Always On", "Availability groups", "Always On is enabled, and " + server + " is in no availability group.",
                           SqlCheckStatus::info, ""});
  }
  std::map<std::string, std::vector<std::size_t>> groups;
  std::vector<std::string> order;
  for (std::size_t row = 0; row < replicas->rows.size(); ++row) {
    const std::string name = cell(*replicas, row, "name");
    if (groups.find(name) == groups.end())
      order.push_back(name);
    groups[name].push_back(row);
  }
  std::map<std::string, std::vector<std::string>> listeners;
  if (const SqlResultSet* set = first_set(batch, 2)) {
    for (std::size_t row = 0; row < set->rows.size(); ++row)
      listeners[cell(*set, row, "ag_name")].push_back(cell(*set, row, "dns_name") + ":" + cell(*set, row, "port"));
  }
  std::string cluster;
  if (const SqlResultSet* set = first_set(batch, 3); set != nullptr && !set->rows.empty())
    cluster = cell(*set, 0, "cluster_name");
  // The groups on this instance, by lower-case name: a distributed group's members say which of
  // them are here.
  std::map<std::string, std::string> local_groups;
  for (const std::string& name : order) {
    if (group_kind(*replicas, groups[name].front()) != GroupKind::distributed)
      local_groups[ascii_lower(name)] = name;
  }
  for (const std::string& name : order) {
    const std::vector<std::size_t>& rows = groups[name];
    const std::size_t first = rows.front();
    const GroupKind kind = group_kind(*replicas, first);
    const bool distributed = kind == GroupKind::distributed;
    std::vector<std::string> members;
    std::vector<std::string> member_names;
    bool unhealthy = false;
    for (const std::size_t row : rows) {
      const std::string role = cell(*replicas, row, "role_desc");
      const std::string health = cell(*replicas, row, "synchronization_health_desc");
      if (!health.empty() && health != "HEALTHY")
        unhealthy = true;
      if (distributed) {
        // A distributed group's replica rows are its member availability groups.
        const std::string member = cell(*replicas, row, "replica_server_name");
        const std::string endpoint = cell(*replicas, row, "endpoint_url");
        std::vector<std::string> facts;
        if (const auto here = local_groups.find(ascii_lower(member)); here != local_groups.end()) {
          const auto listener = listeners.find(here->second);
          facts.push_back("an availability group on this instance");
          facts.push_back(listener == listeners.end() ? std::string("no listener")
                                                      : "listener " + joined(listener->second));
        }
        if (!endpoint.empty())
          facts.push_back("endpoint " + endpoint);
        if (!cell(*replicas, row, "availability_mode_desc").empty())
          facts.push_back(cell(*replicas, row, "availability_mode_desc"));
        if (!cell(*replicas, row, "failover_mode_desc").empty())
          facts.push_back(cell(*replicas, row, "failover_mode_desc") + " failover");
        if (!role.empty())
          facts.push_back(role);
        if (!health.empty())
          facts.push_back(health);
        member_names.push_back(member);
        members.push_back(member + (facts.empty() ? std::string() : " (" + joined(facts) + ")"));
        continue;
      }
      members.push_back(cell(*replicas, row, "replica_server_name") + " (" + (role.empty() ? "role not read" : role) + ", " +
                        cell(*replicas, row, "availability_mode_desc") + ", backup priority " +
                        cell(*replicas, row, "backup_priority") + (health.empty() ? "" : ", " + health) + ")");
      if (truthy(cell(*replicas, row, "is_local")) && role == "SECONDARY")
        add_note(report, "secondary_replica", shown);
    }
    const std::string area = (distributed ? "Distributed availability group " : "Availability group ") + name;
    const bool basic = flag_set(group_flag(*replicas, first, "basic_features"));
    const bool contained = flag_set(group_flag(*replicas, first, "is_contained"));

    if (distributed) {
      report.rows.push_back(
          {area, "Type",
           "Distributed availability group spanning " + std::to_string(member_names.size()) +
               (member_names.size() == 1U ? " availability group: " : " availability groups: ") + joined(member_names) +
               ". It has no listener of its own; each member availability group has one.",
           SqlCheckStatus::info, topology_url("distributed")});
      report.rows.push_back({area, "Member availability groups", joined(members, "; ") + ".",
                             unhealthy ? SqlCheckStatus::attention : SqlCheckStatus::info, ""});
      add_note(report, "distributed_ag", shown);
      continue;
    }

    report.rows.push_back({area, "Type",
                           cluster_type_sentence(*replicas, first, kind) + " " + group_flags_sentence(*replicas, first) +
                               group_extra_sentences(*replicas, first),
                           SqlCheckStatus::info, type_source(*replicas, first, kind)});
    const std::string preference = cell(*replicas, first, "automated_backup_preference_desc");
    std::string detail = "Replicas: " + joined(members) + ".";
    if (!preference.empty())
      detail += " Backup preference: " + preference + ".";
    const auto listener = listeners.find(name);
    detail += listener == listeners.end() ? std::string(" No listener.") : " Listener: " + joined(listener->second) + ".";
    // The cluster's name is read for a Windows Server Failover Cluster; a group that uses no
    // cluster, or an outside cluster manager, gets internal placeholder values from that view.
    if (!cluster.empty() && (kind == GroupKind::wsfc || kind == GroupKind::unreported))
      detail += " Cluster: " + cluster + ".";
    report.rows.push_back({area, "Replicas and backup preference", detail,
                           unhealthy ? SqlCheckStatus::attention : SqlCheckStatus::info, ""});
    if (!preference.empty())
      add_note(report, "backup_preference", shown);
    // A Basic group gets no support note; the Type row describes it only.
    if (contained)
      add_note(report, "contained_ag", shown);
    else if (!basic && (kind == GroupKind::wsfc || kind == GroupKind::unreported))
      add_note(report, "wsfc_ag", shown);
    else if (!basic && kind == GroupKind::clusterless)
      add_note(report, "clusterless_ag", shown);
    if (clustered)
      add_note(report, "ag_on_fci", shown);
  }
  if (const SqlResultSet* set = first_set(batch, 4); set != nullptr && !set->rows.empty()) {
    std::vector<std::string> preferred;
    std::vector<std::string> other;
    for (std::size_t row = 0; row < set->rows.size(); ++row) {
      const std::string database = cell(*set, row, "name");
      (truthy(cell(*set, row, "preferred")) ? preferred : other).push_back(database);
      if (starts_with_ci(database, "Veeam"))
        add_note(report, "configuration_database_in_ag", shown);
    }
    report.rows.push_back({"Always On", "Preferred backup replica",
                           "This node is the preferred backup replica for: " +
                               (preferred.empty() ? std::string("none") : joined(preferred)) +
                               (other.empty() ? std::string() : ". Not for: " + joined(other)) + ".",
                           SqlCheckStatus::info, ""});
  }
  // Notes after the facts.
  std::stable_partition(report.rows.begin(), report.rows.end(),
                        [](const SqlCheckRow& row) { return row.area != "Guide"; });
  return report;
}

// ------------------------------------------------------------------------------------- backups

namespace {

// LSNs are numeric(25,0): compared as decimal text, without leading zeros or a decimal part.
std::string plain_lsn(std::string value) {
  const std::size_t point = value.find('.');
  if (point != std::string::npos)
    value.resize(point);
  const std::size_t first = value.find_first_not_of('0');
  return first == std::string::npos ? std::string("0") : value.substr(first);
}

int compare_lsn(const std::string& left_text, const std::string& right_text) {
  const std::string left = plain_lsn(left_text);
  const std::string right = plain_lsn(right_text);
  if (left.size() != right.size())
    return left.size() < right.size() ? -1 : 1;
  return left < right ? -1 : left > right ? 1 : 0;
}

std::string backup_kind(const std::string& type) {
  return type == "D" ? "full" : type == "I" ? "differential" : type == "L" ? "log" : "type " + type;
}

bool contains_ci(std::string_view text, std::string_view part) {
  return ascii_lower(std::string(text)).find(ascii_lower(std::string(part))) != std::string::npos;
}

// "{3F2504E0-4F89-11D3-9A0C-0305E82C3301}", with or without the braces: the device name a VSS
// snapshot backup records.
bool is_guid_text(std::string_view text) {
  if (text.size() == 38U && text.front() == '{' && text.back() == '}')
    text = text.substr(1, 36);
  if (text.size() != 36U)
    return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    const bool dash = index == 8U || index == 13U || index == 18U || index == 23U;
    if (dash ? text[index] != '-' : std::isxdigit(static_cast<unsigned char>(text[index])) == 0)
      return false;
  }
  return true;
}

bool is_nul_device(const std::string& device) {
  const std::string folded = ascii_lower(device);
  return folded == "nul" || folded == "nul:" || (folded.size() > 4U && folded.substr(folded.size() - 4U) == "\\nul");
}

enum class Taker { veeam, likely_veeam, image_tool, sql_server, other, unknown };

bool veeam_taker(Taker taker) {
  return taker == Taker::veeam || taker == Taker::likely_veeam;
}

// One backup of a database, read from msdb, with its place in the log chain.
struct ChainEntry {
  std::size_t row = 0;
  std::string type;
  bool copy_only = false;
  bool begins_chain = false;
  bool to_nul = false;
  std::string started;
  std::string when; // the time shown: the time alone when every backup shown is from one day
  std::string first_lsn;
  std::string last_lsn;
  std::string checkpoint_lsn;
  std::string base_lsn;
  std::string last_fork;
  Taker taker = Taker::unknown;
  std::string who;
  std::string label; // "Full A", "Log 3", "Differential", "Full, copy-only", "Log to NUL"
  std::string base;  // the letter of the full this backup is based on, when that full is in the window
  bool gap = false;  // a log backup that does not start where the log before it ended
  bool restart = false;
  std::string gap_from; // the LSN the log before it ended at
  SqlCheckStatus status = SqlCheckStatus::info;
  std::string detail;
};

std::string full_letter(std::size_t index) {
  if (index < 26U)
    return std::string(1, static_cast<char>('A' + static_cast<int>(index)));
  return std::to_string(index + 1U);
}

std::string lower_first(std::string text) {
  if (!text.empty())
    text.front() = static_cast<char>(std::tolower(static_cast<unsigned char>(text.front())));
  return text;
}

} // namespace

std::vector<std::string> sql_backup_statements(const SqlBackupOptions& options) {
  const std::string only = options.database.empty() ? std::string() : sql_string_literal(options.database);
  const int days = std::clamp(options.days, 1, 3650);
  return {
      "SELECT d.name, d.state_desc, d.recovery_model_desc, d.log_reuse_wait_desc, drs.last_log_backup_lsn "
      "FROM sys.databases d LEFT JOIN sys.database_recovery_status drs ON drs.database_id = d.database_id "
      "WHERE d.name <> 'tempdb'" + (only.empty() ? std::string() : " AND d.name = " + only) + " ORDER BY d.name",
      "SELECT bs.backup_set_id, bs.database_name, bs.type, bs.is_copy_only, bs.recovery_model, bs.begins_log_chain, "
      "bs.is_snapshot, CONVERT(varchar(19), bs.backup_start_date, 120) AS started, bs.first_lsn, bs.last_lsn, "
      "bs.checkpoint_lsn, bs.database_backup_lsn, "
      "CONVERT(varchar(36), bs.first_recovery_fork_guid) AS first_fork, "
      "CONVERT(varchar(36), bs.last_recovery_fork_guid) AS last_fork, bs.user_name, bs.machine_name, "
      "bms.software_name, bms.software_vendor_id, bmf.physical_device_name, bmf.device_type "
      "FROM msdb.dbo.backupset bs "
      "JOIN msdb.dbo.backupmediaset bms ON bms.media_set_id = bs.media_set_id "
      "OUTER APPLY (SELECT TOP (1) f.physical_device_name, f.device_type FROM msdb.dbo.backupmediafamily f "
      "WHERE f.media_set_id = bs.media_set_id ORDER BY f.family_sequence_number) bmf "
      "WHERE bs.backup_start_date >= DATEADD(DAY, -" + std::to_string(days) + ", SYSDATETIME())" +
          (only.empty() ? std::string() : " AND bs.database_name = " + only) +
          " ORDER BY bs.database_name, bs.backup_start_date, bs.backup_set_id"};
}

SqlCheckReport evaluate_sql_backups(const SqlBatchResult& batch, const SqlBackupOptions& options) {
  SqlCheckReport report;
  std::set<std::string> shown;
  const SqlResultSet* databases = first_set(batch, 0);
  const SqlResultSet* history = first_set(batch, 1);
  if (databases == nullptr) {
    report.rows.push_back({"Databases", "Recovery state", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  if (history == nullptr)
    report.rows.push_back({"msdb", "Backup history", statement_error(batch, 1), SqlCheckStatus::could_not_check, ""});
  const int days = std::clamp(options.days, 1, 3650);
  const std::string window = "in the last " + std::to_string(days) + (days == 1 ? " day" : " days");

  // Veeam's backups: the software name it records, then any vendor id seen with that name. 4608 is
  // Microsoft's own id, which SQL Server's native backups carry, so it never names Veeam.
  std::set<std::string> veeam_vendors;
  if (history != nullptr) {
    for (std::size_t row = 0; row < history->rows.size(); ++row) {
      const std::string vendor = cell(*history, row, "software_vendor_id");
      if (starts_with_ci(cell(*history, row, "software_name"), "Veeam") && !vendor.empty() && vendor != "4608")
        veeam_vendors.insert(vendor);
    }
  }
  // The device's own name, not its folders: a native backup to the default folder of an instance
  // named VEEAM or VEEAMSQL2016 has "Veeam" in its path.
  auto device_name = [&](std::size_t row) {
    const std::string device = cell(*history, row, "physical_device_name");
    const std::size_t separator = device.find_last_of("\\/");
    return separator == std::string::npos ? device : device.substr(separator + 1U);
  };
  auto names_veeam = [&](std::size_t row) {
    return starts_with_ci(cell(*history, row, "software_name"), "Veeam") ||
           contains_ci(device_name(row), "Veeam") ||
           veeam_vendors.count(cell(*history, row, "software_vendor_id")) != 0U;
  };
  auto vss_snapshot = [&](std::size_t row) {
    return truthy(cell(*history, row, "is_snapshot")) && cell(*history, row, "device_type") == "7" &&
           is_guid_text(cell(*history, row, "physical_device_name"));
  };

  std::map<std::string, std::vector<std::size_t>> rows_of_database;
  if (history != nullptr) {
    for (std::size_t row = 0; row < history->rows.size(); ++row)
      rows_of_database[cell(*history, row, "database_name")].push_back(row);
  }
  std::vector<std::pair<std::string, std::vector<SqlCheckRow>>> chains;
  for (std::size_t index = 0; index < databases->rows.size(); ++index) {
    const std::string name = cell(*databases, index, "name");
    const std::string model = cell(*databases, index, "recovery_model_desc");
    const std::string area = name;
    const auto listed = rows_of_database.find(name);
    const std::vector<std::size_t> rows = listed == rows_of_database.end() ? std::vector<std::size_t>() : listed->second;

    // Who took each backup, by general rules: Veeam by name; a VSS snapshot full as likely Veeam's
    // where Veeam is present, else another image-level tool; SQL Server's own; another product.
    bool database_has_veeam = false;
    for (const std::size_t row : rows)
      database_has_veeam = database_has_veeam || names_veeam(row);
    std::vector<ChainEntry> entries;
    bool one_day = true;
    for (const std::size_t row : rows) {
      ChainEntry entry;
      entry.row = row;
      entry.type = cell(*history, row, "type");
      entry.copy_only = truthy(cell(*history, row, "is_copy_only"));
      entry.begins_chain = truthy(cell(*history, row, "begins_log_chain"));
      entry.to_nul = entry.type == "L" && is_nul_device(cell(*history, row, "physical_device_name"));
      entry.started = cell(*history, row, "started");
      entry.first_lsn = cell(*history, row, "first_lsn");
      entry.last_lsn = cell(*history, row, "last_lsn");
      entry.checkpoint_lsn = cell(*history, row, "checkpoint_lsn");
      entry.base_lsn = cell(*history, row, "database_backup_lsn");
      entry.last_fork = cell(*history, row, "last_fork");
      const std::string user = cell(*history, row, "user_name");
      const std::string software = cell(*history, row, "software_name");
      const std::string vendor = cell(*history, row, "software_vendor_id");
      const std::string account = user.empty() ? std::string() : " (" + user + ")";
      if (names_veeam(row)) {
        entry.taker = Taker::veeam;
        entry.who = "Veeam";
      } else if (vss_snapshot(row) && (options.veeam_on_sql_host || database_has_veeam)) {
        entry.taker = Taker::likely_veeam;
        entry.who = "Likely Veeam (VSS snapshot)";
      } else if (vss_snapshot(row)) {
        entry.taker = Taker::image_tool;
        entry.who = "Another image-level tool (VSS snapshot" + (software.empty() ? std::string() : ", " + software) + ")";
      } else if (vendor == "4608" || starts_with_ci(software, "Microsoft SQL Server")) {
        entry.taker = Taker::sql_server;
        entry.who = "SQL Server" + account;
      } else if (!software.empty()) {
        entry.taker = Taker::other;
        entry.who = software + account;
      } else {
        entry.who = "Unknown" + account;
      }
      if (!entries.empty() && entries.front().started.substr(0, 10) != entry.started.substr(0, 10))
        one_day = false;
      entries.push_back(std::move(entry));
    }
    for (ChainEntry& entry : entries)
      entry.when = one_day && entry.started.size() > 11U ? entry.started.substr(11) : entry.started;

    // The chain, oldest first, per recovery fork: base fulls get letters, log backups numbers.
    std::map<std::string, std::string> full_by_checkpoint;
    std::map<std::string, std::size_t> entry_of_full;
    std::size_t letters = 0;
    std::size_t log_count = 0;
    // An index rather than std::optional: GCC's -Wmaybe-uninitialized misreads the optional here.
    constexpr std::size_t kNoLog = static_cast<std::size_t>(-1);
    std::size_t previous_log = kNoLog;
    std::string fork;
    bool base_seen = false;
    bool after_loss = false;
    std::string previous_base;
    auto based_on = [](const std::string& letter) {
      return letter.empty() ? std::string(" Based on a full before this window.") : " Based on full " + letter + ".";
    };
    for (std::size_t position = 0; position < entries.size(); ++position) {
      ChainEntry& entry = entries[position];
      if (!entry.last_fork.empty()) {
        if (!fork.empty() && entry.last_fork != fork) {
          previous_log = kNoLog;
          base_seen = false;
          after_loss = false;
          previous_base.clear();
        }
        fork = entry.last_fork;
      }
      const auto base = full_by_checkpoint.find(plain_lsn(entry.base_lsn));
      entry.base = base == full_by_checkpoint.end() || entry.base_lsn.empty() ? std::string() : base->second;
      if (entry.type == "D") {
        if (entry.copy_only) {
          entry.label = "Full, copy-only";
          entry.detail = "Does not change the chain.";
        } else {
          const std::string letter = full_letter(letters++);
          if (!entry.checkpoint_lsn.empty())
            full_by_checkpoint[plain_lsn(entry.checkpoint_lsn)] = letter;
          entry_of_full[letter] = position;
          entry.label = "Full " + letter;
          if (!base_seen) {
            entry.status = SqlCheckStatus::chain_base;
            entry.detail = "Starts the chain: checkpoint LSN " + entry.checkpoint_lsn + ".";
          } else {
            entry.status = SqlCheckStatus::chain_base_changed;
            entry.detail = "Not copy-only: the logs after it are based on full " + letter + ".";
          }
          base_seen = true;
        }
        after_loss = false;
        continue;
      }
      if (entry.type != "L") {
        entry.label = entry.type == "I" ? "Differential" : "Backup, " + backup_kind(entry.type);
        entry.detail = entry.type == "I" ? based_on(entry.base).substr(1) : std::string();
        after_loss = false;
        continue;
      }
      std::string text = "LSN " + entry.first_lsn + " to " + entry.last_lsn + ".";
      if (entry.copy_only) {
        entry.label = "Log, copy-only";
        entry.detail = text + " Copy-only: does not change the chain.";
        continue;
      }
      if (previous_log != kNoLog) {
        entry.gap_from = entries[previous_log].last_lsn;
        entry.gap = compare_lsn(entry.first_lsn, entry.gap_from) > 0;
        entry.restart = entry.begins_chain;
      }
      const std::string gap_text = " Gap before it: " + entry.gap_from + " to " + entry.first_lsn + ".";
      if (entry.to_nul) {
        entry.label = "Log to NUL";
        entry.status = SqlCheckStatus::chain_lost;
        entry.detail = text + " Written to NUL: this range is lost." + (entry.gap ? gap_text : std::string());
        after_loss = true;
      } else {
        entry.label = "Log " + std::to_string(++log_count);
        if (entry.restart) {
          entry.status = SqlCheckStatus::chain_ok;
          text += based_on(entry.base);
          const auto full = entry.base.empty() ? entry_of_full.end() : entry_of_full.find(entry.base);
          if (full != entry_of_full.end() && full->second > previous_log) {
            ChainEntry& start = entries[full->second];
            start.status = SqlCheckStatus::chain_new_chain;
            start.detail = "Checkpoint LSN " + start.checkpoint_lsn + "." +
                           (entry.gap ? gap_text : std::string(" The log chain starts again here."));
          } else {
            entry.status = SqlCheckStatus::chain_new_chain;
            text += entry.gap ? gap_text : std::string(" The log chain starts again here.");
          }
          after_loss = false;
        } else if (entry.gap) {
          entry.status = SqlCheckStatus::chain_gap_before;
          text += gap_text;
        } else if (previous_log == kNoLog) {
          entry.status = SqlCheckStatus::chain_ok;
          if (entry.begins_chain)
            text += based_on(entry.base) + " First log after the full.";
          else if (!entry.base.empty())
            text += based_on(entry.base);
        } else if (after_loss) {
          entry.status = SqlCheckStatus::chain_after_loss;
          text += entries[previous_log].to_nul
                      ? std::string(" Follows the lost range: restores stop before it.")
                      : " Follows " + lower_first(entries[previous_log].label) +
                            "; restores stop at the lost range before it.";
        } else if (entries[previous_log].to_nul) {
          entry.status = SqlCheckStatus::chain_ok;
          text += " Follows the log to NUL; a restore starts from the backup taken since.";
          if (!entry.base.empty() && entry.base != previous_base)
            text += based_on(entry.base);
        } else {
          entry.status = SqlCheckStatus::chain_ok;
          text += " Follows " + lower_first(entries[previous_log].label) + ".";
          if (!entry.base.empty() && entry.base != previous_base)
            text += based_on(entry.base);
        }
        entry.detail = text;
      }
      previous_log = position;
      previous_base = entry.base;
      base_seen = true;
    }

    // The summary: counts, copy-only fulls apart, and who took them.
    std::size_t full = 0;
    std::size_t copy_full = 0;
    std::size_t differential = 0;
    std::size_t log = 0;
    std::vector<std::pair<std::string, std::size_t>> takers;
    for (const ChainEntry& entry : entries) {
      full += entry.type == "D" && !entry.copy_only ? 1U : 0U;
      copy_full += entry.type == "D" && entry.copy_only ? 1U : 0U;
      differential += entry.type == "I" ? 1U : 0U;
      log += entry.type == "L" ? 1U : 0U;
      const auto known = std::find_if(takers.begin(), takers.end(),
                                      [&entry](const auto& taker) { return taker.first == entry.who; });
      if (known == takers.end())
        takers.emplace_back(entry.who, 1U);
      else
        ++known->second;
    }
    std::string summary = model + " recovery. " + std::to_string(full) + " full, " +
                          (copy_full == 0U ? std::string() : std::to_string(copy_full) + " copy-only full, ") +
                          std::to_string(differential) + " differential and " + std::to_string(log) + " log backups.";
    if (takers.size() == 1U) {
      summary += " Taken by: " + takers.front().first + ".";
    } else if (!takers.empty()) {
      std::vector<std::string> parts;
      for (const auto& [who, count] : takers)
        parts.push_back(who + ", " + std::to_string(count) + (count == 1U ? " backup" : " backups"));
      summary += " Taken by: " + joined(parts, "; ") + ".";
    }
    report.rows.push_back({area, "Backups " + window, summary, SqlCheckStatus::info, ""});

    const bool logged = model == "FULL" || model == "BULK_LOGGED";
    if (logged && is_null(*databases, index, "last_log_backup_lsn")) {
      report.rows.push_back({area, "Log backup possible",
                             "No log backup can be taken until a full backup exists (BACKUP LOG fails with no current "
                             "database backup)." +
                                 (full == 0U && copy_full != 0U
                                      ? std::string(" Every full backup " + window +
                                                    " is copy-only, and a copy-only full does not let log backups start.")
                                      : std::string()),
                             SqlCheckStatus::fail, ""});
      add_note(report, "no_current_backup", shown);
    }
    if (model == "FULL" && cell(*databases, index, "log_reuse_wait_desc") == "LOG_BACKUP" && log == 0U && history != nullptr) {
      report.rows.push_back({area, "Log waiting for a backup",
                             "The log is waiting for a log backup, and none was taken " + window + ".",
                             SqlCheckStatus::attention, ""});
      add_note(report, "log_waiting", shown);
    }
    if (history == nullptr || rows.empty())
      continue;

    // Log backups to NUL: msdb stays continuous, and only the device name shows the range is gone.
    for (const ChainEntry& entry : entries) {
      if (!entry.to_nul)
        continue;
      report.rows.push_back({area, "Log backup to NUL",
                             "At " + entry.when + " a log backup went to NUL. The log from LSN " + entry.first_lsn + " to " +
                                 entry.last_lsn + " is lost: no restore reaches past " + entry.when + ".",
                             SqlCheckStatus::fail, ""});
    }

    // Gaps and restarts, recovery model changes and restores.
    std::string previous_model;
    std::set<std::string> forks;
    std::optional<std::size_t> previous_logged;
    for (std::size_t position = 0; position < entries.size(); ++position) {
      const ChainEntry& entry = entries[position];
      const std::size_t row = entry.row;
      const std::string row_model = cell(*history, row, "recovery_model");
      if (!previous_model.empty() && !row_model.empty() && row_model != previous_model) {
        report.rows.push_back({area, "Recovery model changed",
                               "The recovery model changed from " + previous_model + " to " + row_model + " before " +
                                   entry.when + ".",
                               SqlCheckStatus::attention, ""});
      }
      if (!row_model.empty())
        previous_model = row_model;
      const std::string first_fork = cell(*history, row, "first_fork");
      if (!entry.last_fork.empty())
        forks.insert(entry.last_fork);
      if (!first_fork.empty() && !entry.last_fork.empty() && first_fork != entry.last_fork) {
        report.rows.push_back({area, "Database restored",
                               "The database was restored at about " + entry.when +
                                   "; backups after it belong to a new recovery fork.",
                               SqlCheckStatus::attention, ""});
      }
      if (entry.type != "L")
        continue;
      if (entry.gap && entry.restart) {
        const std::string start = entry.base.empty() ? lower_first(entry.label) : "full " + entry.base;
        report.rows.push_back({area, "Log chain broken and restarted",
                               "No log backup covers LSN " + entry.gap_from + " to " + entry.first_lsn +
                                   ". The recovery model was switched, or a backup is missing. The chain starts again at " +
                                   (entry.base.empty() ? entry.when : entries[entry_of_full[entry.base]].when) + " (" +
                                   start + ").",
                               SqlCheckStatus::attention, ""});
      } else if (entry.gap) {
        report.rows.push_back({area, "Log chain gap",
                               "The log chain has a gap between " +
                                   (previous_logged ? entries[*previous_logged].when : std::string("the log before it")) +
                                   " and " + entry.when + " (LSN " + entry.gap_from + " to " + entry.first_lsn +
                                   "). No backup in this history covers that range.",
                               SqlCheckStatus::fail, ""});
        add_note(report, "foreign_backup", shown);
      } else if (entry.restart) {
        report.rows.push_back({area, "Log chain restarted",
                               "The log chain started again at " + entry.when + " (" + lower_first(entry.label) + ").",
                               SqlCheckStatus::attention, ""});
      }
      previous_logged = position;
    }

    // Backups outside Veeam that change Veeam's chain: after Veeam's first backup, a full that is not
    // copy-only (the logs after it depend on a full Veeam does not hold), or a log backup (Veeam's
    // log chain misses its range). Without Veeam rows but with Veeam installed on the SQL host, a full
    // that moves the base reads the same, for the case where Veeam backs up the database.
    const auto first_veeam = std::find_if(entries.begin(), entries.end(),
                                          [](const ChainEntry& entry) { return veeam_taker(entry.taker); });
    for (std::size_t position = 0; position < entries.size(); ++position) {
      const ChainEntry& entry = entries[position];
      if (veeam_taker(entry.taker) || entry.copy_only || entry.to_nul || (entry.type != "D" && entry.type != "L"))
        continue;
      const bool beside_veeam =
          first_veeam != entries.end() && position > static_cast<std::size_t>(first_veeam - entries.begin());
      if (entry.type == "D" && (beside_veeam || (first_veeam == entries.end() && options.veeam_on_sql_host &&
                                                 entry.status == SqlCheckStatus::chain_base_changed))) {
        report.rows.push_back({area, "Full backup outside Veeam",
                               std::string(beside_veeam ? "" : "(When Veeam backs up this database.) ") + entry.label +
                                   " at " + entry.when +
                                   " is not copy-only: the log backups after it depend on it, and Veeam does not hold "
                                   "it. Taken by " + entry.who + ". KB2117.",
                               SqlCheckStatus::attention, ""});
        add_note(report, "foreign_backup", shown);
      } else if (entry.type == "L" && beside_veeam) {
        const std::string software = cell(*history, entry.row, "software_name");
        const std::string who = cell(*history, entry.row, "user_name") + " on " +
                                cell(*history, entry.row, "machine_name") +
                                (software.empty() ? std::string() : " (" + software + ")");
        report.rows.push_back({area, "Log backup outside Veeam",
                               "A log backup that is not copy-only was taken at " + entry.when + " by " + who + ", LSN " +
                                   entry.first_lsn + " to " + entry.last_lsn + ". Veeam's log chain misses that range.",
                               SqlCheckStatus::fail, ""});
        add_note(report, "foreign_backup", shown);
      }
    }
    if (forks.size() > 1U) {
      report.rows.push_back({area, "Recovery forks",
                             std::to_string(forks.size()) + " recovery forks appear " + window + ": the database was restored.",
                             SqlCheckStatus::attention, ""});
    }

    // The chain rows: the time, the backup, what it is to the chain, and who took it when that changes.
    std::vector<SqlCheckRow> chain;
    std::string previous_who;
    for (const ChainEntry& entry : entries) {
      std::string detail = entry.detail;
      if (entry.who != previous_who)
        detail = entry.who + "." + (detail.empty() ? std::string() : " " + detail);
      previous_who = entry.who;
      chain.push_back({entry.when, entry.label, detail, entry.status, ""});
    }
    chains.emplace_back(name, std::move(chain));
  }

  // Sections: the findings, then each database's chain. The guide's notes stay last.
  std::stable_partition(report.rows.begin(), report.rows.end(),
                        [](const SqlCheckRow& row) { return row.area != "Guide"; });
  if (chains.empty())
    return report;
  const auto guide = std::find_if(report.rows.begin(), report.rows.end(),
                                  [](const SqlCheckRow& row) { return row.area == "Guide"; });
  std::vector<SqlCheckRow> ordered;
  ordered.push_back({"FINDINGS", "", "", SqlCheckStatus::section, ""});
  ordered.insert(ordered.end(), report.rows.begin(), guide);
  for (auto& [database, chain] : chains) {
    ordered.push_back({chains.size() == 1U ? std::string("LOG CHAIN, OLDEST FIRST")
                                           : "LOG CHAIN OF " + database + ", OLDEST FIRST",
                       "", "", SqlCheckStatus::section, ""});
    ordered.insert(ordered.end(), chain.begin(), chain.end());
  }
  ordered.insert(ordered.end(), guide, report.rows.end());
  report.rows = std::move(ordered);
  return report;
}

// ------------------------------------------------------------------------------------- files

std::vector<std::string> sql_files_statements() {
  return {"SELECT DB_NAME(database_id) AS db, type_desc, name, physical_name, state_desc, size "
          "FROM sys.master_files ORDER BY database_id, file_id"};
}

SqlCheckReport evaluate_sql_files(const SqlBatchResult& batch, bool on_this_host) {
  SqlCheckReport report;
  std::set<std::string> shown;
  const SqlResultSet* files = first_set(batch, 0);
  if (files == nullptr) {
    report.rows.push_back({"Files", "Database files", statement_error(batch, 0), SqlCheckStatus::could_not_check, ""});
    return report;
  }
  if (!on_this_host) {
    report.rows.push_back({"Files", "Volumes",
                           "SAT is not running on the SQL host, so the volumes are not classified. Run SQL Tools on the "
                           "SQL host for each file's volume.",
                           SqlCheckStatus::not_applicable, ""});
  }
  std::map<std::string, std::optional<VolumeInfo>> volumes; // by drive or share root
  for (std::size_t row = 0; row < files->rows.size(); ++row) {
    const std::string path = cell(*files, row, "physical_name");
    std::uint64_t pages = 0;
    try {
      pages = std::stoull(cell(*files, row, "size"));
    } catch (...) {
      pages = 0;
    }
    std::string detail = path + " (" + cell(*files, row, "type_desc") + ", " + std::to_string(pages * 8U / 1024U) + " MB)";
    SqlCheckStatus status = SqlCheckStatus::info;
    if (on_this_host) {
      const bool unc = path.rfind("\\\\", 0) == 0;
      if (unc) {
        detail += ": network share path.";
        status = SqlCheckStatus::attention;
        add_note(report, "file_network", shown);
      } else if (starts_with_ci(path, "C:\\ClusterStorage\\")) {
        detail += ": cluster shared volume.";
        status = SqlCheckStatus::attention;
        add_note(report, "file_cluster_shared_volume", shown);
      } else if (path.size() >= 3U && path[1] == ':') {
        const std::string root = path.substr(0, 3);
        if (volumes.find(root) == volumes.end()) {
          auto checked = check_volume(root);
          volumes[root] = checked.ok() ? std::optional<VolumeInfo>(checked.value()) : std::nullopt;
        }
        if (const auto& info = volumes[root]) {
          std::string facts = info->kind.empty() ? std::string("volume") : info->kind;
          if (!info->bus.empty())
            facts += ", " + info->bus;
          if (!info->file_system.empty())
            facts += ", " + info->file_system;
          if (info->logical_sector_bytes != 0U)
            facts += ", " + std::to_string(info->logical_sector_bytes) + "-byte sectors";
          detail += ": " + facts + ".";
          if (info->network_share) {
            status = SqlCheckStatus::attention;
            add_note(report, "file_network", shown);
          }
          if (info->removable) {
            status = SqlCheckStatus::attention;
            add_note(report, "file_removable", shown);
          }
          const std::uint32_t sector = info->physical_sector_bytes != 0U ? info->physical_sector_bytes : info->logical_sector_bytes;
          if (sector != 0U && sector != 512U && sector != 4096U) {
            status = SqlCheckStatus::attention;
            add_note(report, "file_sector_size", shown);
          }
        } else {
          detail += ": the volume was not read.";
        }
      } else {
        detail += ".";
      }
    }
    report.rows.push_back({cell(*files, row, "db"), cell(*files, row, "name"), detail, status, ""});
  }
  std::stable_partition(report.rows.begin(), report.rows.end(),
                        [](const SqlCheckRow& row) { return row.area != "Guide"; });
  return report;
}

bool sql_server_is_this_host(std::string_view server) {
  std::string name = ascii_lower(std::string(trim(server)));
  if (name.rfind("tcp:", 0) == 0)
    name = name.substr(4);
  name = name.substr(0, name.find_first_of("\\,"));
  if (name.empty() || name == "." || name == "localhost" || name == "(local)" || name == "127.0.0.1" || name == "::1")
    return true;
#ifdef _WIN32
  wchar_t buffer[256]{};
  DWORD size = static_cast<DWORD>(std::size(buffer));
  if (GetComputerNameExW(ComputerNameDnsHostname, buffer, &size) != FALSE &&
      ascii_lower(utf8_from_wide(buffer)) == name.substr(0, name.find('.')))
    return true;
  size = static_cast<DWORD>(std::size(buffer));
  if (GetComputerNameW(buffer, &size) != FALSE && ascii_lower(utf8_from_wide(buffer)) == name)
    return true;
#else
  char host[256]{};
  if (gethostname(host, sizeof(host) - 1U) == 0) {
    const std::string mine = ascii_lower(host);
    if (mine == name || mine.substr(0, mine.find('.')) == name.substr(0, name.find('.')))
      return true;
  }
#endif
  return false;
}

bool veeam_installed_on_sql_host(std::string_view server) {
  if (!sql_server_is_this_host(server))
    return false;
  const auto products = installed_veeam_products();
  return products.ok() && !products.value().empty();
}

// ------------------------------------------------------------------------------------- query

std::optional<std::string> sql_query_refusal(std::string_view text) {
  // Strings and bracketed names are blanked so a word inside them is not taken for a keyword.
  std::string plain;
  plain.reserve(text.size());
  for (std::size_t index = 0; index < text.size(); ++index) {
    const char character = text[index];
    if (character == '\'' || character == '[' || character == '"') {
      const char close = character == '[' ? ']' : character;
      ++index;
      while (index < text.size()) {
        if (text[index] == close) {
          if (index + 1U < text.size() && text[index + 1U] == close) {
            index += 2U;
            continue;
          }
          break;
        }
        ++index;
      }
      if (index >= text.size())
        return std::string("Not run: a quote or bracket in the query is not closed.");
      plain += " x ";
      continue;
    }
    plain += static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
  }
  if (plain.find("--") != std::string::npos || plain.find("/*") != std::string::npos)
    return std::string("Not run: remove the comments (-- or /* */) and run the query again.");
  std::string body = std::string(trim(plain));
  while (!body.empty() && (body.back() == ';' || std::isspace(static_cast<unsigned char>(body.back())) != 0))
    body.pop_back();
  // A word that makes changes is named first, wherever it stands, so a DELETE reads as a DELETE.
  std::vector<std::string> words;
  std::string word;
  for (const char character : body) {
    if (std::isalnum(static_cast<unsigned char>(character)) != 0 || character == '_') {
      word += character;
    } else if (!word.empty()) {
      words.push_back(word);
      word.clear();
    }
  }
  if (!word.empty())
    words.push_back(word);
  static const std::set<std::string> refused{"INTO", "EXEC", "EXECUTE", "INSERT", "UPDATE", "DELETE", "MERGE", "DROP",
                                             "ALTER", "CREATE", "TRUNCATE", "GRANT", "REVOKE", "DENY", "BACKUP",
                                             "RESTORE", "SHUTDOWN", "KILL", "DBCC", "OPENROWSET", "OPENQUERY",
                                             "OPENDATASOURCE", "BULK", "WAITFOR", "RECONFIGURE", "USE"};
  for (const std::string& item : words) {
    if (refused.count(item) != 0U || item.rfind("XP_", 0) == 0 || item.rfind("SP_", 0) == 0)
      return "Not run: this query uses " + item +
             ", which can make changes. Only queries that read data run here. To change data, use the database console.";
  }
  if (body.find(';') != std::string::npos)
    return std::string("Not run: run one query at a time.");
  if (body.rfind("SELECT", 0) != 0 && body.rfind("WITH", 0) != 0)
    return std::string("Not run: only queries that read data run here, such as a SELECT. To change data, use the "
                       "database console.");
  return std::nullopt;
}

std::string sql_query_one_line(std::string_view text) {
  std::string line;
  line.reserve(text.size());
  bool pending_space = false;
  const auto is_blank = [](char character) {
    return character == ' ' || character == '\t' || character == '\r' || character == '\n' || character == '\f' ||
           character == '\v';
  };
  for (std::size_t index = 0; index < text.size();) {
    const char character = text[index];
    if (is_blank(character)) {
      pending_space = !line.empty();
      ++index;
      continue;
    }
    if (pending_space) {
      line += ' ';
      pending_space = false;
    }
    // A quoted run is copied as it is, up to its closing mark (or the end, which the guard refuses).
    std::size_t end = index + 1U;
    if (character == '\'' || character == '"' || character == '[') {
      const char close = character == '[' ? ']' : character;
      while (end < text.size()) {
        if (text[end] == close) {
          if (end + 1U < text.size() && text[end + 1U] == close) {
            end += 2U;
            continue;
          }
          ++end;
          break;
        }
        ++end;
      }
    } else if (character == '$') {
      std::size_t tag_end = index + 1U;
      while (tag_end < text.size() &&
             (std::isalnum(static_cast<unsigned char>(text[tag_end])) != 0 || text[tag_end] == '_'))
        ++tag_end;
      if (tag_end < text.size() && text[tag_end] == '$') {
        const std::string_view tag = text.substr(index, tag_end - index + 1U);
        const std::size_t close = text.find(tag, tag_end + 1U);
        end = close == std::string_view::npos ? text.size() : close + tag.size();
      }
    }
    line.append(text.substr(index, end - index));
    index = end;
  }
  return line;
}

SqlCheckReport sql_query_rows(const SqlBatchResult& batch, std::size_t max_rows) {
  SqlCheckReport report;
  if (batch.statements.empty())
    return report;
  const SqlStatementResult& result = batch.statements.front();
  if (!result.ok) {
    report.rows.push_back({"Query", "Error", result.error, SqlCheckStatus::fail, ""});
    return report;
  }
  std::size_t shown = 0;
  for (std::size_t set_index = 0; set_index < result.sets.size(); ++set_index) {
    const SqlResultSet& set = result.sets[set_index];
    // The set's columns first, so a grid can be rebuilt from the rows: the naming column, then the rest.
    std::string others;
    for (std::size_t column = set.columns.size() > 1U ? 1U : 0U; column < set.columns.size(); ++column)
      others += (others.empty() ? "" : "\t") + set.columns[column];
    report.rows.push_back({kSqlQueryColumnsArea, set.columns.size() > 1U ? set.columns.front() : std::string("Row"),
                           others, SqlCheckStatus::info, ""});
    for (std::size_t row = 0; row < set.rows.size() && shown < max_rows; ++row, ++shown) {
      // Named by its first column's value (a database, a login), and the first column is not repeated.
      const auto& first = set.rows[row].empty() ? std::optional<std::string>() : set.rows[row].front();
      const bool named = set.columns.size() > 1U && first && !trim(*first).empty();
      std::string label = named ? *first
                                : "Row " + std::to_string(row + 1U);
      if (result.sets.size() > 1U)
        label = "Set " + std::to_string(set_index + 1U) + ": " + label;
      for (std::size_t column = named ? 1U : 0U; column < set.columns.size() && column < set.rows[row].size();
           ++column) {
        const auto& value = set.rows[row][column];
        report.rows.push_back({label, set.columns[column], value ? *value : std::string("NULL"), SqlCheckStatus::info, ""});
      }
    }
    if (set.rows.empty())
      report.rows.push_back({"Result", "Rows", "No rows.", SqlCheckStatus::info, ""});
  }
  std::size_t total = 0;
  for (const SqlResultSet& set : result.sets)
    total += set.rows.size();
  if (total > max_rows)
    report.rows.push_back({"Result", "Rows", std::to_string(total) + " rows; the first " + std::to_string(max_rows) + " are listed.",
                           SqlCheckStatus::info, ""});
  return report;
}

const std::vector<SqlNamedQuery>& sql_named_queries() {
  static const std::vector<SqlNamedQuery> queries = [] {
    std::vector<SqlNamedQuery> parsed;
    for (const JsonValue& item : data_file("sql-queries.json")["queries"].items()) {
      SqlNamedQuery query{item["name"].as_string(), item["sql"].as_string(), {}};
      for (const JsonValue& column : item["main_columns"].items())
        query.main_columns.push_back(column.as_string());
      parsed.push_back(std::move(query));
    }
    return parsed;
  }();
  return queries;
}

std::vector<SqlQueryGrid> sql_query_grids(const std::vector<std::array<std::string, 3>>& rows) {
  std::vector<SqlQueryGrid> grids;
  std::optional<std::size_t> last_column;
  std::string last_label;
  for (const auto& [area, check, detail] : rows) {
    if (area == kSqlQueryColumnsArea) {
      SqlQueryGrid grid;
      grid.label_heading = check;
      std::size_t start = 0;
      while (start <= detail.size() && !detail.empty()) {
        const std::size_t tab = detail.find('\t', start);
        grid.columns.push_back(detail.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
        if (tab == std::string::npos)
          break;
        start = tab + 1U;
      }
      grids.push_back(std::move(grid));
      last_column.reset();
      continue;
    }
    if (grids.empty())
      grids.emplace_back();
    SqlQueryGrid& grid = grids.back();
    if (area == "Result" || area == "Query") {
      grid.notes.push_back(area == "Query" ? check + ": " + detail : detail);
      continue;
    }
    const auto found = std::find(grid.columns.begin(), grid.columns.end(), check);
    if (found == grid.columns.end())
      continue;
    const auto column = static_cast<std::size_t>(found - grid.columns.begin());
    // A new result row: a new name, or a column at or before the last one read.
    if (grid.labels.empty() || area != last_label || !last_column || column <= *last_column) {
      grid.labels.push_back(area);
      grid.cells.emplace_back(grid.columns.size());
    }
    grid.cells.back()[column] = detail;
    last_label = area;
    last_column = column;
  }
  return grids;
}

std::vector<std::size_t> sql_query_shown_columns(const SqlQueryGrid& grid, const std::vector<std::string>& main_columns,
                                                 std::size_t max_shown) {
  std::vector<std::size_t> shown;
  if (grid.columns.size() <= max_shown) {
    for (std::size_t index = 0; index < grid.columns.size(); ++index)
      shown.push_back(index);
    return shown;
  }
  for (const std::string& name : main_columns) {
    const auto found = std::find(grid.columns.begin(), grid.columns.end(), name);
    if (found != grid.columns.end())
      shown.push_back(static_cast<std::size_t>(found - grid.columns.begin()));
  }
  if (shown.empty()) {
    for (std::size_t index = 0; index < max_shown; ++index)
      shown.push_back(index);
  }
  return shown;
}

const SqlNamedQuery* sql_named_query_for(std::string_view query) {
  const std::string wanted = trim(query);
  for (const auto* list : {&sql_named_queries(), &postgres_named_queries()}) {
    for (const SqlNamedQuery& named : *list) {
      if (trim(named.text) == wanted || named.name == wanted)
        return &named;
    }
  }
  return nullptr;
}

std::vector<std::string> sql_query_main_columns(const SqlQueryGrid& grid) {
  for (const auto* list : {&sql_named_queries(), &postgres_named_queries()}) {
    for (const SqlNamedQuery& named : *list) {
      if (named.main_columns.empty())
        continue;
      const bool all = std::all_of(named.main_columns.begin(), named.main_columns.end(), [&grid](const std::string& name) {
        return std::find(grid.columns.begin(), grid.columns.end(), name) != grid.columns.end();
      });
      if (all)
        return named.main_columns;
    }
  }
  return {};
}

std::string sql_query_text_table(const SqlQueryGrid& grid, const std::vector<std::size_t>& shown) {
  constexpr std::size_t kWidest = 40;
  const auto clipped = [](const std::string& text) {
    return text.size() > kWidest ? text.substr(0, kWidest - 3U) + "..." : text;
  };
  std::vector<std::string> headings{grid.label_heading};
  for (const std::size_t column : shown)
    headings.push_back(grid.columns[column]);
  std::vector<std::vector<std::string>> lines;
  for (std::size_t row = 0; row < grid.labels.size(); ++row) {
    std::vector<std::string> line{clipped(grid.labels[row])};
    for (const std::size_t column : shown)
      line.push_back(clipped(grid.cells[row][column]));
    lines.push_back(std::move(line));
  }
  std::vector<std::size_t> widths;
  for (std::size_t index = 0; index < headings.size(); ++index) {
    std::size_t width = std::min(headings[index].size(), kWidest);
    for (const auto& line : lines)
      width = std::max(width, line[index].size());
    widths.push_back(width);
  }
  const auto row_text = [&widths](const std::vector<std::string>& cells) {
    std::string text;
    for (std::size_t index = 0; index < cells.size(); ++index) {
      const bool last = index + 1U == cells.size();
      text += last ? cells[index] : cells[index] + std::string(widths[index] - cells[index].size() + 2U, ' ');
    }
    return text + "\n";
  };
  std::string out = row_text(headings);
  std::vector<std::string> rules;
  for (const std::size_t width : widths)
    rules.push_back(std::string(width, '-'));
  out += row_text(rules);
  for (const auto& line : lines)
    out += row_text(line);
  return out;
}

std::string sql_query_text_records(const SqlQueryGrid& grid) {
  std::size_t name_width = 0;
  for (const std::string& column : grid.columns)
    name_width = std::max(name_width, column.size());
  std::string out;
  for (std::size_t row = 0; row < grid.labels.size(); ++row) {
    out += (row == 0U ? "" : "\n") + grid.labels[row] + "\n";
    for (std::size_t column = 0; column < grid.columns.size(); ++column)
      out += "  " + grid.columns[column] + std::string(name_width - grid.columns[column].size() + 2U, ' ') +
             grid.cells[row][column] + "\n";
  }
  return out;
}

std::string sql_query_tsv(const SqlQueryGrid& grid) {
  const auto clean = [](std::string text) {
    std::replace(text.begin(), text.end(), '\t', ' ');
    std::replace(text.begin(), text.end(), '\n', ' ');
    std::replace(text.begin(), text.end(), '\r', ' ');
    return text;
  };
  std::string out = clean(grid.label_heading);
  for (const std::string& column : grid.columns)
    out += "\t" + clean(column);
  out += "\n";
  for (std::size_t row = 0; row < grid.labels.size(); ++row) {
    out += clean(grid.labels[row]);
    for (const std::string& cell : grid.cells[row])
      out += "\t" + clean(cell);
    out += "\n";
  }
  return out;
}

// ------------------------------------------------------------------------------------- connect failure

namespace {

// One record of what the drivers reported.
struct DriverRecord {
  std::string state;
  long long native = 0;
  std::string message;
};

// The records as the batch runner writes them: "STATE (native): message", separated by " | ". A part
// that does not start that way continues the record before it.
std::vector<DriverRecord> driver_records(std::string_view text) {
  std::vector<DriverRecord> records;
  std::size_t position = 0;
  while (position <= text.size()) {
    std::size_t end = text.find(" | ", position);
    if (end == std::string_view::npos)
      end = text.size();
    const std::string_view part = text.substr(position, end - position);
    position = end + 3U;
    DriverRecord record;
    bool parsed = false;
    if (part.size() >= 8U && part[5] == ' ' && part[6] == '(') {
      const std::size_t close = part.find("):", 7U);
      if (close != std::string_view::npos && close > 7U) {
        const std::string number(part.substr(7U, close - 7U));
        const std::size_t first_digit = number.front() == '-' ? 1U : 0U;
        if (number.size() > first_digit &&
            std::all_of(number.begin() + static_cast<std::ptrdiff_t>(first_digit), number.end(),
                        [](char c) { return c >= '0' && c <= '9'; })) {
          record.state = std::string(part.substr(0, 5U));
          record.native = std::strtoll(number.c_str(), nullptr, 10);
          record.message = trim(part.substr(close + 2U));
          parsed = true;
        }
      }
    }
    const std::string stripped = trim(part);
    if (parsed) {
      records.push_back(std::move(record));
    } else if (stripped.empty()) {
      continue;
    } else if (!records.empty()) {
      records.back().message += " | " + stripped;
    } else {
      record.message = stripped;
      records.push_back(std::move(record));
    }
  }
  return records;
}

bool mentions(const DriverRecord& record, std::initializer_list<std::string_view> phrases) {
  const std::string lowered = ascii_lower(record.message);
  for (const std::string_view phrase : phrases) {
    if (lowered.find(phrase) != std::string::npos)
      return true;
  }
  return false;
}

// IM002: the driver manager has no driver of that name.
bool is_missing_driver(const DriverRecord& record) {
  return record.state == "IM002";
}

// 28000, or error 18456: the server answered and refused the account.
bool is_sign_in_refusal(const DriverRecord& record) {
  return record.state == "28000" || record.native == 18456 || mentions(record, {"login failed for user"});
}

// A reply that is neither a refusal nor silence, such as a certificate the client does not trust.
bool is_other_server_answer(const DriverRecord& record) {
  return mentions(record, {"certificate", "ssl provider", "ssl security", "tls", "cannot open database",
                           "cannot open server"});
}

// 08001 with a network-level code (17 and 2 from the older driver, 53 and 26 from the newer ones,
// then refused, timed-out and unknown-host socket errors) or the drivers' own wording for it.
bool is_not_reached(const DriverRecord& record) {
  if (record.state != "08001")
    return false;
  switch (record.native) {
  case 2:
  case 17:
  case 26:
  case 53:
  case 1225:
  case 10060:
  case 10061:
  case 11001:
    return true;
  default:
    break;
  }
  return mentions(record, {"does not exist", "network-related", "instance-specific",
                           "could not open a connection to sql server", "no such host", "actively refused",
                           "error locating server", "not found or not accessible"});
}

// HYT00, or the drivers' words for a login that waited out its time.
bool is_login_timeout(const DriverRecord& record) {
  return record.state == "HYT00" || mentions(record, {"login timeout expired", "timeout error"});
}

enum class ConnectFailure { not_recognised, no_driver, sign_in_refused, not_reached, timed_out };

ConnectFailure classify_connect_failure(const std::vector<DriverRecord>& records) {
  if (records.empty())
    return ConnectFailure::not_recognised;
  if (std::all_of(records.begin(), records.end(), is_missing_driver))
    return ConnectFailure::no_driver;
  // A refusal means a server answered, so it outranks the silence the other drivers report. A
  // different reply from the server (a certificate, a protocol) is left to the drivers' own text.
  if (std::any_of(records.begin(), records.end(), is_sign_in_refusal))
    return ConnectFailure::sign_in_refused;
  if (std::any_of(records.begin(), records.end(), is_other_server_answer))
    return ConnectFailure::not_recognised;
  // The timeout record follows the unreachable ones in a single attempt, so the cause comes first.
  if (std::any_of(records.begin(), records.end(), is_not_reached))
    return ConnectFailure::not_reached;
  if (std::any_of(records.begin(), records.end(), is_login_timeout))
    return ConnectFailure::timed_out;
  return ConnectFailure::not_recognised;
}

// The account a "Login failed for user 'NAME'" record names.
std::string refused_account(const std::vector<DriverRecord>& records) {
  const std::string marker = "login failed for user '";
  for (const DriverRecord& record : records) {
    const std::size_t at = ascii_lower(record.message).find(marker);
    if (at == std::string::npos)
      continue;
    const std::size_t start = at + marker.size();
    const std::size_t end = record.message.find('\'', start);
    if (end != std::string::npos && end > start)
      return record.message.substr(start, end - start);
  }
  return {};
}

} // namespace

std::string sql_connect_failure_text(std::string_view server, std::string_view diagnostics,
                                     const std::vector<std::string>& drivers_tried,
                                     const std::optional<std::vector<std::string>>& local_instances) {
  const std::vector<DriverRecord> records = driver_records(diagnostics);
  const ConnectFailure kind = classify_connect_failure(records);
  if (kind == ConnectFailure::not_recognised)
    return "No SQL Server ODBC driver connected: " + std::string(diagnostics);

  const std::string name = trim(server);
  std::string lead;
  if (kind == ConnectFailure::no_driver) {
    lead = "No SQL Server ODBC driver is installed on this machine" +
           (drivers_tried.empty() ? std::string() : " (tried " + joined(drivers_tried) + ")") +
           ". Microsoft's ODBC Driver 18 for SQL Server is the driver to install.";
  } else if (kind == ConnectFailure::sign_in_refused) {
    const std::string account = refused_account(records);
    lead = "The server at " + name + " refused the sign-in for " +
           (account.empty() ? std::string("the account used") : account) + ".";
  } else {
    const bool here = sql_server_is_this_host(name);
    const bool none_installed = here && local_instances.has_value() && local_instances->empty();
    const std::string bare = name.rfind("tcp:", 0) == 0 ? name.substr(4) : name;
    if (none_installed) {
      lead = "No SQL Server instance is installed on this machine (Windows lists none), so nothing answered at " +
             name + ".";
    } else if (kind == ConnectFailure::not_reached) {
      lead = "No SQL Server answered at " + name +
             ". The name may be wrong, the SQL Server service may be stopped, or TCP/IP and named pipes may be "
             "turned off in SQL Server's network settings.";
      if (bare.find('\\') != std::string::npos && bare.find(',') == std::string::npos)
        lead += " A named instance is found through the SQL Server Browser service.";
    } else {
      lead = "The server at " + name + " did not answer in time.";
    }
    if (here && local_instances.has_value() && !local_instances->empty())
      lead += " SQL Server instances installed on this machine: " + joined(*local_instances) + ".";
  }
  return diagnostics.empty() ? lead : lead + " Driver messages: " + std::string(diagnostics);
}

// ------------------------------------------------------------------------------------- lists

std::optional<std::vector<std::string>> sql_local_instances_listed() {
#ifdef _WIN32
  return sql_local_instances();
#else
  return std::nullopt;
#endif
}

std::vector<std::string> sql_local_instances() {
  std::vector<std::string> instances;
#ifdef _WIN32
  wchar_t computer[256]{};
  DWORD size = static_cast<DWORD>(std::size(computer));
  const std::string host = GetComputerNameW(computer, &size) != FALSE ? utf8_from_wide(computer) : std::string("localhost");
  for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL", 0,
                      KEY_READ | view, &key) != ERROR_SUCCESS)
      continue;
    for (DWORD index = 0;; ++index) {
      wchar_t name[256]{};
      DWORD length = static_cast<DWORD>(std::size(name));
      if (RegEnumValueW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
        break;
      const std::string instance = utf8_from_wide(name);
      const std::string server = ascii_lower(instance) == "mssqlserver" ? host : host + "\\" + instance;
      if (std::find(instances.begin(), instances.end(), server) == instances.end())
        instances.push_back(server);
    }
    RegCloseKey(key);
  }
#endif
  return instances;
}

std::vector<std::string> sql_accounts_to_check() {
  std::vector<std::string> accounts;
#ifdef _WIN32
  if (SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)) {
    if (SC_HANDLE service = OpenServiceW(manager, L"VeeamBackupSvc", SERVICE_QUERY_CONFIG)) {
      DWORD needed = 0;
      QueryServiceConfigW(service, nullptr, 0, &needed);
      std::vector<unsigned char> buffer(needed);
      auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
      if (needed != 0U && QueryServiceConfigW(service, config, needed, &needed) != FALSE && config->lpServiceStartName != nullptr) {
        std::string account = utf8_from_wide(config->lpServiceStartName);
        if (ascii_lower(account) == "localsystem")
          account = "NT AUTHORITY\\SYSTEM";
        accounts.push_back(account);
      }
      CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
  }
  if (std::find(accounts.begin(), accounts.end(), "NT AUTHORITY\\SYSTEM") == accounts.end())
    accounts.push_back("NT AUTHORITY\\SYSTEM");
#endif
  return accounts;
}

} // namespace support_assist
