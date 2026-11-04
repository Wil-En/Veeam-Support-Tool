#pragma once

// The values a form field offers in a list, by the field's label, on both editions: Windows puts
// them behind the field's Choose... button, Linux makes the field an editable list. A field still
// takes what is typed; the list offers values, it never restricts them
// (the query and prefill review in docs/).

#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/local_accounts.hpp"
#include "support_assist/postgres_check.hpp"
#include "support_assist/sql_catalog.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "system_differences_run.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

struct FieldChoice {
  std::string value; // what the field takes
  std::string text;  // how the list shows it
};

namespace field_choices_detail {

// The hosts this session already knows: the active case's machines, then the addresses saved in
// Settings > SSH Addresses. Each GUI sets them through set_known_hosts.
inline std::vector<FieldChoice>& known_hosts() {
  static std::vector<FieldChoice> hosts;
  return hosts;
}

// Midnight UTC some days back, in the form the date fields read; To also offers now.
inline std::vector<FieldChoice> recent_days(bool to) {
  constexpr std::int64_t kDay = 86400000LL;
  const std::int64_t now = unix_millis_now();
  const std::int64_t today = now - now % kDay;
  std::vector<FieldChoice> choices;
  if (to)
    choices.push_back({iso8601_from_unix_millis(now - now % 1000), "Now"});
  for (const int days : {0, 1, 3, 7, 14, 30}) {
    const std::int64_t at = today - static_cast<std::int64_t>(days) * kDay;
    const std::string date = iso8601_from_unix_millis(at).substr(0, 10);
    const std::string when = days == 0 ? "today" : days == 1 ? "yesterday" : std::to_string(days) + " days ago";
    choices.push_back({iso8601_from_unix_millis(at), date + "  (" + when + ", 00:00 UTC)"});
  }
  return choices;
}

// This machine's SQL Server instances, then the servers Veeam's configuration names.
inline std::vector<FieldChoice> sql_servers() {
  std::vector<FieldChoice> servers;
  auto add = [&servers](const std::string& value, const std::string& text) {
    if (value.empty())
      return;
    for (const FieldChoice& existing : servers) {
      if (existing.value == value)
        return;
    }
    servers.push_back({value, text});
  };
  // This machine's SQL Server and PostgreSQL instances, each marked with its engine.
  for (const SqlInstanceChoice& instance : local_database_instances())
    add(instance.name, instance.name + "  (" + sql_engine_name(instance.engine) + ", this machine" +
                           (instance.detail.empty() ? std::string() : "; " + instance.detail) + ")");
  if (auto databases = identify_configuration_databases(); databases.ok()) {
    for (const ConfigurationDatabaseInfo& database : databases.value()) {
      if (ascii_lower(database.engine).find("postgre") != std::string::npos || database.server.empty())
        continue;
      const std::string server =
          database.instance.empty() ? database.server : database.server + "\\" + database.instance;
      add(server, server + "  (" + (database.product.empty() ? std::string("Veeam") : database.product) +
                      " configuration database)");
    }
  }
  return servers;
}

inline std::vector<FieldChoice> configuration_databases() {
  std::vector<FieldChoice> names{{"VeeamBackup", "VeeamBackup"}};
  if (auto databases = identify_configuration_databases(); databases.ok()) {
    for (const ConfigurationDatabaseInfo& database : databases.value()) {
      if (database.database.empty() || ascii_lower(database.engine).find("postgre") != std::string::npos)
        continue;
      if (std::none_of(names.begin(), names.end(), [&](const FieldChoice& name) { return name.value == database.database; }))
        names.push_back({database.database, database.database + "  (" + database.product + ")"});
    }
  }
  return names;
}

// Veeam's ports by number, each named by the first role that listens on it (ports.json).
inline std::vector<FieldChoice> veeam_ports() {
  std::map<long, std::string> named;
  for (const auto& preset : port_presets()) {
    for (const auto& entry : preset.entries) {
      if (entry.dynamic || entry.ports.find_first_not_of("0123456789") != std::string::npos || entry.ports.empty())
        continue;
      const long port = std::strtol(entry.ports.c_str(), nullptr, 10);
      if (port > 0 && port <= 65535 && named.find(port) == named.end())
        named[port] = preset.name + (entry.note.empty() ? std::string() : ": " + entry.note);
    }
  }
  std::vector<FieldChoice> choices;
  for (const auto& [port, name] : named)
    choices.push_back({std::to_string(port), std::to_string(port) + "  " + name});
  return choices;
}

// UTC offsets in minutes, whole hours and the half and quarter hours in use.
inline std::vector<FieldChoice> utc_offsets() {
  // This machine's offset first.
  const int here = time_check_detail::local_offset_minutes_at(unix_millis_now());
  const int minutes[] = {-720, -660, -600, -570, -540, -480, -420, -360, -300, -240, -210, -180, -120, -60, 0,
                         60,   120,  180,  210,  240,  270,  300,  330,  345,  360,  390,  420,  480,  525,
                         540,  570,  600,  630,  660,  720,  765,  780,  840};
  std::vector<FieldChoice> choices;
  for (const int offset : minutes) {
    const int hours = std::abs(offset) / 60;
    const int rest = std::abs(offset) % 60;
    std::string text = "UTC";
    text += offset < 0 ? "-" : "+";
    text += (hours < 10 ? "0" : "") + std::to_string(hours) + ":" + (rest < 10 ? "0" : "") + std::to_string(rest);
    choices.push_back({std::to_string(offset), text + "  (" + std::to_string(offset) + ")"});
  }
  const auto local = std::find_if(choices.begin(), choices.end(),
                                  [here](const FieldChoice& choice) { return choice.value == std::to_string(here); });
  if (local != choices.end()) {
    FieldChoice first = *local;
    first.text += ", this machine";
    choices.erase(local);
    choices.insert(choices.begin(), first);
  }
  return choices;
}

// Read-only example queries per WMI namespace, keyed in lower case.
inline const std::map<std::string, std::vector<FieldChoice>>& wql_example_table() {
  static const std::map<std::string, std::vector<FieldChoice>> table{
      {"root\\cimv2",
       {{"SELECT Caption, Version, BuildNumber, LastBootUpTime, FreePhysicalMemory, TotalVisibleMemorySize FROM "
         "Win32_OperatingSystem",
         "Operating system and uptime"},
        {"SELECT Name, DisplayName, State, StartMode, StartName, ProcessId FROM Win32_Service WHERE Name LIKE 'Veeam%'",
         "Veeam services"},
        {"SELECT ProcessId, Name, ExecutablePath, CommandLine, WorkingSetSize FROM Win32_Process WHERE Name LIKE "
         "'Veeam%'",
         "Veeam processes"},
        {"SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace FROM Win32_LogicalDisk WHERE DriveType = 3",
         "Disks with free space"},
        {"SELECT Volume, DiffVolume, UsedSpace, AllocatedSpace, MaxSpace FROM Win32_ShadowStorage",
         "Shadow storage per volume (administrator)"},
        {"SELECT ID, VolumeName, InstallDate, ClientAccessible, Persistent FROM Win32_ShadowCopy",
         "Shadow copies (administrator)"},
        {"SELECT Description, IPAddress, DefaultIPGateway, DNSServerSearchOrder, DHCPEnabled FROM "
         "Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE",
         "Network adapters with an address"},
        {"SELECT Name, AllocatedBaseSize, CurrentUsage, PeakUsage FROM Win32_PageFileUsage", "Page file use"},
        {"SELECT Name, Domain, PartOfDomain, Manufacturer, Model, NumberOfLogicalProcessors, TotalPhysicalMemory "
         "FROM Win32_ComputerSystem",
         "Computer, domain and memory"},
        {"SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering", "Installed updates"}}},
      {"root\\standardcimv2",
       {{"SELECT Name, InterfaceDescription, Status, LinkSpeed, MediaConnectionState FROM MSFT_NetAdapter",
         "Network adapters and link state"},
        {"SELECT DisplayName, Enabled, Direction, Action, Profile FROM MSFT_NetFirewallRule WHERE DisplayName LIKE "
         "'Veeam%'",
         "Firewall rules named Veeam"},
        {"SELECT LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess FROM MSFT_NetTCPConnection "
         "WHERE LocalPort = 9392",
         "Connections on the backup service port"},
        {"SELECT InterfaceAlias, IPAddress, PrefixLength, AddressFamily FROM MSFT_NetIPAddress", "IP addresses"}}},
      {"root\\microsoft\\windows\\storage",
       {{"SELECT DriveLetter, FileSystem, AllocationUnitSize, Size, SizeRemaining, HealthStatus FROM MSFT_Volume",
         "Volumes with cluster size"},
        {"SELECT FriendlyName, MediaType, BusType, Size, HealthStatus, OperationalStatus FROM MSFT_PhysicalDisk",
         "Physical disks and health"},
        {"SELECT Number, FriendlyName, PartitionStyle, IsOffline, BusType, Size FROM MSFT_Disk", "Disks"},
        {"SELECT FriendlyName, Size, AllocatedSize, HealthStatus FROM MSFT_StoragePool", "Storage pools"}}},
      {"root\\virtualization\\v2",
       {{"SELECT ElementName, EnabledState, HealthState, Name FROM Msvm_ComputerSystem WHERE Caption = 'Virtual "
         "Machine'",
         "Virtual machines and state"},
        {"SELECT ElementName, InstanceID, VirtualSystemType FROM Msvm_VirtualSystemSettingData WHERE "
         "VirtualSystemType = 'Microsoft:Hyper-V:Snapshot:Realized'",
         "Checkpoints"},
        {"SELECT ElementName, Name, EnabledState FROM Msvm_ComputerSystem WHERE Caption = 'Hosting Computer System'",
         "The Hyper-V host"}}},
      {"root\\mscluster",
       {{"SELECT Name, State FROM MSCluster_Node", "Nodes"},
        {"SELECT Name, State, Type FROM MSCluster_Resource", "Resources"},
        {"SELECT Name, State FROM MSCluster_ResourceGroup", "Resource groups"},
        {"SELECT Name, Role, State FROM MSCluster_Network", "Cluster networks"}}},
      {"root\\wmi",
       {{"SELECT InstanceName, PredictFailure, Reason FROM MSStorageDriver_FailurePredictStatus",
         "Disks predicting failure"}}},
  };
  return table;
}

} // namespace field_choices_detail

// The example queries for a WMI namespace; root\cimv2's for one with none listed.
inline std::vector<FieldChoice> wql_examples(std::string_view name_space) {
  std::string key(name_space);
  for (char& character : key)
    character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  const auto& table = field_choices_detail::wql_example_table();
  const auto found = table.find(key);
  return found != table.end() ? found->second : table.at("root\\cimv2");
}

// A query that is one of the examples, or the field's default: one the engineer has not written.
inline bool wql_is_example(std::string_view query) {
  if (query.empty() || query == "SELECT * FROM Win32_OperatingSystem")
    return true;
  for (const auto& [name_space, examples] : field_choices_detail::wql_example_table()) {
    for (const auto& example : examples)
      if (example.value == query)
        return true;
  }
  return false;
}

// The active case's machines and the saved SSH addresses, for every host field. A host is listed
// once, in the first group that names it.
inline void set_known_hosts(const std::vector<std::string>& case_machines, const std::vector<std::string>& saved) {
  auto& hosts = field_choices_detail::known_hosts();
  hosts.clear();
  const auto add = [&hosts](const std::string& value, const std::string& where) {
    const std::string name = trim(value);
    if (name.empty())
      return;
    for (const FieldChoice& existing : hosts) {
      if (ascii_lower(existing.value) == ascii_lower(name))
        return;
    }
    hosts.push_back({name, name + "  (" + where + ")"});
  };
  for (const std::string& machine : case_machines)
    add(machine, "in the case");
  for (const std::string& address : saved)
    add(address, "saved in Settings");
}

// The fields that name another machine.
inline bool is_host_label(std::string_view label) {
  return label == "Host" || label == "Target host" || label == "Target machine" || label == "Machine" ||
         label == "Server address" || label == "Server name or address";
}

// ------------------------------------------------------------------------------------- SQL Tools
// The Engine field and what follows it: the engine a run uses, the starting values that belong to
// an engine, and the lists of databases the Database fields offer. Both editions use these.

// The engine an Engine field names: PostgreSQL, and SQL Server for anything else.
inline SqlEngine sql_engine_from_field(std::string_view text) {
  return ascii_lower(trim(text)) == "postgresql" ? SqlEngine::postgresql : SqlEngine::sql_server;
}

// The database every server of the engine has, which a run connects to when none is named.
inline std::string sql_default_database(SqlEngine engine) {
  return engine == SqlEngine::postgresql ? "postgres" : "master";
}

// The named queries of an engine, as the Query field lists them.
inline std::vector<FieldChoice> sql_query_choices(SqlEngine engine) {
  std::vector<FieldChoice> queries;
  const std::vector<SqlNamedQuery>& named = engine == SqlEngine::postgresql ? postgres_named_queries() : sql_named_queries();
  // The field holds the name; the run and the command line read it as the engine's statement.
  for (const SqlNamedQuery& query : named)
    queries.push_back({query.name, query.name});
  return queries;
}

// The query the Query field starts with: the engine's named query listing its databases.
inline std::string sql_default_query(SqlEngine engine) {
  static_cast<void>(engine);
  return "Databases";
}

// Whether a query is one the form offers for the engine: empty, its starting query, a named query by
// its name or its statement, or a starting statement of an earlier build.
inline bool sql_query_is_starting(std::string_view text, SqlEngine engine) {
  const std::string query = trim(text);
  if (query.empty() || query == sql_default_query(engine))
    return true;
  if (engine == SqlEngine::sql_server &&
      (query == "SELECT name FROM sys.databases" || query == "SELECT name, state_desc, recovery_model_desc FROM sys.databases"))
    return true;
  if (engine == SqlEngine::postgresql && query == "SELECT datname FROM pg_database ORDER BY datname")
    return true;
  const std::vector<SqlNamedQuery>& named = engine == SqlEngine::postgresql ? postgres_named_queries() : sql_named_queries();
  return std::any_of(named.begin(), named.end(),
                     [&query](const SqlNamedQuery& item) { return item.name == query || trim(item.text) == query; });
}

// What a SQL Tools field holds after the engine changed, or nothing when it stays as it is. Database
// and Query take the new engine's starting value when they still hold the other engine's; a value
// typed by the engineer stays.
inline std::optional<std::string> sql_value_after_engine_change(std::string_view label, std::string_view current,
                                                                SqlEngine engine) {
  const SqlEngine other = engine == SqlEngine::postgresql ? SqlEngine::sql_server : SqlEngine::postgresql;
  if (label == "Database") {
    if (trim(current) == sql_default_database(other))
      return sql_default_database(engine);
  } else if (label == "Query") {
    if (sql_query_is_starting(current, other) && trim(current) != sql_default_query(engine))
      return sql_default_query(engine);
  }
  return std::nullopt;
}

// Why the Database fields cannot list the server's databases now, as a status line; empty when they
// can. Listing connects as the account running SAT, so it needs Use logged-in user.
inline std::string sql_database_list_blocker(std::string_view server, bool use_logged_in_user) {
  if (trim(server).empty())
    return "Choose or type the server first, then open the list of databases.";
  if (!use_logged_in_user)
    return "Tick Use logged-in user to list the databases, or type the name.";
  return {};
}

// The databases already listed in this session, by engine and server, so opening a list again is
// instant.
class SqlDatabaseCache {
public:
  const std::vector<std::string>* find(SqlEngine engine, std::string_view server) const {
    const auto found = lists_.find(key(engine, server));
    return found == lists_.end() ? nullptr : &found->second;
  }
  void store(SqlEngine engine, std::string_view server, std::vector<std::string> names) {
    lists_[key(engine, server)] = std::move(names);
  }

private:
  static std::string key(SqlEngine engine, std::string_view server) {
    return sql_engine_name(engine) + "\n" + ascii_lower(trim(server));
  }
  std::map<std::string, std::vector<std::string>> lists_;
};

inline SqlDatabaseCache& sql_database_cache() {
  static SqlDatabaseCache cache;
  return cache;
}

// One listing of a server's databases and the status line that says how it went.
struct SqlDatabaseListing {
  bool ok = false;
  std::vector<std::string> names;
  std::string message;
};

// Lists the databases of the server in the form as the account running SAT, and keeps the names for
// the session. Runs a connection: call it off the message thread.
inline SqlDatabaseListing list_form_databases(SqlEngine engine, const std::string& server, bool trust_server_certificate,
                                              const std::filesystem::path& tools_folder, const CancellationToken& cancel) {
  SqlDatabaseListing listing;
  const std::string name = trim(server);
  auto listed = list_databases(engine, name, true, std::string(), std::string(), cancel, trust_server_certificate,
                               tools_folder);
  if (!listed.ok()) {
    listing.message = "The databases on " + name + " were not listed: " + describe_error(listed.error());
    return listing;
  }
  listing.names = std::move(listed.value());
  if (listing.names.empty()) {
    listing.message = "No database on " + name + " accepts connections from this account.";
    return listing;
  }
  listing.ok = true;
  listing.message = "Listed " + std::to_string(listing.names.size()) + (listing.names.size() == 1U ? " database" : " databases") +
                    " on " + name + ".";
  return listing;
}

// The list as a Database field offers it.
inline std::vector<FieldChoice> sql_database_choices(const std::vector<std::string>& names) {
  std::vector<FieldChoice> choices;
  for (const std::string& name : names)
    choices.push_back({name, name});
  return choices;
}

// A list whose values are the only ones the run takes: the field is a list, not a box to type in.
inline bool field_choice_is_fixed(std::string_view label) {
  return label == "Server role" || label == "Check against" || label == "Compare file contents" || label == "Engine" ||
         label == "Registry view" || label == "Ambiguous date order" || label == "Veeam product" ||
         label == "Server's system" || label == "Sign in" || label == "Pipes shown" ||
         label == "Sockets shown";
}

inline std::vector<FieldChoice> field_choices(std::string_view label) {
  // WMI's Machine field: a dot is this machine.
  if (label == "Machine") {
    std::vector<FieldChoice> machines{{".", ".  (this machine)"}};
    for (const FieldChoice& host : field_choices_detail::known_hosts())
      machines.push_back(host);
    return machines;
  }
  if (is_host_label(label))
    return field_choices_detail::known_hosts();
  if (label == "Engine")
    return {{"SQL Server", "SQL Server"}, {"PostgreSQL", "PostgreSQL"}};
  // Host Diagnostics' Unix sockets (Linux).
  if (label == "Sockets shown")
    return {{"Every socket", "Every socket"}, {"Veeam sockets", "Veeam sockets  (Veeam, PostgreSQL and the system's own)"}};
  // Host Diagnostics' Named Pipes.
  if (label == "Pipes shown")
    return {{"Every pipe", "Every pipe"}, {"Veeam pipes", "Veeam pipes  (Veeam, SQL Server and PostgreSQL)"}};
  // WMI's account on another machine.
  if (label == "Sign in")
    return {{"Current Windows account", "Current Windows account"},
            {"Another account", "Another account  (asked for at Query)"}};
  if (label == "Bounded test path")
    return {{"C$\\Windows\\Veeam", "C$\\Windows\\Veeam  (the default)"},
            {"ADMIN$", "ADMIN$  (the Windows folder)"},
            {"C$", "C$  (the system drive)"}};
  if (label == "From date/time (optional)")
    return field_choices_detail::recent_days(false);
  if (label == "To date/time (optional)")
    return field_choices_detail::recent_days(true);
  if (label == "WQL query")
    return wql_examples("root\\cimv2");
  if (label == "Compare file contents")
    return {{kContentsNever, "Never  (names, sizes and times)"},
            {kContentsUpTo64, "Files up to 64 MB  (reads each of them)"},
            {kContentsAll, "All files  (reads every byte)"}};
  if (label == "Ambiguous date order")
    return {{"Auto", "Auto"},
            {"Month/day/year", "Month/day/year"},
            {"Day/month/year", "Day/month/year"},
            {"ISO", "ISO dates only"},
            {"System", "This machine's date order"}};
  if (label == "Assumed UTC offset minutes")
    return field_choices_detail::utc_offsets();
  if (label == "Namespace")
    return {{"root\\cimv2", "root\\cimv2"},
            {"root\\StandardCimv2", "root\\StandardCimv2"},
            {"root\\MSCluster", "root\\MSCluster"},
            {"root\\virtualization\\v2", "root\\virtualization\\v2"},
            {"root\\Microsoft\\Windows\\Storage", "root\\Microsoft\\Windows\\Storage"},
            {"root\\WMI", "root\\WMI"}};
  if (label == "Port" || label == "Port filter")
    return field_choices_detail::veeam_ports();
  if (label == "Registry scope")
    return {{"HKLM\\SOFTWARE\\Veeam", "HKLM\\SOFTWARE\\Veeam  (every Veeam product's settings)"},
            {"HKLM\\Software", "HKLM\\Software"},
            {"HKLM\\SYSTEM\\CurrentControlSet\\Services", "HKLM\\SYSTEM\\CurrentControlSet\\Services"},
            {"HKCU\\Software", "HKCU\\Software"},
            {"HKLM", "HKLM  (the whole hive)"},
            {"HKU", "HKU  (every loaded user profile)"},
            {"HKCR", "HKCR  (the whole hive)"},
            {"HKCC", "HKCC  (the whole hive)"},
            {"HKCU", "HKCU  (the whole hive)"}};
  if (label == "Registry view")
    return {{"both", "both  (64-bit and 32-bit)"}, {"native", "native"}, {"64", "64"}, {"32", "32"}};
  if (label == "SQL Server / instance")
    return field_choices_detail::sql_servers();
  if (label == "Check against")
    return {{"Guest processing", "Guest processing  (sysadmin, or the minimal list)"},
            {"Configuration database", "Configuration database  (install, operation, upgrade)"}};
  if (label == "Configuration database")
    return field_choices_detail::configuration_databases();
  if (label == "Another account") {
    // The accounts Veeam's services run as first, then this machine's accounts.
    std::vector<FieldChoice> accounts;
    const auto add = [&accounts](const std::string& name, const std::string& text) {
      for (const FieldChoice& existing : accounts) {
        if (ascii_lower(existing.value) == ascii_lower(name))
          return;
      }
      accounts.push_back({name, text});
    };
    for (const std::string& account : sql_accounts_to_check())
      add(account, account + "  (a Veeam service runs as it)");
    for (const LocalAccount& account : local_accounts())
      add(account.name, account.name + "  (" + account.kind + ")");
    return accounts;
  }
  if (label == "Server role") {
    std::vector<FieldChoice> roles;
    for (const PortPreset& preset : port_presets())
      roles.push_back({preset.id, preset.id + "  (" + preset.name + ")"});
    return roles;
  }
  if (label == "Server's system")
    return {{"", "From the role  (agent-windows, agent-linux)"}, {"Windows", "Windows"}, {"Linux", "Linux"}};
  if (label == "Veeam product")
    return {{"agent", "agent  (Veeam Agent for Microsoft Windows)"}, {"vbr", "vbr  (Veeam Backup & Replication)"}};
  if (label == "Hours")
    return {{"1", "1 hour"}, {"24", "24 hours"}, {"72", "3 days"}, {"168", "7 days"}};
  if (label == "Days")
    return {{"1", "1 day"}, {"7", "7 days"}, {"14", "14 days"}, {"30", "30 days"}, {"90", "90 days"}};
  // The two engines' own databases to start with; opening the list reads the server's.
  if (label == "Database")
    return {{"master", "master  (SQL Server)"}, {"postgres", "postgres  (PostgreSQL)"}};
  if (label == "Query")
    return sql_query_choices(SqlEngine::sql_server);
  return {};
}

// The list a form offers for a field. A Database field on a form without an Engine field (the SQL
// log chain scenario, which reads SQL Server and takes an empty field as every database) offers
// none: the two engines' own databases belong to SQL Tools.
inline std::vector<FieldChoice> form_field_choices(std::string_view label, bool form_has_engine) {
  if (label == "Database" && !form_has_engine)
    return {};
  return field_choices(label);
}

} // namespace support_assist::gui
