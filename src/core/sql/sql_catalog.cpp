// SQL Tools' lists: the database servers on this machine and the databases of one server, and the
// name handling that tells the two engines apart.
#include "support_assist/sql_catalog.hpp"

#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/postgres_check.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <set>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace support_assist {

namespace {

bool all_digits(std::string_view text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](char character) {
           return std::isdigit(static_cast<unsigned char>(character)) != 0;
         });
}

// 1 to 65535 from digits, else 0.
int port_from(std::string_view text) {
  if (!all_digits(text) || text.size() > 5U)
    return 0;
  const int port = std::atoi(std::string(text).c_str());
  return port >= 1 && port <= 65535 ? port : 0;
}

Error catalog_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "SQL Tools";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

std::string read_small_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::string text(1024U * 1024U, '\0');
  input.read(text.data(), static_cast<std::streamsize>(text.size()));
  text.resize(static_cast<std::size_t>(input.gcount()));
  return text;
}

// postgresql.conf in a data directory: the port it sets, else 5432.
int port_of_data_directory(const std::filesystem::path& directory) {
  const auto port = postgres_conf_port(read_small_file(directory / "postgresql.conf"));
  return port ? *port : 5432;
}

void add_found(std::vector<SqlInstanceChoice>& choices, std::set<int>& ports, int port, std::string detail) {
  if (!ports.insert(port).second)
    return;
  choices.push_back({"localhost:" + std::to_string(port), SqlEngine::postgresql, std::move(detail)});
}

#ifdef _WIN32

std::string registry_text(HKEY key, const wchar_t* name) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS)
    return {};
  if (type == REG_DWORD) {
    DWORD value = 0;
    bytes = sizeof(value);
    if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(&value), &bytes) != ERROR_SUCCESS)
      return {};
    return std::to_string(value);
  }
  if (type != REG_SZ && type != REG_EXPAND_SZ)
    return {};
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2U, L'\0');
  DWORD size = static_cast<DWORD>((buffer.size() - 1U) * sizeof(wchar_t));
  if (RegQueryValueExW(key, name, nullptr, &type, reinterpret_cast<LPBYTE>(buffer.data()), &size) != ERROR_SUCCESS)
    return {};
  return utf8_from_wide(std::wstring(buffer.data()));
}

struct RegistryInstance {
  std::string version;
  std::string data_directory;
  std::string port;
};

// The EnterpriseDB installer records each instance under Installations and Services, keyed by the
// service name; both are read and merged by data directory.
std::vector<RegistryInstance> registry_instances() {
  std::vector<RegistryInstance> found;
  for (const wchar_t* root : {L"SOFTWARE\\PostgreSQL\\Installations", L"SOFTWARE\\PostgreSQL\\Services"}) {
    for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
      HKEY parent = nullptr;
      if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, root, 0, KEY_READ | view, &parent) != ERROR_SUCCESS)
        continue;
      for (DWORD index = 0;; ++index) {
        wchar_t name[256]{};
        DWORD length = static_cast<DWORD>(std::size(name));
        if (RegEnumKeyExW(parent, index, name, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
          break;
        HKEY child = nullptr;
        if (RegOpenKeyExW(parent, name, 0, KEY_READ | view, &child) != ERROR_SUCCESS)
          continue;
        RegistryInstance item;
        item.version = registry_text(child, L"Version");
        item.data_directory = registry_text(child, L"Data Directory");
        item.port = registry_text(child, L"Port");
        RegCloseKey(child);
        if (item.data_directory.empty() && item.port.empty())
          continue;
        const auto same = std::find_if(found.begin(), found.end(), [&item](const RegistryInstance& other) {
          return !item.data_directory.empty() && ascii_lower(other.data_directory) == ascii_lower(item.data_directory);
        });
        if (same == found.end()) {
          found.push_back(std::move(item));
        } else {
          if (same->version.empty())
            same->version = item.version;
          if (same->port.empty())
            same->port = item.port;
        }
      }
      RegCloseKey(parent);
    }
  }
  return found;
}

std::filesystem::path program_files_folder() {
  wchar_t* value = nullptr;
  std::size_t length = 0;
  std::filesystem::path folder;
  if (_wdupenv_s(&value, &length, L"ProgramFiles") == 0 && value != nullptr)
    folder = value;
  std::free(value);
  return folder;
}

void add_windows_instances(std::vector<SqlInstanceChoice>& choices, std::set<int>& ports) {
  std::set<std::string> directories;
  for (const RegistryInstance& item : registry_instances()) {
    int port = port_from(item.port);
    if (port == 0)
      port = item.data_directory.empty() ? 5432 : port_of_data_directory(path_from_utf8(item.data_directory));
    std::string detail = "PostgreSQL" + (item.version.empty() ? std::string() : " " + item.version);
    if (!item.data_directory.empty()) {
      detail += ", data directory " + item.data_directory;
      directories.insert(ascii_lower(item.data_directory));
    }
    add_found(choices, ports, port, std::move(detail));
  }
  // An instance the registry does not record: the program folder's PostgreSQL\<version>\data.
  const std::filesystem::path program_files = program_files_folder();
  if (program_files.empty())
    return;
  const std::filesystem::path root = program_files / "PostgreSQL";
  std::error_code error;
  for (std::filesystem::directory_iterator iterator(root, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && iterator != end; iterator.increment(error)) {
    const std::filesystem::path data = iterator->path() / "data";
    std::error_code exists_error;
    if (!std::filesystem::is_regular_file(data / "postgresql.conf", exists_error))
      continue;
    const std::string text = path_to_utf8(data);
    if (directories.count(ascii_lower(text)) != 0U)
      continue;
    add_found(choices, ports, port_of_data_directory(data),
              "PostgreSQL " + path_to_utf8(iterator->path().filename()) + ", data directory " + text);
  }
}

#else

void add_posix_instances(std::vector<SqlInstanceChoice>& choices, std::set<int>& ports) {
  auto subdirectories = [](const std::filesystem::path& root) {
    std::vector<std::filesystem::path> found;
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(root, std::filesystem::directory_options::skip_permission_denied, error), end;
         !error && iterator != end; iterator.increment(error)) {
      std::error_code kind_error;
      if (iterator->is_directory(kind_error))
        found.push_back(iterator->path());
    }
    std::sort(found.begin(), found.end());
    return found;
  };
  auto has_conf = [](const std::filesystem::path& directory) {
    std::error_code error;
    return std::filesystem::is_regular_file(directory / "postgresql.conf", error);
  };
  // Debian and Ubuntu: /etc/postgresql/<version>/<cluster>/postgresql.conf
  for (const std::filesystem::path& version : subdirectories("/etc/postgresql")) {
    for (const std::filesystem::path& cluster : subdirectories(version)) {
      if (has_conf(cluster))
        add_found(choices, ports, port_of_data_directory(cluster),
                  "PostgreSQL " + path_to_utf8(version.filename()) + ", cluster " + path_to_utf8(cluster.filename()) + " (" +
                      path_to_utf8(cluster) + ")");
    }
  }
  // Red Hat family: /var/lib/pgsql/data and /var/lib/pgsql/<version>/data
  std::vector<std::filesystem::path> data_directories{"/var/lib/pgsql/data"};
  for (const std::filesystem::path& version : subdirectories("/var/lib/pgsql"))
    data_directories.push_back(version / "data");
  for (const std::filesystem::path& data : data_directories) {
    if (has_conf(data))
      add_found(choices, ports, port_of_data_directory(data), "PostgreSQL, data directory " + path_to_utf8(data));
  }
  // Sockets of running servers: .s.PGSQL.<port>
  for (const char* folder : {"/var/run/postgresql", "/run/postgresql"}) {
    std::error_code error;
    for (std::filesystem::directory_iterator iterator(folder, std::filesystem::directory_options::skip_permission_denied, error), end;
         !error && iterator != end; iterator.increment(error)) {
      const std::string name = path_to_utf8(iterator->path().filename());
      if (name.rfind(".s.PGSQL.", 0) != 0)
        continue;
      if (const int port = port_from(std::string_view(name).substr(9U)); port != 0)
        add_found(choices, ports, port, std::string("PostgreSQL, socket in ") + folder);
    }
  }
}

#endif

}  // namespace

std::string sql_engine_name(SqlEngine engine) {
  return engine == SqlEngine::postgresql ? "PostgreSQL" : "SQL Server";
}

std::optional<PostgresAddress> parse_postgres_server(std::string_view text) {
  const std::string value = trim(text);
  if (value.empty() || std::any_of(value.begin(), value.end(), [](char character) {
        return std::isspace(static_cast<unsigned char>(character)) != 0 || static_cast<unsigned char>(character) < 0x20U;
      }))
    return std::nullopt;
  PostgresAddress address;
  std::string port_text;
  if (value.front() == '[') {
    const std::size_t close = value.find(']');
    if (close == std::string::npos || close == 1U)
      return std::nullopt;
    address.host = value.substr(1U, close - 1U);
    const std::string rest = value.substr(close + 1U);
    if (!rest.empty()) {
      if (rest.front() != ':' || rest.size() == 1U)
        return std::nullopt;
      port_text = rest.substr(1U);
    }
  } else if (std::count(value.begin(), value.end(), ':') == 1) {
    const std::size_t colon = value.find(':');
    address.host = value.substr(0U, colon);
    port_text = value.substr(colon + 1U);
    if (port_text.empty())
      return std::nullopt;
  } else {
    address.host = value; // a name, or an IPv6 address written without brackets
  }
  if (address.host.empty())
    return std::nullopt;
  if (!port_text.empty()) {
    address.port = port_from(port_text);
    if (address.port == 0)
      return std::nullopt;
  }
  return address;
}

SqlEngine sql_engine_of(std::string_view name) {
  const std::string value = trim(name);
  if (value.find_first_of("\\,") != std::string::npos)
    return SqlEngine::sql_server;
  const std::string lowered = ascii_lower(value);
  for (const char* prefix : {"tcp:", "np:", "lpc:", "via:"}) {
    if (lowered.rfind(prefix, 0) == 0)
      return SqlEngine::sql_server;
  }
  const std::size_t colon = value.rfind(':');
  if (colon == std::string::npos || colon == 0U || port_from(std::string_view(value).substr(colon + 1U)) == 0)
    return SqlEngine::sql_server;
  const std::string host = value.substr(0U, colon);
  const bool bracketed = host.size() > 2U && host.front() == '[' && host.back() == ']';
  return bracketed || host.find(':') == std::string::npos ? SqlEngine::postgresql : SqlEngine::sql_server;
}

std::optional<int> postgres_conf_port(std::string_view text) {
  std::optional<int> port;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t end = text.find('\n', start);
    std::string line(text.substr(start, end == std::string_view::npos ? end : end - start));
    start = end == std::string_view::npos ? text.size() + 1U : end + 1U;
    const std::size_t comment = line.find('#');
    if (comment != std::string::npos)
      line.resize(comment);
    line = trim(line);
    if (line.size() < 5U || ascii_lower(line.substr(0U, 4U)) != "port")
      continue;
    std::string rest = trim(line.substr(4U));
    if (rest.empty() || (rest.front() != '=' && !std::isspace(static_cast<unsigned char>(line[4]))))
      continue;
    if (rest.front() == '=')
      rest = trim(rest.substr(1U));
    if (rest.size() >= 2U && rest.front() == '\'' && rest.back() == '\'')
      rest = trim(rest.substr(1U, rest.size() - 2U));
    if (const int value = port_from(rest); value != 0)
      port = value;
  }
  return port;
}

std::vector<SqlInstanceChoice> local_database_instances() {
  std::vector<SqlInstanceChoice> choices;
  for (const std::string& instance : sql_local_instances())
    choices.push_back({instance, SqlEngine::sql_server, std::string()});
  std::set<int> ports;
#ifdef _WIN32
  add_windows_instances(choices, ports);
#else
  add_posix_instances(choices, ports);
#endif
  // The instance the backup server stores its configuration database in.
  if (const auto databases = identify_configuration_databases(); databases.ok()) {
    for (const ConfigurationDatabaseInfo& item : databases.value()) {
      if (!item.found || ascii_lower(item.engine) != "postgresql")
        continue;
      const int port = item.port.empty() ? 5432 : port_from(item.port);
      for (SqlInstanceChoice& choice : choices) {
        if (choice.engine == SqlEngine::postgresql && choice.name == "localhost:" + std::to_string(port))
          choice.detail += "; Veeam Backup & Replication configuration database " + item.database;
      }
    }
  }
  return choices;
}

Result<std::vector<std::string>> list_databases(SqlEngine engine, const std::string& server, bool use_logged_in_user,
                                                const std::string& login, const std::string& password,
                                                const CancellationToken& cancel, bool trust_server_certificate,
                                                const std::filesystem::path& tools_folder) {
  std::vector<std::string> names;
  if (engine == SqlEngine::postgresql) {
    auto connection = make_postgres_connection(server, use_logged_in_user, login, password, "postgres", tools_folder);
    if (!connection.ok())
      return Result<std::vector<std::string>>::failure(connection.error());
    auto batch = run_postgres_statements(connection.value(), {"SELECT datname FROM pg_database WHERE datallowconn ORDER BY 1"}, cancel);
    std::fill(connection.value().password.begin(), connection.value().password.end(), '\0');
    if (!batch.ok())
      return Result<std::vector<std::string>>::failure(batch.error());
    if (batch.value().statements.empty())
      return Result<std::vector<std::string>>::success(std::move(names));
    const SqlStatementResult& result = batch.value().statements.front();
    if (!result.ok)
      return Result<std::vector<std::string>>::failure(catalog_error("list databases", server, result.error));
    for (const SqlResultSet& set : result.sets) {
      for (const auto& row : set.rows) {
        if (!row.empty() && row.front() && !row.front()->empty())
          names.push_back(*row.front());
      }
    }
    return Result<std::vector<std::string>>::success(std::move(names));
  }

  SqlConnection connection;
  connection.server = trim(server);
  if (connection.server.empty())
    return Result<std::vector<std::string>>::failure(
        catalog_error("list databases", server, "Enter the SQL Server name, or choose one of this machine's instances."));
  connection.database = "master";
  connection.integrated = use_logged_in_user;
  connection.login = login;
  connection.password = password;
  connection.trust_server_certificate = trust_server_certificate;
  if (!connection.integrated && connection.login.empty())
    return Result<std::vector<std::string>>::failure(
        catalog_error("list databases", server, "Enter the SQL login, or tick Use logged-in user."));
  auto batch = run_sql_statements(connection, {"SELECT name FROM sys.databases WHERE state = 0 ORDER BY name"}, cancel);
  std::fill(connection.password.begin(), connection.password.end(), '\0');
  if (!batch.ok())
    return Result<std::vector<std::string>>::failure(batch.error());
  if (batch.value().statements.empty())
    return Result<std::vector<std::string>>::success(std::move(names));
  const SqlStatementResult& result = batch.value().statements.front();
  if (!result.ok)
    return Result<std::vector<std::string>>::failure(catalog_error("list databases", server, result.error));
  for (const SqlResultSet& set : result.sets) {
    for (const auto& row : set.rows) {
      if (!row.empty() && row.front() && !row.front()->empty())
        names.push_back(*row.front());
    }
  }
  return Result<std::vector<std::string>>::success(std::move(names));
}

}  // namespace support_assist
