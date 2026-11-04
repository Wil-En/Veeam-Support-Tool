#include "support_assist/tool_catalog.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <cstdlib>
#include <system_error>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <shellapi.h>
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace support_assist {
namespace {

std::vector<std::filesystem::path> path_directories() {
  std::vector<std::filesystem::path> output;
#ifdef _WIN32
  wchar_t* value = nullptr;
  std::size_t length = 0;
  if (_wdupenv_s(&value, &length, L"PATH") == 0 && value != nullptr) {
    const std::wstring path_value(value);
    std::free(value);
    std::size_t start = 0;
    while (start <= path_value.size()) {
      const std::size_t end = path_value.find(L';', start);
      const std::wstring item =
          path_value.substr(start, end == std::wstring::npos ? std::wstring::npos : end - start);
      if (!item.empty())
        output.emplace_back(item);
      if (end == std::wstring::npos)
        break;
      start = end + 1U;
    }
  }
#else
  const char* value = std::getenv("PATH");
  if (value != nullptr) {
    const std::string path_value(value);
    std::size_t start = 0;
    while (start <= path_value.size()) {
      const std::size_t end = path_value.find(':', start);
      const std::string item =
          path_value.substr(start, end == std::string::npos ? std::string::npos : end - start);
      if (!item.empty())
        output.emplace_back(item);
      if (end == std::string::npos)
        break;
      start = end + 1U;
    }
  }
#endif
  return output;
}

// Expand one directory glob that may contain a single '*' wildcard matching exactly one path
// component (e.g. ".../PostgreSQL/*/bin"). One level of enumeration only - never recursive.
std::vector<std::filesystem::path> expand_install_glob(const std::string& glob) {
  const std::filesystem::path pattern(glob);
  const auto star = glob.find('*');
  if (star == std::string::npos) {
    std::error_code exists_error;
    if (std::filesystem::is_directory(pattern, exists_error))
      return {pattern};
    return {};
  }
  // Split into <base>/<*>/<tail...>. Enumerate <base> one level, keep directories, append the tail.
  std::filesystem::path base;
  std::filesystem::path tail;
  bool seen_star = false;
  for (const auto& part : pattern) {
    if (!seen_star && path_to_utf8(part).find('*') != std::string::npos) {
      seen_star = true;
      continue;
    }
    if (!seen_star)
      base /= part;
    else
      tail /= part;
  }
  std::vector<std::filesystem::path> output;
  std::error_code error;
  if (!std::filesystem::is_directory(base, error))
    return output;
  for (std::filesystem::directory_iterator iterator(
           base, std::filesystem::directory_options::skip_permission_denied, error), end;
       iterator != end && !error; iterator.increment(error)) {
    if (iterator->is_directory(error)) {
      std::filesystem::path candidate = iterator->path();
      if (!tail.empty())
        candidate /= tail;
      if (std::filesystem::is_directory(candidate, error))
        output.push_back(candidate);
    }
  }
  return output;
}

#ifdef _WIN32
// The registered install path for an executable, from HKLM/HKCU App Paths - an O(1) lookup that
// finds tools (Wireshark and the like) that register there, without touching the filesystem.
std::filesystem::path app_paths_lookup(const std::string& executable_name) {
  const std::wstring subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\" +
                              wide_from_utf8(executable_name);
  for (HKEY root : {HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE}) {
    wchar_t buffer[MAX_PATH]{};
    DWORD size = sizeof(buffer);
    if (RegGetValueW(root, subkey.c_str(), nullptr, RRF_RT_REG_SZ, nullptr, buffer, &size) ==
        ERROR_SUCCESS) {
      std::filesystem::path candidate(buffer);
      std::error_code error;
      if (std::filesystem::is_regular_file(candidate, error))
        return candidate;
    }
  }
  return {};
}
#endif

std::filesystem::path find_candidate(const ExternalToolDefinition& definition,
                                     const std::filesystem::path& third_party_directory) {
  // Managed downloads are stored beneath Tools\<tool>\<version>. Search that
  // small, user-selected tree with a strict depth and entry limit before PATH.
  // This fixes the previous behavior where only executables placed directly in
  // the Tools root were detected after a successful managed download.
  if (!third_party_directory.empty()) {
    std::error_code recursive_error;
    if (std::filesystem::is_directory(third_party_directory, recursive_error)) {
      std::size_t visited = 0;
      std::filesystem::recursive_directory_iterator iterator(
          third_party_directory,
          std::filesystem::directory_options::skip_permission_denied,
          recursive_error);
      const std::filesystem::recursive_directory_iterator end;
      for (; iterator != end && visited < 5000U; iterator.increment(recursive_error)) {
        if (recursive_error) {
          recursive_error.clear();
          continue;
        }
        ++visited;
        if (iterator.depth() >= 4) {
          iterator.disable_recursion_pending();
        }
        if (!iterator->is_regular_file(recursive_error)) {
          recursive_error.clear();
          continue;
        }
        const std::string candidate_name = ascii_lower(path_to_utf8(iterator->path().filename()));
        for (const auto& executable_name : definition.executable_names) {
          if (candidate_name == ascii_lower(executable_name))
            return iterator->path();
        }
      }
    }
  }

  std::vector<std::filesystem::path> directories;
  if (!third_party_directory.empty())
    directories.push_back(third_party_directory);
#ifdef _WIN32
  if (definition.bundled_by_windows) {
    wchar_t system_directory[MAX_PATH]{};
    const UINT length = GetSystemDirectoryW(system_directory, MAX_PATH);
    if (length > 0 && length < MAX_PATH)
      directories.emplace_back(system_directory);
  }
#endif
  // In-box Windows tools (for example pktmon) must resolve only from the trusted
  // Windows system directory. Falling back to PATH would allow an untrusted
  // user-writable directory to substitute a same-named executable.
  if (!definition.bundled_by_windows) {
    const auto path_values = path_directories();
    directories.insert(directories.end(), path_values.begin(), path_values.end());
    // Bounded "detect underneath": each known-install glob expands one level (no recursion).
    for (const auto& glob : definition.known_install_globs) {
      const auto expanded = expand_install_glob(glob);
      directories.insert(directories.end(), expanded.begin(), expanded.end());
    }
  }

  std::error_code error_code;
  for (const auto& directory : directories) {
    for (const auto& name : definition.executable_names) {
      const std::filesystem::path candidate = directory / name;
      if (std::filesystem::is_regular_file(candidate, error_code))
        return candidate;
      error_code.clear();
    }
  }
#ifdef _WIN32
  // Last, the registry App Paths (registered installers). Cheap and covers tools not on PATH.
  if (!definition.bundled_by_windows) {
    for (const auto& name : definition.executable_names) {
      const std::filesystem::path registered = app_paths_lookup(name);
      if (!registered.empty())
        return registered;
    }
  }
#endif
  return {};
}

Error catalog_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "ToolCatalog";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

const ExternalToolDefinition* find_definition(std::string_view id) {
  const std::string folded = ascii_lower(id);
  for (const auto& definition : external_tool_catalog()) {
    if (ascii_lower(definition.id) == folded || ascii_lower(definition.name) == folded) {
      return &definition;
    }
  }
  return nullptr;
}

} // namespace

std::string to_string(ToolAvailability value) {
  switch (value) {
  case ToolAvailability::available:
    return "available";
  case ToolAvailability::missing:
    return "missing";
  case ToolAvailability::unsupported:
    return "unsupported";
  }
  return "unknown";
}

const std::vector<ExternalToolDefinition>& external_tool_catalog() {
  static const std::vector<ExternalToolDefinition> catalog = [] {
    std::vector<ExternalToolDefinition> tools;
    tools.reserve(11);

    ExternalToolDefinition pktmon;
    pktmon.id = "pktmon";
    pktmon.name = "Packet Monitor";
    pktmon.category = "Windows built-in";
    pktmon.executable_names = {"pktmon.exe"};
    pktmon.source_url =
        "https://learn.microsoft.com/windows-server/administration/windows-commands/pktmon";
    pktmon.description =
        "Windows' built-in packet capture - no install needed. Capture network traffic to an .etl, "
        "read counters, and convert the capture to PCAPNG for Wireshark. Use it to prove whether "
        "traffic is reaching a host during a backup or transport problem.";
    pktmon.bundled_by_windows = true;
    pktmon.windows_only = true;
    pktmon.optional_integration = false;
    pktmon.native_alternative = "Primary packet-capture backend";
    tools.push_back(std::move(pktmon));

    ExternalToolDefinition etl2pcapng;
    etl2pcapng.id = "etl2pcapng";
    etl2pcapng.name = "ETL2PCAPNG";
    etl2pcapng.category = "Optional network integration";
    etl2pcapng.executable_names = {"etl2pcapng.exe"};
    etl2pcapng.source_url = "https://github.com/microsoft/etl2pcapng/releases/latest";
    etl2pcapng.description =
        "Converts an .etl network capture into a .pcapng that Wireshark can open. Point it at a "
        "capture pktmon's own converter cannot read. Use it when you need to inspect packets in "
        "Wireshark rather than as text.";
    etl2pcapng.windows_only = true;
    etl2pcapng.native_alternative = "pktmon's built-in ETL to PCAPNG conversion";
    tools.push_back(std::move(etl2pcapng));

    ExternalToolDefinition procmon;
    procmon.id = "procmon";
    procmon.name = "Process Monitor";
    procmon.category = "Optional activity integration";
    procmon.executable_names = {"Procmon64.exe", "Procmon.exe"};
    procmon.source_url = "https://learn.microsoft.com/sysinternals/downloads/procmon";
    procmon.download_url = "https://download.sysinternals.com/files/ProcessMonitor.zip";
    procmon.download_filename = "ProcessMonitor.zip";
    procmon.download_archive = "zip";
    procmon.description =
        "Sysinternals Process Monitor. Records process, registry and filesystem events live so you "
        "can see exactly what a Veeam process touches and where it is denied or blocked. Use it for "
        "permission, path and locking problems the logs only hint at.";
    procmon.automatic_download_supported = true;
    procmon.launches_gui = true;
    procmon.windows_only = true;
    procmon.native_alternative =
        "Native process inventory, WMI diagnostics, and Registry/filesystem baselines";
    tools.push_back(std::move(procmon));

    ExternalToolDefinition iperf3;
    iperf3.id = "iperf3";
    iperf3.name = "iPerf3";
    iperf3.category = "Optional network integration";
    iperf3.executable_names = {"iperf3.exe", "iperf3"};
    // iperf.fr publishes the pre-built binaries (the Windows zip the download config fetches);
    // ESnet's GitHub releases carry source only.
    iperf3.source_url = "https://iperf.fr/iperf-download.php";
    iperf3.description =
        "Measures raw network throughput between two hosts. Run it as a server on one end and a "
        "client on the other. Use it to prove whether a slow backup is the network by testing the "
        "link independently of Veeam.";
    iperf3.native_alternative = "SAT's built-in TCP throughput client/server";
    tools.push_back(std::move(iperf3));

    ExternalToolDefinition wireshark;
    wireshark.id = "wireshark";
    wireshark.name = "Wireshark";
    wireshark.category = "Optional packet viewer";
    wireshark.executable_names = {"Wireshark.exe", "WiresharkPortable64.exe", "WiresharkPortable.exe", "wireshark"};
    wireshark.source_url = "https://www.wireshark.org/download.html";
    wireshark.description =
        "The interactive protocol analyzer. Open a PCAPNG capture to inspect packets, follow "
        "conversations and filter by host or protocol. Use it when a capture needs real analysis "
        "rather than a counter summary. Opening a capture file needs nothing more; a live capture "
        "in Wireshark also needs Npcap, installed separately with administrator rights.";
    wireshark.launches_gui = true;
    wireshark.native_alternative = "SAT's own packet capture and PCAPNG conversion";
    tools.push_back(std::move(wireshark));

    ExternalToolDefinition vsstrace;
    vsstrace.id = "vsstrace";
    vsstrace.name = "VSS Trace";
    vsstrace.category = "Optional VSS integration";
    vsstrace.executable_names = {"vsstrace.exe", "VssTrace.exe"};
    // KB3164: How to Use VSSTrace to Collect VSS Diagnostic Logging. The download is the vendor's
    // published zip named in that article.
    vsstrace.source_url = "https://www.veeam.com/kb3164";
    vsstrace.download_url = "https://storage.veeam.com/utils/Vsstrace.zip";
    vsstrace.download_filename = "Vsstrace.zip";
    vsstrace.download_archive = "zip";
    vsstrace.automatic_download_supported = true;
    vsstrace.description =
        "Veeam's VSS tracing utility (KB3164). SAT runs it elevated with the required flags, you "
        "reproduce the failing backup, and it captures a detailed shadow-copy trace into the case. "
        "Use it for VSS writer and snapshot failures the event log does not fully explain.";
    vsstrace.windows_only = true;
    // SAT runs it with the KB3164 parameters and collects the trace into the case's logs; Run starts
    // it, Stop ends it. The log level must be 255 (-l 255), full flags (+f 0xffff).
    vsstrace.managed_run = true;
    vsstrace.managed_run_arguments = "+f 0xffff -l 255 -o {logfile}";
    vsstrace.managed_run_elevated = true;
    vsstrace.native_alternative =
        "SAT's VSS writer enumeration, test jobs, and Event Log collection";
    tools.push_back(std::move(vsstrace));

    ExternalToolDefinition sqlcmd;
    sqlcmd.id = "sqlcmd";
    sqlcmd.name = "SQLCMD";
    sqlcmd.category = "Optional SQL integration";
    sqlcmd.executable_names = {"sqlcmd.exe", "sqlcmd"};
    sqlcmd.source_url = "https://learn.microsoft.com/sql/tools/sqlcmd/sqlcmd-download-install";
    sqlcmd.description =
        "Microsoft's command-line SQL client for SQL Server. SAT opens an interactive console against "
        "an instance so you can check database state, recovery model or job history when "
        "troubleshooting a Veeam SQL plug-in or a SQL Server configuration database (default "
        "database VeeamBackup). Detected from an existing SQL client install; otherwise acquired.";
    sqlcmd.database_console = true;
    sqlcmd.known_install_globs = {
        "C:/Program Files/sqlcmd",
        "C:/Program Files/Microsoft SQL Server/Client SDK/ODBC/*/Tools/Binn",
        "C:/Program Files (x86)/Microsoft SQL Server/Client SDK/ODBC/*/Tools/Binn",
        "/opt/mssql-tools18/bin",
        "/opt/mssql-tools/bin"};
    sqlcmd.native_alternative = "SAT's built-in ODBC SQL diagnostics";
    tools.push_back(std::move(sqlcmd));

    ExternalToolDefinition psql;
    psql.id = "psql";
    psql.name = "psql (PostgreSQL)";
    psql.category = "Optional SQL integration";
    psql.executable_names = {"psql.exe", "psql"};
    psql.source_url = "https://www.enterprisedb.com/download-postgresql-binaries";
    psql.description =
        "PostgreSQL's command-line client. SAT opens an interactive console against a PostgreSQL "
        "instance - the Veeam Backup & Replication configuration database on v12 and later "
        "(default database VeeamBackup, port 5432). It ships with any PostgreSQL install, including "
        "the one bundled on a Veeam server, so SAT detects it in place before offering a download.";
    psql.database_console = true;
    // The EDB binaries zip carries the server, pgAdmin 4 and debug symbols as well; psql and the
    // libraries it loads are under pgsql/bin.
    psql.download_extract = {"pgsql/bin/"};
    psql.known_install_globs = {
        "C:/Program Files/PostgreSQL/*/bin",
        "C:/Program Files (x86)/PostgreSQL/*/bin",
        "/usr/pgsql-*/bin",
        "/usr/lib/postgresql/*/bin",
        "/usr/local/bin"};
    psql.native_alternative = "SAT's built-in ODBC SQL diagnostics";
    tools.push_back(std::move(psql));

    ExternalToolDefinition tcpdump;
    tcpdump.id = "tcpdump";
    tcpdump.name = "tcpdump";
    tcpdump.category = "Optional capture integration";
    tcpdump.executable_names = {"tcpdump"};
    tcpdump.source_url = "https://www.tcpdump.org/";
    tcpdump.description =
        "The standard Unix packet capture tool - the Linux counterpart of Packet Monitor. SAT runs a "
        "filtered capture on an interface (headers only), matched to the host and port that is "
        "failing, and logs the packet summaries. Veeam's own guidance (KB2256) uses tcpdump on Linux. "
        "Requires root or the cap_net_raw capability.";
    tcpdump.linux_only = true;
    tcpdump.known_install_globs = {"/usr/sbin", "/usr/bin", "/sbin"};
    tcpdump.native_alternative = "SAT's built-in connectivity diagnostics";
    tools.push_back(std::move(tcpdump));

    // The Disk Speed Test's engines (Storage Tools): KB2014 gives a DiskSpd and an fio command for
    // each Veeam operation.
    ExternalToolDefinition diskspd;
    diskspd.id = "diskspd";
    diskspd.name = "DiskSpd";
    diskspd.category = "Optional storage integration";
    diskspd.executable_names = {"diskspd.exe"};
    diskspd.source_url = "https://github.com/microsoft/diskspd/releases/latest";
    diskspd.download_url = "https://github.com/microsoft/diskspd/releases/latest/download/DiskSpd.ZIP";
    diskspd.download_filename = "DiskSpd.zip";
    diskspd.download_archive = "zip";
    diskspd.automatic_download_supported = true;
    diskspd.description =
        "Microsoft's storage load generator. The Disk Speed Test runs it with Veeam's own KB2014 tests "
        "(active full, merge, reverse incremental, restore) on the storage behind a folder, and runs it "
        "only while Microsoft's signature on it checks out.";
    diskspd.windows_only = true;
    diskspd.native_alternative = "The Disk Speed Test needs it on Windows; there is no built-in equivalent";
    tools.push_back(std::move(diskspd));

    ExternalToolDefinition fio;
    fio.id = "fio";
    fio.name = "fio";
    fio.category = "Optional storage integration";
    fio.executable_names = {"fio"};
    fio.source_url = "https://github.com/axboe/fio";
    fio.description =
        "The flexible I/O tester, from the distribution's packages. The Disk Speed Test runs it with "
        "Veeam's own KB2014 tests on the storage behind a folder.";
    fio.linux_only = true;
    fio.known_install_globs = {"/usr/bin", "/usr/local/bin"};
    fio.native_alternative = "The Disk Speed Test needs it on Linux; there is no built-in equivalent";
    tools.push_back(std::move(fio));

    return tools;
  }();
  return catalog;
}

std::vector<ExternalToolStatus>
inspect_external_tools(const std::filesystem::path& third_party_directory) {
  std::vector<ExternalToolStatus> output;
  output.reserve(external_tool_catalog().size());
  for (const auto& definition : external_tool_catalog()) {
    ExternalToolStatus status;
    status.definition = definition;
#ifdef _WIN32
    if (definition.linux_only) {
      status.availability = ToolAvailability::unsupported;
      status.detail = "Linux-only integration";
    } else {
      status.resolved_path = find_candidate(definition, third_party_directory);
      status.availability =
          status.resolved_path.empty() ? ToolAvailability::missing : ToolAvailability::available;
      status.detail =
          status.resolved_path.empty()
              ? "Not found in the configured optional-tools directory, Windows system directory, or PATH"
              : path_to_utf8(status.resolved_path);
    }
#else
    if (definition.windows_only) {
      status.availability = ToolAvailability::unsupported;
      status.detail = "Windows-only integration";
    } else {
      status.resolved_path = find_candidate(definition, third_party_directory);
      status.availability =
          status.resolved_path.empty() ? ToolAvailability::missing : ToolAvailability::available;
      status.detail = status.resolved_path.empty() ? "Not found" : path_to_utf8(status.resolved_path);
    }
#endif
    output.push_back(std::move(status));
  }
  return output;
}

Result<std::filesystem::path>
resolve_external_tool(std::string_view id, const std::filesystem::path& third_party_directory) {
  const ExternalToolDefinition* definition = find_definition(id);
  if (definition == nullptr) {
    return Result<std::filesystem::path>::failure(
        catalog_error("resolve tool", std::string(id), "Unknown tool identifier"));
  }
  const std::filesystem::path path = find_candidate(*definition, third_party_directory);
  if (path.empty()) {
    return Result<std::filesystem::path>::failure(catalog_error(
        "resolve tool",
        definition->name,
        "The tool was not found in the optional-tools directory, Windows system directory, or PATH"));
  }
  return Result<std::filesystem::path>::success(path);
}

Status open_external_tool_source(std::string_view id) {
  const ExternalToolDefinition* definition = find_definition(id);
  if (definition == nullptr) {
    return Status::failure(
        catalog_error("open source page", std::string(id), "Unknown tool identifier"));
  }
#ifdef _WIN32
  const std::wstring url(definition->source_url.begin(), definition->source_url.end());
  const HINSTANCE result =
      ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
  if (reinterpret_cast<INT_PTR>(result) <= 32) {
    return Status::failure(
        catalog_error("open source page", definition->source_url, "ShellExecuteW failed"));
  }
  return Status::success();
#else
  if (definition->windows_only) {
    return Status::failure(catalog_error("open source page",
                                         definition->source_url,
                                         "This integration is not applicable to this platform"));
  }
  const pid_t child = fork();
  if (child < 0) {
    return Status::failure(
        catalog_error("open source page", definition->source_url, "Could not create browser-launch process"));
  }
  if (child == 0) {
#if defined(__APPLE__)
    execlp("open", "open", definition->source_url.c_str(), static_cast<char*>(nullptr));
#else
    execlp("xdg-open", "xdg-open", definition->source_url.c_str(), static_cast<char*>(nullptr));
#endif
    _exit(127);
  }
  int status = 0;
  if (waitpid(child, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    return Status::failure(catalog_error(
        "open source page", definition->source_url, "The platform browser launcher reported failure"));
  }
  return Status::success();
#endif
}

} // namespace support_assist
