#include "support_assist/product_discovery.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <memory>
#include <type_traits>
#include <sstream>
#include <system_error>
#include <set>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace support_assist {
namespace {

bool supports(const ProductDefinition& definition, HostPlatform platform) {
  return std::find(definition.platforms.begin(), definition.platforms.end(), platform) !=
         definition.platforms.end();
}

std::filesystem::path env_path(const char* name) {
#ifdef _WIN32
  const std::wstring wide_name = wide_from_utf8(name);
  wchar_t* value = nullptr;
  std::size_t length = 0;
  if (_wdupenv_s(&value, &length, wide_name.c_str()) == 0 && value != nullptr) {
    const std::filesystem::path result(value);
    std::free(value);
    return result;
  }
  std::free(value);
#else
  if (const char* value = std::getenv(name); value != nullptr && *value != '\0')
    return std::filesystem::path(value);
#endif
  return {};
}


#ifdef _WIN32
std::wstring registry_string_value(HKEY key, const wchar_t* name) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t))
    return {};
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 1U, L'\0');
  if (RegQueryValueExW(key, name, nullptr, &type,
                      reinterpret_cast<BYTE*>(buffer.data()), &bytes) != ERROR_SUCCESS)
    return {};
  return std::wstring(buffer.data());
}

void append_windows_installed_product_names(HKEY root, REGSAM view,
                                            std::vector<std::string>& output) {
  HKEY uninstall = nullptr;
  constexpr wchar_t key_path[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
  if (RegOpenKeyExW(root, key_path, 0, KEY_READ | view, &uninstall) != ERROR_SUCCESS)
    return;
  const std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> owner(uninstall,
                                                                                  RegCloseKey);
  for (DWORD index = 0;; ++index) {
    std::array<wchar_t, 512> subkey{};
    DWORD count = static_cast<DWORD>(subkey.size());
    const LSTATUS status = RegEnumKeyExW(uninstall, index, subkey.data(), &count,
                                         nullptr, nullptr, nullptr, nullptr);
    if (status == ERROR_NO_MORE_ITEMS)
      break;
    if (status != ERROR_SUCCESS)
      continue;
    HKEY product = nullptr;
    if (RegOpenKeyExW(uninstall, subkey.data(), 0, KEY_READ | view, &product) != ERROR_SUCCESS)
      continue;
    const std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> product_owner(
        product, RegCloseKey);
    const std::wstring display_name = registry_string_value(product, L"DisplayName");
    if (!display_name.empty())
      output.push_back(utf8_from_wide(display_name));
  }
}

std::vector<std::string> windows_installed_product_names() {
  std::vector<std::string> names;
  append_windows_installed_product_names(HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY, names);
  append_windows_installed_product_names(HKEY_LOCAL_MACHINE, KEY_WOW64_32KEY, names);
  append_windows_installed_product_names(HKEY_CURRENT_USER, KEY_WOW64_64KEY, names);
  append_windows_installed_product_names(HKEY_CURRENT_USER, KEY_WOW64_32KEY, names);
  std::set<std::string> seen;
  std::vector<std::string> unique;
  for (auto& name : names) {
    const std::string key = ascii_lower(name);
    if (seen.insert(key).second)
      unique.push_back(std::move(name));
  }
  return unique;
}
#endif

bool installed_name_matches(const ProductDefinition& definition,
                            const ProductDiscoveryContext& context) {
  if (definition.installed_product_name_tokens.empty() || context.installed_product_names.empty())
    return false;
  for (const auto& installed : context.installed_product_names) {
    const std::string folded = ascii_lower(installed);
    const bool excluded = std::any_of(
        definition.installed_product_name_exclusion_tokens.begin(),
        definition.installed_product_name_exclusion_tokens.end(), [&](const auto& token) {
          return !token.empty() && folded.find(ascii_lower(token)) != std::string::npos;
        });
    if (excluded)
      continue;
    for (const auto& token : definition.installed_product_name_tokens) {
      if (!token.empty() && folded.find(ascii_lower(token)) != std::string::npos)
        return true;
    }
  }
  return false;
}

ProductDefinition make_product(std::string id,
                               std::string name,
                               std::string role,
                               std::vector<HostPlatform> platforms,
                               std::string architecture,
                               std::string docs) {
  ProductDefinition result;
  result.id = std::move(id);
  result.display_name = std::move(name);
  result.role = std::move(role);
  result.platforms = std::move(platforms);
  result.architecture_note = std::move(architecture);
  result.documentation_reference = std::move(docs);
  return result;
}

// SCOPE OF THIS CATALOG: it drives GATHER, not PARSE.
//
// These entries tell the collector what to pick up FROM THE HOST IT IS RUNNING ON. That makes them
// bounded by where SAT itself runs - Windows, Linux and macOS. Veeam supports several of these
// plug-ins on IBM AIX and Oracle Solaris as well; SAT has no host build for those, so their paths
// are deliberately absent here. That is a limit of the collector, NOT of the parser: an AIX or
// Solaris bundle handed to SAT by a customer still has to be read, and the review side must stay
// permissive about paths it did not collect itself.
//
// Two further exclusions, both intentional:
//
//  * Solutions that only run in MANAGED mode (MongoDB Backup, Epic EHR / InterSystems IRIS) have
//    no standalone plug-in installed on the database server, so there is nothing on that host for
//    this catalog to point at. Their evidence lives on the VBR side.
//  * Database-owned trees (Oracle's /oracle, MaxDB's /sapdb, Db2's DIAGPATH) are recorded where
//    Veeam documents them but flagged so no collector walks them. They hold production data.
//
// Add a path here only when Veeam documents it. A guessed path either collects nothing or collects
// something it should not have touched, and on a customer's database server the second is far worse.
void append_windows_catalog(std::vector<ProductDefinition>& catalog) {
  {
    auto p = make_product("vaw", "Veeam Agent for Microsoft Windows", "Endpoint Agent",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Agent for Microsoft Windows 13.x User Guide");
    p.detection_paths = {"Veeam/Endpoint"};
    p.log_paths = {{"Veeam/Endpoint", "Veeam Agent endpoint logs"},
                   {"Veeam/Backup", "Veeam Agent/VSS-provider and shared Veeam logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("vbr", "Veeam Backup & Replication", "Backup Server / Infrastructure",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Backup & Replication 13.1 Managing Logs");
    // ProgramData\Veeam\Backup is a shared log root used by multiple Veeam
    // products, including Veeam Agent for Microsoft Windows. It must never be
    // treated as a VBR installation signature. Use the actual installed product
    // registration or VBR binaries under Program Files instead.
    p.program_files_detection_paths = {
        "Veeam/Backup and Replication/Backup/Veeam.Backup.Service.exe"};
    p.installed_product_name_tokens = {"Veeam Backup & Replication",
                                       "Veeam Backup and Replication"};
    p.installed_product_name_exclusion_tokens = {"Console"};
    p.log_paths = {{"Veeam/Backup", "Shared Veeam backup/service/job logs (VBR content when present)"},
                   {"Veeam/Setup/Temp", "Veeam installation and upgrade logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("vb365", "Veeam Backup for Microsoft 365", "Microsoft 365 Backup Server",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Backup for Microsoft 365 8.5 Managing Log Files");
    p.detection_paths = {"Veeam/Backup365/Logs"};
    p.log_paths = {{"Veeam/Backup365/Logs", "Veeam Backup for Microsoft 365 logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("vspc", "Veeam Service Provider Console", "Service Provider Console Server",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Service Provider Console 9.3 Downloading Logs");
    p.detection_paths = {"Veeam/Veeam Availability Console/Log"};
    p.log_paths = {{"Veeam/Veeam Availability Console/Log", "VSPC server and Web UI logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("veeam-one", "Veeam ONE", "Monitoring Server",
                          {HostPlatform::windows}, "x64 Windows", "Veeam ONE User Guide");
    p.detection_paths = {"Veeam/Veeam ONE"};
    p.log_paths = {{"Veeam/Veeam ONE", "Veeam ONE operational logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("vro", "Veeam Recovery Orchestrator", "Recovery Orchestrator",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Recovery Orchestrator 13.1 Support Guide");
    p.detection_paths = {"Veeam/Availability Orchestrator", "Veeam/Recovery Orchestrator"};
    p.log_paths = {{"Veeam/Availability Orchestrator", "Orchestrator logs"},
                   {"Veeam/Recovery Orchestrator", "Recovery Orchestrator logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("mssql-plugin", "Veeam Plug-In for Microsoft SQL Server", "Database Plug-In",
                          {HostPlatform::windows}, "x64 Windows", "Veeam Backup & Replication 13.1 Microsoft SQL Server Plug-In Guide");
    p.detection_paths = {"Veeam/Backup/MSSQLPluginLogs"};
    p.program_files_detection_paths = {"Veeam/Plugins/Microsoft SQL"};
    p.log_paths = {{"Veeam/Backup/MSSQLPluginLogs", "Veeam Microsoft SQL Server plug-in logs"},
                   {"Veeam/Backup/Plugin", "VBR-side plug-in operation logs"},
                   {"Veeam/Backup/Rescan", "Managed-mode plug-in rescan logs (VBR side)"}};
    catalog.push_back(std::move(p));
  }
  {
    // Oracle RMAN on WINDOWS. The Linux entry below is a different install layout entirely:
    // KB2871 documents %ProgramData%\Veeam\Backup\RmanPluginLogs for a Windows Oracle server and
    // /tmp/veeam_plugin_logs + /tmp/OracleProxyLogs for Linux/Solaris/AIX. Only the Windows paths
    // belong here.
    auto p = make_product("rman-plugin-windows", "Veeam Plug-In for Oracle RMAN", "Database Plug-In",
                          {HostPlatform::windows}, "x64 Windows Oracle server",
                          "Veeam KB2871 - How to Collect Logs for Veeam Plug-in for Oracle RMAN");
    p.detection_paths = {"Veeam/Backup/RmanPluginLogs"};
    p.log_paths = {{"Veeam/Backup/RmanPluginLogs", "Veeam Oracle RMAN plug-in logs"},
                   {"Veeam/Backup/Plugin", "VBR-side plug-in operation logs"},
                   {"Veeam/Backup/Rescan", "Managed-mode plug-in rescan logs (VBR side)"}};
    catalog.push_back(std::move(p));
  }
  {
    // IBM Db2 on WINDOWS. The user guide documents the install root
    // (%PROGRAMFILES%\Veeam\VeeamPluginforDB2\, which is NOT under \Veeam\Plugins\ like the SQL
    // plug-in), but KB4554 documents only the Linux log directory. No Windows-side plug-in log
    // directory is published, so none is invented here - detection is by install root and the
    // collectable evidence is the VBR-side plug-in folder until Veeam documents more.
    auto p = make_product("db2-plugin-windows", "Veeam Plug-In for IBM Db2", "Database Plug-In",
                          {HostPlatform::windows}, "x64 Windows Db2 server",
                          "Veeam Backup & Replication 13.1 IBM Db2 Plug-In Guide; Veeam KB4554");
    p.program_files_detection_paths = {"Veeam/VeeamPluginforDB2"};
    p.log_paths = {{"Veeam/Backup/Plugin", "VBR-side plug-in operation logs"},
                   {"Veeam/Backup/Rescan", "Managed-mode plug-in rescan logs (VBR side)"}};
    catalog.push_back(std::move(p));
  }
}

void append_linux_catalog(std::vector<ProductDefinition>& catalog) {
  {
    auto p = make_product("val", "Veeam Agent for Linux", "Endpoint Agent", {HostPlatform::linux},
                          "64-bit x86/x64 matrix; nosnap also supports little-endian IBM POWER9/POWER10 on documented RHEL/SLES families",
                          "Veeam Agent for Linux 13.1 User Guide");
    p.detection_paths = {"/etc/veeam", "/usr/sbin/veeamsupporttool", "/usr/bin/veeamconfig"};
    p.log_paths = {{"/var/log/veeam", "Veeam Agent for Linux logs"},
                   {"/var/log/VeeamBackup", "Veeam transport/infrastructure logs"},
                   {"/tmp/VeeamBackup", "Temporary Veeam transport logs"}};
    p.preferred_exporter = "/usr/sbin/veeamsupporttool";
    p.preferred_exporter_arguments = {"grab-logs"};
    p.exporter_requires_elevation = true;
    p.exporter_may_include_configuration = true;
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("vbr-linux", "Veeam Backup & Replication", "Linux Backup Server / Appliance",
                          {HostPlatform::linux}, "x86-64 appliance/server roles",
                          "Veeam Backup & Replication 13.1 Managing Logs");
    // /var/log/VeeamBackup is also used by Agent/transport components and is
    // therefore evidence/log coverage, not a VBR-appliance installation signature.
    p.detection_paths = {"/var/lib/veeam/VeeamBackupLogFolder"};
    p.log_paths = {{"/var/lib/veeam/VeeamBackupLogFolder", "VBR 13.1 clean-install backup service logs"},
                   {"/var/log/VeeamBackup", "VBR/infrastructure logs (upgrades and managed Linux roles)"},
                   {"/var/log/veeam", "Veeam Updater and supporting logs"},
                   {"/tmp/VeeamBackup", "Temporary Veeam transport logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("rman-plugin", "Veeam Plug-In for Oracle RMAN", "Database Plug-In",
                          {HostPlatform::linux}, "x86-64 Linux distributions supported by Oracle/Veeam matrix",
                          "Veeam Backup & Replication 13.1 Oracle RMAN Plug-In Guide");
    p.detection_paths = {"/opt/veeam/VeeamPluginforOracleRMAN"};
    // KB2871 lists TWO directories on the Oracle server. Collecting only veeam_plugin_logs loses
    // the proxy side of the transfer, which is where a stalled or refused data mover shows up.
    p.log_paths = {{"/tmp/veeam_plugin_logs", "Veeam database plug-in temporary logs"},
                   {"/tmp/OracleProxyLogs", "Veeam Oracle proxy logs"},
                   {"/var/log/VeeamBackup/Plugin", "Plug-in logs on a Linux backup repository"},
                   {"/var/log/VeeamBackup", "Managed-mode deployment and transport logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("sap-hana-plugin", "Veeam Plug-In for SAP HANA", "Database Plug-In",
                          {HostPlatform::linux}, "x64 Linux; selected Linux on Power deployments are product-supported",
                          "Veeam Backup & Replication 13.1 SAP HANA Plug-In Guide");
    p.detection_paths = {"/opt/veeam/VeeamPluginforSAPHANA"};
    p.log_paths = {{"/tmp/veeam_plugin_logs", "Veeam plug-in temporary logs"},
                   {"/var/log/VeeamBackup/Plugin", "Plug-in logs on a Linux backup repository"},
                   {"/var/log/VeeamBackup", "Managed-mode deployment and transport logs"}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("sap-oracle-plugin", "Veeam Plug-In for SAP on Oracle", "Database Plug-In",
                          {HostPlatform::linux}, "x86-64 Linux per SAP/Oracle support matrix",
                          "Veeam Backup & Replication SAP on Oracle Plug-In Logs and Support");
    p.detection_paths = {"/opt/veeam/VeeamPluginforSAPOracle"};
    // The Veeam side is /tmp/veeam_plugin_logs/<user_name>/ - SapOracleBackint.log,
    // SapBackintOracleManager.log and Agent.Source.log.
    //
    // BRTools writes its own Detail/Summary logs under /oracle/<SID>/sapbackup and
    // /oracle/<SID>/saparch. Veeam documents the <SID> form, and SAT cannot know the SID, so the
    // only statable root is /oracle - which also contains the Oracle installation and can contain
    // datafiles. It is therefore marked third_party, which means EVERY collector SKIPS it: this
    // entry documents where the evidence lives for the engineer, it does not gather it. Sweeping
    // /oracle recursively on a production database server would be indefensible.
    p.log_paths = {{"/tmp/veeam_plugin_logs", "SAP Backint Veeam plug-in logs"},
                   {"/var/log/VeeamBackup/Plugin", "Plug-in logs on a Linux backup repository"},
                   {"/var/log/VeeamBackup", "Managed-mode deployment and transport logs"},
                   {"/oracle", "SAP BRTools backup/archive logs (sapbackup, saparch)", true, true}};
    catalog.push_back(std::move(p));
  }
  {
    auto p = make_product("db2-plugin", "Veeam Plug-In for IBM Db2", "Database Plug-In",
                          {HostPlatform::linux}, "x64 Linux for current Linux packages; other Unix targets are outside SAT Linux/macOS/Windows host builds",
                          "Veeam Backup & Replication IBM Db2 Plug-In Guide");
    p.detection_paths = {"/opt/veeam/VeeamPluginforDB2"};
    // db2diag.log is NOT at a fixed path - its directory comes from the instance DIAGPATH
    // ("db2 get dbm cfg | grep -i diagpath"), so it cannot be listed as a literal here. It stays a
    // documented follow-up for the engineer rather than a guessed path.
    p.log_paths = {{"/tmp/veeam_plugin_logs", "Veeam Db2 plug-in temporary logs"},
                   {"/var/log/VeeamBackup/Plugin", "Plug-in logs on a Linux backup repository"},
                   {"/var/log/VeeamBackup", "Managed-mode deployment and transport logs"}};
    catalog.push_back(std::move(p));
  }
  {
    // SAP MaxDB. Standalone mode only - Veeam does not support managed mode for this plug-in, so
    // there is no VBR-side rescan evidence to look for and a missing Rescan folder is not a fault.
    auto p = make_product("sap-maxdb-plugin", "Veeam Plug-In for SAP MaxDB", "Database Plug-In",
                          {HostPlatform::linux}, "x86-64 Linux per SAP MaxDB support matrix",
                          "Veeam Backup & Replication 13.1 SAP MaxDB Plug-In Logs and Support");
    p.detection_paths = {"/opt/veeam/VeeamPluginforSAPMaxDB"};
    // Veeam side: /tmp/veeam_plugin_logs/{root,sdb}/ - SapBackintMaxDBManager.log,
    // SAPMaxDBConfigTool.log, Agent.Source.log, SapMaxDBBackint.log.
    // MaxDB side: the database home folder (for example /sapdb/<SID>/data/wrk/<SID>) holds
    // dbm.ebp/ebl/ebf/mdf/knl/prt/ins, KnlMsg*, knltrace, dbm.cfg, dbm.upc, bsi.env and
    // adapter_config.par. Veeam states that folder is installation- and database-name dependent,
    // so /sapdb is the only root SAT can name without guessing the SID. Same treatment as
    // /oracle above: marked third_party so every collector SKIPS it. Recorded as a pointer for
    // the engineer, never gathered automatically - the same tree holds database data.
    p.log_paths = {{"/tmp/veeam_plugin_logs", "SAP MaxDB Backint Veeam plug-in logs"},
                   {"/var/log/VeeamBackup/Plugin", "Plug-in logs on a Linux backup repository"},
                   {"/sapdb", "SAP MaxDB database logs (dbm.*, KnlMsg, knltrace)", true, true}};
    catalog.push_back(std::move(p));
  }
}

void append_portable_management_agent(std::vector<ProductDefinition>& catalog, HostPlatform platform) {
  auto p = make_product("vspc-agent", "Veeam Service Provider Console Management Agent",
                        "Management Agent", {platform},
                        platform == HostPlatform::macos ? "x64/Apple ARM as supported by managed product" : "native OS architecture per VSPC matrix",
                        "Veeam Service Provider Console 9.3 Management Agent Logs");
  if (platform == HostPlatform::windows) {
    p.detection_paths = {"Veeam/Veeam Availability Console/Log/Agent"};
    p.log_paths = {{"Veeam/Veeam Availability Console/Log/Agent", "VSPC Management Agent logs"}};
  } else {
    p.detection_paths = {"/var/log/veeamma"};
    p.log_paths = {{"/var/log/veeamma", "VSPC Management Agent logs"}};
  }
  catalog.push_back(std::move(p));
}

void append_macos_catalog(std::vector<ProductDefinition>& catalog) {
  {
    auto p = make_product("vam", "Veeam Agent for Mac", "Endpoint Agent", {HostPlatform::macos},
                          "x64 and Apple ARM hardware", "Veeam Agent for Mac 13.1 User Guide");
    p.detection_paths = {"/Library/Application Support/Veeam", "/usr/local/bin/veeamconfig"};
    p.log_paths = {{"/var/log/veeam", "Veeam Agent for Mac logs"},
                   {"/Library/Logs/Veeam", "Veeam Agent application logs"}};
    p.preferred_exporter = "/usr/local/bin/veeamconfig";
    p.preferred_exporter_arguments = {"grablogs"};
    p.exporter_may_include_configuration = true;
    catalog.push_back(std::move(p));
  }
}

} // namespace

std::string to_string(HostPlatform platform) {
  switch (platform) {
  case HostPlatform::windows: return "windows";
  case HostPlatform::linux: return "linux";
  case HostPlatform::macos: return "macos";
  case HostPlatform::unknown: break;
  }
  return "unknown";
}

HostPlatform native_host_platform() {
#ifdef _WIN32
  return HostPlatform::windows;
#elif defined(__APPLE__)
  return HostPlatform::macos;
#elif defined(__linux__)
  return HostPlatform::linux;
#else
  return HostPlatform::unknown;
#endif
}

ProductDiscoveryContext native_product_discovery_context() {
  ProductDiscoveryContext context;
  context.platform = native_host_platform();
#ifdef _WIN32
  context.program_data = env_path("PROGRAMDATA");
  context.program_files = env_path("ProgramFiles");
  context.local_app_data = env_path("LOCALAPPDATA");
  context.home_directory = env_path("USERPROFILE");
  context.installed_product_names = windows_installed_product_names();
#else
  context.filesystem_root = "/";
  context.home_directory = env_path("HOME");
  if (context.home_directory.empty()) {
    if (const passwd* entry = getpwuid(getuid()); entry != nullptr && entry->pw_dir != nullptr)
      context.home_directory = entry->pw_dir;
  }
#endif
  return context;
}

std::vector<ProductDefinition> product_catalog(HostPlatform platform) {
  std::vector<ProductDefinition> catalog;
  if (platform == HostPlatform::windows) {
    append_windows_catalog(catalog);
    append_portable_management_agent(catalog, platform);
  } else if (platform == HostPlatform::linux) {
    append_linux_catalog(catalog);
    append_portable_management_agent(catalog, platform);
  } else if (platform == HostPlatform::macos) {
    append_macos_catalog(catalog);
    append_portable_management_agent(catalog, platform);
  }
  return catalog;
}

std::filesystem::path resolve_catalog_path(const ProductDiscoveryContext& context,
                                           const std::filesystem::path& path) {
  if (context.platform == HostPlatform::windows) {
    // Windows catalog entries are deliberately relative to ProgramData unless
    // an explicitly absolute path is supplied.
    if (path.is_absolute())
      return path;
    if (!context.program_data.empty())
      return context.program_data / path;
    return path;
  }
  // Catalog entries for Linux/macOS are POSIX-rooted (for example /opt/veeam).
  // std::filesystem::path::is_absolute() follows the *native build host* rules,
  // so a POSIX path is not necessarily considered absolute when these injected
  // platform tests run under MSVC.  has_root_directory()/relative_path() keeps
  // the injected-root contract host-independent without changing native-root
  // behavior when filesystem_root is "/".
  if (path.has_root_directory() && !context.filesystem_root.empty() &&
      context.filesystem_root != "/") {
    return context.filesystem_root / path.relative_path();
  }
  return path;
}

std::vector<DetectedProduct> detect_products(const ProductDiscoveryContext& context) {
  std::vector<DetectedProduct> detected;
  for (const auto& definition : product_catalog(context.platform)) {
    if (!supports(definition, context.platform))
      continue;
    DetectedProduct match;
    match.definition = definition;
    for (const auto& candidate : definition.detection_paths) {
      const auto resolved = resolve_catalog_path(context, candidate);
      std::error_code error;
      if (std::filesystem::exists(resolved, error) && !error)
        match.evidence_paths.push_back(resolved);
    }
    if (context.platform == HostPlatform::windows && !context.program_files.empty()) {
      for (const auto& candidate : definition.program_files_detection_paths) {
        const auto resolved = context.program_files / candidate;
        std::error_code error;
        if (std::filesystem::exists(resolved, error) && !error)
          match.evidence_paths.push_back(resolved);
      }
    }
    const bool registered_product = installed_name_matches(definition, context);
    if (!match.evidence_paths.empty() || registered_product)
      detected.push_back(std::move(match));
  }
  return detected;
}

std::string format_detected_products_report(const std::vector<DetectedProduct>& products) {
  std::ostringstream output;
  output << "Detected Veeam products/roles: " << products.size() << "\n";
  for (const auto& product : products) {
    output << "- " << product.definition.display_name << " [" << product.definition.id << "]"
           << " | Role: " << product.definition.role
           << " | Signature: " << (product.signature_detected ? "detected" : "engineer-selected") << "\n";
    output << "  Architecture: " << product.definition.architecture_note << "\n";
    for (const auto& evidence : product.evidence_paths)
      output << "  Evidence: " << path_to_utf8(evidence) << "\n";
    if (!product.definition.preferred_exporter.empty()) {
      output << "  Official exporter: " << product.definition.preferred_exporter;
      if (product.definition.exporter_may_include_configuration)
        output << " (not auto-run by SAT privacy-safe collection)";
      output << "\n";
    }
  }
  if (products.empty())
    output << "No catalog signatures were detected on this machine.\n";
  return output.str();
}

} // namespace support_assist
