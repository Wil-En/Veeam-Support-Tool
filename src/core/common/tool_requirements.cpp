// Tool requirements: what SAT's tools need on this machine, read from the registry, the file system
// and the loader. The Windows rows, the Linux rows and the readings both share are in this file. No
// program is started, the network is not asked and nothing is written.
#include "support_assist/tool_requirements.hpp"

#include "support_assist/host_checks.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/tool_catalog.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <optional>
#include <system_error>
#include <utility>

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include "support_assist/security.hpp"

#include <windows.h>
#include <winver.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <sys/utsname.h>
#include <unistd.h>
#if defined(__GLIBC__)
#include <gnu/libc-version.h>
#endif
#endif

namespace support_assist {

namespace tool_requirements_detail {

std::string dotnet_release_name(std::uint32_t release) {
  return host_checks_detail::dotnet_version(release);
}

std::string execution_policy_default(bool server) {
  return server ? "RemoteSigned" : "Restricted";
}

PolicyReading execution_policy_reading(std::optional<std::uint32_t> group_policy_enable_scripts,
                                       const std::string& group_policy, const std::string& local_policy,
                                       bool server) {
  PolicyReading reading;
  if (group_policy_enable_scripts && *group_policy_enable_scripts == 0U) {
    reading.found = "Script execution is turned off by Group Policy.";
    reading.status = kRequirementAttention;
    return reading;
  }
  std::string value = trim(group_policy);
  std::string source = "Group Policy";
  if (value.empty()) {
    value = trim(local_policy);
    source = "set on this computer";
  }
  if (value.empty()) {
    value = execution_policy_default(server);
    reading.found = "not set (Windows default: " + value + ")";
  } else {
    reading.found = value + " (" + source + ")";
  }
  const std::string lower = ascii_lower(value);
  reading.status = lower == "restricted" || lower == "allsigned" ? kRequirementAttention : kRequirementPresent;
  return reading;
}

std::vector<std::string> odbcinst_sections(std::string_view text) {
  std::vector<std::string> sections;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos)
      end = text.size();
    const std::string line = trim(text.substr(start, end - start));
    start = end + 1U;
    if (line.empty() || line.front() != '[')
      continue;
    const std::size_t close = line.find(']');
    if (close == std::string::npos)
      continue;
    const std::string name = trim(std::string_view(line).substr(1U, close - 1U));
    if (!name.empty())
      sections.push_back(name);
  }
  return sections;
}

const std::vector<std::string>& sql_server_driver_names() {
  static const std::vector<std::string> names = {"ODBC Driver 18 for SQL Server", "ODBC Driver 17 for SQL Server",
                                                  "SQL Server"};
  return names;
}

namespace {

std::string joined(const std::vector<std::string>& values) {
  std::string text;
  for (const std::string& value : values) {
    if (!text.empty())
      text += ", ";
    text += value;
  }
  return text;
}

} // namespace

ToolRequirement sql_server_driver_requirement(const std::vector<std::string>& installed, const std::string& source) {
  ToolRequirement row;
  row.name = "ODBC drivers for SQL Server";
  row.used_by = "SQL Tools, Guided Diagnostics SQL steps";

  const std::vector<std::string>& wanted = sql_server_driver_names();
  std::vector<std::string> usable;
  for (const std::string& name : wanted) {
    const std::string lower = ascii_lower(name);
    if (std::any_of(installed.begin(), installed.end(),
                    [&lower](const std::string& item) { return ascii_lower(item) == lower; }))
      usable.push_back(name);
  }
  const bool modern = std::any_of(usable.begin(), usable.end(), [&wanted](const std::string& name) {
    return name != wanted.back();
  });
  if (modern) {
    row.found = joined(usable);
    row.status = kRequirementPresent;
    return row;
  }
  if (!usable.empty()) {
    row.found = "Only the driver named SQL Server is installed. SAT tries " + wanted[0] + ", then " + wanted[1] +
                ", then that one.";
    row.status = kRequirementAttention;
    return row;
  }
  std::vector<std::string> others;
  for (const std::string& name : installed) {
    if (ascii_lower(name).find("sql server") != std::string::npos)
      others.push_back(name);
  }
  if (!others.empty()) {
    row.found = "Installed: " + joined(others) + ". SAT asks for " + wanted[0] + ", " + wanted[1] + " or " +
                wanted[2] + ".";
    row.status = kRequirementAttention;
    return row;
  }
  row.found = "None listed (" + source + ").";
  row.status = kRequirementMissing;
  return row;
}

} // namespace tool_requirements_detail

#if defined(_WIN32) || defined(__linux__)

namespace {

ToolRequirement make_row(std::string name, std::string found, const char* status, std::string used_by) {
  ToolRequirement row;
  row.name = std::move(name);
  row.found = std::move(found);
  row.status = status;
  row.used_by = std::move(used_by);
  return row;
}

ToolRequirement psql_requirement(const std::filesystem::path& tools_folder) {
  const auto resolved = resolve_external_tool("psql", tools_folder);
  if (resolved.ok())
    return make_row("psql", path_to_utf8(resolved.value()), kRequirementPresent,
                    "SQL Tools with PostgreSQL, the database console");
  return make_row("psql", "Not found. Only SQL Tools with PostgreSQL needs it.", kRequirementNotApplicable,
                  "SQL Tools with PostgreSQL, the database console");
}

} // namespace

#endif

#if defined(_WIN32)

namespace {

constexpr const char* kScmUsedBy = "Service and Process Watch, Host Checks, Guided Diagnostics service steps";
constexpr const char* kWmiUsedBy = "WMI Diagnostics, Process Inventory, Guided Diagnostics WMI step";
constexpr const char* kPowerShellUsedBy = "VBR Diagnostics, the VBR certificate fallback";

std::optional<std::uint32_t> registry_dword(const wchar_t* key, const wchar_t* name) {
  DWORD data = 0;
  DWORD size = sizeof(data);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_DWORD, nullptr, &data, &size) != ERROR_SUCCESS)
    return std::nullopt;
  return static_cast<std::uint32_t>(data);
}

std::string registry_text(const wchar_t* key, const wchar_t* name) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, name, RRF_RT_REG_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return trim(utf8_from_wide(text));
}

struct WindowsVersion {
  bool known = false;
  std::uint32_t major = 0;
  std::uint32_t minor = 0;
  std::uint32_t build = 0;
  bool server = false;
};

WindowsVersion read_windows_version() {
  WindowsVersion version;
  if (const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"); ntdll != nullptr) {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    // GetProcAddress returns FARPROC; the double cast avoids a C4191 function-pointer warning.
    const auto rtl_get_version =
        reinterpret_cast<RtlGetVersionFn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
    if (rtl_get_version != nullptr) {
      RTL_OSVERSIONINFOEXW info{};
      info.dwOSVersionInfoSize = sizeof(info);
      if (rtl_get_version(reinterpret_cast<PRTL_OSVERSIONINFOW>(&info)) == 0) {
        version.known = true;
        version.major = static_cast<std::uint32_t>(info.dwMajorVersion);
        version.minor = static_cast<std::uint32_t>(info.dwMinorVersion);
        version.build = static_cast<std::uint32_t>(info.dwBuildNumber);
        version.server = info.wProductType != VER_NT_WORKSTATION;
        return version;
      }
    }
  }
  const wchar_t* key = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
  const std::string build = registry_text(key, L"CurrentBuild");
  if (!build.empty()) {
    version.known = true;
    version.major = registry_dword(key, L"CurrentMajorVersionNumber").value_or(0U);
    version.minor = registry_dword(key, L"CurrentMinorVersionNumber").value_or(0U);
    version.build = static_cast<std::uint32_t>(std::strtoul(build.c_str(), nullptr, 10));
    version.server = ascii_lower(registry_text(key, L"InstallationType")).find("server") != std::string::npos;
  }
  return version;
}

ToolRequirement windows_build_requirement(const WindowsVersion& version) {
  if (!version.known)
    return make_row("Windows build", "The version could not be read.", kRequirementAttention, "Reference only");
  std::string text = std::to_string(version.major) + "." + std::to_string(version.minor) + " build " +
                     std::to_string(version.build);
  if (const auto revision =
          registry_dword(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"UBR"))
    text += "." + std::to_string(*revision);
  text += version.server ? ", server" : ", client";
  return make_row("Windows build", text, kRequirementPresent, "Reference only");
}

ToolRequirement dotnet_requirement() {
  const char* used_by = "Host Checks' .NET and TLS group, Veeam Backup & Replication's system requirements";
  const auto release =
      registry_dword(L"SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", L"Release");
  if (!release)
    return make_row(".NET Framework", ".NET Framework 4.5 or later is not installed.", kRequirementMissing, used_by);
  const std::string version = tool_requirements_detail::dotnet_release_name(*release);
  std::string found = version.empty() ? "release " + std::to_string(*release)
                                      : version + " (release " + std::to_string(*release) + ")";
  const char* status = kRequirementPresent;
  if (host_checks_detail::dotnet_below_minimum(*release)) {
    found += ". Veeam Backup & Replication needs " + host_checks_detail::dotnet_minimum_version() + " or later.";
    status = kRequirementAttention;
  }
  return make_row(".NET Framework", found, status, used_by);
}

std::filesystem::path program_files_powershell7() {
  wchar_t program_files[MAX_PATH]{};
  const DWORD length = GetEnvironmentVariableW(L"ProgramFiles", program_files, static_cast<DWORD>(MAX_PATH));
  if (length == 0 || length >= MAX_PATH)
    return {};
  return std::filesystem::path(program_files) / L"PowerShell" / L"7" / L"pwsh.exe";
}

bool is_file(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::is_regular_file(path, error);
}

// The file version as major.minor.build, or empty when the file carries none.
std::string file_version(const std::filesystem::path& file) {
  const std::wstring native = file.wstring();
  DWORD ignored = 0;
  const DWORD size = GetFileVersionInfoSizeW(native.c_str(), &ignored);
  if (size == 0)
    return {};
  std::vector<unsigned char> data(size);
  if (GetFileVersionInfoW(native.c_str(), 0, size, data.data()) == FALSE)
    return {};
  VS_FIXEDFILEINFO* info = nullptr;
  UINT info_size = 0;
  if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &info_size) == FALSE || info == nullptr ||
      info_size < sizeof(VS_FIXEDFILEINFO))
    return {};
  return std::to_string(HIWORD(info->dwFileVersionMS)) + "." + std::to_string(LOWORD(info->dwFileVersionMS)) + "." +
         std::to_string(HIWORD(info->dwFileVersionLS));
}

ToolRequirement windows_powershell_requirement() {
  const std::string used_by = std::string("Log Collection, ") + kPowerShellUsedBy;
  const std::string version =
      registry_text(L"SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine", L"PowerShellVersion");
  if (!version.empty())
    return make_row("Windows PowerShell", version, kRequirementPresent, used_by);
  wchar_t system_directory[MAX_PATH]{};
  const UINT length = GetSystemDirectoryW(system_directory, MAX_PATH);
  if (length > 0 && length < MAX_PATH &&
      is_file(std::filesystem::path(system_directory) / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe"))
    return make_row("Windows PowerShell", "powershell.exe is installed; its version is not in the registry.",
                    kRequirementPresent, used_by);
  return make_row("Windows PowerShell", "Windows PowerShell was not found.", kRequirementMissing, used_by);
}

ToolRequirement powershell7_requirement() {
  const std::filesystem::path installed = program_files_powershell7();
  if (!installed.empty() && is_file(installed)) {
    const std::string version = file_version(installed);
    return make_row("PowerShell 7", (version.empty() ? std::string() : version + " at ") + path_to_utf8(installed),
                    kRequirementPresent, kPowerShellUsedBy);
  }
  // SAT starts PowerShell 7 from its install folder only; one found on the PATH is reported but not used.
  std::wstring search_path;
  {
    wchar_t* value = nullptr;
    std::size_t length = 0;
    if (_wdupenv_s(&value, &length, L"PATH") == 0 && value != nullptr) {
      search_path = value;
      std::free(value);
    }
  }
  std::size_t start = 0;
  while (start < search_path.size()) {
    std::size_t end = search_path.find(L';', start);
    if (end == std::wstring::npos)
      end = search_path.size();
    const std::wstring directory = search_path.substr(start, end - start);
    start = end + 1U;
    if (directory.empty())
      continue;
    const std::filesystem::path candidate = std::filesystem::path(directory) / L"pwsh.exe";
    if (is_file(candidate))
      return make_row("PowerShell 7",
                      "pwsh.exe is on the PATH at " + path_to_utf8(candidate) + ", but SAT looks in " +
                          (installed.empty() ? std::string("the PowerShell\\7 folder under Program Files")
                                             : path_to_utf8(installed.parent_path())) +
                          ".",
                      kRequirementAttention, kPowerShellUsedBy);
  }
  return make_row("PowerShell 7", "Not installed. Windows PowerShell is used instead.", kRequirementNotApplicable,
                  kPowerShellUsedBy);
}

ToolRequirement execution_policy_requirement(bool server) {
  const auto enable_scripts =
      registry_dword(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", L"EnableScripts");
  const std::string group_policy =
      registry_text(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell", L"ExecutionPolicy");
  const std::string local_policy = registry_text(
      L"SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell", L"ExecutionPolicy");
  const auto reading =
      tool_requirements_detail::execution_policy_reading(enable_scripts, group_policy, local_policy, server);
  return make_row("PowerShell execution policy", reading.found, reading.status.c_str(), kPowerShellUsedBy);
}

const char* start_type_text(DWORD start_type) {
  switch (start_type) {
  case SERVICE_AUTO_START: return "automatic";
  case SERVICE_DEMAND_START: return "manual";
  case SERVICE_DISABLED: return "disabled";
  case SERVICE_BOOT_START: return "boot";
  case SERVICE_SYSTEM_START: return "system";
  default: return "unknown start type";
  }
}

// The Service Control Manager row, then the Winmgmt row read through the same connection. WMI itself
// is not queried: connecting starts COM security for the process and can wait on a stalled provider.
void add_service_rows(std::vector<ToolRequirement>& rows) {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr) {
    const DWORD error = GetLastError();
    rows.push_back(make_row("Service Control Manager", "Could not connect (Windows error " + std::to_string(error) + ").",
                            kRequirementAttention, kScmUsedBy));
    rows.push_back(make_row("WMI service", "Not read, because the Service Control Manager could not be reached.",
                            kRequirementAttention, kWmiUsedBy));
    return;
  }
  rows.push_back(make_row("Service Control Manager", "Reachable.", kRequirementPresent, kScmUsedBy));

  SC_HANDLE service = OpenServiceW(manager, L"Winmgmt", SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  if (service == nullptr) {
    const DWORD error = GetLastError();
    if (error == ERROR_SERVICE_DOES_NOT_EXIST)
      rows.push_back(make_row("WMI service", "The Winmgmt service is not installed.", kRequirementMissing, kWmiUsedBy));
    else
      rows.push_back(make_row("WMI service", "The Winmgmt service could not be read (Windows error " +
                                                 std::to_string(error) + ").",
                              kRequirementAttention, kWmiUsedBy));
    CloseServiceHandle(manager);
    return;
  }
  SERVICE_STATUS status{};
  const bool have_status = QueryServiceStatus(service, &status) != FALSE;
  std::string start_type = "start type not read";
  DWORD needed = 0;
  QueryServiceConfigW(service, nullptr, 0, &needed);
  if (needed != 0U) {
    std::vector<unsigned char> buffer(needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (QueryServiceConfigW(service, config, needed, &needed) != FALSE)
      start_type = start_type_text(config->dwStartType);
  }
  CloseServiceHandle(service);
  CloseServiceHandle(manager);
  if (have_status && status.dwCurrentState == SERVICE_RUNNING)
    rows.push_back(make_row("WMI service", "The Winmgmt service is running (" + start_type + ").",
                            kRequirementPresent, kWmiUsedBy));
  else
    rows.push_back(make_row("WMI service",
                            std::string("The Winmgmt service is ") + (have_status ? "not running" : "in an unknown state") +
                                " (" + start_type + ").",
                            kRequirementAttention, kWmiUsedBy));
}

ToolRequirement administrator_requirement() {
  const char* used_by = "VSS Tools, packet capture, the change journal, Host Checks' shadow storage";
  const auto context = current_security_context();
  if (!context.ok())
    return make_row("Running as administrator", "The account's rights could not be read.", kRequirementAttention,
                    used_by);
  if (context.value().elevated)
    return make_row("Running as administrator", "Yes.", kRequirementPresent, used_by);
  return make_row("Running as administrator", "No, SAT is running without administrator rights.",
                  kRequirementAttention, used_by);
}

std::vector<std::string> odbc_driver_names() {
  std::vector<std::string> names;
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\ODBC\\ODBCINST.INI\\ODBC Drivers", 0, KEY_READ, &key) !=
      ERROR_SUCCESS)
    return names;
  for (DWORD index = 0;; ++index) {
    wchar_t name[512]{};
    DWORD length = static_cast<DWORD>(std::size(name));
    const LONG result = RegEnumValueW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
    if (result == ERROR_NO_MORE_ITEMS)
      break;
    if (result == ERROR_SUCCESS)
      names.push_back(utf8_from_wide(std::wstring_view(name, length)));
  }
  RegCloseKey(key);
  return names;
}

} // namespace

std::vector<ToolRequirement> read_tool_requirements(const std::filesystem::path& tools_folder) {
  std::vector<ToolRequirement> rows;
  const WindowsVersion version = read_windows_version();
  rows.push_back(windows_build_requirement(version));
  rows.push_back(dotnet_requirement());
  rows.push_back(windows_powershell_requirement());
  rows.push_back(powershell7_requirement());
  rows.push_back(execution_policy_requirement(version.server));
  add_service_rows(rows);
  rows.push_back(administrator_requirement());
  rows.push_back(tool_requirements_detail::sql_server_driver_requirement(
      odbc_driver_names(), "HKLM\\SOFTWARE\\ODBC\\ODBCINST.INI\\ODBC Drivers"));
  rows.push_back(psql_requirement(tools_folder));
  return rows;
}

#elif defined(__linux__)

namespace {

ToolRequirement glibc_requirement() {
#if defined(__GLIBC__)
  return make_row("glibc", std::string("glibc ") + gnu_get_libc_version(), kRequirementPresent, "SAT itself");
#else
  return make_row("glibc", "This system does not use glibc.", kRequirementNotApplicable, "SAT itself");
#endif
}

ToolRequirement kernel_requirement() {
  utsname name{};
  const char* used_by = "Host Checks' snapshot module group";
  if (uname(&name) != 0)
    return make_row("Linux kernel", "The kernel release could not be read.", kRequirementAttention, used_by);
  return make_row("Linux kernel", std::string(name.release) + " (" + name.machine + ")", kRequirementPresent,
                  used_by);
}

// The driver manager is loaded and released again; SAT loads it the same way when SQL Tools runs.
ToolRequirement unixodbc_requirement() {
  const char* used_by = "SQL Tools, Guided Diagnostics SQL steps";
  for (const char* candidate : {"libodbc.so.2", "libodbc.so"}) {
    dlerror();
    if (void* library = dlopen(candidate, RTLD_LAZY | RTLD_LOCAL)) {
      dlclose(library);
      return make_row("unixODBC", std::string(candidate) + " loads.", kRequirementPresent, used_by);
    }
  }
  return make_row("unixODBC", "The driver manager (libodbc.so.2) could not be loaded.", kRequirementMissing, used_by);
}

// unixODBC reads odbcinst.ini from ODBCSYSINI when that is set and from /etc otherwise.
ToolRequirement odbc_driver_requirement() {
  const char* directory = std::getenv("ODBCSYSINI");
  const std::filesystem::path file = directory != nullptr && *directory != '\0'
                                         ? std::filesystem::path(directory) / "odbcinst.ini"
                                         : std::filesystem::path("/etc/odbcinst.ini");
  std::ifstream stream(file, std::ios::binary);
  if (!stream)
    return tool_requirements_detail::sql_server_driver_requirement({}, path_to_utf8(file) + " could not be read");
  std::string text(1U << 20, '\0');
  stream.read(text.data(), static_cast<std::streamsize>(text.size()));
  text.resize(static_cast<std::size_t>(stream.gcount()));
  return tool_requirements_detail::sql_server_driver_requirement(tool_requirements_detail::odbcinst_sections(text),
                                                                 path_to_utf8(file));
}

ToolRequirement root_requirement() {
  const char* used_by = "Packet capture with tcpdump, Host Checks' kernel log, Veeam's official log exporters";
  if (geteuid() == 0)
    return make_row("Running as root", "Yes.", kRequirementPresent, used_by);
  return make_row("Running as root", "No, SAT is running as a regular user.", kRequirementAttention, used_by);
}

} // namespace

std::vector<ToolRequirement> read_tool_requirements(const std::filesystem::path& tools_folder) {
  std::vector<ToolRequirement> rows;
  rows.push_back(glibc_requirement());
  rows.push_back(kernel_requirement());
  rows.push_back(unixodbc_requirement());
  rows.push_back(odbc_driver_requirement());
  rows.push_back(psql_requirement(tools_folder));
  rows.push_back(root_requirement());
  return rows;
}

#else

std::vector<ToolRequirement> read_tool_requirements(const std::filesystem::path&) {
  return {};
}

#endif

} // namespace support_assist
