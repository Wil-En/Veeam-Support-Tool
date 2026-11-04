#include "support_assist/log_collection.hpp"

#include "support_assist/case_workspace.hpp"
#include "support_assist/process.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/debug_log.hpp"
#include "support_assist/time.hpp"
#include "support_assist/version.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#endif

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

namespace support_assist {
namespace {
// A path as the engineer reads it: without the \\?\ prefix SAT adds for long paths.
std::string shown_path(const std::filesystem::path& path) {
  std::string text = support_assist::path_to_utf8(path);
  if (text.rfind("\\\\?\\UNC\\", 0) == 0)
    return "\\\\" + text.substr(8);
  if (text.rfind("\\\\?\\", 0) == 0)
    return text.substr(4);
  return text;
}


Error collection_error(std::string operation,
                       const std::filesystem::path& source,
                       std::string message,
                       std::int64_t native_code = 0) {
  Error error;
  error.component = "LogCollection";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.native_code = native_code;
  return error;
}

std::filesystem::path environment_path(const wchar_t* windows_name,
                                       const char* portable_name,
                                       const std::filesystem::path& fallback) {
#ifdef _WIN32
  static_cast<void>(portable_name);
  wchar_t* value = nullptr;
  std::size_t length = 0;
  if (_wdupenv_s(&value, &length, windows_name) == 0 && value != nullptr) {
    const std::filesystem::path path(value);
    std::free(value);
    return path;
  }
#else
  static_cast<void>(windows_name);
  const char* value = std::getenv(portable_name);
  if (value != nullptr && *value != '\0')
    return std::filesystem::path(value);
#endif
  return fallback;
}

std::filesystem::path program_data_path() {
  return environment_path(L"PROGRAMDATA", "PROGRAMDATA", std::filesystem::path("/var/log"));
}

std::filesystem::path local_app_data_path() {
  return environment_path(L"LOCALAPPDATA", "LOCALAPPDATA", {});
}

std::string collector_machine_name() {
#ifdef _WIN32
  // MSVC deprecates getenv under the project's /WX policy. Use the wide,
  // bounds-aware CRT environment API and convert the value to UTF-8.
  wchar_t* value = nullptr;
  std::size_t length = 0;
  const int result = _wdupenv_s(&value, &length, L"COMPUTERNAME");
  std::string name;
  if (result == 0 && value != nullptr && *value != L'\0')
    name = utf8_from_wide(value);
  std::free(value);
  return name.empty() ? std::string("unknown") : name;
#else
  const char* value = std::getenv("HOSTNAME");
  return value != nullptr && *value != '\0' ? std::string(value) : std::string("unknown");
#endif
}

std::string timestamp_token() {
  std::string token = utc_now_iso8601();
  std::replace(token.begin(), token.end(), ':', '-');
  std::replace(token.begin(), token.end(), 'T', '_');
  if (!token.empty() && token.back() == 'Z')
    token.pop_back();
  return token;
}

std::int64_t file_time_to_unix_ms(const std::filesystem::file_time_type& value) {
  const auto system_value = std::chrono::time_point_cast<std::chrono::milliseconds>(
      value - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
  return system_value.time_since_epoch().count();
}

bool in_time_window(const std::filesystem::path& path, const LogCollectionOptions& options) {
  std::error_code error_code;
  const auto write_time = std::filesystem::last_write_time(path, error_code);
  if (error_code)
    return true;
  const std::int64_t millis = file_time_to_unix_ms(write_time);
  if (options.from_utc_ms && millis < *options.from_utc_ms)
    return false;
  if (options.to_utc_ms && millis > *options.to_utc_ms)
    return false;
  return true;
}

std::string safe_source_name(const std::filesystem::path& source, std::size_t index) {
  std::string name = support_assist::path_to_utf8(source.filename());
  if (name.empty())
    name = "root";
  name = sanitize_case_identifier(name);
  if (name.empty())
    name = "source";
  return std::to_string(index + 1U) + "-" + name;
}

std::filesystem::path additional_archive_path(const std::filesystem::path& source) {
  std::filesystem::path relative;
#ifdef _WIN32
  std::string root = path_to_utf8(source.root_name());
  for (char& ch : root) {
    if (ch == ':' || ch == '\\' || ch == '/') ch = '_';
  }
  root = sanitize_case_identifier(root);
  if (root.empty()) root = "root";
  relative = std::filesystem::path(root) / source.relative_path();
#else
  relative = std::filesystem::path("root") / source.relative_path();
#endif
  return std::filesystem::path("Additional") / "Local" / relative;
}

void report(const ProgressCallback& progress,
            std::string phase,
            const std::filesystem::path& path,
            std::uint64_t processed,
            std::uint64_t errors) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = std::move(phase);
  event.current_scope = support_assist::path_to_utf8(path);
  event.processed = processed;
  event.errors = errors;
  progress(event);
}


bool path_is_within_sat_root(const std::filesystem::path& child,
                             const std::filesystem::path& parent) {
  std::error_code child_error;
  std::error_code parent_error;
  const auto child_path = std::filesystem::weakly_canonical(child, child_error);
  const auto parent_path = std::filesystem::weakly_canonical(parent, parent_error);
  const auto normalized_child = child_error ? child.lexically_normal() : child_path;
  const auto normalized_parent = parent_error ? parent.lexically_normal() : parent_path;
  auto child_it = normalized_child.begin();
  auto parent_it = normalized_parent.begin();
  for (; parent_it != normalized_parent.end(); ++parent_it, ++child_it) {
    if (child_it == normalized_child.end())
      return false;
#ifdef _WIN32
    if (ascii_lower(utf8_from_wide(child_it->wstring())) !=
        ascii_lower(utf8_from_wide(parent_it->wstring())))
      return false;
#else
    if (*child_it != *parent_it)
      return false;
#endif
  }
  return true;
}


struct SupplementalEvidenceEntry {
  std::string category;
  std::string name;
  std::string status;
  std::string relative_path;
};

// A folder an older SAT wrote beside the logs it reviewed: its reports and parser caches. It is
// SAT's output, not evidence, and is left out of a collection whole.
bool is_sat_output_directory(const std::filesystem::directory_entry& entry) {
  std::error_code error;
  if (!entry.is_directory(error))
    return false;
  const std::string name = ascii_lower(path_to_utf8(entry.path().filename()));
  return name == "supportassistreports" || name == ".support-assist-parser-cache" ||
         name == ".support-assist-log-cache";
}

#ifdef _WIN32
std::optional<std::filesystem::path> registry_string_value(HKEY root,
                                                           const wchar_t* subkey,
                                                           const wchar_t* value_name) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
    return std::nullopt;
  struct KeyCloser {
    HKEY value = nullptr;
    ~KeyCloser() {
      if (value != nullptr)
        RegCloseKey(value);
    }
  } closer{key};

  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, value_name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || bytes < sizeof(wchar_t))
    return std::nullopt;
  std::vector<wchar_t> buffer(bytes / sizeof(wchar_t) + 2U, L'\0');
  if (RegQueryValueExW(key,
                       value_name,
                       nullptr,
                       &type,
                       reinterpret_cast<LPBYTE>(buffer.data()),
                       &bytes) != ERROR_SUCCESS)
    return std::nullopt;
  std::wstring value(buffer.data());
  if (type == REG_EXPAND_SZ) {
    const DWORD required = ExpandEnvironmentStringsW(value.c_str(), nullptr, 0);
    if (required > 1U) {
      std::vector<wchar_t> expanded(required, L'\0');
      if (ExpandEnvironmentStringsW(value.c_str(), expanded.data(), required) != 0U)
        value.assign(expanded.data());
    }
  }
  if (value.empty())
    return std::nullopt;
  return std::filesystem::path(value);
}

std::string normalized_windows_path(const std::filesystem::path& path) {
  std::error_code error;
  const auto canonical = std::filesystem::weakly_canonical(path, error);
  std::string value = utf8_from_wide((error ? path.lexically_normal() : canonical).wstring());
  value = ascii_lower(value);
  std::replace(value.begin(), value.end(), '\\', '/');
  while (value.size() > 3U && value.back() == '/')
    value.pop_back();
  return value;
}

bool path_is_within(const std::filesystem::path& child, const std::filesystem::path& parent) {
  const std::string child_text = normalized_windows_path(child);
  const std::string parent_text = normalized_windows_path(parent);
  if (child_text.empty() || parent_text.empty())
    return false;
  if (child_text == parent_text)
    return true;
  return child_text.size() > parent_text.size() && child_text.starts_with(parent_text) &&
         child_text[parent_text.size()] == '/';
}

bool covered_by_primary_source(const std::filesystem::path& path,
                               const std::vector<std::filesystem::path>& sources) {
  return std::any_of(sources.begin(), sources.end(), [&](const auto& source) {
    std::error_code error;
    return std::filesystem::is_directory(source, error) && !error && path_is_within(path, source);
  });
}

bool record_generated_file(const std::filesystem::path& path,
                           const LogCollectionOptions& options,
                           LogCollectionResult& result,
                           std::vector<SupplementalEvidenceEntry>& entries,
                           std::string category,
                           std::string name,
                           std::string status) {
  std::error_code error;
  if (!std::filesystem::is_regular_file(path, error) || error)
    return false;
  const std::uint64_t size = std::filesystem::file_size(path, error);
  if (error)
    return false;
  if (result.copied_files >= options.maximum_files || result.copied_bytes > options.maximum_bytes ||
      size > options.maximum_bytes - result.copied_bytes) {
    result.warnings.push_back("Windows support evidence limit reached before " + support_assist::path_to_utf8(path));
    std::filesystem::remove(path, error);
    ++result.skipped_files;
    return false;
  }
  ++result.copied_files;
  ++result.windows_support_files;
  result.copied_bytes += size;
  std::error_code relative_error;
  const auto relative = std::filesystem::relative(path, result.collection_directory, relative_error);
  entries.push_back({std::move(category),
                     std::move(name),
                     std::move(status),
                     relative_error ? support_assist::generic_path_to_utf8(path.filename()) : support_assist::generic_path_to_utf8(relative)});
  return true;
}

bool write_command_output(const std::filesystem::path& destination,
                          const ProcessResult& process,
                          const LogCollectionOptions& options,
                          LogCollectionResult& result,
                          std::vector<SupplementalEvidenceEntry>& entries,
                          std::string category,
                          std::string name) {
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  if (error)
    return false;
  std::ofstream output(destination, std::ios::binary | std::ios::trunc);
  if (!output)
    return false;
  output << "Command: " << process.command_display << "\r\n"
         << "ExitCode: " << process.exit_code << "\r\n"
         << "TimedOut: " << (process.timed_out ? "true" : "false") << "\r\n"
         << "Cancelled: " << (process.cancelled ? "true" : "false") << "\r\n\r\n";
  // A command that ran cleanly and returned nothing is a RESULT - "no Veeam certificates in these
  // stores" - and must not be indistinguishable from a section that failed to collect. Saying so
  // is the same principle applied to skipped sections in environment.log.
  if (trim(process.output).empty() && process.standard_error.empty()) {
    output << "(no output: the command completed and returned no rows)\r\n";
  } else {
    output << process.output;
  }
  if (!process.standard_error.empty()) {
    output << "\r\n\r\n[stderr]\r\n" << process.standard_error;
  }
  output.flush();
  if (!output)
    return false;
  return record_generated_file(destination,
                               options,
                               result,
                               entries,
                               std::move(category),
                               std::move(name),
                               process.exit_code == 0 ? "collected" : "command-exit-" + std::to_string(process.exit_code));
}

void run_text_command(const std::filesystem::path& destination,
                      std::filesystem::path executable,
                      std::vector<std::string> arguments,
                      std::chrono::milliseconds timeout,
                      const LogCollectionOptions& options,
                      LogCollectionResult& result,
                      std::vector<SupplementalEvidenceEntry>& entries,
                      const CancellationToken& cancel,
                      const ProgressCallback& progress,
                      std::string category,
                      std::string name) {
  if (cancel.is_cancelled())
    return;
  ProcessOptions process_options;
  process_options.executable = std::move(executable);
  process_options.arguments = std::move(arguments);
  process_options.timeout = timeout;
  process_options.merge_standard_error = false;
  process_options.maximum_output_bytes = 16U * 1024U * 1024U;
  process_options.maximum_standard_error_bytes = 2U * 1024U * 1024U;
  auto process = run_process_capture(process_options, cancel, progress);
  if (!process.ok()) {
    if (!cancel.is_cancelled()) {
      ++result.error_count;
      result.warnings.push_back("Windows support command failed (" + name + "): " +
                                describe_error(process.error()));
    }
    return;
  }
  if (!write_command_output(destination,
                            process.value(),
                            options,
                            result,
                            entries,
                            std::move(category),
                            name)) {
    ++result.error_count;
    result.warnings.push_back("Could not write Windows support command output: " + name);
  } else if (process.value().exit_code != 0 && !process.value().cancelled) {
    result.warnings.push_back("Windows support command returned exit code " +
                              std::to_string(process.value().exit_code) + ": " + name);
  }
}

void run_powershell_text(const std::filesystem::path& destination,
                         std::string command,
                         std::chrono::milliseconds timeout,
                         const LogCollectionOptions& options,
                         LogCollectionResult& result,
                         std::vector<SupplementalEvidenceEntry>& entries,
                         const CancellationToken& cancel,
                         const ProgressCallback& progress,
                         std::string category,
                         std::string name) {
  run_text_command(destination,
                   L"powershell.exe",
                   {"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", std::move(command)},
                   timeout,
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   std::move(category),
                   std::move(name));
}

void copy_supplemental_file(const std::filesystem::path& source,
                            const std::filesystem::path& destination,
                            const std::vector<std::filesystem::path>& primary_sources,
                            const LogCollectionOptions& options,
                            LogCollectionResult& result,
                            std::vector<SupplementalEvidenceEntry>& entries,
                            std::string category,
                            std::string name) {
  std::error_code error;
  if (covered_by_primary_source(source, primary_sources) ||
      !std::filesystem::is_regular_file(source, error) || error)
    return;
  const std::uint64_t size = std::filesystem::file_size(source, error);
  if (error || result.copied_files >= options.maximum_files ||
      result.copied_bytes > options.maximum_bytes || size > options.maximum_bytes - result.copied_bytes)
    return;
  std::filesystem::create_directories(destination.parent_path(), error);
  if (error)
    return;
  std::filesystem::copy_file(source, destination, std::filesystem::copy_options::overwrite_existing, error);
  if (error) {
    ++result.error_count;
    result.warnings.push_back("Could not copy supplemental Veeam evidence " + path_to_utf8(source) + ": " + error.message());
    return;
  }
  static_cast<void>(record_generated_file(destination,
                                          options,
                                          result,
                                          entries,
                                          std::move(category),
                                          std::move(name),
                                          "copied"));
}

void copy_supplemental_tree(const std::filesystem::path& source,
                            const std::filesystem::path& destination,
                            const std::vector<std::filesystem::path>& primary_sources,
                            const LogCollectionOptions& options,
                            LogCollectionResult& result,
                            std::vector<SupplementalEvidenceEntry>& entries,
                            const CancellationToken& cancel,
                            std::string category,
                            std::string name_prefix) {
  std::error_code error;
  if (covered_by_primary_source(source, primary_sources) ||
      !std::filesystem::is_directory(source, error) || error)
    return;
  std::filesystem::recursive_directory_iterator iterator(
      source, std::filesystem::directory_options::skip_permission_denied, error);
  const std::filesystem::recursive_directory_iterator end;
  for (; !error && iterator != end && !cancel.is_cancelled(); iterator.increment(error)) {
    if (is_sat_output_directory(*iterator)) {
      iterator.disable_recursion_pending();
      continue;
    }
    if (!iterator->is_regular_file(error) || error) {
      error.clear();
      continue;
    }
    const auto relative = std::filesystem::relative(iterator->path(), source, error);
    if (error || relative.empty() || support_assist::generic_path_to_utf8(relative).starts_with("..")) {
      error.clear();
      continue;
    }
    copy_supplemental_file(iterator->path(),
                           destination / relative,
                           {},
                           options,
                           result,
                           entries,
                           category,
                           name_prefix + ": " + support_assist::generic_path_to_utf8(relative));
  }
}

bool backup_root_support_file(std::string_view filename) {
  const std::string folded = ascii_lower(filename);
  const bool log_or_zip = folded.ends_with(".log") || folded.ends_with(".zip");
  return (folded.find("vsshwsnapshotproviderservice") != std::string::npos && log_or_zip) ||
         (folded.find("veeaminstaller") != std::string::npos && folded.ends_with(".log")) ||
         folded == "driver.veeamflr.log" || folded == "cli.veeamtransport.log" ||
         folded == "svc.veeamtransport.log" || folded == "vssproxy.log" ||
         folded.ends_with(".target.log");
}

std::string windows_event_query(const LogCollectionOptions& options) {
  if (!options.from_utc_ms && !options.to_utc_ms)
    return "*";
  const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  if (options.from_utc_ms) {
    const auto age_ms = (std::max<std::int64_t>)(0, now_ms - *options.from_utc_ms);
    return "*[System[TimeCreated[timediff(@SystemTime) <= " + std::to_string(age_ms) + "]]]";
  }
  return "*";
}

void export_event_log(const std::string& channel,
                      const std::filesystem::path& destination,
                      std::string_view query,
                      const LogCollectionOptions& options,
                      LogCollectionResult& result,
                      std::vector<SupplementalEvidenceEntry>& entries,
                      const CancellationToken& cancel,
                      const ProgressCallback& progress) {
  if (cancel.is_cancelled())
    return;
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  if (error) {
    result.warnings.push_back("Could not create Event Log destination for " + channel + ": " + error.message());
    ++result.error_count;
    return;
  }
  const std::wstring channel_w = wide_from_utf8(channel);
  const std::wstring query_w = wide_from_utf8(query);
  const std::wstring destination_w = destination.wstring();
  SetLastError(ERROR_SUCCESS);
  const BOOL exported = EvtExportLog(nullptr, channel_w.c_str(),
                                     query_w.empty() ? L"*" : query_w.c_str(),
                                     destination_w.c_str(), EvtExportLogChannelPath);
  if (exported == FALSE) {
    const DWORD code = GetLastError();
    if (!cancel.is_cancelled()) {
      std::string detail = "Could not export Windows Event Log channel " + channel +
                           " (Win32 " + std::to_string(code) + ")";
      if (code == ERROR_ACCESS_DENIED)
        detail += "; elevation may be required for this channel";
      else if (code == ERROR_EVT_CHANNEL_NOT_FOUND || code == ERROR_FILE_NOT_FOUND)
        detail += "; channel is not present on this host";
      result.warnings.push_back(std::move(detail));
    }
    std::filesystem::remove(destination, error);
    return;
  }
  static_cast<void>(EvtArchiveExportedLog(nullptr, destination_w.c_str(), 0, 0));
  if (record_generated_file(destination, options, result, entries,
                            "EventLog", channel, "exported")) {
    report(progress, "Exporting Windows Event Log", destination,
           result.copied_files, result.error_count);
  }
}

void collect_windows_support_context(const LogCollectionOptions& options,
                                     const std::vector<std::filesystem::path>& primary_sources,
                                     LogCollectionResult& result,
                                     const CancellationToken& cancel,
                                     const ProgressCallback& progress) {
  if (!options.include_windows_support_context || cancel.is_cancelled())
    return;

  result.windows_support_directory = result.collection_directory / "WindowsSupport";
  std::error_code error;
  std::filesystem::create_directories(result.windows_support_directory, error);
  if (error) {
    result.windows_support_directory.clear();
    result.warnings.push_back("Could not create WindowsSupport evidence directory: " + error.message());
    ++result.error_count;
    return;
  }

  std::vector<SupplementalEvidenceEntry> entries;
  const auto sys = result.windows_support_directory / "SystemInfo";
  const auto vss = result.windows_support_directory / "VSS";
  const auto reg = result.windows_support_directory / "Registry";
  const auto events = result.windows_support_directory / "Events";
  const auto veeam = result.windows_support_directory / "Veeam";

  report(progress, "Windows support context", result.windows_support_directory, result.copied_files, result.error_count);

  // VSS state. Writers are independently bounded so a damaged VSS subsystem cannot hang collection.
  run_text_command(vss / "vss_providers.log", L"vssadmin.exe", {"list", "providers"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "VSS", "VSS providers");
  run_text_command(vss / "vss_shadows.log", L"vssadmin.exe", {"list", "shadows"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "VSS", "VSS shadows");
  run_text_command(vss / "vss_shadow_storage.log", L"vssadmin.exe", {"list", "shadowstorage"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "VSS", "VSS shadow storage");
  run_text_command(vss / "vss_writers.log", L"vssadmin.exe", {"list", "writers"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "VSS", "VSS writers");

  // OS, boot, disk, identity, update and driver context.
  run_text_command(sys / "systeminfo.log", L"systeminfo.exe", {}, std::chrono::seconds(60), options, result, entries, cancel, progress, "System", "systeminfo");
  run_text_command(sys / "bcdedit.log", L"bcdedit.exe", {"/v", "/enum"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "System", "BCD configuration");
  run_text_command(sys / "mountvol.log", L"mountvol.exe", {"/l"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "Storage", "mountvol");
  run_text_command(sys / "whoami.log", L"whoami.exe", {"/all"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "System", "whoami");
  run_text_command(sys / "dism_packages.log", L"dism.exe", {"/online", "/Get-Packages", "/Format:Table"}, std::chrono::minutes(2), options, result, entries, cancel, progress, "System", "DISM packages");
  run_text_command(sys / "fsutil_sectorinfo.log", L"fsutil.exe", {"fsinfo", "sectorinfo", "C:"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "Storage", "fsutil sectorinfo C:");
  run_text_command(sys / "minifilters.log", L"fltmc.exe", {"instances"}, std::chrono::seconds(30), options, result, entries, cancel, progress, "System", "Filesystem minifilters");
  run_powershell_text(sys / "computer_info.log",
                      "Get-ComputerInfo | Format-List *",
                      std::chrono::seconds(60),
                      options,
                      result,
                      entries,
                      cancel,
                      progress,
                      "System",
                      "Get-ComputerInfo");
  run_powershell_text(
      sys / "computer_system_product.log",
      "Get-CimInstance -ClassName Win32_ComputerSystemProduct | "
      "Select-Object Name,IdentifyingNumber,Vendor,UUID | Format-List",
      std::chrono::seconds(30),
      options,
      result,
      entries,
      cancel,
      progress,
      "Hardware",
      "ComputerSystemProduct");
  run_powershell_text(
      sys / "drivers.log",
      "Get-CimInstance -ClassName Win32_PnPSignedDriver | "
      "Select-Object DeviceName,DriverName,InfName,DriverVersion | Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(60),
      options,
      result,
      entries,
      cancel,
      progress,
      "Hardware",
      "Signed drivers");
  run_powershell_text(sys / "uptime.log",
                      "Get-CimInstance -ClassName Win32_OperatingSystem | "
                      "Select-Object LastBootUpTime | Format-List",
                      std::chrono::seconds(30),
                      options,
                      result,
                      entries,
                      cancel,
                      progress,
                      "System",
                      "Last boot time");
  run_powershell_text(
      sys / "windows_updates.log",
      "Get-CimInstance -ClassName Win32_QuickFixEngineering | "
      "Select-Object Caption,CSName,Description,HotFixID,InstallDate,InstalledOn | "
      "Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(30),
      options,
      result,
      entries,
      cancel,
      progress,
      "System",
      "Windows updates");
  run_powershell_text(
      sys / "installed_software.log",
      "$x=@();"
      "$x+=Get-ItemProperty 'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
      "-ErrorAction SilentlyContinue;"
      "$x+=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' "
      "-ErrorAction SilentlyContinue;"
      "$x|Where-Object {$_.DisplayName}|Select-Object DisplayName,DisplayVersion,InstallDate|Sort-Object DisplayName|"
      "Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(60),
      options,
      result,
      entries,
      cancel,
      progress,
      "System",
      "Installed software");
  run_powershell_text(sys / "services.log",
                      "Get-CimInstance -ClassName Win32_Service | "
                      "Select-Object DisplayName,Name,StartName,StartMode,State | Format-List",
                      std::chrono::seconds(60),
                      options,
                      result,
                      entries,
                      cancel,
                      progress,
                      "System",
                      "Windows services");

  // Network, firewall and TLS/security context.
  run_powershell_text(sys / "firewall_profiles.log",
                      "Get-NetFirewallProfile | Format-List *",
                      std::chrono::seconds(30),
                      options,
                      result,
                      entries,
                      cancel,
                      progress,
                      "Network",
                      "Firewall profiles");
  run_text_command(sys / "ipconfig.log",
                   L"ipconfig.exe",
                   {"/all"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Network",
                   "ipconfig /all");
  run_text_command(sys / "netstat.log",
                   L"netstat.exe",
                   {"-bona"},
                   std::chrono::seconds(45),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Network",
                   "netstat -bona");
  run_text_command(sys / "route.log",
                   L"route.exe",
                   {"print"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Network",
                   "route print");
  // Effective TLS protocol state, not just the Registry overrides.
  //
  // The SCHANNEL export only contains keys an administrator has explicitly written. On a default
  // installation almost nothing is there, so "which TLS versions are enabled?" - the actual
  // question in a Veeam transport case - could not be answered from the bundle. This walks every
  // protocol/role and reports the effective state, marking whether it came from an explicit
  // Registry value or from the OS default.
  run_powershell_text(
      sys / "tls_protocols.log",
      "$base='HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols';"
      "$rows=@();"
      "foreach ($p in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2','TLS 1.3')) {"
      "  foreach ($r in @('Client','Server')) {"
      "    $k=Join-Path (Join-Path $base $p) $r;"
      "    $enabled='(OS default)'; $disabled='(OS default)'; $src='Default';"
      "    if (Test-Path $k) {"
      "      $v=Get-ItemProperty $k -ErrorAction SilentlyContinue;"
      "      if ($null -ne $v.Enabled) { $enabled=$v.Enabled; $src='Registry' };"
      "      if ($null -ne $v.DisabledByDefault) { $disabled=$v.DisabledByDefault; $src='Registry' } };"
      "    $state='Unknown';"
      "    if ($src -eq 'Registry') { if ($enabled -eq 0) { $state='DISABLED' } "
      "      elseif ($enabled -ne '(OS default)' -and $enabled -ne 0) { $state='ENABLED' } };"
      "    $rows+=[pscustomobject]@{Protocol=$p;Role=$r;State=$state;Enabled=$enabled;"
      "      DisabledByDefault=$disabled;Source=$src} } };"
      "$rows | Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(30), options, result, entries, cancel, progress, "Network",
      "TLS protocol state");
  run_powershell_text(sys / "tls_ciphers.log",
                      "$sat_cs = Get-TlsCipherSuite; $i=0; $sat_rows = foreach ($sat_s in $sat_cs) { $i++; \"{0:D3}`t{1}\" -f $i, $sat_s.Name }; $sat_rows | Out-String -Width 4096",
                      std::chrono::seconds(30),
                      options,
                      result,
                      entries,
                      cancel,
                      progress,
                      "Network",
                      "TLS cipher suites");
  run_powershell_text(
      sys / "network_adapters.log",
      "Get-NetAdapter -IncludeHidden | "
      "Select-Object Name,InterfaceDescription,ifIndex,Status,MacAddress,LinkSpeed,DriverInformation,DriverFileName,DriverVersion,DriverDate,VlanID,MediaType,PhysicalMediaType | "
      "Sort-Object Name | Format-List",
      std::chrono::seconds(45), options, result, entries, cancel, progress, "Network",
      "Network adapter inventory");
  run_powershell_text(
      sys / "network_ip_interfaces.log",
      "Get-NetIPInterface | Select-Object InterfaceAlias,InterfaceIndex,AddressFamily,ConnectionState,NlMtu,InterfaceMetric,AutomaticMetric,Dhcp,Forwarding,WeakHostSend,WeakHostReceive | "
      "Sort-Object InterfaceAlias,AddressFamily | Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(45), options, result, entries, cancel, progress, "Network",
      "Network IP interface / MTU inventory");
  run_powershell_text(
      sys / "network_routes.log",
      "Get-NetRoute | Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceAlias,InterfaceIndex,RouteMetric,Protocol,State,PolicyStore | "
      "Sort-Object InterfaceAlias,AddressFamily,DestinationPrefix | Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(45), options, result, entries, cancel, progress, "Network",
      "Network route inventory");
  run_powershell_text(
      sys / "network_advanced_properties.log",
      "Get-NetAdapterAdvancedProperty -AllProperties -ErrorAction SilentlyContinue | "
      "Select-Object Name,DisplayName,DisplayValue,RegistryKeyword,RegistryValue | "
      "Sort-Object Name,DisplayName | Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(60), options, result, entries, cancel, progress, "Network",
      "Network advanced adapter properties");
  run_powershell_text(
      sys / "file_and_printer_sharing.log",
      "Get-NetAdapterBinding | Where-Object {$_.DisplayName -match 'File and Printer Sharing'} | "
      "Format-Table -AutoSize | Out-String -Width 4096",
      std::chrono::seconds(30),
      options,
      result,
      entries,
      cancel,
      progress,
      "Network",
      "File and Printer Sharing bindings");
  run_powershell_text(
      sys / "vbr_connectivity.log",
      "$p=Get-ItemProperty 'HKLM:\\SOFTWARE\\Veeam\\Veeam Endpoint Backup' "
      "-Name BackupServerIPAddress -ErrorAction SilentlyContinue;"
      "if($p.BackupServerIPAddress){"
      "$p.BackupServerIPAddress -split '\\|' | Where-Object {$_} | ForEach-Object {"
      "Test-NetConnection $_ -Port 10005 -WarningAction SilentlyContinue; "
      "& tracert.exe /d /h 10 /w 1000 $_}} "
      "else {'No VAW BackupServerIPAddress value detected.'}",
      std::chrono::minutes(2),
      options,
      result,
      entries,
      cancel,
      progress,
      "Network",
      "VAW to VBR connectivity");

  // Registry snapshots from the established collection workflow.
  run_text_command(reg / "vaw_registry.log",
                   L"reg.exe",
                   {"query", "HKLM\\SOFTWARE\\Veeam\\Veeam Endpoint Backup", "/s"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Registry",
                   "VAW Registry");
  run_text_command(reg / "vbr_registry.log",
                   L"reg.exe",
                   {"query", "HKLM\\SOFTWARE\\Veeam\\Veeam Backup and Replication", "/s"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Registry",
                   "VBR Registry");
  run_powershell_text(
      reg / "veeam_registry_safe_inventory.log",
      "$root='HKLM:\\SOFTWARE\\Veeam';"
      "$secret='(?i)(password|secret|token|credential|private.?key|connection.?string|access.?key|authorization)';"
      "if(Test-Path $root){ Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue | ForEach-Object {"
      "$k=$_; $p=Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue;"
      "if($p){ $p.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$'} | ForEach-Object {"
      "$n=$_.Name; $v=$_.Value; if($n -match $secret){$v='[REDACTED BY SAT]'};"
      "[pscustomobject]@{Key=$k.Name;Name=$n;Value=$v} } } } | Sort-Object Key,Name | Format-Table -AutoSize } "
      "else {'HKLM\\SOFTWARE\\Veeam was not present.'}",
      std::chrono::seconds(60), options, result, entries, cancel, progress, "Registry",
      "Veeam Registry safe read-only inventory");
  run_text_command(reg / "dotnet_v4_full.log",
                   L"reg.exe",
                   {"query", "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full", "/s"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Registry",
                   ".NET v4 Full Registry");
  run_text_command(reg / "system_policy.log",
                   L"reg.exe",
                   {"query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "/s"},
                   std::chrono::seconds(30),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Registry",
                   "System policy Registry");
  // Privacy boundary: do not dump machine/user environment registry keys.
  // Environment values frequently contain customer-specific tokens, API keys,
  // credentials, paths, and application secrets that are not required for the
  // support workflow. Collect targeted diagnostics instead.
  run_text_command(reg / "gpresult.log",
                   L"gpresult.exe",
                   {"/z"},
                   std::chrono::seconds(60),
                   options,
                   result,
                   entries,
                   cancel,
                   progress,
                   "Registry",
                   "Group Policy result");
  run_powershell_text(
      sys / "veeam_certificates.log",
      "$stores=@('Cert:\\LocalMachine\\My','Cert:\\LocalMachine\\CA','Cert:\\LocalMachine\\Root');"
      "$stores | ForEach-Object { Get-ChildItem $_ -ErrorAction SilentlyContinue } | "
      "Where-Object {$_.FriendlyName -match 'Veeam' -or $_.Subject -match 'Veeam' -or $_.Issuer -match 'Veeam'} | "
      "Select-Object PSParentPath,FriendlyName,Subject,Issuer,SerialNumber,Thumbprint,NotBefore,NotAfter,HasPrivateKey,@{N='EnhancedKeyUsage';E={($_.EnhancedKeyUsageList.FriendlyName -join '; ')}} | "
      "Sort-Object FriendlyName,Subject | Format-List",
      std::chrono::seconds(45), options, result, entries, cancel, progress, "Security",
      "Veeam-named certificates (public metadata only)");

  const auto schannel = sys / "network_customizations.reg";
  {
    ProcessOptions process_options;
    process_options.executable = L"reg.exe";
    process_options.arguments = {"export", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL", path_to_utf8(schannel), "/y"};
    process_options.timeout = std::chrono::seconds(30);
    auto process = run_process_capture(process_options, cancel, progress);
    if (process.ok() && process.value().exit_code == 0)
      static_cast<void>(record_generated_file(schannel, options, result, entries, "Network", "SCHANNEL Registry export", "exported"));
    else {
      std::filesystem::remove(schannel, error);
      result.warnings.push_back("SCHANNEL Registry export was unavailable");
    }
  }

  // Native Event Log export avoids wevtutil argument/XPath quoting failures.
  // Blank time scope means all available records; Last X days sets from_utc_ms.
  const std::string event_query = windows_event_query(options);
  export_event_log("Application", events / ("Application_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);
  export_event_log("Security", events / ("Security_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);
  export_event_log("System", events / ("System_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);
  export_event_log("Veeam Agent", events / ("VeeamAgent_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);
  export_event_log("Microsoft-Windows-SMBClient/Connectivity", events / ("SMB_Client_Connectivity_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);
  export_event_log("Microsoft-Windows-SMBClient/Operational", events / ("SMB_Client_Operational_" + collector_machine_name() + ".evtx"), event_query, options, result, entries, cancel, progress);

  ProcessOptions list_events;
  list_events.executable = L"wevtutil.exe";
  list_events.arguments = {"el"};
  list_events.timeout = std::chrono::seconds(30);
  auto event_list = run_process_capture(list_events, cancel, progress);
  if (event_list.ok() && event_list.value().exit_code == 0) {
    std::istringstream lines(event_list.value().output);
    std::string channel;
    std::size_t exported = 0;
    while (exported < 64U && std::getline(lines, channel) && !cancel.is_cancelled()) {
      if (!channel.empty() && channel.back() == '\r')
        channel.pop_back();
      if (ascii_lower(channel).find("failover") == std::string::npos)
        continue;
      std::string filename = channel;
      for (char& ch : filename) {
        if (ch == '/' || ch == '\\' || ch == ':' || ch == '*')
          ch = '_';
      }
      export_event_log(channel,
                       events / (filename + ".evtx"),
                       event_query,
                       options,
                       result,
                       entries,
                       cancel,
                       progress);
      ++exported;
    }
  }

  // Additional Veeam files/folders from the guest-machine collection workflow.
  const auto program_data = program_data_path();
  const auto setup_temp = program_data / "Veeam" / "Setup" / "Temp";
  for (const char* filename : {"EndPointSetup.log", "SharedManagementObjects.log", "SqlLocalDB.log", "SQLSysClrTypes.log"}) {
    copy_supplemental_file(setup_temp / filename,
                           veeam / "SetupTemp" / filename,
                           primary_sources,
                           options,
                           result,
                           entries,
                           "Veeam",
                           std::string("Setup Temp: ") + filename);
  }
  const auto backup = program_data / "Veeam" / "Backup";
  copy_supplemental_tree(backup / "Setup", veeam / "Backup" / "Setup", primary_sources, options, result, entries, cancel, "Veeam", "Backup Setup");
  copy_supplemental_tree(backup / "cloudmsg", veeam / "Backup" / "cloudmsg", primary_sources, options, result, entries, cancel, "Veeam", "Cloud messaging");
  copy_supplemental_tree(backup / "BackupSearch", veeam / "Backup" / "BackupSearch", primary_sources, options, result, entries, cancel, "Veeam", "BackupSearch/FLR");
  std::filesystem::directory_iterator backup_iterator(backup, std::filesystem::directory_options::skip_permission_denied, error);
  const std::filesystem::directory_iterator backup_end;
  for (; !error && backup_iterator != backup_end && !cancel.is_cancelled(); backup_iterator.increment(error)) {
    if (!backup_iterator->is_regular_file(error) || error) {
      error.clear();
      continue;
    }
    if (!backup_root_support_file(support_assist::path_to_utf8(backup_iterator->path().filename())))
      continue;
    copy_supplemental_file(backup_iterator->path(),
                           veeam / "BackupRoot" / backup_iterator->path().filename(),
                           primary_sources,
                           options,
                           result,
                           entries,
                           "Veeam",
                           "Backup root support log");
  }

  // Explicit raw-evidence inventory. The structured Veeam parser skips this
  // subtree until dedicated Windows support parsers are backed by fixtures.
  result.windows_support_index_path = result.windows_support_directory / "windows-support-index.json";
  {
    std::ofstream index(result.windows_support_index_path, std::ios::binary | std::ios::trunc);
    if (index) {
      index << "{\n"
            << "  \"schema\": 1,\n"
            << "  \"collector_machine\": \"" << json_escape(collector_machine_name()) << "\",\n"
            << "  \"created_utc\": \"" << json_escape(utc_now_iso8601()) << "\",\n"
            << "  \"parser_status\": \"raw-evidence-only\",\n"
            << "  \"items\": [\n";
      for (std::size_t i = 0; i < entries.size(); ++i) {
        const auto& entry = entries[i];
        index << "    {\"category\":\"" << json_escape(entry.category)
              << "\",\"name\":\"" << json_escape(entry.name)
              << "\",\"status\":\"" << json_escape(entry.status)
              << "\",\"path\":\"" << json_escape(entry.relative_path) << "\"}";
        if (i + 1U < entries.size())
          index << ',';
        index << '\n';
      }
      index << "  ]\n}\n";
      index.flush();
      if (index)
        static_cast<void>(record_generated_file(result.windows_support_index_path, options, result, entries, "Index", "Windows support evidence index", "written"));
    }
  }
}
#else
void collect_windows_support_context(const LogCollectionOptions&,
                                     const std::vector<std::filesystem::path>&,
                                     LogCollectionResult&,
                                     const CancellationToken&,
                                     const ProgressCallback&) {}
#endif

Status write_manifest(const LogCollectionOptions& options,
                      const std::vector<std::filesystem::path>& sources,
                      const LogCollectionResult& result) {
  std::ofstream output(result.manifest_path, std::ios::binary | std::ios::trunc);
  if (!output) {
    return Status::failure(collection_error(
        "write manifest", result.manifest_path, "Could not create collection-manifest.json"));
  }
  output << "{\n"
         << "  \"schema\": 2,\n"
         << "  \"profile\": \"" << json_escape(to_string(options.profile)) << "\",\n"
         << "  \"collector_machine\": \"" << json_escape(collector_machine_name()) << "\",\n"
         << "  \"support_assist_version\": \"" << json_escape(std::string(kVersion)) << "\",\n"
         << "  \"created_utc\": \"" << json_escape(utc_now_iso8601()) << "\",\n"
         << "  \"copied_files\": " << result.copied_files << ",\n"
         << "  \"skipped_files\": " << result.skipped_files << ",\n"
         << "  \"error_count\": " << result.error_count << ",\n"
         << "  \"copied_bytes\": " << result.copied_bytes << ",\n"
         << "  \"windows_support_context\": "
         << (options.include_windows_support_context ? "true" : "false") << ",\n"
         << "  \"windows_support_files\": " << result.windows_support_files << ",\n"
         << "  \"tool_output_files\": " << result.tool_output_files << ",\n"
         << "  \"tool_output_files_cleaned\": " << result.tool_output_files_cleaned << ",\n"
         << "  \"sat_log_files\": " << result.sat_log_files << ",\n"
         << "  \"additional_files\": " << result.additional_files << ",\n"
         << "  \"sat_logs_directory_cleaned\": "
         << (result.sat_logs_directory_cleaned ? "true" : "false") << ",\n"
         << "  \"tool_output_copy_complete\": "
         << (result.tool_output_copy_complete ? "true" : "false") << ",\n"
         << "  \"application_logs_copy_complete\": "
         << (result.sat_logs_copy_complete ? "true" : "false") << ",\n"
         << "  \"collection_directory_cleaned\": "
         << (result.collection_directory_cleaned ? "true" : "false") << ",\n"
         << "  \"windows_support_parser_status\": \""
         << (result.windows_support_files == 0U ? "not-collected" : "raw-evidence-only") << "\",\n"
         << "  \"system_health_snapshot\": \""
         << json_escape(result.health_report_path.empty() ? std::string{}
                                                          : support_assist::path_to_utf8(result.health_report_path.filename()))
         << "\",\n"
         << "  \"sources\": [\n";
  for (std::size_t index = 0; index < sources.size(); ++index) {
    output << "    \"" << json_escape(path_to_utf8(sources[index])) << "\"";
    if (index + 1U < sources.size())
      output << ',';
    output << '\n';
  }
  output << "  ],\n  \"additional_sources\": [\n";
  for (std::size_t index = 0; index < options.additional_sources.size(); ++index) {
    output << "    \"" << json_escape(path_to_utf8(options.additional_sources[index])) << "\"";
    if (index + 1U < options.additional_sources.size()) output << ',';
    output << '\n';
  }
  output << "  ],\n  \"warnings\": [\n";
  for (std::size_t index = 0; index < result.warnings.size(); ++index) {
    output << "    \"" << json_escape(result.warnings[index]) << "\"";
    if (index + 1U < result.warnings.size())
      output << ',';
    output << '\n';
  }
  output << "  ]\n}\n";
  if (!output) {
    return Status::failure(collection_error(
        "write manifest", result.manifest_path, "Failed while writing collection manifest"));
  }
  return Status::success();
}

} // namespace

std::string to_string(LogCollectionProfile profile) {
  switch (profile) {
  case LogCollectionProfile::universal:
    return "universal";
  case LogCollectionProfile::vaw:
    return "vaw";
  case LogCollectionProfile::vbr:
    return "vbr";
  case LogCollectionProfile::sql_plugin:
    return "sql-plugin";
  case LogCollectionProfile::rman_plugin:
    return "rman-plugin";
  case LogCollectionProfile::custom:
    return "custom";
  }
  return "custom";
}

Result<LogCollectionProfile> parse_log_collection_profile(std::string_view value) {
  const std::string folded = ascii_lower(value);
  if (folded == "universal" || folded == "auto") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::universal);
  }
  if (folded == "vaw" || folded == "agent") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::vaw);
  }
  if (folded == "vbr" || folded == "backup") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::vbr);
  }
  if (folded == "sql" || folded == "sql-plugin") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::sql_plugin);
  }
  if (folded == "rman" || folded == "rman-plugin" || folded == "oracle") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::rman_plugin);
  }
  if (folded == "custom") {
    return Result<LogCollectionProfile>::success(LogCollectionProfile::custom);
  }
  return Result<LogCollectionProfile>::failure(
      collection_error("parse profile",
                       std::string(value),
                       "Expected universal, vaw, vbr, sql-plugin, rman-plugin, or custom"));
}

std::vector<LogSourceCandidate> discover_shared_veeam_log_sources(
    const ProductDiscoveryContext& context) {
  std::vector<LogSourceCandidate> candidates;
  const auto append = [&](const std::filesystem::path& path, std::string label) {
    if (!path.empty())
      candidates.push_back({path, std::move(label), true});
  };

  // These paths are intentionally product-neutral. Multiple Veeam products and
  // components write into them, so their presence is useful collection evidence
  // but cannot establish that any specific product (especially VBR) is installed.
  if (context.platform == HostPlatform::windows && !context.program_data.empty()) {
    append(context.program_data / "Veeam" / "Backup",
           "Shared Veeam logs (product-neutral common root)");
    append(context.program_data / "Veeam" / "Setup" / "Temp",
           "Shared Veeam setup/upgrade logs");
  } else if (context.platform == HostPlatform::linux) {
    append(resolve_catalog_path(context, "/var/log/VeeamBackup"),
           "Shared Veeam transport/infrastructure logs");
    append(resolve_catalog_path(context, "/tmp/VeeamBackup"),
           "Shared temporary Veeam transport logs");
    append(resolve_catalog_path(context, "/var/log/veeam"),
           "Shared Veeam operational logs");
  } else if (context.platform == HostPlatform::macos) {
    append(resolve_catalog_path(context, "/var/log/veeam"),
           "Shared Veeam operational logs");
    append(resolve_catalog_path(context, "/Library/Logs/Veeam"),
           "Shared Veeam application logs");
  }
  return candidates;
}

std::vector<LogSourceCandidate> discover_log_collection_sources(LogCollectionProfile profile) {
  const std::filesystem::path program_data = program_data_path();
  const std::filesystem::path local_app_data = local_app_data_path();
  std::vector<LogSourceCandidate> candidates;
  switch (profile) {
  case LogCollectionProfile::universal: {
    const auto context = native_product_discovery_context();
    std::vector<std::string> seen;
    const auto append_unique = [&](const std::filesystem::path& path, std::string label) {
      const std::string key = support_assist::generic_path_to_utf8(path.lexically_normal());
      if (std::find(seen.begin(), seen.end(), key) == seen.end()) {
        candidates.push_back({path, std::move(label), true});
        seen.push_back(key);
      }
    };
    for (const auto& product : detect_products(context)) {
      for (const auto& rule : product.definition.log_paths) {
        if (rule.third_party || rule.sensitive_by_nature)
          continue;
        append_unique(resolve_catalog_path(context, rule.path),
                      product.definition.display_name + ": " + rule.label);
      }
    }

    for (const auto& candidate : discover_shared_veeam_log_sources(context))
      append_unique(candidate.path, candidate.label);
    break;
  }
  case LogCollectionProfile::vaw:
#ifdef _WIN32
    if (const auto configured = registry_string_value(
            HKEY_LOCAL_MACHINE, L"SOFTWARE\\Veeam\\Veeam Endpoint Backup", L"LogDirectory")) {
      candidates.push_back({*configured, "VAW configured LogDirectory", true});
    }
#endif
    candidates.push_back({program_data / "Veeam" / "Endpoint", "VAW Endpoint logs", true});
    candidates.push_back(
        {program_data / "Veeam" / "Backup", "VAW installer and VSS-provider logs", true});
    break;
  case LogCollectionProfile::vbr:
    candidates.push_back({program_data / "Veeam" / "Backup", "VBR service and job logs", true});
    candidates.push_back({program_data / "Veeam" / "Setup" / "Temp", "Veeam setup logs", true});
    if (!local_app_data.empty()) {
      candidates.push_back(
          {local_app_data / "Veeam" / "Backup", "VBR console and PowerShell logs", true});
    }
    break;
  case LogCollectionProfile::sql_plugin:
    candidates.push_back({program_data / "Veeam" / "Backup" / "MSSQLPluginLogs",
                          "Microsoft SQL Server plug-in logs",
                          true});
    candidates.push_back({program_data / "Veeam" / "Backup" / "Plugin",
                          "VBR-side plug-in operation logs",
                          true});
    candidates.push_back({program_data / "Veeam" / "Backup" / "Plugins",
                          "Legacy plural plug-in folder",
                          true});
    break;
  case LogCollectionProfile::rman_plugin:
    candidates.push_back({program_data / "Veeam" / "Backup" / "RmanPluginLogs",
                          "Oracle RMAN plug-in logs",
                          true});
    candidates.push_back({program_data / "Veeam" / "Backup" / "Plugin",
                          "VBR-side plug-in operation logs",
                          true});
    candidates.push_back({program_data / "Veeam" / "Backup" / "Plugins",
                          "Legacy plural plug-in folder",
                          true});
    break;
  case LogCollectionProfile::custom:
    break;
  }
  return candidates;
}

Result<LogCollectionResult> collect_logs(const LogCollectionOptions& options,
                                         const CancellationToken& cancel,
                                         ProgressCallback progress) {
  // The operation the engineer is actually waiting on. Duration matters here more than anywhere
  // else in the product: "collection finished" and "collection is still running after 20 minutes"
  // look identical in a log of discrete events.
  DebugScope scope("LogCollection", "collect profile " + std::string(to_string(options.profile)));
  if (options.output_root.empty()) {
    return Result<LogCollectionResult>::failure(
        collection_error("collect logs", {}, "An output directory is required"));
  }
  std::vector<std::filesystem::path> sources = options.sources;
  if (sources.empty()) {
    for (const auto& candidate : discover_log_collection_sources(options.profile)) {
      std::error_code error_code;
      if (std::filesystem::exists(candidate.path, error_code))
        sources.push_back(candidate.path);
    }
  }
  if (sources.empty()) {
    return Result<LogCollectionResult>::failure(collection_error(
        "collect logs",
        {},
        "No source directories were supplied and no candidate profile directories exist"));
  }

  LogCollectionResult result;
  result.profile = options.profile;
  const std::string collector = sanitize_case_identifier(collector_machine_name());
  // SAT-<product>-<host>-<timestamp>. "Support-Assist-Tool-universal-..." said what produced the
  // bundle and nothing about what it is about; the product is what an engineer needs to see in a
  // folder of collections. The profile is the fallback when no product token was supplied.
  const std::string product_token = options.bundle_product_token.empty()
                                        ? to_string(options.profile)
                                        : sanitize_case_identifier(options.bundle_product_token);
  result.collection_directory =
      options.output_root /
      ("SAT-" + (product_token.empty() ? std::string("unknown") : product_token) + "-" +
       (collector.empty() ? std::string("unknown") : collector) + "-" + timestamp_token());
  result.manifest_path = result.collection_directory / "collection-manifest.json";
  std::error_code error_code;
  std::filesystem::create_directories(result.collection_directory, error_code);
  if (error_code) {
    return Result<LogCollectionResult>::failure(collection_error("create collection directory",
                                                                 result.collection_directory,
                                                                 error_code.message(),
                                                                 error_code.value()));
  }

  if (!options.system_health_report.empty()) {
    const std::string health_name = (collector.empty() ? std::string("unknown") : collector) +
                                    "-SystemHealth.txt";
    result.health_report_path = result.collection_directory / health_name;
    std::ofstream health(result.health_report_path, std::ios::binary | std::ios::trunc);
    if (health) {
      health << options.system_health_report;
      health.flush();
      if (!health) {
        ++result.error_count;
        result.warnings.push_back("Could not finish writing the system health snapshot");
        result.health_report_path.clear();
      }
    } else {
      ++result.error_count;
      result.warnings.push_back("Could not create the system health snapshot");
      result.health_report_path.clear();
    }
  }

  for (std::size_t source_index = 0; source_index < sources.size(); ++source_index) {
    if (cancel.is_cancelled())
      break;
    const std::filesystem::path& source = sources[source_index];
    const std::filesystem::path destination_root =
        result.collection_directory / safe_source_name(source, source_index);
    std::filesystem::create_directories(destination_root, error_code);
    if (error_code) {
      ++result.error_count;
      result.warnings.push_back("Could not create destination for " + path_to_utf8(source) + ": " +
                                error_code.message());
      error_code.clear();
      continue;
    }

    const auto directory_options =
        options.follow_directory_symlinks
            ? std::filesystem::directory_options::follow_directory_symlink |
                  std::filesystem::directory_options::skip_permission_denied
            : std::filesystem::directory_options::skip_permission_denied;
    std::filesystem::recursive_directory_iterator iterator(source, directory_options, error_code);
    if (error_code) {
      ++result.error_count;
      result.warnings.push_back("Could not enumerate " + path_to_utf8(source) + ": " +
                                error_code.message());
      error_code.clear();
      continue;
    }
    const std::filesystem::recursive_directory_iterator end;
    for (; iterator != end; iterator.increment(error_code)) {
      if (cancel.is_cancelled())
        break;
      if (error_code) {
        ++result.error_count;
        result.warnings.push_back("Enumeration error under " + path_to_utf8(source) + ": " +
                                  error_code.message());
        error_code.clear();
        continue;
      }
      const auto& entry = *iterator;
      if (is_sat_output_directory(entry)) {
        iterator.disable_recursion_pending();
        continue;
      }
      if (!entry.is_regular_file(error_code)) {
        error_code.clear();
        continue;
      }
      if (!in_time_window(entry.path(), options)) {
        ++result.skipped_files;
        continue;
      }
      if (result.copied_files >= options.maximum_files) {
        result.warnings.push_back("Maximum file count reached");
        break;
      }
      const std::uint64_t size = entry.file_size(error_code);
      if (error_code) {
        ++result.error_count;
        result.warnings.push_back("Could not read the size of " + path_to_utf8(entry.path()) + ": " +
                                  error_code.message());
        error_code.clear();
        continue;
      }
      if (result.copied_bytes > options.maximum_bytes ||
          size > options.maximum_bytes - result.copied_bytes) {
        result.warnings.push_back("Maximum byte count reached");
        break;
      }
      // Lexical: the iterator's paths sit under source, and a lexical result reads nothing from the
      // disk, which fails for a path longer than MAX_PATH.
      std::filesystem::path relative = entry.path().lexically_relative(source);
      if (relative.empty() || path_to_utf8(relative).starts_with("..")) {
        ++result.error_count;
        result.warnings.push_back("Could not place " + path_to_utf8(entry.path()) + " in the collection");
        continue;
      }
      const std::filesystem::path destination = destination_root / relative;
      std::filesystem::create_directories(destination.parent_path(), error_code);
      if (error_code) {
        ++result.error_count;
        result.warnings.push_back("Could not create the folder for " + path_to_utf8(destination) + ": " +
                                  error_code.message());
        error_code.clear();
        continue;
      }
      std::filesystem::copy_file(
          entry.path(), destination, std::filesystem::copy_options::overwrite_existing, error_code);
      if (error_code) {
        ++result.error_count;
        result.warnings.push_back("Could not copy " + support_assist::path_to_utf8(entry.path()) + ": " +
                                  error_code.message());
        error_code.clear();
        continue;
      }
      ++result.copied_files;
      result.copied_bytes += size;
      report(progress, "Collecting", entry.path(), result.copied_files, result.error_count);
    }
  }

  // Explorer "Mark for collection" sources are copied after the normal product
  // sources so their provenance is explicit and they cannot alter discovery.
  for (const auto& additional : options.additional_sources) {
    if (cancel.is_cancelled()) break;
    std::error_code additional_error;
    if (!std::filesystem::exists(additional, additional_error) || additional_error) {
      result.warnings.push_back("Marked additional source is unavailable: " + path_to_utf8(additional));
      continue;
    }
    const auto destination_base = result.collection_directory / additional_archive_path(additional);
    const auto copy_one = [&](const std::filesystem::path& file, const std::filesystem::path& destination) {
      std::error_code item_error;
      if (result.copied_files >= options.maximum_files) { ++result.skipped_files; return; }
      const auto size = std::filesystem::file_size(file, item_error);
      if (item_error || result.copied_bytes > options.maximum_bytes || size > options.maximum_bytes - result.copied_bytes) {
        ++result.skipped_files; return;
      }
      std::filesystem::create_directories(destination.parent_path(), item_error);
      if (!item_error)
        std::filesystem::copy_file(file, destination, std::filesystem::copy_options::overwrite_existing, item_error);
      if (item_error) {
        ++result.error_count;
        result.warnings.push_back("Could not collect marked file " + support_assist::path_to_utf8(file) + ": " + item_error.message());
        return;
      }
      ++result.copied_files; ++result.additional_files; result.copied_bytes += size;
      report(progress, "Collecting marked Explorer item", file, result.copied_files, result.error_count);
    };
    if (std::filesystem::is_regular_file(additional, additional_error) && !additional_error) {
      copy_one(additional, destination_base);
      continue;
    }
    if (!std::filesystem::is_directory(additional, additional_error) || additional_error) {
      result.warnings.push_back("Marked additional source is not a regular file or directory: " + path_to_utf8(additional));
      continue;
    }
    std::filesystem::recursive_directory_iterator it(additional, std::filesystem::directory_options::skip_permission_denied, additional_error), end;
    for (; !additional_error && it != end && !cancel.is_cancelled(); it.increment(additional_error)) {
      std::error_code item_error;
      if (!it->is_regular_file(item_error) || item_error) continue;
      auto relative = std::filesystem::relative(it->path(), additional, item_error);
      if (item_error || relative.empty() || support_assist::generic_path_to_utf8(relative).starts_with("..")) continue;
      copy_one(it->path(), destination_base / relative);
    }
    if (additional_error)
      result.warnings.push_back("Could not fully enumerate marked directory " + path_to_utf8(additional) + ": " + additional_error.message());
  }

  bool sat_logs_copy_attempted = false;
  bool tool_output_copy_attempted = false;
  result.sat_logs_copy_complete = true;
  result.tool_output_copy_complete = true;

  const auto copy_owned_tree = [&](const std::filesystem::path& source_root,
                                   const std::filesystem::path& destination_root,
                                   bool rename_activity,
                                   std::uint64_t& owned_file_counter,
                                   bool& complete,
                                   std::string_view progress_label) {
    std::error_code tree_error;
    if (!std::filesystem::exists(source_root, tree_error)) {
      if (tree_error) {
        complete = false;
        result.warnings.push_back("Could not inspect SAT-owned directory " + support_assist::path_to_utf8(source_root) + ": " + tree_error.message());
      }
      return;
    }
    if (!std::filesystem::is_directory(source_root, tree_error) || tree_error) {
      complete = false;
      result.warnings.push_back("SAT-owned source is not an accessible directory: " + support_assist::path_to_utf8(source_root));
      return;
    }
    const std::filesystem::path long_source = long_path_form(source_root);
    const std::filesystem::path long_destination = long_path_form(destination_root);
    std::filesystem::create_directories(long_destination, tree_error);
    if (tree_error) {
      complete = false;
      ++result.error_count;
      result.warnings.push_back("Could not create collection directory " + support_assist::path_to_utf8(destination_root) + ": " + tree_error.message());
      return;
    }
    std::filesystem::recursive_directory_iterator it(
        long_source, std::filesystem::directory_options::skip_permission_denied, tree_error), end;
    if (tree_error) {
      complete = false;
      ++result.error_count;
      result.warnings.push_back("Could not enumerate SAT-owned directory " + support_assist::path_to_utf8(source_root) + ": " + tree_error.message());
      return;
    }
    for (; !tree_error && it != end; it.increment(tree_error)) {
      if (cancel.is_cancelled()) { complete = false; break; }
      std::error_code item_error;
      if (!it->is_regular_file(item_error) || item_error) continue;
      const std::uint64_t size = it->file_size(item_error);
      if (item_error || result.copied_files >= options.maximum_files ||
          result.copied_bytes > options.maximum_bytes || size > options.maximum_bytes - result.copied_bytes) {
        complete = false; ++result.skipped_files; continue;
      }
      auto relative = it->path().lexically_relative(long_source);
      if (relative.empty() || support_assist::path_to_utf8(relative).starts_with("..")) {
        complete = false; ++result.error_count;
        result.warnings.push_back("Could not place SAT-owned file " + shown_path(it->path()) + " in the collection");
        continue;
      }
      if (rename_activity && relative == std::filesystem::path("activity.tsv"))
        relative = collector_machine_name() + "Activity.tsv";
      const auto destination = long_destination / relative;
      std::filesystem::create_directories(destination.parent_path(), item_error);
      if (!item_error)
        std::filesystem::copy_file(it->path(), destination, std::filesystem::copy_options::overwrite_existing, item_error);
      if (item_error) {
        complete = false; ++result.error_count;
        result.warnings.push_back("Could not collect SAT-owned file " + shown_path(it->path()) + ": " + item_error.message());
        continue;
      }
      ++result.copied_files; ++owned_file_counter; result.copied_bytes += size;
      report(progress, std::string(progress_label), it->path(), result.copied_files, result.error_count);
    }
    if (tree_error) {
      complete = false; ++result.error_count;
      result.warnings.push_back("Could not fully enumerate SAT-owned directory " + support_assist::path_to_utf8(source_root) + ": " + tree_error.message());
    }
  };

  if (options.include_sat_logs && !options.sat_logs_directory.empty() && !cancel.is_cancelled()) {
    sat_logs_copy_attempted = true;
    if (path_is_within_sat_root(result.collection_directory, options.sat_logs_directory)) {
      result.sat_logs_copy_complete = false;
      result.warnings.push_back("ApplicationLogs cleanup was disabled because collection staging is inside ApplicationLogs");
    } else {
      copy_owned_tree(options.sat_logs_directory, result.collection_directory / "ApplicationLogs",
                      true, result.sat_log_files, result.sat_logs_copy_complete,
                      "Collecting SAT application logs");
    }
  }

  // SAT's own activity record for the run that produced this bundle. Collected in BOTH roles and
  // independently of include_sat_logs: it says what was collected and when, so a bundle without it
  // cannot describe itself. Engineer Review does not archive the rest of ApplicationLogs, and this
  // deliberately does not change that - one file, copied, nothing removed.
  if (!options.sat_logs_directory.empty() && !result.sat_logs_copy_complete &&
      !cancel.is_cancelled()) {
    const auto activity = options.sat_logs_directory / "activity.tsv";
    std::error_code activity_error;
    if (std::filesystem::is_regular_file(activity, activity_error)) {
      const auto destination =
          result.collection_directory / (collector_machine_name() + "Activity.tsv");
      std::filesystem::create_directories(destination.parent_path(), activity_error);
      std::filesystem::copy_file(activity, destination,
                                 std::filesystem::copy_options::overwrite_existing, activity_error);
      if (activity_error) {
        result.warnings.push_back("Could not collect the SAT activity record: " +
                                  activity_error.message());
      } else {
        ++result.copied_files;
        ++result.sat_log_files;
      }
    }
  }

  if (options.include_tool_output_logs && !options.tool_output_directory.empty() && !cancel.is_cancelled()) {
    tool_output_copy_attempted = true;
    if (path_is_within_sat_root(result.collection_directory, options.tool_output_directory)) {
      result.tool_output_copy_complete = false;
      result.warnings.push_back("Tool output cleanup was disabled because collection staging is inside Log-Collections\\Tools");
    } else {
      copy_owned_tree(options.tool_output_directory, result.collection_directory / "Tools",
                      false, result.tool_output_files, result.tool_output_copy_complete,
                      "Collecting SAT tool output");
    }
  }

  collect_windows_support_context(options, sources, result, cancel, progress);

  if (auto status = write_manifest(options, sources, result); !status.ok()) {
    return Result<LogCollectionResult>::failure(status.error());
  }
  if (options.create_archive && !cancel.is_cancelled()) {
    result.archive_path = result.collection_directory;
    result.archive_path += ".zip";
    if (auto status = create_zip_archive(result.collection_directory, result.archive_path);
        !status.ok()) {
      result.warnings.push_back(describe_error(status.error()));
      result.archive_path.clear();
      ++result.error_count;
    } else {
      if (options.cleanup_sat_logs_after_archive && sat_logs_copy_attempted &&
          result.sat_logs_copy_complete && !options.sat_logs_directory.empty()) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(options.sat_logs_directory), cleanup_error));
        std::error_code exists_error;
        const bool remains = std::filesystem::exists(options.sat_logs_directory, exists_error);
        if (!cleanup_error && !exists_error && !remains)
          result.sat_logs_directory_cleaned = true;
        else
          result.warnings.push_back("SAT's ApplicationLogs folder is in the bundle, but some of its files could not be deleted afterwards, usually because a program still has them open: " + support_assist::path_to_utf8(options.sat_logs_directory));
      } else if (options.cleanup_sat_logs_after_archive && sat_logs_copy_attempted && !result.sat_logs_copy_complete) {
        result.warnings.push_back("SAT's ApplicationLogs folder was left in place: some of its files could not be copied into the bundle. The warnings above name them.");
      }

      if (options.cleanup_tool_output_after_archive && tool_output_copy_attempted &&
          result.tool_output_copy_complete && !options.tool_output_directory.empty()) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(options.tool_output_directory), cleanup_error));
        std::error_code exists_error;
        const bool remains = std::filesystem::exists(options.tool_output_directory, exists_error);
        if (!cleanup_error && !exists_error && !remains)
          result.tool_output_files_cleaned = result.tool_output_files;
        else
          result.warnings.push_back("The Tools folder under Log-Collections is in the bundle, but some of its files could not be deleted afterwards, usually because a program still has them open: " + support_assist::path_to_utf8(options.tool_output_directory));
      } else if (options.cleanup_tool_output_after_archive && tool_output_copy_attempted && !result.tool_output_copy_complete) {
        result.warnings.push_back("The Tools folder under Log-Collections was left in place: some of its files could not be copied into the bundle. The warnings above name them.");
      }

      if (options.cleanup_collection_directory_after_archive) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(result.collection_directory), cleanup_error));
        std::error_code exists_error;
        const bool remains = std::filesystem::exists(result.collection_directory, exists_error);
        if (!cleanup_error && !exists_error && !remains)
          result.collection_directory_cleaned = true;
        else
          result.warnings.push_back("Collection staging directory could not be fully removed: " + support_assist::path_to_utf8(result.collection_directory));
      }
    }
  }
  // Rewrite the manifest after archive/cleanup so it records the actual cleanup
  // result. The ZIP contains the pre-cleanup manifest, while the retained
  // collection directory records post-archive cleanup truth.
  if (!result.collection_directory_cleaned) {
    if (auto status = write_manifest(options, sources, result); !status.ok())
      return Result<LogCollectionResult>::failure(status.error());
  }
  return Result<LogCollectionResult>::success(std::move(result));
}

std::filesystem::path long_path_form(const std::filesystem::path& path) {
#ifdef _WIN32
  if (!path.is_absolute() || path.native().rfind(L"\\\\?\\", 0) == 0)
    return path;
  std::wstring normal = path.lexically_normal().native();
  std::replace(normal.begin(), normal.end(), L'/', L'\\');
  if (normal.rfind(L"\\\\", 0) == 0)
    return std::filesystem::path(L"\\\\?\\UNC\\" + normal.substr(2));
  return std::filesystem::path(L"\\\\?\\" + normal);
#else
  return path;
#endif
}

Status create_zip_archive(const std::filesystem::path& source_directory,
                          const std::filesystem::path& archive_path) {
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  archive* raw_archive = archive_write_new();
  if (raw_archive == nullptr) {
    return Status::failure(
        collection_error("create archive", archive_path, "archive_write_new failed"));
  }
  struct ArchiveDeleter {
    void operator()(archive* value) const noexcept {
      archive_write_free(value);
    }
  };
  std::unique_ptr<archive, ArchiveDeleter> writer(raw_archive);
  archive_write_set_format_zip(writer.get());
#ifdef _WIN32
  if (archive_write_open_filename_w(writer.get(), archive_path.wstring().c_str()) != ARCHIVE_OK) {
#else
  if (archive_write_open_filename(writer.get(), path_to_utf8(archive_path).c_str()) != ARCHIVE_OK) {
#endif
    return Status::failure(
        collection_error("open archive", archive_path, archive_error_string(writer.get())));
  }
  std::error_code error_code;
  const std::filesystem::path root = long_path_form(source_directory);
  for (std::filesystem::recursive_directory_iterator
           iterator(root,
                    std::filesystem::directory_options::skip_permission_denied,
                    error_code),
       end;
       iterator != end;
       iterator.increment(error_code)) {
    if (error_code) {
      error_code.clear();
      continue;
    }
    if (!iterator->is_regular_file(error_code)) {
      error_code.clear();
      continue;
    }
    const std::filesystem::path relative = iterator->path().lexically_relative(root);
    if (relative.empty())
      continue;
    std::ifstream input(iterator->path(), std::ios::binary);
    if (!input)
      continue;
    const std::uint64_t size = iterator->file_size(error_code);
    if (error_code) {
      error_code.clear();
      continue;
    }
    archive_entry* entry = archive_entry_new();
    if (entry == nullptr)
      continue;
    std::string entry_name = path_to_utf8(relative);
    std::replace(entry_name.begin(), entry_name.end(), '\\', '/');
    archive_entry_set_pathname_utf8(entry, entry_name.c_str());
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_entry_set_size(entry, static_cast<la_int64_t>(size));
    if (archive_write_header(writer.get(), entry) == ARCHIVE_OK) {
      std::vector<char> buffer(64U * 1024U);
      while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = input.gcount();
        if (count > 0) {
          archive_write_data(writer.get(), buffer.data(), static_cast<std::size_t>(count));
        }
      }
    }
    archive_entry_free(entry);
  }
  if (archive_write_close(writer.get()) != ARCHIVE_OK) {
    return Status::failure(
        collection_error("close archive", archive_path, archive_error_string(writer.get())));
  }
  return Status::success();
#else
  static_cast<void>(source_directory);
  return Status::failure(
      collection_error("create archive",
                       archive_path,
                       "Archive creation requires SUPPORT_ASSIST_ENABLE_LIBARCHIVE=ON"));
#endif
}

} // namespace support_assist
