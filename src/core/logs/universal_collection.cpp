#include "support_assist/universal_collection.hpp"

#include "support_assist/named_pipes.hpp"
#include "support_assist/process.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <set>
#include <sstream>
#include <thread>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace support_assist {
namespace {

Error universal_error(std::string operation, const std::filesystem::path& source, std::string message) {
  Error error;
  error.component = "UniversalCollection";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  return error;
}

std::string json_escape_local(std::string_view value) {
  std::string output;
  output.reserve(value.size() + 16U);
  for (const char ch : value) {
    switch (ch) {
    case '\\': output += "\\\\"; break;
    case '"': output += "\\\""; break;
    case '\n': output += "\\n"; break;
    case '\r': output += "\\r"; break;
    case '\t': output += "\\t"; break;
    default: output.push_back(ch); break;
    }
  }
  return output;
}

void emit_progress(const ProgressCallback& progress, std::string phase, const std::filesystem::path& path) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = std::move(phase);
  event.current_scope = support_assist::path_to_utf8(path);
  progress(event);
}

bool readable_regular_file(const std::filesystem::path& path) {
  std::error_code error;
  return std::filesystem::is_regular_file(path, error) && !error;
}

bool likely_text_file(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(support_assist::path_to_utf8(path.extension()));
  return extension.empty() || extension == ".log" || extension == ".txt" || extension == ".out" ||
         extension == ".err" || extension == ".trace" || extension == ".trc";
}

std::filesystem::path unique_destination(const std::filesystem::path& directory,
                                         std::string prefix,
                                         const std::filesystem::path& source) {
  std::string name = support_assist::path_to_utf8(source.filename());
  if (name.empty())
    name = "diagnostic.log";
  for (char& ch : prefix) {
    if (!std::isalnum(static_cast<unsigned char>(ch)) && ch != '-' && ch != '_')
      ch = '_';
  }
  return directory / (prefix + "-" + name);
}

bool copy_sanitized_text(const std::filesystem::path& source,
                         const std::filesystem::path& destination,
                         std::uint64_t maximum_bytes,
                         std::string& warning) {
  std::ifstream input(source, std::ios::binary);
  if (!input) {
    warning = "Could not open third-party error log: " + path_to_utf8(source);
    return false;
  }
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  if (error) {
    warning = "Could not create third-party diagnostic directory: " + error.message();
    return false;
  }
  std::ofstream output(destination, std::ios::binary | std::ios::trunc);
  if (!output) {
    warning = "Could not create sanitized third-party copy: " + path_to_utf8(destination);
    return false;
  }
  output << "# SAT sanitized operational/error-log copy\n"
         << "# Obvious credential, token, connection-string, SQL-statement and key material lines are redacted.\n"
         << "# Source: " << path_to_utf8(source) << "\n\n";
  std::string line;
  std::uint64_t written = 0;
  while (std::getline(input, line)) {
    std::string sanitized = redact_third_party_log_line(line);
    sanitized.push_back('\n');
    if (written + sanitized.size() > maximum_bytes) {
      output << "[SAT truncated this log at its bounded third-party diagnostic limit]\n";
      break;
    }
    output << sanitized;
    written += sanitized.size();
  }
  return static_cast<bool>(output);
}

void find_matching_files(const std::filesystem::path& root,
                         const std::vector<std::string>& names,
                         std::size_t maximum,
                         std::vector<std::filesystem::path>& output) {
  std::error_code error;
  if (!std::filesystem::exists(root, error) || error)
    return;
  const auto options = std::filesystem::directory_options::skip_permission_denied;
  std::filesystem::recursive_directory_iterator it(root, options, error), end;
  while (!error && it != end && output.size() < maximum) {
    std::error_code item_error;
    if (it->is_regular_file(item_error)) {
      const std::string filename = ascii_lower(support_assist::path_to_utf8(it->path().filename()));
      for (const auto& needle : names) {
        if (filename == ascii_lower(needle) ||
            (needle.ends_with("*") && filename.starts_with(ascii_lower(needle.substr(0, needle.size() - 1U))))) {
          output.push_back(it->path());
          break;
        }
      }
    }
    it.increment(error);
  }
}

struct ThirdPartyCandidate {
  std::string product;
  std::filesystem::path path;
};

std::vector<ThirdPartyCandidate> discover_third_party_errors(const ProductDiscoveryContext& context) {
  std::vector<ThirdPartyCandidate> result;
  auto append_matches = [&](std::string product,
                            const std::filesystem::path& root,
                            const std::vector<std::string>& names,
                            std::size_t maximum = 32U) {
    std::vector<std::filesystem::path> matches;
    find_matching_files(resolve_catalog_path(context, root), names, maximum, matches);
    for (auto& match : matches)
      result.push_back({product, std::move(match)});
  };

  if (context.platform == HostPlatform::linux) {
    append_matches("Microsoft SQL Server", "/var/opt/mssql/log", {"errorlog", "errorlog.*", "sqlagent.out"});
    append_matches("PostgreSQL", "/var/log/postgresql", {"postgresql-*"});
    append_matches("MySQL/MariaDB", "/var/log/mysql", {"error.log", "mysqld.log", "mariadb.log"});
    append_matches("MySQL/MariaDB", "/var/log/mariadb", {"mariadb.log", "error.log"});
    append_matches("MongoDB", "/var/log/mongodb", {"mongod.log", "mongodb.log"}, 16U);
    // Oracle diagnostic trees can be very large. Only alert logs are eligible,
    // never datafiles, redo, archived logs, controlfiles or backup pieces.
    append_matches("Oracle Database", "/u01/app/oracle/diag", {"alert_*"}, 16U);
    append_matches("Oracle Database", "/opt/oracle/diag", {"alert_*"}, 16U);
  } else if (context.platform == HostPlatform::windows) {
    std::filesystem::path sql_root = context.program_files / "Microsoft SQL Server";
    append_matches("Microsoft SQL Server", sql_root, {"errorlog", "errorlog.*", "sqlagent.out"}, 32U);
    // PostgreSQL Windows installers commonly place server logs below Program Files.
    append_matches("PostgreSQL", context.program_files / "PostgreSQL", {"postgresql-*"}, 24U);
  }
  return result;
}

void write_process_output(const std::filesystem::path& destination,
                          const std::filesystem::path& executable,
                          std::vector<std::string> arguments,
                          const CancellationToken& cancel,
                          std::vector<std::string>& warnings) {
  ProcessOptions options;
  options.executable = executable;
  options.arguments = std::move(arguments);
  options.timeout = std::chrono::seconds(20);
  options.maximum_output_bytes = 2U * 1024U * 1024U;
  auto result = run_process_capture(options, cancel);
  if (!result.ok()) {
    warnings.push_back("Could not run platform diagnostic " + path_to_utf8(executable));
    return;
  }
  std::ofstream output(destination, std::ios::binary | std::ios::trunc);
  if (!output) {
    warnings.push_back("Could not write platform diagnostic " + path_to_utf8(destination));
    return;
  }
  output << "Command: " << result.value().command_display << "\n"
         << "ExitCode: " << result.value().exit_code << "\n\n"
         << result.value().output;
  if (!result.value().standard_error.empty())
    output << "\n[stderr]\n" << result.value().standard_error;
}

void collect_platform_context(const ProductDiscoveryContext& context,
                              const std::filesystem::path& directory,
                              const CancellationToken& cancel,
                              std::vector<std::string>& warnings) {
  std::error_code error;
  std::filesystem::create_directories(directory, error);
  if (error) {
    warnings.push_back("Could not create platform context directory: " + error.message());
    return;
  }
#ifdef _WIN32
  static_cast<void>(context);
  static_cast<void>(cancel);
  // Windows context is collected by the established bounded Windows collector.
  std::ofstream note(directory / "README.txt", std::ios::binary | std::ios::trunc);
  note << "Windows platform diagnostics are stored in the WindowsSupport subtree.\n";
#else
  if (context.platform == HostPlatform::linux) {
    const auto os_release = resolve_catalog_path(context, "/etc/os-release");
    if (readable_regular_file(os_release)) {
      std::filesystem::copy_file(os_release, directory / "os-release.txt",
                                 std::filesystem::copy_options::overwrite_existing, error);
      error.clear();
    }
    const auto meminfo = resolve_catalog_path(context, "/proc/meminfo");
    if (readable_regular_file(meminfo)) {
      std::filesystem::copy_file(meminfo, directory / "meminfo.txt",
                                 std::filesystem::copy_options::overwrite_existing, error);
      error.clear();
    }
    write_process_output(directory / "uname.txt", "/usr/bin/uname", {"-a"}, cancel, warnings);
    if (std::filesystem::exists("/usr/bin/uptime"))
      write_process_output(directory / "uptime.txt", "/usr/bin/uptime", {}, cancel, warnings);
    if (std::filesystem::exists("/usr/bin/df"))
      write_process_output(directory / "filesystems.txt", "/usr/bin/df", {"-hT"}, cancel, warnings);
    if (std::filesystem::exists("/usr/bin/lsblk"))
      write_process_output(directory / "block-devices.txt", "/usr/bin/lsblk", {"-o", "NAME,TYPE,SIZE,FSTYPE,ROTA,TRAN,MOUNTPOINTS"}, cancel, warnings);
    const std::filesystem::path ip = std::filesystem::exists("/usr/sbin/ip") ? "/usr/sbin/ip" : "/usr/bin/ip";
    if (std::filesystem::exists(ip)) {
      write_process_output(directory / "network-addresses.txt", ip, {"-details", "addr", "show"}, cancel, warnings);
      write_process_output(directory / "network-links.txt", ip, {"-details", "link", "show"}, cancel, warnings);
      write_process_output(directory / "routes.txt", ip, {"route", "show", "table", "all"}, cancel, warnings);
      write_process_output(directory / "routing-rules.txt", ip, {"rule", "show"}, cancel, warnings);
    }
    if (std::filesystem::exists("/usr/bin/ss"))
      write_process_output(directory / "listening-ports.txt", "/usr/bin/ss", {"-lntup"}, cancel, warnings);
    if (std::filesystem::exists("/usr/bin/systemctl")) {
      write_process_output(directory / "services.txt", "/usr/bin/systemctl", {"list-units", "--type=service", "--all", "--no-pager"}, cancel, warnings);
      write_process_output(directory / "service-files.txt", "/usr/bin/systemctl", {"list-unit-files", "--type=service", "--no-pager"}, cancel, warnings);
    }
    if (std::filesystem::exists("/usr/bin/dpkg-query"))
      write_process_output(directory / "installed-software.txt", "/usr/bin/dpkg-query", {"-W", "-f=${Package}\t${Version}\n"}, cancel, warnings);
    else if (std::filesystem::exists("/usr/bin/rpm"))
      write_process_output(directory / "installed-software.txt", "/usr/bin/rpm", {"-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}, cancel, warnings);
    if (std::filesystem::exists("/usr/bin/openssl"))
      write_process_output(directory / "tls-ciphers.txt", "/usr/bin/openssl", {"ciphers", "-v", "ALL:eNULL"}, cancel, warnings);
  } else if (context.platform == HostPlatform::macos) {
    write_process_output(directory / "uname.txt", "/usr/bin/uname", {"-a"}, cancel, warnings);
    write_process_output(directory / "macos-version.txt", "/usr/bin/sw_vers", {}, cancel, warnings);
    write_process_output(directory / "vm-stat.txt", "/usr/bin/vm_stat", {}, cancel, warnings);
    write_process_output(directory / "filesystems.txt", "/bin/df", {"-h"}, cancel, warnings);
    write_process_output(directory / "hardware-summary.txt", "/usr/sbin/sysctl", {"-n", "hw.model", "hw.memsize", "hw.ncpu", "machdep.cpu.brand_string"}, cancel, warnings);
    if (std::filesystem::exists("/sbin/ifconfig"))
      write_process_output(directory / "network-addresses.txt", "/sbin/ifconfig", {"-a"}, cancel, warnings);
    if (std::filesystem::exists("/sbin/route"))
      write_process_output(directory / "routes.txt", "/sbin/route", {"-n", "get", "default"}, cancel, warnings);
    if (std::filesystem::exists("/usr/sbin/netstat"))
      write_process_output(directory / "listening-ports.txt", "/usr/sbin/netstat", {"-anv"}, cancel, warnings);
    if (std::filesystem::exists("/bin/launchctl"))
      write_process_output(directory / "services.txt", "/bin/launchctl", {"list"}, cancel, warnings);
    if (std::filesystem::exists("/usr/sbin/system_profiler"))
      write_process_output(directory / "installed-software.txt", "/usr/sbin/system_profiler", {"SPApplicationsDataType", "-detailLevel", "mini"}, cancel, warnings);
  }
#endif
}


void append_environment_file(std::ofstream& output,
                             std::string_view section,
                             const std::filesystem::path& path,
                             std::size_t maximum_bytes = 1024U * 1024U) {
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    // A section that was never collected is recorded as such rather than omitted, so an empty
    // snapshot from a machine with nothing to report cannot be mistaken for one where collection
    // failed silently. Anything reading this file - an engineer or automated tooling - must be
    // able to tell "not collected" apart from "collected and empty".
    output << "\n[" << section << "]\nNotCollected=" << support_assist::path_to_utf8(path) << "\n\n";
    return;
  }
  output << "\n[" << section << "]\n";
  // `reg export` writes UTF-16LE. Appended verbatim, its BOM and interleaved NUL bytes would make
  // environment.log - otherwise UTF-8 - invalid UTF-8 as a whole, so a strict reader fails on the
  // entire file rather than just the affected section. Transcode UTF-16 sections to UTF-8 so the
  // snapshot stays one consistent encoding.
  {
    std::array<char, 2> bom{};
    const auto mark = input.tellg();
    input.read(bom.data(), 2);
    const auto marked = input.gcount();
    const bool utf16_le = marked == 2 && static_cast<unsigned char>(bom[0]) == 0xFF &&
                          static_cast<unsigned char>(bom[1]) == 0xFE;
    input.clear();
    input.seekg(mark);
    if (utf16_le) {
      std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
      std::string transcoded;
      transcoded.reserve(raw.size() / 2U);
      // Skip the BOM, then take the low byte of each UTF-16 unit. The Registry export is ASCII
      // key and value text, so this is lossless for what is actually collected; anything outside
      // it is replaced rather than emitted as a stray byte.
      for (std::size_t at = 2U; at + 1U < raw.size(); at += 2U) {
        const unsigned char low = static_cast<unsigned char>(raw[at]);
        const unsigned char high = static_cast<unsigned char>(raw[at + 1U]);
        transcoded.push_back(high == 0 && low < 0x80U ? static_cast<char>(low) : '?');
      }
      if (transcoded.size() > maximum_bytes) {
        transcoded.resize(maximum_bytes);
        transcoded += "\n[TRUNCATED BY SAT ENVIRONMENT SNAPSHOT]\n";
      }
      output << transcoded << '\n';
      return;
    }
  }
  std::array<char, 8192> buffer{};
  std::size_t written = 0;
  while (input && written < maximum_bytes) {
    const std::size_t remaining = maximum_bytes - written;
    input.read(buffer.data(), static_cast<std::streamsize>((std::min)(remaining, buffer.size())));
    const auto count = input.gcount();
    if (count <= 0) break;
    output.write(buffer.data(), count);
    written += static_cast<std::size_t>(count);
  }
  if (input.peek() != std::char_traits<char>::eof())
    output << "\n[TRUNCATED BY SAT ENVIRONMENT SNAPSHOT]\n";
  output << '\n';
}

std::filesystem::path write_environment_log(const ProductDiscoveryContext& context,
                                            UniversalCollectionResult& result) {
  const auto path = result.logs.collection_directory / "environment.log";
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) { result.warnings.push_back("Could not create environment.log"); return {}; }
  const auto metadata = make_snapshot_metadata(SnapshotKind::filesystem, "environment-snapshot");
// RC2 writes SAT_ENVIRONMENT_V2; SAT_ENVIRONMENT_V1 remains import-compatible in the GUI loader.
  output << "SAT_ENVIRONMENT_V2\n"
         << "CapturedUTC=" << utc_now_iso8601() << "\n"
         << "Machine=" << metadata.machine_name << "\n"
         << "Platform=" << to_string(context.platform) << "\n"
         << "OS=" << metadata.os_name << "\n"
         << "OSVersion=" << metadata.os_version << "\n"
         << "Architecture=" << metadata.architecture << "\n"
         << "Elevated=" << (metadata.elevated ? "true" : "false") << "\n"
         << "\n[Products]\n";
  for (const auto& product : result.detected_products) {
    output << product.definition.id << '\t' << product.definition.display_name << '\t'
           << product.definition.role << '\t' << (product.signature_detected ? "detected" : "selected") << '\t';
    for (std::size_t i = 0; i < product.evidence_paths.size(); ++i) {
      if (i) output << ';';
      output << support_assist::path_to_utf8(product.evidence_paths[i]);
    }
    output << '\n';
  }
  output << "\n[BundlePaths]\nWindowsSupport=WindowsSupport\nPlatformContext=PlatformContext\nTools=Tools\nApplicationLogs=ApplicationLogs\n";
  // The clock the logs were written by, read when the collection started.
  if (result.time_base) {
    output << "\n[TimeBase]\n";
    for (const TimeBaseField& field : time_base_fields(*result.time_base))
      output << field.key << '=' << field.value << '\n';
  }
#ifdef _WIN32
  const auto sys = result.logs.windows_support_directory / "SystemInfo";
  append_environment_file(output, "SystemInfo", sys / "systeminfo.log");
  append_environment_file(output, "ComputerInfo", sys / "computer_info.log");
  append_environment_file(output, "WindowsMaintenancePackages", sys / "dism_packages.log", 2U * 1024U * 1024U);
  append_environment_file(output, "WindowsHotfixes", sys / "windows_updates.log", 2U * 1024U * 1024U);
  append_environment_file(output, "InstalledSoftware", sys / "installed_software.log", 2U * 1024U * 1024U);
  append_environment_file(output, "Services", sys / "services.log", 2U * 1024U * 1024U);
  append_environment_file(output, "IPConfiguration", sys / "ipconfig.log");
  append_environment_file(output, "ListeningPorts", sys / "netstat.log", 2U * 1024U * 1024U);
  append_environment_file(output, "Routes", sys / "route.log");
  append_environment_file(output, "NetworkAdapterBindings", sys / "file_and_printer_sharing.log", 2U * 1024U * 1024U);
  append_environment_file(output, "NetworkAdapters", sys / "network_adapters.log", 2U * 1024U * 1024U);
  append_environment_file(output, "NetworkIpInterfaces", sys / "network_ip_interfaces.log", 2U * 1024U * 1024U);
  append_environment_file(output, "NetworkRoutesDetailed", sys / "network_routes.log", 2U * 1024U * 1024U);
  append_environment_file(output, "NetworkAdvancedProperties", sys / "network_advanced_properties.log", 2U * 1024U * 1024U);
  append_environment_file(output, "TlsProtocols", sys / "tls_protocols.log");
  append_environment_file(output, "TlsCipherSuites", sys / "tls_ciphers.log", 2U * 1024U * 1024U);
  append_environment_file(output, "VeeamCertificates", sys / "veeam_certificates.log");
  append_environment_file(output, "VeeamRegistrySafe", result.logs.windows_support_directory / "Registry" / "veeam_registry_safe_inventory.log", 2U * 1024U * 1024U);
  append_environment_file(output, "SchannelRegistry", sys / "network_customizations.reg", 2U * 1024U * 1024U);
  append_environment_file(output, "Storage", sys / "fsutil_sectorinfo.log");
  append_environment_file(output, "FilesystemFilters", sys / "minifilters.log");
  // The Veeam, SQL Server and PostgreSQL pipes, read by name only.
  output << "\n[NamedPipes]\nColumns:\tPipe\tInstances\tKnown as\tService or process\n";
  {
    NamedPipesOptions pipe_options;
    pipe_options.veeam_only = true;
    const auto pipes = list_named_pipes(pipe_options, CancellationSource{}.token());
    if (!pipes.ok()) {
      output << "Unavailable\t" << describe_error(pipes.error()) << '\n';
    } else {
      for (const NamedPipeRow& row : named_pipe_rows(pipes.value()))
        output << row.pipe << '\t' << row.instances << '\t' << row.known_as << '\t' << row.owner << '\n';
    }
  }
#else
  append_environment_file(output, "OSRelease", result.platform_context_directory / "os-release.txt");
  append_environment_file(output, "NetworkAddresses", result.platform_context_directory / "network-addresses.txt");
  append_environment_file(output, "NetworkLinks", result.platform_context_directory / "network-links.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "ListeningPorts", result.platform_context_directory / "listening-ports.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "Routes", result.platform_context_directory / "routes.txt");
  append_environment_file(output, "RoutingRules", result.platform_context_directory / "routing-rules.txt");
  append_environment_file(output, "Services", result.platform_context_directory / "services.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "ServiceFiles", result.platform_context_directory / "service-files.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "InstalledSoftware", result.platform_context_directory / "installed-software.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "TlsCipherSuites", result.platform_context_directory / "tls-ciphers.txt", 2U * 1024U * 1024U);
  append_environment_file(output, "Storage", result.platform_context_directory / "filesystems.txt");
#endif
  output.flush();
  if (!output) { result.warnings.push_back("environment.log could not be completely written"); return {}; }
  return path;
}


std::filesystem::path::string_type executable_search_path() {
#ifdef _WIN32
  // The project builds with MSVC warnings-as-errors.  Use the bounds-aware
  // wide CRT API instead of getenv(), which MSVC marks C4996.
  wchar_t* value = nullptr;
  std::size_t length = 0;
  if (_wdupenv_s(&value, &length, L"PATH") == 0 && value != nullptr) {
    const std::filesystem::path::string_type result(value);
    std::free(value);
    return result;
  }
  std::free(value);
  return {};
#else
  if (const char* value = std::getenv("PATH"); value != nullptr)
    return std::filesystem::path::string_type(value);
  return {};
#endif
}

std::optional<std::filesystem::path> locate_executable(const std::filesystem::path& preferred) {
  std::error_code error;
  if (!preferred.empty() && preferred.is_absolute() &&
      std::filesystem::is_regular_file(preferred, error) && !error)
    return preferred;

  const std::filesystem::path name = preferred.filename();
  if (name.empty())
    return std::nullopt;

  const std::filesystem::path::string_type path_value = executable_search_path();
#ifdef _WIN32
  constexpr wchar_t separator = L';';
#else
  constexpr char separator = ':';
#endif
  std::size_t begin = 0;
  while (begin <= path_value.size()) {
    const auto end = path_value.find(separator, begin);
    const auto part = path_value.substr(
        begin, end == std::filesystem::path::string_type::npos
                   ? std::filesystem::path::string_type::npos
                   : end - begin);
    if (!part.empty()) {
      auto candidate = std::filesystem::path(part) / name;
#ifdef _WIN32
      if (candidate.extension().empty())
        candidate += L".exe";
#endif
      error.clear();
      if (std::filesystem::is_regular_file(candidate, error) && !error)
        return candidate;
    }
    if (end == std::filesystem::path::string_type::npos)
      break;
    begin = end + 1U;
  }
  return std::nullopt;
}

void run_official_exporters(const UniversalCollectionOptions& options,
                            UniversalCollectionResult& result,
                            const CancellationToken& cancel,
                            const ProgressCallback& progress) {
  if (!options.include_official_product_exporters || cancel.is_cancelled())
    return;

  const auto export_root = result.logs.collection_directory / "OfficialProductExports";
  std::error_code error;
  std::filesystem::create_directories(export_root, error);
  if (error) {
    result.warnings.push_back("Could not create official product exporter directory: " + error.message());
    return;
  }

  for (const auto& product : result.detected_products) {
    if (cancel.is_cancelled())
      break;
    if (product.definition.preferred_exporter.empty())
      continue;

    OfficialExporterRun record;
    record.product_id = product.definition.id;
    record.product_name = product.definition.display_name;
    record.may_include_configuration = product.definition.exporter_may_include_configuration;
    record.output_directory = export_root / product.definition.id;
    std::filesystem::create_directories(record.output_directory, error);
    if (error) {
      result.warnings.push_back("Could not prepare exporter output for " + product.definition.display_name + ": " + error.message());
      error.clear();
      result.official_exporter_runs.push_back(std::move(record));
      continue;
    }

    const auto executable = locate_executable(product.definition.preferred_exporter);
    if (!executable) {
      result.warnings.push_back("Official exporter for " + product.definition.display_name + " was detected in the catalog but the executable is not available: " + product.definition.preferred_exporter);
      result.official_exporter_runs.push_back(std::move(record));
      continue;
    }
    record.executable = *executable;

#ifndef _WIN32
    if (product.definition.exporter_requires_elevation && geteuid() != 0) {
      result.warnings.push_back("Official exporter for " + product.definition.display_name + " requires root/elevated privileges; SAT did not attempt privilege escalation.");
      result.official_exporter_runs.push_back(std::move(record));
      continue;
    }
#endif

    emit_progress(progress, "Running official Veeam log exporter (explicit opt-in)", *executable);
    ProcessOptions process;
    process.executable = *executable;
    process.arguments = product.definition.preferred_exporter_arguments;
    process.working_directory = record.output_directory;
    process.timeout = std::chrono::minutes(10);
    process.maximum_output_bytes = 4U * 1024U * 1024U;
    process.maximum_standard_error_bytes = 2U * 1024U * 1024U;
    process.merge_standard_error = false;

    auto executed = run_process_capture(process, cancel, progress);
    if (!executed.ok()) {
      result.warnings.push_back("Official exporter failed to launch for " + product.definition.display_name + ": " + describe_error(executed.error()));
      result.official_exporter_runs.push_back(std::move(record));
      continue;
    }

    record.launched = executed.value().launched;
    record.exit_code = executed.value().exit_code;
    record.succeeded = executed.value().launched && !executed.value().timed_out && !executed.value().cancelled && executed.value().exit_code == 0;

    std::ofstream transcript(record.output_directory / "SAT-exporter-transcript.txt", std::ios::binary | std::ios::trunc);
    if (transcript) {
      transcript << "Product: " << product.definition.display_name << "\n"
                 << "Command: " << executed.value().command_display << "\n"
                 << "ExitCode: " << executed.value().exit_code << "\n"
                 << "TimedOut: " << (executed.value().timed_out ? "true" : "false") << "\n"
                 << "Cancelled: " << (executed.value().cancelled ? "true" : "false") << "\n"
                 << "MayIncludeConfiguration: " << (record.may_include_configuration ? "true" : "false") << "\n\n"
                 << executed.value().output;
      if (!executed.value().standard_error.empty())
        transcript << "\n[stderr]\n" << executed.value().standard_error;
    }
    if (!record.succeeded)
      result.warnings.push_back("Official exporter did not complete successfully for " + product.definition.display_name + " (exit " + std::to_string(record.exit_code) + ").");
    result.official_exporter_runs.push_back(std::move(record));
  }
}

Status write_universal_manifest(const UniversalCollectionOptions& options,
                                UniversalCollectionResult& result) {
  result.universal_manifest_path = result.logs.collection_directory / "universal-support-manifest.json";
  std::ofstream output(result.universal_manifest_path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(universal_error("write manifest", result.universal_manifest_path,
                                           "Could not create universal support manifest"));
  output << "{\n  \"schema\": \"support-assist-universal-v1\",\n"
         << "  \"platform\": \"" << to_string(result.platform) << "\",\n"
         << "  \"privacy_mode\": \"support-diagnostics-only\",\n"
         << "  \"official_exporters_auto_run\": "
         << (options.include_official_product_exporters ? "true" : "false") << ",\n"
         << "  \"third_party_error_logs\": "
         << (options.include_third_party_error_logs ? "true" : "false") << ",\n"
         << "  \"product_selection_explicit\": "
         << (options.product_selection_explicit ? "true" : "false") << ",\n"
         << "  \"selected_product_ids\": [";
  for (std::size_t index = 0; index < options.selected_product_ids.size(); ++index) {
    if (index != 0U) output << ',';
    output << '\"' << json_escape_local(options.selected_product_ids[index]) << '\"';
  }
  output << "],\n";
  if (result.time_base) {
    output << "  \"time_base\": {";
    const auto fields = time_base_fields(*result.time_base);
    for (std::size_t index = 0; index < fields.size(); ++index) {
      output << (index == 0U ? "" : ",") << "\n    \"" << json_escape_local(fields[index].key) << "\": ";
      if (fields[index].raw)
        output << fields[index].value;
      else
        output << '"' << json_escape_local(fields[index].value) << '"';
    }
    output << "\n  },\n";
  }
  output << "  \"products\": [\n";
  for (std::size_t index = 0; index < result.detected_products.size(); ++index) {
    const auto& product = result.detected_products[index];
    output << "    {\"id\":\"" << json_escape_local(product.definition.id) << "\",\"name\":\""
           << json_escape_local(product.definition.display_name) << "\",\"role\":\""
           << json_escape_local(product.definition.role) << "\",\"signature_detected\":"
           << (product.signature_detected ? "true" : "false") << ",\"evidence\":[";
    for (std::size_t evidence = 0; evidence < product.evidence_paths.size(); ++evidence) {
      if (evidence != 0U) output << ',';
      output << '"' << json_escape_local(support_assist::path_to_utf8(product.evidence_paths[evidence])) << '"';
    }
    output << "]}" << (index + 1U == result.detected_products.size() ? "" : ",") << "\n";
  }
  output << "  ],\n  \"official_exporter_runs\": [\n";
  for (std::size_t index = 0; index < result.official_exporter_runs.size(); ++index) {
    const auto& run = result.official_exporter_runs[index];
    output << "    {\"product_id\":\"" << json_escape_local(run.product_id)
           << "\",\"executable\":\"" << json_escape_local(path_to_utf8(run.executable))
           << "\",\"output_directory\":\"" << json_escape_local(support_assist::path_to_utf8(run.output_directory))
           << "\",\"launched\":" << (run.launched ? "true" : "false")
           << ",\"succeeded\":" << (run.succeeded ? "true" : "false")
           << ",\"exit_code\":" << run.exit_code
           << ",\"may_include_configuration\":" << (run.may_include_configuration ? "true" : "false")
           << "}" << (index + 1U == result.official_exporter_runs.size() ? "" : ",") << "\n";
  }
  output << "  ],\n  \"third_party_policy\": [\n"
         << "    \"No database files, backup payloads, repositories, home directories, environment dumps, or process command lines are collected by the universal path.\",\n"
         << "    \"Third-party collection is restricted to known operational/error log filenames and sanitized as text.\",\n"
         << "    \"Official Veeam exporters that may include configuration are detected but not auto-run unless explicitly requested.\"\n"
         << "  ]\n}\n";
  return output ? Status::success()
                : Status::failure(universal_error("write manifest", result.universal_manifest_path,
                                                   "Failed while writing universal support manifest"));
}

} // namespace

std::string redact_third_party_log_line(std::string_view line) {
  const std::string folded = ascii_lower(line);
  constexpr std::string_view sensitive_tokens[] = {
      "password", "passwd", "pwd=", "secret", "token=", "access_token", "refresh_token",
      "authorization:", "connection string", "connectionstring", "private key", "client_secret",
      "aws_access_key", "aws_secret", "bearer "};
  for (const auto token : sensitive_tokens) {
    if (folded.find(token) != std::string::npos)
      return "[SAT REDACTED: possible credential/token/secret material]";
  }
  constexpr std::string_view sql_tokens[] = {
      "statement:", "execute:", "query text:", "sql text:", "parameters:",
      "\"command\":", "\"filter\":", "\"pipeline\":", "\"documents\":"};
  for (const auto token : sql_tokens) {
    if (folded.find(token) != std::string::npos)
      return "[SAT REDACTED: SQL statement/parameter payload]";
  }
  return std::string(line);
}

Result<UniversalCollectionResult> collect_universal_support_bundle(
    const UniversalCollectionOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress) {
  if (options.output_root.empty())
    return Result<UniversalCollectionResult>::failure(
        universal_error("collect universal support bundle", {}, "An output directory is required"));

  UniversalCollectionResult result;
  const auto context = native_product_discovery_context();
  result.platform = context.platform;
  result.detected_products = detect_products(context);

  // The machine's time base, read once as the collection starts: one SNTP question to its own time
  // source, nothing changed.
  emit_progress(progress, "Clock and time source", {});
  result.time_base = check_time(std::string(), cancel);
  if (const TimeBaseSummary clock = time_base_summary(*result.time_base); !clock.warning.empty())
    result.warnings.push_back(clock.warning);

  if (options.product_selection_explicit || !options.selected_product_ids.empty()) {
    const std::set<std::string> selected(options.selected_product_ids.begin(),
                                         options.selected_product_ids.end());
    result.detected_products.erase(
        std::remove_if(result.detected_products.begin(), result.detected_products.end(),
                       [&](const auto& product) {
                         return selected.find(product.definition.id) == selected.end();
                       }),
        result.detected_products.end());

    if (options.product_selection_explicit) {
      const auto catalog = product_catalog(context.platform);
      for (const auto& selected_id : selected) {
        const bool already_present = std::any_of(
            result.detected_products.begin(), result.detected_products.end(),
            [&](const auto& product) { return product.definition.id == selected_id; });
        if (already_present)
          continue;
        const auto definition = std::find_if(catalog.begin(), catalog.end(),
                                             [&](const auto& product) {
                                               return product.id == selected_id;
                                             });
        if (definition != catalog.end()) {
          DetectedProduct chosen;
          chosen.definition = *definition;
          chosen.signature_detected = false;
          result.detected_products.push_back(std::move(chosen));
        }
      }
    }
  }

  std::set<std::filesystem::path> unique_sources;

  // Common Veeam roots are deliberately independent of product selection. The
  // engineer's checklist controls product-specific paths/exporters; it does not
  // suppress product-neutral evidence such as ProgramData\Veeam\Backup, which
  // can contain VAW, VBR, plug-in, VSS-provider and transport logs on the same host.
  for (const auto& candidate : discover_shared_veeam_log_sources(context)) {
    std::error_code error;
    if (std::filesystem::exists(candidate.path, error) && !error)
      unique_sources.insert(candidate.path);
  }

  for (const auto& product : result.detected_products) {
    for (const auto& rule : product.definition.log_paths) {
      if (rule.third_party || rule.sensitive_by_nature)
        continue;
      const auto path = resolve_catalog_path(context, rule.path);
      std::error_code error;
      if (std::filesystem::exists(path, error) && !error)
        unique_sources.insert(path);
    }
  }

  // If signatures were inconclusive and the caller did not explicitly choose
  // products, the universal profile may still locate additional known support
  // directories. Shared product-neutral roots were already considered above;
  // an explicit checklist is never broadened to unrelated product-specific paths.
  if (unique_sources.empty() && !options.product_selection_explicit && options.selected_product_ids.empty()) {
    for (const auto& candidate : discover_log_collection_sources(LogCollectionProfile::universal)) {
      std::error_code error;
      if (std::filesystem::exists(candidate.path, error) && !error)
        unique_sources.insert(candidate.path);
    }
  }

  if (unique_sources.empty()) {
    // Do not fail the entire universal collector: system diagnostics are useful
    // even on a machine where Veeam is partially installed or already removed.
    result.warnings.push_back("No Veeam log directories were detected; collecting system/support context only.");
  }

  SystemHealthSampler sampler;
  auto first = sampler.sample({true, true, true, true, true});
  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  auto health = sampler.sample({true, true, true, true, true});
  if (!health.ok())
    health = std::move(first);

  LogCollectionOptions collection;
  // Bundle naming: SAT-<product>-<host>-<timestamp>.
  //
  // A single detected product names the bundle after it. Two or three products are joined with
  // '-', since a mixed collection (e.g. VBR+VAW) is still worth identifying precisely. More than
  // three collapses to "MULTI"; the manifest remains the authoritative product list. No detected
  // product falls back to the profile name.
  {
    std::vector<std::string> product_ids;
    for (const auto& product : result.detected_products) {
      if (!product.definition.id.empty())
        product_ids.push_back(ascii_upper(product.definition.id));
    }
    std::sort(product_ids.begin(), product_ids.end());
    product_ids.erase(std::unique(product_ids.begin(), product_ids.end()), product_ids.end());
    if (product_ids.size() == 1U) {
      collection.bundle_product_token = product_ids.front();
    } else if (product_ids.size() > 1U && product_ids.size() <= 3U) {
      for (const auto& id : product_ids) {
        if (!collection.bundle_product_token.empty())
          collection.bundle_product_token += "-";
        collection.bundle_product_token += id;
      }
    } else if (product_ids.size() > 3U) {
      collection.bundle_product_token = "MULTI";
    }
  }
  collection.profile = LogCollectionProfile::universal;
  collection.sources.assign(unique_sources.begin(), unique_sources.end());
  collection.output_root = options.output_root;
  collection.from_utc_ms = options.from_utc_ms;
  collection.to_utc_ms = options.to_utc_ms;
  collection.create_archive = false;
  collection.maximum_files = options.maximum_files;
  collection.maximum_bytes = options.maximum_bytes;
  collection.include_windows_support_context = context.platform == HostPlatform::windows;
  collection.tool_output_directory = options.tool_output_directory;
  collection.include_tool_output_logs = options.include_tool_output_logs;
  collection.cleanup_tool_output_after_archive = false;
  collection.sat_logs_directory = options.sat_logs_directory;
  collection.include_sat_logs = options.include_sat_logs;
  collection.cleanup_sat_logs_after_archive = false;
  collection.cleanup_collection_directory_after_archive = false;
  collection.additional_sources = options.additional_sources;
  if (health.ok())
    collection.system_health_report = format_system_health_report(health.value());

  if (!collection.sources.empty()) {
    auto logs = collect_logs(collection, cancel, progress);
    if (!logs.ok())
      return Result<UniversalCollectionResult>::failure(logs.error());
    result.logs = std::move(logs.value());
  } else {
    // collect_logs requires at least one primary source. Create a tiny bounded
    // SAT-owned placeholder so the same manifest/archive path is used.
    const auto marker_root = options.output_root / ".sat-universal-marker";
    std::error_code error;
    std::filesystem::create_directories(marker_root, error);
    std::ofstream(marker_root / "README.txt", std::ios::binary | std::ios::trunc)
        << "No Veeam product log source was detected. This marker is SAT-owned.\n";
    collection.sources = {marker_root};
    auto logs = collect_logs(collection, cancel, progress);
    std::filesystem::remove_all(marker_root, error);
    if (!logs.ok())
      return Result<UniversalCollectionResult>::failure(logs.error());
    result.logs = std::move(logs.value());
  }

  if (cancel.is_cancelled())
    return Result<UniversalCollectionResult>::success(std::move(result));

  result.platform_context_directory = result.logs.collection_directory / "PlatformContext";
  if (options.include_platform_context) {
    emit_progress(progress, "Platform context", result.platform_context_directory);
    collect_platform_context(context, result.platform_context_directory, cancel, result.warnings);
  }

  result.environment_log_path = write_environment_log(context, result);

  run_official_exporters(options, result, cancel, progress);

  if (options.include_third_party_error_logs && !cancel.is_cancelled()) {
    const auto third_party_dir = result.logs.collection_directory / "ThirdPartyErrors-Sanitized";
    std::set<std::filesystem::path> seen;
    for (const auto& candidate : discover_third_party_errors(context)) {
      if (!seen.insert(candidate.path).second || !likely_text_file(candidate.path))
        continue;
      emit_progress(progress, "Sanitizing third-party error log", candidate.path);
      const auto destination = unique_destination(third_party_dir, candidate.product, candidate.path);
      std::string warning;
      if (copy_sanitized_text(candidate.path, destination, 16U * 1024U * 1024U, warning)) {
        result.third_party_files.push_back(
            {candidate.product, candidate.path, destination,
             "Operational/error text only; obvious credentials/tokens/SQL payloads redacted"});
      } else if (!warning.empty()) {
        result.warnings.push_back(std::move(warning));
      }
    }
  }

  result.privacy_notes = {
      "Universal collection does not copy database data files, backup payloads, repositories, user home directories, environment-variable dumps, or process command lines.",
      "Third-party application evidence is restricted to known operational/error log files and is copied through SAT's text redaction filter.",
      options.include_official_product_exporters
          ? "Official Veeam product exporters were explicitly requested. Their archives may include Veeam configuration and required system logs."
          : "Official Veeam product exporters may include configuration. SAT detects them but does not run them in privacy-safe mode."};

  if (auto status = write_universal_manifest(options, result); !status.ok())
    return Result<UniversalCollectionResult>::failure(status.error());

  if (options.create_archive && !cancel.is_cancelled()) {
    result.logs.archive_path = result.logs.collection_directory;
    result.logs.archive_path += ".zip";
    if (auto status = create_zip_archive(result.logs.collection_directory, result.logs.archive_path); !status.ok()) {
      result.warnings.push_back(describe_error(status.error()));
      result.logs.archive_path.clear();
    } else {
      if (options.cleanup_sat_logs_after_archive && options.include_sat_logs &&
          result.logs.sat_logs_copy_complete && !options.sat_logs_directory.empty()) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(options.sat_logs_directory), cleanup_error));
        std::error_code exists_error;
        if (!cleanup_error && !std::filesystem::exists(options.sat_logs_directory, exists_error) && !exists_error)
          result.logs.sat_logs_directory_cleaned = true;
        else result.warnings.push_back("SAT's ApplicationLogs folder is in the bundle, but some of its files could not be deleted afterwards, usually because a program still has them open.");
      } else if (options.cleanup_sat_logs_after_archive && !result.logs.sat_logs_copy_complete) {
        result.warnings.push_back("SAT's ApplicationLogs folder was left in place: some of its files could not be copied into the bundle. The warnings above name them.");
      }
      if (options.cleanup_tool_output_after_archive && options.include_tool_output_logs &&
          result.logs.tool_output_copy_complete && !options.tool_output_directory.empty()) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(options.tool_output_directory), cleanup_error));
        std::error_code exists_error;
        if (!cleanup_error && !std::filesystem::exists(options.tool_output_directory, exists_error) && !exists_error)
          result.logs.tool_output_files_cleaned = result.logs.tool_output_files;
        else result.warnings.push_back("The Tools folder under Log-Collections is in the bundle, but some of its files could not be deleted afterwards, usually because a program still has them open.");
      } else if (options.cleanup_tool_output_after_archive && !result.logs.tool_output_copy_complete) {
        result.warnings.push_back("The Tools folder under Log-Collections was left in place: some of its files could not be copied into the bundle. The warnings above name them.");
      }
      if (options.cleanup_collection_directory_after_archive) {
        std::error_code cleanup_error;
        static_cast<void>(std::filesystem::remove_all(long_path_form(result.logs.collection_directory), cleanup_error));
        std::error_code exists_error;
        if (!cleanup_error && !std::filesystem::exists(result.logs.collection_directory, exists_error) && !exists_error)
          result.logs.collection_directory_cleaned = true;
        else result.warnings.push_back("The unzipped copy of the collection could not be fully deleted after the ZIP was written.");
      }
    }
  }
  return Result<UniversalCollectionResult>::success(std::move(result));
}

} // namespace support_assist
