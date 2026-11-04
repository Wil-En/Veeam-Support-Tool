#pragma once

#include "support_assist/error.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace support_assist {

enum class ToolAvailability { available, missing, unsupported };

struct ExternalToolDefinition {
  std::string id;
  std::string name;
  std::string category;
  std::vector<std::string> executable_names;
  std::string source_url;
  std::string download_url;
  std::string download_filename;
  std::string download_archive;
  // The parts of the downloaded archive to unpack, as path prefixes inside it ("pgsql/bin/");
  // empty unpacks all of it. The compiled download sources' Extract= overrides it.
  std::vector<std::string> download_extract;
  std::string published_hash;
  std::string description;
  bool automatic_download_supported = false;
  bool bundled_by_windows = false;
  bool windows_only = false;
  bool linux_only = false;  // a Unix tool (tcpdump) - shown on Linux, hidden on Windows
  bool optional_integration = true;
  // A tool that opens its own window when launched (Process Monitor, Wireshark), as opposed to a
  // command-line / assisted tool SAT drives. Groups the Integrations catalogue: Launch vs Assisted.
  bool launches_gui = false;
  // A tool SAT runs itself with a fixed command and collects the output for a case, rather than one
  // it only launches or acquires. The Integrations page gives these a Run/Stop control (VSS Trace).
  bool managed_run = false;
  // The exact argument line for a managed run. {logfile} expands to the per-host path under SAT's
  // Log-Collections/<id> folder; the run is elevated. Empty unless managed_run is set.
  std::string managed_run_arguments;
  bool managed_run_elevated = false;
  // Bounded "detect underneath" hints. Each entry is a directory that may carry a single '*'
  // wildcard matching one path component (e.g. "C:/Program Files/PostgreSQL/*/bin"). Searched after
  // the managed tools folder and PATH, one level deep only - never a recursive filesystem scan - so
  // an already-installed tool (psql, sqlcmd, Wireshark) is used instead of a download.
  std::vector<std::string> known_install_globs;
  // A database client SAT drives through an interactive console window (sqlcmd, psql) rather than a
  // parameter form. Routed to the DATABASE group; its action opens the console.
  bool database_console = false;
  std::string native_alternative;
};

struct ExternalToolStatus {
  ExternalToolDefinition definition;
  ToolAvailability availability = ToolAvailability::missing;
  std::filesystem::path resolved_path;
  std::string detail;
};

std::string to_string(ToolAvailability value);
const std::vector<ExternalToolDefinition>& external_tool_catalog();
std::vector<ExternalToolStatus>
inspect_external_tools(const std::filesystem::path& third_party_directory = {});
Result<std::filesystem::path>
resolve_external_tool(std::string_view id, const std::filesystem::path& third_party_directory = {});
Status open_external_tool_source(std::string_view id);

} // namespace support_assist
