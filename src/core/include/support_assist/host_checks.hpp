#pragma once

// Host Checks (Host Diagnostics, read-only): the things on a host that most often explain a failed
// snapshot or backup, as groups an engineer ticks. Windows: backup events (volsnap, VSS, disk,
// NTFS), the Veeam drivers, VSS shadow storage, and the .NET and TLS registry values. Linux: the
// Veeam snapshot module and the kernel log. The groups, events, names, keys and signatures are data
// (config/checks/host-checks.json). Nothing is changed and no program is started.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

inline constexpr const char* kHostCheckPass = "Pass";
inline constexpr const char* kHostCheckFinding = "Finding";
inline constexpr const char* kHostCheckInformation = "Information";
inline constexpr const char* kHostCheckNotPresent = "Not present";
inline constexpr const char* kHostCheckNeedsAdministrator = "Needs administrator";

struct HostCheckGroup {
  std::string id;
  std::string title;
  std::string description;
  std::string platform; // windows, linux or both
  bool needs_admin = false;
};

// One result: the group, what was checked, what was found and one of the statuses above.
struct HostCheckRow {
  std::string group;
  std::string check;
  std::string detail;
  std::string status;
  std::string source; // a KB or guide link, when the data names one
};

struct HostChecksOptions {
  std::vector<std::string> groups; // ids; empty runs every group for this system
  int days = 0;                    // the events' window; 0 takes the data file's
};

struct HostChecksReport {
  bool elevated = false;
  bool cancelled = false; // the run was stopped; the rows are those of the checks that finished
  int days = 0;
  std::vector<std::string> groups_run; // titles
  std::vector<HostCheckRow> rows;
};

// Every group in the data file, and the ones that run on this system.
const std::vector<HostCheckGroup>& host_check_groups();
std::vector<HostCheckGroup> host_check_groups_here();

Result<HostChecksReport> run_host_checks(const HostChecksOptions& options, const CancellationToken& cancel,
                                         ProgressCallback progress = {});

// "Host Checks: 6 Pass, 1 Finding, 2 Information."
std::string host_checks_summary(const HostChecksReport& report);
bool host_checks_has_finding(const HostChecksReport& report);

namespace host_checks_detail {

// ".NET Framework 4.8 (release 528449)" for a Release value; the nearest named release below it.
std::string dotnet_name(std::uint32_t release);
// "4.8" for a Release value; empty when the value is below every release in the data file.
std::string dotnet_version(std::uint32_t release);
// The minimum version the data file gives for Veeam Backup & Replication ("4.7.2").
std::string dotnet_minimum_version();
bool dotnet_below_minimum(std::uint32_t release);
// A TLS protocol's two values as a sentence and whether TLS is turned off by them. Absent values
// are the Windows default, which is on for TLS 1.2.
struct TlsReading {
  std::string text;
  bool off = false;
};
TlsReading tls_reading(std::optional<std::uint32_t> enabled, std::optional<std::uint32_t> disabled_by_default);
// "On", "Off (set to 0)" or "Not set (Windows default)" for a .NET crypto value.
std::string switch_text(std::optional<std::uint32_t> value);
// The kernel log signatures a line carries, by their index in the data file.
std::vector<std::size_t> kernel_signatures_in(std::string_view line);
// The size of a shadow storage limit: UINT64_MAX means no limit.
std::string storage_size_text(std::uint64_t bytes);
// "2026-10-16 12:34" from a WMI date: the form query_wmi gives ("2026-10-16 12:34:56 (UTC-05:00)"),
// or a raw CIM datetime such as 20261016123456.000000-300. Other text comes back as it is.
std::string cim_date_text(const std::string& value);
// One line of at most `limit` bytes plus "...", cut at the start of a UTF-8 character.
std::string shortened(std::string text, std::size_t limit = 300);

} // namespace host_checks_detail

} // namespace support_assist
