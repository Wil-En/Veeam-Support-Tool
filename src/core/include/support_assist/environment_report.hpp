#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <string>
#include <vector>

namespace support_assist {

// A collected picture of the host SAT is running on.
//
// This is the Linux collector, kept separate from the Windows collector (a large, tested body of
// PowerShell-driven collection in its own frontend) rather than unified behind a shared
// abstraction, so a change to one cannot break the other. Both produce the same shape - named
// sections of key=value lines under the same eight review categories - so a reader of either
// report recognises the other.
//
// Everything here is read-only. Nothing is installed, started, stopped or configured; the worst a
// section can do is fail and say so in its own coverage note.

struct EnvironmentSection {
  // Bracketed section name as it appears in the report, e.g. "[Operating System]".
  std::string name;
  // Which of the eight Environment Review categories this section belongs under.
  std::string category;
  std::vector<std::string> lines;
  // Names for the tab-separated fields in `lines`, when this section emits them. Only the
  // collector knows what its own columns mean; without this the shared table parser falls back
  // to generic labels such as "Field 1", "Field 2". Left empty by sections that emit plain
  // "key=value" lines.
  std::vector<std::string> column_headers;
  // Set when the section could not be collected. The section is still emitted - an engineer needs
  // to see that SAT looked and what stopped it, not silently receive a shorter report.
  std::string unavailable_reason;

  // --- Fields unique to this collector, not carried over from the Windows report --------
  //
  // Each section records what it is for and its Windows equivalent, since a Linux-specific term
  // like "systemd unit" is not self-explanatory to an engineer used to Windows service
  // management. Example: "systemd unit (Windows equivalent: a Service in services.msc)".
  std::string purpose;
  std::string windows_equivalent;
  // Plain-language observations about THIS host's values - the SELinux mode that will block a
  // repository read, the firewall that is filtering the port a job needs. Not findings in the
  // Health Monitor sense; context a Windows-native engineer may not already know.
  std::vector<std::string> notes;
};

struct EnvironmentReport {
  std::string format = "SAT_ENVIRONMENT_V2";
  std::string machine_name;
  std::string captured_utc;
  std::vector<EnvironmentSection> sections;
  // Stated limits of this collection, mirroring the Windows report's [Coverage Note].
  std::vector<std::string> coverage_notes;
};

// The eight categories, in the order the Environment Review presents them. Exposed so a frontend
// lays the cards out in one order rather than each inventing its own.
const std::vector<std::string>& environment_report_categories();

Result<EnvironmentReport> collect_linux_environment(const CancellationToken& cancel,
                                                    ProgressCallback progress = {});

// Renders the report as the text an engineer reads or attaches, section by section.
std::string format_environment_report(const EnvironmentReport& report);

} // namespace support_assist
