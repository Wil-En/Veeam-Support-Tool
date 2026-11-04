#pragma once

// Pending restart: which marker says a restart is waiting, whose it is, when it was set, and why
// (docs/PROPOSAL_5.x_CHECKS.md section 9.1). Windows: the servicing, Windows Update, file rename,
// installer, computer name, domain join and Server Manager markers, with the Setup log's event 4,
// Windows Update's event 19 and MsiInstaller's event 1038 since the last start naming the cause.
// Linux: /run/reboot-required and its package list, a newer installed kernel, and a newer Veeam
// snapshot module than the one loaded. Read-only.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct RestartMarker {
  std::string id;      // "cbs", "windows-update", "msi", "file-renames", "kernel", ...
  std::string name;    // what the marker is
  std::string meaning; // what it means, in a sentence
  bool restart_needed = false; // the system asks for a restart (a file rename list alone does not)
  std::int64_t set_unix_millis = 0; // registry key or file time; 0 when not known
  std::vector<std::string> details;  // packages, files, products, versions
  std::vector<std::string> reasons;  // events since the last start that name the cause
};

struct PendingRestartResult {
  bool restart_needed = false;
  std::int64_t boot_unix_millis = 0;
  std::vector<RestartMarker> markers;
  std::vector<std::string> notes;
};

PendingRestartResult check_pending_restart();

namespace restart_detail {
// Version order as package managers use it: digit runs compare as numbers, letter runs as text,
// and a digit run sorts after a letter run. Returns <0, 0 or >0.
int compare_versions(std::string_view a, std::string_view b);
// PendingFileRenameOperations: source and target pairs, "\??\" and the "!" flag removed; an empty
// target means the source is deleted.
std::vector<std::pair<std::string, std::string>> rename_pairs(const std::vector<std::string>& values);
// An element's text or a <Data Name='..'> value from an event's XML; empty when absent.
std::string event_value(std::string_view xml, std::string_view name);
// The unnamed <Data> values of an event, in order.
std::vector<std::string> event_data(std::string_view xml);
// The newest of a list of kernel release strings ("5.14.0-427.13.1.el9_4.x86_64").
std::string newest_version(const std::vector<std::string>& versions);
} // namespace restart_detail

} // namespace support_assist
