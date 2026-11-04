#pragma once

// Service and Process Watch (F12): Veeam's services with their state, the processes with their
// start times, and the difference between two snapshots: what started, ended or changed state
// (docs/PROPOSAL_5.x_CHECKS.md section 9). Read-only: the Service Control Manager and a process
// snapshot on Windows; systemd's unit files, cgroups and /proc on Linux.

#include "support_assist/local_ports.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace support_assist {

enum class WatchKind { service, process };

struct WatchItem {
  WatchKind kind = WatchKind::process;
  std::string name;         // service short name or unit, or process name
  std::string display_name; // service display name
  std::string state;        // service: "running", "stopped", "start pending", ...; process: "running"
  std::uint32_t pid = 0;
  std::int64_t started_unix_millis = 0;
  std::string path;         // process program path
  std::string listening;    // "TCP 6160, 6162, 2500-2502; UDP 6162": the ports its process listens on
};

struct WatchSnapshot {
  std::int64_t taken_unix_millis = 0;
  std::vector<WatchItem> items;
  std::string note;
};

// Services and processes whose name, display name or path holds `filter` (case-insensitive).
WatchSnapshot take_watch_snapshot(const std::string& filter = "veeam");

enum class WatchChange { started, ended, state_changed, restarted };

struct WatchEvent {
  std::int64_t at_unix_millis = 0; // the snapshot that saw it
  WatchChange change = WatchChange::started;
  WatchItem item;
  std::string previous_state;
  std::string text; // "VeeamAgent.exe (PID 4120) ended after 12 min 04 s"
};

std::vector<WatchEvent> diff_watch(const WatchSnapshot& before, const WatchSnapshot& after);

std::string format_duration(std::int64_t millis); // "4 s", "12 min 04 s", "2 h 05 min"

namespace watch_detail {
// Services and processes of a full listing that match the filter, as the platform readers use it.
bool matches(const WatchItem& item, const std::string& lowered_filter);
// The TCP ports a PID listens on and the UDP ports it has bound, runs of ports collapsed:
// "TCP 2500-2502, 6162; UDP 6162". Empty when it holds none, or its sockets are not readable.
std::string listening_text(const std::vector<LocalSocket>& sockets, std::uint32_t pid);
// Each running item's listening ports, from one read of the socket tables.
void add_listening_ports(WatchSnapshot& snapshot);
} // namespace watch_detail

} // namespace support_assist
