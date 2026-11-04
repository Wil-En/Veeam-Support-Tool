#pragma once

// The Local Port Checker's result: this machine's socket table and firewall read once, and for each
// port a verdict from what this machine can see (docs/PROPOSAL_5.x_CHECKS.md section 5.10). The
// window on both editions and `network local-ports` render these rows.

#include "support_assist/error.hpp"
#include "support_assist/firewall.hpp"
#include "support_assist/local_ports.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace support_assist {

enum class PortVerdict {
  open,               // listening where other hosts can reach it, and the firewall lets it in or is off
  open_some_profiles, // allowed on some active firewall profiles and blocked on others
  blocked_here,       // listening, but this machine's firewall blocks inbound
  local_only,         // listening on loopback only
  closed,             // nothing listening; the other side gets "connection refused"
  closed_and_blocked, // nothing listening, and the firewall drops the attempt; the other side times out
  listening,          // listening; the firewall was not read
  not_listening,      // nothing listening; the firewall was not read
};

std::string to_string(PortVerdict verdict); // "Open", "Blocked here", ...

struct PortCheckRow {
  LocalPortState state;
  FirewallVerdict firewall;
  PortVerdict verdict = PortVerdict::not_listening;
  std::string explanation; // one sentence: what another host sees
  // A range held only while a job moves data ("2500-3300"): one row for the whole range. state is
  // its first held port, or its first port when none is held; held lists the ports held now.
  std::string range;
  std::vector<std::uint16_t> held;
  // A port of a range held by another program than the range's own: the range ("2500-3300").
  std::string in_range;
};

// "2500-3300" for a range row, else the port.
std::string port_label(const PortCheckRow& row);

struct PortCheckResult {
  std::vector<PortCheckRow> rows;
  FirewallSnapshot firewall;
  std::string sockets_note;
  std::int64_t checked_unix_millis = 0;
};

// The ports asked for, per protocol asked for.
Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& ports, bool tcp, bool udp);
// TCP ports and UDP ports from two lists, for a preset whose entries differ by protocol.
Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& tcp_ports,
                                          const std::vector<std::uint16_t>& udp_ports);

// A Veeam role's ports from config/checks/ports.json (the v13 guide's ports pages).
struct PortPresetEntry {
  bool tcp = true;
  bool udp = false;
  std::string ports; // "6162", "2500-3300", "445,135"
  std::string from;
  std::string note;
  bool optional = false;
  bool dynamic = false; // a range held only while a job moves data
  bool one_of = false;  // a service takes one port of the range: the first free one
  // The programs that hold a dynamic range, for the firewall verdict while none of it is held:
  // Windows' Veeam rules allow a program on any port. %ProgramFiles% and %ProgramFiles(x86)% expand.
  std::vector<std::string> programs;
  // The service listens on the loopback address only: nothing on another machine connects to it.
  bool loopback = false;
  // Any program may hold a port of this range (dynamic RPC): no holder is told apart.
  bool any_program = false;
  std::string platform; // "windows" or "linux" when the entry is for one system of the role; empty: both
  // The VBR versions whose guide lists the entry ("12", "13"); empty: both.
  std::vector<std::string> versions;
};

struct PortPreset {
  std::string id;
  std::string name;
  std::vector<PortPresetEntry> entries;
  std::string source_title;
  std::string source_url;
};

// The roles, with the entries for this platform (an entry for the other one is left out).
std::vector<PortPreset> port_presets();
// The roles for one server system ("windows", "linux"; empty: both) and one VBR version ("12", "13";
// empty: both, each entry of one version only saying so in its note).
std::vector<PortPreset> port_presets_for(const std::string& system, const std::string& version);
// The roles with the entries for one system, "windows" or "linux", wherever this program runs: the
// ports a server of that system listens on. An empty system keeps every entry.
std::vector<PortPreset> port_presets_for(const std::string& system);
const PortPreset* find_port_preset(const std::vector<PortPreset>& presets, const std::string& id);
// The ports of a preset to check: every entry except the ranges held only during a job.
void preset_ports(const PortPreset& preset, std::vector<std::uint16_t>& tcp, std::vector<std::uint16_t>& udp);

// A range held only while a job moves data, checked as one row.
struct PortRangeQuery {
  std::uint16_t first = 0;
  std::uint16_t last = 0;
  bool tcp = true;
  bool udp = false;
  std::vector<std::string> programs;
  std::string about; // who connects to it and when, from the entry
  bool any_program = false;
};
// How many ports of a range held by other programs get rows of their own.
constexpr std::size_t kRangeOtherRows = 16;
// What a preset adds to its port lists: its dynamic ranges, and the ports its services hold on the
// loopback address only.
struct PortQueryExtras {
  std::vector<PortRangeQuery> ranges;
  std::vector<std::uint16_t> loopback_tcp;
  std::vector<std::uint16_t> loopback_udp;
};
// The dynamic ranges of a preset.
std::vector<PortRangeQuery> preset_ranges(const PortPreset& preset);
PortQueryExtras preset_extras(const PortPreset& preset);
// The ports, then one row per range and protocol; a loopback port reads as expected when it
// listens on loopback only.
Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& tcp_ports,
                                          const std::vector<std::uint16_t>& udp_ports,
                                          const PortQueryExtras& extras);
// A row of a port the role's service holds on loopback only, said as such.
void explain_loopback_port(PortCheckRow& row);
// One range from a socket table. The first row is the range: the ports its own program (the data
// mover) holds now, or, while it holds none, the firewall verdict for `program`, the program that
// would hold it. Then a row of its own for each port of the range another program holds, at most
// kRangeOtherRows, so that program's verdict is not read as the range's.
std::vector<PortCheckRow> assess_range(const PortRangeQuery& range, PortProtocol protocol,
                                       const std::vector<LocalSocket>& sockets, const FirewallSnapshot& firewall,
                                       const std::string& program);
// Every port a process (name or PID) holds.
Result<PortCheckResult> check_process_ports(const std::string& process);

// The verdict for one port from its state and the firewall, shared by the functions above.
PortCheckRow assess_port(const LocalPortState& state, const FirewallSnapshot& firewall);

// The rules that name this program: those Windows added when SAT listened and the engineer answered
// its prompt, listed so they can be removed.
std::vector<FirewallRule> rules_for_program(const FirewallSnapshot& firewall, const std::string& program_path);

// This executable's full path, for the firewall verdict on SAT's own listener.
std::string current_executable_path();

} // namespace support_assist
