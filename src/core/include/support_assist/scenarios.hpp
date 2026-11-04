#pragma once

// Guided Diagnostics as scenarios: a symptom the engineer recognises, the inputs it needs, and
// steps in order, each one of SAT's read-only checks with what a pass, an attention and a fail mean
// in Veeam's terms. A decisive step that fails stops the run unless keep_going is set. The scenarios
// are data (config/checks/scenarios.json); the checks are the existing core functions. A scenario
// also says which machine to run it on and what to set up first, and each step says what it checks,
// so the hint card, the Help article and the User Guides can describe a run before it starts.

#include "support_assist/cancellation.hpp"
#include "support_assist/firewall.hpp"
#include "support_assist/local_ports.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/progress.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct ScenarioInput {
  std::string id;
  std::string label;
  std::string hint;
  std::string default_value;
  bool optional = false; // left empty, the steps that use it still run
  std::string about;     // what the field is for, on the card's OPTIONS
  // The starting value by the major version of Veeam Backup & Replication installed here ("12",
  // "13"); default_value when none is installed or its version is not listed.
  std::map<std::string, std::string> default_by_vbr;
};

// The major version of Veeam Backup & Replication installed on this machine ("13"), from its
// Uninstall entry; empty when none is installed. Read once.
const std::string& local_vbr_major_version();

namespace scenarios_detail {
// "13" from "13.1.4.1"; empty when the text does not start with a number.
std::string major_version(std::string_view version);
// The input's starting value for a VBR major version (empty: none installed).
std::string input_default(const ScenarioInput& input, const std::string& vbr_major);
} // namespace scenarios_detail

// What one result of a step means, in the scenario data's words. Empty text: the step has none for
// that result.
struct ScenarioMeaningText {
  std::string meaning;
  std::string next;
  std::vector<std::string> links; // the pages the meaning follows
};

struct ScenarioStepInfo {
  std::string title;
  std::string does; // exactly what the step checks, with the ports, query, events or service it uses
  bool decisive = false;
  bool windows_only = false;
  ScenarioMeaningText pass;
  ScenarioMeaningText attention;
  ScenarioMeaningText fail;
};

struct ScenarioDefinition {
  std::string id;
  std::string title;
  std::string symptom;
  std::string run_on; // the machine to run it on, and why
  // What has to be in place before Run, in order, each line naming the machine it is done on.
  std::vector<std::string> setup;         // every edition
  std::vector<std::string> setup_windows; // added on Windows
  std::vector<std::string> setup_linux;   // added on Linux
  std::vector<std::string> products; // any of them detected; empty: always
  bool windows_only = false;
  std::vector<std::string> aliases;  // the old guided diagnostic ids it replaces
  std::vector<ScenarioInput> inputs;
  std::vector<std::string> step_titles;
  std::vector<ScenarioStepInfo> steps; // in run order, one for each of step_titles
};

const std::vector<ScenarioDefinition>& scenario_catalog();
// The scenarios for this platform and the products found here.
std::vector<ScenarioDefinition> available_scenarios(const ProductDiscoveryContext& context);
// A scenario by its id or an old guided diagnostic id; nullptr when unknown.
const ScenarioDefinition* find_scenario(const std::string& id);

struct ScenarioStepResult {
  std::size_t number = 0;
  std::string title;
  std::string status; // Pass, Attention, Fail, Not applicable, Could not check, Not run
  std::string found;  // what the check read
  std::string meaning; // the scenario's text for the status: Pass, Attention or Fail
  std::string next;
  std::vector<std::string> links;
  bool decisive = false;
};

struct ScenarioResult {
  std::string id;
  std::string title;
  std::vector<ScenarioStepResult> steps;
  std::string result;    // "Stopped at step 3 of 5: ... (Fail)", "All 5 steps passed."
  std::string overall;   // Pass, Attention, Fail
  std::string case_note; // the block an engineer pastes into the case
};

ScenarioResult run_scenario(const std::string& id, const std::map<std::string, std::string>& inputs, bool keep_going,
                            const CancellationToken& cancel, ProgressCallback progress = {});

struct ScenarioCheckOutcome {
  ScenarioCheckOutcome(std::string status_value = {}, std::string found_value = {},
                       std::vector<std::string> links_value = {})
      : status(std::move(status_value)), found(std::move(found_value)), links(std::move(links_value)) {}
  std::string status; // Pass, Attention, Fail, Not applicable, Could not check
  std::string found;
  std::vector<std::string> links; // sources for what was found, added to the step's own
};

// One check of the table by its id with its parameters, as a step runs it ("payload.sat" takes host,
// port and mib). An unknown id reads Could not check.
ScenarioCheckOutcome run_scenario_check(const std::string& check, const std::map<std::string, std::string>& params,
                                        const CancellationToken& cancel);

struct SqlCheckReport;

// A SQL check's rows as one step's status: Fail when a row failed, then Attention, then Could not
// check when a row could not be read, otherwise Pass. The found text is the rows that set it.
ScenarioCheckOutcome scenario_sql_outcome(const SqlCheckReport& report);

// The judgements of the RPC or port exhaustion scenario that need no operating system call: each takes
// what was read and the limits from config/checks/port-exhaustion.json, so a test can give them crafted
// input.
namespace scenarios_detail {

struct PortEventRule {
  std::string group; // "ports", "pool" or "rpc": the step that reads it
  std::string log;
  std::vector<std::string> providers; // any of them; empty for any provider
  std::uint32_t id = 0;
  std::uint32_t fail_within_hours = 0; // 0: this event never fails the step
  std::uint32_t attention_within_days = 0;
  std::string meaning;
  std::string source; // the page that documents the event; may be empty
};

struct PortLimits {
  bool loaded = false; // false when the data file is missing
  std::uint32_t default_start = 0;
  std::uint32_t default_ports = 0;
  std::uint32_t attention_below_ports = 0;
  std::uint32_t fail_below_ports = 0;
  std::uint32_t mover_start = 0;
  std::uint32_t mover_ports = 0;
  std::uint32_t time_wait_default = 0;
  std::uint32_t time_wait_min = 0;
  std::uint32_t time_wait_max = 0;
  std::uint32_t usage_attention_percent = 0;
  std::uint32_t usage_fail_percent = 0;
  std::string usage_note; // what the socket table leaves out
  std::uint32_t holder_top = 0;
  std::uint32_t holder_share_percent = 0;
  std::uint32_t close_wait_attention = 0;
  std::uint32_t time_wait_total_minimum = 0;
  std::uint32_t time_wait_remote_share_percent = 0;
  std::uint32_t handles_attention = 0;
  std::uint32_t handles_fail = 0;
  std::uint32_t handles_fail_port_share_percent = 0;
  std::uint32_t nonpaged_attention_percent = 0;
  std::vector<std::string> handle_exclusions;
  std::uint32_t rpc_minimum_ports = 0;
  std::uint32_t rpc_in_use_attention_percent = 0;
  std::vector<std::string> rpc_services;
  std::uint32_t epmap_port = 0;
  std::string epmap_service;
  std::uint32_t event_days = 0;
  std::vector<PortEventRule> events;
};

// The limits from config/checks/port-exhaustion.json, read once.
const PortLimits& port_limits();

// A run of ports: start through start + count - 1.
struct PortRange {
  std::uint32_t start = 0;
  std::uint32_t count = 0;
};

// What step 1 read: the TCP and UDP dynamic ranges and the two Tcpip registry values.
struct DynamicRangeFacts {
  bool tcp_read = false;
  PortRange tcp;
  std::string tcp_error; // why the TCP range could not be read
  bool udp_read = false;
  PortRange udp;
  std::string udp_error;
  std::optional<std::uint32_t> max_user_port;
  std::optional<std::uint32_t> time_wait_seconds;
};
ScenarioCheckOutcome evaluate_dynamic_range(const DynamicRangeFacts& facts, const PortLimits& limits);

// The sockets of one protocol with a local port inside the range, counted on the local address that
// holds the most distinct ports. A socket bound to every address (0.0.0.0, ::) holds its port on
// each address of its family.
struct PortUsage {
  std::size_t range_ports = 0;
  std::size_t ports_in_use = 0;
  std::string address;
  std::size_t sockets = 0;                   // the sockets behind those ports
  std::map<std::string, std::size_t> states; // sockets by state
};
PortUsage port_usage(const std::vector<LocalSocket>& sockets, PortProtocol protocol, PortRange range);
ScenarioCheckOutcome evaluate_port_usage(const std::vector<LocalSocket>& sockets, PortRange tcp, PortRange udp,
                                         const PortLimits& limits);

// TIME_WAIT sockets inside the range have no owner, so they are grouped by the remote endpoint they
// connected to. likely_process names the process with the most live connections to that endpoint.
struct RemoteGroup {
  std::string address;
  std::uint16_t port = 0;
  std::size_t count = 0;
  std::string likely_process;
  std::uint32_t likely_pid = 0;
};
std::vector<RemoteGroup> time_wait_by_remote(const std::vector<LocalSocket>& sockets, PortRange range, std::size_t top);

// The sockets a process holds inside the range (every state but TIME_WAIT), and its CLOSE_WAIT sockets
// on any port, most held first.
struct ProcessHold {
  std::uint32_t pid = 0;
  std::string name;
  std::string services;
  std::size_t sockets = 0;
  std::size_t close_wait = 0;
};
std::vector<ProcessHold> port_holders(const std::vector<LocalSocket>& sockets, PortRange tcp);
// wanted is a process name (with or without .exe) or a PID; empty for the top processes only.
ScenarioCheckOutcome evaluate_port_holders(const std::vector<LocalSocket>& sockets, PortRange tcp,
                                           const std::string& wanted, const std::string& veeam_prefix,
                                           const PortLimits& limits);

struct HandleCount {
  std::uint32_t pid = 0;
  std::string name;
  std::uint32_t handles = 0;
};
struct PoolFacts {
  bool read = false;
  std::uint64_t nonpaged_bytes = 0;
  std::uint64_t paged_bytes = 0;
  std::uint64_t physical_bytes = 0;
  std::uint64_t total_handles = 0;
};
ScenarioCheckOutcome evaluate_pool_pressure(const std::vector<HandleCount>& handles, const PoolFacts& pool,
                                            const std::vector<LocalSocket>& sockets, PortRange tcp,
                                            const PortLimits& limits);

// The entries of the RPC Internet Ports value: "5984" or "5000-5100". Overlapping ranges are merged.
struct RpcPortList {
  std::vector<std::pair<std::uint32_t, std::uint32_t>> ranges; // first, last
  std::size_t total = 0;
  bool valid = true;
  std::string invalid_entry; // the first entry that is not a port or a range of 0 to 65535
};
RpcPortList parse_rpc_port_list(const std::vector<std::string>& entries);
// The listed ports that some TCP socket holds as its local port.
std::size_t rpc_ports_in_use(const RpcPortList& list, const std::vector<LocalSocket>& sockets);

struct RpcInternetFacts {
  bool key_present = false;
  bool ports_present = false;
  std::vector<std::string> ports;
  std::string ports_available;    // PortsInternetAvailable: Y or N; empty when absent
  std::string use_internet_ports; // UseInternetPorts: Y or N; empty when absent
};
ScenarioCheckOutcome evaluate_rpc_ports(const RpcInternetFacts& facts, const std::vector<LocalSocket>& sockets,
                                        const PortLimits& limits);

// One event found in a log: its id, provider and time.
struct EventHit {
  std::uint32_t id = 0;
  std::string provider;
  std::int64_t unix_millis = 0;
};
// The events of one group of port-exhaustion.json against the hits found: Fail for an event with a
// fail window that has a hit inside it, else Attention for any hit inside its days, else Pass.
ScenarioCheckOutcome tally_events(const std::string& group, const std::vector<EventHit>& hits,
                                  std::int64_t now_unix_millis, const PortLimits& limits);

// The firewall's answer for inbound TCP to the RPC endpoint mapper and to the dynamic range, for
// each active profile. listener_program and listener_services describe what listens on the port.
ScenarioCheckOutcome evaluate_rpc_firewall(const FirewallSnapshot& firewall, PortRange dynamic_tcp,
                                           const std::string& listener_program, const std::string& listener_services,
                                           const PortLimits& limits);

} // namespace scenarios_detail

} // namespace support_assist
