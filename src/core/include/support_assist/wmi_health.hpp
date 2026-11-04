#pragma once

// WMI health (Windows, read-only): the Winmgmt service and each service it depends on, the WMI
// repository's consistency (winmgmt /verifyrepository, run only when SAT is elevated) and size, a
// timed probe of each namespace Veeam reads, and the WMI faults Windows logged in the last days.
// The namespaces, error meanings, events and limits are data (config/checks/wmi-health.json). For
// another machine the service and namespace stages run against it; the repository and the event
// logs are read on this machine only. On other systems the run returns a failure.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/json.hpp"
#include "support_assist/progress.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

inline constexpr const char* kWmiHealthPass = "Pass";
inline constexpr const char* kWmiHealthFinding = "Finding";
inline constexpr const char* kWmiHealthNotPresent = "Not present";
inline constexpr const char* kWmiHealthNeedsAdministrator = "Needs administrator";
inline constexpr const char* kWmiHealthThisMachineOnly = "This machine only";
// WMI-Activity events whose result code the data file marks routine: listed, not a finding.
inline constexpr const char* kWmiHealthRoutine = "Routine";

struct WmiHealthOptions {
  std::string machine = ".";
};

// One result: the stage (Service, Repository, Namespaces, Recent faults), what was checked, what was
// found, and one of the five statuses above.
struct WmiHealthRow {
  std::string stage;
  std::string finding;
  std::string detail;
  std::string status;
};

struct WmiHealthReport {
  std::string machine;       // as given
  bool this_machine = true;  // ".", localhost or this computer's own name
  bool elevated = false;
  bool cancelled = false;
  std::vector<WmiHealthRow> rows;
};

Result<WmiHealthReport> run_wmi_health(const WmiHealthOptions& options,
                                       const CancellationToken& cancel,
                                       ProgressCallback progress = {});

// "WBEM_E_ACCESS_DENIED: This account is not allowed to do that in WMI." for a code the data file
// lists; empty for any other.
std::string wmi_error_meaning(std::int64_t hresult);
// ".", localhost, an empty name, a loopback address, or one of this computer's names. WMI signs in
// on this computer as the account SAT runs as and refuses another account for it.
bool is_this_computer(std::string_view machine);
bool wmi_health_has_finding(const WmiHealthReport& report);
// "WMI health on this machine: 9 Pass, 2 Finding, 1 Needs administrator."
std::string wmi_health_summary(const WmiHealthReport& report);

namespace wmi_health_detail {

struct HealthNamespace {
  std::string name_space;
  std::string role;
  std::string why;
  std::string probe;
  std::string absent_means;
};

struct HealthError {
  std::uint32_t code = 0;
  std::string name;
  std::string meaning;
  bool routine = false;
};

struct HealthEvent {
  std::string log;
  std::string provider;
  std::uint32_t id = 0;
  std::string meaning;
};

struct HealthData {
  double repository_limit_gb = 4.0;
  std::int64_t slow_probe_ms = 2000;
  int event_days = 7;
  std::vector<HealthNamespace> namespaces;
  std::vector<HealthError> errors;
  std::vector<HealthEvent> events;
};

HealthData parse_health_data(const JsonValue& value);
// wmi-health.json, read once.
const HealthData& health_data();

// "0x8004100E".
std::string hresult_text(std::int64_t hresult);
// "0x80041003", "0X80041003" as the number; nothing for any other text.
std::optional<std::uint32_t> parse_hex_code(std::string_view text);
// A known code as "0x8004100E WBEM_E_INVALID_NAMESPACE: The namespace is not on the machine.";
// any other as the code alone.
std::string decode_wmi_error(std::int64_t hresult, const HealthData& data);

// The ResultCode and ClientProcessId of a 5858 event, from its message ("ResultCode = 0x80041032")
// or its XML ("<Data Name='ResultCode'>0x80041032</Data>").
std::optional<std::uint32_t> result_code_from_message(std::string_view message);
std::optional<std::uint32_t> client_process_from_message(std::string_view message);
std::string first_line(std::string_view text);

struct FaultEvent {
  std::int64_t time_unix_millis = 0;
  std::string message;
};

struct FaultGroup {
  std::optional<std::uint32_t> result_code;  // none for the events whose message carries no code
  std::size_t count = 0;
  std::int64_t newest_unix_millis = 0;
  std::string newest_message;
};

// The events by ResultCode, the largest group first; the events without one form one group, last.
std::vector<FaultGroup> group_by_result_code(const std::vector<FaultEvent>& events);
// The Recent faults rows for one event: a Pass row when there are none in the window, else a
// Finding row per group. left_out counts the events of SAT's own process that were not counted.
std::vector<WmiHealthRow> fault_rows(const HealthEvent& event, const std::vector<FaultEvent>& events,
                                     std::size_t left_out, const HealthData& data);
// Whether an event log match's signature ("event-id:5858;provider:Name") names the provider.
bool signature_has_provider(std::string_view signature, std::string_view provider);

// "43.1 MB", "3.70 GB".
std::string size_text(std::uint64_t bytes);
// The repository's size against the limit: a Finding from 90% of it.
WmiHealthRow repository_size_row(std::uint64_t bytes, double limit_gb);

// One namespace probe's row: Pass with the time, Finding when slower than slow_probe_ms, Not
// present when the namespace is absent, Needs administrator for 0x80041003 and E_ACCESSDENIED, and a
// Finding with the decoded error for anything else. error_text is the failure as described.
WmiHealthRow probe_row(const HealthNamespace& name_space, bool succeeded, std::int64_t hresult,
                       std::string_view operation, std::string_view error_text, std::int64_t elapsed_ms,
                       const HealthData& data);
// A failure after which the other namespaces are not probed: the RPC server did not answer.
bool stops_probes(std::int64_t hresult);
// "1,234 ms".
std::string milliseconds_text(std::int64_t milliseconds);

// The service manager's numbers as words: state 4 "Running", start type 2 "Automatic".
std::string service_state_text(unsigned long state);
std::string start_type_text(unsigned long start_type, bool delayed);
// A service that is not running, or is disabled.
bool service_is_finding(unsigned long state, unsigned long start_type);

// ".", "localhost", an empty name, a loopback address, or one of this computer's own names.
bool is_this_machine(std::string_view machine, const std::vector<std::string>& own_names);

} // namespace wmi_health_detail

} // namespace support_assist
