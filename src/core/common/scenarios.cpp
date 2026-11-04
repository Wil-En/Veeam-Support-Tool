// Guided Diagnostics' scenario runner: the scenarios from config/checks/scenarios.json, the checks
// they name (thin wrappers over the existing core functions), and the result and case note.
#include "support_assist/scenarios.hpp"

#include "support_assist/installed_products.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/firewall.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/json.hpp"
#include "support_assist/local_ports.hpp"
#include "support_assist/log_search.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/network.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/service_channel.hpp"
#include "support_assist/sql_check.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/volume_check.hpp"
#include "support_assist/wmi.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <optional>
#include <set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef PSAPI_VERSION
#define PSAPI_VERSION 1
#endif
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <unistd.h>
#endif

namespace support_assist {

namespace {

struct Step {
  std::string title;
  std::string check;
  std::map<std::string, std::string> params;
  bool decisive = false;
  bool windows_only = false;
  std::map<std::string, ScenarioMeaningText> meanings; // by status: Fail, Attention, Pass
};

struct Scenario {
  ScenarioDefinition definition;
  std::vector<Step> steps;
};

const std::vector<Scenario>& scenarios() {
  static const std::vector<Scenario> parsed = [] {
    std::vector<Scenario> list;
    const JsonValue& value = data_file("scenarios.json");
    std::map<std::string, std::string> urls;
    for (const auto& [key, source] : value["sources"].members())
      urls[key] = source["url"].as_string();
    for (const JsonValue& item : value["scenarios"].items()) {
      Scenario scenario;
      ScenarioDefinition& definition = scenario.definition;
      definition.id = item["id"].as_string();
      definition.title = item["title"].as_string();
      definition.symptom = item["symptom"].as_string();
      definition.run_on = item["run_on"].as_string();
      definition.setup = item["setup"].string_items();
      definition.setup_windows = item["setup_windows"].string_items();
      definition.setup_linux = item["setup_linux"].string_items();
      definition.products = item["products"].string_items();
      definition.windows_only = item["platform"].as_string() == "windows";
      definition.aliases = item["aliases"].string_items();
      for (const JsonValue& input : item["inputs"].items()) {
        ScenarioInput field{input["id"].as_string(), input["label"].as_string(), input["hint"].as_string(),
                            input["default"].as_string(), input["optional"].as_bool(), input["about"].as_string(), {}};
        for (const auto& [major, start] : input["default_by_vbr"].members())
          field.default_by_vbr[major] = start.as_string();
        definition.inputs.push_back(std::move(field));
      }
      for (const JsonValue& entry : item["steps"].items()) {
        Step step;
        step.title = entry["title"].as_string();
        step.check = entry["check"].as_string();
        for (const auto& [key, parameter] : entry["params"].members())
          step.params[key] = parameter.as_string();
        step.decisive = entry["decisive"].as_bool(false);
        step.windows_only = entry["platform"].as_string() == "windows";
        for (const char* status : {"fail", "attention", "pass"}) {
          const JsonValue& block = entry[status];
          if (block.is_null())
            continue;
          ScenarioMeaningText meaning{block["meaning"].as_string(), block["next"].as_string(), {}};
          for (const std::string& source : block["sources"].string_items()) {
            const auto url = urls.find(source);
            if (url != urls.end())
              meaning.links.push_back(url->second);
          }
          const std::string key = std::string(status) == "fail" ? "Fail" : std::string(status) == "attention" ? "Attention" : "Pass";
          step.meanings[key] = std::move(meaning);
        }
        ScenarioStepInfo info;
        info.title = step.title;
        info.does = entry["does"].as_string();
        info.decisive = step.decisive;
        info.windows_only = step.windows_only;
        for (const auto& [status, meaning] : step.meanings) {
          (status == "Pass" ? info.pass : status == "Attention" ? info.attention : info.fail) = meaning;
        }
        definition.steps.push_back(std::move(info));
        definition.step_titles.push_back(step.title);
        scenario.steps.push_back(std::move(step));
      }
      if (!definition.id.empty())
        list.push_back(std::move(scenario));
    }
    return list;
  }();
  return parsed;
}

// ------------------------------------------------------------------------------------- checks

struct Outcome {
  Outcome(std::string status_value = {}, std::string found_value = {}, std::vector<std::string> links_value = {})
      : status(std::move(status_value)), found(std::move(found_value)), links(std::move(links_value)) {}
  std::string status; // Pass, Attention, Fail, Not applicable, Could not check
  std::string found;
  std::vector<std::string> links; // sources for what was found, added to the step's own
};

using Params = std::map<std::string, std::string>;

std::string param(const Params& params, const std::string& key) {
  const auto found = params.find(key);
  return found == params.end() ? std::string() : std::string(trim(found->second));
}

std::string joined(const std::vector<std::string>& items, const std::string& separator = ", ") {
  std::string text;
  for (const std::string& item : items)
    text += (text.empty() ? "" : separator) + item;
  return text;
}

// Digits grouped in threes: 16384 reads "16,384".
std::string thousands(unsigned long long value) {
  std::string digits = std::to_string(value);
  for (std::size_t at = digits.size(); at > 3U; at -= 3U)
    digits.insert(at - 3U, ",");
  return digits;
}

// A part of a whole as a percentage with one decimal: 61 of 1000 reads "6.1".
std::string percent_text(unsigned long long part, unsigned long long whole) {
  const unsigned long long tenths = whole == 0U ? 0U : part * 1000U / whole;
  return std::to_string(tenths / 10U) + "." + std::to_string(tenths % 10U);
}

// Whether part is percent or more of whole, in whole numbers.
bool share_at_least(unsigned long long part, unsigned long long whole, unsigned long long percent) {
  return whole != 0U && part * 100U >= whole * percent;
}

std::string mib_text(std::uint64_t bytes) {
  return thousands(bytes / 1048576U) + " MiB";
}

std::string range_text(const scenarios_detail::PortRange& range) {
  return std::to_string(range.start) + " to " + std::to_string(range.start + range.count - 1U) + " (" +
         thousands(range.count) + " ports)";
}

std::uint32_t json_count(const JsonValue& value) {
  const double number = value.as_number(0.0);
  return number <= 0.0 ? 0U : static_cast<std::uint32_t>(number);
}

bool same_name(const std::string& left, const std::string& right) {
  return ascii_lower(left) == ascii_lower(right);
}

// A port number from digits only, 0 to 65535.
bool parse_port_number(const std::string& text, std::uint32_t& port) {
  if (text.empty() || text.size() > 5U)
    return false;
  std::uint32_t value = 0;
  for (const char c : text) {
    if (c < '0' || c > '9')
      return false;
    value = value * 10U + static_cast<std::uint32_t>(c - '0');
  }
  if (value > 65535U)
    return false;
  port = value;
  return true;
}

bool is_wildcard_address(const std::string& address) {
  return address == "0.0.0.0" || address == "::";
}

bool is_decimal_text(const std::string& text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; });
}

// A local port spec of a firewall rule that covers the whole range: "*", the keyword RPC (RPC
// dynamic ports), or a range that holds it.
bool spec_covers_range(const std::string& spec, std::uint32_t first, std::uint32_t last) {
  const std::string folded = ascii_lower(trim(spec));
  if (folded.empty() || folded == "*" || folded == "any")
    return true;
  for (const std::string& token : split(folded, ',')) {
    const std::string part = trim(token);
    if (part == "rpc")
      return true;
    const std::size_t dash = part.find('-');
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    if (dash != std::string::npos && parse_port_number(trim(part.substr(0, dash)), low) &&
        parse_port_number(trim(part.substr(dash + 1U)), high) && low <= first && high >= last)
      return true;
  }
  return false;
}

// Inbound TCP to the dynamic range on one profile: the decision and the rule or default behind it. A
// rule for the keyword RPC allows the range for the programs it names.
std::pair<FirewallDecision, std::string> rpc_dynamic_decision(const FirewallSnapshot& firewall,
                                                              const FirewallProfileState& profile,
                                                              const scenarios_detail::PortRange& range) {
  if (!profile.enabled)
    return {FirewallDecision::firewall_off, "the firewall is off for this profile"};
  if (profile.block_all_inbound)
    return {FirewallDecision::blocked, "every inbound connection is blocked on this profile"};
  const std::uint32_t first = range.start;
  const std::uint32_t last = range.start + range.count - 1U;
  const FirewallRule* allow = nullptr;
  const FirewallRule* scoped = nullptr;
  std::size_t scoped_count = 0;
  const auto any_of_text = [](const std::string& text) {
    const std::string folded = trim(text);
    return folded.empty() || folded == "*";
  };
  for (const FirewallRule& rule : firewall.rules) {
    if (!rule.enabled || (profile.mask != 0U && (rule.profiles & profile.mask) == 0U))
      continue;
    if (!rule.zone.empty() && rule.zone != profile.name)
      continue;
    if (rule.protocol != 256 && rule.protocol != 6)
      continue;
    if (!spec_covers_range(rule.local_ports, first, last) || !firewall_detail::rule_applies_generally(rule))
      continue;
    if (!rule.allow) {
      // A block rule decides only when it names no program, client or address.
      if (any_of_text(rule.program) && any_of_text(rule.remote_addresses) && any_of_text(rule.local_addresses))
        return {FirewallDecision::blocked, "blocked by rule \"" + rule.name + "\""};
      continue;
    }
    // A rule for one program on these ports lets that program in, not the RPC servers in general,
    // unless it names the RPC dynamic ports keyword (how Windows lets each RPC server in) or the
    // program is svchost.exe, which hosts the RPC services.
    const bool rpc_keyword = [&rule]() {
      for (const std::string& token : split(rule.local_ports, ','))
        if (ascii_lower(trim(token)) == "rpc")
          return true;
      return false;
    }();
    const std::string rule_program = ascii_lower(trim(rule.program));
    const bool rpc_host = rule_program.size() >= 11U &&
                          rule_program.compare(rule_program.size() - 11U, 11U, "svchost.exe") == 0;
    if (!any_of_text(rule.program) && !rpc_keyword && !rpc_host) {
      if (scoped == nullptr)
        scoped = &rule;
      ++scoped_count;
      continue;
    }
    if (allow == nullptr)
      allow = &rule;
  }
  if (allow != nullptr)
    return {FirewallDecision::allowed, "allowed by rule \"" + allow->name + "\""};
  const std::string scoped_text =
      scoped == nullptr ? std::string()
                        : "; " + std::to_string(scoped_count) + (scoped_count == 1U ? " rule allows" : " rules allow") +
                              " one program each on these ports, such as \"" + scoped->name + "\"";
  if (profile.inbound_blocked_by_default)
    return {FirewallDecision::blocked,
            "no rule allows every program on it; inbound connections are blocked unless a rule allows them" + scoped_text};
  return {FirewallDecision::allowed, "inbound connections are allowed by default on this profile" + scoped_text};
}

Outcome name_resolve(const Params& params, const CancellationToken& cancel) {
  const std::string name = param(params, "name");
  if (name.empty())
    return {"Could not check", "No name was given."};
  const NameCheckResult result = check_name(name, cancel);
  if (result.addresses.empty())
    return {"Fail", name + " does not resolve from this machine" +
                        (result.resolver_error.empty() ? std::string(".") : ": " + result.resolver_error + ".")};
  std::string found = name + " resolves to " + joined(result.addresses) +
                      (result.source.empty() ? std::string() : " (" + result.source + ")") + ".";
  if (!result.notes.empty())
    return {"Attention", found + " " + joined(result.notes, " ")};
  return {"Pass", found};
}

Outcome time_skew(const Params& params, const CancellationToken& cancel) {
  const TimeCheckResult result = check_time(param(params, "server"), cancel);
  if (!result.sntp.answered)
    return {"Could not check", (result.sntp.server.empty() ? std::string("No time server") : result.sntp.server) +
                                   " did not answer SNTP" + (result.sntp.error.empty() ? std::string(".") : ": " + result.sntp.error + ".")};
  const double seconds = std::fabs(result.sntp.offset_ms) / 1000.0;
  char text[160];
  std::snprintf(text, sizeof(text), "This machine and %s are %.3f s apart.", result.sntp.server.c_str(), seconds);
  return {seconds > 300.0 ? "Fail" : seconds > 60.0 ? "Attention" : "Pass", text};
}

Outcome tcp_ports(const std::string& host, const std::vector<std::uint16_t>& ports, const CancellationToken& cancel) {
  std::vector<std::string> open;
  std::vector<std::string> closed;
  for (const std::uint16_t port : ports) {
    if (cancel.is_cancelled())
      break;
    TcpPortTestOptions options;
    options.host = host;
    options.port = port;
    options.timeout = std::chrono::milliseconds(3000);
    options.detect_sat_listener = false;
    auto result = test_tcp_port(options, cancel);
    (result.ok() && result.value().connected ? open : closed).push_back(std::to_string(port));
  }
  if (cancel.is_cancelled())
    return {"Could not check", "Cancelled."};
  if (closed.empty())
    return {"Pass", "Open on " + host + ": " + joined(open) + "."};
  return {"Fail", "Closed or filtered on " + host + ": " + joined(closed) + "." +
                      (open.empty() ? std::string() : " Open: " + joined(open) + ".")};
}

bool tcp_port_answers(const std::string& host, std::uint16_t port, const CancellationToken& cancel) {
  TcpPortTestOptions options;
  options.host = host;
  options.port = port;
  options.timeout = std::chrono::milliseconds(3000);
  options.detect_sat_listener = false;
  auto result = test_tcp_port(options, cancel);
  return result.ok() && result.value().connected;
}

// The system whose entries of a role are tested: the one given, else the one the role's id names
// (agent-windows, agent-linux); empty when neither says.
std::string server_system(const std::string& given, const std::string& role) {
  const std::string chosen = ascii_lower(given);
  if (chosen == "windows" || chosen == "linux")
    return chosen;
  const std::string id = ascii_lower(role);
  const auto ends_with = [&id](const std::string& tail) {
    return id.size() >= tail.size() && id.compare(id.size() - tail.size(), tail.size(), tail) == 0;
  };
  if (ends_with("-windows"))
    return "windows";
  if (ends_with("-linux"))
    return "linux";
  return {};
}

// The role's TCP entries for the server's system, each checked as the Veeam page states it: a range
// ("6184-6195") is a service that takes the first free port in it, so any one answering is enough; a
// list ("445,135") is each port. A closed required port fails; a closed optional one, for a feature
// the server may not use, needs attention. The ranges held only while a job moves data are left out.
// The entries are those of the server's system, not of the machine SAT runs on.
Outcome port_role(const Params& params, const CancellationToken& cancel) {
  const std::string host = param(params, "host");
  const std::string role = param(params, "role");
  if (host.empty())
    return {"Could not check", "No server was given."};
  const std::string given = param(params, "system");
  const std::string system = server_system(given, role);
  // The VBR version's own guide when one is chosen; both, each port saying its version, when none is.
  std::string version = param(params, "version");
  if (version.rfind("VBR ", 0) == 0)
    version = version.substr(4);
  if (const auto dot = version.find('.'); dot != std::string::npos)
    version = version.substr(0, dot);
  const auto presets = port_presets_for(system, version);
  const PortPreset* preset = find_port_preset(presets, role);
  if (preset == nullptr)
    return {"Could not check", "Unknown server role: " + role + "."};
  if (system.empty() &&
      std::any_of(preset->entries.begin(), preset->entries.end(), [](const PortPresetEntry& entry) { return !entry.platform.empty(); }))
    return {"Could not check", preset->name + " listens on different ports on Windows and on Linux. Choose the server's system, then run it again."};
  if (std::none_of(preset->entries.begin(), preset->entries.end(), [](const PortPresetEntry& entry) { return entry.tcp && !entry.dynamic && !entry.loopback; }))
    return {"Not applicable", preset->name + " lists no TCP port to test" +
                                  (system.empty() ? std::string() : std::string(" on a ") + (system == "windows" ? "Windows" : "Linux") + " server") + "."};
  std::vector<std::string> open;
  std::vector<std::string> closed_required;
  std::vector<std::string> closed_optional;
  for (const PortPresetEntry& entry : preset->entries) {
    // A loopback port is held for programs on the server itself; another machine never reaches it.
    if (!entry.tcp || entry.dynamic || entry.loopback || cancel.is_cancelled())
      continue;
    const std::string spec = trim(entry.ports);
    const std::string why = entry.note.empty() ? std::string() : " (" + entry.note + ")";
    if (const auto dash = spec.find('-'); dash != std::string::npos) {
      const long low = std::strtol(spec.substr(0, dash).c_str(), nullptr, 10);
      const long high = std::strtol(spec.substr(dash + 1).c_str(), nullptr, 10);
      std::optional<long> answered;
      for (long port = low; port >= 1 && port <= high && port <= 65535 && port - low < 64 && !answered; ++port) {
        if (cancel.is_cancelled())
          break;
        if (tcp_port_answers(host, static_cast<std::uint16_t>(port), cancel))
          answered = port;
      }
      if (answered)
        open.push_back(std::to_string(*answered) + " (of " + spec + ")");
      else
        (entry.optional ? closed_optional : closed_required).push_back("none of " + spec + why);
      continue;
    }
    if (entry.one_of) {
      std::optional<long> answered;
      for (const std::string& token : split(spec, ',')) {
        const long port = std::strtol(trim(token).c_str(), nullptr, 10);
        if (port < 1 || port > 65535 || cancel.is_cancelled() || answered)
          continue;
        if (tcp_port_answers(host, static_cast<std::uint16_t>(port), cancel))
          answered = port;
      }
      if (answered)
        open.push_back(std::to_string(*answered) + " (of " + spec + ")");
      else
        (entry.optional ? closed_optional : closed_required).push_back("none of " + spec + why);
      continue;
    }
    for (const std::string& token : split(spec, ',')) {
      const long port = std::strtol(trim(token).c_str(), nullptr, 10);
      if (port < 1 || port > 65535 || cancel.is_cancelled())
        continue;
      if (tcp_port_answers(host, static_cast<std::uint16_t>(port), cancel))
        open.push_back(std::to_string(port));
      else
        (entry.optional ? closed_optional : closed_required).push_back(std::to_string(port) + why);
    }
  }
  // A cancelled run has probed some ports and not others, so it has no verdict.
  if (cancel.is_cancelled())
    return {"Could not check", "Cancelled."};
  const bool system_given = !given.empty() && !system.empty();
  std::string found = preset->name + (!system_given ? std::string() : system == "windows" ? " (Windows server)" : " (Linux server)") + ": ";
  found += open.empty() ? std::string("nothing answered on ") + host + "." : "open on " + host + ": " + joined(open) + ".";
  if (!closed_required.empty())
    found += " Closed or filtered: " + joined(closed_required) + ".";
  if (!closed_optional.empty())
    found += " Closed, and optional on the Veeam page: " + joined(closed_optional) + ".";
  const char* status = !closed_required.empty() ? "Fail" : !closed_optional.empty() ? "Attention" : "Pass";
  return {status, found};
}

// RPC and WMI are Windows services: for a server whose system is Linux (given, or named by its
// role) the step has nothing to test.
std::optional<Outcome> linux_server_outcome(const Params& params, const std::string& server, const char* service) {
  if (server_system(param(params, "system"), param(params, "role")) != "linux")
    return std::nullopt;
  return Outcome{"Not applicable", server + " is a Linux server, which has no " + std::string(service) + "."};
}

Outcome rpc_epmap(const Params& params, const CancellationToken& cancel) {
  const std::string host = param(params, "host");
  if (host.empty())
    return {"Could not check", "No server was given."};
  if (auto linux_server = linux_server_outcome(params, host, "RPC endpoint mapper"))
    return *linux_server;
  RpcConnectivityOptions options;
  options.host = host;
  auto result = test_rpc_endpoint_mapper(options, cancel);
  if (!result.ok())
    return {"Fail", describe_error(result.error())};
  if (result.value().endpoint_mapper_accepted)
    return {"Pass", "The RPC endpoint mapper on " + host + " accepted a bind."};
  return {"Fail", "The RPC endpoint mapper on " + host + " did not accept a bind at " + result.value().failure_stage +
                      (result.value().detail.empty() ? std::string(".") : ": " + result.value().detail + ".")};
}

Outcome wmi_query(const Params& params, const CancellationToken& cancel) {
  WmiConnectivityDiagnosticOptions options;
  options.machine = param(params, "machine").empty() ? "." : param(params, "machine");
  if (auto linux_server = linux_server_outcome(params, options.machine, "WMI"))
    return *linux_server;
  auto result = run_wmi_connectivity_diagnostic(options, cancel);
  if (!result.ok())
    return {"Fail", describe_error(result.error())};
  if (!result.value().query_succeeded)
    return {"Fail", "The WMI query on " + options.machine + " returned no answer."};
  return {"Pass", "WMI on " + result.value().computer_name + " answered: " + result.value().os_caption + " " +
                      result.value().os_version + "."};
}

Outcome tls_handshake(const Params& params, const CancellationToken& cancel) {
  const std::string host = param(params, "host");
  const int port = std::atoi(param(params, "port").c_str());
  if (host.empty() || port <= 0 || port > 65535)
    return {"Could not check", "A server and a port are needed."};
  TlsProbeOptions options;
  options.host = host;
  options.port = static_cast<std::uint16_t>(port);
  options.expected_fingerprint = param(params, "fingerprint");
  // With no fingerprint given on a backup server, the certificate VBR is configured with is the one
  // expected: the thumbprint VBR records, found in the LocalMachine\My store.
  std::string expected_source = options.expected_fingerprint.empty() ? std::string() : "the fingerprint given";
  if (options.expected_fingerprint.empty()) {
    const auto products = detect_products(native_product_discovery_context());
    if (std::any_of(products.begin(), products.end(), [](const DetectedProduct& product) { return product.definition.id == "vbr"; })) {
      auto configured = read_local_vbr_configured_certificate(cancel);
      if (configured.ok() && configured.value().available) {
        options.expected_fingerprint = configured.value().sha1_thumbprint;
        expected_source = configured.value().source;
      }
    }
  }
  auto result = test_tls_handshake(options, cancel);
  if (!result.ok())
    return {"Fail", describe_error(result.error())};
  const TlsProbeResult& probe = result.value();
  if (!probe.handshake_completed)
    return {"Fail", "The TLS handshake with " + host + ":" + std::to_string(port) + " failed at " + probe.failure_stage +
                        (probe.failure_reason.empty() ? std::string(".") : ": " + probe.failure_reason + ".")};
  std::string found = probe.negotiated_version + " with " + probe.negotiated_cipher_suite + ". Certificate " +
                      probe.certificate.subject + ", issued by " + probe.certificate.issuer + ", valid until " +
                      probe.certificate.valid_until + ", SHA-256 " + probe.certificate.sha256_fingerprint + ".";
  if (!expected_source.empty())
    found += " Expected source: " + expected_source + ".";
  if (probe.certificate.expected_fingerprint_provided && !probe.certificate.expected_fingerprint_matches)
    return {"Fail", "The certificate differs from the one expected. " + found};
  return {"Pass", found};
}

// One connection to a SAT listener on the server with a bounded in-memory payload, sent and checked as
// the Remote Port Checker does it. The step is optional: a server with no SAT listener on the port
// cannot be told from a healthy one, so every outcome without a listener is Could not check. Only a
// listener that answered and then did not verify the payload is a finding.
Outcome payload_sat(const Params& params, const CancellationToken& cancel) {
  const std::string host = param(params, "host");
  if (host.empty())
    return {"Could not check", "No server was given."};
  const int port = std::atoi(param(params, "port").c_str());
  if (port <= 0 || port > 65535)
    return {"Could not check", "A SAT listener port from 1 to 65535 is needed."};
  long mib = std::atol(param(params, "mib").c_str());
  if (mib <= 0)
    mib = 50;
  mib = std::min(mib, 1024L);

  TcpPortTestOptions options;
  options.host = host;
  options.port = static_cast<std::uint16_t>(port);
  options.timeout = std::chrono::milliseconds(3000);
  options.detect_sat_listener = true;
  options.sat_payload_bytes = static_cast<std::uint64_t>(mib) * 1024ULL * 1024ULL;
  // One connection: a listener started without Accept multiple connections stops after the first.
  options.both_families = false;
  options.describe_name_source = false;

  const std::string where = host + " port " + std::to_string(port);
  const std::string pointer = " This step needs SAT's TCP listener running on the server at that port; SETUP says how to start it.";
  auto result = test_tcp_port(options, cancel);
  if (!result.ok())
    return {"Could not check", describe_error(result.error()) + "." + pointer};
  const TcpPortTestResult& tested = result.value();
  const auto attempt = std::find_if(tested.attempts.begin(), tested.attempts.end(),
                                    [](const TcpEndpointAttempt& entry) { return entry.connected; });
  if (!tested.connected || attempt == tested.attempts.end()) {
    std::string reason;
    if (!tested.attempts.empty() && !tested.attempts.back().message.empty())
      reason = " (" + tested.attempts.back().message + ")";
    return {"Could not check", "No connection to " + where + reason + "." + pointer};
  }
  if (!attempt->sat_listener_detected) {
    return {"Could not check", "Something accepted a connection on " + where + " but it is not a SAT listener" +
                                   (attempt->peer_banner.empty() ? std::string() : " (it sent: " + attempt->peer_banner + ")") + "." + pointer};
  }
  if (attempt->sat_payload_validated) {
    std::string found = std::to_string(attempt->sat_payload_bytes / (1024ULL * 1024ULL)) + " MiB went from this machine to the SAT listener on " +
                        where + " and arrived intact: the byte count and SHA-256 matched (" + attempt->sat_payload_sha256 + ").";
    if (attempt->sat_payload_bits_per_second > 0.0)
      found += " Rate " + format_transfer_rate(attempt->sat_payload_bits_per_second) + ".";
    return {"Pass", found};
  }
  std::string reason = attempt->message;
  const std::string marker = "SAT validation: ";
  if (const auto at = reason.find(marker); at != std::string::npos)
    reason = reason.substr(at + marker.size());
  return {"Fail", "The SAT listener on " + where + " answered, but the payload was not verified: " + reason + "."};
}

#ifdef _WIN32
struct ServiceFacts {
  bool found = false;
  bool running = false;
  bool disabled = false;
  bool automatic = false;
  std::string account;
  std::string state = "not installed";
};

ServiceFacts service_facts(const std::string& name) {
  ServiceFacts facts;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr)
    return facts;
  SC_HANDLE service = OpenServiceW(manager, wide_from_utf8(name).c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
  if (service != nullptr) {
    facts.found = true;
    SERVICE_STATUS status{};
    if (QueryServiceStatus(service, &status) != FALSE) {
      facts.running = status.dwCurrentState == SERVICE_RUNNING;
      facts.state = facts.running ? "running" : status.dwCurrentState == SERVICE_STOPPED ? "stopped" : "starting or stopping";
    }
    DWORD needed = 0;
    QueryServiceConfigW(service, nullptr, 0, &needed);
    std::vector<unsigned char> buffer(needed == 0U ? 1U : needed);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buffer.data());
    if (needed != 0U && QueryServiceConfigW(service, config, needed, &needed) != FALSE) {
      facts.disabled = config->dwStartType == SERVICE_DISABLED;
      facts.automatic = config->dwStartType == SERVICE_AUTO_START;
      if (config->lpServiceStartName != nullptr)
        facts.account = utf8_from_wide(config->lpServiceStartName);
    }
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
  return facts;
}
#endif

Outcome service_state(const std::string& name) {
#ifdef _WIN32
  const ServiceFacts facts = service_facts(name);
  if (!facts.found)
    return {"Fail", "The " + name + " service is not installed."};
  const std::string found = "The " + name + " service is " + facts.state +
                            (facts.disabled ? " and disabled" : facts.automatic ? " (automatic start)" : " (manual start)") +
                            (facts.account.empty() ? std::string() : ", as " + facts.account) + ".";
  if (facts.running)
    return {"Pass", found};
  if (facts.disabled)
    return {"Fail", found};
  return {facts.automatic ? "Fail" : "Pass", found};
#else
  return {"Not applicable", name + ": a Windows service."};
#endif
}

Outcome sql_service(const Params& params, const CancellationToken&) {
  const std::string server = param(params, "server");
  if (server.empty())
    return {"Could not check", "No SQL Server was given."};
  if (!sql_server_is_this_host(server))
    return {"Not applicable", server + " is not this machine; run the scenario on the SQL host to read its service."};
  const std::size_t slash = server.find('\\');
  const std::string instance = slash == std::string::npos ? std::string() : server.substr(slash + 1U);
  return service_state(instance.empty() || ascii_lower(instance) == "mssqlserver" ? "MSSQLSERVER" : "MSSQL$" + instance);
}

Outcome vss_writers(const Params& params, const CancellationToken&) {
  const std::string only = param(params, "writer");
  auto result = inspect_vss_writer_health();
  if (!result.ok())
    return {"Could not check", describe_error(result.error()) + " Reading the writers needs SAT run as administrator."};
  std::vector<std::string> failed;
  std::vector<std::string> stable;
  for (const VssWriterInfo& writer : result.value().writers) {
    if (!only.empty() && ascii_lower(writer.name) != ascii_lower(only))
      continue;
    (writer.state == 1 && writer.failure_hresult == 0 ? stable : failed).push_back(writer.name + " (" + writer.state_name + ")");
  }
  if (!only.empty() && failed.empty() && stable.empty())
    return {"Fail", only + " is not among this machine's writers: the SQL Server VSS Writer service may be stopped."};
  if (!failed.empty())
    return {"Fail", "Not stable: " + joined(failed) + "."};
  return {"Pass", only.empty() ? std::to_string(stable.size()) + " writers, all stable." : joined(stable) + "."};
}

Outcome events_recent(const Params& params, const CancellationToken& cancel) {
  WindowsEventLogSearchOptions options;
  options.channel = param(params, "log");
  for (const std::string& id : split(param(params, "ids"), ',')) {
    const int number = std::atoi(std::string(trim(id)).c_str());
    if (number > 0)
      options.event_ids.push_back(static_cast<std::uint32_t>(number));
  }
  std::set<std::string> providers;
  for (const std::string& provider : split(param(params, "providers"), ','))
    providers.insert(ascii_lower(std::string(trim(provider))));
  const int days = std::max(1, std::atoi(param(params, "days").c_str()));
  options.from_utc_ms = unix_millis_now() - static_cast<std::int64_t>(days) * 86400000LL;
  std::size_t count = 0;
  std::string newest;
  auto searched = search_windows_event_log(options, cancel, {}, [&](const LogMatch& match) {
    const std::size_t at = match.signature.find("provider:");
    const std::string provider = at == std::string::npos ? std::string() : ascii_lower(match.signature.substr(at + 9U));
    if (!providers.empty() && providers.count(provider) == 0U)
      return Status::success();
    if (count++ == 0U)
      newest = match.matching_line.substr(0, 200);
    return Status::success();
  });
  if (!searched.ok())
    return {"Could not check", describe_error(searched.error())};
  if (count == 0U)
    return {"Pass", "None in the " + options.channel + " log in the last " + std::to_string(days) + " days."};
  return {"Attention", std::to_string(count) + " in the " + options.channel + " log in the last " + std::to_string(days) +
                           " days. Newest: " + newest};
}

Outcome volume_info(const Params& params, const CancellationToken&) {
  const std::string path = param(params, "path");
  if (path.empty())
    return {"Not applicable", "No repository path was given."};
  auto result = check_volume(path);
  if (!result.ok())
    return {"Could not check", describe_error(result.error())};
  const VolumeInfo& info = result.value();
  std::string found = path + " is on " + (info.kind.empty() ? std::string("a volume") : info.kind) +
                      (info.bus.empty() ? std::string() : " (" + info.bus + ")") + ", " + info.file_system +
                      (info.cluster_size != 0U ? ", " + std::to_string(info.cluster_size / 1024U) + " KB clusters" : std::string()) + ".";
  if (!info.fast_clone_text.empty())
    found += " " + info.fast_clone_text;
  return {info.fast_clone_text.empty() || info.fast_clone ? "Pass" : "Attention", found};
}

Outcome bottleneck(const Params& params, const CancellationToken&) {
  const std::vector<std::pair<std::string, std::string>> parts{
      {"Source", param(params, "source")}, {"Proxy", param(params, "proxy")}, {"Network", param(params, "network")}, {"Target", param(params, "target")}};
  std::string busiest;
  int highest = -1;
  std::vector<std::string> read;
  for (const auto& [name, text] : parts) {
    if (text.empty())
      continue;
    const int value = std::atoi(text.c_str());
    read.push_back(name + " " + std::to_string(value) + "%");
    if (value > highest) {
      highest = value;
      busiest = name;
    }
  }
  if (highest < 0)
    return {"Could not check", "Enter the busy percentages from the job's statistics (the Bottleneck field)."};
  return {"Attention", busiest + " is the bottleneck at " + std::to_string(highest) + "% (" + joined(read) + ")."};
}

Outcome sql_report(const SqlConnection& connection, const std::vector<std::string>& statements,
                   const std::function<SqlCheckReport(const SqlBatchResult&)>& evaluate, const CancellationToken& cancel) {
  if (connection.server.empty())
    return {"Could not check", "No SQL Server was given."};
  auto batch = run_sql_statements(connection, statements, cancel);
  if (!batch.ok())
    return {"Could not check", describe_error(batch.error())};
  const ScenarioCheckOutcome outcome = scenario_sql_outcome(evaluate(batch.value()));
  return {outcome.status, outcome.found};
}

Outcome sql_permissions(const Params& params, const CancellationToken& cancel) {
  SqlConnection connection;
  connection.server = param(params, "server");
  SqlPermissionCheckOptions options;
  options.another_account = param(params, "account");
  options.target = param(params, "against") == "config" ? SqlPermissionTarget::configuration_database
                                                         : SqlPermissionTarget::guest_processing;
  options.configuration_database = param(params, "database");
  return sql_report(connection, sql_permission_statements(options),
                    [&](const SqlBatchResult& batch) { return evaluate_sql_permissions(batch, connection, options); }, cancel);
}

Outcome sql_backups(const Params& params, const CancellationToken& cancel) {
  SqlConnection connection;
  connection.server = param(params, "server");
  connection.database = "msdb";
  SqlBackupOptions options;
  options.database = param(params, "database");
  options.days = std::max(1, std::atoi(param(params, "days").c_str()));
  options.veeam_on_sql_host = veeam_installed_on_sql_host(connection.server);
  return sql_report(connection, sql_backup_statements(options),
                    [&](const SqlBatchResult& batch) { return evaluate_sql_backups(batch, options); }, cancel);
}

Outcome sql_shape(const Params& params, const CancellationToken& cancel) {
  SqlConnection connection;
  connection.server = param(params, "server");
  return sql_report(connection, sql_shape_statements(), [](const SqlBatchResult& batch) { return evaluate_sql_shape(batch); },
                    cancel);
}

Outcome grpc_channel(const Params& params, const CancellationToken& cancel) {
  ServiceChannelOptions options;
  options.product = param(params, "product").empty() ? "agent" : param(params, "product");
  const ServiceChannelReport report = run_service_channel_test(options, cancel);
  const bool failed = std::any_of(report.rows.begin(), report.rows.end(), [](const ServiceChannelRow& row) { return row.status == "Fail"; });
  return {failed ? "Fail" : "Pass", report.summary};
}

std::optional<ConfigurationDatabaseInfo> configuration_database() {
  auto databases = identify_configuration_databases();
  if (!databases.ok())
    return std::nullopt;
  for (const ConfigurationDatabaseInfo& database : databases.value()) {
    if (database.found)
      return database;
  }
  return std::nullopt;
}

bool is_postgres(const ConfigurationDatabaseInfo& database) {
  return ascii_lower(database.engine).find("postgre") != std::string::npos;
}

Outcome config_identify(const Params&, const CancellationToken&) {
  const auto database = configuration_database();
  if (!database)
    return {"Fail", "No configuration database is named in this machine's registry."};
  return {"Pass", database->product + " uses " + database->engine + " database " + database->database + " on " +
                      database->server + (database->instance.empty() ? std::string() : "\\" + database->instance) +
                      (database->port.empty() ? std::string() : ", port " + database->port) + "."};
}

Outcome config_reach(const Params&, const CancellationToken& cancel) {
  const auto database = configuration_database();
  if (!database)
    return {"Could not check", "No configuration database is named in this machine's registry."};
  int port = std::atoi(database->port.c_str());
  if (port <= 0)
    port = is_postgres(*database) ? 5432 : database->instance.empty() ? 1433 : 0;
  if (port > 0 && port <= 65535)
    return tcp_ports(database->server, {static_cast<std::uint16_t>(port)}, cancel);
  // A named SQL Server instance without a fixed port: a connection proves the path.
  SqlConnection connection;
  connection.server = database->server + "\\" + database->instance;
  auto batch = run_sql_statements(connection, {"SELECT @@SERVERNAME AS name"}, cancel);
  if (batch.ok())
    return {"Pass", "Connected to " + connection.server + " through " + batch.value().driver + "."};
  const std::string error = describe_error(batch.error());
  if (ascii_lower(error).find("login failed") != std::string::npos)
    return {"Pass", connection.server + " answered; the account running SAT may not log in, which the next step checks."};
  return {"Fail", error};
}

Outcome config_rights(const Params&, const CancellationToken& cancel) {
  const auto database = configuration_database();
  if (!database)
    return {"Could not check", "No configuration database is named in this machine's registry."};
  if (is_postgres(*database))
    return {"Not applicable", "The configuration database is PostgreSQL; the next step reads its authentication."};
  std::string account;
#ifdef _WIN32
  account = service_facts("VeeamBackupSvc").account;
  if (ascii_lower(account) == "localsystem")
    account = "NT AUTHORITY\\SYSTEM";
#endif
  SqlConnection connection;
  connection.server = database->instance.empty() ? database->server : database->server + "\\" + database->instance;
  SqlPermissionCheckOptions options;
  options.target = SqlPermissionTarget::configuration_database;
  options.configuration_database = database->database;
  options.another_account = account;
  return sql_report(connection, sql_permission_statements(options),
                    [&](const SqlBatchResult& batch) { return evaluate_sql_permissions(batch, connection, options); }, cancel);
}

Outcome postgres_sspi(const Params&, const CancellationToken&) {
  const auto database = configuration_database();
  if (database && !is_postgres(*database))
    return {"Not applicable", "The configuration database is SQL Server."};
  auto mappings = inspect_postgresql_sspi_mappings();
  if (!mappings.ok())
    return {"Could not check", describe_error(mappings.error())};
  if (mappings.value().empty())
    return {"Not applicable", "No PostgreSQL installation was found here."};
  std::vector<std::string> accounts;
  std::size_t errors = 0;
  for (const PostgreSqlSspiMapping& mapping : mappings.value()) {
    accounts.insert(accounts.end(), mapping.mapped_windows_accounts.begin(), mapping.mapped_windows_accounts.end());
    errors += mapping.recent_sspi_errors.size();
  }
  const std::string found = "Mapped Windows accounts: " + (accounts.empty() ? std::string("none") : joined(accounts)) + ".";
  if (errors != 0U)
    return {"Attention", found + " " + std::to_string(errors) + " recent SSPI authentication errors in the PostgreSQL log."};
  return {"Pass", found};
}

// ----------------------------------------------------------------------- RPC or port exhaustion

#ifdef _WIN32
std::optional<std::uint32_t> tcpip_dword(const wchar_t* name) {
  DWORD data = 0;
  DWORD size = sizeof(data);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", name,
                   RRF_RT_REG_DWORD | RRF_SUBKEY_WOW6464KEY, nullptr, &data, &size) != ERROR_SUCCESS)
    return std::nullopt;
  return static_cast<std::uint32_t>(data);
}

// One REG_SZ value of the 64-bit registry; empty when absent.
std::string registry_text_64(const wchar_t* subkey, const wchar_t* name) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, subkey, name, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, subkey, name, RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return utf8_from_wide(text);
}

// A REG_MULTI_SZ value of the 64-bit registry, one string for each entry.
bool registry_multi_64(const wchar_t* subkey, const wchar_t* name, std::vector<std::string>& entries) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, subkey, name, RRF_RT_REG_MULTI_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, &size) != ERROR_SUCCESS)
    return false;
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (size >= sizeof(wchar_t) &&
      RegGetValueW(HKEY_LOCAL_MACHINE, subkey, name, RRF_RT_REG_MULTI_SZ | RRF_SUBKEY_WOW6464KEY, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return false;
  std::size_t start = 0;
  while (start < text.size() && text[start] != L'\0') {
    const std::size_t end = text.find(L'\0', start);
    const std::size_t stop = end == std::wstring::npos ? text.size() : end;
    entries.push_back(utf8_from_wide(std::wstring_view(text.data() + start, stop - start)));
    start = stop + 1U;
  }
  return true;
}

// One WMI class's dynamic port range from root\StandardCimv2.
struct StackRange {
  bool ok = false;
  scenarios_detail::PortRange range;
  std::string error;
};

StackRange read_stack_range(const std::string& query, const CancellationToken& cancel) {
  StackRange result;
  WmiQueryOptions options;
  options.name_space = "root\\StandardCimv2";
  options.query = query;
  auto rows = query_wmi(options, cancel);
  if (!rows.ok()) {
    result.error = wmi_namespace_absent(rows.error()) ? std::string("This version of Windows has no root\\StandardCimv2 namespace.")
                                                       : describe_error(rows.error());
    return result;
  }
  if (rows.value().empty()) {
    result.error = "WMI returned no row.";
    return result;
  }
  const auto& values = rows.value().front().values;
  const auto start = values.find("DynamicPortRangeStartPort");
  const auto count = values.find("DynamicPortRangeNumberOfPorts");
  if (start == values.end() || count == values.end()) {
    result.error = "WMI returned no dynamic port range.";
    return result;
  }
  result.range.start = static_cast<std::uint32_t>(std::strtoul(start->second.c_str(), nullptr, 10));
  result.range.count = static_cast<std::uint32_t>(std::strtoul(count->second.c_str(), nullptr, 10));
  result.ok = result.range.count != 0U;
  if (!result.ok)
    result.error = "WMI returned an empty dynamic port range.";
  return result;
}

scenarios_detail::DynamicRangeFacts read_dynamic_range_facts(const CancellationToken& cancel) {
  scenarios_detail::DynamicRangeFacts facts;
  const StackRange tcp = read_stack_range(
      "SELECT SettingName, DynamicPortRangeStartPort, DynamicPortRangeNumberOfPorts FROM MSFT_NetTCPSetting WHERE SettingName = 'Internet'", cancel);
  facts.tcp_read = tcp.ok;
  facts.tcp = tcp.range;
  facts.tcp_error = tcp.error;
  const StackRange udp = read_stack_range("SELECT DynamicPortRangeStartPort, DynamicPortRangeNumberOfPorts FROM MSFT_NetUDPSetting", cancel);
  facts.udp_read = udp.ok;
  facts.udp = udp.range;
  facts.udp_error = udp.error;
  facts.max_user_port = tcpip_dword(L"MaxUserPort");
  facts.time_wait_seconds = tcpip_dword(L"TcpTimedWaitDelay");
  return facts;
}

// The socket table and the dynamic ranges the checks of this scenario read. A range that cannot be
// read is the Windows default, and the note says so.
struct PortState {
  bool sockets_read = false;
  std::string error;
  std::vector<LocalSocket> sockets;
  scenarios_detail::PortRange tcp;
  scenarios_detail::PortRange udp;
  std::string note;
};

PortState read_port_state(const CancellationToken& cancel) {
  PortState state;
  const scenarios_detail::PortLimits& limits = scenarios_detail::port_limits();
  auto table = list_local_sockets();
  if (!table.ok()) {
    state.error = describe_error(table.error());
    return state;
  }
  state.sockets_read = true;
  state.sockets = std::move(table.value().sockets);
  const scenarios_detail::DynamicRangeFacts facts = read_dynamic_range_facts(cancel);
  const scenarios_detail::PortRange fallback{limits.default_start, limits.default_ports};
  state.tcp = facts.tcp_read ? facts.tcp : fallback;
  state.udp = facts.udp_read ? facts.udp : fallback;
  const auto unread = [&](const char* protocol, const std::string& why) {
    state.note += std::string(state.note.empty() ? "" : " ") + "The " + protocol + " dynamic port range could not be read" +
                  (why.empty() ? std::string() : " (" + why + ")") + "; the Windows default " + range_text(fallback) + " is used for it.";
  };
  if (!facts.tcp_read)
    unread("TCP", facts.tcp_error);
  if (!facts.udp_read)
    unread("UDP", facts.udp_error);
  return state;
}

std::vector<scenarios_detail::HandleCount> read_handle_counts() {
  std::vector<scenarios_detail::HandleCount> counts;
  const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot == INVALID_HANDLE_VALUE)
    return counts;
  PROCESSENTRY32W entry{};
  entry.dwSize = sizeof(entry);
  if (Process32FirstW(snapshot, &entry) != FALSE) {
    do {
      const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
      if (process == nullptr)
        continue;
      DWORD handles = 0;
      if (GetProcessHandleCount(process, &handles) != FALSE)
        counts.push_back({entry.th32ProcessID, utf8_from_wide(entry.szExeFile), handles});
      CloseHandle(process);
    } while (Process32NextW(snapshot, &entry) != FALSE);
  }
  CloseHandle(snapshot);
  return counts;
}

scenarios_detail::PoolFacts read_pool_facts() {
  scenarios_detail::PoolFacts facts;
  PERFORMANCE_INFORMATION info{};
  info.cb = static_cast<DWORD>(sizeof(info));
  if (GetPerformanceInfo(&info, static_cast<DWORD>(sizeof(info))) == FALSE)
    return facts;
  facts.read = true;
  facts.nonpaged_bytes = static_cast<std::uint64_t>(info.KernelNonpaged) * info.PageSize;
  facts.paged_bytes = static_cast<std::uint64_t>(info.KernelPaged) * info.PageSize;
  facts.physical_bytes = static_cast<std::uint64_t>(info.PhysicalTotal) * info.PageSize;
  facts.total_handles = info.HandleCount;
  return facts;
}

// The events of a group of port-exhaustion.json found in their logs, newest first.
bool read_event_hits(const std::string& group, const CancellationToken& cancel, std::int64_t now,
                     std::vector<scenarios_detail::EventHit>& hits, std::string& error) {
  const scenarios_detail::PortLimits& limits = scenarios_detail::port_limits();
  std::set<std::string> logs;
  std::vector<std::uint32_t> ids;
  std::uint32_t days = limits.event_days;
  for (const scenarios_detail::PortEventRule& rule : limits.events) {
    if (rule.group != group)
      continue;
    logs.insert(rule.log);
    ids.push_back(rule.id);
    days = std::max(days, rule.attention_within_days);
  }
  for (const std::string& log : logs) {
    WindowsEventLogSearchOptions options;
    options.channel = log;
    options.event_ids = ids;
    options.from_utc_ms = now - static_cast<std::int64_t>(days) * 86400000LL;
    auto searched = search_windows_event_log(options, cancel, {}, [&](const LogMatch& match) {
      const std::size_t id_at = match.signature.find("event-id:");
      const std::size_t provider_at = match.signature.find(";provider:");
      if (id_at == std::string::npos || provider_at == std::string::npos || !match.timestamp_utc_ms)
        return Status::success();
      scenarios_detail::EventHit hit;
      hit.id = static_cast<std::uint32_t>(std::strtoul(match.signature.c_str() + id_at + 9U, nullptr, 10));
      hit.provider = match.signature.substr(provider_at + 10U);
      hit.unix_millis = *match.timestamp_utc_ms;
      hits.push_back(std::move(hit));
      return Status::success();
    });
    if (!searched.ok()) {
      error = describe_error(searched.error());
      return false;
    }
  }
  return true;
}

std::string service_text(const std::string& name, const ServiceFacts& facts) {
  return "The " + name + " service is " + facts.state +
         (facts.disabled ? " and disabled" : facts.automatic ? " (automatic start)" : " (manual start)") +
         (facts.account.empty() ? std::string() : ", as " + facts.account) + ".";
}
#endif

Outcome net_dynamic_range([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const ScenarioCheckOutcome result =
      scenarios_detail::evaluate_dynamic_range(read_dynamic_range_facts(cancel), scenarios_detail::port_limits());
  return {result.status, result.found};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome events_counts([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const std::string group = param(params, "group");
  std::vector<scenarios_detail::EventHit> hits;
  std::string error;
  const std::int64_t now = unix_millis_now();
  if (!read_event_hits(group, cancel, now, hits, error))
    return {"Could not check", error};
  const ScenarioCheckOutcome result = scenarios_detail::tally_events(group, hits, now, scenarios_detail::port_limits());
  return {result.status, result.found, result.links};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome ports_usage([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const PortState state = read_port_state(cancel);
  if (!state.sockets_read)
    return {"Could not check", state.error};
  const ScenarioCheckOutcome result =
      scenarios_detail::evaluate_port_usage(state.sockets, state.tcp, state.udp, scenarios_detail::port_limits());
  return {result.status, result.found + (state.note.empty() ? std::string() : " " + state.note)};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome ports_holder([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const PortState state = read_port_state(cancel);
  if (!state.sockets_read)
    return {"Could not check", state.error};
  const std::string prefix = data_file("host-checks.json")["windows_driver_prefix"].as_string();
  const ScenarioCheckOutcome result = scenarios_detail::evaluate_port_holders(state.sockets, state.tcp, param(params, "process"), prefix,
                                                                             scenarios_detail::port_limits());
  return {result.status, result.found + (state.note.empty() ? std::string() : " " + state.note)};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome pool_pressure([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const PortState state = read_port_state(cancel);
  const ScenarioCheckOutcome result = scenarios_detail::evaluate_pool_pressure(
      read_handle_counts(), read_pool_facts(), state.sockets, state.tcp, scenarios_detail::port_limits());
  return {result.status, result.found + (state.sockets_read ? std::string() : " The socket table could not be read: " + state.error) +
                             (state.note.empty() ? std::string() : " " + state.note)};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome service_states([[maybe_unused]] const Params& params) {
#ifdef _WIN32
  std::vector<std::string> names;
  for (const std::string& name : split(param(params, "names"), ',')) {
    if (!trim(name).empty())
      names.push_back(trim(name));
  }
  if (names.empty())
    names = scenarios_detail::port_limits().rpc_services;
  if (names.empty())
    return {"Could not check", "No service names were given."};
  std::vector<std::string> lines;
  bool failed = false;
  bool attention = false;
  for (const std::string& name : names) {
    const ServiceFacts facts = service_facts(name);
    if (!facts.found) {
      lines.push_back("The " + name + " service is not installed.");
      failed = true;
      continue;
    }
    lines.push_back(service_text(name, facts));
    if (facts.running)
      continue;
    if (facts.disabled || facts.automatic)
      failed = true;
    else
      attention = true;
  }
  return {failed ? "Fail" : attention ? "Attention" : "Pass", joined(lines, " ")};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome rpc_internet_ports([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  constexpr const wchar_t* kKey = L"SOFTWARE\\Microsoft\\Rpc\\Internet";
  scenarios_detail::RpcInternetFacts facts;
  HKEY key = nullptr;
  const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKey, 0, KEY_READ | KEY_WOW64_64KEY, &key);
  if (opened == ERROR_SUCCESS) {
    RegCloseKey(key);
    facts.key_present = true;
  } else if (opened != ERROR_FILE_NOT_FOUND && opened != ERROR_PATH_NOT_FOUND) {
    return {"Could not check", "The registry key HKLM\\Software\\Microsoft\\Rpc\\Internet could not be opened (error " + std::to_string(opened) + ")."};
  }
  if (facts.key_present) {
    facts.ports_present = RegGetValueW(HKEY_LOCAL_MACHINE, kKey, L"Ports", RRF_RT_ANY | RRF_SUBKEY_WOW6464KEY, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
    if (facts.ports_present && !registry_multi_64(kKey, L"Ports", facts.ports))
      facts.ports = {"(not a list of ports)"};
    facts.ports_available = registry_text_64(kKey, L"PortsInternetAvailable");
    facts.use_internet_ports = registry_text_64(kKey, L"UseInternetPorts");
  }
  const PortState state = read_port_state(cancel);
  ScenarioCheckOutcome result =
      scenarios_detail::evaluate_rpc_ports(facts, state.sockets, scenarios_detail::port_limits());
  if (facts.key_present) {
    // A Netlogon event that names the RPC port configuration supports a failure here.
    std::vector<scenarios_detail::EventHit> hits;
    std::string error;
    const std::int64_t now = unix_millis_now();
    if (read_event_hits("rpc", cancel, now, hits, error)) {
      const ScenarioCheckOutcome events = scenarios_detail::tally_events("rpc", hits, now, scenarios_detail::port_limits());
      if (events.status != "Pass")
        result.found += " " + events.found;
    }
  }
  return {result.status, result.found};
#else
  return {"Not applicable", "Windows only."};
#endif
}

Outcome firewall_rpc([[maybe_unused]] const Params& params, [[maybe_unused]] const CancellationToken& cancel) {
#ifdef _WIN32
  const scenarios_detail::PortLimits& limits = scenarios_detail::port_limits();
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  const ServiceFacts firewall_service = service_facts("mpssvc");
  if (!firewall_service.found)
    return {"Could not check", "The Windows Defender Firewall service (mpssvc) is not installed, so there is no Windows firewall to read."};
  if (!firewall_service.running)
    return {"Attention", "The Windows Defender Firewall service (mpssvc) is " + firewall_service.state +
                             ", so Windows Firewall does not filter inbound connections here. Another firewall can still do it."};
  auto firewall = read_firewall();
  if (!firewall.ok())
    return {"Could not check", describe_error(firewall.error())};
  const PortState state = read_port_state(cancel);
  std::string program;
  std::string services = limits.epmap_service;
  for (const LocalSocket& socket : state.sockets) {
    if (socket.protocol == PortProtocol::tcp && socket.state == "LISTEN" && static_cast<std::uint32_t>(socket.local_port) == limits.epmap_port && !socket.process_path.empty()) {
      program = socket.process_path;
      if (!socket.services.empty())
        services = socket.services;
      break;
    }
  }
  if (program.empty()) {
    wchar_t directory[MAX_PATH]{};
    if (GetSystemDirectoryW(directory, static_cast<UINT>(std::size(directory))) != 0U)
      program = utf8_from_wide(directory) + "\\svchost.exe";
  }
  const ScenarioCheckOutcome result =
      scenarios_detail::evaluate_rpc_firewall(firewall.value(), state.tcp, program, services, limits);
  return {result.status, result.found};
#else
  return {"Not applicable", "Windows only."};
#endif
}

const std::map<std::string, std::function<Outcome(const Params&, const CancellationToken&)>>& check_table() {
  static const std::map<std::string, std::function<Outcome(const Params&, const CancellationToken&)>> table{
      {"name.resolve", name_resolve},
      {"time.skew", time_skew},
      {"port.tcp.role", port_role},
      {"payload.sat", payload_sat},
      {"rpc.epmap", rpc_epmap},
      {"wmi.query", wmi_query},
      {"tls.handshake", tls_handshake},
      {"sql.service", sql_service},
      {"vss.writer", vss_writers},
      {"vss.writers", vss_writers},
      {"service.state", [](const Params& params, const CancellationToken&) { return service_state(param(params, "name")); }},
      {"events.recent", events_recent},
      {"volume.info", volume_info},
      {"bottleneck", bottleneck},
      {"sql.permissions", sql_permissions},
      {"sql.backups", sql_backups},
      {"sql.shape", sql_shape},
      {"grpc.channel", grpc_channel},
      {"config.db.identify", config_identify},
      {"config.db.reach", config_reach},
      {"config.db.rights", config_rights},
      {"postgres.sspi", postgres_sspi},
      {"net.dynamic_range", net_dynamic_range},
      {"events.counts", events_counts},
      {"ports.usage", ports_usage},
      {"ports.holder", ports_holder},
      {"pool.pressure", pool_pressure},
      {"service.states", [](const Params& params, const CancellationToken&) { return service_states(params); }},
      {"rpc.internet_ports", rpc_internet_ports},
      {"firewall.rpc", firewall_rpc}};
  return table;
}

std::string this_machine() {
#ifdef _WIN32
  wchar_t name[256]{};
  DWORD size = static_cast<DWORD>(std::size(name));
  return GetComputerNameW(name, &size) != FALSE ? utf8_from_wide(name) : std::string("this machine");
#else
  char name[256]{};
  return gethostname(name, sizeof(name) - 1U) == 0 ? std::string(name) : std::string("this machine");
#endif
}

} // namespace

const std::vector<ScenarioDefinition>& scenario_catalog() {
  static const std::vector<ScenarioDefinition> definitions = [] {
    std::vector<ScenarioDefinition> list;
    for (const Scenario& scenario : scenarios())
      list.push_back(scenario.definition);
    return list;
  }();
  return definitions;
}

namespace scenarios_detail {

std::string major_version(std::string_view version) {
  std::string major;
  for (const char c : trim(version)) {
    if (c < '0' || c > '9')
      break;
    major.push_back(c);
  }
  return major;
}

std::string input_default(const ScenarioInput& input, const std::string& vbr_major) {
  const auto found = vbr_major.empty() ? input.default_by_vbr.end() : input.default_by_vbr.find(vbr_major);
  return found == input.default_by_vbr.end() ? input.default_value : found->second;
}


const PortLimits& port_limits() {
  static const PortLimits limits = [] {
    PortLimits found;
    const JsonValue& file = data_file("port-exhaustion.json");
    if (!file.is_object())
      return found;
    const JsonValue& ranges = file["ranges"];
    found.default_start = json_count(ranges["default_dynamic"]["start"]);
    found.default_ports = json_count(ranges["default_dynamic"]["ports"]);
    found.attention_below_ports = json_count(ranges["attention_below_ports"]);
    found.fail_below_ports = json_count(ranges["fail_below_ports"]);
    found.mover_start = json_count(ranges["veeam_data_mover"]["start"]);
    found.mover_ports = json_count(ranges["veeam_data_mover"]["ports"]);
    const JsonValue& time_wait = file["tcp_time_wait"];
    found.time_wait_default = json_count(time_wait["default_seconds"]);
    found.time_wait_min = json_count(time_wait["valid_min_seconds"]);
    found.time_wait_max = json_count(time_wait["valid_max_seconds"]);
    found.usage_attention_percent = json_count(file["usage"]["attention_percent"]);
    found.usage_fail_percent = json_count(file["usage"]["fail_percent"]);
    found.usage_note = file["usage"]["not_counted_note"].as_string();
    const JsonValue& holder = file["holder"];
    found.holder_top = json_count(holder["top"]);
    found.holder_share_percent = json_count(holder["share_percent"]);
    found.close_wait_attention = json_count(holder["close_wait_attention"]);
    found.time_wait_total_minimum = json_count(holder["time_wait_total_minimum"]);
    found.time_wait_remote_share_percent = json_count(holder["time_wait_remote_share_percent"]);
    const JsonValue& handles = file["handles"];
    found.handles_attention = json_count(handles["attention"]);
    found.handles_fail = json_count(handles["fail"]);
    found.handles_fail_port_share_percent = json_count(handles["fail_also_needs_port_share_percent"]);
    found.nonpaged_attention_percent = json_count(handles["nonpaged_pool_attention_percent_of_ram"]);
    found.handle_exclusions = handles["exclude_processes"].string_items();
    const JsonValue& rpc = file["rpc"];
    found.rpc_minimum_ports = json_count(rpc["minimum_ports"]);
    found.rpc_in_use_attention_percent = json_count(rpc["in_use_attention_percent"]);
    found.rpc_services = rpc["services"].string_items();
    found.epmap_port = json_count(rpc["endpoint_mapper_port"]);
    found.epmap_service = rpc["endpoint_mapper_service"].as_string();
    found.event_days = json_count(file["event_days"]);
    for (const JsonValue& item : file["events"].items()) {
      PortEventRule rule;
      rule.group = item["group"].as_string();
      rule.log = item["log"].as_string();
      rule.providers = item["providers"].string_items();
      rule.id = json_count(item["id"]);
      rule.fail_within_hours = json_count(item["fail_within_hours"]);
      rule.attention_within_days = json_count(item["attention_within_days"]);
      rule.meaning = item["meaning"].as_string();
      if (item.has("source") && item["source"].is_string())
        rule.source = item["source"].as_string();
      found.events.push_back(std::move(rule));
    }
    found.loaded = found.default_ports != 0U && found.usage_fail_percent != 0U;
    return found;
  }();
  return limits;
}

ScenarioCheckOutcome evaluate_dynamic_range(const DynamicRangeFacts& facts, const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  if (!facts.tcp_read)
    return {"Could not check", facts.tcp_error.empty() ? std::string("The TCP dynamic port range could not be read.") : facts.tcp_error};
  const std::uint32_t tcp_last = facts.tcp.start + facts.tcp.count - 1U;
  std::string found = "TCP dynamic ports " + range_text(facts.tcp) + ".";
  if (facts.udp_read) {
    found += " UDP dynamic ports " + range_text(facts.udp) + ".";
  } else {
    found += " The UDP dynamic range could not be read";
    if (!facts.udp_error.empty())
      found += ": " + facts.udp_error;
    found += ".";
  }
  if (facts.max_user_port)
    found += " MaxUserPort is " + std::to_string(*facts.max_user_port) + ".";
  else
    found += " MaxUserPort is not set.";
  const std::uint32_t delay = facts.time_wait_seconds && *facts.time_wait_seconds != 0U ? *facts.time_wait_seconds : limits.time_wait_default;
  if (facts.time_wait_seconds)
    found += " TcpTimedWaitDelay is " + std::to_string(*facts.time_wait_seconds) + " seconds.";
  else
    found += " TcpTimedWaitDelay is not set, so a closed connection keeps its port for " + std::to_string(limits.time_wait_default) + " seconds.";
  if (delay != 0U)
    found += " At " + std::to_string(delay) + " seconds the TCP range allows about " + std::to_string(facts.tcp.count / delay) +
             " new connections per second.";

  std::vector<std::string> failures;
  std::vector<std::string> attention;
  if (facts.tcp.count < limits.fail_below_ports)
    failures.push_back("The TCP range holds fewer than " + thousands(limits.fail_below_ports) + " ports.");
  if (facts.udp_read && facts.udp.count < limits.fail_below_ports)
    failures.push_back("The UDP range holds fewer than " + thousands(limits.fail_below_ports) + " ports.");
  if (facts.tcp.count >= limits.fail_below_ports && facts.tcp.count < limits.attention_below_ports)
    attention.push_back("The TCP range is smaller than the Windows default of " + thousands(limits.default_ports) + " ports.");
  if (facts.udp_read && facts.udp.count >= limits.fail_below_ports && facts.udp.count < limits.attention_below_ports)
    attention.push_back("The UDP range is smaller than the Windows default of " + thousands(limits.default_ports) + " ports.");
  if (facts.udp_read && (facts.udp.start != facts.tcp.start || facts.udp.count != facts.tcp.count))
    attention.push_back("The TCP and UDP ranges differ.");
  if (facts.tcp.start < limits.default_start)
    attention.push_back("The TCP range starts below " + std::to_string(limits.default_start) + ".");
  if (facts.udp_read && facts.udp.start < limits.default_start)
    attention.push_back("The UDP range starts below " + std::to_string(limits.default_start) + ".");
  if (facts.time_wait_seconds) {
    if (*facts.time_wait_seconds > limits.time_wait_max)
      attention.push_back("TcpTimedWaitDelay is above the " + std::to_string(limits.time_wait_max) + " seconds Windows accepts.");
    else if (*facts.time_wait_seconds > limits.time_wait_default)
      attention.push_back("TcpTimedWaitDelay is above the default of " + std::to_string(limits.time_wait_default) + " seconds.");
    else if (*facts.time_wait_seconds < limits.time_wait_min)
      attention.push_back("TcpTimedWaitDelay is below the " + std::to_string(limits.time_wait_min) + " seconds Windows accepts.");
  }
  if (facts.max_user_port && *facts.max_user_port != tcp_last)
    attention.push_back("MaxUserPort differs from the last port of the TCP range, " + std::to_string(tcp_last) +
                        "; the range the stack reports is the one in force.");
  for (const std::string& line : failures)
    found += " " + line;
  for (const std::string& line : attention)
    found += " " + line;
  return {!failures.empty() ? "Fail" : !attention.empty() ? "Attention" : "Pass", found};
}

PortUsage port_usage(const std::vector<LocalSocket>& sockets, PortProtocol protocol, PortRange range) {
  PortUsage usage;
  usage.range_ports = range.count;
  const std::uint32_t end = range.start + range.count;
  struct Family {
    std::set<std::uint16_t> wildcard;
    std::map<std::string, std::set<std::uint16_t>> addresses;
  };
  Family families[2];
  const auto in_range = [&](const LocalSocket& socket) {
    const std::uint32_t port = socket.local_port;
    return socket.protocol == protocol && port >= range.start && port < end;
  };
  for (const LocalSocket& socket : sockets) {
    if (!in_range(socket))
      continue;
    Family& family = families[socket.ipv6 ? 1 : 0];
    if (is_wildcard_address(socket.local_address))
      family.wildcard.insert(socket.local_port);
    else
      family.addresses[socket.local_address].insert(socket.local_port);
  }
  bool best_ipv6 = false;
  for (int index = 0; index < 2; ++index) {
    const Family& family = families[index];
    for (const auto& [address, ports] : family.addresses) {
      std::size_t held = ports.size();
      for (const std::uint16_t port : family.wildcard)
        held += ports.count(port) == 0U ? 1U : 0U;
      if (held > usage.ports_in_use) {
        usage.ports_in_use = held;
        usage.address = address;
        best_ipv6 = index == 1;
      }
    }
    if (family.addresses.empty() && family.wildcard.size() > usage.ports_in_use) {
      usage.ports_in_use = family.wildcard.size();
      usage.address = index == 1 ? "::" : "0.0.0.0";
      best_ipv6 = index == 1;
    }
  }
  if (usage.ports_in_use == 0U)
    return usage;
  for (const LocalSocket& socket : sockets) {
    if (!in_range(socket) || socket.ipv6 != best_ipv6)
      continue;
    if (socket.local_address != usage.address && !is_wildcard_address(socket.local_address))
      continue;
    ++usage.sockets;
    ++usage.states[socket.state];
  }
  return usage;
}

namespace {

std::string usage_line(const std::string& label, const PortUsage& usage) {
  if (usage.ports_in_use == 0U)
    return label + ": none of the " + thousands(usage.range_ports) + " ports is in use.";
  std::string line = label + ": " + thousands(usage.ports_in_use) + " of " + thousands(usage.range_ports) +
                     " ports in use on " + usage.address + " (" + percent_text(usage.ports_in_use, usage.range_ports) + " percent)";
  std::vector<std::string> states;
  std::size_t named = 0;
  for (const char* state : {"ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "LISTEN"}) {
    const auto found = usage.states.find(state);
    if (found == usage.states.end() || found->second == 0U)
      continue;
    named += found->second;
    states.push_back(thousands(found->second) + " " + state);
  }
  if (usage.sockets > named)
    states.push_back(thousands(usage.sockets - named) + " in other states");
  if (!states.empty())
    line += ": " + joined(states);
  return line + ".";
}

// 0 below the attention figure, 1 from it, 2 from the fail figure.
int usage_level(const PortUsage& usage, const PortLimits& limits) {
  if (share_at_least(usage.ports_in_use, usage.range_ports, limits.usage_fail_percent))
    return 2;
  return share_at_least(usage.ports_in_use, usage.range_ports, limits.usage_attention_percent) ? 1 : 0;
}

bool in_dynamic_range(const LocalSocket& socket, PortProtocol protocol, PortRange range) {
  const std::uint32_t port = socket.local_port;
  return socket.protocol == protocol && port >= range.start && port < range.start + range.count;
}

} // namespace

ScenarioCheckOutcome evaluate_port_usage(const std::vector<LocalSocket>& sockets, PortRange tcp, PortRange udp,
                                         const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  const PortUsage tcp_usage = port_usage(sockets, PortProtocol::tcp, tcp);
  const PortUsage udp_usage = port_usage(sockets, PortProtocol::udp, udp);
  const PortRange mover{limits.mover_start, limits.mover_ports};
  const PortUsage mover_usage = port_usage(sockets, PortProtocol::tcp, mover);
  std::string found = usage_line("TCP", tcp_usage) + " " + usage_line("UDP", udp_usage) + " " +
                      usage_line("TCP ports " + std::to_string(mover.start) + " to " + std::to_string(mover.start + mover.count - 1U), mover_usage);
  if (!limits.usage_note.empty())
    found += " " + limits.usage_note;
  const int level = std::max({usage_level(tcp_usage, limits), usage_level(udp_usage, limits), usage_level(mover_usage, limits)});
  return {level == 2 ? "Fail" : level == 1 ? "Attention" : "Pass", found};
}

std::vector<RemoteGroup> time_wait_by_remote(const std::vector<LocalSocket>& sockets, PortRange range, std::size_t top) {
  std::map<std::pair<std::string, std::uint16_t>, std::size_t> counts;
  for (const LocalSocket& socket : sockets) {
    if (in_dynamic_range(socket, PortProtocol::tcp, range) && socket.state == "TIME_WAIT")
      ++counts[{socket.remote_address, socket.remote_port}];
  }
  std::vector<RemoteGroup> groups;
  for (const auto& [endpoint, count] : counts) {
    RemoteGroup group;
    group.address = endpoint.first;
    group.port = endpoint.second;
    group.count = count;
    groups.push_back(std::move(group));
  }
  std::stable_sort(groups.begin(), groups.end(), [](const RemoteGroup& left, const RemoteGroup& right) { return left.count > right.count; });
  if (groups.size() > top)
    groups.resize(top);
  for (RemoteGroup& group : groups) {
    std::map<std::uint32_t, std::pair<std::size_t, std::string>> live;
    for (const LocalSocket& socket : sockets) {
      if (socket.protocol != PortProtocol::tcp || socket.pid == 0U || socket.state == "TIME_WAIT" || socket.state == "LISTEN" ||
          socket.remote_address != group.address || socket.remote_port != group.port)
        continue;
      auto& entry = live[socket.pid];
      ++entry.first;
      entry.second = socket.process_name;
    }
    std::size_t most = 0;
    for (const auto& [pid, entry] : live) {
      if (entry.first > most) {
        most = entry.first;
        group.likely_pid = pid;
        group.likely_process = entry.second;
      }
    }
  }
  return groups;
}

std::vector<ProcessHold> port_holders(const std::vector<LocalSocket>& sockets, PortRange tcp) {
  std::map<std::uint32_t, ProcessHold> by_pid;
  for (const LocalSocket& socket : sockets) {
    if (socket.protocol != PortProtocol::tcp || socket.pid == 0U)
      continue;
    const bool holds = in_dynamic_range(socket, PortProtocol::tcp, tcp) && socket.state != "TIME_WAIT";
    const bool waiting = socket.state == "CLOSE_WAIT";
    if (!holds && !waiting)
      continue;
    ProcessHold& hold = by_pid[socket.pid];
    hold.pid = socket.pid;
    if (hold.name.empty())
      hold.name = socket.process_name;
    if (hold.services.empty())
      hold.services = socket.services;
    hold.sockets += holds ? 1U : 0U;
    hold.close_wait += waiting ? 1U : 0U;
  }
  std::vector<ProcessHold> holders;
  for (auto& entry : by_pid)
    holders.push_back(std::move(entry.second));
  std::stable_sort(holders.begin(), holders.end(), [](const ProcessHold& left, const ProcessHold& right) {
    if (left.sockets != right.sockets)
      return left.sockets > right.sockets;
    return left.close_wait > right.close_wait;
  });
  return holders;
}

namespace {

std::string holder_name(const ProcessHold& hold) {
  return (hold.name.empty() ? std::string("process") : hold.name) + " (pid " + std::to_string(hold.pid) +
         (hold.services.empty() ? std::string() : ", " + hold.services) + ")";
}

std::size_t sockets_in_range(const std::vector<LocalSocket>& sockets, PortRange range) {
  return static_cast<std::size_t>(std::count_if(sockets.begin(), sockets.end(), [&](const LocalSocket& socket) {
    return in_dynamic_range(socket, PortProtocol::tcp, range);
  }));
}

} // namespace

ScenarioCheckOutcome evaluate_port_holders(const std::vector<LocalSocket>& sockets, PortRange tcp, const std::string& wanted,
                                           const std::string& veeam_prefix, const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  const PortUsage usage = port_usage(sockets, PortProtocol::tcp, tcp);
  const std::size_t total = sockets_in_range(sockets, tcp);
  const std::vector<ProcessHold> holders = port_holders(sockets, tcp);
  const std::vector<RemoteGroup> waiting = time_wait_by_remote(sockets, tcp, 3U);
  const std::size_t time_wait_total = static_cast<std::size_t>(std::count_if(sockets.begin(), sockets.end(), [&](const LocalSocket& socket) {
    return in_dynamic_range(socket, PortProtocol::tcp, tcp) && socket.state == "TIME_WAIT";
  }));

  std::string found;
  const ProcessHold* top = holders.empty() || holders.front().sockets == 0U ? nullptr : &holders.front();
  if (total == 0U) {
    found = "No TCP socket holds a port in the dynamic range " + range_text(tcp) + ".";
  } else if (top == nullptr) {
    found = "No process owns a socket in the TCP dynamic range " + range_text(tcp) + ".";
  } else {
    std::vector<std::string> parts;
    for (std::size_t index = 0; index < holders.size() && parts.size() < limits.holder_top && holders[index].sockets != 0U; ++index)
      parts.push_back(holder_name(holders[index]) + " " + thousands(holders[index].sockets) + " ports, " +
                      percent_text(holders[index].sockets, total) + " percent");
    found = "Most ports held in the TCP dynamic range " + range_text(tcp) + ": " + joined(parts, "; ") + ".";
  }
  std::vector<ProcessHold> by_wait = holders;
  std::stable_sort(by_wait.begin(), by_wait.end(), [](const ProcessHold& left, const ProcessHold& right) { return left.close_wait > right.close_wait; });
  std::vector<std::string> waits;
  for (const ProcessHold& hold : by_wait) {
    if (hold.close_wait != 0U && waits.size() < 3U)
      waits.push_back(holder_name(hold) + " " + thousands(hold.close_wait));
  }
  if (!waits.empty())
    found += " Sockets in CLOSE_WAIT: " + joined(waits, "; ") + ".";
  if (!waiting.empty()) {
    std::vector<std::string> remotes;
    for (const RemoteGroup& group : waiting)
      remotes.push_back(thousands(group.count) + " toward " + group.address + ":" + std::to_string(group.port) +
                        (group.likely_process.empty() ? std::string() : ", most likely closed by " + group.likely_process + " (pid " + std::to_string(group.likely_pid) + ")"));
    found += " TIME_WAIT sockets have no owner, so they are listed by remote endpoint: " + joined(remotes, "; ") + ".";
  }

  if (!wanted.empty()) {
    const std::string name = ascii_lower(wanted);
    const bool numeric = is_decimal_text(name);
    const std::uint32_t pid = numeric ? static_cast<std::uint32_t>(std::strtoul(name.c_str(), nullptr, 10)) : 0U;
    const auto matches = [&](const LocalSocket& socket) {
      if (socket.pid == 0U)
        return false;
      if (numeric)
        return socket.pid == pid;
      const std::string own = ascii_lower(socket.process_name);
      return own == name || own == name + ".exe";
    };
    std::set<std::uint32_t> pids;
    std::size_t held = 0;
    for (const LocalSocket& socket : sockets) {
      if (socket.protocol != PortProtocol::tcp || !matches(socket))
        continue;
      pids.insert(socket.pid);
      held += in_dynamic_range(socket, PortProtocol::tcp, tcp) && socket.state != "TIME_WAIT" ? 1U : 0U;
    }
    if (pids.empty())
      found += " " + wanted + ": no TCP socket in the table belongs to it.";
    else
      found += " " + wanted + ": " + std::to_string(pids.size()) + (pids.size() == 1U ? " process holds " : " processes hold ") +
               thousands(held) + " ports in the TCP dynamic range" + (total == 0U ? std::string(".") : ", " + percent_text(held, total) + " percent of the sockets in it.");
  }

  const bool busy = share_at_least(usage.ports_in_use, usage.range_ports, limits.usage_attention_percent);
  const bool exhausted = share_at_least(usage.ports_in_use, usage.range_ports, limits.usage_fail_percent);
  const bool concentrated = top != nullptr && share_at_least(top->sockets, total, limits.holder_share_percent);
  const bool leaking = std::any_of(holders.begin(), holders.end(), [&](const ProcessHold& hold) { return hold.close_wait >= limits.close_wait_attention; });
  const bool one_endpoint = !waiting.empty() && time_wait_total >= limits.time_wait_total_minimum &&
                            share_at_least(waiting.front().count, time_wait_total, limits.time_wait_remote_share_percent);
  const bool veeam = top != nullptr && !veeam_prefix.empty() && ascii_lower(top->name).rfind(ascii_lower(veeam_prefix), 0) == 0U;
  std::string status = "Pass";
  if (exhausted && concentrated) {
    status = "Fail";
  } else if ((busy && concentrated) || leaking || one_endpoint) {
    status = "Attention";
  }
  if (status != "Pass" && concentrated && veeam)
    found += " " + top->name + " is a Veeam program.";
  return {status, found};
}

ScenarioCheckOutcome evaluate_pool_pressure(const std::vector<HandleCount>& handles, const PoolFacts& pool,
                                            const std::vector<LocalSocket>& sockets, PortRange tcp,
                                            const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  if (handles.empty() && !pool.read)
    return {"Could not check", "The process handle counts and the kernel pool sizes could not be read."};
  std::vector<HandleCount> counted;
  for (const HandleCount& item : handles) {
    const bool excluded = std::any_of(limits.handle_exclusions.begin(), limits.handle_exclusions.end(),
                                      [&](const std::string& name) { return same_name(name, item.name); });
    if (!excluded)
      counted.push_back(item);
  }
  std::stable_sort(counted.begin(), counted.end(), [](const HandleCount& left, const HandleCount& right) { return left.handles > right.handles; });
  const std::vector<ProcessHold> holders = port_holders(sockets, tcp);
  const std::size_t total = sockets_in_range(sockets, tcp);
  std::string found;
  if (counted.empty()) {
    found = "The process handle counts could not be read.";
  } else {
    std::vector<std::string> parts;
    for (std::size_t index = 0; index < counted.size() && index < limits.holder_top; ++index)
      parts.push_back(counted[index].name + " (pid " + std::to_string(counted[index].pid) + ") " + thousands(counted[index].handles));
    found = "Most open handles: " + joined(parts, "; ") + ".";
  }
  if (pool.read) {
    found += " Nonpaged pool is " + mib_text(pool.nonpaged_bytes);
    if (pool.physical_bytes != 0U)
      found += ", " + percent_text(pool.nonpaged_bytes, pool.physical_bytes) + " percent of the " + mib_text(pool.physical_bytes) + " of physical memory";
    found += "; paged pool is " + mib_text(pool.paged_bytes) + ". The system holds " + thousands(pool.total_handles) + " open handles.";
  } else {
    found += " The kernel pool sizes could not be read.";
  }

  bool attention = false;
  bool fail = false;
  for (const HandleCount& item : counted) {
    if (item.handles >= limits.handles_attention)
      attention = true;
    if (item.handles < limits.handles_fail)
      continue;
    std::size_t held = 0;
    for (const ProcessHold& hold : holders) {
      if (hold.pid == item.pid)
        held = hold.sockets;
    }
    const bool top_holder = !holders.empty() && holders.front().pid == item.pid && holders.front().sockets != 0U;
    if (top_holder || share_at_least(held, total, limits.handles_fail_port_share_percent))
      fail = true;
  }
  if (pool.read && share_at_least(pool.nonpaged_bytes, pool.physical_bytes, limits.nonpaged_attention_percent))
    attention = true;
  return {fail ? "Fail" : attention ? "Attention" : "Pass", found};
}

RpcPortList parse_rpc_port_list(const std::vector<std::string>& entries) {
  RpcPortList list;
  for (const std::string& entry : entries) {
    const std::string text = trim(entry);
    if (text.empty())
      continue;
    std::uint32_t first = 0;
    std::uint32_t last = 0;
    const std::size_t dash = text.find('-');
    bool read = false;
    if (dash == std::string::npos) {
      read = parse_port_number(text, first);
      last = first;
    } else {
      read = parse_port_number(trim(text.substr(0, dash)), first) && parse_port_number(trim(text.substr(dash + 1U)), last) && first <= last;
    }
    if (!read) {
      list.valid = false;
      list.invalid_entry = text;
      break;
    }
    list.ranges.emplace_back(first, last);
  }
  std::sort(list.ranges.begin(), list.ranges.end());
  std::vector<std::pair<std::uint32_t, std::uint32_t>> merged;
  for (const auto& range : list.ranges) {
    if (!merged.empty() && range.first <= merged.back().second + 1U)
      merged.back().second = std::max(merged.back().second, range.second);
    else
      merged.push_back(range);
  }
  list.ranges = std::move(merged);
  for (const auto& range : list.ranges)
    list.total += range.second - range.first + 1U;
  return list;
}

std::size_t rpc_ports_in_use(const RpcPortList& list, const std::vector<LocalSocket>& sockets) {
  std::set<std::uint16_t> held;
  for (const LocalSocket& socket : sockets) {
    if (socket.protocol == PortProtocol::tcp)
      held.insert(socket.local_port);
  }
  std::size_t count = 0;
  for (const std::uint16_t port : held) {
    const std::uint32_t value = port;
    for (const auto& range : list.ranges) {
      if (value >= range.first && value <= range.second) {
        ++count;
        break;
      }
    }
  }
  return count;
}

namespace {

// "5000-5100, 6000": the first ranges, then how many more.
std::string rpc_list_text(const RpcPortList& list) {
  std::vector<std::string> parts;
  for (std::size_t index = 0; index < list.ranges.size() && index < 6U; ++index) {
    const auto& range = list.ranges[index];
    parts.push_back(range.first == range.second ? std::to_string(range.first)
                                                : std::to_string(range.first) + "-" + std::to_string(range.second));
  }
  std::string text = joined(parts);
  if (list.ranges.size() > 6U)
    text += " and " + std::to_string(list.ranges.size() - 6U) + " more";
  return text;
}

} // namespace

ScenarioCheckOutcome evaluate_rpc_ports(const RpcInternetFacts& facts, const std::vector<LocalSocket>& sockets,
                                        const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  if (!facts.key_present)
    return {"Pass", "The registry key HKLM\\Software\\Microsoft\\Rpc\\Internet is absent, so RPC dynamic ports are not restricted and RPC takes its ports from the dynamic range."};
  std::string policy;
  if (!facts.ports_available.empty())
    policy += " PortsInternetAvailable is " + facts.ports_available + ".";
  if (!facts.use_internet_ports.empty())
    policy += " UseInternetPorts is " + facts.use_internet_ports + ".";
  if (!facts.ports_present)
    return {"Pass", "The registry key HKLM\\Software\\Microsoft\\Rpc\\Internet exists with no Ports value, so RPC dynamic ports are not restricted." + policy};
  const RpcPortList list = parse_rpc_port_list(facts.ports);
  if (!list.valid)
    return {"Fail", "The Ports value holds the entry \"" + list.invalid_entry +
                        "\", which is not a port or a range of 0 to 65535. RPC treats the whole configuration as invalid." + policy};
  std::string found = "RPC is limited to " + thousands(list.total) + " ports (" + rpc_list_text(list) + ")." + policy;
  if (list.total < limits.rpc_minimum_ports)
    return {"Fail", found + " Fewer than " + std::to_string(limits.rpc_minimum_ports) + " ports are listed."};
  const std::size_t used = rpc_ports_in_use(list, sockets);
  found += " " + thousands(used) + " of them are held by a TCP socket (" + percent_text(used, list.total) + " percent).";
  bool attention = share_at_least(used, list.total, limits.rpc_in_use_attention_percent);
  const std::string available = ascii_upper(facts.ports_available);
  const std::string use_internet = ascii_upper(facts.use_internet_ports);
  if ((available == "Y" && use_internet == "N") || (available == "N" && use_internet == "Y")) {
    attention = true;
    found += " PortsInternetAvailable and UseInternetPorts disagree, so a service that takes the default policy gets ports outside the list.";
  }
  return {attention ? "Attention" : "Pass", found};
}

ScenarioCheckOutcome tally_events(const std::string& group, const std::vector<EventHit>& hits, std::int64_t now_unix_millis,
                                  const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  std::vector<std::string> lines;
  std::vector<std::string> sources;
  std::vector<std::string> ids;
  std::vector<std::string> providers;
  std::string log;
  std::uint32_t days = limits.event_days;
  bool fail = false;
  for (const PortEventRule& rule : limits.events) {
    if (rule.group != group)
      continue;
    ids.push_back(std::to_string(rule.id));
    for (const std::string& provider : rule.providers) {
      if (std::find(providers.begin(), providers.end(), provider) == providers.end())
        providers.push_back(provider);
    }
    if (log.empty())
      log = rule.log;
    const std::uint32_t window = rule.attention_within_days != 0U ? rule.attention_within_days : limits.event_days;
    days = std::max(days, window);
    const std::int64_t since = now_unix_millis - static_cast<std::int64_t>(window) * 86400000LL;
    std::size_t count = 0;
    std::int64_t newest = 0;
    for (const EventHit& hit : hits) {
      if (hit.id != rule.id || hit.unix_millis < since)
        continue;
      const bool provider_ok = rule.providers.empty() ||
                               std::any_of(rule.providers.begin(), rule.providers.end(), [&](const std::string& name) { return same_name(name, hit.provider); });
      if (!provider_ok)
        continue;
      ++count;
      newest = std::max(newest, hit.unix_millis);
    }
    if (count == 0U)
      continue;
    if (!rule.source.empty() && std::find(sources.begin(), sources.end(), rule.source) == sources.end())
      sources.push_back(rule.source);
    lines.push_back(std::to_string(rule.id) + ": " + std::to_string(count) + (count == 1U ? " event" : " events") + " in the last " +
                    std::to_string(window) + " days, the newest at " + readable_utc_from_unix_millis(newest) + ". " + rule.meaning);
    if (rule.fail_within_hours != 0U && newest >= now_unix_millis - static_cast<std::int64_t>(rule.fail_within_hours) * 3600000LL)
      fail = true;
  }
  if (ids.empty())
    return {"Could not check", "No events are listed for this step in port-exhaustion.json."};
  if (lines.empty())
    return {"Pass", "None of the events " + joined(ids) + " from " + joined(providers) + " in the " + log + " log in the last " +
                        std::to_string(days) + " days."};
  return {fail ? "Fail" : "Attention", joined(lines, " "), sources};
}

ScenarioCheckOutcome evaluate_rpc_firewall(const FirewallSnapshot& firewall, PortRange dynamic_tcp,
                                           const std::string& listener_program, const std::string& listener_services,
                                           const PortLimits& limits) {
  if (!limits.loaded)
    return {"Could not check", "The data file port-exhaustion.json is missing."};
  if (!firewall.readable)
    return {"Could not check", firewall.note.empty() ? std::string("The firewall could not be read.") : firewall.note};
  const std::uint16_t epmap_port = static_cast<std::uint16_t>(limits.epmap_port);
  const FirewallVerdict epmap = evaluate_inbound(firewall, PortProtocol::tcp, epmap_port, listener_program, listener_services);
  std::vector<const FirewallProfileState*> profiles;
  for (const FirewallProfileState& profile : firewall.profiles) {
    if (profile.active)
      profiles.push_back(&profile);
  }
  if (profiles.empty()) {
    for (const FirewallProfileState& profile : firewall.profiles)
      profiles.push_back(&profile);
  }
  if (profiles.empty())
    return {"Could not check", "The firewall reports no profile."};

  std::vector<std::string> lines;
  std::vector<std::string> failures;
  std::vector<std::string> attention;
  const std::string dynamic_text = std::to_string(dynamic_tcp.start) + " to " + std::to_string(dynamic_tcp.start + dynamic_tcp.count - 1U);
  for (const FirewallProfileState* profile : profiles) {
    std::string mapper_state;
    std::string mapper_because;
    for (const FirewallProfileVerdict& entry : epmap.per_profile) {
      if (entry.profile == profile->name) {
        mapper_state = to_string(entry.decision);
        mapper_because = entry.because;
        if (entry.decision == FirewallDecision::blocked)
          failures.push_back("On the " + profile->name + " profile the firewall blocks inbound TCP " + std::to_string(limits.epmap_port) +
                             ": " + entry.because + ".");
      }
    }
    const auto dynamic = rpc_dynamic_decision(firewall, *profile, dynamic_tcp);
    if (dynamic.first == FirewallDecision::blocked)
      failures.push_back("On the " + profile->name + " profile the firewall blocks inbound TCP " + dynamic_text + ": " + dynamic.second + ".");
    if (!profile->enabled) {
      lines.push_back(profile->name + " profile: the firewall is off.");
    } else {
      lines.push_back(profile->name + " profile: TCP " + std::to_string(limits.epmap_port) + " " + (mapper_state.empty() ? std::string("not evaluated") : mapper_state) +
                      (mapper_because.empty() ? std::string() : " (" + mapper_because + ")") + "; TCP " + dynamic_text + " " + to_string(dynamic.first) + " (" +
                      dynamic.second + ").");
    }
    if (profile->active && ascii_lower(profile->name) == "public")
      attention.push_back("The Public profile is in use" +
                          (profile->networks.empty() ? std::string() : " by " + joined(profile->networks)) + ".");
  }
  std::string found = joined(lines, " ");
  for (const std::string& line : failures)
    found += " " + line;
  for (const std::string& line : attention)
    found += " " + line;
  if (!epmap.note.empty()) {
    found += " " + epmap.note;
    attention.push_back(epmap.note);
  }
  return {!failures.empty() ? "Fail" : !attention.empty() ? "Attention" : "Pass", found};
}

} // namespace scenarios_detail

const std::string& local_vbr_major_version() {
  static const std::string major = [] {
    auto products = installed_veeam_products();
    if (!products.ok())
      return std::string();
    for (const InstalledProduct& product : products.value()) {
      if (product.name.rfind("Veeam Backup & Replication", 0) == 0 &&
          product.name.find("Console") == std::string::npos)
        return scenarios_detail::major_version(product.version);
    }
    return std::string();
  }();
  return major;
}

std::vector<ScenarioDefinition> available_scenarios(const ProductDiscoveryContext& context) {
  std::set<std::string> found;
  for (const auto& product : detect_products(context))
    found.insert(product.definition.id);
  std::vector<ScenarioDefinition> available;
  for (const ScenarioDefinition& definition : scenario_catalog()) {
    if (definition.windows_only && context.platform != HostPlatform::windows)
      continue;
    if (!definition.products.empty() &&
        std::none_of(definition.products.begin(), definition.products.end(),
                     [&found](const std::string& product) { return found.count(product) != 0U; }))
      continue;
    available.push_back(definition);
    // A starting value that differs by VBR version follows the version installed here.
    for (ScenarioInput& input : available.back().inputs) {
      if (!input.default_by_vbr.empty())
        input.default_value = scenarios_detail::input_default(input, local_vbr_major_version());
    }
  }
  return available;
}

const ScenarioDefinition* find_scenario(const std::string& id) {
  for (const ScenarioDefinition& definition : scenario_catalog()) {
    if (definition.id == id || std::find(definition.aliases.begin(), definition.aliases.end(), id) != definition.aliases.end())
      return &definition;
  }
  return nullptr;
}

ScenarioCheckOutcome scenario_sql_outcome(const SqlCheckReport& report) {
  std::vector<std::string> failed;
  std::vector<std::string> attention;
  std::vector<std::string> unread;
  std::string first;
  for (const SqlCheckRow& row : report.rows) {
    if (first.empty())
      first = row.detail;
    if (row.status == SqlCheckStatus::fail)
      failed.push_back(row.check + ": " + row.detail);
    else if (row.status == SqlCheckStatus::attention)
      attention.push_back(row.check + ": " + row.detail);
    else if (row.status == SqlCheckStatus::could_not_check)
      unread.push_back(row.check + ": " + row.detail);
  }
  if (!failed.empty())
    return {"Fail", joined(failed, " ")};
  if (!attention.empty())
    return {"Attention", joined(attention, " ")};
  if (!unread.empty())
    return {"Could not check", joined(unread, " ")};
  return {"Pass", first};
}

ScenarioCheckOutcome run_scenario_check(const std::string& check, const std::map<std::string, std::string>& params,
                                        const CancellationToken& cancel) {
  const auto found = check_table().find(check);
  if (found == check_table().end())
    return {"Could not check", "Unknown check: " + check + "."};
  const Outcome outcome = found->second(params, cancel);
  return {outcome.status, outcome.found};
}

ScenarioResult run_scenario(const std::string& id, const std::map<std::string, std::string>& inputs, bool keep_going,
                            const CancellationToken& cancel, ProgressCallback progress) {
  ScenarioResult result;
  const ScenarioDefinition* definition = find_scenario(id);
  const auto scenario = definition == nullptr ? scenarios().end()
                                              : std::find_if(scenarios().begin(), scenarios().end(), [&](const Scenario& entry) {
                                                  return entry.definition.id == definition->id;
                                                });
  if (scenario == scenarios().end()) {
    result.result = "Unknown scenario: " + id + ".";
    result.overall = "Fail";
    return result;
  }
  result.id = scenario->definition.id;
  result.title = scenario->definition.title;
  // An input not given takes its default.
  std::map<std::string, std::string> values = inputs;
  for (const ScenarioInput& input : scenario->definition.inputs) {
    if (trim(values[input.id]).empty())
      values[input.id] = input.default_by_vbr.empty() ? input.default_value
                                                      : scenarios_detail::input_default(input, local_vbr_major_version());
  }
#ifdef _WIN32
  constexpr bool on_windows = true;
#else
  constexpr bool on_windows = false;
#endif
  bool stopped = false;
  const std::size_t total = scenario->steps.size();
  for (std::size_t index = 0; index < total; ++index) {
    const Step& step = scenario->steps[index];
    ScenarioStepResult outcome;
    outcome.number = index + 1U;
    outcome.title = step.title;
    outcome.decisive = step.decisive;
    if (stopped || cancel.is_cancelled()) {
      outcome.status = "Not run";
      result.steps.push_back(std::move(outcome));
      continue;
    }
    if (progress) {
      ProgressEvent event;
      event.phase = step.title;
      event.processed = index + 1U;
      event.total = total;
      progress(event);
    }
    Params params;
    for (const auto& [key, value] : step.params)
      params[key] = !value.empty() && value[0] == '$' ? values[value.substr(1)] : value;
    // A step that needs an input left empty is not run: an empty server name would otherwise be
    // read as this machine.
    std::string missing;
    for (const auto& [key, value] : step.params) {
      if (value.empty() || value[0] != '$')
        continue;
      for (const ScenarioInput& input : scenario->definition.inputs) {
        if (input.id == value.substr(1) && !input.optional && trim(values[input.id]).empty() &&
            missing.find(input.label) == std::string::npos)
          missing += (missing.empty() ? "" : ", ") + input.label;
      }
    }
    Outcome checked;
    const auto check = check_table().find(step.check);
    if (!missing.empty())
      checked = {"Could not check", "Not given: " + missing + "."};
    else if (step.windows_only && !on_windows)
      checked = {"Not applicable", "Windows only."};
    else if (check == check_table().end())
      checked = {"Could not check", "Unknown check: " + step.check + "."};
    else
      checked = check->second(params, cancel);
    outcome.status = checked.status;
    outcome.found = checked.found;
    const auto meaning = step.meanings.find(checked.status);
    if (meaning != step.meanings.end()) {
      outcome.meaning = meaning->second.meaning;
      outcome.next = meaning->second.next;
      outcome.links = meaning->second.links;
    }
    // The sources of what was found (an event's own page), after the step's.
    for (const std::string& link : checked.links) {
      if (std::find(outcome.links.begin(), outcome.links.end(), link) == outcome.links.end())
        outcome.links.push_back(link);
    }
    if (step.decisive && checked.status == "Fail" && !keep_going)
      stopped = true;
    result.steps.push_back(std::move(outcome));
  }

  // The result: the first decisive failure, else every failure, else what to look at.
  const ScenarioStepResult* first_fail = nullptr;
  std::size_t failures = 0;
  std::size_t attention = 0;
  std::size_t passes = 0;
  std::vector<const ScenarioStepResult*> unchecked;
  for (const ScenarioStepResult& step : result.steps) {
    passes += step.status == "Pass" ? 1U : 0U;
    if (step.status == "Could not check")
      unchecked.push_back(&step);
    if (step.status == "Fail") {
      ++failures;
      if (first_fail == nullptr)
        first_fail = &step;
    }
    attention += step.status == "Attention" ? 1U : 0U;
  }
  const std::string of = " of " + std::to_string(total);
  if (stopped && first_fail != nullptr) {
    result.result = "Stopped at step " + std::to_string(first_fail->number) + of + ": " + first_fail->title + " (Fail).";
  } else if (failures != 0U) {
    result.result = std::to_string(failures) + (failures == 1U ? " step" : " steps") + of + " failed; the first is step " +
                    std::to_string(first_fail->number) + ": " + first_fail->title + ".";
  } else if (attention != 0U) {
    result.result = "No step failed; " + std::to_string(attention) + " to look at.";
  } else if (passes == 0U) {
    result.result = "No step could be checked.";
  } else if (!unchecked.empty()) {
    std::string names;
    for (const ScenarioStepResult* step : unchecked)
      names += (names.empty() ? "" : ", ") + std::to_string(step->number) + " " + step->title;
    result.result = "No step failed, but " + std::string(unchecked.size() == 1U ? "step " : "steps ") + names +
                    (unchecked.size() == 1U ? " could not be checked." : " could not be checked.");
  } else {
    result.result = "Every step passed.";
  }
  result.overall = failures != 0U      ? "Fail"
                   : attention != 0U   ? "Attention"
                   : passes == 0U      ? "Could not check"
                   : !unchecked.empty() ? "Attention"
                                        : "Pass";

  // The case note block.
  const ScenarioStepResult* lead = first_fail;
  if (lead == nullptr) {
    for (const ScenarioStepResult& step : result.steps) {
      if (step.status == "Attention") {
        lead = &step;
        break;
      }
    }
  }
  std::string note = "GUIDED DIAGNOSTIC  " + result.title + "\n";
  note += "Host " + this_machine() + "   Run " + utc_now_iso8601() + "\n";
  note += "RESULT  " + result.result + "\n";
  if (lead != nullptr) {
    note += "FOUND   " + lead->found + "\n";
    if (!lead->meaning.empty())
      note += "MEANING " + lead->meaning + "\n";
    if (!lead->next.empty())
      note += "NEXT    " + lead->next + "\n";
  }
  std::vector<std::string> passed;
  std::vector<std::string> not_run;
  std::vector<std::string> links;
  for (const ScenarioStepResult& step : result.steps) {
    if (step.status == "Pass")
      passed.push_back(std::to_string(step.number) + " " + step.title);
    else if (step.status == "Not run")
      not_run.push_back(std::to_string(step.number) + " " + step.title);
    for (const std::string& link : step.links) {
      if (std::find(links.begin(), links.end(), link) == links.end())
        links.push_back(link);
    }
  }
  if (!passed.empty())
    note += "PASSED  " + joined(passed, "   ") + "\n";
  if (!not_run.empty())
    note += "NOT RUN " + joined(not_run, "   ") + "\n";
  if (!links.empty())
    note += "LINKS   " + joined(links, "  ") + "\n";
  result.case_note = note;
  return result;
}

} // namespace support_assist
