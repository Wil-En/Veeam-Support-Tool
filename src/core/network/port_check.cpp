// Local Port Checker verdicts: the socket table and the firewall, read once, joined per port.
#include "support_assist/port_check.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <cstdlib>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#else
#include <climits>
#include <unistd.h>
#endif

namespace support_assist {
namespace {

FirewallSnapshot read_firewall_or_note() {
  auto firewall = read_firewall();
  if (firewall.ok())
    return std::move(firewall.value());
  FirewallSnapshot unread;
  unread.note = "The firewall could not be read: " + firewall.error().message + ".";
  return unread;
}

std::string environment_value(const char* name) {
#ifdef _WIN32
  char* value = nullptr;
  std::size_t length = 0;
  std::string text;
  if (_dupenv_s(&value, &length, name) == 0 && value != nullptr)
    text = value;
  std::free(value);
  return text;
#else
  const char* value = std::getenv(name);
  return value == nullptr ? std::string() : std::string(value);
#endif
}

// %ProgramFiles% and %ProgramFiles(x86)% in a program path, from the environment.
std::string expand_program(const std::string& program) {
  std::string out = program;
  for (const char* name : {"ProgramFiles(x86)", "ProgramFiles"}) {
    const std::string token = std::string("%") + name + "%";
    const std::size_t at = out.find(token);
    if (at == std::string::npos)
      continue;
    const std::string value = environment_value(name);
    if (value.empty())
      return {};
    out.replace(at, token.size(), value);
  }
  return out;
}

// The first program of the list that exists here; empty when none does.
std::string present_program(const std::vector<std::string>& programs) {
  for (const std::string& program : programs) {
    const std::string path = expand_program(program);
    std::error_code error;
    if (!path.empty() && std::filesystem::is_regular_file(path_from_utf8(path), error))
      return path;
  }
  return {};
}

// "2869", or "2869 (loopback only)" for a port no other host can reach.
std::string port_scope_text(const LocalPortState& state) {
  return std::to_string(state.port) + (state.scope == ListenScope::loopback_only ? " (loopback only)" : "");
}

std::string text_list(const std::vector<std::string>& items, std::size_t shown) {
  std::string text;
  for (std::size_t index = 0; index < items.size() && index < shown; ++index)
    text += (index == 0 ? "" : ", ") + items[index];
  if (items.size() > shown)
    text += " and " + std::to_string(items.size() - shown) + " more";
  return text;
}

std::string file_name_of(const std::string& path) {
  const std::size_t slash = path.find_last_of("\\/");
  return slash == std::string::npos ? path : path.substr(slash + 1U);
}

} // namespace

std::string port_label(const PortCheckRow& row) {
  return row.range.empty() ? std::to_string(row.state.port) : row.range;
}

std::vector<PortCheckRow> assess_range(const PortRangeQuery& range, PortProtocol protocol,
                                       const std::vector<LocalSocket>& sockets, const FirewallSnapshot& firewall,
                                       const std::string& program) {
  std::vector<std::uint16_t> ports;
  for (std::uint32_t port = range.first; port <= range.last && port != 0U; ++port)
    ports.push_back(static_cast<std::uint16_t>(port));
  const bool tcp = protocol == PortProtocol::tcp;
  const std::vector<LocalPortState> states = summarize_local_ports(sockets, ports, tcp, !tcp);
  // The range's own holder is the data mover: the program the entry names, or VeeamAgent by its
  // name when it names none. A range any program takes (dynamic RPC) has no other holders.
  const std::string expected = range.programs.empty() ? std::string() : ascii_lower(file_name_of(range.programs.front()));
  const auto own = [&](const LocalPortState& state) {
    if (range.any_program)
      return true;
    if (state.owners.empty() || state.owners.front().pid == 0)
      return false;
    const std::string name = ascii_lower(state.owners.front().process_name);
    return expected.empty() ? name.rfind("veeamagent", 0) == 0 : name == expected;
  };
  const auto holder_name = [](const LocalPortState& state) {
    const LocalSocket* owner = state.owners.empty() ? nullptr : &state.owners.front();
    return owner == nullptr || owner->pid == 0 ? std::string("a process this account cannot read")
                                               : owner->process_name + " (PID " + std::to_string(owner->pid) + ")";
  };
  std::vector<const LocalPortState*> held;
  std::vector<const LocalPortState*> others;
  for (const LocalPortState& state : states) {
    if (state.listening)
      (own(state) ? held : others).push_back(&state);
  }
  const std::string text = std::to_string(range.first) + "-" + std::to_string(range.last);
  const std::string mover = range.any_program ? std::string()
                            : program.empty() ? std::string("the data mover")
                                              : file_name_of(program) + ", the data mover";
  PortCheckRow row;
  if (!held.empty()) {
    row = assess_port(*held.front(), firewall);
    for (std::size_t index = 1; index < held.size(); ++index) {
      for (const LocalSocket& owner : held[index]->owners) {
        const bool known = std::any_of(row.state.owners.begin(), row.state.owners.end(),
                                       [&](const LocalSocket& kept) { return kept.pid == owner.pid; });
        if (!known)
          row.state.owners.push_back(owner);
      }
    }
    const std::string verdict_text = row.explanation;
    // The ports each program holds, in the order first seen.
    std::vector<std::pair<std::string, std::vector<std::string>>> by_program;
    for (const LocalPortState* state : held) {
      row.held.push_back(state->port);
      const std::string name = holder_name(*state);
      auto found = std::find_if(by_program.begin(), by_program.end(), [&](const auto& kept) { return kept.first == name; });
      if (found == by_program.end())
        by_program.push_back({name, {port_scope_text(*state)}});
      else
        found->second.push_back(port_scope_text(*state));
    }
    std::string holders;
    for (const auto& [name, held_ports] : by_program)
      holders += (holders.empty() ? "" : "; ") + text_list(held_ports, 8U) + " by " + name;
    row.explanation = (range.any_program ? "Held now: " : "Held by the data mover now: ") + holders + ". " + verdict_text;
  } else {
    LocalPortState idle;
    idle.port = range.first;
    idle.protocol = protocol;
    row.state = idle;
    // Windows' Veeam rules allow a program on any port: without the program here, a verdict for no
    // program would read the range as blocked.
#ifdef _WIN32
    const bool judged = !program.empty();
#else
    const bool judged = true;
#endif
    if (judged)
      row.firewall = evaluate_inbound(firewall, protocol, range.first, program, std::string());
    const FirewallDecision decision = row.firewall.decision;
    const std::string holder = program.empty() ? std::string("the data mover") : file_name_of(program);
    row.explanation = others.empty() || range.any_program ? "None of the range is held now."
                                                          : "None of the range is held by the data mover now.";
    if (!range.about.empty())
      row.explanation += " " + range.about;
    if (!judged)
      row.explanation += " The data mover is not installed here, so the firewall was not judged for it.";
    if (decision == FirewallDecision::blocked && !row.firewall.mixed) {
      row.verdict = PortVerdict::closed_and_blocked;
      row.explanation += " This machine's firewall blocks the range for " + holder +
                         ", so a job's data connections to it would time out.";
    } else {
      row.verdict = PortVerdict::not_listening;
      if (decision == FirewallDecision::allowed)
        row.explanation += " This machine's firewall lets " + holder + " in on it.";
      else if (decision == FirewallDecision::firewall_off)
        row.explanation += " The firewall is off.";
      else if (row.firewall.mixed)
        row.explanation += " The firewall lets it in on some active profiles and blocks it on others.";
    }
  }
  row.range = text;

  // Another program on a port of the range: a row of its own, so its verdict is not the range's.
  std::vector<PortCheckRow> rows{row};
  if (!others.empty()) {
    std::vector<std::string> other_ports;
    for (const LocalPortState* state : others)
      other_ports.push_back(port_scope_text(*state));
    rows.front().explanation += " Held by other programs: " + text_list(other_ports, 8U) +
                                (others.size() > kRangeOtherRows ? ", the first " + std::to_string(kRangeOtherRows) +
                                                                       " on rows of their own."
                                                                 : ", on rows of their own.");
    for (std::size_t index = 0; index < others.size() && index < kRangeOtherRows; ++index) {
      PortCheckRow other = assess_port(*others[index], firewall);
      other.in_range = text;
      other.explanation = "In the " + text + " range, held by " + holder_name(*others[index]) + ", not by " + mover +
                          ". " + other.explanation;
      rows.push_back(std::move(other));
    }
  }
  return rows;
}

std::vector<PortRangeQuery> preset_ranges(const PortPreset& preset) {
  std::vector<PortRangeQuery> ranges;
  for (const PortPresetEntry& entry : preset.entries) {
    if (!entry.dynamic)
      continue;
    auto ports = parse_port_list(entry.ports, 70000);
    if (!ports.ok() || ports.value().empty())
      continue;
    PortRangeQuery range;
    range.first = *std::min_element(ports.value().begin(), ports.value().end());
    range.last = *std::max_element(ports.value().begin(), ports.value().end());
    range.tcp = entry.tcp;
    range.udp = entry.udp;
    range.programs = entry.programs;
    range.any_program = entry.any_program;
    range.about = entry.from.empty() ? entry.note : "From " + entry.from + "." + (entry.note.empty() ? "" : " " + entry.note);
    const bool seen = std::any_of(ranges.begin(), ranges.end(), [&](const PortRangeQuery& kept) {
      return kept.first == range.first && kept.last == range.last && kept.tcp == range.tcp && kept.udp == range.udp;
    });
    if (!seen)
      ranges.push_back(std::move(range));
  }
  return ranges;
}

std::string to_string(PortVerdict verdict) {
  switch (verdict) {
  case PortVerdict::open: return "Open";
  case PortVerdict::open_some_profiles: return "Open on some profiles";
  case PortVerdict::blocked_here: return "Blocked here";
  case PortVerdict::local_only: return "Local only";
  case PortVerdict::closed: return "Closed";
  case PortVerdict::closed_and_blocked: return "Closed and blocked";
  case PortVerdict::listening: return "Listening";
  case PortVerdict::not_listening: break;
  }
  return "Not listening";
}

PortCheckRow assess_port(const LocalPortState& state, const FirewallSnapshot& firewall) {
  PortCheckRow row;
  row.state = state;
  const std::string program = state.owners.empty() ? std::string() : state.owners.front().process_path;
  const std::string services = state.owners.empty() ? std::string() : state.owners.front().services;
  row.firewall = evaluate_inbound(firewall, state.protocol, state.port, program, services);
  const bool udp = state.protocol == PortProtocol::udp;
  const FirewallDecision decision = row.firewall.decision;

  if (state.listening && state.scope == ListenScope::loopback_only) {
    row.verdict = PortVerdict::local_only;
    row.explanation = "Listening on the loopback address only; other hosts cannot reach it.";
  } else if (state.listening) {
    if (decision == FirewallDecision::not_evaluated) {
      row.verdict = PortVerdict::listening;
      row.explanation = udp ? "Bound; the firewall was not read." : "Listening; the firewall was not read.";
    } else if (row.firewall.mixed) {
      row.verdict = PortVerdict::open_some_profiles;
      row.explanation = "The firewall lets it in on some active profiles and blocks it on others.";
    } else if (decision == FirewallDecision::blocked) {
      row.verdict = PortVerdict::blocked_here;
      row.explanation = "Listening, but this machine's firewall blocks inbound connections; another host "
                        "sees a timeout.";
    } else {
      row.verdict = PortVerdict::open;
      row.explanation = udp ? "Bound, and this machine lets it in. UDP has no handshake, so this is as far as "
                              "this machine can tell."
                            : "Listening, and this machine lets it in.";
    }
  } else if (decision == FirewallDecision::blocked) {
    row.verdict = PortVerdict::closed_and_blocked;
    row.explanation = "Nothing listens, and the firewall drops the attempt; another host sees a timeout.";
  } else if (decision == FirewallDecision::not_evaluated) {
    row.verdict = PortVerdict::not_listening;
    row.explanation = udp ? "Nothing is bound to it." : "Nothing listens on it.";
  } else {
    row.verdict = PortVerdict::closed;
    row.explanation = udp ? "Nothing is bound to it." : "Nothing listens; another host gets \"connection refused\".";
  }
  return row;
}

Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& ports, bool tcp, bool udp) {
  return check_local_ports(tcp ? ports : std::vector<std::uint16_t>{}, udp ? ports : std::vector<std::uint16_t>{});
}

Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& tcp_ports,
                                          const std::vector<std::uint16_t>& udp_ports) {
  auto sockets = list_local_sockets();
  if (!sockets.ok())
    return Result<PortCheckResult>::failure(sockets.error());
  PortCheckResult result;
  result.checked_unix_millis = unix_millis_now();
  result.sockets_note = sockets.value().note;
  result.firewall = read_firewall_or_note();
  for (const LocalPortState& state : summarize_local_ports(sockets.value().sockets, tcp_ports, true, false))
    result.rows.push_back(assess_port(state, result.firewall));
  for (const LocalPortState& state : summarize_local_ports(sockets.value().sockets, udp_ports, false, true))
    result.rows.push_back(assess_port(state, result.firewall));
  return Result<PortCheckResult>::success(std::move(result));
}

PortQueryExtras preset_extras(const PortPreset& preset) {
  PortQueryExtras extras;
  extras.ranges = preset_ranges(preset);
  for (const PortPresetEntry& entry : preset.entries) {
    if (!entry.loopback || entry.dynamic)
      continue;
    auto ports = parse_port_list(entry.ports, 70000);
    if (!ports.ok())
      continue;
    for (const std::uint16_t port : ports.value()) {
      if (entry.tcp)
        extras.loopback_tcp.push_back(port);
      if (entry.udp)
        extras.loopback_udp.push_back(port);
    }
  }
  return extras;
}

void explain_loopback_port(PortCheckRow& row) {
  if (row.verdict == PortVerdict::local_only) {
    row.explanation = "Listening on the loopback address only, as this service does: only programs on this "
                      "machine connect to it.";
  } else if (!row.state.listening) {
    row.explanation = "Nothing listens on it: the service that holds it on the loopback address is stopped or "
                      "not installed.";
  } else {
    row.explanation += " This service usually listens on the loopback address only.";
  }
}

Result<PortCheckResult> check_local_ports(const std::vector<std::uint16_t>& tcp_ports,
                                          const std::vector<std::uint16_t>& udp_ports,
                                          const PortQueryExtras& extras) {
  const auto& ranges = extras.ranges;
  auto sockets = list_local_sockets();
  if (!sockets.ok())
    return Result<PortCheckResult>::failure(sockets.error());
  PortCheckResult result;
  result.checked_unix_millis = unix_millis_now();
  result.sockets_note = sockets.value().note;
  result.firewall = read_firewall_or_note();
  for (const LocalPortState& state : summarize_local_ports(sockets.value().sockets, tcp_ports, true, false))
    result.rows.push_back(assess_port(state, result.firewall));
  for (const LocalPortState& state : summarize_local_ports(sockets.value().sockets, udp_ports, false, true))
    result.rows.push_back(assess_port(state, result.firewall));
  for (PortCheckRow& row : result.rows) {
    const auto& loopback = row.state.protocol == PortProtocol::udp ? extras.loopback_udp : extras.loopback_tcp;
    if (std::find(loopback.begin(), loopback.end(), row.state.port) != loopback.end())
      explain_loopback_port(row);
  }
  for (const PortRangeQuery& range : ranges) {
    const std::string program = present_program(range.programs);
    for (const PortProtocol protocol : {PortProtocol::tcp, PortProtocol::udp}) {
      if (protocol == PortProtocol::tcp ? !range.tcp : !range.udp)
        continue;
      for (PortCheckRow& row : assess_range(range, protocol, sockets.value().sockets, result.firewall, program))
        result.rows.push_back(std::move(row));
    }
  }
  return Result<PortCheckResult>::success(std::move(result));
}

std::vector<PortPreset> port_presets() {
#ifdef _WIN32
  return port_presets_for("windows");
#else
  return port_presets_for("linux");
#endif
}

std::vector<PortPreset> port_presets_for(const std::string& system) {
  return port_presets_for(system, {});
}

std::vector<PortPreset> port_presets_for(const std::string& system, const std::string& version) {
  std::vector<PortPreset> presets;
  const JsonValue& data = data_file("ports.json");
  for (const JsonValue& role : data["roles"].items()) {
    PortPreset preset;
    preset.id = role["id"].as_string();
    preset.name = role["name"].as_string();
    for (const JsonValue& item : role["listens"].items()) {
      const std::string platform = item["platform"].as_string();
      if (!system.empty() && !platform.empty() && platform != system)
        continue;
      PortPresetEntry entry;
      entry.versions = item["versions"].string_items();
      if (!version.empty() && !entry.versions.empty() &&
          std::find(entry.versions.begin(), entry.versions.end(), version) == entry.versions.end())
        continue;
      entry.platform = platform;
      const std::string protocol = item["protocol"].as_string();
      entry.tcp = protocol.find("tcp") != std::string::npos;
      entry.udp = protocol.find("udp") != std::string::npos;
      entry.ports = item["ports"].as_string();
      entry.from = item["from"].as_string();
      entry.note = item["note"].as_string();
      // Listed in one version's guide only: said so where no version was chosen.
      if (version.empty() && entry.versions.size() == 1U)
        entry.note = "VBR " + entry.versions.front() + " only" + (entry.note.empty() ? std::string() : "; " + entry.note);
      entry.optional = item["optional"].as_bool();
      entry.dynamic = item["dynamic"].as_bool();
      entry.one_of = item["one_of"].as_bool();
      entry.programs = item["programs"].string_items();
      entry.loopback = item["loopback"].as_bool();
      entry.any_program = item["any_program"].as_bool();
      // The role's page: its first entry's, or for VBR 12 the first entry from a VBR 12 page.
      const std::string source_id = item["source"].as_string();
      const bool version_page = version == "12" && source_id.rfind("vbr12", 0) == 0 &&
                                preset.source_url.find("ver=120") == std::string::npos;
      if (preset.source_url.empty() || version_page) {
        const JsonValue& source = data["sources"][source_id];
        preset.source_title = source["title"].as_string();
        preset.source_url = source["url"].as_string();
      }
      preset.entries.push_back(std::move(entry));
    }
    if (!preset.id.empty())
      presets.push_back(std::move(preset));
  }
  return presets;
}

const PortPreset* find_port_preset(const std::vector<PortPreset>& presets, const std::string& id) {
  for (const PortPreset& preset : presets) {
    if (preset.id == id)
      return &preset;
  }
  return nullptr;
}

void preset_ports(const PortPreset& preset, std::vector<std::uint16_t>& tcp, std::vector<std::uint16_t>& udp) {
  for (const PortPresetEntry& entry : preset.entries) {
    if (entry.dynamic)
      continue;
    auto ports = parse_port_list(entry.ports, 70000);
    if (!ports.ok())
      continue;
    std::vector<std::uint16_t> chosen = ports.value();
    // A service that takes the first free port of a range uses one of them: the port it listens on,
    // or the range's first port when nothing in the range listens.
    if (entry.one_of && chosen.size() > 1U) {
      std::vector<std::uint16_t> listening;
      if (auto sockets = list_local_sockets(); sockets.ok()) {
        for (const LocalPortState& state : summarize_local_ports(sockets.value().sockets, chosen, entry.tcp, entry.udp)) {
          if (state.listening && std::find(listening.begin(), listening.end(), state.port) == listening.end())
            listening.push_back(state.port);
        }
      }
      chosen = listening.empty() ? std::vector<std::uint16_t>{chosen.front()} : listening;
    }
    for (const std::uint16_t port : chosen) {
      if (entry.tcp && std::find(tcp.begin(), tcp.end(), port) == tcp.end())
        tcp.push_back(port);
      if (entry.udp && std::find(udp.begin(), udp.end(), port) == udp.end())
        udp.push_back(port);
    }
  }
  std::sort(tcp.begin(), tcp.end());
  std::sort(udp.begin(), udp.end());
}

Result<PortCheckResult> check_process_ports(const std::string& process) {
  auto sockets = list_local_sockets();
  if (!sockets.ok())
    return Result<PortCheckResult>::failure(sockets.error());
  PortCheckResult result;
  result.checked_unix_millis = unix_millis_now();
  result.sockets_note = sockets.value().note;
  result.firewall = read_firewall_or_note();
  for (const LocalPortState& state : ports_held_by_process(sockets.value().sockets, process))
    result.rows.push_back(assess_port(state, result.firewall));
  return Result<PortCheckResult>::success(std::move(result));
}

std::vector<FirewallRule> rules_for_program(const FirewallSnapshot& firewall, const std::string& program_path) {
  std::vector<FirewallRule> rules;
  if (trim(program_path).empty())
    return rules;
  for (const FirewallRule& rule : firewall.rules) {
    if (!trim(rule.program).empty() && rule.program != "*" &&
        firewall_detail::program_matches(rule.program, program_path))
      rules.push_back(rule);
  }
  return rules;
}

std::string current_executable_path() {
#ifdef _WIN32
  std::wstring path(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
  if (length == 0 || length >= path.size())
    return {};
  path.resize(length);
  return utf8_from_wide(path);
#else
  char path[PATH_MAX] = {};
  const ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
  return length > 0 ? std::string(path, static_cast<std::size_t>(length)) : std::string();
#endif
}

} // namespace support_assist
