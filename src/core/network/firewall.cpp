// Firewall evaluation shared by every platform: which active profile or zone lets an inbound
// connection through to a port and program, and the parsers for the Linux front-ends' text.
#include "support_assist/firewall.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <cstdlib>

namespace support_assist {
namespace firewall_detail {
namespace {

bool is_wildcard(std::string_view text) {
  const std::string value = ascii_lower(trim(text));
  return value.empty() || value == "*" || value == "any";
}

bool parse_number(std::string_view text, unsigned long& value) {
  const std::string item = trim(text);
  if (item.empty() || item.size() > 5 || item.find_first_not_of("0123456789") != std::string::npos)
    return false;
  value = std::strtoul(item.c_str(), nullptr, 10);
  return value <= 65535U;
}

// %SystemRoot% and similar, as the firewall stores program paths.
std::string expand_variables(std::string_view text) {
  std::string out;
  for (std::size_t at = 0; at < text.size();) {
    if (text[at] == '%') {
      const std::size_t end = text.find('%', at + 1);
      if (end != std::string_view::npos && end > at + 1) {
        const std::string name(text.substr(at + 1, end - at - 1));
#ifdef _WIN32
        char* value = nullptr;
        std::size_t length = 0;
        if (_dupenv_s(&value, &length, name.c_str()) == 0 && value != nullptr) {
          out += value;
          std::free(value);
          at = end + 1;
          continue;
        }
        std::free(value);
#else
        if (const char* value = std::getenv(name.c_str())) {
          out += value;
          at = end + 1;
          continue;
        }
#endif
      }
    }
    out += text[at];
    ++at;
  }
  return out;
}

std::string normalised_path(std::string_view text) {
  std::string value = ascii_lower(trim(expand_variables(text)));
  std::replace(value.begin(), value.end(), '/', '\\');
  return value;
}

std::string file_name_of(std::string_view path) {
  const std::size_t slash = path.find_last_of("\\/");
  return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

std::vector<std::string> lines_of(std::string_view text) {
  std::vector<std::string> lines = split(text, '\n');
  for (std::string& line : lines) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
  }
  return lines;
}

std::vector<std::string> words_of(std::string_view text) {
  std::vector<std::string> words;
  for (const std::string& word : split(text, ' ')) {
    const std::string item = trim(word);
    if (!item.empty())
      words.push_back(item);
  }
  return words;
}

int protocol_number(std::string_view name) {
  const std::string value = ascii_lower(trim(name));
  if (value == "tcp")
    return 6;
  if (value == "udp")
    return 17;
  return value.empty() ? 256 : -1;
}

// name="value" or name='value' inside an XML element or a firewalld rich rule.
std::string attribute_value(std::string_view text, std::string_view name) {
  std::size_t at = 0;
  const std::string key = std::string(name) + "=";
  while ((at = text.find(key, at)) != std::string_view::npos) {
    const bool starts_word = at == 0 || text[at - 1] == ' ' || text[at - 1] == '\t' || text[at - 1] == '<';
    const std::size_t quote_at = at + key.size();
    if (starts_word && quote_at < text.size() && (text[quote_at] == '"' || text[quote_at] == '\'')) {
      const std::size_t end = text.find(text[quote_at], quote_at + 1);
      if (end != std::string_view::npos)
        return std::string(text.substr(quote_at + 1, end - quote_at - 1));
    }
    at = quote_at;
  }
  return {};
}

// Words of a rich rule, keeping a quoted value with its spaces in one word.
std::vector<std::string> rich_rule_words(std::string_view text) {
  std::vector<std::string> words;
  std::string current;
  char quote = 0;
  for (const char c : text) {
    if (quote != 0) {
      current += c;
      if (c == quote)
        quote = 0;
    } else if (c == '"' || c == '\'') {
      quote = c;
      current += c;
    } else if (c == ' ' || c == '\t') {
      if (!current.empty())
        words.push_back(std::move(current));
      current.clear();
    } else {
      current += c;
    }
  }
  if (!current.empty())
    words.push_back(std::move(current));
  return words;
}

std::string unquoted_value(std::string_view word) {
  const std::size_t equals = word.find('=');
  if (equals == std::string_view::npos)
    return {};
  std::string value(word.substr(equals + 1));
  if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') && value.back() == value.front())
    value = value.substr(1, value.size() - 2);
  return value;
}

FirewallRule firewalld_rule(std::string name, const std::string& zone, std::string ports, int protocol, bool allow) {
  FirewallRule rule;
  rule.name = std::move(name);
  rule.zone = zone;
  rule.local_ports = std::move(ports);
  rule.protocol = protocol;
  rule.allow = allow;
  return rule;
}

const std::vector<std::pair<std::string, int>>* ports_of_service(
    const std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>>& service_ports,
    const std::string& service) {
  for (const auto& [name, ports] : service_ports) {
    if (name == service)
      return &ports;
  }
  return nullptr;
}

// One rich rule: its service or port, the source it is limited to, and whether it accepts. Rules
// that forward, masquerade or match ICMP describe no local listener and add nothing.
void add_rich_rule(const std::string& text, const std::string& zone,
                   const std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>>& service_ports,
                   std::vector<FirewallRule>& rules) {
  const std::vector<std::string> words = rich_rule_words(text);
  std::string source;
  std::string port;
  std::string protocol;
  std::string service;
  bool port_element = false;
  bool other_element = false;
  int action = 0; // 1 accept, 2 reject or drop
  for (std::size_t i = 0; i < words.size(); ++i) {
    const std::string& word = words[i];
    if (word == "source" || word == "destination") {
      // source [NOT] address="10.0.0.0/8" | mac=".." | ipset=".."
      const bool is_source = word == "source";
      std::string limit;
      if (i + 1 < words.size() && words[i + 1] == "NOT") {
        limit = "not ";
        ++i;
      }
      while (i + 1 < words.size() && words[i + 1].find('=') != std::string::npos) {
        ++i;
        limit += unquoted_value(words[i]);
      }
      if (is_source)
        source = limit;
    } else if (word == "port") {
      port_element = true;
    } else if (word.rfind("port=", 0) == 0 && port_element) {
      port = unquoted_value(word);
    } else if (word.rfind("protocol=", 0) == 0 && port_element) {
      protocol = unquoted_value(word);
    } else if (word == "service") {
      if (i + 1 < words.size() && words[i + 1].rfind("name=", 0) == 0)
        service = unquoted_value(words[++i]);
    } else if (word == "forward-port" || word == "masquerade" || word == "icmp-block" ||
               word == "icmp-type" || word == "protocol" || word == "source-port") {
      other_element = true;
    } else if (word == "accept") {
      action = 1;
    } else if (word == "reject" || word == "drop") {
      action = 2;
    }
  }
  if (action == 0 || other_element)
    return;
  const bool allow = action == 1;
  std::vector<FirewallRule> added;
  if (!service.empty()) {
    if (const auto* ports = ports_of_service(service_ports, service)) {
      for (const auto& [spec, number] : *ports)
        added.push_back(firewalld_rule("rich rule: service " + service, zone, spec, number, allow));
    }
  } else if (!port.empty()) {
    const int number = protocol_number(protocol);
    if (number > 0)
      added.push_back(firewalld_rule("rich rule: " + port + "/" + protocol, zone, port, number, allow));
  } else {
    added.push_back(firewalld_rule("rich rule: every port", zone, "*", 256, allow));
  }
  for (FirewallRule& rule : added) {
    rule.remote_addresses = source;
    rules.push_back(std::move(rule));
  }
}

// "22/tcp", "80,443/tcp", "60000:61000/udp", "137,138/udp|139,445/tcp" (ufw application ports).
void add_ufw_ports(std::string_view spec, const std::string& name, bool allow, const std::string& from,
                   std::vector<FirewallRule>& rules) {
  for (const std::string& part : split(spec, '|')) {
    std::string ports = trim(part);
    int protocol = 256;
    if (const std::size_t slash = ports.find('/'); slash != std::string::npos) {
      protocol = protocol_number(ports.substr(slash + 1));
      ports.resize(slash);
    }
    if (protocol < 0 || ports.empty())
      continue;
    std::replace(ports.begin(), ports.end(), ':', '-');
    FirewallRule rule;
    rule.name = name;
    rule.allow = allow;
    rule.protocol = protocol;
    rule.local_ports = ports;
    rule.remote_addresses = from;
    rules.push_back(std::move(rule));
  }
}

} // namespace

bool rule_applies_generally(const FirewallRule& rule) {
  if (!trim(rule.app_package).empty() || !trim(rule.user_condition).empty() || rule.requires_ipsec)
    return false;
  const std::string types = ascii_lower(rule.interface_types);
  return types.empty() || types.find("all") != std::string::npos || types.find("lan") != std::string::npos;
}

namespace {

bool is_port_spec(std::string_view text) {
  const std::string value = trim(text);
  const std::string ports = value.substr(0, value.find('/'));
  return !ports.empty() && ports.find_first_not_of("0123456789,:") == std::string::npos;
}

} // namespace

bool port_spec_matches(std::string_view spec, std::uint16_t port) {
  if (is_wildcard(spec))
    return true;
  for (const std::string& token : split(spec, ',')) {
    // RPC-EPMap is the RPC endpoint mapper, TCP 135; RPC and IPHTTPS name no single port.
    if (ascii_lower(trim(token)) == "rpc-epmap") {
      if (port == 135)
        return true;
      continue;
    }
    const std::size_t dash = token.find('-');
    unsigned long first = 0;
    unsigned long last = 0;
    if (dash == std::string::npos) {
      if (parse_number(token, first) && first == port)
        return true;
      continue; // a keyword such as RPC or IPHTTPS names no single port
    }
    if (parse_number(token.substr(0, dash), first) && parse_number(token.substr(dash + 1), last) &&
        port >= first && port <= last)
      return true;
  }
  return false;
}

bool program_matches(std::string_view rule_program, std::string_view program_path) {
  if (is_wildcard(rule_program))
    return true;
  if (trim(program_path).empty())
    return false;
  return normalised_path(rule_program) == normalised_path(program_path);
}

bool service_matches(std::string_view rule_service, std::string_view services) {
  const std::string wanted = ascii_lower(trim(rule_service));
  if (wanted.empty())
    return true;
  const std::string hosted = ascii_lower(services);
  if (wanted == "*")
    return !trim(hosted).empty();
  for (const std::string& name : split(hosted, ',')) {
    if (trim(name) == wanted)
      return true;
  }
  return false;
}

std::vector<FirewalldZone> parse_firewalld_zones(std::string_view text) {
  std::vector<FirewalldZone> zones;
  for (const std::string& line : lines_of(text)) {
    const std::string item = trim(line);
    if (item.empty())
      continue;
    if (line.front() != ' ' && line.front() != '\t') {
      FirewalldZone zone;
      zone.name = item;
      // "public (active)", and on newer firewalld "public (default, active)".
      if (const std::size_t paren = item.find(" ("); paren != std::string::npos) {
        const std::string flags = item.substr(paren);
        zone.name = item.substr(0, paren);
        zone.active = flags.find("active") != std::string::npos;
        zone.is_default = flags.find("default") != std::string::npos;
      }
      zones.push_back(std::move(zone));
      continue;
    }
    if (zones.empty())
      continue;
    FirewalldZone& zone = zones.back();
    if (item.rfind("rule ", 0) == 0) {
      zone.rich_rules.push_back(item);
      continue;
    }
    const std::size_t colon = item.find(':');
    if (colon == std::string::npos)
      continue;
    const std::string key = item.substr(0, colon);
    const std::string value = trim(item.substr(colon + 1));
    if (key == "target")
      zone.target = value;
    else if (key == "interfaces")
      zone.interfaces = words_of(value);
    else if (key == "sources")
      zone.sources = words_of(value);
    else if (key == "services")
      zone.services = words_of(value);
    else if (key == "ports")
      zone.ports = words_of(value);
  }
  return zones;
}

std::vector<std::pair<std::string, int>> parse_firewalld_service_ports(std::string_view xml) {
  std::vector<std::pair<std::string, int>> ports;
  std::size_t at = 0;
  while ((at = xml.find("<port", at)) != std::string_view::npos) {
    const std::size_t after = at + 5;
    const std::size_t end = xml.find('>', after);
    if (end == std::string_view::npos)
      break;
    if (after < xml.size() && (xml[after] == ' ' || xml[after] == '\t' || xml[after] == '\n' || xml[after] == '\r')) {
      const std::string_view element = xml.substr(at, end - at);
      const std::string port = attribute_value(element, "port");
      const int protocol = protocol_number(attribute_value(element, "protocol"));
      if (!port.empty() && (protocol == 6 || protocol == 17))
        ports.emplace_back(port, protocol);
    }
    at = end;
  }
  return ports;
}

void add_firewalld_zones(const std::vector<FirewalldZone>& zones,
                         const std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>>& service_ports,
                         FirewallSnapshot& snapshot) {
  const bool any_active = std::any_of(zones.begin(), zones.end(), [](const FirewalldZone& zone) { return zone.active; });
  for (const FirewalldZone& zone : zones) {
    if (!(zone.active || (!any_active && zone.is_default)))
      continue;
    FirewallProfileState profile;
    profile.name = zone.name;
    profile.active = true;
    profile.inbound_blocked_by_default = ascii_upper(zone.target) != "ACCEPT";
    for (const std::string& name : zone.interfaces)
      profile.networks.push_back("interface " + name);
    for (const std::string& source : zone.sources)
      profile.networks.push_back("source " + source);
    if (profile.networks.empty() && zone.is_default)
      profile.networks.push_back("interfaces bound to no other zone");
    snapshot.profiles.push_back(std::move(profile));

    for (const std::string& service : zone.services) {
      if (const auto* ports = ports_of_service(service_ports, service)) {
        for (const auto& [spec, number] : *ports)
          snapshot.rules.push_back(firewalld_rule("service " + service, zone.name, spec, number, true));
      }
    }
    for (const std::string& port : zone.ports) {
      const std::size_t slash = port.find('/');
      if (slash == std::string::npos)
        continue;
      const int number = protocol_number(port.substr(slash + 1));
      if (number > 0)
        snapshot.rules.push_back(firewalld_rule("port " + port, zone.name, port.substr(0, slash), number, true));
    }
    for (const std::string& rule : zone.rich_rules)
      add_rich_rule(rule, zone.name, service_ports, snapshot.rules);
  }
}

bool parse_ufw_status(std::string_view text,
                      const std::vector<std::pair<std::string, std::string>>& app_ports,
                      FirewallSnapshot& snapshot) {
  FirewallProfileState profile;
  profile.name = "ufw";
  profile.active = true;
  bool status_seen = false;
  bool rows = false;
  std::vector<FirewallRule> rules;
  for (const std::string& line : lines_of(text)) {
    const std::string item = trim(line);
    if (item.rfind("Status:", 0) == 0) {
      status_seen = true;
      profile.enabled = trim(item.substr(7)) == "active";
      continue;
    }
    if (item.rfind("Default:", 0) == 0) {
      // "Default: deny (incoming), allow (outgoing), disabled (routed)"
      for (const std::string& part : split(item.substr(8), ',')) {
        const std::string value = trim(part);
        if (value.find("(incoming)") != std::string::npos)
          profile.inbound_blocked_by_default = value.rfind("allow", 0) != 0;
      }
      continue;
    }
    if (item.rfind("--", 0) == 0) {
      rows = true;
      continue;
    }
    if (!rows || item.empty())
      continue;

    // "22/tcp   ALLOW IN   Anywhere", "OpenSSH (v6)   ALLOW IN   Anywhere (v6)"
    std::size_t action_at = std::string::npos;
    std::string action;
    for (const char* keyword : {" ALLOW", " DENY", " REJECT", " LIMIT"}) {
      const std::size_t found = line.find(keyword);
      if (found != std::string::npos && found < action_at) {
        action_at = found;
        action = trim(keyword);
      }
    }
    if (action_at == std::string::npos)
      continue;
    std::string destination = trim(line.substr(0, action_at));
    std::string rest = trim(line.substr(action_at + 1 + action.size()));
    std::string direction = "IN";
    for (const char* word : {"IN", "OUT", "FWD"}) {
      const std::string prefix = std::string(word);
      if (rest.rfind(prefix, 0) == 0 && (rest.size() == prefix.size() || rest[prefix.size()] == ' ')) {
        direction = prefix;
        rest = trim(rest.substr(prefix.size()));
      }
    }
    if (direction != "IN")
      continue;
    std::string from = rest;
    if (const std::size_t comment = from.find(" #"); comment != std::string::npos)
      from = trim(from.substr(0, comment));
    if (const std::size_t v6 = from.find(" (v6)"); v6 != std::string::npos)
      from.erase(v6, 5);
    if (from == "Anywhere")
      from.clear();
    const std::string name = "ufw: " + destination;
    if (const std::size_t v6 = destination.find(" (v6)"); v6 != std::string::npos)
      destination.erase(v6, 5);
    if (const std::size_t on = destination.find(" on "); on != std::string::npos)
      destination = trim(destination.substr(0, on)); // the interface stays in the rule name
    const bool allow = action == "ALLOW" || action == "LIMIT";
    const std::vector<std::string> words = words_of(destination);
    if (destination == "Anywhere" || words.empty()) {
      add_ufw_ports("*", name, allow, from, rules);
    } else if (is_port_spec(words.back())) {
      add_ufw_ports(words.back(), name, allow, from, rules); // "10.0.0.5 22/tcp" keeps the port
    } else {
      for (const auto& [app, ports] : app_ports) {
        if (app == destination) {
          add_ufw_ports(ports, name, allow, from, rules);
          break;
        }
      }
    }
  }
  if (!status_seen)
    return false;
  snapshot.first_match_wins = true;
  snapshot.profiles.push_back(std::move(profile));
  for (FirewallRule& rule : rules)
    snapshot.rules.push_back(std::move(rule));
  return true;
}

std::vector<std::pair<std::string, std::string>> parse_ufw_app_profiles(std::string_view text) {
  std::vector<std::pair<std::string, std::string>> profiles;
  std::string current;
  for (const std::string& line : lines_of(text)) {
    const std::string item = trim(line);
    if (item.size() > 2 && item.front() == '[' && item.back() == ']') {
      current = item.substr(1, item.size() - 2);
      continue;
    }
    if (!current.empty() && item.rfind("ports=", 0) == 0)
      profiles.emplace_back(current, trim(item.substr(6)));
  }
  return profiles;
}

} // namespace firewall_detail

std::string to_string(FirewallDecision decision) {
  switch (decision) {
  case FirewallDecision::allowed: return "allowed";
  case FirewallDecision::blocked: return "blocked";
  case FirewallDecision::firewall_off: return "firewall off";
  case FirewallDecision::not_evaluated: break;
  }
  return "not evaluated";
}

FirewallVerdict evaluate_inbound(const FirewallSnapshot& firewall, PortProtocol protocol,
                                 std::uint16_t port, const std::string& program_path,
                                 const std::string& services) {
  using namespace firewall_detail;
  FirewallVerdict verdict;
  if (!firewall.readable) {
    verdict.note = firewall.note;
    return verdict;
  }
  const int wanted_protocol = protocol == PortProtocol::tcp ? 6 : 17;
  std::vector<const FirewallProfileState*> profiles;
  for (const auto& profile : firewall.profiles) {
    if (profile.active)
      profiles.push_back(&profile);
  }
  if (profiles.empty()) {
    for (const auto& profile : firewall.profiles)
      profiles.push_back(&profile);
  }

  bool any_allowed = false;
  bool any_blocked = false;
  bool all_off = !profiles.empty();
  for (const FirewallProfileState* profile : profiles) {
    FirewallProfileVerdict result;
    result.profile = profile->name;
    result.networks = profile->networks;
    if (!profile->enabled) {
      result.decision = FirewallDecision::firewall_off;
      result.because = "the firewall is off for this profile";
    } else if (profile->block_all_inbound) {
      result.decision = FirewallDecision::blocked;
      result.because = "every inbound connection is blocked on this profile";
    } else {
      const FirewallRule* block = nullptr;
      const FirewallRule* allow = nullptr;
      for (const auto& rule : firewall.rules) {
        if (!rule.enabled)
          continue;
        if (profile->mask != 0 && (rule.profiles & profile->mask) == 0U)
          continue;
        if (!rule.zone.empty() && rule.zone != profile->name)
          continue;
        if (rule.protocol != 256 && rule.protocol != wanted_protocol)
          continue;
        if (!port_spec_matches(rule.local_ports, port) || !program_matches(rule.program, program_path) ||
            !service_matches(rule.service, services))
          continue;
        if (!rule_applies_generally(rule))
          continue;
        if (!rule.allow && (!is_wildcard(rule.remote_addresses) || !is_wildcard(rule.local_addresses)))
          continue;
        if (!rule.allow) {
          block = &rule;
          break;
        }
        if (allow == nullptr)
          allow = &rule;
        if (firewall.first_match_wins)
          break;
      }
      if (block != nullptr) {
        result.decision = FirewallDecision::blocked;
        result.because = "blocked by rule \"" + block->name + "\"";
      } else if (allow != nullptr) {
        result.decision = FirewallDecision::allowed;
        result.because = "allowed by rule \"" + allow->name + "\"";
        if (!is_wildcard(allow->program))
          result.because += ", for " + file_name_of(allow->program) + " only";
        if (!is_wildcard(allow->remote_addresses))
          result.because += ", from " + allow->remote_addresses + " only";
        if (!is_wildcard(allow->local_addresses))
          result.because += ", to " + allow->local_addresses + " only";
      } else if (profile->inbound_blocked_by_default) {
        result.decision = FirewallDecision::blocked;
        result.because = "no rule allows it; inbound connections are blocked unless a rule allows them";
      } else {
        result.decision = FirewallDecision::allowed;
        result.because = "inbound connections are allowed by default on this profile";
      }
    }
    all_off = all_off && result.decision == FirewallDecision::firewall_off;
    any_allowed = any_allowed || result.decision == FirewallDecision::allowed ||
                  result.decision == FirewallDecision::firewall_off;
    any_blocked = any_blocked || result.decision == FirewallDecision::blocked;
    verdict.per_profile.push_back(std::move(result));
  }
  verdict.mixed = any_allowed && any_blocked;
  verdict.decision = all_off ? FirewallDecision::firewall_off
                     : any_blocked ? FirewallDecision::blocked
                                   : any_allowed ? FirewallDecision::allowed
                                                 : FirewallDecision::not_evaluated;
  if (firewall.group_policy_overrides_local_rules)
    verdict.note = "Group policy manages this firewall; its rules can differ from the local rules read here.";
  if (!firewall.third_party.empty()) {
    if (!verdict.note.empty())
      verdict.note += " ";
    verdict.note += "Another firewall is also registered (" + firewall.third_party + "); it is not evaluated.";
  }
  return verdict;
}

} // namespace support_assist
