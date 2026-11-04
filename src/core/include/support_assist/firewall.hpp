#pragma once

// This machine's firewall, read-only: the profiles (Windows) or zones (Linux firewalld) in force,
// their defaults, and the inbound rules; and whether an inbound connection to a port would reach the
// program listening on it. Nothing is changed. A third-party firewall is named when Windows reports
// one, and not evaluated (docs/PROPOSAL_5.x_CHECKS.md section 5.10).

#include "support_assist/error.hpp"
#include "support_assist/local_ports.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

enum class FirewallDecision { allowed, blocked, firewall_off, not_evaluated };

std::string to_string(FirewallDecision decision);

struct FirewallProfileState {
  std::string name;   // "Domain", "Private", "Public"; a firewalld zone; "ufw"
  unsigned mask = 0;  // Windows profile bit (1 Domain, 2 Private, 4 Public); 0 elsewhere
  bool active = false;
  bool enabled = true;
  bool inbound_blocked_by_default = true;
  bool block_all_inbound = false;
  std::vector<std::string> networks; // adapters or interfaces in this profile or zone
};

struct FirewallRule {
  std::string name;
  bool enabled = true;
  bool allow = true;
  int protocol = 256;       // 6 TCP, 17 UDP, 256 any
  std::string local_ports;  // "*", "80,443", "5000-5010", or a keyword such as "RPC"
  std::string program;      // a full path (may hold %SystemRoot%), or empty for any program
  std::string service;      // a service short name, "*" for any service, empty for no condition
  // The clients the rule is limited to: "*" or empty for any, else addresses, ranges or a keyword
  // such as LocalSubnet. A block rule limited this way does not decide for any client, so it is
  // skipped; an allow rule limited this way says so.
  std::string remote_addresses;
  // The local addresses the rule is limited to ("*" or empty for any), handled as remote ones are.
  std::string local_addresses;
  // Conditions SAT does not evaluate, so a rule carrying one decides nothing here: a Windows app
  // package (Store apps' rules are "any port" for that app only), a user, IPsec, or interface
  // types other than LAN.
  std::string app_package;
  std::string user_condition;
  bool requires_ipsec = false;
  std::string interface_types; // "All", "Lan", "Wireless", "RemoteAccess", comma separated
  unsigned profiles = 0x7FFFFFFFU; // Windows profile bits the rule applies to
  std::string zone;         // Linux firewalld zone the rule belongs to
};

struct FirewallSnapshot {
  bool readable = false;
  std::string product;       // "Windows Defender Firewall", "firewalld", "ufw"
  std::string note;          // what could not be read, and why
  bool group_policy_overrides_local_rules = false;
  std::string third_party;   // a third-party firewall Windows reports as on, named only
  // ufw applies the first rule that matches, in order. Windows Defender Firewall and firewalld
  // apply a matching block rule before any allow rule.
  bool first_match_wins = false;
  std::vector<FirewallProfileState> profiles;
  std::vector<FirewallRule> rules; // inbound rules only
};

// Reads the firewall. Fails only when the read itself fails; a machine with no firewall found
// returns readable = false with the reason in note.
Result<FirewallSnapshot> read_firewall();

struct FirewallProfileVerdict {
  std::string profile;
  std::vector<std::string> networks;
  FirewallDecision decision = FirewallDecision::not_evaluated;
  std::string because;
};

struct FirewallVerdict {
  FirewallDecision decision = FirewallDecision::not_evaluated; // when every active profile agrees
  bool mixed = false; // allowed on some active profiles, blocked on others
  std::vector<FirewallProfileVerdict> per_profile;
  std::string note;
};

// Would an inbound connection to this port reach the program listening on it? program_path and
// services describe the listener; both empty when nothing listens, so a rule limited to a program
// does not count.
FirewallVerdict evaluate_inbound(const FirewallSnapshot& firewall, PortProtocol protocol,
                                 std::uint16_t port, const std::string& program_path,
                                 const std::string& services);

namespace firewall_detail {
bool port_spec_matches(std::string_view spec, std::uint16_t port);
bool program_matches(std::string_view rule_program, std::string_view program_path);
bool service_matches(std::string_view rule_service, std::string_view services);
// False for a rule limited by a condition SAT does not evaluate (app package, user, IPsec,
// interface types other than LAN): such a rule decides nothing for the port's own listener.
bool rule_applies_generally(const FirewallRule& rule);

// Parsers for the Linux front-ends, shared so the unit tests reach them on every platform.
struct FirewalldZone {
  std::string name;
  bool active = false;
  bool is_default = false;
  std::string target; // "default", "ACCEPT", "DROP", "%%REJECT%%"
  std::vector<std::string> interfaces;
  std::vector<std::string> sources;
  std::vector<std::string> services;
  std::vector<std::string> ports; // "9392/tcp", "10000-10010/udp"
  std::vector<std::string> rich_rules;
};
// The output of firewall-cmd --list-all-zones.
std::vector<FirewalldZone> parse_firewalld_zones(std::string_view text);
// The <port protocol=".." port=".."/> entries of a firewalld service definition: {"22", 6}.
std::vector<std::pair<std::string, int>> parse_firewalld_service_ports(std::string_view xml);
// The active zones as profiles (the default zone when none is active) and their services, ports and
// rich rules as rules. service_ports maps a service name to its ports.
void add_firewalld_zones(const std::vector<FirewalldZone>& zones,
                         const std::vector<std::pair<std::string, std::vector<std::pair<std::string, int>>>>& service_ports,
                         FirewallSnapshot& snapshot);
// The output of ufw status verbose. app_ports maps an application profile to its ports ("22/tcp").
bool parse_ufw_status(std::string_view text,
                      const std::vector<std::pair<std::string, std::string>>& app_ports,
                      FirewallSnapshot& snapshot);
// The [Name] and ports= lines of the files in /etc/ufw/applications.d.
std::vector<std::pair<std::string, std::string>> parse_ufw_app_profiles(std::string_view text);
} // namespace firewall_detail

} // namespace support_assist
