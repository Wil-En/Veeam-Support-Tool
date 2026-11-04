#pragma once

// The Remote Port Checker's result rows, built once for both editions and for the Windows guided
// managed-server test: where a name's addresses came from, one row per address family, then each
// address tried with the SAT listener, banner and payload found there. Also the TCP / UDP
// Listener's firewall note and the rules that name SAT (N16).

#include "support_assist/firewall.hpp"
#include "support_assist/network.hpp"
#include "support_assist/port_check.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

struct ConnectivityRow {
  std::string kind;
  std::string target;
  std::string detail;
  std::string state;
};

namespace connectivity_detail {

inline std::string family_of(std::string_view address) {
  return address.find(':') != std::string_view::npos ? "IPv6" : "IPv4";
}

// One decimal: 0.4 ms, 12.3 ms.
inline std::string millis(double value) {
  char text[32];
  std::snprintf(text, sizeof(text), "%.1f", value < 0.0 ? 0.0 : value);
  return text;
}

inline std::string source_text(std::string_view interface_name, std::string_view address) {
  if (interface_name.empty() && address.empty())
    return {};
  std::string text = "; source ";
  if (!interface_name.empty()) {
    text += interface_name;
    if (!address.empty())
      text += " (" + std::string(address) + ")";
  } else {
    text += address;
  }
  return text;
}

inline std::string attempt_family(const std::string& declared, const std::string& address) {
  return declared == "IPv4" || declared == "IPv6" ? declared : family_of(address);
}

} // namespace connectivity_detail

class ConnectivityRows {
public:
  ConnectivityRows(std::string host, std::uint16_t port) : host_(std::move(host)), port_(port) {}

  // A row above the results, such as how a loopback target was routed.
  void note(ConnectivityRow row) { notes_.push_back(std::move(row)); }
  // A row among the results, such as a source interface whose test could not run.
  void detail(ConnectivityRow row) { details_.push_back(std::move(row)); }
  // The caller resolved the name itself (localhost), so no name rows are wanted.
  void name_rows_done() { names_done_ = true; }

  // One test, from the machine's default route or from the source interface named.
  void add(const TcpPortTestResult& result, std::string_view interface_name = {},
           std::string_view interface_address = {}) {
    add_names(result.host, result.dns_lookup_required, result.canonical_name, result.resolved_addresses,
              result.name_source);
    for (const auto& attempt : result.attempts) {
      TcpSeen seen{attempt, std::string(interface_name)};
      tcp_.push_back(seen);
      connected_ = connected_ || attempt.connected;
      payload_verified_ = payload_verified_ || attempt.sat_payload_validated;
      const std::string source_name =
          !attempt.source_interface.empty() ? attempt.source_interface : std::string(interface_name);
      const std::string source_address =
          !attempt.local_address.empty() ? attempt.local_address
                                         : (!attempt.source_address.empty() ? attempt.source_address
                                                                            : std::string(interface_address));
      std::string text = "Port " + std::to_string(port_) + "; " + connectivity_detail::millis(attempt.elapsed_ms) +
                         " ms" + connectivity_detail::source_text(source_name, source_address);
      if (!attempt.connected && attempt.native_code != 0) {
        text += "; native error " + std::to_string(attempt.native_code) + " (" + attempt.message + ")";
        // What the two common codes mean, in plain words (Winsock 10061 and 10060, POSIX 111 and 110).
        if (attempt.native_code == 10061 || attempt.native_code == 111)
          text += ". The machine refused the connection: nothing listens on this port there";
        else if (attempt.native_code == 10060 || attempt.native_code == 110)
          text += ". No answer before the timeout: a firewall dropped it, or nothing answers at this address";
      }
      else if (!attempt.message.empty())
        text += "; " + attempt.message;
      details_.push_back({"TCP", attempt.address, std::move(text), attempt.connected ? "CONNECTED" : "FAILED"});
      if (attempt.sat_listener_detected) {
        details_.push_back({"SAT", attempt.address,
                            attempt.sat_test_id.empty() ? "SAT listener detected" : "Test ID " + attempt.sat_test_id,
                            attempt.sat_handshake_completed ? "VERIFIED" : "DETECTED"});
      }
      if (!attempt.peer_banner.empty())
        details_.push_back({"BANNER", attempt.address, attempt.peer_banner, "RECEIVED"});
      if (attempt.sat_payload_validated) {
        std::string payload = std::to_string(attempt.sat_payload_bytes / (1024ULL * 1024ULL)) +
                              " MiB volatile payload verified";
        if (attempt.sat_payload_bits_per_second > 0.0)
          payload += "; " + format_transfer_rate(attempt.sat_payload_bits_per_second);
        details_.push_back({"PAYLOAD", attempt.address, std::move(payload), "VERIFIED"});
      }
    }
    nothing_from_source("TCP", result.host, result.attempts.empty(), interface_name, interface_address);
  }

  void add(const UdpPortTestResult& result, std::string_view interface_name = {},
           std::string_view interface_address = {}) {
    add_names(result.host, result.dns_lookup_required, result.canonical_name, result.resolved_addresses,
              result.name_source);
    for (const auto& attempt : result.attempts) {
      udp_.push_back(attempt);
      sent_ = sent_ || attempt.datagram_sent;
      acknowledged_ = acknowledged_ || attempt.sat_acknowledged;
      const std::string source_name =
          !attempt.source_interface.empty() ? attempt.source_interface : std::string(interface_name);
      const std::string source_address =
          !attempt.local_address.empty() ? attempt.local_address
                                         : (!attempt.source_address.empty() ? attempt.source_address
                                                                            : std::string(interface_address));
      std::string text = "Port " + std::to_string(port_) + "; " + connectivity_detail::millis(attempt.elapsed_ms) +
                         " ms" + connectivity_detail::source_text(source_name, source_address);
      if (!attempt.message.empty())
        text += "; " + attempt.message;
      details_.push_back({"UDP", attempt.address, std::move(text), udp_state(attempt)});
      if (!attempt.sat_test_id.empty()) {
        details_.push_back({"SAT", attempt.address, "Test ID " + attempt.sat_test_id,
                            attempt.sat_acknowledged ? "VERIFIED" : "NO ACK"});
      }
    }
    nothing_from_source("UDP", result.host, result.attempts.empty(), interface_name, interface_address);
  }

  // The notes, the name, one row per address family, then each address tried.
  std::vector<ConnectivityRow> rows() const {
    std::vector<ConnectivityRow> all = notes_;
    all.insert(all.end(), names_.begin(), names_.end());
    for (const char* family : {"IPv4", "IPv6"})
      family_row(family, all);
    all.insert(all.end(), details_.begin(), details_.end());
    return all;
  }

  bool connected() const { return connected_; }
  bool payload_verified() const { return payload_verified_; }
  bool acknowledged() const { return acknowledged_; }
  bool sent() const { return sent_; }

private:
  struct TcpSeen {
    TcpEndpointAttempt attempt;
    std::string interface_name;
  };

  // A source address tests only targets of its own family: an IPv6 source against an IPv4 address
  // has nothing to try, which is said rather than left as a missing row.
  void nothing_from_source(const char* protocol, const std::string& host, bool no_attempts,
                           std::string_view interface_name, std::string_view interface_address) {
    if (!no_attempts || interface_address.empty())
      return;
    std::string text = "Nothing to test from ";
    text += interface_name.empty() ? std::string(interface_address)
                                   : std::string(interface_name) + " (" + std::string(interface_address) + ")";
    text += ": the target has no " + connectivity_detail::family_of(interface_address) + " address";
    details_.push_back({protocol, host, std::move(text), "NOT TESTED"});
  }

  static std::string udp_state(const UdpEndpointAttempt& attempt) {
    if (attempt.sat_acknowledged)
      return "VERIFIED";
    if (attempt.response_received)
      return "RESPONSE RECEIVED";
    return attempt.datagram_sent ? "INDETERMINATE" : "FAILED";
  }

  void add_names(const std::string& host, bool lookup_required, const std::string& canonical,
                 const std::vector<std::string>& addresses, const std::string& name_source) {
    if (lookup_required) {
      looked_up_ = true;
      for (const auto& address : addresses)
        resolved_.push_back(address);
    }
    if (names_done_)
      return;
    names_done_ = true;
    if (!lookup_required) {
      names_.push_back({"DNS", host, "Literal IP address; DNS lookup not required", "NOT REQUIRED"});
      return;
    }
    // Where the addresses came from first: the hosts file, a DNS server, or the resolver itself.
    if (!name_source.empty())
      names_.push_back({"DNS", host, name_source, "SOURCE"});
    for (const auto& address : addresses) {
      std::string text = connectivity_detail::family_of(address) + " address of " + host;
      if (!canonical.empty())
        text += "; canonical name " + canonical;
      names_.push_back({"DNS", address, std::move(text), "RESOLVED"});
    }
  }

  // Whether the family worked: the first address of it that connected (or answered), else what
  // was tried, else that the name has no address of that family.
  void family_row(const std::string& family, std::vector<ConnectivityRow>& all) const {
    bool known_address = false;
    for (const auto& address : resolved_)
      known_address = known_address || connectivity_detail::family_of(address) == family;
    std::size_t tried = 0;
    if (!udp_.empty()) {
      const UdpEndpointAttempt* best = nullptr;
      for (const auto& attempt : udp_) {
        if (connectivity_detail::attempt_family(attempt.address_family, attempt.address) != family)
          continue;
        ++tried;
        if (best == nullptr || rank(attempt) > rank(*best))
          best = &attempt;
      }
      if (tried == 0) {
        absent_family_row(family, known_address, all);
        return;
      }
      std::string text;
      if (best->sat_acknowledged)
        text = "SAT listener answered from " + best->address + " in " + connectivity_detail::millis(best->elapsed_ms) + " ms";
      else if (best->response_received)
        text = "A reply came from " + best->address + " in " + connectivity_detail::millis(best->elapsed_ms) + " ms";
      else if (best->datagram_sent)
        text = "Sent to " + std::to_string(tried) + " address(es); no reply";
      else
        text = "Nothing could be sent to " + std::to_string(tried) + " address(es)";
      all.push_back({family, best->sat_acknowledged || best->response_received ? best->address : host_, std::move(text),
                     udp_state(*best)});
      return;
    }
    const TcpSeen* first = nullptr;
    for (const auto& seen : tcp_) {
      if (connectivity_detail::attempt_family(seen.attempt.address_family, seen.attempt.address) != family)
        continue;
      ++tried;
      if (first == nullptr && seen.attempt.connected)
        first = &seen;
    }
    if (tried == 0) {
      absent_family_row(family, known_address, all);
      return;
    }
    if (first == nullptr) {
      all.push_back({family, host_, "No " + family + " address connected (" + std::to_string(tried) + " tried)",
                     "FAILED"});
      return;
    }
    const auto& attempt = first->attempt;
    std::string text = "Connected in " + connectivity_detail::millis(attempt.elapsed_ms) + " ms";
    const std::string from = !attempt.source_interface.empty() ? attempt.source_interface : first->interface_name;
    if (!from.empty())
      text += " from " + from;
    if (attempt.sat_payload_validated)
      text += "; SAT listener and payload verified";
    else if (attempt.sat_handshake_completed)
      text += "; SAT listener verified";
    all.push_back({family, attempt.address, std::move(text), "CONNECTED"});
  }

  // A family with no attempt: said only for a name, since a literal address has one family.
  void absent_family_row(const std::string& family, bool known_address, std::vector<ConnectivityRow>& all) const {
    if (!looked_up_)
      return;
    if (known_address)
      all.push_back({family, host_, "Not tested", "NOT TESTED"});
    else
      all.push_back({family, host_, host_ + " has no " + family + " address", "NO ADDRESS"});
  }

  static int rank(const UdpEndpointAttempt& attempt) {
    return attempt.sat_acknowledged ? 3 : attempt.response_received ? 2 : attempt.datagram_sent ? 1 : 0;
  }

  std::string host_;
  std::uint16_t port_ = 0;
  bool names_done_ = false;
  bool looked_up_ = false;
  std::vector<std::string> resolved_;
  std::vector<ConnectivityRow> notes_;
  std::vector<ConnectivityRow> names_;
  std::vector<ConnectivityRow> details_;
  std::vector<TcpSeen> tcp_;
  std::vector<UdpEndpointAttempt> udp_;
  bool connected_ = false;
  bool payload_verified_ = false;
  bool acknowledged_ = false;
  bool sent_ = false;
};

// N16: the first listen on a network address can make Windows ask whether to allow SAT, and the
// answer stays on the machine as a firewall rule. Empty where there is no such prompt.
inline std::string listener_firewall_note() {
#ifdef _WIN32
  return "Windows can ask whether to allow SupportAssistTool.exe the first time it listens on a network. "
         "The answer stays as a firewall rule; the rules that name SAT are listed when the listener stops.";
#else
  return {};
#endif
}

// The firewall rules that name this program, as rows, so they can be found and removed.
inline std::vector<ConnectivityRow> listener_firewall_rows(const FirewallSnapshot& firewall,
                                                           const std::string& program_path) {
  std::vector<ConnectivityRow> rows;
  // The file name, cut from the UTF-8 text rather than through a path, which on Windows would go
  // through the ANSI code page.
  const auto slash = program_path.find_last_of("\\/");
  const std::string program = slash == std::string::npos ? program_path : program_path.substr(slash + 1);
  for (const auto& rule : rules_for_program(firewall, program_path)) {
    std::string text = std::string(rule.allow ? "Allows " : "Blocks ") + program + " inbound";
    if (!rule.enabled)
      text += " (rule disabled)";
    text += "; it stays until it is removed from the firewall";
    rows.push_back({"FIREWALL", rule.name, std::move(text), rule.allow ? "ALLOW" : "BLOCK"});
  }
  return rows;
}

// The rules that name SAT on this machine, read when a listener stops. Nothing is read where no
// prompt adds such a rule.
inline std::vector<ConnectivityRow> listener_firewall_rows_here() {
#ifdef _WIN32
  auto firewall = read_firewall();
  if (!firewall.ok())
    return {};
  return listener_firewall_rows(firewall.value(), current_executable_path());
#else
  return {};
#endif
}

} // namespace support_assist::gui
