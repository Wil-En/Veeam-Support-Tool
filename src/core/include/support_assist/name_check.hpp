#pragma once

// Name Check (F2) and the name lookups behind the Remote Port Checker: what a name resolves to on
// this machine and where the answer came from first, the hosts file or which DNS server. Every A
// and AAAA record, each configured DNS server's own answer (so a split answer shows), the suffix
// that completed a short name, and the reverse lookup of each address with whether it agrees
// (docs/PROPOSAL_5.x_CHECKS.md section 9). Queries go only to the DNS servers this machine is
// configured with, one UDP packet per question.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct DnsServer {
  std::string address;        // "10.0.0.1", "fd00::53", "fe80::1%12"
  std::string interface_name; // the adapter that lists it (Windows), empty from resolv.conf
};

struct ResolverSettings {
  std::vector<DnsServer> servers;
  std::vector<std::string> search_suffixes;
  std::string hosts_file;
  std::string lookup_order; // "hosts file, then DNS" (nsswitch.conf on Linux)
  std::string note;         // the systemd-resolved stub and where its servers were read
};

// This machine's resolver: DNS servers in order, search suffixes and the hosts file.
ResolverSettings read_resolver_settings();

struct HostsEntry {
  std::string address;
  std::size_t line_number = 0;
};

enum class DnsRecordType : std::uint16_t { a = 1, cname = 5, ptr = 12, aaaa = 28 };

std::string to_string(DnsRecordType type);

struct DnsRecord {
  DnsRecordType type = DnsRecordType::a;
  std::string name;
  std::string value; // an address, or a name for CNAME and PTR
  std::uint32_t ttl = 0;
};

struct DnsAnswer {
  std::string server;
  std::string question;
  DnsRecordType type = DnsRecordType::a;
  bool answered = false; // a response arrived
  int rcode = -1;        // 0 no error, 2 server failure, 3 no such name, 5 refused
  bool truncated = false;
  bool authoritative = false;
  std::vector<DnsRecord> records;
  double elapsed_ms = 0.0;
  std::string error; // no answer: timed out, unreachable, or a socket error
};

// One question to one server, over UDP port 53.
DnsAnswer query_dns_server(const std::string& server, const std::string& name, DnsRecordType type,
                           std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

struct ReverseLookup {
  std::string address;
  std::string name;   // empty when the address has no reverse record
  bool agrees = false; // the name resolves back to the address
  std::string error;
};

struct NameCheckResult {
  std::string name;
  bool is_address = false; // an IP address was given: the reverse lookup only
  ResolverSettings settings;
  std::vector<HostsEntry> hosts_entries;
  std::vector<std::string> addresses; // what this machine's resolver returns, in its order
  std::string resolver_error;
  std::string source;                 // where the answer came from first
  std::string completed_name;         // a short name with the suffix that completed it
  std::vector<std::string> aliases;   // CNAME chain from the DNS answer
  std::vector<DnsAnswer> per_server;  // A and AAAA from each DNS server
  std::vector<ReverseLookup> reverse;
  std::vector<std::string> notes;     // split answers, a hosts entry that overrides DNS
};

NameCheckResult check_name(const std::string& name, const CancellationToken& cancel);

// The part the Remote Port Checker shows beside a test given a name: where these addresses came
// from first. Empty for an IP address.
std::string describe_name_source(const std::string& name, const std::vector<std::string>& addresses);

namespace dns_detail {
// A query packet. Fails for a name that is not plain ASCII labels of up to 63 characters.
Result<std::vector<std::uint8_t>> build_query(std::uint16_t id, std::string_view name, DnsRecordType type);
bool parse_response(const std::vector<std::uint8_t>& packet, std::uint16_t id, DnsAnswer& answer);
std::string reverse_name(const std::string& address); // in-addr.arpa or ip6.arpa; empty if not an address
std::string rcode_text(int rcode);
std::vector<HostsEntry> find_hosts_entries(std::string_view hosts_text, std::string_view name);
// nameserver, search and domain lines of resolv.conf.
ResolverSettings parse_resolv_conf(std::string_view text);
// The sources of the hosts line of nsswitch.conf, readable: "hosts file, then DNS".
std::string nsswitch_hosts_order(std::string_view text);
// Whether one server's answers hold every one of the addresses.
bool answer_holds(const std::vector<DnsAnswer>& answers, const std::vector<std::string>& addresses);
// query_dns_server on another port, for the unit tests' own responder.
DnsAnswer query_server_port(const std::string& server, std::uint16_t port, const std::string& name,
                            DnsRecordType type, std::chrono::milliseconds timeout);
} // namespace dns_detail

} // namespace support_assist
