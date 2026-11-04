// Name Check, the parts every platform shares: the DNS client (one UDP question to one configured
// server), the hosts file and resolv.conf readers, and the comparison that says where an answer came
// from first. The platform files read the resolver settings.
#include "support_assist/name_check.hpp"

#include "support_assist/local_ports.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/udp_exchange.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <random>
#include <set>

namespace support_assist {
namespace {

#ifdef _WIN32
using SocketLength = int;
class SocketRuntime {
public:
  SocketRuntime() {
    WSADATA data{};
    ok_ = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  SocketRuntime(const SocketRuntime&) = delete;
  SocketRuntime& operator=(const SocketRuntime&) = delete;
  ~SocketRuntime() {
    if (ok_)
      WSACleanup();
  }

private:
  bool ok_ = false;
};
#else
using SocketLength = socklen_t;
class SocketRuntime {};
#endif

std::uint16_t read_u16(const std::vector<std::uint8_t>& packet, std::size_t at) {
  return static_cast<std::uint16_t>((static_cast<unsigned>(packet[at]) << 8U) | packet[at + 1]);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& packet, std::size_t at) {
  return (static_cast<std::uint32_t>(read_u16(packet, at)) << 16U) | read_u16(packet, at + 2);
}

// A name at `at`, following compression pointers; `at` moves past the name as written there.
bool read_name(const std::vector<std::uint8_t>& packet, std::size_t& at, std::string& out) {
  out.clear();
  std::size_t position = at;
  bool jumped = false;
  for (int hops = 0; hops < 128; ++hops) {
    if (position >= packet.size())
      return false;
    const std::uint8_t length = packet[position];
    if (length == 0) {
      if (!jumped)
        at = position + 1;
      return true;
    }
    if ((length & 0xC0U) == 0xC0U) {
      if (position + 1 >= packet.size())
        return false;
      const std::size_t target = (static_cast<std::size_t>(length & 0x3FU) << 8U) | packet[position + 1];
      if (!jumped)
        at = position + 2;
      jumped = true;
      position = target;
      continue;
    }
    if ((length & 0xC0U) != 0 || position + 1U + length > packet.size())
      return false;
    if (!out.empty())
      out += '.';
    out.append(reinterpret_cast<const char*>(packet.data() + position + 1), length);
    if (out.size() > 255)
      return false;
    position += 1U + length;
  }
  return false;
}

std::string strip_scope(const std::string& address) {
  return address.substr(0, address.find('%'));
}

bool parse_ipv4(const std::string& text, std::array<std::uint8_t, 4>& bytes) {
  in_addr value{};
  if (inet_pton(AF_INET, text.c_str(), &value) != 1)
    return false;
  std::memcpy(bytes.data(), &value, 4);
  return true;
}

bool parse_ipv6(const std::string& text, std::array<std::uint8_t, 16>& bytes) {
  in6_addr value{};
  if (inet_pton(AF_INET6, strip_scope(text).c_str(), &value) != 1)
    return false;
  std::memcpy(bytes.data(), &value, 16);
  return true;
}

bool is_ip_address(const std::string& text) {
  std::array<std::uint8_t, 4> v4{};
  std::array<std::uint8_t, 16> v6{};
  return parse_ipv4(text, v4) || parse_ipv6(text, v6);
}

std::string numeric_host(const sockaddr* address, std::size_t length) {
  char text[NI_MAXHOST] = {};
  if (getnameinfo(address, static_cast<SocketLength>(length), text, sizeof(text), nullptr, 0, NI_NUMERICHOST) != 0)
    return {};
  return text;
}

std::string read_text(const std::string& path, std::size_t max_bytes = 1024U * 1024U) {
  if (path.empty())
    return {};
  std::ifstream input(path_from_utf8(path), std::ios::binary);
  if (!input)
    return {};
  std::string text(max_bytes, '\0');
  input.read(text.data(), static_cast<std::streamsize>(max_bytes));
  text.resize(static_cast<std::size_t>(input.gcount()));
  return text;
}

std::string lower_name(std::string_view text) {
  std::string value = ascii_lower(trim(text));
  if (!value.empty() && value.back() == '.')
    value.pop_back();
  return value;
}

// What this machine's resolver returns for the name, in its order.
std::vector<std::string> system_addresses(const std::string& name, std::string& error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo* raw = nullptr;
  const int status = getaddrinfo(name.c_str(), nullptr, &hints, &raw);
  std::vector<std::string> addresses;
  if (status != 0 || raw == nullptr) {
#ifdef _WIN32
    error = utf8_from_wide(gai_strerrorW(status));
#else
    error = gai_strerror(status);
#endif
    return addresses;
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> results(raw, freeaddrinfo);
  std::set<std::string> seen;
  for (const addrinfo* current = results.get(); current != nullptr; current = current->ai_next) {
    const std::string text = numeric_host(current->ai_addr, current->ai_addrlen);
    if (!text.empty() && seen.insert(text).second)
      addresses.push_back(text);
  }
  return addresses;
}

bool is_loopback_address(const std::string& address) {
  const std::string text = strip_scope(address);
  return text.rfind("127.", 0) == 0 || text == "::1" || text.rfind("::ffff:127.", 0) == 0;
}

bool is_localhost(const std::string& name) {
  const std::string lowered = lower_name(name);
  return lowered == "localhost" ||
         (lowered.size() > 10 && lowered.compare(lowered.size() - 10, 10, ".localhost") == 0);
}

ReverseLookup reverse_lookup(const std::string& address) {
  ReverseLookup lookup;
  lookup.address = address;
  if (is_loopback_address(address)) {
    lookup.name = "this machine (loopback)";
    lookup.agrees = true;
    return lookup;
  }
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_NUMERICHOST;
  addrinfo* raw = nullptr;
  if (getaddrinfo(address.c_str(), nullptr, &hints, &raw) != 0 || raw == nullptr) {
    lookup.error = "not an IP address";
    return lookup;
  }
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> target(raw, freeaddrinfo);
  char name[NI_MAXHOST] = {};
  if (getnameinfo(target->ai_addr, static_cast<SocketLength>(target->ai_addrlen), name, sizeof(name), nullptr, 0,
                  NI_NAMEREQD) != 0) {
    lookup.error = "no reverse record";
    return lookup;
  }
  lookup.name = name;
  std::string ignored;
  const auto forward = system_addresses(lookup.name, ignored);
  lookup.agrees = std::find(forward.begin(), forward.end(), address) != forward.end() ||
                  std::find(forward.begin(), forward.end(), strip_scope(address)) != forward.end();
  return lookup;
}

std::set<std::string> answered_addresses(const std::vector<DnsAnswer>& answers) {
  std::set<std::string> addresses;
  for (const DnsAnswer& answer : answers) {
    for (const DnsRecord& record : answer.records) {
      if (record.type == DnsRecordType::a || record.type == DnsRecordType::aaaa)
        addresses.insert(record.value);
    }
  }
  return addresses;
}

// A and AAAA from one server; a server that does not answer the first question is not asked again.
std::vector<DnsAnswer> ask_server(const std::string& server, const std::string& name) {
  std::vector<DnsAnswer> answers{query_dns_server(server, name, DnsRecordType::a)};
  if (answers.front().answered)
    answers.push_back(query_dns_server(server, name, DnsRecordType::aaaa));
  return answers;
}

// A short name completed by the first search suffix that the first DNS server knows. A server that
// does not answer ends the search, so a dead server costs one timeout rather than one per suffix.
std::string complete_short_name(const std::string& name, const ResolverSettings& settings) {
  if (name.find('.') != std::string::npos || settings.servers.empty())
    return name;
  for (const std::string& suffix : settings.search_suffixes) {
    const std::string candidate = name + "." + suffix;
    for (const DnsRecordType type : {DnsRecordType::a, DnsRecordType::aaaa}) {
      const DnsAnswer answer = query_dns_server(settings.servers.front().address, candidate, type);
      if (!answer.answered)
        return name;
      if (answer.rcode != 0)
        break; // no such name with this suffix
      if (!answer.records.empty())
        return candidate;
    }
  }
  return name;
}

std::string server_label(const DnsServer& server) {
  return "DNS server " + server.address + (server.interface_name.empty() ? "" : " (" + server.interface_name + ")");
}

std::string join(const std::set<std::string>& values) {
  std::string text;
  for (const std::string& value : values)
    text += (text.empty() ? "" : ", ") + value;
  return text;
}

} // namespace

std::string to_string(DnsRecordType type) {
  switch (type) {
  case DnsRecordType::a: return "A";
  case DnsRecordType::cname: return "CNAME";
  case DnsRecordType::ptr: return "PTR";
  case DnsRecordType::aaaa: return "AAAA";
  }
  return "?";
}

namespace dns_detail {

Result<std::vector<std::uint8_t>> build_query(std::uint16_t id, std::string_view name, DnsRecordType type) {
  const auto failure = [](const std::string& message) {
    Error error;
    error.component = "network";
    error.operation = "build a DNS question";
    error.message = message;
    return Result<std::vector<std::uint8_t>>::failure(error);
  };
  std::string text = trim(name);
  if (!text.empty() && text.back() == '.')
    text.pop_back();
  if (text.empty() || text.size() > 253)
    return failure("a name of 1 to 253 characters is needed");
  std::vector<std::uint8_t> packet{static_cast<std::uint8_t>(id >> 8U), static_cast<std::uint8_t>(id & 0xFFU),
                                   0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t dot = text.find('.', start);
    const std::string label = text.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
    if (label.empty() || label.size() > 63)
      return failure("\"" + text + "\" has an empty part or a part longer than 63 characters");
    for (const char c : label) {
      if (std::isalnum(static_cast<unsigned char>(c)) == 0 && c != '-' && c != '_')
        return failure("\"" + text + "\" holds a character a DNS name cannot hold");
    }
    packet.push_back(static_cast<std::uint8_t>(label.size()));
    packet.insert(packet.end(), label.begin(), label.end());
    if (dot == std::string::npos)
      break;
    start = dot + 1;
  }
  packet.push_back(0);
  const auto code = static_cast<std::uint16_t>(type);
  packet.push_back(static_cast<std::uint8_t>(code >> 8U));
  packet.push_back(static_cast<std::uint8_t>(code & 0xFFU));
  packet.push_back(0x00);
  packet.push_back(0x01); // class IN
  return Result<std::vector<std::uint8_t>>::success(std::move(packet));
}

bool parse_response(const std::vector<std::uint8_t>& packet, std::uint16_t id, DnsAnswer& answer) {
  if (packet.size() < 12 || read_u16(packet, 0) != id)
    return false;
  const std::uint16_t flags = read_u16(packet, 2);
  if ((flags & 0x8000U) == 0)
    return false; // a question, not an answer
  answer.rcode = static_cast<int>(flags & 0x000FU);
  answer.truncated = (flags & 0x0200U) != 0;
  answer.authoritative = (flags & 0x0400U) != 0;
  const std::uint16_t questions = read_u16(packet, 4);
  const std::uint16_t answers = read_u16(packet, 6);
  std::size_t at = 12;
  std::string ignored;
  for (std::uint16_t i = 0; i < questions; ++i) {
    if (!read_name(packet, at, ignored) || at + 4 > packet.size())
      return false;
    at += 4;
  }
  answer.records.clear();
  for (std::uint16_t i = 0; i < answers; ++i) {
    DnsRecord record;
    if (!read_name(packet, at, record.name) || at + 10 > packet.size())
      return false;
    const std::uint16_t type = read_u16(packet, at);
    const std::uint16_t record_class = read_u16(packet, at + 2);
    record.ttl = read_u32(packet, at + 4);
    const std::uint16_t length = read_u16(packet, at + 8);
    at += 10;
    if (at + length > packet.size())
      return false;
    bool keep = record_class == 1;
    if (keep && type == 1 && length == 4) {
      record.type = DnsRecordType::a;
      record.value = local_ports_detail::format_ipv4(packet[at], packet[at + 1], packet[at + 2], packet[at + 3]);
    } else if (keep && type == 28 && length == 16) {
      std::array<std::uint8_t, 16> bytes{};
      std::copy(packet.begin() + static_cast<std::ptrdiff_t>(at), packet.begin() + static_cast<std::ptrdiff_t>(at + 16),
                bytes.begin());
      record.type = DnsRecordType::aaaa;
      record.value = local_ports_detail::format_ipv6(bytes);
    } else if (keep && (type == 5 || type == 12)) {
      std::size_t name_at = at;
      record.type = type == 5 ? DnsRecordType::cname : DnsRecordType::ptr;
      keep = read_name(packet, name_at, record.value);
    } else {
      keep = false;
    }
    if (keep)
      answer.records.push_back(std::move(record));
    at += length;
  }
  return true;
}

std::string reverse_name(const std::string& address) {
  [[maybe_unused]] SocketRuntime runtime;
  std::array<std::uint8_t, 4> v4{};
  if (parse_ipv4(address, v4)) {
    return std::to_string(v4[3]) + "." + std::to_string(v4[2]) + "." + std::to_string(v4[1]) + "." +
           std::to_string(v4[0]) + ".in-addr.arpa";
  }
  std::array<std::uint8_t, 16> v6{};
  if (!parse_ipv6(address, v6))
    return {};
  static constexpr char kHex[] = "0123456789abcdef";
  std::string name;
  for (std::size_t i = v6.size(); i-- > 0;) {
    name += kHex[v6[i] & 0x0FU];
    name += '.';
    name += kHex[(v6[i] >> 4U) & 0x0FU];
    name += '.';
  }
  return name + "ip6.arpa";
}

std::string rcode_text(int rcode) {
  switch (rcode) {
  case 0: return "answered";
  case 1: return "format error";
  case 2: return "server failure";
  case 3: return "no such name";
  case 4: return "not implemented";
  case 5: return "refused";
  default: return rcode < 0 ? "no answer" : "error " + std::to_string(rcode);
  }
}

std::vector<HostsEntry> find_hosts_entries(std::string_view hosts_text, std::string_view name) {
  std::vector<HostsEntry> entries;
  const std::string wanted = lower_name(name);
  if (wanted.empty())
    return entries;
  std::size_t number = 0;
  for (const std::string& raw : split(hosts_text, '\n')) {
    ++number;
    std::string line = raw.substr(0, raw.find('#'));
    std::replace(line.begin(), line.end(), '\t', ' ');
    std::vector<std::string> words;
    for (const std::string& word : split(line, ' ')) {
      const std::string item = trim(word);
      if (!item.empty())
        words.push_back(item);
    }
    for (std::size_t i = 1; i < words.size(); ++i) {
      if (lower_name(words[i]) == wanted) {
        entries.push_back({words[0], number});
        break;
      }
    }
  }
  return entries;
}

ResolverSettings parse_resolv_conf(std::string_view text) {
  ResolverSettings settings;
  for (const std::string& raw : split(text, '\n')) {
    std::string line = raw.substr(0, raw.find_first_of("#;"));
    std::replace(line.begin(), line.end(), '\t', ' ');
    std::vector<std::string> words;
    for (const std::string& word : split(line, ' ')) {
      const std::string item = trim(word);
      if (!item.empty())
        words.push_back(item);
    }
    if (words.size() < 2)
      continue;
    if (words[0] == "nameserver") {
      settings.servers.push_back({words[1], {}});
    } else if (words[0] == "search") {
      settings.search_suffixes.assign(words.begin() + 1, words.end()); // the last search or domain line wins
    } else if (words[0] == "domain") {
      settings.search_suffixes = {words[1]};
    }
  }
  return settings;
}

std::string nsswitch_hosts_order(std::string_view text) {
  static const std::map<std::string, std::string> kNames{
      {"files", "hosts file"},       {"dns", "DNS"},           {"resolve", "systemd-resolved"},
      {"mdns4_minimal", "mDNS"},     {"mdns4", "mDNS"},        {"mdns", "mDNS"},
      {"mdns_minimal", "mDNS"},      {"myhostname", "this machine's own name"},
      {"mymachines", "local containers"}, {"wins", "WINS"}, {"nis", "NIS"}, {"sss", "SSSD"}};
  for (const std::string& raw : split(text, '\n')) {
    const std::string line = trim(raw.substr(0, raw.find('#')));
    if (line.rfind("hosts:", 0) != 0)
      continue;
    std::string order;
    std::replace_copy(line.begin() + 6, line.end(), std::back_inserter(order), '\t', ' ');
    std::string readable;
    std::set<std::string> added;
    for (const std::string& word : split(order, ' ')) {
      const std::string item = trim(word);
      if (item.empty() || item.front() == '[')
        continue;
      const auto known = kNames.find(item);
      const std::string label = known != kNames.end() ? known->second : item;
      if (!added.insert(label).second)
        continue;
      readable += (readable.empty() ? "" : ", then ") + label;
    }
    return readable;
  }
  return {};
}

bool answer_holds(const std::vector<DnsAnswer>& answers, const std::vector<std::string>& addresses) {
  if (addresses.empty())
    return false;
  const std::set<std::string> held = answered_addresses(answers);
  return std::all_of(addresses.begin(), addresses.end(),
                     [&](const std::string& address) { return held.count(strip_scope(address)) > 0; });
}

// The question and its answer, with the port open for the unit tests' own responder.
DnsAnswer query_server_port(const std::string& server, std::uint16_t port, const std::string& name,
                            DnsRecordType type, std::chrono::milliseconds timeout) {
  DnsAnswer answer;
  answer.server = server;
  answer.question = name;
  answer.type = type;
  std::random_device random;
  const auto id = static_cast<std::uint16_t>(random() & 0xFFFFU);
  auto packet = build_query(id, name, type);
  if (!packet.ok()) {
    answer.error = packet.error().message;
    return answer;
  }
  const UdpExchange exchange = udp_exchange(
      server, port, true, [&]() { return packet.value(); },
      [&](const std::vector<std::uint8_t>& response) { return parse_response(response, id, answer); }, timeout);
  answer.answered = exchange.answered;
  answer.elapsed_ms = exchange.elapsed_ms;
  if (!exchange.answered)
    answer.error = exchange.error;
  return answer;
}

} // namespace dns_detail

DnsAnswer query_dns_server(const std::string& server, const std::string& name, DnsRecordType type,
                           std::chrono::milliseconds timeout) {
  return dns_detail::query_server_port(server, 53, name, type, timeout);
}

NameCheckResult check_name(const std::string& name, const CancellationToken& cancel) {
  NameCheckResult result;
  result.name = trim(name);
  [[maybe_unused]] SocketRuntime runtime;
  result.settings = read_resolver_settings();
  if (result.name.empty())
    return result;
  result.is_address = is_ip_address(result.name);
  if (result.is_address) {
    result.addresses = {result.name};
    result.reverse.push_back(reverse_lookup(result.name));
    return result;
  }

  result.hosts_entries = dns_detail::find_hosts_entries(read_text(result.settings.hosts_file), result.name);
  result.addresses = system_addresses(result.name, result.resolver_error);
  if (cancel.is_cancelled())
    return result;
  if (is_localhost(result.name)) {
    // localhost never goes to DNS: the hosts file names it, or the resolver answers it itself.
    result.source = !result.hosts_entries.empty()
                        ? "hosts file (" + result.settings.hosts_file + ", line " +
                              std::to_string(result.hosts_entries.front().line_number) + ")"
                        : "this machine: the resolver answers localhost itself";
    for (const std::string& address : result.addresses)
      result.reverse.push_back(reverse_lookup(address));
    return result;
  }

  const std::string question = complete_short_name(result.name, result.settings);
  if (question != result.name)
    result.completed_name = question;
  std::vector<std::pair<const DnsServer*, std::vector<DnsAnswer>>> by_server;
  for (const DnsServer& server : result.settings.servers) {
    if (cancel.is_cancelled())
      return result;
    by_server.push_back({&server, ask_server(server.address, question)});
    for (const DnsAnswer& answer : by_server.back().second)
      result.per_server.push_back(answer);
  }
  for (const auto& [server, answers] : by_server) {
    for (const DnsAnswer& answer : answers) {
      for (const DnsRecord& record : answer.records) {
        if (record.type == DnsRecordType::cname &&
            std::find(result.aliases.begin(), result.aliases.end(), record.value) == result.aliases.end())
          result.aliases.push_back(record.value);
      }
    }
    if (!result.aliases.empty())
      break;
  }

  // Where the answer came from first: the hosts file is read before DNS on both systems.
  if (!result.hosts_entries.empty()) {
    result.source = "hosts file (" + result.settings.hosts_file + ", line " +
                    std::to_string(result.hosts_entries.front().line_number) + ")";
    for (const auto& [server, answers] : by_server) {
      const std::set<std::string> dns = answered_addresses(answers);
      if (!dns.empty()) {
        result.notes.push_back("The hosts file overrides DNS for this name: " + server->address + " answers " +
                               join(dns) + ".");
        break;
      }
    }
  } else if (!result.addresses.empty()) {
    for (const auto& [server, answers] : by_server) {
      if (dns_detail::answer_holds(answers, result.addresses)) {
        result.source = server_label(*server);
        break;
      }
    }
    if (result.source.empty())
      result.source = "not from the hosts file or the configured DNS servers: the DNS cache, LLMNR, mDNS or NetBIOS "
                      "answered";
  }

  // A split answer: servers that answer with different addresses.
  std::map<std::string, std::string> answers_by_server;
  for (const auto& [server, answers] : by_server) {
    const bool answered = std::any_of(answers.begin(), answers.end(),
                                      [](const DnsAnswer& answer) { return answer.answered && answer.rcode == 0; });
    if (answered)
      answers_by_server[server->address] = join(answered_addresses(answers));
  }
  std::set<std::string> distinct;
  for (const auto& entry : answers_by_server)
    distinct.insert(entry.second);
  if (distinct.size() > 1) {
    std::string text = "The DNS servers disagree:";
    for (const auto& [server, addresses] : answers_by_server)
      text += " " + server + " answers " + (addresses.empty() ? "no address" : addresses) + ";";
    text.back() = '.';
    result.notes.push_back(text);
  }

  for (const std::string& address : result.addresses) {
    if (cancel.is_cancelled() || result.reverse.size() >= 8)
      break;
    result.reverse.push_back(reverse_lookup(address));
  }
  return result;
}

std::string describe_name_source(const std::string& name, const std::vector<std::string>& addresses) {
  [[maybe_unused]] SocketRuntime runtime;
  const std::string host = trim(name);
  if (host.empty() || is_ip_address(host))
    return {};
  const ResolverSettings settings = read_resolver_settings();
  const auto entries = dns_detail::find_hosts_entries(read_text(settings.hosts_file), host);
  if (!entries.empty())
    return "hosts file (" + settings.hosts_file + ", line " + std::to_string(entries.front().line_number) + ")";
  if (is_localhost(host))
    return "this machine: the resolver answers localhost itself";
  const std::string question = complete_short_name(host, settings);
  for (const DnsServer& server : settings.servers) {
    if (dns_detail::answer_holds(ask_server(server.address, question), addresses))
      return server_label(server) + (question != host ? ", as " + question : "");
  }
  return "not from the hosts file or the configured DNS servers: the DNS cache, LLMNR, mDNS or NetBIOS answered";
}

} // namespace support_assist
