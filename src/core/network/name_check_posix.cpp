// Linux resolver settings: /etc/resolv.conf, and when it points at the systemd-resolved stub, the
// servers systemd-resolved itself uses; the lookup order from nsswitch.conf; /etc/hosts.
#include "support_assist/name_check.hpp"

#include <algorithm>
#include <fstream>
#include <sstream>

namespace support_assist {
namespace {

std::string read_text(const char* path) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return {};
  std::ostringstream text;
  text << input.rdbuf();
  return text.str();
}

bool is_stub(const std::string& address) {
  return address == "127.0.0.53" || address == "127.0.0.54";
}

} // namespace

ResolverSettings read_resolver_settings() {
  ResolverSettings settings = dns_detail::parse_resolv_conf(read_text("/etc/resolv.conf"));
  settings.hosts_file = "/etc/hosts";
  settings.lookup_order = dns_detail::nsswitch_hosts_order(read_text("/etc/nsswitch.conf"));
  if (settings.lookup_order.empty())
    settings.lookup_order = "hosts file, then DNS";
  const bool stub_only = !settings.servers.empty() &&
                         std::all_of(settings.servers.begin(), settings.servers.end(),
                                     [](const DnsServer& server) { return is_stub(server.address); });
  if (stub_only) {
    const ResolverSettings upstream = dns_detail::parse_resolv_conf(read_text("/run/systemd/resolve/resolv.conf"));
    if (!upstream.servers.empty()) {
      settings.note = "systemd-resolved answers on " + settings.servers.front().address +
                      "; the DNS servers it uses are read from /run/systemd/resolve/resolv.conf.";
      settings.servers = upstream.servers;
      if (settings.search_suffixes.empty())
        settings.search_suffixes = upstream.search_suffixes;
    } else {
      settings.note = "systemd-resolved answers on " + settings.servers.front().address +
                      ", and the DNS servers it uses could not be read.";
    }
  }
  return settings;
}

} // namespace support_assist
