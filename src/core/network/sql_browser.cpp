#include "support_assist/sql_browser.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/udp_exchange.hpp"

#include <cstdint>
#include <utility>

namespace support_assist {
namespace {

constexpr std::uint8_t kClientUnicastEx = 0x03; // CLNT_UCAST_EX: every instance on the server
constexpr std::uint8_t kServerResponse = 0x05;  // SVR_RESP

} // namespace

std::string sql_instance_name(const SqlInstance& instance) {
  if (instance.instance.empty() || ascii_lower(instance.instance) == "mssqlserver")
    return instance.server;
  return instance.server + "\\" + instance.instance;
}

std::vector<SqlInstance> parse_sql_browser_reply(std::string_view text) {
  std::vector<SqlInstance> instances;
  // Records end with ";;"; within one, names and values alternate, separated by ";".
  while (!text.empty()) {
    const std::size_t end = text.find(";;");
    std::string_view record = text.substr(0, end);
    text = end == std::string_view::npos ? std::string_view() : text.substr(end + 2U);
    SqlInstance instance;
    while (!record.empty()) {
      const std::size_t name_end = record.find(';');
      if (name_end == std::string_view::npos)
        break;
      const std::string name = ascii_lower(record.substr(0, name_end));
      record.remove_prefix(name_end + 1U);
      const std::size_t value_end = record.find(';');
      const std::string value(record.substr(0, value_end));
      record = value_end == std::string_view::npos ? std::string_view() : record.substr(value_end + 1U);
      if (name == "servername")
        instance.server = value;
      else if (name == "instancename")
        instance.instance = value;
      else if (name == "version")
        instance.version = value;
      else if (name == "tcp")
        instance.tcp_port = value;
      else if (name == "isclustered")
        instance.clustered = ascii_lower(value) == "yes";
    }
    if (!instance.server.empty() || !instance.instance.empty())
      instances.push_back(std::move(instance));
  }
  return instances;
}

SqlBrowserScan scan_sql_instances(const std::string& host, std::chrono::milliseconds timeout) {
  SqlBrowserScan scan;
  scan.host = host;
  if (host.empty()) {
    scan.error = "Type the host to scan.";
    return scan;
  }
  const UdpExchange exchange = udp_exchange(
      host, kSqlBrowserPort, false, []() { return std::vector<std::uint8_t>{kClientUnicastEx}; },
      [](const std::vector<std::uint8_t>& reply) { return reply.size() >= 3U && reply[0] == kServerResponse; },
      timeout);
  scan.address = exchange.address;
  if (!exchange.answered) {
    scan.error = exchange.error.empty() ? "SQL Server Browser did not answer on UDP 1434." : exchange.error;
    return scan;
  }
  scan.answered = true;
  const std::size_t length = static_cast<std::size_t>(exchange.response[1]) |
                             (static_cast<std::size_t>(exchange.response[2]) << 8U);
  const std::size_t available = exchange.response.size() - 3U;
  const std::string text(reinterpret_cast<const char*>(exchange.response.data() + 3U),
                         length < available ? length : available);
  scan.instances = parse_sql_browser_reply(text);
  if (scan.instances.empty())
    scan.error = "SQL Server Browser answered but listed no instance.";
  return scan;
}

} // namespace support_assist
