#pragma once

// The SQL Server instances a host serves, asked of its SQL Server Browser on UDP 1434 the way SQL
// Server Management Studio asks (MC-SQLR): one request, CLNT_UCAST_EX, and one reply listing each
// instance with its version and TCP port. A stopped Browser service or a firewall leaves the list
// empty, and the instance can still be typed.

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

inline constexpr unsigned short kSqlBrowserPort = 1434;

struct SqlInstance {
  std::string server;
  std::string instance; // MSSQLSERVER for the default instance
  std::string version;
  std::string tcp_port; // empty when the instance does not listen on TCP
  bool clustered = false;
};

// How a client names the instance: the server for the default instance, "SERVER\NAME" otherwise.
std::string sql_instance_name(const SqlInstance& instance);

struct SqlBrowserScan {
  std::string host;
  std::string address; // the address the request went to
  bool answered = false;
  std::string error; // why nothing was listed
  std::vector<SqlInstance> instances;
};

// The reply's text: "ServerName;H;InstanceName;I;IsClustered;No;Version;16.0.1000.6;tcp;1433;;" for
// each instance.
std::vector<SqlInstance> parse_sql_browser_reply(std::string_view text);

SqlBrowserScan scan_sql_instances(const std::string& host,
                                  std::chrono::milliseconds timeout = std::chrono::seconds(3));

} // namespace support_assist
