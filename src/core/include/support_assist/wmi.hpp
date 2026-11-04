#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// The account a connection to another machine signs in with, asked for each run and never kept. An
// empty user signs in as the account SAT runs as. WMI refuses an account for this machine
// (WBEM_E_LOCAL_CREDENTIALS).
struct WmiSignIn {
  std::string user;  // DOMAIN\name, name@domain, or the name of an account on the other machine
  std::string password;
};

// Overwrites the password's characters, then empties it.
inline void forget_wmi_password(WmiSignIn& sign_in) {
  std::fill(sign_in.password.begin(), sign_in.password.end(), '\0');
  sign_in.password.clear();
}

struct WmiQueryOptions {
  std::string machine = ".";
  std::string name_space = "root\\cimv2";
  std::string query = "SELECT * FROM Win32_OperatingSystem";
  std::size_t maximum_rows = 1000;
  std::size_t maximum_properties = 128;
  WmiSignIn sign_in;
};

namespace wmi_detail {

struct WmiAccount {
  std::string domain;
  std::string user;
};

// The domain and user DCOM signs in with. DOMAIN\name gives DOMAIN and name; name@domain is passed
// whole with no domain; a name alone is an account of the other machine, so its domain is the
// machine's first label (hv01 of hv01.contoso.local) or, for an address, the address.
inline WmiAccount split_wmi_account(std::string_view account, std::string_view machine) {
  const auto trim_view = [](std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t'))
      text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t'))
      text.remove_suffix(1);
    return text;
  };
  account = trim_view(account);
  machine = trim_view(machine);
  while (!machine.empty() && (machine.front() == '\\' || machine.front() == '/'))
    machine.remove_prefix(1);
  if (const auto slash = account.find('\\'); slash != std::string_view::npos)
    return {std::string(account.substr(0, slash)), std::string(account.substr(slash + 1))};
  if (account.find('@') != std::string_view::npos)
    return {std::string(), std::string(account)};
  const bool address = machine.find(':') != std::string_view::npos ||
                       (!machine.empty() && machine.find_first_not_of("0123456789.") == std::string_view::npos);
  const std::string_view domain = address ? machine : machine.substr(0, machine.find('.'));
  return {std::string(domain), std::string(account)};
}

} // namespace wmi_detail

struct WmiRow {
  std::map<std::string, std::string> values;
  // The property names in the order of the query's SELECT list, then the rest in the order the object
  // gave them (alphabetical); values is for lookups.
  std::vector<std::string> order;
};

namespace wmi_detail {
// The property names of a WQL SELECT list, in the order typed; empty for SELECT * or a query that is
// not a SELECT.
inline std::vector<std::string> wql_select_list(std::string_view query) {
  const auto lower = [](std::string_view text) {
    std::string out(text);
    for (char& c : out)
      c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
    return out;
  };
  const std::string folded = lower(query);
  const std::size_t select = folded.find("select");
  const std::size_t from = folded.find(" from ");
  if (select == std::string::npos || from == std::string::npos || from < select + 6U)
    return {};
  std::vector<std::string> names;
  std::string current;
  const auto flush = [&]() {
    while (!current.empty() && (current.back() == ' ' || current.back() == '\t'))
      current.pop_back();
    std::size_t start = 0;
    while (start < current.size() && (current[start] == ' ' || current[start] == '\t'))
      ++start;
    if (start < current.size())
      names.push_back(current.substr(start));
    current.clear();
  };
  for (std::size_t at = select + 6U; at < from; ++at) {
    if (query[at] == ',')
      flush();
    else
      current.push_back(query[at]);
  }
  flush();
  if (names.size() == 1U && names.front() == "*")
    return {};
  return names;
}

// The row's columns with the SELECT list's names first, in its order (names compared without case),
// then the others as they were.
inline void order_by_select(WmiRow& row, const std::vector<std::string>& selected) {
  if (selected.empty())
    return;
  const auto same = [](std::string_view left, std::string_view right) {
    if (left.size() != right.size())
      return false;
    for (std::size_t index = 0; index < left.size(); ++index) {
      char a = left[index];
      char b = right[index];
      a = (a >= 'A' && a <= 'Z') ? static_cast<char>(a - 'A' + 'a') : a;
      b = (b >= 'A' && b <= 'Z') ? static_cast<char>(b - 'A' + 'a') : b;
      if (a != b)
        return false;
    }
    return true;
  };
  std::vector<std::string> ordered;
  for (const std::string& wanted : selected) {
    for (const std::string& name : row.order) {
      if (same(name, wanted) && std::find(ordered.begin(), ordered.end(), name) == ordered.end()) {
        ordered.push_back(name);
        break;
      }
    }
  }
  for (const std::string& name : row.order) {
    if (std::find(ordered.begin(), ordered.end(), name) == ordered.end())
      ordered.push_back(name);
  }
  row.order = std::move(ordered);
}
} // namespace wmi_detail

Result<std::vector<WmiRow>> query_wmi(const WmiQueryOptions& options,
                                      const CancellationToken& cancel,
                                      ProgressCallback progress = {});

WmiQueryOptions make_host_wmi_preset(std::string machine = ".");
WmiQueryOptions make_cluster_wmi_preset(std::string machine = ".");

// The namespace is not on the machine (WBEM_E_INVALID_NAMESPACE): the role it belongs to is not
// installed, such as root\MSCluster without the failover cluster role.
inline bool wmi_namespace_absent(const Error& error) {
  return static_cast<std::uint32_t>(error.hresult) == 0x8004100EU;
}
WmiQueryOptions make_process_wmi_preset(std::string machine = ".");

// A CIM datetime ("20261007013221.740968-300") as "2026-10-07 01:32:21 (UTC-05:00)", and one with no
// time of day ("20240927000000.000000+000") as "2024-09-27". Any other text comes back as it is.
inline std::string format_cim_datetime(std::string_view text) {
  if (text.size() != 25 || text[14] != '.' || (text[21] != '+' && text[21] != '-'))
    return std::string(text);
  for (std::size_t index = 0; index < text.size(); ++index) {
    if (index != 14 && index != 21 && (text[index] < '0' || text[index] > '9'))
      return std::string(text);
  }
  std::string output;
  output.append(text.substr(0, 4)).append("-").append(text.substr(4, 2)).append("-").append(text.substr(6, 2));
  const std::string_view clock = text.substr(8, 6);
  if (clock == "000000" && text.substr(15, 6) == "000000")
    return output;
  output.append(" ").append(clock.substr(0, 2)).append(":").append(clock.substr(2, 2)).append(":").append(
      clock.substr(4, 2));
  const int offset = (text[22] - '0') * 100 + (text[23] - '0') * 10 + (text[24] - '0');
  const int hours = offset / 60;
  const int minutes = offset % 60;
  output += " (UTC";
  output += text[21];
  output += static_cast<char>('0' + hours / 10);
  output += static_cast<char>('0' + hours % 10);
  output += ':';
  output += static_cast<char>('0' + minutes / 10);
  output += static_cast<char>('0' + minutes % 10);
  output += ')';
  return output;
}

} // namespace support_assist
