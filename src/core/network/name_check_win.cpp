// Windows resolver settings: the DNS servers of each connected adapter (GetAdaptersAddresses), the
// suffix search list (group policy, then the TCP/IP setting, then the primary and connection
// suffixes, the order Windows uses) and the hosts file under the system folder.
#include "support_assist/name_check.hpp"

#include "support_assist/strings.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

#include <algorithm>
#include <set>

namespace support_assist {
namespace {

std::wstring registry_text(const wchar_t* key, const wchar_t* value) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return text;
}

std::vector<std::string> suffix_list(const std::wstring& text) {
  std::vector<std::string> suffixes;
  for (const std::string& item : split(utf8_from_wide(text), ',')) {
    const std::string suffix = trim(item);
    if (!suffix.empty())
      suffixes.push_back(suffix);
  }
  return suffixes;
}

std::string numeric_address(const SOCKET_ADDRESS& address) {
  char text[NI_MAXHOST] = {};
  if (address.lpSockaddr == nullptr ||
      getnameinfo(address.lpSockaddr, address.iSockaddrLength, text, sizeof(text), nullptr, 0, NI_NUMERICHOST) != 0)
    return {};
  return text;
}

} // namespace

ResolverSettings read_resolver_settings() {
  ResolverSettings settings;
  settings.lookup_order =
      "hosts file, then the DNS cache and the DNS servers; LLMNR and NetBIOS for a name DNS does not answer";
  wchar_t system_folder[MAX_PATH] = {};
  const UINT length = GetSystemDirectoryW(system_folder, MAX_PATH);
  if (length > 0 && length < MAX_PATH)
    settings.hosts_file = utf8_from_wide(system_folder) + "\\drivers\\etc\\hosts";

  WSADATA data{};
  const bool sockets = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  std::vector<std::string> adapter_suffixes;
  ULONG size = 32U * 1024U;
  std::vector<unsigned char> buffer(size);
  ULONG status = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
    buffer.resize(size);
    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (status == NO_ERROR) {
    std::set<std::string> seen;
    for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter != nullptr;
         adapter = adapter->Next) {
      if (adapter->OperStatus != IfOperStatusUp || adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
        continue;
      const std::string interface_name = utf8_from_wide(adapter->FriendlyName != nullptr ? adapter->FriendlyName : L"");
      for (auto* server = adapter->FirstDnsServerAddress; server != nullptr; server = server->Next) {
        const std::string address = numeric_address(server->Address);
        // fec0:0:0:ffff::1 to 3 are placeholders Windows lists when no IPv6 DNS server is set.
        if (address.empty() || address.rfind("fec0:0:0:ffff::", 0) == 0 || !seen.insert(address).second)
          continue;
        settings.servers.push_back({address, interface_name});
      }
      if (adapter->DnsSuffix != nullptr && adapter->DnsSuffix[0] != L'\0') {
        const std::string suffix = utf8_from_wide(adapter->DnsSuffix);
        if (std::find(adapter_suffixes.begin(), adapter_suffixes.end(), suffix) == adapter_suffixes.end())
          adapter_suffixes.push_back(suffix);
      }
    }
  }
  if (sockets)
    WSACleanup();

  settings.search_suffixes =
      suffix_list(registry_text(L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", L"SearchList"));
  if (settings.search_suffixes.empty())
    settings.search_suffixes =
        suffix_list(registry_text(L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", L"SearchList"));
  if (settings.search_suffixes.empty()) {
    wchar_t domain[256] = {};
    DWORD domain_length = 256;
    if (GetComputerNameExW(ComputerNameDnsDomain, domain, &domain_length) != FALSE && domain_length > 0)
      settings.search_suffixes.push_back(utf8_from_wide(domain));
    for (const std::string& suffix : adapter_suffixes) {
      if (std::find(settings.search_suffixes.begin(), settings.search_suffixes.end(), suffix) ==
          settings.search_suffixes.end())
        settings.search_suffixes.push_back(suffix);
    }
  }
  return settings;
}

} // namespace support_assist
