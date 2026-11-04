// Windows Defender Firewall, read through its COM policy object (INetFwPolicy2): the profiles, their
// defaults and the inbound rules. The network list manager names the adapters in each profile, and
// Windows Security Center names a third-party firewall that is on (client editions only). Nothing
// is changed, and no command-line tool is started.
#include "support_assist/firewall.hpp"

#include "support_assist/strings.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <netfw.h>
#include <netlistmgr.h>
#include <wscapi.h>
#include <iwscapi.h>
#include <shlwapi.h>
#include <wrl/client.h>

#include <map>
#include <optional>

using Microsoft::WRL::ComPtr;

namespace support_assist {
namespace {

class ComScope {
public:
  ComScope() {
    const HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    initialized_ = SUCCEEDED(result);
    usable_ = initialized_ || result == RPC_E_CHANGED_MODE; // the thread already has an apartment
  }
  ComScope(const ComScope&) = delete;
  ComScope& operator=(const ComScope&) = delete;
  ~ComScope() {
    if (initialized_)
      CoUninitialize();
  }
  [[nodiscard]] bool usable() const { return usable_; }

private:
  bool initialized_ = false;
  bool usable_ = false;
};

std::string take_bstr(BSTR value) {
  std::string text = value != nullptr ? utf8_from_wide(std::wstring_view(value, SysStringLen(value))) : std::string();
  if (value != nullptr)
    SysFreeString(value);
  return text;
}

std::string guid_text(const GUID& guid) {
  wchar_t buffer[64] = {};
  StringFromGUID2(guid, buffer, 64);
  return ascii_upper(utf8_from_wide(buffer));
}

// "{GUID}" -> "Ethernet0 10.0.4.10"
std::map<std::string, std::string> adapter_names() {
  std::map<std::string, std::string> names;
  ULONG size = 16 * 1024;
  std::vector<unsigned char> buffer(size);
  ULONG status = ERROR_BUFFER_OVERFLOW;
  for (int attempt = 0; attempt < 3 && status == ERROR_BUFFER_OVERFLOW; ++attempt) {
    buffer.resize(size);
    status = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                  nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (status != NO_ERROR)
    return names;
  for (auto* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()); adapter != nullptr;
       adapter = adapter->Next) {
    std::string text = utf8_from_wide(adapter->FriendlyName != nullptr ? adapter->FriendlyName : L"");
    for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr; unicast = unicast->Next) {
      const sockaddr* address = unicast->Address.lpSockaddr;
      if (address == nullptr || address->sa_family != AF_INET)
        continue;
      char ip[INET_ADDRSTRLEN] = {};
      const auto* v4 = reinterpret_cast<const sockaddr_in*>(address);
      if (inet_ntop(AF_INET, &v4->sin_addr, ip, sizeof(ip)) != nullptr)
        text += std::string(" ") + ip;
    }
    names[ascii_upper(adapter->AdapterName != nullptr ? adapter->AdapterName : "")] = text;
  }
  return names;
}

// Networks per profile bit, from the network list manager.
std::map<unsigned, std::vector<std::string>> networks_by_profile() {
  std::map<unsigned, std::vector<std::string>> result;
  ComPtr<INetworkListManager> manager;
  if (FAILED(CoCreateInstance(__uuidof(NetworkListManager), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&manager))))
    return result;
  ComPtr<IEnumNetworkConnections> connections;
  if (FAILED(manager->GetNetworkConnections(&connections)) || !connections)
    return result;
  const auto names = adapter_names();
  for (;;) {
    ComPtr<INetworkConnection> connection;
    ULONG fetched = 0;
    if (connections->Next(1, &connection, &fetched) != S_OK || fetched == 0)
      break;
    GUID adapter{};
    ComPtr<INetwork> network;
    if (FAILED(connection->GetAdapterId(&adapter)) || FAILED(connection->GetNetwork(&network)) || !network)
      continue;
    NLM_NETWORK_CATEGORY category = NLM_NETWORK_CATEGORY_PUBLIC;
    if (FAILED(network->GetCategory(&category)))
      continue;
    BSTR network_name = nullptr;
    network->GetName(&network_name);
    const std::string label = take_bstr(network_name);
    const auto adapter_name = names.find(guid_text(adapter));
    std::string text = adapter_name != names.end() ? adapter_name->second : std::string("adapter");
    if (!label.empty())
      text += " (network " + label + ")";
    const unsigned bit = category == NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED ? NET_FW_PROFILE2_DOMAIN
                         : category == NLM_NETWORK_CATEGORY_PRIVATE ? NET_FW_PROFILE2_PRIVATE
                                                                    : NET_FW_PROFILE2_PUBLIC;
    result[bit].push_back(text);
  }
  return result;
}

// A third-party firewall that Windows Security Center reports as on. Security Center exists on
// client editions only; on Windows Server the class is not registered and nothing is named.
std::string third_party_firewall() {
  ComPtr<IWSCProductList> products;
  if (FAILED(CoCreateInstance(__uuidof(WSCProductList), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&products))))
    return {};
  if (FAILED(products->Initialize(WSC_SECURITY_PROVIDER_FIREWALL)))
    return {};
  LONG count = 0;
  if (FAILED(products->get_Count(&count)))
    return {};
  std::string names;
  for (LONG i = 0; i < count; ++i) {
    ComPtr<IWscProduct> product;
    if (FAILED(products->get_Item(static_cast<ULONG>(i), &product)) || !product)
      continue;
    WSC_SECURITY_PRODUCT_STATE state = WSC_SECURITY_PRODUCT_STATE_OFF;
    if (FAILED(product->get_ProductState(&state)) || state != WSC_SECURITY_PRODUCT_STATE_ON)
      continue;
    BSTR name = nullptr;
    product->get_ProductName(&name);
    const std::string text = take_bstr(name);
    const std::string lower = ascii_lower(text);
    if (text.empty() || lower.find("windows") != std::string::npos || lower.find("microsoft defender") != std::string::npos)
      continue;
    if (!names.empty())
      names += ", ";
    names += text;
  }
  return names;
}

// INetFwPolicy2 reports a profile's local settings; group policy overrides them, and a domain
// usually sets the Domain profile there. The policy keys: DomainProfile, PrivateProfile and
// PublicProfile (Windows Defender Firewall with Advanced Security), and StandardProfile for both
// non-domain profiles (the older Windows Firewall policy), which the newer key overrides.
std::optional<DWORD> policy_value(const wchar_t* profile_key, const wchar_t* name) {
  const std::wstring key = std::wstring(L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\") + profile_key;
  DWORD value = 0;
  DWORD size = sizeof(value);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), name, RRF_RT_REG_DWORD, nullptr, &value, &size) != ERROR_SUCCESS)
    return std::nullopt;
  return value;
}

std::optional<DWORD> profile_policy(NET_FW_PROFILE_TYPE2 bit, const wchar_t* name) {
  if (bit == NET_FW_PROFILE2_DOMAIN)
    return policy_value(L"DomainProfile", name);
  if (auto value = policy_value(bit == NET_FW_PROFILE2_PRIVATE ? L"PrivateProfile" : L"PublicProfile", name))
    return value;
  return policy_value(L"StandardProfile", name);
}

std::string readable_name(const std::string& reference) {
  const std::wstring source = wide_from_utf8(reference);
  wchar_t buffer[512] = {};
  if (SUCCEEDED(SHLoadIndirectString(source.c_str(), buffer, 512, nullptr)) && buffer[0] != L'\0')
    return utf8_from_wide(buffer);
  return reference;
}

// A rule's Profiles read through its dispatch interface. Read through INetFwRule's own get_Profiles,
// every rule here came back as NET_FW_PROFILE2_ALL (a rule for the Domain profile only counted on
// Private and Public), while the dispatch read gives the profiles Windows Defender Firewall shows.
long rule_profiles(IDispatch* rule, long fallback) {
  DISPID id = 0;
  LPOLESTR member = const_cast<LPOLESTR>(L"Profiles");
  if (rule == nullptr || FAILED(rule->GetIDsOfNames(IID_NULL, &member, 1, LOCALE_USER_DEFAULT, &id)))
    return fallback;
  DISPPARAMS none{};
  VARIANT value;
  VariantInit(&value);
  long profiles = fallback;
  if (SUCCEEDED(rule->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &none, &value, nullptr,
                             nullptr)) &&
      SUCCEEDED(VariantChangeType(&value, &value, 0, VT_I4)))
    profiles = value.lVal;
  VariantClear(&value);
  return profiles;
}

Error firewall_error(const std::string& operation, HRESULT result) {
  Error error;
  error.component = "network";
  error.operation = operation;
  error.hresult = static_cast<std::int64_t>(result);
  error.message = "Windows Defender Firewall did not answer";
  return error;
}

} // namespace

Result<FirewallSnapshot> read_firewall() {
  ComScope com;
  FirewallSnapshot snapshot;
  snapshot.product = "Windows Defender Firewall";
  if (!com.usable())
    return Result<FirewallSnapshot>::failure(firewall_error("start COM", E_FAIL));

  ComPtr<INetFwPolicy2> policy;
  HRESULT result = CoCreateInstance(__uuidof(NetFwPolicy2), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&policy));
  if (FAILED(result))
    return Result<FirewallSnapshot>::failure(firewall_error("open the firewall policy", result));

  long current = 0;
  policy->get_CurrentProfileTypes(&current);
  const auto networks = networks_by_profile();
  for (const auto& [bit, name] : {std::pair<NET_FW_PROFILE_TYPE2, const char*>{NET_FW_PROFILE2_DOMAIN, "Domain"},
                                  {NET_FW_PROFILE2_PRIVATE, "Private"},
                                  {NET_FW_PROFILE2_PUBLIC, "Public"}}) {
    FirewallProfileState profile;
    profile.name = name;
    profile.mask = static_cast<unsigned>(bit);
    profile.active = (static_cast<unsigned long>(current) & static_cast<unsigned long>(bit)) != 0UL;
    VARIANT_BOOL enabled = VARIANT_TRUE;
    policy->get_FirewallEnabled(bit, &enabled);
    profile.enabled = enabled != VARIANT_FALSE;
    NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
    policy->get_DefaultInboundAction(bit, &action);
    profile.inbound_blocked_by_default = action == NET_FW_ACTION_BLOCK;
    VARIANT_BOOL block_all = VARIANT_FALSE;
    policy->get_BlockAllInboundTraffic(bit, &block_all);
    profile.block_all_inbound = block_all != VARIANT_FALSE;
    if (const auto value = profile_policy(bit, L"EnableFirewall"))
      profile.enabled = *value != 0;
    if (const auto value = profile_policy(bit, L"DefaultInboundAction"))
      profile.inbound_blocked_by_default = *value != 0; // 1 blocks, 0 allows
    if (const auto value = profile_policy(bit, L"DoNotAllowExceptions"))
      profile.block_all_inbound = *value != 0;
    if (const auto found = networks.find(profile.mask); found != networks.end())
      profile.networks = found->second;
    snapshot.profiles.push_back(std::move(profile));
  }

  NET_FW_MODIFY_STATE modify_state = NET_FW_MODIFY_STATE_OK;
  if (SUCCEEDED(policy->get_LocalPolicyModifyState(&modify_state)))
    snapshot.group_policy_overrides_local_rules = modify_state != NET_FW_MODIFY_STATE_OK;

  ComPtr<INetFwRules> rules;
  if (FAILED(result = policy->get_Rules(&rules)) || !rules)
    return Result<FirewallSnapshot>::failure(firewall_error("read the firewall rules", result));
  ComPtr<IUnknown> enumerator_unknown;
  ComPtr<IEnumVARIANT> enumerator;
  if (FAILED(result = rules->get__NewEnum(&enumerator_unknown)) || FAILED(enumerator_unknown.As(&enumerator)))
    return Result<FirewallSnapshot>::failure(firewall_error("read the firewall rules", result));
  for (;;) {
    VARIANT item;
    VariantInit(&item);
    ULONG fetched = 0;
    if (enumerator->Next(1, &item, &fetched) != S_OK || fetched == 0) {
      VariantClear(&item);
      break;
    }
    ComPtr<INetFwRule> rule;
    if (item.vt == VT_DISPATCH && item.pdispVal != nullptr &&
        SUCCEEDED(item.pdispVal->QueryInterface(IID_PPV_ARGS(&rule)))) {
      NET_FW_RULE_DIRECTION direction = NET_FW_RULE_DIR_OUT;
      rule->get_Direction(&direction);
      if (direction == NET_FW_RULE_DIR_IN) {
        FirewallRule entry;
        BSTR text = nullptr;
        rule->get_Name(&text);
        entry.name = take_bstr(text);
        VARIANT_BOOL enabled = VARIANT_FALSE;
        rule->get_Enabled(&enabled);
        entry.enabled = enabled != VARIANT_FALSE;
        NET_FW_ACTION action = NET_FW_ACTION_BLOCK;
        rule->get_Action(&action);
        entry.allow = action == NET_FW_ACTION_ALLOW;
        long protocol = NET_FW_IP_PROTOCOL_ANY;
        rule->get_Protocol(&protocol);
        entry.protocol = static_cast<int>(protocol);
        text = nullptr;
        rule->get_LocalPorts(&text);
        entry.local_ports = take_bstr(text);
        text = nullptr;
        rule->get_ApplicationName(&text);
        entry.program = take_bstr(text);
        text = nullptr;
        rule->get_ServiceName(&text);
        entry.service = take_bstr(text);
        text = nullptr;
        rule->get_RemoteAddresses(&text);
        entry.remote_addresses = take_bstr(text);
        text = nullptr;
        rule->get_LocalAddresses(&text);
        entry.local_addresses = take_bstr(text);
        text = nullptr;
        rule->get_InterfaceTypes(&text);
        entry.interface_types = take_bstr(text);
        long profiles = NET_FW_PROFILE2_ALL;
        rule->get_Profiles(&profiles);
        entry.profiles = static_cast<unsigned>(rule_profiles(item.pdispVal, profiles));
        ComPtr<INetFwRule3> conditions;
        if (SUCCEEDED(rule.As(&conditions)) && conditions) {
          text = nullptr;
          conditions->get_LocalAppPackageId(&text);
          entry.app_package = take_bstr(text);
          text = nullptr;
          conditions->get_LocalUserOwner(&text);
          entry.user_condition = take_bstr(text);
          if (entry.user_condition.empty()) {
            text = nullptr;
            conditions->get_LocalUserAuthorizedList(&text);
            entry.user_condition = take_bstr(text);
          }
          long secure = 0;
          if (SUCCEEDED(conditions->get_SecureFlags(&secure)))
            entry.requires_ipsec = secure != 0;
        }
        // Built-in rules store their names as resource references ("@FirewallAPI.dll,-28502").
        if (entry.enabled && entry.app_package.empty() && entry.name.rfind('@', 0) == 0)
          entry.name = readable_name(entry.name);
        snapshot.rules.push_back(std::move(entry));
      }
    }
    VariantClear(&item);
  }
  snapshot.third_party = third_party_firewall();
  snapshot.readable = true;
  return Result<FirewallSnapshot>::success(std::move(snapshot));
}

} // namespace support_assist
