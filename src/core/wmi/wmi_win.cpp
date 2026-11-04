#include "support_assist/wmi.hpp"

#include "support_assist/strings.hpp"

#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <wbemidl.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

template <typename T> class ComPtr {
public:
  ComPtr() = default;
  explicit ComPtr(T* value) : value_(value) {}
  ~ComPtr() {
    reset();
  }
  ComPtr(const ComPtr&) = delete;
  ComPtr& operator=(const ComPtr&) = delete;
  ComPtr(ComPtr&& other) noexcept : value_(other.release()) {}
  ComPtr& operator=(ComPtr&& other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  T* get() const noexcept {
    return value_;
  }
  T** put() noexcept {
    reset();
    return &value_;
  }
  T* operator->() const noexcept {
    return value_;
  }
  T* release() noexcept {
    T* value = value_;
    value_ = nullptr;
    return value;
  }
  void reset(T* replacement = nullptr) noexcept {
    if (value_ != nullptr)
      value_->Release();
    value_ = replacement;
  }

private:
  T* value_ = nullptr;
};

class Bstr {
public:
  explicit Bstr(std::wstring_view value)
      : value_(SysAllocStringLen(value.data(), static_cast<UINT>(value.size()))) {}
  ~Bstr() {
    SysFreeString(value_);
  }
  Bstr(const Bstr&) = delete;
  Bstr& operator=(const Bstr&) = delete;
  BSTR get() const noexcept {
    return value_;
  }

private:
  BSTR value_ = nullptr;
};

// A BSTR holding a password: its characters are overwritten before it is freed.
class SecretBstr {
public:
  explicit SecretBstr(std::wstring_view value)
      : value_(SysAllocStringLen(value.data(), static_cast<UINT>(value.size()))) {}
  ~SecretBstr() {
    if (value_ != nullptr)
      SecureZeroMemory(value_, SysStringByteLen(value_));
    SysFreeString(value_);
  }
  SecretBstr(const SecretBstr&) = delete;
  SecretBstr& operator=(const SecretBstr&) = delete;
  BSTR get() const noexcept {
    return value_;
  }

private:
  BSTR value_ = nullptr;
};

// Another account for the WMI proxies. The proxies point at these strings, so the holder is declared
// before them and outlives them; its destructor overwrites them.
class AccountIdentity {
public:
  AccountIdentity(const WmiSignIn& sign_in, std::string_view machine) {
    const wmi_detail::WmiAccount account = wmi_detail::split_wmi_account(sign_in.user, machine);
    user_ = wide_from_utf8(account.user);
    domain_ = wide_from_utf8(account.domain);
    password_ = wide_from_utf8(sign_in.password);
    full_user_ = domain_.empty() ? user_ : domain_ + L"\\" + user_;
    identity_.User = reinterpret_cast<USHORT*>(user_.data());
    identity_.UserLength = static_cast<ULONG>(user_.size());
    identity_.Domain = domain_.empty() ? nullptr : reinterpret_cast<USHORT*>(domain_.data());
    identity_.DomainLength = static_cast<ULONG>(domain_.size());
    identity_.Password = reinterpret_cast<USHORT*>(password_.data());
    identity_.PasswordLength = static_cast<ULONG>(password_.size());
    identity_.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
  }
  ~AccountIdentity() {
    SecureZeroMemory(password_.data(), password_.size() * sizeof(wchar_t));
    SecureZeroMemory(&identity_, sizeof(identity_));
  }
  AccountIdentity(const AccountIdentity&) = delete;
  AccountIdentity& operator=(const AccountIdentity&) = delete;
  COAUTHIDENTITY* identity() noexcept {
    return &identity_;
  }
  const std::wstring& full_user() const noexcept {
    return full_user_;
  }
  const std::wstring& password() const noexcept {
    return password_;
  }

private:
  std::wstring user_;
  std::wstring domain_;
  std::wstring password_;
  std::wstring full_user_;
  COAUTHIDENTITY identity_{};
};

// The proxy's security: as the account SAT runs as (NTLM at call level, as before), or as another
// account with packet privacy, so the sign-in and the results are encrypted.
HRESULT secure_proxy(IUnknown* proxy, AccountIdentity* account) {
  if (account == nullptr)
    return CoSetProxyBlanket(proxy, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
  return CoSetProxyBlanket(proxy, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL,
                           RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, account->identity(), EOAC_NONE);
}

class ComApartment {
public:
  ComApartment() {
    result_ = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    owns_ = SUCCEEDED(result_);
  }
  ~ComApartment() {
    if (owns_)
      CoUninitialize();
  }
  bool usable() const noexcept {
    return SUCCEEDED(result_) || result_ == RPC_E_CHANGED_MODE;
  }
  HRESULT result() const noexcept {
    return result_;
  }

private:
  HRESULT result_ = E_FAIL;
  bool owns_ = false;
};

Error wmi_error(std::string operation, std::string source, std::string message, HRESULT result) {
  Error error;
  error.component = "WMI";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  error.hresult = result;
  return error;
}

std::string variant_text(VARIANT& value);

// An array property (IPAddress, DNSServerSearchOrder) as its values joined with "; ".
std::string array_text(const VARIANT& value) {
  SAFEARRAY* array = (value.vt & VT_BYREF) != 0 ? (value.pparray == nullptr ? nullptr : *value.pparray) : value.parray;
  if (array == nullptr || SafeArrayGetDim(array) != 1)
    return "<unprintable>";
  LONG lower = 0;
  LONG upper = -1;
  if (FAILED(SafeArrayGetLBound(array, 1, &lower)) || FAILED(SafeArrayGetUBound(array, 1, &upper)))
    return "<unprintable>";
  const VARTYPE element_type = static_cast<VARTYPE>(value.vt & VT_TYPEMASK);
  if (element_type == VT_DECIMAL || element_type == VT_RECORD || element_type == VT_UNKNOWN ||
      element_type == VT_DISPATCH)
    return "<unprintable>";
  constexpr LONG kMaximumElements = 256;
  std::string output;
  for (LONG index = lower; index <= upper && index - lower < kMaximumElements; ++index) {
    VARIANT element;
    VariantInit(&element);
    HRESULT read = E_FAIL;
    if (element_type == VT_VARIANT) {
      read = SafeArrayGetElement(array, &index, &element);
    } else {
      element.llVal = 0;
      read = SafeArrayGetElement(array, &index, &element.llVal);
      element.vt = SUCCEEDED(read) ? element_type : static_cast<VARTYPE>(VT_EMPTY);
    }
    if (FAILED(read))
      return "<unprintable>";
    if (index > lower)
      output += "; ";
    output += variant_text(element);
    VariantClear(&element);
  }
  if (upper - lower + 1 > kMaximumElements)
    output += "; ...";
  return output;
}

std::string variant_text(VARIANT& value) {
  if (value.vt == VT_NULL || value.vt == VT_EMPTY)
    return {};
  if ((value.vt & VT_ARRAY) != 0)
    return array_text(value);
  // VariantChangeType turns a boolean into "-1" or "0"; readers compare against True and False.
  if (value.vt == VT_BOOL)
    return value.boolVal != VARIANT_FALSE ? "True" : "False";
  VARIANT converted;
  VariantInit(&converted);
  const HRESULT result = VariantChangeType(&converted, &value, 0, VT_BSTR);
  if (FAILED(result) || converted.bstrVal == nullptr) {
    VariantClear(&converted);
    return "<unprintable>";
  }
  const std::string output = format_cim_datetime(utf8_from_wide(converted.bstrVal));
  VariantClear(&converted);
  return output;
}

std::wstring connection_namespace(const WmiQueryOptions& options) {
  const std::wstring name_space = wide_from_utf8(options.name_space);
  if (options.machine.empty() || options.machine == "." || options.machine == "localhost") {
    return name_space;
  }
  return L"\\\\" + wide_from_utf8(options.machine) + L"\\" + name_space;
}

} // namespace

Result<std::vector<WmiRow>> query_wmi(const WmiQueryOptions& options,
                                      const CancellationToken& cancel,
                                      ProgressCallback progress) {
  const std::vector<std::string> selected = wmi_detail::wql_select_list(options.query);
  if (options.query.empty()) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("query", options.machine, "A WQL query is required", E_INVALIDARG));
  }
  ComApartment apartment;
  if (!apartment.usable()) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("initialize COM", options.machine, "CoInitializeEx failed", apartment.result()));
  }
  const HRESULT security = CoInitializeSecurity(nullptr,
                                                -1,
                                                nullptr,
                                                nullptr,
                                                RPC_C_AUTHN_LEVEL_DEFAULT,
                                                RPC_C_IMP_LEVEL_IMPERSONATE,
                                                nullptr,
                                                EOAC_NONE,
                                                nullptr);
  if (FAILED(security) && security != RPC_E_TOO_LATE) {
    return Result<std::vector<WmiRow>>::failure(wmi_error(
        "initialize COM security", options.machine, "CoInitializeSecurity failed", security));
  }

  ComPtr<IWbemLocator> locator;
  HRESULT result = CoCreateInstance(CLSID_WbemLocator,
                                    nullptr,
                                    CLSCTX_INPROC_SERVER,
                                    IID_IWbemLocator,
                                    reinterpret_cast<void**>(locator.put()));
  if (FAILED(result)) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("create locator", options.machine, "CoCreateInstance failed", result));
  }
  const std::wstring namespace_value = connection_namespace(options);
  Bstr namespace_bstr(namespace_value);
  // Declared before the proxies, so it outlives them.
  std::unique_ptr<AccountIdentity> account;
  if (!options.sign_in.user.empty())
    account = std::make_unique<AccountIdentity>(options.sign_in, options.machine);
  ComPtr<IWbemServices> services;
  // Each stage shows as it starts: connecting to another machine can take seconds before any row.
  const auto stage = [&progress](const char* phase, std::string scope, std::uint64_t processed) {
    if (!progress)
      return;
    ProgressEvent event;
    event.phase = phase;
    event.current_scope = std::move(scope);
    event.processed = processed;
    progress(event);
  };
  stage("Connect", options.machine + "\\" + options.name_space, 0);
  // WBEM_FLAG_CONNECT_USE_MAX_WAIT bounds the connection to two minutes, so an address behind a
  // firewall fails instead of waiting on DCOM's own timeouts.
  {
    std::unique_ptr<Bstr> user;
    std::unique_ptr<SecretBstr> password;
    if (account) {
      user = std::make_unique<Bstr>(account->full_user());
      password = std::make_unique<SecretBstr>(account->password());
    }
    result = locator->ConnectServer(namespace_bstr.get(),
                                    user ? user->get() : nullptr,
                                    password ? password->get() : nullptr,
                                    nullptr,
                                    WBEM_FLAG_CONNECT_USE_MAX_WAIT,
                                    nullptr,
                                    nullptr,
                                    services.put());
  }
  if (FAILED(result)) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("connect",
                  options.machine + "\\" + options.name_space,
                  account ? "IWbemLocator::ConnectServer failed with the account given"
                          : "IWbemLocator::ConnectServer failed",
                  result));
  }
  result = secure_proxy(services.get(), account.get());
  if (FAILED(result)) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("configure proxy", options.machine, "CoSetProxyBlanket failed", result));
  }

  stage("Query", options.machine, 0);
  Bstr query_language(L"WQL");
  Bstr query_text(wide_from_utf8(options.query));
  ComPtr<IEnumWbemClassObject> enumerator;
  result = services->ExecQuery(query_language.get(),
                               query_text.get(),
                               WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                               nullptr,
                               enumerator.put());
  if (FAILED(result)) {
    return Result<std::vector<WmiRow>>::failure(
        wmi_error("execute query", options.query, "IWbemServices::ExecQuery failed", result));
  }
  // The enumerator is a proxy of its own: with another account it needs the account too.
  if (account) {
    result = secure_proxy(enumerator.get(), account.get());
    if (FAILED(result)) {
      return Result<std::vector<WmiRow>>::failure(
          wmi_error("configure proxy", options.machine, "CoSetProxyBlanket failed", result));
    }
  }

  std::vector<WmiRow> rows;
  int waits = 0;
  while (rows.size() < options.maximum_rows && !cancel.is_cancelled()) {
    ComPtr<IWbemClassObject> object;
    ULONG returned = 0;
    result = enumerator->Next(500, 1, object.put(), &returned);
    // Nothing yet within 500 ms is not the end of the results: ask again, up to two minutes.
    if (result == WBEM_S_TIMEDOUT && returned == 0) {
      if (++waits >= 240)
        return Result<std::vector<WmiRow>>::failure(wmi_error(
            "enumerate results", options.query, "No result arrived within two minutes", result));
      continue;
    }
    waits = 0;
    if (result == WBEM_S_FALSE || returned == 0)
      break;
    if (FAILED(result)) {
      return Result<std::vector<WmiRow>>::failure(wmi_error(
          "enumerate results", options.query, "IEnumWbemClassObject::Next failed", result));
    }

    WmiRow row;
    result = object->BeginEnumeration(WBEM_FLAG_NONSYSTEM_ONLY);
    if (SUCCEEDED(result)) {
      for (std::size_t property_index = 0; property_index < options.maximum_properties;
           ++property_index) {
        BSTR raw_name = nullptr;
        VARIANT value;
        VariantInit(&value);
        CIMTYPE type = 0;
        LONG flavor = 0;
        result = object->Next(0, &raw_name, &value, &type, &flavor);
        if (result == WBEM_S_NO_MORE_DATA) {
          VariantClear(&value);
          break;
        }
        if (FAILED(result)) {
          VariantClear(&value);
          break;
        }
        const std::string name = raw_name == nullptr ? "" : utf8_from_wide(raw_name);
        if (raw_name != nullptr)
          SysFreeString(raw_name);
        if (row.values.emplace(name, variant_text(value)).second)
          row.order.push_back(name);
        VariantClear(&value);
      }
      object->EndEnumeration();
    }
    wmi_detail::order_by_select(row, selected);
    rows.push_back(std::move(row));
    stage("Read rows", options.machine, static_cast<std::uint64_t>(rows.size()));
  }
  return Result<std::vector<WmiRow>>::success(std::move(rows));
}

WmiQueryOptions make_host_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.query = "SELECT CSName, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime "
                  "FROM Win32_OperatingSystem";
  return options;
}

WmiQueryOptions make_cluster_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.name_space = "root\\MSCluster";
  options.query = "SELECT Name, State FROM MSCluster_Node";
  return options;
}

WmiQueryOptions make_process_wmi_preset(std::string machine) {
  WmiQueryOptions options;
  options.machine = std::move(machine);
  options.query = "SELECT ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine, "
                  "CreationDate, ThreadCount, WorkingSetSize FROM Win32_Process";
  options.maximum_rows = 10000;
  return options;
}

} // namespace support_assist
