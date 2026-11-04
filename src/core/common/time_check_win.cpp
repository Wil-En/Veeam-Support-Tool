// Windows side of Time Check: the dynamic time zone, the Windows Time settings (group policy before
// the service's own), whether the service runs, and under the domain hierarchy the domain controller
// that serves time. Registry, Service Control Manager and DsGetDcName reads only; w32tm is not run.
#include "support_assist/time_check.hpp"

#include "support_assist/strings.hpp"

#include <windows.h>
#include <dsgetdc.h>
#include <lm.h>

namespace support_assist {
namespace {

std::wstring registry_text(const wchar_t* key, const wchar_t* value) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr,
                   nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key, value, RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND, nullptr,
                   text.data(), &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return text;
}

std::string time_setting(const wchar_t* value) {
  std::wstring text = registry_text(L"SOFTWARE\\Policies\\Microsoft\\W32Time\\Parameters", value);
  if (text.empty())
    text = registry_text(L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters", value);
  return utf8_from_wide(text);
}

bool windows_time_running() {
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (manager == nullptr)
    return true; // unknown: say nothing
  bool running = true;
  if (SC_HANDLE service = OpenServiceW(manager, L"W32Time", SERVICE_QUERY_STATUS)) {
    SERVICE_STATUS status{};
    if (QueryServiceStatus(service, &status) != FALSE)
      running = status.dwCurrentState == SERVICE_RUNNING;
    CloseServiceHandle(service);
  }
  CloseServiceHandle(manager);
  return running;
}

bool joined_to_domain() {
  LPWSTR name = nullptr;
  NETSETUP_JOIN_STATUS status = NetSetupUnknownStatus;
  if (NetGetJoinInformation(nullptr, &name, &status) != NERR_Success)
    return false;
  if (name != nullptr)
    NetApiBufferFree(name);
  return status == NetSetupDomainName;
}

std::string time_domain_controller() {
  PDOMAIN_CONTROLLER_INFOW info = nullptr;
  if (DsGetDcNameW(nullptr, nullptr, nullptr, nullptr, DS_TIMESERV_REQUIRED | DS_RETURN_DNS_NAME, &info) !=
          ERROR_SUCCESS ||
      info == nullptr)
    return {};
  std::wstring name = info->DomainControllerName != nullptr ? info->DomainControllerName : L"";
  NetApiBufferFree(info);
  while (!name.empty() && name.front() == L'\\')
    name.erase(name.begin());
  return utf8_from_wide(name);
}

std::int64_t unix_millis_from_filetime(const FILETIME& time) {
  ULARGE_INTEGER value{};
  value.LowPart = time.dwLowDateTime;
  value.HighPart = time.dwHighDateTime;
  return (static_cast<std::int64_t>(value.QuadPart) - 116444736000000000LL) / 10000;
}

} // namespace

TimeZoneInfo read_time_zone() {
  TimeZoneInfo zone;
  DYNAMIC_TIME_ZONE_INFORMATION information{};
  const DWORD kind = GetDynamicTimeZoneInformation(&information);
  zone.name = utf8_from_wide(information.TimeZoneKeyName[0] != L'\0' ? information.TimeZoneKeyName
                                                                     : information.StandardName);
  long bias = information.Bias;
  if (kind == TIME_ZONE_ID_DAYLIGHT)
    bias += information.DaylightBias;
  else if (kind == TIME_ZONE_ID_STANDARD)
    bias += information.StandardBias;
  zone.utc_offset_minutes = static_cast<int>(-bias);
  zone.daylight_saving_now = kind == TIME_ZONE_ID_DAYLIGHT;
  return zone;
}

TimeSourceSettings read_time_source() {
  TimeSourceSettings source;
  source.service = "Windows Time";
  const std::string type = time_setting(L"Type");
  if (type == "NT5DS")
    source.mode = "domain hierarchy (NT5DS)";
  else if (type == "NTP")
    source.mode = "the listed NTP servers (NTP)";
  else if (type == "AllSync")
    source.mode = "domain hierarchy and the listed NTP servers (AllSync)";
  else if (type == "NoSync")
    source.mode = "not synchronized (NoSync)";
  else
    source.mode = type;
  source.servers = time_check_detail::parse_w32time_servers(time_setting(L"NtpServer"));
  if ((type == "NT5DS" || type == "AllSync") && joined_to_domain())
    source.domain_controller = time_domain_controller();
  if (!windows_time_running())
    source.note = "The Windows Time service is not running.";
  else if (type == "NoSync")
    source.note = "Windows Time is set not to synchronize this clock.";
  return source;
}

namespace time_check_detail {

int local_offset_minutes_at(std::int64_t unix_millis) {
  const std::int64_t filetime = unix_millis * 10000 + 116444736000000000LL;
  FILETIME utc_file{};
  utc_file.dwLowDateTime = static_cast<DWORD>(static_cast<std::uint64_t>(filetime) & 0xFFFFFFFFULL);
  utc_file.dwHighDateTime = static_cast<DWORD>(static_cast<std::uint64_t>(filetime) >> 32U);
  SYSTEMTIME utc{};
  SYSTEMTIME local{};
  FILETIME local_file{};
  DYNAMIC_TIME_ZONE_INFORMATION information{};
  GetDynamicTimeZoneInformation(&information);
  if (FileTimeToSystemTime(&utc_file, &utc) == FALSE ||
      SystemTimeToTzSpecificLocalTimeEx(&information, &utc, &local) == FALSE ||
      SystemTimeToFileTime(&local, &local_file) == FALSE)
    return read_time_zone().utc_offset_minutes;
  return static_cast<int>((unix_millis_from_filetime(local_file) - unix_millis) / 60000);
}

} // namespace time_check_detail

} // namespace support_assist
