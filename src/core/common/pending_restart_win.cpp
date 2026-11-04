// Pending restart on Windows: registry markers, each key's last-write time, and the events since the
// last start that name a cause (Setup 4, Windows Update 19, MsiInstaller 1038), read through
// EvtQuery. No command-line tool is started.
#include "support_assist/pending_restart.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <windows.h>
#include <winevt.h>

#include <memory>

namespace support_assist {
namespace {

constexpr std::size_t kMaxEvents = 40;

std::int64_t unix_millis_from_filetime(const FILETIME& time) {
  ULARGE_INTEGER value{};
  value.LowPart = time.dwLowDateTime;
  value.HighPart = time.dwHighDateTime;
  if (value.QuadPart < 116444736000000000ULL)
    return 0;
  return static_cast<std::int64_t>((value.QuadPart - 116444736000000000ULL) / 10000ULL);
}

// Whether the key exists, and when it was last written.
bool key_time(const wchar_t* path, std::int64_t& written) {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
    return false;
  FILETIME time{};
  if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                       &time) == ERROR_SUCCESS)
    written = unix_millis_from_filetime(time);
  RegCloseKey(key);
  return true;
}

bool value_exists(const wchar_t* path, const wchar_t* name) {
  return RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_ANY, nullptr, nullptr, nullptr) == ERROR_SUCCESS;
}

std::string text_value(const wchar_t* path, const wchar_t* name) {
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_REG_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return {};
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_REG_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return utf8_from_wide(text);
}

std::vector<std::string> multi_text_value(const wchar_t* path, const wchar_t* name) {
  std::vector<std::string> values;
  DWORD size = 0;
  if (RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_REG_MULTI_SZ, nullptr, nullptr, &size) != ERROR_SUCCESS ||
      size < sizeof(wchar_t))
    return values;
  std::wstring text(size / sizeof(wchar_t), L'\0');
  if (RegGetValueW(HKEY_LOCAL_MACHINE, path, name, RRF_RT_REG_MULTI_SZ, nullptr, text.data(), &size) != ERROR_SUCCESS)
    return values;
  // Each entry ends with a NUL and the list with one more. An empty entry (a delete target) is a NUL
  // of its own, so the list's own terminator is the only one to drop.
  std::size_t length = size / sizeof(wchar_t);
  if (length >= 2 && text[length - 1] == L'\0' && text[length - 2] == L'\0')
    --length;
  std::size_t start = 0;
  while (start < length) {
    std::size_t end = text.find(L'\0', start);
    if (end == std::wstring::npos || end > length)
      end = length;
    values.push_back(utf8_from_wide(std::wstring_view(text.data() + start, end - start)));
    start = end + 1;
  }
  return values;
}

struct EventHandle {
  explicit EventHandle(EVT_HANDLE value) : handle(value) {}
  EventHandle(const EventHandle&) = delete;
  EventHandle& operator=(const EventHandle&) = delete;
  ~EventHandle() {
    if (handle != nullptr)
      EvtClose(handle);
  }
  EVT_HANDLE handle;
};

// The XML of the events matching the query in one log, oldest first, at most kMaxEvents.
std::vector<std::string> query_events(const wchar_t* channel, const std::wstring& query) {
  std::vector<std::string> events;
  EventHandle results(EvtQuery(nullptr, channel, query.c_str(), EvtQueryChannelPath | EvtQueryForwardDirection));
  if (results.handle == nullptr)
    return events;
  EVT_HANDLE batch[16] = {};
  DWORD returned = 0;
  while (events.size() < kMaxEvents && EvtNext(results.handle, 16, batch, 2000, 0, &returned) != FALSE) {
    for (DWORD i = 0; i < returned; ++i) {
      EventHandle event(batch[i]);
      if (events.size() >= kMaxEvents)
        continue;
      DWORD used = 0;
      DWORD properties = 0;
      EvtRender(nullptr, event.handle, EvtRenderEventXml, 0, nullptr, &used, &properties);
      if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0)
        continue;
      std::wstring xml(used / sizeof(wchar_t) + 1, L'\0');
      if (EvtRender(nullptr, event.handle, EvtRenderEventXml, static_cast<DWORD>(xml.size() * sizeof(wchar_t)),
                    xml.data(), &used, &properties) != FALSE) {
        xml.resize(wcsnlen(xml.c_str(), xml.size()));
        events.push_back(utf8_from_wide(xml));
      }
    }
  }
  return events;
}

std::string event_time(const std::string& xml) {
  const std::size_t at = xml.find("SystemTime=");
  if (at == std::string::npos || at + 12 >= xml.size())
    return {};
  const char quote = xml[at + 11];
  const std::size_t end = xml.find(quote, at + 12);
  if (end == std::string::npos)
    return {};
  const auto parsed = parse_timestamp(xml.substr(at + 12, end - at - 12), DateOrder::iso_only, 0);
  return parsed ? readable_utc_from_unix_millis(parsed->unix_millis) : std::string();
}

std::wstring since_boot(const wchar_t* filter, std::int64_t boot_unix_millis) {
  const std::string boot = iso8601_from_unix_millis(boot_unix_millis);
  return L"*[System[" + std::wstring(filter) + L" and TimeCreated[@SystemTime>='" + wide_from_utf8(boot) + L"']]]";
}

} // namespace

PendingRestartResult check_pending_restart() {
  PendingRestartResult result;
  result.boot_unix_millis = unix_millis_now() - static_cast<std::int64_t>(GetTickCount64());

  std::int64_t written = 0;
  if (key_time(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending", written)) {
    RestartMarker marker;
    marker.id = "cbs";
    marker.name = "Component Based Servicing\\RebootPending";
    marker.meaning = "Windows servicing (updates, roles or features) needs a restart.";
    marker.restart_needed = true;
    marker.set_unix_millis = written;
    for (const std::string& xml : query_events(L"Setup", since_boot(L"(EventID=4)", result.boot_unix_millis))) {
      const std::string package = restart_detail::event_value(xml, "PackageIdentifier");
      if (!package.empty())
        marker.reasons.push_back(event_time(xml) + ": package " + package + " waits for a restart to reach the " +
                                 restart_detail::event_value(xml, "IntendedPackageStateTextized") + " state (Setup event 4)");
    }
    result.markers.push_back(std::move(marker));
  }

  written = 0;
  if (key_time(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired", written)) {
    RestartMarker marker;
    marker.id = "windows-update";
    marker.name = "WindowsUpdate\\Auto Update\\RebootRequired";
    marker.meaning = "An update Windows Update installed needs a restart.";
    marker.restart_needed = true;
    marker.set_unix_millis = written;
    for (const std::string& xml : query_events(
             L"System", since_boot(L"Provider[@Name='Microsoft-Windows-WindowsUpdateClient'] and (EventID=19)",
                                   result.boot_unix_millis))) {
      const std::string title = restart_detail::event_value(xml, "updateTitle");
      if (!title.empty())
        marker.reasons.push_back(event_time(xml) + ": installed " + title + " (Windows Update event 19)");
    }
    result.markers.push_back(std::move(marker));
  }

  {
    RestartMarker marker;
    marker.id = "msi";
    marker.name = "Windows Installer (MsiInstaller event 1038)";
    marker.meaning = "A Windows Installer package asked for a restart since the last start.";
    marker.restart_needed = true;
    for (const std::string& xml :
         query_events(L"Application", since_boot(L"Provider[@Name='MsiInstaller'] and (EventID=1038)",
                                                 result.boot_unix_millis))) {
      const auto data = restart_detail::event_data(xml);
      if (data.empty())
        continue;
      std::string product = data[0];
      if (data.size() > 1 && !data[1].empty())
        product += " " + data[1];
      if (data.size() > 3 && !data[3].empty())
        product += ", " + data[3];
      marker.reasons.push_back(event_time(xml) + ": " + product);
    }
    if (!marker.reasons.empty())
      result.markers.push_back(std::move(marker));
  }

  const wchar_t* session_manager = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
  auto renames = multi_text_value(session_manager, L"PendingFileRenameOperations");
  const auto renames2 = multi_text_value(session_manager, L"PendingFileRenameOperations2");
  renames.insert(renames.end(), renames2.begin(), renames2.end());
  if (!renames.empty()) {
    RestartMarker marker;
    marker.id = "file-renames";
    marker.name = "Session Manager\\PendingFileRenameOperations";
    marker.meaning = "Files wait to be replaced or deleted at the next start. Browsers and security software set "
                     "this routinely; on its own it is not Windows asking for a restart.";
    written = 0;
    key_time(session_manager, written);
    marker.set_unix_millis = written;
    const auto pairs = restart_detail::rename_pairs(renames);
    for (std::size_t i = 0; i < pairs.size() && i < 12; ++i)
      marker.details.push_back(pairs[i].second.empty() ? "delete " + pairs[i].first
                                                       : pairs[i].first + " -> " + pairs[i].second);
    if (pairs.size() > 12)
      marker.details.push_back(std::to_string(pairs.size() - 12) + " more");
    result.markers.push_back(std::move(marker));
  }

  written = 0;
  if (key_time(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\InProgress", written)) {
    RestartMarker marker;
    marker.id = "installer-in-progress";
    marker.name = "Installer\\InProgress";
    marker.meaning = "A Windows Installer install is running. Another install, a Veeam setup included, fails with "
                     "1618 until it ends.";
    marker.set_unix_millis = written;
    result.markers.push_back(std::move(marker));
  }

  const std::string active_name =
      text_value(L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", L"ComputerName");
  const std::string pending_name =
      text_value(L"SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", L"ComputerName");
  if (!active_name.empty() && !pending_name.empty() && ascii_lower(active_name) != ascii_lower(pending_name)) {
    RestartMarker marker;
    marker.id = "computer-rename";
    marker.name = "Computer name";
    marker.meaning = "A new computer name waits for a restart.";
    marker.restart_needed = true;
    marker.details = {"now " + active_name, "after the restart " + pending_name};
    result.markers.push_back(std::move(marker));
  }

  const wchar_t* netlogon = L"SYSTEM\\CurrentControlSet\\Services\\Netlogon";
  if (value_exists(netlogon, L"JoinDomain") || value_exists(netlogon, L"AvoidSpnSet")) {
    RestartMarker marker;
    marker.id = "domain-join";
    marker.name = "Netlogon JoinDomain";
    marker.meaning = "A domain join waits for a restart.";
    marker.restart_needed = true;
    result.markers.push_back(std::move(marker));
  }

  written = 0;
  if (key_time(L"SOFTWARE\\Microsoft\\ServerManager\\CurrentRebootAttempts", written)) {
    RestartMarker marker;
    marker.id = "server-manager";
    marker.name = "ServerManager\\CurrentRebootAttempts";
    marker.meaning = "A role or feature change waits for a restart.";
    marker.restart_needed = true;
    marker.set_unix_millis = written;
    result.markers.push_back(std::move(marker));
  }

  for (const RestartMarker& marker : result.markers)
    result.restart_needed = result.restart_needed || marker.restart_needed;
  for (RestartMarker& marker : result.markers) {
    if (marker.restart_needed && marker.reasons.empty() && marker.id != "msi")
      marker.reasons.push_back("No event since the last start names the cause.");
  }
  return result;
}

} // namespace support_assist
