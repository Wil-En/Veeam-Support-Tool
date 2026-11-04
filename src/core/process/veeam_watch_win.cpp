// Service and Process Watch on Windows: every Win32 service from the Service Control Manager with
// its state and process, and the process snapshot; both filtered.
#include "support_assist/veeam_watch.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <windows.h>

namespace support_assist {
namespace {

std::string service_state(DWORD state) {
  switch (state) {
  case SERVICE_STOPPED: return "stopped";
  case SERVICE_START_PENDING: return "starting";
  case SERVICE_STOP_PENDING: return "stopping";
  case SERVICE_RUNNING: return "running";
  case SERVICE_CONTINUE_PENDING: return "resuming";
  case SERVICE_PAUSE_PENDING: return "pausing";
  case SERVICE_PAUSED: return "paused";
  default: return "unknown";
  }
}

} // namespace

WatchSnapshot take_watch_snapshot(const std::string& filter) {
  WatchSnapshot snapshot;
  snapshot.taken_unix_millis = unix_millis_now();
  const std::string lowered = ascii_lower(trim(filter));
  const ProcessDirectory processes = ProcessDirectory::capture();

  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr) {
    snapshot.note = "The service list could not be read (error " + std::to_string(GetLastError()) + ").";
  } else {
    DWORD needed = 0;
    DWORD returned = 0;
    DWORD resume = 0;
    std::vector<BYTE> buffer;
    EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &needed,
                          &returned, &resume, nullptr);
    for (int attempt = 0; attempt < 4 && needed > 0; ++attempt) {
      buffer.resize(needed + 8192U);
      resume = 0;
      if (EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(),
                                static_cast<DWORD>(buffer.size()), &needed, &returned, &resume, nullptr) != FALSE) {
        const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
        for (DWORD i = 0; i < returned; ++i) {
          WatchItem item;
          item.kind = WatchKind::service;
          item.name = utf8_from_wide(entries[i].lpServiceName);
          item.display_name = utf8_from_wide(entries[i].lpDisplayName != nullptr ? entries[i].lpDisplayName : L"");
          item.state = service_state(entries[i].ServiceStatusProcess.dwCurrentState);
          item.pid = entries[i].ServiceStatusProcess.dwProcessId;
          if (const ProcessIdentity* identity = item.pid != 0 ? processes.find(item.pid) : nullptr) {
            item.started_unix_millis = identity->started_unix_millis;
            item.path = identity->path;
          }
          if (watch_detail::matches(item, lowered))
            snapshot.items.push_back(std::move(item));
        }
        break;
      }
      if (GetLastError() != ERROR_MORE_DATA)
        break;
    }
    CloseServiceHandle(manager);
  }

  // SAT itself is left out: it often runs from a folder whose name holds "Veeam".
  const DWORD self = GetCurrentProcessId();
  for (const ProcessIdentity& process : processes.all()) {
    WatchItem item;
    item.kind = WatchKind::process;
    item.name = process.name;
    item.state = "running";
    item.pid = process.pid;
    item.started_unix_millis = process.started_unix_millis;
    item.path = process.path;
    if (process.pid != 0 && process.pid != 4 && process.pid != self && watch_detail::matches(item, lowered))
      snapshot.items.push_back(std::move(item));
  }
  watch_detail::add_listening_ports(snapshot);
  return snapshot;
}

} // namespace support_assist
