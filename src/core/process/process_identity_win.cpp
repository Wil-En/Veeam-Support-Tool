// Windows process identities: the Toolhelp snapshot for names and parents, the image path and start
// time where the account may open the process, and the Service Control Manager for the services
// each process hosts. Read-only throughout.
#include "support_assist/process_identity.hpp"

#include "support_assist/strings.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <map>
#include <memory>

namespace support_assist {
namespace {

std::map<std::uint32_t, std::string> services_by_pid() {
  std::map<std::uint32_t, std::string> result;
  SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
  if (manager == nullptr)
    return result;
  DWORD needed = 0;
  DWORD returned = 0;
  DWORD resume = 0;
  std::vector<BYTE> buffer;
  EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, nullptr, 0, &needed,
                        &returned, &resume, nullptr);
  for (int attempt = 0; attempt < 4 && needed > 0; ++attempt) {
    buffer.resize(needed + 4096U);
    resume = 0;
    if (EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, buffer.data(),
                              static_cast<DWORD>(buffer.size()), &needed, &returned, &resume, nullptr)) {
      const auto* entries = reinterpret_cast<const ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
      for (DWORD i = 0; i < returned; ++i) {
        const std::uint32_t pid = entries[i].ServiceStatusProcess.dwProcessId;
        if (pid == 0)
          continue;
        std::string& names = result[pid];
        if (!names.empty())
          names += ", ";
        names += utf8_from_wide(entries[i].lpServiceName);
      }
      break;
    }
    if (GetLastError() != ERROR_MORE_DATA)
      break;
  }
  CloseServiceHandle(manager);
  return result;
}

std::int64_t unix_millis_from_filetime(const FILETIME& time) {
  ULARGE_INTEGER value{};
  value.LowPart = time.dwLowDateTime;
  value.HighPart = time.dwHighDateTime;
  constexpr std::uint64_t kEpochDifference = 116444736000000000ULL; // 1601 to 1970 in 100 ns
  if (value.QuadPart < kEpochDifference)
    return 0;
  return static_cast<std::int64_t>((value.QuadPart - kEpochDifference) / 10000ULL);
}

} // namespace

ProcessDirectory ProcessDirectory::capture() {
  std::vector<ProcessIdentity> processes;
  const auto services = services_by_pid();
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry)) {
      ProcessIdentity identity;
      identity.pid = entry.th32ProcessID;
      identity.parent_pid = entry.th32ParentProcessID;
      identity.name = utf8_from_wide(entry.szExeFile);
      if (identity.pid == 0)
        identity.name = "System Idle Process";
      if (const auto found = services.find(identity.pid); found != services.end())
        identity.services = found->second;
      if (identity.pid != 0 && identity.pid != 4) {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, identity.pid);
        if (process != nullptr) {
          std::wstring path(32768, L'\0');
          DWORD length = static_cast<DWORD>(path.size());
          if (QueryFullProcessImageNameW(process, 0, path.data(), &length) != FALSE) {
            path.resize(length);
            identity.path = utf8_from_wide(path);
          }
          FILETIME created{};
          FILETIME exited{};
          FILETIME kernel{};
          FILETIME user{};
          if (GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE)
            identity.started_unix_millis = unix_millis_from_filetime(created);
          CloseHandle(process);
        }
      }
      processes.push_back(std::move(identity));
    }
    CloseHandle(snapshot);
  }
  return make_process_directory(std::move(processes));
}

} // namespace support_assist
