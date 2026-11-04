#include "support_assist/local_accounts.hpp"

#include "support_assist/strings.hpp"

#include <cstdlib>
#include <fstream>
#include <unordered_set>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef SECURITY_WIN32
#define SECURITY_WIN32
#endif
#include <windows.h>
#include <dsrole.h>
#include <lm.h>
#include <security.h>
#else
#include <pwd.h>
#include <unistd.h>
#endif

namespace support_assist {

#ifdef _WIN32
namespace {

// On a domain controller NetUserEnum lists the accounts of the whole domain, not local ones.
bool is_domain_controller() {
  PBYTE buffer = nullptr;
  bool controller = false;
  if (DsRoleGetPrimaryDomainInformation(nullptr, DsRolePrimaryDomainInfoBasic, &buffer) == ERROR_SUCCESS &&
      buffer != nullptr) {
    const DSROLE_MACHINE_ROLE role = reinterpret_cast<const DSROLE_PRIMARY_DOMAIN_INFO_BASIC*>(buffer)->MachineRole;
    controller = role == DsRole_RoleBackupDomainController || role == DsRole_RolePrimaryDomainController;
  }
  if (buffer != nullptr)
    DsRoleFreeMemory(buffer);
  return controller;
}

} // namespace
#endif

std::vector<LocalAccount> local_accounts() {
  std::vector<LocalAccount> accounts;
  std::unordered_set<std::string> seen;
  const auto add = [&accounts, &seen](const std::string& name, const char* kind) {
    if (name.empty())
      return;
    if (seen.insert(ascii_lower(name)).second)
      accounts.push_back({name, kind});
  };
#ifdef _WIN32
  wchar_t own[512] = {};
  ULONG own_size = static_cast<ULONG>(std::size(own));
  if (GetUserNameExW(NameSamCompatible, own, &own_size))
    add(utf8_from_wide(own), "this account");

  wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
  DWORD computer_size = static_cast<DWORD>(std::size(computer));
  const std::string machine = GetComputerNameW(computer, &computer_size) ? utf8_from_wide(computer) : std::string();
  // A domain controller has no local user accounts, and its list is the domain's.
  if (!is_domain_controller()) {
    LPBYTE buffer = nullptr;
    DWORD read = 0;
    DWORD total = 0;
    DWORD resume = 0;
    const NET_API_STATUS status =
        NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT, &buffer, MAX_PREFERRED_LENGTH, &read, &total, &resume);
    if ((status == NERR_Success || status == ERROR_MORE_DATA) && buffer != nullptr) {
      const auto* users = reinterpret_cast<const USER_INFO_1*>(buffer);
      for (DWORD index = 0; index < read; ++index) {
        if (users[index].usri1_name == nullptr || (users[index].usri1_flags & UF_ACCOUNTDISABLE) != 0U)
          continue;
        const std::string name = utf8_from_wide(users[index].usri1_name);
        add(machine.empty() ? name : machine + "\\" + name, "local user");
      }
    }
    if (buffer != nullptr)
      NetApiBufferFree(buffer);
  }
  for (const char* service : {"NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\NETWORK SERVICE", "NT AUTHORITY\\LOCAL SERVICE"})
    add(service, "service account");
#else
  if (const passwd* own = getpwuid(geteuid()); own != nullptr && own->pw_name != nullptr)
    add(own->pw_name, "this account");
  add("root", "local user");
  std::ifstream file("/etc/passwd");
  std::string line;
  while (std::getline(file, line)) {
    const auto fields = split(line, ':');
    if (fields.size() < 7U)
      continue;
    const long uid = std::strtol(fields[2].c_str(), nullptr, 10);
    const std::string& shell = fields[6];
    const bool login_shell = shell.find("nologin") == std::string::npos && shell.find("/false") == std::string::npos;
    if ((uid >= 1000 && uid < 60000 && login_shell) || fields[0] == "postgres" || fields[0] == "mssql")
      add(fields[0], fields[0] == "postgres" || fields[0] == "mssql" ? "service account" : "local user");
  }
#endif
  return accounts;
}

} // namespace support_assist
