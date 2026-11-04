#pragma once

// The accounts of this machine a form can offer: on Windows the account SAT runs as, the local
// user accounts that are enabled (MACHINE\name), none on a domain controller, where the list would
// be the whole domain's, and the built-in service accounts; elsewhere the account SAT runs as, root
// and the accounts with a login shell. Domain accounts are not listed; a field still takes any name
// typed.

#include <string>
#include <vector>

namespace support_assist {

struct LocalAccount {
  std::string name;  // as SQL Server or the operating system writes it, e.g. SPECTR\backup
  std::string kind;  // "this account", "local user", "service account"
};

std::vector<LocalAccount> local_accounts();

} // namespace support_assist
