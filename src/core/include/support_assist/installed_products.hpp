#pragma once

#include "support_assist/error.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// A Veeam product or component installed on this machine, as the operating system records it.
struct InstalledProduct {
  std::string name;
  std::string version;
  std::string install_date; // "2026-08-24", or empty when not recorded
  std::string publisher;
  std::string location;
  bool hidden = false;      // Windows: a component that Programs and Features does not list
};

// Windows: the Uninstall registry, both views, entries whose publisher or name is Veeam's.
// Linux: the package manager (dpkg-query, else rpm), packages whose name starts with veeam.
// Sorted by name, then version.
Result<std::vector<InstalledProduct>> installed_veeam_products();

namespace installed_products_detail {
// "veeam=6.3.0.1234\nlibfoo=1.0" (dpkg-query or rpm output in name=version lines): the veeam ones.
std::vector<InstalledProduct> parse_package_lines(std::string_view text);
// Windows' InstallDate "20260824" as "2026-08-24"; anything else as it is.
std::string install_date_text(std::string_view value);
bool is_veeam(std::string_view publisher, std::string_view name);
} // namespace installed_products_detail

} // namespace support_assist
