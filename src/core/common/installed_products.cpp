#include "support_assist/installed_products.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/process.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <iterator>
#include <sstream>
#include <tuple>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace support_assist {

namespace installed_products_detail {

bool is_veeam(std::string_view publisher, std::string_view name) {
  const std::string folded_publisher = ascii_lower(publisher);
  const std::string folded_name = ascii_lower(name);
  return folded_publisher.find("veeam") != std::string::npos || folded_name.rfind("veeam", 0) == 0;
}

std::string install_date_text(std::string_view value) {
  if (value.size() == 8U && std::all_of(value.begin(), value.end(), [](char c) { return c >= '0' && c <= '9'; }))
    return std::string(value.substr(0, 4)) + "-" + std::string(value.substr(4, 2)) + "-" +
           std::string(value.substr(6, 2));
  return std::string(value);
}

std::vector<InstalledProduct> parse_package_lines(std::string_view text) {
  std::vector<InstalledProduct> products;
  std::istringstream input{std::string(text)};
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos || equals == 0U)
      continue;
    InstalledProduct product;
    product.name = trim(line.substr(0, equals));
    product.version = trim(line.substr(equals + 1U));
    if (ascii_lower(product.name).rfind("veeam", 0) == 0)
      products.push_back(std::move(product));
  }
  return products;
}

} // namespace installed_products_detail

namespace {

void sort_products(std::vector<InstalledProduct>& products) {
  std::sort(products.begin(), products.end(), [](const InstalledProduct& left, const InstalledProduct& right) {
    return std::tie(left.name, left.version) < std::tie(right.name, right.version);
  });
  products.erase(std::unique(products.begin(), products.end(),
                             [](const InstalledProduct& left, const InstalledProduct& right) {
                               return left.name == right.name && left.version == right.version;
                             }),
                 products.end());
}

#ifdef _WIN32
std::string registry_text(HKEY key, const wchar_t* value) {
  DWORD type = 0;
  DWORD bytes = 0;
  if (RegQueryValueExW(key, value, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
      (type != REG_SZ && type != REG_EXPAND_SZ) || bytes == 0U)
    return {};
  std::wstring text(bytes / sizeof(wchar_t) + 1U, L'\0');
  if (RegQueryValueExW(key, value, nullptr, nullptr, reinterpret_cast<BYTE*>(text.data()), &bytes) != ERROR_SUCCESS)
    return {};
  text.resize(wcsnlen(text.c_str(), text.size()));
  return utf8_from_wide(text);
}

DWORD registry_number(HKEY key, const wchar_t* value) {
  DWORD number = 0;
  DWORD bytes = sizeof(number);
  DWORD type = 0;
  if (RegQueryValueExW(key, value, nullptr, &type, reinterpret_cast<BYTE*>(&number), &bytes) != ERROR_SUCCESS ||
      type != REG_DWORD)
    return 0;
  return number;
}
#endif

} // namespace

Result<std::vector<InstalledProduct>> installed_veeam_products() {
  std::vector<InstalledProduct> products;
#ifdef _WIN32
  for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
    HKEY uninstall = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", 0,
                      KEY_READ | view, &uninstall) != ERROR_SUCCESS)
      continue;
    for (DWORD index = 0;; ++index) {
      wchar_t subkey[256];
      DWORD length = static_cast<DWORD>(std::size(subkey));
      if (RegEnumKeyExW(uninstall, index, subkey, &length, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
        break;
      HKEY entry = nullptr;
      if (RegOpenKeyExW(uninstall, subkey, 0, KEY_READ | view, &entry) != ERROR_SUCCESS)
        continue;
      InstalledProduct product;
      product.name = registry_text(entry, L"DisplayName");
      product.publisher = registry_text(entry, L"Publisher");
      if (!product.name.empty() && installed_products_detail::is_veeam(product.publisher, product.name)) {
        product.version = registry_text(entry, L"DisplayVersion");
        product.install_date = installed_products_detail::install_date_text(registry_text(entry, L"InstallDate"));
        product.location = registry_text(entry, L"InstallLocation");
        product.hidden = registry_number(entry, L"SystemComponent") == 1U;
        products.push_back(std::move(product));
      }
      RegCloseKey(entry);
    }
    RegCloseKey(uninstall);
  }
#else
  const auto query = [](const char* executable, std::vector<std::string> arguments) -> std::string {
    std::error_code ignored;
    if (!std::filesystem::exists(executable, ignored))
      return {};
    ProcessOptions options;
    options.executable = executable;
    options.arguments = std::move(arguments);
    options.timeout = std::chrono::milliseconds(30000);
    options.merge_standard_error = false;
    CancellationSource never;
    auto ran = run_process_capture(options, never.token());
    return ran.ok() && ran.value().exit_code == 0 ? ran.value().output : std::string();
  };
  std::string listing = query("/usr/bin/dpkg-query", {"-W", "-f=${Package}=${Version}\\n"});
  if (listing.empty())
    listing = query("/usr/bin/rpm", {"-qa", "--qf", "%{NAME}=%{VERSION}-%{RELEASE}\\n"});
  products = installed_products_detail::parse_package_lines(listing);
#endif
  sort_products(products);
  return Result<std::vector<InstalledProduct>>::success(std::move(products));
}

} // namespace support_assist
