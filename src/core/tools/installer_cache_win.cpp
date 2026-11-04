// Installer Cache Check: the Windows Installer records of installed products and the cached
// packages Windows keeps for them, read through msi.dll, and an installer's identity and SHA-256.
// Read-only: databases open with MSIDBOPEN_READONLY, registry keys with KEY_READ, and no product is
// opened, installed, repaired or removed. The rows and the matching are shared by every platform;
// the reading is Windows only.
#include "support_assist/installer_cache.hpp"

#include "support_assist/filesystem.hpp"
#include "support_assist/installed_products.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/tool_download.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cwchar>
#include <map>
#include <optional>
#include <set>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <msidefs.h>
#endif

namespace support_assist {

namespace installer_cache_detail {

namespace {

bool is_hex(char character) {
  return std::isxdigit(static_cast<unsigned char>(character)) != 0;
}

std::string reversed(std::string_view text) {
  return std::string(text.rbegin(), text.rend());
}

// The 32 hex digits in order, first three groups reversed and each byte of the rest swapped. The
// transform is its own inverse, so it packs and unpacks.
std::string swap_guid_digits(std::string_view hex) {
  std::string out = reversed(hex.substr(0, 8)) + reversed(hex.substr(8, 4)) + reversed(hex.substr(12, 4));
  for (std::size_t index = 16; index + 1U < 32U; index += 2U) {
    out += hex[index + 1U];
    out += hex[index];
  }
  return out;
}

std::string braced(std::string_view hex) {
  return "{" + std::string(hex.substr(0, 8)) + "-" + std::string(hex.substr(8, 4)) + "-" +
         std::string(hex.substr(12, 4)) + "-" + std::string(hex.substr(16, 4)) + "-" +
         std::string(hex.substr(20, 12)) + "}";
}

int match_rank(InstallerMatch match) {
  return static_cast<int>(match);
}

} // namespace

std::string normalize_guid(std::string_view text) {
  std::string value = trim(text);
  if (value.size() == 38U && value.front() == '{' && value.back() == '}')
    value = value.substr(1, 36);
  if (value.size() != 36U)
    return {};
  for (std::size_t index = 0; index < value.size(); ++index) {
    const bool dash = index == 8U || index == 13U || index == 18U || index == 23U;
    if (dash ? value[index] != '-' : !is_hex(value[index]))
      return {};
  }
  return "{" + ascii_upper(value) + "}";
}

std::string pack_guid(std::string_view guid) {
  const std::string normalized = normalize_guid(guid);
  if (normalized.empty())
    return {};
  std::string hex;
  for (const char character : normalized) {
    if (character != '{' && character != '}' && character != '-')
      hex += character;
  }
  return swap_guid_digits(hex);
}

std::string unpack_guid(std::string_view packed) {
  const std::string value = ascii_upper(trim(packed));
  if (value.size() != 32U || !std::all_of(value.begin(), value.end(), is_hex))
    return {};
  return braced(swap_guid_digits(value));
}

std::string last_used_source_text(std::string_view raw) {
  const std::string value = trim(raw);
  // "<n|u|m>;<index>;<source>": a folder or network path, a URL, or media.
  if (value.size() > 4U && (value[0] == 'n' || value[0] == 'u' || value[0] == 'm') && value[1] == ';') {
    const std::size_t second = value.find(';', 2);
    if (second != std::string::npos && second > 2U &&
        std::all_of(value.begin() + 2, value.begin() + static_cast<std::ptrdiff_t>(second),
                    [](char character) { return character >= '0' && character <= '9'; }))
      return value.substr(second + 1U);
  }
  return value;
}

std::string display_icon_path(std::string_view raw) {
  std::string value = trim(raw);
  if (!value.empty() && value.front() == '"') {
    const std::size_t close = value.find('"', 1);
    return close == std::string::npos ? value.substr(1) : value.substr(1, close - 1U);
  }
  const std::size_t comma = value.rfind(',');
  if (comma != std::string::npos) {
    std::string index = trim(std::string_view(value).substr(comma + 1U));
    if (!index.empty() && index.front() == '-')
      index.erase(0, 1);
    if (!index.empty() && std::all_of(index.begin(), index.end(), [](char c) { return c >= '0' && c <= '9'; }))
      value = trim(std::string_view(value).substr(0, comma));
  }
  return value;
}

bool versions_agree(std::string_view left, std::string_view right) {
  const std::vector<std::string> a = split(trim(left), '.');
  const std::vector<std::string> b = split(trim(right), '.');
  if (trim(left).empty() || trim(right).empty())
    return false;
  const auto numeric = [](const std::string& part) {
    return !part.empty() && std::all_of(part.begin(), part.end(), [](char c) { return c >= '0' && c <= '9'; });
  };
  const auto without_zeros = [](const std::string& part) {
    const std::size_t first = part.find_first_not_of('0');
    return first == std::string::npos ? std::string("0") : part.substr(first);
  };
  const std::size_t count = std::max(a.size(), b.size());
  for (std::size_t index = 0; index < count; ++index) {
    const std::string x = index < a.size() ? trim(a[index]) : std::string("0");
    const std::string y = index < b.size() ? trim(b[index]) : std::string("0");
    if (numeric(x) && numeric(y)) {
      if (without_zeros(x) != without_zeros(y))
        return false;
    } else if (ascii_lower(x) != ascii_lower(y)) {
      return false;
    }
  }
  return true;
}

bool name_matches(std::string_view filter, std::string_view name) {
  const std::string wanted = ascii_lower(trim(filter));
  return wanted.empty() || ascii_lower(name).find(wanted) != std::string::npos;
}

bool program_names_product(std::string_view program_product, std::string_view product_name) {
  const auto folded = [](std::string_view text) {
    std::string out;
    for (const char character : text) {
      if (character != ' ')
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
    }
    return out;
  };
  const std::string program = folded(program_product);
  const std::string product = folded(product_name);
  if (program.empty() || product.empty())
    return false;
  return program.find(product) != std::string::npos || product.find(program) != std::string::npos;
}

InstallerMatch classify_installer(std::string_view package_code, std::string_view product_code,
                                  std::string_view upgrade_code, const InstallerCacheProduct& product) {
  const auto same = [](std::string_view left, std::string_view right) {
    const std::string normalized = normalize_guid(left);
    return !normalized.empty() && normalized == normalize_guid(right);
  };
  if (same(package_code, product.package_code))
    return InstallerMatch::package_code;
  if (same(product_code, product.product_code))
    return InstallerMatch::product_code;
  if (same(upgrade_code, product.upgrade_code))
    return InstallerMatch::upgrade_code;
  return InstallerMatch::none;
}

std::pair<InstallerMatch, std::size_t> best_installer_match(std::string_view package_code,
                                                            std::string_view product_code,
                                                            std::string_view upgrade_code,
                                                            const std::vector<InstallerCacheProduct>& products) {
  std::pair<InstallerMatch, std::size_t> best{InstallerMatch::none, 0};
  for (std::size_t index = 0; index < products.size(); ++index) {
    const InstallerMatch match = classify_installer(package_code, product_code, upgrade_code, products[index]);
    if (match_rank(match) > match_rank(best.first))
      best = {match, index};
  }
  return best;
}

std::string patch_state_text(std::string_view state) {
  const std::string value = trim(state);
  if (value == "1")
    return "Applied";
  if (value == "2")
    return "Superseded";
  if (value == "4")
    return "Obsoleted";
  if (value == "8")
    return "Registered";
  return value;
}

} // namespace installer_cache_detail

namespace {

using installer_cache_detail::versions_agree;

std::string product_label(const InstallerCacheProduct& product) {
  std::string label = product.name.empty() ? product.product_code : product.name;
  if (!product.version.empty() && label.find(product.version) == std::string::npos)
    label += " " + product.version;
  return label;
}

std::string or_not_recorded(const std::string& value) {
  return value.empty() ? std::string("Not recorded") : value;
}

bool product_cache_missing(const InstallerCacheProduct& product) {
  return !product.local_package_exists;
}

Error installer_error(std::string operation, std::string message, std::int64_t code = 0) {
  Error error;
  error.component = "Installer Cache Check";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.native_code = code;
  return error;
}

} // namespace

bool installer_cache_has_missing(const InstallerCacheResult& result) {
  for (const InstallerCacheProduct& product : result.products) {
    if (product_cache_missing(product))
      return true;
    for (const InstallerCachePatch& patch : product.patches) {
      if (!patch.local_package_exists)
        return true;
    }
  }
  return false;
}

std::string installer_cache_summary(const InstallerCacheResult& result) {
  std::size_t missing = 0;
  for (const InstallerCacheProduct& product : result.products) {
    if (product_cache_missing(product))
      ++missing;
    for (const InstallerCachePatch& patch : product.patches) {
      if (!patch.local_package_exists)
        ++missing;
    }
  }
  std::string text = std::to_string(result.products.size()) +
                     (result.products.size() == 1U ? " product found" : " products found");
  if (!result.products.empty())
    text += missing == 0U ? "; every cached package is present"
                          : "; " + std::to_string(missing) + (missing == 1U ? " cached package is missing"
                                                                             : " cached packages are missing");
  const auto package = std::find_if(result.candidates.begin(), result.candidates.end(), [&](const InstallerCandidate& c) {
    return c.match == InstallerMatch::package_code && c.matched_product < result.products.size();
  });
  const bool any_msi = std::any_of(result.candidates.begin(), result.candidates.end(),
                                   [](const InstallerCandidate& c) { return c.kind == "msi" && c.error.empty(); });
  const auto same_version = std::find_if(result.candidates.begin(), result.candidates.end(), [&](const InstallerCandidate& c) {
    return c.version_matches_product && c.matched_product < result.products.size();
  });
  if (package != result.candidates.end())
    text += "; " + path_to_utf8(package->path.filename()) + " is the package " +
            product_label(result.products[package->matched_product]) + " was installed from";
  else if (any_msi)
    text += "; no .msi checked has the PackageCode of a listed product";
  else if (same_version != result.candidates.end())
    text += "; " + path_to_utf8(same_version->path.filename()) + " has the version of " +
            product_label(result.products[same_version->matched_product]);
  return text;
}

std::vector<InstallerCacheRow> installer_cache_rows(const InstallerCacheResult& result) {
  std::vector<InstallerCacheRow> rows;
  const std::string machine = "This machine";
  rows.push_back({machine, "Installer cache folder",
                  result.installer_folder + ": " + std::to_string(result.cached_msi_files) + " .msi and " +
                      std::to_string(result.cached_msp_files) + " .msp files",
                  result.installer_folder_exists ? "PRESENT" : "MISSING"});
  rows.push_back({machine, "Searched for", result.searched,
                  result.products.empty() ? std::string("NONE FOUND") : std::to_string(result.products.size()) + " FOUND"});
  for (const std::string& note : result.notes)
    rows.push_back({machine, "Note", note, "NOTE"});

  for (const InstallerCacheProduct& product : result.products) {
    const std::string label = product_label(product);
    if (!product.found_by.empty())
      rows.push_back({label, "Found", product.found_by, "NOTE"});
    rows.push_back({label, "ProductCode", product.product_code, ""});
    rows.push_back({label, "UpgradeCode", or_not_recorded(product.upgrade_code), ""});
    rows.push_back({label, "Version", or_not_recorded(product.version), ""});
    if (!product.listed_name.empty() || !product.listed_version.empty()) {
      std::string listed = product.listed_name;
      if (!product.listed_version.empty())
        listed += (listed.empty() ? "" : " ") + product.listed_version;
      std::string state;
      if (!product.listed_version.empty() && !product.version.empty())
        state = versions_agree(product.listed_version, product.version) ? "SAME VERSION" : "DIFFERENT VERSION";
      rows.push_back({label, "Programs and Features", std::move(listed), std::move(state)});
    }
    rows.push_back({label, "Installed on", or_not_recorded(product.install_date), ""});
    if (!product.context.empty())
      rows.push_back({label, "Installed for", product.context, ""});
    rows.push_back({label, "Original package", or_not_recorded(product.package_name), ""});
    rows.push_back({label, "PackageCode", or_not_recorded(product.package_code), ""});
    rows.push_back({label, "Last used source", or_not_recorded(product.last_used_source), ""});
    rows.push_back({label, "Install location", or_not_recorded(product.install_location), ""});
    rows.push_back({label, "Cached package", or_not_recorded(product.local_package),
                    product.local_package.empty() ? "NOT RECORDED"
                                                  : (product.local_package_exists ? "PRESENT" : "MISSING")});
    for (const auto& [key_label, key_path] : product.registry_keys)
      rows.push_back({label, key_label, key_path, ""});
    if (product.patches.empty())
      rows.push_back({label, "Patches", "None applied", ""});
    for (const InstallerCachePatch& patch : product.patches) {
      std::string value = or_not_recorded(patch.local_package) + " (" + patch.patch_code;
      if (!patch.state.empty())
        value += ", " + patch.state;
      value += ")";
      rows.push_back({label, "Patch " + (patch.name.empty() ? patch.patch_code : patch.name), std::move(value),
                      patch.local_package.empty() ? "NOT RECORDED" : (patch.local_package_exists ? "PRESENT" : "MISSING")});
    }
    if (!product.main_program.empty()) {
      std::string value = product.main_program;
      if (!product.main_program_version.empty())
        value += ", version " + product.main_program_version;
      std::string state;
      if (!product.main_program_version.empty() && !product.version.empty())
        state = versions_agree(product.main_program_version, product.version) ? "SAME VERSION" : "DIFFERENT VERSION";
      rows.push_back({label, "Main program", std::move(value), std::move(state)});
    }
    if (!product.from_registry.empty()) {
      std::string names;
      for (const std::string& name : product.from_registry)
        names += (names.empty() ? "" : ", ") + name;
      rows.push_back({label, "Read from the registry", names, "NOTE"});
    }
  }

  const std::string checked = "Installer checked";
  if (result.checked_kind == "missing")
    rows.push_back({checked, "Path", result.checked_path, "NOT FOUND"});
  if (result.checked_kind == "folder") {
    rows.push_back({checked, "Folder",
                    result.checked_path + ": " + std::to_string(result.folder_msi_found) +
                        (result.folder_msi_found == 1U ? " .msi file" : " .msi files") +
                        " in it and the four folder levels below it",
                    result.folder_msi_found == 0U ? "NONE FOUND" : ""});
    if (result.folder_limit_reached)
      rows.push_back({checked, "Folder", "Only the first " + std::to_string(result.candidates.size()) +
                                             " .msi files were read",
                      "NOTE"});
  }
  for (const InstallerCandidate& candidate : result.candidates) {
    const std::string file = path_to_utf8(candidate.path.filename());
    const InstallerCacheProduct* matched =
        candidate.matched_product < result.products.size() ? &result.products[candidate.matched_product] : nullptr;
    rows.push_back({file, "Path", path_to_utf8(candidate.path), ""});
    rows.push_back({file, "SHA-256", candidate.sha256.empty() ? "Not read: " + candidate.sha256_error : candidate.sha256,
                    candidate.sha256.empty() ? "FAILED" : ""});
    if (!candidate.error.empty()) {
      rows.push_back({file, "Read", candidate.error, "FAILED"});
      continue;
    }
    if (candidate.kind == "msi") {
      std::string product = candidate.product_name;
      if (!candidate.product_version.empty())
        product += (product.empty() ? "" : " ") + candidate.product_version;
      rows.push_back({file, "Product", or_not_recorded(product), ""});
      rows.push_back({file, "PackageCode", or_not_recorded(candidate.package_code), ""});
      rows.push_back({file, "ProductCode", or_not_recorded(candidate.product_code), ""});
      rows.push_back({file, "UpgradeCode", or_not_recorded(candidate.upgrade_code), ""});
      switch (matched == nullptr ? InstallerMatch::none : candidate.match) {
      case InstallerMatch::package_code:
        rows.push_back({file, "Match", "The package " + product_label(*matched) +
                                           " was installed from: the same PackageCode. This is the installer it needs.",
                        "MATCH"});
        break;
      case InstallerMatch::product_code:
        rows.push_back({file, "Match", "The same ProductCode as " + product_label(*matched) +
                                           " with another PackageCode: a different build of its package.",
                        "DIFFERENT BUILD"});
        break;
      case InstallerMatch::upgrade_code:
        rows.push_back({file, "Match", "The same UpgradeCode as " + product_label(*matched) +
                                           ": the same product in a different version or build.",
                        "DIFFERENT BUILD"});
        break;
      case InstallerMatch::none:
        rows.push_back({file, "Match", "No listed product has its PackageCode, ProductCode or UpgradeCode.",
                        "NO MATCH"});
        break;
      }
      if (matched == nullptr || candidate.match == InstallerMatch::none) {
        rows.push_back({file, "Installed", "No product with its ProductCode or UpgradeCode is installed.",
                        "NOT INSTALLED"});
      } else {
        const std::string installed = matched->version.empty() ? std::string("version not recorded")
                                                               : "version " + matched->version;
        std::string value = (candidate.match == InstallerMatch::upgrade_code ? "Another version of its product: "
                                                                             : "Its product: ") +
                            (matched->name.empty() ? matched->product_code : matched->name) + ", " + installed;
        std::string state;
        if (!candidate.product_version.empty() && !matched->version.empty()) {
          const bool same = versions_agree(candidate.product_version, matched->version);
          value += same ? ", the version of this package." : "; this package is version " + candidate.product_version + ".";
          state = same ? "SAME VERSION" : "DIFFERENT VERSION";
        } else {
          value += ".";
        }
        rows.push_back({file, "Installed", std::move(value), std::move(state)});
      }
      continue;
    }
    rows.push_back({file, "File version", or_not_recorded(candidate.file_version), ""});
    if (!candidate.file_product_name.empty())
      rows.push_back({file, "Product", candidate.file_product_name, ""});
    if (candidate.signature_trusted)
      rows.push_back({file, "Signed by", or_not_recorded(candidate.signer), "SIGNED"});
    else
      rows.push_back({file, "Signed by", candidate.signature_note.empty() ? std::string("Not signed") : candidate.signature_note,
                      "NOT VERIFIED"});
    if (candidate.signature_trusted && !candidate.signature_note.empty())
      rows.push_back({file, "Signature", candidate.signature_note, "NOTE"});
    if (candidate.version_matches_product && matched != nullptr)
      rows.push_back({file, "Version", "The version of " + product_label(*matched), "SAME VERSION"});
    else if (!result.products.empty())
      rows.push_back({file, "Version", "No listed product has this version", ""});
    rows.push_back({file, "Contents",
                    "An .exe installer carries its MSI packages inside it. The PackageCode Windows asks for is in "
                    "those .msi files, such as the ones on the product's ISO.",
                    "NOTE"});
  }
  return rows;
}

std::vector<InstallerCacheRow> installer_cache_table_rows(const InstallerCacheResult& result) {
  std::vector<InstallerCacheRow> rows;
  std::string current;
  bool first = true;
  for (InstallerCacheRow& row : installer_cache_rows(result)) {
    if (first || row.product != current) {
      current = row.product;
      first = false;
      rows.push_back({current, "", "", ""});
    }
    row.product.clear();
    rows.push_back(std::move(row));
  }
  return rows;
}

#ifdef _WIN32

namespace {

using installer_cache_detail::normalize_guid;
using installer_cache_detail::pack_guid;
using installer_cache_detail::unpack_guid;

constexpr wchar_t kUserDataProducts[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products\\";
constexpr wchar_t kUserDataPatches[] =
    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Patches\\";
constexpr wchar_t kClassesProducts[] = L"SOFTWARE\\Classes\\Installer\\Products\\";
constexpr wchar_t kClassesUpgradeCodes[] = L"SOFTWARE\\Classes\\Installer\\UpgradeCodes";
constexpr wchar_t kUninstall[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";

std::string system_text(DWORD code) {
  wchar_t* buffer = nullptr;
  const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                          FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
  std::string text;
  if (length != 0U && buffer != nullptr)
    text = trim(utf8_from_wide(std::wstring_view(buffer, length)));
  if (buffer != nullptr)
    LocalFree(buffer);
  if (text.empty())
    text = "Windows error";
  return text + " (" + std::to_string(code) + ")";
}

class RegistryKey {
public:
  RegistryKey(const std::wstring& path, REGSAM view = KEY_WOW64_64KEY) {
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ | view, &key_) != ERROR_SUCCESS)
      key_ = nullptr;
  }
  ~RegistryKey() {
    if (key_ != nullptr)
      RegCloseKey(key_);
  }
  RegistryKey(const RegistryKey&) = delete;
  RegistryKey& operator=(const RegistryKey&) = delete;
  explicit operator bool() const noexcept { return key_ != nullptr; }

  std::string text(const wchar_t* name) const {
    if (key_ == nullptr)
      return {};
    DWORD type = 0;
    DWORD bytes = 0;
    if (RegQueryValueExW(key_, name, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS || bytes == 0U)
      return {};
    if (type == REG_DWORD) {
      DWORD number = 0;
      DWORD size = sizeof(number);
      if (RegQueryValueExW(key_, name, nullptr, nullptr, reinterpret_cast<BYTE*>(&number), &size) != ERROR_SUCCESS)
        return {};
      return std::to_string(number);
    }
    if (type != REG_SZ && type != REG_EXPAND_SZ)
      return {};
    std::wstring value(bytes / sizeof(wchar_t) + 1U, L'\0');
    if (RegQueryValueExW(key_, name, nullptr, nullptr, reinterpret_cast<BYTE*>(value.data()), &bytes) != ERROR_SUCCESS)
      return {};
    value.resize(wcsnlen(value.c_str(), value.size()));
    return trim(utf8_from_wide(value));
  }

  std::vector<std::wstring> subkeys() const {
    std::vector<std::wstring> names;
    if (key_ == nullptr)
      return names;
    for (DWORD index = 0;; ++index) {
      wchar_t name[256]{};
      DWORD length = 256;
      const LONG status = RegEnumKeyExW(key_, index, name, &length, nullptr, nullptr, nullptr, nullptr);
      if (status != ERROR_SUCCESS)
        break;
      names.emplace_back(name, length);
    }
    return names;
  }

  std::vector<std::wstring> value_names() const {
    std::vector<std::wstring> names;
    if (key_ == nullptr)
      return names;
    for (DWORD index = 0;; ++index) {
      wchar_t name[256]{};
      DWORD length = 256;
      const LONG status = RegEnumValueW(key_, index, name, &length, nullptr, nullptr, nullptr, nullptr);
      if (status == ERROR_NO_MORE_ITEMS)
        break;
      if (status == ERROR_SUCCESS)
        names.emplace_back(name, length);
      else if (status != ERROR_MORE_DATA)
        break;
    }
    return names;
  }

private:
  HKEY key_ = nullptr;
};

// A value from an MSI call that takes a buffer and its size in characters: asked for its size first.
template <typename Read>
std::string msi_text(Read read) {
  DWORD size = 0;
  UINT status = read(nullptr, &size);
  if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA)
    return {};
  std::wstring buffer(static_cast<std::size_t>(size) + 1U, L'\0');
  DWORD capacity = size + 1U;
  status = read(buffer.data(), &capacity);
  if (status == ERROR_MORE_DATA) {
    buffer.assign(static_cast<std::size_t>(capacity) + 1U, L'\0');
    capacity += 1U;
    status = read(buffer.data(), &capacity);
  }
  if (status != ERROR_SUCCESS)
    return {};
  buffer.resize(wcsnlen(buffer.c_str(), buffer.size()));
  return trim(utf8_from_wide(buffer));
}

std::string product_info(const std::wstring& code, MSIINSTALLCONTEXT context, const wchar_t* property) {
  return msi_text([&](LPWSTR buffer, LPDWORD size) {
    return MsiGetProductInfoExW(code.c_str(), nullptr, context, property, buffer, size);
  });
}

std::string patch_info(const std::wstring& patch, const std::wstring& product, MSIINSTALLCONTEXT context,
                       const wchar_t* property) {
  return msi_text([&](LPWSTR buffer, LPDWORD size) {
    return MsiGetPatchInfoExW(patch.c_str(), product.c_str(), nullptr, context, property, buffer, size);
  });
}

bool file_present(const std::string& path) {
  if (path.empty())
    return false;
  std::error_code error;
  return std::filesystem::is_regular_file(path_from_utf8(path), error);
}

// The file version from a program's version resource, and its ProductName string.
std::string file_version(const std::filesystem::path& path, std::string* product_name = nullptr) {
  DWORD ignored = 0;
  const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
  if (size == 0U)
    return {};
  std::vector<unsigned char> data(size);
  if (GetFileVersionInfoW(path.c_str(), 0, size, data.data()) == FALSE)
    return {};
  std::string version;
  VS_FIXEDFILEINFO* info = nullptr;
  UINT info_size = 0;
  if (VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&info), &info_size) != FALSE && info != nullptr &&
      info_size >= sizeof(VS_FIXEDFILEINFO))
    version = std::to_string(HIWORD(info->dwFileVersionMS)) + "." + std::to_string(LOWORD(info->dwFileVersionMS)) +
              "." + std::to_string(HIWORD(info->dwFileVersionLS)) + "." + std::to_string(LOWORD(info->dwFileVersionLS));
  if (product_name != nullptr) {
    struct Translation {
      WORD language;
      WORD code_page;
    };
    Translation* translations = nullptr;
    UINT translations_size = 0;
    if (VerQueryValueW(data.data(), L"\\VarFileInfo\\Translation", reinterpret_cast<void**>(&translations),
                       &translations_size) != FALSE &&
        translations != nullptr && translations_size >= sizeof(Translation)) {
      wchar_t query[64]{};
      swprintf_s(query, L"\\StringFileInfo\\%04x%04x\\ProductName", translations[0].language,
                 translations[0].code_page);
      wchar_t* text = nullptr;
      UINT text_size = 0;
      if (VerQueryValueW(data.data(), query, reinterpret_cast<void**>(&text), &text_size) != FALSE &&
          text != nullptr && text_size > 0U)
        *product_name = trim(utf8_from_wide(std::wstring_view(text, wcsnlen(text, text_size))));
    }
  }
  return version;
}

struct ProductKey {
  std::wstring code;
  MSIINSTALLCONTEXT context = MSIINSTALLCONTEXT_MACHINE;
  std::string found_by;
  std::string upgrade_code;  // known when the product was found by its UpgradeCode
};

std::string context_text(MSIINSTALLCONTEXT context) {
  switch (context) {
  case MSIINSTALLCONTEXT_MACHINE: return "Per machine";
  case MSIINSTALLCONTEXT_USERMANAGED: return "Per user (managed)";
  case MSIINSTALLCONTEXT_USERUNMANAGED: return "Per user";
  default: return {};
  }
}

// The context a product is installed in, for a code found without one; none when not installed.
std::optional<MSIINSTALLCONTEXT> product_context(const std::wstring& code) {
  for (const MSIINSTALLCONTEXT context :
       {MSIINSTALLCONTEXT_MACHINE, MSIINSTALLCONTEXT_USERMANAGED, MSIINSTALLCONTEXT_USERUNMANAGED}) {
    if (!product_info(code, context, L"State").empty())
      return context;
  }
  return std::nullopt;
}

// Product codes by UpgradeCode, through MsiEnumRelatedProducts; the UpgradeCodes key when the API
// returns none.
std::vector<std::wstring> related_product_codes(const std::string& upgrade_code, bool& from_registry) {
  std::vector<std::wstring> codes;
  from_registry = false;
  const std::wstring upgrade = wide_from_utf8(upgrade_code);
  for (DWORD index = 0;; ++index) {
    wchar_t code[39]{};
    if (MsiEnumRelatedProductsW(upgrade.c_str(), 0, index, code) != ERROR_SUCCESS)
      break;
    codes.emplace_back(code);
  }
  if (!codes.empty())
    return codes;
  const std::string packed = pack_guid(upgrade_code);
  if (packed.empty())
    return codes;
  const RegistryKey key(std::wstring(kClassesUpgradeCodes) + L"\\" + wide_from_utf8(packed));
  for (const std::wstring& name : key.value_names()) {
    const std::string code = unpack_guid(utf8_from_wide(name));
    if (!code.empty())
      codes.push_back(wide_from_utf8(code));
  }
  from_registry = !codes.empty();
  return codes;
}

// Packed product code to UpgradeCode, from the UpgradeCodes key: the API gives no UpgradeCode for a
// product.
std::map<std::string, std::string> upgrade_codes_by_product() {
  std::map<std::string, std::string> found;
  const RegistryKey root(kClassesUpgradeCodes);
  for (const std::wstring& packed_upgrade : root.subkeys()) {
    const std::string upgrade = unpack_guid(utf8_from_wide(packed_upgrade));
    if (upgrade.empty())
      continue;
    const RegistryKey key(std::wstring(kClassesUpgradeCodes) + L"\\" + packed_upgrade);
    for (const std::wstring& product : key.value_names())
      found.emplace(ascii_upper(utf8_from_wide(product)), upgrade);
  }
  return found;
}

std::vector<InstallerCachePatch> read_patches(const std::wstring& product_code, MSIINSTALLCONTEXT context) {
  std::vector<InstallerCachePatch> patches;
  for (DWORD index = 0;; ++index) {
    wchar_t patch[39]{};
    wchar_t target[39]{};
    MSIINSTALLCONTEXT target_context = MSIINSTALLCONTEXT_NONE;
    if (MsiEnumPatchesExW(product_code.c_str(), nullptr, context, MSIPATCHSTATE_ALL, index, patch, target,
                          &target_context, nullptr, nullptr) != ERROR_SUCCESS)
      break;
    InstallerCachePatch item;
    item.patch_code = normalize_guid(utf8_from_wide(patch));
    item.name = patch_info(patch, product_code, context, L"DisplayName");
    item.state = installer_cache_detail::patch_state_text(patch_info(patch, product_code, context, L"State"));
    item.local_package = patch_info(patch, product_code, context, L"LocalPackage");
    if (item.local_package.empty() && context == MSIINSTALLCONTEXT_MACHINE) {
      const RegistryKey key(std::wstring(kUserDataPatches) + wide_from_utf8(pack_guid(item.patch_code)));
      item.local_package = key.text(L"LocalPackage");
    }
    item.local_package_exists = file_present(item.local_package);
    patches.push_back(std::move(item));
  }
  if (!patches.empty() || context != MSIINSTALLCONTEXT_MACHINE)
    return patches;
  // The API listed none: the patches the machine's Installer keys record for the product.
  const std::string packed_product = pack_guid(utf8_from_wide(product_code));
  const std::wstring product_patches = std::wstring(kUserDataProducts) + wide_from_utf8(packed_product) + L"\\Patches";
  const RegistryKey list(product_patches);
  for (const std::wstring& packed_patch : list.subkeys()) {
    InstallerCachePatch item;
    item.patch_code = unpack_guid(utf8_from_wide(packed_patch));
    if (item.patch_code.empty())
      continue;
    const RegistryKey detail(product_patches + L"\\" + packed_patch);
    item.name = detail.text(L"DisplayName");
    item.state = installer_cache_detail::patch_state_text(detail.text(L"State")) + " (registry)";
    const RegistryKey cached(std::wstring(kUserDataPatches) + packed_patch);
    item.local_package = cached.text(L"LocalPackage");
    item.local_package_exists = file_present(item.local_package);
    patches.push_back(std::move(item));
  }
  return patches;
}

// The program the Uninstall entry names as its icon, else the largest program in the install folder.
void read_main_program(InstallerCacheProduct& product) {
  const std::wstring uninstall = std::wstring(kUninstall) + wide_from_utf8(product.product_code);
  for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
    const RegistryKey key(uninstall, view);
    const std::string icon = installer_cache_detail::display_icon_path(key.text(L"DisplayIcon"));
    if (!icon.empty() && ascii_lower(path_to_utf8(path_from_utf8(icon).extension())) == ".exe" && file_present(icon)) {
      product.main_program = icon;
      break;
    }
  }
  // Several products can share an install folder (a component installed into the server's folder),
  // so a program found there is the product's only when its version resource names the product.
  if (product.main_program.empty() && !product.install_location.empty() && !product.name.empty()) {
    std::error_code error;
    std::filesystem::directory_iterator entries(path_from_utf8(product.install_location), error);
    std::uintmax_t largest = 0;
    for (; !error && entries != std::filesystem::directory_iterator(); entries.increment(error)) {
      const std::filesystem::path& file = entries->path();
      if (ascii_lower(path_to_utf8(file.extension())) != ".exe")
        continue;
      std::error_code size_error;
      const std::uintmax_t size = std::filesystem::file_size(file, size_error);
      if (size_error || size <= largest)
        continue;
      std::string program_product;
      static_cast<void>(file_version(file, &program_product));
      if (!installer_cache_detail::program_names_product(program_product, product.name))
        continue;
      largest = size;
      product.main_program = path_to_utf8(file);
    }
  }
  if (!product.main_program.empty())
    product.main_program_version = file_version(path_from_utf8(product.main_program));
}

// Programs and Features: the DisplayName and DisplayVersion of the product's own Uninstall entry,
// both from the same entry.
void read_listed_entry(InstallerCacheProduct& product) {
  const std::wstring uninstall = std::wstring(kUninstall) + wide_from_utf8(product.product_code);
  for (const REGSAM view : {KEY_WOW64_64KEY, KEY_WOW64_32KEY}) {
    const RegistryKey key(uninstall, view);
    const std::string name = key.text(L"DisplayName");
    const std::string version = key.text(L"DisplayVersion");
    if (name.empty() && version.empty())
      continue;
    product.listed_name = name;
    product.listed_version = version;
    product.registry_keys.push_back(
        {"Uninstall key", std::string(view == KEY_WOW64_32KEY ? "HKLM\\SOFTWARE\\WOW6432Node" : "HKLM\\SOFTWARE") +
                               "\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + product.product_code});
    return;
  }
}

// The Windows Installer keys that hold the product, the ones present on this machine.
void read_installer_keys(InstallerCacheProduct& product) {
  const std::string packed = pack_guid(product.product_code);
  if (packed.empty())
    return;
  const auto note = [&product](const char* label, const std::wstring& path) {
    if (RegistryKey(path))
      product.registry_keys.push_back({label, "HKLM\\" + utf8_from_wide(path)});
  };
  note("Installer product key", std::wstring(kClassesProducts) + wide_from_utf8(packed));
  note("Install properties key", std::wstring(kUserDataProducts) + wide_from_utf8(packed) + L"\\InstallProperties");
  const std::string packed_upgrade = pack_guid(product.upgrade_code);
  if (!packed_upgrade.empty())
    note("Upgrade code key", std::wstring(kClassesUpgradeCodes) + L"\\" + wide_from_utf8(packed_upgrade));
}

InstallerCacheProduct read_product(const ProductKey& key) {
  InstallerCacheProduct product;
  product.product_code = normalize_guid(utf8_from_wide(key.code));
  product.context = context_text(key.context);
  product.found_by = key.found_by;
  const auto info = [&](const wchar_t* property) { return product_info(key.code, key.context, property); };
  product.name = info(L"InstalledProductName");
  if (product.name.empty())
    product.name = info(L"ProductName");
  product.version = info(L"VersionString");
  product.install_date = installed_products_detail::install_date_text(info(L"InstallDate"));
  product.package_name = info(L"PackageName");
  product.package_code = info(L"PackageCode");
  if (!product.package_code.empty() && normalize_guid(product.package_code).empty())
    product.package_code = unpack_guid(product.package_code);
  else
    product.package_code = normalize_guid(product.package_code);
  product.last_used_source = installer_cache_detail::last_used_source_text(info(L"LastUsedSource"));
  product.local_package = info(L"LocalPackage");
  product.install_location = info(L"InstallLocation");

  // The machine's Installer keys, for a value the API returned nothing for.
  if (key.context == MSIINSTALLCONTEXT_MACHINE) {
    const std::wstring packed = wide_from_utf8(pack_guid(product.product_code));
    const RegistryKey properties(std::wstring(kUserDataProducts) + packed + L"\\InstallProperties");
    const RegistryKey classes(std::wstring(kClassesProducts) + packed);
    const RegistryKey sources(std::wstring(kClassesProducts) + packed + L"\\SourceList");
    const auto fill = [&](std::string& field, const char* label, const RegistryKey& from, const wchar_t* name) {
      if (!field.empty())
        return;
      field = from.text(name);
      if (!field.empty())
        product.from_registry.emplace_back(label);
    };
    fill(product.name, "Name", properties, L"DisplayName");
    fill(product.name, "Name", classes, L"ProductName");
    fill(product.version, "Version", properties, L"DisplayVersion");
    fill(product.install_date, "Install date", properties, L"InstallDate");
    product.install_date = installed_products_detail::install_date_text(product.install_date);
    fill(product.package_name, "Original package", sources, L"PackageName");
    if (product.package_code.empty()) {
      product.package_code = unpack_guid(classes.text(L"PackageCode"));
      if (!product.package_code.empty())
        product.from_registry.emplace_back("PackageCode");
    }
    if (product.last_used_source.empty()) {
      product.last_used_source = installer_cache_detail::last_used_source_text(sources.text(L"LastUsedSource"));
      if (!product.last_used_source.empty())
        product.from_registry.emplace_back("Last used source");
    }
    fill(product.local_package, "Cached package", properties, L"LocalPackage");
    fill(product.install_location, "Install location", properties, L"InstallLocation");
  }
  product.local_package_exists = file_present(product.local_package);
  product.patches = read_patches(key.code, key.context);
  read_listed_entry(product);
  read_installer_keys(product);
  read_main_program(product);
  return product;
}

std::string record_text(MSIHANDLE record, UINT field) {
  return msi_text([&](LPWSTR buffer, LPDWORD size) {
    if (buffer == nullptr) {
      wchar_t empty[1]{};
      *size = 0;
      return MsiRecordGetStringW(record, field, empty, size);
    }
    return MsiRecordGetStringW(record, field, buffer, size);
  });
}

std::string database_property(MSIHANDLE database, const wchar_t* name) {
  const std::wstring query = std::wstring(L"SELECT `Value` FROM `Property` WHERE `Property` = '") + name + L"'";
  MSIHANDLE view = 0;
  if (MsiDatabaseOpenViewW(database, query.c_str(), &view) != ERROR_SUCCESS)
    return {};
  std::string value;
  if (MsiViewExecute(view, 0) == ERROR_SUCCESS) {
    MSIHANDLE record = 0;
    if (MsiViewFetch(view, &record) == ERROR_SUCCESS) {
      value = record_text(record, 1);
      MsiCloseHandle(record);
    }
    MsiViewClose(view);
  }
  MsiCloseHandle(view);
  return value;
}

void read_msi(InstallerCandidate& candidate) {
  candidate.kind = "msi";
  MSIHANDLE database = 0;
  const UINT opened = MsiOpenDatabaseW(candidate.path.c_str(), MSIDBOPEN_READONLY, &database);
  if (opened != ERROR_SUCCESS) {
    candidate.error = "Windows Installer could not open it as a package: " + system_text(opened);
    return;
  }
  MSIHANDLE summary = 0;
  if (MsiGetSummaryInformationW(database, nullptr, 0, &summary) == ERROR_SUCCESS) {
    candidate.package_code = msi_text([&](LPWSTR buffer, LPDWORD size) {
      UINT type = 0;
      INT number = 0;
      FILETIME time{};
      if (buffer == nullptr) {
        wchar_t empty[1]{};
        *size = 0;
        return MsiSummaryInfoGetPropertyW(summary, PID_REVNUMBER, &type, &number, &time, empty, size);
      }
      return MsiSummaryInfoGetPropertyW(summary, PID_REVNUMBER, &type, &number, &time, buffer, size);
    });
    MsiCloseHandle(summary);
  }
  const std::string normalized = normalize_guid(candidate.package_code);
  if (!normalized.empty())
    candidate.package_code = normalized;
  candidate.product_code = normalize_guid(database_property(database, L"ProductCode"));
  candidate.product_name = database_property(database, L"ProductName");
  candidate.product_version = database_property(database, L"ProductVersion");
  candidate.upgrade_code = normalize_guid(database_property(database, L"UpgradeCode"));
  candidate.manufacturer = database_property(database, L"Manufacturer");
  MsiCloseHandle(database);
}

void read_exe(InstallerCandidate& candidate) {
  candidate.kind = "exe";
  candidate.file_version = file_version(candidate.path, &candidate.file_product_name);
  const DownloadPublisherCheck signature = verify_installer_publisher(candidate.path, "");
  candidate.signature_trusted = signature.trusted;
  candidate.signer = signature.signer_subject;
  candidate.signature_note = signature.trusted ? signature.warning : signature.failure;
}

InstallerCandidate read_candidate(const std::filesystem::path& path, const CancellationToken& cancel) {
  InstallerCandidate candidate;
  candidate.path = path;
  const std::string extension = ascii_lower(path_to_utf8(path.extension()));
  if (extension == ".msi")
    read_msi(candidate);
  else if (extension == ".exe")
    read_exe(candidate);
  else
    candidate.error = "Not an .msi or an .exe installer.";
  auto hashed = hash_file_sha256(path, cancel);
  if (hashed.ok())
    candidate.sha256 = hashed.value();
  else
    candidate.sha256_error = describe_error(hashed.error());
  return candidate;
}

std::vector<std::filesystem::path> msi_files_under(const std::filesystem::path& root, int depth, std::size_t limit,
                                                   bool& limit_reached, const CancellationToken& cancel) {
  std::vector<std::filesystem::path> found;
  limit_reached = false;
  std::error_code error;
  std::filesystem::recursive_directory_iterator entries(
      root, std::filesystem::directory_options::skip_permission_denied, error);
  for (; !error && entries != std::filesystem::recursive_directory_iterator(); entries.increment(error)) {
    if (cancel.is_cancelled())
      break;
    std::error_code type_error;
    if (entries->is_directory(type_error)) {
      if (entries.depth() >= depth)
        entries.disable_recursion_pending();
      continue;
    }
    if (ascii_lower(path_to_utf8(entries->path().extension())) != ".msi")
      continue;
    if (found.size() >= limit) {
      limit_reached = true;
      break;
    }
    found.push_back(entries->path());
  }
  std::sort(found.begin(), found.end(), [](const std::filesystem::path& left, const std::filesystem::path& right) {
    return ascii_lower(path_to_utf8(left)) < ascii_lower(path_to_utf8(right));
  });
  return found;
}

void count_cache_folder(InstallerCacheResult& result) {
  wchar_t windows[MAX_PATH]{};
  const UINT length = GetWindowsDirectoryW(windows, MAX_PATH);
  const std::filesystem::path folder =
      std::filesystem::path(length == 0U || length >= MAX_PATH ? std::wstring(L"C:\\Windows") : std::wstring(windows, length)) /
      L"Installer";
  result.installer_folder = path_to_utf8(folder);
  std::error_code error;
  result.installer_folder_exists = std::filesystem::is_directory(folder, error);
  if (!result.installer_folder_exists)
    return;
  std::filesystem::directory_iterator entries(folder, error);
  for (; !error && entries != std::filesystem::directory_iterator(); entries.increment(error)) {
    const std::string extension = ascii_lower(path_to_utf8(entries->path().extension()));
    if (extension == ".msi")
      ++result.cached_msi_files;
    else if (extension == ".msp")
      ++result.cached_msp_files;
  }
}

} // namespace

Result<InstallerCacheResult> check_installer_cache(const InstallerCacheOptions& options,
                                                   const CancellationToken& cancel,
                                                   const ProgressCallback& progress) {
  InstallerCacheResult result;
  std::uint64_t step = 0;
  const auto report = [&](std::string phase, std::string scope) {
    if (progress)
      progress(ProgressEvent{std::move(phase), std::move(scope), ++step, 0});
  };
  const auto cancelled = [] {
    Error error = installer_error("check installer cache", "The check was cancelled.");
    error.skipped = true;
    return Result<InstallerCacheResult>::failure(std::move(error));
  };

  const std::string upgrade = normalize_guid(options.upgrade_code);
  if (!trim(options.upgrade_code).empty() && upgrade.empty())
    return Result<InstallerCacheResult>::failure(installer_error(
        "read UpgradeCode", "\"" + options.upgrade_code + "\" is not a GUID. An UpgradeCode reads like "
                            "{12345678-90AB-CDEF-1234-567890ABCDEF}, with or without the braces."));

  report("Installer cache", "Counting the cached packages");
  count_cache_folder(result);

  std::vector<ProductKey> keys;
  std::set<std::wstring> seen;
  const auto add_key = [&](const std::wstring& code, std::optional<MSIINSTALLCONTEXT> context, std::string found_by,
                           std::string upgrade_code = {}) {
    const std::wstring normalized = wide_from_utf8(normalize_guid(utf8_from_wide(code)));
    if (normalized.empty() || seen.count(normalized) != 0U)
      return;
    if (!context)
      context = product_context(normalized);
    if (!context)
      return;
    seen.insert(normalized);
    keys.push_back({normalized, *context, std::move(found_by), std::move(upgrade_code)});
  };

  if (!upgrade.empty()) {
    result.searched = "UpgradeCode " + upgrade;
    bool from_registry = false;
    for (const std::wstring& code : related_product_codes(upgrade, from_registry))
      add_key(code, std::nullopt, from_registry ? "From the UpgradeCodes registry key" : "", upgrade);
    if (keys.empty()) {
      // A ProductCode typed in the UpgradeCode's place.
      const std::wstring as_product = wide_from_utf8(upgrade);
      if (product_context(as_product)) {
        add_key(as_product, std::nullopt, "");
        result.notes.push_back(upgrade + " is a ProductCode, not an UpgradeCode. The product it names is listed.");
      }
    }
  } else {
    const std::string filter = trim(options.name_filter);
    result.searched = filter.empty() ? std::string("Every installed product")
                                     : "Products whose name or publisher holds \"" + filter + "\"";
    report("Installer cache", "Listing the installed products");
    for (DWORD index = 0;; ++index) {
      if (cancel.is_cancelled())
        return cancelled();
      wchar_t code[39]{};
      MSIINSTALLCONTEXT context = MSIINSTALLCONTEXT_NONE;
      const UINT status = MsiEnumProductsExW(nullptr, nullptr, MSIINSTALLCONTEXT_ALL, index, code, &context, nullptr,
                                             nullptr);
      if (status == ERROR_NO_MORE_ITEMS)
        break;
      if (status != ERROR_SUCCESS) {
        result.notes.push_back("Windows Installer stopped listing products: " + system_text(status));
        break;
      }
      std::string name = product_info(code, context, L"InstalledProductName");
      if (name.empty())
        name = product_info(code, context, L"ProductName");
      if (installer_cache_detail::name_matches(filter, name) ||
          (!filter.empty() && installer_cache_detail::name_matches(filter, product_info(code, context, L"Publisher"))))
        add_key(code, context, "");
    }
    if (keys.empty()) {
      // The API listed nothing that matches: the products the machine's Installer keys record.
      const RegistryKey products(std::wstring(kUserDataProducts).substr(0, std::wstring(kUserDataProducts).size() - 1U));
      for (const std::wstring& packed : products.subkeys()) {
        const RegistryKey properties(std::wstring(kUserDataProducts) + packed + L"\\InstallProperties");
        if (!installer_cache_detail::name_matches(filter, properties.text(L"DisplayName")) &&
            (filter.empty() || !installer_cache_detail::name_matches(filter, properties.text(L"Publisher"))))
          continue;
        const std::string code = unpack_guid(utf8_from_wide(packed));
        if (!code.empty())
          add_key(wide_from_utf8(code), MSIINSTALLCONTEXT_MACHINE, "From the Installer UserData registry key");
      }
    }
  }

  std::optional<std::map<std::string, std::string>> upgrade_map;
  const auto read_keys = [&](std::size_t from) -> bool {
    for (std::size_t index = from; index < keys.size(); ++index) {
      if (cancel.is_cancelled())
        return false;
      report("Installer cache", "Reading " + utf8_from_wide(keys[index].code));
      InstallerCacheProduct product = read_product(keys[index]);
      if (!keys[index].upgrade_code.empty()) {
        product.upgrade_code = keys[index].upgrade_code;
      } else {
        if (!upgrade_map)
          upgrade_map = upgrade_codes_by_product();
        const auto found = upgrade_map->find(ascii_upper(pack_guid(product.product_code)));
        if (found != upgrade_map->end())
          product.upgrade_code = found->second;
      }
      result.products.push_back(std::move(product));
    }
    return true;
  };
  if (!read_keys(0))
    return cancelled();

  if (!options.check_path.empty()) {
    const std::filesystem::path& checked = options.check_path;
    result.checked_path = path_to_utf8(checked);
    std::error_code error;
    const auto status = std::filesystem::status(checked, error);
    if (std::filesystem::is_directory(status)) {
      result.checked_kind = "folder";
      report("Installer cache", "Searching " + result.checked_path + " for .msi files");
      const auto files = msi_files_under(checked, std::max(0, options.folder_depth), std::max<std::size_t>(1U, options.folder_limit),
                                         result.folder_limit_reached, cancel);
      result.folder_msi_found = files.size();
      for (const std::filesystem::path& file : files) {
        if (cancel.is_cancelled())
          return cancelled();
        report("Installer cache", "Reading and hashing " + path_to_utf8(file));
        result.candidates.push_back(read_candidate(file, cancel));
      }
    } else if (std::filesystem::is_regular_file(status)) {
      report("Installer cache", "Reading and hashing " + result.checked_path);
      result.candidates.push_back(read_candidate(checked, cancel));
      result.checked_kind = result.candidates.back().kind.empty() ? "file" : result.candidates.back().kind;
    } else {
      result.checked_kind = "missing";
    }
    if (cancel.is_cancelled())
      return cancelled();

    // The installed products an installer relates to that the search did not list.
    const std::size_t listed = keys.size();
    for (const InstallerCandidate& candidate : result.candidates) {
      if (candidate.kind != "msi" || !candidate.error.empty())
        continue;
      if (!candidate.upgrade_code.empty()) {
        bool from_registry = false;
        for (const std::wstring& code : related_product_codes(candidate.upgrade_code, from_registry))
          add_key(code, std::nullopt, "Related to the installer checked: the same UpgradeCode",
                  candidate.upgrade_code);
      }
      if (!candidate.product_code.empty())
        add_key(wide_from_utf8(candidate.product_code), std::nullopt,
                "Related to the installer checked: the same ProductCode");
    }
    if (!read_keys(listed))
      return cancelled();

    for (InstallerCandidate& candidate : result.candidates) {
      if (!candidate.error.empty())
        continue;
      if (candidate.kind == "msi") {
        const auto [match, index] = installer_cache_detail::best_installer_match(
            candidate.package_code, candidate.product_code, candidate.upgrade_code, result.products);
        candidate.match = match;
        candidate.matched_product = match == InstallerMatch::none ? result.products.size() : index;
      } else {
        candidate.matched_product = result.products.size();
        for (std::size_t index = 0; index < result.products.size(); ++index) {
          if (installer_cache_detail::versions_agree(candidate.file_version, result.products[index].version)) {
            candidate.version_matches_product = true;
            candidate.matched_product = index;
            break;
          }
        }
      }
    }
    // The package a product was installed from first, then the rest in path order.
    std::stable_sort(result.candidates.begin(), result.candidates.end(),
                     [](const InstallerCandidate& left, const InstallerCandidate& right) {
                       return static_cast<int>(left.match) > static_cast<int>(right.match);
                     });
  }
  return Result<InstallerCacheResult>::success(std::move(result));
}

#else

Result<InstallerCacheResult> check_installer_cache(const InstallerCacheOptions& options,
                                                   const CancellationToken& cancel,
                                                   const ProgressCallback& progress) {
  static_cast<void>(options);
  static_cast<void>(cancel);
  static_cast<void>(progress);
  return Result<InstallerCacheResult>::failure(installer_error(
      "check installer cache",
      "Installer Cache Check is a Windows check: it reads the Windows Installer records and cache of a Windows "
      "machine."));
}

#endif

} // namespace support_assist
