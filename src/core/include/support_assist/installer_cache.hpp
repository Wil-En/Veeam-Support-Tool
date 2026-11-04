#pragma once

// Installer Cache Check (Windows, read-only). For the installed products with an UpgradeCode, or
// whose name or publisher holds a text: what Windows Installer records of each (version, install date, original
// package name, PackageCode, last used source) and the cached package it keeps in
// C:\Windows\Installer (LocalPackage), with whether that file and each patch's cached .msp exist.
// Read through the Windows Installer API (msi.dll); the Installer registry keys are read only for a
// value the API returns nothing for. An installer given to check (an .msi, an .exe or a folder) is
// read for its identity and SHA-256 and compared with those products. On other systems the check
// returns a failure.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct InstallerCachePatch {
  std::string patch_code;     // {GUID}
  std::string name;           // the patch's display name
  std::string state;          // Applied, Superseded, Obsoleted, Registered
  std::string local_package;  // the cached .msp Windows keeps for it
  bool local_package_exists = false;
};

struct InstallerCacheProduct {
  std::string product_code;      // {GUID}
  std::string upgrade_code;      // {GUID}, when known
  std::string name;
  std::string version;
  std::string install_date;      // "2026-08-24", or as recorded
  std::string package_name;      // the original .msi file name
  std::string package_code;      // {GUID}
  std::string last_used_source;  // the folder or media the product was last installed from
  std::string install_location;
  std::string local_package;     // the cached .msi Windows expects, in C:\Windows\Installer
  bool local_package_exists = false;
  std::string context;           // "Per machine" or "Per user"
  std::string listed_name;       // Programs and Features: the DisplayName of the product's Uninstall entry
  std::string listed_version;    // and the DisplayVersion of the same entry
  std::string main_program;      // the product's own program: its Uninstall entry's icon, or an .exe
                                 // in its install location whose version resource names the product
  std::string main_program_version;
  std::vector<InstallerCachePatch> patches;
  std::vector<std::string> from_registry;  // the values read from the Installer registry keys
  // The registry keys that hold the product, as label and full path (HKLM\...), the ones present.
  std::vector<std::pair<std::string, std::string>> registry_keys;
  std::string found_by;          // how the product was found, when not by the search itself
};

// How an installer relates to an installed product, from closest to none.
enum class InstallerMatch {
  none,
  upgrade_code,  // the same UpgradeCode: the product line, a different version
  product_code,  // the same ProductCode with another PackageCode: a different build of the package
  package_code,  // the same PackageCode: the package the product was installed from
};

struct InstallerCandidate {
  std::filesystem::path path;
  std::string kind;              // "msi" or "exe"
  std::string sha256;
  std::string sha256_error;      // why the SHA-256 could not be read
  std::string error;             // why its identity could not be read, when it could not
  // An .msi's identity.
  std::string package_code;
  std::string product_code;
  std::string product_name;
  std::string product_version;
  std::string upgrade_code;
  std::string manufacturer;
  // An .exe's identity.
  std::string file_version;
  std::string file_product_name;
  std::string signer;
  bool signature_trusted = false;
  std::string signature_note;    // why the signature was not accepted, or a revocation warning
  // The closest installed product.
  InstallerMatch match = InstallerMatch::none;
  std::size_t matched_product = 0;  // index into InstallerCacheResult::products
  bool version_matches_product = false;  // an .exe whose file version is a listed product's version
};

struct InstallerCacheOptions {
  std::string upgrade_code;             // braces optional; when set, the name filter is not used
  std::string name_filter = "Veeam";    // part of the product name or publisher; empty lists every product
  std::filesystem::path check_path;     // optional: an .msi, an .exe or a folder
  int folder_depth = 4;                 // folders searched below the one given
  std::size_t folder_limit = 500;       // .msi files read from a folder at most
};

struct InstallerCacheResult {
  std::string searched;                 // what was searched for, as a sentence fragment
  std::string installer_folder;         // C:\Windows\Installer
  bool installer_folder_exists = false;
  std::size_t cached_msi_files = 0;
  std::size_t cached_msp_files = 0;
  std::vector<InstallerCacheProduct> products;
  std::string checked_path;             // the installer or folder given, as typed
  std::string checked_kind;             // "msi", "exe", "folder" or "missing"
  std::size_t folder_msi_found = 0;
  bool folder_limit_reached = false;
  std::vector<InstallerCandidate> candidates;
  std::vector<std::string> notes;
};

// One line of the result as both the CLI and the Windows GUI show it.
struct InstallerCacheRow {
  std::string product;
  std::string item;
  std::string value;
  std::string state;
};

Result<InstallerCacheResult> check_installer_cache(const InstallerCacheOptions& options,
                                                   const CancellationToken& cancel,
                                                   const ProgressCallback& progress = {});

// The rows of a result: this machine's cache folder, each product, then each installer checked.
std::vector<InstallerCacheRow> installer_cache_rows(const InstallerCacheResult& result);
// The same rows as a table shows them: each product (and the cache folder, and each installer) on a
// row of its own, then its items under it with the first column empty.
std::vector<InstallerCacheRow> installer_cache_table_rows(const InstallerCacheResult& result);
// A one-line summary: products found, cached packages missing, the installer that matches.
std::string installer_cache_summary(const InstallerCacheResult& result);
// Whether a cached package (a product's or a patch's) is missing.
bool installer_cache_has_missing(const InstallerCacheResult& result);

namespace installer_cache_detail {
// "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" in capitals, from a GUID with or without braces;
// empty when the text is not a GUID.
std::string normalize_guid(std::string_view text);
// The 32-character form the Installer registry keys use: the first three groups reversed, each
// byte of the last two swapped. Empty when the text is not a GUID.
std::string pack_guid(std::string_view guid);
// A packed GUID back to "{...}"; empty when the text is not 32 hexadecimal characters.
std::string unpack_guid(std::string_view packed);
// LastUsedSource as Windows stores it, "n;1;C:\Source\", as the source alone.
std::string last_used_source_text(std::string_view raw);
// A DisplayIcon value ("\"C:\\Program Files\\App\\app.exe\",0") as the file path alone.
std::string display_icon_path(std::string_view raw);
// Two version strings name the same version: each number equal, a missing one read as 0.
bool versions_agree(std::string_view left, std::string_view right);
// Whether a product name holds the filter, ignoring case; an empty filter takes every name.
bool name_matches(std::string_view filter, std::string_view name);
// Whether a program's version resource names the product: either name holds the other, ignoring
// case and spaces. Empty names never match.
bool program_names_product(std::string_view program_product, std::string_view product_name);
// How an installer's codes relate to a product's.
InstallerMatch classify_installer(std::string_view package_code, std::string_view product_code,
                                  std::string_view upgrade_code, const InstallerCacheProduct& product);
// The closest product for an installer, and its index; none when no product relates.
std::pair<InstallerMatch, std::size_t> best_installer_match(std::string_view package_code,
                                                            std::string_view product_code,
                                                            std::string_view upgrade_code,
                                                            const std::vector<InstallerCacheProduct>& products);
// The patch state number MsiGetPatchInfoEx gives ("1") as a word.
std::string patch_state_text(std::string_view state);
} // namespace installer_cache_detail

} // namespace support_assist
