#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace support_assist {

struct ExternalToolInstallOptions {
  std::string tool_id;
  std::filesystem::path destination_root;
  bool replace_existing_version = true;
};

struct ExternalToolInstallResult {
  std::string tool_id;
  std::string tool_name;
  std::string version;
  std::string source_url;
  std::string sha256;
  // For a kind that runs an installer, the Authenticode subject (publisher) that was verified before
  // SAT executed it. Empty for a plain archive extraction (nothing was executed).
  std::string verified_publisher;
  bool executed_installer = false;
  std::filesystem::path installed_directory;
  std::vector<std::filesystem::path> installed_files;
  std::vector<std::string> warnings;
};

Result<ExternalToolInstallResult>
install_external_tool(const ExternalToolInstallOptions& options,
                      const CancellationToken& cancel,
                      ProgressCallback progress = {});

Status remove_managed_external_tool(std::string_view tool_id,
                                    const std::filesystem::path& destination_root);

// Where earlier builds wrote tool-sources.ini. The download sources are compiled into SAT now;
// a file here is neither read nor written.
std::filesystem::path tool_sources_config_path(const std::filesystem::path& destination_root);

// True when an automatic, locked-down download is available for the tool: the compiled sources or
// the catalog carry a download URL. Lets the Integrations page
// show "Acquire" (real download) rather than "Get" (open the source page) for a configured tool.
bool tool_supports_locked_down_download(std::string_view tool_id,
                                        const std::filesystem::path& destination_root);

// The parts of a tool's archive a download unpacks, as path prefixes inside the archive: the
// compiled sources' Extract=, else the catalog's; empty when the whole archive is unpacked.
std::vector<std::string> tool_extract_paths(std::string_view tool_id, const std::filesystem::path& destination_root);

namespace tool_download_detail {
// True when an archive entry ("pgsql/bin/psql.exe") is under one of the prefixes, ignoring case and
// the slash direction; every entry is wanted when there are none.
bool archive_entry_wanted(std::string_view entry, const std::vector<std::string>& prefixes);
// After an update: removes the other versions SAT installed in the tool's folder (each a folder
// holding SAT's manifest), keeping `keep` and anything SAT did not install. Returns a line for each
// version that could not be removed.
std::vector<std::string> remove_earlier_versions(const std::filesystem::path& tool_folder,
                                                 const std::filesystem::path& keep);
// What a tool's download is checked against before it reaches the Tools folder: its publishers
// ("Microsoft Windows|Microsoft Corporation"), "SHA-256" for a pinned download, or empty for none.
std::string download_check(std::string_view tool_id);
// Every program unpacked from an archive (.exe, .dll, .sys) must carry a valid signature from one of
// the publishers in `signers`, each matched in full; a download with no program is refused too.
// `publisher` takes the first signer found; a revocation server that could not be reached adds a
// warning.
Status verify_archive_programs(const std::vector<std::filesystem::path>& files, const std::string& signers,
                               const std::string& url, std::string& publisher, std::vector<std::string>& warnings);
} // namespace tool_download_detail

// The outcome of checking a downloaded installer before SAT executes it.
struct DownloadPublisherCheck {
  bool trusted = false;         // safe to execute: valid trust chain AND signer matches expectation
  std::string signer_subject;   // the Authenticode subject actually found on the file
  std::string failure;          // why it was refused (empty when trusted)
  std::string warning;          // a non-fatal note, e.g. revocation servers were unreachable
};

// Verify that an installer SAT downloaded is safe to run: its signature must chain to a trusted root
// and its signer subject must contain the expected publisher. This is the gate that stops the
// installer-execution download from being an attack vector -- an unsigned, untrusted or
// unexpected-publisher file is never executed. On non-Windows it always returns not-trusted.
DownloadPublisherCheck verify_installer_publisher(const std::filesystem::path& installer,
                                                  const std::string& expected_signer);

} // namespace support_assist
