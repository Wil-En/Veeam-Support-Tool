#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace support_assist {

struct SshConnectionOptions {
  std::string host;
  std::uint16_t port = 22;
  std::string username;
  std::string password;
  std::filesystem::path private_key_path;
  std::string private_key_passphrase;
  // Lowercase hexadecimal SHA-256 fingerprint without separators. When set,
  // every operation refuses a host-key mismatch before authenticating.
  std::string expected_host_key_sha256;
  std::uint32_t timeout_seconds = 20;
};

struct SshHostKeyInfo {
  std::string fingerprint_sha256;
  std::string algorithm;
};

struct SftpEntry {
  std::string name;
  std::string path;
  bool directory = false;
  bool symlink = false;
  std::uint64_t size = 0;
  std::uint64_t modified_unix = 0;
  std::uint32_t permissions = 0;
};

struct SshCommandResult {
  int exit_status = -1;
  std::string standard_output;
  std::string standard_error;
};

// True only when this build contains libssh2-backed SSH/SFTP support.
bool ssh_available() noexcept;

// Performs transport negotiation only. It does not authenticate and is safe to
// use for explicit first-use host-key confirmation.
Result<SshHostKeyInfo> ssh_probe_host_key(const SshConnectionOptions& options,
                                          const CancellationToken& cancel);

Result<std::vector<SftpEntry>> ssh_list_directory(const SshConnectionOptions& options,
                                                   std::string_view remote_path,
                                                   const CancellationToken& cancel);

// Lists `remote_path`, or the nearest folder above it that can be listed when it cannot, in one
// session. `listed_path` receives the folder actually listed, so a default folder that is missing
// on this host opens its parent instead of an empty pane.
Result<std::vector<SftpEntry>> ssh_list_nearest_directory(const SshConnectionOptions& options,
                                                          std::string_view remote_path,
                                                          std::string& listed_path,
                                                          const CancellationToken& cancel);

// The folder above `remote_path`: "/var/log" for "/var/log/VeeamBackup". "/" stays "/".
std::string ssh_parent_directory(std::string_view remote_path);

Status ssh_download_file(const SshConnectionOptions& options,
                         std::string_view remote_path,
                         const std::filesystem::path& local_path,
                         const CancellationToken& cancel,
                         ProgressCallback progress = {});

Status ssh_upload_file(const SshConnectionOptions& options,
                       const std::filesystem::path& local_path,
                       std::string_view remote_path,
                       const CancellationToken& cancel,
                       ProgressCallback progress = {});

Result<SshCommandResult> ssh_execute_command(const SshConnectionOptions& options,
                                             std::string_view command,
                                             const CancellationToken& cancel,
                                             ProgressCallback progress = {});

// --- Interactive shell -----------------------------------------------------------------------
//
// A persistent shell channel with a PTY, for the Remote troubleshooting console. Distinct from
// ssh_execute_command, which opens a channel, runs one command and closes: an engineer reading logs
// needs a session that stays open, keeps its working directory, and can run an interactive pager.
//
// The remote host provides the PTY, so nothing is spawned locally.
struct SshShell;

// cols/rows are the initial terminal size and are sent to the remote host, so a pager knows how
// much screen it has.
Result<std::shared_ptr<SshShell>> ssh_open_shell(const SshConnectionOptions& options,
                                                 int columns,
                                                 int rows,
                                                 const CancellationToken& cancel);

// Returns whatever has arrived, possibly empty. Never blocks: the caller polls from its own thread
// and hands the bytes to a TerminalScreen.
Result<std::string> ssh_shell_read(SshShell& shell);

Status ssh_shell_write(SshShell& shell, std::string_view bytes);

// Tell the remote host the window changed, so full-screen output reflows.
Status ssh_shell_resize(SshShell& shell, int columns, int rows);

// False once the remote shell has exited or the connection dropped.
bool ssh_shell_connected(const SshShell& shell);

void ssh_shell_close(SshShell& shell);

} // namespace support_assist
