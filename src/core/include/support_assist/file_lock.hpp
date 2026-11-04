#pragma once

// File Lock Check (F8): the processes that hold a file open, or every file under a folder. Windows
// asks the file system for the processes using each file (FileProcessIdsUsingFileInformation);
// Restart Manager is not used, as EDR products watch its calls. Linux reads each process's open
// descriptors under /proc once and matches them to the files; other accounts' processes need root
// (docs/PROPOSAL_5.x_CHECKS.md section 9).

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace support_assist {

struct FileHolder {
  std::uint32_t pid = 0;
  std::string name;
  std::string path;
  std::string services;
  std::int64_t started_unix_millis = 0;
};

struct FileLockResult {
  std::string file;       // as checked, made absolute
  bool is_directory = false;
  std::vector<FileHolder> holders;
  std::size_t processes_not_readable = 0; // Linux without root: other accounts' processes
  std::string note;
};

// Fails when the file does not exist or cannot be opened to ask.
Result<FileLockResult> find_file_holders(const std::string& file);

struct HeldFile {
  std::string path;                 // absolute
  bool is_directory = false;
  std::vector<std::uint32_t> pids;  // the processes holding it, each one in FolderLockResult::holders
};

struct FolderLockResult {
  std::string folder;               // as checked, made absolute
  std::size_t files_checked = 0;
  std::size_t folders_checked = 0;  // the folder itself and every folder under it
  std::size_t not_checked = 0;      // entries that could not be opened to ask
  bool stopped_at_limit = false;
  std::vector<HeldFile> held;       // in the order the walk met them
  std::vector<FileHolder> holders;  // every process holding one or more of them, by PID
  std::size_t processes_not_readable = 0; // Linux without root: other accounts' processes
  std::string note;
};

constexpr std::size_t kFolderLockMaxEntries = 50000;

// The walk so far, while it runs: the counts and the entries held up to now, with the processes
// known when the walk started named. Sent at most every kFolderLockProgressMs, and once more
// when an entry is found held after a quiet spell.
using FolderLockProgress = std::function<void(const FolderLockResult&)>;
constexpr int kFolderLockProgressMs = 500;

// The folder, every folder under it and every file in them, and the processes holding each. Links
// and junctions are listed but not followed. Stops after max_entries entries, or when cancelled.
Result<FolderLockResult> find_folder_holders(const std::string& folder, const CancellationToken& cancel,
                                             std::size_t max_entries = kFolderLockMaxEntries,
                                             const FolderLockProgress& progress = {});

} // namespace support_assist
