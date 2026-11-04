// File Lock Check on Windows: one NtQueryInformationFile call with FileProcessIdsUsingFileInformation
// on a handle opened for attributes only, sharing everything, so asking never blocks the holder.
#include "support_assist/file_lock.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <filesystem>

// Exported by ntdll.dll and documented, but declared only in the driver kit's headers.
extern "C" __declspec(dllimport) NTSTATUS NTAPI NtQueryInformationFile(HANDLE file, PIO_STATUS_BLOCK io,
                                                                        PVOID information, ULONG length,
                                                                        FILE_INFORMATION_CLASS information_class);

namespace support_assist {
namespace {

// winternl.h names only the first file information class; this one is documented as 47.
constexpr auto kFileProcessIdsUsingFileInformation = static_cast<FILE_INFORMATION_CLASS>(47);

struct ProcessIdsUsingFile {
  ULONG NumberOfProcessIdsInList;
  ULONG_PTR ProcessIdList[1];
};

constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
constexpr NTSTATUS kStatusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);

Error lock_error(const std::string& file, const std::string& message, std::int64_t code = 0) {
  Error error;
  error.component = "filesystem";
  error.operation = "find the processes holding a file";
  error.source = file;
  error.native_code = code;
  error.message = message;
  return error;
}

// The processes using one file or folder: 0 and the PIDs, or the Win32 error that stopped the open,
// or the NTSTATUS of the query.
struct PidQuery {
  DWORD open_error = 0;
  NTSTATUS status = 0;
  std::vector<std::uint32_t> pids;
};

PidQuery query_pids(const std::filesystem::path& path, std::vector<unsigned char>& buffer, bool follow_link) {
  PidQuery query;
  HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | (follow_link ? 0U : static_cast<DWORD>(FILE_FLAG_OPEN_REPARSE_POINT)),
                              nullptr);
  if (handle == INVALID_HANDLE_VALUE) {
    query.open_error = GetLastError();
    return query;
  }
  NTSTATUS status = kStatusInfoLengthMismatch;
  for (int attempt = 0; attempt < 6 && (status == kStatusInfoLengthMismatch || status == kStatusBufferOverflow);
       ++attempt) {
    IO_STATUS_BLOCK io{};
    status = NtQueryInformationFile(handle, &io, buffer.data(), static_cast<ULONG>(buffer.size()),
                                    kFileProcessIdsUsingFileInformation);
    if (status == kStatusInfoLengthMismatch || status == kStatusBufferOverflow)
      buffer.resize(buffer.size() * 4U);
  }
  CloseHandle(handle);
  query.status = status;
  if (status < 0)
    return query;
  const auto* list = reinterpret_cast<const ProcessIdsUsingFile*>(buffer.data());
  const auto self = static_cast<std::uint32_t>(GetCurrentProcessId());
  for (ULONG i = 0; i < list->NumberOfProcessIdsInList; ++i) {
    const auto pid = static_cast<std::uint32_t>(list->ProcessIdList[i]);
    if (pid != self) // SAT's own handle, open only to ask
      query.pids.push_back(pid);
  }
  return query;
}

FileHolder holder_for(std::uint32_t pid, const ProcessDirectory& processes) {
  FileHolder holder;
  holder.pid = pid;
  if (const ProcessIdentity* identity = processes.find(pid)) {
    holder.name = identity->name;
    holder.path = identity->path;
    holder.services = identity->services;
    holder.started_unix_millis = identity->started_unix_millis;
  }
  return holder;
}

} // namespace

Result<FolderLockResult> find_folder_holders(const std::string& folder, const CancellationToken& cancel,
                                             std::size_t max_entries, const FolderLockProgress& progress) {
  FolderLockResult result;
  if (trim(folder).empty())
    return Result<FolderLockResult>::failure(lock_error(folder, "no folder was given"));
  std::error_code error;
  const std::filesystem::path root = std::filesystem::absolute(path_from_utf8(trim(folder)), error);
  if (error)
    return Result<FolderLockResult>::failure(lock_error(folder, "the path is not valid"));
  result.folder = path_to_utf8(root);
  const DWORD root_attributes = GetFileAttributesW(root.c_str());
  if (root_attributes == INVALID_FILE_ATTRIBUTES || (root_attributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
    return Result<FolderLockResult>::failure(lock_error(result.folder, "the folder does not exist", GetLastError()));

  std::vector<unsigned char> buffer(16U * 1024U);
  std::vector<std::uint32_t> seen;
  // The walk so far, sent while it runs, with the processes known at the start named.
  const ProcessDirectory started = progress ? ProcessDirectory::capture() : ProcessDirectory{};
  auto last_sent = std::chrono::steady_clock::now();
  std::size_t held_sent = 0;
  const auto send = [&](bool found_held) {
    if (!progress)
      return;
    const auto now = std::chrono::steady_clock::now();
    const auto quiet = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_sent).count();
    if (quiet < kFolderLockProgressMs && !(found_held && quiet >= kFolderLockProgressMs / 2))
      return;
    last_sent = now;
    held_sent = result.held.size();
    FolderLockResult partial = result;
    for (const std::uint32_t pid : seen)
      partial.holders.push_back(holder_for(pid, started));
    progress(partial);
  };
  const auto check = [&](const std::filesystem::path& path, bool directory) {
    ++(directory ? result.folders_checked : result.files_checked);
    PidQuery query = query_pids(path, buffer, false);
    if (query.open_error != 0 || query.status < 0) {
      ++result.not_checked;
      return;
    }
    if (query.pids.empty())
      return;
    for (const std::uint32_t pid : query.pids) {
      if (std::find(seen.begin(), seen.end(), pid) == seen.end())
        seen.push_back(pid);
    }
    result.held.push_back({path_to_utf8(path), directory, std::move(query.pids)});
  };

  check(root, true);
  std::filesystem::recursive_directory_iterator walk(root, std::filesystem::directory_options::skip_permission_denied,
                                                     error);
  for (; !error && walk != std::filesystem::recursive_directory_iterator(); walk.increment(error)) {
    if (cancel.is_cancelled())
      break;
    if (result.files_checked + result.folders_checked >= max_entries) {
      result.stopped_at_limit = true;
      break;
    }
    const DWORD attributes = GetFileAttributesW(walk->path().c_str());
    const bool directory = attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (directory && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
      walk.disable_recursion_pending(); // a junction or link: listed, not followed
    check(walk->path(), directory);
    send(result.held.size() > held_sent);
  }

  const ProcessDirectory processes = ProcessDirectory::capture();
  std::sort(seen.begin(), seen.end());
  for (const std::uint32_t pid : seen)
    result.holders.push_back(holder_for(pid, processes));
  if (result.not_checked > 0)
    result.note = std::to_string(result.not_checked) +
                  " entries could not be opened to ask; running SAT as administrator may read them.";
  return Result<FolderLockResult>::success(std::move(result));
}

Result<FileLockResult> find_file_holders(const std::string& file) {
  FileLockResult result;
  std::error_code error;
  if (trim(file).empty())
    return Result<FileLockResult>::failure(lock_error(file, "no file was given"));
  const std::filesystem::path path = std::filesystem::absolute(path_from_utf8(trim(file)), error);
  if (error)
    return Result<FileLockResult>::failure(lock_error(file, "the path is not valid"));
  result.file = path_to_utf8(path);
  // Attributes read even on a file another process holds exclusively, where std::filesystem's
  // existence check fails with a sharing error.
  const DWORD attributes = GetFileAttributesW(path.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND || code == ERROR_INVALID_NAME)
      return Result<FileLockResult>::failure(lock_error(result.file, "the file does not exist", code));
  } else {
    result.is_directory = (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
  }

  std::vector<unsigned char> buffer(16U * 1024U);
  const PidQuery query = query_pids(path, buffer, true);
  if (query.open_error != 0) {
    const DWORD code = query.open_error;
    Error refused = lock_error(result.file,
                               code == ERROR_ACCESS_DENIED
                                   ? "this account may not open the file to ask; an administrator can"
                                   : "the file could not be opened to ask (error " + std::to_string(code) + ")",
                               code);
    refused.elevation_may_help = code == ERROR_ACCESS_DENIED;
    return Result<FileLockResult>::failure(refused);
  }
  if (query.status < 0) {
    return Result<FileLockResult>::failure(
        lock_error(result.file, "Windows did not report the file's users", static_cast<std::int64_t>(query.status)));
  }
  const ProcessDirectory processes = ProcessDirectory::capture();
  for (const std::uint32_t pid : query.pids)
    result.holders.push_back(holder_for(pid, processes));
  return Result<FileLockResult>::success(std::move(result));
}

} // namespace support_assist
