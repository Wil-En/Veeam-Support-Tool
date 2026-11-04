// File Lock Check on Linux: the processes with the file open, found by comparing the device and
// inode of each /proc/<pid>/fd entry with the file's, so a hard link or another spelling of the
// path still matches. A folder also counts as held by a process working in it.
#include "support_assist/file_lock.hpp"

#include "support_assist/process_identity.hpp"
#include "support_assist/strings.hpp"

#include <chrono>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <set>
#include <utility>

namespace support_assist {
namespace {

Error lock_error(const std::string& file, const std::string& message, std::int64_t code = 0) {
  Error error;
  error.component = "filesystem";
  error.operation = "find the processes holding a file";
  error.source = file;
  error.native_code = code;
  error.message = message;
  return error;
}

bool same_file(const std::string& link, const struct stat& target) {
  struct stat entry {};
  return stat(link.c_str(), &entry) == 0 && entry.st_dev == target.st_dev && entry.st_ino == target.st_ino;
}

using FileKey = std::pair<std::uint64_t, std::uint64_t>; // device, inode

// Every file and folder any readable process has open or works in, with the processes, read once.
std::map<FileKey, std::set<std::uint32_t>> open_files(std::size_t& not_readable) {
  std::map<FileKey, std::set<std::uint32_t>> files;
  const auto self = static_cast<std::uint32_t>(getpid());
  const auto add = [&](const std::string& link, std::uint32_t pid) {
    struct stat entry {};
    if (stat(link.c_str(), &entry) == 0)
      files[{static_cast<std::uint64_t>(entry.st_dev), static_cast<std::uint64_t>(entry.st_ino)}].insert(pid);
  };
  DIR* proc = opendir("/proc");
  if (proc == nullptr)
    return files;
  while (const dirent* entry = readdir(proc)) {
    const std::string pid = entry->d_name;
    if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
      continue;
    const auto number = static_cast<std::uint32_t>(std::strtoul(pid.c_str(), nullptr, 10));
    if (number == self)
      continue;
    const std::string base = "/proc/" + pid;
    add(base + "/cwd", number);
    DIR* fds = opendir((base + "/fd").c_str());
    if (fds == nullptr) {
      if (errno == EACCES)
        ++not_readable;
      continue;
    }
    while (const dirent* fd = readdir(fds)) {
      if (fd->d_name[0] != '.')
        add(base + "/fd/" + fd->d_name, number);
    }
    closedir(fds);
  }
  closedir(proc);
  return files;
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
  const std::filesystem::path root = std::filesystem::absolute(trim(folder), error);
  result.folder = root.string();
  struct stat target {};
  if (error || stat(result.folder.c_str(), &target) != 0 || !S_ISDIR(target.st_mode))
    return Result<FolderLockResult>::failure(lock_error(result.folder, "the folder does not exist", errno));

  const auto files = open_files(result.processes_not_readable);
  std::set<std::uint32_t> seen;
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
  const auto check = [&](const std::filesystem::path& path) {
    struct stat entry {};
    if (lstat(path.c_str(), &entry) != 0) {
      ++result.not_checked;
      return;
    }
    const bool directory = S_ISDIR(entry.st_mode);
    ++(directory ? result.folders_checked : result.files_checked);
    const auto found =
        files.find({static_cast<std::uint64_t>(entry.st_dev), static_cast<std::uint64_t>(entry.st_ino)});
    if (found == files.end())
      return;
    seen.insert(found->second.begin(), found->second.end());
    result.held.push_back({path.string(), directory, {found->second.begin(), found->second.end()}});
  };

  check(root);
  std::filesystem::recursive_directory_iterator walk(root, std::filesystem::directory_options::skip_permission_denied,
                                                     error);
  for (; !error && walk != std::filesystem::recursive_directory_iterator(); walk.increment(error)) {
    if (cancel.is_cancelled())
      break;
    if (result.files_checked + result.folders_checked >= max_entries) {
      result.stopped_at_limit = true;
      break;
    }
    check(walk->path()); // symbolic links are listed, and the iterator does not follow them
    send(result.held.size() > held_sent);
  }

  const ProcessDirectory processes = ProcessDirectory::capture();
  for (const std::uint32_t pid : seen)
    result.holders.push_back(holder_for(pid, processes));
  if (result.processes_not_readable > 0 && geteuid() != 0) {
    result.note = std::to_string(result.processes_not_readable) +
                  " processes of other accounts could not be read; their open files are readable as root.";
  }
  return Result<FolderLockResult>::success(std::move(result));
}

Result<FileLockResult> find_file_holders(const std::string& file) {
  FileLockResult result;
  if (trim(file).empty())
    return Result<FileLockResult>::failure(lock_error(file, "no file was given"));
  std::error_code error;
  const std::filesystem::path path = std::filesystem::absolute(trim(file), error);
  result.file = path.string();
  struct stat target {};
  if (error || stat(result.file.c_str(), &target) != 0)
    return Result<FileLockResult>::failure(lock_error(result.file, "the file does not exist", errno));
  result.is_directory = S_ISDIR(target.st_mode);

  std::set<std::uint32_t> holders;
  const auto self = static_cast<std::uint32_t>(getpid());
  if (DIR* proc = opendir("/proc")) {
    while (const dirent* entry = readdir(proc)) {
      const std::string pid = entry->d_name;
      if (pid.empty() || pid.find_first_not_of("0123456789") != std::string::npos)
        continue;
      const auto number = static_cast<std::uint32_t>(std::strtoul(pid.c_str(), nullptr, 10));
      if (number == self)
        continue;
      const std::string base = "/proc/" + pid;
      if (result.is_directory && same_file(base + "/cwd", target)) {
        holders.insert(number);
        continue;
      }
      DIR* fds = opendir((base + "/fd").c_str());
      if (fds == nullptr) {
        if (errno == EACCES)
          ++result.processes_not_readable;
        continue;
      }
      while (const dirent* fd = readdir(fds)) {
        if (fd->d_name[0] == '.')
          continue;
        if (same_file(base + "/fd/" + fd->d_name, target)) {
          holders.insert(number);
          break;
        }
      }
      closedir(fds);
    }
    closedir(proc);
  }

  const ProcessDirectory processes = ProcessDirectory::capture();
  for (const std::uint32_t pid : holders)
    result.holders.push_back(holder_for(pid, processes));
  if (result.processes_not_readable > 0 && geteuid() != 0) {
    result.note = std::to_string(result.processes_not_readable) +
                  " processes of other accounts could not be read; their open files are readable as root.";
  }
  return Result<FileLockResult>::success(std::move(result));
}

} // namespace support_assist
