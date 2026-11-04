#include "support_assist/filesystem.hpp"
#include "support_assist/ntfs_mft.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

class UniqueHandle {
public:
  explicit UniqueHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~UniqueHandle() {
    if (valid())
      CloseHandle(value_);
  }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;
  UniqueHandle(UniqueHandle&& other) noexcept
      : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
  UniqueHandle& operator=(UniqueHandle&& other) noexcept {
    if (this != &other) {
      if (valid())
        CloseHandle(value_);
      value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
    }
    return *this;
  }
  HANDLE get() const noexcept {
    return value_;
  }
  bool valid() const noexcept {
    return value_ != INVALID_HANDLE_VALUE && value_ != nullptr;
  }

private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

class FindHandle {
public:
  explicit FindHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~FindHandle() {
    if (valid())
      FindClose(value_);
  }
  FindHandle(const FindHandle&) = delete;
  FindHandle& operator=(const FindHandle&) = delete;
  HANDLE get() const noexcept {
    return value_;
  }
  bool valid() const noexcept {
    return value_ != INVALID_HANDLE_VALUE;
  }

private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

std::wstring extended_path(const std::filesystem::path& input) {
  std::wstring raw = input.native();
  if (raw.rfind(L"\\\\?\\", 0) == 0 || raw.rfind(L"\\\\.\\", 0) == 0)
    return raw;
  const DWORD required = GetFullPathNameW(raw.c_str(), 0, nullptr, nullptr);
  if (required == 0)
    return raw;
  std::wstring full(static_cast<std::size_t>(required), L'\0');
  const DWORD written = GetFullPathNameW(raw.c_str(), required, full.data(), nullptr);
  if (written == 0 || written >= required)
    return raw;
  full.resize(written);
  if (full.rfind(L"\\\\", 0) == 0)
    return L"\\\\?\\UNC\\" + full.substr(2);
  return L"\\\\?\\" + full;
}

std::int64_t filetime_100ns(const FILETIME& value) {
  ULARGE_INTEGER result{};
  result.LowPart = value.dwLowDateTime;
  result.HighPart = value.dwHighDateTime;
  return static_cast<std::int64_t>(result.QuadPart);
}

Error filesystem_error(std::string operation,
                       std::wstring_view source,
                       DWORD code,
                       bool skipped = true) {
  Error error;
  error.component = "Filesystem";
  error.operation = std::move(operation);
  error.source = utf8_from_wide(source);
  error.native_code = code;
  error.message = "Windows filesystem API returned error " + std::to_string(code);
  error.recoverable = true;
  error.elevation_may_help = code == ERROR_ACCESS_DENIED;
  error.skipped = skipped;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

bool wildcard_match(std::string_view pattern, std::string_view value) {
  std::size_t pattern_index = 0;
  std::size_t value_index = 0;
  std::size_t star = std::string_view::npos;
  std::size_t star_value = 0;
  while (value_index < value.size()) {
    const auto folded_pattern = pattern_index < pattern.size()
                                    ? static_cast<unsigned char>(std::tolower(
                                          static_cast<unsigned char>(pattern[pattern_index])))
                                    : 0;
    const auto folded_value =
        static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(value[value_index])));
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == '?' || folded_pattern == folded_value)) {
      ++pattern_index;
      ++value_index;
    } else if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      star = pattern_index++;
      star_value = value_index;
    } else if (star != std::string_view::npos) {
      pattern_index = star + 1;
      value_index = ++star_value;
    } else {
      return false;
    }
  }
  while (pattern_index < pattern.size() && pattern[pattern_index] == '*')
    ++pattern_index;
  return pattern_index == pattern.size();
}

bool excluded(const FilesystemScanOptions& options, std::string_view relative_path) {
  return std::any_of(
      options.exclusions.begin(), options.exclusions.end(), [&](const std::string& pattern) {
        return wildcard_match(pattern, relative_path);
      });
}

std::string file_id_hex(const FILE_ID_128& id) {
  return hex_encode(id.Identifier, sizeof(id.Identifier));
}

std::string stream_list_json(std::wstring_view path) {
  WIN32_FIND_STREAM_DATA stream{};
  const std::wstring owned_path(path);
  HANDLE raw = FindFirstStreamW(owned_path.c_str(), FindStreamInfoStandard, &stream, 0);
  if (raw == INVALID_HANDLE_VALUE)
    return "[]";
  FindHandle find(raw);
  std::ostringstream output;
  output << '[';
  bool first = true;
  do {
    if (!first)
      output << ',';
    first = false;
    output << "{\"name\":\"" << json_escape(utf8_from_wide(stream.cStreamName))
           << "\",\"size\":" << stream.StreamSize.QuadPart << '}';
  } while (FindNextStreamW(find.get(), &stream));
  output << ']';
  return output.str();
}

std::string extension_utf8(const std::filesystem::path& path) {
  const auto extension = path.extension().u8string();
  return std::string(reinterpret_cast<const char*>(extension.data()), extension.size());
}

bool should_hash(const FilesystemScanOptions& options,
                 const FilesystemRecord& record,
                 const std::filesystem::path& path) {
  if (record.object_type != "file")
    return false;
  switch (options.hash_mode) {
  case HashMode::none:
    return false;
  case HashMode::all:
    return true;
  case HashMode::below_size:
    return record.size <= options.hash_size_limit;
  case HashMode::extensions: {
    const std::string extension = ascii_lower(extension_utf8(path));
    return std::any_of(
        options.hash_extensions.begin(),
        options.hash_extensions.end(),
        [&](const std::string& configured) { return ascii_lower(configured) == extension; });
  }
  }
  return false;
}

struct Identity {
  std::uint64_t volume = 0;
  std::string file_id;
  bool operator==(const Identity& other) const noexcept {
    return volume == other.volume && file_id == other.file_id;
  }
};

struct IdentityHash {
  std::size_t operator()(const Identity& identity) const noexcept {
    return std::hash<std::uint64_t>{}(identity.volume) ^
           (std::hash<std::string>{}(identity.file_id) << 1U);
  }
};

struct DirectoryWork {
  std::wstring full_path;
  std::wstring relative_path;
  std::uint32_t depth = 0;
};

Result<Identity> followed_directory_identity(std::wstring_view path) {
  const std::wstring owned_path(path);
  UniqueHandle handle(CreateFileW(owned_path.c_str(),
                                  FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS,
                                  nullptr));
  if (!handle.valid()) {
    return Result<Identity>::failure(
        filesystem_error("open reparse target identity", path, GetLastError()));
  }
  FILE_ID_INFO identity{};
  if (!GetFileInformationByHandleEx(handle.get(), FileIdInfo, &identity, sizeof(identity))) {
    return Result<Identity>::failure(
        filesystem_error("query reparse target identity", path, GetLastError()));
  }
  return Result<Identity>::success(
      Identity{identity.VolumeSerialNumber, file_id_hex(identity.FileId)});
}

Status record_error(SnapshotBatchWriter& writer,
                    std::string_view snapshot_id,
                    const Error& error,
                    ScanSummary& summary) {
  auto status = writer.add_error(snapshot_id, error);
  if (status.ok())
    ++summary.errors;
  return status;
}

FilesystemRecord inspect_object(std::string_view snapshot_id,
                                const WIN32_FIND_DATAW& find_data,
                                std::wstring_view full_path,
                                std::wstring_view relative_path,
                                const FilesystemScanOptions& options,
                                const CancellationToken& cancel,
                                ScanSummary& summary,
                                SnapshotBatchWriter& writer) {
  FilesystemRecord record;
  record.snapshot_id = std::string(snapshot_id);
  record.relative_path = relative_path.empty() ? "." : utf8_from_wide(relative_path);
  record.source_path = utf8_from_wide(full_path);
  record.attributes = find_data.dwFileAttributes;
  record.reparse_point = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
  record.reparse_tag = find_data.dwReserved0;
  record.object_type =
      record.reparse_point
          ? "reparse"
          : ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 ? "directory" : "file");
  ULARGE_INTEGER size{};
  size.HighPart = find_data.nFileSizeHigh;
  size.LowPart = find_data.nFileSizeLow;
  record.size = size.QuadPart;
  record.creation_100ns = filetime_100ns(find_data.ftCreationTime);
  record.access_100ns = filetime_100ns(find_data.ftLastAccessTime);
  record.write_100ns = filetime_100ns(find_data.ftLastWriteTime);

  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  if (record.reparse_point)
    flags |= FILE_FLAG_OPEN_REPARSE_POINT;
  const std::wstring owned_path(full_path);
  UniqueHandle handle(CreateFileW(owned_path.c_str(),
                                  FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_EXISTING,
                                  flags,
                                  nullptr));
  if (!handle.valid()) {
    const DWORD error_code = GetLastError();
    record.access_result = static_cast<int>(error_code);
    record.enumeration_error = "CreateFileW for metadata failed";
    static_cast<void>(record_error(
        writer, snapshot_id, filesystem_error("open metadata", full_path, error_code), summary));
    return record;
  }

  FILE_BASIC_INFO basic{};
  if (GetFileInformationByHandleEx(handle.get(), FileBasicInfo, &basic, sizeof(basic))) {
    record.creation_100ns = basic.CreationTime.QuadPart;
    record.access_100ns = basic.LastAccessTime.QuadPart;
    record.write_100ns = basic.LastWriteTime.QuadPart;
    record.change_100ns = basic.ChangeTime.QuadPart;
    record.attributes = basic.FileAttributes;
  }
  FILE_STANDARD_INFO standard{};
  if (GetFileInformationByHandleEx(handle.get(), FileStandardInfo, &standard, sizeof(standard))) {
    record.allocation_size = static_cast<std::uint64_t>(standard.AllocationSize.QuadPart);
    record.hard_link_count = standard.NumberOfLinks;
  }
  FILE_ATTRIBUTE_TAG_INFO tag{};
  if (GetFileInformationByHandleEx(handle.get(), FileAttributeTagInfo, &tag, sizeof(tag))) {
    record.reparse_tag = tag.ReparseTag;
  }
  if (options.capture_file_identity) {
    FILE_ID_INFO identity{};
    if (GetFileInformationByHandleEx(handle.get(), FileIdInfo, &identity, sizeof(identity))) {
      record.volume_serial = identity.VolumeSerialNumber;
      record.file_id_hex = file_id_hex(identity.FileId);
    }
  }
  if (record.object_type == "directory") {
    FILE_CASE_SENSITIVE_INFO case_sensitive{};
    if (GetFileInformationByHandleEx(
            handle.get(), FileCaseSensitiveInfo, &case_sensitive, sizeof(case_sensitive))) {
      record.case_sensitive_directory =
          (case_sensitive.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR) != 0;
    }
  }
  if (options.capture_streams && record.object_type == "file") {
    record.streams_json = stream_list_json(full_path);
  }

  if (should_hash(options, record, std::filesystem::path(owned_path))) {
    bool recall = false;
#ifdef FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    recall = recall || ((record.attributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS) != 0);
#endif
#ifdef FILE_ATTRIBUTE_RECALL_ON_OPEN
    recall = recall || ((record.attributes & FILE_ATTRIBUTE_RECALL_ON_OPEN) != 0);
#endif
    if (recall && !options.hydrate_cloud_files) {
      record.hash_status = "skipped-cloud-placeholder";
    } else {
      auto hash = hash_file_sha256(std::filesystem::path(owned_path), cancel);
      if (hash.ok()) {
        record.content_hash = std::move(hash.value());
        record.hash_algorithm = "SHA-256";
        record.hash_status = "complete";
      } else {
        record.hash_status = "error";
        static_cast<void>(record_error(writer, snapshot_id, hash.error(), summary));
      }
    }
  }
  return record;
}

// The scan root without a trailing backslash, except where the backslash is the root itself: a
// drive (\\?\C:\), a volume GUID path (\\?\Volume{...}\) and a share (\\?\UNC\server\share\) keep it,
// and a bare drive gets it. \\?\C: is not a path the file API takes.
std::wstring normalized_scan_root(std::wstring root) {
  const std::wstring prefix = L"\\\\?\\";
  const auto is_root = [&](const std::wstring& path) {
    if (path.rfind(prefix, 0) != 0)
      return path.size() == 2 && path[1] == L':';
    const std::wstring rest = path.substr(prefix.size());
    if (rest.size() == 2 && rest[1] == L':')
      return true;
    if (rest.rfind(L"Volume{", 0) == 0 && !rest.empty() && rest.back() == L'}')
      return true;
    if (rest.rfind(L"UNC\\", 0) == 0)
      return std::count(rest.begin() + 4, rest.end(), L'\\') == 1;
    return false;
  };
  while (root.size() > 3 && root.back() == L'\\') {
    std::wstring trimmed = root.substr(0, root.size() - 1);
    if (is_root(trimmed))
      break;
    root = std::move(trimmed);
  }
  if (is_root(root))
    root.push_back(L'\\');
  return root;
}

Result<WIN32_FIND_DATAW> root_find_data(std::wstring_view root) {
  WIN32_FILE_ATTRIBUTE_DATA attributes{};
  const std::wstring path(root);
  if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes)) {
    return Result<WIN32_FIND_DATAW>::failure(
        filesystem_error("read root attributes", root, GetLastError()));
  }
  WIN32_FIND_DATAW data{};
  data.dwFileAttributes = attributes.dwFileAttributes;
  data.ftCreationTime = attributes.ftCreationTime;
  data.ftLastAccessTime = attributes.ftLastAccessTime;
  data.ftLastWriteTime = attributes.ftLastWriteTime;
  data.nFileSizeHigh = attributes.nFileSizeHigh;
  data.nFileSizeLow = attributes.nFileSizeLow;
  return Result<WIN32_FIND_DATAW>::success(data);
}

// One entry of a folder as GetFileInformationByHandleEx lists it: the find data the per-object path
// takes, and what the listing adds (change time, allocated size, the 128-bit file id).
struct FolderEntry {
  WIN32_FIND_DATAW find{};
  std::int64_t change_100ns = 0;
  std::uint64_t allocation_size = 0;
  FILE_ID_128 file_id{};
};

// Every entry of a folder, read in a few calls (FileIdExtdDirectoryInfo) instead of a file open
// per entry, and the folder's volume serial. False when the folder or its file system does not
// list this way (FAT, some network file systems); the caller then enumerates the folder entry by
// entry.
bool list_folder(const std::wstring& folder, std::vector<FolderEntry>& entries, std::uint64_t& volume_serial) {
  UniqueHandle handle(CreateFileW(folder.c_str(),
                                  FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr,
                                  OPEN_EXISTING,
                                  FILE_FLAG_BACKUP_SEMANTICS,
                                  nullptr));
  if (!handle.valid())
    return false;
  FILE_ID_INFO identity{};
  if (!GetFileInformationByHandleEx(handle.get(), FileIdInfo, &identity, sizeof(identity)))
    return false;
  volume_serial = identity.VolumeSerialNumber;
  // 8-byte aligned, as the listing's records require.
  std::vector<std::uint64_t> buffer(64U * 1024U / sizeof(std::uint64_t));
  bool first = true;
  for (;;) {
    if (!GetFileInformationByHandleEx(handle.get(), first ? FileIdExtdDirectoryRestartInfo : FileIdExtdDirectoryInfo,
                                      buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(std::uint64_t)))) {
      const DWORD code = GetLastError();
      if (code == ERROR_NO_MORE_FILES)
        return true;
      entries.clear();
      return false;
    }
    first = false;
    const auto* bytes = reinterpret_cast<const unsigned char*>(buffer.data());
    for (std::size_t offset = 0;;) {
      const auto* info = reinterpret_cast<const FILE_ID_EXTD_DIR_INFO*>(bytes + offset);
      FolderEntry entry;
      const std::size_t length = std::min<std::size_t>(info->FileNameLength / sizeof(wchar_t), MAX_PATH - 1U);
      std::wmemcpy(entry.find.cFileName, info->FileName, length);
      entry.find.cFileName[length] = L'\0';
      entry.find.dwFileAttributes = info->FileAttributes;
      entry.find.ftCreationTime = {static_cast<DWORD>(info->CreationTime.LowPart),
                                   static_cast<DWORD>(info->CreationTime.HighPart)};
      entry.find.ftLastAccessTime = {static_cast<DWORD>(info->LastAccessTime.LowPart),
                                     static_cast<DWORD>(info->LastAccessTime.HighPart)};
      entry.find.ftLastWriteTime = {static_cast<DWORD>(info->LastWriteTime.LowPart),
                                    static_cast<DWORD>(info->LastWriteTime.HighPart)};
      entry.find.nFileSizeLow = info->EndOfFile.LowPart;
      entry.find.nFileSizeHigh = static_cast<DWORD>(info->EndOfFile.HighPart);
      entry.find.dwReserved0 = (info->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ? info->ReparsePointTag : 0;
      entry.change_100ns = info->ChangeTime.QuadPart;
      entry.allocation_size = static_cast<std::uint64_t>(info->AllocationSize.QuadPart);
      entry.file_id = info->FileId;
      // A name longer than the find data holds goes the per-object way, which builds its path from it.
      if (info->FileNameLength / sizeof(wchar_t) < MAX_PATH)
        entries.push_back(entry);
      else {
        entries.clear();
        return false;
      }
      if (info->NextEntryOffset == 0)
        break;
      offset += info->NextEntryOffset;
    }
  }
}

// A plain file's record from its folder entry, without opening it. The hard-link count is not in
// the listing, so it reads 0 (not read); a compare does not count that as a change.
FilesystemRecord listed_file_record(std::string_view snapshot_id, const FolderEntry& entry, std::wstring_view full_path,
                                    std::wstring_view relative_path, std::uint64_t volume_serial,
                                    const FilesystemScanOptions& options) {
  FilesystemRecord record;
  record.snapshot_id = std::string(snapshot_id);
  record.relative_path = utf8_from_wide(relative_path);
  record.source_path = utf8_from_wide(full_path);
  record.object_type = "file";
  record.attributes = entry.find.dwFileAttributes;
  ULARGE_INTEGER size{};
  size.HighPart = entry.find.nFileSizeHigh;
  size.LowPart = entry.find.nFileSizeLow;
  record.size = size.QuadPart;
  record.allocation_size = entry.allocation_size;
  record.creation_100ns = filetime_100ns(entry.find.ftCreationTime);
  record.access_100ns = filetime_100ns(entry.find.ftLastAccessTime);
  record.write_100ns = filetime_100ns(entry.find.ftLastWriteTime);
  record.change_100ns = entry.change_100ns;
  if (options.capture_file_identity) {
    record.volume_serial = volume_serial;
    record.file_id_hex = file_id_hex(entry.file_id);
  }
  return record;
}

// ---- The master file table ------------------------------------------------------------------
//
// Elevated, on a local NTFS volume, the folder is read from the NTFS master file table
// (ntfs_mft.hpp) instead of folder by folder. A file's and a folder's record come from the
// table; a reparse point and a file whose contents are read are opened as the listing opens them.

// The find data the per-object path starts from, for a table entry.
WIN32_FIND_DATAW find_data_from_entry(const MftEntry& entry) {
  const auto filetime = [](std::int64_t value) {
    const auto bits = static_cast<std::uint64_t>(value);
    return FILETIME{static_cast<DWORD>(bits & 0xFFFFFFFFULL), static_cast<DWORD>(bits >> 32U)};
  };
  WIN32_FIND_DATAW data{};
  const std::size_t length = std::min<std::size_t>(entry.name.size(), MAX_PATH - 1U);
  std::wmemcpy(data.cFileName, entry.name.data(), length);
  data.cFileName[length] = L'\0';
  data.dwFileAttributes = entry.attributes;
  data.ftCreationTime = filetime(entry.creation_100ns);
  data.ftLastAccessTime = filetime(entry.access_100ns);
  data.ftLastWriteTime = filetime(entry.write_100ns);
  data.nFileSizeLow = static_cast<DWORD>(entry.size & 0xFFFFFFFFULL);
  data.nFileSizeHigh = static_cast<DWORD>(entry.size >> 32U);
  data.dwReserved0 = entry.reparse_tag;
  return data;
}

// A plain file's or a folder's record from its table entry. On NTFS the 128-bit file id is the
// 64-bit file reference followed by zeros, as GetFileInformationByHandleEx(FileIdInfo) gives it.
FilesystemRecord mft_file_record(std::string_view snapshot_id, const MftEntry& entry, std::wstring_view full_path,
                                 std::wstring_view relative_path, std::uint64_t volume_serial,
                                 const FilesystemScanOptions& options) {
  FilesystemRecord record;
  record.snapshot_id = std::string(snapshot_id);
  record.relative_path = utf8_from_wide(relative_path);
  record.source_path = utf8_from_wide(full_path);
  record.object_type = entry.directory ? "directory" : "file";
  record.attributes = entry.attributes;
  record.size = entry.directory ? 0U : entry.size;
  record.allocation_size = entry.directory ? 0U : entry.allocation_size;
  record.creation_100ns = entry.creation_100ns;
  record.access_100ns = entry.access_100ns;
  record.write_100ns = entry.write_100ns;
  record.change_100ns = entry.change_100ns;
  record.hard_link_count = entry.hard_links;
  if (options.capture_file_identity) {
    FILE_ID_128 id{};
    static_assert(sizeof(entry.record) <= sizeof(id.Identifier));
    std::memcpy(id.Identifier, &entry.record, sizeof(entry.record));
    record.volume_serial = volume_serial;
    record.file_id_hex = file_id_hex(id);
  }
  return record;
}

// Whether a path, or a folder it lies in, is excluded. The table hands entries over in no folder
// order, so an excluded folder's contents are found by their own paths.
bool excluded_or_under(const FilesystemScanOptions& options, std::string_view relative_path) {
  if (options.exclusions.empty())
    return false;
  for (std::size_t at = relative_path.find('\\'); at != std::string_view::npos; at = relative_path.find('\\', at + 1U)) {
    if (excluded(options, relative_path.substr(0, at)))
      return true;
  }
  return excluded(options, relative_path);
}

Result<std::int64_t> highest_row_id(SnapshotStore& store, const char* sql, std::string_view snapshot_id) {
  auto query = store.db().prepare(sql);
  if (!query.ok())
    return Result<std::int64_t>::failure(query.error());
  if (auto status = query.value().bind(1, snapshot_id); !status.ok())
    return Result<std::int64_t>::failure(status.error());
  auto row = query.value().step();
  if (!row.ok())
    return Result<std::int64_t>::failure(row.error());
  return Result<std::int64_t>::success(row.value() ? query.value().column_int64(0) : 0);
}

Status remove_rows_after(SnapshotStore& store, const char* sql, std::string_view snapshot_id, std::int64_t after) {
  auto statement = store.db().prepare(sql);
  if (!statement.ok())
    return Status::failure(statement.error());
  if (auto status = statement.value().bind(1, snapshot_id); !status.ok())
    return status;
  if (auto status = statement.value().bind(2, after); !status.ok())
    return status;
  auto row = statement.value().step();
  return row.ok() ? Status::success() : Status::failure(row.error());
}

struct MftScan {
  bool used = false;      // the folder was read from the table (or the read was cancelled)
  std::string why_not;    // why it was not
  std::optional<Error> failure; // a write that failed: the scan fails
};

// Reads everything under the root from the master file table. When the table cannot be read, what
// this wrote is removed again and `why_not` says why, so the caller lists the folder instead.
MftScan scan_from_mft(SnapshotStore& store, SnapshotBatchWriter& writer, std::string_view snapshot_id,
                      const FilesystemScanOptions& options, const std::wstring& root, std::uint64_t volume_serial,
                      const CancellationToken& cancel, const ProgressCallback& progress,
                      std::chrono::steady_clock::time_point started, ScanSummary& summary) {
  MftScan scan;
  // What is in the file before the table is read, so a read that fails part way can be taken out.
  if (auto status = writer.flush(); !status.ok()) {
    scan.failure = status.error();
    return scan;
  }
  auto objects_before =
      highest_row_id(store, "SELECT COALESCE(MAX(id),0) FROM filesystem_objects WHERE snapshot_id=?;", snapshot_id);
  auto errors_before =
      highest_row_id(store, "SELECT COALESCE(MAX(id),0) FROM scan_errors WHERE snapshot_id=?;", snapshot_id);
  if (!objects_before.ok() || !errors_before.ok()) {
    scan.failure = objects_before.ok() ? errors_before.error() : objects_before.error();
    return scan;
  }
  const ScanSummary summary_before = summary;

  std::optional<Error> write_failure;
  bool handed_over = false;
  const auto visit = [&](const MftEntry& entry, const std::wstring& relative_path) -> bool {
    if (cancel.is_cancelled()) {
      summary.cancelled = true;
      return false;
    }
    if (relative_path.empty())
      return true; // the root, recorded already
    handed_over = true;
    const auto separators = static_cast<std::uint64_t>(std::count(relative_path.begin(), relative_path.end(), L'\\'));
    if (separators > options.maximum_depth)
      return true;
    const std::string relative_utf8 = utf8_from_wide(relative_path);
    if (excluded_or_under(options, relative_utf8))
      return true;
    std::wstring full_path = root;
    if (full_path.back() != L'\\')
      full_path.push_back(L'\\');
    full_path += relative_path;

    // Files and folders come from the table; a reparse point, and a file whose contents are read,
    // are opened.
    std::optional<FilesystemRecord> listed_record;
    if (!entry.reparse) {
      listed_record = mft_file_record(snapshot_id, entry, full_path, relative_path, volume_serial, options);
      if (!entry.directory && should_hash(options, *listed_record, std::filesystem::path(full_path)))
        listed_record.reset();
    }
    auto record = listed_record ? std::move(*listed_record)
                                : inspect_object(snapshot_id, find_data_from_entry(entry), full_path, relative_path,
                                                 options, cancel, summary, writer);
    if (auto status = writer.add_filesystem_object(record); !status.ok()) {
      write_failure = status.error();
      return false;
    }
    ++summary.objects;
    if (summary.objects >= options.maximum_objects) {
      summary.cancelled = true;
      return false;
    }
    if (progress && summary.objects % 1000 == 0) {
      const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      progress(ProgressEvent{"filesystem-scan", record.source_path, summary.objects, summary.errors, elapsed,
                             elapsed > 0.0 ? static_cast<double>(summary.objects) / elapsed : 0.0});
    }
    return true;
  };

  auto read = read_mft_folder(std::filesystem::path(root), cancel, visit);
  if (write_failure) {
    scan.failure = std::move(write_failure);
    return scan;
  }
  if (read.ok() || summary.cancelled || cancel.is_cancelled()) {
    summary.cancelled = summary.cancelled || cancel.is_cancelled();
    scan.used = true;
    return scan;
  }
  scan.why_not = read.error().elevation_may_help ? std::string("SAT is not running as administrator")
                                                 : read.error().message;
  if (handed_over) {
    if (auto status = writer.flush(); !status.ok()) {
      scan.failure = status.error();
      return scan;
    }
    if (auto status = remove_rows_after(store, "DELETE FROM filesystem_objects WHERE snapshot_id=? AND id>?;",
                                        snapshot_id, objects_before.value());
        !status.ok()) {
      scan.failure = status.error();
      return scan;
    }
    if (auto status = remove_rows_after(store, "DELETE FROM scan_errors WHERE snapshot_id=? AND id>?;", snapshot_id,
                                        errors_before.value());
        !status.ok()) {
      scan.failure = status.error();
      return scan;
    }
    summary = summary_before;
  }
  return scan;
}

} // namespace

Result<ScanSummary> scan_filesystem(SnapshotStore& store,
                                    std::string_view snapshot_id,
                                    const FilesystemScanOptions& options,
                                    const CancellationToken& cancel,
                                    ProgressCallback progress) {
  if (options.root.empty()) {
    Error error;
    error.component = "Filesystem";
    error.operation = "scan";
    error.message = "No root path was selected";
    return Result<ScanSummary>::failure(std::move(error));
  }
  auto batch = SnapshotBatchWriter::create(store, options.batch_size);
  if (!batch.ok())
    return Result<ScanSummary>::failure(batch.error());
  auto writer = std::move(batch.value());
  ScanSummary summary;
  const auto started = std::chrono::steady_clock::now();

  const std::wstring root = normalized_scan_root(extended_path(options.root));
  auto root_data = root_find_data(root);
  if (!root_data.ok())
    return Result<ScanSummary>::failure(root_data.error());
  auto root_record =
      inspect_object(snapshot_id, root_data.value(), root, L"", options, cancel, summary, writer);
  if (auto status = writer.add_filesystem_object(root_record); !status.ok()) {
    return Result<ScanSummary>::failure(status.error());
  }
  ++summary.objects;

  std::vector<DirectoryWork> stack;
  std::unordered_set<Identity, IdentityHash> visited;
  bool descend_root = root_record.object_type == "directory";
  if (descend_root && root_record.reparse_point) {
    descend_root = options.follow_reparse_points;
    if (descend_root) {
      auto target_identity = followed_directory_identity(root);
      if (target_identity.ok()) {
        visited.insert(std::move(target_identity.value()));
      } else {
        descend_root = false;
        if (auto status = record_error(writer, snapshot_id, target_identity.error(), summary);
            !status.ok()) {
          return Result<ScanSummary>::failure(status.error());
        }
      }
    }
  } else if (descend_root && !root_record.file_id_hex.empty()) {
    visited.insert(Identity{root_record.volume_serial, root_record.file_id_hex});
  }
  // The master file table first, when it may be used; the folder listing below otherwise.
  summary.source = kCaptureSourceListing;
  if (descend_root && options.try_mft && !root_record.reparse_point && !options.follow_reparse_points &&
      !options.capture_streams) {
    MftScan mft = scan_from_mft(store, writer, snapshot_id, options, root, root_record.volume_serial, cancel, progress,
                                started, summary);
    if (mft.failure)
      return Result<ScanSummary>::failure(*mft.failure);
    if (mft.used) {
      summary.source = kCaptureSourceMft;
      descend_root = false;
    } else {
      summary.source_note = mft.why_not;
    }
  }
  if (descend_root) {
    stack.push_back(DirectoryWork{root, L"", 0});
  }

  while (!stack.empty()) {
    if (cancel.is_cancelled()) {
      summary.cancelled = true;
      break;
    }
    // The object limit, or a cancel seen inside the last folder, ends the walk here too.
    if (summary.cancelled)
      break;
    DirectoryWork directory = std::move(stack.back());
    stack.pop_back();
    if (directory.depth > options.maximum_depth)
      continue;

    // One entry of the folder: recorded, counted, and queued when it is a folder to descend.
    // Returns false when the walk stops (cancelled, the object limit, or a failed write).
    std::optional<Error> write_failure;
    const auto visit = [&](const WIN32_FIND_DATAW& find_data, const FolderEntry* listed,
                           std::uint64_t listed_volume) -> bool {
      if (cancel.is_cancelled()) {
        summary.cancelled = true;
        return false;
      }
      if (std::wcscmp(find_data.cFileName, L".") == 0 || std::wcscmp(find_data.cFileName, L"..") == 0)
        return true;
      std::wstring full_path = directory.full_path;
      if (full_path.back() != L'\\')
        full_path.push_back(L'\\');
      full_path += find_data.cFileName;
      std::wstring relative_path = directory.relative_path;
      if (!relative_path.empty())
        relative_path.push_back(L'\\');
      relative_path += find_data.cFileName;
      const std::string relative_utf8 = utf8_from_wide(relative_path);
      if (excluded(options, relative_utf8))
        return true;

      const bool is_directory = (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
      const bool is_reparse = (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
      // A plain file from the listing needs no open of its own unless its contents or streams are read.
      std::optional<FilesystemRecord> listed_record;
      if (listed != nullptr && !is_directory && !is_reparse && !options.capture_streams) {
        listed_record = listed_file_record(snapshot_id, *listed, full_path, relative_path, listed_volume, options);
        if (should_hash(options, *listed_record, std::filesystem::path(full_path)))
          listed_record.reset();
      }
      auto record = listed_record ? std::move(*listed_record)
                                  : inspect_object(snapshot_id, find_data, full_path, relative_path, options, cancel,
                                                   summary, writer);
      if (auto status = writer.add_filesystem_object(record); !status.ok()) {
        write_failure = status.error();
        return false;
      }
      ++summary.objects;
      if (summary.objects >= options.maximum_objects) {
        summary.cancelled = true;
        return false;
      }

      if (is_directory && (!is_reparse || options.follow_reparse_points)) {
        bool descend = true;
        if (is_reparse) {
          auto target_identity = followed_directory_identity(full_path);
          if (!target_identity.ok()) {
            descend = false;
            if (auto status = record_error(writer, snapshot_id, target_identity.error(), summary); !status.ok()) {
              write_failure = status.error();
              return false;
            }
          } else {
            descend = visited.insert(std::move(target_identity.value())).second;
          }
        }
        if (descend) {
          stack.push_back(DirectoryWork{std::move(full_path), std::move(relative_path), directory.depth + 1});
        }
      }

      if (progress && summary.objects % 1000 == 0) {
        const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        progress(ProgressEvent{"filesystem-scan", record.source_path, summary.objects, summary.errors, elapsed,
                               elapsed > 0.0 ? static_cast<double>(summary.objects) / elapsed : 0.0});
      }
      return true;
    };

    std::vector<FolderEntry> listed_entries;
    std::uint64_t listed_volume = 0;
    if (list_folder(directory.full_path, listed_entries, listed_volume)) {
      for (const FolderEntry& entry : listed_entries) {
        if (!visit(entry.find, &entry, listed_volume))
          break;
      }
      if (write_failure)
        return Result<ScanSummary>::failure(*write_failure);
      continue;
    }

    std::wstring pattern = directory.full_path;
    if (!pattern.empty() && pattern.back() != L'\\')
      pattern.push_back(L'\\');
    pattern.push_back(L'*');
    WIN32_FIND_DATAW find_data{};
    HANDLE raw_find = FindFirstFileExW(pattern.c_str(),
                                       FindExInfoBasic,
                                       &find_data,
                                       FindExSearchNameMatch,
                                       nullptr,
                                       FIND_FIRST_EX_LARGE_FETCH);
    if (raw_find == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER) {
      raw_find = FindFirstFileExW(
          pattern.c_str(), FindExInfoBasic, &find_data, FindExSearchNameMatch, nullptr, 0);
    }
    if (raw_find == INVALID_HANDLE_VALUE) {
      const DWORD code = GetLastError();
      if (auto status =
              record_error(writer,
                           snapshot_id,
                           filesystem_error("enumerate directory", directory.full_path, code),
                           summary);
          !status.ok()) {
        return Result<ScanSummary>::failure(status.error());
      }
      continue;
    }
    FindHandle find(raw_find);

    bool walking = true;
    do {
      walking = visit(find_data, nullptr, 0);
    } while (walking && FindNextFileW(find.get(), &find_data));
    if (write_failure)
      return Result<ScanSummary>::failure(*write_failure);

    const DWORD end_error = GetLastError();
    if (end_error != ERROR_NO_MORE_FILES && !summary.cancelled) {
      if (auto status = record_error(
              writer,
              snapshot_id,
              filesystem_error("continue directory enumeration", directory.full_path, end_error),
              summary);
          !status.ok()) {
        return Result<ScanSummary>::failure(status.error());
      }
    }
  }

  if (auto status = writer.finish(); !status.ok()) {
    return Result<ScanSummary>::failure(status.error());
  }
  return Result<ScanSummary>::success(summary);
}

} // namespace support_assist
