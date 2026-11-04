// Asks the volume that holds a folder for its file layout and hands the replies to the lister
// (Windows). The volume is opened for FILE_READ_DATA and FILE_READ_ATTRIBUTES and queried with
// FSCTL_QUERY_FILE_LAYOUT; NTFS answers from its own file table and no block of the disk is read
// through the handle. Opening a volume this way needs administrator rights. Other systems get a
// plain failure.

#include "support_assist/ntfs_mft.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winioctl.h>
#endif

namespace support_assist {

#ifdef _WIN32

namespace {

namespace at = ntfs_mft_detail::layout_offset;

// The reader takes the fields of the reply at fixed offsets; these fail the build when the SDK's
// structures say otherwise.
static_assert(sizeof(QUERY_FILE_LAYOUT_OUTPUT) == at::kOutputSize);
static_assert(offsetof(QUERY_FILE_LAYOUT_OUTPUT, FileEntryCount) == at::kOutputFileCount);
static_assert(offsetof(QUERY_FILE_LAYOUT_OUTPUT, FirstFileOffset) == at::kOutputFirstFile);
static_assert(sizeof(FILE_LAYOUT_ENTRY) == at::kEntrySize);
static_assert(offsetof(FILE_LAYOUT_ENTRY, NextFileOffset) == at::kEntryNext);
static_assert(offsetof(FILE_LAYOUT_ENTRY, FileAttributes) == at::kEntryAttributes);
static_assert(offsetof(FILE_LAYOUT_ENTRY, FileReferenceNumber) == at::kEntryReference);
static_assert(offsetof(FILE_LAYOUT_ENTRY, FirstNameOffset) == at::kEntryFirstName);
static_assert(offsetof(FILE_LAYOUT_ENTRY, FirstStreamOffset) == at::kEntryFirstStream);
static_assert(offsetof(FILE_LAYOUT_ENTRY, ExtraInfoOffset) == at::kEntryExtraInfo);
static_assert(at::kEntryExtraInfoLength + sizeof(DWORD) == sizeof(FILE_LAYOUT_ENTRY));
static_assert(offsetof(FILE_LAYOUT_NAME_ENTRY, NextNameOffset) == at::kNameNext);
static_assert(offsetof(FILE_LAYOUT_NAME_ENTRY, Flags) == at::kNameFlags);
static_assert(offsetof(FILE_LAYOUT_NAME_ENTRY, ParentFileReferenceNumber) == at::kNameParent);
static_assert(offsetof(FILE_LAYOUT_NAME_ENTRY, FileNameLength) == at::kNameLength);
static_assert(offsetof(FILE_LAYOUT_NAME_ENTRY, FileName) == at::kNameChars);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, NextStreamOffset) == at::kStreamNext);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, Flags) == at::kStreamFlags);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, AllocationSize) == at::kStreamAllocation);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, EndOfFile) == at::kStreamEndOfFile);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, AttributeTypeCode) == at::kStreamType);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, StreamIdentifierLength) == at::kStreamIdentifierLength);
static_assert(offsetof(STREAM_LAYOUT_ENTRY, StreamIdentifier) == at::kStreamIdentifier);
static_assert(offsetof(FILE_LAYOUT_INFO_ENTRY, BasicInformation.CreationTime) == at::kInfoCreation);
static_assert(offsetof(FILE_LAYOUT_INFO_ENTRY, BasicInformation.LastAccessTime) == at::kInfoAccess);
static_assert(offsetof(FILE_LAYOUT_INFO_ENTRY, BasicInformation.LastWriteTime) == at::kInfoWrite);
static_assert(offsetof(FILE_LAYOUT_INFO_ENTRY, BasicInformation.ChangeTime) == at::kInfoChange);
static_assert(offsetof(FILE_LAYOUT_INFO_ENTRY, BasicInformation.FileAttributes) == at::kInfoAttributes);
static_assert(at::kInfoAttributes + sizeof(DWORD) == at::kInfoBasicSize);
static_assert(QUERY_FILE_LAYOUT_RESTART == ntfs_mft_detail::kLayoutRestart);
static_assert(QUERY_FILE_LAYOUT_INCLUDE_NAMES == ntfs_mft_detail::kLayoutNames);
static_assert(QUERY_FILE_LAYOUT_INCLUDE_STREAMS == ntfs_mft_detail::kLayoutStreams);
static_assert(QUERY_FILE_LAYOUT_INCLUDE_EXTRA_INFO == ntfs_mft_detail::kLayoutExtraInfo);
static_assert(QUERY_FILE_LAYOUT_INCLUDE_STREAMS_WITH_NO_CLUSTERS_ALLOCATED == ntfs_mft_detail::kLayoutStreamsWithoutClusters);
static_assert(FILE_LAYOUT_NAME_ENTRY_PRIMARY == ntfs_mft_detail::kNamePrimary);
static_assert(FILE_LAYOUT_NAME_ENTRY_DOS == ntfs_mft_detail::kNameDos);

class Handle {
public:
  explicit Handle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
  ~Handle() {
    if (handle_ != INVALID_HANDLE_VALUE)
      CloseHandle(handle_);
  }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  [[nodiscard]] HANDLE get() const {
    return handle_;
  }
  [[nodiscard]] bool valid() const {
    return handle_ != INVALID_HANDLE_VALUE;
  }

private:
  HANDLE handle_;
};

constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// What Windows says about an error code, without the closing full stop and line break.
std::string windows_error_text(DWORD code) {
  wchar_t* message = nullptr;
  const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                          FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
  std::string text;
  if (length > 0 && message != nullptr)
    text = utf8_from_wide(std::wstring_view(message, length));
  if (message != nullptr)
    LocalFree(message);
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '.'))
    text.pop_back();
  if (text.empty())
    text = "Windows error " + std::to_string(code);
  return text;
}

// The volume a handle on one of its files lives on, as \\?\Volume{GUID}, and the name of the
// file the handle is on. The GUID names the volume whatever it is mounted as (a drive letter, a
// folder, or nothing) and follows a junction or symbolic link to the volume the folder really is
// on. Both are empty when Windows cannot name the volume.
struct VolumeName {
  std::wstring device;
  std::wstring leaf;
};

VolumeName volume_name_of(HANDLE handle) {
  std::wstring buffer(512U, L'\0');
  for (int attempt = 0; attempt < 2; ++attempt) {
    const DWORD length = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                   FILE_NAME_NORMALIZED | VOLUME_NAME_GUID);
    if (length == 0)
      return {};
    if (length < buffer.size()) {
      buffer.resize(length);
      break;
    }
    buffer.assign(static_cast<std::size_t>(length) + 1U, L'\0');
  }
  constexpr std::wstring_view kPrefix = L"\\\\?\\Volume{";
  if (buffer.compare(0, kPrefix.size(), kPrefix) != 0)
    return {};
  const std::size_t closing = buffer.find(L'}', kPrefix.size());
  if (closing == std::wstring::npos)
    return {};
  VolumeName name;
  name.device = buffer.substr(0, closing + 1U);
  std::wstring rest = buffer.substr(closing + 1U);
  while (!rest.empty() && rest.back() == L'\\')
    rest.pop_back();
  const std::size_t slash = rest.rfind(L'\\');
  name.leaf = slash == std::wstring::npos ? rest : rest.substr(slash + 1U);
  return name;
}

// The volume as a layout source. Each query is one DeviceIoControl call; the reply is the buffer
// NTFS filled. The end of a pass is ERROR_HANDLE_EOF. ERROR_MORE_DATA with files in the buffer
// means the buffer is full and more follows; with no file in it, the buffer is too small for the
// next one and the call is repeated with a larger buffer.
class VolumeLayout final : public ntfs_mft_detail::LayoutSource {
public:
  explicit VolumeLayout(HANDLE volume) : volume_(volume) {}

  ntfs_mft_detail::LayoutStatus query(std::uint32_t flags, std::vector<std::uint8_t>& reply) override {
    using ntfs_mft_detail::LayoutStatus;
    QUERY_FILE_LAYOUT_INPUT input = {};
    input.FilterEntryCount = 0;
    input.Flags = flags;
    input.FilterType = QUERY_FILE_LAYOUT_FILTER_TYPE_NONE;
    needs_elevation_ = false;
    for (;;) {
      reply.assign(capacity_, 0);
      DWORD returned = 0;
      if (DeviceIoControl(volume_, FSCTL_QUERY_FILE_LAYOUT, &input, sizeof(input), reply.data(),
                          static_cast<DWORD>(reply.size()), &returned, nullptr)) {
        if (returned < at::kOutputSize)
          return LayoutStatus::end;
        reply.resize(returned);
        return LayoutStatus::entries;
      }
      const DWORD code = GetLastError();
      if (code == ERROR_HANDLE_EOF)
        return LayoutStatus::end;
      if (code == ERROR_MORE_DATA) {
        std::uint32_t announced = 0;
        std::memcpy(&announced, reply.data() + at::kOutputFileCount, sizeof(announced));
        if (announced != 0U) {
          reply.resize(returned >= at::kOutputSize && returned <= reply.size() ? returned : reply.size());
          return LayoutStatus::entries;
        }
        if (capacity_ < kLargestReply) {
          capacity_ *= 2U;
          continue;
        }
        error_ = "one file's layout does not fit in " + std::to_string(kLargestReply >> 20U) + " MB";
        return LayoutStatus::failed;
      }
      needs_elevation_ = code == ERROR_ACCESS_DENIED;
      if (code == ERROR_ACCESS_DENIED)
        error_ = "this needs administrator rights";
      else if (code == ERROR_INVALID_FUNCTION)
        error_ = "this volume does not support the file layout query";
      else
        error_ = windows_error_text(code);
      return LayoutStatus::failed;
    }
  }

  [[nodiscard]] std::string error_text() const override {
    return error_;
  }

  [[nodiscard]] bool needs_elevation() const override {
    return needs_elevation_;
  }

private:
  static constexpr std::size_t kInitialReply = 2U << 20U;
  static constexpr std::size_t kLargestReply = 64U << 20U;

  HANDLE volume_;
  std::size_t capacity_ = kInitialReply;
  std::string error_;
  bool needs_elevation_ = false;
};

} // namespace

Result<std::uint64_t> read_mft_folder(const std::filesystem::path& folder, const CancellationToken& cancel,
                                      const MftVisit& visit, MftReadInfo* info) {
  using Outcome = Result<std::uint64_t>;
  if (info != nullptr)
    *info = MftReadInfo();
  const auto failure = [&folder](std::string operation, std::string message, DWORD code = 0,
                                 bool elevation_may_help = false) {
    Error error = ntfs_mft_detail::mft_error(std::move(operation), std::move(message), code, elevation_may_help);
    error.source = path_to_utf8(folder);
    return Outcome::failure(std::move(error));
  };
  if (folder.empty())
    return failure("open folder", "No folder was given.");

  Handle opened(CreateFileW(folder.c_str(), FILE_READ_ATTRIBUTES, kShareAll, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (!opened.valid()) {
    const DWORD code = GetLastError();
    return failure("open folder", "The folder could not be opened: " + windows_error_text(code) + ".", code,
                   code == ERROR_ACCESS_DENIED);
  }
  BY_HANDLE_FILE_INFORMATION details = {};
  if (!GetFileInformationByHandle(opened.get(), &details)) {
    const DWORD code = GetLastError();
    return failure("open folder", "The folder could not be read: " + windows_error_text(code) + ".", code);
  }
  if ((details.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0U)
    return failure("open folder", "The path is not a folder.");

  wchar_t file_system[MAX_PATH + 1] = {};
  DWORD short_serial = 0;
  if (!GetVolumeInformationByHandleW(opened.get(), nullptr, 0, &short_serial, nullptr, nullptr, file_system,
                                     MAX_PATH + 1)) {
    const DWORD code = GetLastError();
    return failure("open folder", "The volume could not be identified: " + windows_error_text(code) + ".", code);
  }
  if (std::wstring(file_system) != L"NTFS") {
    return failure("open volume", "The file layout is read on NTFS volumes; this volume is " +
                                      (file_system[0] == L'\0' ? std::string("not NTFS") : utf8_from_wide(file_system)) +
                                      ".");
  }
  const VolumeName volume_name = volume_name_of(opened.get());
  if (volume_name.device.empty())
    return failure("open volume", "The file layout is read on local NTFS volumes; this folder is not on one.");

  ntfs_mft_detail::MftFolder identity;
  identity.reference = (static_cast<std::uint64_t>(details.nFileIndexHigh) << 32U) | details.nFileIndexLow;
  identity.volume_serial = details.dwVolumeSerialNumber;
  FILE_ID_INFO file_id = {};
  if (GetFileInformationByHandleEx(opened.get(), FileIdInfo, &file_id, sizeof(file_id))) {
    std::uint64_t upper = 0;
    std::memcpy(&identity.reference, file_id.FileId.Identifier, sizeof(identity.reference));
    std::memcpy(&upper, file_id.FileId.Identifier + sizeof(identity.reference), sizeof(upper));
    if (upper != 0U)
      return failure("open volume", "The folder's file identifier is not an NTFS one.");
    identity.volume_serial = file_id.VolumeSerialNumber;
  }

  // What the open folder says about itself fills its own entry.
  FILE_BASIC_INFO basic = {};
  if (GetFileInformationByHandleEx(opened.get(), FileBasicInfo, &basic, sizeof(basic))) {
    identity.has_details = true;
    identity.details.attributes = basic.FileAttributes;
    identity.details.creation_100ns = basic.CreationTime.QuadPart;
    identity.details.access_100ns = basic.LastAccessTime.QuadPart;
    identity.details.write_100ns = basic.LastWriteTime.QuadPart;
    identity.details.change_100ns = basic.ChangeTime.QuadPart;
    identity.details.reparse = (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
    identity.details.hard_links = 1;
    identity.details.name = volume_name.leaf;
    FILE_STANDARD_INFO standard = {};
    if (GetFileInformationByHandleEx(opened.get(), FileStandardInfo, &standard, sizeof(standard))) {
      identity.details.allocation_size = static_cast<std::uint64_t>(standard.AllocationSize.QuadPart);
      identity.details.hard_links = standard.NumberOfLinks;
    }
  }

  Handle volume(CreateFileW(volume_name.device.c_str(), FILE_READ_DATA | FILE_READ_ATTRIBUTES, kShareAll, nullptr,
                            OPEN_EXISTING, 0, nullptr));
  if (!volume.valid()) {
    const DWORD code = GetLastError();
    if (code == ERROR_ACCESS_DENIED)
      return failure("open volume", "Listing a folder from the file layout needs administrator rights.", code, true);
    return failure("open volume", "The volume could not be opened: " + windows_error_text(code) + ".", code);
  }
  VolumeLayout source(volume.get());
  Outcome outcome = ntfs_mft_detail::read_folder_from_layout(source, identity, cancel, visit, info);
  if (!outcome.ok() && outcome.error().source.empty())
    outcome.error().source = path_to_utf8(folder);
  return outcome;
}

#else

Result<std::uint64_t> read_mft_folder(const std::filesystem::path&, const CancellationToken&, const MftVisit&,
                                      MftReadInfo* info) {
  if (info != nullptr)
    *info = MftReadInfo();
  return Result<std::uint64_t>::failure(
      ntfs_mft_detail::mft_error("list folder", "The file layout is read on Windows (NTFS) only."));
}

#endif

} // namespace support_assist
