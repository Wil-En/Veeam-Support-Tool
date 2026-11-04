#pragma once

// Lists every file and folder under one folder of a local NTFS volume from NTFS's own file table,
// for System Differences captures.
//
// Run as administrator, it asks the volume for its file layout (FSCTL_QUERY_FILE_LAYOUT) instead of
// asking the file system for each directory in turn. The reply carries, for every file record, its
// names with their parent folders, the times and attributes from $STANDARD_INFORMATION and the
// size of the unnamed data stream. NTFS builds the reply, so it is current and nothing is read
// from the disk's blocks. The folder tree is rebuilt from the parent references.
//
// Decoding the reply, building the tree and listing the folder are here and in ntfs_mft.cpp and use
// no system calls: they work on a LayoutSource, which the tests back with a model of a volume.
// ntfs_mft_win.cpp opens the volume and supplies the source; other systems get a plain failure.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// One name of one file or folder. A file with several hard links is reported once per link, each
// with its own parent and name and the same record.
struct MftEntry {
  std::uint64_t record = 0; // the file reference: record number | sequence << 48
  std::uint64_t parent = 0; // the reference of the folder holding this name
  std::wstring name;
  std::uint32_t attributes = 0; // FILE_ATTRIBUTE_* as NTFS reports them
  std::int64_t creation_100ns = 0; // FILETIME values: 100 ns since 1601-01-01 UTC
  std::int64_t write_100ns = 0;
  std::int64_t change_100ns = 0;
  std::int64_t access_100ns = 0;
  std::uint64_t size = 0; // the unnamed data stream; 0 for a folder
  std::uint64_t allocation_size = 0; // space the stream takes on disk; 0 while the data lives inside the record
  std::uint32_t hard_links = 0; // the record's names that are not DOS-only
  bool reparse = false;
  std::uint32_t reparse_tag = 0; // always 0: the layout reply does not carry it, so a caller that needs it opens the file
  bool directory = false;
};

// What a read found and how long it took.
struct MftReadInfo {
  std::uint64_t volume_serial = 0; // of the volume holding the folder
  std::uint64_t records_total = 0; // file records the second pass saw
  std::uint64_t entries = 0; // entries handed to the visitor
  std::uint64_t calls = 0; // times the volume was asked for the next part of the layout
  std::uint64_t elapsed_milliseconds = 0;
};

using MftVisit = std::function<bool(const MftEntry&, const std::wstring& relative_path)>;

// Lists the folder itself first (relative path empty) and then everything under it (relative paths
// with backslashes, no leading separator). The visitor returns false to stop; the entries counted
// so far are returned. The result is the number of entries handed over.
//
// Fails, with the reason in the message, off Windows, for a folder that is not on a local NTFS
// volume, without administrator rights (elevation_may_help is set) and on any error from the
// volume, so the caller can list the folder through the file system instead. A cancelled read
// fails too.
Result<std::uint64_t> read_mft_folder(const std::filesystem::path& folder, const CancellationToken& cancel,
                                      const MftVisit& visit, MftReadInfo* info = nullptr);

namespace ntfs_mft_detail {

// A file reference holds the record number in its low 48 bits and the sequence number above.
inline constexpr std::uint64_t kReferenceNumberMask = 0x0000FFFFFFFFFFFFULL;
inline constexpr std::uint64_t kRootRecord = 5U;
inline constexpr std::uint64_t kFirstUserRecord = 24U; // records below this, other than the root, are NTFS's own files

inline std::uint64_t reference_number(std::uint64_t reference) noexcept {
  return reference & kReferenceNumberMask;
}
inline std::uint16_t reference_sequence(std::uint64_t reference) noexcept {
  return static_cast<std::uint16_t>(reference >> 48U);
}
inline std::uint64_t make_reference(std::uint64_t number, std::uint16_t sequence) noexcept {
  return (number & kReferenceNumberMask) | (static_cast<std::uint64_t>(sequence) << 48U);
}

// Flags of the layout query (the QUERY_FILE_LAYOUT_* values of winioctl.h).
inline constexpr std::uint32_t kLayoutRestart = 0x01U;
inline constexpr std::uint32_t kLayoutNames = 0x02U;
inline constexpr std::uint32_t kLayoutStreams = 0x04U;
inline constexpr std::uint32_t kLayoutExtraInfo = 0x10U;
inline constexpr std::uint32_t kLayoutStreamsWithoutClusters = 0x20U;

// Flags of a name entry (FILE_LAYOUT_NAME_ENTRY_*).
inline constexpr std::uint32_t kNamePrimary = 0x01U;
inline constexpr std::uint32_t kNameDos = 0x02U;

inline constexpr std::uint32_t kAttributeDirectory = 0x10U;
inline constexpr std::uint32_t kAttributeReparsePoint = 0x400U;
inline constexpr std::uint32_t kDataAttributeType = 0x80U;

// Where the fields are in the reply, in bytes. ntfs_mft_win.cpp checks each against the SDK's
// structures.
namespace layout_offset {
// QUERY_FILE_LAYOUT_OUTPUT
inline constexpr std::size_t kOutputFileCount = 0;
inline constexpr std::size_t kOutputFirstFile = 4;
inline constexpr std::size_t kOutputSize = 16;
// FILE_LAYOUT_ENTRY
inline constexpr std::size_t kEntryNext = 4;
inline constexpr std::size_t kEntryAttributes = 12;
inline constexpr std::size_t kEntryReference = 16;
inline constexpr std::size_t kEntryFirstName = 24;
inline constexpr std::size_t kEntryFirstStream = 28;
inline constexpr std::size_t kEntryExtraInfo = 32;
inline constexpr std::size_t kEntryExtraInfoLength = 36;
inline constexpr std::size_t kEntrySize = 40;
// FILE_LAYOUT_NAME_ENTRY
inline constexpr std::size_t kNameNext = 0;
inline constexpr std::size_t kNameFlags = 4;
inline constexpr std::size_t kNameParent = 8;
inline constexpr std::size_t kNameLength = 16;
inline constexpr std::size_t kNameChars = 24;
// STREAM_LAYOUT_ENTRY
inline constexpr std::size_t kStreamNext = 4;
inline constexpr std::size_t kStreamFlags = 8;
inline constexpr std::size_t kStreamAllocation = 16;
inline constexpr std::size_t kStreamEndOfFile = 24;
inline constexpr std::size_t kStreamType = 36;
inline constexpr std::size_t kStreamIdentifierLength = 44;
inline constexpr std::size_t kStreamIdentifier = 48;
// FILE_LAYOUT_INFO_ENTRY: BasicInformation
inline constexpr std::size_t kInfoCreation = 0;
inline constexpr std::size_t kInfoAccess = 8;
inline constexpr std::size_t kInfoWrite = 16;
inline constexpr std::size_t kInfoChange = 24;
inline constexpr std::size_t kInfoAttributes = 32;
inline constexpr std::size_t kInfoBasicSize = 36; // bytes of the entry the reader needs
} // namespace layout_offset

// One name of a file in the reply. `chars` points into the reply: UTF-16, little endian.
struct LayoutName {
  std::uint32_t flags = 0;
  std::uint64_t parent = 0;
  const std::uint8_t* chars = nullptr;
  std::size_t units = 0;
};

struct LayoutStream {
  std::uint32_t type = 0;
  std::uint32_t flags = 0;
  std::uint64_t allocation = 0;
  std::uint64_t end_of_file = 0;
  const std::uint8_t* identifier = nullptr;
  std::size_t identifier_units = 0;
};

// One file in the reply. It is valid while the reply it points into is, and only inside the call
// that is handed it.
struct LayoutFile {
  std::uint64_t reference = 0;
  std::uint32_t attributes = 0; // of the file layout entry
  bool has_info = false; // the extra information was returned
  std::int64_t creation_100ns = 0;
  std::int64_t access_100ns = 0;
  std::int64_t write_100ns = 0;
  std::int64_t change_100ns = 0;
  std::uint32_t info_attributes = 0;
  std::vector<LayoutName> names;
  std::vector<LayoutStream> streams;
};

enum class LayoutParse { ok, stopped, malformed };

using LayoutEach = std::function<bool(const LayoutFile&)>;

// Walks one reply of the layout query and hands each file to `each`, which returns false to stop.
// Every offset and length is checked against the end of the reply; a reply that does not hold
// together is malformed, with the reason in *why, and nothing past its end is read. *count is the
// number of files handed over.
LayoutParse parse_layout_buffer(std::span<const std::uint8_t> buffer, const LayoutEach& each,
                                std::string* why = nullptr, std::uint32_t* count = nullptr);

// Which of a file's names are listed: every name except a DOS-only one (DOS without primary), and a
// DOS-only name when it is the only name in its parent folder. Indexes into file.names.
std::vector<std::size_t> listed_layout_names(const LayoutFile& file);

// True for the unnamed $DATA stream: attribute 0x80 with no stream name (NTFS writes ::$DATA).
bool is_unnamed_data_stream(const LayoutStream& stream);

// The size and allocated size of the unnamed data stream. False when the file has none.
bool unnamed_data_sizes(const LayoutFile& file, std::uint64_t& size, std::uint64_t& allocation);

// The entry for one of a file's listed names; `links` is how many names the file lists.
MftEntry make_layout_entry(const LayoutFile& file, const LayoutName& name, std::size_t links);

// UTF-16 units as a wide string (a surrogate pair becomes one character where wchar_t is 32 bit).
std::wstring wide_from_utf16(std::u16string_view text);

// The text of a name or stream identifier in the reply.
std::u16string layout_text(const std::uint8_t* chars, std::size_t units);

// NTFS's own files that sit in the root folder and are not listed ($MFT, $Extend and so on).
bool is_metafile_name(std::u16string_view name);

// ---- The volume ----------------------------------------------------------------------------

enum class LayoutStatus { entries, end, failed };

// Where the replies come from: the volume, or a model of one.
class LayoutSource {
public:
  LayoutSource() = default;
  LayoutSource(const LayoutSource&) = delete;
  LayoutSource& operator=(const LayoutSource&) = delete;
  virtual ~LayoutSource() = default;
  // One call of the query with `flags` (kLayoutRestart on the first call of a pass). On entries
  // the reply is left in `reply`; end means there are no more files in this pass.
  virtual LayoutStatus query(std::uint32_t flags, std::vector<std::uint8_t>& reply) = 0;
  // Why the last query failed.
  [[nodiscard]] virtual std::string error_text() const {
    return {};
  }
  [[nodiscard]] virtual bool needs_elevation() const {
    return false;
  }
};

// The folder as the caller knows it. `details` is what the open folder says about itself (times,
// attributes, link count, and its name when the layout does not give one); it is used for the
// first entry when has_details is set.
struct MftFolder {
  std::uint64_t reference = 0; // the file reference as the file system reports it
  std::uint64_t volume_serial = 0;
  MftEntry details;
  bool has_details = false;
};

// The whole read over a layout source: a first pass for the folders, a second for everything under
// the folder.
Result<std::uint64_t> read_folder_from_layout(LayoutSource& source, const MftFolder& folder,
                                              const CancellationToken& cancel, const MftVisit& visit,
                                              MftReadInfo* info = nullptr);

// An Error for this reader.
Error mft_error(std::string operation, std::string message, std::int64_t native_code = 0,
                bool elevation_may_help = false);

} // namespace ntfs_mft_detail

} // namespace support_assist
