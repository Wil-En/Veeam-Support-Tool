// Decoding the reply of the NTFS file layout query and listing the files under one folder from it.
// No system calls; the volume is queried in ntfs_mft_win.cpp.
//
// The listing makes two passes over the volume's files. The first asks for names only and keeps
// the folders (record, parent, name); from them it works out which folders lie under the requested
// folder. The second asks for names, streams and the extra information, and hands over each name
// whose parent is one of those folders. That keeps memory in proportion to the number of folders
// rather than the number of files.

#include "support_assist/ntfs_mft.hpp"

#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <unordered_map>
#include <utility>

namespace support_assist {
namespace ntfs_mft_detail {

namespace {

std::uint16_t le16(const std::uint8_t* bytes) noexcept {
  return static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8));
}

std::uint32_t le32(const std::uint8_t* bytes) noexcept {
  return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) | (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

std::uint64_t le64(const std::uint8_t* bytes) noexcept {
  return static_cast<std::uint64_t>(le32(bytes)) | (static_cast<std::uint64_t>(le32(bytes + 4)) << 32U);
}

// True when [offset, offset + length) lies inside a buffer of `size` bytes.
bool within(std::size_t size, std::uint64_t offset, std::uint64_t length) noexcept {
  return offset <= size && length <= size - offset;
}

// Most names or streams one file can list; a reply that goes on past this is not a real one.
constexpr std::size_t kMaximumItems = 1U << 20U;

bool equals_ignoring_case(std::u16string_view text, std::u16string_view lower) noexcept {
  if (text.size() != lower.size())
    return false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    char16_t unit = text[index];
    if (unit >= u'A' && unit <= u'Z')
      unit = static_cast<char16_t>(unit - u'A' + u'a');
    if (unit != lower[index])
      return false;
  }
  return true;
}

constexpr std::uint8_t kUnknown = 0;
constexpr std::uint8_t kInside = 1;
constexpr std::uint8_t kOutside = 2;
constexpr std::uint8_t kVisiting = 3;
constexpr std::size_t kMaximumFolderDepth = 65536U;
constexpr std::size_t kNoFolder = std::numeric_limits<std::size_t>::max();

// A folder found by the first pass.
struct FolderRecord {
  std::uint64_t number = 0;
  std::uint64_t parent = 0; // the reference, sequence included
  std::uint32_t name_offset = 0; // into the name store
  std::uint16_t name_length = 0;
};

class Walk {
public:
  Walk(LayoutSource& source, const MftFolder& folder, const CancellationToken& cancel, const MftVisit& visit,
       MftReadInfo& stats)
      : source_(source), folder_(folder), folder_number_(reference_number(folder.reference)), cancel_(cancel),
        visit_(visit), stats_(stats) {}

  bool run() {
    return first_pass() && emit_folder() && second_pass();
  }

  Error take_error() {
    return std::move(error_);
  }

private:
  bool fail(std::string operation, std::string message) {
    error_ = mft_error(std::move(operation), std::move(message));
    return false;
  }

  bool check_cancel() {
    if (!cancel_.is_cancelled())
      return true;
    return fail("list folder", "The folder listing was cancelled.");
  }

  // Runs one pass: the first query carries kLayoutRestart, and each reply is handed to `each`.
  bool run_pass(std::uint32_t flags, const LayoutEach& each) {
    std::uint32_t request = flags | kLayoutRestart;
    std::vector<std::uint8_t> reply;
    for (;;) {
      if (!check_cancel())
        return false;
      ++stats_.calls;
      const LayoutStatus status = source_.query(request, reply);
      if (status == LayoutStatus::end)
        return true;
      if (status == LayoutStatus::failed) {
        std::string detail = source_.error_text();
        if (detail.empty())
          detail = "the volume did not answer";
        error_ = mft_error("query file layout", "The volume's file layout could not be read: " + detail + ".", 0,
                           source_.needs_elevation());
        return false;
      }
      request = flags;
      std::string why;
      std::uint32_t count = 0;
      const LayoutParse outcome = parse_layout_buffer(reply, each, &why, &count);
      if (outcome == LayoutParse::malformed)
        return fail("query file layout", why);
      if (outcome == LayoutParse::stopped || count == 0U)
        return true;
    }
  }

  // ---- First pass --------------------------------------------------------------------------

  bool first_pass() {
    folders_.clear();
    const bool done = run_pass(kLayoutNames, [this](const LayoutFile& file) {
      if ((file.attributes & kAttributeDirectory) == 0U)
        return true;
      const std::vector<std::size_t> listed = listed_layout_names(file);
      if (listed.empty())
        return true;
      const LayoutName& name = file.names[listed.front()];
      if (names_.size() + name.units >= std::numeric_limits<std::uint32_t>::max())
        return true;
      FolderRecord record;
      record.number = reference_number(file.reference);
      record.parent = name.parent;
      record.name_offset = static_cast<std::uint32_t>(names_.size());
      record.name_length = static_cast<std::uint16_t>(std::min<std::size_t>(name.units, 255U));
      names_.append(layout_text(name.chars, record.name_length));
      folders_.push_back(record);
      return true;
    });
    if (!done)
      return false;
    std::sort(folders_.begin(), folders_.end(),
              [](const FolderRecord& left, const FolderRecord& right) { return left.number < right.number; });
    state_.assign(folders_.size(), kUnknown);
    return true;
  }

  std::size_t find_folder(std::uint64_t number) const {
    const auto found = std::lower_bound(folders_.begin(), folders_.end(), number,
                                        [](const FolderRecord& record, std::uint64_t key) { return record.number < key; });
    if (found == folders_.end() || found->number != number)
      return kNoFolder;
    return static_cast<std::size_t>(found - folders_.begin());
  }

  std::u16string_view folder_name(const FolderRecord& record) const {
    return std::u16string_view(names_.data() + record.name_offset, record.name_length);
  }

  // True when the folder `start` is the requested folder or lies under it. The files of NTFS
  // itself, and the metafile folders directly under the root, never do.
  bool is_inside(std::uint64_t start) {
    if (start == cached_start_)
      return cached_verdict_;
    chain_.clear();
    std::uint64_t current = start;
    std::uint8_t verdict = kOutside;
    for (;;) {
      if (chain_.size() > kMaximumFolderDepth)
        break;
      const std::size_t index = find_folder(current);
      if (current == folder_number_) {
        if (index != kNoFolder)
          state_[index] = kInside;
        verdict = kInside;
        break;
      }
      if (index == kNoFolder)
        break;
      const std::uint8_t known = state_[index];
      if (known == kInside || known == kOutside) {
        verdict = known;
        break;
      }
      if (known == kVisiting)
        break;
      const FolderRecord& record = folders_[index];
      const std::uint64_t parent = reference_number(record.parent);
      if (current < kFirstUserRecord || parent == current ||
          (parent == kRootRecord && is_metafile_name(folder_name(record)))) {
        state_[index] = kOutside;
        break;
      }
      state_[index] = kVisiting;
      chain_.push_back(index);
      current = parent;
    }
    for (const std::size_t member : chain_)
      state_[member] = verdict;
    cached_start_ = start;
    cached_verdict_ = verdict == kInside;
    return cached_verdict_;
  }

  // The path of a folder under the requested folder, relative to it.
  const std::wstring& folder_path(std::uint64_t number) {
    if (number == folder_number_)
      return empty_path_;
    const auto cached = folder_paths_.find(number);
    if (cached != folder_paths_.end())
      return cached->second;
    std::vector<std::size_t> missing;
    std::uint64_t current = number;
    while (current != folder_number_ && folder_paths_.find(current) == folder_paths_.end() &&
           missing.size() < kMaximumFolderDepth) {
      const std::size_t index = find_folder(current);
      if (index == kNoFolder)
        break;
      missing.push_back(index);
      current = reference_number(folders_[index].parent);
    }
    std::wstring base;
    if (current != folder_number_) {
      const auto known = folder_paths_.find(current);
      if (known != folder_paths_.end())
        base = known->second;
    }
    for (auto it = missing.rbegin(); it != missing.rend(); ++it) {
      const std::wstring name = wide_from_utf16(folder_name(folders_[*it]));
      base = base.empty() ? name : base + L'\\' + name;
      folder_paths_[folders_[*it].number] = base;
    }
    return folder_paths_[number];
  }

  // ---- Second pass -------------------------------------------------------------------------

  bool emit_folder() {
    if (!check_cancel())
      return false;
    MftEntry entry = folder_.has_details ? folder_.details : MftEntry();
    entry.record = folder_.reference;
    entry.directory = true;
    entry.attributes |= kAttributeDirectory;
    entry.size = 0;
    if (entry.hard_links == 0U)
      entry.hard_links = 1;
    const std::size_t index = find_folder(folder_number_);
    if (index != kNoFolder) {
      entry.parent = folders_[index].parent;
      entry.name = wide_from_utf16(folder_name(folders_[index]));
    } else if (folder_number_ == kRootRecord) {
      entry.parent = make_reference(kRootRecord, static_cast<std::uint16_t>(kRootRecord));
    }
    if (entry.name.empty())
      entry.name = L".";
    ++stats_.entries;
    if (!visit_(entry, std::wstring()))
      stopped_ = true;
    return true;
  }

  bool second_pass() {
    if (stopped_)
      return true;
    constexpr std::uint32_t kFlags = kLayoutNames | kLayoutStreams | kLayoutStreamsWithoutClusters | kLayoutExtraInfo;
    return run_pass(kFlags, [this](const LayoutFile& file) {
      ++stats_.records_total;
      const std::uint64_t number = reference_number(file.reference);
      if (number < kFirstUserRecord || number == folder_number_)
        return true;
      const std::vector<std::size_t> listed = listed_layout_names(file);
      for (const std::size_t index : listed) {
        const LayoutName& name = file.names[index];
        const std::uint64_t parent = reference_number(name.parent);
        if (parent == kRootRecord && is_metafile_name(layout_text(name.chars, name.units)))
          continue;
        if (!is_inside(parent))
          continue;
        const MftEntry entry = make_layout_entry(file, name, listed.size());
        const std::wstring& directory = folder_path(parent);
        const std::wstring path = directory.empty() ? entry.name : directory + L'\\' + entry.name;
        ++stats_.entries;
        if (!visit_(entry, path)) {
          stopped_ = true;
          return false;
        }
      }
      return true;
    });
  }

  LayoutSource& source_;
  const MftFolder& folder_;
  std::uint64_t folder_number_;
  const CancellationToken& cancel_;
  const MftVisit& visit_;
  MftReadInfo& stats_;
  Error error_;
  std::vector<FolderRecord> folders_;
  std::u16string names_;
  std::vector<std::uint8_t> state_;
  std::vector<std::size_t> chain_;
  std::unordered_map<std::uint64_t, std::wstring> folder_paths_;
  std::wstring empty_path_;
  std::uint64_t cached_start_ = std::numeric_limits<std::uint64_t>::max();
  bool cached_verdict_ = false;
  bool stopped_ = false;
};

} // namespace

// ---- Public pieces --------------------------------------------------------------------------

Error mft_error(std::string operation, std::string message, std::int64_t native_code, bool elevation_may_help) {
  Error error;
  error.component = "MasterFileTable";
  error.operation = std::move(operation);
  error.native_code = native_code;
  error.message = std::move(message);
  error.recoverable = true;
  error.elevation_may_help = elevation_may_help;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

LayoutParse parse_layout_buffer(std::span<const std::uint8_t> buffer, const LayoutEach& each, std::string* why,
                                std::uint32_t* count_out) {
  namespace at = layout_offset;
  const std::uint8_t* data = buffer.data();
  const std::size_t size = buffer.size();
  if (count_out != nullptr)
    *count_out = 0;
  const auto bad = [why](const char* text) {
    if (why != nullptr)
      *why = std::string("The file layout reply is malformed: ") + text + ".";
    return LayoutParse::malformed;
  };
  if (size < at::kOutputSize)
    return bad("it is shorter than its header");
  const std::uint32_t count = le32(data + at::kOutputFileCount);
  if (count == 0U)
    return LayoutParse::ok;
  std::uint64_t position = le32(data + at::kOutputFirstFile);
  if (position < at::kOutputSize)
    return bad("the first file starts inside the header");

  LayoutFile file;
  for (std::uint32_t index = 0; index < count; ++index) {
    if (!within(size, position, at::kEntrySize))
      return bad("a file entry runs past the end");
    const std::uint8_t* entry = data + position;
    file.names.clear();
    file.streams.clear();
    file.has_info = false;
    file.creation_100ns = 0;
    file.access_100ns = 0;
    file.write_100ns = 0;
    file.change_100ns = 0;
    file.info_attributes = 0;
    file.reference = le64(entry + at::kEntryReference);
    file.attributes = le32(entry + at::kEntryAttributes);

    const std::uint32_t first_name = le32(entry + at::kEntryFirstName);
    if (first_name != 0U) {
      if (first_name < at::kEntrySize)
        return bad("a name starts inside its file entry");
      std::uint64_t name_position = position + first_name;
      for (;;) {
        if (file.names.size() >= kMaximumItems)
          return bad("a file lists too many names");
        if (!within(size, name_position, at::kNameChars))
          return bad("a name entry runs past the end");
        const std::uint8_t* name = data + name_position;
        const std::uint32_t length = le32(name + at::kNameLength);
        if ((length & 1U) != 0U || !within(size, name_position + at::kNameChars, length))
          return bad("a name runs past the end");
        LayoutName item;
        item.flags = le32(name + at::kNameFlags);
        item.parent = le64(name + at::kNameParent);
        item.chars = name + at::kNameChars;
        item.units = length / 2U;
        file.names.push_back(item);
        const std::uint32_t next = le32(name + at::kNameNext);
        if (next == 0U)
          break;
        if (next < at::kNameChars)
          return bad("name entries overlap");
        name_position += next;
      }
    }

    const std::uint32_t first_stream = le32(entry + at::kEntryFirstStream);
    if (first_stream != 0U) {
      if (first_stream < at::kEntrySize)
        return bad("a stream starts inside its file entry");
      std::uint64_t stream_position = position + first_stream;
      for (;;) {
        if (file.streams.size() >= kMaximumItems)
          return bad("a file lists too many streams");
        if (!within(size, stream_position, at::kStreamIdentifier))
          return bad("a stream entry runs past the end");
        const std::uint8_t* stream = data + stream_position;
        const std::uint32_t length = le32(stream + at::kStreamIdentifierLength);
        if ((length & 1U) != 0U || !within(size, stream_position + at::kStreamIdentifier, length))
          return bad("a stream name runs past the end");
        LayoutStream item;
        item.type = le32(stream + at::kStreamType);
        item.flags = le32(stream + at::kStreamFlags);
        item.allocation = le64(stream + at::kStreamAllocation);
        item.end_of_file = le64(stream + at::kStreamEndOfFile);
        item.identifier = stream + at::kStreamIdentifier;
        item.identifier_units = length / 2U;
        file.streams.push_back(item);
        const std::uint32_t next = le32(stream + at::kStreamNext);
        if (next == 0U)
          break;
        if (next < at::kStreamIdentifier)
          return bad("stream entries overlap");
        stream_position += next;
      }
    }

    const std::uint32_t extra = le32(entry + at::kEntryExtraInfo);
    if (extra != 0U) {
      if (extra < at::kEntrySize || !within(size, position + extra, at::kInfoBasicSize))
        return bad("the extra information runs past the end");
      // A length of 0 means the information is complete up to its update sequence number.
      const std::uint32_t extra_length = le32(entry + at::kEntryExtraInfoLength);
      if (extra_length == 0U || extra_length >= at::kInfoBasicSize) {
        const std::uint8_t* info = entry + extra;
        file.has_info = true;
        file.creation_100ns = static_cast<std::int64_t>(le64(info + at::kInfoCreation));
        file.access_100ns = static_cast<std::int64_t>(le64(info + at::kInfoAccess));
        file.write_100ns = static_cast<std::int64_t>(le64(info + at::kInfoWrite));
        file.change_100ns = static_cast<std::int64_t>(le64(info + at::kInfoChange));
        file.info_attributes = le32(info + at::kInfoAttributes);
      }
    }

    if (count_out != nullptr)
      *count_out = index + 1U;
    if (!each(file))
      return LayoutParse::stopped;

    if (index + 1U < count) {
      const std::uint32_t next = le32(entry + at::kEntryNext);
      if (next == 0U)
        return bad("it holds fewer files than it announces");
      if (next < at::kEntrySize)
        return bad("file entries overlap");
      position += next;
    }
  }
  return LayoutParse::ok;
}

std::vector<std::size_t> listed_layout_names(const LayoutFile& file) {
  std::vector<std::size_t> listed;
  for (std::size_t index = 0; index < file.names.size(); ++index) {
    const std::uint32_t flags = file.names[index].flags;
    if ((flags & kNameDos) == 0U || (flags & kNamePrimary) != 0U)
      listed.push_back(index);
  }
  // A DOS-only name stands for the file in a folder that holds no other name of it.
  for (std::size_t index = 0; index < file.names.size(); ++index) {
    const std::uint32_t flags = file.names[index].flags;
    if ((flags & kNameDos) == 0U || (flags & kNamePrimary) != 0U)
      continue;
    bool covered = false;
    for (std::size_t earlier = 0; earlier < listed.size(); ++earlier) {
      if (reference_number(file.names[listed[earlier]].parent) == reference_number(file.names[index].parent)) {
        covered = true;
        break;
      }
    }
    if (!covered)
      listed.push_back(index);
  }
  return listed;
}

bool is_unnamed_data_stream(const LayoutStream& stream) {
  if (stream.type != kDataAttributeType)
    return false;
  if (stream.identifier_units == 0U)
    return true;
  return equals_ignoring_case(layout_text(stream.identifier, stream.identifier_units), u"::$data");
}

bool unnamed_data_sizes(const LayoutFile& file, std::uint64_t& size, std::uint64_t& allocation) {
  size = 0;
  allocation = 0;
  for (const LayoutStream& stream : file.streams) {
    if (!is_unnamed_data_stream(stream))
      continue;
    size = stream.end_of_file;
    allocation = stream.allocation;
    return true;
  }
  return false;
}

std::u16string layout_text(const std::uint8_t* chars, std::size_t units) {
  std::u16string text(units, u'\0');
  for (std::size_t index = 0; index < units; ++index)
    text[index] = static_cast<char16_t>(le16(chars + index * 2U));
  return text;
}

std::wstring wide_from_utf16(std::u16string_view text) {
  std::wstring wide;
  wide.reserve(text.size());
  for (std::size_t index = 0; index < text.size(); ++index) {
    const auto unit = static_cast<std::uint32_t>(text[index]);
    if constexpr (sizeof(wchar_t) > 2) {
      if (unit >= 0xD800U && unit < 0xDC00U && index + 1U < text.size()) {
        const auto low = static_cast<std::uint32_t>(text[index + 1U]);
        if (low >= 0xDC00U && low < 0xE000U) {
          wide.push_back(static_cast<wchar_t>(0x10000U + ((unit - 0xD800U) << 10U) + (low - 0xDC00U)));
          ++index;
          continue;
        }
      }
    }
    wide.push_back(static_cast<wchar_t>(unit));
  }
  return wide;
}

MftEntry make_layout_entry(const LayoutFile& file, const LayoutName& name, std::size_t links) {
  MftEntry entry;
  entry.record = file.reference;
  entry.parent = name.parent;
  entry.name = wide_from_utf16(layout_text(name.chars, name.units));
  entry.attributes = file.has_info ? file.info_attributes : file.attributes;
  entry.directory = ((file.attributes | file.info_attributes) & kAttributeDirectory) != 0U;
  if (entry.directory)
    entry.attributes |= kAttributeDirectory;
  entry.reparse = (entry.attributes & kAttributeReparsePoint) != 0U;
  entry.creation_100ns = file.creation_100ns;
  entry.access_100ns = file.access_100ns;
  entry.write_100ns = file.write_100ns;
  entry.change_100ns = file.change_100ns;
  entry.hard_links = static_cast<std::uint32_t>(links);
  if (!entry.directory)
    unnamed_data_sizes(file, entry.size, entry.allocation_size);
  return entry;
}

bool is_metafile_name(std::u16string_view name) {
  static constexpr std::array<std::u16string_view, 12> kNames = {
      u"$mft",  u"$mftmirr", u"$logfile", u"$volume", u"$attrdef", u"$bitmap",
      u"$boot", u"$badclus", u"$secure",  u"$upcase", u"$extend",  u"$rmmetadata"};
  if (name.size() < 4U || name.front() != u'$')
    return false;
  return std::any_of(kNames.begin(), kNames.end(),
                     [name](std::u16string_view lower) { return equals_ignoring_case(name, lower); });
}

Result<std::uint64_t> read_folder_from_layout(LayoutSource& source, const MftFolder& folder,
                                              const CancellationToken& cancel, const MftVisit& visit,
                                              MftReadInfo* info) {
  const auto started = std::chrono::steady_clock::now();
  MftReadInfo scratch;
  MftReadInfo& stats = info != nullptr ? *info : scratch;
  stats = MftReadInfo();
  stats.volume_serial = folder.volume_serial;
  Walk walk(source, folder, cancel, visit, stats);
  const bool done = walk.run();
  stats.elapsed_milliseconds = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count());
  if (!done)
    return Result<std::uint64_t>::failure(walk.take_error());
  return Result<std::uint64_t>::success(stats.entries);
}

} // namespace ntfs_mft_detail
} // namespace support_assist
