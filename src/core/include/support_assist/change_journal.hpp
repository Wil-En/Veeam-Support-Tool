#pragma once

// The NTFS change journal as System Differences uses it.
//
// A capture records where the journal stood (a mark). A later compare reads the records written
// after the mark, keeps those under the captured folder and sums them per file, which shows a file
// that was created and removed between the two moments. Decoding, summing and wording are here and
// have no system calls. Reading a volume is change_journal_win.cpp; other systems get the plain
// failure in change_journal_stub.cpp. The journal is only read: it is never created, resized or
// deleted.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace support_assist {

// True where the journal can be read (Windows). Elsewhere a compare says nothing about it.
#ifdef _WIN32
inline constexpr bool kChangeJournalSystem = true;
#else
inline constexpr bool kChangeJournalSystem = false;
#endif

// Where the journal stood when a capture finished: the volume, which journal it was, and the USN
// the next record would get. Records at or after next_usn happened after the capture.
struct ChangeJournalMark {
  std::string volume; // volume path in the \\?\Volume{...}\ form, which survives a drive letter change
  std::uint64_t journal_id = 0;
  std::int64_t next_usn = 0;
  std::string recorded_utc; // ISO 8601
};

// The reason bits of a journal record (the values of the USN_REASON_* flags).
namespace journal_reason {
inline constexpr std::uint32_t data_overwrite = 0x00000001U;
inline constexpr std::uint32_t data_extend = 0x00000002U;
inline constexpr std::uint32_t data_truncation = 0x00000004U;
inline constexpr std::uint32_t named_data_overwrite = 0x00000010U;
inline constexpr std::uint32_t named_data_extend = 0x00000020U;
inline constexpr std::uint32_t named_data_truncation = 0x00000040U;
inline constexpr std::uint32_t file_create = 0x00000100U;
inline constexpr std::uint32_t file_delete = 0x00000200U;
inline constexpr std::uint32_t extended_attribute_change = 0x00000400U;
inline constexpr std::uint32_t security_change = 0x00000800U;
inline constexpr std::uint32_t rename_old_name = 0x00001000U;
inline constexpr std::uint32_t rename_new_name = 0x00002000U;
inline constexpr std::uint32_t indexable_change = 0x00004000U;
inline constexpr std::uint32_t basic_info_change = 0x00008000U;
inline constexpr std::uint32_t hard_link_change = 0x00010000U;
inline constexpr std::uint32_t compression_change = 0x00020000U;
inline constexpr std::uint32_t encryption_change = 0x00040000U;
inline constexpr std::uint32_t object_id_change = 0x00080000U;
inline constexpr std::uint32_t reparse_point_change = 0x00100000U;
inline constexpr std::uint32_t stream_change = 0x00200000U;
inline constexpr std::uint32_t file_closed = 0x80000000U;
} // namespace journal_reason

inline constexpr std::uint32_t kJournalDirectoryAttribute = 0x00000010U;

// The reasons in words, in a fixed order, lower case and comma separated: "created, contents
// changed, renamed". The close flag and flags that only follow from other changes are not words.
// Empty when no reason is set.
inline std::string journal_reason_words(std::uint32_t reasons) {
  namespace r = journal_reason;
  struct Word {
    std::uint32_t mask;
    const char* text;
  };
  static constexpr Word kWords[] = {
      {r::file_create, "created"},
      {r::file_delete, "deleted"},
      {r::rename_old_name | r::rename_new_name, "renamed"},
      {r::data_overwrite | r::data_extend | r::data_truncation, "contents changed"},
      {r::named_data_overwrite | r::named_data_extend | r::named_data_truncation | r::stream_change,
       "data stream changed"},
      {r::basic_info_change, "attributes or times changed"},
      {r::security_change, "permissions changed"},
      {r::extended_attribute_change, "extended attributes changed"},
      {r::hard_link_change, "hard link changed"},
      {r::compression_change, "compression changed"},
      {r::encryption_change, "encryption changed"},
      {r::reparse_point_change, "reparse point changed"},
  };
  std::string text;
  std::uint32_t covered = r::file_closed | r::indexable_change | r::object_id_change;
  for (const Word& word : kWords) {
    covered |= word.mask;
    if ((reasons & word.mask) == 0U)
      continue;
    if (!text.empty())
      text += ", ";
    text += word.text;
  }
  if (text.empty() && (reasons & ~covered) != 0U)
    text = "other changes";
  return text;
}

// ---- Paths ----------------------------------------------------------------------------------

// A path as the journal code compares it: backslashes, no \\?\ prefix, and no trailing backslash
// except on a drive root.
inline std::string journal_path_form(std::string_view path) {
  std::string text(path);
  for (char& character : text) {
    if (character == '/')
      character = '\\';
  }
  if (text.rfind("\\\\?\\UNC\\", 0) == 0)
    text = "\\\\" + text.substr(8);
  else if (text.rfind("\\\\?\\", 0) == 0 || text.rfind("\\\\.\\", 0) == 0)
    text.erase(0, 4);
  while (text.size() > 3U && text.back() == '\\')
    text.pop_back();
  if (text.size() == 2U && text[1] == ':')
    text.push_back('\\');
  return text;
}

inline char journal_fold(char character) {
  return (character >= 'A' && character <= 'Z') ? static_cast<char>(character - 'A' + 'a') : character;
}

// Equal ignoring ASCII case. Both sides come from the file system in its own letter case, so
// letters outside ASCII are compared as they are.
inline bool journal_path_equal(std::string_view left, std::string_view right) {
  if (left.size() != right.size())
    return false;
  for (std::size_t index = 0; index < left.size(); ++index) {
    if (journal_fold(left[index]) != journal_fold(right[index]))
      return false;
  }
  return true;
}

// Whether path is root or lies below it. Both are in journal_path_form.
inline bool journal_path_under(std::string_view path, std::string_view root) {
  if (root.empty() || path.size() < root.size())
    return false;
  if (!journal_path_equal(path.substr(0, root.size()), root))
    return false;
  if (path.size() == root.size() || root.back() == '\\')
    return true;
  return path[root.size()] == '\\';
}

// A folder's path and the name of an entry in it, joined.
inline std::string journal_path_join(std::string_view folder, std::string_view name) {
  std::string path(folder);
  if (!path.empty() && path.back() != '\\')
    path.push_back('\\');
  path.append(name);
  return path;
}

// Paths are matched without the volume, because a volume mounted in a folder has no drive letter
// for Windows to name it by. The part of path below the volume's mount point, with a leading
// backslash ("\Data\Watched"); empty when path is not on that mount point. Both are in
// journal_path_form.
inline std::string journal_volume_relative(std::string_view path, std::string_view mount) {
  if (!journal_path_under(path, mount))
    return {};
  std::string rest(path.substr(mount.size()));
  if (rest.empty() || rest.front() != '\\')
    rest.insert(rest.begin(), '\\');
  return rest;
}

// A volume-relative path put back under the volume's mount point for display: ("C:\", "\Data") is
// "C:\Data" and ("E:\Repo", "\") is "E:\Repo". A path that does not start with a backslash is
// already complete and is returned as it is.
inline std::string journal_path_with_volume(std::string_view mount, std::string_view relative) {
  if (mount.empty() || relative.empty() || relative.front() != '\\')
    return std::string(relative);
  std::string path(mount);
  while (!path.empty() && path.back() == '\\')
    path.pop_back();
  path.append(relative);
  if (path.size() > 3U && path.back() == '\\')
    path.pop_back();
  return path;
}

// ---- Records --------------------------------------------------------------------------------

// One journal record, decoded.
struct JournalRecord {
  std::uint64_t file_reference = 0;
  std::uint64_t parent_reference = 0;
  std::int64_t usn = 0;
  std::int64_t time_ticks = 0; // 100 ns intervals since 1601-01-01 UTC
  std::uint32_t reason = 0;
  std::uint32_t attributes = 0;
  std::string name; // UTF-8
};

namespace journal_detail {

inline std::uint32_t read_u16(const unsigned char* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8U);
}

inline std::uint32_t read_u32(const unsigned char* bytes) {
  return read_u16(bytes) | (read_u16(bytes + 2) << 16U);
}

inline std::uint64_t read_u64(const unsigned char* bytes) {
  return static_cast<std::uint64_t>(read_u32(bytes)) | (static_cast<std::uint64_t>(read_u32(bytes + 4)) << 32U);
}

inline void append_utf8(std::string& text, std::uint32_t code_point) {
  if (code_point < 0x80U) {
    text.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800U) {
    text.push_back(static_cast<char>(0xC0U | (code_point >> 6U)));
    text.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else if (code_point < 0x10000U) {
    text.push_back(static_cast<char>(0xE0U | (code_point >> 12U)));
    text.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    text.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else {
    text.push_back(static_cast<char>(0xF0U | (code_point >> 18U)));
    text.push_back(static_cast<char>(0x80U | ((code_point >> 12U) & 0x3FU)));
    text.push_back(static_cast<char>(0x80U | ((code_point >> 6U) & 0x3FU)));
    text.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  }
}

} // namespace journal_detail

// UTF-16 little-endian text as UTF-8. A lone surrogate becomes U+FFFD.
inline std::string journal_utf8_from_utf16le(const unsigned char* bytes, std::size_t units) {
  std::string text;
  text.reserve(units);
  for (std::size_t index = 0; index < units; ++index) {
    std::uint32_t code_point = journal_detail::read_u16(bytes + index * 2U);
    if (code_point >= 0xD800U && code_point <= 0xDBFFU) {
      const bool has_low = index + 1U < units;
      const std::uint32_t low = has_low ? journal_detail::read_u16(bytes + (index + 1U) * 2U) : 0U;
      if (has_low && low >= 0xDC00U && low <= 0xDFFFU) {
        code_point = 0x10000U + ((code_point - 0xD800U) << 10U) + (low - 0xDC00U);
        ++index;
      } else {
        code_point = 0xFFFDU;
      }
    } else if (code_point >= 0xDC00U && code_point <= 0xDFFFU) {
      code_point = 0xFFFDU;
    }
    journal_detail::append_utf8(text, code_point);
  }
  return text;
}

// The version 2 records in `size` bytes, which are what FSCTL_READ_USN_JOURNAL returns after its
// leading 8-byte next USN. A record of another version is skipped. `damaged` is set when the
// bytes end inside a record or a record is not laid out as its length says.
inline std::vector<JournalRecord> decode_usn_records(const unsigned char* data, std::size_t size,
                                                     bool* damaged = nullptr) {
  constexpr std::size_t kHeader = 60U; // bytes before the name in a version 2 record
  std::vector<JournalRecord> records;
  std::size_t offset = 0;
  while (offset + 8U <= size) {
    const unsigned char* bytes = data + offset;
    const std::size_t length = journal_detail::read_u32(bytes);
    if (length < 8U || length > size - offset) {
      if (damaged != nullptr)
        *damaged = true;
      break;
    }
    const std::uint32_t major = journal_detail::read_u16(bytes + 4);
    if (major == 2U) {
      if (length < kHeader) {
        if (damaged != nullptr)
          *damaged = true;
        break;
      }
      JournalRecord record;
      record.file_reference = journal_detail::read_u64(bytes + 8);
      record.parent_reference = journal_detail::read_u64(bytes + 16);
      record.usn = static_cast<std::int64_t>(journal_detail::read_u64(bytes + 24));
      record.time_ticks = static_cast<std::int64_t>(journal_detail::read_u64(bytes + 32));
      record.reason = journal_detail::read_u32(bytes + 40);
      record.attributes = journal_detail::read_u32(bytes + 52);
      const std::size_t name_length = journal_detail::read_u16(bytes + 56);
      const std::size_t name_offset = journal_detail::read_u16(bytes + 58);
      if (name_offset + name_length <= length)
        record.name = journal_utf8_from_utf16le(bytes + name_offset, name_length / 2U);
      else if (damaged != nullptr)
        *damaged = true;
      records.push_back(std::move(record));
    }
    offset += length;
  }
  return records;
}

// ---- Time -----------------------------------------------------------------------------------

// "2026-10-17 14:03:09 UTC" from a record's time, or empty for no time.
inline std::string journal_time_text(std::int64_t ticks) {
  if (ticks <= 0)
    return {};
  const std::int64_t seconds = ticks / 10000000LL - 11644473600LL;
  std::int64_t days = seconds / 86400LL;
  std::int64_t second_of_day = seconds % 86400LL;
  if (second_of_day < 0) {
    second_of_day += 86400LL;
    --days;
  }
  // Civil date from a day count (days since 1970-01-01).
  const std::int64_t shifted = days + 719468LL;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096LL) / 146097LL;
  const std::int64_t day_of_era = shifted - era * 146097LL;
  const std::int64_t year_of_era =
      (day_of_era - day_of_era / 1460LL + day_of_era / 36524LL - day_of_era / 146096LL) / 365LL;
  const std::int64_t day_of_year = day_of_era - (365LL * year_of_era + year_of_era / 4LL - year_of_era / 100LL);
  const std::int64_t month_part = (5LL * day_of_year + 2LL) / 153LL;
  const int day = static_cast<int>(day_of_year - (153LL * month_part + 2LL) / 5LL + 1LL);
  const int month = static_cast<int>(month_part < 10LL ? month_part + 3LL : month_part - 9LL);
  const int year = static_cast<int>(year_of_era + era * 400LL + (month <= 2 ? 1LL : 0LL));
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%04d-%02d-%02d %02d:%02d:%02d UTC", year, month, day,
                static_cast<int>(second_of_day / 3600LL), static_cast<int>((second_of_day / 60LL) % 60LL),
                static_cast<int>(second_of_day % 60LL));
  return text;
}

// ---- Summing the records of one file ---------------------------------------------------------

// Everything the journal recorded for one file or folder in the window.
struct JournalChange {
  std::uint64_t file_reference = 0;
  std::string path; // from the newest record kept
  std::string renamed_from; // the name before the first rename seen; empty when none or not known
  std::string renamed_to; // the name after the last rename seen
  bool directory = false;
  std::uint32_t reasons = 0;
  std::uint32_t records = 0;
  std::int64_t first_usn = 0;
  std::int64_t first_time = 0;
  std::int64_t last_time = 0;
  std::int64_t created_time = 0;
  std::int64_t deleted_time = 0;
  std::int64_t renamed_time = 0;

  [[nodiscard]] bool created_and_deleted() const {
    return (reasons & journal_reason::file_create) != 0U && (reasons & journal_reason::file_delete) != 0U;
  }
  [[nodiscard]] bool renamed() const {
    return (reasons & journal_reason::rename_new_name) != 0U && !renamed_to.empty() &&
           !journal_path_equal(renamed_from, renamed_to);
  }
};

// Keeps the records under one folder and sums them per file reference. The reference includes its
// sequence number, so a file record slot that is reused is a different file.
class JournalAggregator {
public:
  static constexpr std::size_t kDefaultMaximumChanges = 500000U;
  static constexpr std::size_t kMaximumOutsideNames = 100000U;

  explicit JournalAggregator(std::string_view root, std::size_t maximum_changes = kDefaultMaximumChanges)
      : root_(journal_path_form(root)), maximum_changes_(maximum_changes) {}

  // parent_path is the folder the record's parent reference names (journal_path_form, in the same
  // form as the root: both with a drive, or both volume-relative; empty when it could not be
  // found). A file that has left the folder keeps its later renames, and anything else it does
  // elsewhere is not under the folder. Records are added in USN order.
  void add(const JournalRecord& record, std::string_view parent_path) {
    ++records_seen_;
    if (parent_path.empty()) {
      ++unplaced_;
      return;
    }
    std::string path = journal_path_join(parent_path, record.name);
    const bool inside = journal_path_under(path, root_);
    auto found = index_.find(record.file_reference);
    if (found == index_.end()) {
      if (!inside) {
        if ((record.reason & journal_reason::rename_old_name) != 0U && outside_names_.size() < kMaximumOutsideNames)
          outside_names_[record.file_reference] = std::move(path);
        return;
      }
      if (changes_.size() >= maximum_changes_) {
        ++dropped_;
        return;
      }
      JournalChange change;
      change.file_reference = record.file_reference;
      change.first_usn = record.usn;
      change.first_time = record.time_ticks;
      index_.emplace(record.file_reference, changes_.size());
      changes_.push_back(std::move(change));
      found = index_.find(record.file_reference);
    } else if (!inside && (record.reason & journal_reason::rename_new_name) == 0U) {
      return;
    }
    if (inside)
      ++records_inside_;
    JournalChange& change = changes_[found->second];
    change.reasons |= record.reason;
    ++change.records;
    change.last_time = record.time_ticks;
    if ((record.attributes & kJournalDirectoryAttribute) != 0U)
      change.directory = true;
    if ((record.reason & journal_reason::file_create) != 0U && change.created_time == 0)
      change.created_time = record.time_ticks;
    if ((record.reason & journal_reason::file_delete) != 0U)
      change.deleted_time = record.time_ticks;
    if ((record.reason & journal_reason::rename_old_name) != 0U && change.renamed_from.empty())
      change.renamed_from = path;
    if ((record.reason & journal_reason::rename_new_name) != 0U) {
      change.renamed_to = path;
      change.renamed_time = record.time_ticks;
      if (change.renamed_from.empty()) {
        const auto outside = outside_names_.find(record.file_reference);
        if (outside != outside_names_.end()) {
          change.renamed_from = outside->second;
          outside_names_.erase(outside);
        }
      }
    }
    change.path = std::move(path);
  }

  // Oldest first.
  [[nodiscard]] std::vector<JournalChange> changes() const {
    std::vector<JournalChange> sorted = changes_;
    std::stable_sort(sorted.begin(), sorted.end(),
                     [](const JournalChange& left, const JournalChange& right) { return left.first_usn < right.first_usn; });
    return sorted;
  }

  [[nodiscard]] std::uint64_t records_seen() const { return records_seen_; }
  [[nodiscard]] std::uint64_t records_inside() const { return records_inside_; }
  [[nodiscard]] std::uint64_t unplaced() const { return unplaced_; }
  // Files that were not kept because the limit on files and folders was reached.
  [[nodiscard]] std::uint64_t dropped() const { return dropped_; }

private:
  std::string root_;
  std::size_t maximum_changes_;
  std::vector<JournalChange> changes_;
  std::unordered_map<std::uint64_t, std::size_t> index_;
  std::unordered_map<std::uint64_t, std::string> outside_names_;
  std::uint64_t records_seen_ = 0;
  std::uint64_t records_inside_ = 0;
  std::uint64_t unplaced_ = 0;
  std::uint64_t dropped_ = 0;
};

// The records summed per file for one folder, in one call.
inline std::vector<JournalChange> aggregate_journal(const std::vector<std::pair<JournalRecord, std::string>>& records,
                                                    std::string_view root) {
  JournalAggregator aggregator(root);
  for (const auto& entry : records)
    aggregator.add(entry.first, entry.second);
  return aggregator.changes();
}

// Puts the volume's mount point back in front of the volume-relative paths of the changes, for
// display.
inline void journal_show_volume_paths(std::vector<JournalChange>& changes, std::string_view mount) {
  for (JournalChange& change : changes) {
    change.path = journal_path_with_volume(mount, change.path);
    change.renamed_from = journal_path_with_volume(mount, change.renamed_from);
    change.renamed_to = journal_path_with_volume(mount, change.renamed_to);
  }
}

// ---- Naming folders --------------------------------------------------------------------------

// Names the folder behind a file reference. A folder that still exists is looked up live. One
// that was removed in the window is put together from the journal's own records of it. The
// records of a removed folder's children come before the record that removes the folder, so
// note() has to see every record of the window before the first path_of(): read the window twice,
// noting in the first pass and summing in the second.
class JournalFolderNames {
public:
  using Lookup = std::function<std::string(std::uint64_t)>;
  static constexpr std::size_t kMaximumKnown = 500000U;
  static constexpr std::size_t kMaximumCached = 1000000U;
  static constexpr int kMaximumDepth = 64;

  // live gives the path of a folder that exists now (journal_path_form), or empty.
  explicit JournalFolderNames(Lookup live) : live_(std::move(live)) {}

  // Remembers where a folder sat, from a record about it. The newest record wins.
  void note(const JournalRecord& record) {
    if ((record.attributes & kJournalDirectoryAttribute) == 0U ||
        (record.reason & journal_reason::rename_old_name) != 0U)
      return;
    if (known_.size() < kMaximumKnown || known_.count(record.file_reference) != 0U)
      known_[record.file_reference] = Known{record.parent_reference, record.name};
    const auto cached = paths_.find(record.file_reference);
    if (cached != paths_.end() && cached->second.empty())
      paths_.erase(cached);
  }

  // The folder's path, empty when it cannot be named. Valid until the next call.
  const std::string& path_of(std::uint64_t reference) {
    if (paths_.size() > kMaximumCached)
      paths_.clear();
    return resolve(reference, 0);
  }

  [[nodiscard]] std::size_t known_folders() const { return known_.size(); }

private:
  struct Known {
    std::uint64_t parent = 0;
    std::string name;
  };

  const std::string& resolve(std::uint64_t reference, int depth) {
    const auto cached = paths_.find(reference);
    if (cached != paths_.end())
      return cached->second;
    std::string path = live_ ? live_(reference) : std::string();
    if (path.empty() && depth < kMaximumDepth) {
      const auto known = known_.find(reference);
      if (known != known_.end()) {
        const std::string parent = resolve(known->second.parent, depth + 1);
        if (!parent.empty())
          path = journal_path_join(parent, known->second.name);
      }
    }
    return paths_.emplace(reference, std::move(path)).first->second;
  }

  Lookup live_;
  std::unordered_map<std::uint64_t, std::string> paths_;
  std::unordered_map<std::uint64_t, Known> known_;
};

// ---- Reading --------------------------------------------------------------------------------

// What a capture can record about the journal of its folder's volume.
struct ChangeJournalProbe {
  bool available = false;
  bool needs_administrator = false;
  bool inactive = false; // an NTFS volume whose journal is not active
  std::string reason; // why not available, in plain words; empty when available
  ChangeJournalMark mark; // the position now, valid when available
};

// The sentence a capture result adds when no mark was recorded, or empty when there is nothing
// worth saying (another file system, or a system without the journal).
inline std::string journal_mark_missing_sentence(const ChangeJournalProbe& probe) {
  if (probe.available)
    return {};
  if (probe.needs_administrator)
    return "Run SAT as administrator to also record the change journal.";
  if (probe.inactive)
    return "The NTFS change journal is not active on this volume, so none was recorded.";
  return {};
}

// Looks at the journal of the volume holding `folder`: whether it can be read, and where it stands.
ChangeJournalProbe probe_change_journal(const std::filesystem::path& folder);

// The records to read: those written after `start` up to `end_usn` (exclusive), or up to now when
// end_usn is 0. folder is the captured root.
struct ChangeJournalWindow {
  std::filesystem::path folder;
  ChangeJournalMark start;
  std::int64_t end_usn = 0;
  std::uint64_t maximum_records = 4000000U;
  std::uint32_t maximum_seconds = 60U;
};

struct ChangeJournalReadout {
  std::vector<JournalChange> changes; // under the folder, oldest first
  std::uint64_t records_read = 0; // on the whole volume
  std::uint64_t records_inside = 0; // under the folder
  std::uint64_t unplaced = 0; // records whose folder could not be named
  std::uint64_t dropped = 0; // files and folders left out because the list was full
  bool cut_short = false;
  std::string cut_short_reason; // "the limit of 4,000,000 records", "the time limit of 60 seconds"
  std::int64_t reached_time = 0; // time of the last record read, when cut short
  bool cancelled = false;
};

// Reads the window. Fails, with a sentence that says why, when the journal was recreated after the
// start, when the records at the start have been overwritten, when SAT is not elevated, or when
// the folder is not on the volume the start was recorded for.
Result<ChangeJournalReadout> read_change_journal(const ChangeJournalWindow& window, const CancellationToken& cancel);

} // namespace support_assist
