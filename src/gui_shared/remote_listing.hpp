#pragma once

// The Remote (SSH) file pane's listing rules, shared so both editions order a folder, show a size
// and a date, and decide whether an upload replaces a file the same way.

#include "support_assist/ssh_client.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

namespace detail {

inline char fold_ascii(char value) {
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
}

inline bool name_before(std::string_view left, std::string_view right) {
  const std::size_t shared = std::min(left.size(), right.size());
  for (std::size_t index = 0; index < shared; ++index) {
    const char a = fold_ascii(left[index]);
    const char b = fold_ascii(right[index]);
    if (a != b)
      return static_cast<unsigned char>(a) < static_cast<unsigned char>(b);
  }
  return left.size() < right.size();
}

} // namespace detail

// Folders first, then names in order without regard to case. A log folder holds hundreds of files,
// and the one subfolder an engineer is looking for should not be lost among them.
inline void sort_remote_entries(std::vector<SftpEntry>& entries) {
  std::stable_sort(entries.begin(), entries.end(), [](const SftpEntry& left, const SftpEntry& right) {
    if (left.directory != right.directory)
      return left.directory;
    return detail::name_before(left.name, right.name);
  });
}

// Whole units, as the Windows file pane has always shown them: bytes are unreadable at a glance and
// kilobytes alone read "0 KB" for anything small. A folder has no size.
inline std::string remote_size_text(const SftpEntry& entry) {
  if (entry.directory)
    return {};
  constexpr std::uint64_t kilobyte = 1024ULL;
  constexpr std::uint64_t megabyte = kilobyte * 1024ULL;
  if (entry.size >= megabyte)
    return std::to_string(entry.size / megabyte) + " MB";
  if (entry.size >= kilobyte)
    return std::to_string(entry.size / kilobyte) + " KB";
  return std::to_string(entry.size) + " B";
}

// When the file last changed, in UTC, or nothing when the host did not say.
inline std::string remote_modified_text(const SftpEntry& entry) {
  if (entry.modified_unix == 0)
    return {};
  return readable_utc_from_unix_millis(static_cast<std::int64_t>(entry.modified_unix) * 1000);
}

// True when the listed folder already holds a file of this name, so an upload there would replace
// it. The engineer is asked first.
inline bool remote_listing_has_file(const std::vector<SftpEntry>& entries, std::string_view name) {
  return std::any_of(entries.begin(), entries.end(), [name](const SftpEntry& entry) {
    return !entry.directory && entry.name == name;
  });
}

} // namespace support_assist::gui
