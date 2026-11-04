#pragma once

// The rows of the checksum window, shared by both GUIs. Each dropped file is read for its SHA-256.
// A checksum list dropped with the files (SHA256SUMS, or a "<name>.sha256" file) checks each file
// it names against the value it gives. A list dropped on its own brings in every file it names,
// looked for beside the list as sha256sum -c does. Files are only read, and a list only leads to
// files in its own folder or below it.

#include "support_assist/filesystem.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui {

// A checksum list and the values it gives.
struct ChecksumList {
  std::filesystem::path path;
  std::string name;  // the list's file name, as the window shows it
  std::vector<Sha256SumsEntry> entries;
};

// What a row stands for: a file that is read, a listed file not found beside its list, or a listed
// name that leads outside the list's folder and is never looked for.
enum class ChecksumRowKind { file, missing, outside };

struct ChecksumRow {
  std::filesystem::path path;  // for an outside row, the list's folder
  std::optional<std::uint64_t> size;
  std::string sha256;
  std::string error;
  bool done = false;
  ChecksumRowKind kind = ChecksumRowKind::file;
  // The list that names this file, when one does, and the value it gives.
  std::optional<std::size_t> list;
  std::string expected;
  std::string listed_name;  // the name as the list writes it
};

// The Check column for one row.
enum class ChecksumCheck {
  none,         // no list has been dropped
  pending,      // listed, and still being read
  match,        // listed, and the SHA-256 is the value the list gives
  mismatch,     // listed, and the SHA-256 differs
  missing,      // listed, and not found beside the list
  not_checked,  // listed, and not read: an error, or a name outside the list's folder
  not_listed,   // lists have been dropped, and none names this file
};

// The summary above the table: its text, and its colour as the match line uses it (0 neutral,
// 1 every listed file matches, 2 a file does not match or is missing, 3 a file was not checked).
struct ChecksumSummary {
  std::string text;
  int state = 0;
};

// Checksum lists are a few kilobytes; nothing larger is read as one.
inline constexpr std::uintmax_t kChecksumListMaximumBytes = 4U * 1024U * 1024U;

// The list in a dropped file, when the file is one: named like a checksum list, no larger than
// kChecksumListMaximumBytes, and read in full as one. Any other file is an ordinary file.
inline std::optional<ChecksumList> read_checksum_list(const std::filesystem::path& path) {
  const std::string name = path_to_utf8(path.filename());
  if (!looks_like_sha256_sums_name(name))
    return std::nullopt;
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (size == static_cast<std::uintmax_t>(-1) || size == 0U || size > kChecksumListMaximumBytes)
    return std::nullopt;
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return std::nullopt;
  std::string content(static_cast<std::size_t>(size), '\0');
  input.read(content.data(), static_cast<std::streamsize>(content.size()));
  content.resize(static_cast<std::size_t>(input.gcount()));
  std::vector<Sha256SumsEntry> entries = sha256_sums_from_file_text(content, name);
  if (entries.empty())
    return std::nullopt;
  return ChecksumList{path, name, std::move(entries)};
}

namespace checksum_detail {

// Paths and names compared the way the platform compares file names: without regard to case on
// Windows.
inline std::string comparable(std::string text) {
#ifdef _WIN32
  return ascii_lower(text);
#else
  return text;
#endif
}

inline std::string comparable_path(const std::filesystem::path& path) {
  return comparable(path_to_utf8(path.lexically_normal()));
}

// The file name part of a name as a list writes it.
inline std::string listed_file_name(std::string_view name) {
  std::u8string utf8;
  utf8.reserve(name.size());
  for (const char character : name)
    utf8.push_back(static_cast<char8_t>(character));
  return path_to_utf8(std::filesystem::path(utf8).filename());
}

}  // namespace checksum_detail

class ChecksumSet {
public:
  using Job = std::pair<std::size_t, std::filesystem::path>;

  const std::vector<ChecksumRow>& rows() const { return rows_; }
  const std::vector<ChecksumList>& lists() const { return lists_; }
  bool has_lists() const { return !lists_.empty(); }

  void clear() {
    rows_.clear();
    lists_.clear();
  }

  // Adds dropped files and lists, and returns the rows to read as (row, path) pairs. Rows already
  // in the window that no list named are checked against the new lists. When lists arrive without
  // files, every file they name joins the window: read when it is beside the list, shown as not
  // found when it is not.
  std::vector<Job> add(const std::vector<std::filesystem::path>& files,
                       std::vector<ChecksumList> lists) {
    std::vector<Job> jobs;
    const std::size_t first_list = lists_.size();
    for (auto& list : lists) {
      const std::string key = checksum_detail::comparable_path(list.path);
      bool known = false;
      for (const auto& loaded : lists_)
        known = known || checksum_detail::comparable_path(loaded.path) == key;
      if (!known)
        lists_.push_back(std::move(list));
    }
    for (auto& row : rows_) {
      if (!row.list && row.kind == ChecksumRowKind::file)
        match(row, first_list);
    }
    for (const auto& file : files) {
      ChecksumRow row;
      row.path = file;
      std::error_code error;
      const std::uintmax_t size = std::filesystem::file_size(file, error);
      if (size != static_cast<std::uintmax_t>(-1))
        row.size = static_cast<std::uint64_t>(size);
      match(row, 0);
      jobs.emplace_back(rows_.size(), file);
      rows_.push_back(std::move(row));
    }
    if (!files.empty())
      return jobs;

    for (std::size_t list_index = first_list; list_index < lists_.size(); ++list_index) {
      const ChecksumList& list = lists_[list_index];
      const std::filesystem::path folder = list.path.parent_path();
      for (std::size_t entry_index = 0; entry_index < list.entries.size(); ++entry_index) {
        const Sha256SumsEntry& entry = list.entries[entry_index];
        const std::filesystem::path beside = sha256_sums_entry_path(folder, entry.name);
        if (!beside.empty() && holds(beside))
          continue;
        ChecksumRow row;
        row.list = list_index;
        row.expected = entry.sha256;
        row.listed_name = entry.name;
        if (beside.empty()) {
          row.kind = ChecksumRowKind::outside;
          row.path = folder;
          row.done = true;
          rows_.push_back(std::move(row));
          continue;
        }
        row.path = beside;
        std::error_code error;
        const std::filesystem::file_status status = std::filesystem::status(beside, error);
        if (std::filesystem::is_regular_file(status)) {
          const std::uintmax_t size = std::filesystem::file_size(beside, error);
          if (size != static_cast<std::uintmax_t>(-1))
            row.size = static_cast<std::uint64_t>(size);
          jobs.emplace_back(rows_.size(), beside);
        } else if (status.type() == std::filesystem::file_type::not_found ||
                   status.type() == std::filesystem::file_type::none) {
          row.kind = ChecksumRowKind::missing;
          row.done = true;
        } else {
          row.error = "This is not a regular file.";
          row.done = true;
        }
        rows_.push_back(std::move(row));
      }
    }
    return jobs;
  }

  void set_result(std::size_t index, std::string sha256, std::string error) {
    if (index >= rows_.size())
      return;
    ChecksumRow& row = rows_[index];
    row.sha256 = std::move(sha256);
    row.error = std::move(error);
    row.done = true;
  }

  ChecksumCheck check(std::size_t index) const {
    if (lists_.empty() || index >= rows_.size())
      return ChecksumCheck::none;
    const ChecksumRow& row = rows_[index];
    if (!row.list)
      return ChecksumCheck::not_listed;
    if (row.kind == ChecksumRowKind::missing)
      return ChecksumCheck::missing;
    if (row.kind == ChecksumRowKind::outside)
      return ChecksumCheck::not_checked;
    if (!row.done)
      return ChecksumCheck::pending;
    if (!row.error.empty())
      return ChecksumCheck::not_checked;
    return row.sha256 == row.expected ? ChecksumCheck::match : ChecksumCheck::mismatch;
  }

  std::string file_text(std::size_t index) const {
    if (index >= rows_.size())
      return {};
    const ChecksumRow& row = rows_[index];
    return row.kind == ChecksumRowKind::outside ? row.listed_name
                                                : path_to_utf8(row.path.filename());
  }

  std::string hash_text(std::size_t index) const {
    if (index >= rows_.size())
      return {};
    const ChecksumRow& row = rows_[index];
    if (row.kind == ChecksumRowKind::missing)
      return "Not found";
    if (row.kind == ChecksumRowKind::outside)
      return "Not read: the name points outside the list's folder";
    if (!row.done)
      return "Calculating...";
    return row.error.empty() ? row.sha256 : "Not read: " + row.error;
  }

  std::string check_text(std::size_t index) const {
    const ChecksumCheck state = check(index);
    const std::string list = state == ChecksumCheck::match || state == ChecksumCheck::mismatch
                                 ? lists_[*rows_[index].list].name
                                 : std::string();
    switch (state) {
    case ChecksumCheck::match:
      return "Matches " + list;
    case ChecksumCheck::mismatch:
      return "Does not match " + list;
    case ChecksumCheck::missing:
      return "Not found";
    case ChecksumCheck::not_checked:
      return "Not checked";
    case ChecksumCheck::not_listed:
      return "Not listed";
    case ChecksumCheck::none:
    case ChecksumCheck::pending:
      break;
    }
    return {};
  }

  std::string size_text(std::size_t index) const {
    if (index >= rows_.size() || !rows_[index].size)
      return {};
    return format_health_bytes(*rows_[index].size);
  }

  std::string folder_text(std::size_t index) const {
    if (index >= rows_.size())
      return {};
    const ChecksumRow& row = rows_[index];
    return path_to_utf8(row.kind == ChecksumRowKind::outside ? row.path : row.path.parent_path());
  }

  // The line above the table once a list has been dropped.
  ChecksumSummary summary() const {
    if (lists_.empty())
      return {};
    std::string names = lists_.front().name;
    if (lists_.size() == 2U)
      names += " and " + lists_[1].name;
    else if (lists_.size() > 2U)
      names += " and " + std::to_string(lists_.size() - 1U) + " more lists";
    std::size_t listed = 0;
    std::size_t pending = 0;
    std::size_t counts[7] = {};
    for (std::size_t index = 0; index < rows_.size(); ++index) {
      const ChecksumCheck state = check(index);
      ++counts[static_cast<std::size_t>(state)];
      listed += rows_[index].list ? 1U : 0U;
      pending += state == ChecksumCheck::pending ? 1U : 0U;
    }
    const auto count = [&](ChecksumCheck state) { return counts[static_cast<std::size_t>(state)]; };
    if (pending != 0U) {
      return {"Checking against " + names + ": " + std::to_string(listed - pending) + " of " +
                  std::to_string(listed) + " listed files read.",
              0};
    }
    if (listed == 0U)
      return {names + " does not name any file in this window.", 3};
    const std::size_t matched = count(ChecksumCheck::match);
    if (matched == listed && count(ChecksumCheck::not_listed) == 0U) {
      return {names + ": " + (matched == 1U ? std::string("the listed file matches.")
                                            : "all " + std::to_string(matched) +
                                                  " listed files match."),
              1};
    }
    std::string parts;
    const auto part = [&](std::size_t number, const char* one, const char* many) {
      if (number == 0U)
        return;
      parts += (parts.empty() ? "" : ", ") + std::to_string(number) + " " +
               (number == 1U ? one : many);
    };
    part(matched, "matches", "match");
    part(count(ChecksumCheck::mismatch), "does not match", "do not match");
    part(count(ChecksumCheck::missing), "not found", "not found");
    part(count(ChecksumCheck::not_checked), "not checked", "not checked");
    part(count(ChecksumCheck::not_listed), "not listed", "not listed");
    const int state = count(ChecksumCheck::mismatch) + count(ChecksumCheck::missing) != 0U ? 2
                      : count(ChecksumCheck::not_checked) != 0U                          ? 3
                                                                                          : 1;
    return {names + ": " + parts + ".", state};
  }

  // Copy all: a heading row and one tab-separated row per file. The Check column is there once a
  // list has been dropped, as it is in the window.
  std::string copy_all(std::string_view line_end) const {
    std::string text =
        has_lists() ? "File\tSHA-256\tCheck\tSize\tFolder" : "File\tSHA-256\tSize\tFolder";
    text += line_end;
    for (std::size_t index = 0; index < rows_.size(); ++index) {
      text += file_text(index) + "\t" + hash_text(index) + "\t";
      if (has_lists())
        text += check_text(index) + "\t";
      text += size_text(index) + "\t" + folder_text(index);
      text += line_end;
    }
    return text;
  }

private:
  // Gives a row the first list, from `first_list` on, that names its file: the entry whose path
  // beside the list is the file itself, or failing that the entry with the same file name.
  void match(ChecksumRow& row, std::size_t first_list) const {
    const std::string path_key = checksum_detail::comparable_path(row.path);
    const std::string name_key = checksum_detail::comparable(path_to_utf8(row.path.filename()));
    for (std::size_t list_index = first_list; list_index < lists_.size(); ++list_index) {
      const ChecksumList& list = lists_[list_index];
      const std::filesystem::path folder = list.path.parent_path();
      std::optional<std::size_t> by_name;
      for (std::size_t entry_index = 0; entry_index < list.entries.size(); ++entry_index) {
        const std::string& name = list.entries[entry_index].name;
        const std::filesystem::path beside = sha256_sums_entry_path(folder, name);
        if (!beside.empty() && checksum_detail::comparable_path(beside) == path_key) {
          by_name = entry_index;
          break;
        }
        if (!by_name &&
            checksum_detail::comparable(checksum_detail::listed_file_name(name)) == name_key)
          by_name = entry_index;
      }
      if (by_name) {
        row.list = list_index;
        row.expected = list.entries[*by_name].sha256;
        row.listed_name = list.entries[*by_name].name;
        return;
      }
    }
  }

  // Whether a row already stands for this file.
  bool holds(const std::filesystem::path& path) const {
    const std::string key = checksum_detail::comparable_path(path);
    for (const auto& row : rows_) {
      if (row.kind != ChecksumRowKind::outside && checksum_detail::comparable_path(row.path) == key)
        return true;
    }
    return false;
  }

  std::vector<ChecksumRow> rows_;
  std::vector<ChecksumList> lists_;
};

}  // namespace support_assist::gui
