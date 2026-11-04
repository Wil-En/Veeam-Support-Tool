#pragma once
#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/models.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/registry.hpp"
#include "support_assist/snapshot_store.hpp"
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>
namespace support_assist {
enum class HashMode { none, all, below_size, extensions };
struct FilesystemScanOptions {
  std::filesystem::path root;
  std::vector<std::string> exclusions;
  bool follow_reparse_points = false;
  std::uint32_t maximum_depth = 1024;
  std::uint64_t maximum_objects = 100000000;
  HashMode hash_mode = HashMode::none;
  std::uint64_t hash_size_limit = 64ULL * 1024ULL * 1024ULL;
  std::vector<std::string> hash_extensions;
  bool capture_streams = false;
  bool capture_file_identity = true;
  bool hydrate_cloud_files = false;
  std::size_t batch_size = 1000;
  // Windows: read the folder from the NTFS master file table when SAT runs as administrator and
  // the folder is on a local NTFS volume, folder by folder otherwise. A compare with now reads
  // the folder the way its capture was read.
  bool try_mft = true;
};
Result<ScanSummary> scan_filesystem(SnapshotStore& store,
                                    std::string_view snapshot_id,
                                    const FilesystemScanOptions& options,
                                    const CancellationToken& cancel,
                                    ProgressCallback progress);
struct FilesystemCompareOptions {
  std::int64_t timestamp_tolerance_100ns = 0;
  bool detect_moves = true;
  bool infer_moves_by_hash = true;
  // Reading a file moves its last-access time, so by default that alone is not a difference.
  bool ignore_access_time = true;
};
Result<std::uint64_t> compare_filesystem(const std::filesystem::path& before,
                                         std::string_view before_id,
                                         const std::filesystem::path& after,
                                         std::string_view after_id,
                                         const FilesystemCompareOptions& options,
                                         const DiffCallback& callback,
                                         const CancellationToken& cancel = CancellationToken{},
                                         ProgressCallback progress = {});
// The stages compare_filesystem reports through `progress`: phase "Comparing", the stage's name and
// the differences found so far in current_scope, and the stage number in processed of
// kCompareStages in total.
inline constexpr std::uint64_t kCompareStages = 6;
Result<std::string> hash_file_sha256(const std::filesystem::path& path,
                                     const CancellationToken& cancel);

// A SHA-256 value as a person pastes it - any case, and with or without the spaces older certutil
// output puts between bytes - reduced to the 64 lowercase hex characters hash_file_sha256 returns.
// Empty when the text is not a SHA-256 value.
inline std::string normalize_sha256_text(std::string_view text) {
  std::string hex;
  hex.reserve(64U);
  for (const char character : text) {
    if (character == ' ' || character == '\t' || character == '\r' || character == '\n')
      continue;
    if (character >= '0' && character <= '9')
      hex += character;
    else if (character >= 'a' && character <= 'f')
      hex += character;
    else if (character >= 'A' && character <= 'F')
      hex += static_cast<char>(character - 'A' + 'a');
    else
      return {};
  }
  return hex.size() == 64U ? hex : std::string();
}

// One line of a SHA256SUMS list: the expected value and the file it names, relative to the list.
struct Sha256SumsEntry {
  std::string sha256;  // 64 lowercase hex characters
  std::string name;    // as written, with any leading "./" removed
};

// The entries of a checksum list in the form sha256sum writes ("<hash>  <name>", or " *<name>" for
// binary mode) or the BSD form ("SHA256 (<name>) = <hash>"). Blank lines and "#" comments are
// skipped. Any other line means the text is not a checksum list, and the result is empty, so an
// ordinary text file is never read as one.
inline std::vector<Sha256SumsEntry> parse_sha256_sums(std::string_view text) {
  std::vector<Sha256SumsEntry> entries;
  if (text.size() >= 3U && static_cast<unsigned char>(text[0]) == 0xEF &&
      static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF)
    text.remove_prefix(3U);
  const auto clean_name = [](std::string_view name) {
    while (name.size() >= 2U && name.substr(0, 2) == "./")
      name.remove_prefix(2U);
    return std::string(name);
  };
  while (!text.empty()) {
    const std::size_t end = text.find('\n');
    std::string_view line = text.substr(0, end);
    text = end == std::string_view::npos ? std::string_view() : text.substr(end + 1U);
    while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
      line.remove_suffix(1U);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
      line.remove_prefix(1U);
    if (line.empty() || line.front() == '#')
      continue;
    // sha256sum escapes a name holding a backslash or a newline and marks the line with "\".
    const bool escaped = line.front() == '\\';
    if (escaped)
      line.remove_prefix(1U);

    Sha256SumsEntry entry;
    if (line.size() > 66U && normalize_sha256_text(line.substr(0, 64U)).size() == 64U &&
        line[64] == ' ') {
      entry.sha256 = normalize_sha256_text(line.substr(0, 64U));
      std::string_view name = line.substr(65U);
      if (!name.empty() && (name.front() == ' ' || name.front() == '*'))
        name.remove_prefix(1U);
      entry.name = clean_name(name);
    } else if (line.substr(0, 8) == "SHA256 (" && line.size() > 8U) {
      const std::size_t close = line.rfind(") = ");
      if (close == std::string_view::npos || close < 8U)
        return {};
      entry.sha256 = normalize_sha256_text(line.substr(close + 4U));
      entry.name = clean_name(line.substr(8U, close - 8U));
    } else {
      return {};
    }
    if (entry.sha256.empty() || entry.name.empty())
      return {};
    if (escaped) {
      std::string unescaped;
      for (std::size_t index = 0; index < entry.name.size(); ++index) {
        if (entry.name[index] == '\\' && index + 1U < entry.name.size()) {
          const char next = entry.name[++index];
          unescaped += next == 'n' ? '\n' : next;
        } else {
          unescaped += entry.name[index];
        }
      }
      entry.name = unescaped;
    }
    entries.push_back(std::move(entry));
  }
  return entries;
}

// Whether a file name is one checksum lists are published under: SHA256SUMS (with any suffix, such
// as SHA256SUMS-<version>.txt), or an extension of .sha256, .sha256sum or .sha256sums.
inline bool looks_like_sha256_sums_name(std::string_view name) {
  std::string folded;
  folded.reserve(name.size());
  for (const char character : name)
    folded += (character >= 'A' && character <= 'Z') ? static_cast<char>(character - 'A' + 'a')
                                                     : character;
  const auto ends_with = [&](std::string_view suffix) {
    return folded.size() >= suffix.size() &&
           folded.compare(folded.size() - suffix.size(), suffix.size(), suffix) == 0;
  };
  return folded.rfind("sha256sums", 0) == 0 || ends_with(".sha256") || ends_with(".sha256sum") ||
         ends_with(".sha256sums");
}

// The entries of a checksum list file whose text has been read. Beyond the forms
// parse_sha256_sums reads, a file named "<name>.sha256" or "<name>.sha256sum" that holds a single
// value and no file name gives the value for <name>, as many download pages publish it.
inline std::vector<Sha256SumsEntry> sha256_sums_from_file_text(std::string_view text,
                                                               std::string_view list_name) {
  std::vector<Sha256SumsEntry> entries = parse_sha256_sums(text);
  if (!entries.empty())
    return entries;
  std::string folded;
  for (const char character : list_name)
    folded += (character >= 'A' && character <= 'Z') ? static_cast<char>(character - 'A' + 'a')
                                                     : character;
  std::size_t suffix = 0;
  if (folded.size() > 7U && folded.ends_with(".sha256"))
    suffix = 7U;
  else if (folded.size() > 10U && folded.ends_with(".sha256sum"))
    suffix = 10U;
  if (suffix == 0U)
    return entries;
  if (text.size() >= 3U && static_cast<unsigned char>(text[0]) == 0xEF &&
      static_cast<unsigned char>(text[1]) == 0xBB && static_cast<unsigned char>(text[2]) == 0xBF)
    text.remove_prefix(3U);
  std::string sha256 = normalize_sha256_text(text);
  if (!sha256.empty()) {
    const std::string_view named = list_name.substr(0, list_name.size() - suffix);
    entries.push_back({std::move(sha256), std::string(named)});
  }
  return entries;
}

// Where a file named in a checksum list is looked for: in the list's folder, or below it. A name
// that is absolute, starts with a drive or a server, climbs out with "..", or names a Windows
// alternate stream gives an empty path, so a list only ever leads to files beside it.
inline std::filesystem::path sha256_sums_entry_path(const std::filesystem::path& list_folder,
                                                    std::string_view name) {
  std::u8string utf8;
  utf8.reserve(name.size());
  for (const char character : name)
    utf8.push_back(static_cast<char8_t>(character));
  const std::filesystem::path relative(utf8);
  if (relative.empty() || relative.has_root_name() || relative.has_root_directory())
    return {};
  for (const auto& part : relative) {
    if (part == std::filesystem::path(u8".."))
      return {};
  }
#ifdef _WIN32
  if (name.find(':') != std::string_view::npos)
    return {};
#endif
  return list_folder / relative;
}

// Capturing a filesystem baseline is a SEQUENCE, not a call: create the snapshot store, begin the
// snapshot, persist the scan configuration so a later comparison can reproduce exactly what was
// captured, scan, then finish with the right terminal state. Every frontend was reimplementing
// that sequence with its own copy of the ordering and its own error handling - which means one
// fix has to be made in as many places as there are frontends, and the copies drift. It belongs
// here, once.
struct FilesystemBaselineResult {
  std::string snapshot_id;
  SnapshotState state = SnapshotState::complete;
  std::uint64_t objects = 0;
  std::uint64_t errors = 0;
  std::string source;      // as ScanSummary::source
  std::string source_note; // as ScanSummary::source_note
};

Result<FilesystemBaselineResult> capture_filesystem_baseline(
    const std::filesystem::path& snapshot_path,
    const FilesystemScanOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {},
    std::string_view options_json = "{}");

// Reads a completed baseline's own scan configuration back out so a comparison reproduces what the
// baseline actually captured rather than guessing at it. Fails if the file is not a complete
// filesystem baseline, which is the check every frontend had to remember to write for itself.
Result<FilesystemScanOptions> load_filesystem_baseline_options(
    const std::filesystem::path& snapshot_path,
    std::string& snapshot_id);

// The text form of a hash mode as it is persisted in a baseline, and back again. Keeping both
// directions next to each other is what stops a baseline being readable but not reproducible.
std::string to_string(HashMode mode);
HashMode parse_hash_mode(std::string_view value);
} // namespace support_assist
