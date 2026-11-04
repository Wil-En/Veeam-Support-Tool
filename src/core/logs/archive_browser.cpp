#include "support_assist/archive_browser.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif

namespace support_assist {
namespace {

Error archive_error(std::string operation, const std::filesystem::path& source, std::string message) {
  Error error;
  error.component = "Archive Browser";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.recoverable = true;
  return error;
}

// Archive-member path helpers.
//
// Guarded because they are used only by the libarchive code paths below. A build configured
// without libarchive compiled them as dead code, which GCC rejects under -Werror=unused-function
// while MSVC stays silent - so the Linux build broke and the Windows build never noticed.
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
std::string normalized_member(std::string value) {
  std::replace(value.begin(), value.end(), '\\', '/');
  while (value.starts_with("./")) value.erase(0U, 2U);
  while (!value.empty() && value.front() == '/') value.erase(value.begin());
  while (!value.empty() && value.back() == '/') value.pop_back();
  return value;
}

bool unsafe_raw_member(std::string_view value) {
  if (value.empty()) return true;
  if (value.front() == '/' || value.front() == '\\') return true;
  // Reject Windows drive-qualified archive member names as well as UNC-like
  // paths. Archive browsing is read-only, but keeping the virtual namespace
  // relative prevents a later extraction feature from inheriting a trap.
  if (value.size() >= 2U && ((value[0] >= 'A' && value[0] <= 'Z') ||
                             (value[0] >= 'a' && value[0] <= 'z')) &&
      value[1] == ':') return true;
  return false;
}

bool safe_member(std::string_view value) {
  if (value.empty()) return false;
  std::size_t start = 0U;
  while (start <= value.size()) {
    const std::size_t end = value.find('/', start);
    const auto part = value.substr(start, end == std::string_view::npos ? value.size() - start : end - start);
    if (part == ".." || part.empty()) return false;
    if (end == std::string_view::npos) break;
    start = end + 1U;
  }
  return true;
}

class Reader {
public:
  Reader() : value_(archive_read_new()) {}
  ~Reader() { if (value_ != nullptr) archive_read_free(value_); }
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;
  archive* get() const noexcept { return value_; }
private:
  archive* value_ = nullptr;
};

Status open_archive(Reader& reader, const std::filesystem::path& path) {
  if (reader.get() == nullptr)
    return Status::failure(archive_error("open", path, "Could not allocate archive reader"));
  archive_read_support_filter_all(reader.get());
  archive_read_support_format_all(reader.get());
  #ifdef _WIN32
  // libarchive's narrow open takes an ANSI path on Windows, and building that string via
  // path::string() throws for any non-ANSI character - a customer bundle under a path with
  // accented or CJK characters would fail before a single entry was read. The _w variant
  // takes the native wide path directly.
  if (archive_read_open_filename_w(reader.get(), path.wstring().c_str(), 128U * 1024U) != ARCHIVE_OK)
#else
  if (archive_read_open_filename(reader.get(), path.string().c_str(), 128U * 1024U) != ARCHIVE_OK)
#endif
    return Status::failure(archive_error("open", path, archive_error_string(reader.get()) == nullptr
                                                     ? "Could not open archive"
                                                     : archive_error_string(reader.get())));
  return Status::success();
}
#endif

} // namespace

bool archive_browser_available() noexcept {
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  return true;
#else
  return false;
#endif
}

Result<std::vector<ArchiveBrowserEntry>> archive_list_directory(
    const std::filesystem::path& archive_path,
    std::string_view virtual_directory) {
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  Reader reader;
  if (auto opened = open_archive(reader, archive_path); !opened.ok())
    return Result<std::vector<ArchiveBrowserEntry>>::failure(opened.error());

  std::string prefix = normalized_member(std::string(virtual_directory));
  if (!prefix.empty()) prefix += '/';
  std::map<std::string, ArchiveBrowserEntry> visible;
  archive_entry* raw_entry = nullptr;
  while (archive_read_next_header(reader.get(), &raw_entry) == ARCHIVE_OK) {
    const char* raw_name = archive_entry_pathname(raw_entry);
    if (raw_name == nullptr || unsafe_raw_member(raw_name)) { archive_read_data_skip(reader.get()); continue; }
    const std::string full = normalized_member(raw_name);
    if (!safe_member(full) || (!prefix.empty() && !full.starts_with(prefix))) {
      archive_read_data_skip(reader.get());
      continue;
    }
    const std::string remainder = prefix.empty() ? full : full.substr(prefix.size());
    if (remainder.empty()) { archive_read_data_skip(reader.get()); continue; }
    const std::size_t slash = remainder.find('/');
    const std::string child_name = slash == std::string::npos ? remainder : remainder.substr(0U, slash);
    if (child_name.empty()) { archive_read_data_skip(reader.get()); continue; }
    const bool virtual_dir = slash != std::string::npos;
    const std::string child_path = prefix + child_name;
    auto& item = visible[ascii_lower(child_name)];
    if (item.name.empty()) {
      item.name = child_name;
      item.path = child_path;
      item.directory = virtual_dir || archive_entry_filetype(raw_entry) == AE_IFDIR;
      if (!item.directory && archive_entry_size_is_set(raw_entry) != 0)
        item.size = static_cast<std::uint64_t>(std::max<la_int64_t>(0, archive_entry_size(raw_entry)));
      item.modified_unix = static_cast<std::int64_t>(archive_entry_mtime(raw_entry));
    } else if (virtual_dir) {
      item.directory = true;
      item.size = 0U;
    }
    archive_read_data_skip(reader.get());
  }
  std::vector<ArchiveBrowserEntry> result;
  result.reserve(visible.size());
  for (auto& [_, item] : visible) result.push_back(std::move(item));
  std::stable_sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
    if (left.directory != right.directory) return left.directory;
    return ascii_lower(left.name) < ascii_lower(right.name);
  });
  return Result<std::vector<ArchiveBrowserEntry>>::success(std::move(result));
#else
  static_cast<void>(archive_path); static_cast<void>(virtual_directory);
  return Result<std::vector<ArchiveBrowserEntry>>::failure(
      archive_error("list", archive_path, "Archive browsing is unavailable in this build"));
#endif
}

Result<std::string> archive_read_member_text(const std::filesystem::path& archive_path,
                                             std::string_view member_path,
                                             std::size_t maximum_bytes) {
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
  if (unsafe_raw_member(member_path))
    return Result<std::string>::failure(archive_error("read member", archive_path, "Unsafe archive member path"));
  const std::string wanted = normalized_member(std::string(member_path));
  if (!safe_member(wanted))
    return Result<std::string>::failure(archive_error("read member", archive_path, "Unsafe archive member path"));
  Reader reader;
  if (auto opened = open_archive(reader, archive_path); !opened.ok())
    return Result<std::string>::failure(opened.error());
  archive_entry* raw_entry = nullptr;
  while (archive_read_next_header(reader.get(), &raw_entry) == ARCHIVE_OK) {
    const char* raw_name = archive_entry_pathname(raw_entry);
    if (raw_name == nullptr || unsafe_raw_member(raw_name) || normalized_member(raw_name) != wanted) {
      archive_read_data_skip(reader.get());
      continue;
    }
    if (archive_entry_filetype(raw_entry) == AE_IFDIR)
      return Result<std::string>::failure(archive_error("read member", archive_path, "The selected archive member is a directory"));
    std::string output;
    output.reserve(std::min<std::size_t>(maximum_bytes, 1024U * 1024U));
    std::vector<char> buffer(64U * 1024U);
    while (output.size() < maximum_bytes) {
      const std::size_t remaining = maximum_bytes - output.size();
      const la_ssize_t read = archive_read_data(reader.get(), buffer.data(), std::min(buffer.size(), remaining));
      if (read == 0) break;
      if (read < 0)
        return Result<std::string>::failure(archive_error("read member", archive_path,
            archive_error_string(reader.get()) == nullptr ? "Could not read archive member" : archive_error_string(reader.get())));
      output.append(buffer.data(), static_cast<std::size_t>(read));
    }
    const bool truncated = output.size() >= maximum_bytes;
    static_cast<void>(archive_read_data_skip(reader.get()));
    if (truncated)
      output += "\n\n[Preview truncated by Support Assist Tool]\n";
    return Result<std::string>::success(std::move(output));
  }
  return Result<std::string>::failure(archive_error("read member", archive_path, "Archive member was not found"));
#else
  static_cast<void>(member_path); static_cast<void>(maximum_bytes);
  return Result<std::string>::failure(archive_error("read member", archive_path, "Archive browsing is unavailable in this build"));
#endif
}

} // namespace support_assist
