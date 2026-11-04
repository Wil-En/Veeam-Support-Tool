#include "support_assist/activity_record.hpp"

#include "support_assist/archive_browser.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <array>
#include <deque>
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace support_assist {
namespace {

constexpr std::size_t kRecordByteLimit = 64U * 1024U * 1024U;
constexpr std::size_t kInspectLimit = 50000U;
constexpr std::string_view kRecordName = "activity.tsv";

Error activity_error(std::string operation, const std::filesystem::path& source, std::string message) {
  Error error;
  error.component = "ActivityRecord";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

bool ends_with(std::string_view text, std::string_view suffix) {
  return text.size() >= suffix.size() && text.substr(text.size() - suffix.size()) == suffix;
}

bool is_archive(const std::filesystem::path& path) {
  const std::string name = ascii_lower(path_to_utf8(path.filename()));
  return ends_with(name, ".zip") || ends_with(name, ".7z") || ends_with(name, ".tar") ||
         ends_with(name, ".tar.gz") || ends_with(name, ".tgz") || ends_with(name, ".tar.bz2") ||
         ends_with(name, ".tar.xz");
}

bool in_application_logs(std::string_view parent_name) {
  return ascii_lower(parent_name) == "applicationlogs";
}

// The record in a folder: the first under an ApplicationLogs folder, or else the first found.
std::filesystem::path find_in_folder(const std::filesystem::path& folder) {
  std::filesystem::path found;
  std::size_t inspected = 0;
  std::error_code error;
  std::filesystem::recursive_directory_iterator walker(
      folder, std::filesystem::directory_options::skip_permission_denied, error);
  const std::filesystem::recursive_directory_iterator end;
  for (; !error && walker != end && inspected < kInspectLimit; walker.increment(error)) {
    ++inspected;
    if (ascii_lower(path_to_utf8(walker->path().filename())) != kRecordName)
      continue;
    if (in_application_logs(path_to_utf8(walker->path().parent_path().filename())))
      return walker->path();
    if (found.empty())
      found = walker->path();
  }
  return found;
}

// The record in an archive, its directories read breadth first, the ApplicationLogs copy first.
std::string find_in_archive(const std::filesystem::path& archive) {
  std::string found;
  std::deque<std::string> pending{""};
  std::size_t inspected = 0;
  while (!pending.empty() && inspected < kInspectLimit) {
    const std::string directory = pending.front();
    pending.pop_front();
    auto entries = archive_list_directory(archive, directory);
    if (!entries.ok())
      continue;
    for (const ArchiveBrowserEntry& entry : entries.value()) {
      ++inspected;
      if (entry.directory) {
        pending.push_back(entry.path);
        continue;
      }
      if (ascii_lower(entry.name) != kRecordName)
        continue;
      if (ascii_lower(entry.path).find("applicationlogs/") != std::string::npos)
        return entry.path;
      if (found.empty())
        found = entry.path;
    }
  }
  return found;
}

} // namespace

std::vector<ActivityEntry> parse_activity_record(std::string_view text) {
  std::vector<ActivityEntry> entries;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos)
      end = text.size();
    std::string_view line = text.substr(start, end - start);
    start = end + 1U;
    while (!line.empty() && line.back() == '\r')
      line.remove_suffix(1);
    if (line.empty())
      continue;
    std::array<std::string, 5> fields{};
    std::size_t field_start = 0;
    for (std::size_t field = 0; field < fields.size(); ++field) {
      const std::size_t tab = line.find('\t', field_start);
      fields[field] = std::string(line.substr(field_start, tab == std::string_view::npos
                                                                ? std::string_view::npos
                                                                : tab - field_start));
      if (tab == std::string_view::npos)
        break;
      field_start = tab + 1U;
    }
    entries.push_back({std::move(fields[0]), std::move(fields[1]), std::move(fields[2]), std::move(fields[3]),
                       std::move(fields[4])});
  }
  if (entries.size() > kActivityEntryLimit)
    entries.erase(entries.begin(), entries.end() - static_cast<std::ptrdiff_t>(kActivityEntryLimit));
  std::reverse(entries.begin(), entries.end());
  return entries;
}

Result<ArchivedActivity> open_archived_activity(const std::filesystem::path& chosen) {
  if (chosen.empty())
    return Result<ArchivedActivity>::failure(
        activity_error("open", chosen, "Choose a collected bundle folder, a ZIP or an Activity TSV."));
  std::filesystem::path path = chosen;
  std::error_code error;
  if (std::filesystem::is_directory(path, error)) {
    path = find_in_folder(chosen);
    if (path.empty())
      return Result<ArchivedActivity>::failure(activity_error(
          "find", chosen,
          "No activity.tsv was found in that folder. Choose a collected SAT bundle, its ApplicationLogs "
          "folder or the Activity TSV itself."));
  }

  ArchivedActivity opened;
  opened.source = path;
  std::string text;
  if (is_archive(path)) {
    if (!archive_browser_available())
      return Result<ArchivedActivity>::failure(
          activity_error("open", path, "This build cannot read archives. Extract it and choose the folder."));
    opened.member = find_in_archive(path);
    if (opened.member.empty())
      return Result<ArchivedActivity>::failure(activity_error(
          "find", path,
          "No activity.tsv was found inside that archive. Choose a collected SAT bundle, its "
          "ApplicationLogs folder or the Activity TSV itself."));
    auto read = archive_read_member_text(path, opened.member, kRecordByteLimit);
    if (!read.ok())
      return Result<ArchivedActivity>::failure(read.error());
    text = std::move(read.value());
  } else {
    std::ifstream input(path, std::ios::binary);
    if (!input)
      return Result<ArchivedActivity>::failure(
          activity_error("open", path, "The Activity TSV could not be opened."));
    // A record past the limit is read from its newest part, from the first whole line in it.
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    const auto limit = static_cast<std::streamoff>(kRecordByteLimit);
    const bool trimmed = size > limit;
    input.seekg(trimmed ? size - limit : 0, std::ios::beg);
    text.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
    if (trimmed) {
      const std::size_t line_end = text.find('\n');
      text.erase(0, line_end == std::string::npos ? text.size() : line_end + 1U);
    }
  }
  opened.entries = parse_activity_record(text);
  return Result<ArchivedActivity>::success(std::move(opened));
}

} // namespace support_assist
