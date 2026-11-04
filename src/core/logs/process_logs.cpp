#include "support_assist/process_logs.hpp"

#include "support_assist/log_clock.hpp"
#include "support_assist/log_collection.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <system_error>

namespace support_assist {

namespace {

std::int64_t written_unix_millis(const std::filesystem::file_time_type& value) {
  const auto system_value = std::chrono::time_point_cast<std::chrono::milliseconds>(
      value - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
  return system_value.time_since_epoch().count();
}

bool is_log_file(const std::filesystem::path& path) {
  const std::string extension = ascii_lower(path_to_utf8(path.extension()));
  return extension == ".log" || extension == ".txt";
}

// A folder walk stops here: a backup server's log tree holds tens of thousands of files.
constexpr std::size_t kMaximumEntries = 400000;
constexpr std::uintmax_t kTailBytes = 32ULL * 1024ULL * 1024ULL;

} // namespace

std::vector<std::filesystem::path> veeam_log_folders() {
  const ProductDiscoveryContext context = native_product_discovery_context();
  std::set<std::filesystem::path> folders;
  const auto add = [&folders](const std::filesystem::path& path) {
    std::error_code error;
    if (!path.empty() && std::filesystem::is_directory(path, error) && !error)
      folders.insert(path.lexically_normal());
  };
  for (const auto& candidate : discover_shared_veeam_log_sources(context))
    add(candidate.path);
  for (const auto& product : detect_products(context)) {
    for (const auto& rule : product.definition.log_paths) {
      if (!rule.third_party && !rule.sensitive_by_nature)
        add(resolve_catalog_path(context, rule.path));
    }
  }
  // A folder inside another is walked with it.
  std::vector<std::filesystem::path> outer;
  for (const auto& folder : folders) {
    const bool inside = std::any_of(outer.begin(), outer.end(), [&folder](const std::filesystem::path& parent) {
      const auto relative = folder.lexically_relative(parent);
      return !relative.empty() && *relative.begin() != "..";
    });
    if (!inside)
      outer.push_back(folder);
  }
  return outer;
}

std::vector<LogWrittenNear> logs_written_near(const std::vector<std::filesystem::path>& folders,
                                              std::int64_t at_unix_millis, std::size_t limit) {
  std::vector<LogWrittenNear> found;
  std::size_t visited = 0;
  for (const auto& folder : folders) {
    std::error_code error;
    for (std::filesystem::recursive_directory_iterator iterator(
             folder, std::filesystem::directory_options::skip_permission_denied, error),
         end;
         iterator != end && visited < kMaximumEntries; iterator.increment(error)) {
      if (error) {
        error.clear();
        continue;
      }
      ++visited;
      std::error_code entry_error;
      if (!iterator->is_regular_file(entry_error) || entry_error || !is_log_file(iterator->path()))
        continue;
      const auto written = iterator->last_write_time(entry_error);
      if (entry_error)
        continue;
      const std::int64_t millis = written_unix_millis(written);
      if (millis >= at_unix_millis - kLogNearBeforeMillis && millis <= at_unix_millis + kLogNearAfterMillis)
        found.push_back({iterator->path(), millis});
    }
  }
  std::sort(found.begin(), found.end(), [](const LogWrittenNear& left, const LogWrittenNear& right) {
    return left.written_unix_millis != right.written_unix_millis ? left.written_unix_millis > right.written_unix_millis
                                                                 : left.path < right.path;
  });
  if (found.size() > limit)
    found.resize(limit);
  return found;
}

std::uint64_t log_line_before(const std::filesystem::path& path, std::int64_t at_unix_millis, int utc_offset_minutes) {
  std::ifstream input(path, std::ios::binary);
  if (!input)
    return 1;
  std::error_code error;
  const std::uintmax_t size = std::filesystem::file_size(path, error);
  if (error)
    return 1;
  // The lines before the part read are counted, not parsed.
  std::uint64_t line = 1;
  std::uintmax_t start = size > kTailBytes ? size - kTailBytes : 0;
  std::array<char, 64 * 1024> buffer{};
  std::uintmax_t counted = 0;
  while (counted < start) {
    const auto want = static_cast<std::streamsize>(std::min<std::uintmax_t>(buffer.size(), start - counted));
    input.read(buffer.data(), want);
    const std::streamsize got = input.gcount();
    if (got <= 0)
      break;
    line += static_cast<std::uint64_t>(std::count(buffer.data(), buffer.data() + got, '\n'));
    counted += static_cast<std::uintmax_t>(got);
  }
  // The part read starts at a line's start: a cut line before it is skipped.
  std::string text;
  if (start > 0 && start == counted) {
    input.seekg(static_cast<std::streamoff>(start) - 1);
    char previous = '\n';
    input.get(previous);
    if (previous != '\n') {
      std::getline(input, text);
      ++line;
    }
  }
  // The line prefixes read as if UTC; the moment moved into the same local reading.
  const std::int64_t target = at_unix_millis + static_cast<std::int64_t>(utc_offset_minutes) * 60000LL + 1000LL;
  std::uint64_t best = 0;
  while (std::getline(input, text)) {
    if (const auto millis = log_clock_detail::line_prefix_millis(text); millis && *millis <= target)
      best = line;
    ++line;
  }
  return best == 0 ? 1 : best;
}

} // namespace support_assist
