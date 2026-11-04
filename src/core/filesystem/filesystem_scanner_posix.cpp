#include "support_assist/filesystem.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <system_error>

namespace support_assist {
namespace {

bool wildcard_match(std::string_view pattern, std::string_view value) {
  std::size_t pattern_index = 0;
  std::size_t value_index = 0;
  std::size_t star = std::string_view::npos;
  std::size_t star_value = 0;
  while (value_index < value.size()) {
    if (pattern_index < pattern.size() &&
        (pattern[pattern_index] == '?' || pattern[pattern_index] == value[value_index])) {
      ++pattern_index;
      ++value_index;
    } else if (pattern_index < pattern.size() && pattern[pattern_index] == '*') {
      star = pattern_index++;
      star_value = value_index;
    } else if (star != std::string_view::npos) {
      pattern_index = star + 1U;
      value_index = ++star_value;
    } else {
      return false;
    }
  }
  while (pattern_index < pattern.size() && pattern[pattern_index] == '*')
    ++pattern_index;
  return pattern_index == pattern.size();
}

bool excluded(const FilesystemScanOptions& options, std::string_view relative_path) {
  return std::any_of(options.exclusions.begin(), options.exclusions.end(),
                     [&](const std::string& pattern) { return wildcard_match(pattern, relative_path); });
}

std::string extension_utf8(const std::filesystem::path& path) {
  const auto extension = path.extension().u8string();
  return std::string(reinterpret_cast<const char*>(extension.data()), extension.size());
}

bool should_hash(const FilesystemScanOptions& options,
                 const FilesystemRecord& record,
                 const std::filesystem::path& path) {
  if (record.object_type != "file")
    return false;
  switch (options.hash_mode) {
  case HashMode::none:
    return false;
  case HashMode::all:
    return true;
  case HashMode::below_size:
    return record.size <= options.hash_size_limit;
  case HashMode::extensions: {
    const std::string extension = ascii_lower(extension_utf8(path));
    return std::any_of(options.hash_extensions.begin(), options.hash_extensions.end(),
                       [&](const std::string& configured) {
                         return ascii_lower(configured) == extension;
                       });
  }
  }
  return false;
}

Error filesystem_error(std::string operation,
                       const std::filesystem::path& source,
                       const std::error_code& code,
                       bool skipped = true) {
  Error error;
  error.component = "Filesystem";
  error.operation = std::move(operation);
  error.source = source.string();
  error.native_code = code.value();
  error.message = code.message();
  error.recoverable = true;
  error.skipped = skipped;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

} // namespace

Result<ScanSummary> scan_filesystem(SnapshotStore& store,
                                    std::string_view snapshot_id,
                                    const FilesystemScanOptions& options,
                                    const CancellationToken& cancel,
                                    ProgressCallback progress) {
  ScanSummary summary;
  std::error_code error;
  if (!std::filesystem::exists(options.root, error) || error) {
    Error failure;
    failure.component = "Filesystem";
    failure.operation = "scan";
    failure.source = options.root.string();
    failure.native_code = error.value();
    failure.message = error ? error.message() : "Root does not exist";
    return Result<ScanSummary>::failure(std::move(failure));
  }

  const auto started = std::chrono::steady_clock::now();
  const auto add = [&](const std::filesystem::directory_entry& entry,
                       const std::filesystem::path& relative) -> Status {
    FilesystemRecord record;
    record.snapshot_id = std::string(snapshot_id);
    record.relative_path = relative.generic_string();
    record.source_path = entry.path().string();

    std::error_code local_error;
    const auto symlink_status = entry.symlink_status(local_error);
    if (local_error) {
      record.object_type = "unknown";
      record.enumeration_error = local_error.message();
    } else if (std::filesystem::is_symlink(symlink_status)) {
      record.object_type = "reparse";
    } else if (std::filesystem::is_directory(symlink_status)) {
      record.object_type = "directory";
    } else {
      record.object_type = "file";
    }

    if (record.object_type == "file") {
      record.size = entry.file_size(local_error);
      if (local_error) {
        record.enumeration_error = local_error.message();
        local_error.clear();
      }
    }

    const auto timestamp = entry.last_write_time(local_error);
    if (!local_error) {
      const auto system_time = std::chrono::clock_cast<std::chrono::system_clock>(timestamp);
      record.write_100ns =
          std::chrono::duration_cast<std::chrono::nanoseconds>(system_time.time_since_epoch()).count() /
          100;
    } else {
      if (record.enumeration_error.empty())
        record.enumeration_error = local_error.message();
      local_error.clear();
    }

    if (should_hash(options, record, entry.path())) {
      auto hash = hash_file_sha256(entry.path(), cancel);
      if (hash.ok()) {
        record.content_hash = std::move(hash.value());
        record.hash_algorithm = "SHA-256";
        record.hash_status = "complete";
      } else {
        record.hash_status = "error";
        record.enumeration_error = hash.error().message;
        static_cast<void>(store.add_error(snapshot_id, hash.error()));
        ++summary.errors;
      }
    }

    // Alternate data streams, Windows cloud-file hydration and Windows file IDs do not
    // have a truthful portable equivalent. POSIX baselines intentionally leave those
    // Windows-specific fields empty while preserving the common comparison schema.
    auto status = store.add_filesystem_object(record);
    if (!status.ok())
      return status;
    ++summary.objects;
    return Status::success();
  };

  std::filesystem::directory_entry root_entry(options.root, error);
  if (!error) {
    auto status = add(root_entry, std::filesystem::path("."));
    if (!status.ok())
      return Result<ScanSummary>::failure(status.error());
  } else {
    static_cast<void>(store.add_error(snapshot_id, filesystem_error("stat root", options.root, error)));
    ++summary.errors;
    error.clear();
  }

  const auto directory_options = options.follow_reparse_points
                                     ? std::filesystem::directory_options::skip_permission_denied |
                                           std::filesystem::directory_options::follow_directory_symlink
                                     : std::filesystem::directory_options::skip_permission_denied;
  std::filesystem::recursive_directory_iterator iterator(options.root, directory_options, error), end;
  if (error) {
    return Result<ScanSummary>::failure(filesystem_error("enumerate root", options.root, error, false));
  }

  for (; iterator != end; iterator.increment(error)) {
    if (cancel.is_cancelled()) {
      summary.cancelled = true;
      break;
    }
    if (error) {
      const auto source = iterator == end ? options.root : iterator->path();
      static_cast<void>(store.add_error(snapshot_id, filesystem_error("enumerate", source, error)));
      ++summary.errors;
      error.clear();
      continue;
    }

    if (static_cast<std::uint32_t>(iterator.depth()) > options.maximum_depth) {
      iterator.disable_recursion_pending();
      continue;
    }
    auto relative = std::filesystem::relative(iterator->path(), options.root, error);
    if (error) {
      static_cast<void>(store.add_error(snapshot_id, filesystem_error("make relative path", iterator->path(), error)));
      ++summary.errors;
      error.clear();
      continue;
    }
    const std::string relative_text = relative.generic_string();
    if (excluded(options, relative_text)) {
      std::error_code type_error;
      if (iterator->is_directory(type_error) && !type_error)
        iterator.disable_recursion_pending();
      continue;
    }

    auto status = add(*iterator, relative);
    if (!status.ok())
      return Result<ScanSummary>::failure(status.error());
    if (summary.objects >= options.maximum_objects) {
      summary.cancelled = true;
      break;
    }
    if (progress && summary.objects % std::max<std::size_t>(1U, options.batch_size) == 0U) {
      const double seconds =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      progress(ProgressEvent{"filesystem-scan",
                             iterator->path().string(),
                             summary.objects,
                             summary.errors,
                             seconds,
                             seconds > 0.0 ? static_cast<double>(summary.objects) / seconds : 0.0});
    }
  }
  return Result<ScanSummary>::success(summary);
}

} // namespace support_assist
