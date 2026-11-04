#pragma once

// Files and folders handed to SAT by the desktop, dropped on its window or on the application
// itself (which starts it with their paths as arguments). A file is read to show its SHA-256; a
// folder is offered to Log Review. Nothing dropped is run or opened with its own program.

#include <filesystem>
#include <string>
#include <system_error>
#include <vector>

namespace support_assist::gui {

struct DroppedPaths {
  std::vector<std::filesystem::path> files;    // regular files: their SHA-256 is shown
  std::vector<std::filesystem::path> folders;  // folders: offered to Log Review
  std::vector<std::filesystem::path> skipped;  // anything else: devices, pipes, missing paths
};

// Sorted by what each path is on disk now. Only a regular file is hashed, so a device or a pipe
// dropped by accident is never read.
inline DroppedPaths sort_dropped_paths(const std::vector<std::filesystem::path>& paths) {
  DroppedPaths sorted;
  for (const auto& path : paths) {
    std::error_code error;
    const std::filesystem::file_status status = std::filesystem::status(path, error);
    if (std::filesystem::is_directory(status))
      sorted.folders.push_back(path);
    else if (std::filesystem::is_regular_file(status))
      sorted.files.push_back(path);
    else
      sorted.skipped.push_back(path);
  }
  return sorted;
}

// True when a launch's arguments are only paths the desktop handed over: every one absolute and
// present on disk. A command line always starts with a command word, so the two are never confused.
inline bool arguments_are_dropped_paths(const std::vector<std::filesystem::path>& arguments) {
  if (arguments.empty())
    return false;
  for (const auto& argument : arguments) {
    std::error_code error;
    if (!argument.is_absolute() || !std::filesystem::exists(argument, error))
      return false;
  }
  return true;
}

}  // namespace support_assist::gui
