#pragma once

#include "support_assist/error.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct ArchiveBrowserEntry {
  std::string name;
  std::string path;
  bool directory = false;
  std::uint64_t size = 0;
  std::int64_t modified_unix = 0;
};

bool archive_browser_available() noexcept;

// Lists one virtual directory from a supported archive without extracting it.
// Unsafe absolute/traversal members are omitted from the view.
Result<std::vector<ArchiveBrowserEntry>> archive_list_directory(
    const std::filesystem::path& archive_path,
    std::string_view virtual_directory = {});

// Reads one archive member into memory for bounded text/log preview. No member
// is ever written to disk by this function.
Result<std::string> archive_read_member_text(const std::filesystem::path& archive_path,
                                             std::string_view member_path,
                                             std::size_t maximum_bytes = 16U * 1024U * 1024U);

} // namespace support_assist
