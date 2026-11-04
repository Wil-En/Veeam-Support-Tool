#pragma once
#include "support_assist/error.hpp"
#include <cstdint>
#include <filesystem>
#include <string>
namespace support_assist {
struct UsnJournalState {
  bool eligible = false;
  std::string reason;
  std::uint64_t journal_id = 0;
  std::int64_t next_usn = 0;
  std::int64_t lowest_valid_usn = 0;
  // The first record the journal still holds; a USN before it has been overwritten.
  std::int64_t first_usn = 0;
  // An NTFS volume whose journal is not active.
  bool inactive = false;
  // The volume's file system, when it could be read.
  std::string filesystem;
};
Result<UsnJournalState> query_usn_journal(const std::filesystem::path& volume);
} // namespace support_assist
