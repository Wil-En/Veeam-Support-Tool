#include "support_assist/usn.hpp"
namespace support_assist {
Result<UsnJournalState> query_usn_journal(const std::filesystem::path&) {
  UsnJournalState s;
  s.reason = "USN journals are available only on eligible local NTFS volumes in Windows builds.";
  return Result<UsnJournalState>::success(std::move(s));
}
} // namespace support_assist
