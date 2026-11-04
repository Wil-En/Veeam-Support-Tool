// Systems without an NTFS change journal: a capture records no mark and a read fails plainly.

#include "support_assist/change_journal.hpp"

#include <utility>

namespace support_assist {

namespace {
constexpr const char* kUnavailable = "The change journal is read on Windows (NTFS) only.";
}

ChangeJournalProbe probe_change_journal(const std::filesystem::path&) {
  ChangeJournalProbe probe;
  probe.reason = kUnavailable;
  return probe;
}

Result<ChangeJournalReadout> read_change_journal(const ChangeJournalWindow&, const CancellationToken&) {
  Error error;
  error.component = "ChangeJournal";
  error.operation = "read journal";
  error.message = kUnavailable;
  return Result<ChangeJournalReadout>::failure(std::move(error));
}

} // namespace support_assist
