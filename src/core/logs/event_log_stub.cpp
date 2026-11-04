#include "support_assist/log_search.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

namespace support_assist {
Result<std::uint64_t> search_windows_event_log(const WindowsEventLogSearchOptions&,
                                               const CancellationToken&,
                                               ProgressCallback,
                                               const LogMatchCallback&) {
  Error error;
  error.component = "WindowsEventLog";
  error.operation = "search";
  error.message = "Windows Event Log search is available only in Windows builds";
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return Result<std::uint64_t>::failure(std::move(error));
}
} // namespace support_assist
