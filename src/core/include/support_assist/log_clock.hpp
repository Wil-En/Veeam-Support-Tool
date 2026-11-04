#pragma once

// A log's own record of its clock against UTC. Veeam's line prefix ([29.09.2026 12:15:47.134]) is
// the writing machine's local time with no zone; each process ties that clock to UTC in the header
// it writes when it starts, and some services name their zone:
//   native processes   "[05.08.2026 13:52:05.042] < 12056> | UTC Time: 18:52:05. UTC offset: -0500."
//   .NET services      "UTC Time: [9/29/2026 5:15:47 PM], DaylightSavingTime: [True]", against the
//                      first stamped line after it
//   the backup server  "UTC offset: -5.00 hours"
//   a zone by name     "Timezone       : (UTC-06:00) Central Time (US & Canada)"
// The forms and their counts in real bundles: docs/PROPOSAL_TIME_CORRELATION.md.

#include "support_assist/time_zones.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

enum class LogClockSource { native_header, dotnet_header, offset_hours, zone_name };

struct LogClockAnchor {
  LogClockSource source = LogClockSource::native_header;
  std::size_t line_number = 0;        // from 1
  std::string text;                   // the line as written, trimmed
  bool has_local_time = false;        // the log's clock there is known: its own prefix or a stamped line near it
  std::int64_t local_millis = 0;      // that clock time read as if it were UTC
  std::optional<int> offset_minutes;  // stated, or the UTC time against the log's clock
  std::optional<bool> daylight;       // "DaylightSavingTime: [True]", "Daylight saving: True"
  const NamedTimeZone* zone = nullptr; // a zone named that Time Check lists
  std::string zone_text;              // the zone as named: "(UTC-06:00) Central Time (US & Canada)"
};

struct LogClock {
  std::string source;  // the file read, or "pasted text"
  std::string machine; // "MachineName: [SPECTR]" in a .NET header
  std::size_t lines_read = 0;
  bool has_stamped_lines = false;
  std::int64_t first_local_millis = 0; // the first and last line prefix, read as if UTC
  std::int64_t last_local_millis = 0;
  std::vector<LogClockAnchor> anchors; // in the order written
  bool stopped_at_limit = false;       // the file is larger than kLogClockReadLimitBytes
  std::string error;
};

inline constexpr std::uintmax_t kLogClockReadLimitBytes = 512ULL * 1024ULL * 1024ULL;

// Reads a log, UTF-8 or UTF-16 by its byte order mark, for the lines above.
LogClock read_log_clock(const std::filesystem::path& file);
LogClock read_log_clock_text(std::string_view text, std::string source = "pasted text");

// The UTC offset of a time on that log's clock (local_millis: read as if UTC). The zone the log names
// when its headers agree with it, so that daylight saving applies on any date; otherwise the nearest
// header at or before that time, or the first after it when none is before.
struct LogClockReading {
  bool found = false;
  int offset_minutes = 0;
  std::optional<bool> daylight;
  const LogClockAnchor* anchor = nullptr; // the header or zone line used
  const NamedTimeZone* zone = nullptr;    // the named zone whose rules gave the offset
  bool ambiguous = false;                 // the zone's clock showed this time twice
  bool skipped = false;                   // the zone's clock never showed it
  std::string how;                        // "the log's header at line 8"
  std::vector<std::string> notes;
};
LogClockReading log_clock_at(const LogClock& clock, std::int64_t local_millis);

// One group of headers that agree: their offset, daylight saving state and where they are.
struct LogClockGroup {
  int offset_minutes = 0;
  std::optional<bool> daylight;
  std::size_t count = 0;
  std::size_t first_line = 0;
  std::size_t last_line = 0;
  bool has_local_time = false;
  std::int64_t first_local_millis = 0;
  std::int64_t last_local_millis = 0;
  const LogClockAnchor* example = nullptr;
};
// The headers grouped by offset and daylight saving state, in the order first seen.
std::vector<LogClockGroup> log_clock_groups(const LogClock& clock);
// The zone the log names that Time Check lists, if any.
const LogClockAnchor* log_clock_named_zone(const LogClock& clock);

// What a log records of its own clock, as a headline and labelled rows for a report or the command
// line: the machine, the lines and their span, the zone named, each group of headers, the zones on
// the latest offset, and one line that says so.
struct LogClockSummary {
  std::string headline;
  bool tied = false; // a header or a listed zone ties the log's clock to UTC
  std::vector<std::pair<std::string, std::string>> rows;
  std::vector<std::string> notes;
};
LogClockSummary summarize_log_clock(const LogClock& clock);

namespace log_clock_detail {
// "[29.09.2026 12:15:47.134] ..." -> that time read as if UTC. Seconds-only prefixes too.
std::optional<std::int64_t> line_prefix_millis(std::string_view line);
// A .NET header's date and time ("9/29/2026 5:15:47 PM", "29.09.2026 17:15:47"): every reading the
// culture could give, as if UTC. Month and day are tried both ways when both are 12 or less.
std::vector<std::int64_t> header_time_readings(std::string_view text);
} // namespace log_clock_detail

} // namespace support_assist
