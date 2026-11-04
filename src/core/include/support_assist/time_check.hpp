#pragma once

// Time Check (F7): the time zone and its UTC offset, the configured time source, one SNTP query to
// it (UDP port 123) with the clock difference, and a note past the 5 minutes Kerberos allows. The
// converter turns a timestamp or a whole line copied from a log (a Veeam line prefix, Unix time,
// .NET ticks, a Windows FILETIME) into UTC, reading the offset from the log's own headers when the
// log is given (log_clock.hpp), and shows it in another zone and this machine's
// (docs/PROPOSAL_5.x_CHECKS.md section 9, docs/PROPOSAL_TIME_CORRELATION.md).

#include "support_assist/cancellation.hpp"
#include "support_assist/log_clock.hpp"
#include "support_assist/time_zones.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct TimeZoneInfo {
  std::string name;           // "Eastern Standard Time", "America/New_York"
  int utc_offset_minutes = 0; // now, daylight saving included
  bool daylight_saving_now = false;
};

TimeZoneInfo read_time_zone();

struct TimeSourceSettings {
  std::string service;              // "Windows Time", "chrony", "systemd-timesyncd", "ntpd"
  std::string mode;                 // "domain hierarchy (NT5DS)", "NTP", "not synchronized (NoSync)"
  std::vector<std::string> servers; // configured servers, flags removed
  std::string domain_controller;    // the DC the domain hierarchy uses, when one is found
  std::string note;
};

TimeSourceSettings read_time_source();

struct SntpResult {
  std::string server;
  std::string address;
  bool answered = false;
  // The server's time minus this clock. Positive: this clock is behind.
  double offset_ms = 0.0;
  double round_trip_ms = 0.0;
  int stratum = 0;
  std::string reference; // reference id; for stratum 0 the server's refusal code ("RATE", "DENY")
  std::string error;
};

SntpResult query_sntp(const std::string& server, std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

inline constexpr int kKerberosSkewMinutes = 5;

struct TimeCheckResult {
  std::int64_t checked_unix_millis = 0;
  TimeZoneInfo zone;
  TimeSourceSettings source;
  SntpResult sntp;
  bool beyond_kerberos = false; // the difference is more than 5 minutes
  std::vector<std::string> notes;
};

// Asks server when given, else the domain controller or the first configured server.
TimeCheckResult check_time(const std::string& server, const CancellationToken& cancel);

// The time base Log Collection records with the logs (docs/PROPOSAL_TIME_CORRELATION.md steps 1 and
// 2): one Time Check, written as environment.log's [TimeBase] section and the manifest's
// "time_base" object, and summarized as the collection's Clock row.
struct TimeBaseField {
  std::string key;   // "UtcOffsetMinutes"
  std::string value; // "-300"
  bool raw = false;  // a JSON number or true/false rather than a string
};
std::vector<TimeBaseField> time_base_fields(const TimeCheckResult& result);

// A difference past this many seconds is noted in the summary: the machine's log lines are that far
// off its time source. Past the 5 minutes Kerberos allows it is a warning.
inline constexpr double kTimeBaseNoteSeconds = 5.0;

struct TimeBaseSummary {
  std::string zone;       // "Central Time (US & Canada), UTC-05:00, daylight saving time"
  std::string difference; // "0.901 s behind dc01", or why it was not measured
  std::string state;      // "OK", "Review", "Warning" or "Not measured"
  std::string warning;    // a sentence for the collection's warnings; empty when within 5 seconds
};
TimeBaseSummary time_base_summary(const TimeCheckResult& result);

struct ConvertedTime {
  bool ok = false;
  std::string format; // "Veeam log line", "Unix seconds", "Unix milliseconds", ".NET ticks", ...
  std::int64_t unix_millis = 0;
  bool zone_in_text = false;   // the text carried its own zone or is UTC by definition
  int source_offset_minutes = 0; // the offset applied when the text carried none
  std::string utc_text;        // "2023-09-15 19:28:14.428 UTC"
  std::string local_text;      // in this machine's zone, with its offset at that moment
  // Read in a named zone: its name, the time there with that day's offset and whether it was
  // daylight saving time, and a note when the clock there showed the time twice or never.
  std::string zone_name;
  std::string zone_text;
  std::string zone_note;
  // Where the offset came from, as the report says it: "UTC-05:00, daylight saving time, from the
  // log's header at line 8"; the log line that says so; and the listed zones on that offset then.
  std::string written_in;
  std::string evidence;
  std::vector<std::string> zone_candidates;
  // Show in: the same moment in another zone.
  std::string shown_name;
  std::string shown_text;
  std::vector<std::string> notes;
  std::string error;
};

// source_offset_minutes: the zone the log was written in, for text that does not carry one.
ConvertedTime convert_timestamp(std::string_view text, int source_offset_minutes);
// The same, for text written in a named zone: the offset is that zone's on that date, daylight
// saving included.
ConvertedTime convert_timestamp(std::string_view text, const NamedTimeZone& zone);
// The same, for text from a log whose own clock was read (read_log_clock): the offset its headers or
// its named zone give at that time. Not ok when the log does not tie its clock to UTC.
ConvertedTime convert_timestamp(std::string_view text, const LogClock& clock);
// A conversion made with a zone or offset chosen by hand, checked against the log's own clock: a
// note when the log gives another offset at that time.
void compare_with_log_clock(ConvertedTime& converted, const LogClock& clock);
// The conversion as labelled rows for a report or the command line: Read as, Written in, Log says,
// Zone could be, UTC, Shown in, Here, and a Note for each note.
std::vector<std::pair<std::string, std::string>> converted_time_rows(const ConvertedTime& converted);
// The converted moment in another zone, or at another offset.
void show_converted_in(ConvertedTime& converted, const NamedTimeZone& zone);
void show_converted_in(ConvertedTime& converted, int offset_minutes);

// Written in's first entry: read the offset from the log's own headers.
inline constexpr std::string_view kFromLogFile = "From the log file";

// Written in or Show in as chosen or typed: From the log file, a listed zone, a UTC offset, or
// nothing.
struct ZoneChoice {
  enum class Kind { none, from_log, zone, offset, invalid };
  Kind kind = Kind::none;
  const NamedTimeZone* zone = nullptr;
  int offset_minutes = 0;
};
ZoneChoice read_zone_choice(std::string_view text);

// The converter as Time Check runs it on both editions and the command line. A line that states its
// own offset is read by it; otherwise the text is read as written_in says (From the log file needs
// the log's clock), checked against the log when one was read, and shown in show_in.
ConvertedTime convert_with_choices(std::string_view text, const ZoneChoice& written_in, const LogClock* log,
                                   const ZoneChoice& show_in);

// "UTC", "UTC+05:30", "UTC-05:00"
std::string format_utc_offset(int minutes);
// "UTC", "Z", "UTC-05:00", "+05:30", "-0500", "-5" (hours), "-300" (minutes); nothing past 14 hours.
std::optional<int> parse_utc_offset(std::string_view text);

namespace time_check_detail {
std::vector<std::uint8_t> build_sntp_request(std::uint64_t transmit_timestamp);
// Reads a reply to the request carrying `originate`; t1 and t4 are this clock's send and receive
// times in Unix milliseconds.
bool parse_sntp_response(const std::vector<std::uint8_t>& packet, std::uint64_t originate, double t1_ms,
                         double t4_ms, SntpResult& result);
std::uint64_t ntp_from_unix_millis(double unix_millis);
double unix_millis_from_ntp(std::uint64_t ntp);
// "time.windows.com,0x9 pool.ntp.org,0x8" -> {"time.windows.com", "pool.ntp.org"}
std::vector<std::string> parse_w32time_servers(std::string_view value);
// server, pool and peer lines of chrony.conf or ntp.conf.
std::vector<std::string> parse_ntp_conf_servers(std::string_view text);
// NTP= lines of timesyncd.conf (the last one wins, as systemd reads it).
std::vector<std::string> parse_timesyncd_servers(std::string_view text);
std::string format_unix_millis(std::int64_t unix_millis, int offset_minutes);
// This machine's UTC offset at that moment, daylight saving included (platform files).
int local_offset_minutes_at(std::int64_t unix_millis);
// query_sntp on another port, for the unit tests' own responder.
SntpResult query_sntp_port(const std::string& server, std::uint16_t port, std::chrono::milliseconds timeout);
} // namespace time_check_detail

} // namespace support_assist
