#pragma once

// Time Check's named zones (config/checks/time-zones.json, generated from Windows' own zone data by
// tools/dev/Generate-TimeZones.ps1): the display names Windows and Veeam's logs print, and each
// zone's offset at a given moment, daylight saving included, year by year. Used to read a log
// written in a known zone.

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// A daylight saving transition in a year: a weekday of a month (week 1 to 5, 5 the last) or a fixed
// day, at a local time of day.
struct ZoneTransition {
  int month = 0;
  int week = 0;    // 0 for a fixed day
  int weekday = 0; // 0 = Sunday
  int day = 0;     // the fixed day of the month when week is 0
  int seconds = 0; // the local time of day, 0 to 86400
};

struct ZoneRule {
  int from_year = 0;
  int to_year = 9999;
  int standard_offset_minutes = 0;
  std::optional<int> daylight_offset_minutes;
  ZoneTransition daylight_start; // in local standard time
  ZoneTransition daylight_end;   // in local daylight time
};

struct NamedTimeZone {
  std::string id;            // Windows' id: "Eastern Standard Time"
  std::string name;          // "(UTC-05:00) Eastern Time (US & Canada)"
  std::string standard_name; // "Eastern Standard Time"
  std::string daylight_name; // "Eastern Daylight Time"
  std::string iana;          // "America/New_York"
  std::vector<ZoneRule> rules;
};

const std::vector<NamedTimeZone>& named_time_zones();
// By display name (with or without its "(UTC-05:00)" part), Windows id, standard or daylight name,
// or IANA name, ignoring case.
const NamedTimeZone* find_named_time_zone(std::string_view text);

struct ZoneOffset {
  int offset_minutes = 0;
  bool daylight = false;
};

// The zone's offset at a moment.
ZoneOffset zone_offset_at(const NamedTimeZone& zone, std::int64_t unix_millis);

// A clock time read in the zone (local_millis: the time of day and date as if they were UTC): the
// moment it names, and whether the clock showed it twice (the hour daylight saving ends; the first
// is given) or never (the hour daylight saving starts; read as standard time).
struct ZoneLocalTime {
  std::int64_t unix_millis = 0;
  ZoneOffset offset;
  bool ambiguous = false;
  bool skipped = false;
};
ZoneLocalTime zone_local_to_utc(const NamedTimeZone& zone, std::int64_t local_millis);

// The listed zones on that offset at that moment, and in daylight saving time or not when that is
// known.
std::vector<const NamedTimeZone*> zones_at_offset(int offset_minutes, std::int64_t unix_millis,
                                                  std::optional<bool> daylight = std::nullopt);

// Zone names for one line of text: the first few, then how many more.
std::string zone_names_text(const std::vector<std::string>& names, std::size_t shown = 6);

// A calendar date and time of day as milliseconds since 1970-01-01, read as if it were UTC. Nothing
// when the date does not exist.
std::optional<std::int64_t> civil_millis(int year, int month, int day, int hour = 0, int minute = 0, int second = 0,
                                         int millis = 0);

} // namespace support_assist
