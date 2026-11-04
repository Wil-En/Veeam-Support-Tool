#include "support_assist/time_zones.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <utility>

namespace support_assist {
namespace {

constexpr std::int64_t kMillisPerDay = 86400000;
constexpr std::int64_t kMillisPerMinute = 60000;

// Days since 1970-01-01 for a date, and the year of such a day (proleptic Gregorian calendar).
std::int64_t days_from_civil(std::int64_t year, std::int64_t month, std::int64_t day) {
  year -= month <= 2 ? 1 : 0;
  const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
  const std::int64_t year_of_era = year - era * 400;
  const std::int64_t day_of_year = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
  const std::int64_t day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  return era * 146097 + day_of_era - 719468;
}

int year_of_days(std::int64_t days) {
  days += 719468;
  const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
  const std::int64_t day_of_era = days - era * 146097;
  const std::int64_t year_of_era =
      (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
  const std::int64_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  const std::int64_t shifted_month = (5 * day_of_year + 2) / 153;
  const std::int64_t month = shifted_month < 10 ? shifted_month + 3 : shifted_month - 9;
  return static_cast<int>(year_of_era + era * 400 + (month <= 2 ? 1 : 0));
}

std::int64_t floor_days(std::int64_t millis) {
  return millis >= 0 ? millis / kMillisPerDay : -((-millis + kMillisPerDay - 1) / kMillisPerDay);
}

int year_of_millis(std::int64_t millis) { return year_of_days(floor_days(millis)); }

// 0 = Sunday; 1970-01-01 was a Thursday.
int weekday_of(std::int64_t days) { return static_cast<int>(((days + 4) % 7 + 7) % 7); }

// The transition's local time in a year, as milliseconds since 1970 read as if local were UTC.
std::int64_t transition_local_millis(int year, const ZoneTransition& transition) {
  std::int64_t day = 0;
  if (transition.week == 0) {
    day = days_from_civil(year, transition.month, transition.day);
  } else {
    const std::int64_t first = days_from_civil(year, transition.month, 1);
    const std::int64_t next = transition.month == 12 ? days_from_civil(year + 1, 1, 1)
                                                     : days_from_civil(year, transition.month + 1, 1);
    std::int64_t offset = (transition.weekday - weekday_of(first) + 7) % 7 + 7 * (transition.week - 1);
    while (offset >= next - first)
      offset -= 7;
    day = first + offset;
  }
  return day * kMillisPerDay + static_cast<std::int64_t>(transition.seconds) * 1000;
}

const ZoneRule* rule_for(const NamedTimeZone& zone, int year) {
  if (zone.rules.empty())
    return nullptr;
  for (const ZoneRule& rule : zone.rules) {
    if (year >= rule.from_year && year <= rule.to_year)
      return &rule;
  }
  return year < zone.rules.front().from_year ? &zone.rules.front() : &zone.rules.back();
}

int seconds_of_day(const std::string& text) {
  const auto parts = split(text, ':');
  int seconds = 0;
  int scale = 3600;
  for (std::size_t index = 0; index < parts.size() && index < 3U; ++index) {
    int value = 0;
    for (const char character : trim(parts[index])) {
      if (character < '0' || character > '9')
        break;
      value = value * 10 + (character - '0');
    }
    seconds += value * scale;
    scale /= 60;
  }
  return std::clamp(seconds, 0, 86400);
}

ZoneTransition transition_from(const JsonValue& value) {
  ZoneTransition transition;
  transition.month = static_cast<int>(value["month"].as_number());
  if (value.has("day")) {
    transition.day = static_cast<int>(value["day"].as_number());
  } else {
    transition.week = static_cast<int>(value["week"].as_number());
    transition.weekday = static_cast<int>(value["weekday"].as_number());
  }
  transition.seconds = seconds_of_day(value["time"].as_string());
  return transition;
}

std::vector<NamedTimeZone> load_zones() {
  std::vector<NamedTimeZone> zones;
  for (const JsonValue& item : data_file("time-zones.json")["zones"].items()) {
    NamedTimeZone zone;
    zone.id = item["id"].as_string();
    zone.name = item["name"].as_string();
    zone.standard_name = item["standard_name"].as_string();
    zone.daylight_name = item["daylight_name"].as_string();
    zone.iana = item["iana"].as_string();
    for (const JsonValue& value : item["rules"].items()) {
      ZoneRule rule;
      rule.from_year = static_cast<int>(value["from"].as_number());
      rule.to_year = static_cast<int>(value["to"].as_number(9999.0));
      rule.standard_offset_minutes = static_cast<int>(value["offset"].as_number());
      if (value.has("daylight")) {
        const JsonValue& daylight = value["daylight"];
        rule.daylight_offset_minutes = static_cast<int>(daylight["offset"].as_number());
        rule.daylight_start = transition_from(daylight["start"]);
        rule.daylight_end = transition_from(daylight["end"]);
      }
      zone.rules.push_back(rule);
    }
    if (!zone.id.empty() && !zone.rules.empty())
      zones.push_back(std::move(zone));
  }
  return zones;
}

// "(UTC-05:00) Eastern Time (US & Canada)" without its "(UTC-05:00) ".
std::string name_without_offset(const std::string& name) {
  if (name.empty() || name.front() != '(')
    return name;
  const std::size_t close = name.find(") ");
  return close == std::string::npos ? name : name.substr(close + 2);
}

} // namespace

const std::vector<NamedTimeZone>& named_time_zones() {
  static const std::vector<NamedTimeZone> zones = load_zones();
  return zones;
}

const NamedTimeZone* find_named_time_zone(std::string_view text) {
  const std::string wanted = ascii_lower(trim(text));
  if (wanted.empty())
    return nullptr;
  const auto& zones = named_time_zones();
  for (const NamedTimeZone& zone : zones) {
    for (const std::string* name : {&zone.name, &zone.id, &zone.standard_name, &zone.daylight_name, &zone.iana}) {
      if (!name->empty() && ascii_lower(*name) == wanted)
        return &zone;
    }
    if (ascii_lower(name_without_offset(zone.name)) == wanted)
      return &zone;
  }
  // A unique start of a name, then a unique part of one: "Eastern Time", "Sydney".
  for (const bool anywhere : {false, true}) {
    const NamedTimeZone* found = nullptr;
    bool unique = true;
    for (const NamedTimeZone& zone : zones) {
      const std::string name = ascii_lower(name_without_offset(zone.name));
      const std::size_t at = name.find(wanted);
      if (at == std::string::npos || (!anywhere && at != 0))
        continue;
      unique = unique && found == nullptr;
      found = &zone;
    }
    if (found != nullptr)
      return unique ? found : nullptr;
  }
  return nullptr;
}

ZoneOffset zone_offset_at(const NamedTimeZone& zone, std::int64_t unix_millis) {
  const ZoneRule* rough = rule_for(zone, year_of_millis(unix_millis));
  if (rough == nullptr)
    return {};
  const int year = year_of_millis(unix_millis + rough->standard_offset_minutes * kMillisPerMinute);
  const ZoneRule* rule = rule_for(zone, year);
  ZoneOffset offset{rule->standard_offset_minutes, false};
  if (!rule->daylight_offset_minutes)
    return offset;
  const std::int64_t start =
      transition_local_millis(year, rule->daylight_start) - rule->standard_offset_minutes * kMillisPerMinute;
  const std::int64_t end =
      transition_local_millis(year, rule->daylight_end) - *rule->daylight_offset_minutes * kMillisPerMinute;
  // South of the equator daylight saving spans the new year: it starts late in the year and ends early.
  const bool daylight = start < end ? unix_millis >= start && unix_millis < end : unix_millis >= start || unix_millis < end;
  if (daylight)
    offset = {*rule->daylight_offset_minutes, true};
  return offset;
}

ZoneLocalTime zone_local_to_utc(const NamedTimeZone& zone, std::int64_t local_millis) {
  ZoneLocalTime result;
  result.unix_millis = local_millis;
  const int year = year_of_millis(local_millis);
  const ZoneRule* rule = rule_for(zone, year);
  if (rule == nullptr)
    return result;
  // Every offset the zone could be on around that date, including a change at the new year.
  std::vector<int> offsets;
  for (const int around : {year - 1, year, year + 1}) {
    const ZoneRule* other = rule_for(zone, around);
    offsets.push_back(other->standard_offset_minutes);
    if (other->daylight_offset_minutes)
      offsets.push_back(*other->daylight_offset_minutes);
  }
  std::sort(offsets.begin(), offsets.end());
  offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());
  std::vector<std::pair<std::int64_t, ZoneOffset>> readings;
  for (const int offset : offsets) {
    const std::int64_t candidate = local_millis - offset * kMillisPerMinute;
    const ZoneOffset actual = zone_offset_at(zone, candidate);
    if (actual.offset_minutes == offset)
      readings.emplace_back(candidate, actual);
  }
  if (readings.empty()) {
    // The clock skipped this time as it moved forward; it reads as the time before the move.
    result.unix_millis = local_millis - rule->standard_offset_minutes * kMillisPerMinute;
    result.offset = zone_offset_at(zone, result.unix_millis);
    result.skipped = true;
    return result;
  }
  std::sort(readings.begin(), readings.end(),
            [](const auto& left, const auto& right) { return left.first < right.first; });
  result.unix_millis = readings.front().first;
  result.offset = readings.front().second;
  result.ambiguous = readings.size() > 1U;
  return result;
}

std::vector<const NamedTimeZone*> zones_at_offset(int offset_minutes, std::int64_t unix_millis,
                                                  std::optional<bool> daylight) {
  std::vector<const NamedTimeZone*> found;
  for (const NamedTimeZone& zone : named_time_zones()) {
    const ZoneOffset offset = zone_offset_at(zone, unix_millis);
    if (offset.offset_minutes == offset_minutes && (!daylight || offset.daylight == *daylight))
      found.push_back(&zone);
  }
  return found;
}

std::string zone_names_text(const std::vector<std::string>& names, std::size_t shown) {
  std::string text;
  for (std::size_t index = 0; index < names.size() && index < shown; ++index)
    text += (index == 0 ? "" : "; ") + names[index];
  if (names.size() > shown)
    text += "; and " + std::to_string(names.size() - shown) + " more";
  return text;
}

std::optional<std::int64_t> civil_millis(int year, int month, int day, int hour, int minute, int second, int millis) {
  static constexpr int kDaysInMonth[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 || hour < 0 || hour > 23 || minute < 0 ||
      minute > 59 || second < 0 || second > 60 || millis < 0 || millis > 999)
    return std::nullopt;
  const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  if (day > kDaysInMonth[month - 1] + (month == 2 && leap ? 1 : 0))
    return std::nullopt;
  return days_from_civil(year, month, day) * kMillisPerDay +
         ((static_cast<std::int64_t>(hour) * 60 + minute) * 60 + second) * 1000 + millis;
}

} // namespace support_assist
