#include "support_assist/time.hpp"

#include <algorithm>
#include <ctime>
#include <iomanip>
#include <regex>
#include <sstream>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace support_assist {
namespace {

std::tm utc_tm(std::time_t value) {
  std::tm result{};
#ifdef _WIN32
  gmtime_s(&result, &value);
#else
  gmtime_r(&value, &result);
#endif
  return result;
}

std::optional<std::int64_t> to_epoch_ms(int year,
                                        int month,
                                        int day,
                                        int hour,
                                        int minute,
                                        int second,
                                        int milliseconds,
                                        int offset_minutes) {
  std::tm value{};
  value.tm_year = year - 1900;
  value.tm_mon = month - 1;
  value.tm_mday = day;
  value.tm_hour = hour;
  value.tm_min = minute;
  value.tm_sec = second;
#ifdef _WIN32
  const auto seconds = _mkgmtime(&value);
#else
  const auto seconds = timegm(&value);
#endif
  if (seconds == static_cast<std::time_t>(-1))
    return std::nullopt;
  const auto check = utc_tm(seconds);
  if (check.tm_year != value.tm_year || check.tm_mon != value.tm_mon ||
      check.tm_mday != value.tm_mday || check.tm_hour != value.tm_hour ||
      check.tm_min != value.tm_min || check.tm_sec != value.tm_sec) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(seconds) * 1000 + milliseconds -
         static_cast<std::int64_t>(offset_minutes) * 60 * 1000;
}

DateOrder system_date_order() {
#ifdef _WIN32
  wchar_t pattern[128]{};
  const int count = GetLocaleInfoEx(
      LOCALE_NAME_USER_DEFAULT, LOCALE_SSHORTDATE, pattern, static_cast<int>(std::size(pattern)));
  if (count > 0) {
    const std::wstring value(pattern);
    const auto month = value.find_first_of(L"Mm");
    const auto day = value.find_first_of(L"Dd");
    if (day != std::wstring::npos && month != std::wstring::npos) {
      return day < month ? DateOrder::day_month_year : DateOrder::month_day_year;
    }
  }
#endif
  return DateOrder::month_day_year;
}

int milliseconds_from_fraction(std::string fraction) {
  while (fraction.size() < 3)
    fraction.push_back('0');
  if (fraction.size() > 3)
    fraction.resize(3);
  return fraction.empty() ? 0 : std::stoi(fraction);
}

} // namespace

std::int64_t unix_millis_now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string iso8601_from_unix_millis(std::int64_t millis) {
  std::int64_t seconds = millis / 1000;
  int remainder = static_cast<int>(millis % 1000);
  if (remainder < 0) {
    remainder += 1000;
    --seconds;
  }
  const auto value = utc_tm(static_cast<std::time_t>(seconds));
  std::ostringstream output;
  output << std::put_time(&value, "%Y-%m-%dT%H:%M:%S") << '.' << std::setw(3) << std::setfill('0')
         << remainder << 'Z';
  return output.str();
}

std::string readable_utc_from_unix_millis(std::int64_t millis) {
  std::int64_t seconds = millis / 1000;
  int remainder = static_cast<int>(millis % 1000);
  if (remainder < 0) {
    remainder += 1000;
    --seconds;
  }
  const auto value = utc_tm(static_cast<std::time_t>(seconds));
  std::ostringstream output;
  output << std::put_time(&value, "%b %d, %Y %H:%M:%S");
  if (remainder != 0)
    output << '.' << std::setw(3) << std::setfill('0') << remainder;
  output << " UTC";
  return output.str();
}

std::string utc_now_iso8601() {
  return iso8601_from_unix_millis(unix_millis_now());
}

std::optional<ParsedTime>
parse_timestamp(std::string_view text, DateOrder order, int assumed_offset_minutes) {
  // Timestamp recognition is intentionally bounded. Parsing an entire multi-megabyte
  // error line is unnecessary and makes regex cost depend on unrelated payload text.
  constexpr std::size_t kTimestampSearchLimit = 2048;
  const std::string input(text.substr(0, std::min(text.size(), kTimestampSearchLimit)));
  std::smatch match;
  static const std::regex iso(
      R"((\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(?:\s?(Z)|\s?([+-])(\d{2}):?(\d{2}))?)?)",
      std::regex::ECMAScript | std::regex::optimize);
  if (std::regex_search(input, match, iso)) {
    int offset = assumed_offset_minutes;
    bool timezone_assumed = true;
    if (match[8].matched) {
      offset = 0;
      timezone_assumed = false;
    } else if (match[9].matched) {
      const int hours = std::stoi(match[10]);
      const int minutes = std::stoi(match[11]);
      if (hours > 23 || minutes > 59)
        return std::nullopt;
      offset = hours * 60 + minutes;
      if (match[9].str() == "-")
        offset = -offset;
      timezone_assumed = false;
    }
    const int milliseconds = match[7].matched ? milliseconds_from_fraction(match[7].str()) : 0;
    auto epoch = to_epoch_ms(std::stoi(match[1]),
                             std::stoi(match[2]),
                             std::stoi(match[3]),
                             match[4].matched ? std::stoi(match[4]) : 0,
                             match[5].matched ? std::stoi(match[5]) : 0,
                             match[6].matched ? std::stoi(match[6]) : 0,
                             milliseconds,
                             offset);
    if (epoch) {
      ParsedTime parsed;
      parsed.unix_millis = *epoch;
      parsed.original_text = match[0].str();
      parsed.format = "ISO-8601";
      parsed.confidence = timezone_assumed ? 0.9 : 1.0;
      parsed.source_offset_minutes = offset;
      parsed.timezone_assumed = timezone_assumed;
      return parsed;
    }
  }

  static const std::regex veeam_dot(
      R"((\d{1,2})\.(\d{1,2})\.(\d{4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?)",
      std::regex::ECMAScript | std::regex::optimize);
  if (order != DateOrder::iso_only && std::regex_search(input, match, veeam_dot)) {
    const int day = std::stoi(match[1]);
    const int month = std::stoi(match[2]);
    const int year = std::stoi(match[3]);
    const int milliseconds = match[7].matched ? milliseconds_from_fraction(match[7].str()) : 0;
    auto epoch = to_epoch_ms(year,
                             month,
                             day,
                             match[4].matched ? std::stoi(match[4]) : 0,
                             match[5].matched ? std::stoi(match[5]) : 0,
                             match[6].matched ? std::stoi(match[6]) : 0,
                             milliseconds,
                             assumed_offset_minutes);
    if (epoch) {
      ParsedTime parsed;
      parsed.unix_millis = *epoch;
      parsed.original_text = match[0].str();
      parsed.format = "Veeam-DMY";
      parsed.confidence = 0.98;
      parsed.source_offset_minutes = assumed_offset_minutes;
      parsed.timezone_assumed = true;
      return parsed;
    }
  }

  static const std::regex slash(
      R"((\d{1,2})/(\d{1,2})/(\d{2,4})(?:[ T](\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?)",
      std::regex::ECMAScript | std::regex::optimize);
  if (order != DateOrder::iso_only && std::regex_search(input, match, slash)) {
    int first = std::stoi(match[1]);
    int second = std::stoi(match[2]);
    int year = std::stoi(match[3]);
    if (year < 100)
      year += 2000;
    if (first < 1 || second < 1 || first > 31 || second > 31)
      return std::nullopt;

    const bool ambiguous_input = first <= 12 && second <= 12;
    DateOrder effective = order;
    if (effective == DateOrder::system_locale)
      effective = system_date_order();
    if (effective == DateOrder::automatic) {
      if (first > 12)
        effective = DateOrder::day_month_year;
      else
        effective = DateOrder::month_day_year;
    }
    int month = first;
    int day = second;
    if (effective == DateOrder::day_month_year) {
      month = second;
      day = first;
    }
    const int milliseconds = match[7].matched ? milliseconds_from_fraction(match[7].str()) : 0;
    auto epoch = to_epoch_ms(year,
                             month,
                             day,
                             match[4].matched ? std::stoi(match[4]) : 0,
                             match[5].matched ? std::stoi(match[5]) : 0,
                             match[6].matched ? std::stoi(match[6]) : 0,
                             milliseconds,
                             assumed_offset_minutes);
    if (epoch) {
      ParsedTime parsed;
      parsed.unix_millis = *epoch;
      parsed.original_text = match[0].str();
      parsed.format = effective == DateOrder::day_month_year ? "DMY" : "MDY";
      parsed.ambiguous = ambiguous_input && order == DateOrder::automatic;
      parsed.confidence = parsed.ambiguous ? 0.5 : 0.95;
      parsed.source_offset_minutes = assumed_offset_minutes;
      parsed.timezone_assumed = true;
      return parsed;
    }
  }
  return std::nullopt;
}

} // namespace support_assist
