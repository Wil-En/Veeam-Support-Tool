#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace support_assist {

std::string utc_now_iso8601();
std::string iso8601_from_unix_millis(std::int64_t millis);
std::string readable_utc_from_unix_millis(std::int64_t millis);
std::int64_t unix_millis_now();

struct ParsedTime {
  std::int64_t unix_millis = 0;
  std::string original_text;
  std::string format;
  bool ambiguous = false;
  double confidence = 0.0;
  std::optional<int> source_offset_minutes;
  bool timezone_assumed = false;
};

enum class DateOrder { iso_only, month_day_year, day_month_year, system_locale, automatic };

std::optional<ParsedTime>
parse_timestamp(std::string_view text, DateOrder order, int assumed_offset_minutes = 0);

} // namespace support_assist
