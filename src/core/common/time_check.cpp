// Time Check, the parts every platform shares: the SNTP question and its arithmetic (RFC 4330), the
// timestamp converter, and the readers for the time services' configuration text. The platform
// files read the zone and the configured source.
#include "support_assist/time_check.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/udp_exchange.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

namespace support_assist {
namespace {

constexpr std::uint64_t kNtpToUnixSeconds = 2208988800ULL; // 1900-01-01 to 1970-01-01
constexpr std::int64_t kDotNetTicksAtUnixEpoch = 621355968000000000LL;
constexpr std::int64_t kFileTimeAtUnixEpoch = 116444736000000000LL;

double now_unix_millis() {
  return std::chrono::duration<double, std::milli>(std::chrono::system_clock::now().time_since_epoch()).count();
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& packet, std::size_t at) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i)
    value = (value << 8U) | packet[at + i];
  return value;
}

std::string reference_text(const std::vector<std::uint8_t>& packet, int stratum) {
  if (stratum <= 1) {
    std::string code;
    for (std::size_t i = 12; i < 16; ++i) {
      if (packet[i] >= 0x20 && packet[i] < 0x7F)
        code += static_cast<char>(packet[i]);
    }
    return code;
  }
  return std::to_string(packet[12]) + "." + std::to_string(packet[13]) + "." + std::to_string(packet[14]) + "." +
         std::to_string(packet[15]);
}

// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
void civil_from_days(std::int64_t days, int& year, int& month, int& day) {
  days += 719468;
  const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
  const auto day_of_era = static_cast<unsigned>(days - era * 146097);
  const unsigned year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
  const unsigned day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  const unsigned shifted_month = (5 * day_of_year + 2) / 153;
  day = static_cast<int>(day_of_year - (153 * shifted_month + 2) / 5 + 1);
  month = static_cast<int>(shifted_month < 10 ? shifted_month + 3 : shifted_month - 9);
  year = static_cast<int>(static_cast<std::int64_t>(year_of_era) + era * 400 + (month <= 2 ? 1 : 0));
}

std::vector<std::string> words_in(std::string_view text) {
  std::vector<std::string> words;
  std::string current;
  for (const char c : text) {
    if (c == ' ' || c == '\t' || c == '\r') {
      if (!current.empty())
        words.push_back(std::move(current));
      current.clear();
    } else {
      current += c;
    }
  }
  if (!current.empty())
    words.push_back(std::move(current));
  return words;
}

} // namespace

namespace time_check_detail {

std::uint64_t ntp_from_unix_millis(double unix_millis) {
  const double seconds = std::floor(unix_millis / 1000.0);
  const double fraction = (unix_millis - seconds * 1000.0) / 1000.0;
  const auto ntp_seconds = static_cast<std::uint64_t>(static_cast<std::int64_t>(seconds) +
                                                      static_cast<std::int64_t>(kNtpToUnixSeconds)) &
                           0xFFFFFFFFULL;
  const auto ntp_fraction = static_cast<std::uint64_t>(fraction * 4294967296.0) & 0xFFFFFFFFULL;
  return (ntp_seconds << 32U) | ntp_fraction;
}

double unix_millis_from_ntp(std::uint64_t ntp) {
  std::uint64_t seconds = ntp >> 32U;
  const std::uint64_t fraction = ntp & 0xFFFFFFFFULL;
  if (seconds < 0x80000000ULL)
    seconds += 0x100000000ULL; // era 1, which starts in February 2036
  return (static_cast<double>(seconds) - static_cast<double>(kNtpToUnixSeconds)) * 1000.0 +
         static_cast<double>(fraction) * 1000.0 / 4294967296.0;
}

std::vector<std::uint8_t> build_sntp_request(std::uint64_t transmit_timestamp) {
  std::vector<std::uint8_t> packet(48, 0);
  packet[0] = 0x23; // no leap warning, version 4, client
  for (std::size_t i = 0; i < 8; ++i)
    packet[40 + i] = static_cast<std::uint8_t>((transmit_timestamp >> (56U - 8U * i)) & 0xFFU);
  return packet;
}

bool parse_sntp_response(const std::vector<std::uint8_t>& packet, std::uint64_t originate, double t1_ms,
                         double t4_ms, SntpResult& result) {
  if (packet.size() < 48)
    return false;
  const int mode = packet[0] & 0x07;
  if ((mode != 4 && mode != 5) || read_u64(packet, 24) != originate)
    return false; // not the answer to this request
  result.stratum = packet[1];
  result.reference = reference_text(packet, result.stratum);
  if (result.stratum == 0) {
    result.answered = false;
    result.error = "the server declined to answer (" + (result.reference.empty() ? "no code" : result.reference) + ")";
    return true;
  }
  const std::uint64_t receive = read_u64(packet, 32);
  const std::uint64_t transmit = read_u64(packet, 40);
  if (transmit == 0) {
    result.answered = false;
    result.error = "the server's reply carries no time";
    return true;
  }
  const double t2 = unix_millis_from_ntp(receive);
  const double t3 = unix_millis_from_ntp(transmit);
  result.offset_ms = ((t2 - t1_ms) + (t3 - t4_ms)) / 2.0;
  result.round_trip_ms = (t4_ms - t1_ms) - (t3 - t2);
  result.answered = true;
  result.error.clear();
  return true;
}

std::vector<std::string> parse_w32time_servers(std::string_view value) {
  std::vector<std::string> servers;
  for (const std::string& word : words_in(value)) {
    const std::string name = trim(word.substr(0, word.find(',')));
    if (!name.empty())
      servers.push_back(name);
  }
  return servers;
}

std::vector<std::string> parse_ntp_conf_servers(std::string_view text) {
  std::vector<std::string> servers;
  for (const std::string& raw : split(text, '\n')) {
    const std::vector<std::string> words = words_in(raw.substr(0, raw.find('#')));
    if (words.size() < 2 || (words[0] != "server" && words[0] != "pool" && words[0] != "peer"))
      continue;
    if (words[1].rfind("127.127.", 0) == 0)
      continue; // an ntpd reference clock driver, not a server
    servers.push_back(words[1]);
  }
  return servers;
}

std::vector<std::string> parse_timesyncd_servers(std::string_view text) {
  std::vector<std::string> servers;
  for (const std::string& raw : split(text, '\n')) {
    const std::string line = trim(raw.substr(0, raw.find_first_of("#;")));
    if (line.rfind("NTP=", 0) != 0)
      continue;
    servers = words_in(line.substr(4)); // a later NTP= line replaces an earlier one
  }
  return servers;
}

std::string format_unix_millis(std::int64_t unix_millis, int offset_minutes) {
  const std::int64_t shifted = unix_millis + static_cast<std::int64_t>(offset_minutes) * 60000;
  constexpr std::int64_t kDay = 86400000;
  std::int64_t days = shifted / kDay;
  std::int64_t of_day = shifted % kDay;
  if (of_day < 0) {
    of_day += kDay;
    --days;
  }
  int year = 0;
  int month = 0;
  int day = 0;
  civil_from_days(days, year, month, day);
  const auto hours = static_cast<int>(of_day / 3600000);
  const auto minutes = static_cast<int>((of_day / 60000) % 60);
  const auto seconds = static_cast<int>((of_day / 1000) % 60);
  const auto millis = static_cast<int>(of_day % 1000);
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%04d-%02d-%02d %02d:%02d:%02d.%03d", year, month, day, hours, minutes, seconds,
                millis);
  return text;
}

} // namespace time_check_detail

std::string format_utc_offset(int minutes) {
  if (minutes == 0)
    return "UTC";
  const int magnitude = std::abs(minutes);
  char text[16] = {};
  std::snprintf(text, sizeof(text), "UTC%c%02d:%02d", minutes < 0 ? '-' : '+', magnitude / 60, magnitude % 60);
  return text;
}

std::optional<int> parse_utc_offset(std::string_view text) {
  std::string value = trim(text);
  const std::string lowered = ascii_lower(value);
  if (lowered == "utc" || lowered == "z" || lowered == "gmt")
    return 0;
  if (lowered.rfind("utc", 0) == 0 || lowered.rfind("gmt", 0) == 0)
    value = value.substr(3);
  if (value.empty())
    return std::nullopt;
  int sign = 1;
  if (value.front() == '+' || value.front() == '-') {
    sign = value.front() == '-' ? -1 : 1;
    value.erase(value.begin());
  }
  if (value.empty() || value.size() > 5 || value.find_first_not_of("0123456789:") != std::string::npos ||
      value.front() == ':' || value.back() == ':' || std::count(value.begin(), value.end(), ':') > 1)
    return std::nullopt;
  const std::size_t colon = value.find(':');
  int minutes = 0;
  if (colon != std::string::npos) {
    minutes = std::atoi(value.substr(0, colon).c_str()) * 60 + std::atoi(value.substr(colon + 1).c_str());
  } else if (value.size() == 4) {
    minutes = std::atoi(value.substr(0, 2).c_str()) * 60 + std::atoi(value.substr(2).c_str());
  } else {
    const int number = std::atoi(value.c_str());
    minutes = number <= 14 ? number * 60 : number;
  }
  if (minutes > 14 * 60)
    return std::nullopt;
  return sign * minutes;
}

SntpResult query_sntp(const std::string& server, std::chrono::milliseconds timeout) {
  return time_check_detail::query_sntp_port(server, 123, timeout);
}

SntpResult time_check_detail::query_sntp_port(const std::string& server, std::uint16_t port,
                                              std::chrono::milliseconds timeout) {
  SntpResult result;
  result.server = trim(server);
  if (result.server.empty()) {
    result.error = "no time server given";
    return result;
  }
  std::uint64_t originate = 0;
  double t1 = 0.0;
  const UdpExchange exchange = udp_exchange(
      result.server, port, false,
      [&]() {
        t1 = now_unix_millis();
        originate = time_check_detail::ntp_from_unix_millis(t1);
        return time_check_detail::build_sntp_request(originate);
      },
      [&](const std::vector<std::uint8_t>& reply) {
        return time_check_detail::parse_sntp_response(reply, originate, t1, now_unix_millis(), result);
      },
      timeout);
  result.address = exchange.address;
  if (!exchange.answered) {
    result.answered = false;
    result.error = exchange.error;
  }
  return result;
}

TimeCheckResult check_time(const std::string& server, const CancellationToken& cancel) {
  TimeCheckResult result;
  result.checked_unix_millis = unix_millis_now();
  result.zone = read_time_zone();
  result.source = read_time_source();
  std::string target = trim(server);
  if (target.empty())
    target = !result.source.domain_controller.empty() ? result.source.domain_controller
             : !result.source.servers.empty()          ? result.source.servers.front()
                                                       : std::string();
  if (target.empty()) {
    result.notes.push_back("No time server is configured here. Enter one to compare this clock with it.");
    return result;
  }
  if (cancel.is_cancelled())
    return result;
  result.sntp = query_sntp(target);
  if (result.sntp.answered) {
    const double difference = std::fabs(result.sntp.offset_ms);
    result.beyond_kerberos = difference > kKerberosSkewMinutes * 60000.0;
    if (result.beyond_kerberos)
      result.notes.push_back("The difference is more than the 5 minutes Kerberos allows.");
    if (difference > 15 * 60000.0)
      result.notes.push_back("The difference is more than the 15 minutes object storage allows for a signed request.");
  }
  return result;
}

namespace {

std::string fixed_text(double value, int decimals) {
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%.*f", decimals, value);
  return text;
}

// "0.901 s behind dc01" or "7 min 12 s ahead of dc01": the source's time minus this clock.
std::string clock_difference_text(const SntpResult& sntp) {
  const double seconds = std::fabs(sntp.offset_ms) / 1000.0;
  std::string amount;
  if (seconds < 60.0) {
    amount = fixed_text(seconds, 3) + " s";
  } else {
    const auto whole = static_cast<long long>(seconds);
    amount = std::to_string(whole / 60) + " min " + std::to_string(whole % 60) + " s";
  }
  return amount + (sntp.offset_ms >= 0 ? " behind " : " ahead of ") + sntp.server;
}

} // namespace

std::vector<TimeBaseField> time_base_fields(const TimeCheckResult& result) {
  std::vector<TimeBaseField> fields;
  const auto add = [&fields](std::string key, std::string value, bool raw = false) {
    if (!value.empty())
      fields.push_back({std::move(key), std::move(value), raw});
  };
  add("MeasuredUTC", iso8601_from_unix_millis(result.checked_unix_millis));
  add("Zone", result.zone.name);
  if (const NamedTimeZone* named = find_named_time_zone(result.zone.name))
    add("ZoneName", named->name);
  add("UtcOffset", format_utc_offset(result.zone.utc_offset_minutes));
  add("UtcOffsetMinutes", std::to_string(result.zone.utc_offset_minutes), true);
  add("DaylightSavingNow", result.zone.daylight_saving_now ? "true" : "false", true);
  add("TimeService", result.source.service);
  add("SyncMode", result.source.mode);
  std::string servers;
  for (const std::string& server : result.source.servers)
    servers += (servers.empty() ? "" : ", ") + server;
  add("TimeServers", servers);
  add("DomainController", result.source.domain_controller);
  add("AskedServer", result.sntp.server);
  if (result.sntp.address != result.sntp.server)
    add("AskedAddress", result.sntp.address);
  if (!result.sntp.server.empty())
    add("Answered", result.sntp.answered ? "true" : "false", true);
  if (result.sntp.answered) {
    // The source's time minus this clock: positive when this clock is behind.
    add("ClockDifferenceMs", fixed_text(result.sntp.offset_ms, 1), true);
    add("RoundTripMs", fixed_text(result.sntp.round_trip_ms, 1), true);
    add("Stratum", std::to_string(result.sntp.stratum), true);
  } else {
    add("Error", result.sntp.error);
  }
  return fields;
}

TimeBaseSummary time_base_summary(const TimeCheckResult& result) {
  TimeBaseSummary summary;
  const NamedTimeZone* named = find_named_time_zone(result.zone.name);
  summary.zone = (named != nullptr ? named->name : result.zone.name);
  summary.zone += (summary.zone.empty() ? "" : ", ") + format_utc_offset(result.zone.utc_offset_minutes) +
                  (result.zone.daylight_saving_now ? ", daylight saving time" : "");
  if (result.sntp.server.empty()) {
    summary.difference = "not compared: no time server is configured";
    summary.state = "Not measured";
    return summary;
  }
  if (!result.sntp.answered) {
    summary.difference = result.sntp.server + " did not answer" + (result.sntp.error.empty() ? "" : ": " + result.sntp.error);
    summary.state = "Not measured";
    return summary;
  }
  const std::string difference = clock_difference_text(result.sntp);
  summary.difference = difference;
  const double seconds = std::fabs(result.sntp.offset_ms) / 1000.0;
  if (result.beyond_kerberos) {
    summary.state = "Warning";
    summary.warning = "This machine's clock is " + difference +
                      ", more than the 5 minutes Kerberos allows; its log times are that far off.";
  } else if (seconds > kTimeBaseNoteSeconds) {
    summary.state = "Review";
    summary.warning = "This machine's clock is " + difference + "; its log times are that far off.";
  } else {
    summary.state = "OK";
  }
  return summary;
}

namespace {

// The part of pasted text to read: a whole Veeam line's prefix, or the text without the quotes and
// brackets around it.
std::string timestamp_part(std::string_view text) {
  std::string input = trim(text);
  if (!input.empty() && input.front() == '[') {
    const std::size_t close = input.find(']');
    if (close != std::string::npos && close <= 32)
      return trim(input.substr(1, close - 1));
  }
  while (!input.empty() && (input.front() == '[' || input.front() == '"' || input.front() == '\''))
    input.erase(input.begin());
  while (!input.empty() && (input.back() == ']' || input.back() == '"' || input.back() == '\''))
    input.pop_back();
  return trim(input);
}

// "9/29/2026 5:15:47 PM": the hours a 12-hour clock adds to the time read (12 for PM, -12 for 12 AM).
std::int64_t twelve_hour_shift(std::string_view input, std::int64_t local_millis) {
  std::string word;
  std::string designator;
  for (std::size_t at = 0; at <= input.size(); ++at) {
    const char character = at < input.size() ? input[at] : ' ';
    if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '.') {
      if (character != '.')
        word += static_cast<char>(character >= 'a' ? character - 32 : character);
      continue;
    }
    if (word == "AM" || word == "PM")
      designator = word;
    word.clear();
  }
  if (designator.empty())
    return 0;
  constexpr std::int64_t kDay = 86400000;
  const std::int64_t hour = ((local_millis % kDay + kDay) % kDay) / 3600000;
  if (designator == "PM" && hour < 12)
    return 12 * 3600000LL;
  if (designator == "AM" && hour == 12)
    return -12 * 3600000LL;
  return 0;
}

void finish_texts(ConvertedTime& converted) {
  converted.utc_text = time_check_detail::format_unix_millis(converted.unix_millis, 0) + " UTC";
  const int local_offset = time_check_detail::local_offset_minutes_at(converted.unix_millis);
  converted.local_text =
      time_check_detail::format_unix_millis(converted.unix_millis, local_offset) + " " + format_utc_offset(local_offset);
}

// "2023-09-15 14:28:14.428 UTC-04:00, Eastern Daylight Time"
std::string time_in_zone(const NamedTimeZone& zone, std::int64_t unix_millis) {
  const ZoneOffset there = zone_offset_at(zone, unix_millis);
  return time_check_detail::format_unix_millis(unix_millis, there.offset_minutes) + " " +
         format_utc_offset(there.offset_minutes) + ", " + (there.daylight ? zone.daylight_name : zone.standard_name);
}

void note_zone_reading(ConvertedTime& converted, bool ambiguous, bool skipped) {
  if (ambiguous) {
    converted.zone_note = "The clock there showed this time twice, in the hour daylight saving ended; this is the "
                          "first. The second was in standard time, an hour later in UTC.";
  } else if (skipped) {
    converted.zone_note = "The clock there never showed this time: it moved forward as daylight saving started. "
                          "It is read in standard time.";
  }
}

bool ties_own_clock(const LogClock& clock) {
  for (const LogClockAnchor& anchor : clock.anchors) {
    if (anchor.source != LogClockSource::zone_name && anchor.offset_minutes && anchor.has_local_time)
      return true;
  }
  return false;
}

} // namespace

ConvertedTime convert_timestamp(std::string_view text, int source_offset_minutes) {
  ConvertedTime converted;
  const std::string whole = trim(text);
  const std::string input = timestamp_part(text);
  if (input.empty()) {
    converted.error = "Paste a timestamp or a line from a log.";
    return converted;
  }
  converted.source_offset_minutes = source_offset_minutes;
  // A .NET log header states UTC: "UTC Time: [9/29/2026 5:15:47 PM], DaylightSavingTime: [True]".
  if (whole.rfind("UTC Time: [", 0) == 0) {
    const std::size_t close = whole.find(']');
    const auto readings = close == std::string::npos
                              ? std::vector<std::int64_t>()
                              : log_clock_detail::header_time_readings(std::string_view(whole).substr(11, close - 11));
    if (!readings.empty()) {
      converted.ok = true;
      converted.format = readings.size() > 1U ? "log header in UTC, month/day/year (could also be day/month)"
                                              : "log header in UTC";
      converted.unix_millis = readings.front();
      converted.zone_in_text = true;
      converted.written_in = "UTC, as the header states";
      finish_texts(converted);
      return converted;
    }
  }
  const bool digits = input.find_first_not_of("0123456789") == std::string::npos;
  if (digits && (input.size() == 10 || input.size() == 13)) {
    const long long value = std::strtoll(input.c_str(), nullptr, 10);
    converted.unix_millis = input.size() == 10 ? value * 1000 : value;
    converted.format = input.size() == 10 ? "Unix seconds" : "Unix milliseconds";
    converted.zone_in_text = true;
  } else if (digits && input.size() == 18 && (input.front() == '6' || input.front() == '1')) {
    const long long value = std::strtoll(input.c_str(), nullptr, 10);
    if (input.front() == '6') {
      converted.format = ".NET ticks";
      converted.unix_millis = (value - kDotNetTicksAtUnixEpoch) / 10000 -
                              static_cast<std::int64_t>(source_offset_minutes) * 60000;
    } else {
      converted.format = "Windows FILETIME";
      converted.unix_millis = (value - kFileTimeAtUnixEpoch) / 10000;
      converted.zone_in_text = true;
    }
  } else {
    const auto parsed = parse_timestamp(input, DateOrder::automatic, source_offset_minutes);
    if (!parsed) {
      converted.error = "\"" + input + "\" is not a timestamp this converter reads.";
      return converted;
    }
    converted.unix_millis = parsed->unix_millis;
    converted.zone_in_text = !parsed->timezone_assumed;
    if (parsed->format == "Veeam-DMY")
      converted.format = "Veeam log line (day.month.year)";
    else if (parsed->format == "ISO-8601")
      converted.format = "ISO 8601";
    else if (parsed->format == "DMY")
      converted.format = parsed->ambiguous ? "day/month/year (could also be month/day)" : "day/month/year";
    else
      converted.format = parsed->ambiguous ? "month/day/year (could also be day/month)" : "month/day/year";
    if (parsed->format != "ISO-8601") {
      const std::int64_t local = converted.unix_millis + static_cast<std::int64_t>(parsed->source_offset_minutes.value_or(
                                                             source_offset_minutes)) * 60000;
      converted.unix_millis += twelve_hour_shift(input, local);
    }
  }
  converted.ok = true;
  converted.written_in = converted.zone_in_text ? "the zone the text carries" : format_utc_offset(source_offset_minutes);
  finish_texts(converted);
  return converted;
}

ConvertedTime convert_timestamp(std::string_view text, const NamedTimeZone& zone) {
  // Read as the clock showed it (no offset), then placed in the zone on that date.
  ConvertedTime converted = convert_timestamp(text, 0);
  if (!converted.ok)
    return converted;
  converted.zone_name = zone.name;
  if (!converted.zone_in_text) {
    const ZoneLocalTime local = zone_local_to_utc(zone, converted.unix_millis);
    converted.source_offset_minutes = static_cast<int>((converted.unix_millis - local.unix_millis) / 60000);
    converted.unix_millis = local.unix_millis;
    note_zone_reading(converted, local.ambiguous, local.skipped);
    const ZoneOffset there = zone_offset_at(zone, converted.unix_millis);
    converted.written_in = zone.name + ", " + format_utc_offset(converted.source_offset_minutes) + " on that date (" +
                           (there.daylight ? zone.daylight_name : zone.standard_name) + ")";
    finish_texts(converted);
  }
  converted.zone_text = time_in_zone(zone, converted.unix_millis);
  return converted;
}

ConvertedTime convert_timestamp(std::string_view text, const LogClock& clock) {
  // Read as the log's clock showed it, then given the offset the log itself records at that time.
  ConvertedTime converted = convert_timestamp(text, 0);
  if (!converted.ok || converted.zone_in_text)
    return converted;
  const std::int64_t local = converted.unix_millis;
  const LogClockReading reading = log_clock_at(clock, local);
  converted.notes = reading.notes;
  if (!reading.found) {
    converted.ok = false;
    const LogClockAnchor* unlisted = nullptr;
    for (const LogClockAnchor& anchor : clock.anchors) {
      if (anchor.source == LogClockSource::zone_name && unlisted == nullptr)
        unlisted = &anchor;
    }
    converted.error = unlisted != nullptr
                          ? "The log names " + unlisted->zone_text + " at line " + std::to_string(unlisted->line_number) +
                                ", which is not in the list. Choose the zone it was written in, or type its offset."
                          : "This log does not tie its clock to UTC: it has no header with a UTC time or offset and "
                            "names no zone. Choose the zone it was written in.";
    return converted;
  }
  converted.unix_millis = local - static_cast<std::int64_t>(reading.offset_minutes) * 60000;
  converted.source_offset_minutes = reading.offset_minutes;
  std::string state;
  if (reading.daylight) {
    if (reading.zone != nullptr)
      state = *reading.daylight ? reading.zone->daylight_name : reading.zone->standard_name;
    else
      state = *reading.daylight ? "daylight saving time" : "standard time";
  }
  converted.written_in = format_utc_offset(reading.offset_minutes) + (state.empty() ? "" : ", " + state) + ", from " +
                         reading.how;
  converted.evidence = "Line " + std::to_string(reading.anchor->line_number) + ": " + reading.anchor->text;
  if (reading.zone != nullptr) {
    converted.zone_name = reading.zone->name;
    note_zone_reading(converted, reading.ambiguous, reading.skipped);
  } else {
    for (const NamedTimeZone* zone : zones_at_offset(reading.offset_minutes, converted.unix_millis, reading.daylight))
      converted.zone_candidates.push_back(zone->name);
  }
  finish_texts(converted);
  if (reading.zone != nullptr)
    converted.zone_text = time_in_zone(*reading.zone, converted.unix_millis);
  return converted;
}

void compare_with_log_clock(ConvertedTime& converted, const LogClock& clock) {
  if (!converted.ok || converted.zone_in_text)
    return;
  const std::int64_t local =
      converted.unix_millis + static_cast<std::int64_t>(converted.source_offset_minutes) * 60000;
  const LogClockReading reading = log_clock_at(clock, local);
  if (!reading.found || reading.offset_minutes == converted.source_offset_minutes)
    return;
  converted.notes.push_back("The log's own clock gives " + format_utc_offset(reading.offset_minutes) + " at this time (" +
                            reading.how + "), not " + format_utc_offset(converted.source_offset_minutes) + ". Choose " +
                            std::string(kFromLogFile) + " in Written in to use it.");
}

std::vector<std::pair<std::string, std::string>> converted_time_rows(const ConvertedTime& converted) {
  std::vector<std::pair<std::string, std::string>> rows;
  if (!converted.ok)
    return rows;
  rows.emplace_back("Read as", converted.format);
  std::string written_in = converted.written_in;
  if (written_in.empty())
    written_in = converted.zone_in_text ? "the zone the text carries" : format_utc_offset(converted.source_offset_minutes);
  rows.emplace_back("Written in", written_in);
  if (!converted.evidence.empty())
    rows.emplace_back("Log says", converted.evidence);
  if (!converted.zone_candidates.empty())
    rows.emplace_back("Zone could be", zone_names_text(converted.zone_candidates));
  rows.emplace_back("UTC", converted.utc_text);
  if (!converted.shown_text.empty())
    rows.emplace_back("Shown in", converted.shown_text);
  rows.emplace_back("Here", converted.local_text);
  if (!converted.zone_note.empty())
    rows.emplace_back("Note", converted.zone_note);
  for (const std::string& note : converted.notes)
    rows.emplace_back("Note", note);
  return rows;
}

void show_converted_in(ConvertedTime& converted, const NamedTimeZone& zone) {
  if (!converted.ok)
    return;
  converted.shown_name = zone.name;
  converted.shown_text = time_in_zone(zone, converted.unix_millis);
}

void show_converted_in(ConvertedTime& converted, int offset_minutes) {
  if (!converted.ok)
    return;
  converted.shown_name = format_utc_offset(offset_minutes);
  converted.shown_text = time_check_detail::format_unix_millis(converted.unix_millis, offset_minutes) + " " +
                         format_utc_offset(offset_minutes);
}

ZoneChoice read_zone_choice(std::string_view text) {
  ZoneChoice choice;
  const std::string value = trim(text);
  if (value.empty())
    return choice;
  if (ascii_lower(value) == ascii_lower(kFromLogFile)) {
    choice.kind = ZoneChoice::Kind::from_log;
  } else if (const NamedTimeZone* zone = find_named_time_zone(value)) {
    choice.kind = ZoneChoice::Kind::zone;
    choice.zone = zone;
  } else if (const auto offset = parse_utc_offset(value)) {
    choice.kind = ZoneChoice::Kind::offset;
    choice.offset_minutes = *offset;
  } else {
    choice.kind = ZoneChoice::Kind::invalid;
  }
  return choice;
}

ConvertedTime convert_with_choices(std::string_view text, const ZoneChoice& written_in, const LogClock* log,
                                   const ZoneChoice& show_in) {
  ConvertedTime converted;
  if (show_in.kind == ZoneChoice::Kind::invalid) {
    converted.error = "Show in takes a zone from the list or a UTC offset such as UTC-05:00, +0530 or UTC.";
    return converted;
  }
  // A line that states its own offset, as a native process header does, is read by it.
  const LogClock pasted = read_log_clock_text(text, "the line pasted");
  const bool states_own = ties_own_clock(pasted);
  if (states_own) {
    converted = convert_timestamp(text, pasted);
    if (converted.ok && !converted.zone_in_text) {
      converted.written_in = format_utc_offset(converted.source_offset_minutes) + ", as the line itself states";
      converted.evidence.clear();
    }
  } else {
    switch (written_in.kind) {
    case ZoneChoice::Kind::from_log:
      if (log == nullptr) {
        converted.error = "Choose the log file first, or the zone the log was written in.";
        return converted;
      }
      if (!log->error.empty()) {
        converted.error = log->error;
        return converted;
      }
      converted = convert_timestamp(text, *log);
      break;
    case ZoneChoice::Kind::zone:
      converted = convert_timestamp(text, *written_in.zone);
      break;
    case ZoneChoice::Kind::offset:
      converted = convert_timestamp(text, written_in.offset_minutes);
      if (converted.ok && !converted.zone_in_text)
        converted.written_in += ", as typed";
      break;
    case ZoneChoice::Kind::none: {
      const int here = read_time_zone().utc_offset_minutes;
      converted = convert_timestamp(text, here);
      if (converted.ok && !converted.zone_in_text)
        converted.written_in = format_utc_offset(here) + ", this machine's offset now";
      break;
    }
    case ZoneChoice::Kind::invalid:
      converted.error = "Written in takes " + std::string(kFromLogFile) +
                        ", a zone from the list, or a UTC offset such as UTC-05:00, +0530 or UTC.";
      return converted;
    }
  }
  if (!converted.ok)
    return converted;
  if (log != nullptr && log->error.empty() && !states_own && written_in.kind != ZoneChoice::Kind::from_log)
    compare_with_log_clock(converted, *log);
  if (show_in.kind == ZoneChoice::Kind::zone)
    show_converted_in(converted, *show_in.zone);
  else if (show_in.kind == ZoneChoice::Kind::offset)
    show_converted_in(converted, show_in.offset_minutes);
  return converted;
}

} // namespace support_assist
