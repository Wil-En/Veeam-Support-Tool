// Where a log ties its own clock to UTC (support_assist/log_clock.hpp).
#include "support_assist/log_clock.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time_check.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <utility>

namespace support_assist {
namespace {

constexpr std::int64_t kMillisPerMinute = 60000;
constexpr std::int64_t kMillisPerDay = 86400000;
constexpr std::int64_t kQuarterHour = 15 * kMillisPerMinute;
// A header waits this many lines for the stamped line that dates it.
constexpr std::size_t kHeaderReach = 60;
// A .NET header's UTC time is in whole seconds and the first line follows it within moments.
constexpr std::int64_t kHeaderPairingSlack = 2 * kMillisPerMinute;
constexpr std::size_t kAnchorTextLimit = 240;
constexpr std::size_t kAnchorLimit = 20000;
// Only the start of a longer line is kept; the anchors are short lines.
constexpr std::size_t kLineKeepLimit = 64 * 1024;
constexpr std::size_t kChunkBytes = 1024 * 1024;

bool digits_at(std::string_view text, std::size_t at, std::size_t count, int& value) {
  if (at + count > text.size())
    return false;
  value = 0;
  for (std::size_t index = 0; index < count; ++index) {
    const char character = text[at + index];
    if (character < '0' || character > '9')
      return false;
    value = value * 10 + (character - '0');
  }
  return true;
}

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

// The line as the report shows it: trimmed, and cut at a character boundary past the limit.
std::string anchor_text(std::string_view line) {
  std::string text = trim(line);
  if (text.size() > kAnchorTextLimit) {
    std::size_t cut = kAnchorTextLimit;
    while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0U) == 0x80U)
      --cut;
    text = text.substr(0, cut) + "...";
  }
  return text;
}

struct StatedOffset {
  int minutes = 0;
  bool hours = false; // "-5.00 hours" rather than "-0500."
};

// The text after "UTC offset: ": "-0500." (a native header) or "-5.00 hours".
std::optional<StatedOffset> stated_offset(std::string_view text) {
  std::size_t at = 0;
  int sign = 1;
  if (at < text.size() && (text[at] == '+' || text[at] == '-')) {
    sign = text[at] == '-' ? -1 : 1;
    ++at;
  }
  const std::size_t start = at;
  while (at < text.size() && text[at] >= '0' && text[at] <= '9')
    ++at;
  const std::size_t whole_digits = at - start;
  if (whole_digits == 0)
    return std::nullopt;
  StatedOffset stated;
  const bool fraction_follows = at + 1 < text.size() && text[at] == '.' && text[at + 1] >= '0' && text[at + 1] <= '9';
  if (whole_digits == 4 && !fraction_follows) {
    int hours = 0;
    int minutes = 0;
    digits_at(text, start, 2, hours);
    digits_at(text, start + 2, 2, minutes);
    if (minutes > 59)
      return std::nullopt;
    stated.minutes = hours * 60 + minutes;
  } else {
    if (whole_digits > 2)
      return std::nullopt;
    int hours = 0;
    digits_at(text, start, whole_digits, hours);
    int fraction_minutes = 0;
    if (fraction_follows) {
      ++at;
      int numerator = 0;
      int denominator = 1;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9') {
        if (denominator < 10000) {
          numerator = numerator * 10 + (text[at] - '0');
          denominator *= 10;
        }
        ++at;
      }
      fraction_minutes = (numerator * 60 + denominator / 2) / denominator;
    }
    while (at < text.size() && text[at] == ' ')
      ++at;
    if (ascii_lower(text.substr(at, 5)) != "hours")
      return std::nullopt;
    stated.minutes = hours * 60 + fraction_minutes;
    stated.hours = true;
  }
  if (stated.minutes > 14 * 60)
    return std::nullopt;
  stated.minutes *= sign;
  return stated;
}

// "Timezone       : (UTC-06:00) Central Time (US & Canada)", "Time Zone: (UTC-06:00) ...",
// "TimeZone : (UTC...)": the zone's name as written.
std::optional<std::string> named_zone_in(std::string_view line) {
  const std::size_t utc = line.find("(UTC");
  if (utc == std::string_view::npos)
    return std::nullopt;
  const std::string lowered = ascii_lower(line.substr(0, utc));
  std::size_t key = lowered.rfind("timezone");
  std::size_t key_length = 8;
  if (key == std::string::npos) {
    key = lowered.rfind("time zone");
    key_length = 9;
  }
  if (key == std::string::npos)
    return std::nullopt;
  // Only spaces and one colon between the key and the zone.
  const std::string between = lowered.substr(key + key_length);
  if (std::count(between.begin(), between.end(), ':') != 1 || between.find_first_not_of(" \t:") != std::string::npos)
    return std::nullopt;
  std::string zone = trim(line.substr(utc));
  return zone.empty() ? std::nullopt : std::optional<std::string>(zone);
}

// The offset a .NET header's UTC time gives against the log's clock right after it: a whole
// quarter hour within the slack, the reading closest to one.
std::optional<int> offset_against(std::int64_t local_millis, const std::vector<std::int64_t>& readings) {
  std::optional<int> best;
  std::int64_t best_residual = 0;
  for (const std::int64_t utc : readings) {
    const std::int64_t difference = local_millis - utc;
    const std::int64_t quarters = difference >= 0 ? (difference + kQuarterHour / 2) / kQuarterHour
                                                  : -((-difference + kQuarterHour / 2) / kQuarterHour);
    const std::int64_t residual = difference - quarters * kQuarterHour;
    const std::int64_t magnitude = residual < 0 ? -residual : residual;
    if (quarters > 14 * 4 || quarters < -14 * 4 || magnitude > kHeaderPairingSlack)
      continue;
    if (!best || magnitude < best_residual) {
      best = static_cast<int>(quarters * 15);
      best_residual = magnitude;
    }
  }
  return best;
}

// Reads a file's lines as UTF-8, whether it is UTF-8 or UTF-16 with a byte order mark.
class TextLines {
public:
  explicit TextLines(const std::filesystem::path& file) : in_(file, std::ios::binary) {
    if (!in_)
      return;
    unsigned char mark[3] = {};
    in_.read(reinterpret_cast<char*>(mark), 3);
    const auto count = in_.gcount();
    in_.clear();
    if (count >= 2 && mark[0] == 0xFF && mark[1] == 0xFE) {
      encoding_ = Encoding::utf16le;
      in_.seekg(2);
    } else if (count >= 2 && mark[0] == 0xFE && mark[1] == 0xFF) {
      encoding_ = Encoding::utf16be;
      in_.seekg(2);
    } else {
      in_.seekg(count == 3 && mark[0] == 0xEF && mark[1] == 0xBB && mark[2] == 0xBF ? 3 : 0);
    }
  }

  bool is_open() const { return in_.is_open(); }
  bool stopped_at_limit() const { return stopped_at_limit_; }

  bool next(std::string& line) {
    for (;;) {
      const std::size_t newline = text_.find('\n', start_);
      if (newline != std::string::npos) {
        take(line, newline);
        start_ = newline + 1;
        return true;
      }
      if (done_) {
        if (start_ >= text_.size())
          return false;
        take(line, text_.size());
        start_ = text_.size();
        return true;
      }
      text_.erase(0, start_);
      start_ = 0;
      if (text_.size() > kLineKeepLimit * 4) {
        // A line with no end in sight: keep its start and drop the rest up to the next line.
        text_.resize(kLineKeepLimit);
        skipping_ = true;
      }
      fill();
    }
  }

private:
  enum class Encoding { utf8, utf16le, utf16be };

  void take(std::string& line, std::size_t end) {
    line.assign(text_, start_, std::min(end - start_, kLineKeepLimit));
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
  }

  void fill() {
    in_.read(buffer_.data(), static_cast<std::streamsize>(buffer_.size()));
    const auto count = static_cast<std::size_t>(in_.gcount());
    read_ += count;
    if (count == 0) {
      done_ = true;
      return;
    }
    if (read_ >= kLogClockReadLimitBytes) {
      done_ = true;
      stopped_at_limit_ = true;
    }
    std::string decoded;
    if (encoding_ == Encoding::utf8) {
      decoded.assign(buffer_.data(), count);
    } else {
      decode_utf16(buffer_.data(), count, decoded);
    }
    if (skipping_) {
      const std::size_t newline = decoded.find('\n');
      if (newline == std::string::npos)
        return;
      decoded.erase(0, newline);
      skipping_ = false;
    }
    text_ += decoded;
  }

  void decode_utf16(const char* data, std::size_t count, std::string& out) {
    std::size_t index = 0;
    auto unit_at = [&](unsigned char first, unsigned char second) {
      return encoding_ == Encoding::utf16le ? static_cast<std::uint32_t>(first | (second << 8U))
                                            : static_cast<std::uint32_t>((first << 8U) | second);
    };
    while (index < count) {
      if (!carry_.has_value()) {
        if (index + 1 >= count) {
          carry_ = static_cast<unsigned char>(data[index]);
          return;
        }
      }
      unsigned char first = 0;
      unsigned char second = 0;
      if (carry_.has_value()) {
        first = *carry_;
        second = static_cast<unsigned char>(data[index]);
        carry_.reset();
        index += 1;
      } else {
        first = static_cast<unsigned char>(data[index]);
        second = static_cast<unsigned char>(data[index + 1]);
        index += 2;
      }
      std::uint32_t code = unit_at(first, second);
      if (high_surrogate_ != 0) {
        if (code >= 0xDC00 && code <= 0xDFFF) {
          code = 0x10000 + ((high_surrogate_ - 0xD800) << 10U) + (code - 0xDC00);
          high_surrogate_ = 0;
          append_utf8(code, out);
          continue;
        }
        high_surrogate_ = 0;
        append_utf8(0xFFFD, out);
      }
      if (code >= 0xD800 && code <= 0xDBFF) {
        high_surrogate_ = code;
        continue;
      }
      if (code >= 0xDC00 && code <= 0xDFFF)
        code = 0xFFFD;
      append_utf8(code, out);
    }
  }

  static void append_utf8(std::uint32_t code, std::string& out) {
    if (code <= 0x7F) {
      out.push_back(static_cast<char>(code));
    } else if (code <= 0x7FF) {
      out.push_back(static_cast<char>(0xC0U | (code >> 6U)));
      out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
    } else if (code <= 0xFFFF) {
      out.push_back(static_cast<char>(0xE0U | (code >> 12U)));
      out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
    } else {
      out.push_back(static_cast<char>(0xF0U | (code >> 18U)));
      out.push_back(static_cast<char>(0x80U | ((code >> 12U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | ((code >> 6U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | (code & 0x3FU)));
    }
  }

  std::ifstream in_;
  Encoding encoding_ = Encoding::utf8;
  std::vector<char> buffer_ = std::vector<char>(kChunkBytes);
  std::string text_;
  std::size_t start_ = 0;
  std::uintmax_t read_ = 0;
  bool done_ = false;
  bool skipping_ = false;
  bool stopped_at_limit_ = false;
  std::optional<unsigned char> carry_;
  std::uint32_t high_surrogate_ = 0;
};

// Reads lines one at a time into a LogClock.
class ClockReader {
public:
  explicit ClockReader(LogClock& clock) : clock_(clock) {}

  void line(std::string_view text) {
    ++clock_.lines_read;
    const std::size_t number = clock_.lines_read;
    const auto local = log_clock_detail::line_prefix_millis(text);
    if (local) {
      if (!clock_.has_stamped_lines) {
        clock_.has_stamped_lines = true;
        clock_.first_local_millis = *local;
      }
      clock_.last_local_millis = *local;
      settle_pending(*local);
    } else if (!pending_.empty() && number - pending_.front().line > kHeaderReach) {
      drop_pending();
    }
    const std::string_view trimmed = trim_view(text);
    if (clock_.machine.empty() && starts_with(trimmed, "MachineName: [")) {
      const std::size_t close = trimmed.find(']');
      if (close != std::string_view::npos)
        clock_.machine = std::string(trimmed.substr(14, close - 14));
    } else if (clock_.machine.empty() && starts_with(trimmed, "Machine")) {
      // "Machine        :  WIN-8CT3S591F6V" in the plug-in services' header.
      const std::string_view rest = trimmed.substr(7);
      const std::size_t colon = rest.find(':');
      if (colon != std::string_view::npos && rest.substr(0, colon).find_first_not_of(' ') == std::string_view::npos)
        clock_.machine = trim(rest.substr(colon + 1));
    }
    if (last_zone_ != kNone && number - clock_.anchors[last_zone_].line_number <= 3 &&
        starts_with(ascii_lower(trimmed.substr(0, 16)), "daylight saving:")) {
      const std::string value = ascii_lower(trim(trimmed.substr(16)));
      if (value == "true" || value == "false")
        clock_.anchors[last_zone_].daylight = value == "true";
    }
    if (text.find("UTC") == std::string_view::npos || clock_.anchors.size() >= kAnchorLimit)
      return;
    if (const std::size_t at = text.find("UTC Time: ["); at != std::string_view::npos) {
      dotnet_header(text, at, number);
      return;
    }
    if (const std::size_t at = text.find("UTC offset: "); at != std::string_view::npos) {
      const auto stated = stated_offset(text.substr(at + 12));
      if (stated) {
        LogClockAnchor anchor;
        anchor.source = stated->hours ? LogClockSource::offset_hours : LogClockSource::native_header;
        anchor.line_number = number;
        anchor.text = anchor_text(text);
        anchor.offset_minutes = stated->minutes;
        add(std::move(anchor), local, {});
        return;
      }
    }
    if (const auto zone = named_zone_in(text)) {
      LogClockAnchor anchor;
      anchor.source = LogClockSource::zone_name;
      anchor.line_number = number;
      anchor.text = anchor_text(text);
      anchor.zone_text = *zone;
      anchor.zone = find_named_time_zone(*zone);
      last_zone_ = clock_.anchors.size();
      add(std::move(anchor), local, {});
    }
  }

  void finish() {
    drop_pending();
  }

private:
  static constexpr std::size_t kNone = static_cast<std::size_t>(-1);

  struct Pending {
    std::size_t index = 0; // in clock_.anchors
    std::size_t line = 0;
    std::vector<std::int64_t> readings; // a .NET header's UTC time, each way the culture could write it
  };

  static std::string_view trim_view(std::string_view text) {
    const std::size_t first = text.find_first_not_of(" \t\r");
    if (first == std::string_view::npos)
      return {};
    const std::size_t last = text.find_last_not_of(" \t\r");
    return text.substr(first, last - first + 1);
  }

  void dotnet_header(std::string_view text, std::size_t at, std::size_t number) {
    const std::size_t open = at + 10;
    const std::size_t close = text.find(']', open);
    if (close == std::string_view::npos)
      return;
    LogClockAnchor anchor;
    anchor.source = LogClockSource::dotnet_header;
    anchor.line_number = number;
    anchor.text = anchor_text(text);
    const std::size_t flag = text.find("DaylightSavingTime: [", close);
    if (flag != std::string_view::npos) {
      const std::string_view value = text.substr(flag + 21, 5);
      if (starts_with(value, "True"))
        anchor.daylight = true;
      else if (starts_with(value, "False"))
        anchor.daylight = false;
    }
    auto readings = log_clock_detail::header_time_readings(text.substr(open + 1, close - open - 1));
    if (readings.empty())
      return;
    add(std::move(anchor), log_clock_detail::line_prefix_millis(text), std::move(readings));
  }

  void add(LogClockAnchor anchor, std::optional<std::int64_t> local, std::vector<std::int64_t> readings) {
    const std::size_t index = clock_.anchors.size();
    clock_.anchors.push_back(std::move(anchor));
    if (local) {
      settle(index, *local, readings);
      return;
    }
    pending_.push_back({index, clock_.anchors[index].line_number, std::move(readings)});
  }

  void settle(std::size_t index, std::int64_t local, const std::vector<std::int64_t>& readings) {
    LogClockAnchor& anchor = clock_.anchors[index];
    anchor.has_local_time = true;
    anchor.local_millis = local;
    if (anchor.source == LogClockSource::dotnet_header)
      anchor.offset_minutes = offset_against(local, readings);
  }

  void settle_pending(std::int64_t local) {
    for (const Pending& pending : pending_)
      settle(pending.index, local, pending.readings);
    pending_.clear();
  }

  // Headers that no stamped line followed keep their stated offset and no place on the clock; a
  // .NET header needs that line for its offset, so it goes.
  void drop_pending() {
    std::vector<std::size_t> unpaired;
    for (const Pending& pending : pending_) {
      if (clock_.anchors[pending.index].source == LogClockSource::dotnet_header)
        unpaired.push_back(pending.index);
    }
    pending_.clear();
    for (auto index = unpaired.rbegin(); index != unpaired.rend(); ++index) {
      clock_.anchors.erase(clock_.anchors.begin() + static_cast<std::ptrdiff_t>(*index));
      if (last_zone_ != kNone && last_zone_ > *index)
        --last_zone_;
    }
  }

  LogClock& clock_;
  std::vector<Pending> pending_;
  std::size_t last_zone_ = kNone;
};

bool usable(const LogClockAnchor& anchor) {
  return anchor.offset_minutes.has_value() && anchor.source != LogClockSource::zone_name;
}

// "(UTC-05:00) Eastern Time (US & Canada)" -> "Eastern Time (US & Canada)".
std::string short_zone_name(const NamedTimeZone& zone) {
  const std::size_t close = zone.name.find(") ");
  return zone.name.front() == '(' && close != std::string::npos ? zone.name.substr(close + 2) : zone.name;
}

} // namespace

namespace log_clock_detail {

std::optional<std::int64_t> line_prefix_millis(std::string_view line) {
  int day = 0;
  int month = 0;
  int year = 0;
  int hour = 0;
  int minute = 0;
  int second = 0;
  std::size_t at = 0;
  const bool veeam = line.size() >= 21 && line[0] == '[';
  if (veeam) {
    // "[29.09.2026 12:15:47.134]"
    if (!digits_at(line, 1, 2, day) || line[3] != '.' || !digits_at(line, 4, 2, month) || line[6] != '.' ||
        !digits_at(line, 7, 4, year) || line[11] != ' ' || !digits_at(line, 12, 2, hour) || line[14] != ':' ||
        !digits_at(line, 15, 2, minute) || line[17] != ':' || !digits_at(line, 18, 2, second))
      return std::nullopt;
    at = 20;
  } else {
    // "2025-02-08 17:59:27.0961 Info": the plug-in services' stamp, local time with no zone.
    if (line.size() < 19 || !digits_at(line, 0, 4, year) || line[4] != '-' || !digits_at(line, 5, 2, month) ||
        line[7] != '-' || !digits_at(line, 8, 2, day) || line[10] != ' ' || !digits_at(line, 11, 2, hour) ||
        line[13] != ':' || !digits_at(line, 14, 2, minute) || line[16] != ':' || !digits_at(line, 17, 2, second))
      return std::nullopt;
    at = 19;
  }
  int millis = 0;
  if (at < line.size() && line[at] == '.') {
    ++at;
    int scale = 100;
    while (at < line.size() && line[at] >= '0' && line[at] <= '9') {
      millis += (line[at] - '0') * scale;
      scale /= 10;
      ++at;
    }
  }
  if (veeam) {
    if (at >= line.size() || line[at] != ']')
      return std::nullopt;
  } else {
    if (at < line.size() && line[at] != ' ' && line[at] != '\t')
      return std::nullopt;
    // A stamp followed by its own offset or Z is not the log's local clock.
    while (at < line.size() && (line[at] == ' ' || line[at] == '\t'))
      ++at;
    const bool signed_offset =
        at + 1 < line.size() && (line[at] == '+' || line[at] == '-') && line[at + 1] >= '0' && line[at + 1] <= '9';
    const bool zulu = at < line.size() && line[at] == 'Z' && (at + 1 == line.size() || line[at + 1] == ' ');
    if (signed_offset || zulu)
      return std::nullopt;
  }
  return civil_millis(year, month, day, hour, minute, second, millis);
}

std::vector<std::int64_t> header_time_readings(std::string_view text) {
  std::vector<int> numbers;
  std::vector<std::size_t> widths;
  std::string letters;
  for (std::size_t at = 0; at < text.size();) {
    const char character = text[at];
    if (character >= '0' && character <= '9') {
      int value = 0;
      const std::size_t start = at;
      while (at < text.size() && text[at] >= '0' && text[at] <= '9' && at - start < 4) {
        value = value * 10 + (text[at] - '0');
        ++at;
      }
      numbers.push_back(value);
      widths.push_back(at - start);
      continue;
    }
    if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z'))
      letters += static_cast<char>(character >= 'a' ? character - 32 : character);
    ++at;
  }
  std::vector<std::int64_t> readings;
  if (numbers.size() < 6)
    return readings;
  int hour = numbers[3];
  if (letters == "PM" && hour < 12)
    hour += 12;
  else if (letters == "AM" && hour == 12)
    hour = 0;
  std::vector<std::array<int, 3>> dates; // year, month, day
  if (widths[0] == 4) {
    dates.push_back({numbers[0], numbers[1], numbers[2]});
  } else if (widths[2] == 4 || widths[2] == 2) {
    const int year = widths[2] == 2 ? numbers[2] + 2000 : numbers[2];
    dates.push_back({year, numbers[0], numbers[1]}); // month first, as en-US writes it
    if (numbers[0] != numbers[1])
      dates.push_back({year, numbers[1], numbers[0]});
  }
  for (const auto& date : dates) {
    if (const auto millis = civil_millis(date[0], date[1], date[2], hour, numbers[4], numbers[5]))
      readings.push_back(*millis);
  }
  return readings;
}

} // namespace log_clock_detail

LogClock read_log_clock(const std::filesystem::path& file) {
  LogClock clock;
  clock.source = path_to_utf8(file);
  TextLines lines(file);
  if (!lines.is_open()) {
    clock.error = "The log could not be opened: " + clock.source;
    return clock;
  }
  ClockReader reader(clock);
  std::string line;
  while (lines.next(line))
    reader.line(line);
  reader.finish();
  clock.stopped_at_limit = lines.stopped_at_limit();
  return clock;
}

LogClock read_log_clock_text(std::string_view text, std::string source) {
  LogClock clock;
  clock.source = std::move(source);
  ClockReader reader(clock);
  std::size_t start = 0;
  while (start <= text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos)
      end = text.size();
    std::string_view line = text.substr(start, end - start);
    if (!line.empty() && line.back() == '\r')
      line.remove_suffix(1);
    if (!(end == text.size() && line.empty()))
      reader.line(line);
    start = end + 1;
  }
  reader.finish();
  return clock;
}

const LogClockAnchor* log_clock_named_zone(const LogClock& clock) {
  for (const LogClockAnchor& anchor : clock.anchors) {
    if (anchor.source == LogClockSource::zone_name && anchor.zone != nullptr)
      return &anchor;
  }
  return nullptr;
}

std::vector<LogClockGroup> log_clock_groups(const LogClock& clock) {
  std::vector<LogClockGroup> groups;
  // Headers that state daylight saving group by offset and that state first; one that does not
  // (a native header, the offset in hours) joins the first group on its offset.
  for (const bool stated : {true, false}) {
    for (const LogClockAnchor& anchor : clock.anchors) {
      if (!usable(anchor) || anchor.daylight.has_value() != stated)
        continue;
      auto group = std::find_if(groups.begin(), groups.end(), [&](const LogClockGroup& existing) {
        return existing.offset_minutes == *anchor.offset_minutes && (!stated || existing.daylight == anchor.daylight);
      });
      if (group == groups.end()) {
        LogClockGroup added;
        added.offset_minutes = *anchor.offset_minutes;
        added.daylight = anchor.daylight;
        added.first_line = anchor.line_number;
        added.last_line = anchor.line_number;
        added.example = &anchor;
        groups.push_back(added);
        group = groups.end() - 1;
      }
      ++group->count;
      group->first_line = std::min(group->first_line, anchor.line_number);
      group->last_line = std::max(group->last_line, anchor.line_number);
      if (anchor.has_local_time) {
        if (!group->has_local_time || anchor.local_millis < group->first_local_millis)
          group->first_local_millis = anchor.local_millis;
        if (!group->has_local_time || anchor.local_millis > group->last_local_millis)
          group->last_local_millis = anchor.local_millis;
        group->has_local_time = true;
      }
    }
  }
  std::sort(groups.begin(), groups.end(),
            [](const LogClockGroup& left, const LogClockGroup& right) { return left.first_line < right.first_line; });
  return groups;
}

LogClockSummary summarize_log_clock(const LogClock& clock) {
  LogClockSummary summary;
  if (!clock.error.empty()) {
    summary.headline = clock.error;
    return summary;
  }
  const std::vector<LogClockGroup> groups = log_clock_groups(clock);
  const LogClockAnchor* named = log_clock_named_zone(clock);
  const LogClockAnchor* unlisted = nullptr;
  for (const LogClockAnchor& anchor : clock.anchors) {
    if (anchor.source == LogClockSource::zone_name && anchor.zone == nullptr && unlisted == nullptr)
      unlisted = &anchor;
  }
  auto offset_words = [](int offset, std::optional<bool> daylight) {
    return format_utc_offset(offset) +
           (daylight ? (*daylight ? ", daylight saving time" : ", standard time") : std::string());
  };
  auto minute = [](std::int64_t local) { return time_check_detail::format_unix_millis(local, 0).substr(0, 16); };
  if (named != nullptr) {
    summary.headline = "This log names its zone: " + named->zone->name;
    summary.tied = true;
  } else if (!groups.empty()) {
    summary.headline = "This log was written at ";
    for (std::size_t index = 0; index < groups.size(); ++index)
      summary.headline += (index == 0 ? "" : " and at ") + offset_words(groups[index].offset_minutes, groups[index].daylight);
    summary.tied = true;
  } else if (unlisted != nullptr) {
    summary.headline = "This log names " + unlisted->zone_text + ", which is not in the list";
  } else {
    summary.headline = "This log does not tie its clock to UTC";
    summary.notes.push_back("It has no header with a UTC time or offset and names no zone. Choose the zone it was "
                            "written in from Written in.");
  }
  if (clock.stopped_at_limit)
    summary.notes.push_back("Only the first 512 MiB of the log were read.");

  if (!clock.machine.empty())
    summary.rows.emplace_back("Machine", clock.machine);
  std::string lines = std::to_string(clock.lines_read) + " lines";
  if (clock.has_stamped_lines)
    lines += ", stamped " + minute(clock.first_local_millis) + " to " + minute(clock.last_local_millis) +
             " on its own clock";
  summary.rows.emplace_back("Lines", lines);
  if (const LogClockAnchor* zone = named != nullptr ? named : unlisted) {
    std::string value = zone->zone_text + " at line " + std::to_string(zone->line_number);
    if (zone->daylight)
      value += *zone->daylight ? ", daylight saving time then" : ", standard time then";
    summary.rows.emplace_back("Zone named", value);
  }
  for (const LogClockGroup& group : groups) {
    std::string value = std::to_string(group.count) + (group.count == 1U ? " header" : " headers");
    value += group.first_line == group.last_line
                 ? ", line " + std::to_string(group.first_line)
                 : ", lines " + std::to_string(group.first_line) + " to " + std::to_string(group.last_line);
    if (group.has_local_time)
      value += group.first_local_millis == group.last_local_millis
                   ? ", " + minute(group.first_local_millis)
                   : ", " + minute(group.first_local_millis) + " to " + minute(group.last_local_millis);
    summary.rows.emplace_back(offset_words(group.offset_minutes, group.daylight), value);
  }
  if (named == nullptr && !groups.empty()) {
    // The listed zones on the latest offset, at the latest header.
    const LogClockGroup* latest = &groups.front();
    for (const LogClockGroup& group : groups) {
      if (group.last_local_millis > latest->last_local_millis)
        latest = &group;
    }
    const std::int64_t at = latest->last_local_millis - static_cast<std::int64_t>(latest->offset_minutes) * kMillisPerMinute;
    std::vector<std::string> names;
    for (const NamedTimeZone* zone : zones_at_offset(latest->offset_minutes, at, latest->daylight))
      names.push_back(zone->name);
    summary.rows.emplace_back("Zone could be", names.empty() ? "none of the listed zones" : zone_names_text(names));
  }
  const LogClockAnchor* example = named != nullptr ? named : !groups.empty() ? groups.front().example : unlisted;
  if (example != nullptr)
    summary.rows.emplace_back("Log says", "Line " + std::to_string(example->line_number) + ": " + example->text);
  return summary;
}

LogClockReading log_clock_at(const LogClock& clock, std::int64_t local_millis) {
  LogClockReading reading;
  const LogClockAnchor* before = nullptr;
  const LogClockAnchor* after = nullptr;
  const LogClockAnchor* unplaced = nullptr;
  for (const LogClockAnchor& anchor : clock.anchors) {
    if (!usable(anchor))
      continue;
    if (!anchor.has_local_time) {
      if (unplaced == nullptr)
        unplaced = &anchor;
    } else if (anchor.local_millis <= local_millis) {
      if (before == nullptr || anchor.local_millis >= before->local_millis)
        before = &anchor;
    } else if (after == nullptr || anchor.local_millis < after->local_millis) {
      after = &anchor;
    }
  }
  const LogClockAnchor* nearest = before != nullptr ? before : after;
  if (clock.has_stamped_lines &&
      (local_millis < clock.first_local_millis - kMillisPerDay || local_millis > clock.last_local_millis + kMillisPerDay))
    reading.notes.push_back("This time is outside the log's own lines, " +
                            time_check_detail::format_unix_millis(clock.first_local_millis, 0).substr(0, 19) + " to " +
                            time_check_detail::format_unix_millis(clock.last_local_millis, 0).substr(0, 19) +
                            ". It may be from another log.");

  if (const LogClockAnchor* named = log_clock_named_zone(clock)) {
    // The zone's rules apply on any date, so long as the log's own headers agree with them.
    const LogClockAnchor* disagrees = nullptr;
    for (const LogClockAnchor& anchor : clock.anchors) {
      if (usable(anchor) && anchor.has_local_time &&
          zone_local_to_utc(*named->zone, anchor.local_millis).offset.offset_minutes != *anchor.offset_minutes) {
        disagrees = &anchor;
        break;
      }
    }
    if (disagrees == nullptr) {
      const ZoneLocalTime local = zone_local_to_utc(*named->zone, local_millis);
      reading.found = true;
      reading.offset_minutes = static_cast<int>((local_millis - local.unix_millis) / kMillisPerMinute);
      reading.daylight = local.offset.daylight;
      reading.anchor = named;
      reading.zone = named->zone;
      reading.ambiguous = local.ambiguous;
      reading.skipped = local.skipped;
      reading.how = "the zone the log names at line " + std::to_string(named->line_number);
      if (nearest != nullptr)
        reading.how += ", which its headers agree with";
      return reading;
    }
    reading.notes.push_back("The log names " + named->zone->name + " at line " + std::to_string(named->line_number) +
                            ", but its header at line " + std::to_string(disagrees->line_number) + " gives " +
                            format_utc_offset(*disagrees->offset_minutes) + " at that time. The headers are used.");
  }

  if (nearest == nullptr)
    nearest = unplaced;
  if (nearest == nullptr)
    return reading;
  reading.found = true;
  reading.offset_minutes = *nearest->offset_minutes;
  reading.daylight = nearest->daylight;
  reading.anchor = nearest;
  reading.how = "the log's header at line " + std::to_string(nearest->line_number);
  if (!nearest->has_local_time) {
    reading.notes.push_back("No stamped line follows that header, so its offset is used for every time in the log.");
    return reading;
  }
  if (before == nullptr) {
    reading.how += ", the first after this time";
  }
  // A daylight saving change after the header shows only at the next header: name the zones on the
  // header's offset that changed by this time.
  const std::int64_t header_utc = nearest->local_millis - *nearest->offset_minutes * kMillisPerMinute;
  const std::int64_t this_utc = local_millis - *nearest->offset_minutes * kMillisPerMinute;
  std::vector<std::string> changed;
  std::optional<int> changed_to;
  bool one_offset = true;
  for (const NamedTimeZone* zone : zones_at_offset(*nearest->offset_minutes, header_utc, nearest->daylight)) {
    const ZoneOffset then = zone_offset_at(*zone, this_utc);
    if (then.offset_minutes == *nearest->offset_minutes)
      continue;
    if (changed_to && *changed_to != then.offset_minutes)
      one_offset = false;
    changed_to = then.offset_minutes;
    changed.push_back(short_zone_name(*zone));
  }
  if (!changed.empty()) {
    std::string names;
    for (std::size_t index = 0; index < changed.size(); ++index)
      names += (index == 0 ? "" : index + 1 == changed.size() ? " or " : ", ") + changed[index];
    reading.notes.push_back("Daylight saving changed between that header and this time in " + names +
                            (one_offset ? " (" + format_utc_offset(*changed_to) + " at this time)" : std::string()) +
                            ". If the log was written there, the next header in the log shows the new offset.");
  }
  return reading;
}

} // namespace support_assist
