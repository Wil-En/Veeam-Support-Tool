#include "support_assist/file_transfer.hpp"

#include "support_assist/disk_speed_test.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/support_tools.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>

namespace support_assist {
namespace {

Error transfer_error(std::string operation, std::string message) {
  Error error;
  error.component = "FileTransfer";
  error.operation = std::move(operation);
  error.message = std::move(message);
  return error;
}

// A number and the unit after it, read the same in every locale: "1,500 GB" -> 1500 and "GB".
struct NumberAndUnit {
  double number = 0.0;
  std::string unit;
};

std::optional<NumberAndUnit> split_number(std::string_view text) {
  std::string cleaned;
  for (const char character : text) {
    if (character != ',' && character != ' ' && character != '\t' && character != '\'')
      cleaned.push_back(character);
  }
  std::size_t at = 0;
  double whole = 0.0;
  double fraction = 0.0;
  double scale = 1.0;
  bool digits = false;
  bool point = false;
  for (; at < cleaned.size(); ++at) {
    const char character = cleaned[at];
    if (character >= '0' && character <= '9') {
      digits = true;
      if (point) {
        scale /= 10.0;
        fraction += (character - '0') * scale;
      } else {
        whole = whole * 10.0 + (character - '0');
      }
      continue;
    }
    if (character == '.' && !point) {
      point = true;
      continue;
    }
    break;
  }
  if (!digits)
    return std::nullopt;
  return NumberAndUnit{whole + fraction, cleaned.substr(at)};
}

// "1,234,567"
std::string grouped(double value) {
  std::string digits = std::to_string(static_cast<long long>(std::llround(value)));
  for (std::size_t at = digits.size(); at > 3U; at -= 3U)
    digits.insert(at - 3U, ",");
  return digits;
}

// Up to the given decimals, without trailing zeros: 2.50 -> "2.5", 10.00 -> "10".
std::string trimmed(double value, int decimals) {
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%.*f", decimals, value);
  std::string out = text;
  if (out.find('.') != std::string::npos) {
    while (!out.empty() && out.back() == '0')
      out.pop_back();
    if (!out.empty() && out.back() == '.')
      out.pop_back();
  }
  return out;
}

// "10 billion", "1.25 billion", "125 million", "500,000".
std::string in_words(double value) {
  if (value >= 1e9)
    return trimmed(value / 1e9, 2) + " billion";
  if (value >= 1e6)
    return trimmed(value / 1e6, 2) + " million";
  return grouped(value);
}

std::string percent_text(double value) { return trimmed(value, 1) + "%"; }

std::string rate_only(double bytes_per_second) { return plain_rate(bytes_per_second / kTransferMiB); }

// "3.9 TB" or "540 GB" an hour.
std::string per_hour_text(double bytes_per_second) {
  const double bytes = bytes_per_second * 3600.0;
  if (bytes >= kTransferTiB)
    return trimmed(bytes / kTransferTiB, 1) + " TB";
  return grouped(bytes / kTransferGiB) + " GB";
}

std::string packets_text(int mtu) {
  if (mtu == kStandardMtu)
    return "standard packets (MTU 1500)";
  if (mtu == kJumboMtu)
    return "jumbo frames (MTU 9000)";
  return "MTU " + grouped(mtu);
}

std::string protocol_text(TransferIp ip, bool tcp_timestamps) {
  return std::string("TCP over ") + (ip == TransferIp::ipv6 ? "IPv6" : "IPv4") +
         (tcp_timestamps ? " with timestamps" : "");
}

std::string lower_first(std::string text) {
  if (!text.empty() && text.front() >= 'A' && text.front() <= 'Z' && (text.size() < 2U || text[1] < 'A' || text[1] > 'Z'))
    text.front() = static_cast<char>(text.front() - 'A' + 'a');
  return text;
}

// How a speed reads in a sentence: its phrase, or its name in lower case.
std::string phrase_of(const TransferSpeed& speed) {
  return speed.phrase.empty() ? lower_first(speed.name) : speed.phrase;
}

} // namespace

Result<double> parse_data_size(std::string_view text, std::string_view default_unit) {
  const auto parsed = split_number(trim(text));
  if (!parsed || parsed->number <= 0.0)
    return Result<double>::failure(transfer_error("data size", "Enter the data to move as a number and a unit, such as 20 TB."));
  std::string unit = ascii_lower(parsed->unit.empty() ? std::string(default_unit) : parsed->unit);
  if (unit.size() > 1U && unit.back() == 'b' && unit[unit.size() - 2U] == 'i')
    unit.erase(unit.size() - 2U, 1U); // TiB reads as TB
  double multiplier = 0.0;
  if (unit == "b" || unit == "bytes" || unit == "byte")
    multiplier = 1.0;
  else if (unit == "k" || unit == "kb")
    multiplier = 1024.0;
  else if (unit == "m" || unit == "mb")
    multiplier = kTransferMiB;
  else if (unit == "g" || unit == "gb")
    multiplier = kTransferGiB;
  else if (unit == "t" || unit == "tb")
    multiplier = kTransferTiB;
  else if (unit == "p" || unit == "pb")
    multiplier = kTransferPiB;
  if (multiplier == 0.0)
    return Result<double>::failure(transfer_error(
        "data size", "\"" + parsed->unit + "\" is not a size unit: use MB, GB, TB or PB, such as 20 TB."));
  return Result<double>::success(parsed->number * multiplier);
}

Result<double> parse_link_speed(std::string_view text, std::string_view default_unit) {
  const auto parsed = split_number(trim(text));
  if (!parsed || parsed->number <= 0.0)
    return Result<double>::failure(transfer_error("link speed", "Enter the link speed as a number and a unit, such as 10 Gb/s."));
  const std::string unit = ascii_lower(parsed->unit.empty() ? std::string(default_unit) : parsed->unit);
  double multiplier = 0.0;
  std::string rest = unit;
  if (!unit.empty()) {
    switch (unit.front()) {
    case 'k': multiplier = 1e3; break;
    case 'm': multiplier = 1e6; break;
    case 'g': multiplier = 1e9; break;
    case 't': multiplier = 1e12; break;
    default: break;
    }
    if (multiplier != 0.0)
      rest = unit.substr(1);
  }
  if (multiplier == 0.0 && (unit == "b/s" || unit == "bps" || unit == "bit/s" || unit == "bits/s"))
    return Result<double>::success(parsed->number);
  static const char* const kAccepted[] = {"", "b", "b/s", "bps", "bit", "bits", "bit/s", "bits/s", "be", "bit/sec"};
  const bool accepted = std::any_of(std::begin(kAccepted), std::end(kAccepted),
                                    [&](const char* candidate) { return rest == candidate; });
  if (multiplier == 0.0 || !accepted)
    return Result<double>::failure(
        transfer_error("link speed", "\"" + parsed->unit + "\" is not a link speed unit: use Mb/s or Gb/s, such as 10 Gb/s."));
  const double bits = parsed->number * multiplier;
  if (bits > 1e13)
    return Result<double>::failure(transfer_error("link speed", "A link speed above 10 Tb/s is not one a network carries."));
  return Result<double>::success(bits);
}

Result<double> parse_byte_rate(std::string_view text, std::string_view default_unit) {
  const auto parsed = split_number(trim(text));
  if (!parsed || parsed->number <= 0.0)
    return Result<double>::failure(transfer_error("speed", "Enter a speed as a number and a unit, such as 520 MB/s."));
  const std::string unit = parsed->unit.empty() ? std::string(default_unit) : parsed->unit;
  const char prefix = static_cast<char>(ascii_lower(unit.substr(0, 1)).front());
  double bytes_multiplier = 0.0;
  double bits_multiplier = 0.0;
  switch (prefix) {
  case 'k':
    bytes_multiplier = 1024.0;
    bits_multiplier = 1e3 / 8.0;
    break;
  case 'm':
    bytes_multiplier = kTransferMiB;
    bits_multiplier = 1e6 / 8.0;
    break;
  case 'g':
    bytes_multiplier = kTransferGiB;
    bits_multiplier = 1e9 / 8.0;
    break;
  case 't':
    bytes_multiplier = kTransferTiB;
    bits_multiplier = 1e12 / 8.0;
    break;
  default: break;
  }
  const std::string rest = unit.substr(1);
  // A small b is bits (Mb/s, a WAN link's speed); a capital B, or none, is bytes (MB/s).
  const bool bits = !rest.empty() && rest.front() == 'b';
  const std::string after = ascii_lower(rest.empty() ? rest : rest.substr(1));
  static const char* const kAccepted[] = {"", "/s", "ps", "it/s", "its/s", "it", "its", "/sec"};
  const bool accepted = std::any_of(std::begin(kAccepted), std::end(kAccepted),
                                    [&](const char* candidate) { return after == candidate; });
  if (bytes_multiplier == 0.0 || !accepted || (!rest.empty() && rest.front() != 'b' && rest.front() != 'B'))
    return Result<double>::failure(
        transfer_error("speed", "\"" + parsed->unit + "\" is not a speed unit: use MB/s, GB/s or Mb/s, such as 520 MB/s."));
  return Result<double>::success(parsed->number * (bits ? bits_multiplier : bytes_multiplier));
}

Result<int> parse_mtu(std::string_view text) {
  // The first run of digits: "Standard, 1500" and "1500 (standard)" read alike.
  long long value = 0;
  bool digits = false;
  for (const char character : text) {
    if (character >= '0' && character <= '9') {
      digits = true;
      value = value * 10 + (character - '0');
      if (value > 100000)
        break;
      continue;
    }
    if (character == ',' && digits)
      continue;
    if (digits)
      break;
  }
  if (!digits || value < 576 || value > 9216)
    return Result<int>::failure(
        transfer_error("packet size", "The packet size is an MTU from 576 to 9216 bytes: 1500 is standard, 9000 jumbo."));
  return Result<int>::success(static_cast<int>(value));
}

Result<double> parse_percent(std::string_view text, std::string_view what) {
  std::string value = trim(text);
  if (!value.empty() && value.back() == '%')
    value.pop_back();
  const auto parsed = split_number(value);
  if (!parsed || !trim(parsed->unit).empty() || parsed->number < 1.0 || parsed->number > 100.0)
    return Result<double>::failure(transfer_error(std::string(what), std::string(what) + " is a percentage from 1 to 100."));
  return Result<double>::success(parsed->number);
}

double packet_efficiency(int mtu, TransferIp ip, bool tcp_timestamps) {
  const int headers = (ip == TransferIp::ipv6 ? 40 : 20) + 20 + (tcp_timestamps ? 12 : 0);
  if (mtu <= headers)
    return 0.0;
  return static_cast<double>(mtu - headers) / static_cast<double>(mtu + kEthernetFrameBytes);
}

std::string transfer_duration_text(double seconds) {
  if (seconds < 30.0)
    return "under a minute";
  const long long minutes = std::llround(seconds / 60.0);
  if (minutes < 60)
    return std::to_string(minutes) + " min";
  const long long hours = minutes / 60;
  const long long rest = minutes % 60;
  return std::to_string(hours) + " h" + (rest == 0 ? std::string() : " " + std::to_string(rest) + " min");
}

std::string transfer_duration_words(double seconds) {
  if (seconds < 30.0)
    return "under a minute";
  const long long minutes = std::llround(seconds / 60.0);
  const auto unit = [](long long value, const char* one, const char* many) {
    return std::to_string(value) + " " + (value == 1 ? one : many);
  };
  if (minutes < 60)
    return unit(minutes, "minute", "minutes");
  const long long hours = minutes / 60;
  const long long rest = minutes % 60;
  return unit(hours, "hour", "hours") + (rest == 0 ? std::string() : " " + unit(rest, "minute", "minutes"));
}

std::string transfer_rate_text(double bytes_per_second) {
  const double mib = bytes_per_second / kTransferMiB;
  if (mib < 100.0)
    return plain_rate(mib);
  char gib[32] = {};
  std::snprintf(gib, sizeof(gib), "%.2f", mib / 1024.0);
  return plain_rate(mib) + " (" + gib + " GB/s)";
}

std::string transfer_rate_figure(double bytes_per_second) {
  std::string text = rate_only(bytes_per_second);
  const std::string unit = " MB/s";
  if (text.size() > unit.size() && text.compare(text.size() - unit.size(), unit.size(), unit) == 0)
    text.resize(text.size() - unit.size());
  return text;
}

std::string transfer_size_text(double bytes) {
  if (bytes >= kTransferPiB)
    return trimmed(bytes / kTransferPiB, 1) + " PB";
  if (bytes >= kTransferTiB)
    return trimmed(bytes / kTransferTiB, 1) + " TB";
  if (bytes >= kTransferGiB)
    return trimmed(bytes / kTransferGiB, 1) + " GB";
  return trimmed(bytes / kTransferMiB, 1) + " MB";
}

std::string link_speed_text(double bits_per_second) {
  if (bits_per_second >= 1e9)
    return trimmed(bits_per_second / 1e9, 2) + " Gb/s";
  if (bits_per_second >= 1e6)
    return trimmed(bits_per_second / 1e6, 2) + " Mb/s";
  return trimmed(bits_per_second / 1e3, 2) + " kb/s";
}

Result<TransferEstimate> estimate_transfer(const TransferInputs& inputs) {
  if (!(inputs.size_bytes > 0.0))
    return Result<TransferEstimate>::failure(transfer_error("estimate", "Enter the data to move, such as 20 TB."));
  if (!(inputs.link_bits_per_second > 0.0))
    return Result<TransferEstimate>::failure(transfer_error("estimate", "Enter the link speed, such as 10 Gb/s."));
  if (inputs.mtu < 576 || inputs.mtu > 9216)
    return Result<TransferEstimate>::failure(
        transfer_error("estimate", "The packet size is an MTU from 576 to 9216 bytes: 1500 is standard, 9000 jumbo."));
  if (inputs.share_percent < 1.0 || inputs.share_percent > 100.0)
    return Result<TransferEstimate>::failure(
        transfer_error("estimate", "Link throttle is from 1 to 100% of the link."));
  if (inputs.reduced_to_percent < 1.0 || inputs.reduced_to_percent > 100.0)
    return Result<TransferEstimate>::failure(
        transfer_error("estimate", "Compression is from 1 to 100% of the data."));

  TransferEstimate estimate;
  estimate.inputs = inputs;
  estimate.efficiency = packet_efficiency(inputs.mtu, inputs.ip, inputs.tcp_timestamps);
  estimate.line_bytes_per_second = inputs.link_bits_per_second / 8.0;
  const double data_full = estimate.line_bytes_per_second * estimate.efficiency;
  estimate.data_bytes_per_second = data_full * inputs.share_percent / 100.0;
  estimate.moved_bytes = inputs.size_bytes * inputs.reduced_to_percent / 100.0;
  const bool shared = inputs.share_percent < 100.0;
  const bool reduced = inputs.reduced_to_percent < 100.0;
  const std::string link = link_speed_text(inputs.link_bits_per_second);
  const std::string size = transfer_size_text(inputs.size_bytes);
  const std::string moved = transfer_size_text(estimate.moved_bytes);
  const double overhead = (1.0 - estimate.efficiency) * 100.0;

  // The speeds the time can be set by, the link first so it wins a tie.
  std::vector<TransferSpeed> speeds;
  speeds.push_back({"Link, for data",
                    (inputs.link_name.empty() ? std::string() : inputs.link_name + ": ") + link + ", MTU " +
                        std::to_string(inputs.mtu),
                    estimate.data_bytes_per_second, "the link"});
  for (const TransferSpeed& measured : inputs.measured) {
    if (measured.bytes_per_second > 0.0)
      speeds.push_back(measured);
  }
  if (inputs.network_bytes_per_second && *inputs.network_bytes_per_second > 0.0)
    speeds.push_back({"Network speed", "", *inputs.network_bytes_per_second, "the network speed"});
  if (inputs.storage_bytes_per_second && *inputs.storage_bytes_per_second > 0.0)
    speeds.push_back({"Storage speed", "", *inputs.storage_bytes_per_second, "the storage speed"});
  std::size_t lowest = 0;
  for (std::size_t index = 1; index < speeds.size(); ++index) {
    if (speeds[index].bytes_per_second < speeds[lowest].bytes_per_second)
      lowest = index;
  }
  estimate.rate_bytes_per_second = speeds[lowest].bytes_per_second;
  estimate.seconds = estimate.moved_bytes / estimate.rate_bytes_per_second;
  estimate.lowest_name = lowest == 0 ? std::string() : speeds[lowest].name;
  estimate.lowest_phrase = lowest == 0 ? std::string() : phrase_of(speeds[lowest]);
  for (std::size_t index = 0; index < speeds.size(); ++index)
    estimate.speeds.push_back({speeds[index], estimate.moved_bytes / speeds[index].bytes_per_second, index == lowest});

  const std::string rate = rate_only(estimate.rate_bytes_per_second);
  const std::string per_hour = per_hour_text(estimate.rate_bytes_per_second);
  const std::string time = transfer_duration_text(estimate.seconds);

  if (lowest == 0) {
    estimate.headline = size + (reduced ? " (" + moved + " to send)" : std::string()) + " at " + link + ": about " + time;
    estimate.summary = rate + " for the data, " + per_hour + " per hour. Disk speed, other traffic and the devices on "
                                                             "the path can lengthen it.";
  } else {
    estimate.headline = size + (reduced ? " (" + moved + " to send)" : std::string()) + ": about " + time + " at " + rate;
    estimate.summary = "The lowest speed is " + phrase_of(speeds[lowest]) + ": " + rate + ".";
  }

  // Simple: the link, the rate for the data, a terabyte's time and this size's.
  estimate.simple.push_back({"Link", (inputs.link_name.empty() ? std::string() : inputs.link_name + ": ") + link + ", " +
                                         packets_text(inputs.mtu)});
  estimate.simple.push_back({"For the data", transfer_rate_text(data_full) + ", " + per_hour_text(data_full) + " per hour"});
  if (shared)
    estimate.simple.push_back({"Link throttle", percent_text(inputs.share_percent) + " of the link: " +
                                                       transfer_rate_text(estimate.data_bytes_per_second)});
  if (lowest != 0)
    estimate.simple.push_back({"Lowest speed", speeds[lowest].name + ": " + transfer_rate_text(estimate.rate_bytes_per_second)});
  if (reduced)
    estimate.simple.push_back({"After compression", moved + ", " + percent_text(inputs.reduced_to_percent) + " of " + size});
  estimate.simple.push_back({"1 TB takes", transfer_duration_text(kTransferTiB / estimate.rate_bytes_per_second)});
  estimate.simple.push_back({size + " takes", time});

  // How it is worked out, one step at a time.
  estimate.steps.push_back({link, "link speed: " + grouped(inputs.link_bits_per_second) + " bits per second"});
  estimate.steps.push_back({rate_only(estimate.line_bytes_per_second),
                            "in bytes, at 8 bits per byte: " + grouped(estimate.line_bytes_per_second) +
                                " bytes per second, which Windows shows as " + rate_only(estimate.line_bytes_per_second)});
  estimate.steps.push_back({rate_only(data_full), "for data, after " + percent_text(overhead) +
                                                      " Ethernet and TCP/IP overhead (MTU " + std::to_string(inputs.mtu) +
                                                      ", " + protocol_text(inputs.ip, inputs.tcp_timestamps) + ")"});
  if (shared)
    estimate.steps.push_back({rate_only(estimate.data_bytes_per_second),
                              "link throttle: " + percent_text(inputs.share_percent) + " of the link"});
  if (lowest != 0)
    estimate.steps.push_back({rate, "the lowest speed: " + phrase_of(speeds[lowest])});
  estimate.steps.push_back({per_hour, "per hour: " + rate + " \xC3\x97 3,600 seconds"});
  if (reduced)
    estimate.steps.push_back({moved, "to send: " + percent_text(inputs.reduced_to_percent) + " of " + size +
                                         " after Veeam's reduction"});
  estimate.steps.push_back({time, moved + " \xC3\xB7 " + per_hour + " per hour"});

  // Other amounts to send at the same rate.
  for (const double terabytes : {1.0, 5.0, 10.0, 20.0, 50.0, 100.0})
    estimate.other_sizes.push_back({trimmed(terabytes, 0) + " TB",
                                    transfer_duration_text(terabytes * kTransferTiB / estimate.rate_bytes_per_second)});

  // Jumbo frames change the time only when the link sets it.
  if (lowest == 0 && inputs.mtu < kJumboMtu) {
    double jumbo_rate = estimate.line_bytes_per_second * packet_efficiency(kJumboMtu, inputs.ip, inputs.tcp_timestamps) *
                        inputs.share_percent / 100.0;
    for (std::size_t index = 1; index < speeds.size(); ++index)
      jumbo_rate = std::min(jumbo_rate, speeds[index].bytes_per_second);
    estimate.jumbo_seconds = estimate.moved_bytes / jumbo_rate;
    estimate.jumbo_note = "With jumbo frames (MTU 9000) on every device on the path: " + moved + " in " +
                          transfer_duration_text(*estimate.jumbo_seconds) + ".";
  }

  estimate.terms = {
      {"Gb/s", "gigabits per second, how a network link's speed is given. 8 bits make 1 byte."},
      {"MB/s, GB/s, TB", "bytes, as Windows counts them: 1 GB = 1,024 MB, 1 TB = 1,024 GB and 1 PB = 1,024 TB."},
      {"Overhead", "each packet's Ethernet frame (its header, frame check, preamble and the gap between frames) and "
                   "its IP and TCP headers. Worked out for " +
                       protocol_text(inputs.ip, inputs.tcp_timestamps) +
                       (inputs.ip == TransferIp::ipv4 ? "; IPv6 headers take 20 bytes more a packet." : ".")},
      {"MTU", "the largest packet the network carries. Standard is 1,500 bytes; jumbo frames are 9,000, and every "
              "device on the path must allow them."},
  };
  if (shared)
    estimate.terms.push_back({"Link throttle", "the part of the link this transfer can use, as a Veeam network "
                                               "traffic rule throttles it or other traffic shares it."});
  if (reduced)
    estimate.terms.push_back({"Compression", "the share of the data left to send after Veeam compresses it, as a "
                                             "job session's Transferred \xC3\xB7 Read."});
  return Result<TransferEstimate>::success(std::move(estimate));
}

Result<TransferSpeed> storage_speed_from_result(std::string_view json_text) {
  auto parsed = parse_json(json_text);
  if (!parsed.ok() || !parsed.value().is_object())
    return Result<TransferSpeed>::failure(
        transfer_error("storage result", "That file is not a Disk Speed Test result.json: it is not JSON SAT can read."));
  const JsonValue& result = parsed.value();
  const double write = result["write"]["mib_per_second"].as_number();
  const double read = result["read"]["mib_per_second"].as_number();
  if (!(write > 0.0) && !(read > 0.0))
    return Result<TransferSpeed>::failure(transfer_error(
        "storage result", "That result.json has no read or write speed: open the result.json a Disk Speed Test kept."));
  const std::string role = result["role"].as_string();
  bool writing = write > 0.0;
  if (role == "source" && read > 0.0)
    writing = false;
  else if (role != "repository" && write > 0.0 && read > 0.0)
    writing = write <= read;
  TransferSpeed speed;
  speed.name = writing ? "Storage, writing" : "Storage, reading";
  speed.phrase = writing ? "the storage's write speed" : "the storage's read speed";
  speed.bytes_per_second = (writing ? write : read) * kTransferMiB;
  std::string detail = result["name"].as_string();
  const std::string file = result["file"].as_string();
  if (!file.empty()) {
    const std::size_t slash = file.find_last_of("/\\");
    detail += (detail.empty() ? "" : ", ") + (slash == std::string::npos ? file : file.substr(0, slash));
  }
  const std::string ended = result["ended_utc"].as_string();
  if (ended.size() >= 16U)
    detail += (detail.empty() ? "" : ", ") + ended.substr(0, 10) + " " + ended.substr(11, 5) + " UTC";
  speed.detail = std::move(detail);
  return Result<TransferSpeed>::success(std::move(speed));
}

Result<TransferSpeed> iperf3_speed_from_json(std::string_view json_text, std::string_view host, int streams) {
  auto parsed = parse_json(json_text);
  if (!parsed.ok() || !parsed.value().is_object())
    return Result<TransferSpeed>::failure(transfer_error("iPerf3", "iPerf3 did not print its JSON report."));
  const JsonValue& report = parsed.value();
  if (report.has("error"))
    return Result<TransferSpeed>::failure(transfer_error("iPerf3", "iPerf3: " + report["error"].as_string()));
  const double bits = report["end"]["sum_received"]["bits_per_second"].as_number();
  if (!(bits > 0.0))
    return Result<TransferSpeed>::failure(transfer_error("iPerf3", "iPerf3's report has no received speed."));
  TransferSpeed speed;
  speed.name = "Network test to " + std::string(host);
  speed.phrase = "the network test to " + std::string(host);
  speed.detail = "iPerf3, " + std::to_string(streams) + (streams == 1 ? " stream, " : " streams, ") +
                 link_speed_text(bits);
  speed.bytes_per_second = bits / 8.0;
  return Result<TransferSpeed>::success(std::move(speed));
}

Result<TransferSpeed> run_iperf3_transfer_test(const IperfTransferOptions& options, const CancellationToken& cancel) {
  if (options.host.empty())
    return Result<TransferSpeed>::failure(transfer_error("iPerf3", "Enter the machine running the iPerf3 server."));
  IperfOptions iperf;
  iperf.host = options.host;
  iperf.port = options.port;
  iperf.third_party_directory = options.tools_folder;
  iperf.custom_arguments = {"-J", "-t", std::to_string(std::clamp(options.seconds, 1, 60))};
  if (options.streams > 1) {
    iperf.custom_arguments.push_back("-P");
    iperf.custom_arguments.push_back(std::to_string(std::min(options.streams, 16)));
  }
  auto ran = run_iperf(iperf, cancel);
  if (!ran.ok())
    return Result<TransferSpeed>::failure(ran.error());
  return iperf3_speed_from_json(ran.value().output, options.host, std::max(options.streams, 1));
}

TransferEmail transfer_email(const TransferEstimate& estimate) {
  const TransferInputs& inputs = estimate.inputs;
  const std::string link = link_speed_text(inputs.link_bits_per_second);
  const std::string size = transfer_size_text(inputs.size_bytes);
  const double data_full = estimate.line_bytes_per_second * estimate.efficiency;
  const double overhead = (1.0 - estimate.efficiency) * 100.0;
  TransferEmail email;
  email.subject = "Estimated transfer time: " + size + " over " + link;
  std::string body = "A " + link + " link carries " + in_words(inputs.link_bits_per_second) +
                     " bits per second. At 8 bits per byte that is " + in_words(estimate.line_bytes_per_second) +
                     " bytes per second, which Windows shows as " + rate_only(estimate.line_bytes_per_second) +
                     ". Ethernet and TCP/IP overhead uses about " +
                     (overhead < 1.0 ? trimmed(overhead, 1) : trimmed(overhead, 0)) + "% of it, which leaves " +
                     rate_only(data_full) + " (" + per_hour_text(data_full) + " per hour) for the data.";
  if (inputs.share_percent < 100.0)
    body += " This transfer can use " + percent_text(inputs.share_percent) + " of the link: " +
            rate_only(estimate.data_bytes_per_second) + ".";
  body += "\n\n";
  const std::string amount = inputs.reduced_to_percent < 100.0
                                 ? size + ", reduced to " + transfer_size_text(estimate.moved_bytes) + " to send,"
                                 : size;
  if (estimate.lowest_name.empty()) {
    body += "At that rate, " + amount + " takes about " + transfer_duration_words(estimate.seconds) +
            ". That is the most the link carries: disk speed, other traffic and the devices on the path can lengthen "
            "it.";
  } else {
    body += "The lowest speed is " + estimate.lowest_phrase + ", " + rate_only(estimate.rate_bytes_per_second) +
            ", so " + amount + " takes about " + transfer_duration_words(estimate.seconds) + ".";
  }
  body += "\n\nSizes as Windows shows them: 1 TB = 1,024 GB.";
  email.body = std::move(body);
  return email;
}

std::string transfer_text(const TransferEstimate& estimate) {
  std::string text = estimate.headline + "\n" + estimate.summary + "\n";
  const auto block = [&](const char* title, const std::vector<TransferRow>& rows) {
    if (rows.empty())
      return;
    std::vector<std::string> lines;
    for (const TransferRow& row : rows)
      lines.push_back("  " + row.label + "\t" + row.value);
    text += std::string("\n") + title + "\n";
    for (const std::string& line : align_tab_columns(lines))
      text += line + "\n";
  };
  block("Simple", estimate.simple);
  block("How it is worked out", estimate.steps);
  if (estimate.speeds.size() > 1U) {
    std::vector<TransferRow> speeds;
    for (const TransferSpeedRow& row : estimate.speeds)
      speeds.push_back({row.speed.name, rate_only(row.speed.bytes_per_second) + ": " + transfer_duration_text(row.seconds) +
                                            (row.lowest ? " (the lowest)" : "") +
                                            (row.speed.detail.empty() ? std::string() : ", " + row.speed.detail)});
    block("Speeds", speeds);
  }
  block(("Other amounts at " + rate_only(estimate.rate_bytes_per_second)).c_str(), estimate.other_sizes);
  if (!estimate.jumbo_note.empty())
    text += "  " + estimate.jumbo_note + "\n";
  block("Terms", estimate.terms);
  return text;
}

} // namespace support_assist
