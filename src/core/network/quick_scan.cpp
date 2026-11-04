// Quick scan's platform-neutral half: counting attempts, reading pktmon's real-time text and
// decoding an IP packet. The captures themselves are quick_scan_win.cpp and quick_scan_posix.cpp.

#include "support_assist/quick_scan.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>

namespace support_assist::quick_scan_detail {
namespace {

// Beyond this many distinct source sockets a flood is counted without the retransmission check.
constexpr std::size_t kMaxTracked = 100000;

bool all_digits(std::string_view text) {
  return !text.empty() && std::all_of(text.begin(), text.end(), [](char c) { return c >= '0' && c <= '9'; });
}

bool looks_like_ipv4(std::string_view text) {
  int parts = 0;
  std::size_t start = 0;
  while (start <= text.size()) {
    const std::size_t dot = text.find('.', start);
    const std::string_view part = text.substr(start, dot == std::string_view::npos ? text.size() - start : dot - start);
    if (!all_digits(part) || part.size() > 3 || std::stoi(std::string(part)) > 255)
      return false;
    ++parts;
    if (dot == std::string_view::npos)
      break;
    start = dot + 1;
  }
  return parts == 4;
}

bool looks_like_ipv6(std::string_view text) {
  if (text.find(':') == std::string_view::npos)
    return false;
  return std::all_of(text.begin(), text.end(), [](char c) {
    return std::isxdigit(static_cast<unsigned char>(c)) != 0 || c == ':' || c == '.' || c == '%';
  });
}

std::uint16_t read16(const std::uint8_t* data) {
  return static_cast<std::uint16_t>((static_cast<unsigned>(data[0]) << 8U) | data[1]);
}

std::string ipv4_text(const std::uint8_t* data) {
  char text[16] = {};
  std::snprintf(text, sizeof(text), "%u.%u.%u.%u", static_cast<unsigned>(data[0]), static_cast<unsigned>(data[1]),
                static_cast<unsigned>(data[2]), static_cast<unsigned>(data[3]));
  return text;
}

// RFC 5952: lower case, leading zeros dropped, the longest run of two or more zero groups as "::".
std::string ipv6_text(const std::uint8_t* data) {
  std::uint16_t groups[8] = {};
  for (int index = 0; index < 8; ++index)
    groups[index] = read16(data + index * 2);
  int best_start = -1;
  int best_length = 0;
  for (int index = 0; index < 8;) {
    if (groups[index] != 0) {
      ++index;
      continue;
    }
    int end = index;
    while (end < 8 && groups[end] == 0)
      ++end;
    if (end - index > best_length && end - index >= 2) {
      best_start = index;
      best_length = end - index;
    }
    index = end;
  }
  std::string text;
  char group[8] = {};
  for (int index = 0; index < 8; ++index) {
    if (index == best_start) {
      text += "::";
      index += best_length - 1;
      continue;
    }
    if (!text.empty() && text.back() != ':')
      text.push_back(':');
    std::snprintf(group, sizeof(group), "%x", static_cast<unsigned>(groups[index]));
    text += group;
  }
  return text;
}

} // namespace

bool AttemptCounter::add(const Packet& packet) {
  if (!packet.inbound || packet.destination_port != port_)
    return false;
  if (protocol_ == PortProtocol::tcp) {
    if (!packet.tcp || !packet.syn || packet.ack)
      return false;
  } else if (packet.tcp) {
    return false;
  }
  // A retransmitted SYN comes from the same source address and port: one attempt.
  if (seen_.size() < kMaxTracked && !seen_.insert({packet.source, packet.source_port}).second)
    return false;
  ++attempts_;
  const auto found = std::find_if(sources_.begin(), sources_.end(),
                                  [&](const QuickScanSource& source) { return source.address == packet.source; });
  if (found != sources_.end())
    ++found->attempts;
  else
    sources_.push_back({packet.source, 1});
  return true;
}

QuickScanCounts AttemptCounter::counts() const {
  QuickScanCounts result;
  result.attempts = attempts_;
  result.sources = sources_;
  std::stable_sort(result.sources.begin(), result.sources.end(), [](const QuickScanSource& left, const QuickScanSource& right) {
    return left.attempts != right.attempts ? left.attempts > right.attempts : left.address < right.address;
  });
  if (result.sources.size() > kQuickScanMaxSources) {
    result.sources.resize(kQuickScanMaxSources);
    result.more_sources = true;
  }
  if (seen_.size() >= kMaxTracked)
    result.note = "More than " + std::to_string(kMaxTracked) +
                  " sources were seen, so later retransmissions may count as attempts.";
  return result;
}

std::optional<std::pair<std::string, std::uint16_t>> split_address_port(std::string_view text) {
  while (!text.empty() && (text.back() == ':' || text.back() == ',' || text.back() == ' '))
    text.remove_suffix(1);
  const std::size_t dot = text.rfind('.');
  if (dot == std::string_view::npos || dot == 0)
    return std::nullopt;
  const std::string_view port = text.substr(dot + 1);
  const std::string_view address = text.substr(0, dot);
  if (!all_digits(port) || port.size() > 5)
    return std::nullopt;
  const int number = std::stoi(std::string(port));
  if (number > 65535)
    return std::nullopt;
  if (!looks_like_ipv4(address) && !looks_like_ipv6(address))
    return std::nullopt;
  return std::make_pair(std::string(address), static_cast<std::uint16_t>(number));
}

// A packet's next appearance at another component follows within microseconds; the same packet sent
// again (a SYN retransmitted) follows a second or more later.
constexpr std::int64_t kRepeatWindowNs = 50'000'000;

// The time of day a header carries ("00:34:11.474561800 PktGroupId ..."), in nanoseconds; -1 when
// it carries none.
static std::int64_t time_of_day_ns(std::string_view text) {
  const auto digit = [&](std::size_t at) { return at < text.size() && text[at] >= '0' && text[at] <= '9'; };
  for (std::size_t at = 0; at + 8 < text.size(); ++at) {
    if (!(digit(at) && digit(at + 1) && text[at + 2] == ':' && digit(at + 3) && digit(at + 4) &&
          text[at + 5] == ':' && digit(at + 6) && digit(at + 7) && text[at + 8] == '.'))
      continue;
    const auto two = [&](std::size_t from) {
      return static_cast<std::int64_t>((text[from] - '0') * 10 + (text[from + 1] - '0'));
    };
    std::int64_t nanos = (two(at) * 3600 + two(at + 3) * 60 + two(at + 6)) * 1'000'000'000LL;
    std::int64_t scale = 100'000'000LL;
    for (std::size_t index = at + 9; digit(index) && scale > 0; ++index, scale /= 10)
      nanos += static_cast<std::int64_t>(text[index] - '0') * scale;
    return nanos;
  }
  return -1;
}

std::optional<Packet> PktmonReader::line(std::string_view text) {
  // A header: "... PktGroupId 281474976710657, PktNumber 1, Appearance 1, Direction Rx , ...".
  if (const std::size_t group = text.find("PktGroupId "); group != std::string_view::npos) {
    time_ns_ = time_of_day_ns(text.substr(0, group));
    const auto number_after = [&](std::string_view label) {
      const std::size_t at = text.find(label);
      if (at == std::string_view::npos)
        return std::string();
      std::size_t end = at + label.size();
      while (end < text.size() && text[end] >= '0' && text[end] <= '9')
        ++end;
      return std::string(text.substr(at + label.size(), end - at - label.size()));
    };
    header_seen_ = true;
    key_ = number_after("PktGroupId ") + "/" + number_after("PktNumber ");
    const std::size_t direction = text.find("Direction ");
    inbound_ = direction == std::string_view::npos || text.substr(direction + 10, 2) != "Tx";
    return std::nullopt;
  }
  // The decoded packet: the first "address.port > address.port" pair on the line; a link-layer
  // "mac > mac" before it does not parse as addresses.
  std::size_t search = 0;
  while (true) {
    const std::size_t arrow = text.find(" > ", search);
    if (arrow == std::string_view::npos)
      return std::nullopt;
    search = arrow + 3;
    const std::size_t left_start = text.rfind(' ', arrow == 0 ? 0 : arrow - 1);
    const std::string_view left = text.substr(left_start == std::string_view::npos ? 0 : left_start + 1,
                                              arrow - (left_start == std::string_view::npos ? 0 : left_start + 1));
    const std::size_t right_end = text.find(": ", arrow + 3);
    if (right_end == std::string_view::npos)
      continue;
    const std::string_view right = text.substr(arrow + 3, right_end - arrow - 3);
    const auto source = split_address_port(left);
    const auto destination = split_address_port(right);
    if (!source || !destination)
      continue;
    Packet packet;
    packet.source = source->first;
    packet.source_port = source->second;
    packet.destination = destination->first;
    packet.destination_port = destination->second;
    packet.inbound = inbound_;
    const std::string_view rest = text.substr(right_end + 2);
    if (const std::size_t flags = rest.find("Flags ["); flags != std::string_view::npos) {
      const std::size_t close = rest.find(']', flags);
      const std::string_view set = rest.substr(flags + 7, close == std::string_view::npos ? 0 : close - flags - 7);
      packet.tcp = true;
      packet.syn = set.find('S') != std::string_view::npos;
      packet.ack = set.find('.') != std::string_view::npos;
    } else if (rest.find("UDP") == std::string_view::npos) {
      return std::nullopt; // neither TCP nor UDP
    }
    // One packet shows once per component it passes; count it once.
    if (header_seen_ && !key_.empty() && key_ != "/" && !seen_.insert(key_).second)
      return std::nullopt;
    if (seen_.size() > kMaxTracked)
      seen_.clear();
    // Where each appearance has its own PktGroupId, the same decoded packet within a moment is the
    // next component's view of it. Without a time, only the appearance just before can be one.
    std::string identity(text.substr(left_start == std::string_view::npos ? 0 : left_start + 1));
    identity += inbound_ ? "|in" : "|out";
    bool repeat = false;
    if (time_ns_ >= 0) {
      std::erase_if(recent_, [&](const auto& seen) {
        return time_ns_ < seen.second || time_ns_ - seen.second > kRepeatWindowNs;
      });
      repeat = std::any_of(recent_.begin(), recent_.end(), [&](const auto& seen) { return seen.first == identity; });
      if (!repeat)
        recent_.emplace_back(identity, time_ns_);
    } else {
      repeat = identity == last_identity_;
    }
    last_identity_ = std::move(identity);
    if (repeat)
      return std::nullopt;
    return packet;
  }
}

std::optional<Packet> parse_ip_packet(const std::uint8_t* data, std::size_t size) {
  if (data == nullptr || size < 1)
    return std::nullopt;
  Packet packet;
  std::size_t transport = 0;
  int protocol = 0;
  const int version = data[0] >> 4;
  if (version == 4) {
    const std::size_t header = static_cast<std::size_t>(data[0] & 0x0F) * 4U;
    if (header < 20 || size < header + 4)
      return std::nullopt;
    if ((read16(data + 6) & 0x1FFF) != 0)
      return std::nullopt; // a later fragment carries no ports
    protocol = data[9];
    packet.source = ipv4_text(data + 12);
    packet.destination = ipv4_text(data + 16);
    transport = header;
  } else if (version == 6) {
    if (size < 40)
      return std::nullopt;
    protocol = data[6];
    packet.source = ipv6_text(data + 8);
    packet.destination = ipv6_text(data + 24);
    transport = 40;
    // Hop-by-hop, routing and destination options headers before the transport header.
    while ((protocol == 0 || protocol == 43 || protocol == 60) && size >= transport + 8) {
      protocol = data[transport];
      transport += (static_cast<std::size_t>(data[transport + 1]) + 1U) * 8U;
    }
  } else {
    return std::nullopt;
  }
  if (protocol == 6) {
    if (size < transport + 14)
      return std::nullopt;
    packet.tcp = true;
    packet.syn = (data[transport + 13] & 0x02) != 0;
    packet.ack = (data[transport + 13] & 0x10) != 0;
  } else if (protocol == 17) {
    if (size < transport + 4)
      return std::nullopt;
  } else {
    return std::nullopt;
  }
  packet.source_port = read16(data + transport);
  packet.destination_port = read16(data + transport + 2);
  return packet;
}

} // namespace support_assist::quick_scan_detail
