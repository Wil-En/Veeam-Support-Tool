// Packet events: reads a .pcapng or .pcap record by record, takes TCP over IPv4 and IPv6 from the
// link layers captures use (Ethernet with VLAN tags, raw IP, BSD loopback, Linux cooked), and
// follows each TCP direction from its headers to name the events Wireshark's expert view flags.
// TLS records are read where one starts a segment, before the session turns encrypted.
#include "support_assist/packet_events.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/json.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <deque>
#include <fstream>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace support_assist {

namespace {

constexpr std::array<std::string_view, kPacketEventKinds> kKindKeys{
    "retransmission", "fast_retransmission", "spurious_retransmission", "out_of_order",
    "previous_segment_lost", "duplicate_ack", "keep_alive", "reset", "zero_window", "tls_handshake",
    "tls_alert"};

struct NamedCode {
  std::uint32_t code = 0;
  std::string name;
  std::string meaning;
};

struct EventData {
  std::int64_t copy_window_micros = 10000;
  std::int64_t out_of_order_micros = 3000;
  std::size_t shown_per_kind = 50;
  std::array<NamedCode, kPacketEventKinds> events{};
  std::vector<NamedCode> versions;
  std::vector<NamedCode> handshakes;
  std::vector<NamedCode> alerts;
  std::vector<NamedCode> suites;
};

// A code written as a number or as "0x...".
std::optional<std::uint32_t> code_of(const JsonValue& value) {
  const double number = value.as_number(-1.0);
  if (number >= 0.0)
    return static_cast<std::uint32_t>(number);
  const std::string text = value.as_string();
  if (text.size() < 3U || text[0] != '0' || (text[1] != 'x' && text[1] != 'X'))
    return std::nullopt;
  std::uint32_t code = 0;
  for (std::size_t index = 2; index < text.size(); ++index) {
    const char character = text[index];
    std::uint32_t digit = 0;
    if (character >= '0' && character <= '9')
      digit = static_cast<std::uint32_t>(character - '0');
    else if (character >= 'a' && character <= 'f')
      digit = static_cast<std::uint32_t>(character - 'a' + 10);
    else if (character >= 'A' && character <= 'F')
      digit = static_cast<std::uint32_t>(character - 'A' + 10);
    else
      return std::nullopt;
    code = code * 16U + digit;
  }
  return code;
}

std::vector<NamedCode> named_codes(const JsonValue& list) {
  std::vector<NamedCode> codes;
  for (const JsonValue& item : list.items()) {
    const auto code = code_of(item["code"]);
    if (code)
      codes.push_back({*code, item["name"].as_string(), item["meaning"].as_string()});
  }
  return codes;
}

EventData load_event_data(const JsonValue& value) {
  EventData data;
  data.copy_window_micros = static_cast<std::int64_t>(value["copy_window_ms"].as_number(10.0) * 1000.0);
  data.out_of_order_micros = static_cast<std::int64_t>(value["out_of_order_ms"].as_number(3.0) * 1000.0);
  data.shown_per_kind = static_cast<std::size_t>(std::max(1.0, value["events_shown_per_kind"].as_number(50.0)));
  for (std::size_t index = 0; index < kPacketEventKinds; ++index)
    data.events[index].name = std::string(kKindKeys[index]);
  for (const JsonValue& item : value["events"].items()) {
    const std::string key = item["kind"].as_string();
    for (std::size_t index = 0; index < kPacketEventKinds; ++index) {
      if (key == kKindKeys[index])
        data.events[index] = {0, item["name"].as_string(std::string(kKindKeys[index])), item["meaning"].as_string()};
    }
  }
  data.versions = named_codes(value["tls_versions"]);
  data.handshakes = named_codes(value["tls_handshake_types"]);
  data.alerts = named_codes(value["tls_alerts"]);
  data.suites = named_codes(value["tls_cipher_suites"]);
  return data;
}

const EventData& event_data() {
  static const EventData data = load_event_data(data_file("packet-events.json"));
  return data;
}

const NamedCode* find_code(const std::vector<NamedCode>& codes, std::uint32_t code) {
  for (const NamedCode& entry : codes) {
    if (entry.code == code)
      return &entry;
  }
  return nullptr;
}

std::string hex4(std::uint32_t value) {
  char buffer[12];
  std::snprintf(buffer, sizeof(buffer), "0x%04X", static_cast<unsigned int>(value));
  return buffer;
}

std::string with_thousands(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (std::size_t position = digits.size(); position > 3U; position -= 3U)
    digits.insert(position - 3U, ",");
  return digits;
}

std::uint16_t be16(const std::uint8_t* bytes) {
  return static_cast<std::uint16_t>((bytes[0] << 8) | bytes[1]);
}

std::uint32_t be24(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 16) | (static_cast<std::uint32_t>(bytes[1]) << 8) | bytes[2];
}

std::uint32_t be32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) | bytes[3];
}

std::uint32_t le32(const std::uint8_t* bytes) {
  return (static_cast<std::uint32_t>(bytes[3]) << 24) | (static_cast<std::uint32_t>(bytes[2]) << 16) |
         (static_cast<std::uint32_t>(bytes[1]) << 8) | bytes[0];
}

// ------------------------------------------------------------------------------------- reading

struct Record {
  std::int64_t time_micros = 0;
  std::uint32_t link_type = 0;
  const std::uint8_t* data = nullptr;
  std::size_t captured = 0;
};

struct Interface {
  std::uint32_t link_type = 0;
  bool base2 = false;
  std::uint8_t exponent = 6;
  std::int64_t offset_seconds = 0;
};

constexpr std::uint32_t kMaxBlock = 64U * 1024U * 1024U;

class CaptureReader {
public:
  explicit CaptureReader(std::istream& input) : input_(input) {}

  // Reads the file's first bytes; false when it is neither format.
  bool open() {
    if (!read(first_, 4))
      return false;
    if (first_[0] == 0x0A && first_[1] == 0x0D && first_[2] == 0x0D && first_[3] == 0x0A) {
      pcapng_ = true;
      first_pending_ = true;
      return true;
    }
    const std::uint32_t magic_le = le32(first_);
    const std::uint32_t magic_be = be32(first_);
    if (magic_le == 0xA1B2C3D4U || magic_le == 0xA1B23C4DU) {
      little_ = true;
      nanoseconds_ = magic_le == 0xA1B23C4DU;
    } else if (magic_be == 0xA1B2C3D4U || magic_be == 0xA1B23C4DU) {
      little_ = false;
      nanoseconds_ = magic_be == 0xA1B23C4DU;
    } else {
      return false;
    }
    std::uint8_t header[20];
    if (!read(header, sizeof(header)))
      return false;
    pcap_link_ = u32(header + 16) & 0xFFFFU;
    return true;
  }

  bool next(Record& record) { return pcapng_ ? next_pcapng(record) : next_pcap(record); }

  std::string warning;

private:
  bool read(void* destination, std::size_t count) {
    input_.read(static_cast<char*>(destination), static_cast<std::streamsize>(count));
    if (static_cast<std::size_t>(input_.gcount()) != count)
      return false;
    offset_ += count;
    return true;
  }

  std::uint16_t u16(const std::uint8_t* bytes) const {
    return little_ ? static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8)) : be16(bytes);
  }
  std::uint32_t u32(const std::uint8_t* bytes) const { return little_ ? le32(bytes) : be32(bytes); }

  void damaged(std::uint64_t at) {
    warning = "The capture ends early: the block at byte " + with_thousands(at) +
              " is damaged or unfinished. The events up to it are listed.";
  }

  std::int64_t to_micros(const Interface& face, std::uint64_t stamp) const {
    static constexpr std::uint64_t kPowers[] = {1ULL,
                                                10ULL,
                                                100ULL,
                                                1000ULL,
                                                10000ULL,
                                                100000ULL,
                                                1000000ULL,
                                                10000000ULL,
                                                100000000ULL,
                                                1000000000ULL,
                                                10000000000ULL,
                                                100000000000ULL,
                                                1000000000000ULL,
                                                10000000000000ULL,
                                                100000000000000ULL,
                                                1000000000000000ULL,
                                                10000000000000000ULL,
                                                100000000000000000ULL,
                                                1000000000000000000ULL,
                                                10000000000000000000ULL};
    std::int64_t micros = 0;
    if (face.base2) {
      const long double seconds = static_cast<long double>(stamp) / static_cast<long double>(1ULL << std::min<int>(face.exponent, 63));
      micros = static_cast<std::int64_t>(seconds * 1000000.0L);
    } else if (face.exponent >= 6) {
      micros = static_cast<std::int64_t>(stamp / kPowers[std::min<int>(face.exponent - 6, 19)]);
    } else {
      micros = static_cast<std::int64_t>(stamp * kPowers[6 - face.exponent]);
    }
    return micros + face.offset_seconds * 1000000;
  }

  bool next_pcap(Record& record) {
    std::uint8_t header[16];
    const std::uint64_t at = offset_;
    if (!read(header, 1)) // a clean end
      return false;
    if (!read(header + 1, sizeof(header) - 1)) {
      damaged(at);
      return false;
    }
    const std::uint32_t seconds = u32(header);
    const std::uint32_t fraction = u32(header + 4);
    const std::uint32_t captured = u32(header + 8);
    if (captured > kMaxBlock) {
      damaged(at);
      return false;
    }
    buffer_.resize(captured);
    if (captured != 0U && !read(buffer_.data(), captured)) {
      damaged(at);
      return false;
    }
    record.time_micros = static_cast<std::int64_t>(seconds) * 1000000 +
                         static_cast<std::int64_t>(nanoseconds_ ? fraction / 1000U : fraction);
    record.link_type = pcap_link_;
    record.data = buffer_.data();
    record.captured = captured;
    return true;
  }

  bool next_pcapng(Record& record) {
    for (;;) {
      const std::uint64_t at = offset_ - (first_pending_ ? 4U : 0U);
      std::uint8_t type_bytes[4];
      if (first_pending_) {
        std::memcpy(type_bytes, first_, 4);
        first_pending_ = false;
      } else if (!read(type_bytes, 1)) {
        return false; // a clean end
      } else if (!read(type_bytes + 1, 3)) {
        damaged(at);
        return false;
      }
      std::uint8_t length_bytes[4];
      if (!read(length_bytes, 4)) {
        damaged(at);
        return false;
      }
      std::uint32_t length = 0;
      std::size_t consumed = 8;
      if (type_bytes[0] == 0x0A && type_bytes[1] == 0x0D && type_bytes[2] == 0x0D && type_bytes[3] == 0x0A) {
        std::uint8_t magic[4];
        if (!read(magic, 4)) {
          damaged(at);
          return false;
        }
        consumed = 12;
        if (le32(magic) == 0x1A2B3C4DU)
          little_ = true;
        else if (be32(magic) == 0x1A2B3C4DU)
          little_ = false;
        else {
          damaged(at);
          return false;
        }
        section_ = true;
        interfaces_.clear();
      } else if (!section_) {
        damaged(at);
        return false;
      }
      const std::uint32_t type = u32(type_bytes);
      length = u32(length_bytes);
      if (length < consumed + 4U || length % 4U != 0U || length > kMaxBlock) {
        damaged(at);
        return false;
      }
      const std::size_t body = length - consumed; // the trailing length included
      buffer_.resize(body);
      if (!read(buffer_.data(), body)) {
        damaged(at);
        return false;
      }
      const std::size_t content = body - 4U;
      const std::uint8_t* data = buffer_.data();
      if (type == 0x0A0D0D0AU) {
        continue;
      }
      if (type == 1U) { // Interface Description Block
        if (content < 8U) {
          damaged(at);
          return false;
        }
        Interface face;
        face.link_type = u16(data);
        std::size_t option = 8;
        while (option + 4U <= content) {
          const std::uint16_t code = u16(data + option);
          const std::uint16_t size = u16(data + option + 2);
          if (code == 0U || option + 4U + size > content)
            break;
          if (code == 9U && size >= 1U) {
            face.base2 = (data[option + 4] & 0x80U) != 0U;
            face.exponent = static_cast<std::uint8_t>(data[option + 4] & 0x7FU);
          } else if (code == 14U && size >= 8U) {
            const std::uint64_t high = u32(data + option + 4 + (little_ ? 4 : 0));
            const std::uint64_t low = u32(data + option + 4 + (little_ ? 0 : 4));
            face.offset_seconds = static_cast<std::int64_t>((high << 32) | low);
          }
          option += 4U + ((size + 3U) & ~3U);
        }
        interfaces_.push_back(face);
        continue;
      }
      if (type == 6U || type == 2U) { // Enhanced Packet Block, obsolete Packet Block
        if (content < 20U) {
          damaged(at);
          return false;
        }
        const std::uint32_t face_id = type == 6U ? u32(data) : u16(data);
        const std::uint64_t stamp = (static_cast<std::uint64_t>(u32(data + 4)) << 32) | u32(data + 8);
        const std::uint32_t captured = u32(data + 12);
        if (20U + static_cast<std::size_t>(captured) > content) {
          damaged(at);
          return false;
        }
        if (face_id >= interfaces_.size())
          continue;
        const Interface& face = interfaces_[face_id];
        record.time_micros = to_micros(face, stamp);
        last_time_ = record.time_micros;
        record.link_type = face.link_type;
        record.data = data + 20;
        record.captured = captured;
        return true;
      }
      if (type == 3U) { // Simple Packet Block: interface 0, no time
        if (content < 4U || interfaces_.empty())
          continue;
        const std::uint32_t original = u32(data);
        record.time_micros = last_time_;
        record.link_type = interfaces_[0].link_type;
        record.data = data + 4;
        record.captured = std::min<std::size_t>(original, content - 4U);
        return true;
      }
    }
  }

  std::istream& input_;
  std::uint64_t offset_ = 0;
  std::uint8_t first_[4]{};
  bool first_pending_ = false;
  bool pcapng_ = false;
  bool section_ = false;
  bool little_ = true;
  bool nanoseconds_ = false;
  std::uint32_t pcap_link_ = 0;
  std::int64_t last_time_ = 0;
  std::vector<Interface> interfaces_;
  std::vector<std::uint8_t> buffer_;
};

// ------------------------------------------------------------------------------------- packets

struct TcpPacket {
  bool v6 = false;
  std::array<std::uint8_t, 16> source{};
  std::array<std::uint8_t, 16> destination{};
  std::uint16_t source_port = 0;
  std::uint16_t destination_port = 0;
  std::uint32_t seq = 0;
  std::uint32_t ack = 0;
  std::uint8_t flags = 0;
  std::uint16_t window = 0;
  std::uint32_t payload_length = 0;
  const std::uint8_t* payload = nullptr;
  std::size_t payload_captured = 0;
};

constexpr std::uint8_t kFin = 0x01;
constexpr std::uint8_t kSyn = 0x02;
constexpr std::uint8_t kRst = 0x04;
constexpr std::uint8_t kAck = 0x10;

enum class PacketShape { tcp, other };

struct Fnv {
  std::uint64_t value = 1469598103934665603ULL;
  void add(const std::uint8_t* bytes, std::size_t count) {
    for (std::size_t index = 0; index < count; ++index) {
      value ^= bytes[index];
      value *= 1099511628211ULL;
    }
  }
  void add_value(std::uint64_t number) {
    std::uint8_t bytes[8];
    for (int index = 0; index < 8; ++index)
      bytes[index] = static_cast<std::uint8_t>(number >> (index * 8));
    add(bytes, 8);
  }
};

// Finds the IP header behind the record's link layer: its offset and version (4 or 6, 0 when none).
std::pair<std::size_t, int> network_layer(const Record& record) {
  const std::uint8_t* data = record.data;
  const std::size_t size = record.captured;
  auto by_ethertype = [](std::uint16_t type) { return type == 0x0800U ? 4 : type == 0x86DDU ? 6 : 0; };
  switch (record.link_type) {
  case 1: { // Ethernet
    if (size < 14U)
      return {0, 0};
    std::size_t offset = 12;
    std::uint16_t type = be16(data + offset);
    while ((type == 0x8100U || type == 0x88A8U || type == 0x9100U) && size >= offset + 6U) {
      offset += 4;
      type = be16(data + offset);
    }
    return {offset + 2, by_ethertype(type)};
  }
  case 101: // raw IP
    if (size < 1U)
      return {0, 0};
    return {0, (data[0] >> 4) == 4 ? 4 : (data[0] >> 4) == 6 ? 6 : 0};
  case 228:
    return {0, 4};
  case 229:
    return {0, 6};
  case 0:     // BSD loopback, the family in the capturing machine's order
  case 108: { // OpenBSD loopback, network order
    if (size < 4U)
      return {0, 0};
    const std::uint32_t family = record.link_type == 108U ? be32(data) : std::min(le32(data), be32(data));
    return {4, family == 2U ? 4 : (family == 24U || family == 28U || family == 30U) ? 6 : 0};
  }
  case 113: // Linux cooked
    if (size < 16U)
      return {0, 0};
    return {16, by_ethertype(be16(data + 14))};
  case 276: // Linux cooked v2
    if (size < 20U)
      return {0, 0};
    return {20, by_ethertype(be16(data))};
  default:
    return {0, 0};
  }
}

// Parses one record. The hash identifies the packet for the copy check: addresses, IPv4 ID and the
// transport bytes, leaving out the TTL and the checksums, which differ between components.
PacketShape parse_packet(const Record& record, TcpPacket& tcp, std::uint64_t& hash, bool& hashed) {
  hashed = false;
  const auto [net, version] = network_layer(record);
  if (version == 0)
    return PacketShape::other;
  const std::uint8_t* data = record.data;
  const std::size_t size = record.captured;
  Fnv fnv;
  std::size_t transport = 0;
  std::uint32_t transport_length = 0;
  std::uint8_t protocol = 0;
  if (version == 4) {
    if (size < net + 20U || (data[net] >> 4) != 4)
      return PacketShape::other;
    const std::size_t header = static_cast<std::size_t>(data[net] & 0x0FU) * 4U;
    if (header < 20U || size < net + header)
      return PacketShape::other;
    const std::uint16_t total = be16(data + net + 2);
    if ((be16(data + net + 6) & 0x1FFFU) != 0U) // a later fragment
      return PacketShape::other;
    protocol = data[net + 9];
    // A large send carries total length 0 above the adapter; the captured length is the packet then.
    const std::size_t length = total != 0U ? total : size - net;
    if (length < header)
      return PacketShape::other;
    transport = net + header;
    transport_length = static_cast<std::uint32_t>(length - header);
    tcp.v6 = false;
    tcp.source.fill(0);
    tcp.destination.fill(0);
    std::memcpy(tcp.source.data(), data + net + 12, 4);
    std::memcpy(tcp.destination.data(), data + net + 16, 4);
    fnv.add_value(4);
    fnv.add(data + net + 12, 8);
    fnv.add(data + net + 4, 2); // identification
  } else {
    if (size < net + 40U || (data[net] >> 4) != 6)
      return PacketShape::other;
    const std::uint16_t payload = be16(data + net + 4);
    std::uint8_t next = data[net + 6];
    std::size_t position = net + 40;
    std::size_t length = payload != 0U ? payload : size - net - 40U;
    while (next == 0U || next == 43U || next == 60U || next == 51U || next == 44U) {
      if (size < position + 8U)
        return PacketShape::other;
      std::size_t extension = 8;
      if (next == 44U) {
        if ((be16(data + position + 2) >> 3) != 0U)
          return PacketShape::other;
      } else if (next == 51U) {
        extension = (static_cast<std::size_t>(data[position + 1]) + 2U) * 4U;
      } else {
        extension = (static_cast<std::size_t>(data[position + 1]) + 1U) * 8U;
      }
      if (length < extension)
        return PacketShape::other;
      next = data[position];
      position += extension;
      length -= extension;
    }
    protocol = next;
    transport = position;
    transport_length = static_cast<std::uint32_t>(length);
    tcp.v6 = true;
    std::memcpy(tcp.source.data(), data + net + 8, 16);
    std::memcpy(tcp.destination.data(), data + net + 24, 16);
    fnv.add_value(6);
    fnv.add(data + net + 8, 32);
  }
  fnv.add_value(protocol);
  fnv.add_value(transport_length);
  // The transport bytes, at most the header and 256 bytes after it, without the checksum.
  const std::size_t available = size > transport ? size - transport : 0U;
  const bool has_checksum = protocol == 6U || protocol == 17U;
  const std::size_t checksum = protocol == 6U ? 16U : 6U;
  const std::size_t hashed_bytes = std::min<std::size_t>(available, 60U + 256U);
  for (std::size_t index = 0; index < hashed_bytes; ++index) {
    if (has_checksum && (index == checksum || index == checksum + 1U))
      continue;
    fnv.add(data + transport + index, 1);
  }
  hash = fnv.value;
  hashed = true;
  if (protocol != 6U || available < 20U)
    return PacketShape::other;
  const std::uint8_t* header = data + transport;
  const std::size_t header_length = static_cast<std::size_t>(header[12] >> 4) * 4U;
  if (header_length < 20U)
    return PacketShape::other;
  tcp.source_port = be16(header);
  tcp.destination_port = be16(header + 2);
  tcp.seq = be32(header + 4);
  tcp.ack = be32(header + 8);
  tcp.flags = header[13];
  tcp.window = be16(header + 14);
  tcp.payload_length = transport_length > header_length ? static_cast<std::uint32_t>(transport_length - header_length) : 0U;
  tcp.payload = data + transport + header_length;
  tcp.payload_captured = available > header_length ? std::min<std::size_t>(tcp.payload_length, available - header_length) : 0U;
  return PacketShape::tcp;
}

// The hash of a frame that parse_packet does not take as IP (ARP, LLDP, a damaged header): pktmon
// logs such a frame unchanged at each component, so its leading bytes identify it.
std::uint64_t frame_hash(const Record& record) {
  Fnv fnv;
  fnv.add_value(0);
  fnv.add_value(record.captured);
  fnv.add(record.data, std::min<std::size_t>(record.captured, 60U + 256U));
  return fnv.value;
}

std::string address_text(const TcpPacket& packet, bool source) {
  const auto& bytes = source ? packet.source : packet.destination;
  const std::uint16_t port = source ? packet.source_port : packet.destination_port;
  char buffer[64];
  if (!packet.v6) {
    std::snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u:%u", static_cast<unsigned int>(bytes[0]),
                  static_cast<unsigned int>(bytes[1]), static_cast<unsigned int>(bytes[2]),
                  static_cast<unsigned int>(bytes[3]), static_cast<unsigned int>(port));
    return buffer;
  }
  std::uint16_t groups[8];
  for (int index = 0; index < 8; ++index)
    groups[index] = be16(bytes.data() + index * 2);
  int best_start = -1;
  int best_length = 0;
  for (int index = 0; index < 8;) {
    if (groups[index] != 0U) {
      ++index;
      continue;
    }
    int end = index;
    while (end < 8 && groups[end] == 0U)
      ++end;
    if (end - index > best_length && end - index >= 2) {
      best_start = index;
      best_length = end - index;
    }
    index = end;
  }
  std::string text = "[";
  for (int index = 0; index < 8; ++index) {
    if (index == best_start) {
      text += "::";
      index += best_length - 1;
      continue;
    }
    if (!text.empty() && text.back() != '[' && text.back() != ':')
      text += ':';
    std::snprintf(buffer, sizeof(buffer), "%x", static_cast<unsigned int>(groups[index]));
    text += buffer;
  }
  text += "]:" + std::to_string(port);
  return text;
}

bool seq_lt(std::uint32_t left, std::uint32_t right) {
  return static_cast<std::int32_t>(left - right) < 0;
}
bool seq_gt(std::uint32_t left, std::uint32_t right) {
  return static_cast<std::int32_t>(left - right) > 0;
}
bool seq_le(std::uint32_t left, std::uint32_t right) {
  return !seq_gt(left, right);
}

// ------------------------------------------------------------------------------------- analysis

constexpr std::size_t kNoGroup = static_cast<std::size_t>(-1);

struct Direction {
  bool seen = false;
  std::uint32_t initial_seq = 0;
  bool syn_seen = false;
  std::uint32_t next_seq = 0;
  std::int64_t next_seq_time = 0;
  bool ack_known = false;
  std::uint32_t last_ack = 0;
  std::uint16_t last_window = 0;
  std::uint32_t duplicate_acks = 0;
  bool tls_encrypted = false;
  bool keep_alive_sent = false; // this side's last packet was a keep-alive
  std::size_t keep_alive_group = kNoGroup; // the entry in the analyzer's keep-alive groups
  std::deque<std::pair<std::uint32_t, std::uint32_t>> recent; // (seq, length) of data sent
};

struct Connection {
  std::array<Direction, 2> sides{};
  bool keep_alive_counted = false; // a keep-alive was seen on this connection
};

// The keep-alives one connection direction sent, listed as a single event row.
struct KeepAliveGroup {
  std::size_t row = kNoGroup; // the row in the report's events, none when the list limit was reached
  std::uint64_t count = 0;
  std::int64_t first = 0;
  std::int64_t last = 0;
};

class Analyzer {
public:
  explicit Analyzer(PacketEventReport& report) : report_(report), data_(event_data()) {}

  void packet(std::int64_t time, const TcpPacket& packet) {
    // The connection, keyed by its two ends in a fixed order; the side is the sender's.
    const std::size_t address_size = packet.v6 ? 16U : 4U;
    std::string source(reinterpret_cast<const char*>(packet.source.data()), address_size);
    source += static_cast<char>(packet.source_port >> 8);
    source += static_cast<char>(packet.source_port & 0xFF);
    std::string destination(reinterpret_cast<const char*>(packet.destination.data()), address_size);
    destination += static_cast<char>(packet.destination_port >> 8);
    destination += static_cast<char>(packet.destination_port & 0xFF);
    const bool first = source < destination;
    const std::string key = (packet.v6 ? "6" : "4") + (first ? source + destination : destination + source);
    auto found = connections_.find(key);
    if (found == connections_.end()) {
      found = connections_.emplace(key, Connection{}).first;
      ++report_.connections;
    }
    Connection& connection = found->second;
    Direction& side = connection.sides[first ? 0U : 1U];
    Direction& other = connection.sides[first ? 1U : 0U];
    const std::string label = address_text(packet, true) + " -> " + address_text(packet, false);

    const bool syn = (packet.flags & kSyn) != 0U;
    const bool fin = (packet.flags & kFin) != 0U;
    const bool rst = (packet.flags & kRst) != 0U;
    const bool has_ack = (packet.flags & kAck) != 0U;
    const std::uint32_t length = packet.payload_length + (syn ? 1U : 0U) + (fin ? 1U : 0U);

    // A new SYN on the same ends is a new connection; the same SYN again is a retransmission.
    if (syn && side.syn_seen && packet.seq == side.initial_seq) {
      emit(PacketEventKind::retransmission, time, label,
           std::string(has_ack ? "SYN/ACK" : "SYN") + " sent again: no answer to the first one");
      remember_ack(side, packet, has_ack);
      return;
    }
    if (syn) {
      if (!has_ack && side.seen) {
        connection = Connection{};
        ++report_.connections;
      } else if (has_ack) {
        side = Direction{};
      }
      Direction& fresh = connection.sides[first ? 0U : 1U];
      fresh.seen = true;
      fresh.syn_seen = true;
      fresh.initial_seq = packet.seq;
      fresh.next_seq = packet.seq + length;
      fresh.next_seq_time = time;
      remember_ack(fresh, packet, has_ack);
      return;
    }

    if (rst)
      emit(PacketEventKind::reset, time, label, "Connection reset by " + address_text(packet, true));
    if (packet.window == 0U && !fin && !rst)
      emit(PacketEventKind::zero_window, time, label, "Window 0 at seq " + std::to_string(packet.seq));

    bool keep_alive = false;
    bool covered = false; // the segment starts inside data this side sent before
    if (!side.seen) {
      side.seen = true;
      side.next_seq = packet.seq + length;
      side.next_seq_time = time;
    } else if (length <= 1U && !fin && !rst && packet.seq == side.next_seq - 1U) {
      keep_alive = true;
      note_keep_alive(time, label, connection, side);
    } else if (length > 0U) {
      // Only a segment with data or a FIN reaches this branch (a SYN is handled above). An ACK with
      // neither has length 0 and is never a retransmission, out-of-order or missing-segment event.
      if (seq_gt(packet.seq, side.next_seq)) {
        emit(PacketEventKind::previous_segment_lost, time, label,
             with_thousands(packet.seq - side.next_seq) + " bytes missing before seq " + std::to_string(packet.seq));
      } else if (seq_lt(packet.seq, side.next_seq)) {
        const bool seen_before = std::any_of(side.recent.begin(), side.recent.end(), [&](const auto& sent) {
          return sent.first == packet.seq;
        });
        const bool out_of_order = !seen_before && time - side.next_seq_time <= data_.out_of_order_micros;
        const std::string detail = segment_detail(packet, fin, !out_of_order);
        if (out_of_order) {
          emit(PacketEventKind::out_of_order, time, label, detail);
        } else {
          // Data the capture never saw sent the first time reaches the TLS reader below.
          covered = std::any_of(side.recent.begin(), side.recent.end(), [&](const auto& sent) {
            return !seq_lt(packet.seq, sent.first) && seq_lt(packet.seq, sent.first + sent.second);
          });
          if (other.ack_known && seq_le(packet.seq + length, other.last_ack))
            emit(PacketEventKind::spurious_retransmission, time, label, detail + ", already acknowledged");
          else if (other.duplicate_acks >= 2U && other.last_ack == packet.seq)
            emit(PacketEventKind::fast_retransmission, time, label,
                 detail + ", after " + std::to_string(other.duplicate_acks) + " duplicate ACKs");
          else
            emit(PacketEventKind::retransmission, time, label, detail);
        }
      }
    }
    if (length > 0U && !keep_alive) {
      if (seq_gt(packet.seq + length, side.next_seq)) {
        side.next_seq = packet.seq + length;
        side.next_seq_time = time;
      }
      side.recent.emplace_back(packet.seq, length);
      if (side.recent.size() > 256U)
        side.recent.pop_front();
    }

    // A duplicate ACK: no data, the same acknowledgement and window as the last one this side sent.
    // The answer to the other side's keep-alive is a keep-alive ACK, not a duplicate.
    if (has_ack && length == 0U && !rst && !keep_alive && side.ack_known && packet.ack == side.last_ack &&
        packet.window == side.last_window && packet.window != 0U && !other.keep_alive_sent) {
      ++side.duplicate_acks;
      emit(PacketEventKind::duplicate_ack, time, label,
           "#" + std::to_string(side.duplicate_acks) + " for ack " + std::to_string(packet.ack));
    } else {
      remember_ack(side, packet, has_ack);
    }
    side.keep_alive_sent = keep_alive;

    if (packet.payload_captured >= 5U && !covered && !keep_alive)
      tls(time, label, packet, side, other);
  }

  // Writes each keep-alive row's text, then puts the rows in time order. A keep-alive row sits at the
  // time of the first probe.
  void finish() {
    for (const KeepAliveGroup& group : keep_alive_groups_) {
      if (group.row != kNoGroup)
        report_.events[group.row].detail = keep_alive_text(group);
    }
    std::stable_sort(report_.events.begin(), report_.events.end(),
                     [](const PacketEvent& left, const PacketEvent& right) { return left.time_micros < right.time_micros; });
  }

private:
  // "seq 1101, 100 bytes". A segment that carries only a FIN names it: "seq 5000, FIN sent again".
  static std::string segment_detail(const TcpPacket& packet, bool fin, bool again) {
    std::string text = "seq " + std::to_string(packet.seq);
    if (packet.payload_length != 0U) {
      text += ", " + with_thousands(packet.payload_length) + " bytes";
      if (fin)
        text += ", with FIN";
    } else if (fin) {
      text += again ? ", FIN sent again" : ", FIN";
    }
    return text;
  }

  // The keep-alives of one connection direction are counted in full and listed as one row, placed at
  // the first probe.
  void note_keep_alive(std::int64_t time, const std::string& label, Connection& connection, Direction& side) {
    const auto index = static_cast<std::size_t>(PacketEventKind::keep_alive);
    ++report_.counts[index];
    if (!connection.keep_alive_counted) {
      connection.keep_alive_counted = true;
      ++report_.keep_alive_connections;
    }
    if (side.keep_alive_group == kNoGroup) {
      KeepAliveGroup fresh;
      fresh.first = time;
      if (shown_[index] < data_.shown_per_kind) {
        ++shown_[index];
        fresh.row = report_.events.size();
        report_.events.push_back({time, PacketEventKind::keep_alive, label, std::string()});
      }
      side.keep_alive_group = keep_alive_groups_.size();
      keep_alive_groups_.push_back(fresh);
      ++report_.keep_alive_groups;
    }
    KeepAliveGroup& group = keep_alive_groups_[side.keep_alive_group];
    ++group.count;
    group.last = time;
  }

  // "24 keep-alives from 17:04:22.170 to 17:05:12.584", with the date when the run crosses midnight.
  static std::string keep_alive_text(const KeepAliveGroup& group) {
    const std::string first = packet_event_time(group.first);
    const std::string last = packet_event_time(group.last);
    const bool same_day = first.compare(0, 10, last, 0, 10) == 0;
    const std::string from = same_day ? first.substr(11) : first;
    const std::string to = same_day ? last.substr(11) : last;
    if (group.count == 1U)
      return "1 keep-alive at " + from;
    return with_thousands(group.count) + " keep-alives from " + from + " to " + to;
  }

  static void remember_ack(Direction& side, const TcpPacket& packet, bool has_ack) {
    if (!has_ack)
      return;
    if (!side.ack_known || packet.ack != side.last_ack)
      side.duplicate_acks = 0;
    side.ack_known = true;
    side.last_ack = packet.ack;
    side.last_window = packet.window;
  }

  void emit(PacketEventKind kind, std::int64_t time, const std::string& connection, std::string detail) {
    const auto index = static_cast<std::size_t>(kind);
    ++report_.counts[index];
    if (shown_[index] >= data_.shown_per_kind)
      return;
    ++shown_[index];
    report_.events.push_back({time, kind, connection, std::move(detail)});
  }

  std::string version_name(std::uint32_t code) const {
    const NamedCode* entry = find_code(data_.versions, code);
    return entry != nullptr ? entry->name : hex4(code);
  }

  // The handshake message's line: its name, and for the hellos the version, server name and suite.
  std::string hello_detail(std::uint8_t type, const std::uint8_t* body, std::size_t size, bool& tls13) const {
    tls13 = false;
    std::size_t at = 0;
    auto need = [&](std::size_t count) { return at + count <= size; };
    if (!need(2 + 32 + 1))
      return {};
    const std::uint32_t legacy = be16(body);
    at = 34;
    const std::size_t session = body[at];
    at += 1 + session;
    std::string text;
    if (type == 1U) {
      if (!need(2))
        return {};
      const std::size_t suites = be16(body + at);
      at += 2 + suites;
      if (!need(1))
        return {};
      at += 1 + body[at];
      std::uint32_t highest = legacy;
      std::string server_name;
      if (need(2)) {
        const std::size_t end = std::min(size, at + 2 + be16(body + at));
        at += 2;
        while (at + 4 <= end) {
          const std::uint16_t extension = be16(body + at);
          const std::size_t length = be16(body + at + 2);
          const std::size_t start = at + 4;
          if (start + length > end)
            break;
          if (extension == 0U && length >= 5U) {
            const std::size_t name_length = be16(body + start + 3);
            if (body[start + 2] == 0U && start + 5 + name_length <= start + length)
              server_name.assign(reinterpret_cast<const char*>(body + start + 5), name_length);
          } else if (extension == 43U && length >= 1U) {
            for (std::size_t offered = start + 1; offered + 2 <= start + 1 + body[start] && offered + 2 <= start + length;
                 offered += 2) {
              const std::uint32_t version = be16(body + offered);
              if ((version & 0x0F0FU) == 0x0A0AU) // GREASE
                continue;
              if (version > highest && version <= 0x0304U)
                highest = version;
            }
          }
          at = start + length;
        }
      }
      text = "offers up to " + version_name(highest) + ", " + std::to_string(suites / 2) + " cipher suites";
      if (!server_name.empty())
        text += ", server name " + server_name;
      return text;
    }
    // Server Hello
    if (!need(3))
      return {};
    const std::uint32_t suite = be16(body + at);
    at += 3;
    std::uint32_t chosen = legacy;
    if (need(2)) {
      const std::size_t end = std::min(size, at + 2 + be16(body + at));
      at += 2;
      while (at + 4 <= end) {
        const std::uint16_t extension = be16(body + at);
        const std::size_t length = be16(body + at + 2);
        if (at + 4 + length > end)
          break;
        if (extension == 43U && length == 2U)
          chosen = be16(body + at + 4);
        at += 4 + length;
      }
    }
    tls13 = chosen == 0x0304U;
    const NamedCode* named = find_code(data_.suites, suite);
    return version_name(chosen) + ", " + (named != nullptr ? named->name : "cipher suite " + hex4(suite));
  }

  void tls(std::int64_t time, const std::string& label, const TcpPacket& packet, Direction& side, Direction& other) {
    const std::uint8_t* bytes = packet.payload;
    const std::size_t size = packet.payload_captured;
    auto record_at = [&](std::size_t at) {
      return at + 5U <= size && bytes[at] >= 20U && bytes[at] <= 23U && bytes[at + 1] == 3U && bytes[at + 2] <= 4U &&
             be16(bytes + at + 3) <= 18432U;
    };
    std::size_t at = 0;
    while (record_at(at)) {
      const std::uint8_t type = bytes[at];
      const std::size_t length = be16(bytes + at + 3);
      const std::uint8_t* body = bytes + at + 5;
      const std::size_t available = std::min(length, size - at - 5U);
      if (type == 20U) {
        emit(PacketEventKind::tls_handshake, time, label, "Change Cipher Spec");
        side.tls_encrypted = true;
      } else if (type == 21U) {
        if (!side.tls_encrypted && length == 2U && available == 2U) {
          const NamedCode* alert = find_code(data_.alerts, body[1]);
          std::string text = std::string(body[0] == 2U ? "Fatal: " : "Warning: ") +
                             (alert != nullptr ? alert->name : "alert") + " (" + std::to_string(body[1]) + ")";
          if (alert != nullptr && !alert->meaning.empty())
            text += ". " + alert->meaning;
          emit(PacketEventKind::tls_alert, time, label, text);
        } else {
          emit(PacketEventKind::tls_alert, time, label, "Encrypted alert; at the end of a session it is usually close_notify");
        }
      } else if (type == 22U) {
        if (side.tls_encrypted) {
          emit(PacketEventKind::tls_handshake, time, label, "Encrypted handshake message");
        } else {
          std::size_t message = 0;
          while (message + 4U <= available) {
            const std::uint8_t kind = body[message];
            const NamedCode* named = find_code(data_.handshakes, kind);
            if (named == nullptr)
              break;
            const std::size_t message_length = be24(body + message + 1);
            const std::size_t present = std::min(message_length, available - message - 4U);
            std::string text = named->name;
            if (kind == 1U || kind == 2U) {
              bool tls13 = false;
              const std::string detail = hello_detail(kind, body + message + 4, present, tls13);
              if (!detail.empty())
                text += ", " + detail;
              if (tls13) {
                side.tls_encrypted = true;
                other.tls_encrypted = true;
              }
            }
            emit(PacketEventKind::tls_handshake, time, label, text);
            message += 4U + message_length;
          }
        }
      }
      at += 5U + length;
    }
  }

  PacketEventReport& report_;
  const EventData& data_;
  std::array<std::size_t, kPacketEventKinds> shown_{};
  std::unordered_map<std::string, Connection> connections_;
  std::vector<KeepAliveGroup> keep_alive_groups_;
};

Error packet_error(std::string operation, std::string message) {
  Error error;
  error.component = "PacketEvents";
  error.operation = std::move(operation);
  error.message = std::move(message);
  return error;
}

} // namespace

std::string packet_event_name(PacketEventKind kind) {
  return event_data().events[static_cast<std::size_t>(kind)].name;
}

std::string packet_event_meaning(PacketEventKind kind) {
  return event_data().events[static_cast<std::size_t>(kind)].meaning;
}

std::string packet_event_time(std::int64_t time_micros) {
  std::int64_t seconds = time_micros / 1000000;
  std::int64_t micros = time_micros % 1000000;
  if (micros < 0) {
    micros += 1000000;
    --seconds;
  }
  std::int64_t days = seconds / 86400;
  std::int64_t of_day = seconds % 86400;
  if (of_day < 0) {
    of_day += 86400;
    --days;
  }
  // Days since 1970 to a civil date (H. Hinnant's algorithm).
  const std::int64_t shifted = days + 719468;
  const std::int64_t era = (shifted >= 0 ? shifted : shifted - 146096) / 146097;
  const std::int64_t day_of_era = shifted - era * 146097;
  const std::int64_t year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
  const std::int64_t day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
  const std::int64_t month_index = (5 * day_of_year + 2) / 153;
  const std::int64_t day = day_of_year - (153 * month_index + 2) / 5 + 1;
  const std::int64_t month = month_index < 10 ? month_index + 3 : month_index - 9;
  const std::int64_t year = year_of_era + era * 400 + (month <= 2 ? 1 : 0);
  char buffer[128];
  std::snprintf(buffer, sizeof(buffer), "%04lld-%02lld-%02lld %02lld:%02lld:%02lld.%03lld", static_cast<long long>(year),
                static_cast<long long>(month), static_cast<long long>(day), static_cast<long long>(of_day / 3600),
                static_cast<long long>(of_day / 60 % 60), static_cast<long long>(of_day % 60),
                static_cast<long long>(micros / 1000));
  return buffer;
}

Result<PacketEventReport> analyze_packet_stream(std::istream& input, const CancellationToken& cancel) {
  CaptureReader reader(input);
  if (!reader.open())
    return Result<PacketEventReport>::failure(
        packet_error("read", "The file is not a packet capture SAT can read (.pcapng or .pcap)."));
  PacketEventReport report;
  Analyzer analyzer(report);
  const EventData& data = event_data();
  std::unordered_map<std::uint64_t, std::int64_t> recent;
  Record record;
  TcpPacket packet;
  while (reader.next(record)) {
    ++report.packets;
    if ((report.packets & 0xFFFU) == 0U) {
      if (cancel.is_cancelled())
        return Result<PacketEventReport>::failure(packet_error("read", "Cancelled."));
      for (auto entry = recent.begin(); entry != recent.end();) {
        if (record.time_micros - entry->second > data.copy_window_micros)
          entry = recent.erase(entry);
        else
          ++entry;
      }
    }
    if (report.first_micros == 0 || record.time_micros < report.first_micros)
      report.first_micros = record.time_micros;
    report.last_micros = std::max(report.last_micros, record.time_micros);
    std::uint64_t hash = 0;
    bool hashed = false;
    const PacketShape shape = parse_packet(record, packet, hash, hashed);
    if (!hashed)
      hash = frame_hash(record);
    auto [entry, inserted] = recent.emplace(hash, record.time_micros);
    if (!inserted) {
      const std::int64_t apart = record.time_micros - entry->second;
      entry->second = record.time_micros;
      if (apart <= data.copy_window_micros && apart >= -data.copy_window_micros) {
        ++report.copies;
        continue;
      }
    }
    if (shape != PacketShape::tcp) {
      ++report.other_packets;
      continue;
    }
    ++report.tcp_packets;
    analyzer.packet(record.time_micros, packet);
  }
  if (!reader.warning.empty())
    report.warnings.push_back(reader.warning);
  analyzer.finish();
  return Result<PacketEventReport>::success(std::move(report));
}

Result<PacketEventReport> analyze_packet_capture(const std::filesystem::path& capture, const CancellationToken& cancel) {
  std::ifstream input(capture, std::ios::binary);
  if (!input)
    return Result<PacketEventReport>::failure(packet_error("open", "Cannot open " + path_to_utf8(capture) + "."));
  return analyze_packet_stream(input, cancel);
}

std::vector<std::pair<std::string, std::string>> packet_event_summary(const PacketEventReport& report) {
  std::vector<std::pair<std::string, std::string>> lines;
  std::string packets = with_thousands(report.packets) + " read";
  if (report.copies != 0U)
    packets += ", " + with_thousands(report.copies) + " of them copies of a packet logged at another component (counted once)";
  lines.emplace_back("Packets", packets);
  if (report.packets != 0U)
    lines.emplace_back("Time span", packet_event_time(report.first_micros) + " to " + packet_event_time(report.last_micros) + " UTC");
  lines.emplace_back("TCP", with_thousands(report.tcp_packets) + " packets in " + with_thousands(report.connections) +
                                (report.connections == 1U ? " connection" : " connections"));
  if (report.other_packets != 0U)
    lines.emplace_back("Other packets", with_thousands(report.other_packets) + " (not TCP)");
  std::uint64_t total = 0;
  const std::size_t shown = event_data().shown_per_kind;
  for (std::size_t index = 0; index < kPacketEventKinds; ++index) {
    const std::uint64_t count = report.counts[index];
    total += count;
    if (count == 0U)
      continue;
    std::string value = with_thousands(count);
    const auto kind = static_cast<PacketEventKind>(index);
    // Keep-alives are listed once per connection direction, so the limit counts those rows.
    std::uint64_t rows = count;
    if (kind == PacketEventKind::keep_alive) {
      value += " on " + with_thousands(report.keep_alive_connections) +
               (report.keep_alive_connections == 1U ? " connection" : " connections");
      rows = report.keep_alive_groups;
    }
    if (rows > shown)
      value += ", the first " + std::to_string(shown) + " listed";
    lines.emplace_back(packet_event_name(kind), value);
  }
  if (total == 0U)
    lines.emplace_back("Notable events", "None found");
  for (const std::string& warning : report.warnings)
    lines.emplace_back("Note", warning);
  return lines;
}

} // namespace support_assist
