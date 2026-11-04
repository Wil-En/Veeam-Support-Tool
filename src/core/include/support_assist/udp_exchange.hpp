#pragma once

// One datagram out and one reply back, for the checks that ask a single question of a single
// server: a DNS query (Name Check) and an SNTP query (Time Check). The request is built after the
// name is resolved and the socket is ready, so a timestamp it carries is taken just before sending.

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace support_assist {

struct UdpExchange {
  bool answered = false;
  std::vector<std::uint8_t> response;
  std::string address; // the numeric address the datagram went to
  std::string error;   // why no reply was taken
  double elapsed_ms = 0.0;
  std::chrono::system_clock::time_point received_at;
};

// host: an IP address, or a name when numeric_only is false (the first address it resolves to).
// accept: true for the reply that answers this request; any other datagram is ignored.
UdpExchange udp_exchange(const std::string& host, std::uint16_t port, bool numeric_only,
                         const std::function<std::vector<std::uint8_t>()>& request,
                         const std::function<bool(const std::vector<std::uint8_t>&)>& accept,
                         std::chrono::milliseconds timeout);

} // namespace support_assist
