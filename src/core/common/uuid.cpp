#include "support_assist/uuid.hpp"
#include <array>
#include <iomanip>
#include <random>
#include <sstream>
namespace support_assist {
std::string make_uuid_v4() {
  std::array<unsigned char, 16> b{};
  std::random_device rd;
  for (auto& x : b)
    x = static_cast<unsigned char>(rd());
  b[6] = static_cast<unsigned char>((b[6] & 0x0f) | 0x40);
  b[8] = static_cast<unsigned char>((b[8] & 0x3f) | 0x80);
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < b.size(); ++i) {
    out << std::setw(2) << static_cast<unsigned>(b[i]);
    if (i == 3 || i == 5 || i == 7 || i == 9)
      out << '-';
  }
  return out.str();
}
} // namespace support_assist
