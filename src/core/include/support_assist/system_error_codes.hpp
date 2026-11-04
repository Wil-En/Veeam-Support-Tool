// Decoding for the system error codes that appear in Veeam logs.
//
// The table behind this was derived from real evidence rather than from winerror.h: 1,919 log files
// across seven case snapshots and the live tree, counting only codes written in an explicit error
// context. See system_error_codes.cpp for the observed frequencies.
//
// Decoding ADDS meaning; it never replaces the product's own text. An engineer pasting a log line
// into a case must still be pasting what Veeam wrote.

#ifndef SUPPORT_ASSIST_SYSTEM_ERROR_CODES_HPP
#define SUPPORT_ASSIST_SYSTEM_ERROR_CODES_HPP

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace support_assist {

// Which layer produced the code. Worth carrying because it says where to look next: a winsock code
// is a connectivity question, a win32 one is usually storage or permissions.
enum class SystemErrorFamily {
  win32,
  winsock,
  rpc,
  wmi,
  security,
  dotnet,
};

struct SystemErrorMeaning {
  // The platform's own name for it, e.g. ERROR_DISK_FULL.
  std::string symbol;
  // One sentence an engineer can act on.
  std::string description;
  SystemErrorFamily family = SystemErrorFamily::win32;
  // The code that was actually decoded. Differs from the input when an HRESULT wrapped a Win32
  // code in its low word.
  std::uint32_t decoded_code = 0;
  bool from_hresult_wrapper = false;
};

// Decode a numeric code. Handles 0x8007xxxx HRESULTs by unwrapping the Win32 code inside.
std::optional<SystemErrorMeaning> decode_system_error(std::uint32_t code);

// Decode "0x00000070" or "112" as written in a log line.
std::optional<SystemErrorMeaning> decode_system_error_text(std::string_view text);

// "ERROR_DISK_FULL - There is not enough space on the disk.", or empty when unknown.
std::string describe_system_error(std::uint32_t code);

}  // namespace support_assist

#endif  // SUPPORT_ASSIST_SYSTEM_ERROR_CODES_HPP
