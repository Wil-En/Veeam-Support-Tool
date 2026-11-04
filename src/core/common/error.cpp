#include "support_assist/error.hpp"
#include <cstdint>
#include <sstream>
namespace support_assist {
std::string to_string(Severity value) {
  switch (value) {
  case Severity::info:
    return "info";
  case Severity::warning:
    return "warning";
  case Severity::error:
    return "error";
  case Severity::fatal:
    return "fatal";
  }
  return "unknown";
}
std::string describe_error(const Error& error) {
  std::ostringstream out;
  out << error.component << ": " << error.operation;
  if (!error.source.empty())
    out << " [" << error.source << "]";
  if (!error.message.empty())
    out << ": " << error.message;
  if (error.native_code != 0)
    out << " (native=" << error.native_code << ')';
  if (error.hresult != 0)
    out << " (HRESULT=0x" << std::hex << static_cast<std::uint32_t>(error.hresult) << std::dec << ')';
  if (error.sqlite_code != 0)
    out << " (sqlite=" << error.sqlite_code << ')';
  return out.str();
}
} // namespace support_assist
