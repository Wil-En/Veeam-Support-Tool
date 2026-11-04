// Decode the system error codes Veeam logs actually contain.
//
// The table comes from the evidence: seven case snapshots plus the live tree gave 1,919 log
// files spanning 2023-2026, and counting the codes that appear in an
// explicit error context produced the table below. Every entry here was observed in real evidence -
// nothing is included because it exists in winerror.h.
//
// Ranked by what the evidence actually contained:
//
//     0x00000070  ERROR_DISK_FULL              8507 occurrences
//     0x00002746  WSAECONNRESET                1433
//     0x00000002  ERROR_FILE_NOT_FOUND         1245
//     0x00002743  WSAENETUNREACH                274
//     0x0000274D  WSAECONNREFUSED                58
//
// The first one is the whole of field tests 01-03: a 63 GB drive and a 174 GB backup, reported to
// the engineer as "Error code: 0x00000070" and nothing else.
//
// Codes are decoded, never rewritten: the original text stays and the meaning is added beside it.
// A support engineer pasting a log line into a case must still be pasting the product's own words.

#include "support_assist/system_error_codes.hpp"


#include <array>
#include <cctype>
#include <cstdlib>

namespace support_assist {
namespace {

struct CodeEntry {
  std::uint32_t code;
  const char* symbol;
  const char* meaning;
  SystemErrorFamily family;
};

// Win32 (winerror.h), observed in this evidence.
constexpr std::array<CodeEntry, 26> kWin32{{
    {1U, "ERROR_INVALID_FUNCTION", "The operation is not supported by this device or driver.",
     SystemErrorFamily::win32},
    {2U, "ERROR_FILE_NOT_FOUND", "The file does not exist at the path given.",
     SystemErrorFamily::win32},
    {3U, "ERROR_PATH_NOT_FOUND", "The directory in the path does not exist.",
     SystemErrorFamily::win32},
    {5U, "ERROR_ACCESS_DENIED", "Access denied - permissions, or the file is held by something else.",
     SystemErrorFamily::win32},
    {15U, "ERROR_INVALID_DRIVE", "The drive letter does not exist on this machine.",
     SystemErrorFamily::win32},
    {19U, "ERROR_WRITE_PROTECT", "The media is write protected.", SystemErrorFamily::win32},
    {21U, "ERROR_NOT_READY", "The device is not ready - typically removable media that is absent.",
     SystemErrorFamily::win32},
    {32U, "ERROR_SHARING_VIOLATION", "Another process holds the file open.",
     SystemErrorFamily::win32},
    {33U, "ERROR_LOCK_VIOLATION", "Part of the file is locked by another process.",
     SystemErrorFamily::win32},
    {53U, "ERROR_BAD_NETPATH", "The network path was not found.", SystemErrorFamily::win32},
    {59U, "ERROR_UNEXP_NET_ERR", "An unexpected network error occurred.",
     SystemErrorFamily::win32},
    {64U, "ERROR_NETNAME_DELETED", "The network name is no longer available.",
     SystemErrorFamily::win32},
    {67U, "ERROR_BAD_NET_NAME", "The network name cannot be found.", SystemErrorFamily::win32},
    {70U, "ERROR_REM_NOT_LIST", "The remote computer is not available.",
     SystemErrorFamily::win32},
    {112U, "ERROR_DISK_FULL", "There is not enough space on the disk.",
     SystemErrorFamily::win32},
    {126U, "ERROR_MOD_NOT_FOUND", "A required library could not be loaded.",
     SystemErrorFamily::win32},
    {267U, "ERROR_DIRECTORY", "The directory name is invalid.", SystemErrorFamily::win32},
    {1056U, "ERROR_SERVICE_ALREADY_RUNNING", "The service is already running.",
     SystemErrorFamily::win32},
    {1063U, "ERROR_FAILED_SERVICE_CONTROLLER_CONNECT",
     "The service could not connect to the service controller.", SystemErrorFamily::win32},
    {1231U, "ERROR_NETWORK_UNREACHABLE", "The network location cannot be reached.",
     SystemErrorFamily::win32},
    {1326U, "ERROR_LOGON_FAILURE", "The user name or password is incorrect.",
     SystemErrorFamily::win32},
    {1455U, "ERROR_COMMITMENT_LIMIT", "The paging file is too small for this operation.",
     SystemErrorFamily::win32},
    {1722U, "RPC_S_SERVER_UNAVAILABLE", "The RPC server is unavailable.",
     SystemErrorFamily::rpc},
    {1726U, "RPC_S_CALL_FAILED", "The remote procedure call failed.", SystemErrorFamily::rpc},
    {1740U, "RPC_S_DUPLICATE_ENDPOINT", "The RPC endpoint is already registered.",
     SystemErrorFamily::rpc},
    {1753U, "EPT_S_NOT_REGISTERED", "No endpoints are available from the endpoint mapper.",
     SystemErrorFamily::rpc},
}};

// Winsock (10000+), observed in this evidence.
constexpr std::array<CodeEntry, 9> kWinsock{{
    {10013U, "WSAEACCES", "Permission denied on the socket operation.",
     SystemErrorFamily::winsock},
    {10035U, "WSAEWOULDBLOCK", "The socket operation would block.", SystemErrorFamily::winsock},
    {10048U, "WSAEADDRINUSE", "The address is already in use - something else holds the port.",
     SystemErrorFamily::winsock},
    {10049U, "WSAEADDRNOTAVAIL", "The requested address is not valid on this machine.",
     SystemErrorFamily::winsock},
    {10051U, "WSAENETUNREACH", "The network is unreachable.", SystemErrorFamily::winsock},
    {10053U, "WSAECONNABORTED", "The connection was aborted by the local host.",
     SystemErrorFamily::winsock},
    {10054U, "WSAECONNRESET", "The connection was reset by the remote host.",
     SystemErrorFamily::winsock},
    {10060U, "WSAETIMEDOUT", "The connection attempt timed out.", SystemErrorFamily::winsock},
    {10061U, "WSAECONNREFUSED", "The connection was refused - nothing is listening on that port.",
     SystemErrorFamily::winsock},
}};

// HRESULTs that are not simply a wrapped Win32 code.
constexpr std::array<CodeEntry, 6> kHresult{{
    {0x80041014U, "WBEM_E_INITIALIZATION_FAILURE",
     "WMI failed to initialise - the WMI repository or service is unhealthy.",
     SystemErrorFamily::wmi},
    {0x80041003U, "WBEM_E_ACCESS_DENIED", "WMI access denied.", SystemErrorFamily::wmi},
    {0x80090322U, "SEC_E_WRONG_PRINCIPAL",
     "The target principal name is incorrect - usually an SPN or certificate name mismatch.",
     SystemErrorFamily::security},
    {0x8009030EU, "SEC_E_NO_CREDENTIALS", "No credentials are available in the security package.",
     SystemErrorFamily::security},
    {0x80131904U, "COR_E_SQL", "A .NET data-provider error - the underlying database call failed.",
     SystemErrorFamily::dotnet},
    {0x800705AAU, "E_OUTOFMEMORY_RESOURCES", "Insufficient system resources to complete the call.",
     SystemErrorFamily::win32},
}};

const CodeEntry* lookup(std::uint32_t code) {
  for (const auto& entry : kWin32)
    if (entry.code == code)
      return &entry;
  for (const auto& entry : kWinsock)
    if (entry.code == code)
      return &entry;
  for (const auto& entry : kHresult)
    if (entry.code == code)
      return &entry;
  return nullptr;
}

}  // namespace

std::optional<SystemErrorMeaning> decode_system_error(std::uint32_t code) {
  if (const auto* entry = lookup(code); entry != nullptr) {
    return SystemErrorMeaning{entry->symbol, entry->meaning, entry->family, code, false};
  }

  // An HRESULT of the form 0x8007xxxx carries a Win32 code in its low word. Decoding the wrapper
  // rather than reporting "unknown" is the difference between 0x80070070 meaning nothing and
  // meaning "the disk is full".
  if ((code & 0xFFFF0000U) == 0x80070000U) {
    const std::uint32_t inner = code & 0x0000FFFFU;
    if (const auto* entry = lookup(inner); entry != nullptr) {
      return SystemErrorMeaning{entry->symbol, entry->meaning, entry->family, inner, true};
    }
  }
  return std::nullopt;
}

std::optional<SystemErrorMeaning> decode_system_error_text(std::string_view text) {
  // Trimmed here rather than pulling in a string helper: this file has no other dependency and
  // should keep it that way.
  std::size_t first = 0;
  std::size_t last = text.size();
  while (first < last && std::isspace(static_cast<unsigned char>(text[first])) != 0)
    ++first;
  while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])) != 0)
    --last;
  const std::string trimmed(text.substr(first, last - first));
  if (trimmed.empty())
    return std::nullopt;

  const bool hex = trimmed.size() > 2 && trimmed[0] == '0' &&
                   (trimmed[1] == 'x' || trimmed[1] == 'X');
  char* end = nullptr;
  const unsigned long long value =
      std::strtoull(hex ? trimmed.c_str() + 2 : trimmed.c_str(), &end, hex ? 16 : 10);
  if (end == nullptr || *end != '\0' || value > 0xFFFFFFFFULL)
    return std::nullopt;
  return decode_system_error(static_cast<std::uint32_t>(value));
}

std::string describe_system_error(std::uint32_t code) {
  const auto meaning = decode_system_error(code);
  if (!meaning.has_value())
    return {};
  std::string text = meaning->symbol;
  text += " - ";
  text += meaning->description;
  if (meaning->from_hresult_wrapper)
    text += " (Win32 code carried inside an HRESULT)";
  return text;
}

}  // namespace support_assist
