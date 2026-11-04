#include "support_assist/system_info.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <optional>
#include <string_view>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/utsname.h>
#endif
namespace support_assist {
SnapshotMetadata make_snapshot_metadata(SnapshotKind kind, std::string scope, std::string options) {
  SnapshotMetadata m;
  m.id = make_uuid_v4();
  m.kind = kind;
  m.state = SnapshotState::creating;
  m.application_version = std::string(kVersion);
  m.schema_version = kSnapshotSchemaVersion;
  m.created_start_utc = utc_now_iso8601();
  m.user_scope = std::move(scope);
  m.options_json = std::move(options);
#ifdef _WIN32
  wchar_t name[256]{};
  DWORD n = 256;
  if (GetComputerNameW(name, &n))
    m.machine_name = utf8_from_wide(std::wstring_view(name, n));
  m.os_name = "Windows";
  // RtlGetVersion is used rather than GetVersionEx because GetVersionEx is subject to
  // application-manifest shimming and reports 6.2 on unmanifested processes, which would
  // silently misidentify the OS of the machine being examined.
  if (const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll"); ntdll != nullptr) {
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    // GetProcAddress returns FARPROC; the double cast avoids a C4191 function-pointer warning
    // under /WX while keeping the call type-correct.
    const auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
        reinterpret_cast<void*>(GetProcAddress(ntdll, "RtlGetVersion")));
    if (rtl_get_version != nullptr) {
      RTL_OSVERSIONINFOW version{};
      version.dwOSVersionInfoSize = sizeof(version);
      if (rtl_get_version(&version) == 0) {
        m.os_version = std::to_string(version.dwMajorVersion) + "." +
                       std::to_string(version.dwMinorVersion) + "." +
                       std::to_string(version.dwBuildNumber);
      }
    }
  }
  SYSTEM_INFO si{};
  GetNativeSystemInfo(&si);
  m.architecture = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64   ? "x64"
                   : si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64 ? "ARM64"
                                                                               : "other";
#else
  utsname u{};
  if (uname(&u) == 0) {
    m.machine_name = u.nodename;
    m.os_name = u.sysname;
    m.os_version = std::string(u.release) + " " + u.version;
    m.architecture = u.machine;
  }
  // uname reports the kernel, which does not identify the distribution an engineer is
  // troubleshooting. /etc/os-release is the freedesktop standard every supported distribution
  // publishes; PRETTY_NAME is the line a human recognises ("Ubuntu 26.04 LTS").
  {
    std::ifstream release("/etc/os-release", std::ios::binary);
    std::string line;
    while (std::getline(release, line)) {
      constexpr std::string_view key = "PRETTY_NAME=";
      if (line.rfind(key.data(), 0) != 0) {
        continue;
      }
      std::string value = line.substr(key.size());
      if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
        value = value.substr(1, value.size() - 2);
      }
      m.os_distribution = value;
      break;
    }
  }
#endif
  auto sec = current_security_context();
  if (sec.ok()) {
    m.elevated = sec.value().elevated;
    std::ostringstream p;
    for (std::size_t i = 0; i < sec.value().enabled_privileges.size(); ++i) {
      if (i)
        p << ',';
      p << sec.value().enabled_privileges[i];
    }
    m.enabled_privileges = p.str();
  }
  return m;
}
} // namespace support_assist

namespace support_assist {
namespace {

struct AltitudeBand {
  std::uint32_t first;
  std::uint32_t last;
  std::string_view group;
};

// Transcribed from Microsoft's allocated-altitudes documentation, not inferred. Ordered high to
// low, which is also the order the filters stack above the volume.
constexpr std::array<AltitudeBand, 21> kAltitudeBands{{
    {420000U, 429999U, "Filter"},
    {400000U, 409999U, "FSFilter Top"},
    {392000U, 394999U, "FSFilter Security Monitor"},
    {360000U, 389999U, "FSFilter Activity Monitor"},
    {340000U, 349999U, "FSFilter Undelete"},
    {320000U, 329998U, "FSFilter Anti-Virus"},
    {300000U, 309998U, "FSFilter Replication"},
    {280000U, 289998U, "FSFilter Continuous Backup"},
    {272000U, 274999U, "FSFilter Security Content Screener"},
    {260000U, 269998U, "FSFilter Content Screener"},
    {240000U, 249999U, "FSFilter Quota Management"},
    {220000U, 229999U, "FSFilter System Recovery"},
    {200000U, 209999U, "FSFilter Cluster File System"},
    {180000U, 189999U, "FSFilter HSM"},
    {170000U, 174999U, "FSFilter Imaging"},
    {160000U, 169999U, "FSFilter Compression"},
    {140000U, 149999U, "FSFilter Encryption"},
    {130000U, 139999U, "FSFilter Virtualization"},
    {120000U, 129999U, "FSFilter Physical Quota Management"},
    {100000U, 109999U, "FSFilter Open File"},
    {80000U, 89999U, "FSFilter Security Enhancer"},
}};

} // namespace

std::optional<std::string_view> minifilter_altitude_group(std::uint32_t altitude) {
  for (const auto& band : kAltitudeBands) {
    if (altitude >= band.first && altitude <= band.last)
      return band.group;
  }
  return std::nullopt;
}

std::optional<std::uint32_t> parse_minifilter_altitude(std::string_view row) {
  // Third whitespace-separated column. Split on runs of spaces rather than a fixed offset: the
  // Filter and Volume Name columns widen with the longest value on the machine, so fixed offsets
  // would silently read the wrong field on a host with a long filter name.
  std::size_t column = 0;
  std::size_t index = 0;
  while (index < row.size()) {
    while (index < row.size() && (row[index] == ' ' || row[index] == '\t' || row[index] == '\r'))
      ++index;
    const std::size_t start = index;
    while (index < row.size() && row[index] != ' ' && row[index] != '\t' && row[index] != '\r')
      ++index;
    if (start == index)
      break;
    if (column == 2U) {
      const std::string_view field = row.substr(start, index - start);
      if (field.empty() ||
          !std::all_of(field.begin(), field.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        return std::nullopt;
      std::uint64_t value = 0;
      for (const char digit : field) {
        value = value * 10U + static_cast<std::uint64_t>(digit - '0');
        if (value > 0xFFFFFFFFULL)
          return std::nullopt;
      }
      return static_cast<std::uint32_t>(value);
    }
    ++column;
  }
  return std::nullopt;
}

} // namespace support_assist
