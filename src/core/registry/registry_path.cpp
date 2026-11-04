#include "support_assist/registry.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <array>
namespace support_assist {
namespace {
// The canonical hive name for a short or long spelling, or an empty view when the text is not a
// hive. The comparison is on lower-case text.
std::string_view canonical_hive(std::string_view lower) {
  if (lower == "hklm" || lower == "hkey_local_machine")
    return "HKEY_LOCAL_MACHINE";
  if (lower == "hkcu" || lower == "hkey_current_user")
    return "HKEY_CURRENT_USER";
  if (lower == "hku" || lower == "hkey_users")
    return "HKEY_USERS";
  if (lower == "hkcc" || lower == "hkey_current_config")
    return "HKEY_CURRENT_CONFIG";
  if (lower == "hkcr" || lower == "hkey_classes_root")
    return "HKEY_CLASSES_ROOT";
  return {};
}
} // namespace
// A scope is a hive alone ("HKLM", "HKEY_USERS\") or a key under one. A hive alone leaves the
// subkey empty, which the scanner reads as the whole hive. The text may start with the "Computer\"
// that regedit shows in its address bar and may name the hive as "HKLM:".
Result<RegistryScope> parse_registry_scope(std::string_view input, RegistryView view) {
  const auto text = trim(input);
  std::string s;
  s.reserve(text.size());
  for (const char raw : text) {
    const char c = raw == '/' ? '\\' : raw;
    if (c == '\\' && (s.empty() || s.back() == '\\'))
      continue;
    s.push_back(c);
  }
  while (!s.empty() && s.back() == '\\')
    s.pop_back();
  if (s.size() >= 9 && ascii_lower(s.substr(0, 9)) == "computer\\")
    s.erase(0, 9);
  auto pos = s.find('\\');
  auto head = ascii_lower(pos == std::string::npos ? s : s.substr(0, pos));
  if (!head.empty() && head.back() == ':')
    head.pop_back();
  const auto hive = canonical_hive(head);
  if (hive.empty()) {
    Error e;
    e.component = "Registry";
    e.operation = "parse scope";
    e.source = s;
    e.message = "Unknown Registry hive";
    e.timestamp_utc = utc_now_iso8601();
    e.correlation_id = make_uuid_v4();
    return Result<RegistryScope>::failure(std::move(e));
  }
  RegistryScope scope;
  scope.hive = std::string(hive);
  scope.subkey = pos == std::string::npos ? "" : s.substr(pos + 1);
  scope.view = view;
  return Result<RegistryScope>::success(std::move(scope));
}
} // namespace support_assist
