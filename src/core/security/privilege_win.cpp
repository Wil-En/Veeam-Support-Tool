#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <windows.h>
#include <sddl.h>

#include <vector>

namespace support_assist {
namespace {
class TokenHandle {
public:
  explicit TokenHandle(HANDLE h = nullptr) : h_(h) {}
  ~TokenHandle() {
    if (h_)
      CloseHandle(h_);
  }
  HANDLE get() const {
    return h_;
  }

private:
  HANDLE h_;
};
Error sec_error(std::string op, DWORD code) {
  Error e;
  e.component = "Security";
  e.operation = std::move(op);
  e.native_code = code;
  e.message = "Windows token operation failed";
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return e;
}
} // namespace
Result<SecurityContext> current_security_context() {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))
    return Result<SecurityContext>::failure(sec_error("OpenProcessToken", GetLastError()));
  TokenHandle token(raw);
  SecurityContext c;
  TOKEN_ELEVATION elevation{};
  DWORD size = 0;
  if (GetTokenInformation(token.get(), TokenElevation, &elevation, sizeof(elevation), &size))
    c.elevated = elevation.TokenIsElevated != 0;
  DWORD session = 0;
  if (GetTokenInformation(token.get(), TokenSessionId, &session, sizeof(session), &size))
    c.session_id = session;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
  std::vector<std::byte> user_buf(size);
  if (GetTokenInformation(token.get(), TokenUser, user_buf.data(), size, &size)) {
    auto* user = reinterpret_cast<TOKEN_USER*>(user_buf.data());
    wchar_t name[256]{}, domain[256]{};
    DWORD nc = 256, dc = 256;
    SID_NAME_USE use{};
    if (LookupAccountSidW(nullptr, user->User.Sid, name, &nc, domain, &dc, &use))
      c.user = utf8_from_wide(std::wstring(domain) + L"\\" + name);
  }
  size = 0;
  GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &size);
  std::vector<std::byte> priv_buf(size);
  if (size && GetTokenInformation(token.get(), TokenPrivileges, priv_buf.data(), size, &size)) {
    auto* p = reinterpret_cast<TOKEN_PRIVILEGES*>(priv_buf.data());
    for (DWORD i = 0; i < p->PrivilegeCount; ++i) {
      if ((p->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) == 0)
        continue;
      wchar_t name[256]{};
      DWORD chars = 256;
      if (LookupPrivilegeNameW(nullptr, &p->Privileges[i].Luid, name, &chars))
        c.enabled_privileges.push_back(utf8_from_wide(std::wstring_view(name, chars)));
    }
  }
  return Result<SecurityContext>::success(std::move(c));
}
Status enable_privilege(std::string_view privilege_name) {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &raw))
    return Status::failure(sec_error("OpenProcessToken", GetLastError()));
  TokenHandle token(raw);
  LUID luid{};
  auto wide = wide_from_utf8(privilege_name);
  if (!LookupPrivilegeValueW(nullptr, wide.c_str(), &luid))
    return Status::failure(sec_error("LookupPrivilegeValueW", GetLastError()));
  TOKEN_PRIVILEGES tp{};
  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luid;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  SetLastError(ERROR_SUCCESS);
  if (!AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr))
    return Status::failure(sec_error("AdjustTokenPrivileges", GetLastError()));
  DWORD code = GetLastError();
  if (code != ERROR_SUCCESS)
    return Status::failure(sec_error("AdjustTokenPrivileges", code));
  return Status::success();
}
} // namespace support_assist
