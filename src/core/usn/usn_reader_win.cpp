#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/usn.hpp"
#include "support_assist/version.hpp"
#include "support_assist/uuid.hpp"
#include <windows.h>
#include <winioctl.h>

#include <cwctype>

namespace support_assist {
namespace {
class Handle {
public:
  explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
  ~Handle() {
    if (h_ != INVALID_HANDLE_VALUE)
      CloseHandle(h_);
  }
  HANDLE get() const {
    return h_;
  }

private:
  HANDLE h_;
};
Error err(std::string op, const std::filesystem::path& p, DWORD code) {
  Error e;
  e.component = "USN";
  e.operation = std::move(op);
  e.source = utf8_from_wide(p.native());
  e.native_code = code;
  e.message = "USN journal query failed";
  e.recoverable = true;
  e.elevation_may_help = code == ERROR_ACCESS_DENIED;
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return e;
}
bool is_volume_guid_path(const std::wstring& s) {
  return s.rfind(L"\\\\?\\Volume{", 0) == 0;
}
std::wstring volume_device(const std::filesystem::path& p) {
  auto s = p.native();
  if (s.rfind(L"\\\\.\\", 0) == 0)
    return s;
  // A volume GUID path opens as the volume without its trailing backslash; with it the open
  // reaches the root folder instead.
  if (is_volume_guid_path(s)) {
    while (!s.empty() && s.back() == L'\\')
      s.pop_back();
    return s;
  }
  if (s.size() >= 2 && s[1] == L':')
    return L"\\\\.\\" + s.substr(0, 2);
  return s;
}
} // namespace
Result<UsnJournalState> query_usn_journal(const std::filesystem::path& volume) {
  UsnJournalState state;
  std::wstring root = volume.native();
  if (root.size() == 2 && root[1] == L':')
    root += L'\\';
  else if (is_volume_guid_path(root) && root.back() != L'\\')
    root += L'\\';
  wchar_t fs[64]{};
  if (!GetVolumeInformationW(root.c_str(), nullptr, 0, nullptr, nullptr, nullptr, fs, 64)) {
    state.reason = "Unable to query volume filesystem: " + std::to_string(GetLastError());
    return Result<UsnJournalState>::success(std::move(state));
  }
  state.filesystem = utf8_from_wide(fs);
  if (_wcsicmp(fs, L"NTFS") != 0) {
    state.reason =
        "USN acceleration is limited to local NTFS volumes; detected " + utf8_from_wide(fs);
    return Result<UsnJournalState>::success(std::move(state));
  }
  auto device = volume_device(volume);
  Handle h(CreateFileW(device.c_str(),
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       nullptr,
                       OPEN_EXISTING,
                       0,
                       nullptr));
  if (h.get() == INVALID_HANDLE_VALUE)
    return Result<UsnJournalState>::failure(err("open volume", volume, GetLastError()));
  USN_JOURNAL_DATA_V0 data{};
  DWORD bytes = 0;
  if (!DeviceIoControl(
          h.get(), FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &data, sizeof(data), &bytes, nullptr)) {
    DWORD code = GetLastError();
    if (code == ERROR_JOURNAL_NOT_ACTIVE) {
      state.inactive = true;
      state.reason =
          "The NTFS change journal is not active. " + std::string(kProductName) +
              " did not create or resize it.";
      return Result<UsnJournalState>::success(std::move(state));
    }
    return Result<UsnJournalState>::failure(err("FSCTL_QUERY_USN_JOURNAL", volume, code));
  }
  state.eligible = true;
  state.reason = "Active NTFS change journal found";
  state.journal_id = data.UsnJournalID;
  state.next_usn = data.NextUsn;
  state.lowest_valid_usn = data.LowestValidUsn;
  state.first_usn = data.FirstUsn;
  return Result<UsnJournalState>::success(std::move(state));
}
} // namespace support_assist
