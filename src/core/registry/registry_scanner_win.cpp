#include "support_assist/registry.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <memory>
#include <sstream>
#include <utility>

#include <windows.h>
#include <winreg.h>

namespace support_assist {
namespace {
class UniqueKey {
public:
  UniqueKey() = default;
  explicit UniqueKey(HKEY key) : key_(key) {}
  ~UniqueKey() {
    if (key_)
      RegCloseKey(key_);
  }
  UniqueKey(const UniqueKey&) = delete;
  UniqueKey& operator=(const UniqueKey&) = delete;
  UniqueKey(UniqueKey&& other) noexcept : key_(other.key_) {
    other.key_ = nullptr;
  }
  UniqueKey& operator=(UniqueKey&& other) noexcept {
    if (this != &other) {
      if (key_)
        RegCloseKey(key_);
      key_ = other.key_;
      other.key_ = nullptr;
    }
    return *this;
  }
  HKEY get() const noexcept {
    return key_;
  }

private:
  HKEY key_ = nullptr;
};

HKEY hive_handle(std::string_view hive) {
  if (hive == "HKEY_LOCAL_MACHINE")
    return HKEY_LOCAL_MACHINE;
  if (hive == "HKEY_CURRENT_USER")
    return HKEY_CURRENT_USER;
  if (hive == "HKEY_USERS")
    return HKEY_USERS;
  if (hive == "HKEY_CURRENT_CONFIG")
    return HKEY_CURRENT_CONFIG;
  if (hive == "HKEY_CLASSES_ROOT")
    return HKEY_CLASSES_ROOT;
  return nullptr;
}
REGSAM view_access(RegistryView view) {
  if (view == RegistryView::view32)
    return KEY_WOW64_32KEY;
  if (view == RegistryView::view64)
    return KEY_WOW64_64KEY;
  return 0;
}
std::vector<RegistryView> expand_views(RegistryView view) {
  if (view == RegistryView::both)
    return {RegistryView::view64, RegistryView::view32};
  return {view};
}
std::int64_t filetime_100ns(const FILETIME& value) {
  ULARGE_INTEGER x{};
  x.LowPart = value.dwLowDateTime;
  x.HighPart = value.dwHighDateTime;
  return static_cast<std::int64_t>(x.QuadPart);
}
std::string last_component(std::string_view path) {
  const auto pos = path.find_last_of('\\');
  return pos == std::string_view::npos ? std::string(path) : std::string(path.substr(pos + 1));
}
// A key's name in an error: the hive, then the path when there is one.
std::string key_display(const RegistryScope& scope, std::string_view relative_path) {
  return relative_path.empty() ? scope.hive : scope.hive + "\\" + std::string(relative_path);
}
Error win_error(std::string operation, std::string source, LSTATUS code, bool skipped = true) {
  Error e;
  e.component = "Registry";
  e.operation = std::move(operation);
  e.source = std::move(source);
  e.native_code = code;
  e.message = "Windows Registry API returned error " + std::to_string(code);
  e.recoverable = true;
  e.elevation_may_help = code == ERROR_ACCESS_DENIED;
  e.skipped = skipped;
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return e;
}
std::string
display_value(DWORD type, const std::vector<std::byte>& data, std::size_t limit, bool& truncated) {
  truncated = false;
  auto trim_display = [&](std::string value) {
    if (value.size() > limit) {
      value.resize(limit);
      value += "...";
      truncated = true;
    }
    return value;
  };
  if (type == REG_DWORD && data.size() >= sizeof(DWORD)) {
    DWORD value{};
    std::memcpy(&value, data.data(), sizeof(value));
    std::ostringstream out;
    out << value << " (0x" << std::hex << std::uppercase << value << ')';
    return out.str();
  }
  if (type == REG_DWORD_BIG_ENDIAN && data.size() >= sizeof(DWORD)) {
    const auto* b = reinterpret_cast<const unsigned char*>(data.data());
    DWORD value = (static_cast<DWORD>(b[0]) << 24) | (static_cast<DWORD>(b[1]) << 16) |
                  (static_cast<DWORD>(b[2]) << 8) | b[3];
    std::ostringstream out;
    out << value << " (0x" << std::hex << std::uppercase << value << ", big-endian)";
    return out.str();
  }
  if (type == REG_QWORD && data.size() >= sizeof(ULONGLONG)) {
    ULONGLONG value{};
    std::memcpy(&value, data.data(), sizeof(value));
    std::ostringstream out;
    out << value << " (0x" << std::hex << std::uppercase << value << ')';
    return out.str();
  }
  if (type == REG_SZ || type == REG_EXPAND_SZ || type == REG_LINK) {
    const auto count = data.size() / sizeof(wchar_t);
    std::wstring text(reinterpret_cast<const wchar_t*>(data.data()), count);
    while (!text.empty() && text.back() == L'\0')
      text.pop_back();
    return trim_display(utf8_from_wide(text));
  }
  if (type == REG_MULTI_SZ) {
    const auto count = data.size() / sizeof(wchar_t);
    const auto* ptr = reinterpret_cast<const wchar_t*>(data.data());
    std::ostringstream out;
    std::size_t start = 0;
    bool first = true;
    while (start < count) {
      std::size_t end = start;
      while (end < count && ptr[end] != L'\0')
        ++end;
      if (end == start)
        break;
      if (!first)
        out << " | ";
      first = false;
      out << utf8_from_wide(std::wstring_view(ptr + start, end - start));
      start = end + 1;
    }
    return trim_display(out.str());
  }
  const auto bytes = std::min(data.size(), limit / 2);
  truncated = bytes < data.size();
  return hex_encode(data.data(), data.size(), bytes);
}
Status record_error(SnapshotBatchWriter& writer,
                    std::string_view sid,
                    const Error& error,
                    ScanSummary& summary) {
  auto status = writer.add_error(sid, error);
  if (status.ok())
    ++summary.errors;
  return status;
}

Status enumerate_key(SnapshotBatchWriter& writer,
                     std::string_view snapshot_id,
                     const RegistryScope& scope,
                     RegistryView view,
                     std::string_view relative_path,
                     std::vector<std::string>& children,
                     std::size_t display_limit,
                     ScanSummary& summary) {
  const auto root = hive_handle(scope.hive);
  const auto wide_path = wide_from_utf8(relative_path);
  HKEY raw = nullptr;
  const LSTATUS opened = RegOpenKeyExW(root,
                                       wide_path.empty() ? nullptr : wide_path.c_str(),
                                       0,
                                       KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | view_access(view),
                                       &raw);
  if (opened != ERROR_SUCCESS) {
    RegistryKeyRecord denied;
    denied.snapshot_id = std::string(snapshot_id);
    denied.hive = scope.hive;
    denied.relative_path = std::string(relative_path);
    denied.view = view;
    denied.key_name = last_component(relative_path);
    denied.access_result = opened;
    denied.enumeration_error = "RegOpenKeyExW failed";
    if (auto s = writer.add_registry_key(denied); !s.ok())
      return s;
    ++summary.objects;
    return record_error(
        writer,
        snapshot_id,
        win_error("open key", key_display(scope, relative_path), opened),
        summary);
  }
  UniqueKey key(raw);
  DWORD subkey_count = 0, max_subkey_chars = 0, value_count = 0, max_value_name_chars = 0,
        max_value_bytes = 0;
  FILETIME last_write{};
  std::vector<wchar_t> class_buffer(1024, L'\0');
  DWORD class_chars = static_cast<DWORD>(class_buffer.size());
  LSTATUS info = RegQueryInfoKeyW(key.get(),
                                  class_buffer.data(),
                                  &class_chars,
                                  nullptr,
                                  &subkey_count,
                                  &max_subkey_chars,
                                  nullptr,
                                  &value_count,
                                  &max_value_name_chars,
                                  &max_value_bytes,
                                  nullptr,
                                  &last_write);
  if (info == ERROR_MORE_DATA) {
    class_buffer.resize(static_cast<std::size_t>(class_chars) + 1);
    class_chars = static_cast<DWORD>(class_buffer.size());
    info = RegQueryInfoKeyW(key.get(),
                            class_buffer.data(),
                            &class_chars,
                            nullptr,
                            &subkey_count,
                            &max_subkey_chars,
                            nullptr,
                            &value_count,
                            &max_value_name_chars,
                            &max_value_bytes,
                            nullptr,
                            &last_write);
  }
  RegistryKeyRecord kr;
  kr.snapshot_id = std::string(snapshot_id);
  kr.hive = scope.hive;
  kr.relative_path = std::string(relative_path);
  kr.view = view;
  kr.key_name = last_component(relative_path);
  kr.access_result = info;
  kr.last_write_100ns = filetime_100ns(last_write);
  if (info == ERROR_SUCCESS)
    kr.class_name = utf8_from_wide(std::wstring_view(class_buffer.data(), class_chars));
  else
    kr.enumeration_error = "RegQueryInfoKeyW failed";
  if (auto s = writer.add_registry_key(kr); !s.ok())
    return s;
  ++summary.objects;
  if (info != ERROR_SUCCESS) {
    return record_error(
        writer,
        snapshot_id,
        win_error("query key", key_display(scope, relative_path), info),
        summary);
  }

  std::vector<wchar_t> value_name(static_cast<std::size_t>(max_value_name_chars) + 2);
  std::vector<std::byte> value_data(
      std::max<std::size_t>(1, static_cast<std::size_t>(max_value_bytes) + 2));
  for (DWORD index = 0; index < value_count; ++index) {
    DWORD name_chars = static_cast<DWORD>(value_name.size());
    DWORD data_bytes = static_cast<DWORD>(value_data.size());
    DWORD type = 0;
    LSTATUS rc = RegEnumValueW(key.get(),
                               index,
                               value_name.data(),
                               &name_chars,
                               nullptr,
                               &type,
                               reinterpret_cast<BYTE*>(value_data.data()),
                               &data_bytes);
    if (rc == ERROR_MORE_DATA) {
      value_name.resize(static_cast<std::size_t>(name_chars) + 2);
      value_data.resize(static_cast<std::size_t>(data_bytes) + 2);
      name_chars = static_cast<DWORD>(value_name.size());
      data_bytes = static_cast<DWORD>(value_data.size());
      rc = RegEnumValueW(key.get(),
                         index,
                         value_name.data(),
                         &name_chars,
                         nullptr,
                         &type,
                         reinterpret_cast<BYTE*>(value_data.data()),
                         &data_bytes);
    }
    if (rc != ERROR_SUCCESS) {
      if (auto s = record_error(
              writer,
              snapshot_id,
              win_error("enumerate value", key_display(scope, relative_path), rc),
              summary);
          !s.ok())
        return s;
      continue;
    }
    RegistryValueRecord vr;
    vr.snapshot_id = std::string(snapshot_id);
    vr.hive = scope.hive;
    vr.relative_path = std::string(relative_path);
    vr.view = view;
    vr.value_name = utf8_from_wide(std::wstring_view(value_name.data(), name_chars));
    vr.is_default = name_chars == 0;
    vr.type = type;
    vr.raw_data.assign(value_data.begin(), value_data.begin() + data_bytes);
    vr.display_data = display_value(type, vr.raw_data, display_limit, vr.display_truncated);
    if (auto s = writer.add_registry_value(vr); !s.ok())
      return s;
    ++summary.objects;
  }

  std::vector<wchar_t> child_name(static_cast<std::size_t>(max_subkey_chars) + 2);
  for (DWORD index = 0; index < subkey_count; ++index) {
    DWORD chars = static_cast<DWORD>(child_name.size());
    FILETIME child_write{};
    LSTATUS rc = RegEnumKeyExW(
        key.get(), index, child_name.data(), &chars, nullptr, nullptr, nullptr, &child_write);
    if (rc == ERROR_MORE_DATA) {
      child_name.resize(static_cast<std::size_t>(chars) + 2);
      chars = static_cast<DWORD>(child_name.size());
      rc = RegEnumKeyExW(
          key.get(), index, child_name.data(), &chars, nullptr, nullptr, nullptr, &child_write);
    }
    if (rc != ERROR_SUCCESS) {
      if (auto s = record_error(
              writer,
              snapshot_id,
              win_error("enumerate subkey", key_display(scope, relative_path), rc),
              summary);
          !s.ok())
        return s;
      continue;
    }
    std::string child = std::string(relative_path);
    if (!child.empty())
      child.push_back('\\');
    child += utf8_from_wide(std::wstring_view(child_name.data(), chars));
    children.push_back(std::move(child));
  }
  return Status::success();
}
} // namespace

Result<ScanSummary> scan_registry(SnapshotStore& store,
                                  std::string_view snapshot_id,
                                  const RegistryScanOptions& options,
                                  const CancellationToken& cancel,
                                  ProgressCallback progress) {
  if (options.scopes.empty()) {
    Error e;
    e.component = "Registry";
    e.operation = "scan";
    e.message = "No Registry scopes were selected.";
    return Result<ScanSummary>::failure(std::move(e));
  }
  auto writer_result = SnapshotBatchWriter::create(store, options.batch_size);
  if (!writer_result.ok())
    return Result<ScanSummary>::failure(writer_result.error());
  auto writer = std::move(writer_result.value());
  ScanSummary summary;
  const auto started = std::chrono::steady_clock::now();
  for (const auto& scope : options.scopes) {
    if (!hive_handle(scope.hive)) {
      Error e;
      e.component = "Registry";
      e.operation = "scan";
      e.source = scope.hive;
      e.message = "Unsupported hive.";
      return Result<ScanSummary>::failure(std::move(e));
    }
    for (const auto view : expand_views(scope.view)) {
      std::vector<std::string> stack{scope.subkey};
      while (!stack.empty()) {
        if (cancel.is_cancelled()) {
          summary.cancelled = true;
          break;
        }
        auto current = std::move(stack.back());
        stack.pop_back();
        std::vector<std::string> children;
        auto status = enumerate_key(
            writer, snapshot_id, scope, view, current, children, options.display_limit, summary);
        if (!status.ok())
          return Result<ScanSummary>::failure(status.error());
        for (auto& child : children)
          stack.push_back(std::move(child));
        if (progress && (summary.objects % 250 == 0 || stack.empty())) {
          const auto seconds =
              std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
          progress(
              ProgressEvent{"registry-scan",
                            scope.hive + "[" + to_string(view) + "]" + (current.empty() ? std::string() : "\\" + current),
                            summary.objects,
                            summary.errors,
                            seconds,
                            seconds > 0 ? static_cast<double>(summary.objects) / seconds : 0.0});
        }
      }
      if (summary.cancelled)
        break;
    }
    if (summary.cancelled)
      break;
  }
  auto finished = writer.finish();
  if (!finished.ok())
    return Result<ScanSummary>::failure(finished.error());
  return Result<ScanSummary>::success(summary);
}
} // namespace support_assist
