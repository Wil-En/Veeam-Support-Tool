#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/vss.hpp"
#include "support_assist/version.hpp"

#include <windows.h>
#include <vss.h>
#include <vswriter.h>
#include <vsbackup.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

template <typename T> class ComPtr {
public:
  ComPtr() = default;
  explicit ComPtr(T* value) : value_(value) {}
  ~ComPtr() {
    reset();
  }
  ComPtr(const ComPtr&) = delete;
  ComPtr& operator=(const ComPtr&) = delete;
  ComPtr(ComPtr&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
  ComPtr& operator=(ComPtr&& other) noexcept {
    if (this != &other)
      reset(std::exchange(other.value_, nullptr));
    return *this;
  }
  T* get() const noexcept {
    return value_;
  }
  T** put() noexcept {
    reset();
    return &value_;
  }
  T* operator->() const noexcept {
    return value_;
  }
  explicit operator bool() const noexcept {
    return value_ != nullptr;
  }
  void reset(T* next = nullptr) noexcept {
    if (value_)
      value_->Release();
    value_ = next;
  }

private:
  T* value_ = nullptr;
};

class Bstr {
public:
  Bstr() = default;
  ~Bstr() {
    if (value_)
      SysFreeString(value_);
  }
  Bstr(const Bstr&) = delete;
  Bstr& operator=(const Bstr&) = delete;
  BSTR* put() noexcept {
    if (value_)
      SysFreeString(value_);
    value_ = nullptr;
    return &value_;
  }
  std::wstring_view view() const noexcept {
    return value_ ? std::wstring_view(value_, SysStringLen(value_)) : std::wstring_view{};
  }

private:
  BSTR value_ = nullptr;
};

class ComRuntime {
public:
  static Result<std::unique_ptr<ComRuntime>> create() {
    auto runtime = std::unique_ptr<ComRuntime>(new ComRuntime());
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized)) {
      return Result<std::unique_ptr<ComRuntime>>::failure(
          runtime->make_error("CoInitializeEx", initialized));
    }
    runtime->must_uninitialize_ = true;

    const HRESULT secured = CoInitializeSecurity(nullptr,
                                                 -1,
                                                 nullptr,
                                                 nullptr,
                                                 RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                                 RPC_C_IMP_LEVEL_IMPERSONATE,
                                                 nullptr,
                                                 EOAC_STATIC_CLOAKING,
                                                 nullptr);
    if (FAILED(secured) && secured != RPC_E_TOO_LATE) {
      return Result<std::unique_ptr<ComRuntime>>::failure(
          runtime->make_error("CoInitializeSecurity", secured));
    }
    return Result<std::unique_ptr<ComRuntime>>::success(std::move(runtime));
  }

  ~ComRuntime() {
    if (must_uninitialize_)
      CoUninitialize();
  }

private:
  Error make_error(std::string operation, HRESULT hr) const {
    Error error;
    error.component = "VSS";
    error.operation = std::move(operation);
    error.hresult = hr;
    error.message = "COM initialization for the VSS requester failed";
    error.elevation_may_help = hr == E_ACCESSDENIED;
    error.timestamp_utc = utc_now_iso8601();
    error.correlation_id = make_uuid_v4();
    return error;
  }
  bool must_uninitialize_ = false;
};

Error vss_error(std::string operation, HRESULT hr, std::string source = {}) {
  Error error;
  error.component = "VSS";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.hresult = hr;
  error.native_code = HRESULT_CODE(hr);
  error.elevation_may_help = hr == E_ACCESSDENIED || hr == VSS_E_INSUFFICIENT_STORAGE;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();

  wchar_t* buffer = nullptr;
  const DWORD flags =
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
  const DWORD count = FormatMessageW(flags,
                                     nullptr,
                                     static_cast<DWORD>(hr),
                                     MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                     reinterpret_cast<wchar_t*>(&buffer),
                                     0,
                                     nullptr);
  if (count != 0 && buffer) {
    std::wstring message(buffer, count);
    LocalFree(buffer);
    while (!message.empty() &&
           (message.back() == L'\r' || message.back() == L'\n' || message.back() == L' ')) {
      message.pop_back();
    }
    error.message = utf8_from_wide(message);
  } else {
    error.message = "VSS operation failed with HRESULT 0x";
    constexpr char digits[] = "0123456789ABCDEF";
    const auto value = static_cast<std::uint32_t>(hr);
    for (int shift = 28; shift >= 0; shift -= 4) {
      error.message.push_back(digits[(value >> shift) & 0x0FU]);
    }
  }
  return error;
}

std::string guid_string(REFGUID value) {
  std::array<wchar_t, 64> buffer{};
  const int written = StringFromGUID2(value, buffer.data(), static_cast<int>(buffer.size()));
  return written > 1 ? utf8_from_wide(
                           std::wstring_view(buffer.data(), static_cast<std::size_t>(written - 1)))
                     : std::string{};
}

Result<VSS_ID> parse_guid(std::string_view text) {
  const std::wstring wide = wide_from_utf8(text);
  VSS_ID id{};
  const HRESULT hr = CLSIDFromString(wide.c_str(), &id);
  if (FAILED(hr)) {
    return Result<VSS_ID>::failure(vss_error("parse writer class GUID", hr, std::string(text)));
  }
  return Result<VSS_ID>::success(id);
}

std::string writer_state_name(VSS_WRITER_STATE state) {
  switch (state) {
  case VSS_WS_UNKNOWN:
    return "unknown";
  case VSS_WS_STABLE:
    return "stable";
  case VSS_WS_WAITING_FOR_FREEZE:
    return "waiting-for-freeze";
  case VSS_WS_WAITING_FOR_THAW:
    return "waiting-for-thaw";
  case VSS_WS_WAITING_FOR_POST_SNAPSHOT:
    return "waiting-for-post-snapshot";
  case VSS_WS_WAITING_FOR_BACKUP_COMPLETE:
    return "waiting-for-backup-complete";
  case VSS_WS_FAILED_AT_IDENTIFY:
    return "failed-at-identify";
  case VSS_WS_FAILED_AT_PREPARE_BACKUP:
    return "failed-at-prepare-backup";
  case VSS_WS_FAILED_AT_PREPARE_SNAPSHOT:
    return "failed-at-prepare-snapshot";
  case VSS_WS_FAILED_AT_FREEZE:
    return "failed-at-freeze";
  case VSS_WS_FAILED_AT_THAW:
    return "failed-at-thaw";
  case VSS_WS_FAILED_AT_POST_SNAPSHOT:
    return "failed-at-post-snapshot";
  case VSS_WS_FAILED_AT_BACKUP_COMPLETE:
    return "failed-at-backup-complete";
  case VSS_WS_FAILED_AT_PRE_RESTORE:
    return "failed-at-pre-restore";
  case VSS_WS_FAILED_AT_POST_RESTORE:
    return "failed-at-post-restore";
  case VSS_WS_FAILED_AT_BACKUPSHUTDOWN:
    return "failed-at-backup-shutdown";
  }
  return "unrecognized";
}

std::string snapshot_state_name(VSS_SNAPSHOT_STATE state) {
  switch (state) {
  case VSS_SS_UNKNOWN:
    return "unknown";
  case VSS_SS_PREPARING:
    return "preparing";
  case VSS_SS_PROCESSING_PREPARE:
    return "processing-prepare";
  case VSS_SS_PREPARED:
    return "prepared";
  case VSS_SS_PROCESSING_PRECOMMIT:
    return "processing-precommit";
  case VSS_SS_PRECOMMITTED:
    return "precommitted";
  case VSS_SS_PROCESSING_COMMIT:
    return "processing-commit";
  case VSS_SS_COMMITTED:
    return "committed";
  case VSS_SS_PROCESSING_POSTCOMMIT:
    return "processing-postcommit";
  case VSS_SS_PROCESSING_PREFINALCOMMIT:
    return "processing-prefinalcommit";
  case VSS_SS_PREFINALCOMMITTED:
    return "prefinalcommitted";
  case VSS_SS_PROCESSING_POSTFINALCOMMIT:
    return "processing-postfinalcommit";
  case VSS_SS_CREATED:
    return "created";
  case VSS_SS_ABORTED:
    return "aborted";
  case VSS_SS_DELETED:
    return "deleted";
  case VSS_SS_POSTCOMMITTED:
    return "postcommitted";
  case VSS_SS_COUNT:
    return "count";
  }
  return "unrecognized";
}

Status wait_async(IVssAsync* async,
                  std::string_view operation,
                  const CancellationToken& cancel,
                  ProgressCallback progress) {
  if (!async)
    return Status::failure(vss_error(std::string(operation), E_POINTER));
  for (;;) {
    if (cancel.is_cancelled()) {
      const HRESULT cancelled = async->Cancel();
      if (FAILED(cancelled) && cancelled != VSS_E_BAD_STATE) {
        return Status::failure(vss_error(std::string(operation) + " cancel", cancelled));
      }
      return Status::failure(
          vss_error(std::string(operation), HRESULT_FROM_WIN32(ERROR_CANCELLED)));
    }

    HRESULT result = VSS_S_ASYNC_PENDING;
    INT reserved = 0;
    const HRESULT queried = async->QueryStatus(&result, &reserved);
    if (FAILED(queried))
      return Status::failure(vss_error(std::string(operation) + " status", queried));
    if (result != VSS_S_ASYNC_PENDING) {
      if (FAILED(result))
        return Status::failure(vss_error(std::string(operation), result));
      return Status::success();
    }
    if (progress)
      progress(ProgressEvent{std::string(operation), {}, 0, 0, 0.0, 0.0});
    const HRESULT waited = async->Wait(250);
    if (FAILED(waited) && waited != VSS_S_ASYNC_PENDING) {
      return Status::failure(vss_error(std::string(operation) + " wait", waited));
    }
  }
}

Result<std::wstring> canonical_volume(std::string_view input) {
  std::wstring path = wide_from_utf8(input);
  if (path.empty())
    return Result<std::wstring>::failure(vss_error("canonicalize volume", E_INVALIDARG));
  if (path.back() != L'\\')
    path.push_back(L'\\');

  std::array<wchar_t, MAX_PATH + 1> mount_point{};
  if (!GetVolumePathNameW(
          path.c_str(), mount_point.data(), static_cast<DWORD>(mount_point.size()))) {
    return Result<std::wstring>::failure(
        vss_error("GetVolumePathNameW", HRESULT_FROM_WIN32(GetLastError()), std::string(input)));
  }
  std::array<wchar_t, MAX_PATH + 1> volume_name{};
  if (!GetVolumeNameForVolumeMountPointW(
          mount_point.data(), volume_name.data(), static_cast<DWORD>(volume_name.size()))) {
    return Result<std::wstring>::failure(vss_error("GetVolumeNameForVolumeMountPointW",
                                                   HRESULT_FROM_WIN32(GetLastError()),
                                                   std::string(input)));
  }
  return Result<std::wstring>::success(std::wstring(volume_name.data()));
}

Status collect_writer_status(IVssBackupComponents* backup,
                             std::vector<VssWriterInfo>& output,
                             const CancellationToken& cancel,
                             ProgressCallback progress) {
  ComPtr<IVssAsync> async;
  HRESULT hr = backup->GatherWriterStatus(async.put());
  if (FAILED(hr))
    return Status::failure(vss_error("GatherWriterStatus", hr));
  if (auto status = wait_async(async.get(), "gather-writer-status", cancel, std::move(progress));
      !status.ok()) {
    return status;
  }

  UINT count = 0;
  hr = backup->GetWriterStatusCount(&count);
  if (FAILED(hr))
    return Status::failure(vss_error("GetWriterStatusCount", hr));
  std::vector<std::string> selected_writer_classes;
  selected_writer_classes.reserve(output.size());
  for (const auto& writer : output) {
    if (writer.selected)
      selected_writer_classes.push_back(writer.writer_class_id);
  }
  output.clear();
  output.reserve(count);
  for (UINT index = 0; index < count; ++index) {
    VSS_ID instance{};
    VSS_ID writer{};
    Bstr name;
    VSS_WRITER_STATE state = VSS_WS_UNKNOWN;
    HRESULT failure = S_OK;
    hr = backup->GetWriterStatus(index, &instance, &writer, name.put(), &state, &failure);
    if (FAILED(hr)) {
      backup->FreeWriterStatus();
      return Status::failure(vss_error("GetWriterStatus", hr));
    }
    VssWriterInfo info;
    info.writer_class_id = guid_string(writer);
    info.writer_instance_id = guid_string(instance);
    info.name = utf8_from_wide(name.view());
    info.state = static_cast<int>(state);
    info.state_name = writer_state_name(state);
    info.failure_hresult = failure;
    info.selected = std::find(selected_writer_classes.begin(),
                              selected_writer_classes.end(),
                              info.writer_class_id) != selected_writer_classes.end();
    output.push_back(std::move(info));
  }
  hr = backup->FreeWriterStatus();
  if (FAILED(hr))
    return Status::failure(vss_error("FreeWriterStatus", hr));
  return Status::success();
}

Status select_components(IVssBackupComponents* backup,
                         bool select_all,
                         std::vector<VssWriterInfo>& writers) {
  if (!select_all) {
    return Status::failure(
        vss_error("component selection",
                  E_INVALIDARG,
                  "Component mode requires --select-all-components in this implementation"));
  }

  UINT writer_count = 0;
  HRESULT hr = backup->GetWriterMetadataCount(&writer_count);
  if (FAILED(hr))
    return Status::failure(vss_error("GetWriterMetadataCount", hr));
  for (UINT writer_index = 0; writer_index < writer_count; ++writer_index) {
    VSS_ID writer_instance{};
    ComPtr<IVssExamineWriterMetadata> metadata;
    hr = backup->GetWriterMetadata(writer_index, &writer_instance, metadata.put());
    if (FAILED(hr))
      return Status::failure(vss_error("GetWriterMetadata", hr));

    VSS_ID identity_instance{};
    VSS_ID writer_class{};
    Bstr writer_name;
    VSS_USAGE_TYPE usage = VSS_UT_UNDEFINED;
    VSS_SOURCE_TYPE source = VSS_ST_UNDEFINED;
    hr = metadata->GetIdentity(
        &identity_instance, &writer_class, writer_name.put(), &usage, &source);
    if (FAILED(hr))
      return Status::failure(vss_error("writer metadata identity", hr));

    UINT include_file_count = 0;
    UINT exclude_file_count = 0;
    UINT component_count = 0;
    hr = metadata->GetFileCounts(&include_file_count, &exclude_file_count, &component_count);
    if (FAILED(hr))
      return Status::failure(vss_error("GetFileCounts", hr));
    bool selected_any = false;
    for (UINT component_index = 0; component_index < component_count; ++component_index) {
      ComPtr<IVssWMComponent> component;
      hr = metadata->GetComponent(component_index, component.put());
      if (FAILED(hr))
        return Status::failure(vss_error("GetComponent", hr));
      PVSSCOMPONENTINFO info = nullptr;
      hr = component->GetComponentInfo(&info);
      if (FAILED(hr))
        return Status::failure(vss_error("GetComponentInfo", hr));
      if (info && info->bSelectable) {
        hr = backup->AddComponent(writer_instance,
                                  writer_class,
                                  info->type,
                                  info->bstrLogicalPath,
                                  info->bstrComponentName);
        if (SUCCEEDED(hr))
          selected_any = true;
        const HRESULT freed = component->FreeComponentInfo(info);
        if (FAILED(freed))
          return Status::failure(vss_error("FreeComponentInfo", freed));
        if (FAILED(hr))
          return Status::failure(vss_error("AddComponent", hr));
      } else if (info) {
        const HRESULT freed = component->FreeComponentInfo(info);
        if (FAILED(freed))
          return Status::failure(vss_error("FreeComponentInfo", freed));
      }
    }
    if (selected_any) {
      auto found = std::find_if(writers.begin(), writers.end(), [&](const VssWriterInfo& item) {
        return item.writer_class_id == guid_string(writer_class);
      });
      if (found != writers.end())
        found->selected = true;
    }
  }
  return Status::success();
}

class SnapshotSetCleanup {
public:
  SnapshotSetCleanup(IVssBackupComponents* backup, VSS_ID snapshot_set_id)
      : backup_(backup), snapshot_set_id_(snapshot_set_id) {}
  ~SnapshotSetCleanup() {
    if (!active_ || !backup_)
      return;
    LONG deleted = 0;
    VSS_ID first_non_deleted{};
    static_cast<void>(backup_->DeleteSnapshots(
        snapshot_set_id_, VSS_OBJECT_SNAPSHOT_SET, TRUE, &deleted, &first_non_deleted));
  }
  SnapshotSetCleanup(const SnapshotSetCleanup&) = delete;
  SnapshotSetCleanup& operator=(const SnapshotSetCleanup&) = delete;
  void dismiss() noexcept {
    active_ = false;
  }

private:
  IVssBackupComponents* backup_ = nullptr;
  VSS_ID snapshot_set_id_{};
  bool active_ = true;
};

class WindowsVssSession final : public VssSession {
public:
  WindowsVssSession(std::unique_ptr<ComRuntime> runtime,
                    ComPtr<IVssBackupComponents> backup,
                    VssSessionDetails details,
                    std::vector<VSS_ID> snapshot_ids,
                    bool snapshot_created,
                    bool component_mode)
      : runtime_(std::move(runtime)), backup_(std::move(backup)), details_(std::move(details)),
        snapshot_ids_(std::move(snapshot_ids)), snapshot_created_(snapshot_created),
        component_mode_(component_mode), owning_thread_(GetCurrentThreadId()) {}

  ~WindowsVssSession() override {
    if (details_.active && GetCurrentThreadId() == owning_thread_) {
      static_cast<void>(release(false));
    }
  }

  const VssSessionDetails& details() const noexcept override {
    return details_;
  }

  Status release(bool backup_succeeded, ProgressCallback progress = {}) override {
    if (!details_.active)
      return Status::success();
    if (GetCurrentThreadId() != owning_thread_) {
      return Status::failure(
          vss_error("release VSS session",
                    RPC_E_WRONG_THREAD,
                    "The VSS session must be released on its owning requester thread"));
    }

    Error first_error;
    bool failed = false;
    if (snapshot_created_) {
      if (component_mode_) {
        // Apply the requester result to every explicitly selected component before
        // BackupComplete. Continue through all components so cleanup still runs, but
        // retain the first failure for the caller.
        UINT writer_component_count = 0;
        const HRESULT count_hr = backup_->GetWriterComponentsCount(&writer_component_count);
        if (FAILED(count_hr)) {
          first_error = vss_error("GetWriterComponentsCount", count_hr);
          failed = true;
        } else {
          for (UINT writer_index = 0; writer_index < writer_component_count; ++writer_index) {
            ComPtr<IVssWriterComponentsExt> components;
            const HRESULT components_hr =
                backup_->GetWriterComponents(writer_index, components.put());
            if (FAILED(components_hr)) {
              if (!failed)
                first_error = vss_error("GetWriterComponents", components_hr);
              failed = true;
              continue;
            }

            VSS_ID instance{};
            VSS_ID writer{};
            const HRESULT writer_info_hr = components->GetWriterInfo(&instance, &writer);
            if (FAILED(writer_info_hr)) {
              if (!failed)
                first_error = vss_error("GetWriterInfo", writer_info_hr);
              failed = true;
              continue;
            }

            UINT selected_count = 0;
            const HRESULT selected_count_hr = components->GetComponentCount(&selected_count);
            if (FAILED(selected_count_hr)) {
              if (!failed)
                first_error = vss_error("GetComponentCount", selected_count_hr);
              failed = true;
              continue;
            }

            for (UINT component_index = 0; component_index < selected_count; ++component_index) {
              ComPtr<IVssComponent> component;
              const HRESULT component_hr =
                  components->GetComponent(component_index, component.put());
              if (FAILED(component_hr)) {
                if (!failed)
                  first_error = vss_error("GetComponent", component_hr);
                failed = true;
                continue;
              }

              BSTR logical = nullptr;
              BSTR name = nullptr;
              VSS_COMPONENT_TYPE type = VSS_CT_UNDEFINED;
              const HRESULT logical_hr = component->GetLogicalPath(&logical);
              const HRESULT name_hr = component->GetComponentName(&name);
              const HRESULT type_hr = component->GetComponentType(&type);
              if (FAILED(logical_hr) || FAILED(name_hr) || FAILED(type_hr)) {
                const HRESULT component_info_hr =
                    FAILED(logical_hr) ? logical_hr : (FAILED(name_hr) ? name_hr : type_hr);
                if (!failed)
                  first_error = vss_error("read selected component identity", component_info_hr);
                failed = true;
              } else {
                const HRESULT set_hr = backup_->SetBackupSucceeded(
                    instance, writer, type, logical, name, backup_succeeded ? TRUE : FALSE);
                if (FAILED(set_hr)) {
                  if (!failed)
                    first_error = vss_error("SetBackupSucceeded", set_hr);
                  failed = true;
                }
              }
              if (logical)
                SysFreeString(logical);
              if (name)
                SysFreeString(name);
            }
          }
        }
      }

      ComPtr<IVssAsync> complete;
      const HRESULT complete_hr = backup_->BackupComplete(complete.put());
      if (SUCCEEDED(complete_hr)) {
        CancellationSource never_cancel;
        const auto complete_status =
            wait_async(complete.get(), "backup-complete", never_cancel.token(), {});
        if (!complete_status.ok() && !failed) {
          first_error = complete_status.error();
          failed = true;
        }
      } else if (!failed) {
        first_error = vss_error("BackupComplete", complete_hr);
        failed = true;
      }

      CancellationSource never_cancel_status;
      const auto final_writer_status =
          collect_writer_status(backup_.get(), details_.writers, never_cancel_status.token(), {});
      if (!final_writer_status.ok() && !failed) {
        first_error = final_writer_status.error();
        failed = true;
      }
    }

    if (progress)
      progress(ProgressEvent{"vss-cleanup-delete", "Deleting SAT-owned snapshot set", 0, 0, 0.0, 0.0, 0});
    for (auto& snapshot : details_.snapshots)
      snapshot.status = "delete-requested";

    LONG deleted = 0;
    VSS_ID first_non_deleted{};
    const HRESULT delete_hr = backup_->DeleteSnapshots(
        snapshot_set_id_, VSS_OBJECT_SNAPSHOT_SET, TRUE, &deleted, &first_non_deleted);
    if (FAILED(delete_hr) && !failed) {
      first_error = vss_error("DeleteSnapshots", delete_hr, guid_string(first_non_deleted));
      failed = true;
    }
    details_.active = false;
    details_.released_utc = utc_now_iso8601();
    details_.cleanup_deleted_snapshots = static_cast<std::uint32_t>(std::max<LONG>(0, deleted));
    details_.cleanup_succeeded = SUCCEEDED(delete_hr);

    // A successful DeleteSnapshots call is not treated as proof that the test snapshot has
    // disappeared. RC2 performs three one-second, SAT-owned-ID-only checks. This intentionally
    // never enumerates or deletes unrelated customer snapshots.
    details_.cleanup_verified = false;
    details_.cleanup_verification_seconds = 0;
    details_.cleanup_remaining_snapshots = static_cast<std::uint32_t>(snapshot_ids_.size());
    if (SUCCEEDED(delete_hr)) {
      std::uint32_t consecutive_absent_passes = 0;
      std::uint32_t remaining = static_cast<std::uint32_t>(snapshot_ids_.size());
      for (std::uint32_t pass = 1; pass <= 3; ++pass) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        remaining = 0;
        bool indeterminate = false;
        for (const auto snapshot_id : snapshot_ids_) {
          VSS_SNAPSHOT_PROP property{};
          const HRESULT query_hr = backup_->GetSnapshotProperties(snapshot_id, &property);
          if (SUCCEEDED(query_hr)) {
            ++remaining;
            VssFreeSnapshotProperties(&property);
          } else if (query_hr != VSS_E_OBJECT_NOT_FOUND) {
            indeterminate = true;
          }
        }
        details_.cleanup_verification_seconds = pass;
        details_.cleanup_remaining_snapshots = remaining;
        if (remaining == 0 && !indeterminate)
          ++consecutive_absent_passes;
        else
          consecutive_absent_passes = 0;
        if (progress) {
          progress(ProgressEvent{"vss-cleanup-verify",
                                 remaining == 0 && !indeterminate
                                     ? "SAT-owned snapshot absent"
                                     : (indeterminate ? "Snapshot state could not be verified"
                                                      : "SAT-owned snapshot still visible"),
                                 pass,
                                 indeterminate ? 1U : 0U,
                                 0.0,
                                 0.0,
                                 3});
        }
      }
      details_.cleanup_verified = consecutive_absent_passes == 3;
      for (auto& snapshot : details_.snapshots)
        snapshot.status = details_.cleanup_verified ? "cleanup-verified" : "cleanup-warning";
    } else {
      for (auto& snapshot : details_.snapshots)
        snapshot.status = "cleanup-failed";
    }

    return failed ? Status::failure(std::move(first_error)) : Status::success();
  }

  void set_snapshot_set_id(VSS_ID id) noexcept {
    snapshot_set_id_ = id;
  }

private:
  std::unique_ptr<ComRuntime> runtime_;
  ComPtr<IVssBackupComponents> backup_;
  VssSessionDetails details_;
  std::vector<VSS_ID> snapshot_ids_;
  bool snapshot_created_ = false;
  bool component_mode_ = false;
  DWORD owning_thread_ = 0;
  VSS_ID snapshot_set_id_{};
};

Result<ComPtr<IVssBackupComponents>> initialized_requester(const VssTestOptions& options,
                                                           const CancellationToken& cancel,
                                                           ProgressCallback progress,
                                                           std::vector<VssWriterInfo>& writers) {
  ComPtr<IVssBackupComponents> backup;
  HRESULT hr = CreateVssBackupComponents(backup.put());
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(
        vss_error("CreateVssBackupComponents", hr));
  hr = backup->InitializeForBackup();
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("InitializeForBackup", hr));
  hr = backup->SetContext(options.context);
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("SetContext", hr));
  hr =
      backup->SetBackupState(options.component_mode ? TRUE : FALSE,
                             options.backup_bootable_system_state ? TRUE : FALSE,
                             options.backup_type == VssBackupType::full ? VSS_BT_FULL : VSS_BT_COPY,
                             options.partial_file_support ? TRUE : FALSE);
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("SetBackupState", hr));

  if (!options.enabled_writer_class_ids.empty()) {
    std::vector<VSS_ID> ids;
    ids.reserve(options.enabled_writer_class_ids.size());
    for (const auto& text : options.enabled_writer_class_ids) {
      auto parsed = parse_guid(text);
      if (!parsed.ok())
        return Result<ComPtr<IVssBackupComponents>>::failure(parsed.error());
      ids.push_back(parsed.value());
    }
    hr = backup->EnableWriterClasses(ids.data(), static_cast<UINT>(ids.size()));
    if (FAILED(hr))
      return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("EnableWriterClasses", hr));
  }

  ComPtr<IVssAsync> gather;
  hr = backup->GatherWriterMetadata(gather.put());
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("GatherWriterMetadata", hr));
  if (auto status = wait_async(gather.get(), "gather-writer-metadata", cancel, progress);
      !status.ok()) {
    return Result<ComPtr<IVssBackupComponents>>::failure(status.error());
  }

  UINT count = 0;
  hr = backup->GetWriterMetadataCount(&count);
  if (FAILED(hr))
    return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("GetWriterMetadataCount", hr));
  writers.clear();
  writers.reserve(count);
  for (UINT index = 0; index < count; ++index) {
    VSS_ID instance{};
    ComPtr<IVssExamineWriterMetadata> metadata;
    hr = backup->GetWriterMetadata(index, &instance, metadata.put());
    if (FAILED(hr))
      return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("GetWriterMetadata", hr));
    VSS_ID identity_instance{};
    VSS_ID writer{};
    Bstr name;
    VSS_USAGE_TYPE usage = VSS_UT_UNDEFINED;
    VSS_SOURCE_TYPE source = VSS_ST_UNDEFINED;
    hr = metadata->GetIdentity(&identity_instance, &writer, name.put(), &usage, &source);
    if (FAILED(hr))
      return Result<ComPtr<IVssBackupComponents>>::failure(vss_error("GetIdentity", hr));
    VssWriterInfo info;
    info.writer_class_id = guid_string(writer);
    info.writer_instance_id = guid_string(instance);
    info.name = utf8_from_wide(name.view());
    info.selected =
        options.enabled_writer_class_ids.empty() ||
        std::any_of(options.enabled_writer_class_ids.begin(),
                    options.enabled_writer_class_ids.end(),
                    [&](const std::string& selected) {
                      auto selected_guid = parse_guid(selected);
                      return selected_guid.ok() && IsEqualGUID(selected_guid.value(), writer);
                    });
    writers.push_back(std::move(info));
  }

  if (options.component_mode) {
    if (auto status = select_components(backup.get(), options.select_all_components, writers);
        !status.ok()) {
      return Result<ComPtr<IVssBackupComponents>>::failure(status.error());
    }
  }
  return Result<ComPtr<IVssBackupComponents>>::success(std::move(backup));
}

} // namespace

std::string windows_product_type_label() {
  OSVERSIONINFOEXW version{};
  version.dwOSVersionInfoSize = sizeof(version);
  version.wProductType = VER_NT_WORKSTATION;
  DWORDLONG condition = 0;
  VER_SET_CONDITION(condition, VER_PRODUCT_TYPE, VER_EQUAL);
  if (VerifyVersionInfoW(&version, VER_PRODUCT_TYPE, condition) != FALSE)
    return "Windows client / workstation";
  const DWORD code = GetLastError();
  if (code == ERROR_OLD_WIN_VERSION)
    return "Windows Server";
  return "Windows (product type not resolved)";
}

Result<std::vector<VssWriterInfo>> enumerate_vss_writers() {
  auto runtime = ComRuntime::create();
  if (!runtime.ok())
    return Result<std::vector<VssWriterInfo>>::failure(runtime.error());
  CancellationSource cancellation;
  VssTestOptions options;
  std::vector<VssWriterInfo> writers;
  auto requester = initialized_requester(options, cancellation.token(), {}, writers);
  if (!requester.ok())
    return Result<std::vector<VssWriterInfo>>::failure(requester.error());
  auto status = collect_writer_status(requester.value().get(), writers, cancellation.token(), {});
  if (!status.ok())
    return Result<std::vector<VssWriterInfo>>::failure(status.error());
  return Result<std::vector<VssWriterInfo>>::success(std::move(writers));
}

Result<std::unique_ptr<VssSession>> create_vss_test_session(const VssTestOptions& options,
                                                            const CancellationToken& cancel,
                                                            ProgressCallback progress) {
  if (options.volumes.empty()) {
    return Result<std::unique_ptr<VssSession>>::failure(
        vss_error("create test session", E_INVALIDARG, "No volumes were selected"));
  }
  if (options.context != VSS_CTX_BACKUP) {
    return Result<std::unique_ptr<VssSession>>::failure(vss_error(
        "create test session",
        E_INVALIDARG,
        std::string(kProductName) +
        " VSS Lab currently permits only writer-participating VSS_CTX_BACKUP"));
  }

  auto runtime = ComRuntime::create();
  if (!runtime.ok())
    return Result<std::unique_ptr<VssSession>>::failure(runtime.error());

  std::vector<VssWriterInfo> writers;
  auto requester = initialized_requester(options, cancel, progress, writers);
  if (!requester.ok())
    return Result<std::unique_ptr<VssSession>>::failure(requester.error());
  ComPtr<IVssBackupComponents> backup = std::move(requester.value());

  VSS_ID set_id{};
  HRESULT hr = backup->StartSnapshotSet(&set_id);
  if (FAILED(hr))
    return Result<std::unique_ptr<VssSession>>::failure(vss_error("StartSnapshotSet", hr));
  SnapshotSetCleanup cleanup(backup.get(), set_id);

  std::vector<VSS_ID> snapshot_ids;
  std::vector<std::wstring> canonical_volumes;
  snapshot_ids.reserve(options.volumes.size());
  canonical_volumes.reserve(options.volumes.size());
  for (const auto& volume : options.volumes) {
    auto canonical = canonical_volume(volume);
    if (!canonical.ok())
      return Result<std::unique_ptr<VssSession>>::failure(canonical.error());
    BOOL supported = FALSE;
    hr = backup->IsVolumeSupported(
        GUID_NULL, const_cast<wchar_t*>(canonical.value().c_str()), &supported);
    if (FAILED(hr))
      return Result<std::unique_ptr<VssSession>>::failure(
          vss_error("IsVolumeSupported", hr, volume));
    if (!supported) {
      return Result<std::unique_ptr<VssSession>>::failure(
          vss_error("IsVolumeSupported", VSS_E_VOLUME_NOT_SUPPORTED, volume));
    }
    VSS_ID snapshot_id{};
    hr = backup->AddToSnapshotSet(
        const_cast<wchar_t*>(canonical.value().c_str()), GUID_NULL, &snapshot_id);
    if (FAILED(hr))
      return Result<std::unique_ptr<VssSession>>::failure(
          vss_error("AddToSnapshotSet", hr, volume));
    canonical_volumes.push_back(canonical.value());
    snapshot_ids.push_back(snapshot_id);
  }

  ComPtr<IVssAsync> prepare;
  hr = backup->PrepareForBackup(prepare.put());
  if (FAILED(hr))
    return Result<std::unique_ptr<VssSession>>::failure(vss_error("PrepareForBackup", hr));
  if (auto status = wait_async(prepare.get(), "prepare-for-backup", cancel, progress);
      !status.ok()) {
    return Result<std::unique_ptr<VssSession>>::failure(status.error());
  }

  ComPtr<IVssAsync> snapshot;
  hr = backup->DoSnapshotSet(snapshot.put());
  if (FAILED(hr))
    return Result<std::unique_ptr<VssSession>>::failure(vss_error("DoSnapshotSet", hr));
  if (auto status = wait_async(snapshot.get(), "create-shadow-copy", cancel, progress);
      !status.ok()) {
    return Result<std::unique_ptr<VssSession>>::failure(status.error());
  }

  auto writer_status = collect_writer_status(backup.get(), writers, cancel, progress);
  if (!writer_status.ok())
    return Result<std::unique_ptr<VssSession>>::failure(writer_status.error());
  if (progress) {
    for (const auto& writer : writers) {
      progress(ProgressEvent{"vss-writer",
                             writer.name + " | " + writer.state_name +
                                 (writer.selected ? " | selected" : " | observed"),
                             writer.selected ? 1U : 0U,
                             writer.failure_hresult == 0 ? 0U : 1U,
                             0.0,
                             0.0,
                             static_cast<std::uint64_t>(writers.size())});
    }
  }

  VssSessionDetails details;
  details.session_id = make_uuid_v4();
  details.snapshot_set_id = guid_string(set_id);
  details.started_utc = utc_now_iso8601();
  details.writers = writers;
  details.active = true;
  details.consistency_label =
      options.component_mode ? "writer-coordinated VSS requester test (component selection enabled)"
                             : "writer-coordinated VSS requester test (non-component backup mode)";
  details.windows_product_type = windows_product_type_label();
  details.context_description =
      "VSS_CTX_BACKUP - auto-release, nonpersistent shadow copy with writer participation";
  details.backup_type = options.backup_type;
  details.component_mode = options.component_mode;
  details.context = options.context;

  for (std::size_t index = 0; index < snapshot_ids.size(); ++index) {
    VSS_SNAPSHOT_PROP property{};
    hr = backup->GetSnapshotProperties(snapshot_ids[index], &property);
    if (FAILED(hr))
      return Result<std::unique_ptr<VssSession>>::failure(vss_error("GetSnapshotProperties", hr));
    VssSnapshotInfo info;
    info.snapshot_id = guid_string(property.m_SnapshotId);
    info.snapshot_set_id = guid_string(property.m_SnapshotSetId);
    info.original_volume = property.m_pwszOriginalVolumeName
                               ? utf8_from_wide(property.m_pwszOriginalVolumeName)
                               : utf8_from_wide(canonical_volumes[index]);
    info.device_object = property.m_pwszSnapshotDeviceObject
                             ? utf8_from_wide(property.m_pwszSnapshotDeviceObject)
                             : std::string{};
    info.provider_id = guid_string(property.m_ProviderId);
    info.attributes = static_cast<std::uint32_t>(property.m_lSnapshotAttributes);
    info.status = snapshot_state_name(property.m_eStatus);
    details.snapshots.push_back(std::move(info));
    VssFreeSnapshotProperties(&property);
  }

  auto session = std::make_unique<WindowsVssSession>(std::move(runtime.value()),
                                                     std::move(backup),
                                                     std::move(details),
                                                     std::move(snapshot_ids),
                                                     true,
                                                     options.component_mode);
  session->set_snapshot_set_id(set_id);
  cleanup.dismiss();
  return Result<std::unique_ptr<VssSession>>::success(std::move(session));
}

} // namespace support_assist
