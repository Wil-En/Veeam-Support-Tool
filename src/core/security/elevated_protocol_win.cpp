#include "support_assist/elevated.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

namespace support_assist::elevated_protocol {
namespace {

Error protocol_error(std::string operation, DWORD code, std::string message) {
  Error error;
  error.component = "ElevatedProtocol";
  error.operation = std::move(operation);
  error.native_code = code;
  error.message = std::move(message);
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

Status write_all(HANDLE handle, const void* data, std::size_t bytes) {
  const auto* cursor = static_cast<const std::byte*>(data);
  while (bytes > 0) {
    const DWORD chunk =
        static_cast<DWORD>(std::min<std::size_t>(bytes, std::numeric_limits<DWORD>::max()));
    DWORD written = 0;
    if (!WriteFile(handle, cursor, chunk, &written, nullptr)) {
      return Status::failure(protocol_error("WriteFile", GetLastError(), "IPC write failed"));
    }
    if (written == 0) {
      return Status::failure(
          protocol_error("WriteFile", ERROR_WRITE_FAULT, "IPC write made no progress"));
    }
    cursor += written;
    bytes -= written;
  }
  return Status::success();
}

Status read_all(HANDLE handle, void* data, std::size_t bytes) {
  auto* cursor = static_cast<std::byte*>(data);
  while (bytes > 0) {
    const DWORD chunk =
        static_cast<DWORD>(std::min<std::size_t>(bytes, std::numeric_limits<DWORD>::max()));
    DWORD read = 0;
    if (!ReadFile(handle, cursor, chunk, &read, nullptr)) {
      return Status::failure(protocol_error("ReadFile", GetLastError(), "IPC read failed"));
    }
    if (read == 0) {
      return Status::failure(protocol_error("ReadFile", ERROR_HANDLE_EOF, "IPC peer closed early"));
    }
    cursor += read;
    bytes -= read;
  }
  return Status::success();
}

template <typename T> Status write_scalar(HANDLE handle, T value) {
  static_assert(std::is_integral_v<T> || std::is_enum_v<T>);
  return write_all(handle, &value, sizeof(value));
}

template <typename T> Result<T> read_scalar(HANDLE handle) {
  static_assert(std::is_integral_v<T> || std::is_enum_v<T>);
  T value{};
  auto status = read_all(handle, &value, sizeof(value));
  if (!status.ok())
    return Result<T>::failure(status.error());
  return Result<T>::success(value);
}

Status write_string(HANDLE handle, std::string_view value) {
  if (value.size() > kMaximumStringBytes) {
    return Status::failure(protocol_error(
        "serialize string", ERROR_BUFFER_OVERFLOW, "IPC string exceeds protocol limit"));
  }
  if (auto status = write_scalar(handle, static_cast<std::uint32_t>(value.size())); !status.ok()) {
    return status;
  }
  return write_all(handle, value.data(), value.size());
}

Result<std::string> read_string(HANDLE handle) {
  auto length = read_scalar<std::uint32_t>(handle);
  if (!length.ok())
    return Result<std::string>::failure(length.error());
  if (length.value() > kMaximumStringBytes) {
    return Result<std::string>::failure(protocol_error(
        "deserialize string", ERROR_BUFFER_OVERFLOW, "IPC string exceeds protocol limit"));
  }
  std::string value(length.value(), '\0');
  auto status = read_all(handle, value.data(), value.size());
  if (!status.ok())
    return Result<std::string>::failure(status.error());
  return Result<std::string>::success(std::move(value));
}

Status write_writer(HANDLE handle, const VssWriterInfo& writer) {
  for (const auto value : {std::string_view(writer.writer_class_id),
                           std::string_view(writer.writer_instance_id),
                           std::string_view(writer.name),
                           std::string_view(writer.state_name)}) {
    if (auto status = write_string(handle, value); !status.ok())
      return status;
  }
  if (auto status = write_scalar(handle, static_cast<std::int32_t>(writer.state)); !status.ok())
    return status;
  if (auto status = write_scalar(handle, writer.failure_hresult); !status.ok())
    return status;
  return write_scalar(handle, static_cast<std::uint8_t>(writer.selected ? 1 : 0));
}

Result<VssWriterInfo> read_writer(HANDLE handle) {
  VssWriterInfo writer;
  auto class_id = read_string(handle);
  if (!class_id.ok())
    return Result<VssWriterInfo>::failure(class_id.error());
  auto instance_id = read_string(handle);
  if (!instance_id.ok())
    return Result<VssWriterInfo>::failure(instance_id.error());
  auto name = read_string(handle);
  if (!name.ok())
    return Result<VssWriterInfo>::failure(name.error());
  auto state_name = read_string(handle);
  if (!state_name.ok())
    return Result<VssWriterInfo>::failure(state_name.error());
  auto state = read_scalar<std::int32_t>(handle);
  if (!state.ok())
    return Result<VssWriterInfo>::failure(state.error());
  auto failure = read_scalar<std::int64_t>(handle);
  if (!failure.ok())
    return Result<VssWriterInfo>::failure(failure.error());
  auto selected = read_scalar<std::uint8_t>(handle);
  if (!selected.ok())
    return Result<VssWriterInfo>::failure(selected.error());
  writer.writer_class_id = std::move(class_id.value());
  writer.writer_instance_id = std::move(instance_id.value());
  writer.name = std::move(name.value());
  writer.state_name = std::move(state_name.value());
  writer.state = state.value();
  writer.failure_hresult = failure.value();
  writer.selected = selected.value() != 0;
  return Result<VssWriterInfo>::success(std::move(writer));
}

Status write_snapshot(HANDLE handle, const VssSnapshotInfo& snapshot) {
  for (const auto value : {std::string_view(snapshot.snapshot_id),
                           std::string_view(snapshot.snapshot_set_id),
                           std::string_view(snapshot.original_volume),
                           std::string_view(snapshot.device_object),
                           std::string_view(snapshot.provider_id),
                           std::string_view(snapshot.status)}) {
    if (auto status = write_string(handle, value); !status.ok())
      return status;
  }
  return write_scalar(handle, snapshot.attributes);
}

Result<VssSnapshotInfo> read_snapshot(HANDLE handle) {
  VssSnapshotInfo snapshot;
  auto snapshot_id = read_string(handle);
  if (!snapshot_id.ok())
    return Result<VssSnapshotInfo>::failure(snapshot_id.error());
  auto set_id = read_string(handle);
  if (!set_id.ok())
    return Result<VssSnapshotInfo>::failure(set_id.error());
  auto volume = read_string(handle);
  if (!volume.ok())
    return Result<VssSnapshotInfo>::failure(volume.error());
  auto device = read_string(handle);
  if (!device.ok())
    return Result<VssSnapshotInfo>::failure(device.error());
  auto provider = read_string(handle);
  if (!provider.ok())
    return Result<VssSnapshotInfo>::failure(provider.error());
  auto status = read_string(handle);
  if (!status.ok())
    return Result<VssSnapshotInfo>::failure(status.error());
  auto attributes = read_scalar<std::uint32_t>(handle);
  if (!attributes.ok())
    return Result<VssSnapshotInfo>::failure(attributes.error());
  snapshot.snapshot_id = std::move(snapshot_id.value());
  snapshot.snapshot_set_id = std::move(set_id.value());
  snapshot.original_volume = std::move(volume.value());
  snapshot.device_object = std::move(device.value());
  snapshot.provider_id = std::move(provider.value());
  snapshot.status = std::move(status.value());
  snapshot.attributes = attributes.value();
  return Result<VssSnapshotInfo>::success(std::move(snapshot));
}

Status write_details(HANDLE handle, const VssSessionDetails& details) {
  for (const auto value : {std::string_view(details.session_id),
                           std::string_view(details.snapshot_set_id),
                           std::string_view(details.started_utc),
                           std::string_view(details.released_utc),
                           std::string_view(details.consistency_label),
                           std::string_view(details.windows_product_type),
                           std::string_view(details.context_description)}) {
    if (auto status = write_string(handle, value); !status.ok())
      return status;
  }
  if (auto status = write_scalar(handle, static_cast<std::uint32_t>(details.backup_type));
      !status.ok())
    return status;
  if (auto status = write_scalar(handle, static_cast<std::uint8_t>(details.component_mode ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(handle, details.context); !status.ok())
    return status;
  if (auto status = write_scalar(handle, static_cast<std::uint8_t>(details.active ? 1 : 0));
      !status.ok())
    return status;
  if (auto status =
          write_scalar(handle, static_cast<std::uint8_t>(details.cleanup_succeeded ? 1 : 0));
      !status.ok())
    return status;
  if (auto status =
          write_scalar(handle, static_cast<std::uint8_t>(details.cleanup_verified ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(handle, details.cleanup_deleted_snapshots); !status.ok())
    return status;
  if (auto status = write_scalar(handle, details.cleanup_verification_seconds); !status.ok())
    return status;
  if (auto status = write_scalar(handle, details.cleanup_remaining_snapshots); !status.ok())
    return status;
  if (details.writers.size() > kMaximumWriters || details.snapshots.size() > kMaximumVolumes) {
    return Status::failure(protocol_error(
        "serialize details", ERROR_BUFFER_OVERFLOW, "VSS response exceeds protocol count limit"));
  }
  if (auto status = write_scalar(handle, static_cast<std::uint32_t>(details.writers.size()));
      !status.ok())
    return status;
  for (const auto& writer : details.writers)
    if (auto status = write_writer(handle, writer); !status.ok())
      return status;
  if (auto status = write_scalar(handle, static_cast<std::uint32_t>(details.snapshots.size()));
      !status.ok())
    return status;
  for (const auto& snapshot : details.snapshots)
    if (auto status = write_snapshot(handle, snapshot); !status.ok())
      return status;
  return Status::success();
}

Result<VssSessionDetails> read_details(HANDLE handle) {
  VssSessionDetails details;
  auto session_id = read_string(handle);
  if (!session_id.ok())
    return Result<VssSessionDetails>::failure(session_id.error());
  auto set_id = read_string(handle);
  if (!set_id.ok())
    return Result<VssSessionDetails>::failure(set_id.error());
  auto started = read_string(handle);
  if (!started.ok())
    return Result<VssSessionDetails>::failure(started.error());
  auto released = read_string(handle);
  if (!released.ok())
    return Result<VssSessionDetails>::failure(released.error());
  auto label = read_string(handle);
  if (!label.ok())
    return Result<VssSessionDetails>::failure(label.error());
  auto product_type = read_string(handle);
  if (!product_type.ok())
    return Result<VssSessionDetails>::failure(product_type.error());
  auto context_description = read_string(handle);
  if (!context_description.ok())
    return Result<VssSessionDetails>::failure(context_description.error());
  auto backup_type = read_scalar<std::uint32_t>(handle);
  if (!backup_type.ok())
    return Result<VssSessionDetails>::failure(backup_type.error());
  auto component = read_scalar<std::uint8_t>(handle);
  if (!component.ok())
    return Result<VssSessionDetails>::failure(component.error());
  auto context = read_scalar<std::int32_t>(handle);
  if (!context.ok())
    return Result<VssSessionDetails>::failure(context.error());
  auto active = read_scalar<std::uint8_t>(handle);
  if (!active.ok())
    return Result<VssSessionDetails>::failure(active.error());
  auto cleanup = read_scalar<std::uint8_t>(handle);
  if (!cleanup.ok())
    return Result<VssSessionDetails>::failure(cleanup.error());
  auto cleanup_verified = read_scalar<std::uint8_t>(handle);
  if (!cleanup_verified.ok())
    return Result<VssSessionDetails>::failure(cleanup_verified.error());
  auto deleted = read_scalar<std::uint32_t>(handle);
  if (!deleted.ok())
    return Result<VssSessionDetails>::failure(deleted.error());
  auto verification_seconds = read_scalar<std::uint32_t>(handle);
  if (!verification_seconds.ok())
    return Result<VssSessionDetails>::failure(verification_seconds.error());
  auto remaining_snapshots = read_scalar<std::uint32_t>(handle);
  if (!remaining_snapshots.ok())
    return Result<VssSessionDetails>::failure(remaining_snapshots.error());
  auto writer_count = read_scalar<std::uint32_t>(handle);
  if (!writer_count.ok())
    return Result<VssSessionDetails>::failure(writer_count.error());
  if (writer_count.value() > kMaximumWriters)
    return Result<VssSessionDetails>::failure(
        protocol_error("read writers", ERROR_BUFFER_OVERFLOW, "Writer count exceeds limit"));
  details.writers.reserve(writer_count.value());
  for (std::uint32_t i = 0; i < writer_count.value(); ++i) {
    auto writer = read_writer(handle);
    if (!writer.ok())
      return Result<VssSessionDetails>::failure(writer.error());
    details.writers.push_back(std::move(writer.value()));
  }
  auto snapshot_count = read_scalar<std::uint32_t>(handle);
  if (!snapshot_count.ok())
    return Result<VssSessionDetails>::failure(snapshot_count.error());
  if (snapshot_count.value() > kMaximumVolumes)
    return Result<VssSessionDetails>::failure(
        protocol_error("read snapshots", ERROR_BUFFER_OVERFLOW, "Snapshot count exceeds limit"));
  details.snapshots.reserve(snapshot_count.value());
  for (std::uint32_t i = 0; i < snapshot_count.value(); ++i) {
    auto snapshot = read_snapshot(handle);
    if (!snapshot.ok())
      return Result<VssSessionDetails>::failure(snapshot.error());
    details.snapshots.push_back(std::move(snapshot.value()));
  }
  details.session_id = std::move(session_id.value());
  details.snapshot_set_id = std::move(set_id.value());
  details.started_utc = std::move(started.value());
  details.released_utc = std::move(released.value());
  details.consistency_label = std::move(label.value());
  details.windows_product_type = std::move(product_type.value());
  details.context_description = std::move(context_description.value());
  details.backup_type = static_cast<VssBackupType>(backup_type.value());
  details.component_mode = component.value() != 0;
  details.context = context.value();
  details.active = active.value() != 0;
  details.cleanup_succeeded = cleanup.value() != 0;
  details.cleanup_verified = cleanup_verified.value() != 0;
  details.cleanup_deleted_snapshots = deleted.value();
  details.cleanup_verification_seconds = verification_seconds.value();
  details.cleanup_remaining_snapshots = remaining_snapshots.value();
  return Result<VssSessionDetails>::success(std::move(details));
}

} // namespace

Status write_request(void* raw_handle, const Request& request) {
  const HANDLE handle = static_cast<HANDLE>(raw_handle);
  if (request.options.volumes.size() > kMaximumVolumes ||
      request.options.enabled_writer_class_ids.size() > kMaximumWriters) {
    return Status::failure(protocol_error(
        "write request", ERROR_BUFFER_OVERFLOW, "Request exceeds protocol count limit"));
  }
  if (auto status = write_scalar(handle, kMagic); !status.ok())
    return status;
  if (auto status = write_scalar(handle, kProtocolVersion); !status.ok())
    return status;
  const std::uint32_t command = request.command != 0U        ? request.command
                                : request.writer_health_only ? kCommandVssWriterHealth
                                                             : kCommandVssTest;
  if (auto status = write_scalar(handle, command); !status.ok())
    return status;
  if (auto status = write_string(handle, request.nonce); !status.ok())
    return status;
  if (command == kCommandUniversalCollection)
    return write_string(handle, request.collection_options);
  if (command == kCommandFilesCapture) {
    for (const auto value : {std::string_view(request.files_root), std::string_view(request.files_output),
                             std::string_view(request.files_hash), std::string_view(request.files_options_json)}) {
      if (auto status = write_string(handle, value); !status.ok())
        return status;
    }
    return write_scalar(handle, static_cast<std::uint8_t>(request.files_streams ? 1 : 0));
  }
  if (command == kCommandPacketCaptureStart || command == kCommandPacketCaptureStop) {
    for (const auto value : {std::string_view(request.capture_output), std::string_view(request.capture_state),
                             std::string_view(request.capture_backend), std::string_view(request.capture_ip_filter)}) {
      if (auto status = write_string(handle, value); !status.ok())
        return status;
    }
    return write_scalar(handle, request.capture_port);
  }
  if (auto status = write_scalar(handle, static_cast<std::uint32_t>(request.options.backup_type));
      !status.ok())
    return status;
  if (auto status =
          write_scalar(handle, static_cast<std::uint8_t>(request.options.component_mode ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(
          handle, static_cast<std::uint8_t>(request.options.select_all_components ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(
          handle, static_cast<std::uint8_t>(request.options.backup_bootable_system_state ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(
          handle, static_cast<std::uint8_t>(request.options.partial_file_support ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(handle, request.options.context); !status.ok())
    return status;
  if (auto status = write_scalar(handle, request.options.hold_seconds); !status.ok())
    return status;
  if (auto status =
          write_scalar(handle, static_cast<std::uint32_t>(request.options.volumes.size()));
      !status.ok())
    return status;
  for (const auto& volume : request.options.volumes)
    if (auto status = write_string(handle, volume); !status.ok())
      return status;
  if (auto status = write_scalar(
          handle, static_cast<std::uint32_t>(request.options.enabled_writer_class_ids.size()));
      !status.ok())
    return status;
  for (const auto& writer : request.options.enabled_writer_class_ids)
    if (auto status = write_string(handle, writer); !status.ok())
      return status;
  return Status::success();
}

Result<Request> read_request(void* raw_handle) {
  const HANDLE handle = static_cast<HANDLE>(raw_handle);
  auto magic = read_scalar<std::uint32_t>(handle);
  if (!magic.ok())
    return Result<Request>::failure(magic.error());
  auto version = read_scalar<std::uint32_t>(handle);
  if (!version.ok())
    return Result<Request>::failure(version.error());
  auto command = read_scalar<std::uint32_t>(handle);
  if (!command.ok())
    return Result<Request>::failure(command.error());
  if (magic.value() != kMagic || version.value() != kProtocolVersion ||
      command.value() < kCommandVssTest || command.value() > kCommandFilesCapture) {
    return Result<Request>::failure(protocol_error(
        "read request", ERROR_REVISION_MISMATCH, "Unsupported elevated-helper protocol"));
  }
  Request request;
  request.writer_health_only = command.value() == kCommandVssWriterHealth;
  auto nonce = read_string(handle);
  if (!nonce.ok())
    return Result<Request>::failure(nonce.error());
  if (command.value() == kCommandUniversalCollection) {
    request.command = command.value();
    request.nonce = std::move(nonce.value());
    auto options = read_string(handle);
    if (!options.ok())
      return Result<Request>::failure(options.error());
    request.collection_options = std::move(options.value());
    return Result<Request>::success(std::move(request));
  }
  if (command.value() == kCommandFilesCapture) {
    request.command = command.value();
    request.nonce = std::move(nonce.value());
    for (std::string* field :
         {&request.files_root, &request.files_output, &request.files_hash, &request.files_options_json}) {
      auto value = read_string(handle);
      if (!value.ok())
        return Result<Request>::failure(value.error());
      *field = std::move(value.value());
    }
    auto streams = read_scalar<std::uint8_t>(handle);
    if (!streams.ok())
      return Result<Request>::failure(streams.error());
    request.files_streams = streams.value() != 0U;
    return Result<Request>::success(std::move(request));
  }
  if (command.value() == kCommandPacketCaptureStart || command.value() == kCommandPacketCaptureStop) {
    request.command = command.value();
    request.nonce = std::move(nonce.value());
    for (std::string* field : {&request.capture_output, &request.capture_state, &request.capture_backend,
                               &request.capture_ip_filter}) {
      auto value = read_string(handle);
      if (!value.ok())
        return Result<Request>::failure(value.error());
      *field = std::move(value.value());
    }
    auto port = read_scalar<std::uint32_t>(handle);
    if (!port.ok())
      return Result<Request>::failure(port.error());
    request.capture_port = port.value();
    return Result<Request>::success(std::move(request));
  }
  auto backup_type = read_scalar<std::uint32_t>(handle);
  if (!backup_type.ok())
    return Result<Request>::failure(backup_type.error());
  auto component = read_scalar<std::uint8_t>(handle);
  if (!component.ok())
    return Result<Request>::failure(component.error());
  auto select_all = read_scalar<std::uint8_t>(handle);
  if (!select_all.ok())
    return Result<Request>::failure(select_all.error());
  auto bootable = read_scalar<std::uint8_t>(handle);
  if (!bootable.ok())
    return Result<Request>::failure(bootable.error());
  auto partial = read_scalar<std::uint8_t>(handle);
  if (!partial.ok())
    return Result<Request>::failure(partial.error());
  auto context = read_scalar<std::int32_t>(handle);
  if (!context.ok())
    return Result<Request>::failure(context.error());
  auto hold = read_scalar<std::uint32_t>(handle);
  if (!hold.ok())
    return Result<Request>::failure(hold.error());
  auto volume_count = read_scalar<std::uint32_t>(handle);
  if (!volume_count.ok())
    return Result<Request>::failure(volume_count.error());
  if (volume_count.value() > kMaximumVolumes)
    return Result<Request>::failure(
        protocol_error("read request", ERROR_BUFFER_OVERFLOW, "Volume count exceeds limit"));
  request.options.volumes.reserve(volume_count.value());
  for (std::uint32_t i = 0; i < volume_count.value(); ++i) {
    auto volume = read_string(handle);
    if (!volume.ok())
      return Result<Request>::failure(volume.error());
    request.options.volumes.push_back(std::move(volume.value()));
  }
  auto writer_count = read_scalar<std::uint32_t>(handle);
  if (!writer_count.ok())
    return Result<Request>::failure(writer_count.error());
  if (writer_count.value() > kMaximumWriters)
    return Result<Request>::failure(
        protocol_error("read request", ERROR_BUFFER_OVERFLOW, "Writer count exceeds limit"));
  request.options.enabled_writer_class_ids.reserve(writer_count.value());
  for (std::uint32_t i = 0; i < writer_count.value(); ++i) {
    auto writer = read_string(handle);
    if (!writer.ok())
      return Result<Request>::failure(writer.error());
    request.options.enabled_writer_class_ids.push_back(std::move(writer.value()));
  }
  request.nonce = std::move(nonce.value());
  request.options.backup_type = static_cast<VssBackupType>(backup_type.value());
  request.options.component_mode = component.value() != 0;
  request.options.select_all_components = select_all.value() != 0;
  request.options.backup_bootable_system_state = bootable.value() != 0;
  request.options.partial_file_support = partial.value() != 0;
  request.options.context = context.value();
  request.options.hold_seconds = hold.value();
  return Result<Request>::success(std::move(request));
}

Status write_response(void* raw_handle, const Response& response) {
  const HANDLE handle = static_cast<HANDLE>(raw_handle);
  if (auto status = write_scalar(handle, kMagic); !status.ok())
    return status;
  if (auto status = write_scalar(handle, kProtocolVersion); !status.ok())
    return status;
  if (auto status = write_scalar(handle, static_cast<std::uint8_t>(response.final ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_scalar(handle, static_cast<std::uint8_t>(response.success ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_string(handle, response.phase); !status.ok())
    return status;
  if (auto status = write_string(handle, response.current_scope); !status.ok())
    return status;
  if (auto status = write_scalar(handle, response.current); !status.ok())
    return status;
  if (auto status = write_scalar(handle, response.total); !status.ok())
    return status;
  if (auto status = write_scalar(handle, response.native_code); !status.ok())
    return status;
  if (auto status = write_scalar(handle, response.hresult); !status.ok())
    return status;
  if (auto status = write_string(handle, response.message); !status.ok())
    return status;
  if (auto status =
          write_scalar(handle, static_cast<std::uint8_t>(response.result.backup_succeeded ? 1 : 0));
      !status.ok())
    return status;
  if (auto status = write_string(handle, response.result.diagnostic_message); !status.ok())
    return status;
  return write_details(handle, response.result.details);
}

Result<Response> read_response(void* raw_handle) {
  const HANDLE handle = static_cast<HANDLE>(raw_handle);
  auto magic = read_scalar<std::uint32_t>(handle);
  if (!magic.ok())
    return Result<Response>::failure(magic.error());
  auto version = read_scalar<std::uint32_t>(handle);
  if (!version.ok())
    return Result<Response>::failure(version.error());
  if (magic.value() != kMagic || version.value() != kProtocolVersion) {
    return Result<Response>::failure(protocol_error(
        "read response", ERROR_REVISION_MISMATCH, "Unsupported elevated-helper response"));
  }
  auto final = read_scalar<std::uint8_t>(handle);
  if (!final.ok())
    return Result<Response>::failure(final.error());
  auto success = read_scalar<std::uint8_t>(handle);
  if (!success.ok())
    return Result<Response>::failure(success.error());
  auto phase = read_string(handle);
  if (!phase.ok())
    return Result<Response>::failure(phase.error());
  auto current_scope = read_string(handle);
  if (!current_scope.ok())
    return Result<Response>::failure(current_scope.error());
  auto current = read_scalar<std::uint64_t>(handle);
  if (!current.ok())
    return Result<Response>::failure(current.error());
  auto total = read_scalar<std::uint64_t>(handle);
  if (!total.ok())
    return Result<Response>::failure(total.error());
  auto native = read_scalar<std::int64_t>(handle);
  if (!native.ok())
    return Result<Response>::failure(native.error());
  auto hresult = read_scalar<std::int64_t>(handle);
  if (!hresult.ok())
    return Result<Response>::failure(hresult.error());
  auto message = read_string(handle);
  if (!message.ok())
    return Result<Response>::failure(message.error());
  auto backup = read_scalar<std::uint8_t>(handle);
  if (!backup.ok())
    return Result<Response>::failure(backup.error());
  auto diagnostic = read_string(handle);
  if (!diagnostic.ok())
    return Result<Response>::failure(diagnostic.error());
  auto details = read_details(handle);
  if (!details.ok())
    return Result<Response>::failure(details.error());
  Response response;
  response.final = final.value() != 0;
  response.success = success.value() != 0;
  response.phase = std::move(phase.value());
  response.current_scope = std::move(current_scope.value());
  response.current = current.value();
  response.total = total.value();
  response.native_code = native.value();
  response.hresult = hresult.value();
  response.message = std::move(message.value());
  response.result.backup_succeeded = backup.value() != 0;
  response.result.diagnostic_message = std::move(diagnostic.value());
  response.result.details = std::move(details.value());
  return Result<Response>::success(std::move(response));
}

std::string encode_universal_options(const UniversalCollectionOptions& options) {
  std::string text;
  const auto line = [&text](std::string_view key, const std::string& value) {
    text.append(key).append("=").append(value).append("\n");
  };
  const auto flag = [](bool value) { return std::string(value ? "1" : "0"); };
  line("output_root", path_to_utf8(options.output_root));
  if (options.from_utc_ms)
    line("from_utc_ms", std::to_string(*options.from_utc_ms));
  if (options.to_utc_ms)
    line("to_utc_ms", std::to_string(*options.to_utc_ms));
  line("tool_output_directory", path_to_utf8(options.tool_output_directory));
  line("include_tool_output_logs", flag(options.include_tool_output_logs));
  line("cleanup_tool_output_after_archive", flag(options.cleanup_tool_output_after_archive));
  line("sat_logs_directory", path_to_utf8(options.sat_logs_directory));
  line("include_sat_logs", flag(options.include_sat_logs));
  line("cleanup_sat_logs_after_archive", flag(options.cleanup_sat_logs_after_archive));
  line("cleanup_collection_directory_after_archive", flag(options.cleanup_collection_directory_after_archive));
  line("create_archive", flag(options.create_archive));
  line("include_third_party_error_logs", flag(options.include_third_party_error_logs));
  line("include_platform_context", flag(options.include_platform_context));
  line("include_official_product_exporters", flag(options.include_official_product_exporters));
  line("product_selection_explicit", flag(options.product_selection_explicit));
  for (const auto& product : options.selected_product_ids)
    line("product", product);
  for (const auto& source : options.additional_sources)
    line("source", path_to_utf8(source));
  return text;
}

UniversalCollectionOptions decode_universal_options(std::string_view text) {
  UniversalCollectionOptions options;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos)
      end = text.size();
    const std::string_view line = text.substr(start, end - start);
    start = end + 1U;
    const std::size_t split = line.find('=');
    if (split == std::string_view::npos)
      continue;
    const std::string_view key = line.substr(0, split);
    const std::string value(line.substr(split + 1U));
    const bool on = value == "1";
    const auto number = [&value]() -> std::optional<std::int64_t> {
      try {
        return std::stoll(value);
      } catch (...) {
        return std::nullopt;
      }
    };
    if (key == "output_root") options.output_root = path_from_utf8(value);
    else if (key == "from_utc_ms") options.from_utc_ms = number();
    else if (key == "to_utc_ms") options.to_utc_ms = number();
    else if (key == "tool_output_directory") options.tool_output_directory = path_from_utf8(value);
    else if (key == "include_tool_output_logs") options.include_tool_output_logs = on;
    else if (key == "cleanup_tool_output_after_archive") options.cleanup_tool_output_after_archive = on;
    else if (key == "sat_logs_directory") options.sat_logs_directory = path_from_utf8(value);
    else if (key == "include_sat_logs") options.include_sat_logs = on;
    else if (key == "cleanup_sat_logs_after_archive") options.cleanup_sat_logs_after_archive = on;
    else if (key == "cleanup_collection_directory_after_archive") options.cleanup_collection_directory_after_archive = on;
    else if (key == "create_archive") options.create_archive = on;
    else if (key == "include_third_party_error_logs") options.include_third_party_error_logs = on;
    else if (key == "include_platform_context") options.include_platform_context = on;
    else if (key == "include_official_product_exporters") options.include_official_product_exporters = on;
    else if (key == "product_selection_explicit") options.product_selection_explicit = on;
    else if (key == "product") options.selected_product_ids.push_back(value);
    else if (key == "source") options.additional_sources.push_back(path_from_utf8(value));
  }
  return options;
}

std::string encode_rows(const std::vector<std::array<std::string, 4>>& rows) {
  std::string text;
  for (const auto& row : rows) {
    for (std::size_t cell = 0; cell < row.size(); ++cell) {
      if (cell != 0U)
        text += '\t';
      for (const char c : row[cell])
        text += (c == '\t' || c == '\n' || c == '\r') ? ' ' : c;
    }
    text += '\n';
  }
  return text;
}

std::vector<std::array<std::string, 4>> decode_rows(std::string_view text) {
  std::vector<std::array<std::string, 4>> rows;
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos)
      end = text.size();
    const std::string_view line = text.substr(start, end - start);
    start = end + 1U;
    if (line.empty())
      continue;
    std::array<std::string, 4> row;
    std::size_t from = 0;
    for (std::size_t cell = 0; cell < row.size(); ++cell) {
      const std::size_t tab = cell + 1U < row.size() ? line.find('\t', from) : std::string_view::npos;
      row[cell] = std::string(line.substr(from, tab == std::string_view::npos ? std::string_view::npos : tab - from));
      if (tab == std::string_view::npos)
        break;
      from = tab + 1U;
    }
    rows.push_back(std::move(row));
  }
  return rows;
}

} // namespace support_assist::elevated_protocol
