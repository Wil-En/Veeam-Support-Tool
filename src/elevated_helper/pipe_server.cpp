#include "pipe_server.hpp"
#include "support_assist/elevated.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/support_tools.hpp"
#include "support_assist/universal_collection.hpp"
#include "collection_rows.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/vss.hpp"

#include <windows.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <string>
#include <thread>
#include <utility>

namespace {
class UniqueHandle {
public:
  explicit UniqueHandle(HANDLE value = INVALID_HANDLE_VALUE) : value_(value) {}
  ~UniqueHandle() {
    if (valid())
      CloseHandle(value_);
  }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;
  HANDLE get() const noexcept {
    return value_;
  }
  bool valid() const noexcept {
    return value_ != INVALID_HANDLE_VALUE && value_ != nullptr;
  }

private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

class MutexOwnership {
public:
  explicit MutexOwnership(HANDLE mutex) : mutex_(mutex) {}
  ~MutexOwnership() {
    if (mutex_ != nullptr && mutex_ != INVALID_HANDLE_VALUE)
      ReleaseMutex(mutex_);
  }
  MutexOwnership(const MutexOwnership&) = delete;
  MutexOwnership& operator=(const MutexOwnership&) = delete;
private:
  HANDLE mutex_ = nullptr;
};

support_assist::elevated_protocol::Response error_response(const support_assist::Error& error) {
  support_assist::elevated_protocol::Response response;
  response.success = false;
  response.native_code = error.native_code;
  response.hresult = error.hresult;
  response.message = support_assist::describe_error(error);
  return response;
}

support_assist::Error helper_error(std::string operation, DWORD code, std::string message) {
  support_assist::Error error;
  error.component = "ElevatedHelper";
  error.operation = std::move(operation);
  error.native_code = code;
  error.message = std::move(message);
  error.timestamp_utc = support_assist::utc_now_iso8601();
  error.correlation_id = support_assist::make_uuid_v4();
  return error;
}

// Progress messages are deliberately best-effort. If the parent disconnects while VSS is
// active, the helper must continue to the release path rather than abandoning its snapshots.
bool send_progress(HANDLE pipe,
                   std::string phase,
                   std::string scope = {},
                   std::uint64_t current = 0,
                   std::uint64_t total = 0) {
  support_assist::elevated_protocol::Response response;
  response.final = false;
  response.success = true;
  response.phase = std::move(phase);
  response.current_scope = std::move(scope);
  response.current = current;
  response.total = total;
  const auto written = support_assist::elevated_protocol::write_response(pipe, response);
  if (written.ok())
    FlushFileBuffers(pipe);
  return written.ok();
}

// The folder this SAT runs from: SAT's own folders (tool output, SAT logs) are cleaned only there.
std::filesystem::path own_folder() {
  std::wstring buffer(32768, L'\0');
  const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (length == 0 || length >= buffer.size())
    return {};
  buffer.resize(length);
  return std::filesystem::path(buffer).parent_path();
}

bool inside_folder(const std::filesystem::path& path, const std::filesystem::path& folder) {
  if (path.empty() || folder.empty() || !path.is_absolute())
    return false;
  const std::filesystem::path relative = path.lexically_normal().lexically_relative(folder.lexically_normal());
  return !relative.empty() && *relative.begin() != "..";
}

// Universal Log Collection with administrator rights, for a SAT that is not elevated: the collection
// the window runs, with its options, its progress sent as it goes and its rows as the answer.
int run_universal_collection_request(HANDLE pipe, const support_assist::elevated_protocol::Request& request) {
  namespace protocol = support_assist::elevated_protocol;
  support_assist::CancellationSource cancellation;
  auto options = protocol::decode_universal_options(request.collection_options);
  const std::filesystem::path folder = own_folder();
  if (!inside_folder(options.tool_output_directory, folder)) {
    options.tool_output_directory.clear();
    options.include_tool_output_logs = false;
    options.cleanup_tool_output_after_archive = false;
  }
  if (!inside_folder(options.sat_logs_directory, folder)) {
    options.sat_logs_directory.clear();
    options.include_sat_logs = false;
    options.cleanup_sat_logs_after_archive = false;
  }
  protocol::Response response;
  if (!options.output_root.is_absolute()) {
    response = error_response(helper_error("Universal log collection", ERROR_INVALID_PARAMETER,
                                           "The output folder is not an absolute path"));
  } else {
    const support_assist::ProgressCallback forward = [pipe, &cancellation](const support_assist::ProgressEvent& event) {
      if (!send_progress(pipe, event.phase.empty() ? "collection" : event.phase, event.current_scope, event.processed,
                         event.total))
        cancellation.cancel();
    };
    auto collected = support_assist::collect_universal_support_bundle(options, cancellation.token(), forward);
    if (!collected.ok()) {
      response = error_response(collected.error());
    } else {
      response.success = true;
      response.message = support_assist::path_to_utf8(support_assist::gui::collection_result_path(collected.value().logs));
      response.result.diagnostic_message =
          protocol::encode_rows(support_assist::gui::universal_collection_rows(collected.value()));
    }
  }
  const auto written = protocol::write_response(pipe, response);
  FlushFileBuffers(pipe);
  return written.ok() && response.success ? 0 : 70;
}

// A System Differences files capture with administrator rights, for a SAT that is not elevated: the
// capture the page takes, written to the capture file it names, its progress sent as it goes. Only a
// .satsnap file is written, and an existing file is replaced only when it is a capture file.
bool is_capture_file(const std::filesystem::path& path) {
  auto store = support_assist::SnapshotStore::open(path, true);
  return store.ok() && store.value().validate().ok();
}

int run_files_capture_request(HANDLE pipe, const support_assist::elevated_protocol::Request& request) {
  namespace protocol = support_assist::elevated_protocol;
  support_assist::CancellationSource cancellation;
  support_assist::FilesystemScanOptions options;
  options.root = support_assist::path_from_utf8(request.files_root);
  options.hash_mode = support_assist::parse_hash_mode(request.files_hash);
  options.capture_streams = request.files_streams;
  const std::filesystem::path output = support_assist::path_from_utf8(request.files_output);
  std::error_code error;
  protocol::Response response;
  const std::string extension = support_assist::ascii_lower(support_assist::path_to_utf8(output.extension()));
  if (!options.root.is_absolute() || !std::filesystem::is_directory(options.root, error)) {
    response = error_response(helper_error("Capturing", ERROR_INVALID_PARAMETER, "The folder is not an absolute path to a folder"));
  } else if (!output.is_absolute() || extension != ".satsnap") {
    response = error_response(helper_error("Capturing", ERROR_INVALID_PARAMETER, "The capture file is not an absolute path to a .satsnap file"));
  } else if (std::filesystem::exists(output, error) && !is_capture_file(output)) {
    response = error_response(helper_error("Capturing", ERROR_FILE_EXISTS, "The file is not a capture file, so it is not replaced"));
  } else {
    for (const wchar_t* suffix : {L"", L"-wal", L"-shm", L"-journal"}) {
      std::filesystem::path companion = output;
      companion += suffix;
      std::filesystem::remove(companion, error);
    }
    const support_assist::ProgressCallback forward = [pipe, &cancellation](const support_assist::ProgressEvent& event) {
      if (!send_progress(pipe, "Capturing as administrator", event.current_scope, event.processed, event.total))
        cancellation.cancel();
    };
    auto captured = support_assist::capture_filesystem_baseline(output, options, cancellation.token(), forward,
                                                                request.files_options_json);
    if (!captured.ok()) {
      response = error_response(captured.error());
    } else {
      const auto& value = captured.value();
      response.success = true;
      response.message = value.snapshot_id;
      response.result.diagnostic_message = protocol::encode_rows(
          {{"state", value.state == support_assist::SnapshotState::complete ? "complete" : "cancelled", "", ""},
           {"objects", std::to_string(value.objects), "", ""},
           {"errors", std::to_string(value.errors), "", ""},
           {"source", value.source, "", ""},
           {"note", value.source_note, "", ""}});
    }
  }
  const auto written = protocol::write_response(pipe, response);
  FlushFileBuffers(pipe);
  return written.ok() && response.success ? 0 : 70;
}

// Stops the capture a state file describes and sends the final response. After a pktmon stop it also
// writes the .pcapng and the .txt beside the ETL with pktmon.
int stop_packet_capture(HANDLE pipe, const std::filesystem::path& state_path) {
  namespace protocol = support_assist::elevated_protocol;
  support_assist::CancellationSource cancellation;
  const support_assist::ProgressCallback forward = [pipe](const support_assist::ProgressEvent& event) {
    static_cast<void>(send_progress(pipe, event.phase.empty() ? "packet-capture" : event.phase, event.current_scope));
  };
  protocol::Response response;
  auto session = support_assist::load_packet_capture_session(state_path);
  if (!session.ok()) {
    response = error_response(session.error());
  } else {
    auto stopped = support_assist::packet_capture_stop_owned(session.value(), cancellation.token(), forward);
    if (!stopped.ok()) {
      response = error_response(stopped.error());
    } else {
      response.success = true;
      response.native_code = stopped.value().exit_code;
      response.message = stopped.value().output;
      response.result.diagnostic_message = support_assist::path_to_utf8(session.value().state_path);
      if (stopped.value().exit_code == 0 && session.value().backend == support_assist::PacketCaptureBackend::pktmon) {
        std::filesystem::path pcapng = session.value().output_etl;
        pcapng.replace_extension(L".pcapng");
        static_cast<void>(support_assist::convert_packet_capture_native(session.value().output_etl, pcapng,
                                                                        cancellation.token(), forward));
        std::filesystem::path text_path = session.value().output_etl;
        text_path.replace_extension(L".txt");
        static_cast<void>(support_assist::packet_capture_text(session.value().output_etl, text_path,
                                                              cancellation.token(), forward));
      }
    }
  }
  const auto written = protocol::write_response(pipe, response);
  FlushFileBuffers(pipe);
  return written.ok() && response.success ? 0 : 70;
}

// The helper stays with a capture it started: the counts every 5 seconds as progress, until the stop
// request arrives on the same connection. If SAT exits or closes the connection, the capture keeps
// running and the helper ends.
int watch_packet_capture(HANDLE pipe, const support_assist::PacketCaptureSession& session, HANDLE parent,
                         const std::string& nonce) {
  namespace protocol = support_assist::elevated_protocol;
  support_assist::CancellationSource cancellation;
  auto next_count = std::chrono::steady_clock::now() + std::chrono::seconds(2);
  for (;;) {
    if (WaitForSingleObject(parent, 250) != WAIT_TIMEOUT)
      return 0;
    DWORD available = 0;
    if (!PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr))
      return 0;
    if (available > 0) {
      auto request = protocol::read_request(pipe);
      if (!request.ok() || request.value().nonce != nonce ||
          request.value().command != protocol::kCommandPacketCaptureStop) {
        auto response = error_response(helper_error("watch packet capture", ERROR_ACCESS_DENIED,
                                                    "Only the stop request is taken while the capture runs"));
        static_cast<void>(protocol::write_response(pipe, response));
        FlushFileBuffers(pipe);
        return 70;
      }
      return stop_packet_capture(pipe, session.state_path);
    }
    const auto now = std::chrono::steady_clock::now();
    if (now >= next_count) {
      next_count = now + std::chrono::seconds(5);
      if (!send_progress(pipe, "packet-capture-counts",
                         support_assist::packet_capture_progress_text(session, cancellation.token())))
        return 0;
    }
  }
}

// Packet capture's pktmon or netsh trace steps for a SAT that is not elevated. The ETL must be an
// absolute .etl path in an existing folder. Only Windows' own programs run here.
int run_packet_capture_request(HANDLE pipe, const support_assist::elevated_protocol::Request& request,
                               HANDLE parent, const std::string& nonce) {
  namespace protocol = support_assist::elevated_protocol;
  support_assist::CancellationSource cancellation;
  const support_assist::ProgressCallback forward = [pipe](const support_assist::ProgressEvent& event) {
    static_cast<void>(send_progress(pipe, event.phase.empty() ? "packet-capture" : event.phase, event.current_scope));
  };
  protocol::Response response;
  if (request.command == protocol::kCommandPacketCaptureStart) {
    support_assist::PacketCaptureOptions options;
    options.output_etl = support_assist::path_from_utf8(request.capture_output);
    const std::filesystem::path state_directory = support_assist::path_from_utf8(request.capture_state);
    std::error_code ignored;
    const bool folder_present = std::filesystem::is_directory(options.output_etl.parent_path(), ignored);
    if (!options.output_etl.is_absolute() || !state_directory.is_absolute() || !folder_present ||
        support_assist::ascii_lower(support_assist::path_to_utf8(options.output_etl.extension())) != ".etl") {
      response = error_response(helper_error("start packet capture", ERROR_INVALID_PARAMETER,
                                             "The capture path is not an absolute .etl path in an existing folder"));
    } else {
      options.backend = request.capture_backend == "netsh" ? support_assist::PacketCaptureBackend::netsh
                                                           : support_assist::PacketCaptureBackend::automatic;
      if (!request.capture_ip_filter.empty())
        options.ip_filter = request.capture_ip_filter;
      if (request.capture_port != 0U && request.capture_port <= 65535U)
        options.port_filter = static_cast<std::uint16_t>(request.capture_port);
      auto started =
          support_assist::packet_capture_start_owned(options, state_directory, cancellation.token(), forward);
      if (!started.ok()) {
        response = error_response(started.error());
      } else {
        // Started: the state file goes back as progress, and the helper stays with the capture.
        if (!send_progress(pipe, "packet-capture-started", support_assist::path_to_utf8(started.value().state_path)))
          return 0;
        return watch_packet_capture(pipe, started.value(), parent, nonce);
      }
    }
  } else {
    return stop_packet_capture(pipe, support_assist::path_from_utf8(request.capture_state));
  }
  const auto written = protocol::write_response(pipe, response);
  FlushFileBuffers(pipe);
  return written.ok() && response.success ? 0 : 70;
}
} // namespace

int run_elevated_pipe_client(const std::wstring& pipe_name,
                             const std::string& expected_nonce,
                             std::uint32_t parent_pid) {
  auto security = support_assist::current_security_context();
  if (!security.ok() || !security.value().elevated)
    return ERROR_ELEVATION_REQUIRED;

  UniqueHandle parent(
      OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parent_pid));
  if (!parent.valid())
    return static_cast<int>(GetLastError());

  if (!WaitNamedPipeW(pipe_name.c_str(), 30000))
    return static_cast<int>(GetLastError());
  UniqueHandle pipe(CreateFileW(pipe_name.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                nullptr));
  if (!pipe.valid())
    return static_cast<int>(GetLastError());

  ULONG server_pid = 0;
  if (!GetNamedPipeServerProcessId(pipe.get(), &server_pid) || server_pid != parent_pid) {
    return ERROR_ACCESS_DENIED;
  }

  auto request = support_assist::elevated_protocol::read_request(pipe.get());
  if (!request.ok()) {
    auto response = error_response(request.error());
    static_cast<void>(support_assist::elevated_protocol::write_response(pipe.get(), response));
    return 70;
  }
  if (request.value().nonce != expected_nonce) {
    auto response = error_response(
        helper_error("authenticate request", ERROR_ACCESS_DENIED, "The IPC nonce did not match"));
    static_cast<void>(support_assist::elevated_protocol::write_response(pipe.get(), response));
    return ERROR_ACCESS_DENIED;
  }

  if (request.value().command == support_assist::elevated_protocol::kCommandUniversalCollection)
    return run_universal_collection_request(pipe.get(), request.value());
  if (request.value().command == support_assist::elevated_protocol::kCommandFilesCapture)
    return run_files_capture_request(pipe.get(), request.value());
  if (request.value().command == support_assist::elevated_protocol::kCommandPacketCaptureStart ||
      request.value().command == support_assist::elevated_protocol::kCommandPacketCaptureStop)
    return run_packet_capture_request(pipe.get(), request.value(), parent.get(), expected_nonce);

  // Serialize privileged VSS diagnostics across SAT instances on this machine. Multiple
  // review windows remain supported; only stateful VSS requester work is single-owner.
  UniqueHandle vss_mutex(CreateMutexW(nullptr, FALSE, L"Global\\SupportAssistTool-VssDiagnosticLab"));
  if (!vss_mutex.valid()) {
    auto response = error_response(helper_error(
        "create VSS diagnostic mutex", GetLastError(), "Unable to create the machine-wide VSS diagnostic lock"));
    static_cast<void>(support_assist::elevated_protocol::write_response(pipe.get(), response));
    return 70;
  }
  const DWORD mutex_wait = WaitForSingleObject(vss_mutex.get(), 0);
  if (mutex_wait != WAIT_OBJECT_0 && mutex_wait != WAIT_ABANDONED) {
    auto response = error_response(helper_error(
        "start VSS diagnostic", ERROR_BUSY, "Another Support Assist Tool VSS diagnostic is already active on this machine"));
    static_cast<void>(support_assist::elevated_protocol::write_response(pipe.get(), response));
    return ERROR_BUSY;
  }
  MutexOwnership mutex_ownership(vss_mutex.get());

  support_assist::CancellationSource cancellation;
  send_progress(pipe.get(), "vss-helper-ready", "Elevated VSS helper authenticated");
  if (request.value().writer_health_only) {
    send_progress(pipe.get(), "vss-writers-enumerating", "Gathering VSS writer metadata and status");
    auto writers = support_assist::enumerate_vss_writers();
    support_assist::elevated_protocol::Response response;
    if (!writers.ok()) {
      response = error_response(writers.error());
    } else {
      response.success = true;
      response.message = "VSS writer health enumeration completed";
      response.result.backup_succeeded = true;
      response.result.diagnostic_message = "Native VSS writer enumeration completed in the elevated SAT helper";
      response.result.details.writers = std::move(writers.value());
    }
    const auto written = support_assist::elevated_protocol::write_response(pipe.get(), response);
    FlushFileBuffers(pipe.get());
    return written.ok() && response.success ? 0 : 70;
  }

  send_progress(pipe.get(), "vss-requester-initializing", "Initializing native writer-aware VSS requester");
  auto session = support_assist::create_vss_test_session(
      request.value().options,
      cancellation.token(),
      [&](const support_assist::ProgressEvent& event) {
        if (!send_progress(pipe.get(),
                           event.phase.empty() ? "vss-requester" : event.phase,
                           event.current_scope,
                           event.processed,
                           event.total))
          cancellation.cancel();
      });
  if (!session.ok()) {
    auto response = error_response(session.error());
    static_cast<void>(support_assist::elevated_protocol::write_response(pipe.get(), response));
    return 70;
  }

  for (const auto& snapshot : session.value()->details().snapshots) {
    send_progress(pipe.get(),
                  "vss-snapshot-active",
                  snapshot.original_volume + " | " + snapshot.device_object + " | " + snapshot.snapshot_id,
                  0,
                  request.value().options.hold_seconds);
  }

  bool parent_alive = true;
  for (std::uint32_t elapsed = 0; elapsed < request.value().options.hold_seconds; ++elapsed) {
    if (WaitForSingleObject(parent.get(), 1000) != WAIT_TIMEOUT) {
      parent_alive = false;
      break;
    }
    DWORD available = 0;
    if (!PeekNamedPipe(pipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
      const DWORD pipe_error = GetLastError();
      if (pipe_error == ERROR_BROKEN_PIPE || pipe_error == ERROR_PIPE_NOT_CONNECTED ||
          pipe_error == ERROR_NO_DATA) {
        parent_alive = false;
        break;
      }
    }
    if (parent_alive) {
      send_progress(pipe.get(),
                    "vss-hold",
                    "SAT-owned snapshot active; " +
                        std::to_string(request.value().options.hold_seconds - elapsed - 1) +
                        " second(s) remaining",
                    elapsed + 1,
                    request.value().options.hold_seconds);
    }
  }

  auto& active_session = *session.value();
  send_progress(pipe.get(),
                parent_alive ? "vss-backup-completing" : "vss-cancel-cleanup",
                parent_alive ? "Completing requester state before cleanup"
                             : "Parent cancelled/exited; releasing SAT-owned snapshots as unsuccessful");
  auto release = active_session.release(
      parent_alive,
      [&](const support_assist::ProgressEvent& event) {
        send_progress(pipe.get(),
                      event.phase.empty() ? "vss-cleanup" : event.phase,
                      event.current_scope,
                      event.processed,
                      event.total);
      });
  support_assist::elevated_protocol::Response response;
  response.result.details = active_session.details();
  response.result.backup_succeeded = parent_alive && release.ok();
  if (!release.ok()) {
    response = error_response(release.error());
    response.result.details = active_session.details();
  } else {
    response.success = true;
    response.message = active_session.details().cleanup_verified
                           ? "VSS test completed; owned snapshot cleanup was independently verified"
                           : "VSS test completed; delete returned success but cleanup verification needs review";
    response.result.diagnostic_message =
        parent_alive
            ? (active_session.details().cleanup_verified
                   ? "The configured hold period completed normally and SAT-owned snapshots remained absent for the verification window"
                   : "The configured hold period completed normally; review the cleanup verification state")
            : "The parent process exited; the helper released the snapshots as unsuccessful";
  }
  const auto written = support_assist::elevated_protocol::write_response(pipe.get(), response);
  FlushFileBuffers(pipe.get());
  return written.ok() && response.success ? 0 : 70;
}
