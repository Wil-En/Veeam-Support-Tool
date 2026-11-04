#include "support_assist/elevated.hpp"
#include "support_assist/secure_temp.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"

#include <windows.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <thread>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

class UniqueHandle {
public:
  UniqueHandle() = default;
  explicit UniqueHandle(HANDLE value) : value_(value) {}
  ~UniqueHandle() {
    if (valid())
      CloseHandle(value_);
  }
  UniqueHandle(const UniqueHandle&) = delete;
  UniqueHandle& operator=(const UniqueHandle&) = delete;
  UniqueHandle(UniqueHandle&& other) noexcept
      : value_(std::exchange(other.value_, INVALID_HANDLE_VALUE)) {}
  UniqueHandle& operator=(UniqueHandle&& other) noexcept {
    if (this != &other) {
      if (valid())
        CloseHandle(value_);
      value_ = std::exchange(other.value_, INVALID_HANDLE_VALUE);
    }
    return *this;
  }
  HANDLE get() const noexcept {
    return value_;
  }
  bool valid() const noexcept {
    return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
  }

private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

class LocalMemory {
public:
  explicit LocalMemory(void* value = nullptr) : value_(value) {}
  ~LocalMemory() {
    if (value_)
      LocalFree(value_);
  }
  LocalMemory(const LocalMemory&) = delete;
  LocalMemory& operator=(const LocalMemory&) = delete;
  void* get() const noexcept {
    return value_;
  }

private:
  void* value_ = nullptr;
};

Error client_error(std::string operation, DWORD code, std::string message) {
  Error error;
  error.component = "ElevatedClient";
  error.operation = std::move(operation);
  error.native_code = code;
  error.message = std::move(message);
  error.elevation_may_help = true;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

Result<std::wstring> current_user_sid_string() {
  HANDLE raw_token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw_token)) {
    return Result<std::wstring>::failure(client_error(
        "OpenProcessToken", GetLastError(), "Unable to inspect the current user token"));
  }
  UniqueHandle token(raw_token);
  DWORD bytes = 0;
  GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
  if (bytes == 0) {
    return Result<std::wstring>::failure(
        client_error("GetTokenInformation", GetLastError(), "Unable to size the current user SID"));
  }
  std::vector<std::byte> buffer(bytes);
  if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), bytes, &bytes)) {
    return Result<std::wstring>::failure(
        client_error("GetTokenInformation", GetLastError(), "Unable to read the current user SID"));
  }
  const auto* token_user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
  LPWSTR sid_text = nullptr;
  if (!ConvertSidToStringSidW(token_user->User.Sid, &sid_text)) {
    return Result<std::wstring>::failure(client_error(
        "ConvertSidToStringSidW", GetLastError(), "Unable to format the current user SID"));
  }
  LocalMemory memory(sid_text);
  return Result<std::wstring>::success(std::wstring(sid_text));
}

Result<std::filesystem::path> application_path() {
  std::wstring buffer(32768, L'\0');
  const DWORD written =
      GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
  if (written == 0 || written >= buffer.size()) {
    return Result<std::filesystem::path>::failure(
        client_error("GetModuleFileNameW",
                     GetLastError(),
                     "Unable to locate the " + std::string(kProductName) + " executable"));
  }
  buffer.resize(written);
  return Result<std::filesystem::path>::success(std::filesystem::path(buffer));
}

std::wstring quote_argument(std::wstring_view value) {
  std::wstring result = L"\"";
  std::size_t slash_count = 0;
  for (const wchar_t ch : value) {
    if (ch == L'\\') {
      ++slash_count;
      continue;
    }
    if (ch == L'\"') {
      result.append(slash_count * 2 + 1, L'\\');
      result.push_back(ch);
      slash_count = 0;
      continue;
    }
    result.append(slash_count, L'\\');
    slash_count = 0;
    result.push_back(ch);
  }
  result.append(slash_count * 2, L'\\');
  result.push_back(L'\"');
  return result;
}

} // namespace

namespace {
// The phase names one kind of helper request reports while it waits for approval and connects.
struct HelperPhases {
  const char* requesting;
  const char* approved;
  const char* connected;
  const char* operation;
};

// A helper connection kept after the exchange: the pipe, the helper process and the request's nonce.
struct HelperConnection {
  UniqueHandle pipe;
  UniqueHandle process;
  std::string nonce;
};

// Starts SAT's elevated helper through the administrator prompt, authenticates it over a private
// pipe, sends one request and returns its final response; progress responses go to `progress`. With
// `kept_phase`, the progress response of that phase returns instead, and the connection moves into
// `kept` for the caller to go on with.
Result<elevated_protocol::Response> exchange_with_helper(elevated_protocol::Request request,
                                                         const HelperPhases& phases,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress,
                                                         const char* kept_phase = nullptr,
                                                         HelperConnection* kept = nullptr) {
  using Exchange = Result<elevated_protocol::Response>;
  if (cancel.is_cancelled()) {
    return Exchange::failure(client_error(
        "start elevated operation", ERROR_CANCELLED, "Operation was cancelled before elevation"));
  }
  auto sid = current_user_sid_string();
  if (!sid.ok())
    return Exchange::failure(sid.error());
  // SAT-SEC-05: the nonce authenticates the privileged helper request, so it must come from the
  // operating system CSPRNG rather than std::random_device, which the standard permits to be a
  // deterministic engine. 32 bytes / 256 bits. Fail closed if the OS source is unavailable:
  // proceeding with weak randomness would silently degrade an authentication control.
  auto nonce_material = secure_random_hex(32U);
  if (!nonce_material.ok())
    return Exchange::failure(nonce_material.error());
  const std::string nonce = nonce_material.value();
  const std::wstring pipe_name =
      L"\\\\.\\pipe\\" + wide_from_utf8(kExecutableName) + L"-" +
      wide_from_utf8(make_uuid_v4());
  const std::wstring sddl = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + sid.value() + L")";
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr)) {
    return Exchange::failure(client_error(
        "build pipe ACL", GetLastError(), "Unable to build the elevated-helper pipe ACL"));
  }
  LocalMemory descriptor_memory(descriptor);
  SECURITY_ATTRIBUTES attributes{};
  attributes.nLength = sizeof(attributes);
  attributes.lpSecurityDescriptor = descriptor;
  attributes.bInheritHandle = FALSE;

  UniqueHandle pipe(CreateNamedPipeW(pipe_name.c_str(),
                                     PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT |
                                         PIPE_REJECT_REMOTE_CLIENTS,
                                     1,
                                     1024U * 1024U,
                                     1024U * 1024U,
                                     0,
                                     &attributes));
  if (!pipe.valid()) {
    return Exchange::failure(client_error(
        "CreateNamedPipeW", GetLastError(), "Unable to create the authenticated helper pipe"));
  }

  auto path = application_path();
  if (!path.ok())
    return Exchange::failure(path.error());
  const std::wstring parameters = L"--internal-elevated-helper --pipe " + quote_argument(pipe_name) + L" --nonce " +
                                  quote_argument(wide_from_utf8(nonce)) + L" --parent-pid " +
                                  std::to_wstring(GetCurrentProcessId());
  SHELLEXECUTEINFOW execute{};
  execute.cbSize = sizeof(execute);
  execute.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
  execute.lpVerb = L"runas";
  execute.lpFile = path.value().c_str();
  execute.lpParameters = parameters.c_str();
  execute.nShow = SW_HIDE;
  if (progress)
    progress(ProgressEvent{phases.requesting, "Requesting administrator approval", 0, 0, 0.0, 0.0, 0});
  // ShellExecuteEx can need COM on the calling thread, and an operation's worker has none of its own.
  const HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
  const BOOL launched = ShellExecuteExW(&execute);
  const DWORD launch_error = GetLastError();
  if (SUCCEEDED(com))
    CoUninitialize();
  if (!launched) {
    const DWORD code = launch_error;
    return Exchange::failure(
        client_error("ShellExecuteExW",
                     code,
                     code == ERROR_CANCELLED ? "Elevation was declined"
                                             : "Unable to start the elevated helper"));
  }
  UniqueHandle helper_process(execute.hProcess);
  if (progress)
    progress(ProgressEvent{phases.approved, "Administrator approval received; starting helper", 0, 0, 0.0, 0.0, 0});

  bool connected = false;
  const auto connection_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
  while (!connected) {
    if (ConnectNamedPipe(pipe.get(), nullptr)) {
      connected = true;
      break;
    }
    const DWORD connect_error = GetLastError();
    if (connect_error == ERROR_PIPE_CONNECTED) {
      connected = true;
      break;
    }
    if (connect_error != ERROR_PIPE_LISTENING && connect_error != ERROR_NO_DATA) {
      return Exchange::failure(
          client_error("ConnectNamedPipe", connect_error, "The elevated helper did not connect"));
    }
    if (cancel.is_cancelled()) {
      return Exchange::failure(
          client_error("connect elevated helper",
                       ERROR_CANCELLED,
                       "Operation was cancelled while waiting for the elevated helper"));
    }
    if (WaitForSingleObject(helper_process.get(), 0) == WAIT_OBJECT_0) {
      return Exchange::failure(
          client_error("connect elevated helper",
                       ERROR_PROCESS_ABORTED,
                       "The elevated helper exited before connecting"));
    }
    if (std::chrono::steady_clock::now() >= connection_deadline) {
      return Exchange::failure(
          client_error("connect elevated helper",
                       ERROR_TIMEOUT,
                       "Timed out waiting for the elevated helper to connect"));
    }
    Sleep(50);
  }
  DWORD blocking_mode = PIPE_READMODE_BYTE | PIPE_WAIT;
  if (!SetNamedPipeHandleState(pipe.get(), &blocking_mode, nullptr, nullptr)) {
    return Exchange::failure(
        client_error("SetNamedPipeHandleState",
                     GetLastError(),
                     "Unable to switch the helper pipe to blocking message transfer"));
  }
  ULONG client_pid = 0;
  if (!GetNamedPipeClientProcessId(pipe.get(), &client_pid)) {
    return Exchange::failure(client_error(
        "GetNamedPipeClientProcessId", GetLastError(), "Unable to authenticate helper process"));
  }
  if (client_pid != GetProcessId(helper_process.get())) {
    return Exchange::failure(
        client_error("authenticate helper",
                     ERROR_ACCESS_DENIED,
                     "Unexpected process connected to the helper pipe"));
  }

  request.nonce = nonce;
  if (auto status = elevated_protocol::write_request(pipe.get(), request); !status.ok()) {
    return Exchange::failure(status.error());
  }
  FlushFileBuffers(pipe.get());
  if (progress)
    progress(ProgressEvent{phases.connected, "Elevated helper connected and authenticated", 0, 0, 0.0, 0.0, 0});

  // Protocol v4 is a framed stream. Progress responses keep the main GUI visibly alive
  // during VSS metadata work, snapshot creation, hold, cleanup and cleanup verification.
  for (;;) {
    DWORD available = 0;
    if (!PeekNamedPipe(pipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
      return Exchange::failure(
          client_error("PeekNamedPipe", GetLastError(), "The elevated helper connection was lost"));
    }
    if (available > 0) {
      auto response = elevated_protocol::read_response(pipe.get());
      if (!response.ok())
        return Exchange::failure(response.error());
      if (!response.value().final) {
        if (kept_phase != nullptr && response.value().phase == kept_phase) {
          if (kept != nullptr) {
            kept->pipe = std::move(pipe);
            kept->process = std::move(helper_process);
            kept->nonce = nonce;
          }
          return Exchange::success(std::move(response.value()));
        }
        if (progress) {
          ProgressEvent event;
          event.phase = response.value().phase.empty() ? std::string(phases.operation) : response.value().phase;
          event.current_scope = response.value().current_scope;
          event.processed = response.value().current;
          event.total = response.value().total;
          progress(event);
        }
        continue;
      }
      if (!response.value().success) {
        Error error;
        error.component = "ElevatedHelper";
        error.operation = phases.operation;
        error.native_code = response.value().native_code;
        error.hresult = response.value().hresult;
        error.message = response.value().message;
        error.timestamp_utc = utc_now_iso8601();
        error.correlation_id = make_uuid_v4();
        return Exchange::failure(std::move(error));
      }
      return Exchange::success(std::move(response.value()));
    }
    if (cancel.is_cancelled()) {
      static_cast<void>(DisconnectNamedPipe(pipe.get()));
      static_cast<void>(WaitForSingleObject(helper_process.get(), 30000));
      return Exchange::failure(client_error(
          phases.operation,
          ERROR_CANCELLED,
          "The operation was cancelled; the helper was asked to release what it owns"));
    }
    if (WaitForSingleObject(helper_process.get(), 0) == WAIT_OBJECT_0) {
      return Exchange::failure(
          client_error(phases.operation,
                       ERROR_PROCESS_ABORTED,
                       "The elevated helper exited without returning a final response"));
    }
    Sleep(100);
  }
}

Result<ElevatedVssResult> run_elevated_vss_operation(const VssTestOptions& options,
                                                      bool writer_health_only,
                                                      const CancellationToken& cancel,
                                                      ProgressCallback progress) {
  if (options.hold_seconds > 86400U) {
    return Result<ElevatedVssResult>::failure(
        client_error("validate hold duration",
                     ERROR_INVALID_PARAMETER,
                     "The elevated helper limits one VSS hold request to 24 hours"));
  }
  elevated_protocol::Request request;
  request.options = options;
  request.writer_health_only = writer_health_only;
  const HelperPhases phases{"vss-elevation-request", "vss-elevation-approved",
                            writer_health_only ? "vss-writer-helper-connected" : "vss-helper-connected",
                            writer_health_only ? "VSS writer health" : "VSS test"};
  auto exchanged = exchange_with_helper(std::move(request), phases, cancel, std::move(progress));
  if (!exchanged.ok())
    return Result<ElevatedVssResult>::failure(exchanged.error());
  return Result<ElevatedVssResult>::success(std::move(exchanged.value().result));
}

// A capture SAT runs itself, elevated: the counts come from this process.
class LocalCaptureMonitor final : public PacketCaptureMonitor {
public:
  LocalCaptureMonitor(PacketCaptureSession session, CountsCallback on_counts)
      : session_(std::move(session)), on_counts_(std::move(on_counts)) {
    poller_ = std::jthread([this](std::stop_token stop) { poll(stop); });
  }
  ~LocalCaptureMonitor() override { end_polling(); }
  PacketCaptureSession session() const override {
    std::scoped_lock lock(mutex_);
    return session_;
  }
  std::string last_counts() const override {
    std::scoped_lock lock(mutex_);
    return last_counts_;
  }
  Result<ProcessResult> stop(const CancellationToken& cancel, ProgressCallback progress) override {
    end_polling();
    PacketCaptureSession current = session();
    auto stopped = packet_capture_stop_owned(current, cancel, std::move(progress));
    std::scoped_lock lock(mutex_);
    session_ = std::move(current);
    return stopped;
  }

private:
  void end_polling() {
    poller_.request_stop();
    if (poller_.joinable())
      poller_.join();
  }
  void poll(std::stop_token stop) {
    CancellationToken never;
    while (!stop.stop_requested()) {
      for (int tick = 0; tick < 50 && !stop.stop_requested(); ++tick)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      if (stop.stop_requested())
        return;
      const std::string counts = packet_capture_progress_text(session(), never);
      {
        std::scoped_lock lock(mutex_);
        last_counts_ = counts;
      }
      if (on_counts_)
        on_counts_(counts);
    }
  }
  mutable std::mutex mutex_;
  PacketCaptureSession session_;
  std::string last_counts_;
  CountsCallback on_counts_;
  std::jthread poller_;
};

// A capture the elevated helper holds: it sends the counts and takes the stop on the same connection.
class HelperCaptureMonitor final : public PacketCaptureMonitor {
public:
  HelperCaptureMonitor(HelperConnection connection, PacketCaptureSession session, CountsCallback on_counts)
      : connection_(std::move(connection)), session_(std::move(session)), on_counts_(std::move(on_counts)) {
    reader_ = std::jthread([this](std::stop_token stop) { read(stop); });
  }
  // Closing the connection leaves the capture running; the helper ends.
  ~HelperCaptureMonitor() override {
    reader_.request_stop();
    if (reader_.joinable())
      reader_.join();
  }
  PacketCaptureSession session() const override {
    std::scoped_lock lock(state_mutex_);
    return session_;
  }
  std::string last_counts() const override {
    std::scoped_lock lock(state_mutex_);
    return last_counts_;
  }
  Result<ProcessResult> stop(const CancellationToken& cancel, ProgressCallback progress) override {
    {
      std::scoped_lock lock(pipe_mutex_);
      if (!stop_sent_) {
        elevated_protocol::Request request;
        request.nonce = connection_.nonce;
        request.command = elevated_protocol::kCommandPacketCaptureStop;
        request.capture_state = path_to_utf8(session().state_path);
        if (auto written = elevated_protocol::write_request(connection_.pipe.get(), request); !written.ok())
          return Result<ProcessResult>::failure(written.error());
        FlushFileBuffers(connection_.pipe.get());
        stop_sent_ = true;
      }
    }
    if (progress)
      progress(ProgressEvent{"packet-capture-stopping", "Stopping the capture in the elevated helper", 0, 0, 0.0, 0.0, 0});
    std::unique_lock lock(state_mutex_);
    while (!final_) {
      if (cancel.is_cancelled())
        return Result<ProcessResult>::failure(client_error("stop packet capture", ERROR_CANCELLED,
                                                           "Stopped waiting; the helper finishes the stop on its own"));
      final_ready_.wait_for(lock, std::chrono::milliseconds(200));
    }
    auto response = std::move(*final_);
    final_.reset();
    lock.unlock();
    if (!response.ok())
      return Result<ProcessResult>::failure(response.error());
    if (!response.value().success) {
      Error error;
      error.component = "ElevatedHelper";
      error.operation = "stop packet capture";
      error.native_code = response.value().native_code;
      error.hresult = response.value().hresult;
      error.message = response.value().message;
      error.timestamp_utc = utc_now_iso8601();
      error.correlation_id = make_uuid_v4();
      return Result<ProcessResult>::failure(std::move(error));
    }
    if (auto reloaded = load_packet_capture_session(session().state_path); reloaded.ok()) {
      std::scoped_lock state(state_mutex_);
      session_ = std::move(reloaded.value());
    }
    ProcessResult result;
    result.launched = true;
    result.exit_code = static_cast<int>(response.value().native_code);
    result.output = response.value().message;
    return Result<ProcessResult>::success(std::move(result));
  }

private:
  void finish(Result<elevated_protocol::Response> outcome) {
    std::scoped_lock lock(state_mutex_);
    final_.emplace(std::move(outcome));
    final_ready_.notify_all();
  }
  void read(std::stop_token stop) {
    while (!stop.stop_requested()) {
      std::optional<Result<elevated_protocol::Response>> received;
      {
        std::scoped_lock lock(pipe_mutex_);
        DWORD available = 0;
        if (!PeekNamedPipe(connection_.pipe.get(), nullptr, 0, nullptr, &available, nullptr)) {
          finish(Result<elevated_protocol::Response>::failure(
              client_error("PeekNamedPipe", GetLastError(), "The elevated helper connection was lost")));
          return;
        }
        if (available > 0)
          received.emplace(elevated_protocol::read_response(connection_.pipe.get()));
      }
      if (received) {
        if (!received->ok() || received->value().final) {
          finish(std::move(*received));
          return;
        }
        if (received->value().phase == "packet-capture-counts") {
          {
            std::scoped_lock lock(state_mutex_);
            last_counts_ = received->value().current_scope;
          }
          if (on_counts_)
            on_counts_(received->value().current_scope);
        }
        continue;
      }
      if (WaitForSingleObject(connection_.process.get(), 0) == WAIT_OBJECT_0) {
        finish(Result<elevated_protocol::Response>::failure(client_error(
            "packet capture", ERROR_PROCESS_ABORTED, "The elevated helper exited while the capture ran")));
        return;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
  }
  HelperConnection connection_;
  mutable std::mutex pipe_mutex_;
  mutable std::mutex state_mutex_;
  std::condition_variable final_ready_;
  std::optional<Result<elevated_protocol::Response>> final_;
  PacketCaptureSession session_;
  std::string last_counts_;
  CountsCallback on_counts_;
  bool stop_sent_ = false;
  std::jthread reader_;
};
} // namespace

Result<ElevatedVssResult> run_vss_test_elevated(const VssTestOptions& options,
                                                const CancellationToken& cancel,
                                                ProgressCallback progress) {
  return run_elevated_vss_operation(options, false, cancel, std::move(progress));
}

Result<std::vector<VssWriterInfo>> run_vss_writer_health_elevated(
    const CancellationToken& cancel, ProgressCallback progress) {
  VssTestOptions options;
  auto elevated = run_elevated_vss_operation(options, true, cancel, std::move(progress));
  if (!elevated.ok())
    return Result<std::vector<VssWriterInfo>>::failure(elevated.error());
  return Result<std::vector<VssWriterInfo>>::success(std::move(elevated.value().details.writers));
}

Result<PacketCaptureSession> packet_capture_start_owned_elevated(const PacketCaptureOptions& options,
                                                                 const std::filesystem::path& state_directory,
                                                                 const CancellationToken& cancel,
                                                                 ProgressCallback progress) {
  elevated_protocol::Request request;
  request.command = elevated_protocol::kCommandPacketCaptureStart;
  request.capture_output = path_to_utf8(options.output_etl);
  request.capture_state = path_to_utf8(state_directory);
  request.capture_backend = options.backend == PacketCaptureBackend::netsh ? "netsh" : "auto";
  request.capture_ip_filter = options.ip_filter.value_or(std::string());
  request.capture_port = options.port_filter.value_or(0);
  const HelperPhases phases{"packet-capture-elevation-request", "packet-capture-elevation-approved",
                            "packet-capture-helper-connected", "start packet capture"};
  // The helper answers "started" with the state file and stays with the capture; closing the
  // connection here leaves the capture running.
  auto exchanged =
      exchange_with_helper(std::move(request), phases, cancel, std::move(progress), "packet-capture-started");
  if (!exchanged.ok())
    return Result<PacketCaptureSession>::failure(exchanged.error());
  return load_packet_capture_session(path_from_utf8(exchanged.value().current_scope));
}

Result<ElevatedCollectionResult> run_universal_collection_elevated(const UniversalCollectionOptions& options,
                                                                   const CancellationToken& cancel,
                                                                   ProgressCallback progress) {
  elevated_protocol::Request request;
  request.command = elevated_protocol::kCommandUniversalCollection;
  request.collection_options = elevated_protocol::encode_universal_options(options);
  const HelperPhases phases{"collection-elevation-request", "collection-elevation-approved",
                            "collection-helper-connected", "Universal log collection"};
  auto exchanged = exchange_with_helper(std::move(request), phases, cancel, std::move(progress));
  if (!exchanged.ok())
    return Result<ElevatedCollectionResult>::failure(exchanged.error());
  ElevatedCollectionResult result;
  result.result_path = path_from_utf8(exchanged.value().message);
  result.rows = elevated_protocol::decode_rows(exchanged.value().result.diagnostic_message);
  return Result<ElevatedCollectionResult>::success(std::move(result));
}

Result<FilesystemBaselineResult> capture_filesystem_baseline_elevated(const std::filesystem::path& snapshot_path,
                                                                      const FilesystemScanOptions& options,
                                                                      const CancellationToken& cancel,
                                                                      ProgressCallback progress,
                                                                      std::string_view options_json) {
  elevated_protocol::Request request;
  request.command = elevated_protocol::kCommandFilesCapture;
  request.files_root = path_to_utf8(options.root);
  request.files_output = path_to_utf8(snapshot_path);
  request.files_hash = to_string(options.hash_mode);
  request.files_options_json = std::string(options_json);
  request.files_streams = options.capture_streams;
  const HelperPhases phases{"Asking for administrator approval", "Starting the capture as administrator",
                            "Capturing as administrator", "Capturing"};
  // The helper reports counts only; the time and the pace are measured here.
  const auto started = std::chrono::steady_clock::now();
  const ProgressCallback timed = [progress, started](const ProgressEvent& event) {
    if (!progress)
      return;
    ProgressEvent copy = event;
    copy.elapsed_seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (copy.elapsed_seconds > 0.0 && copy.processed > 0U)
      copy.items_per_second = static_cast<double>(copy.processed) / copy.elapsed_seconds;
    progress(copy);
  };
  auto exchanged = exchange_with_helper(std::move(request), phases, cancel, timed);
  if (!exchanged.ok())
    return Result<FilesystemBaselineResult>::failure(exchanged.error());
  FilesystemBaselineResult result;
  result.snapshot_id = exchanged.value().message;
  for (const auto& row : elevated_protocol::decode_rows(exchanged.value().result.diagnostic_message)) {
    if (row[0] == "state")
      result.state = row[1] == "complete" ? SnapshotState::complete : SnapshotState::cancelled;
    else if (row[0] == "objects")
      result.objects = std::strtoull(row[1].c_str(), nullptr, 10);
    else if (row[0] == "errors")
      result.errors = std::strtoull(row[1].c_str(), nullptr, 10);
    else if (row[0] == "source")
      result.source = row[1];
    else if (row[0] == "note")
      result.source_note = row[1];
  }
  return Result<FilesystemBaselineResult>::success(std::move(result));
}

Result<std::shared_ptr<PacketCaptureMonitor>> PacketCaptureMonitor::start(const PacketCaptureOptions& options,
                                                                         const std::filesystem::path& state_directory,
                                                                         CountsCallback on_counts,
                                                                         const CancellationToken& cancel,
                                                                         ProgressCallback progress) {
  using Started = Result<std::shared_ptr<PacketCaptureMonitor>>;
  auto security = current_security_context();
  if (security.ok() && security.value().elevated) {
    auto started = packet_capture_start_owned(options, state_directory, cancel, std::move(progress));
    if (!started.ok())
      return Started::failure(started.error());
    return Started::success(std::make_shared<LocalCaptureMonitor>(std::move(started.value()), std::move(on_counts)));
  }
  elevated_protocol::Request request;
  request.command = elevated_protocol::kCommandPacketCaptureStart;
  request.capture_output = path_to_utf8(options.output_etl);
  request.capture_state = path_to_utf8(state_directory);
  request.capture_backend = options.backend == PacketCaptureBackend::netsh ? "netsh" : "auto";
  request.capture_ip_filter = options.ip_filter.value_or(std::string());
  request.capture_port = options.port_filter.value_or(0);
  const HelperPhases phases{"packet-capture-elevation-request", "packet-capture-elevation-approved",
                            "packet-capture-helper-connected", "start packet capture"};
  HelperConnection connection;
  auto exchanged = exchange_with_helper(std::move(request), phases, cancel, std::move(progress),
                                        "packet-capture-started", &connection);
  if (!exchanged.ok())
    return Started::failure(exchanged.error());
  auto session = load_packet_capture_session(path_from_utf8(exchanged.value().current_scope));
  if (!session.ok())
    return Started::failure(session.error());
  return Started::success(std::make_shared<HelperCaptureMonitor>(std::move(connection), std::move(session.value()),
                                                                 std::move(on_counts)));
}

Result<ProcessResult> packet_capture_stop_owned_elevated(PacketCaptureSession& session,
                                                         const CancellationToken& cancel,
                                                         ProgressCallback progress) {
  elevated_protocol::Request request;
  request.command = elevated_protocol::kCommandPacketCaptureStop;
  request.capture_state = path_to_utf8(session.state_path);
  const HelperPhases phases{"packet-capture-elevation-request", "packet-capture-elevation-approved",
                            "packet-capture-helper-connected", "stop packet capture"};
  auto exchanged = exchange_with_helper(std::move(request), phases, cancel, std::move(progress));
  if (!exchanged.ok())
    return Result<ProcessResult>::failure(exchanged.error());
  auto reloaded = load_packet_capture_session(session.state_path);
  if (reloaded.ok())
    session = std::move(reloaded.value());
  ProcessResult result;
  result.launched = true;
  result.exit_code = static_cast<int>(exchanged.value().native_code);
  result.output = std::move(exchanged.value().message);
  return Result<ProcessResult>::success(std::move(result));
}

} // namespace support_assist
