#include "support_assist/process.hpp"

#include "support_assist/strings.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cwchar>
#include <filesystem>
#include <limits>
#include <system_error>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

// CreateProcessW does not search %PATH% when lpApplicationName is supplied; it resolves only
// against the current directory. An executable named without a directory component (for example
// "systeminfo.exe", "vssadmin.exe", "fltmc.exe", "dism.exe", "powershell.exe") must be resolved
// here first, or CreateProcessW fails with ERROR_FILE_NOT_FOUND.
//
// The system directory is searched before %PATH% deliberately: these are Windows' own tools, and
// SAT runs on machines it does not control, so a PATH entry that shadows fltmc.exe must not be
// what gets executed while collecting support evidence. The resolved absolute path is passed as
// lpApplicationName rather than left to the command line, avoiding the unquoted-path ambiguity of
// lpCommandLine-only resolution.
std::filesystem::path resolve_executable_path(const std::filesystem::path& executable) {
  if (executable.empty() || executable.has_parent_path())
    return executable;

  const std::wstring name = executable.wstring();
  std::array<wchar_t, MAX_PATH> system_directory{};
  const UINT length =
      GetSystemDirectoryW(system_directory.data(), static_cast<UINT>(system_directory.size()));
  if (length != 0 && length < system_directory.size()) {
    std::filesystem::path candidate =
        std::filesystem::path(std::wstring(system_directory.data(), length)) / name;
    std::error_code error;
    if (std::filesystem::exists(candidate, error) && !error)
      return candidate;
  }

  std::vector<wchar_t> buffer(1024);
  for (int attempt = 0; attempt < 2; ++attempt) {
    wchar_t* file_part = nullptr;
    const DWORD written = SearchPathW(nullptr, name.c_str(), nullptr,
                                      static_cast<DWORD>(buffer.size()), buffer.data(), &file_part);
    if (written == 0)
      break;
    if (written < buffer.size())
      return std::filesystem::path(std::wstring(buffer.data(), written));
    buffer.assign(written + 1U, L'\0');
  }
  // Unresolved: hand the original name back so the caller still reports a launch failure naming
  // the executable it was asked for, rather than a rewritten path the engineer never specified.
  return executable;
}

class HandleOwner {
public:
  HandleOwner() = default;
  explicit HandleOwner(HANDLE handle) : handle_(handle) {}
  ~HandleOwner() { reset(); }
  HandleOwner(const HandleOwner&) = delete;
  HandleOwner& operator=(const HandleOwner&) = delete;
  HandleOwner(HandleOwner&& other) noexcept : handle_(other.release()) {}
  HandleOwner& operator=(HandleOwner&& other) noexcept {
    if (this != &other)
      reset(other.release());
    return *this;
  }
  [[nodiscard]] HANDLE get() const noexcept { return handle_; }
  [[nodiscard]] bool valid() const noexcept {
    return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE;
  }
  HANDLE release() noexcept {
    const HANDLE value = handle_;
    handle_ = nullptr;
    return value;
  }
  void reset(HANDLE replacement = nullptr) noexcept {
    if (valid())
      CloseHandle(handle_);
    handle_ = replacement;
  }

private:
  HANDLE handle_ = nullptr;
};

struct PipePair {
  HandleOwner read;
  HandleOwner write;
};

struct CaseInsensitiveWideLess {
  bool operator()(const std::wstring& left, const std::wstring& right) const noexcept {
    return _wcsicmp(left.c_str(), right.c_str()) < 0;
  }
};

std::vector<wchar_t> child_environment_block(
    const std::vector<std::pair<std::string, std::string>>& overrides) {
  if (overrides.empty())
    return {};
  std::map<std::wstring, std::wstring, CaseInsensitiveWideLess> values;
  LPWCH inherited = GetEnvironmentStringsW();
  if (inherited != nullptr) {
    for (const wchar_t* cursor = inherited; *cursor != L'\0'; cursor += std::wcslen(cursor) + 1U) {
      const std::wstring entry(cursor);
      // Windows keeps per-drive current-directory entries in the form =C:=...
      // Preserve them verbatim by treating the second '=' as the separator.
      const std::size_t separator = entry.front() == L'=' ? entry.find(L'=', 1U) : entry.find(L'=');
      if (separator == std::wstring::npos)
        continue;
      values[entry.substr(0U, separator)] = entry.substr(separator + 1U);
    }
    FreeEnvironmentStringsW(inherited);
  }
  for (const auto& [name_utf8, value_utf8] : overrides) {
    if (name_utf8.empty())
      continue;
    values[wide_from_utf8(name_utf8)] = wide_from_utf8(value_utf8);
  }
  std::vector<wchar_t> block;
  for (const auto& [name, value] : values) {
    const std::wstring entry = name + L"=" + value;
    block.insert(block.end(), entry.begin(), entry.end());
    block.push_back(L'\0');
  }
  block.push_back(L'\0');
  return block;
}

std::wstring quote_argument(std::wstring_view argument) {
  if (argument.empty())
    return L"\"\"";
  if (argument.find_first_of(L" \t\n\v\"") == std::wstring_view::npos)
    return std::wstring(argument);
  std::wstring output = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t c : argument) {
    if (c == L'\\') {
      ++backslashes;
      continue;
    }
    if (c == L'\"') {
      output.append(backslashes * 2U + 1U, L'\\');
      output.push_back(L'\"');
      backslashes = 0;
      continue;
    }
    output.append(backslashes, L'\\');
    backslashes = 0;
    output.push_back(c);
  }
  output.append(backslashes * 2U, L'\\');
  output.push_back(L'\"');
  return output;
}

std::wstring build_command_line(const ProcessOptions& options) {
  std::wstring command = quote_argument(options.executable.wstring());
  for (const auto& argument : options.arguments) {
    command.push_back(L' ');
    command += quote_argument(wide_from_utf8(argument));
  }
  return command;
}

Error process_error(std::string operation,
                    const std::filesystem::path& source,
                    std::string message,
                    std::int64_t native_code = 0) {
  Error error;
  error.component = "Process";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = std::move(message);
  error.native_code = native_code;
  return error;
}

void publish(const ProgressCallback& progress,
             std::string phase,
             std::string current_scope,
             std::uint64_t processed = 0) {
  if (!progress)
    return;
  ProgressEvent event;
  event.phase = std::move(phase);
  event.current_scope = std::move(current_scope);
  event.processed = processed;
  progress(event);
}

Result<PipePair> create_output_pipe(const std::filesystem::path& executable,
                                    std::string_view label) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (CreatePipe(&raw_read, &raw_write, &security, 0) == FALSE) {
    return Result<PipePair>::failure(process_error("create " + std::string(label) + " pipe",
                                                   executable,
                                                   "CreatePipe failed",
                                                   static_cast<std::int64_t>(GetLastError())));
  }
  PipePair pair;
  pair.read.reset(raw_read);
  pair.write.reset(raw_write);
  if (SetHandleInformation(pair.read.get(), HANDLE_FLAG_INHERIT, 0) == FALSE) {
    return Result<PipePair>::failure(process_error("configure " + std::string(label) + " pipe",
                                                   executable,
                                                   "SetHandleInformation failed",
                                                   static_cast<std::int64_t>(GetLastError())));
  }
  return Result<PipePair>::success(std::move(pair));
}

void append_bounded(std::string& output,
                    const char* data,
                    std::size_t count,
                    std::size_t limit,
                    bool& truncated) {
  if (limit == 0U) {
    truncated = truncated || count != 0U;
    return;
  }
  if (output.size() >= limit) {
    truncated = truncated || count != 0U;
    return;
  }
  const std::size_t remaining = limit - output.size();
  const std::size_t accepted = std::min(remaining, count);
  output.append(data, accepted);
  if (accepted != count)
    truncated = true;
}

void drain_pipe(HANDLE pipe,
                std::string& output,
                std::size_t limit,
                bool& truncated) {
  if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE)
    return;
  std::array<char, 8192> buffer{};
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) == FALSE || available == 0)
      break;
    const DWORD requested = std::min<DWORD>(available, static_cast<DWORD>(buffer.size()));
    DWORD read = 0;
    if (ReadFile(pipe, buffer.data(), requested, &read, nullptr) == FALSE || read == 0)
      break;
    append_bounded(output, buffer.data(), static_cast<std::size_t>(read), limit, truncated);
  }
}

HandleOwner create_kill_on_close_job() {
  HandleOwner job(CreateJobObjectW(nullptr, nullptr));
  if (!job.valid())
    return {};
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION information{};
  information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                              &information, sizeof(information)) == FALSE) {
    job.reset();
  }
  return job;
}

void terminate_owned_process_tree(HANDLE job, HANDLE process, UINT exit_code) {
  if (job != nullptr && job != INVALID_HANDLE_VALUE) {
    static_cast<void>(TerminateJobObject(job, exit_code));
    return;
  }
  if (process != nullptr && process != INVALID_HANDLE_VALUE)
    static_cast<void>(TerminateProcess(process, exit_code));
}

} // namespace

std::string format_command_display(const ProcessOptions& options) {
  std::string command = '"' + path_to_utf8(options.executable) + '"';
  for (const auto& argument : options.arguments)
    command += " \"" + argument + "\"";
  return command;
}

Result<ProcessResult> run_process_capture(const ProcessOptions& options,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress) {
  if (options.executable.empty()) {
    return Result<ProcessResult>::failure(
        process_error("run process", {}, "No executable was supplied"));
  }

  auto stdout_created = create_output_pipe(options.executable, "stdout");
  if (!stdout_created.ok())
    return Result<ProcessResult>::failure(stdout_created.error());
  PipePair stdout_pipe = std::move(stdout_created.value());

  PipePair stderr_pipe;
  if (!options.merge_standard_error) {
    auto stderr_created = create_output_pipe(options.executable, "stderr");
    if (!stderr_created.ok())
      return Result<ProcessResult>::failure(stderr_created.error());
    stderr_pipe = std::move(stderr_created.value());
  }

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = stdout_pipe.write.get();
  startup.hStdError = options.merge_standard_error ? stdout_pipe.write.get() : stderr_pipe.write.get();
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

  PROCESS_INFORMATION process_info{};
  std::wstring command_line = build_command_line(options);
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');
  const std::wstring working =
      options.working_directory.empty() ? std::wstring() : options.working_directory.wstring();

  // Start suspended so an owned Job Object can be attached before the child has
  // an opportunity to create descendants. This makes timeout/cancellation a
  // process-tree boundary rather than only terminating the direct executable.
  DWORD creation_flags = CREATE_SUSPENDED;
  if (options.create_no_window)
    creation_flags |= CREATE_NO_WINDOW;
  std::vector<wchar_t> environment = child_environment_block(options.environment_overrides);
  if (!environment.empty())
    creation_flags |= CREATE_UNICODE_ENVIRONMENT;

  publish(progress, "Launching", format_command_display(options));
  const std::wstring resolved_executable = resolve_executable_path(options.executable).wstring();
  if (CreateProcessW(resolved_executable.c_str(),
                     mutable_command.data(),
                     nullptr,
                     nullptr,
                     TRUE,
                     creation_flags,
                     environment.empty() ? nullptr : environment.data(),
                     working.empty() ? nullptr : working.c_str(),
                     &startup,
                     &process_info) == FALSE) {
    return Result<ProcessResult>::failure(process_error("launch process",
                                                        options.executable,
                                                        "CreateProcessW failed",
                                                        static_cast<std::int64_t>(GetLastError())));
  }

  HandleOwner process(process_info.hProcess);
  HandleOwner thread(process_info.hThread);
  HandleOwner job = create_kill_on_close_job();
  if (job.valid() && AssignProcessToJobObject(job.get(), process.get()) == FALSE) {
    // A restrictive parent job can make assignment unavailable. Keep the direct
    // process fallback rather than failing a read-only diagnostic solely for this.
    job.reset();
  }
  if (ResumeThread(thread.get()) == static_cast<DWORD>(-1)) {
    const DWORD code = GetLastError();
    terminate_owned_process_tree(job.get(), process.get(), 1U);
    return Result<ProcessResult>::failure(process_error("resume process",
                                                        options.executable,
                                                        "ResumeThread failed",
                                                        static_cast<std::int64_t>(code)));
  }

  stdout_pipe.write.reset();
  stderr_pipe.write.reset();

  ProcessResult result;
  result.launched = true;
  result.command_display = format_command_display(options);
  const auto started = std::chrono::steady_clock::now();
  for (;;) {
    drain_pipe(stdout_pipe.read.get(), result.output,
               options.maximum_output_bytes, result.output_truncated);
    if (!options.merge_standard_error) {
      drain_pipe(stderr_pipe.read.get(), result.standard_error,
                 options.maximum_standard_error_bytes, result.standard_error_truncated);
    }

    const DWORD wait_result = WaitForSingleObject(process.get(), 50);
    if (wait_result == WAIT_OBJECT_0)
      break;
    if (wait_result == WAIT_FAILED) {
      return Result<ProcessResult>::failure(
          process_error("wait for process", options.executable, "WaitForSingleObject failed",
                        static_cast<std::int64_t>(GetLastError())));
    }
    if (cancel.is_cancelled()) {
      result.cancelled = true;
      if (options.terminate_on_cancel)
        terminate_owned_process_tree(job.get(), process.get(), 130U);
      break;
    }
    if (options.timeout.count() > 0 &&
        std::chrono::steady_clock::now() - started >= options.timeout) {
      result.timed_out = true;
      terminate_owned_process_tree(job.get(), process.get(), 1460U);
      break;
    }
  }

  static_cast<void>(WaitForSingleObject(process.get(), 5000));
  drain_pipe(stdout_pipe.read.get(), result.output,
             options.maximum_output_bytes, result.output_truncated);
  if (!options.merge_standard_error) {
    drain_pipe(stderr_pipe.read.get(), result.standard_error,
               options.maximum_standard_error_bytes, result.standard_error_truncated);
  }

  DWORD exit_code = 0;
  if (GetExitCodeProcess(process.get(), &exit_code) != FALSE)
    result.exit_code = static_cast<int>(exit_code);

  publish(progress, "Completed", path_to_utf8(options.executable),
          static_cast<std::uint64_t>(result.output.size() + result.standard_error.size()));
  return Result<ProcessResult>::success(std::move(result));
}

Result<DetachedProcess> launch_process_detached_owned(const ProcessOptions& options) {
  if (options.executable.empty()) {
    return Result<DetachedProcess>::failure(
        process_error("launch detached", {}, "No executable was supplied"));
  }
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  PROCESS_INFORMATION process_info{};
  std::wstring command_line = build_command_line(options);
  std::vector<wchar_t> mutable_command(command_line.begin(), command_line.end());
  mutable_command.push_back(L'\0');
  const std::wstring working =
      options.working_directory.empty() ? std::wstring() : options.working_directory.wstring();
  DWORD flags = DETACHED_PROCESS;
  if (options.create_no_window)
    flags |= CREATE_NO_WINDOW;
  std::vector<wchar_t> environment = child_environment_block(options.environment_overrides);
  if (!environment.empty())
    flags |= CREATE_UNICODE_ENVIRONMENT;
  const std::wstring resolved_executable = resolve_executable_path(options.executable).wstring();
  if (CreateProcessW(resolved_executable.c_str(),
                     mutable_command.data(),
                     nullptr,
                     nullptr,
                     FALSE,
                     flags,
                     environment.empty() ? nullptr : environment.data(),
                     working.empty() ? nullptr : working.c_str(),
                     &startup,
                     &process_info) == FALSE) {
    return Result<DetachedProcess>::failure(process_error("launch detached",
                                                          options.executable,
                                                          "CreateProcessW failed",
                                                          static_cast<std::int64_t>(GetLastError())));
  }
  DetachedProcess detached;
  detached.process_id = static_cast<std::uint32_t>(process_info.dwProcessId);
  CloseHandle(process_info.hThread);
  CloseHandle(process_info.hProcess);
  return Result<DetachedProcess>::success(detached);
}

Status launch_process_detached(const ProcessOptions& options) {
  auto launched = launch_process_detached_owned(options);
  return launched.ok() ? Status::success() : Status::failure(launched.error());
}

} // namespace support_assist
