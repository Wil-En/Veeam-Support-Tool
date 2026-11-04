#include "support_assist/local_shell.hpp"

#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <mutex>
#include <vector>

namespace support_assist {
namespace {

Error shell_error(std::string operation, std::string message, int code = 0) {
  Error error;
  error.component = "LocalShell";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.native_code = code;
  return error;
}

// Report what Windows said, not what we guessed it meant. An invented message reads as a diagnosis
// and gets believed - the rule that came out of the libssh2 channel-open failure.
std::string windows_message(DWORD code) {
  LPWSTR buffer = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&buffer),
      0, nullptr);
  std::string text;
  if (length != 0 && buffer != nullptr)
    text = utf8_from_wide(std::wstring_view(buffer, length));
  if (buffer != nullptr)
    LocalFree(buffer);
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' '))
    text.pop_back();
  if (text.empty())
    text = "Windows error " + std::to_string(code);
  return text;
}

Error last_error(std::string operation, std::string context) {
  const DWORD code = GetLastError();
  return shell_error(std::move(operation), context + ": " + windows_message(code),
                     static_cast<int>(code));
}

class Handle {
public:
  Handle() = default;
  explicit Handle(HANDLE value) : value_(value) {}
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = nullptr; }
  Handle& operator=(Handle&& other) noexcept {
    if (this != &other) {
      reset();
      value_ = other.value_;
      other.value_ = nullptr;
    }
    return *this;
  }
  ~Handle() { reset(); }

  void reset(HANDLE value = nullptr) {
    if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE)
      CloseHandle(value_);
    value_ = value;
  }
  HANDLE get() const noexcept { return value_; }
  bool valid() const noexcept { return value_ != nullptr && value_ != INVALID_HANDLE_VALUE; }

private:
  HANDLE value_ = nullptr;
};

struct PipePair {
  Handle read;
  Handle write;
};

// The child must inherit the end it uses; SAT's end must NOT be inheritable, or a later unrelated
// child would hold the pipe open and the reader would never see end-of-file.
Result<PipePair> create_pipe(bool child_writes, std::string_view label) {
  SECURITY_ATTRIBUTES security{};
  security.nLength = sizeof(security);
  security.bInheritHandle = TRUE;
  HANDLE raw_read = nullptr;
  HANDLE raw_write = nullptr;
  if (CreatePipe(&raw_read, &raw_write, &security, 0) == FALSE)
    return Result<PipePair>::failure(
        last_error("open local shell", "The " + std::string(label) + " pipe could not be created"));

  PipePair pair;
  pair.read.reset(raw_read);
  pair.write.reset(raw_write);
  const HANDLE ours = child_writes ? pair.read.get() : pair.write.get();
  if (SetHandleInformation(ours, HANDLE_FLAG_INHERIT, 0) == FALSE)
    return Result<PipePair>::failure(
        last_error("open local shell", "The " + std::string(label) + " pipe could not be configured"));
  return Result<PipePair>::success(std::move(pair));
}

std::filesystem::path default_shell(bool prefer_cmd) {
  std::array<wchar_t, MAX_PATH> system_directory{};
  const UINT length = GetSystemDirectoryW(system_directory.data(),
                                          static_cast<UINT>(system_directory.size()));
  const std::filesystem::path system_root =
      length != 0 ? std::filesystem::path(std::wstring(system_directory.data(), length))
                  : std::filesystem::path(L"C:\\Windows\\System32");

  if (!prefer_cmd) {
    const auto powershell = system_root / L"WindowsPowerShell" / L"v1.0" / L"powershell.exe";
    std::error_code error;
    if (std::filesystem::exists(powershell, error) && !error)
      return powershell;
  }
  return system_root / L"cmd.exe";
}

// The shell has to keep reading standard input rather than running one thing and leaving.
//
//   cmd.exe   /Q disables command echo, /K keeps the session open after each command.
//   powershell -NoLogo -NoProfile -NonInteractive is WRONG here - it suppresses the prompting this
//             session exists to support. `-Command -` makes it read commands from standard input
//             until the stream closes, which is exactly the lifetime wanted.
std::wstring shell_command_line(const std::filesystem::path& executable) {
  std::wstring name = executable.filename().wstring();
  for (wchar_t& character : name) {
    if (character >= L'A' && character <= L'Z')
      character = static_cast<wchar_t>(character - L'A' + L'a');
  }
  std::wstring line = L"\"" + executable.wstring() + L"\"";
  if (name == L"cmd.exe")
    line += L" /Q /K";
  else if (name == L"powershell.exe" || name == L"pwsh.exe")
    line += L" -NoLogo -NoProfile -Command -";
  return line;
}

} // namespace

struct LocalShell {
  Handle input_write;
  Handle output_read;
  Handle process;
  // The job the shell and everything it starts belong to. Closing the session ends the job, so a
  // command still running (ping -t, Get-Content -Wait) does not outlive it. Empty when Windows
  // refused the job, in which case closing ends the shell alone, as before.
  Handle job;
  bool finished = false;
  // read() runs on the UI timer and close() on the UI thread; a worker must not be able to close
  // the pipes out from under an in-flight read.
  std::mutex mutex;
};

bool local_shell_supported() { return true; }

std::string local_shell_context_label() {
  auto context = current_security_context();
  if (!context.ok())
    return "Local session (account unknown)";
  const auto& value = context.value();
  std::string label = value.user.empty() ? "Local session" : value.user;
  label += value.elevated ? " - elevated (Administrator)" : " - not elevated";
  return label;
}

Result<std::shared_ptr<LocalShell>> local_open_shell(const LocalShellOptions& options) {
  auto shell = std::make_shared<LocalShell>();

  auto input = create_pipe(/*child_writes=*/false, "shell input");
  if (!input.ok())
    return Result<std::shared_ptr<LocalShell>>::failure(input.error());
  auto output = create_pipe(/*child_writes=*/true, "shell output");
  if (!output.ok())
    return Result<std::shared_ptr<LocalShell>>::failure(output.error());

  shell->input_write = std::move(input.value().write);
  shell->output_read = std::move(output.value().read);

  const std::filesystem::path executable =
      options.executable.empty() ? default_shell(options.prefer_cmd) : options.executable;

  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = input.value().read.get();
  startup.hStdOutput = output.value().write.get();
  // Errors belong in the transcript beside the command that caused them, not in a second stream
  // the engineer has to correlate by hand.
  startup.hStdError = output.value().write.get();

  std::wstring command_line = shell_command_line(executable);
  std::vector<wchar_t> mutable_command_line(command_line.begin(), command_line.end());
  mutable_command_line.push_back(L'\0');

  std::wstring working_directory = options.working_directory.wstring();
  {
    std::error_code error;
    if (working_directory.empty() ||
        !std::filesystem::is_directory(options.working_directory, error) || error) {
      working_directory.clear();
    }
  }

  // Everything the session starts is kept in one job that ends with it. The shell starts suspended
  // and joins the job before it can run anything, so nothing it starts escapes the job.
  Handle job(CreateJobObjectW(nullptr, nullptr));
  if (job.valid()) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation, &limits,
                                sizeof(limits)) == FALSE)
      job.reset();
  }

  PROCESS_INFORMATION process{};
  // No token is passed and none is requested: the child inherits SAT's own, so the session runs at
  // exactly the elevation SAT was started with. That is the security posture of this console and
  // it is a deliberate absence, not an omission.
  //
  // CREATE_NO_WINDOW keeps a console window from flashing up on the customer's desktop.
  const BOOL started = CreateProcessW(
      nullptr, mutable_command_line.data(), nullptr, nullptr, /*bInheritHandles=*/TRUE,
      CREATE_NO_WINDOW | (job.valid() ? CREATE_SUSPENDED : 0), nullptr,
      working_directory.empty() ? nullptr : working_directory.c_str(), &startup, &process);
  if (started == FALSE) {
    return Result<std::shared_ptr<LocalShell>>::failure(
        last_error("open local shell", "The shell could not be started: " + path_to_utf8(executable)));
  }

  if (job.valid()) {
    // A job Windows will not take the shell into leaves a session that still works; closing it
    // then ends the shell alone.
    if (AssignProcessToJobObject(job.get(), process.hProcess) == FALSE)
      job.reset();
    ResumeThread(process.hThread);
  }
  if (process.hThread != nullptr)
    CloseHandle(process.hThread);
  shell->process.reset(process.hProcess);
  shell->job = std::move(job);

  // Our copies of the child's ends must go, or the output pipe never reports end-of-file when the
  // shell exits and the reader waits forever on a session that is already gone.
  input.value().read.reset();
  output.value().write.reset();

  return Result<std::shared_ptr<LocalShell>>::success(std::move(shell));
}

Result<std::string> local_shell_read(LocalShell& shell) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  if (!shell.output_read.valid())
    return Result<std::string>::success(std::string());

  std::string collected;
  for (;;) {
    DWORD available = 0;
    if (PeekNamedPipe(shell.output_read.get(), nullptr, 0, nullptr, &available, nullptr) == FALSE) {
      const DWORD code = GetLastError();
      // The shell closed its end. That is the session ending, not a failure to report.
      if (code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED) {
        shell.finished = true;
        break;
      }
      return Result<std::string>::failure(shell_error(
          "read local shell",
          "The shell output pipe could not be inspected: " + windows_message(code),
          static_cast<int>(code)));
    }
    if (available == 0)
      break;

    std::string chunk(std::min<DWORD>(available, 64U * 1024U), 0);
    DWORD read = 0;
    if (ReadFile(shell.output_read.get(), chunk.data(), static_cast<DWORD>(chunk.size()), &read,
                 nullptr) == FALSE) {
      const DWORD code = GetLastError();
      if (code == ERROR_BROKEN_PIPE) {
        shell.finished = true;
        break;
      }
      return Result<std::string>::failure(shell_error(
          "read local shell", "The shell output could not be read: " + windows_message(code),
          static_cast<int>(code)));
    }
    if (read == 0)
      break;
    chunk.resize(read);
    collected += chunk;
    // Bound one pass so a command producing output continuously cannot hold the UI thread.
    if (collected.size() >= 256U * 1024U)
      break;
  }

  if (shell.process.valid() && WaitForSingleObject(shell.process.get(), 0) == WAIT_OBJECT_0)
    shell.finished = true;

  return Result<std::string>::success(std::move(collected));
}

Status local_shell_write(LocalShell& shell, std::string_view bytes) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  if (!shell.input_write.valid())
    return Status::failure(shell_error("write local shell", "The local shell is not open"));

  std::size_t written_total = 0;
  while (written_total < bytes.size()) {
    DWORD written = 0;
    if (WriteFile(shell.input_write.get(), bytes.data() + written_total,
                  static_cast<DWORD>(bytes.size() - written_total), &written, nullptr) == FALSE) {
      const DWORD code = GetLastError();
      if (code == ERROR_BROKEN_PIPE || code == ERROR_NO_DATA) {
        shell.finished = true;
        return Status::failure(shell_error("write local shell",
                                           "The shell has exited, so nothing is listening.",
                                           static_cast<int>(code)));
      }
      return Status::failure(shell_error(
          "write local shell", "The shell input could not be written: " + windows_message(code),
          static_cast<int>(code)));
    }
    if (written == 0)
      break;
    written_total += written;
  }
  return Status::success();
}

bool local_shell_connected(const LocalShell& shell) { return !shell.finished; }

void local_shell_close(LocalShell& shell) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  shell.finished = true;

  // Closing standard input asks the shell to exit on its own terms, which lets it flush. A shell
  // still running after that is running a command, and the session ends with everything it started.
  shell.input_write.reset();

  if (shell.process.valid()) {
    if (WaitForSingleObject(shell.process.get(), 2000) != WAIT_OBJECT_0) {
      if (shell.job.valid())
        TerminateJobObject(shell.job.get(), 1);
      else
        TerminateProcess(shell.process.get(), 0);
    }
    shell.process.reset();
  }
  // Whatever the shell started and left running ends with the session too.
  if (shell.job.valid()) {
    TerminateJobObject(shell.job.get(), 1);
    shell.job.reset();
  }
  shell.output_read.reset();
}

} // namespace support_assist
