#include "support_assist/local_shell.hpp"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

// The POSIX side of the persistent local shell: the same design as local_shell_win.cpp. One shell
// process reads commands from a pipe, and its output and errors come back on a second pipe.
//
// The shell starts in a session of its own (setsid). It borrows no controlling terminal from SAT,
// so a program that insists on one says so instead of prompting on the terminal SAT was started
// from, and everything the session runs shares one process group, which is how closing the session
// ends a command that is still running along with the shell.

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

// What the system said, not what we guessed it meant.
Error errno_error(std::string operation, const std::string& context, int code) {
  return shell_error(std::move(operation), context + ": " + std::generic_category().message(code),
                     code);
}

void close_descriptor(int& descriptor) {
  if (descriptor >= 0) {
    ::close(descriptor);
    descriptor = -1;
  }
}

// Both ends close on exec, so a later, unrelated child of SAT cannot hold the pipe open and keep
// the reader from ever seeing end-of-file. The child's copies on 0, 1 and 2 come from dup2, which
// clears the flag on the copy.
bool open_pipe(std::array<int, 2>& ends) {
#if defined(__linux__)
  if (::pipe2(ends.data(), O_CLOEXEC) != 0)
    return false;
#else
  if (::pipe(ends.data()) != 0)
    return false;
  ::fcntl(ends[0], F_SETFD, FD_CLOEXEC);
  ::fcntl(ends[1], F_SETFD, FD_CLOEXEC);
#endif
  // A descriptor below 3 would be overwritten by the child's own dup2 onto 0, 1 and 2 before it
  // was copied. That only happens when SAT was started with a standard stream closed.
  for (int& end : ends) {
    if (end >= 0 && end <= 2) {
      const int moved = ::fcntl(end, F_DUPFD_CLOEXEC, 3);
      if (moved < 0)
        return false;
      ::close(end);
      end = moved;
    }
  }
  return true;
}

std::filesystem::path default_shell(bool prefer_minimal) {
  if (!prefer_minimal && ::access("/bin/bash", X_OK) == 0)
    return "/bin/bash";
  return "/bin/sh";
}

// Has the shell exited? Asked without reaping it, so its process ID, which is also the session's
// process group ID, cannot be handed to another process while the group is still being signalled.
bool shell_has_exited(pid_t shell) {
  siginfo_t info{};
  info.si_pid = 0;
  if (::waitid(P_PID, static_cast<id_t>(shell), &info, WEXITED | WNOHANG | WNOWAIT) != 0)
    return errno == ECHILD;  // already reaped elsewhere: gone either way
  return info.si_pid == shell;
}

bool wait_for_exit(pid_t shell, std::chrono::milliseconds budget) {
  const auto deadline = std::chrono::steady_clock::now() + budget;
  for (;;) {
    if (shell_has_exited(shell))
      return true;
    if (std::chrono::steady_clock::now() >= deadline)
      return false;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
}

} // namespace

struct LocalShell {
  int input_write = -1;
  int output_read = -1;
  // The shell's process ID, which setsid also made the ID of its session and process group.
  pid_t process = -1;
  bool reaped = false;
  bool finished = false;
  // read() runs on the UI timer and close() on the UI thread, as on Windows.
  std::mutex mutex;

  ~LocalShell() { end(); }

  // Closing standard input asks the shell to exit on its own terms. A shell still running after
  // that is running a command, and the session ends with everything it started.
  void end() {
    finished = true;
    close_descriptor(input_write);
    if (process > 0 && !reaped) {
      // An idle shell leaves as soon as its input closes; half a second is plenty.
      if (!wait_for_exit(process, std::chrono::milliseconds(500))) {
        ::kill(-process, SIGTERM);
        wait_for_exit(process, std::chrono::milliseconds(1000));
      }
      // Whatever the session started and left behind, in the background or still running.
      ::kill(-process, SIGKILL);
      int status = 0;
      while (::waitpid(process, &status, 0) < 0 && errno == EINTR) {
      }
      reaped = true;
    }
    close_descriptor(output_read);
  }
};

bool local_shell_supported() { return true; }

std::string local_shell_context_label() {
  const uid_t user_id = ::geteuid();
  std::string user;
  {
    passwd entry{};
    passwd* found = nullptr;
    std::vector<char> buffer(16384);
    if (::getpwuid_r(user_id, &entry, buffer.data(), buffer.size(), &found) == 0 &&
        found != nullptr && found->pw_name != nullptr)
      user = found->pw_name;
  }
  if (user.empty()) {
    if (const char* name = std::getenv("USER"); name != nullptr)
      user = name;
  }
  std::string label = user.empty() ? "Local session" : user;
  label += user_id == 0 ? " - elevated (root)" : " - not elevated";
  return label;
}

Result<std::shared_ptr<LocalShell>> local_open_shell(const LocalShellOptions& options) {
  const std::filesystem::path executable =
      options.executable.empty() ? default_shell(options.prefer_cmd) : options.executable;
  const std::string program = executable.string();
  if (::access(program.c_str(), X_OK) != 0) {
    return Result<std::shared_ptr<LocalShell>>::failure(
        errno_error("open local shell", "The shell could not be started: " + program, errno));
  }

  std::string working_directory;
  {
    std::error_code error;
    if (!options.working_directory.empty() &&
        std::filesystem::is_directory(options.working_directory, error) && !error)
      working_directory = options.working_directory.string();
  }

  // A login shell reading its commands from standard input: the profile an engineer has at a
  // prompt, and a session that lasts until the input closes. bash, sh and zsh all take -l and -s.
  std::vector<std::string> arguments{program, "-l", "-s"};
  std::vector<char*> argv;
  for (auto& argument : arguments)
    argv.push_back(argument.data());
  argv.push_back(nullptr);

  std::array<int, 2> input{-1, -1};
  std::array<int, 2> output{-1, -1};
  if (!open_pipe(input)) {
    const int code = errno;
    close_descriptor(input[0]);
    close_descriptor(input[1]);
    return Result<std::shared_ptr<LocalShell>>::failure(
        errno_error("open local shell", "The shell input pipe could not be created", code));
  }
  if (!open_pipe(output)) {
    const int code = errno;
    for (int* end : {&input[0], &input[1], &output[0], &output[1]})
      close_descriptor(*end);
    return Result<std::shared_ptr<LocalShell>>::failure(
        errno_error("open local shell", "The shell output pipe could not be created", code));
  }

  const pid_t child = ::fork();
  if (child < 0) {
    const int code = errno;
    for (int* end : {&input[0], &input[1], &output[0], &output[1]})
      close_descriptor(*end);
    return Result<std::shared_ptr<LocalShell>>::failure(
        errno_error("open local shell", "The shell could not be started: " + program, code));
  }

  if (child == 0) {
    // In the child only async-signal-safe calls, up to exec.
    ::setsid();
    // Default dispositions and an empty mask, whatever SAT set for itself, so a pipeline ends the
    // way it does at a prompt. An ignored signal would otherwise stay ignored across exec.
    struct sigaction reset {};
    reset.sa_handler = SIG_DFL;
    sigemptyset(&reset.sa_mask);
    for (const int signal_number : {SIGPIPE, SIGINT, SIGQUIT, SIGTERM, SIGHUP, SIGCHLD})
      ::sigaction(signal_number, &reset, nullptr);
    sigset_t none;
    sigemptyset(&none);
    ::sigprocmask(SIG_SETMASK, &none, nullptr);

    ::dup2(input[0], STDIN_FILENO);
    ::dup2(output[1], STDOUT_FILENO);
    // Errors belong in the transcript beside the command that caused them.
    ::dup2(output[1], STDERR_FILENO);
    if (!working_directory.empty() && ::chdir(working_directory.c_str()) != 0) {
      // A folder that has gone since it was chosen: the shell starts where SAT is.
    }
    ::execv(program.c_str(), argv.data());
    static const char failed[] = "The shell could not be started.\n";
    const ssize_t reported = ::write(STDERR_FILENO, failed, sizeof failed - 1);
    ::_exit(reported < 0 ? 126 : 127);
  }

  // Our copies of the child's ends must go, or end-of-file never arrives once the shell exits.
  close_descriptor(input[0]);
  close_descriptor(output[1]);
  // Reads return what has arrived, which is often nothing.
  ::fcntl(output[0], F_SETFL, ::fcntl(output[0], F_GETFL) | O_NONBLOCK);

  auto shell = std::make_shared<LocalShell>();
  shell->input_write = input[1];
  shell->output_read = output[0];
  shell->process = child;
  return Result<std::shared_ptr<LocalShell>>::success(std::move(shell));
}

Result<std::string> local_shell_read(LocalShell& shell) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  if (shell.output_read < 0)
    return Result<std::string>::success(std::string());

  std::string collected;
  std::array<char, 64 * 1024> chunk{};
  for (;;) {
    const ssize_t count = ::read(shell.output_read, chunk.data(), chunk.size());
    if (count > 0) {
      collected.append(chunk.data(), static_cast<std::size_t>(count));
      // Bound one pass so a command producing output continuously cannot hold the UI thread.
      if (collected.size() >= 256U * 1024U)
        break;
      continue;
    }
    if (count == 0) {
      // Every writer has closed its end: the session is over.
      shell.finished = true;
      break;
    }
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      break;
    const int code = errno;
    return Result<std::string>::failure(
        errno_error("read local shell", "The shell output could not be read", code));
  }

  // A shell can exit while something it started in the background still holds the pipe open.
  if (!shell.finished && shell.process > 0 && !shell.reaped && shell_has_exited(shell.process))
    shell.finished = true;

  return Result<std::string>::success(std::move(collected));
}

Status local_shell_write(LocalShell& shell, std::string_view bytes) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  if (shell.input_write < 0)
    return Status::failure(shell_error("write local shell", "The local shell is not open"));

  // Writing to a shell that has gone raises SIGPIPE, whose default action would end SAT. Hold it
  // for this thread, take one that arrives, and report the session as gone instead.
  sigset_t pipe_signal;
  sigemptyset(&pipe_signal);
  sigaddset(&pipe_signal, SIGPIPE);
  sigset_t previous;
  sigemptyset(&previous);
  ::pthread_sigmask(SIG_BLOCK, &pipe_signal, &previous);

  std::size_t written_total = 0;
  int failure_code = 0;
  while (written_total < bytes.size()) {
    const ssize_t written =
        ::write(shell.input_write, bytes.data() + written_total, bytes.size() - written_total);
    if (written > 0) {
      written_total += static_cast<std::size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR)
      continue;
    failure_code = written < 0 ? errno : EIO;
    break;
  }

  if (failure_code == EPIPE && !sigismember(&previous, SIGPIPE)) {
    sigset_t pending;
    sigemptyset(&pending);
    if (::sigpending(&pending) == 0 && sigismember(&pending, SIGPIPE)) {
      int taken = 0;
      ::sigwait(&pipe_signal, &taken);
    }
  }
  ::pthread_sigmask(SIG_SETMASK, &previous, nullptr);

  if (failure_code == EPIPE) {
    shell.finished = true;
    return Status::failure(
        shell_error("write local shell", "The shell has exited, so nothing is listening.", EPIPE));
  }
  if (failure_code != 0)
    return Status::failure(
        errno_error("write local shell", "The shell input could not be written", failure_code));
  return Status::success();
}

bool local_shell_connected(const LocalShell& shell) { return !shell.finished; }

void local_shell_close(LocalShell& shell) {
  std::lock_guard<std::mutex> guard(shell.mutex);
  shell.end();
}

} // namespace support_assist
