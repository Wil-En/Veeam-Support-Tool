#include "support_assist/process.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <string_view>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

// execv() does not search PATH, so an executable named without a directory component - "ss", "ip",
// "systemctl", "sh" - never launches. This is the POSIX half of the same defect that emptied the
// Windows support collection, where CreateProcessW with lpApplicationName also skips PATH.
//
// Resolution happens BEFORE fork(). Searching PATH in the child would allocate, and only
// async-signal-safe calls are permitted between fork() and exec(). Well-known system directories
// are searched ahead of PATH for the same reason as on Windows: SAT runs on machines it does not
// control, and a PATH entry shadowing a diagnostic binary must not be what gets executed.
std::filesystem::path resolve_executable_path(const std::filesystem::path& executable) {
  if (executable.empty() || executable.has_parent_path())
    return executable;

  const auto usable = [](const std::filesystem::path& candidate) {
    return ::access(candidate.c_str(), X_OK) == 0;
  };
  for (const char* directory : {"/usr/sbin", "/sbin", "/usr/bin", "/bin"}) {
    std::filesystem::path candidate = std::filesystem::path(directory) / executable;
    if (usable(candidate))
      return candidate;
  }
  if (const char* path = std::getenv("PATH"); path != nullptr) {
    std::string_view remaining(path);
    while (!remaining.empty()) {
      const std::size_t separator = remaining.find(':');
      const std::string_view entry = remaining.substr(0, separator);
      if (!entry.empty()) {
        std::filesystem::path candidate = std::filesystem::path(entry) / executable;
        if (usable(candidate))
          return candidate;
      }
      if (separator == std::string_view::npos)
        break;
      remaining.remove_prefix(separator + 1U);
    }
  }
  // Unresolved: hand the original back so the caller reports a failure naming what it was asked
  // for, rather than a rewritten path the caller never specified.
  return executable;
}


Error process_error(std::string operation,
                    const std::filesystem::path& source,
                    std::string message,
                    std::int64_t native_code = 0) {
  Error error;
  error.component = "Process";
  error.operation = std::move(operation);
  error.source = source.string();
  error.message = std::move(message);
  error.native_code = native_code;
  return error;
}

std::vector<char*> argument_pointers(std::vector<std::string>& values) {
  std::vector<char*> pointers;
  pointers.reserve(values.size() + 1U);
  for (auto& value : values)
    pointers.push_back(value.data());
  pointers.push_back(nullptr);
  return pointers;
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

void make_nonblocking(int descriptor) {
  const int flags = fcntl(descriptor, F_GETFL, 0);
  if (flags >= 0)
    static_cast<void>(fcntl(descriptor, F_SETFL, flags | O_NONBLOCK));
}

void drain_descriptor(int descriptor,
                      std::string& output,
                      std::size_t limit,
                      bool& truncated) {
  std::array<char, 8192> buffer{};
  for (;;) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count > 0) {
      append_bounded(output, buffer.data(), static_cast<std::size_t>(count), limit, truncated);
      continue;
    }
    break;
  }
}

void terminate_process_group(pid_t child, int signal) {
  // The capture child creates its own process group before exec. Kill the group
  // first so helper/child processes do not survive a SAT cancellation/timeout.
  if (child > 0)
    static_cast<void>(kill(-child, signal));
}

} // namespace

std::string format_command_display(const ProcessOptions& options) {
  std::string command = '"' + options.executable.string() + '"';
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

  int stdout_pipe[2]{};
  if (pipe(stdout_pipe) != 0) {
    return Result<ProcessResult>::failure(
        process_error("create stdout pipe", options.executable, std::strerror(errno), errno));
  }
  int stderr_pipe[2]{-1, -1};
  if (!options.merge_standard_error && pipe(stderr_pipe) != 0) {
    const int saved_errno = errno;
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    return Result<ProcessResult>::failure(
        process_error("create stderr pipe", options.executable, std::strerror(saved_errno), saved_errno));
  }

  // Resolved before fork(): PATH lookup allocates, and only async-signal-safe calls are
  // permitted between fork() and exec().
  const std::filesystem::path resolved_executable = resolve_executable_path(options.executable);
  const pid_t child = fork();
  if (child < 0) {
    const int saved_errno = errno;
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
    if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
    return Result<ProcessResult>::failure(
        process_error("fork process", options.executable, std::strerror(saved_errno), saved_errno));
  }
  if (child == 0) {
    // Create a private group so SAT cancellation can terminate descendants too.
    static_cast<void>(setpgid(0, 0));
    static_cast<void>(dup2(stdout_pipe[1], STDOUT_FILENO));
    static_cast<void>(dup2(options.merge_standard_error ? stdout_pipe[1] : stderr_pipe[1], STDERR_FILENO));
    close(stdout_pipe[0]);
    close(stdout_pipe[1]);
    if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);
    if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
    if (!options.working_directory.empty() && chdir(options.working_directory.c_str()) != 0)
      _exit(126);
    for (const auto& [name, value] : options.environment_overrides) {
      if (!name.empty())
        static_cast<void>(setenv(name.c_str(), value.c_str(), 1));
    }
    std::vector<std::string> values;
    values.reserve(options.arguments.size() + 1U);
    values.push_back(options.executable.string());
    values.insert(values.end(), options.arguments.begin(), options.arguments.end());
    auto pointers = argument_pointers(values);
    execv(resolved_executable.c_str(), pointers.data());
    _exit(127);
  }

  // Close child ends and make parent reads nonblocking. The parent-side setpgid
  // narrows the fork/exec race if the child has not executed setpgid yet.
  static_cast<void>(setpgid(child, child));
  close(stdout_pipe[1]);
  if (stderr_pipe[1] >= 0) close(stderr_pipe[1]);
  make_nonblocking(stdout_pipe[0]);
  if (stderr_pipe[0] >= 0) make_nonblocking(stderr_pipe[0]);

  ProcessResult result;
  result.launched = true;
  result.command_display = format_command_display(options);
  if (progress) {
    ProgressEvent event;
    event.phase = "Running";
    event.current_scope = result.command_display;
    progress(event);
  }

  const auto started = std::chrono::steady_clock::now();
  bool finished = false;
  int status = 0;
  while (!finished) {
    std::array<pollfd, 2> descriptors{};
    nfds_t count = 1;
    descriptors[0].fd = stdout_pipe[0];
    descriptors[0].events = POLLIN;
    if (stderr_pipe[0] >= 0) {
      descriptors[1].fd = stderr_pipe[0];
      descriptors[1].events = POLLIN;
      count = 2;
    }
    static_cast<void>(poll(descriptors.data(), count, 50));
    drain_descriptor(stdout_pipe[0], result.output, options.maximum_output_bytes, result.output_truncated);
    if (stderr_pipe[0] >= 0) {
      drain_descriptor(stderr_pipe[0], result.standard_error,
                       options.maximum_standard_error_bytes, result.standard_error_truncated);
    }

    const pid_t waited = waitpid(child, &status, WNOHANG);
    finished = waited == child;
    if (!finished && cancel.is_cancelled()) {
      result.cancelled = true;
      if (options.terminate_on_cancel) {
        terminate_process_group(child, SIGTERM);
        for (int attempt = 0; attempt < 20; ++attempt) {
          if (waitpid(child, &status, WNOHANG) == child) {
            finished = true;
            break;
          }
          usleep(25000);
        }
        if (!finished) {
          terminate_process_group(child, SIGKILL);
          static_cast<void>(waitpid(child, &status, 0));
          finished = true;
        }
      } else {
        static_cast<void>(waitpid(child, &status, 0));
        finished = true;
      }
    }
    if (!finished && options.timeout.count() > 0 &&
        std::chrono::steady_clock::now() - started >= options.timeout) {
      result.timed_out = true;
      terminate_process_group(child, SIGTERM);
      for (int attempt = 0; attempt < 20; ++attempt) {
        if (waitpid(child, &status, WNOHANG) == child) {
          finished = true;
          break;
        }
        usleep(25000);
      }
      if (!finished) {
        terminate_process_group(child, SIGKILL);
        static_cast<void>(waitpid(child, &status, 0));
        finished = true;
      }
    }
  }

  drain_descriptor(stdout_pipe[0], result.output, options.maximum_output_bytes, result.output_truncated);
  if (stderr_pipe[0] >= 0) {
    drain_descriptor(stderr_pipe[0], result.standard_error,
                     options.maximum_standard_error_bytes, result.standard_error_truncated);
  }
  close(stdout_pipe[0]);
  if (stderr_pipe[0] >= 0) close(stderr_pipe[0]);

  if (WIFEXITED(status))
    result.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status))
    result.exit_code = 128 + WTERMSIG(status);

  if (progress) {
    ProgressEvent event;
    event.phase = "Completed";
    event.current_scope = options.executable.string();
    event.processed = static_cast<std::uint64_t>(result.output.size() + result.standard_error.size());
    progress(event);
  }
  return Result<ProcessResult>::success(std::move(result));
}

Result<DetachedProcess> launch_process_detached_owned(const ProcessOptions& options) {
  if (options.executable.empty()) {
    return Result<DetachedProcess>::failure(
        process_error("launch detached", {}, "No executable was supplied"));
  }
  // Resolved before fork(): PATH lookup allocates, and only async-signal-safe calls are
  // permitted between fork() and exec().
  const std::filesystem::path resolved_executable = resolve_executable_path(options.executable);
  const pid_t child = fork();
  if (child < 0) {
    return Result<DetachedProcess>::failure(
        process_error("launch detached", options.executable, std::strerror(errno), errno));
  }
  if (child == 0) {
    if (setsid() < 0)
      _exit(126);
    if (!options.working_directory.empty() && chdir(options.working_directory.c_str()) != 0)
      _exit(126);
    for (const auto& [name, value] : options.environment_overrides) {
      if (!name.empty())
        static_cast<void>(setenv(name.c_str(), value.c_str(), 1));
    }
    std::vector<std::string> values;
    values.reserve(options.arguments.size() + 1U);
    values.push_back(options.executable.string());
    values.insert(values.end(), options.arguments.begin(), options.arguments.end());
    auto pointers = argument_pointers(values);
    execv(resolved_executable.c_str(), pointers.data());
    _exit(127);
  }
  DetachedProcess detached;
  detached.process_id = static_cast<std::uint32_t>(child);
  return Result<DetachedProcess>::success(detached);
}

Status launch_process_detached(const ProcessOptions& options) {
  auto launched = launch_process_detached_owned(options);
  return launched.ok() ? Status::success() : Status::failure(launched.error());
}

} // namespace support_assist
