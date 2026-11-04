#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace support_assist {

struct ProcessOptions {
  std::filesystem::path executable;
  std::vector<std::string> arguments;
  std::filesystem::path working_directory;
  std::chrono::milliseconds timeout{60000};
  bool merge_standard_error = true;
  bool terminate_on_cancel = true;
  bool create_no_window = true;
  // Environment values supplied only to the child process. These are never
  // included in command_display, which allows callers to pass short-lived
  // credentials/tokens without placing them on the command line or writing
  // them to disk. Existing environment values are inherited unless overridden.
  std::vector<std::pair<std::string, std::string>> environment_overrides;
  // Bound captured command output so a noisy external diagnostic cannot consume
  // the engineer/customer host memory indefinitely. Separate stderr uses its
  // own cap when merge_standard_error is false.
  std::size_t maximum_output_bytes = 8U * 1024U * 1024U;
  std::size_t maximum_standard_error_bytes = 2U * 1024U * 1024U;
};

struct ProcessResult {
  int exit_code = -1;
  bool launched = false;
  bool timed_out = false;
  bool cancelled = false;
  std::string output;
  std::string standard_error;
  bool output_truncated = false;
  bool standard_error_truncated = false;
  std::string command_display;
};

struct DetachedProcess {
  std::uint32_t process_id = 0;
};

Result<ProcessResult> run_process_capture(const ProcessOptions& options,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress = {});

Result<DetachedProcess> launch_process_detached_owned(const ProcessOptions& options);
Status launch_process_detached(const ProcessOptions& options);
std::string format_command_display(const ProcessOptions& options);

} // namespace support_assist
