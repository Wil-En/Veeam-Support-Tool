#pragma once

#include <chrono>
#include <filesystem>
#include <string>
#include <string_view>

namespace support_assist {

// Debug logging is deliberately disabled at process start. The GUI enables it
// only after an explicit user action and supplies an application-local path.
void configure_debug_log(std::filesystem::path path);
void set_debug_logging_enabled(bool enabled);
bool debug_logging_enabled() noexcept;
std::filesystem::path debug_log_path();
// Severity for a debug line. Debug logs are read by an engineer scanning for the moment something
// went wrong in a file that may hold thousands of lines, so the level exists to be grepped:
// "[E]" finds every failure in one pass.
enum class DebugLevel { trace, info, warning, error };

void write_debug_log(std::string_view component, std::string_view message) noexcept;
void write_debug_log(DebugLevel level, std::string_view component, std::string_view message) noexcept;

// Records an exception that was caught and handled. A swallowed exception is the single hardest
// class of defect to work from a customer's machine: the product carries on, the symptom appears
// somewhere else entirely, and nothing in the log says why. Every catch site that intends to
// continue should leave one of these behind.
void write_debug_exception(std::string_view component,
                           std::string_view operation,
                           std::string_view detail) noexcept;

// Records a user interface interaction - which control the engineer activated, and what it maps to.
//
// NEVER pass field CONTENTS to this. Control names and identifiers only: SAT runs on customer
// machines, and a debug log that captured what was typed into a credential or path box would turn a
// diagnostic file into a data-disclosure problem.
void write_debug_interaction(std::string_view surface,
                             std::string_view control,
                             std::string_view detail) noexcept;

// Times an operation and logs its start and end, including failures.
//
// Duration is the point: "collection took 4 minutes" is invisible in a log of discrete events, and
// a run that ends without its closing line is itself the finding - that is where the product hung
// or crashed. Declare one at the top of an operation and let scope exit close it.
class DebugScope {
public:
  DebugScope(std::string_view component, std::string_view operation) noexcept;
  ~DebugScope() noexcept;
  DebugScope(const DebugScope&) = delete;
  DebugScope& operator=(const DebugScope&) = delete;
  // Records the outcome. Without a call the scope closes as "completed".
  void fail(std::string_view reason) noexcept;
  void note(std::string_view detail) noexcept;

private:
  std::string component_;
  std::string operation_;
  std::string failure_;
  std::chrono::steady_clock::time_point started_;
};

// Writes a small always-on recovery breadcrumb even when verbose Debug logging is disabled.
// Use only for crash-prone lifecycle boundaries (for example parser/VSS orchestration); never
// write raw log lines, credentials, private keys, or other customer payload data here.
void write_recovery_log(std::string_view component, std::string_view message) noexcept;
std::filesystem::path recovery_log_path();

} // namespace support_assist
