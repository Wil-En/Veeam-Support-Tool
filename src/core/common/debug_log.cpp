#include "support_assist/debug_log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace support_assist {
namespace {

std::atomic_bool g_enabled{false};
std::mutex g_mutex;
std::filesystem::path g_path;
std::filesystem::path g_recovery_path;

std::string timestamp_now() {
  const auto now = std::chrono::system_clock::now();
  const std::time_t value = std::chrono::system_clock::to_time_t(now);
  std::tm local{};
#ifdef _WIN32
  localtime_s(&local, &value);
#else
  localtime_r(&value, &local);
#endif
  char buffer[40]{};
  std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local);
  // Milliseconds matter: this log is read side by side with Veeam's own millisecond-stamped logs,
  // and second resolution cannot order events inside a single operation.
  const auto milliseconds =
      std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
  char fraction[8]{};
  std::snprintf(fraction, sizeof(fraction), ".%03d", static_cast<int>(milliseconds.count()));
  return std::string(buffer) + fraction;
}

std::string thread_token() {
  // The GUI runs operations on worker threads while the UI thread keeps painting. Without a thread
  // id, interleaved lines from a background collection and the UI read as one impossible sequence.
  std::ostringstream stream;
  stream << std::this_thread::get_id();
  return stream.str();
}

const char* level_token(DebugLevel level) {
  switch (level) {
  case DebugLevel::trace:
    return "T";
  case DebugLevel::info:
    return "I";
  case DebugLevel::warning:
    return "W";
  case DebugLevel::error:
    return "E";
  }
  return "I";
}

} // namespace

void configure_debug_log(std::filesystem::path path) {
  std::scoped_lock lock(g_mutex);
  g_path = std::move(path);
  g_recovery_path = g_path.empty() ? std::filesystem::path{}
                                   : g_path.parent_path() / "SupportAssistTool-recovery.log";
}

void set_debug_logging_enabled(bool enabled) {
  g_enabled.store(enabled, std::memory_order_release);
  if (enabled)
    write_debug_log("Debug", "Debug logging enabled for this process");
}

bool debug_logging_enabled() noexcept {
  return g_enabled.load(std::memory_order_acquire);
}

std::filesystem::path debug_log_path() {
  std::scoped_lock lock(g_mutex);
  return g_path;
}

namespace {

void append_log_line(const std::filesystem::path& path, std::string_view component,
                     std::string_view message, const char* level = "I") noexcept {
  try {
    if (path.empty())
      return;
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    FILE* file = nullptr;
#ifdef _WIN32
    if (_wfopen_s(&file, path.c_str(), L"ab") != 0 || file == nullptr)
      return;
#else
    file = std::fopen(path.string().c_str(), "ab");
    if (file == nullptr)
      return;
#endif
    const std::string line = timestamp_now() + " [" + level + "] [tid " + thread_token() +
                             "] [" + std::string(component) + "] " + std::string(message) + "\r\n";
    std::fwrite(line.data(), 1, line.size(), file);
    std::fclose(file);
  } catch (...) {
    // Diagnostic logging must never interfere with a support operation.
  }
}

} // namespace

void write_debug_log(std::string_view component, std::string_view message) noexcept {
  write_debug_log(DebugLevel::info, component, message);
}

void write_debug_log(DebugLevel level, std::string_view component,
                     std::string_view message) noexcept {
  if (!debug_logging_enabled())
    return;
  std::scoped_lock lock(g_mutex);
  append_log_line(g_path, component, message, level_token(level));
}

void write_debug_exception(std::string_view component, std::string_view operation,
                           std::string_view detail) noexcept {
  if (!debug_logging_enabled())
    return;
  std::scoped_lock lock(g_mutex);
  append_log_line(g_path, component,
                  "caught during " + std::string(operation) + ": " + std::string(detail),
                  level_token(DebugLevel::warning));
}

void write_debug_interaction(std::string_view surface, std::string_view control,
                             std::string_view detail) noexcept {
  if (!debug_logging_enabled())
    return;
  std::scoped_lock lock(g_mutex);
  std::string message = std::string(surface) + " -> " + std::string(control);
  if (!detail.empty())
    message += " (" + std::string(detail) + ")";
  append_log_line(g_path, "UI", message, level_token(DebugLevel::trace));
}

DebugScope::DebugScope(std::string_view component, std::string_view operation) noexcept
    : component_(component), operation_(operation), started_(std::chrono::steady_clock::now()) {
  write_debug_log(DebugLevel::info, component_, "begin " + operation_);
}

void DebugScope::fail(std::string_view reason) noexcept {
  failure_ = std::string(reason);
}

void DebugScope::note(std::string_view detail) noexcept {
  write_debug_log(DebugLevel::trace, component_, operation_ + ": " + std::string(detail));
}

DebugScope::~DebugScope() noexcept {
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - started_);
  const std::string duration = " after " + std::to_string(elapsed.count()) + " ms";
  if (failure_.empty()) {
    write_debug_log(DebugLevel::info, component_, "end " + operation_ + duration);
  } else {
    // A scope that fails is the line an engineer greps for first.
    write_debug_log(DebugLevel::error, component_,
                    "FAILED " + operation_ + duration + ": " + failure_);
  }
}

void write_recovery_log(std::string_view component, std::string_view message) noexcept {
  std::scoped_lock lock(g_mutex);
  append_log_line(g_recovery_path, component, message);
}

std::filesystem::path recovery_log_path() {
  std::scoped_lock lock(g_mutex);
  return g_recovery_path;
}

} // namespace support_assist
