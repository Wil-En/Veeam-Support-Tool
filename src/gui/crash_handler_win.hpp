#pragma once

#include <cstdint>
#include <string_view>

namespace support_assist::gui {

// Installs a process-level last-resort Windows crash recorder that captures
// diagnostic context for native exceptions before the process terminates.
// Normal operation errors still use Result/Status and debug logging.
void install_crash_handler() noexcept;
void set_crash_thread_context(std::wstring_view tool, std::wstring_view phase) noexcept;

// Runs a worker body behind a narrow Windows SEH boundary. This is intentionally
// limited to background tool/artifact workers: ordinary C++ errors still use the
// Result/Status path, while an access violation or stack overflow in a worker is
// converted into a failed operation instead of terminating the entire GUI.
using NativeGuardCallback = void (*)(void*) noexcept;
std::uint32_t run_native_exception_guarded(NativeGuardCallback callback, void* context) noexcept;

} // namespace support_assist::gui
