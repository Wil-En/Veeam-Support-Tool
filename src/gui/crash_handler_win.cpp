#include "crash_handler_win.hpp"

#include "support_assist/version.hpp"
#include "support_assist/debug_log.hpp"

#include <windows.h>
#include <dbghelp.h>
#include <excpt.h>
#include <malloc.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>
#include <cwchar>

namespace support_assist::gui {
namespace {

thread_local std::array<wchar_t, 192> g_tool{};
thread_local std::array<wchar_t, 192> g_phase{};

void copy_context(std::array<wchar_t, 192>& target, std::wstring_view value) noexcept {
  const std::size_t count = (std::min)(value.size(), target.size() - 1U);
  if (count != 0U)
    std::wmemcpy(target.data(), value.data(), count);
  target[count] = L'\0';
}

LONG WINAPI crash_filter(EXCEPTION_POINTERS* exception) noexcept {
  if (exception == nullptr || exception->ExceptionRecord == nullptr)
    return EXCEPTION_EXECUTE_HANDLER;

  if (exception->ExceptionRecord->ExceptionCode == EXCEPTION_STACK_OVERFLOW)
    static_cast<void>(_resetstkoflw());

  // Crash artifacts live beside the executable under ApplicationLogs, like the rest of SAT's own
  // state, never in the user profile: deleting the SAT folder removes them too, satisfying
  // "leave nothing behind". GetModuleFileNameW is safe here: no heap allocation, and it is the
  // same query the running app uses to resolve its own ApplicationLogs directory.
  wchar_t base[MAX_PATH]{};
  DWORD length = GetModuleFileNameW(nullptr, base, static_cast<DWORD>(std::size(base)));
  if (length == 0U || length >= std::size(base))
    return EXCEPTION_EXECUTE_HANDLER;
  // Strip the executable file name, keeping the trailing separator so "%s..." concatenates.
  while (length > 0U && base[length - 1U] != L'\\' && base[length - 1U] != L'/')
    --length;
  base[length] = L'\0';

  SYSTEMTIME now{};
  GetSystemTime(&now);
  wchar_t directory[MAX_PATH]{};
  _snwprintf_s(directory, _TRUNCATE,
               L"%sApplicationLogs\\SupportAssistTool-Crashes\\SAT-Crash-%04u%02u%02u-%02u%02u%02u-%lu",
               base, now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
               GetCurrentProcessId());
  // Create each level in turn; the earlier levels may not exist yet on a first-run host.
  CreateDirectoryW((std::wstring(base) + L"ApplicationLogs").c_str(), nullptr);
  CreateDirectoryW((std::wstring(base) + L"ApplicationLogs\\SupportAssistTool-Crashes").c_str(),
                   nullptr);
  CreateDirectoryW(directory, nullptr);

  wchar_t context_path[MAX_PATH]{};
  _snwprintf_s(context_path, _TRUNCATE, L"%s\\crash-context.txt", directory);
  HANDLE context = CreateFileW(context_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (context != INVALID_HANDLE_VALUE) {
    char text[4096]{};
    const int count = _snprintf_s(
        text, _TRUNCATE,
        "Support Assist Tool native crash\r\n"
        "Version: %.*s %.*s\r\n"
        "Build revision: %.*s\r\n"
        "UTC: %04u-%02u-%02uT%02u:%02u:%02uZ\r\n"
        "Exception code: 0x%08lX\r\n"
        "Exception address: %p\r\n"
        "Process ID: %lu\r\n"
        "Thread ID: %lu\r\n"
        "Tool: %ls\r\n"
        "Phase: %ls\r\n",
        static_cast<int>(kVersion.size()), kVersion.data(),
        static_cast<int>(kReleaseChannel.size()), kReleaseChannel.data(),
        static_cast<int>(kBuildRevision.size()), kBuildRevision.data(),
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
        exception->ExceptionRecord->ExceptionCode,
        exception->ExceptionRecord->ExceptionAddress,
        GetCurrentProcessId(), GetCurrentThreadId(),
        g_tool[0] == L'\0' ? L"Not identified" : g_tool.data(),
        g_phase[0] == L'\0' ? L"Not identified" : g_phase.data());
    if (count > 0) {
      DWORD written = 0;
      WriteFile(context, text, static_cast<DWORD>(count), &written, nullptr);
    }
    CloseHandle(context);
  }

  wchar_t dump_path[MAX_PATH]{};
  _snwprintf_s(dump_path, _TRUNCATE, L"%s\\SupportAssistTool.dmp", directory);
  HANDLE dump = CreateFileW(dump_path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (dump != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION info{};
    info.ThreadId = GetCurrentThreadId();
    info.ExceptionPointers = exception;
    info.ClientPointers = FALSE;
    MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dump,
                      MiniDumpWithThreadInfo, &info, nullptr, nullptr);
    CloseHandle(dump);
  }
  return EXCEPTION_EXECUTE_HANDLER;
}

[[noreturn]] void terminate_handler() noexcept {
  set_crash_thread_context(L"Application", L"Unhandled C++ termination");
  support_assist::write_recovery_log(
      "Crash",
      "std::terminate invoked | native crash artifacts will be written under the SAT crash directory");
  constexpr DWORD kSatTerminateException = 0xE0005341UL;
  RaiseException(kSatTerminateException, EXCEPTION_NONCONTINUABLE, 0, nullptr);
  TerminateProcess(GetCurrentProcess(), kSatTerminateException);
  std::abort();
}

} // namespace

void install_crash_handler() noexcept {
  ULONG guarantee = 64U * 1024U;
  static_cast<void>(SetThreadStackGuarantee(&guarantee));
  SetUnhandledExceptionFilter(crash_filter);
  std::set_terminate(terminate_handler);
  set_crash_thread_context(L"Application", L"GUI / CLI startup");
}

void set_crash_thread_context(std::wstring_view tool, std::wstring_view phase) noexcept {
  copy_context(g_tool, tool);
  copy_context(g_phase, phase);
}

std::uint32_t run_native_exception_guarded(NativeGuardCallback callback, void* context) noexcept {
  if (callback == nullptr)
    return 0U;
#if defined(_MSC_VER)
  __try {
    callback(context);
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    const std::uint32_t seh_code = static_cast<std::uint32_t>(GetExceptionCode());
    if (seh_code == static_cast<std::uint32_t>(EXCEPTION_STACK_OVERFLOW))
      static_cast<void>(_resetstkoflw());
    return seh_code;
  }
  return 0U;
#else
  // The production Windows build uses MSVC. Keep the source usable by alternate
  // Windows compilers without pretending they provide the same SEH isolation.
  callback(context);
  return 0U;
#endif
}

} // namespace support_assist::gui
