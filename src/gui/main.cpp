#include "app_window.hpp"
#include "crash_handler_win.hpp"
#include "dropped_paths.hpp"
#include "../elevated_helper/pipe_server.hpp"
#include "../cli/commands.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/version.hpp"

#include <windows.h>
#include <commctrl.h>
#include <objbase.h>
#include <rpcdce.h>
#include <shellapi.h>

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {
support_assist::CancellationToken* g_cli_token = nullptr;

const std::wstring& product_name_wide() {
  static const std::wstring value = support_assist::wide_from_utf8(support_assist::kProductName);
  return value;
}

const std::wstring& startup_failure_title() {
  static const std::wstring value = product_name_wide() + L" startup failure";
  return value;
}

void configure_dpi_awareness() {
  using SetProcessDpiAwarenessContextFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
  const HMODULE user32 = GetModuleHandleW(L"user32.dll");
  if (user32 != nullptr) {
    const auto set_context = reinterpret_cast<SetProcessDpiAwarenessContextFn>(
        GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
    if (set_context != nullptr &&
        set_context(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != FALSE) {
      return;
    }
  }
  static_cast<void>(SetProcessDPIAware());
}

std::optional<std::wstring> option(int argc,
                                   wchar_t** argv,
                                   std::wstring_view name) {
  for (int index = 1; index + 1 < argc; ++index) {
    if (argv[index] == name)
      return std::wstring(argv[index + 1]);
  }
  return std::nullopt;
}

bool has_argument(int argc, wchar_t** argv, std::wstring_view value) {
  for (int index = 1; index < argc; ++index) {
    if (argv[index] == value)
      return true;
  }
  return false;
}

int run_elevated_mode(int argc, wchar_t** argv) {
  const auto pipe = option(argc, argv, L"--pipe");
  const auto nonce = option(argc, argv, L"--nonce");
  const auto parent = option(argc, argv, L"--parent-pid");
  if (!pipe || !nonce || !parent)
    return 64;

  std::uint32_t parent_pid = 0;
  try {
    parent_pid = static_cast<std::uint32_t>(std::stoul(*parent));
  } catch (...) {
    return 64;
  }

  return run_elevated_pipe_client(
      *pipe,
      support_assist::utf8_from_wide(*nonce),
      parent_pid);
}

void on_cli_signal(int) {
  if (g_cli_token != nullptr)
    g_cli_token->cancel();
}

// True when the shell has already pointed this standard handle somewhere - a file, a pipe - and
// SAT must not take it back. FILE_TYPE_CHAR is a console or a character device, which is the only
// case that needs reopening; an unset or invalid handle needs it too.
bool standard_handle_is_redirected(DWORD standard_handle) {
  const HANDLE handle = GetStdHandle(standard_handle);
  if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
    return false;
  const DWORD type = GetFileType(handle) & ~FILE_TYPE_REMOTE;
  return type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE;
}

void attach_cli_console() {
  if (GetConsoleWindow() == nullptr) {
    if (AttachConsole(ATTACH_PARENT_PROCESS) == FALSE && GetLastError() != ERROR_ACCESS_DENIED)
      static_cast<void>(AllocConsole());
  }

  // Only reopen the streams the shell has NOT redirected. Reopening all three onto CONOUT$ put
  // the output on screen no matter what the caller asked for, so "SupportAssistTool.exe --help >
  // help.txt" printed the help and wrote an empty file - and a pipe into findstr received nothing.
  FILE* stream = nullptr;
  if (!standard_handle_is_redirected(STD_INPUT_HANDLE))
    static_cast<void>(freopen_s(&stream, "CONIN$", "r", stdin));
  if (!standard_handle_is_redirected(STD_OUTPUT_HANDLE))
    static_cast<void>(freopen_s(&stream, "CONOUT$", "w", stdout));
  if (!standard_handle_is_redirected(STD_ERROR_HANDLE))
    static_cast<void>(freopen_s(&stream, "CONOUT$", "w", stderr));
  static_cast<void>(SetConsoleCP(CP_UTF8));
  static_cast<void>(SetConsoleOutputCP(CP_UTF8));
}

int run_cli_mode(int argc, wchar_t** argv) {
  attach_cli_console();

  support_assist::CancellationToken token;
  g_cli_token = &token;
  std::signal(SIGINT, on_cli_signal);
  std::signal(SIGTERM, on_cli_signal);

  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc > 1 ? argc - 1 : 0));
  for (int index = 1; index < argc; ++index)
    args.push_back(support_assist::utf8_from_wide(argv[index]));

  int exit_code = 0;
  try {
    exit_code = support_assist::cli::dispatch(args, token);
  } catch (const std::exception& error) {
    std::cerr << "fatal: " << error.what() << '\n';
    exit_code = 70;
  } catch (...) {
    std::cerr << "fatal: unknown exception\n";
    exit_code = 70;
  }

  std::cout.flush();
  std::cerr.flush();
  g_cli_token = nullptr;
  return exit_code;
}

int run_gui_mode(HINSTANCE instance, int show_command,
                 std::vector<std::filesystem::path> dropped = {}) {
  configure_dpi_awareness();

  const HRESULT com_result = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  if (FAILED(com_result)) {
    MessageBoxW(nullptr,
                (product_name_wide() + L" could not initialize the required COM apartment.").c_str(),
                startup_failure_title().c_str(),
                MB_OK | MB_ICONERROR);
    return 2;
  }

  const HRESULT security_result = CoInitializeSecurity(nullptr,
                                                       -1,
                                                       nullptr,
                                                       nullptr,
                                                       RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                                                       RPC_C_IMP_LEVEL_IMPERSONATE,
                                                       nullptr,
                                                       EOAC_STATIC_CLOAKING,
                                                       nullptr);
  if (FAILED(security_result) && security_result != RPC_E_TOO_LATE) {
    MessageBoxW(nullptr,
                (product_name_wide() +
                 L" could not initialize COM security required by Windows diagnostic modules.")
                    .c_str(),
                startup_failure_title().c_str(),
                MB_OK | MB_ICONERROR);
    CoUninitialize();
    return 3;
  }

  INITCOMMONCONTROLSEX common_controls{};
  common_controls.dwSize = sizeof(common_controls);
  common_controls.dwICC = ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES |
                          ICC_PROGRESS_CLASS | ICC_TAB_CLASSES;
  if (InitCommonControlsEx(&common_controls) == FALSE) {
    CoUninitialize();
    return 4;
  }

  AppWindow application(instance);
#ifdef SUPPORT_ASSIST_UI_SELFCHECK
  // Same contract as the Qt build: SAT_UI_SCREENSHOT names a directory and the application drives
  // itself through every page, captures each one and exits instead of waiting for a person.
  // SAT_UI_QA drives the same self-check build through every page and card transition, checking
  // after each one that no control from the page just left is still painted over the new one.
  wchar_t qa_report[1024] = {};
  const DWORD qa_length = GetEnvironmentVariableW(L"SAT_UI_QA", qa_report, 1024);
  if (qa_length > 0U && qa_length < 1024U) {
    attach_cli_console();
    const int qa_result =
        application.create(show_command) ? application.run_ui_qa_sweep(qa_report) : 1;
    CoUninitialize();
    return qa_result;
  }

  wchar_t shot_directory[1024] = {};
  const DWORD shot_length = GetEnvironmentVariableW(L"SAT_UI_SCREENSHOT", shot_directory, 1024);
  if (shot_length > 0U && shot_length < 1024U) {
    attach_cli_console();
    const int shot_result = application.create(show_command)
                                ? application.run_screenshot_harness(shot_directory)
                                : 1;
    CoUninitialize();
    return shot_result;
  }
#endif
  if (!application.create(show_command)) {
    CoUninitialize();
    return 1;
  }
  // Files or folders dropped on the executable: handled once the window is up.
  if (!dropped.empty())
    application.queue_dropped_paths(std::move(dropped));
  const int result = application.message_loop();
  CoUninitialize();
  return result;
}
} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show_command) {
  support_assist::gui::install_crash_handler();
  int argc = 0;
  wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
  if (argv == nullptr)
    return 64;

  int result = 0;
  if (has_argument(argc, argv, L"--internal-elevated-helper")) {
    result = run_elevated_mode(argc, argv);
  } else if (argc > 1) {
    // Files or folders dropped on the executable arrive as absolute paths and open the window; a
    // command line always starts with a command word.
    std::vector<std::filesystem::path> dropped;
    for (int index = 1; index < argc; ++index)
      dropped.emplace_back(argv[index]);
    if (support_assist::gui::arguments_are_dropped_paths(dropped))
      result = run_gui_mode(instance, show_command, std::move(dropped));
    else
      result = run_cli_mode(argc, argv);
  } else {
    result = run_gui_mode(instance, show_command);
  }

  LocalFree(argv);
  return result;
}
