#include "portable_app.hpp"
#include "dropped_paths.hpp"
#include "../cli/commands.hpp"
#include "support_assist/cancellation.hpp"

#include <csignal>
#include <exception>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

namespace {
support_assist::CancellationToken* g_token = nullptr;
void on_signal(int) { if (g_token != nullptr) g_token->cancel(); }
}

#ifdef SUPPORT_ASSIST_LINUX_QT
// Implemented in src/gui_qt/qt_app.cpp. Declared here rather than in a header because it is the
// only symbol the Qt frontend exposes, and the Xlib build must not see it at all.
int support_assist_run_qt_gui(int argc, char** argv);
#endif

int main(int argc, char** argv) {
#ifdef SUPPORT_ASSIST_LINUX_QT
  // Files or folders dropped on the application arrive as absolute paths and open the window; a
  // command line always starts with a command word.
  std::vector<std::filesystem::path> dropped;
  for (int index = 1; index < argc; ++index) dropped.emplace_back(argv[index]);
  const bool opened_with_paths = support_assist::gui::arguments_are_dropped_paths(dropped);
#else
  const bool opened_with_paths = false;
#endif
  if (argc == 1 || opened_with_paths) {
#ifdef SUPPORT_ASSIST_LINUX_QT
    try { return support_assist_run_qt_gui(argc, argv); }
#else
    try { return support_assist::gui::run_portable_gui(); }
#endif
    catch (const std::exception& error) { std::cerr << "GUI fatal: " << error.what() << '\n'; return 70; }
    catch (...) { std::cerr << "GUI fatal: unknown exception\n"; return 70; }
  }
  support_assist::CancellationToken token;
  g_token = &token;
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::vector<std::string> arguments;
  for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
  try { return support_assist::cli::dispatch(arguments, token); }
  catch (const std::exception& error) { std::cerr << "fatal: " << error.what() << '\n'; return 70; }
  catch (...) { std::cerr << "fatal: unknown exception\n"; return 70; }
}
