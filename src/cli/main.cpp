#include "commands.hpp"
#include "support_assist/cancellation.hpp"
#include <csignal>
#include <iostream>
#include <string>
#include <vector>
namespace {
support_assist::CancellationToken* g_token = nullptr;
void on_signal(int) {
  if (g_token)
    g_token->cancel();
}
} // namespace
int main(int argc, char** argv) {
  support_assist::CancellationToken token;
  g_token = &token;
  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i)
    args.emplace_back(argv[i]);
  try {
    return support_assist::cli::dispatch(args, token);
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << '\n';
    return 70;
  } catch (...) {
    std::cerr << "fatal: unknown exception\n";
    return 70;
  }
}
