// Quick scan on Windows: Packet Monitor (pktmon) in its real-time mode, which writes no file, with a
// filter named SAT-QuickScan on the port (TCP SYN, or UDP), captured at the network adapters. The
// capture's text is read on a worker and counted (quick_scan.cpp). A scan starts only when pktmon
// is not capturing and has no filters, and on stop it removes the filters only while they are
// still exactly its own. Needs SAT running as administrator.

#include "support_assist/quick_scan.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/process.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/support_tools.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <thread>

namespace support_assist {
namespace {

constexpr char kFilterName[] = "SAT-QuickScan";
// Lines read without a packet decoded before the output is taken as unreadable.
constexpr std::size_t kUnreadableAfterLines = 200;

Error scan_error(std::string message, bool elevation_may_help) {
  Error error;
  error.component = "Quick scan";
  error.operation = "start quick scan";
  error.message = std::move(message);
  error.elevation_may_help = elevation_may_help;
  return error;
}

std::filesystem::path pktmon_path() {
  wchar_t system[MAX_PATH] = {};
  const UINT length = GetSystemDirectoryW(system, MAX_PATH);
  if (length == 0 || length >= MAX_PATH)
    return {};
  return std::filesystem::path(std::wstring(system, length)) / L"PktMon.exe";
}

Result<ProcessResult> pktmon(std::vector<std::string> arguments) {
  ProcessOptions options;
  options.executable = pktmon_path();
  options.arguments = std::move(arguments);
  options.timeout = std::chrono::seconds(30);
  CancellationSource cancel;
  return run_process_capture(options, cancel.token());
}

bool mentions(std::string_view text, std::string_view word) {
  return ascii_lower(text).find(word) != std::string::npos;
}

bool capture_inactive(std::string_view text) {
  return mentions(text, "not running") || mentions(text, "not started") || mentions(text, "stopped");
}

std::string normalized(std::string value) {
  value.erase(std::remove(value.begin(), value.end(), '\r'), value.end());
  while (!value.empty() && (value.back() == '\n' || value.back() == ' ' || value.back() == '\t'))
    value.pop_back();
  return value;
}

std::string first_line(std::string text) {
  text = normalized(std::move(text));
  const std::size_t newline = text.find('\n');
  return newline == std::string::npos ? text : text.substr(0, newline);
}

} // namespace

struct QuickScan::Impl {
  quick_scan_detail::AttemptCounter counter;
  quick_scan_detail::PktmonReader lines;
  mutable std::mutex mutex;
  std::atomic<bool> stopping{false};
  HANDLE process = nullptr;
  HANDLE output = nullptr; // the read end of the capture's standard output
  std::thread reader;
  bool filter_owned = false;
  std::string filter_snapshot;
  std::size_t lines_read = 0;
  std::size_t packets_decoded = 0;
  std::string note;

  Impl(std::uint16_t port, PortProtocol protocol) : counter(port, protocol) {}

  void read_lines() {
    std::string pending;
    char buffer[4096];
    DWORD read = 0;
    while (ReadFile(output, buffer, sizeof(buffer), &read, nullptr) != FALSE && read > 0) {
      pending.append(buffer, read);
      std::size_t newline = pending.find('\n');
      while (newline != std::string::npos) {
        std::string text = pending.substr(0, newline);
        pending.erase(0, newline + 1);
        if (!text.empty() && text.back() == '\r')
          text.pop_back();
        std::scoped_lock lock(mutex);
        ++lines_read;
        if (auto packet = lines.line(text)) {
          ++packets_decoded;
          counter.add(*packet);
        }
        newline = pending.find('\n');
      }
      if (pending.size() > 65536)
        pending.clear();
    }
  }

  void remove_filter() {
    if (!filter_owned)
      return;
    filter_owned = false;
    const auto current = pktmon({"filter", "list"});
    if (current.ok() && normalized(current.value().output) == filter_snapshot)
      static_cast<void>(pktmon({"filter", "remove"}));
    else
      note = "Packet Monitor's filters changed while the scan ran, so they were left as they are.";
  }

  void close_handles() {
    for (HANDLE* handle : {&process, &output}) {
      if (*handle != nullptr)
        CloseHandle(*handle);
      *handle = nullptr;
    }
  }
};

QuickScanSupport quick_scan_support() {
  QuickScanSupport support;
  const auto context = current_security_context();
  if (!context.ok() || !context.value().elevated) {
    support.reason = "Quick scan needs SAT running as administrator: Packet Monitor captures only for an "
                     "administrator.";
    return support;
  }
  std::error_code error;
  const std::filesystem::path program = pktmon_path();
  if (program.empty() || !std::filesystem::exists(program, error)) {
    support.reason = "Quick scan uses Packet Monitor (pktmon), which this Windows does not have.";
    return support;
  }
  static const bool real_time = []() {
    const auto help = pktmon({"start", "help"});
    return help.ok() && mentions(help.value().output, "real-time");
  }();
  if (!real_time) {
    support.reason = "This Windows's Packet Monitor has no real-time mode, which Quick scan needs so that no "
                     "capture file is written.";
    return support;
  }
  support.available = true;
  return support;
}

Result<std::unique_ptr<QuickScan>> QuickScan::start(std::uint16_t port, PortProtocol protocol) {
  using Failure = Result<std::unique_ptr<QuickScan>>;
  const QuickScanSupport support = quick_scan_support();
  if (!support.available)
    return Failure::failure(scan_error(support.reason, true));
  const auto status = pktmon({"status"});
  if (!status.ok())
    return Failure::failure(status.error());
  if (!capture_inactive(status.value().output))
    return Failure::failure(scan_error(
        "Packet Monitor is already capturing (pktmon status), from another tool or a Packet Capture in SAT. "
        "Stop that capture, then start the scan.",
        false));
  const auto listed = pktmon({"filter", "list"});
  if (!listed.ok())
    return Failure::failure(listed.error());
  if (!pktmon_filter_list_empty(listed.value().output))
    return Failure::failure(scan_error(
        "Packet Monitor already has filters (pktmon filter list). Quick scan adds its own and removes them when "
        "it ends, so it starts only when there are none.",
        false));

  auto impl = std::make_unique<Impl>(port, protocol);
  std::vector<std::string> add{"filter", "add", kFilterName, "-t"};
  if (protocol == PortProtocol::tcp) {
    add.emplace_back("TCP");
    add.emplace_back("SYN");
  } else {
    add.emplace_back("UDP");
  }
  add.emplace_back("-p");
  add.push_back(std::to_string(port));
  const auto added = pktmon(add);
  if (!added.ok())
    return Failure::failure(added.error());
  if (added.value().exit_code != 0)
    return Failure::failure(scan_error("Packet Monitor did not take the filter: " + first_line(added.value().output), false));
  impl->filter_owned = true;
  const auto snapshot = pktmon({"filter", "list"});
  impl->filter_snapshot = snapshot.ok() ? normalized(snapshot.value().output) : std::string();

  // The capture, with its standard output (and errors) on a pipe this process reads.
  SECURITY_ATTRIBUTES inherit{};
  inherit.nLength = sizeof(inherit);
  inherit.bInheritHandle = TRUE;
  HANDLE read_end = nullptr;
  HANDLE write_end = nullptr;
  if (CreatePipe(&read_end, &write_end, &inherit, 0) == FALSE ||
      SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0) == FALSE) {
    if (read_end != nullptr)
      CloseHandle(read_end);
    if (write_end != nullptr)
      CloseHandle(write_end);
    impl->remove_filter();
    return Failure::failure(scan_error("The pipe for Packet Monitor's output could not be made.", false));
  }
  const std::wstring program = pktmon_path().wstring();
  std::wstring command = L"\"" + program + L"\" start --capture --comp nics --log-mode real-time";
  std::vector<wchar_t> mutable_command(command.begin(), command.end());
  mutable_command.push_back(L'\0');
  STARTUPINFOW startup{};
  startup.cb = sizeof(startup);
  startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdOutput = write_end;
  startup.hStdError = write_end;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  PROCESS_INFORMATION process{};
  const BOOL launched = CreateProcessW(program.c_str(), mutable_command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                       nullptr, nullptr, &startup, &process);
  CloseHandle(write_end);
  if (launched == FALSE) {
    CloseHandle(read_end);
    impl->remove_filter();
    return Failure::failure(scan_error("Packet Monitor could not be started (error " + std::to_string(GetLastError()) + ").", false));
  }
  CloseHandle(process.hThread);
  impl->process = process.hProcess;
  impl->output = read_end;
  Impl* raw = impl.get();
  impl->reader = std::thread([raw]() { raw->read_lines(); });
  return Result<std::unique_ptr<QuickScan>>::success(std::unique_ptr<QuickScan>(new QuickScan(std::move(impl))));
}

QuickScanCounts QuickScan::counts() const {
  std::scoped_lock lock(impl_->mutex);
  QuickScanCounts counts = impl_->counter.counts();
  if (impl_->packets_decoded == 0 && impl_->lines_read >= kUnreadableAfterLines)
    counts.note = "Packet Monitor's output could not be read, so what arrived is not known.";
  else if (!impl_->note.empty())
    counts.note = impl_->note;
  return counts;
}

void QuickScan::stop() {
  if (!impl_ || impl_->stopping.exchange(true))
    return;
  // Ending the session ends the real-time capture, whose output then closes.
  static_cast<void>(pktmon({"stop"}));
  if (impl_->process != nullptr && WaitForSingleObject(impl_->process, 5000) != WAIT_OBJECT_0)
    TerminateProcess(impl_->process, 1);
  if (impl_->reader.joinable())
    impl_->reader.join();
  impl_->close_handles();
  impl_->remove_filter();
}

QuickScan::QuickScan(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

QuickScan::~QuickScan() { stop(); }

} // namespace support_assist
