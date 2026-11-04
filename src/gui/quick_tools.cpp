// The quick tools' windows on Windows: Name Check (F2), Local Port Checker (F6), Time Check (F7),
// File Lock Check (F8), Volume Check (F9), the File Transfer Calculator (F10) and Service and Process
// Watch (F12), with the Object Storage Check from its Tools card. One window per
// tool, opened by its key or the Tools menu in both roles. Each check runs on a worker thread and
// its result is drawn by report_panel.cpp from gui_shared/quick_tool_reports.hpp.

#include "app_window.hpp"

#include "keyboard_shortcuts.hpp"
#include "quick_tool_guides.hpp"
#include "quick_tool_output.hpp"
#include "quick_tool_reports.hpp"
#include "report_panel.hpp"
#include "ui_theme.hpp"
#include "workspace_cards.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/debug_log.hpp"
#include "support_assist/file_lock.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/local_ports.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/network.hpp"
#include "support_assist/object_storage.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/process_logs.hpp"
#include "support_assist/quick_scan.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/tool_results.hpp"
#include "support_assist/tool_run_profiles.hpp"
#include "support_assist/veeam_watch.hpp"
#include "support_assist/volume_check.hpp"

#include <commctrl.h>
#include <commdlg.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <uxtheme.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace {

namespace gui = support_assist::gui;
using gui::ShortcutCommand;

enum class QuickTool { name_check, local_ports, time_check, file_lock, volume_check, watch, object_storage, transfer };

constexpr int kRunId = IDOK; // Enter in a field runs the check
constexpr int kInputId = 8101;
constexpr int kBrowseId = 8102;
constexpr int kCopyId = 8103;
constexpr int kNoteId = 8104;
constexpr int kLinkId = 8105;
constexpr int kTcpId = 8106;
constexpr int kUdpId = 8107;
constexpr int kPresetId = 8108;
constexpr int kProcessId = 8109;
constexpr int kProcessRunId = 8110;
constexpr int kTableId = 8111;
constexpr int kListenStartId = 8112;
constexpr int kListenStopId = 8113;
constexpr int kMinutesId = 8114;
constexpr int kBannerId = 8115;
constexpr int kConvertInputId = 8116;
constexpr int kOffsetId = 8117;
constexpr int kConvertId = 8118;
constexpr int kEventsId = 8119;
constexpr int kQuickScanId = 8120;
constexpr int kConnectionsId = 8121;
constexpr int kFolderBrowseId = 8122;
constexpr int kLogInputId = 8123;
constexpr int kLogBrowseId = 8124;
constexpr int kShowInId = 8125;
constexpr int kStoragePresetId = 8126;
constexpr int kEndpointId = 8127;
constexpr int kRegionId = 8128;
constexpr int kAddressingId = 8129;
constexpr int kFingerprintId = 8130;
constexpr int kAccessKeyId = 8131;
constexpr int kSecretKeyId = 8132;
constexpr int kModeEnterId = 8133;
constexpr int kModeMeasureId = 8134;
constexpr int kSizeUnitId = 8135;
constexpr int kLinkSpeedId = 8136;
constexpr int kLinkUnitId = 8137;
constexpr int kMtuId = 8138;
constexpr int kShareId = 8139;
constexpr int kReducedId = 8140;
constexpr int kNetworkSpeedId = 8141;
constexpr int kAdapterId = 8142;
constexpr int kAdapterRefreshId = 8143;
constexpr int kTestHostId = 8144;
constexpr int kTestPortId = 8145;
constexpr int kUsingId = 8146;
constexpr int kSendId = 8147;
constexpr int kMeasureId = 8148;
constexpr int kOpenResultId = 8149;
constexpr int kClearResultId = 8150;
constexpr int kEmailId = 8151;
constexpr int kProductId = 8152;
constexpr int kTrustId = 8153;
constexpr int kCertificateOpenId = 8154;
constexpr int kStorageSpeedId = 8155;
constexpr int kNetworkUnitId = 8156;
constexpr int kStorageUnitId = 8157;
constexpr int kLogLinkId = 8158;
constexpr int kExportId = 8159; // Local Port Checker: the ports as CSV or JSON
constexpr UINT kLogMenuFirst = 9000;

constexpr UINT kResultMessage = WM_APP + 41;
constexpr UINT kListenerEventMessage = WM_APP + 42;
constexpr UINT kListenerDoneMessage = WM_APP + 43;
constexpr UINT kScanStartedMessage = WM_APP + 44;
constexpr UINT kScanEndedMessage = WM_APP + 45;
constexpr UINT_PTR kWatchTimer = 1;
constexpr UINT_PTR kCountdownTimer = 2;
// The check again, a moment after a listener starts or stops, so its row shows it.
constexpr UINT_PTR kRecheckTimer = 3;
constexpr UINT kRecheckDelayMs = 1500;
// While a port check's result is shown, the sockets and the firewall are read again this often, so
// a port opened or a rule added later shows without another check.
constexpr UINT kLiveRecheckMs = 5000;
constexpr UINT kWatchIntervalMs = 2000;

constexpr COLORREF kWindowColour = RGB(18, 30, 28);
constexpr COLORREF kFieldColour = RGB(22, 42, 44);
constexpr COLORREF kTableColour = RGB(13, 31, 33);
constexpr COLORREF kTextColour = RGB(225, 236, 231);
constexpr COLORREF kLabelColour = RGB(196, 214, 207);
constexpr COLORREF kHeadingColour = RGB(114, 224, 106);

std::wstring widen(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

std::string narrow_text(const std::wstring& text) {
  return support_assist::utf8_from_wide(text);
}

std::wstring text_of(HWND control) {
  if (control == nullptr)
    return {};
  const int length = GetWindowTextLengthW(control);
  std::wstring text(static_cast<std::size_t>(length) + 1U, L'\0');
  GetWindowTextW(control, text.data(), length + 1);
  text.resize(static_cast<std::size_t>(length));
  return text;
}

std::optional<QuickTool> tool_for(ShortcutCommand command) {
  switch (command) {
  case ShortcutCommand::name_check: return QuickTool::name_check;
  case ShortcutCommand::local_port_checker: return QuickTool::local_ports;
  case ShortcutCommand::time_check: return QuickTool::time_check;
  case ShortcutCommand::file_lock_check: return QuickTool::file_lock;
  case ShortcutCommand::volume_check: return QuickTool::volume_check;
  case ShortcutCommand::service_watch: return QuickTool::watch;
  case ShortcutCommand::object_storage_check: return QuickTool::object_storage;
  case ShortcutCommand::file_transfer_calculator: return QuickTool::transfer;
  default: return std::nullopt;
  }
}

std::wstring tool_title(QuickTool tool) {
  switch (tool) {
  case QuickTool::name_check: return L"Name Check";
  case QuickTool::local_ports: return L"Local Port Checker";
  case QuickTool::time_check: return L"Time Check";
  case QuickTool::file_lock: return L"File Lock Check";
  case QuickTool::volume_check: return L"Volume Check";
  case QuickTool::watch: return L"Service and Process Watch";
  case QuickTool::object_storage: return L"Object Storage Check";
  case QuickTool::transfer: return L"File Transfer Calculator";
  }
  return L"";
}

ShortcutCommand command_for(QuickTool tool) {
  switch (tool) {
  case QuickTool::name_check: return ShortcutCommand::name_check;
  case QuickTool::local_ports: return ShortcutCommand::local_port_checker;
  case QuickTool::time_check: return ShortcutCommand::time_check;
  case QuickTool::file_lock: return ShortcutCommand::file_lock_check;
  case QuickTool::volume_check: return ShortcutCommand::volume_check;
  case QuickTool::watch: return ShortcutCommand::service_watch;
  case QuickTool::object_storage: return ShortcutCommand::object_storage_check;
  case QuickTool::transfer: return ShortcutCommand::file_transfer_calculator;
  }
  return ShortcutCommand::help;
}

// What the tool checks and how to use it, in its report area until it has a result. The calculator
// shows its mode's entries.
void show_guide(HWND report, QuickTool tool, bool measuring = false) {
  const std::string_view mode = tool != QuickTool::transfer ? std::string_view()
                                : measuring                 ? std::string_view(gui::kTransferModeLive)
                                                            : std::string_view(gui::kTransferModeManual);
  set_report_panel_report(report, gui::quick_tool_guide_report(command_for(tool), mode));
}

bool copy_to_clipboard(HWND owner, const std::wstring& text) {
  if (OpenClipboard(owner) == FALSE)
    return false;
  EmptyClipboard();
  const std::size_t bytes = (text.size() + 1U) * sizeof(wchar_t);
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
  bool copied = false;
  if (memory != nullptr) {
    if (void* target = GlobalLock(memory)) {
      std::memcpy(target, text.c_str(), bytes);
      GlobalUnlock(memory);
      copied = SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    }
    if (!copied)
      GlobalFree(memory);
  }
  CloseClipboard();
  return copied;
}

// A file or a folder from the shell's own dialog.
std::wstring choose_path(HWND owner, bool folder) {
  IFileOpenDialog* raw_dialog = nullptr;
  if (FAILED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&raw_dialog))))
    return {};
  std::unique_ptr<IFileOpenDialog, void (*)(IFileOpenDialog*)> dialog(
      raw_dialog, [](IFileOpenDialog* value) { value->Release(); });
  FILEOPENDIALOGOPTIONS options{};
  if (SUCCEEDED(dialog->GetOptions(&options)))
    dialog->SetOptions(options | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST |
                       (folder ? FOS_PICKFOLDERS : FOS_FILEMUSTEXIST));
  if (FAILED(dialog->Show(owner)))
    return {};
  IShellItem* raw_item = nullptr;
  if (FAILED(dialog->GetResult(&raw_item)))
    return {};
  std::unique_ptr<IShellItem, void (*)(IShellItem*)> item(raw_item, [](IShellItem* value) { value->Release(); });
  PWSTR path = nullptr;
  if (FAILED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) || path == nullptr)
    return {};
  std::wstring chosen = path;
  CoTaskMemFree(path);
  return chosen;
}

std::string this_machine_name() {
  wchar_t name[256] = {};
  DWORD length = 256;
  if (GetComputerNameExW(ComputerNameDnsHostname, name, &length) == FALSE)
    return {};
  return narrow_text(name);
}

std::wstring minutes_seconds(std::chrono::seconds remaining) {
  const long long total = std::max<long long>(0, remaining.count());
  wchar_t text[32] = {};
  std::swprintf(text, 32, L"%lld:%02lld", total / 60, total % 60);
  return text;
}

void insert_columns(HWND list, const std::vector<std::pair<const wchar_t*, int>>& columns, int scale_percent) {
  for (std::size_t column = 0; column < columns.size(); ++column) {
    LVCOLUMNW definition{};
    definition.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    definition.pszText = const_cast<LPWSTR>(columns[column].first);
    definition.cx = MulDiv(columns[column].second, scale_percent, 100);
    definition.iSubItem = static_cast<int>(column);
    ListView_InsertColumn(list, static_cast<int>(column), &definition);
  }
}

int insert_row(HWND list, int at, const std::vector<std::wstring>& cells) {
  std::wstring first = cells.empty() ? std::wstring() : cells.front();
  LVITEMW item{};
  item.mask = LVIF_TEXT;
  item.iItem = at;
  item.pszText = first.data();
  const int row = ListView_InsertItem(list, &item);
  if (row < 0)
    return row;
  for (std::size_t column = 1; column < cells.size(); ++column) {
    std::wstring cell = cells[column];
    ListView_SetItemText(list, row, static_cast<int>(column), cell.data());
  }
  return row;
}

// The result a worker hands back to its window.
struct Outcome {
  std::optional<gui::QuickToolReport> report;
  bool partial = false; // a report of work still running; the final Outcome follows
  std::optional<support_assist::PortCheckResult> ports;
  std::optional<support_assist::WatchSnapshot> snapshot;
  std::optional<std::vector<support_assist::VolumeInfo>> volumes; // Volume Check's list
  std::string resolved_address; // Name Check: the first address the name resolved to
  std::string error;
  std::string activity_result;
  std::string activity_detail;
  std::string result_json; // the raw result, kept as the run's output on a Customer / Lab machine
  bool quiet = false; // the check run again for a listener: no activity line
  // Time Check's converter: a log's own clock, read from the path given.
  std::shared_ptr<const support_assist::LogClock> log_clock;
  std::wstring log_path;
  // The Object Storage Check: the storage's clock against this machine's, when it was read.
  std::optional<double> clock_offset_seconds;
  // The File Transfer Calculator's network test.
  bool transfer_measure = false;
  std::optional<support_assist::TransferSpeed> transfer_speed;
  bool transfer_ipv6 = false;
  // Watch's Its log: the logs written near the moment a process ended.
  std::optional<std::vector<support_assist::LogWrittenNear>> logs_near;
  std::int64_t logs_near_at = 0;
  std::string logs_near_name;
};

// A Quick scan that started, or why it did not.
struct ScanStart {
  std::unique_ptr<support_assist::QuickScan> scan;
  std::string error;
};

// Stops a Quick scan away from the window's thread: pktmon takes a moment to stop.
void stop_scan_in_background(std::unique_ptr<support_assist::QuickScan> scan) {
  if (!scan)
    return;
  std::thread([owned = std::move(scan)]() mutable { owned->stop(); }).detach();
}

// Runs work on a worker and posts its Outcome to the window. When the window has gone, PostMessage
// fails and the Outcome is freed here.
template <typename Work> void run_in_background(HWND window, Work work) {
  std::thread([window, work]() mutable {
    auto outcome = std::make_unique<Outcome>();
    try {
      *outcome = work();
    } catch (const std::exception& failure) {
      outcome->error = failure.what();
    }
    if (PostMessageW(window, kResultMessage, 0, reinterpret_cast<LPARAM>(outcome.get())) != FALSE)
      outcome.release();
  }).detach();
}

struct ListenerEvent {
  std::wstring text; // why the listener ended; empty when it ended on time or on Stop
  std::wstring time; // a connection's clock time, UTC
  std::wstring peer; // its address and port
  std::wstring what; // a connection, a datagram, a SAT probe
  std::string time_utc; // the connection's time in full, for the run's output
};

// "2026-09-29T14:05:31.123Z" -> "14:05:31".
std::wstring clock_of(const std::string& iso) {
  const std::size_t at = iso.find('T');
  return widen(at == std::string::npos ? iso : iso.substr(at + 1, 8));
}

} // namespace

// Everything a quick tool window holds. Owned by the window and deleted when it closes.
struct QuickToolState {
  AppWindow* app = nullptr;
  QuickTool tool = QuickTool::name_check;
  HWND window = nullptr;
  HWND input_label = nullptr;
  HWND input = nullptr;
  HWND run = nullptr;
  HWND browse = nullptr;
  HWND folder_browse = nullptr; // File Lock Check: a folder, for everything under it
  HWND report = nullptr;
  HWND status = nullptr;
  HWND copy = nullptr;
  HWND save_as = nullptr; // Export...: the Local Port Checker's rows as CSV or JSON
  HWND note = nullptr;
  HWND link = nullptr;
  HWND log_link = nullptr; // Watch: the logs written when the selected change's process ended
  // Local Port Checker
  HWND tcp = nullptr;
  HWND udp = nullptr;
  HWND preset = nullptr;
  HWND process_label = nullptr;
  HWND process = nullptr;
  HWND process_run = nullptr;
  HWND table = nullptr;
  HWND listen_start = nullptr;
  HWND listen_stop = nullptr;
  HWND minutes_label = nullptr;
  HWND minutes = nullptr;
  HWND banner_label = nullptr;
  HWND banner = nullptr;
  HWND listen_status = nullptr;
  // The listener's panel on the right: its state, Quick scan and each connection.
  HWND side_title = nullptr;
  HWND side_clock = nullptr;
  HWND side_left = nullptr;
  HWND side_progress = nullptr;
  HWND quick_scan = nullptr;
  HWND scan_reading = nullptr;
  HWND connections = nullptr;
  RECT side_box{};
  // Time Check's converter
  HWND converter_heading = nullptr;
  HWND convert_label = nullptr;
  HWND convert_input = nullptr;
  HWND log_label = nullptr;
  HWND log_input = nullptr;
  HWND log_browse = nullptr;
  HWND offset_label = nullptr;
  HWND offset = nullptr;
  HWND show_label = nullptr;
  HWND show_in = nullptr;
  HWND convert = nullptr;
  HWND convert_report = nullptr;
  // The log Written in's From the log file reads, once read, and the path it was read from.
  std::shared_ptr<const support_assist::LogClock> log_clock;
  std::wstring log_clock_path;
  bool reading_log = false;
  bool convert_after_read = false;
  // Service and Process Watch
  HWND events = nullptr;
  // The Object Storage Check
  HWND storage_preset_label = nullptr;
  HWND storage_preset = nullptr;
  HWND endpoint_label = nullptr;
  HWND endpoint = nullptr;
  HWND region_label = nullptr;
  HWND region = nullptr;
  HWND addressing_label = nullptr;
  HWND addressing = nullptr;
  HWND fingerprint_label = nullptr;
  HWND fingerprint = nullptr;
  HWND access_label = nullptr;
  HWND access = nullptr;
  HWND secret_label = nullptr;
  HWND secret = nullptr;
  std::vector<support_assist::ObjectStoragePreset> storage_presets;
  HWND trust = nullptr;            // the certificate store, a certificate file or a fingerprint
  HWND certificate_open = nullptr;
  HWND product_label = nullptr;
  HWND product = nullptr;
  std::vector<std::string> product_ids; // in the Compare with list's order
  // The File Transfer Calculator
  HWND mode_enter = nullptr;
  HWND mode_measure = nullptr;
  HWND size_unit = nullptr;
  HWND link_label = nullptr;
  HWND link_speed = nullptr;
  HWND link_unit = nullptr;
  HWND mtu_label = nullptr;
  HWND mtu = nullptr;
  HWND share_label = nullptr;
  HWND share = nullptr;
  HWND share_suffix = nullptr;
  HWND reduced_label = nullptr;
  HWND reduced = nullptr;
  HWND reduced_suffix = nullptr;
  HWND percent_tips = nullptr; // hover help on the two percentages
  HWND network_speed_label = nullptr; // Manual: the speeds the live test measures, typed in
  HWND network_speed_field = nullptr;
  HWND network_unit = nullptr;
  HWND storage_speed_label = nullptr;
  HWND storage_speed_field = nullptr;
  HWND storage_unit = nullptr;
  HWND adapter_label = nullptr;
  HWND adapter = nullptr;
  HWND adapter_refresh = nullptr;
  HWND test_label = nullptr;
  HWND test_host = nullptr;
  HWND test_port_label = nullptr;
  HWND test_port = nullptr;
  HWND using_label = nullptr;
  HWND using_tool = nullptr;
  HWND send_label = nullptr;
  HWND send_size = nullptr;
  HWND measure = nullptr;
  HWND storage_text = nullptr; // Live test: which figure to type, or where an opened one came from
  HWND open_result = nullptr;
  HWND clear_result = nullptr;
  HWND email = nullptr;
  HWND side_report = nullptr; // the speeds, the email text and the terms
  bool measuring = false;
  std::string transfer_recorded; // the last estimate written to the history
  std::vector<support_assist::NetworkAdapter> adapters;
  std::optional<support_assist::TransferSpeed> network_speed;
  bool network_ipv6 = false;
  std::optional<support_assist::TransferSpeed> storage_speed; // opened from a result.json
  std::wstring storage_filled;                                // what Open a result put in the field
  std::optional<support_assist::TransferEstimate> estimate;
  std::shared_ptr<support_assist::CancellationSource> transfer_cancel; // set while the network test runs

  bool running = false;
  bool embedded = false; // the view of a task's session tab, a child of the main window
  std::optional<gui::QuickToolReport> last_report;
  std::string resolved_address;
  std::optional<support_assist::PortCheckResult> ports;
  std::uint16_t selected_port = 0;
  support_assist::PortProtocol selected_protocol = support_assist::PortProtocol::tcp;
  std::vector<support_assist::PortPreset> presets;
  std::optional<support_assist::WatchSnapshot> snapshot;
  std::vector<support_assist::WatchEvent> watch_events;
  std::vector<support_assist::VolumeInfo> volumes; // Volume Check's list, in the table's order
  std::int64_t volumes_read_unix_millis = 0;
  bool watching = false;
  bool watch_busy = false;
  std::shared_ptr<support_assist::CancellationSource> listener;
  std::chrono::steady_clock::time_point listener_until{};
  std::chrono::steady_clock::time_point listener_started{};
  int listener_minutes = 0;
  std::uint16_t listener_port = 0;
  bool listener_udp = false;
  int listener_connections = 0;
  int listener_row = -1; // the table row of the listener's port, -1 when not shown
  // The last check, run again when a listener starts or stops.
  std::vector<std::uint16_t> checked_tcp;
  std::vector<std::uint16_t> checked_udp;
  support_assist::PortQueryExtras checked_extras;
  std::string checked_process;
  bool has_check = false;
  // Quick scan, while the listener runs.
  std::unique_ptr<support_assist::QuickScan> scan;
  bool scan_wanted = false;
  bool scan_available = false;
  std::string scan_unavailable;
  // The listener's run as it is kept: its start and what arrived.
  std::int64_t listener_started_unix_millis = 0;
  std::vector<support_assist::ListenerRunRecord::Arrival> listener_arrivals;
  // Add to #note: Engineer Review only, where there are cases.
  bool note_shown = true;
};

namespace {

QuickToolState* state_of(HWND window) {
  return reinterpret_cast<QuickToolState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

void set_status(QuickToolState& state, const std::wstring& text) {
  if (state.status != nullptr)
    SetWindowTextW(state.status, text.c_str());
}

// A path as typed, or as Explorer's Copy as path gives it, in quotes.
std::wstring path_in(HWND field) {
  std::wstring path = text_of(field);
  const auto blank = [](wchar_t character) { return character == L' ' || character == L'\t' || character == L'"'; };
  while (!path.empty() && blank(path.front()))
    path.erase(path.begin());
  while (!path.empty() && blank(path.back()))
    path.pop_back();
  return path;
}

// Reads the log in Log file for its own clock on a worker; Convert runs when it is back if asked.
void read_log_file(QuickToolState& state, bool convert_after) {
  const std::wstring path = path_in(state.log_input);
  if (path.empty())
    return;
  state.reading_log = true;
  state.convert_after_read = convert_after;
  state.log_clock.reset();
  state.log_clock_path = path;
  set_status(state, L"Reading the log's own clock: " + path);
  run_in_background(state.window, [path]() {
    Outcome outcome;
    outcome.log_clock =
        std::make_shared<const support_assist::LogClock>(support_assist::read_log_clock(std::filesystem::path(path)));
    outcome.log_path = path;
    return outcome;
  });
}

// The File Transfer Calculator's Storage speed: its cue in each mode, and in Live test the figure a Disk
// Speed Test result gives.
constexpr wchar_t kStorageCueManual[] = L"Optional: such as 520, from a Disk Speed Test";
constexpr wchar_t kStorageCueLive[] = L"Optional: such as 520";
// The units a speed takes, in the order its drop-down lists them; an opened result is in MB/s.
constexpr int kUnitMegabytes = 0;
constexpr int kUnitGigabits = 3;
constexpr wchar_t kStorageHelper[] =
    L"A Disk Speed Test's Writes on a repository, Reads on a source";

// The chosen item of a drop-down list, or the text typed into an editable one.
std::string combo_text(HWND combo) {
  const int chosen = static_cast<int>(SendMessageW(combo, CB_GETCURSEL, 0, 0));
  if (chosen < 0)
    return narrow_text(text_of(combo));
  const int length = static_cast<int>(SendMessageW(combo, CB_GETLBTEXTLEN, static_cast<WPARAM>(chosen), 0));
  if (length <= 0)
    return {};
  std::wstring text(static_cast<std::size_t>(length) + 1U, L'\0');
  SendMessageW(combo, CB_GETLBTEXT, static_cast<WPARAM>(chosen), reinterpret_cast<LPARAM>(text.data()));
  text.resize(static_cast<std::size_t>(length));
  return narrow_text(text);
}

// Manual takes the network's and the storage's speed typed in; Live test measures them here, with this
// machine's adapter, the network test and a storage result.
void transfer_apply_adapter(QuickToolState& state);

void transfer_show_mode(QuickToolState& state, bool measuring) {
  state.measuring = measuring;
  // Live test: the chosen adapter's link speed and packet size are the figures; Manual types them.
  for (HWND control : {state.link_speed, state.link_unit, state.mtu})
    EnableWindow(control, TRUE);
  if (measuring)
    transfer_apply_adapter(state);
  for (HWND control : {state.adapter_label, state.adapter, state.adapter_refresh, state.test_label, state.test_host,
                       state.test_port_label, state.test_port, state.using_label, state.using_tool, state.send_label,
                       state.send_size, state.measure, state.storage_text, state.open_result, state.clear_result})
    ShowWindow(control, measuring ? SW_SHOW : SW_HIDE);
  // Link throttle is Manual's: in Live test the network test measures what the link gives.
  for (HWND control : {state.network_speed_label, state.network_speed_field, state.network_unit, state.share_label,
                       state.share, state.share_suffix})
    ShowWindow(control, measuring ? SW_HIDE : SW_SHOW);
  // Storage speed is in both modes; Live test adds Open a result beside it.
  for (HWND control : {state.storage_speed_label, state.storage_speed_field, state.storage_unit})
    ShowWindow(control, SW_SHOW);
  SendMessageW(state.storage_speed_field, EM_SETCUEBANNER, TRUE,
               reinterpret_cast<LPARAM>(measuring ? kStorageCueLive : kStorageCueManual));
  SendMessageW(state.mode_enter, BM_SETCHECK, measuring ? BST_UNCHECKED : BST_CHECKED, 0);
  SendMessageW(state.mode_measure, BM_SETCHECK, measuring ? BST_CHECKED : BST_UNCHECKED, 0);
}

// The chosen adapter's link speed and packet size fill the figures.
void transfer_apply_adapter(QuickToolState& state) {
  const int chosen = static_cast<int>(SendMessageW(state.adapter, CB_GETCURSEL, 0, 0));
  if (chosen < 0 || static_cast<std::size_t>(chosen) >= state.adapters.size())
    return;
  const auto& adapter = state.adapters[static_cast<std::size_t>(chosen)];
  if (adapter.link_bits_per_second > 0U) {
    const std::string speed = support_assist::link_speed_text(static_cast<double>(adapter.link_bits_per_second));
    SetWindowTextW(state.link_speed, widen(speed.substr(0, speed.find(' '))).c_str());
    SendMessageW(state.link_unit, CB_SETCURSEL, adapter.link_bits_per_second >= 1000000000ULL ? 1 : 0, 0);
  }
  if (adapter.mtu == 1500U)
    SendMessageW(state.mtu, CB_SETCURSEL, 0, 0);
  else if (adapter.mtu == 9000U)
    SendMessageW(state.mtu, CB_SETCURSEL, 1, 0);
  else if (adapter.mtu >= 576U && adapter.mtu <= 9216U)
    SetWindowTextW(state.mtu, std::to_wstring(adapter.mtu).c_str());
  // The adapter's figures show as its own; one it does not report stays open to type.
  const BOOL speed_open = adapter.link_bits_per_second > 0U ? FALSE : TRUE;
  EnableWindow(state.link_speed, speed_open);
  EnableWindow(state.link_unit, speed_open);
  EnableWindow(state.mtu, adapter.mtu >= 576U && adapter.mtu <= 9216U ? FALSE : TRUE);
}

// This machine's adapters, the first one up with a speed and an address chosen.
void transfer_fill_adapters(QuickToolState& state) {
  SendMessageW(state.adapter, CB_RESETCONTENT, 0, 0);
  state.adapters.clear();
  auto listed = support_assist::list_network_adapters();
  if (!listed.ok()) {
    set_status(state, widen(listed.error().message));
    return;
  }
  int chosen = -1;
  for (const auto& adapter : listed.value()) {
    if (adapter.loopback)
      continue;
    if (chosen < 0 && adapter.up && adapter.link_bits_per_second > 0U && !adapter.addresses.empty())
      chosen = static_cast<int>(state.adapters.size());
    state.adapters.push_back(adapter);
    const std::string label = support_assist::network_adapter_label(adapter) +
                              (adapter.description.empty() ? std::string() : "   " + adapter.description);
    SendMessageW(state.adapter, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(label).c_str()));
  }
  if (chosen >= 0) {
    SendMessageW(state.adapter, CB_SETCURSEL, static_cast<WPARAM>(chosen), 0);
    transfer_apply_adapter(state);
  }
}

// The figures as typed, with the measured speeds when measuring. An empty share or reduction is 100%.
bool transfer_read_inputs(const QuickToolState& state, support_assist::TransferInputs& inputs, std::wstring& problem) {
  const auto field = [](HWND control) { return support_assist::trim(narrow_text(text_of(control))); };
  auto size = support_assist::parse_data_size(field(state.input), combo_text(state.size_unit));
  if (!size.ok()) {
    problem = widen(size.error().message);
    return false;
  }
  inputs.size_bytes = size.value();
  auto link = support_assist::parse_link_speed(field(state.link_speed), combo_text(state.link_unit));
  if (!link.ok()) {
    problem = widen(link.error().message);
    return false;
  }
  inputs.link_bits_per_second = link.value();
  auto mtu = support_assist::parse_mtu(field(state.mtu));
  if (!mtu.ok()) {
    problem = widen(mtu.error().message);
    return false;
  }
  inputs.mtu = mtu.value();
  if (!state.measuring && !field(state.share).empty()) {
    auto share = support_assist::parse_percent(field(state.share), "Link throttle");
    if (!share.ok()) {
      problem = widen(share.error().message);
      return false;
    }
    inputs.share_percent = share.value();
  }
  if (!field(state.reduced).empty()) {
    auto reduced = support_assist::parse_percent(field(state.reduced), "Compression");
    if (!reduced.ok()) {
      problem = widen(reduced.error().message);
      return false;
    }
    inputs.reduced_to_percent = reduced.value();
  }
  if (!state.measuring && !field(state.network_speed_field).empty()) {
    // Manual: the network speed a test elsewhere measured, typed in with its unit.
    auto network = support_assist::parse_byte_rate(field(state.network_speed_field), combo_text(state.network_unit));
    if (!network.ok()) {
      problem = widen(network.error().message);
      return false;
    }
    inputs.network_bytes_per_second = network.value();
  }
  // The storage speed: the opened result while the field still holds what it filled in, in MB/s,
  // otherwise the figure typed, in the unit chosen.
  const std::string storage_typed = field(state.storage_speed_field);
  const bool opened_figure = state.storage_speed &&
                             storage_typed == support_assist::trim(narrow_text(state.storage_filled)) &&
                             SendMessageW(state.storage_unit, CB_GETCURSEL, 0, 0) == kUnitMegabytes;
  if (opened_figure) {
    inputs.measured.push_back(*state.storage_speed);
  } else if (!storage_typed.empty()) {
    auto storage = support_assist::parse_byte_rate(storage_typed, combo_text(state.storage_unit));
    if (!storage.ok()) {
      problem = widen(storage.error().message);
      return false;
    }
    inputs.storage_bytes_per_second = storage.value();
  }
  if (state.measuring) {
    const int chosen = static_cast<int>(SendMessageW(state.adapter, CB_GETCURSEL, 0, 0));
    if (chosen >= 0 && static_cast<std::size_t>(chosen) < state.adapters.size())
      inputs.link_name = state.adapters[static_cast<std::size_t>(chosen)].name;
    if (state.network_speed) {
      inputs.measured.push_back(*state.network_speed);
      if (state.network_ipv6)
        inputs.ip = support_assist::TransferIp::ipv6;
    }
  }
  return true;
}

// The field a hand-off from another tool fills, and the command that then runs.
HWND subject_field(const QuickToolState& state) {
  return state.tool == QuickTool::local_ports ? state.process : state.input;
}

const support_assist::WatchEvent* selected_ended_event(const QuickToolState& state) {
  if (state.events == nullptr)
    return nullptr;
  const int row = ListView_GetNextItem(state.events, -1, LVNI_SELECTED);
  if (row < 0 || static_cast<std::size_t>(row) >= state.watch_events.size())
    return nullptr;
  const auto& event = state.watch_events[state.watch_events.size() - 1U - static_cast<std::size_t>(row)];
  return event.change == support_assist::WatchChange::ended || event.change == support_assist::WatchChange::restarted
             ? &event
             : nullptr;
}

int subject_command(const QuickToolState& state) {
  return state.tool == QuickTool::local_ports ? kProcessRunId : kRunId;
}

// A watch as it is kept when it stops, by Stop or by closing the window.
gui::QuickToolOutput watch_output(const QuickToolState& state, const std::string& filter) {
  std::string report = "Service and Process Watch: " + filter + "\n";
  for (const auto& event : state.watch_events)
    report += gui::report_detail::utc_text(event.at_unix_millis) + "  " + event.text + "\n";
  return {"Service and Process Watch", support_assist::tool_json::watch(filter, *state.snapshot, state.watch_events),
          report, std::to_string(state.watch_events.size()) + " change(s) seen", gui::ReportTone::normal};
}

// The listener's run as it is kept, with Quick scan's count as the listener ended.
support_assist::ListenerRunRecord listener_record(const QuickToolState& state, const std::string& error) {
  support_assist::ListenerRunRecord run;
  run.port = state.listener_port;
  run.protocol = state.listener_udp ? support_assist::PortProtocol::udp : support_assist::PortProtocol::tcp;
  run.minutes = state.listener_minutes;
  run.started_unix_millis = state.listener_started_unix_millis;
  run.ended_unix_millis = support_assist::unix_millis_now();
  run.arrivals = state.listener_arrivals;
  run.error = error;
  if (state.scan) {
    run.scanned = true;
    run.scan = state.scan->counts();
  }
  return run;
}

gui::QuickToolOutput listener_output(const support_assist::ListenerRunRecord& run, const std::string& text) {
  std::string report = text;
  for (const auto& arrival : run.arrivals)
    report += "\n" + arrival.time_utc + "  " + arrival.peer + "  " + arrival.what;
  return {"Local Port Checker Listener", support_assist::tool_json::listener_run(run), report, text,
          run.error.empty() ? gui::ReportTone::normal : gui::ReportTone::attention};
}

bool has_guide_row(const gui::QuickToolReport& report) {
  for (const auto& section : report.sections)
    for (const auto& row : section.rows)
      if (row.label == "Guide")
        return true;
  return false;
}

// Volume Check's table from the last list.
void fill_volumes(QuickToolState& state) {
  ListView_DeleteAllItems(state.table);
  for (std::size_t index = 0; index < state.volumes.size(); ++index) {
    std::vector<std::wstring> cells;
    for (const std::string& cell : gui::volume_row(state.volumes[index]))
      cells.push_back(widen(cell));
    insert_row(state.table, static_cast<int>(index), cells);
  }
}

} // namespace

int AppWindow::help_mode_for_window(HWND source) {
  const HWND root = source != nullptr ? GetAncestor(source, GA_ROOT) : nullptr;
  if (root == nullptr)
    return help_mode_for_page(page_);
  HWND tool_view = is_quick_tool_window(root) ? root : nullptr;
  if (tool_view == nullptr && root == window_) {
    // In the main window: the task view the key came from, else the task view on screen.
    tool_view = task_view_containing(source);
    if (tool_view == nullptr) {
      const ToolSession* task = active_session();
      tool_view = !menu_view_ && task != nullptr && task->page == page_ ? task->embedded_view : nullptr;
    }
  }
  if (tool_view != nullptr) {
    if (const QuickToolState* state = state_of(tool_view)) {
      if (const auto topic = gui::quick_tool_help_topic(command_for(state->tool)))
        return static_cast<int>(*topic);
    }
  }
  // An operation's form on a Tools page: that operation's own article.
  if (root == window_ && tool_view == nullptr && operation_help_available())
    return kOperationHelpMode;
  if (root == run_window_) {
    return static_cast<int>(support_assist::tool_run_is_storage_test(run_tool_id_) ? gui::HelpTopic::storage_tools
                                                                                    : gui::HelpTopic::integrations);
  }
  if (root == edit_window_)
    return static_cast<int>(gui::HelpTopic::integrations);
  if (root == db_console_ || root == query_editor_)
    return static_cast<int>(gui::HelpTopic::sql_tools);
  return help_mode_for_page(page_);
}

bool AppWindow::run_shortcut_command(ShortcutCommand command, HWND source) {
  switch (command) {
  case ShortcutCommand::help:
    // The window the key was pressed in decides the article; F1 in the Help window keeps its topic.
    if (source != nullptr && help_window_ != nullptr && GetAncestor(source, GA_ROOT) == help_window_)
      return true;
    open_help_window(source != nullptr ? help_mode_for_window(source) : help_mode_for_page(page_));
    return true;
  case ShortcutCommand::refresh: refresh_entire_gui(true); return true;
  case ShortcutCommand::jump_to: open_palette(); return true;
  case ShortcutCommand::full_screen: toggle_full_screen(); return true;
  case ShortcutCommand::text_larger: set_text_scale(ui_text_scale_percent() + 10); return true;
  case ShortcutCommand::text_smaller: set_text_scale(ui_text_scale_percent() - 10); return true;
  case ShortcutCommand::text_reset: set_text_scale(100); return true;
  case ShortcutCommand::name_check:
  case ShortcutCommand::local_port_checker:
  case ShortcutCommand::time_check:
  case ShortcutCommand::file_lock_check:
  case ShortcutCommand::volume_check:
  case ShortcutCommand::file_transfer_calculator:
  case ShortcutCommand::service_watch: open_quick_tool(command); return true;
  default: return false;
  }
}

void AppWindow::quick_tool_choose_log(QuickToolState& state, const std::vector<support_assist::LogWrittenNear>& logs,
                                      std::int64_t at_unix_millis, const std::string& name) {
  if (logs.empty()) {
    set_status(state, L"No Veeam log was written in the 2 minutes before " + widen(name) + L" ended.");
    return;
  }
  set_status(state, std::to_wstring(logs.size()) + L" Veeam log(s) written in the 2 minutes before " + widen(name) +
                        L" ended. Choose one to open it at that time.");
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr)
    return;
  for (std::size_t index = 0; index < logs.size(); ++index) {
    const std::string written = gui::report_detail::utc_text(logs[index].written_unix_millis);
    const std::wstring label = widen(support_assist::path_to_utf8(logs[index].path.filename())) + L"\t" +
                               widen(written.size() > 19U ? written.substr(11, 8) : written) + L" UTC";
    AppendMenuW(menu, MF_STRING, kLogMenuFirst + static_cast<UINT>(index), label.c_str());
  }
  RECT button{};
  GetWindowRect(state.log_link, &button);
  const UINT chosen = static_cast<UINT>(TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_RIGHTALIGN,
                                                       button.right, button.bottom, 0, state.window, nullptr));
  DestroyMenu(menu);
  if (chosen < kLogMenuFirst || chosen - kLogMenuFirst >= logs.size())
    return;
  const auto& log = logs[chosen - kLogMenuFirst];
  const std::uint64_t line = support_assist::log_line_before(log.path, at_unix_millis,
                                                             support_assist::read_time_zone().utc_offset_minutes);
  open_log_in_viewer(log.path, line);
  append_activity(tool_title(state.tool), L"Opened its log",
                  widen(name) + L": " + widen(support_assist::path_to_utf8(log.path.filename())) + L", line " +
                      std::to_wstring(line));
}

bool AppWindow::quick_tool_view_running(HWND view) const {
  const QuickToolState* state = view != nullptr && IsWindow(view) != FALSE ? state_of(view) : nullptr;
  return state != nullptr && state->running;
}

bool AppWindow::is_quick_tool_window(HWND root) const {
  return root != nullptr &&
         std::find(quick_tool_windows_.begin(), quick_tool_windows_.end(), root) != quick_tool_windows_.end();
}

HWND AppWindow::open_quick_tool(ShortcutCommand command, const std::wstring& subject, bool embedded) {
  // The Object Storage Check is a Storage Tools task, not a window of its own.
  if (command == ShortcutCommand::object_storage_check && !embedded) {
    open_object_storage_task();
    return nullptr;
  }
  const auto tool = tool_for(command);
  if (!tool)
    return nullptr;
  const auto slot = static_cast<std::size_t>(*tool);
  if (HWND existing = quick_tool_windows_[slot]; !embedded && existing != nullptr && IsWindow(existing) != FALSE) {
    if (IsIconic(existing) != FALSE)
      ShowWindow(existing, SW_RESTORE);
    SetForegroundWindow(existing);
    QuickToolState* state = state_of(existing);
    if (state != nullptr && !subject.empty() && subject_field(*state) != nullptr) {
      SetWindowTextW(subject_field(*state), subject.c_str());
      SendMessageW(existing, WM_COMMAND, MAKEWPARAM(subject_command(*state), BN_CLICKED), 0);
    }
    return existing;
  }
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.style = CS_HREDRAW | CS_VREDRAW;
    description.lpfnWndProc = &AppWindow::quick_tool_proc;
    description.hInstance = instance_;
    description.lpszClassName = L"SupportAssistQuickToolWindow";
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    description.hIcon = LoadIconW(instance_, MAKEINTRESOURCEW(1));
    RegisterClassW(&description);
    registered = true;
  }
  auto* state = new QuickToolState();
  state->app = this;
  state->tool = *tool;
  state->embedded = embedded;
  const bool wide_window = *tool == QuickTool::local_ports || *tool == QuickTool::watch ||
                           *tool == QuickTool::volume_check || *tool == QuickTool::object_storage ||
                           *tool == QuickTool::transfer;
  const int height = *tool == QuickTool::object_storage || *tool == QuickTool::transfer ? 900
                     : wide_window                                                  ? 760
                     : *tool == QuickTool::time_check                               ? 920
                                                                                    : 660;
  // The Local Port Checker carries the listener's panel beside its table.
  const int window_width = *tool == QuickTool::local_ports ? 1240
                           : *tool == QuickTool::transfer || *tool == QuickTool::object_storage ? 1140
                           : wide_window                      ? 1000
                           : *tool == QuickTool::file_lock || *tool == QuickTool::time_check ? 900
                                                                                            : 780;
  // Embedded, the view starts hidden and empty-sized; the session's layout places and shows it.
  HWND window = embedded ? CreateWindowExW(WS_EX_CONTROLPARENT, L"SupportAssistQuickToolWindow", tool_title(*tool).c_str(),
                                           WS_CHILD | WS_CLIPCHILDREN | WS_CLIPSIBLINGS, 0, 0, 0, 0, window_, nullptr,
                                           instance_, state)
                         : CreateWindowExW(WS_EX_CONTROLPARENT, L"SupportAssistQuickToolWindow", tool_title(*tool).c_str(),
                                           WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                                           sx(window_width), sx(height), window_, nullptr, instance_, state);
  if (window == nullptr) {
    delete state;
    return nullptr;
  }
  quick_tool_windows_[slot] = window;
  if (!embedded) {
    const BOOL dark = themed_title_bar_dark();
    DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
  }

  const auto make = [&](const wchar_t* type, const wchar_t* text, DWORD style, int id, DWORD extended = 0) {
    HWND control = CreateWindowExW(extended, type, text, WS_CHILD | WS_VISIBLE | style, 0, 0, 0, 0, window,
                                   reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
    return control;
  };
  const auto make_button = [&](const wchar_t* text, int id, DWORD style = BS_PUSHBUTTON) {
    HWND button = make(WC_BUTTONW, text, WS_TABSTOP | style, id);
    apply_control_theme(button);
    return button;
  };
  const auto make_check = [&](const wchar_t* text, int id, bool checked) {
    HWND check = make(WC_BUTTONW, text, WS_TABSTOP | BS_AUTOCHECKBOX, id);
    SetWindowTheme(check, L"", L""); // WM_CTLCOLORSTATIC colours the label
    SendMessageW(check, BM_SETCHECK, checked ? BST_CHECKED : BST_UNCHECKED, 0);
    return check;
  };
  const auto make_edit = [&](int id, const wchar_t* cue) {
    HWND edit = make(WC_EDITW, L"", WS_TABSTOP | ES_AUTOHSCROLL, id, WS_EX_CLIENTEDGE);
    SendMessageW(edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(cue));
    return edit;
  };
  const auto make_label = [&](const wchar_t* text) { return make(WC_STATICW, text, SS_LEFT | SS_NOPREFIX, 0); };
  const auto make_list = [&](int id, DWORD style) {
    HWND list = make(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | style, id, WS_EX_CLIENTEDGE);
    ListView_SetExtendedListViewStyle(list, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
    apply_control_theme(list);
    ListView_SetBkColor(list, themed(kTableColour));
    ListView_SetTextBkColor(list, themed(kTableColour));
    ListView_SetTextColor(list, themed(kTextColour));
    theme_list_header(list);
    return list;
  };
  const ReportPanelStyle panel_style{card_font_, heading_font_, ui_font_, small_font_, ui_scale_percent_};

  switch (*tool) {
  case QuickTool::name_check:
    state->input_label = make_label(L"Name or address");
    state->input = make_edit(kInputId, L"vbr01, vbr01.corp.example.com or 10.0.4.21");
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    state->link = make_button(L"Remote Port Checker...", kLinkId);
    break;
  case QuickTool::time_check:
    state->input_label = make_label(L"Time server");
    state->input = make_edit(kInputId, L"empty: the configured time source");
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    state->converter_heading = make_label(L"LOG TIMESTAMP CONVERTER");
    SendMessageW(state->converter_heading, WM_SETFONT, reinterpret_cast<WPARAM>(heading_font_), TRUE);
    state->convert_label = make_label(L"Timestamp from a log");
    state->convert_input = make_edit(kConvertInputId, L"[29.09.2026 12:15:47.134], a whole line, 1694788094 or 638303848944280000");
    state->log_label = make_label(L"Log file");
    state->log_input = make_edit(kLogInputId, L"Optional: the log it came from, for the log's own UTC offset");
    state->log_browse = make_button(L"Log...", kLogBrowseId);
    state->offset_label = make_label(L"Written in");
    // From the log file, a zone from the list with its daylight saving dates, or a UTC offset typed in.
    state->offset = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, kOffsetId);
    apply_control_theme(state->offset, true);
    SendMessageW(state->offset, CB_ADDSTRING, 0,
                 reinterpret_cast<LPARAM>(widen(support_assist::kFromLogFile).c_str()));
    for (const auto& zone : support_assist::named_time_zones())
      SendMessageW(state->offset, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(zone.name).c_str()));
    SendMessageW(state->offset, CB_SETDROPPEDWIDTH, static_cast<WPARAM>(sx(440)), 0);
    {
      const auto here = support_assist::read_time_zone();
      const auto* named = support_assist::find_named_time_zone(here.name);
      SetWindowTextW(state->offset,
                     widen(named != nullptr ? named->name : support_assist::format_utc_offset(here.utc_offset_minutes)).c_str());
    }
    state->show_label = make_label(L"Show in");
    // The same moment in another zone, such as another machine's.
    state->show_in = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, kShowInId);
    apply_control_theme(state->show_in, true);
    for (const auto& zone : support_assist::named_time_zones())
      SendMessageW(state->show_in, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(zone.name).c_str()));
    SendMessageW(state->show_in, CB_SETDROPPEDWIDTH, static_cast<WPARAM>(sx(440)), 0);
    SendMessageW(state->show_in, CB_SETCUEBANNER, 0, reinterpret_cast<LPARAM>(L"Optional: another zone"));
    state->convert = make_button(L"Convert", kConvertId);
    state->convert_report = create_report_panel(window, instance_, panel_style);
    set_report_panel_empty(state->convert_report,
                           L"Paste a time or a whole line from a log and press Convert. Choose the log it came from, "
                           L"or drop it here, to read the log's own UTC offset; otherwise set the zone it was written in.");
    DragAcceptFiles(window, TRUE);
    break;
  case QuickTool::file_lock:
    state->input_label = make_label(L"File or folder");
    state->input = make_edit(kInputId, L"D:\\Backups\\Job\\Job.vbk, or a folder for every file under it");
    state->browse = make_button(L"File...", kBrowseId);
    state->folder_browse = make_button(L"Folder...", kFolderBrowseId);
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    break;
  case QuickTool::volume_check: {
    state->input_label = make_label(L"Folder");
    state->input = make_edit(kInputId, L"optional: D:\\Backups, for its own compression and encryption");
    state->browse = make_button(L"Browse...", kBrowseId);
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    state->link = make_button(L"Open the guide", kLinkId);
    EnableWindow(state->link, FALSE);
    state->table = make_list(kTableId, LVS_SINGLESEL);
    static const int kWidths[] = {110, 110, 110, 200, 80, 110, 140, 120};
    std::vector<std::wstring> titles;
    for (const std::string& title : gui::volume_columns())
      titles.push_back(widen(title));
    std::vector<std::pair<const wchar_t*, int>> columns;
    for (std::size_t column = 0; column < titles.size(); ++column)
      columns.emplace_back(titles[column].c_str(), column < std::size(kWidths) ? kWidths[column] : 100);
    insert_columns(state->table, columns, ui_scale_percent_);
    break;
  }
  case QuickTool::local_ports:
    state->input_label = make_label(L"Ports");
    state->input = make_edit(kInputId, L"6162, 2500-2510");
    state->tcp = make_check(L"TCP", kTcpId, true);
    state->udp = make_check(L"UDP", kUdpId, false);
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    state->preset = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, kPresetId);
    apply_control_theme(state->preset, true);
    SendMessageW(state->preset, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"A Veeam role's ports..."));
    state->presets = support_assist::port_presets();
    for (const auto& preset : state->presets)
      SendMessageW(state->preset, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(preset.name).c_str()));
    SendMessageW(state->preset, CB_SETCURSEL, 0, 0);
    state->process_label = make_label(L"Process");
    state->process = make_edit(kProcessId, L"VeeamAgent.exe or a PID");
    state->process_run = make_button(L"Its ports", kProcessRunId);
    state->table = make_list(kTableId, LVS_SINGLESEL);
    insert_columns(state->table,
                   {{L"Port", 64}, {L"Protocol", 76}, {L"Verdict", 150}, {L"Listening on", 170},
                    {L"Process", 220}, {L"Firewall", 150}},
                   ui_scale_percent_);
    state->listen_start = make_button(L"Start listener", kListenStartId);
    state->minutes_label = make_label(L"Minutes");
    state->minutes = make(WC_EDITW, L"5", WS_TABSTOP | ES_NUMBER, kMinutesId, WS_EX_CLIENTEDGE);
    state->banner_label = make_label(L"Banner");
    state->banner = make_edit(kBannerId, L"sent to each TCP connection; empty sends none");
    SetWindowTextW(state->banner, widen(support_assist::kDefaultListenerBanner).c_str());
    state->listen_stop = make_button(L"Stop", kListenStopId);
    state->listen_status = make_label(
        L"Choose a port nothing listens on, then Start listener: the other machine can test the path with the "
        L"Remote Port Checker before the real service runs.");
    EnableWindow(state->listen_start, FALSE);
    ShowWindow(state->listen_stop, SW_HIDE);
    state->side_title = make_label(L"LISTENER");
    SendMessageW(state->side_title, WM_SETFONT, reinterpret_cast<WPARAM>(heading_font_), TRUE);
    state->side_clock = make_label(L"Not running");
    SendMessageW(state->side_clock, WM_SETFONT, reinterpret_cast<WPARAM>(heading_font_), TRUE);
    state->side_left = make_label(L"");
    state->side_progress = make(PROGRESS_CLASSW, L"", PBS_SMOOTH, 0);
    SetWindowTheme(state->side_progress, L"", L""); // the bar and its ground in the scheme's colours
    SendMessageW(state->side_progress, PBM_SETBKCOLOR, 0, static_cast<LPARAM>(themed(kTableColour)));
    SendMessageW(state->side_progress, PBM_SETBARCOLOR, 0, static_cast<LPARAM>(themed(RGB(85, 190, 88))));
    ShowWindow(state->side_progress, SW_HIDE);
    state->quick_scan = make_check(L"Quick scan", kQuickScanId, false);
    {
      const auto support = support_assist::quick_scan_support();
      state->scan_available = support.available;
      state->scan_unavailable = support.reason;
    }
    EnableWindow(state->quick_scan, state->scan_available ? TRUE : FALSE);
    {
      const std::wstring scan_text =
          state->scan_available
              ? std::wstring(L"While the listener runs, Quick scan counts the attempts that arrive at the port and "
                             L"where they come from, against those that reach the listener. The capture stays in "
                             L"memory.")
              : widen(state->scan_unavailable);
      state->scan_reading = make_label(scan_text.c_str());
    }
    state->connections = make_list(kConnectionsId, LVS_NOSORTHEADER);
    insert_columns(state->connections, {{L"Time", 64}, {L"From", 130}, {L"What happened", 260}}, ui_scale_percent_);
    break;
  case QuickTool::object_storage: {
    // Where the bucket is, then how to sign in and what to trust, then the product its permissions are
    // compared with, created in the order Tab takes them.
    state->storage_preset_label = make_label(L"Storage");
    state->storage_preset = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, kStoragePresetId);
    apply_control_theme(state->storage_preset, true);
    for (const auto& preset : support_assist::object_storage_catalog().presets) {
      if (preset.later)
        continue;
      state->storage_presets.push_back(preset);
      SendMessageW(state->storage_preset, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(preset.name).c_str()));
    }
    SendMessageW(state->storage_preset, CB_SETCURSEL, 0, 0);
    state->region_label = make_label(L"Region");
    // The provider's regions to pick from; any other can be typed.
    state->region = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, kRegionId);
    apply_control_theme(state->region, true);
    state->addressing_label = make_label(L"Addressing");
    state->addressing = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST, kAddressingId);
    apply_control_theme(state->addressing, true);
    for (const wchar_t* style : {L"The preset's", L"Virtual-hosted", L"Path style"})
      SendMessageW(state->addressing, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(style));
    SendMessageW(state->addressing, CB_SETCURSEL, 0, 0);
    state->input_label = make_label(L"Bucket");
    state->input = make_edit(kInputId, L"veeam-backups");
    state->endpoint_label = make_label(L"Endpoint");
    state->endpoint = make_edit(kEndpointId, L"");
    state->run = make_button(L"Check", kRunId, BS_DEFPUSHBUTTON);
    state->access_label = make_label(L"Access key");
    state->access = make_edit(kAccessKeyId, L"Optional: the access key Veeam uses");
    state->secret_label = make_label(L"Secret key");
    state->secret = make(WC_EDITW, L"", WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, kSecretKeyId, WS_EX_CLIENTEDGE);
    SendMessageW(state->secret, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"kept for this session only"));
    // This machine's certificate store is checked always; a certificate file or a fingerprint can trust
    // the storage's certificate as well.
    state->fingerprint_label = make_label(L"Certificate");
    state->trust = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST, kTrustId);
    apply_control_theme(state->trust, true);
    for (const wchar_t* choice : {L"This machine's certificate store", L"A certificate file (PEM, CRT or CER)",
                                  L"A SHA-256 fingerprint"})
      SendMessageW(state->trust, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(choice));
    SendMessageW(state->trust, CB_SETCURSEL, 0, 0);
    state->fingerprint = make_edit(kFingerprintId, L"");
    state->certificate_open = make_button(L"Open...", kCertificateOpenId);
    state->product_label = make_label(L"Compare with");
    state->product = make(WC_COMBOBOXW, L"", WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL, kProductId);
    apply_control_theme(state->product, true);
    for (const auto& product : support_assist::object_storage_catalog().permissions) {
      state->product_ids.push_back(product.id);
      SendMessageW(state->product, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(product.product).c_str()));
    }
    SendMessageW(state->product, CB_SETCURSEL, 0, 0);
    SendMessageW(state->product, CB_SETDROPPEDWIDTH, static_cast<WPARAM>(sx(480)), 0);
    state->link = make_button(L"Time Check...", kLinkId);
    EnableWindow(state->link, FALSE);
    // The first preset's regions and endpoint, as choosing it fills them, and the store's trust.
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(kStoragePresetId, CBN_SELCHANGE),
                 reinterpret_cast<LPARAM>(state->storage_preset));
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(kTrustId, CBN_SELCHANGE), reinterpret_cast<LPARAM>(state->trust));
    break;
  }
  case QuickTool::transfer: {
    // Manual, or Live test: this machine's adapter, a network test and a storage result.
    state->mode_enter =
        make(WC_BUTTONW, L"Manual", WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON | BS_PUSHLIKE, kModeEnterId);
    state->mode_measure = make(WC_BUTTONW, L"Live test", BS_AUTORADIOBUTTON | BS_PUSHLIKE, kModeMeasureId);
    apply_control_theme(state->mode_enter);
    apply_control_theme(state->mode_measure);
    const auto make_list_combo = [&](int id, std::initializer_list<const wchar_t*> items, int chosen, bool editable) {
      HWND combo = make(WC_COMBOBOXW, L"",
                        WS_TABSTOP | WS_VSCROLL | (editable ? CBS_DROPDOWN | CBS_AUTOHSCROLL : CBS_DROPDOWNLIST), id);
      apply_control_theme(combo, true);
      for (const wchar_t* item : items)
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(item));
      SendMessageW(combo, CB_SETCURSEL, static_cast<WPARAM>(chosen), 0);
      return combo;
    };
    state->input_label = make_label(L"Data to move");
    state->input = make_edit(kInputId, L"such as 20");
    state->size_unit = make_list_combo(kSizeUnitId, {}, -1, false);
    for (const char* unit : support_assist::kTransferSizeUnits)
      SendMessageW(state->size_unit, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(unit).c_str()));
    SendMessageW(state->size_unit, CB_SETCURSEL, static_cast<WPARAM>(support_assist::kTransferSizeUnitChosen), 0);
    state->link_label = make_label(L"Link speed");
    state->link_speed = make_edit(kLinkSpeedId, L"such as 10");
    state->link_unit = make_list_combo(kLinkUnitId, {L"Mb/s", L"Gb/s"}, 1, false);
    state->mtu_label = make_label(L"Packet size");
    state->mtu = make_list_combo(kMtuId, {L"1500 (standard)", L"9000 (jumbo)"}, 0, true);
    state->run = make_button(L"Calculate", kRunId, BS_DEFPUSHBUTTON);
    // SS_NOTIFY lets a label take the mouse, so its hover help shows on the words too.
    state->share_label = make(WC_STATICW, L"Link throttle", SS_LEFT | SS_NOPREFIX | SS_NOTIFY, 0);
    state->share = make(WC_EDITW, L"100", WS_TABSTOP | ES_AUTOHSCROLL, kShareId, WS_EX_CLIENTEDGE);
    state->share_suffix = make(WC_STATICW, L"% of the link", SS_LEFT | SS_NOPREFIX | SS_NOTIFY, 0);
    state->reduced_label = make(WC_STATICW, L"Compression", SS_LEFT | SS_NOPREFIX | SS_NOTIFY, 0);
    state->reduced = make(WC_EDITW, L"100", WS_TABSTOP | ES_AUTOHSCROLL, kReducedId, WS_EX_CLIENTEDGE);
    state->reduced_suffix = make(WC_STATICW, L"% left to send", SS_LEFT | SS_NOPREFIX | SS_NOTIFY, 0);
    state->percent_tips = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr, WS_POPUP | TTS_ALWAYSTIP | TTS_NOPREFIX,
                                          CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, window, nullptr,
                                          instance_, nullptr);
    if (state->percent_tips != nullptr) {
      SendMessageW(state->percent_tips, TTM_SETMAXTIPWIDTH, 0, sx(460));
      SendMessageW(state->percent_tips, TTM_SETDELAYTIME, TTDT_AUTOPOP, MAKELPARAM(30000, 0));
      const std::wstring share_help = widen(gui::transfer_usable_bandwidth_help());
      const std::wstring reduced_help = widen(gui::transfer_compression_help());
      const auto add_tip = [&](HWND control, const std::wstring& text) {
        TOOLINFOW info{};
        info.cbSize = sizeof(info);
        info.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
        info.hwnd = window;
        info.uId = reinterpret_cast<UINT_PTR>(control);
        info.lpszText = const_cast<wchar_t*>(text.c_str()); // the tooltip keeps a copy
        SendMessageW(state->percent_tips, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&info));
      };
      for (HWND control : {state->share_label, state->share, state->share_suffix})
        add_tip(control, share_help);
      for (HWND control : {state->reduced_label, state->reduced, state->reduced_suffix})
        add_tip(control, reduced_help);
    }
    state->network_speed_label = make_label(L"Network speed");
    state->network_speed_field = make_edit(kNetworkSpeedId, L"Optional: such as 6, from iPerf3");
    state->network_unit = make_list_combo(kNetworkUnitId, {L"MB/s", L"GB/s", L"Mb/s", L"Gb/s"}, kUnitGigabits, false);
    state->adapter_label = make_label(L"Adapter");
    state->adapter = make_list_combo(kAdapterId, {}, -1, false);
    SendMessageW(state->adapter, CB_SETDROPPEDWIDTH, static_cast<WPARAM>(sx(760)), 0);
    state->adapter_refresh = make_button(L"Refresh", kAdapterRefreshId);
    state->test_label = make_label(L"Network test to");
    state->test_host = make_edit(kTestHostId, L"repo01 or 10.0.4.21");
    state->test_port_label = make_label(L"Port");
    state->test_port = make(WC_EDITW, L"2500", WS_TABSTOP | ES_NUMBER, kTestPortId, WS_EX_CLIENTEDGE);
    state->using_label = make_label(L"Using");
    state->using_tool = make_list_combo(kUsingId, {L"SAT listener", L"iPerf3, 1 stream", L"iPerf3, 4 streams"}, 0, false);
    state->send_label = make_label(L"Send");
    state->send_size = make_list_combo(kSendId, {L"1 GB", L"4 GB", L"8 GB"}, 0, false);
    state->measure = make_button(L"Measure", kMeasureId);
    // After the network test, so Tab reaches it there in Live test; in Manual it follows Network speed.
    state->storage_speed_label = make_label(L"Storage speed");
    state->storage_speed_field = make_edit(kStorageSpeedId, kStorageCueManual);
    state->storage_unit = make_list_combo(kStorageUnitId, {L"MB/s", L"GB/s", L"Mb/s", L"Gb/s"}, kUnitMegabytes, false);
    state->storage_text = make(WC_STATICW, kStorageHelper, SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, 0);
    state->open_result = make_button(L"Open a result...", kOpenResultId);
    state->clear_result = make_button(L"Clear", kClearResultId);
    EnableWindow(state->clear_result, FALSE);
    state->email = make_button(L"Copy for email", kEmailId);
    EnableWindow(state->email, FALSE);
    state->side_report = create_report_panel(window, instance_, panel_style);
    set_report_panel_empty(state->side_report, L"The speeds, the email text and the terms show here after Calculate.");
    break;
  }
  case QuickTool::watch:
    state->input_label = make_label(L"Names that hold");
    state->input = make_edit(kInputId, L"veeam");
    SetWindowTextW(state->input, L"veeam");
    state->run = make_button(L"Start watching", kRunId, BS_DEFPUSHBUTTON);
    state->link = make_button(L"Its ports...", kLinkId);
    EnableWindow(state->link, FALSE);
    state->log_link = make_button(L"Its log...", kLogLinkId);
    EnableWindow(state->log_link, FALSE);
    state->table = make_list(kTableId, LVS_SINGLESEL);
    state->events = make_list(kEventsId, LVS_NOSORTHEADER);
    insert_columns(state->table,
                   {{L"Kind", 80}, {L"Name", 280}, {L"State", 110}, {L"PID", 80}, {L"Started", 200}, {L"Listening on", 200}},
                   ui_scale_percent_);
    insert_columns(state->events, {{L"Seen", 200}, {L"What changed", 640}}, ui_scale_percent_);
    break;
  }

  state->report = create_report_panel(window, instance_, panel_style);
  show_guide(state->report, *tool);
  if (*tool == QuickTool::watch) {
    ShowWindow(state->table, SW_HIDE);
    ShowWindow(state->events, SW_HIDE);
  }
  if (*tool == QuickTool::transfer)
    transfer_show_mode(*state, false);
  state->status = make(WC_STATICW, L"", SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS, 0);
  state->copy = make_button(L"Copy", kCopyId);
  state->note = make_button(L"Add to #note", kNoteId);
  if (*tool == QuickTool::local_ports) {
    state->save_as = make_button(L"Export...", kExportId);
    EnableWindow(state->save_as, FALSE);
  }
  EnableWindow(state->copy, FALSE);
  EnableWindow(state->note, FALSE);
  // #note belongs to a case, and cases are Engineer Review's.
  state->note_shown = !execution_host_enabled();
  if (!state->note_shown)
    ShowWindow(state->note, SW_HIDE);
  if (*tool == QuickTool::watch)
    set_status(*state, L"Press Start watching. Every 2 seconds the list is read again and changes are listed below.");

  quick_tool_layout(*state);
  if (embedded)
    return window;
  ShowWindow(window, SW_SHOWNORMAL);
  SetForegroundWindow(window);
  SetFocus(state->input);
  if (!subject.empty() && subject_field(*state) != nullptr) {
    SetWindowTextW(subject_field(*state), subject.c_str());
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(subject_command(*state), BN_CLICKED), 0);
  } else if (*tool == QuickTool::time_check || *tool == QuickTool::volume_check) {
    SendMessageW(window, WM_COMMAND, MAKEWPARAM(kRunId, BN_CLICKED), 0);
  }
  return window;
}

void AppWindow::quick_tool_layout(QuickToolState& state) {
  RECT client{};
  GetClientRect(state.window, &client);
  const int width = client.right;
  const int height = client.bottom;
  const int margin = sx(12);
  const int gap = sx(8);
  const int row = sx(28);
  const int label_width = sx(state.tool == QuickTool::time_check ? 160 : 130);
  const int button_width = sx(120);
  const int label_drop = sx(5);
  int y = margin;
  // SWP_NOCOPYBITS: a moved control repaints rather than carrying its old pixels to the new place.
  const auto move = [](HWND control, int left, int top, int control_width, int control_height) {
    if (control != nullptr)
      SetWindowPos(control, nullptr, left, top, control_width, control_height,
                   SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
  };

  // The input row: label and field on the left, the buttons from the right. The calculator places its
  // own rows below.
  if (state.tool != QuickTool::transfer && state.tool != QuickTool::object_storage) {
    int right = width - margin;
    const auto place_right = [&](HWND control, int control_width) {
      if (control == nullptr)
        return;
      move(control, right - control_width, y, control_width, row);
      right -= control_width + gap;
    };
    place_right(state.log_link, sx(110));
    if (state.tool != QuickTool::local_ports)
      place_right(state.link, sx(state.tool == QuickTool::name_check ? 190 : 130));
    place_right(state.run, button_width);
    place_right(state.folder_browse, sx(100));
    place_right(state.browse, sx(100));
    if (state.tool == QuickTool::local_ports) {
      place_right(state.udp, sx(60));
      place_right(state.tcp, sx(60));
    }
    move(state.input_label, margin, y + label_drop, label_width, row);
    move(state.input, margin + label_width, y, std::max(sx(80), right - margin - label_width), row);
    y += row + gap;
  }

  if (state.tool == QuickTool::local_ports) {
    const int preset_width = sx(300);
    move(state.preset, margin, y, preset_width, sx(320));
    const int process_left = margin + preset_width + gap * 2;
    move(state.process_label, process_left, y + label_drop, sx(64), row);
    move(state.process, process_left + sx(64), y,
               std::max(sx(80), width - margin - button_width - gap - process_left - sx(64)), row);
    move(state.process_run, width - margin - button_width, y, button_width, row);
    y += row + gap;
  }

  const int bottom_row = height - margin - row;
  int x = width - margin - button_width;
  if (state.note_shown) {
    move(state.note, x, bottom_row, button_width, row);
    x -= button_width + gap;
  }
  move(state.copy, x, bottom_row, button_width, row);
  if (state.save_as != nullptr) {
    x -= button_width + gap;
    move(state.save_as, x, bottom_row, button_width, row);
  }
  move(state.status, margin, bottom_row + label_drop, std::max(0, x - gap - margin), row);
  const int content_bottom = bottom_row - gap;
  const int full_width = width - 2 * margin;

  switch (state.tool) {
  case QuickTool::local_ports: {
    // The table and the selected port's detail on the left, the listener's panel on the right.
    const int side_width = std::clamp(full_width * 32 / 100, sx(300), sx(400));
    const int left_width = std::max(sx(200), full_width - side_width - gap * 2);
    const int table_height = std::max(sx(120), (content_bottom - y) * 45 / 100);
    move(state.table, margin, y, left_width, table_height);
    const int report_top = y + table_height + gap;
    move(state.report, margin, report_top, left_width, std::max(sx(80), content_bottom - report_top));

    const int panel_left = margin + left_width + gap * 2;
    state.side_box = RECT{panel_left, y, width - margin, content_bottom};
    const int pad = sx(12);
    const int px = panel_left + pad;
    const int pw = std::max(sx(120), width - margin - pad - px);
    int py = y + pad;
    move(state.side_title, px, py, pw, sx(22));
    py += sx(26);
    move(state.side_clock, px, py, pw, sx(26));
    py += sx(28);
    move(state.side_left, px, py, pw, sx(20));
    py += sx(22);
    move(state.side_progress, px, py, pw, sx(6));
    py += sx(14);
    move(state.minutes_label, px, py + label_drop, sx(64), row);
    move(state.minutes, px + sx(64), py, sx(56), row);
    py += row + gap;
    move(state.banner_label, px, py + label_drop, sx(64), row);
    move(state.banner, px + sx(64), py, std::max(sx(80), pw - sx(64)), row);
    py += row + gap;
    move(state.quick_scan, px, py, pw, row);
    py += row;
    move(state.scan_reading, px, py, pw, sx(70));
    py += sx(74);
    move(state.listen_start, px, py, button_width, row);
    move(state.listen_stop, px, py, button_width, row);
    py += row + gap;
    move(state.listen_status, px, py, pw, sx(70));
    py += sx(74);
    move(state.connections, px, py, pw, std::max(sx(60), content_bottom - pad - py));
    break;
  }
  case QuickTool::time_check: {
    // The converter's heading, three rows and report take the bottom 45%, at least enough for its section.
    const int converter_height = std::max(sx(360), (content_bottom - y) * 45 / 100);
    const int report_height = std::max(sx(120), content_bottom - y - converter_height - gap);
    move(state.report, margin, y, full_width, report_height);
    y += report_height + gap;
    move(state.converter_heading, margin, y + sx(4), full_width, sx(24));
    y += sx(30);
    const int field_left = margin + label_width;
    const int field_width = std::max(sx(80), width - margin - button_width - gap - field_left);
    const int button_left = width - margin - button_width;
    // The timestamp, then Convert.
    move(state.convert_label, margin, y + label_drop, label_width, row);
    move(state.convert_input, field_left, y, field_width, row);
    move(state.convert, button_left, y, button_width, row);
    y += row + gap;
    // The log it came from, then Log...
    move(state.log_label, margin, y + label_drop, label_width, row);
    move(state.log_input, field_left, y, field_width, row);
    move(state.log_browse, button_left, y, button_width, row);
    y += row + gap;
    // Written in and Show in side by side. A combo box's height includes its open list.
    const int show_label_width = sx(84);
    const int combo_width = std::max(sx(140), (width - margin - field_left - show_label_width - gap) / 2);
    move(state.offset_label, margin, y + label_drop, label_width, row);
    move(state.offset, field_left, y, combo_width, sx(360));
    const int show_left = field_left + combo_width + gap;
    move(state.show_label, show_left, y + label_drop, show_label_width - gap, row);
    move(state.show_in, show_left + show_label_width, y, combo_width, sx(360));
    y += row + gap;
    move(state.convert_report, margin, y, full_width, std::max(sx(60), content_bottom - y));
    break;
  }
  case QuickTool::watch: {
    // The guide fills the area the two lists take once watching starts.
    move(state.report, margin, y, full_width, std::max(sx(80), content_bottom - y));
    const int table_height = std::max(sx(120), (content_bottom - y) * 55 / 100);
    move(state.table, margin, y, full_width, table_height);
    y += table_height + gap;
    move(state.events, margin, y, full_width, std::max(sx(60), content_bottom - y));
    break;
  }
  case QuickTool::volume_check: {
    // The volumes above, the chosen one's details below.
    const int table_height = std::max(sx(120), (content_bottom - y) * 42 / 100);
    move(state.table, margin, y, full_width, table_height);
    y += table_height + gap;
    move(state.report, margin, y, full_width, std::max(sx(80), content_bottom - y));
    break;
  }
  case QuickTool::object_storage: {
    // Five rows: Storage | Region and Addressing; Bucket | Endpoint and Check; the keys; Certificate |
    // the file or fingerprint and Open...; Compare with | Time Check. The result below.
    const int drop = sx(320); // a combo box's height includes its open list
    const int second_label = sx(100);
    const int half = std::max(sx(160), (full_width - label_width - second_label - gap * 2) / 2);
    const int second_left = margin + label_width + half + gap * 2;
    const int field_left = second_left + second_label;
    const int field_right = width - margin;
    const auto left_pair = [&](HWND caption, HWND field, int field_height) {
      move(caption, margin, y + label_drop, label_width, row);
      move(field, margin + label_width, y, half, field_height);
    };
    left_pair(state.storage_preset_label, state.storage_preset, drop);
    move(state.region_label, second_left, y + label_drop, second_label, row);
    const int region_width = sx(170);
    move(state.region, field_left, y, region_width, drop);
    const int addressing_left = field_left + region_width + gap * 2;
    move(state.addressing_label, addressing_left, y + label_drop, sx(90), row);
    move(state.addressing, addressing_left + sx(90), y, std::max(sx(100), field_right - addressing_left - sx(90)),
         sx(200));
    y += row + gap;
    left_pair(state.input_label, state.input, row);
    move(state.endpoint_label, second_left, y + label_drop, second_label, row);
    move(state.endpoint, field_left, y, std::max(sx(80), field_right - button_width - gap - field_left), row);
    move(state.run, field_right - button_width, y, button_width, row);
    y += row + gap;
    left_pair(state.access_label, state.access, row);
    move(state.secret_label, second_left, y + label_drop, second_label, row);
    move(state.secret, field_left, y, std::max(sx(80), field_right - field_left), row);
    y += row + gap;
    left_pair(state.fingerprint_label, state.trust, sx(200));
    move(state.fingerprint, second_left, y, std::max(sx(80), field_right - sx(100) - gap - second_left), row);
    move(state.certificate_open, field_right - sx(100), y, sx(100), row);
    y += row + gap;
    left_pair(state.product_label, state.product, drop);
    move(state.link, field_right - sx(130), y, sx(130), row);
    y += row + gap;
    move(state.report, margin, y, full_width, std::max(sx(80), content_bottom - y));
    break;
  }
  case QuickTool::transfer: {
    // The two modes, two rows of figures, the three measurements while measuring, then the result.
    int at = margin;
    const int drop = sx(240); // a combo box's height includes its open list
    const auto place = [&](HWND control, int control_width, int control_height) {
      move(control, at, y, control_width, control_height);
      at += control_width + gap;
    };
    const auto place_label = [&](HWND control, int control_width) {
      move(control, at, y + label_drop, control_width, row);
      at += control_width;
    };
    move(state.mode_enter, margin, y, sx(140), row);
    move(state.mode_measure, margin + sx(140), y, sx(140), row);
    y += row + gap;

    at = margin;
    place_label(state.input_label, sx(110));
    place(state.input, sx(80), row);
    place(state.size_unit, sx(70), drop);
    at += gap;
    place_label(state.link_label, sx(90));
    place(state.link_speed, sx(80), row);
    place(state.link_unit, sx(80), drop);
    at += gap;
    place_label(state.mtu_label, sx(90));
    place(state.mtu, sx(150), drop);
    move(state.run, width - margin - button_width, y, button_width, row);
    y += row + gap;

    at = margin;
    if (!state.measuring) {
      place_label(state.share_label, sx(130));
      place(state.share, sx(60), row);
      place_label(state.share_suffix, sx(110));
      at += gap;
    }
    place_label(state.reduced_label, sx(150));
    place(state.reduced, sx(60), row);
    place_label(state.reduced_suffix, sx(110));
    y += row + gap;

    if (!state.measuring) {
      // Manual: the network's and the storage's speed, as the live test measures them.
      at = margin;
      const int unit_width = sx(80);
      const int speed_width =
          std::max(sx(140), (width - margin - at - sx(130) - sx(120) - unit_width * 2 - gap * 5) / 2);
      place_label(state.network_speed_label, sx(130));
      place(state.network_speed_field, speed_width, row);
      place(state.network_unit, unit_width, drop);
      at += gap;
      place_label(state.storage_speed_label, sx(120));
      place(state.storage_speed_field, speed_width, row);
      place(state.storage_unit, unit_width, drop);
      y += row + gap;
    }

    if (state.measuring) {
      at = margin;
      place_label(state.adapter_label, sx(130));
      move(state.adapter, at, y, std::max(sx(200), width - margin - sx(100) - gap - at), drop);
      move(state.adapter_refresh, width - margin - sx(100), y, sx(100), row);
      y += row + gap;

      at = margin;
      place_label(state.test_label, sx(130));
      place(state.test_host, sx(200), row);
      place_label(state.test_port_label, sx(40));
      place(state.test_port, sx(64), row);
      place_label(state.using_label, sx(50));
      place(state.using_tool, sx(160), drop);
      place_label(state.send_label, sx(46));
      place(state.send_size, sx(80), drop);
      move(state.measure, width - margin - button_width, y, button_width, row);
      y += row + gap;

      at = margin;
      place_label(state.storage_speed_label, sx(130));
      place(state.storage_speed_field, sx(140), row);
      place(state.storage_unit, sx(80), drop);
      const int buttons = sx(140) + gap + sx(80);
      move(state.storage_text, at, y + label_drop, std::max(sx(120), width - margin - buttons - gap - at), row);
      move(state.open_result, width - margin - buttons, y, sx(140), row);
      move(state.clear_result, width - margin - sx(80), y, sx(80), row);
      y += row + gap;
    }
    // The estimate on the left; the speeds, the email text with Copy for email and the terms beside it.
    const int side_width = std::clamp(full_width * 40 / 100, sx(340), sx(500));
    const int main_width = std::max(sx(240), full_width - side_width - gap);
    move(state.report, margin, y, main_width, std::max(sx(80), content_bottom - y));
    const int side_left = margin + main_width + gap;
    const int email_top = content_bottom - row;
    move(state.side_report, side_left, y, side_width, std::max(sx(80), email_top - gap - y));
    move(state.email, side_left, email_top, side_width, row);
    break;
  }
  case QuickTool::name_check:
  case QuickTool::file_lock:
    move(state.report, margin, y, full_width, std::max(sx(80), content_bottom - y));
    break;
  }
  // The last column of each list fills what is left of its width.
  for (HWND list : {state.table, state.events, state.connections}) {
    if (list != nullptr) {
      const int columns = Header_GetItemCount(ListView_GetHeader(list));
      if (columns > 0)
        ListView_SetColumnWidth(list, columns - 1, LVSCW_AUTOSIZE_USEHEADER);
    }
  }
  // Moving an editable combo box selects its text. One without the focus shows its text unselected.
  EnumChildWindows(
      state.window,
      [](HWND child, LPARAM) -> BOOL {
        wchar_t name[32]{};
        if (GetClassNameW(child, name, static_cast<int>(std::size(name))) == 0 || _wcsicmp(name, WC_COMBOBOXW) != 0)
          return TRUE;
        if ((GetWindowLongPtrW(child, GWL_STYLE) & 0x3) != CBS_DROPDOWN)
          return TRUE;
        const HWND focus = GetFocus();
        if (focus != child && IsChild(child, focus) == FALSE)
          SendMessageW(child, CB_SETEDITSEL, 0, MAKELPARAM(-1, 0));
        return TRUE;
      },
      0);
  RedrawWindow(state.window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

void AppWindow::quick_tools_after_rescale() {
  const ReportPanelStyle style{card_font_, heading_font_, ui_font_, small_font_, ui_scale_percent_};
  for (HWND window : quick_tool_windows_) {
    QuickToolState* state = window != nullptr ? state_of(window) : nullptr;
    if (state == nullptr)
      continue;
    EnumChildWindows(
        window,
        [](HWND child, LPARAM font) -> BOOL {
          SendMessageW(child, WM_SETFONT, static_cast<WPARAM>(font), TRUE);
          return TRUE;
        },
        reinterpret_cast<LPARAM>(ui_font_));
    set_report_panel_style(state->report, style);
    set_report_panel_style(state->convert_report, style);
    set_report_panel_style(state->side_report, style);
    for (HWND list : {state->table, state->events, state->connections}) {
      if (list == nullptr)
        continue;
      apply_control_theme(list);
      ListView_SetBkColor(list, themed(kTableColour));
      ListView_SetTextBkColor(list, themed(kTableColour));
      ListView_SetTextColor(list, themed(kTextColour));
    }
    const BOOL dark = themed_title_bar_dark();
    DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
    quick_tool_layout(*state);
    RedrawWindow(window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
  }
}

// Fills the Local Port Checker's table from the last check.
void AppWindow::quick_tool_fill_ports(QuickToolState& state) {
  ListView_DeleteAllItems(state.table);
  if (!state.ports)
    return;
  for (std::size_t index = 0; index < state.ports->rows.size(); ++index) {
    const auto& row = state.ports->rows[index];
    std::wstring owner;
    if (!row.state.owners.empty()) {
      const auto& first = row.state.owners.front();
      owner = first.pid == 0 ? L"not readable by this account"
                             : widen(first.process_name) + L" (PID " + std::to_wstring(first.pid) + L")";
    }
    const std::wstring firewall =
        row.firewall.mixed ? L"differs by profile" : widen(support_assist::to_string(row.firewall.decision));
    insert_row(state.table, static_cast<int>(index),
               {widen(support_assist::port_label(row)), widen(support_assist::to_string(row.state.protocol)),
                widen(support_assist::to_string(row.verdict)),
                widen(gui::report_detail::joined(row.state.listen_addresses)), owner, firewall});
  }
  // The listener's port shows SAT listening, with the time left.
  state.listener_row = -1;
  for (std::size_t index = 0; state.listener && index < state.ports->rows.size(); ++index) {
    const auto& row = state.ports->rows[index];
    if (row.state.port == state.listener_port &&
        (row.state.protocol == support_assist::PortProtocol::udp) == state.listener_udp) {
      state.listener_row = static_cast<int>(index);
      quick_tool_show_listener_row(state);
    }
  }
  // The port chosen before, when the table is filled again.
  int chosen = 0;
  for (std::size_t index = 0; index < state.ports->rows.size(); ++index) {
    if (state.ports->rows[index].state.port == state.selected_port &&
        state.ports->rows[index].state.protocol == state.selected_protocol)
      chosen = static_cast<int>(index);
  }
  if (!state.ports->rows.empty())
    ListView_SetItemState(state.table, chosen, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
}

// The listener's row: SAT listening, and the time left in the Process column.
void AppWindow::quick_tool_show_listener_row(QuickToolState& state) {
  if (state.listener_row < 0 || !state.listener)
    return;
  const auto left = std::chrono::duration_cast<std::chrono::seconds>(state.listener_until -
                                                                     std::chrono::steady_clock::now());
  std::wstring verdict = L"SAT listening";
  std::wstring process = L"SAT listener, " + minutes_seconds(left) + L" left";
  ListView_SetItemText(state.table, state.listener_row, 2, verdict.data());
  ListView_SetItemText(state.table, state.listener_row, 4, process.data());
}

// The selected port's detail, and whether a listener can start on it.
void AppWindow::quick_tool_port_selected(QuickToolState& state) {
  const int item = ListView_GetNextItem(state.table, -1, LVNI_SELECTED);
  if (!state.ports || item < 0 || static_cast<std::size_t>(item) >= state.ports->rows.size()) {
    show_guide(state.report, QuickTool::local_ports);
    EnableWindow(state.listen_start, FALSE);
    state.last_report.reset();
    return;
  }
  const auto& row = state.ports->rows[static_cast<std::size_t>(item)];
  state.selected_port = row.state.port;
  state.selected_protocol = row.state.protocol;
  auto report = gui::port_detail_report(row, state.ports->firewall);
  report.checked_unix_millis = state.ports->checked_unix_millis;
  const bool free_port = !row.state.found;
  if (free_port) {
    // The firewall's verdict for SAT's own listener here, which can differ from its verdict for
    // the Veeam program that uses the port.
    const auto verdict = support_assist::evaluate_inbound(state.ports->firewall, row.state.protocol,
                                                          row.state.port, support_assist::current_executable_path(), "");
    gui::ReportSection listener{"A listener from SAT on this port", {}, {}};
    for (const auto& profile : verdict.per_profile)
      listener.rows.push_back({profile.profile, support_assist::to_string(profile.decision) + ": " + profile.because,
                               gui::report_detail::tone_of(profile.decision)});
    if (verdict.per_profile.empty())
      listener.rows.push_back({"Firewall", support_assist::to_string(verdict.decision) +
                                               (verdict.note.empty() ? std::string() : ": " + verdict.note),
                               gui::report_detail::tone_of(verdict.decision)});
    listener.note = "When a program listens and no rule covers it, Windows may ask whether to allow it, and "
                    "keeps the answer as a firewall rule for that program.";
    report.sections.push_back(std::move(listener));
  }
  set_report_panel_report(state.report, report);
  state.last_report = report;
  EnableWindow(state.listen_start, free_port && !state.listener ? TRUE : FALSE);
  EnableWindow(state.copy, TRUE);
  EnableWindow(state.note, active_case() != nullptr ? TRUE : FALSE);
}

void AppWindow::quick_tool_run(QuickToolState& state, int command) {
  if (state.running)
    return;
  HWND window = state.window;
  const std::string input = support_assist::trim(narrow_text(text_of(state.input)));
  switch (state.tool) {
  case QuickTool::name_check: {
    if (input.empty()) {
      set_status(state, L"Type a name or an address first.");
      return;
    }
    state.running = true;
    set_status(state, L"Checking " + widen(input) + L"...");
    run_in_background(window, [input]() {
      Outcome outcome;
      support_assist::CancellationSource cancel;
      const auto result = support_assist::check_name(input, cancel.token());
      outcome.report = gui::name_check_report(result);
      outcome.result_json = support_assist::tool_json::name_check(result);
      outcome.report->checked_unix_millis = support_assist::unix_millis_now();
      outcome.resolved_address = result.is_address ? input
                                 : result.addresses.empty() ? std::string()
                                                            : result.addresses.front();
      outcome.activity_result = outcome.report->headline;
      outcome.activity_detail = input;
      return outcome;
    });
    return;
  }
  case QuickTool::time_check: {
    state.running = true;
    set_status(state, L"Asking the time source...");
    run_in_background(window, [input]() {
      Outcome outcome;
      support_assist::CancellationSource cancel;
      const auto result = support_assist::check_time(input, cancel.token());
      outcome.report = gui::time_check_report(result);
      outcome.result_json = support_assist::tool_json::time_check(result);
      outcome.activity_result = outcome.report->headline;
      outcome.activity_detail = result.sntp.server;
      return outcome;
    });
    return;
  }
  case QuickTool::file_lock: {
    if (input.empty()) {
      set_status(state, L"Choose a file or a folder first.");
      return;
    }
    // A folder: the folder and everything under it.
    std::error_code ignored;
    const bool folder = std::filesystem::is_directory(support_assist::path_from_utf8(input), ignored);
    state.running = true;
    set_status(state, folder ? L"Checking every file under " + widen(input) + L"..." : std::wstring(L"Checking..."));
    run_in_background(window, [input, folder, window]() {
      Outcome outcome;
      if (folder) {
        support_assist::CancellationSource cancel;
        // The rows found so far reach the window while the walk runs.
        const auto stream = [window](const support_assist::FolderLockResult& partial) {
          auto sent = std::make_unique<Outcome>();
          sent->partial = true;
          sent->report = gui::folder_lock_progress_report(partial);
          if (PostMessageW(window, kResultMessage, 0, reinterpret_cast<LPARAM>(sent.get())) != FALSE)
            sent.release();
        };
        auto result = support_assist::find_folder_holders(input, cancel.token(),
                                                          support_assist::kFolderLockMaxEntries, stream);
        if (!result.ok()) {
          outcome.error = result.error().message;
          return outcome;
        }
        outcome.report = gui::folder_lock_report(result.value());
        outcome.result_json = support_assist::tool_json::folder_lock(result.value());
        outcome.report->checked_unix_millis = support_assist::unix_millis_now();
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = input;
        return outcome;
      }
      auto result = support_assist::find_file_holders(input);
      if (!result.ok()) {
        outcome.error = result.error().message;
        return outcome;
      }
      outcome.report = gui::file_lock_report(result.value());
      outcome.result_json = support_assist::tool_json::file_lock(result.value());
      outcome.report->checked_unix_millis = support_assist::unix_millis_now();
      outcome.activity_result = outcome.report->headline;
      outcome.activity_detail = input;
      return outcome;
    });
    return;
  }
  case QuickTool::volume_check: {
    // Every volume, read again each time; with a folder, that folder too.
    state.running = true;
    set_status(state, input.empty() ? L"Reading the volumes..." : L"Checking " + widen(input) + L"...");
    run_in_background(window, [input]() {
      Outcome outcome;
      auto volumes = support_assist::list_volumes();
      if (volumes.ok())
        outcome.volumes = std::move(volumes.value());
      const std::string listed_json =
          outcome.volumes ? support_assist::tool_json::volumes(*outcome.volumes) : std::string("[]");
      if (input.empty()) {
        if (!volumes.ok()) {
          outcome.error = volumes.error().message;
          return outcome;
        }
        const auto listed = outcome.volumes->size();
        outcome.activity_result = std::to_string(listed) + (listed == 1 ? " volume" : " volumes");
        outcome.result_json = "{\"volumes\":" + listed_json + "}";
        return outcome;
      }
      auto result = support_assist::check_volume(input);
      if (!result.ok()) {
        outcome.error = result.error().message;
        return outcome;
      }
      outcome.report = gui::volume_report(result.value());
      outcome.result_json =
          "{\"folder\":" + support_assist::tool_json::volume(result.value()) + ",\"volumes\":" + listed_json + "}";
      outcome.report->checked_unix_millis = support_assist::unix_millis_now();
      outcome.activity_result = outcome.report->headline;
      outcome.activity_detail = input;
      return outcome;
    });
    return;
  }
  case QuickTool::local_ports: {
    std::vector<std::uint16_t> tcp_ports;
    std::vector<std::uint16_t> udp_ports;
    support_assist::PortQueryExtras extras;
    std::string process;
    std::string detail;
    if (command == kPresetId) {
      const int selection = static_cast<int>(SendMessageW(state.preset, CB_GETCURSEL, 0, 0));
      if (selection <= 0 || static_cast<std::size_t>(selection) > state.presets.size())
        return;
      const auto& preset = state.presets[static_cast<std::size_t>(selection - 1)];
      support_assist::preset_ports(preset, tcp_ports, udp_ports);
      extras = support_assist::preset_extras(preset);
      detail = "role " + preset.name;
    } else if (command == kProcessRunId) {
      process = support_assist::trim(narrow_text(text_of(state.process)));
      if (process.empty()) {
        set_status(state, L"Type a process name or a PID first.");
        return;
      }
      detail = "process " + process;
    } else {
      auto ports = support_assist::parse_port_list(input);
      if (!ports.ok()) {
        set_status(state, widen(ports.error().message));
        return;
      }
      const bool tcp = SendMessageW(state.tcp, BM_GETCHECK, 0, 0) == BST_CHECKED;
      const bool udp = SendMessageW(state.udp, BM_GETCHECK, 0, 0) == BST_CHECKED;
      if (!tcp && !udp) {
        set_status(state, L"Tick TCP, UDP or both.");
        return;
      }
      if (tcp)
        tcp_ports = ports.value();
      if (udp)
        udp_ports = ports.value();
      detail = "ports " + input;
    }
    state.checked_tcp = tcp_ports;
    state.checked_udp = udp_ports;
    state.checked_extras = extras;
    state.checked_process = process;
    state.has_check = true;
    state.running = true;
    SetTimer(window, kRecheckTimer, kLiveRecheckMs, nullptr);
    set_status(state, L"Reading this machine's sockets and firewall...");
    run_in_background(window, [tcp_ports, udp_ports, extras, process, detail]() {
      Outcome outcome;
      auto result = process.empty() ? support_assist::check_local_ports(tcp_ports, udp_ports, extras)
                                     : support_assist::check_process_ports(process);
      if (!result.ok()) {
        outcome.error = result.error().message;
        return outcome;
      }
      outcome.ports = std::move(result.value());
      outcome.activity_result = std::to_string(outcome.ports->rows.size()) + " port(s) checked";
      outcome.activity_detail = detail;
      outcome.result_json = support_assist::tool_json::port_check(*outcome.ports);
      return outcome;
    });
    return;
  }
  case QuickTool::object_storage: {
    const int chosen = static_cast<int>(SendMessageW(state.storage_preset, CB_GETCURSEL, 0, 0));
    if (chosen < 0 || static_cast<std::size_t>(chosen) >= state.storage_presets.size())
      return;
    support_assist::ObjectStorageOptions options;
    options.target.preset = state.storage_presets[static_cast<std::size_t>(chosen)].id;
    options.target.bucket = input;
    options.target.endpoint = support_assist::trim(narrow_text(text_of(state.endpoint)));
    options.target.region = support_assist::trim(narrow_text(text_of(state.region)));
    const int style = static_cast<int>(SendMessageW(state.addressing, CB_GETCURSEL, 0, 0));
    options.target.addressing = style == 1 ? "virtual-hosted" : style == 2 ? "path" : "";
    const int trust = static_cast<int>(SendMessageW(state.trust, CB_GETCURSEL, 0, 0));
    const std::string certificate = support_assist::trim(narrow_text(path_in(state.fingerprint)));
    if (trust == 1)
      options.target.certificate_file = certificate;
    else if (trust == 2)
      options.target.pinned_sha256 = certificate;
    if (trust != 0 && certificate.empty()) {
      set_status(state, trust == 1 ? L"Open the certificate file, or type its path." : L"Type the SHA-256 fingerprint.");
      return;
    }
    const int product = static_cast<int>(SendMessageW(state.product, CB_GETCURSEL, 0, 0));
    if (product >= 0 && static_cast<std::size_t>(product) < state.product_ids.size())
      options.product = state.product_ids[static_cast<std::size_t>(product)];
    const auto endpoint = support_assist::resolve_object_storage_endpoint(options.target);
    if (!endpoint.ok()) {
      set_status(state, widen(endpoint.error().message));
      return;
    }
    support_assist::ObjectStorageCredentials keys;
    keys.access_key = support_assist::trim(narrow_text(text_of(state.access)));
    keys.secret_key = narrow_text(text_of(state.secret));
    if (!keys.access_key.empty() && !keys.secret_key.empty()) {
      options.credentials = keys;
      const auto estimate = support_assist::estimate_object_storage_check(options.target);
      if (estimate.needs_agreement) {
        const std::wstring question = widen(estimate.text) + L"\n\nSend the signed reads?";
        options.accept_cost = MessageBoxW(window, question.c_str(), L"Object Storage Check",
                                          MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES;
        if (!options.accept_cost)
          options.credentials.reset();
      }
    }
    state.running = true;
    set_status(state, L"Checking " + widen(endpoint.value().request_host) + L"...");
    run_in_background(window, [options]() {
      Outcome outcome;
      support_assist::CancellationSource cancel;
      auto result = support_assist::check_object_storage(options, cancel.token());
      if (!result.ok()) {
        outcome.error = result.error().message;
        return outcome;
      }
      outcome.report = gui::object_storage_report(result.value());
      outcome.result_json = support_assist::tool_json::object_storage(result.value());
      outcome.clock_offset_seconds = result.value().clock_offset_seconds;
      outcome.activity_result = outcome.report->headline;
      outcome.activity_detail = result.value().endpoint.request_host;
      return outcome;
    });
    return;
  }
  case QuickTool::transfer: {
    if (command == kMeasureId) {
      // The network test on a worker: SAT's listener, or an iPerf3 server, on the port given.
      const std::string host = support_assist::trim(narrow_text(text_of(state.test_host)));
      if (host.empty()) {
        set_status(state, L"Type the machine to test to first.");
        return;
      }
      const std::string port_text = support_assist::trim(narrow_text(text_of(state.test_port)));
      const long port = port_text.empty() || port_text.size() > 5U ? 0L : std::strtol(port_text.c_str(), nullptr, 10);
      if (port < 1 || port > 65535) {
        set_status(state, L"The port is a number from 1 to 65535.");
        return;
      }
      const int using_index = static_cast<int>(SendMessageW(state.using_tool, CB_GETCURSEL, 0, 0));
      const int send_index = static_cast<int>(SendMessageW(state.send_size, CB_GETCURSEL, 0, 0));
      const std::uint64_t bytes = (send_index == 2 ? 8ULL : send_index == 1 ? 4ULL : 1ULL) << 30U;
      auto cancel = std::make_shared<support_assist::CancellationSource>();
      state.transfer_cancel = cancel;
      state.running = true;
      SetWindowTextW(state.measure, L"Stop");
      set_status(state, (using_index >= 1 ? L"iPerf3 to " : L"Sending to SAT's listener on ") + widen(host) + L", port " +
                            std::to_wstring(port) + L"...");
      const std::filesystem::path tools = default_tools_folder();
      const auto port_number = static_cast<std::uint16_t>(port);
      run_in_background(window, [host, port_number, bytes, using_index, cancel, tools]() {
        Outcome outcome;
        outcome.transfer_measure = true;
        outcome.activity_detail = host + ":" + std::to_string(port_number);
        if (using_index >= 1) {
          support_assist::IperfTransferOptions iperf;
          iperf.host = host;
          iperf.port = port_number;
          iperf.streams = using_index == 2 ? 4 : 1;
          iperf.tools_folder = tools;
          auto speed = support_assist::run_iperf3_transfer_test(iperf, cancel->token());
          if (!speed.ok()) {
            outcome.error = speed.error().message;
            return outcome;
          }
          outcome.activity_result = support_assist::transfer_rate_text(speed.value().bytes_per_second) + ", " +
                                    speed.value().detail;
          outcome.transfer_speed = speed.value();
          return outcome;
        }
        support_assist::TransferTestOptions test;
        test.host = host;
        test.port = port_number;
        test.bytes = bytes;
        auto measured = support_assist::run_transfer_test(test, cancel->token());
        if (!measured.ok()) {
          outcome.error = measured.error().message;
          return outcome;
        }
        if (measured.value().cancelled) {
          outcome.error = "The network test stopped before it finished.";
          return outcome;
        }
        support_assist::TransferSpeed speed;
        speed.name = "Network test to " + host;
        speed.phrase = "the network test to " + host;
        speed.detail = measured.value().answered_by + ", one connection, " +
                       support_assist::link_speed_text(measured.value().bytes_per_second * 8.0);
        speed.bytes_per_second = measured.value().bytes_per_second;
        outcome.activity_result = support_assist::transfer_rate_text(speed.bytes_per_second) + ", " + speed.detail;
        outcome.transfer_speed = std::move(speed);
        outcome.transfer_ipv6 = measured.value().ipv6;
        return outcome;
      });
      return;
    }
    support_assist::TransferInputs inputs;
    std::wstring problem;
    if (!transfer_read_inputs(state, inputs, problem)) {
      set_status(state, problem);
      return;
    }
    auto estimate = support_assist::estimate_transfer(inputs);
    if (!estimate.ok()) {
      set_status(state, widen(estimate.error().message));
      return;
    }
    quick_tool_transfer_show(state, estimate.value(), false);
    return;
  }
  case QuickTool::watch:
    if (state.watching) {
      state.watching = false;
      KillTimer(window, kWatchTimer);
      SetWindowTextW(state.run, L"Start watching");
      set_status(state, L"Stopped. " + std::to_wstring(state.watch_events.size()) + L" change(s) seen.");
      append_activity(tool_title(state.tool), L"Stopped",
                      widen(input) + L": " + std::to_wstring(state.watch_events.size()) + L" change(s)");
      if (state.snapshot)
        quick_tool_keep_output(watch_output(state, input));
      return;
    }
    state.watching = true;
    state.snapshot.reset();
    state.watch_events.clear();
    ListView_DeleteAllItems(state.events);
    ShowWindow(state.report, SW_HIDE);
    ShowWindow(state.table, SW_SHOW);
    ShowWindow(state.events, SW_SHOW);
    SetWindowTextW(state.run, L"Stop watching");
    set_status(state, L"Reading services and processes...");
    append_activity(tool_title(state.tool), L"Started", widen(input));
    SetTimer(window, kWatchTimer, kWatchIntervalMs, nullptr);
    quick_tool_watch_tick(state);
    return;
  }
}

// The calculator's estimate in its report; a measured one is kept as the run's output.
void AppWindow::quick_tool_transfer_show(QuickToolState& state, const support_assist::TransferEstimate& estimate,
                                         bool keep) {
  auto report = gui::file_transfer_report(estimate);
  report.checked_unix_millis = support_assist::unix_millis_now();
  set_report_panel_report(state.report, report);
  set_report_panel_report(state.side_report, gui::file_transfer_side_report(estimate));
  // Copy and #note take every section, the side's too.
  report = gui::file_transfer_full_report(estimate);
  report.checked_unix_millis = support_assist::unix_millis_now();
  state.last_report = report;
  state.estimate = estimate;
  set_status(state, widen(report.headline));
  EnableWindow(state.copy, TRUE);
  EnableWindow(state.email, TRUE);
  EnableWindow(state.note, active_case() != nullptr ? TRUE : FALSE);
  // Every estimate shown goes into the history once, however it was asked for.
  if (report.headline != state.transfer_recorded) {
    state.transfer_recorded = report.headline;
    append_activity(tool_title(state.tool), L"Calculated", widen(report.headline));
  }
  if (keep)
    quick_tool_keep_output(gui::quick_tool_output_of(narrow_text(tool_title(state.tool)),
                                                     support_assist::tool_json::file_transfer(estimate), report));
}

void AppWindow::quick_tool_watch_tick(QuickToolState& state) {
  if (state.watch_busy)
    return;
  state.watch_busy = true;
  const std::string filter = support_assist::trim(narrow_text(text_of(state.input)));
  run_in_background(state.window, [filter]() {
    Outcome outcome;
    outcome.snapshot = support_assist::take_watch_snapshot(filter);
    return outcome;
  });
}

void AppWindow::quick_tool_fill_watch(QuickToolState& state, const support_assist::WatchSnapshot& snapshot) {
  if (state.snapshot) {
    for (auto& event : support_assist::diff_watch(*state.snapshot, snapshot)) {
      insert_row(state.events, 0, {widen(gui::report_detail::utc_text(event.at_unix_millis)), widen(event.text)});
      if (event.change == support_assist::WatchChange::ended || event.change == support_assist::WatchChange::restarted)
        append_activity(tool_title(state.tool), L"Changed", widen(event.text));
      state.watch_events.push_back(std::move(event));
    }
  }
  // Keep the selected row selected across the refresh.
  std::string selected_key;
  const int selected = ListView_GetNextItem(state.table, -1, LVNI_SELECTED);
  if (selected >= 0 && state.snapshot && static_cast<std::size_t>(selected) < state.snapshot->items.size()) {
    const auto& item = state.snapshot->items[static_cast<std::size_t>(selected)];
    selected_key = item.name + "|" + std::to_string(item.pid);
  }
  SendMessageW(state.table, WM_SETREDRAW, FALSE, 0);
  ListView_DeleteAllItems(state.table);
  std::size_t services = 0;
  for (std::size_t index = 0; index < snapshot.items.size(); ++index) {
    const auto& entry = snapshot.items[index];
    const bool service = entry.kind == support_assist::WatchKind::service;
    if (service)
      ++services;
    std::wstring name = widen(entry.name);
    if (service && !entry.display_name.empty() && entry.display_name != entry.name)
      name = widen(entry.display_name) + L" (" + name + L")";
    const int row = insert_row(state.table, static_cast<int>(index),
                               {service ? L"Service" : L"Process", name, widen(entry.state),
                                entry.pid == 0 ? L"" : std::to_wstring(entry.pid),
                                widen(gui::report_detail::utc_text(entry.started_unix_millis)),
                                widen(entry.listening)});
    if (!selected_key.empty() && entry.name + "|" + std::to_string(entry.pid) == selected_key)
      ListView_SetItemState(state.table, row, LVIS_SELECTED, LVIS_SELECTED);
  }
  SendMessageW(state.table, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(state.table, nullptr, TRUE);
  set_status(state, std::to_wstring(services) + L" service(s) and " + std::to_wstring(snapshot.items.size() - services) +
                        L" process(es), read " + widen(gui::report_detail::utc_text(snapshot.taken_unix_millis)) +
                        L"; " + std::to_wstring(state.watch_events.size()) + L" change(s) seen" +
                        (snapshot.note.empty() ? L"" : L". " + widen(snapshot.note)));
  state.snapshot = snapshot;
  EnableWindow(state.copy, TRUE);
  EnableWindow(state.note, active_case() != nullptr && !state.watch_events.empty() ? TRUE : FALSE);
}

void AppWindow::quick_tool_start_listener(QuickToolState& state) {
  const int item = ListView_GetNextItem(state.table, -1, LVNI_SELECTED);
  if (!state.ports || item < 0 || static_cast<std::size_t>(item) >= state.ports->rows.size() || state.listener)
    return;
  const auto& row = state.ports->rows[static_cast<std::size_t>(item)];
  const int minutes = std::clamp(_wtoi(text_of(state.minutes).c_str()), 1, 60);
  SetWindowTextW(state.minutes, std::to_wstring(minutes).c_str());
  auto cancel = std::make_shared<support_assist::CancellationSource>();
  state.listener = cancel;
  state.listener_port = row.state.port;
  state.listener_udp = row.state.protocol == support_assist::PortProtocol::udp;
  state.listener_until = std::chrono::steady_clock::now() + std::chrono::minutes(minutes);
  state.listener_connections = 0;
  const HWND window = state.window;
  const std::uint16_t port = row.state.port;
  const bool udp = state.listener_udp;
  const std::string banner = narrow_text(text_of(state.banner));
  std::thread([window, cancel, port, udp, minutes, banner]() {
    const auto post = [window](UINT message, std::wstring text) {
      auto event = std::make_unique<ListenerEvent>();
      event->text = std::move(text);
      if (PostMessageW(window, message, 0, reinterpret_cast<LPARAM>(event.get())) != FALSE)
        event.release();
    };
    const auto post_connection = [window](const std::string& at, std::string peer, std::string what) {
      auto event = std::make_unique<ListenerEvent>();
      event->time = clock_of(at);
      event->time_utc = at;
      event->peer = widen(peer);
      event->what = widen(what);
      if (PostMessageW(window, kListenerEventMessage, 0, reinterpret_cast<LPARAM>(event.get())) != FALSE)
        event.release();
    };
    std::wstring failure;
    if (udp) {
      support_assist::UdpListenerOptions options;
      options.port = port;
      options.duration = std::chrono::seconds(minutes * 60);
      options.accept_multiple = true;
      auto result = support_assist::listen_udp(
          options, cancel->token(), {}, [&](const support_assist::UdpReceivedDatagram& datagram) {
            post_connection(datagram.received_utc,
                            datagram.remote_address + ":" + std::to_string(datagram.remote_port),
                            datagram.sat_probe ? "SAT probe, answered" : "Datagram");
          });
      if (!result.ok())
        failure = widen(result.error().message);
    } else {
      support_assist::TcpListenerOptions options;
      options.port = port;
      options.duration = std::chrono::seconds(minutes * 60);
      options.accept_multiple = true;
      options.banner = banner;
      auto result = support_assist::listen_tcp(
          options, cancel->token(), {},
          [&](support_assist::TcpListenerEventKind kind, const support_assist::TcpAcceptedConnection& connection) {
            if (kind != support_assist::TcpListenerEventKind::updated) // after the SAT exchange, so it can be named
              return;
            post_connection(connection.accepted_utc,
                            connection.remote_address + ":" + std::to_string(connection.remote_port),
                            support_assist::describe_listener_connection(connection));
          });
      if (!result.ok())
        failure = widen(result.error().message);
    }
    post(kListenerDoneMessage, failure);
  }).detach();

  ShowWindow(state.listen_start, SW_HIDE);
  ShowWindow(state.listen_stop, SW_SHOW);
  EnableWindow(state.minutes, FALSE);
  EnableWindow(state.banner, FALSE);
  EnableWindow(state.quick_scan, FALSE);
  state.listener_started = std::chrono::steady_clock::now();
  state.listener_started_unix_millis = support_assist::unix_millis_now();
  state.listener_arrivals.clear();
  state.listener_minutes = minutes;
  const std::wstring protocol_name = udp ? L"UDP" : L"TCP";
  SetWindowTextW(state.side_title, (L"SAT LISTENING ON " + protocol_name + L" " + std::to_wstring(port)).c_str());
  SendMessageW(state.side_progress, PBM_SETRANGE32, 0, minutes * 60);
  SendMessageW(state.side_progress, PBM_SETPOS, 0, 0);
  ShowWindow(state.side_progress, SW_SHOW);
  ListView_DeleteAllItems(state.connections);
  SetWindowTextW(state.listen_status,
                 (L"On the other machine, run the Remote Port Checker to this machine's address, " + protocol_name +
                  L" port " + std::to_wstring(port) +
                  L". The first time, Windows may ask whether to allow SupportAssistTool.exe and keep the answer as "
                  L"a firewall rule.")
                     .c_str());
  state.scan_wanted = state.scan_available && SendMessageW(state.quick_scan, BM_GETCHECK, 0, 0) == BST_CHECKED;
  if (state.scan_wanted) {
    SetWindowTextW(state.scan_reading, L"Quick scan is starting Packet Monitor...");
    const auto scan_protocol = udp ? support_assist::PortProtocol::udp : support_assist::PortProtocol::tcp;
    std::thread([window, port, scan_protocol]() {
      auto result = std::make_unique<ScanStart>();
      auto started = support_assist::QuickScan::start(port, scan_protocol);
      if (started.ok())
        result->scan = std::move(started.value());
      else
        result->error = started.error().message;
      if (PostMessageW(window, kScanStartedMessage, 0, reinterpret_cast<LPARAM>(result.get())) != FALSE)
        result.release();
      else
        stop_scan_in_background(std::move(result->scan));
    }).detach();
  }
  SetTimer(state.window, kCountdownTimer, 1000, nullptr);
  SendMessageW(state.window, WM_TIMER, kCountdownTimer, 0);
  SetTimer(state.window, kRecheckTimer, kRecheckDelayMs, nullptr);
  append_activity(tool_title(state.tool), L"Listener started",
                  std::to_wstring(port) + (udp ? L"/UDP" : L"/TCP") + L" for " + std::to_wstring(minutes) + L" min" +
                      (state.scan_wanted ? L", with Quick scan" : L""));
}

// The check again, with what it read last, so the listener's row comes and goes.
void AppWindow::quick_tool_recheck_ports(QuickToolState& state) {
  if (!state.has_check || state.running)
    return;
  state.running = true;
  const auto tcp_ports = state.checked_tcp;
  const auto udp_ports = state.checked_udp;
  const auto extras = state.checked_extras;
  const std::string process = state.checked_process;
  run_in_background(state.window, [tcp_ports, udp_ports, extras, process]() {
    Outcome outcome;
    outcome.quiet = true;
    auto result = process.empty() ? support_assist::check_local_ports(tcp_ports, udp_ports, extras)
                                  : support_assist::check_process_ports(process);
    if (!result.ok()) {
      outcome.error = result.error().message;
      return outcome;
    }
    outcome.ports = std::move(result.value());
    outcome.activity_result = std::to_string(outcome.ports->rows.size()) + " port(s) checked";
    return outcome;
  });
}

// The panel while the listener runs: time active and left, the bar, and Quick scan's reading.
void AppWindow::quick_tool_show_listener(QuickToolState& state) {
  const auto now = std::chrono::steady_clock::now();
  const auto active = std::chrono::duration_cast<std::chrono::seconds>(now - state.listener_started);
  const auto left = std::chrono::duration_cast<std::chrono::seconds>(state.listener_until - now);
  SetWindowTextW(state.side_clock, (L"Active " + minutes_seconds(active)).c_str());
  SetWindowTextW(state.side_left,
                 (minutes_seconds(left) + L" left of " + std::to_wstring(state.listener_minutes) + L":00, " +
                  std::to_wstring(state.listener_connections) +
                  (state.listener_udp ? L" datagram(s)" : L" connection(s)"))
                     .c_str());
  SendMessageW(state.side_progress, PBM_SETPOS, static_cast<WPARAM>(std::max<long long>(0, active.count())), 0);
  quick_tool_show_listener_row(state);
  if (state.scan)
    SetWindowTextW(state.scan_reading,
                   widen("Quick scan: " + gui::quick_scan_summary(state.scan->counts(),
                                                                 static_cast<std::size_t>(state.listener_connections)))
                       .c_str());
}

void AppWindow::quick_tool_listener_ended(QuickToolState& state, const std::wstring& error) {
  KillTimer(state.window, kCountdownTimer);
  if (!error.empty() || state.listener)
    quick_tool_show_listener(state);
  state.listener.reset();
  state.listener_row = -1;
  ShowWindow(state.listen_stop, SW_HIDE);
  ShowWindow(state.listen_start, SW_SHOW);
  ShowWindow(state.side_progress, SW_HIDE);
  EnableWindow(state.minutes, TRUE);
  EnableWindow(state.banner, TRUE);
  EnableWindow(state.quick_scan, state.scan_available ? TRUE : FALSE);
  SetWindowTextW(state.side_title, L"LISTENER");
  SetWindowTextW(state.side_clock, error.empty() ? L"Stopped" : L"Did not start");
  if (error.empty()) {
    const auto ran = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() -
                                                                      state.listener_started);
    SetWindowTextW(state.side_left, (L"Ran " + minutes_seconds(ran) + L", " +
                                     std::to_wstring(state.listener_connections) +
                                     (state.listener_udp ? L" datagram(s)" : L" connection(s)"))
                                        .c_str());
  } else {
    SetWindowTextW(state.side_left, L"");
  }
  // The run as it is kept on a Customer / Lab machine.
  const support_assist::ListenerRunRecord run = listener_record(state, narrow_text(error));
  // Quick scan's last reading comes back from its worker.
  if (state.scan) {
    SetWindowTextW(state.scan_reading, L"Quick scan is stopping Packet Monitor...");
    const HWND window = state.window;
    const auto reached = static_cast<std::size_t>(state.listener_connections);
    std::thread([window, reached, owned = std::move(state.scan)]() mutable {
      owned->stop();
      auto reading = std::make_unique<std::string>("Quick scan: " + gui::quick_scan_summary(owned->counts(), reached));
      if (PostMessageW(window, kScanEndedMessage, 0, reinterpret_cast<LPARAM>(reading.get())) != FALSE)
        reading.release();
    }).detach();
  }
  SetTimer(state.window, kRecheckTimer, kRecheckDelayMs, nullptr);
  // The rules that name SAT's executable, which Windows adds when it asks and the answer is kept.
  std::wstring rules;
  if (auto firewall = support_assist::read_firewall(); firewall.ok()) {
    for (const auto& rule :
         support_assist::rules_for_program(firewall.value(), support_assist::current_executable_path()))
      rules += (rules.empty() ? L"" : L", ") + widen(rule.name) + (rule.allow ? L" (allow)" : L" (block)");
  }
  const std::wstring protocol = state.listener_udp ? L"/UDP" : L"/TCP";
  std::wstring text = error.empty() ? L"The listener on " + std::to_wstring(state.listener_port) + protocol +
                                          L" stopped after " + std::to_wstring(state.listener_connections) +
                                          (state.listener_udp ? L" datagram(s)." : L" connection(s).")
                                    : L"The listener did not start: " + error;
  if (!rules.empty())
    text += L" Firewall rules for SupportAssistTool.exe: " + rules + L".";
  SetWindowTextW(state.listen_status, text.c_str());
  append_activity(tool_title(state.tool), error.empty() ? L"Listener stopped" : L"Listener failed",
                  std::to_wstring(state.listener_port) + protocol + L": " +
                      (error.empty() ? std::to_wstring(state.listener_connections) + L" seen" : error));
  quick_tool_keep_output(listener_output(run, narrow_text(text)));
  quick_tool_port_selected(state);
}

// A run's raw result, kept on the Customer / Lab machine as each Tools run keeps its output: Home's
// Last output and Prepare output include it.
void AppWindow::quick_tool_keep_output(const gui::QuickToolOutput& output) {
  if (!execution_host_enabled() || output.result_json.empty())
    return;
  auto artifact = gui::write_quick_tool_output(execution_artifact_directory(), output);
  if (!artifact.ok()) {
    support_assist::write_debug_log("QuickTools", output.tool + " output not kept: " + artifact.error().message);
    return;
  }
  last_execution_artifact_ = std::move(artifact.value());
  health_quick_checks_.invalidate();
  // Environment Review lists the newest run of its checks, beside the last collection.
  if (gui::quick_check_in_view(output.tool, gui::QuickCheckView::environment) && environment_import_text_.empty() &&
      !environment_live_snapshot_.empty())
    populate_environment_topology_from_snapshot(environment_live_snapshot_, true);
  last_output_changed();
}

// Add to #note shows in Engineer Review only; a role switch shows or hides it in open windows.
void AppWindow::quick_tools_role_changed() {
  for (HWND window : quick_tool_windows_) {
    QuickToolState* state = window != nullptr && IsWindow(window) != FALSE ? state_of(window) : nullptr;
    if (state == nullptr)
      continue;
    state->note_shown = !execution_host_enabled();
    ShowWindow(state->note, state->note_shown ? SW_SHOW : SW_HIDE);
    quick_tool_layout(*state);
  }
}

LRESULT CALLBACK AppWindow::quick_tool_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_NCCREATE) {
    const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    auto* created = static_cast<QuickToolState*>(create->lpCreateParams);
    created->window = window;
    SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(created));
    return DefWindowProcW(window, message, wparam, lparam);
  }
  QuickToolState* state = state_of(window);
  if (state == nullptr)
    return DefWindowProcW(window, message, wparam, lparam);
  AppWindow* self = state->app;
  switch (message) {
  case WM_ERASEBKGND: {
    RECT client{};
    GetClientRect(window, &client);
    const auto dc = reinterpret_cast<HDC>(wparam);
    FillRect(dc, &client, themed_brush(kWindowColour));
    if (state->tool == QuickTool::local_ports && state->side_box.right > state->side_box.left) {
      // The listener's panel: a rounded frame around its controls.
      HPEN pen = CreatePen(PS_SOLID, 1, themed(RGB(43, 86, 78)));
      const HGDIOBJ previous_pen = SelectObject(dc, pen);
      const HGDIOBJ previous_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
      const int radius = self->sx(14);
      RoundRect(dc, state->side_box.left, state->side_box.top, state->side_box.right, state->side_box.bottom, radius,
                radius);
      SelectObject(dc, previous_brush);
      SelectObject(dc, previous_pen);
      DeleteObject(pen);
    }
    return 1;
  }
  case WM_CTLCOLORSTATIC:
  case WM_CTLCOLORBTN: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    // A heading takes the green of a report's section titles.
    SetTextColor(dc, themed(reinterpret_cast<HWND>(lparam) == state->converter_heading ? kHeadingColour : kLabelColour));
    SetBkColor(dc, themed(kWindowColour));
    return reinterpret_cast<LRESULT>(themed_brush(kWindowColour));
  }
  case WM_CTLCOLOREDIT: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    SetTextColor(dc, themed(kTextColour));
    SetBkColor(dc, themed(kFieldColour));
    return reinterpret_cast<LRESULT>(themed_brush(kFieldColour));
  }
  case WM_SIZE:
    if (state->input != nullptr)
      self->quick_tool_layout(*state);
    return 0;
  case WM_DROPFILES: {
    const auto drop = reinterpret_cast<HDROP>(wparam);
    if (state->tool == QuickTool::time_check && DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0) > 0) {
      const UINT length = DragQueryFileW(drop, 0, nullptr, 0);
      std::wstring dropped(static_cast<std::size_t>(length) + 1U, L'\0');
      DragQueryFileW(drop, 0, dropped.data(), length + 1);
      dropped.resize(length);
      SetWindowTextW(state->log_input, dropped.c_str());
      read_log_file(*state, !path_in(state->convert_input).empty());
    }
    DragFinish(drop);
    return 0;
  }
  case WM_GETMINMAXINFO: {
    auto* limits = reinterpret_cast<MINMAXINFO*>(lparam);
    limits->ptMinTrackSize.x = self->sx(620);
    limits->ptMinTrackSize.y = self->sx(460);
    return 0;
  }
  case kResultMessage: {
    std::unique_ptr<Outcome> outcome(reinterpret_cast<Outcome*>(lparam));
    if (outcome->partial) {
      if (state->running && outcome->report) {
        set_report_panel_report(state->report, *outcome->report);
        set_status(*state, widen(outcome->report->headline));
      }
      return 0;
    }
    if (outcome->log_clock) {
      // A path changed while this one was read: the newer read answers.
      if (outcome->log_path != state->log_clock_path)
        return 0;
      state->reading_log = false;
      state->log_clock = outcome->log_clock;
      const auto report = gui::log_clock_report(*state->log_clock);
      // A log that ties its clock to UTC is read by it.
      if (support_assist::summarize_log_clock(*state->log_clock).tied)
        SetWindowTextW(state->offset, widen(support_assist::kFromLogFile).c_str());
      if (state->convert_after_read && !path_in(state->convert_input).empty() && state->log_clock->error.empty()) {
        state->convert_after_read = false;
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(kConvertId, BN_CLICKED), 0);
        return 0;
      }
      state->convert_after_read = false;
      set_report_panel_report(state->convert_report, report);
      state->last_report = report;
      set_status(*state, widen(report.headline));
      EnableWindow(state->copy, TRUE);
      EnableWindow(state->note, self->active_case() != nullptr ? TRUE : FALSE);
      return 0;
    }
    if (outcome->snapshot) {
      state->watch_busy = false;
      if (state->watching)
        self->quick_tool_fill_watch(*state, *outcome->snapshot);
      return 0;
    }
    if (outcome->logs_near) {
      EnableWindow(state->log_link, TRUE);
      self->quick_tool_choose_log(*state, *outcome->logs_near, outcome->logs_near_at, outcome->logs_near_name);
      return 0;
    }
    if (outcome->transfer_measure) {
      state->running = false;
      state->transfer_cancel.reset();
      SetWindowTextW(state->measure, L"Measure");
      if (!outcome->error.empty()) {
        set_status(*state, widen(outcome->error));
        self->append_activity(tool_title(state->tool), L"Network test failed", widen(outcome->error));
        return 0;
      }
      state->network_speed = outcome->transfer_speed;
      state->network_ipv6 = outcome->transfer_ipv6;
      self->append_activity(tool_title(state->tool), widen(outcome->activity_result), widen(outcome->activity_detail));
      // The calculation again with the measured speed, kept as this run's output.
      support_assist::TransferInputs inputs;
      std::wstring problem;
      if (!transfer_read_inputs(*state, inputs, problem)) {
        set_status(*state, L"Measured " + widen(outcome->activity_result) + L". " + problem);
        return 0;
      }
      auto estimate = support_assist::estimate_transfer(inputs);
      if (estimate.ok())
        self->quick_tool_transfer_show(*state, estimate.value(), true);
      return 0;
    }
    state->running = false;
    if (outcome->volumes) {
      state->volumes = std::move(*outcome->volumes);
      state->volumes_read_unix_millis = support_assist::unix_millis_now();
      fill_volumes(*state);
      EnableWindow(state->copy, state->volumes.empty() ? FALSE : TRUE);
      EnableWindow(state->note, !state->volumes.empty() && self->active_case() != nullptr ? TRUE : FALSE);
    }
    if (!outcome->error.empty()) {
      set_status(*state, widen(outcome->error));
      if (!outcome->quiet)
        self->append_activity(tool_title(state->tool), L"Failed", widen(outcome->error));
      return 0;
    }
    if (state->tool == QuickTool::volume_check && !outcome->report) {
      // A new list: the guide again until a volume is chosen.
      state->last_report.reset();
      show_guide(state->report, state->tool);
      EnableWindow(state->link, FALSE);
      set_status(*state, widen(outcome->activity_result) + L". Choose one for its details.");
      self->append_activity(tool_title(state->tool), widen(outcome->activity_result), L"");
      const auto listed = gui::volumes_report(state->volumes);
      self->quick_tool_keep_output(gui::quick_tool_output_of(narrow_text(tool_title(state->tool)), outcome->result_json,
                                                           listed));
      return 0;
    }
    if (outcome->ports) {
      state->ports = std::move(outcome->ports);
      EnableWindow(state->save_as, TRUE);
      self->quick_tool_fill_ports(*state);
      self->quick_tool_port_selected(*state);
      std::wstring status = widen(outcome->activity_result) + L", " +
                            widen(gui::report_detail::utc_text(state->ports->checked_unix_millis));
      if (!state->ports->sockets_note.empty())
        status += L". " + widen(state->ports->sockets_note);
      set_status(*state, status);
      if (outcome->quiet)
        return 0;
    } else if (outcome->report) {
      set_report_panel_report(state->report, *outcome->report);
      state->last_report = *outcome->report;
      state->resolved_address = outcome->resolved_address;
      set_status(*state, widen(outcome->report->headline));
      EnableWindow(state->copy, TRUE);
      EnableWindow(state->note, self->active_case() != nullptr ? TRUE : FALSE);
      if (state->tool == QuickTool::volume_check)
        EnableWindow(state->link, has_guide_row(*outcome->report) ? TRUE : FALSE);
      if (state->tool == QuickTool::object_storage)
        EnableWindow(state->link, outcome->clock_offset_seconds && std::fabs(*outcome->clock_offset_seconds) >= 60.0
                                      ? TRUE
                                      : FALSE);
    }
    self->append_activity(tool_title(state->tool), widen(outcome->activity_result), widen(outcome->activity_detail));
    if (outcome->report) {
      self->quick_tool_keep_output(gui::quick_tool_output_of(narrow_text(tool_title(state->tool)), outcome->result_json,
                                                           *outcome->report));
    } else if (state->ports) {
      self->quick_tool_keep_output({narrow_text(tool_title(state->tool)), outcome->result_json,
                                    gui::port_check_text(*state->ports), outcome->activity_result,
                                    gui::ReportTone::normal});
    }
    return 0;
  }
  case kListenerEventMessage: {
    std::unique_ptr<ListenerEvent> event(reinterpret_cast<ListenerEvent*>(lparam));
    ++state->listener_connections;
    insert_row(state->connections, 0, {event->time, event->peer, event->what});
    state->listener_arrivals.push_back({event->time_utc, narrow_text(event->peer), narrow_text(event->what)});
    self->quick_tool_show_listener(*state);
    return 0;
  }
  case kScanStartedMessage: {
    std::unique_ptr<ScanStart> started(reinterpret_cast<ScanStart*>(lparam));
    if (!started->error.empty()) {
      SetWindowTextW(state->scan_reading, widen("Quick scan did not start: " + started->error).c_str());
      self->append_activity(tool_title(state->tool), L"Quick scan failed", widen(started->error));
      return 0;
    }
    if (!state->listener) {
      // The listener ended while Packet Monitor was starting.
      stop_scan_in_background(std::move(started->scan));
      return 0;
    }
    state->scan = std::move(started->scan);
    SetWindowTextW(state->scan_reading, L"Quick scan: counting what arrives at the port.");
    self->append_activity(tool_title(state->tool), L"Quick scan started",
                          std::to_wstring(state->listener_port) + (state->listener_udp ? L"/UDP" : L"/TCP"));
    return 0;
  }
  case kScanEndedMessage: {
    std::unique_ptr<std::string> reading(reinterpret_cast<std::string*>(lparam));
    SetWindowTextW(state->scan_reading, widen(*reading).c_str());
    self->append_activity(tool_title(state->tool), L"Quick scan", widen(*reading));
    return 0;
  }
  case kListenerDoneMessage: {
    std::unique_ptr<ListenerEvent> event(reinterpret_cast<ListenerEvent*>(lparam));
    self->quick_tool_listener_ended(*state, event->text);
    return 0;
  }
  case WM_TIMER:
    if (wparam == kWatchTimer) {
      self->quick_tool_watch_tick(*state);
      return 0;
    }
    if (wparam == kCountdownTimer && state->listener) {
      self->quick_tool_show_listener(*state);
      return 0;
    }
    if (wparam == kRecheckTimer) {
      KillTimer(window, kRecheckTimer);
      self->quick_tool_recheck_ports(*state);
      if (state->has_check)
        SetTimer(window, kRecheckTimer, kLiveRecheckMs, nullptr);
      return 0;
    }
    break;
  case WM_NOTIFY: {
    const auto* header = reinterpret_cast<const NMHDR*>(lparam);
    if (header->hwndFrom == state->table && header->code == NM_CUSTOMDRAW && state->tool == QuickTool::local_ports) {
      auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lparam);
      if (draw->nmcd.dwDrawStage == CDDS_PREPAINT)
        return CDRF_NOTIFYITEMDRAW;
      if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
        return CDRF_NOTIFYSUBITEMDRAW;
      if (draw->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
        draw->clrText = themed(kTextColour);
        const auto index = static_cast<std::size_t>(draw->nmcd.dwItemSpec);
        if (draw->iSubItem == 2 && static_cast<int>(index) == state->listener_row && state->listener) {
          draw->clrText = themed(RGB(126, 224, 130));
        } else if (draw->iSubItem == 2 && state->ports && index < state->ports->rows.size()) {
          switch (gui::report_detail::tone_of(state->ports->rows[index].verdict)) {
          case gui::ReportTone::good: draw->clrText = themed(RGB(126, 224, 130)); break;
          case gui::ReportTone::attention: draw->clrText = themed(RGB(255, 199, 91)); break;
          case gui::ReportTone::problem: draw->clrText = themed(RGB(255, 120, 120)); break;
          case gui::ReportTone::normal:
          case gui::ReportTone::quiet: break;
          }
        }
        return CDRF_NEWFONT;
      }
      return CDRF_DODEFAULT;
    }
    if (header->hwndFrom == state->table && header->code == NM_CUSTOMDRAW && state->tool == QuickTool::volume_check) {
      // The Fast Clone column in the tone of its verdict.
      auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lparam);
      if (draw->nmcd.dwDrawStage == CDDS_PREPAINT)
        return CDRF_NOTIFYITEMDRAW;
      if (draw->nmcd.dwDrawStage == CDDS_ITEMPREPAINT)
        return CDRF_NOTIFYSUBITEMDRAW;
      if (draw->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
        draw->clrText = themed(kTextColour);
        const auto index = static_cast<std::size_t>(draw->nmcd.dwItemSpec);
        if (draw->iSubItem == 7 && index < state->volumes.size()) {
          switch (gui::report_detail::fast_clone_tone(state->volumes[index].fast_clone_state)) {
          case gui::ReportTone::good: draw->clrText = themed(RGB(126, 224, 130)); break;
          case gui::ReportTone::attention: draw->clrText = themed(RGB(255, 199, 91)); break;
          case gui::ReportTone::problem:
          case gui::ReportTone::normal:
          case gui::ReportTone::quiet: break;
          }
        }
        return CDRF_NEWFONT;
      }
      return CDRF_DODEFAULT;
    }
    if (header->hwndFrom == state->events && header->code == LVN_ITEMCHANGED) {
      EnableWindow(state->log_link, selected_ended_event(*state) != nullptr ? TRUE : FALSE);
      return 0;
    }
    if (header->hwndFrom == state->table && header->code == LVN_ITEMCHANGED) {
      const auto* change = reinterpret_cast<const NMLISTVIEW*>(lparam);
      if ((change->uChanged & LVIF_STATE) != 0 && (change->uNewState & LVIS_SELECTED) != 0) {
        if (state->tool == QuickTool::local_ports) {
          self->quick_tool_port_selected(*state);
        } else if (state->tool == QuickTool::watch) {
          EnableWindow(state->link, TRUE);
        } else if (state->tool == QuickTool::volume_check && change->iItem >= 0 &&
                   static_cast<std::size_t>(change->iItem) < state->volumes.size()) {
          auto report = gui::volume_report(state->volumes[static_cast<std::size_t>(change->iItem)]);
          report.checked_unix_millis = state->volumes_read_unix_millis;
          set_report_panel_report(state->report, report);
          EnableWindow(state->link, has_guide_row(report) ? TRUE : FALSE);
          set_status(*state, widen(report.headline));
          state->last_report = std::move(report);
        }
      }
      return 0;
    }
    break;
  }
  case WM_COMMAND: {
    const int id = LOWORD(wparam);
    const int code = HIWORD(wparam);
    if (state->tool == QuickTool::transfer) {
      const auto recalculate = [&]() {
        if (!text_of(state->input).empty() && !text_of(state->link_speed).empty())
          self->quick_tool_run(*state, kRunId);
      };
      switch (id) {
      case kModeEnterId:
      case kModeMeasureId:
        if (code == BN_CLICKED) {
          const bool measuring = id == kModeMeasureId;
          if (measuring && state->adapters.empty())
            transfer_fill_adapters(*state);
          transfer_show_mode(*state, measuring);
          self->quick_tool_layout(*state);
          // With figures to work from the mode's result shows; without them, the mode's guide.
          if (!text_of(state->input).empty() && !text_of(state->link_speed).empty()) {
            recalculate();
          } else {
            state->last_report.reset();
            show_guide(state->report, state->tool, measuring);
          }
        }
        return 0;
      case kAdapterId:
        if (code == CBN_SELCHANGE) {
          transfer_apply_adapter(*state);
          recalculate();
        }
        return 0;
      case kAdapterRefreshId:
        transfer_fill_adapters(*state);
        return 0;
      case kUsingId:
        if (code == CBN_SELCHANGE) {
          // iPerf3 listens on 5201 unless told otherwise; SAT's listener on the port chosen, 2500 here.
          const int using_index = static_cast<int>(SendMessageW(state->using_tool, CB_GETCURSEL, 0, 0));
          const std::wstring port = text_of(state->test_port);
          if (using_index >= 1 && port == L"2500")
            SetWindowTextW(state->test_port, L"5201");
          else if (using_index == 0 && port == L"5201")
            SetWindowTextW(state->test_port, L"2500");
          EnableWindow(state->send_size, using_index == 0 ? TRUE : FALSE);
        }
        return 0;
      case kMeasureId:
        if (state->transfer_cancel) {
          state->transfer_cancel->cancel();
          set_status(*state, L"Stopping the network test...");
        } else {
          self->quick_tool_run(*state, kMeasureId);
        }
        return 0;
      case kOpenResultId: {
        const std::wstring chosen = choose_path(window, false);
        if (chosen.empty())
          return 0;
        std::ifstream input(std::filesystem::path(chosen), std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
        auto speed = support_assist::storage_speed_from_result(text);
        if (!speed.ok()) {
          set_status(*state, widen(speed.error().message));
          return 0;
        }
        // The figure goes into Storage speed; where it came from shows beside it.
        state->storage_speed = speed.value();
        state->storage_filled = widen(support_assist::transfer_rate_figure(speed.value().bytes_per_second));
        SetWindowTextW(state->storage_speed_field, state->storage_filled.c_str());
        SendMessageW(state->storage_unit, CB_SETCURSEL, kUnitMegabytes, 0);
        SetWindowTextW(state->storage_text,
                       widen(speed.value().name + ", from the result.json: " + speed.value().detail).c_str());
        EnableWindow(state->clear_result, TRUE);
        recalculate();
        return 0;
      }
      case kClearResultId:
        state->storage_speed.reset();
        state->storage_filled.clear();
        SetWindowTextW(state->storage_speed_field, L"");
        SetWindowTextW(state->storage_text, kStorageHelper);
        EnableWindow(state->clear_result, FALSE);
        recalculate();
        return 0;
      case kStorageSpeedId:
        if (code == EN_CHANGE) {
          // A figure typed over the opened one replaces it.
          const std::wstring typed = text_of(state->storage_speed_field);
          if (state->storage_speed && typed != state->storage_filled) {
            state->storage_speed.reset();
            state->storage_filled.clear();
            SetWindowTextW(state->storage_text, kStorageHelper);
          }
          EnableWindow(state->clear_result, typed.empty() ? FALSE : TRUE);
        }
        return 0;
      case kNetworkUnitId:
      case kStorageUnitId:
        if (code == CBN_SELCHANGE) {
          // Another unit for an opened figure makes it a figure of the engineer's own.
          if (id == kStorageUnitId && state->storage_speed &&
              SendMessageW(state->storage_unit, CB_GETCURSEL, 0, 0) != kUnitMegabytes) {
            state->storage_speed.reset();
            state->storage_filled.clear();
            SetWindowTextW(state->storage_text, kStorageHelper);
          }
          recalculate();
        }
        return 0;
      case kEmailId:
        if (state->estimate && copy_to_clipboard(window, widen(gui::file_transfer_email_text(*state->estimate))))
          set_status(*state, L"Email text copied.");
        return 0;
      default:
        break;
      }
    }
    if (id == kPresetId) {
      if (code == CBN_SELCHANGE)
        self->quick_tool_run(*state, kPresetId);
      return 0;
    }
    if (id == kTrustId) {
      // The certificate store needs nothing more; a file is typed or opened; a fingerprint is typed.
      if (code == CBN_SELCHANGE) {
        const int choice = static_cast<int>(SendMessageW(state->trust, CB_GETCURSEL, 0, 0));
        SetWindowTextW(state->fingerprint, L"");
        const wchar_t* cue = choice == 1   ? L"C:\\Certificates\\storage.crt: the storage's certificate or the CA that issued it"
                             : choice == 2 ? L"AB:CD:EF:...: the SHA-256 fingerprint of the storage's certificate"
                                           : L"Nothing to enter: the store is checked on every connection";
        SendMessageW(state->fingerprint, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(cue));
        // The store needs nothing more, so the field and Open... show only for a file or a fingerprint.
        ShowWindow(state->fingerprint, choice == 0 ? SW_HIDE : SW_SHOW);
        ShowWindow(state->certificate_open, choice == 1 ? SW_SHOW : SW_HIDE);
      }
      return 0;
    }
    if (id == kCertificateOpenId) {
      const std::wstring chosen = choose_path(window, false);
      if (!chosen.empty())
        SetWindowTextW(state->fingerprint, chosen.c_str());
      return 0;
    }
    if (id == kStoragePresetId || id == kRegionId) {
      // A new preset brings its own regions and its default; the endpoint's hint follows the region.
      const int chosen = static_cast<int>(SendMessageW(state->storage_preset, CB_GETCURSEL, 0, 0));
      if (chosen < 0 || static_cast<std::size_t>(chosen) >= state->storage_presets.size())
        return 0;
      const auto& preset = state->storage_presets[static_cast<std::size_t>(chosen)];
      const bool new_preset = id == kStoragePresetId && code == CBN_SELCHANGE;
      if (new_preset) {
        SendMessageW(state->region, CB_RESETCONTENT, 0, 0);
        for (const std::string& region : preset.regions)
          SendMessageW(state->region, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(widen(region).c_str()));
        SetWindowTextW(state->region, widen(preset.default_region).c_str());
        SendMessageW(state->region, CB_SETEDITSEL, 0, MAKELPARAM(-1, -1)); // the text, not selected
      }
      if (new_preset || (id == kRegionId && (code == CBN_SELCHANGE || code == CBN_EDITCHANGE))) {
        // A choice from the list is not in the field yet when CBN_SELCHANGE arrives.
        std::string region = support_assist::trim(id == kRegionId && code == CBN_SELCHANGE
                                                      ? combo_text(state->region)
                                                      : narrow_text(text_of(state->region)));
        if (region.empty())
          region = preset.default_region;
        std::string endpoint = preset.endpoint;
        for (std::size_t at = endpoint.find("{region}"); at != std::string::npos; at = endpoint.find("{region}"))
          endpoint.replace(at, 8U, region);
        const std::wstring cue = preset.endpoint.empty() ? std::wstring(L"s3.example.com or 10.0.4.30:9000")
                                                         : L"empty: " + widen(endpoint);
        SendMessageW(state->endpoint, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(cue.c_str()));
      }
      return 0;
    }
    if (id == kInputId && code == EN_CHANGE) {
      state->resolved_address.clear(); // a new name has not been checked yet
      return 0;
    }
    switch (id) {
    case kRunId: {
      // Enter in a converter field converts; in the Process field it asks for that process's ports.
      const HWND focus = GetFocus();
      if (state->tool == QuickTool::time_check && focus != nullptr &&
          (focus == state->convert_input || focus == state->log_input || GetParent(focus) == state->offset ||
           GetParent(focus) == state->show_in)) {
        SendMessageW(window, WM_COMMAND, MAKEWPARAM(kConvertId, BN_CLICKED), 0);
        return 0;
      }
      self->quick_tool_run(*state, state->process != nullptr && focus == state->process ? kProcessRunId : kRunId);
      return 0;
    }
    case kLogBrowseId: {
      const std::wstring chosen = choose_path(window, false);
      if (!chosen.empty()) {
        SetWindowTextW(state->log_input, chosen.c_str());
        read_log_file(*state, !path_in(state->convert_input).empty());
      }
      return 0;
    }
    case kProcessRunId:
      self->quick_tool_run(*state, kProcessRunId);
      return 0;
    case kBrowseId:
    case kFolderBrowseId: {
      const std::wstring chosen = choose_path(window, id == kFolderBrowseId || state->tool == QuickTool::volume_check);
      if (!chosen.empty()) {
        SetWindowTextW(state->input, chosen.c_str());
        self->quick_tool_run(*state, kRunId);
      }
      return 0;
    }
    case kConvertId: {
      const std::string text = support_assist::trim(narrow_text(text_of(state->convert_input)));
      const std::wstring log_path = path_in(state->log_input);
      // A log named and not yet read, or changed since, is read first; Convert follows.
      if (!log_path.empty() && log_path != state->log_clock_path) {
        read_log_file(*state, !text.empty());
        return 0;
      }
      if (state->reading_log) {
        state->convert_after_read = !text.empty();
        set_status(*state, L"Reading the log's own clock first...");
        return 0;
      }
      if (text.empty()) {
        set_status(*state, L"Paste a time or a whole line from a log first.");
        return 0;
      }
      const auto converted = support_assist::convert_with_choices(
          text, support_assist::read_zone_choice(narrow_text(text_of(state->offset))),
          log_path.empty() ? nullptr : state->log_clock.get(),
          support_assist::read_zone_choice(narrow_text(text_of(state->show_in))));
      const auto report = gui::time_conversion_report(text, converted);
      set_report_panel_report(state->convert_report, report);
      state->last_report = report;
      set_status(*state, widen(report.headline));
      self->append_activity(tool_title(state->tool), L"Converted", widen(report.headline));
      EnableWindow(state->copy, TRUE);
      EnableWindow(state->note, self->active_case() != nullptr ? TRUE : FALSE);
      return 0;
    }
    case kListenStartId:
      self->quick_tool_start_listener(*state);
      return 0;
    case kListenStopId:
      if (state->listener)
        state->listener->cancel();
      return 0;
    case kCopyId: {
      std::string text;
      if (state->tool == QuickTool::local_ports && state->ports) {
        text = gui::port_check_text(*state->ports);
        if (state->last_report)
          text += "\n" + gui::report_text(*state->last_report);
      } else if (state->tool == QuickTool::watch && state->snapshot) {
        text = "Service and Process Watch: " + narrow_text(text_of(state->input)) + "\n";
        for (const auto& item : state->snapshot->items)
          text += std::string(item.kind == support_assist::WatchKind::service ? "service" : "process") + "\t" +
                  item.name + "\t" + item.state + "\t" + std::to_string(item.pid) + "\t" +
                  gui::report_detail::utc_text(item.started_unix_millis) + "\t" + item.listening + "\n";
        if (!state->watch_events.empty())
          text += "\nChanges\n";
        for (const auto& event : state->watch_events)
          text += gui::report_detail::utc_text(event.at_unix_millis) + "  " + event.text + "\n";
      } else if (state->last_report) {
        text = gui::report_text(*state->last_report);
      } else if (state->tool == QuickTool::volume_check && !state->volumes.empty()) {
        auto report = gui::volumes_report(state->volumes);
        report.checked_unix_millis = state->volumes_read_unix_millis;
        text = gui::report_text(report);
      }
      if (!text.empty() && copy_to_clipboard(window, widen(text)))
        set_status(*state, L"Copied.");
      return 0;
    }
    case kExportId: {
      // The rows as CSV, or the result as the JSON the CLI prints with --json, to a file the engineer names.
      if (!state->ports)
        return 0;
      wchar_t file[MAX_PATH] = L"local-port-check.csv";
      OPENFILENAMEW dialog{};
      dialog.lStructSize = sizeof(dialog);
      dialog.hwndOwner = window;
      dialog.lpstrFilter = L"CSV (*.csv)\0*.csv\0JSON (*.json)\0*.json\0";
      dialog.nFilterIndex = 1;
      dialog.lpstrFile = file;
      dialog.nMaxFile = MAX_PATH;
      dialog.lpstrDefExt = L"csv";
      dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
      if (GetSaveFileNameW(&dialog) == FALSE)
        return 0;
      std::filesystem::path target(file);
      const bool json = dialog.nFilterIndex == 2 || support_assist::ascii_lower(narrow_text(target.extension().wstring())) == ".json";
      if (json && support_assist::ascii_lower(narrow_text(target.extension().wstring())) != ".json")
        target.replace_extension(L".json");
      const std::string content = json ? support_assist::tool_json::port_check(*state->ports)
                                       : "\xEF\xBB\xBF" + gui::port_check_csv(*state->ports);
      std::ofstream out(target, std::ios::binary | std::ios::trunc);
      out << content;
      out.close();
      set_status(*state, out ? L"Exported to " + target.wstring() : L"Could not write " + target.wstring());
      return 0;
    }
    case kNoteId: {
      const auto* workspace = self->active_case();
      if (workspace == nullptr)
        return 0;
      gui::QuickToolReport report;
      if (state->tool == QuickTool::watch) {
        report.tool = "Service and Process Watch";
        report.subject = narrow_text(text_of(state->input));
        report.headline = std::to_string(state->watch_events.size()) + " change(s) seen";
        report.checked_unix_millis = support_assist::unix_millis_now();
        gui::ReportSection section{"Changes", {}, {}};
        for (const auto& event : state->watch_events)
          section.rows.push_back(
              {gui::report_detail::utc_text(event.at_unix_millis), event.text, gui::ReportTone::normal});
        report.sections.push_back(std::move(section));
      } else if (state->last_report) {
        report = *state->last_report;
      } else if (state->tool == QuickTool::volume_check && !state->volumes.empty()) {
        report = gui::volumes_report(state->volumes);
        report.checked_unix_millis = state->volumes_read_unix_millis;
      } else {
        return 0;
      }
      const auto written = gui::add_quick_tool_report_to_note(*workspace, report, this_machine_name());
      if (written == gui::NoteWrite::added) {
        set_status(*state, L"Added to #note.");
        self->append_activity(tool_title(state->tool), L"Added to #note", widen(report.headline));
      } else {
        set_status(*state, written == gui::NoteWrite::already_there ? L"This result is in #note already."
                                                                     : L"#note could not be written.");
      }
      return 0;
    }
    case kLinkId:
      if (state->tool == QuickTool::name_check) {
        // The address the name resolved to; the name itself until it has been checked.
        self->open_remote_port_checker(state->resolved_address.empty() ? text_of(state->input)
                                                                       : widen(state->resolved_address));
      } else if (state->tool == QuickTool::volume_check && state->last_report) {
        for (const auto& section : state->last_report->sections) {
          for (const auto& row : section.rows) {
            const std::size_t at = row.value.find("https://");
            if (row.label == "Guide" && at != std::string::npos)
              ShellExecuteW(window, L"open", widen(row.value.substr(at)).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
          }
        }
      } else if (state->tool == QuickTool::object_storage) {
        self->open_quick_tool(ShortcutCommand::time_check);
      } else if (state->tool == QuickTool::watch && state->snapshot) {
        const int item = ListView_GetNextItem(state->table, -1, LVNI_SELECTED);
        if (item >= 0 && static_cast<std::size_t>(item) < state->snapshot->items.size()) {
          const auto& entry = state->snapshot->items[static_cast<std::size_t>(item)];
          if (entry.pid != 0)
            self->open_quick_tool(ShortcutCommand::local_port_checker, std::to_wstring(entry.pid));
          else
            set_status(*state, L"That service is not running, so it holds no ports.");
        }
      }
      return 0;
    case kLogLinkId:
      if (const support_assist::WatchEvent* event = selected_ended_event(*state)) {
        EnableWindow(state->log_link, FALSE);
        set_status(*state, L"Looking for the Veeam logs written before " + widen(event->item.name) + L" ended...");
        const std::int64_t at = event->at_unix_millis;
        std::string name = event->item.name;
        run_in_background(window, [at, name]() {
          Outcome outcome;
          outcome.logs_near = support_assist::logs_written_near(support_assist::veeam_log_folders(), at);
          outcome.logs_near_at = at;
          outcome.logs_near_name = name;
          return outcome;
        });
      }
      return 0;
    case IDCANCEL:
      // Escape closes a quick tool's window; a task's view closes with its session tab.
      if (!state->embedded)
        DestroyWindow(window);
      return 0;
    default:
      break;
    }
    break;
  }
  case WM_HELP:
    // F1 in the window, or in a dialog it owns, opens this tool's article.
    self->open_help_window(self->help_mode_for_window(window));
    return TRUE;
  case WM_CLOSE:
    DestroyWindow(window);
    return 0;
  case WM_DESTROY: {
    KillTimer(window, kWatchTimer);
    KillTimer(window, kCountdownTimer);
    KillTimer(window, kRecheckTimer);
    // Closing the window ends a watch or a listener; its run is kept as Stop keeps it.
    if (state->watching && state->snapshot)
      self->quick_tool_keep_output(watch_output(*state, support_assist::trim(narrow_text(text_of(state->input)))));
    if (state->listener) {
      const auto run = listener_record(*state, "");
      self->quick_tool_keep_output(listener_output(
          run, "The listener on " + std::to_string(run.port) + (state->listener_udp ? "/UDP" : "/TCP") +
                   " stopped when its window closed, after " + std::to_string(run.arrivals.size()) +
                   (state->listener_udp ? " datagram(s)." : " connection(s).")));
    }
    if (state->listener)
      state->listener->cancel();
    if (state->transfer_cancel)
      state->transfer_cancel->cancel();
    // A running Quick scan still removes its pktmon filter.
    stop_scan_in_background(std::move(state->scan));
    // Results already posted to this window would otherwise never be freed.
    MSG pending{};
    while (PeekMessageW(&pending, window, kResultMessage, kResultMessage, PM_REMOVE) != FALSE)
      delete reinterpret_cast<Outcome*>(pending.lParam);
    while (PeekMessageW(&pending, window, kListenerEventMessage, kListenerDoneMessage, PM_REMOVE) != FALSE)
      delete reinterpret_cast<ListenerEvent*>(pending.lParam);
    while (PeekMessageW(&pending, window, kScanStartedMessage, kScanStartedMessage, PM_REMOVE) != FALSE) {
      std::unique_ptr<ScanStart> started(reinterpret_cast<ScanStart*>(pending.lParam));
      stop_scan_in_background(std::move(started->scan));
    }
    while (PeekMessageW(&pending, window, kScanEndedMessage, kScanEndedMessage, PM_REMOVE) != FALSE)
      delete reinterpret_cast<std::string*>(pending.lParam);
    for (HWND& slot : self->quick_tool_windows_) {
      if (slot == window)
        slot = nullptr;
    }
    return 0;
  }
  case WM_NCDESTROY:
    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
    delete state;
    return DefWindowProcW(window, message, wparam, lparam);
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
