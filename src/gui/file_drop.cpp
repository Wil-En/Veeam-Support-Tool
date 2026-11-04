// Files and folders dropped on SAT. A file is read to show its SHA-256 in the checksum window; a
// folder is offered to Log Review. A checksum list dropped with files (SHA256SUMS, or a
// "<name>.sha256" file) checks them against the values it gives. Nothing dropped is run or opened
// with its own program.
//
// A drop reaches the main window from Explorer as WM_DROPFILES, or arrives as launch arguments when
// the files are dropped on the executable itself (main.cpp). Windows does not deliver a drop from
// an Explorer running without elevation to an elevated SAT, and SAT leaves that boundary in place.
// Kept out of app_window.cpp, which is already past 35,000 lines.

#include "app_window.hpp"

#include "dropped_paths.hpp"

#include "support_assist/error.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"

#include <dwmapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

constexpr UINT kChecksumResultMessage = WM_APP + 20;
constexpr UINT kDroppedPathsMessage = WM_APP + 21;
constexpr int kChecksumCopyId = 7201;
constexpr int kChecksumCopyAllId = 7202;
constexpr int kChecksumCloseId = 7203;
constexpr int kChecksumExpectedId = 7204;
constexpr int kChecksumListId = 7205;
// The checksum table's columns. Check stays folded away until a checksum list is dropped.
constexpr int kChecksumCheckColumn = 2;
constexpr int kChecksumCheckWidth = 200;

constexpr const wchar_t* kChecksumNote =
    L"Each file is read to calculate its SHA-256. Drop more files on this window or on SAT to add "
    L"them, and drop a SHA256SUMS file with them to check each one against it.";

// A finished hash, handed from the worker to the UI thread.
struct ChecksumResultPayload {
  std::uint64_t generation = 0;
  std::size_t index = 0;
  std::string sha256;
  std::string error;
};

std::wstring widen(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

// The paths in an Explorer drop. The handle is released here, whatever the paths turn out to be.
std::vector<std::filesystem::path> paths_from_drop(HDROP drop) {
  std::vector<std::filesystem::path> paths;
  const UINT count = DragQueryFileW(drop, 0xFFFFFFFFU, nullptr, 0);
  for (UINT index = 0; index < count; ++index) {
    const UINT length = DragQueryFileW(drop, index, nullptr, 0);
    if (length == 0U)
      continue;
    std::wstring path(static_cast<std::size_t>(length) + 1U, L'\0');
    DragQueryFileW(drop, index, path.data(), length + 1U);
    path.resize(length);
    paths.emplace_back(std::move(path));
  }
  DragFinish(drop);
  return paths;
}

bool copy_to_clipboard(HWND owner, const std::wstring& text) {
  if (text.empty() || OpenClipboard(owner) == FALSE)
    return false;
  EmptyClipboard();
  const std::size_t bytes = (text.size() + 1U) * sizeof(wchar_t);
  HGLOBAL memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
  if (memory == nullptr) {
    CloseClipboard();
    return false;
  }
  auto* destination = static_cast<wchar_t*>(GlobalLock(memory));
  if (destination == nullptr) {
    GlobalFree(memory);
    CloseClipboard();
    return false;
  }
  std::memcpy(destination, text.data(), text.size() * sizeof(wchar_t));
  destination[text.size()] = L'\0';
  GlobalUnlock(memory);
  if (SetClipboardData(CF_UNICODETEXT, memory) == nullptr) {
    GlobalFree(memory);
    CloseClipboard();
    return false;
  }
  CloseClipboard();
  return true;
}

}  // namespace

#ifdef SUPPORT_ASSIST_UI_SELFCHECK
void AppWindow::selfcheck_send_drop(const std::vector<std::filesystem::path>& paths) {
  std::size_t characters = 1U;
  for (const auto& path : paths)
    characters += path.wstring().size() + 1U;
  HGLOBAL memory = GlobalAlloc(GHND, sizeof(DROPFILES) + characters * sizeof(wchar_t));
  if (memory == nullptr)
    return;
  auto* drop = static_cast<DROPFILES*>(GlobalLock(memory));
  if (drop == nullptr) {
    GlobalFree(memory);
    return;
  }
  drop->pFiles = sizeof(DROPFILES);
  drop->fWide = TRUE;
  auto* names = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(drop) + sizeof(DROPFILES));
  for (const auto& path : paths) {
    const std::wstring text = path.wstring();
    std::memcpy(names, text.c_str(), (text.size() + 1U) * sizeof(wchar_t));
    names += text.size() + 1U;
  }
  *names = L'\0';
  GlobalUnlock(memory);
  // The handler's DragFinish frees the memory, as it does for a real drop.
  SendMessageW(window_, WM_DROPFILES, reinterpret_cast<WPARAM>(memory), 0);
}
#endif

void AppWindow::queue_dropped_paths(std::vector<std::filesystem::path> paths) {
  launch_dropped_paths_ = std::move(paths);
  if (window_ != nullptr && !launch_dropped_paths_.empty())
    PostMessageW(window_, kDroppedPathsMessage, 0, 0);
}

bool AppWindow::handle_file_drop_message(UINT message, WPARAM wparam, LPARAM lparam,
                                         LRESULT& result) {
  switch (message) {
  case WM_CREATE:
    DragAcceptFiles(window_, TRUE);
    return false;  // the window's own WM_CREATE handling still runs
  case WM_DROPFILES:
    accept_dropped_paths(paths_from_drop(reinterpret_cast<HDROP>(wparam)));
    result = 0;
    return true;
  case kDroppedPathsMessage: {
    const std::vector<std::filesystem::path> paths = std::move(launch_dropped_paths_);
    launch_dropped_paths_.clear();
    accept_dropped_paths(paths);
    result = 0;
    return true;
  }
  case kChecksumResultMessage: {
    std::unique_ptr<ChecksumResultPayload> payload(
        reinterpret_cast<ChecksumResultPayload*>(lparam));
    if (payload != nullptr)
      apply_checksum_result(payload->generation, payload->index, std::move(payload->sha256),
                            std::move(payload->error));
    result = 0;
    return true;
  }
  default:
    return false;
  }
}

void AppWindow::accept_dropped_paths(const std::vector<std::filesystem::path>& paths) {
  const auto sorted = support_assist::gui::sort_dropped_paths(paths);
  // A checksum list is read for its values rather than listed with its own SHA-256.
  std::vector<std::filesystem::path> files;
  std::vector<support_assist::gui::ChecksumList> lists;
  for (const auto& file : sorted.files) {
    if (auto list = support_assist::gui::read_checksum_list(file))
      lists.push_back(std::move(*list));
    else
      files.push_back(file);
  }
  if (!files.empty() || !lists.empty())
    add_checksum_files(files, std::move(lists));
  if (!sorted.folders.empty())
    review_dropped_folders(sorted.folders);
  if (!sorted.skipped.empty()) {
    set_status_message(L"Skipped " + std::to_wstring(sorted.skipped.size()) +
                       L" dropped item(s) that are neither a file nor a folder: " +
                       sorted.skipped.front().wstring());
  }
}

// A dropped folder opens Log Review with Auto Detect, the same way File Browser's Analyze does:
// with a case active the engineer chooses whether the result joins the case; without one the drop
// is confirmed first, so a folder dragged across the window by accident starts nothing.
void AppWindow::review_dropped_folders(const std::vector<std::filesystem::path>& folders) {
  std::wstring sources;
  std::wstring listed;
  for (std::size_t index = 0; index < folders.size(); ++index) {
    if (!sources.empty())
      sources += L";";
    sources += folders[index].wstring();
    if (index < 10U)
      listed += L"\n" + folders[index].wstring();
    else if (index == 10U)
      listed += L"\n... and " + std::to_wstring(folders.size() - 10U) + L" more";
  }
  const auto* workspace = active_case();
  bool append_to_case = false;
  if (workspace != nullptr) {
    const std::wstring question =
        std::wstring(folders.size() == 1U ? L"Review the dropped folder"
                                          : L"Review the dropped folders") +
        L" with Auto Detect and add the resulting evidence to case " +
        widen(workspace->case_id) + L"?\n" + listed +
        L"\n\nYes = review and append to the active case.\nNo = review only.\nCancel = do nothing.";
    const int choice = MessageBoxW(window_, question.c_str(), L"Review dropped folder",
                                   MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON1);
    if (choice == IDCANCEL)
      return;
    append_to_case = choice == IDYES;
  } else {
    const std::wstring question =
        std::wstring(folders.size() == 1U ? L"Review the dropped folder"
                                          : L"Review the dropped folders") +
        L" in Log Review with Auto Detect?\n" + listed;
    if (MessageBoxW(window_, question.c_str(), L"Review dropped folder",
                    MB_OKCANCEL | MB_ICONQUESTION | MB_DEFBUTTON1) != IDOK)
      return;
  }

  Card card{L"AUTO",
            L"Auto Detect Veeam Logs: " + folders.front().filename().wstring() +
                (folders.size() > 1U ? L" and " + std::to_wstring(folders.size() - 1U) + L" more"
                                     : L""),
            L"Review the dropped folders with Auto Detect.",
            Page::log_review,
            5,
            false};
  suppress_auto_local_review_ = true;
  const bool opened = create_tool_session(card);
  suppress_auto_local_review_ = false;
  if (!opened)
    return;
  ToolSession* session = active_session();
  if (session == nullptr)
    return;
  session->primary = sources;
  session->append_to_case = append_to_case;
  session->protect_case_review_on_completion = append_to_case;
  session->return_to_case_dashboard = append_to_case;
  session->review_only = workspace != nullptr && !append_to_case;
  if (session->review_only) {
    // The report goes where a review without a case writes it, not into the case folder.
    session->secondary.clear();
    set_control_text(secondary_edit_, L"");
  }
  set_control_text(primary_edit_, sources);
  append_activity(L"Log Review", L"Dropped folder opened", sources);
  start_operation();
}

void AppWindow::add_checksum_files(const std::vector<std::filesystem::path>& files,
                                   std::vector<support_assist::gui::ChecksumList> lists) {
  open_checksum_window();
  if (checksum_window_ == nullptr)
    return;
  const std::size_t first_new = checksum_set_.rows().size();
  auto jobs = checksum_set_.add(files, std::move(lists));
  bool start_worker = false;
  {
    std::scoped_lock lock(checksum_mutex_);
    for (auto& job : jobs)
      checksum_queue_.push_back(std::move(job));
    if (!checksum_queue_.empty() && !checksum_worker_busy_) {
      checksum_worker_busy_ = true;
      start_worker = true;
    }
  }
  if (checksum_set_.has_lists() &&
      ListView_GetColumnWidth(checksum_list_, kChecksumCheckColumn) < sx(kChecksumCheckWidth))
    ListView_SetColumnWidth(checksum_list_, kChecksumCheckColumn, sx(kChecksumCheckWidth));
  // Earlier rows are shown again: a list dropped now gives them a Check.
  for (std::size_t index = 0; index < checksum_set_.rows().size(); ++index)
    show_checksum_row(index, index >= first_new);
  update_checksum_match();
  update_checksum_summary();
  if (!start_worker)
    return;

  // A worker that has already drained the queue is finished; joining it only collects the thread.
  if (checksum_worker_.joinable())
    checksum_worker_.join();
  const auto token = checksum_cancel_.token();
  const std::uint64_t generation = checksum_generation_;
  const HWND target = window_;
  checksum_worker_ = std::jthread([this, token, generation, target](std::stop_token stop) {
    for (;;) {
      std::pair<std::size_t, std::filesystem::path> job;
      {
        std::scoped_lock lock(checksum_mutex_);
        if (checksum_queue_.empty() || stop.stop_requested() || token.is_cancelled()) {
          checksum_worker_busy_ = false;
          return;
        }
        job = std::move(checksum_queue_.front());
        checksum_queue_.pop_front();
      }
      auto* payload = new ChecksumResultPayload{};
      payload->generation = generation;
      payload->index = job.first;
      auto hashed = support_assist::hash_file_sha256(job.second, token);
      if (hashed.ok())
        payload->sha256 = hashed.value();
      else
        payload->error = support_assist::describe_error(hashed.error());
      if (PostMessageW(target, kChecksumResultMessage, 0, reinterpret_cast<LPARAM>(payload)) ==
          FALSE)
        delete payload;
    }
  });
}

void AppWindow::apply_checksum_result(std::uint64_t generation, std::size_t index,
                                      std::string sha256, std::string error) {
  if (generation != checksum_generation_ || index >= checksum_set_.rows().size())
    return;
  checksum_set_.set_result(index, std::move(sha256), std::move(error));
  show_checksum_row(index, false);
  update_checksum_match();
  update_checksum_summary();
  const auto& row = checksum_set_.rows()[index];
  append_activity(L"File checksum", row.error.empty() ? L"SHA-256 calculated" : L"Not read",
                  row.path.wstring());
}

void AppWindow::show_checksum_row(std::size_t index, bool insert) {
  if (checksum_list_ == nullptr || index >= checksum_set_.rows().size())
    return;
  std::wstring name = widen(checksum_set_.file_text(index));
  std::wstring hash = widen(checksum_set_.hash_text(index));
  std::wstring verdict = widen(checksum_set_.check_text(index));
  std::wstring size = widen(checksum_set_.size_text(index));
  std::wstring folder = widen(checksum_set_.folder_text(index));
  const int item = static_cast<int>(index);
  if (insert) {
    LVITEMW entry{};
    entry.mask = LVIF_TEXT;
    entry.iItem = item;
    entry.pszText = name.data();
    ListView_InsertItem(checksum_list_, &entry);
  }
  ListView_SetItemText(checksum_list_, item, 0, name.data());
  ListView_SetItemText(checksum_list_, item, 1, hash.data());
  ListView_SetItemText(checksum_list_, item, kChecksumCheckColumn, verdict.data());
  ListView_SetItemText(checksum_list_, item, 3, size.data());
  ListView_SetItemText(checksum_list_, item, 4, folder.data());
}

// The line above the table: the window's note, or once a checksum list has been dropped, how the
// files compare with it.
void AppWindow::update_checksum_summary() {
  if (checksum_note_ == nullptr)
    return;
  const auto summary = checksum_set_.summary();
  const std::wstring text = checksum_set_.has_lists() ? widen(summary.text) : kChecksumNote;
  checksum_note_state_ = checksum_set_.has_lists() ? summary.state : -1;
  SetWindowTextW(checksum_note_, text.c_str());
  InvalidateRect(checksum_note_, nullptr, TRUE);
}

// The expected value is compared as text only, once reduced to plain lowercase hex.
void AppWindow::update_checksum_match() {
  if (checksum_expected_ == nullptr || checksum_match_ == nullptr)
    return;
  const int length = GetWindowTextLengthW(checksum_expected_);
  std::wstring typed(static_cast<std::size_t>(length) + 1U, L'\0');
  GetWindowTextW(checksum_expected_, typed.data(), length + 1);
  typed.resize(static_cast<std::size_t>(length));
  const std::string expected =
      support_assist::normalize_sha256_text(support_assist::utf8_from_wide(typed));

  std::wstring text;
  int state = 0;
  if (typed.find_first_not_of(L" \t\r\n") == std::wstring::npos) {
    state = 0;
  } else if (expected.empty()) {
    text = L"Not a SHA-256 value (64 hexadecimal characters).";
    state = 3;
  } else {
    std::vector<std::wstring> matches;
    bool pending = false;
    for (const auto& row : checksum_set_.rows()) {
      if (!row.done)
        pending = true;
      else if (row.sha256 == expected)
        matches.push_back(row.path.filename().wstring());
    }
    if (!matches.empty()) {
      text = L"Matches " + matches.front() +
             (matches.size() > 1U ? L" and " + std::to_wstring(matches.size() - 1U) + L" more"
                                  : L"");
      state = 1;
    } else if (pending) {
      text = L"No match yet. Files are still being read.";
      state = 0;
    } else {
      text = L"No file in the list matches this value.";
      state = 2;
    }
  }
  checksum_match_state_ = state;
  SetWindowTextW(checksum_match_, text.c_str());
  InvalidateRect(checksum_match_, nullptr, TRUE);
}

// Copy SHA-256 puts only the values on the clipboard, one per line; Copy all puts the whole list
// as tab-separated rows under a heading row.
void AppWindow::copy_checksums(bool hashes_only) {
  if (checksum_list_ == nullptr)
    return;
  std::vector<std::size_t> chosen;
  for (int item = ListView_GetNextItem(checksum_list_, -1, LVNI_SELECTED); item >= 0;
       item = ListView_GetNextItem(checksum_list_, item, LVNI_SELECTED))
    chosen.push_back(static_cast<std::size_t>(item));
  if (!hashes_only || chosen.empty()) {
    chosen.clear();
    for (std::size_t index = 0; index < checksum_set_.rows().size(); ++index)
      chosen.push_back(index);
  }
  std::wstring text = hashes_only ? L"" : widen(checksum_set_.copy_all("\r\n"));
  for (const std::size_t index : chosen) {
    if (!hashes_only || index >= checksum_set_.rows().size())
      continue;
    const auto& row = checksum_set_.rows()[index];
    if (!row.sha256.empty())
      text += widen(row.sha256) + L"\r\n";
  }
  if (copy_to_clipboard(checksum_window_, text))
    set_status_message(hashes_only ? L"Copied the SHA-256 value(s)." : L"Copied the checksum list.");
}

void AppWindow::stop_checksum_work() {
  checksum_cancel_.cancel();
  if (checksum_worker_.joinable()) {
    checksum_worker_.request_stop();
    checksum_worker_.join();
  }
  std::scoped_lock lock(checksum_mutex_);
  checksum_queue_.clear();
  checksum_set_.clear();
  checksum_worker_busy_ = false;
  checksum_cancel_ = support_assist::CancellationSource{};
  ++checksum_generation_;
}

void AppWindow::open_checksum_window() {
  if (checksum_window_ != nullptr) {
    ShowWindow(checksum_window_, SW_SHOWNORMAL);
    SetForegroundWindow(checksum_window_);
    return;
  }
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.lpfnWndProc = &AppWindow::checksum_window_proc;
    description.hInstance = instance_;
    description.lpszClassName = L"SupportAssistChecksumWindow";
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    description.hbrBackground = background_brush_;
    RegisterClassW(&description);
    registered = true;
  }
  // WS_EX_ACCEPTFILES so files dropped on this window are added to it too.
  checksum_window_ = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_ACCEPTFILES,
                                     L"SupportAssistChecksumWindow", L"File checksum (SHA-256)",
                                     WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, sx(1040),
                                     sx(460), window_, nullptr, instance_, this);
  if (checksum_window_ == nullptr)
    return;
  const BOOL dark = themed_title_bar_dark();
  DwmSetWindowAttribute(checksum_window_, 20, &dark, sizeof(dark));

  const auto make_static = [&](const wchar_t* text) {
    return CreateWindowExW(0, WC_STATICW, text, WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0,
                           0, 0, 0, checksum_window_, nullptr, instance_, nullptr);
  };
  const auto make_button = [&](const wchar_t* text, int id) {
    const HWND button = CreateWindowExW(
        0, WC_BUTTONW, text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0,
        checksum_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    apply_control_theme(button);
    return button;
  };
  checksum_note_ = make_static(kChecksumNote);
  checksum_list_ = CreateWindowExW(
      WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0,
      checksum_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kChecksumListId)), instance_,
      nullptr);
  ListView_SetExtendedListViewStyle(checksum_list_,
                                    LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
  apply_control_theme(checksum_list_);
  theme_list_header(checksum_list_);
  ListView_SetBkColor(checksum_list_, themed(RGB(13, 31, 33)));
  ListView_SetTextBkColor(checksum_list_, themed(RGB(13, 31, 33)));
  ListView_SetTextColor(checksum_list_, themed(RGB(225, 236, 231)));
  const std::pair<const wchar_t*, int> columns[] = {
      {L"File", 220}, {L"SHA-256", 500}, {L"Check", 0}, {L"Size", 100}, {L"Folder", 360}};
  for (int column = 0; column < 5; ++column) {
    LVCOLUMNW definition{};
    definition.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    definition.pszText = const_cast<LPWSTR>(columns[column].first);
    definition.cx = sx(columns[column].second);
    definition.iSubItem = column;
    ListView_InsertColumn(checksum_list_, column, &definition);
  }
  checksum_expected_label_ = make_static(L"Expected SHA-256");
  checksum_expected_ = CreateWindowExW(
      WS_EX_CLIENTEDGE, WC_EDITW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0,
      0, 0, checksum_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kChecksumExpectedId)),
      instance_, nullptr);
  SendMessageW(checksum_expected_, EM_SETCUEBANNER, TRUE,
               reinterpret_cast<LPARAM>(L"Paste a published SHA-256 to compare"));
  checksum_match_ = make_static(L"");
  checksum_copy_ = make_button(L"Copy SHA-256", kChecksumCopyId);
  checksum_copy_all_ = make_button(L"Copy all", kChecksumCopyAllId);
  checksum_close_ = make_button(L"Close", kChecksumCloseId);

  for (HWND control : {checksum_note_, checksum_list_, checksum_expected_label_, checksum_match_,
                       checksum_copy_, checksum_copy_all_, checksum_close_})
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
  SendMessageW(checksum_expected_, WM_SETFONT, reinterpret_cast<WPARAM>(mono_font_), TRUE);

  layout_checksum_window();
  ShowWindow(checksum_window_, SW_SHOWNORMAL);
  SetForegroundWindow(checksum_window_);
}

void AppWindow::layout_checksum_window() {
  if (checksum_window_ == nullptr)
    return;
  RECT client{};
  GetClientRect(checksum_window_, &client);
  const int width = client.right;
  const int height = client.bottom;
  const int margin = sx(12);
  const int row = sx(28);
  const int button_width = sx(120);
  const int label_width = sx(130);
  MoveWindow(checksum_note_, margin, margin, std::max(0, width - margin * 2), sx(20), TRUE);
  const int list_top = margin + sx(26);
  const int bottom_rows = row * 2 + sx(10) + margin;
  MoveWindow(checksum_list_, margin, list_top, std::max(0, width - margin * 2),
             std::max(sx(80), height - list_top - bottom_rows - sx(8)), TRUE);
  const int expected_top = height - margin - row * 2 - sx(10);
  MoveWindow(checksum_expected_label_, margin, expected_top + sx(5), label_width, sx(20), TRUE);
  MoveWindow(checksum_expected_, margin + label_width, expected_top,
             std::max(sx(200), width - margin * 2 - label_width), row, TRUE);
  const int button_top = height - margin - row;
  int x = width - margin - button_width;
  MoveWindow(checksum_close_, x, button_top, button_width, row, TRUE);
  x -= button_width + sx(8);
  MoveWindow(checksum_copy_all_, x, button_top, button_width, row, TRUE);
  x -= button_width + sx(8);
  MoveWindow(checksum_copy_, x, button_top, button_width, row, TRUE);
  MoveWindow(checksum_match_, margin, button_top + sx(5), std::max(0, x - margin * 2), sx(20),
             TRUE);
}

LRESULT CALLBACK AppWindow::checksum_window_proc(HWND window, UINT message, WPARAM wparam,
                                                 LPARAM lparam) {
  if (message == WM_NCCREATE) {
    const auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
    SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    return DefWindowProcW(window, message, wparam, lparam);
  }
  auto* self = reinterpret_cast<AppWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
  if (self == nullptr)
    return DefWindowProcW(window, message, wparam, lparam);
  switch (message) {
  case WM_CTLCOLORSTATIC: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    COLORREF colour = themed(RGB(236, 244, 240));
    if (reinterpret_cast<HWND>(lparam) == self->checksum_match_) {
      colour = self->checksum_match_state_ == 1   ? themed(RGB(114, 224, 106))
               : self->checksum_match_state_ == 2 ? themed(RGB(255, 112, 112))
               : self->checksum_match_state_ == 3 ? themed(RGB(255, 199, 91))
                                                  : themed(RGB(165, 188, 178));
    } else if (reinterpret_cast<HWND>(lparam) == self->checksum_note_) {
      colour = self->checksum_note_state_ == 1   ? themed(RGB(114, 224, 106))
               : self->checksum_note_state_ == 2 ? themed(RGB(255, 112, 112))
               : self->checksum_note_state_ == 3 ? themed(RGB(255, 199, 91))
                                                 : themed(RGB(165, 188, 178));
    }
    SetTextColor(dc, colour);
    SetBkMode(dc, TRANSPARENT);
    SetBkColor(dc, themed(RGB(7, 24, 26)));
    return reinterpret_cast<LRESULT>(self->background_brush_);
  }
  case WM_CTLCOLOREDIT: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    SetTextColor(dc, themed(RGB(236, 244, 240)));
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, themed(RGB(22, 42, 44)));
    return reinterpret_cast<LRESULT>(self->input_brush_);
  }
  case WM_SIZE:
    self->layout_checksum_window();
    return 0;
  case WM_DROPFILES:
    self->accept_dropped_paths(paths_from_drop(reinterpret_cast<HDROP>(wparam)));
    return 0;
  case WM_COMMAND:
    switch (LOWORD(wparam)) {
    case kChecksumCopyId:
      self->copy_checksums(true);
      return 0;
    case kChecksumCopyAllId:
      self->copy_checksums(false);
      return 0;
    case kChecksumCloseId:
      DestroyWindow(window);
      return 0;
    case kChecksumExpectedId:
      if (HIWORD(wparam) == EN_CHANGE)
        self->update_checksum_match();
      return 0;
    default:
      break;
    }
    break;
  case WM_NOTIFY: {
    const auto* header = reinterpret_cast<const NMHDR*>(lparam);
    if (header->code == NM_CUSTOMDRAW && self->checksum_list_ != nullptr &&
        header->hwndFrom == ListView_GetHeader(self->checksum_list_))
      return self->paint_list_header(header, lparam);
    if (header->hwndFrom == self->checksum_list_ && header->code == LVN_KEYDOWN) {
      const auto* key = reinterpret_cast<const NMLVKEYDOWN*>(lparam);
      const bool control = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
      if (control && key->wVKey == 'C')
        self->copy_checksums(true);
      else if (control && key->wVKey == 'A')
        ListView_SetItemState(self->checksum_list_, -1, LVIS_SELECTED, LVIS_SELECTED);
      return 0;
    }
    break;
  }
  case WM_CONTEXTMENU:
    if (reinterpret_cast<HWND>(wparam) == self->checksum_list_) {
      HMENU menu = CreatePopupMenu();
      if (menu == nullptr)
        return 0;
      AppendMenuW(menu, MF_STRING, 1, L"Copy SHA-256");
      AppendMenuW(menu, MF_STRING, 2, L"Copy all");
      POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      if (point.x == -1 && point.y == -1)
        GetCursorPos(&point);
      const UINT command = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN,
                                          point.x, point.y, 0, window, nullptr);
      DestroyMenu(menu);
      if (command == 1)
        self->copy_checksums(true);
      else if (command == 2)
        self->copy_checksums(false);
      return 0;
    }
    break;
  case WM_CLOSE:
    DestroyWindow(window);
    return 0;
  case WM_DESTROY:
    // Closing the window stops any file still being read and forgets the list.
    self->stop_checksum_work();
    self->checksum_window_ = nullptr;
    self->checksum_note_ = nullptr;
    self->checksum_list_ = nullptr;
    self->checksum_expected_label_ = nullptr;
    self->checksum_expected_ = nullptr;
    self->checksum_match_ = nullptr;
    self->checksum_copy_ = nullptr;
    self->checksum_copy_all_ = nullptr;
    self->checksum_close_ = nullptr;
    self->checksum_match_state_ = 0;
    self->checksum_note_state_ = -1;
    return 0;
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
