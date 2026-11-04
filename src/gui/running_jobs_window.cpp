// The Running Jobs window: every session tab, in every case, with its state, how long it has run
// and its newest progress report. Opened from View > Running Jobs and by clicking the running time
// at the top right of the main window. A row opens its session, switching to the session's case
// when it belongs to another; a running job can be cancelled from here.
//
// Kept out of app_window.cpp, which is already past 35,000 lines.

#include "app_window.hpp"

#include "running_jobs.hpp"

#include "support_assist/strings.hpp"

#include <dwmapi.h>
#include <uxtheme.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace {

constexpr int kJobsListId = 7301;
constexpr int kJobsGoId = 7302;
constexpr int kJobsCancelId = 7303;
constexpr int kJobsCloseId = 7304;
constexpr UINT_PTR kJobsRefreshTimer = 1;
constexpr UINT kJobsRefreshMs = 500;

std::wstring widen(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

}  // namespace

std::vector<support_assist::gui::JobEntry> AppWindow::collect_jobs() const {
  using support_assist::gui::JobState;
  std::vector<support_assist::gui::JobEntry> jobs;
  const auto now = std::chrono::steady_clock::now();
  for (const auto& owned : sessions_) {
    if (owned == nullptr)
      continue;
    const ToolSession& session = *owned;
    support_assist::gui::JobEntry job;
    job.key = static_cast<std::size_t>(session.id);
    job.session = support_assist::utf8_from_wide(session.title);
    const auto found = std::find_if(navigation_items_.begin(), navigation_items_.end(),
                                    [&](const auto& item) {
                                      return item.selectable && item.page == session.page;
                                    });
    if (found != navigation_items_.end())
      job.page = support_assist::utf8_from_wide(found->label);
    job.case_id = support_assist::utf8_from_wide(session.context_case_id);
    if (session.busy) {
      job.state = session.cancellation.is_cancelled() ? JobState::cancelling : JobState::running;
      job.elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - session.started);
    } else if (session.artifact_busy) {
      job.state = JobState::finalizing;
    } else if (session.completed) {
      job.state = JobState::finished;
    }
    job.progress = support_assist::utf8_from_wide(session.status);
    jobs.push_back(std::move(job));
  }
  support_assist::gui::order_jobs(jobs);
  return jobs;
}

void AppWindow::open_jobs_window() {
  if (jobs_window_ != nullptr) {
    ShowWindow(jobs_window_, SW_SHOWNORMAL);
    SetForegroundWindow(jobs_window_);
    refresh_jobs_window();
    return;
  }
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.lpfnWndProc = &AppWindow::jobs_window_proc;
    description.hInstance = instance_;
    description.lpszClassName = L"SupportAssistJobsWindow";
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    description.hbrBackground = background_brush_;
    RegisterClassW(&description);
    registered = true;
  }
  jobs_window_ = CreateWindowExW(WS_EX_CONTROLPARENT, L"SupportAssistJobsWindow", L"Running Jobs",
                                 WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, sx(980),
                                 sx(420), window_, nullptr, instance_, this);
  if (jobs_window_ == nullptr)
    return;
  const BOOL dark = themed_title_bar_dark();
  DwmSetWindowAttribute(jobs_window_, 20, &dark, sizeof(dark));

  jobs_summary_ = CreateWindowExW(0, WC_STATICW, L"",
                                  WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_ENDELLIPSIS,
                                  0, 0, 0, 0, jobs_window_, nullptr, instance_, nullptr);
  jobs_list_ = CreateWindowExW(
      WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS, 0, 0,
      0, 0, jobs_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kJobsListId)), instance_,
      nullptr);
  ListView_SetExtendedListViewStyle(jobs_list_,
                                    LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP);
  apply_control_theme(jobs_list_);
  theme_list_header(jobs_list_);
  ListView_SetBkColor(jobs_list_, themed(RGB(13, 31, 33)));
  ListView_SetTextBkColor(jobs_list_, themed(RGB(13, 31, 33)));
  ListView_SetTextColor(jobs_list_, themed(RGB(225, 236, 231)));
  const int widths[support_assist::gui::kJobColumnCount] = {230, 150, 130, 140, 300};
  for (int column = 0; column < support_assist::gui::kJobColumnCount; ++column) {
    std::wstring heading = widen(support_assist::gui::kJobColumns[column]);
    LVCOLUMNW definition{};
    definition.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    definition.pszText = heading.data();
    definition.cx = sx(widths[column]);
    definition.iSubItem = column;
    ListView_InsertColumn(jobs_list_, column, &definition);
  }
  const auto make_button = [&](const wchar_t* text, int id) {
    const HWND button = CreateWindowExW(
        0, WC_BUTTONW, text, WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0, 0, 0, 0,
        jobs_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    apply_control_theme(button);
    return button;
  };
  jobs_go_ = make_button(L"Go to Session", kJobsGoId);
  jobs_cancel_ = make_button(L"Cancel Job", kJobsCancelId);
  jobs_close_ = make_button(L"Close", kJobsCloseId);
  for (HWND control : {jobs_summary_, jobs_list_, jobs_go_, jobs_cancel_, jobs_close_})
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);

  jobs_shown_.clear();
  refresh_jobs_window();
  layout_jobs_window();
  SetTimer(jobs_window_, kJobsRefreshTimer, kJobsRefreshMs, nullptr);
  ShowWindow(jobs_window_, SW_SHOWNORMAL);
  SetForegroundWindow(jobs_window_);
  SetFocus(jobs_list_);
}

void AppWindow::layout_jobs_window() {
  if (jobs_window_ == nullptr)
    return;
  RECT client{};
  GetClientRect(jobs_window_, &client);
  const int width = client.right;
  const int height = client.bottom;
  const int margin = sx(12);
  const int row = sx(28);
  const int button_width = sx(130);
  MoveWindow(jobs_summary_, margin, margin, std::max(0, width - margin * 2), sx(20), TRUE);
  const int list_top = margin + sx(26);
  MoveWindow(jobs_list_, margin, list_top, std::max(0, width - margin * 2),
             std::max(sx(80), height - list_top - row - margin - sx(10)), TRUE);
  const int button_top = height - margin - row;
  int x = width - margin - button_width;
  MoveWindow(jobs_close_, x, button_top, button_width, row, TRUE);
  x -= button_width + sx(8);
  MoveWindow(jobs_cancel_, x, button_top, button_width, row, TRUE);
  x -= button_width + sx(8);
  MoveWindow(jobs_go_, x, button_top, button_width, row, TRUE);
}

// Repaints only what changed, so a list refreshed twice a second does not flicker.
void AppWindow::refresh_jobs_window() {
  if (jobs_window_ == nullptr || jobs_list_ == nullptr)
    return;
  auto jobs = collect_jobs();
  const int selected_item = ListView_GetNextItem(jobs_list_, -1, LVNI_SELECTED);
  const bool had_selection =
      selected_item >= 0 && static_cast<std::size_t>(selected_item) < jobs_shown_.size();
  const std::size_t selected_key =
      had_selection ? jobs_shown_[static_cast<std::size_t>(selected_item)].key : 0U;
  bool same_rows = jobs.size() == jobs_shown_.size();
  for (std::size_t index = 0; same_rows && index < jobs.size(); ++index)
    same_rows = jobs[index].key == jobs_shown_[index].key;

  SendMessageW(jobs_list_, WM_SETREDRAW, FALSE, 0);
  if (!same_rows) {
    ListView_DeleteAllItems(jobs_list_);
    for (std::size_t index = 0; index < jobs.size(); ++index) {
      std::wstring first = widen(support_assist::gui::job_column_text(jobs[index], 0));
      LVITEMW entry{};
      entry.mask = LVIF_TEXT;
      entry.iItem = static_cast<int>(index);
      entry.pszText = first.data();
      ListView_InsertItem(jobs_list_, &entry);
    }
  }
  for (std::size_t index = 0; index < jobs.size(); ++index) {
    for (int column = 0; column < support_assist::gui::kJobColumnCount; ++column) {
      const std::string text = support_assist::gui::job_column_text(jobs[index], column);
      if (same_rows &&
          text == support_assist::gui::job_column_text(jobs_shown_[index], column))
        continue;
      std::wstring cell = widen(text);
      ListView_SetItemText(jobs_list_, static_cast<int>(index), column, cell.data());
    }
    if (!same_rows && had_selection && jobs[index].key == selected_key)
      ListView_SetItemState(jobs_list_, static_cast<int>(index), LVIS_SELECTED | LVIS_FOCUSED,
                            LVIS_SELECTED | LVIS_FOCUSED);
  }
  // New rows size the columns to what they hold; a refresh of the same rows keeps a width the engineer dragged.
  if (!same_rows)
    fit_report_columns(jobs_list_);
  SendMessageW(jobs_list_, WM_SETREDRAW, TRUE, 0);
  if (!same_rows)
    InvalidateRect(jobs_list_, nullptr, TRUE);

  const std::wstring summary = widen(support_assist::gui::jobs_summary(jobs));
  if (control_text(jobs_summary_) != summary)
    set_control_text(jobs_summary_, summary);
  jobs_shown_ = std::move(jobs);
  update_jobs_buttons();
}

void AppWindow::update_jobs_buttons() {
  if (jobs_list_ == nullptr)
    return;
  const int item = ListView_GetNextItem(jobs_list_, -1, LVNI_SELECTED);
  const bool chosen = item >= 0 && static_cast<std::size_t>(item) < jobs_shown_.size();
  EnableWindow(jobs_go_, chosen ? TRUE : FALSE);
  EnableWindow(jobs_cancel_,
               chosen && support_assist::gui::job_can_cancel(
                             jobs_shown_[static_cast<std::size_t>(item)])
                   ? TRUE
                   : FALSE);
}

// Opens the session in the main window. A session that belongs to another case is shown by
// switching to that case first, as choosing the case in the case box does.
bool AppWindow::go_to_job(std::size_t key) {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(), [&](const auto& session) {
    return session != nullptr && static_cast<std::size_t>(session->id) == key;
  });
  if (found == sessions_.end())
    return false;
  const int index = static_cast<int>(std::distance(sessions_.begin(), found));
  if (!session_matches_active_case_context(**found)) {
    int combo = 0;
    if (!(*found)->context_case_root.empty()) {
      const auto root = (*found)->context_case_root.lexically_normal();
      const auto owner = std::find_if(cases_.begin(), cases_.end(), [&](const auto& workspace) {
        return workspace.root.lexically_normal() == root;
      });
      if (owner == cases_.end())
        return false;
      combo = static_cast<int>(std::distance(cases_.begin(), owner)) + 1;
    }
    SendMessageW(active_case_combo_, CB_SETCURSEL, static_cast<WPARAM>(combo), 0);
    activate_case_from_combo();
  }
  activate_session(index);
  if (IsIconic(window_))
    ShowWindow(window_, SW_RESTORE);
  SetForegroundWindow(window_);
  return active_session() == found->get();
}

// Cancels a running job the way its own Cancel button does.
void AppWindow::cancel_job(std::size_t key) {
  const auto found = std::find_if(sessions_.begin(), sessions_.end(), [&](const auto& session) {
    return session != nullptr && static_cast<std::size_t>(session->id) == key;
  });
  if (found == sessions_.end())
    return;
  ToolSession& session = **found;
  if (&session == active_session()) {
    cancel_operation();
  } else if (session.busy && !session.cancellation.is_cancelled()) {
    session.cancellation.cancel();
    session.status = L"Cancellation requested; waiting for a safe interruption point...";
    append_activity(session.title, L"Cancel requested", session.status, session.bound_case_id);
  }
  refresh_jobs_window();
}

LRESULT CALLBACK AppWindow::jobs_window_proc(HWND window, UINT message, WPARAM wparam,
                                             LPARAM lparam) {
  if (message == WM_NCCREATE) {
    const auto* create = reinterpret_cast<CREATESTRUCTW*>(lparam);
    SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    return DefWindowProcW(window, message, wparam, lparam);
  }
  auto* self = reinterpret_cast<AppWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
  if (self == nullptr)
    return DefWindowProcW(window, message, wparam, lparam);
  const auto chosen_key = [self]() -> std::optional<std::size_t> {
    const int item = ListView_GetNextItem(self->jobs_list_, -1, LVNI_SELECTED);
    if (item < 0 || static_cast<std::size_t>(item) >= self->jobs_shown_.size())
      return std::nullopt;
    return self->jobs_shown_[static_cast<std::size_t>(item)].key;
  };
  switch (message) {
  case WM_CTLCOLORSTATIC: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    SetTextColor(dc, themed(RGB(165, 188, 178)));
    SetBkMode(dc, TRANSPARENT);
    SetBkColor(dc, themed(RGB(7, 24, 26)));
    return reinterpret_cast<LRESULT>(self->background_brush_);
  }
  case WM_SIZE:
    self->layout_jobs_window();
    return 0;
  case WM_TIMER:
    if (wparam == kJobsRefreshTimer) {
      self->refresh_jobs_window();
      return 0;
    }
    break;
  case WM_COMMAND:
    switch (LOWORD(wparam)) {
    case kJobsGoId:
      if (const auto key = chosen_key())
        self->go_to_job(*key);
      return 0;
    case kJobsCancelId:
      if (const auto key = chosen_key())
        self->cancel_job(*key);
      return 0;
    case kJobsCloseId:
      DestroyWindow(window);
      return 0;
    case IDOK:
      // Enter in the list opens the chosen session.
      if (const auto key = chosen_key())
        self->go_to_job(*key);
      return 0;
    case IDCANCEL:
      DestroyWindow(window);
      return 0;
    default:
      break;
    }
    break;
  case WM_NOTIFY: {
    const auto* header = reinterpret_cast<const NMHDR*>(lparam);
    if (header->code == NM_CUSTOMDRAW && self->jobs_list_ != nullptr &&
        header->hwndFrom == ListView_GetHeader(self->jobs_list_))
      return self->paint_list_header(header, lparam);
    if (header->hwndFrom == self->jobs_list_) {
      if (header->code == LVN_ITEMCHANGED) {
        self->update_jobs_buttons();
        return 0;
      }
      if (header->code == NM_DBLCLK) {
        if (const auto key = chosen_key())
          self->go_to_job(*key);
        return 0;
      }
    }
    break;
  }
  case WM_CLOSE:
    DestroyWindow(window);
    return 0;
  case WM_DESTROY:
    KillTimer(window, kJobsRefreshTimer);
    self->jobs_window_ = nullptr;
    self->jobs_summary_ = nullptr;
    self->jobs_list_ = nullptr;
    self->jobs_go_ = nullptr;
    self->jobs_cancel_ = nullptr;
    self->jobs_close_ = nullptr;
    self->jobs_shown_.clear();
    return 0;
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
