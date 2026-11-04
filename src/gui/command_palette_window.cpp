// Jump To (Ctrl+K): a page, a tool, a case or a command, found by typing part of its name. The
// matching and the order come from gui_shared/command_palette.hpp, which the Linux edition uses
// too. Enter opens the selected row, Up and Down move through the list, Esc or a click elsewhere
// closes it.
//
// Kept out of app_window.cpp, which is already past 35,000 lines.

#include "app_window.hpp"

#include "command_palette.hpp"

#include "support_assist/strings.hpp"

#include <commctrl.h>
#include <dwmapi.h>

#include <algorithm>
#include <string>
#include <vector>

namespace {

constexpr int kPaletteEditId = 7401;
constexpr int kPaletteListId = 7402;

std::wstring widen(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

std::string narrow_text(const std::wstring& text) {
  return support_assist::utf8_from_wide(text);
}

}  // namespace

// Pages as the sidebar lists them, the tool cards of the Tools catalogue and Log Review, every
// case SAT knows, and the commands.
std::vector<support_assist::gui::PaletteEntry> AppWindow::collect_palette_entries() {
  using support_assist::gui::PaletteEntry;
  using support_assist::gui::PaletteKind;
  std::vector<PaletteEntry> entries;
  palette_cards_.clear();
  const auto page_name = [this](Page page) {
    const auto found = std::find_if(navigation_items_.begin(), navigation_items_.end(),
                                    [&](const auto& item) {
                                      return item.selectable && item.page == page;
                                    });
    return found == navigation_items_.end() ? std::string() : narrow_text(found->label);
  };
  for (const auto& item : navigation_items_) {
    if (!item.selectable || item.section || item.label.empty())
      continue;
    PaletteEntry entry;
    entry.kind = PaletteKind::page;
    entry.title = narrow_text(item.label);
    entry.page = static_cast<int>(item.page);
    entries.push_back(std::move(entry));
  }
  // The Tools category pages, whether or not the Tools group is open in the sidebar.
  if (execution_host_enabled()) {
    for (const auto category : listed_tool_categories()) {
      if (category == support_assist::gui::ToolCategory::last_output)
        continue;
      const int page = static_cast<int>(page_of_category(category));
      const bool listed = std::any_of(entries.begin(), entries.end(), [&](const PaletteEntry& existing) {
        return existing.kind == PaletteKind::page && existing.page == page;
      });
      if (listed)
        continue;
      PaletteEntry entry;
      entry.kind = PaletteKind::page;
      entry.title = std::string(support_assist::gui::tool_category_title(category));
      entry.page = page;
      entries.push_back(std::move(entry));
    }
  }
  for (const Page source : {Page::tools, Page::log_review}) {
    // Every tool in every Tools category.
    for (const auto& card : source == Page::tools ? all_tool_cards() : cards_for_page(source)) {
      // Section headings, cards that only open a page (the page is listed already), the
      // Integrations rows, which belong to their own page, and the quick tools, which are commands.
      if (card.section_header || card.opens_page || card.closes_application || card.quick_tool ||
          card.title.empty() || card.destination == Page::tool_manager)
        continue;
      PaletteEntry entry;
      entry.kind = PaletteKind::tool;
      entry.title = narrow_text(card.title);
      entry.detail = page_name(card.destination);
      entry.keywords = narrow_text(card.badge);
      entry.page = static_cast<int>(card.destination);
      entry.mode = card.mode;
      entry.index = palette_cards_.size();
      palette_cards_.push_back(card);
      entries.push_back(std::move(entry));
    }
  }
  for (std::size_t index = 0; index < cases_.size(); ++index) {
    PaletteEntry entry;
    entry.kind = PaletteKind::case_workspace;
    entry.title = cases_[index].case_id;
    entry.detail = narrow_text(cases_[index].root.wstring());
    entry.keywords = cases_[index].title;
    entry.index = index;
    entries.push_back(std::move(entry));
  }
  for (auto& command : support_assist::gui::palette_commands())
    entries.push_back(std::move(command));
  return entries;
}

void AppWindow::open_palette() {
  if (palette_window_ != nullptr) {
    SetForegroundWindow(palette_window_);
    SetFocus(palette_edit_);
    return;
  }
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.lpfnWndProc = &AppWindow::palette_window_proc;
    description.hInstance = instance_;
    description.lpszClassName = L"SupportAssistPaletteWindow";
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    description.hbrBackground = panel_brush_;
    RegisterClassW(&description);
    registered = true;
  }
  RECT frame{};
  GetWindowRect(window_, &frame);
  const int width = std::min(sx(720), std::max(sx(360), static_cast<int>(frame.right - frame.left) - sx(40)));
  const int height = sx(420);
  const int left = frame.left + ((frame.right - frame.left) - width) / 2;
  const int top = frame.top + sx(90);
  palette_window_ = CreateWindowExW(WS_EX_CONTROLPARENT | WS_EX_TOOLWINDOW,
                                    L"SupportAssistPaletteWindow", L"Jump To",
                                    WS_POPUP | WS_BORDER, left, top, width, height, window_, nullptr,
                                    instance_, this);
  if (palette_window_ == nullptr)
    return;
  palette_edit_ = CreateWindowExW(
      WS_EX_CLIENTEDGE, WC_EDITW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0,
      0, palette_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPaletteEditId)), instance_,
      nullptr);
  SendMessageW(palette_edit_, EM_SETCUEBANNER, TRUE,
               reinterpret_cast<LPARAM>(L"Type part of a page, tool, case or command"));
  SetWindowSubclass(palette_edit_, &AppWindow::palette_edit_proc, 1,
                    reinterpret_cast<DWORD_PTR>(this));
  palette_list_ = CreateWindowExW(
      0, WC_LISTBOXW, L"",
      WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT, 0, 0, 0,
      0, palette_window_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kPaletteListId)), instance_,
      nullptr);
  apply_control_theme(palette_list_);
  palette_hint_ = CreateWindowExW(0, WC_STATICW,
                                  L"Enter opens the selected row. Up and Down move. Esc closes.",
                                  WS_CHILD | WS_VISIBLE | SS_LEFT | SS_NOPREFIX, 0, 0, 0, 0,
                                  palette_window_, nullptr, instance_, nullptr);
  for (HWND control : {palette_edit_, palette_list_})
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
  SendMessageW(palette_hint_, WM_SETFONT, reinterpret_cast<WPARAM>(small_font_), TRUE);

  palette_entries_ = collect_palette_entries();
  layout_palette();
  refresh_palette_matches();
  ShowWindow(palette_window_, SW_SHOW);
  SetForegroundWindow(palette_window_);
  SetFocus(palette_edit_);
}

void AppWindow::layout_palette() {
  if (palette_window_ == nullptr)
    return;
  RECT client{};
  GetClientRect(palette_window_, &client);
  const int margin = sx(10);
  const int edit_height = sx(30);
  const int hint_height = sx(18);
  MoveWindow(palette_edit_, margin, margin, client.right - margin * 2, edit_height, TRUE);
  const int list_top = margin + edit_height + sx(8);
  MoveWindow(palette_list_, margin, list_top, client.right - margin * 2,
             std::max(sx(60), static_cast<int>(client.bottom) - list_top - hint_height - margin * 2),
             TRUE);
  MoveWindow(palette_hint_, margin, client.bottom - margin - hint_height, client.right - margin * 2,
             hint_height, TRUE);
}

void AppWindow::refresh_palette_matches() {
  if (palette_list_ == nullptr)
    return;
  const int length = GetWindowTextLengthW(palette_edit_);
  std::wstring typed(static_cast<std::size_t>(length) + 1U, L'\0');
  GetWindowTextW(palette_edit_, typed.data(), length + 1);
  typed.resize(static_cast<std::size_t>(length));
  palette_shown_ = support_assist::gui::palette_matches(palette_entries_, narrow_text(typed));
  SendMessageW(palette_list_, WM_SETREDRAW, FALSE, 0);
  SendMessageW(palette_list_, LB_RESETCONTENT, 0, 0);
  for (const std::size_t index : palette_shown_) {
    const std::wstring row = widen(support_assist::gui::palette_row_text(palette_entries_[index]));
    SendMessageW(palette_list_, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(row.c_str()));
  }
  if (!palette_shown_.empty())
    SendMessageW(palette_list_, LB_SETCURSEL, 0, 0);
  SendMessageW(palette_list_, WM_SETREDRAW, TRUE, 0);
  InvalidateRect(palette_list_, nullptr, TRUE);
}

void AppWindow::close_palette() {
  if (palette_window_ != nullptr)
    DestroyWindow(palette_window_);
}

// Opens the row: the palette closes first, so whatever the row opens takes the focus.
void AppWindow::run_palette_row(int row) {
  if (row < 0 || static_cast<std::size_t>(row) >= palette_shown_.size())
    return;
  const support_assist::gui::PaletteEntry entry = palette_entries_[palette_shown_[row]];
  const std::vector<Card> cards = palette_cards_;
  close_palette();
  using support_assist::gui::PaletteCommand;
  using support_assist::gui::PaletteKind;
  switch (entry.kind) {
  case PaletteKind::page:
    select_page(static_cast<Page>(entry.page));
    return;
  case PaletteKind::tool: {
    if (entry.index >= cards.size())
      return;
    const Card& card = cards[entry.index];
    // The actions some cards carry instead of a tool, as their own card runs them.
    if (card.destination == Page::home && card.mode == 6) {
      resume_last_case_review();
    } else if (card.destination == Page::home && card.mode == 3) {
      delete_active_case();
    } else if (card.destination == Page::home && card.mode == 7) {
      toggle_workspace_role();
    } else if (card.destination == Page::home && card.mode == 8) {
      prepare_last_execution_artifact();
    } else if (card.destination == Page::home && card.mode == 9) {
      delete_last_execution_artifact();
    } else {
      create_tool_session(card);
    }
    return;
  }
  case PaletteKind::case_workspace:
    if (entry.index < cases_.size()) {
      SendMessageW(active_case_combo_, CB_SETCURSEL, static_cast<WPARAM>(entry.index + 1U), 0);
      activate_case_from_combo();
    }
    return;
  case PaletteKind::command:
    switch (static_cast<PaletteCommand>(entry.index)) {
    case PaletteCommand::running_jobs:
      open_jobs_window();
      return;
    case PaletteCommand::settings:
      open_settings_window();
      return;
    case PaletteCommand::user_guide:
      open_user_guide();
      return;
    case PaletteCommand::reset_panes:
      reset_pane_layout();
      return;
    case PaletteCommand::refresh:
      refresh_entire_gui(true);
      return;
    case PaletteCommand::name_check:
    case PaletteCommand::local_port_checker:
    case PaletteCommand::time_check:
    case PaletteCommand::file_lock_check:
    case PaletteCommand::volume_check:
    case PaletteCommand::service_watch:
    case PaletteCommand::file_transfer_calculator:
      if (const auto tool = support_assist::gui::palette_quick_tool(static_cast<PaletteCommand>(entry.index)))
        open_quick_tool(*tool);
      return;
    }
    return;
  }
}

// Up, Down, Page Up and Page Down in the typing box move through the list.
LRESULT CALLBACK AppWindow::palette_edit_proc(HWND window, UINT message, WPARAM wparam,
                                              LPARAM lparam, UINT_PTR, DWORD_PTR reference) {
  auto* self = reinterpret_cast<AppWindow*>(reference);
  if (message == WM_KEYDOWN && self != nullptr && self->palette_list_ != nullptr) {
    int step = 0;
    if (wparam == VK_DOWN)
      step = 1;
    else if (wparam == VK_UP)
      step = -1;
    else if (wparam == VK_NEXT)
      step = 10;
    else if (wparam == VK_PRIOR)
      step = -10;
    if (step != 0) {
      const int count = static_cast<int>(SendMessageW(self->palette_list_, LB_GETCOUNT, 0, 0));
      if (count > 0) {
        const int current =
            static_cast<int>(SendMessageW(self->palette_list_, LB_GETCURSEL, 0, 0));
        const int next = std::clamp(current < 0 ? 0 : current + step, 0, count - 1);
        SendMessageW(self->palette_list_, LB_SETCURSEL, static_cast<WPARAM>(next), 0);
      }
      return 0;
    }
  }
  if (message == WM_NCDESTROY)
    RemoveWindowSubclass(window, &AppWindow::palette_edit_proc, 1);
  return DefSubclassProc(window, message, wparam, lparam);
}

LRESULT CALLBACK AppWindow::palette_window_proc(HWND window, UINT message, WPARAM wparam,
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
  case WM_CTLCOLOREDIT:
  case WM_CTLCOLORLISTBOX: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    SetTextColor(dc, themed(RGB(236, 244, 240)));
    SetBkMode(dc, OPAQUE);
    SetBkColor(dc, themed(RGB(22, 42, 44)));
    return reinterpret_cast<LRESULT>(self->input_brush_);
  }
  case WM_CTLCOLORSTATIC: {
    const auto dc = reinterpret_cast<HDC>(wparam);
    SetTextColor(dc, themed(RGB(165, 188, 178)));
    SetBkMode(dc, TRANSPARENT);
    return reinterpret_cast<LRESULT>(self->panel_brush_);
  }
  case WM_ACTIVATE:
    // A click anywhere else closes the palette, as a menu closes.
    if (LOWORD(wparam) == WA_INACTIVE)
      PostMessageW(window, WM_CLOSE, 0, 0);
    return 0;
  case WM_COMMAND:
    switch (LOWORD(wparam)) {
    case IDOK:
      self->run_palette_row(
          static_cast<int>(SendMessageW(self->palette_list_, LB_GETCURSEL, 0, 0)));
      return 0;
    case IDCANCEL:
      DestroyWindow(window);
      return 0;
    case kPaletteEditId:
      if (HIWORD(wparam) == EN_CHANGE)
        self->refresh_palette_matches();
      return 0;
    case kPaletteListId:
      if (HIWORD(wparam) == LBN_DBLCLK)
        self->run_palette_row(
            static_cast<int>(SendMessageW(self->palette_list_, LB_GETCURSEL, 0, 0)));
      return 0;
    default:
      break;
    }
    break;
  case WM_CLOSE:
    DestroyWindow(window);
    return 0;
  case WM_DESTROY:
    self->palette_window_ = nullptr;
    self->palette_edit_ = nullptr;
    self->palette_list_ = nullptr;
    self->palette_hint_ = nullptr;
    self->palette_shown_.clear();
    return 0;
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}
