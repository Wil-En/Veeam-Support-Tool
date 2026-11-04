// Remote console: connect, an interactive terminal, and a file pane for moving a file.
//
// Kept in its own translation unit rather than added to app_window.cpp, which is already past
// 25,000 lines and needs /bigobj. The page owns no policy of its own - the capability line and the
// customer-machine guard are described in docs/DESIGN_REMOTE_SECTION.md.

#include "app_window.hpp"

#include <commdlg.h>
#include <uxtheme.h>
#include <windowsx.h>

#include "progress_text.hpp"
#include "remote_listing.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>

namespace {

// The same palette the rest of the application draws with, so the page reads as part of SAT rather
// than as a terminal bolted onto it.
constexpr COLORREF kPanelBackground = RGB(18, 48, 49);
constexpr COLORREF kPanelBorder = RGB(43, 86, 78);
constexpr COLORREF kTerminalBackground = RGB(12, 26, 27);
constexpr COLORREF kTerminalForeground = RGB(220, 228, 224);
constexpr COLORREF kAccent = RGB(101, 205, 175);
constexpr COLORREF kMutedText = RGB(176, 196, 188);

// The 16 ANSI colours, chosen to sit against the dark panel rather than the stock VGA values, which
// look wrong beside the rest of the application.
constexpr std::array<COLORREF, 16> kAnsiPalette{{
    RGB(38, 44, 45),    RGB(224, 108, 117), RGB(140, 214, 158), RGB(229, 192, 123),
    RGB(122, 174, 226), RGB(198, 155, 222), RGB(120, 205, 205), RGB(200, 210, 206),
    RGB(92, 102, 103),  RGB(240, 138, 145), RGB(160, 232, 178), RGB(245, 212, 148),
    RGB(150, 194, 240), RGB(216, 180, 236), RGB(150, 226, 226), RGB(236, 244, 240),
}};

constexpr wchar_t kTerminalClassName[] = L"SupportAssistRemoteTerminal";

// The customer-machine guard, switched off for now.
//
// Turn this to true to re-enable it. Everything it needs is still here and still compiled, so it
// cannot rot while it is off:
//   - Connect asks whether the target is a customer machine.
//   - remote_confirm_write() refuses uploads on one.
//   - remote_send_text()/remote_send_key() refuse terminal input on one.
//
// It is a single switch rather than commented-out blocks precisely so that turning it back on is
// one edit and cannot miss a site.
constexpr bool kCustomerMachineGuardEnabled = false;

// The same helper app_window.cpp uses; it lives in that file's anonymous namespace and so is not
// visible here.
// The same two conversions app_window.cpp declares in its anonymous namespace, expressed in terms
// of the shared core helpers so there is one implementation of the conversion itself.
std::wstring wide(std::string_view value) { return support_assist::wide_from_utf8(value); }
std::string narrow(std::wstring_view value) { return support_assist::utf8_from_wide(value); }

HMENU control_id(int identifier) noexcept {
  return reinterpret_cast<HMENU>(static_cast<INT_PTR>(identifier));
}

AppWindow* owner_from(HWND window) {
  return reinterpret_cast<AppWindow*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

LRESULT CALLBACK terminal_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  AppWindow* owner = owner_from(window);
  switch (message) {
  case WM_PAINT: {
    PAINTSTRUCT paint{};
    const HDC device = BeginPaint(window, &paint);
    RECT client{};
    GetClientRect(window, &client);
    if (owner != nullptr)
      owner->paint_remote_terminal(device, client);
    EndPaint(window, &paint);
    return 0;
  }
  case WM_ERASEBKGND:
    return 1;                       // painted whole in WM_PAINT; erasing first only flickers
  case WM_GETDLGCODE:
    // Take every key, including Tab and Return, or the dialog manager eats them before the remote
    // shell ever sees them.
    return DLGC_WANTALLKEYS | DLGC_WANTCHARS | DLGC_WANTARROWS | DLGC_WANTTAB;
  case WM_LBUTTONDOWN:
    SetFocus(window);
    if (owner != nullptr) {
      SetCapture(window);
      owner->remote_terminal_mouse_down(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
    }
    return 0;
  case WM_MOUSEMOVE:
    if (owner != nullptr && (wparam & MK_LBUTTON) != 0)
      owner->remote_terminal_mouse_move(GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam));
    return 0;
  case WM_LBUTTONUP:
    if (GetCapture() == window)
      ReleaseCapture();
    if (owner != nullptr)
      owner->remote_terminal_mouse_up();
    return 0;
  case WM_RBUTTONUP:
    if (owner != nullptr) {
      POINT point{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)};
      ClientToScreen(window, &point);
      owner->remote_show_terminal_menu(point.x, point.y);
    }
    return 0;
  case WM_MOUSEWHEEL:
    if (owner != nullptr) {
      // Three rows per notch, the usual Windows step. Scrolling back does not disturb the session:
      // the screen model is untouched and any new output still arrives underneath.
      const int notches = GET_WHEEL_DELTA_WPARAM(wparam) / WHEEL_DELTA;
      owner->remote_scroll_by(notches * 3);
    }
    return 0;
  case WM_KEYUP:
    return 0;
  case WM_SETFOCUS:
  case WM_KILLFOCUS:
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_KEYDOWN:
    if (owner != nullptr) {
      owner->remote_send_key(wparam, (GetKeyState(VK_CONTROL) & 0x8000) != 0,
                             (GetKeyState(VK_SHIFT) & 0x8000) != 0);
    }
    return 0;
  case WM_SYSKEYDOWN:
    // F10 arrives as a system key, which would otherwise open the menu bar.
    if (wparam == VK_F10 && owner != nullptr) {
      owner->remote_send_key(wparam, (GetKeyState(VK_CONTROL) & 0x8000) != 0,
                             (GetKeyState(VK_SHIFT) & 0x8000) != 0);
      return 0;
    }
    break;
  case WM_CHAR:
    if (owner != nullptr) {
      const wchar_t character = static_cast<wchar_t>(wparam);
      // Control characters arrive through WM_KEYDOWN, which knows which key produced them.
      if (character >= 0x20 || character == 0x0D || character == 0x09 || character == 0x08)
        owner->remote_send_text(std::wstring_view(&character, 1));
    }
    return 0;
  case WM_SIZE:
    if (owner != nullptr)
      owner->remote_recompute_geometry();
    return 0;
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

void ensure_terminal_class(HINSTANCE instance) {
  static bool registered = false;
  if (registered)
    return;
  WNDCLASSEXW description{};
  description.cbSize = sizeof(description);
  description.style = CS_HREDRAW | CS_VREDRAW;
  description.lpfnWndProc = terminal_proc;
  description.hInstance = instance;
  description.hCursor = LoadCursorW(nullptr, IDC_IBEAM);
  description.hbrBackground = nullptr;
  description.lpszClassName = kTerminalClassName;
  RegisterClassExW(&description);
  registered = true;
}

// Enter in the remote path box lists that path.
//
// An edit control does not report Return through WM_COMMAND, so without this the box accepts typing
// and then does nothing at all - which reads as the connection being broken rather than the key
// being unhandled.
LRESULT CALLBACK remote_path_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                  UINT_PTR /*id*/, DWORD_PTR reference) {
  if (message == WM_KEYDOWN && wparam == VK_RETURN) {
    if (auto* owner = reinterpret_cast<AppWindow*>(reference); owner != nullptr) {
      owner->remote_refresh_files();
      return 0;
    }
  }
  if (message == WM_CHAR && wparam == VK_RETURN)
    return 0;                       // swallow the beep the control would otherwise make
  if (message == WM_GETDLGCODE)
    return DefSubclassProc(window, message, wparam, lparam) | DLGC_WANTALLKEYS;
  if (message == WM_NCDESTROY)
    RemoveWindowSubclass(window, remote_path_proc, 1);
  return DefSubclassProc(window, message, wparam, lparam);
}

std::filesystem::path prompt_for_existing_file(HWND owner) {
  wchar_t chosen[MAX_PATH]{};
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = owner;
  dialog.lpstrFilter = L"All files\0*.*\0";
  dialog.lpstrFile = chosen;
  dialog.nMaxFile = static_cast<DWORD>(std::size(chosen));
  dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  if (GetOpenFileNameW(&dialog) == FALSE)
    return {};
  return std::filesystem::path(chosen);
}

// `folder`, when given, is where the dialog opens: the open case's logs folder for a download.
std::filesystem::path prompt_for_save_file(HWND owner, const std::wstring& suggested,
                                           const std::filesystem::path& folder) {
  wchar_t chosen[MAX_PATH]{};
  wcsncpy_s(chosen, suggested.c_str(), _TRUNCATE);
  const std::wstring initial = folder.wstring();
  OPENFILENAMEW dialog{};
  dialog.lStructSize = sizeof(dialog);
  dialog.hwndOwner = owner;
  dialog.lpstrFilter = L"All files\0*.*\0";
  dialog.lpstrFile = chosen;
  dialog.nMaxFile = static_cast<DWORD>(std::size(chosen));
  dialog.lpstrInitialDir = initial.empty() ? nullptr : initial.c_str();
  dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
  if (GetSaveFileNameW(&dialog) == FALSE)
    return {};
  return std::filesystem::path(chosen);
}

std::string narrow_utf8(std::wstring_view text) {
  if (text.empty())
    return {};
  const int size = WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0, nullptr, nullptr);
  std::string output(static_cast<std::size_t>(size), '\0');
  WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), output.data(), size,
                      nullptr, nullptr);
  return output;
}

} // namespace

void AppWindow::create_remote_controls() {
  ensure_terminal_class(instance_);

  const auto label = [&](const wchar_t* text) {
    HWND control = CreateWindowExW(0, WC_STATICW, text, WS_CHILD | SS_LEFT, 0, 0, 0, 0, window_,
                                   nullptr, instance_, nullptr);
    remote_labels_.push_back(control);
    return control;
  };

  label(L"Host");
  // Editable combobox: type a host, or pick a saved favourite lab address from the dropdown
  // (managed in Settings > SSH Addresses). Favourites carry the address only; credentials are typed.
  remote_host_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_COMBOBOXW, L"",
      WS_CHILD | WS_TABSTOP | CBS_DROPDOWN | CBS_AUTOHSCROLL | WS_VSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemoteHostId), instance_, nullptr);
  label(L"Port");
  remote_port_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"22",
      WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL | ES_NUMBER, 0, 0, 0, 0, window_,
      control_id(kRemotePortId), instance_, nullptr);
  label(L"User");
  remote_user_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
      WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemoteUserId), instance_, nullptr);
  remote_password_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
      WS_CHILD | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemotePasswordId), instance_, nullptr);
  set_edit_cue(remote_password_, L"Password (session only)");
  // The second row: a private key file, Browse, and the key's passphrase when it has one. A key
  // protected by a passphrase is the usual kind, and without the field it could not be used.
  label(L"Key");
  remote_key_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
      WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemoteKeyId), instance_, nullptr);
  set_edit_cue(remote_key_, L"Private key file (optional; used instead of the password)");
  remote_key_browse_ = CreateWindowExW(0, WC_BUTTONW, L"Browse", WS_CHILD | WS_TABSTOP | BS_OWNERDRAW,
      0, 0, 0, 0, window_, control_id(kRemoteKeyBrowseId), instance_, nullptr);
  remote_key_passphrase_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
      WS_CHILD | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemoteKeyPassphraseId), instance_, nullptr);
  set_edit_cue(remote_key_passphrase_, L"Key passphrase (if the key has one)");

  remote_connect_button_ = CreateWindowExW(0, WC_BUTTONW, L"Connect", WS_CHILD | BS_OWNERDRAW,
      0, 0, 0, 0, window_, control_id(kRemoteConnectId), instance_, nullptr);
  remote_disconnect_button_ = CreateWindowExW(0, WC_BUTTONW, L"Disconnect", WS_CHILD | BS_OWNERDRAW,
      0, 0, 0, 0, window_, control_id(kRemoteDisconnectId), instance_, nullptr);

  remote_terminal_ = CreateWindowExW(0, kTerminalClassName, L"",
      WS_CHILD | WS_TABSTOP | WS_CLIPCHILDREN, 0, 0, 0, 0, window_, nullptr, instance_, nullptr);
  SetWindowLongPtrW(remote_terminal_, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));

  remote_path_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"/var/log/VeeamBackup",
      WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, window_,
      control_id(kRemotePathId), instance_, nullptr);
  SetWindowSubclass(remote_path_, remote_path_proc, 1, reinterpret_cast<DWORD_PTR>(this));
  remote_files_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
      WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, 0, 0, 0, 0, window_,
      control_id(kRemoteFilesId), instance_, nullptr);
  ListView_SetExtendedListViewStyle(remote_files_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
  apply_control_theme(remote_files_);
  // The dark theme alone leaves the list white; every other list in the application sets these
  // three explicitly and this one must match or the page reads as a foreign control.
  ListView_SetBkColor(remote_files_, themed(RGB(13, 31, 33)));
  ListView_SetTextBkColor(remote_files_, themed(RGB(13, 31, 33)));
  ListView_SetTextColor(remote_files_, themed(RGB(225, 236, 231)));
  {
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH;
    // Name and Size fit the pane at its starting width; Modified is beside them when the divider
    // gives the pane more room.
    column.pszText = const_cast<wchar_t*>(L"Name");
    column.cx = 160;
    ListView_InsertColumn(remote_files_, 0, &column);
    column.pszText = const_cast<wchar_t*>(L"Size");
    column.cx = 70;
    ListView_InsertColumn(remote_files_, 1, &column);
    column.pszText = const_cast<wchar_t*>(L"Modified");
    column.cx = 160;
    ListView_InsertColumn(remote_files_, 2, &column);
  }

  remote_download_ = CreateWindowExW(0, WC_BUTTONW, L"Download", WS_CHILD | BS_OWNERDRAW,
      0, 0, 0, 0, window_, control_id(kRemoteDownloadId), instance_, nullptr);
  remote_upload_ = CreateWindowExW(0, WC_BUTTONW, L"Upload", WS_CHILD | BS_OWNERDRAW,
      0, 0, 0, 0, window_, control_id(kRemoteUploadId), instance_, nullptr);

  remote_status_ = CreateWindowExW(0, WC_STATICW,
      L"Not connected.",
      WS_CHILD | SS_LEFT | SS_ENDELLIPSIS, 0, 0, 0, 0, window_, nullptr, instance_, nullptr);

  // A fixed-pitch face, because a terminal grid that is not fixed pitch is not a terminal. Consolas
  // ships with Windows; the fallback keeps the page usable if it has been removed.
  remote_terminal_font_ = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                      OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                      FIXED_PITCH | FF_MODERN, L"Consolas");
  if (remote_terminal_font_ == nullptr) {
    remote_terminal_font_ = CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                        DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                                        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, nullptr);
  }

  for (HWND control : {remote_host_, remote_port_, remote_user_, remote_password_, remote_key_,
                       remote_key_passphrase_, remote_key_browse_, remote_path_})
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
  for (HWND control : remote_labels_)
    SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(small_font_), TRUE);
  SendMessageW(remote_status_, WM_SETFONT, reinterpret_cast<WPARAM>(small_font_), TRUE);
  SendMessageW(remote_files_, WM_SETFONT, reinterpret_cast<WPARAM>(ui_font_), TRUE);
  SendMessageW(remote_terminal_, WM_SETFONT, reinterpret_cast<WPARAM>(remote_terminal_font_), TRUE);
}

// The terminal's fixed-pitch font is not one of the six AppWindow fonts, so Text scale has to
// rebuild it separately or the terminal is the one pane that ignores the setting. -15 is the
// shipped 100% height; the cell grid is recomputed from the new metrics.
void AppWindow::rescale_remote_terminal_font() {
  if (remote_terminal_ == nullptr)
    return;
  const HFONT previous = remote_terminal_font_;
  const int height = -std::max(8, MulDiv(15, ui_scale_percent_, 100));
  HFONT rebuilt = CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                              OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                              FIXED_PITCH | FF_MODERN, L"Consolas");
  if (rebuilt == nullptr) {
    rebuilt = CreateFontW(height, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                          OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                          FIXED_PITCH | FF_MODERN, nullptr);
  }
  if (rebuilt == nullptr)
    return;
  remote_terminal_font_ = rebuilt;
  SendMessageW(remote_terminal_, WM_SETFONT, reinterpret_cast<WPARAM>(remote_terminal_font_), TRUE);
  if (previous != nullptr)
    DeleteObject(previous);
  remote_recompute_geometry();
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::populate_remote_favourites() {
  if (remote_host_ == nullptr)
    return;
  // Refilling the list leaves the edit text untouched, but capture and restore it anyway so a
  // half-typed host survives navigating away and back.
  const std::wstring typed = control_text(remote_host_);
  SendMessageW(remote_host_, CB_RESETCONTENT, 0, 0);
  for (const auto& address : load_ssh_addresses())
    SendMessageW(remote_host_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(address.c_str()));
  SetWindowTextW(remote_host_, typed.c_str());
}

void AppWindow::show_remote_controls(bool visible) {
  const int command = visible ? SW_SHOW : SW_HIDE;
  if (visible)
    populate_remote_favourites();
  for (HWND control : {remote_host_, remote_port_, remote_user_, remote_password_, remote_key_,
                       remote_key_browse_, remote_key_passphrase_,
                       remote_connect_button_, remote_disconnect_button_, remote_terminal_,
                       remote_files_, remote_path_, remote_download_, remote_upload_,
                       remote_status_}) {
    if (control != nullptr)
      ShowWindow(control, command);
  }
  for (HWND control : remote_labels_)
    ShowWindow(control, command);
}

void AppWindow::layout_remote(int content_left, int content_top, int content_width,
                              int content_height) {
  const int row_height = 26;
  const int gap = 8;

  // Connection rows: host, port, user and password, then the two buttons; below them the private
  // key file, Browse and the key's passphrase.
  int x = content_left;
  const int label_width = 40;
  const int top = content_top;
  MoveWindow(remote_labels_[0], x, top + 5, label_width, 18, TRUE);
  x += label_width;
  const int host_width = std::max(140, content_width / 7);
  // For a combobox the height parameter caps the dropped-down list; give the favourites room.
  MoveWindow(remote_host_, x, top, host_width, row_height + 200, TRUE);
  x += host_width + gap;
  MoveWindow(remote_labels_[1], x, top + 5, label_width, 18, TRUE);
  x += label_width;
  MoveWindow(remote_port_, x, top, 60, row_height, TRUE);
  x += 60 + gap;
  MoveWindow(remote_labels_[2], x, top + 5, label_width, 18, TRUE);
  x += label_width;
  const int user_width = std::max(110, content_width / 8);
  MoveWindow(remote_user_, x, top, user_width, row_height, TRUE);
  x += user_width + gap;
  const int buttons_left = content_left + content_width - 240;
  MoveWindow(remote_password_, x, top, std::max(150, buttons_left - gap - x), row_height, TRUE);

  MoveWindow(remote_connect_button_, buttons_left, top, 110, row_height, TRUE);
  MoveWindow(remote_disconnect_button_, content_left + content_width - 122, top, 122, row_height,
             TRUE);

  const int key_top = top + row_height + 8;
  MoveWindow(remote_labels_[3], content_left, key_top + 5, label_width, 18, TRUE);
  const int browse_width = 84;
  const int passphrase_width = std::max(200, content_width / 4);
  const int key_width =
      std::max(160, content_width - label_width - browse_width - passphrase_width - gap * 2);
  x = content_left + label_width;
  MoveWindow(remote_key_, x, key_top, key_width, row_height, TRUE);
  x += key_width + gap;
  MoveWindow(remote_key_browse_, x, key_top, browse_width, row_height, TRUE);
  x += browse_width + gap;
  MoveWindow(remote_key_passphrase_, x, key_top, passphrase_width, row_height, TRUE);

  const int body_top = key_top + row_height + 14;
  const int status_height = 20;
  const int body_height = content_height - (body_top - content_top) - status_height - 6;

  // A draggable divider between the file pane and the terminal, kept between sessions like the
  // other pages' dividers. The terminal is what the page is for, so it starts with most of the room.
  const auto columns = place_split(SplitId::remote_columns, content_left, content_width, body_top,
                                   body_height, 12);
  const int files_width = columns[0].size;
  MoveWindow(remote_path_, content_left, body_top, files_width, row_height, TRUE);
  const int button_row = body_top + body_height - row_height;
  MoveWindow(remote_files_, content_left, body_top + row_height + 6, files_width,
             body_height - row_height * 2 - 12, TRUE);
  MoveWindow(remote_download_, content_left, button_row, files_width / 2 - 4, row_height, TRUE);
  MoveWindow(remote_upload_, content_left + files_width / 2 + 4, button_row, files_width / 2 - 4,
             row_height, TRUE);

  MoveWindow(remote_terminal_, columns[1].start, body_top, columns[1].size, body_height, TRUE);

  MoveWindow(remote_status_, content_left, content_top + content_height - status_height,
             content_width, status_height, TRUE);

  remote_recompute_geometry();
}

void AppWindow::remote_recompute_geometry() {
  if (remote_terminal_ == nullptr)
    return;
  RECT client{};
  GetClientRect(remote_terminal_, &client);

  // Measure the cell once from the font rather than assuming, or the grid drifts from the glyphs
  // and long lines wrap in the wrong place.
  const HDC device = GetDC(remote_terminal_);
  const HGDIOBJ previous = SelectObject(device, remote_terminal_font_);
  TEXTMETRICW metrics{};
  GetTextMetricsW(device, &metrics);
  SIZE size{};
  GetTextExtentPoint32W(device, L"0", 1, &size);
  SelectObject(device, previous);
  ReleaseDC(remote_terminal_, device);

  remote_cell_width_ = static_cast<int>(std::max<LONG>(1, size.cx));
  remote_cell_height_ = static_cast<int>(std::max<LONG>(1, metrics.tmHeight));

  const int padding = 6;
  const int columns = std::max(20, static_cast<int>(client.right - client.left - padding * 2) / remote_cell_width_);
  const int rows = std::max(5, static_cast<int>(client.bottom - client.top - padding * 2) / remote_cell_height_);

  if (remote_screen_ == nullptr) {
    remote_screen_ = std::make_unique<support_assist::TerminalScreen>(columns, rows);
  } else if (remote_screen_->columns() != columns || remote_screen_->rows() != rows) {
    remote_screen_->resize(columns, rows);
    // resize() re-indexes the retained rows, so selection coordinates no longer point at the text
    // they were taken from - same reason remote_scroll_by() and remote_pump() clear it.
    remote_has_selection_ = false;
    remote_selecting_ = false;
    if (remote_shell_)
      static_cast<void>(support_assist::ssh_shell_resize(*remote_shell_, columns, rows));
  }
}

void AppWindow::paint_remote_terminal(HDC device, const RECT& area) {
  // Draw into a memory bitmap and blit once. A terminal repaints on every burst of output, and
  // painting cell by cell straight to the screen flickers badly.
  const int width = area.right - area.left;
  const int height = area.bottom - area.top;
  const HDC memory = CreateCompatibleDC(device);
  const HBITMAP bitmap = CreateCompatibleBitmap(device, width, height);
  const HGDIOBJ old_bitmap = SelectObject(memory, bitmap);

  HBRUSH background = CreateSolidBrush(kTerminalBackground);
  RECT full{0, 0, width, height};
  FillRect(memory, &full, background);
  DeleteObject(background);

  // A rounded border, so the terminal reads as one of the application's panels rather than a raw
  // console pasted into the page.
  HBRUSH panel = CreateSolidBrush(kTerminalBackground);
  HPEN border = CreatePen(PS_SOLID, 1, GetFocus() == remote_terminal_ ? kAccent : kPanelBorder);
  const HGDIOBJ old_brush = SelectObject(memory, panel);
  const HGDIOBJ old_pen = SelectObject(memory, border);
  RoundRect(memory, 0, 0, width, height, 10, 10);
  SelectObject(memory, old_brush);
  SelectObject(memory, old_pen);
  DeleteObject(panel);
  DeleteObject(border);

  SetBkMode(memory, TRANSPARENT);
  const HGDIOBJ old_font = SelectObject(memory, remote_terminal_font_);

  if (remote_screen_ != nullptr) {
    const int padding = 6;
    std::wstring run;

    // Resolve a visible row through the scrollback.
    //
    // With no offset this is just the live screen. Scrolled back, the top rows come from history
    // instead: TerminalScreen keeps up to 5,000 rows, so anything that scrolled past the top is
    // retained and reachable here.
    const auto& history = remote_screen_->scrollback();
    const int history_rows = static_cast<int>(history.size());
    const int offset = std::clamp(remote_scroll_offset_, 0, history_rows);
    static const support_assist::TerminalCell blank{};
    const auto cell_at = [&](int row, int column) -> const support_assist::TerminalCell& {
      const int index = row - offset;
      if (index >= 0)
        return remote_screen_->cell(index, column);
      const int history_index = history_rows + index;
      if (history_index < 0 || history_index >= history_rows)
        return blank;
      const auto& line = history[static_cast<std::size_t>(history_index)];
      if (column < 0 || column >= static_cast<int>(line.size()))
        return blank;
      return line[static_cast<std::size_t>(column)];
    };

    for (int row = 0; row < remote_screen_->rows(); ++row) {
      int column = 0;
      while (column < remote_screen_->columns()) {
        const support_assist::TerminalCell& first = cell_at(row, column);
        const bool first_selected = remote_cell_selected(row, column);
        run.clear();
        int span = 0;
        // Gather a run of cells sharing attributes (and selection state) and draw them in one call.
        while (column + span < remote_screen_->columns()) {
          const support_assist::TerminalCell& cell = cell_at(row, column + span);
          if (cell.foreground != first.foreground || cell.background != first.background ||
              cell.bold != first.bold || cell.inverse != first.inverse ||
              cell.underline != first.underline ||
              remote_cell_selected(row, column + span) != first_selected) {
            break;
          }
          run.push_back(cell.glyph < 0x10000 ? static_cast<wchar_t>(cell.glyph) : L'?');
          ++span;
        }
        if (span == 0)
          break;

        COLORREF foreground = first.foreground >= 0
                                  ? kAnsiPalette[static_cast<std::size_t>(first.foreground)]
                                  : kTerminalForeground;
        COLORREF cell_background = first.background >= 0
                                       ? kAnsiPalette[static_cast<std::size_t>(first.background)]
                                       : kTerminalBackground;
        if (first.inverse)
          std::swap(foreground, cell_background);
        if (first_selected) {
          cell_background = RGB(52, 84, 110);
          foreground = RGB(236, 244, 240);
        }

        const int x = padding + column * remote_cell_width_;
        const int y = padding + row * remote_cell_height_;
        if (cell_background != kTerminalBackground) {
          RECT fill{x, y, x + span * remote_cell_width_, y + remote_cell_height_};
          HBRUSH brush = CreateSolidBrush(cell_background);
          FillRect(memory, &fill, brush);
          DeleteObject(brush);
        }
        SetTextColor(memory, foreground);
        ExtTextOutW(memory, x, y, 0, nullptr, run.c_str(), static_cast<UINT>(run.size()), nullptr);
        if (first.underline) {
          RECT rule{x, y + remote_cell_height_ - 1, x + span * remote_cell_width_,
                    y + remote_cell_height_};
          HBRUSH brush = CreateSolidBrush(foreground);
          FillRect(memory, &rule, brush);
          DeleteObject(brush);
        }
        column += span;
      }
    }

    if (remote_screen_->cursor_visible() && remote_connected_) {
      const int x = 6 + remote_screen_->cursor_column() * remote_cell_width_;
      const int y = 6 + remote_screen_->cursor_row() * remote_cell_height_;
      RECT caret{x, y, x + remote_cell_width_, y + remote_cell_height_};
      HBRUSH brush = CreateSolidBrush(kAccent);
      FillRect(memory, &caret, brush);
      DeleteObject(brush);
    }
  }

  if (!remote_connected_) {
    SelectObject(memory, small_font_);
    std::wstring hint_text = L"Not connected.";
    if (!remote_progress_.empty()) {
      // While connecting, the narrative replaces the standing hint. It disappears the moment the
      // shell has the screen, which is what makes it a progress report rather than clutter. The
      // same lines stay on the status line at the bottom, so nothing is lost when it goes.
      hint_text.clear();
      for (const std::wstring& line : remote_progress_)
        hint_text += line + L"\n";
    }
    SetTextColor(memory, remote_progress_.empty() ? kMutedText : RGB(233, 196, 106));
    RECT hint{16, 16, width - 16, height - 16};
    DrawTextW(memory, hint_text.c_str(), -1, &hint, DT_LEFT | DT_WORDBREAK | DT_NOPREFIX);
  }

  SelectObject(memory, old_font);
  BitBlt(device, area.left, area.top, width, height, memory, 0, 0, SRCCOPY);
  SelectObject(memory, old_bitmap);
  DeleteObject(bitmap);
  DeleteDC(memory);
}

namespace {
constexpr int kTerminalPadding = 6;
constexpr int kRemoteMenuCopy = 1;
constexpr int kRemoteMenuPaste = 2;
constexpr int kRemoteMenuSelectAll = 3;
}  // namespace

bool AppWindow::remote_point_to_cell(int x, int y, int& row, int& col) const {
  if (remote_screen_ == nullptr)
    return false;
  row = std::clamp((y - kTerminalPadding) / std::max(1, remote_cell_height_), 0,
                   remote_screen_->rows() - 1);
  col = std::clamp((x - kTerminalPadding) / std::max(1, remote_cell_width_), 0,
                   remote_screen_->columns());
  return true;
}

// One visible cell's glyph, resolved through the scrollback exactly as the paint loop does, so a
// copied region matches what is on screen.
wchar_t AppWindow::remote_visible_glyph(int visible_row, int col) const {
  if (remote_screen_ == nullptr)
    return L' ';
  const auto& history = remote_screen_->scrollback();
  const int history_rows = static_cast<int>(history.size());
  const int offset = std::clamp(remote_scroll_offset_, 0, history_rows);
  const int index = visible_row - offset;
  char32_t glyph = U' ';
  if (index >= 0) {
    if (index < remote_screen_->rows() && col >= 0 && col < remote_screen_->columns())
      glyph = remote_screen_->cell(index, col).glyph;
  } else {
    const int history_index = history_rows + index;
    if (history_index >= 0 && history_index < history_rows) {
      const auto& line = history[static_cast<std::size_t>(history_index)];
      if (col >= 0 && col < static_cast<int>(line.size()))
        glyph = line[static_cast<std::size_t>(col)].glyph;
    }
  }
  return glyph < 0x10000 ? static_cast<wchar_t>(glyph) : L'?';
}

bool AppWindow::remote_cell_selected(int row, int col) const {
  if (!remote_has_selection_)
    return false;
  int top_row = remote_sel_anchor_row_, top_col = remote_sel_anchor_col_;
  int bot_row = remote_sel_row_, bot_col = remote_sel_col_;
  if (bot_row < top_row || (bot_row == top_row && bot_col < top_col)) {
    std::swap(top_row, bot_row);
    std::swap(top_col, bot_col);
  }
  if (row < top_row || row > bot_row)
    return false;
  if (top_row == bot_row)
    return col >= top_col && col < bot_col;
  if (row == top_row)
    return col >= top_col;
  if (row == bot_row)
    return col < bot_col;
  return true;
}

void AppWindow::remote_terminal_mouse_down(int x, int y) {
  int row = 0, col = 0;
  if (!remote_point_to_cell(x, y, row, col))
    return;
  remote_selecting_ = true;
  remote_has_selection_ = false;
  remote_sel_anchor_row_ = row;
  remote_sel_anchor_col_ = col;
  remote_sel_row_ = row;
  remote_sel_col_ = col;
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_terminal_mouse_move(int x, int y) {
  if (!remote_selecting_)
    return;
  int row = 0, col = 0;
  if (!remote_point_to_cell(x, y, row, col))
    return;
  remote_sel_row_ = row;
  remote_sel_col_ = col;
  remote_has_selection_ = (row != remote_sel_anchor_row_ || col != remote_sel_anchor_col_);
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_terminal_mouse_up() { remote_selecting_ = false; }

void AppWindow::remote_select_all() {
  if (remote_screen_ == nullptr)
    return;
  remote_sel_anchor_row_ = 0;
  remote_sel_anchor_col_ = 0;
  remote_sel_row_ = remote_screen_->rows() - 1;
  remote_sel_col_ = remote_screen_->columns();
  remote_has_selection_ = true;
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_copy_selection() {
  if (!remote_has_selection_ || remote_screen_ == nullptr)
    return;
  int top_row = remote_sel_anchor_row_, top_col = remote_sel_anchor_col_;
  int bot_row = remote_sel_row_, bot_col = remote_sel_col_;
  if (bot_row < top_row || (bot_row == top_row && bot_col < top_col)) {
    std::swap(top_row, bot_row);
    std::swap(top_col, bot_col);
  }
  std::wstring text;
  for (int row = top_row; row <= bot_row; ++row) {
    const int start = (row == top_row) ? top_col : 0;
    const int end = (row == bot_row) ? bot_col : remote_screen_->columns();
    std::wstring line;
    for (int col = start; col < end; ++col)
      line.push_back(remote_visible_glyph(row, col));
    while (!line.empty() && line.back() == L' ')
      line.pop_back();
    text += line;
    if (row != bot_row)
      text += L"\r\n";
  }
  if (text.empty() || !OpenClipboard(remote_terminal_))
    return;
  EmptyClipboard();
  const std::size_t bytes = (text.size() + 1) * sizeof(wchar_t);
  if (HGLOBAL handle = GlobalAlloc(GMEM_MOVEABLE, bytes)) {
    if (void* memory = GlobalLock(handle)) {
      std::memcpy(memory, text.c_str(), bytes);
      GlobalUnlock(handle);
      SetClipboardData(CF_UNICODETEXT, handle);
    } else {
      GlobalFree(handle);
    }
  }
  CloseClipboard();
  remote_note(L"Copied the selection to the clipboard.");
}

void AppWindow::remote_paste_clipboard() {
  if (!remote_shell_ || !remote_connected_)
    return;
  if (!OpenClipboard(remote_terminal_))
    return;
  std::wstring text;
  if (HANDLE handle = GetClipboardData(CF_UNICODETEXT)) {
    if (const wchar_t* data = static_cast<const wchar_t*>(GlobalLock(handle))) {
      text = data;
      GlobalUnlock(handle);
    }
  }
  CloseClipboard();
  if (text.empty())
    return;
  // A PTY expects CR for Enter; collapse CRLF/LF to a single CR so a pasted multi-line block runs.
  std::wstring normalised;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == L'\r') {
      normalised.push_back(L'\r');
      if (i + 1 < text.size() && text[i + 1] == L'\n')
        ++i;
    } else if (text[i] == L'\n') {
      normalised.push_back(L'\r');
    } else {
      normalised.push_back(text[i]);
    }
  }
  if (!support_assist::ssh_shell_write(*remote_shell_, narrow(normalised)).ok())
    remote_disconnect(L"The remote shell stopped accepting input.");
}

void AppWindow::remote_show_terminal_menu(int screen_x, int screen_y) {
  HMENU menu = CreatePopupMenu();
  if (menu == nullptr)
    return;
  AppendMenuW(menu, MF_STRING | (remote_has_selection_ ? 0U : static_cast<UINT>(MF_GRAYED)),
              kRemoteMenuCopy, L"Copy\tCtrl+Shift+C");
  AppendMenuW(menu,
              MF_STRING |
                  ((remote_shell_ && remote_connected_) ? 0U : static_cast<UINT>(MF_GRAYED)),
              kRemoteMenuPaste, L"Paste\tCtrl+Shift+V");
  AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
  AppendMenuW(menu, MF_STRING, kRemoteMenuSelectAll, L"Select All");
  const int chosen = static_cast<int>(TrackPopupMenu(
      menu, TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN, screen_x, screen_y, 0, remote_terminal_,
      nullptr));
  DestroyMenu(menu);
  if (chosen == kRemoteMenuCopy)
    remote_copy_selection();
  else if (chosen == kRemoteMenuPaste)
    remote_paste_clipboard();
  else if (chosen == kRemoteMenuSelectAll)
    remote_select_all();
}

void AppWindow::remote_note(const std::wstring& text) {
  set_control_text(remote_status_, text);
  // Keep the running account for the console area, and keep it short - this is a connection
  // narrative, not a log.
  remote_progress_.push_back(text);
  if (remote_progress_.size() > 12U)
    remote_progress_.erase(remote_progress_.begin());
  if (remote_terminal_ != nullptr)
    InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_send_text(std::wstring_view text) {
  // Typing returns to the live bottom. Typing into a view that is scrolled back would put
  // the engineer's own keystrokes somewhere they cannot see them.
  if (remote_scroll_offset_ != 0)
    remote_scroll_by(-remote_scroll_offset_);
  if (!remote_shell_ || !remote_connected_)
    return;
  // Read only means the terminal does not accept typing either. Blocking uploads while leaving a
  // shell prompt live would be a guard in name only.
  if constexpr (kCustomerMachineGuardEnabled) {
    if (remote_customer_machine_)
      return;
  }
  const std::string bytes = narrow_utf8(text);
  if (bytes.empty())
    return;
  if (!support_assist::ssh_shell_write(*remote_shell_, bytes).ok())
    remote_disconnect(L"The remote shell stopped accepting input.");
}

void AppWindow::remote_send_key(WPARAM key, bool control_down, bool shift_down) {
  // Clipboard first, so plain Ctrl+C stays the terminal interrupt. Copy works even when
  // disconnected, to grab output that is still on screen.
  if (control_down && shift_down && (key == 'C' || key == 'V')) {
    if (key == 'C')
      remote_copy_selection();
    else
      remote_paste_clipboard();
    return;
  }
  if (shift_down && key == VK_INSERT) {
    remote_paste_clipboard();
    return;
  }
  // Typing returns to the live bottom. Typing into a view that is scrolled back would put
  // the engineer's own keystrokes somewhere they cannot see them.
  if (remote_scroll_offset_ != 0)
    remote_scroll_by(-remote_scroll_offset_);
  if (!remote_shell_ || !remote_connected_)
    return;
  if constexpr (kCustomerMachineGuardEnabled) {
    if (remote_customer_machine_)
      return;
  }
  std::string sequence;
  switch (key) {
  case VK_UP: sequence = "\x1b[A"; break;
  case VK_DOWN: sequence = "\x1b[B"; break;
  case VK_RIGHT: sequence = "\x1b[C"; break;
  case VK_LEFT: sequence = "\x1b[D"; break;
  case VK_HOME: sequence = "\x1b[H"; break;
  case VK_END: sequence = "\x1b[F"; break;
  case VK_PRIOR: sequence = "\x1b[5~"; break;
  case VK_NEXT: sequence = "\x1b[6~"; break;
  case VK_DELETE: sequence = "\x1b[3~"; break;
  case VK_ESCAPE: sequence = "\x1b"; break;
  default:
    // F1 to F12 as xterm sends them. Ctrl+letter is the control character. Ctrl+C interrupting a
    // runaway command is the single most important key on this page.
    if (key >= VK_F1 && key <= VK_F12)
      sequence = support_assist::gui::function_key_sequence(static_cast<int>(key - VK_F1) + 1);
    else if (control_down && key >= 'A' && key <= 'Z')
      sequence.push_back(static_cast<char>(key - 'A' + 1));
    break;
  }
  static_cast<void>(shift_down);
  if (sequence.empty())
    return;
  if (!support_assist::ssh_shell_write(*remote_shell_, sequence).ok())
    remote_disconnect(L"The remote shell stopped accepting input.");
}

void AppWindow::remote_scroll_by(int rows) {
  if (remote_screen_ == nullptr)
    return;
  const int history = static_cast<int>(remote_screen_->scrollback().size());
  const int wanted = std::clamp(remote_scroll_offset_ + rows, 0, history);
  if (wanted == remote_scroll_offset_)
    return;
  remote_scroll_offset_ = wanted;
  // The selection is held in visible-row space, so scrolling would leave the highlight - and Copy -
  // pointing at whatever scrolled into those rows instead of what was selected.
  remote_has_selection_ = false;
  remote_selecting_ = false;
  if (remote_terminal_ != nullptr)
    InvalidateRect(remote_terminal_, nullptr, FALSE);
  set_control_text(remote_status_,
                   remote_scroll_offset_ == 0
                       ? L"Live"
                       : L"Scrolled back " + std::to_wstring(remote_scroll_offset_) + L" of " +
                             std::to_wstring(history) + L" line(s) - type or press End to return");
}

void AppWindow::remote_pump() {
  if (!remote_shell_ || !remote_connected_ || remote_screen_ == nullptr)
    return;
  auto read = support_assist::ssh_shell_read(*remote_shell_);
  if (!read.ok()) {
    remote_disconnect(L"The remote shell closed.");
    return;
  }
  if (!read.value().empty()) {
    remote_screen_->write(read.value());
    // New output shifts the visible grid, so a selection in visible-row space no longer means what
    // it did. Clear it rather than leave a highlight over the wrong text.
    remote_has_selection_ = false;
    remote_selecting_ = false;
  }
  if (!support_assist::ssh_shell_connected(*remote_shell_)) {
    remote_disconnect(L"The remote shell exited.");
    return;
  }
  if (remote_screen_->revision() != remote_painted_revision_) {
    remote_painted_revision_ = remote_screen_->revision();
    InvalidateRect(remote_terminal_, nullptr, FALSE);
  }
}

bool AppWindow::remote_confirm_write(const std::wstring& what) {
  // if constexpr, not a plain if: a constant condition is C4127 and this build is -Werror.
  if constexpr (!kCustomerMachineGuardEnabled) {
    static_cast<void>(what);
    return true;
  } else {
  if (!remote_customer_machine_)
    return true;
  // A customer machine is READ ONLY. Writing a file to, or running a command on, someone else's
  // production server is the risk this page must not take, and a confirmation dialog is not a
  // control - it is a prompt an engineer clicks through at the end of a long day.
  //
  // Reading and listing stay open, because pulling diagnostics is the entire point of connecting.
  const std::wstring text =
      L"This connection is marked as a customer's machine, so it is read only.\n\n" + what +
      L"\n\nHost: " + wide(remote_options_.host) +
      L"\n\nReconnect and answer No to that question if this is our own machine.";
  MessageBoxW(window_, text.c_str(), L"Read only on a customer machine", MB_OK | MB_ICONWARNING);
  return false;
  }
}

void AppWindow::remote_connect() {
  if (remote_busy_)
    return;
  support_assist::SshConnectionOptions options;
  options.host = narrow(control_text(remote_host_));
  options.username = narrow(control_text(remote_user_));
  options.password = narrow(control_text(remote_password_));
  {
    const std::wstring key = control_text(remote_key_);
    if (!key.empty()) {
      options.private_key_path = std::filesystem::path(key);
      options.private_key_passphrase = narrow(control_text(remote_key_passphrase_));
    }
  }
  {
    // An invalid or empty port is a typing error, not a reason to silently use 22 and then report
    // a confusing refusal from whatever is listening there.
    const std::wstring text = control_text(remote_port_);
    unsigned long port = 0UL;
    try {
      port = text.empty() ? 22UL : std::stoul(text);
    } catch (...) {
      port = 0UL;
    }
    if (port == 0UL || port > 65535UL) {
      set_control_text(remote_status_, L"Enter a port between 1 and 65535.");
      return;
    }
    options.port = static_cast<std::uint16_t>(port);
  }

  if (options.host.empty() || options.username.empty() ||
      (options.password.empty() && options.private_key_path.empty())) {
    set_control_text(remote_status_,
                     L"Host and credentials required.");
    return;
  }

  // Ask once, before anything is sent, which kind of machine this is. SAT cannot tell and the
  // operator can; the answer governs every write and every command for this connection.
  //
  // Skipped entirely while the guard is off - asking a question whose answer changes nothing is
  // worse than not asking it.
  if constexpr (kCustomerMachineGuardEnabled) {
  const int answer = MessageBoxW(
      window_,
      L"Is this a customer's machine?\n\n"
      L"Yes - READ ONLY. Browse and download only. Uploads and commands are refused, and the\n"
      L"       terminal will not accept typing.\n\n"
      L"No - our own lab or test machine. Full access: browse, download, upload and run commands.",
      L"Which machine is this?", MB_YESNOCANCEL | MB_ICONQUESTION | MB_DEFBUTTON1);
  if (answer == IDCANCEL)
    return;
  remote_customer_machine_ = answer == IDYES;
  }

  remote_options_ = options;
  remote_busy_ = true;
  remote_progress_.clear();
  remote_note(L"Reading the host key...");

  // The host key is confirmed before authenticating, with the same yes/no dialog the Explorer tab
  // uses. Nothing is sent until the operator has seen the fingerprint.
  support_assist::CancellationSource probe_cancel;
  auto probed = support_assist::ssh_probe_host_key(options, probe_cancel.token());
  if (!probed.ok()) {
    remote_busy_ = false;
    set_control_text(remote_status_, L"Could not reach the host: " + wide(probed.error().message));
    return;
  }

  explorer_ssh_options_ = options;
  explorer_ssh_options_.expected_host_key_sha256 = probed.value().fingerprint_sha256;
  explorer_ssh_host_key_algorithm_ = wide(probed.value().algorithm);
  explorer_ssh_host_key_probed_ = true;
  Button_SetCheck(explorer_ssh_trust_, BST_UNCHECKED);
  if (!confirm_ssh_host_key()) {
    remote_busy_ = false;
    remote_note(L"Host key not trusted.");
    return;
  }
  remote_options_.expected_host_key_sha256 = probed.value().fingerprint_sha256;

  remote_recompute_geometry();
  const int columns = remote_screen_ != nullptr ? remote_screen_->columns() : 80;
  const int rows = remote_screen_ != nullptr ? remote_screen_->rows() : 24;

  support_assist::CancellationSource shell_cancel;
  auto shell = support_assist::ssh_open_shell(remote_options_, columns, rows, shell_cancel.token());
  remote_busy_ = false;
  if (!shell.ok()) {
    remote_note(L"Could not open a shell: " + wide(shell.error().message));
    return;
  }

  remote_shell_ = shell.value();
  remote_connected_ = true;
  remote_screen_ = std::make_unique<support_assist::TerminalScreen>(columns, rows);
  remote_painted_revision_ = 0;

  // Poll the channel. A shell produces output when it feels like it, so there is nothing to wait
  // on; 40 ms is fast enough to feel live and cheap enough not to matter.
  if (remote_timer_ == 0)
    remote_timer_ = SetTimer(window_, kRemoteTimerId, 40, nullptr);

  // Connected: the shell takes the screen, so the narrative goes and only the status line remains.
  remote_progress_.clear();
  set_control_text(remote_status_,
                   remote_customer_machine_
                       ? L"Connected. Marked as a customer machine - writes and commands are confirmed."
                       : L"Connected to " + wide(remote_options_.host) + L".");
  append_activity(L"Remote", L"Connected", wide(remote_options_.host));
  SetFocus(remote_terminal_);
  remote_refresh_files();
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_disconnect(const wchar_t* reason) {
  if (remote_timer_ != 0) {
    KillTimer(window_, kRemoteTimerId);
    remote_timer_ = 0;
  }
  if (remote_shell_) {
    support_assist::ssh_shell_close(*remote_shell_);
    remote_shell_.reset();
  }
  const bool was_connected = remote_connected_;
  remote_connected_ = false;

  // Credentials are session-only. Clearing them here is what makes that true rather than stated:
  // the copies are overwritten before they are released, the password and the key's passphrase
  // alike.
  set_control_text(remote_password_, L"");
  set_control_text(remote_key_passphrase_, L"");
  // remote_connect() also leaves a copy in the host-key state it shares with File Browser.
  for (std::string* secret : {&remote_options_.password, &remote_options_.private_key_passphrase,
                              &explorer_ssh_options_.password,
                              &explorer_ssh_options_.private_key_passphrase}) {
    std::fill(secret->begin(), secret->end(), '\0');
    secret->clear();
  }
  ListView_DeleteAllItems(remote_files_);
  remote_entries_.clear();

  if (reason != nullptr)
    set_control_text(remote_status_, reason);
  if (was_connected)
    append_activity(L"Remote", L"Disconnected", wide(remote_options_.host));
  InvalidateRect(remote_terminal_, nullptr, FALSE);
}

void AppWindow::remote_refresh_files() {
  if (!remote_connected_)
    return;
  // Normalise before listing so a typed path and a clicked one produce the same result, and so
  // the box always shows where the listing actually came from.
  std::wstring normalised = control_text(remote_path_);
  if (normalised.empty())
    normalised = L"/";
  std::replace(normalised.begin(), normalised.end(), L'\\', L'/');
  while (normalised.size() > 1U && normalised.back() == L'/')
    normalised.pop_back();
  if (normalised.front() != L'/')
    normalised.insert(normalised.begin(), L'/');
  set_control_text(remote_path_, normalised);

  const std::string path = narrow(normalised);
  support_assist::CancellationSource cancel;
  // A folder that is not on this host opens the nearest one above it that is.
  std::string listed_path;
  auto listed = support_assist::ssh_list_nearest_directory(remote_options_, path, listed_path,
                                                           cancel.token());
  if (!listed.ok()) {
    set_control_text(remote_status_,
                     L"Could not list that path: " + wide(listed.error().message));
    return;
  }
  std::wstring note;
  if (listed_path != path) {
    note = normalised + L" is not on this host. ";
    normalised = wide(listed_path);
    set_control_text(remote_path_, normalised);
  }
  remote_entries_ = std::move(listed.value());

  // Directories first, then names in order, by the rule both editions share.
  support_assist::gui::sort_remote_entries(remote_entries_);

  // Drop the entries a Windows engineer would not expect to see and cannot use here.
  remote_entries_.erase(
      std::remove_if(remote_entries_.begin(), remote_entries_.end(),
                     [](const support_assist::SftpEntry& entry) {
                       return entry.name == "." || entry.name == "..";
                     }),
      remote_entries_.end());

  ListView_DeleteAllItems(remote_files_);
  int index = 0;

  // A parent entry, unless already at the root. This is the whole "go back" affordance for someone
  // who does not know that ".." means anything.
  remote_at_root_ = normalised == L"/";
  if (!remote_at_root_) {
    LVITEMW parent{};
    parent.mask = LVIF_TEXT;
    parent.iItem = 0;
    parent.pszText = const_cast<wchar_t*>(L"[..]  up one level");
    ListView_InsertItem(remote_files_, &parent);
    ++index;
  }

  for (const auto& entry : remote_entries_) {
    const std::wstring name = entry.directory ? L"[" + wide(entry.name) + L"]" : wide(entry.name);
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = index;
    item.pszText = const_cast<wchar_t*>(name.c_str());
    ListView_InsertItem(remote_files_, &item);
    const std::wstring size = wide(support_assist::gui::remote_size_text(entry));
    ListView_SetItemText(remote_files_, index, 1, const_cast<wchar_t*>(size.c_str()));
    const std::wstring modified = wide(support_assist::gui::remote_modified_text(entry));
    ListView_SetItemText(remote_files_, index, 2, const_cast<wchar_t*>(modified.c_str()));
    ++index;
  }
  fit_report_columns(remote_files_);
  set_control_text(remote_status_, note + std::to_wstring(remote_entries_.size()) +
                                       L" item(s) in " + normalised);
}

void AppWindow::remote_open_selected() {
  if (!remote_connected_)
    return;
  const int selected = ListView_GetNextItem(remote_files_, -1, LVNI_SELECTED);
  if (selected < 0)
    return;

  const std::wstring current = control_text(remote_path_);
  const int offset = remote_at_root_ ? 0 : 1;
  if (!remote_at_root_ && selected == 0) {
    // The parent entry.
    const std::size_t cut = current.find_last_of(L'/');
    set_control_text(remote_path_, cut == 0 || cut == std::wstring::npos ? L"/"
                                                                        : current.substr(0, cut));
    remote_refresh_files();
    return;
  }

  const std::size_t index = static_cast<std::size_t>(selected - offset);
  if (index >= remote_entries_.size())
    return;
  const auto entry = remote_entries_[index];
  if (entry.directory) {
    set_control_text(remote_path_,
                     (current == L"/" ? L"/" : current + L"/") + wide(entry.name));
    remote_refresh_files();
    return;
  }
  // A file: the reason the engineer came here.
  remote_transfer(false);
}

// The bytes a transfer has moved, on the Remote page's status line at most four times a second.
// Called on the worker the transfer runs on; SetWindowText reaches the pumping message thread.
support_assist::ProgressCallback AppWindow::remote_transfer_progress() {
  auto shown_at = std::make_shared<std::chrono::steady_clock::time_point>();
  return [this, shown_at](const support_assist::ProgressEvent& event) {
    const auto now = std::chrono::steady_clock::now();
    if (now - *shown_at < std::chrono::milliseconds(250))
      return;
    *shown_at = now;
    set_control_text(remote_status_, wide(support_assist::gui::progress_event_text(event)));
  };
}

// Evidence belongs to the case when there is one, the rule every other collection follows: a
// download opens in the open case's logs folder. With no case the dialog opens where Windows puts it.
std::filesystem::path AppWindow::remote_download_folder() const {
  const auto* workspace = active_case();
  if (workspace == nullptr)
    return {};
  std::error_code error;
  if (!std::filesystem::is_directory(workspace->logs, error) || error)
    return {};
  return workspace->logs;
}

void AppWindow::browse_remote_key() {
  const std::filesystem::path chosen = prompt_for_existing_file(window_);
  if (!chosen.empty())
    set_control_text(remote_key_, chosen.wstring());
}

void AppWindow::remote_transfer(bool upload) {
  if (!remote_connected_) {
    set_control_text(remote_status_, L"Connect first.");
    return;
  }
  const std::wstring remote_directory = control_text(remote_path_);

  if (upload) {
    const std::filesystem::path local = prompt_for_existing_file(window_);
    if (local.empty())
      return;
    const std::wstring destination = remote_directory + L"/" + local.filename().wstring();
    // A file of the same name in the listed folder would be replaced; ask first, No by default.
    if (support_assist::gui::remote_listing_has_file(remote_entries_,
                                                     support_assist::path_to_utf8(local.filename()))) {
      const std::wstring question = local.filename().wstring() + L" already exists in " +
                                    remote_directory + L".\n\nReplace it?";
      if (MessageBoxW(window_, question.c_str(), L"Replace file", MB_YESNO | MB_ICONWARNING |
                      MB_DEFBUTTON2) != IDYES)
        return;
    }
    if (!remote_confirm_write(L"Upload " + local.filename().wstring() + L" to " + destination))
      return;
    // On a worker, so the window keeps painting while a large file goes; the status line counts
    // the bytes.
    const std::wstring uploading = L"Uploading " + local.filename().wstring() + L"...";
    set_control_text(remote_status_, uploading);
    const auto status = run_keeping_ui_alive(uploading.c_str(), [&]() {
      support_assist::CancellationSource cancel;
      return support_assist::ssh_upload_file(remote_options_, local, narrow(destination),
                                             cancel.token(), remote_transfer_progress());
    });
    set_control_text(remote_status_, status.ok()
                                         ? L"Uploaded " + local.filename().wstring()
                                         : L"Upload failed: " + wide(status.error().message));
    if (status.ok()) {
      append_activity(L"Remote", L"Uploaded", destination);
      remote_refresh_files();
    }
    return;
  }

  const int selected = ListView_GetNextItem(remote_files_, -1, LVNI_SELECTED);
  if (selected < 0 || static_cast<std::size_t>(selected) >= remote_entries_.size()) {
    set_control_text(remote_status_, L"Select a file to download.");
    return;
  }
  const int offset = remote_at_root_ ? 0 : 1;
  if (!remote_at_root_ && selected == 0) {
    remote_open_selected();          // the parent entry
    return;
  }
  const std::size_t entry_index = static_cast<std::size_t>(selected - offset);
  if (entry_index >= remote_entries_.size()) {
    remote_note(L"Select a file to download.");
    return;
  }
  const auto entry = remote_entries_[entry_index];
  if (entry.directory) {
    remote_open_selected();          // pressing Download on a folder opens it
    return;
  }
  const std::filesystem::path local =
      prompt_for_save_file(window_, wide(entry.name), remote_download_folder());
  if (local.empty())
    return;
  const std::wstring downloading = L"Downloading " + wide(entry.name) + L"...";
  set_control_text(remote_status_, downloading);
  const auto status = run_keeping_ui_alive(downloading.c_str(), [&]() {
    support_assist::CancellationSource cancel;
    return support_assist::ssh_download_file(remote_options_, entry.path, local, cancel.token(),
                                             remote_transfer_progress());
  });
  set_control_text(remote_status_, status.ok()
                                       ? L"Downloaded to " + local.wstring()
                                       : L"Download failed: " + wide(status.error().message));
  if (status.ok())
    append_activity(L"Remote", L"Downloaded", wide(entry.path));
}
