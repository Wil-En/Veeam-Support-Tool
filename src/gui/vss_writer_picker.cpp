// The writer picker: a modal dialog holding a checked list of writers, Use these and Cancel. The
// dialog manager gives it Tab, Enter and Escape.

#include "vss_writer_picker.hpp"

#include "ui_theme.hpp"

#include <commctrl.h>

#include <algorithm>
#include <array>
#include <cwctype>

namespace {

constexpr int kListId = 100;

struct PickerState {
  const std::vector<VssWriterChoice>* writers = nullptr;
  const std::vector<std::wstring>* ticked = nullptr;
  HFONT font = nullptr;
  HWND list = nullptr;
  HWND use = nullptr;
  HWND cancel = nullptr;
  HBRUSH background = nullptr;
  std::vector<std::wstring> result;
};

std::wstring folded(std::wstring text) {
  for (wchar_t& character : text)
    character = static_cast<wchar_t>(std::towlower(character));
  std::erase_if(text, [](wchar_t character) { return character == L'{' || character == L'}'; });
  return text;
}

void layout(HWND dialog, const PickerState& state) {
  RECT client{};
  GetClientRect(dialog, &client);
  const int margin = 12;
  const int button_width = 110;
  const int button_height = 30;
  const int bottom = client.bottom - margin - button_height;
  MoveWindow(state.list, margin, margin, client.right - 2 * margin, bottom - 2 * margin, TRUE);
  MoveWindow(state.cancel, client.right - margin - button_width, bottom, button_width, button_height, TRUE);
  MoveWindow(state.use, client.right - 2 * (margin + button_width) + margin, bottom, button_width, button_height, TRUE);
}

INT_PTR CALLBACK picker_proc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
  auto* state = reinterpret_cast<PickerState*>(GetWindowLongPtrW(dialog, DWLP_USER));
  switch (message) {
  case WM_INITDIALOG: {
    state = reinterpret_cast<PickerState*>(lparam);
    SetWindowLongPtrW(dialog, DWLP_USER, lparam);
    SetWindowTextW(dialog, L"Choose writers");
    state->background = CreateSolidBrush(themed(RGB(13, 31, 33)));
    const HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog, GWLP_HINSTANCE));
    state->list = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0,
                                  dialog, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kListId)), instance, nullptr);
    ListView_SetExtendedListViewStyle(state->list, LVS_EX_CHECKBOXES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
    ListView_SetBkColor(state->list, themed(RGB(13, 31, 33)));
    ListView_SetTextBkColor(state->list, themed(RGB(13, 31, 33)));
    ListView_SetTextColor(state->list, themed(RGB(225, 236, 231)));
    state->use = CreateWindowExW(0, WC_BUTTONW, L"Use these", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON,
                                 0, 0, 0, 0, dialog, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDOK)), instance,
                                 nullptr);
    state->cancel = CreateWindowExW(0, WC_BUTTONW, L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON, 0,
                                    0, 0, 0, dialog, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDCANCEL)), instance,
                                    nullptr);
    for (HWND control : {state->list, state->use, state->cancel})
      SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(state->font), TRUE);
    const std::array<std::pair<const wchar_t*, int>, 2> columns{{{L"Writer", 260}, {L"Class ID", 300}}};
    for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
      LVCOLUMNW column{};
      column.mask = LVCF_TEXT | LVCF_WIDTH;
      column.pszText = const_cast<LPWSTR>(columns[static_cast<std::size_t>(index)].first);
      column.cx = columns[static_cast<std::size_t>(index)].second;
      ListView_InsertColumn(state->list, index, &column);
    }
    std::vector<std::wstring> ticked;
    for (const auto& id : *state->ticked)
      ticked.push_back(folded(id));
    int row = 0;
    for (const auto& writer : *state->writers) {
      LVITEMW item{};
      item.mask = LVIF_TEXT;
      item.iItem = row;
      item.pszText = const_cast<LPWSTR>(writer.name.c_str());
      ListView_InsertItem(state->list, &item);
      ListView_SetItemText(state->list, row, 1, const_cast<LPWSTR>(writer.class_id.c_str()));
      if (std::find(ticked.begin(), ticked.end(), folded(writer.class_id)) != ticked.end())
        ListView_SetCheckState(state->list, row, TRUE);
      ++row;
    }
    // Over the owner, at a size that shows a long writer list.
    RECT owner{};
    GetWindowRect(GetParent(dialog), &owner);
    const int width = 640;
    const int height = 440;
    SetWindowPos(dialog, nullptr, owner.left + ((owner.right - owner.left) - width) / 2,
                 owner.top + ((owner.bottom - owner.top) - height) / 2, width, height, SWP_NOZORDER);
    layout(dialog, *state);
    SetFocus(state->list);
    return FALSE;
  }
  case WM_SIZE:
    if (state != nullptr)
      layout(dialog, *state);
    return TRUE;
  case WM_CTLCOLORDLG:
    return state != nullptr ? reinterpret_cast<INT_PTR>(state->background) : FALSE;
  case WM_COMMAND:
    if (state != nullptr && LOWORD(wparam) == IDOK) {
      state->result.clear();
      const int count = ListView_GetItemCount(state->list);
      for (int row = 0; row < count && row < static_cast<int>(state->writers->size()); ++row) {
        if (ListView_GetCheckState(state->list, row) != FALSE)
          state->result.push_back((*state->writers)[static_cast<std::size_t>(row)].class_id);
      }
      EndDialog(dialog, IDOK);
      return TRUE;
    }
    if (LOWORD(wparam) == IDCANCEL) {
      EndDialog(dialog, IDCANCEL);
      return TRUE;
    }
    break;
  case WM_DESTROY:
    if (state != nullptr && state->background != nullptr) {
      DeleteObject(state->background);
      state->background = nullptr;
    }
    break;
  default:
    break;
  }
  return FALSE;
}

} // namespace

std::optional<std::vector<std::wstring>> pick_vss_writers(HWND owner, HINSTANCE instance,
                                                          const std::vector<VssWriterChoice>& writers,
                                                          const std::vector<std::wstring>& ticked, HFONT font) {
  // A template with no controls: they are made in WM_INITDIALOG, sized in pixels.
  struct alignas(DWORD) Template {
    DLGTEMPLATE header;
    WORD menu;
    WORD window_class;
    WORD title;
  } dialog_template{};
  dialog_template.header.style = WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | DS_MODALFRAME;
  dialog_template.header.cx = 300;
  dialog_template.header.cy = 200;
  PickerState state;
  state.writers = &writers;
  state.ticked = &ticked;
  state.font = font;
  const INT_PTR answer = DialogBoxIndirectParamW(instance, &dialog_template.header, owner, &picker_proc,
                                                 reinterpret_cast<LPARAM>(&state));
  if (answer != IDOK)
    return std::nullopt;
  return state.result;
}
