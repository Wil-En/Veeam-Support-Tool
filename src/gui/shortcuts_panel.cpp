// Settings > Keyboard Shortcuts: each group a card, each shortcut its key caps beside its name
// and detail, in one or two columns by width.

#include "shortcuts_panel.hpp"

#include "keyboard_shortcuts.hpp"
#include "panel_drawing.hpp"
#include "ui_theme.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace {

namespace gui = support_assist::gui;
using namespace panel_drawing;

constexpr wchar_t kClassName[] = L"SupportAssistShortcutsPanel";

struct PanelState {
  ShortcutsPanelStyle style;
  HFONT cap = nullptr; // the detail font in semibold, owned here
  Scroller scroller;
};

PanelState* state_of(HWND window) {
  return reinterpret_cast<PanelState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

int scaled(const PanelState& state, int pixels) {
  return MulDiv(pixels, state.style.scale_percent, 100);
}

std::wstring wide(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

void rebuild_cap_font(PanelState& state) {
  if (state.cap != nullptr)
    DeleteObject(state.cap);
  state.cap = nullptr;
  LOGFONTW description{};
  if (state.style.detail != nullptr && GetObjectW(state.style.detail, sizeof(description), &description) != 0) {
    description.lfWeight = FW_SEMIBOLD;
    state.cap = CreateFontIndirectW(&description);
  }
}

struct Metrics {
  int padding = 0;  // inside a card
  int gap = 0;      // between cards, and around them
  int row_gap = 0;  // between shortcuts
  int cap_height = 0;
  int cap_padding = 0;
  int cap_gap = 0;  // either side of the "+" between caps
  int radius = 0;
  int plus_width = 0;
};

Metrics metrics_for(HDC dc, const PanelState& state) {
  Metrics metrics;
  metrics.padding = scaled(state, 16);
  metrics.gap = scaled(state, 14);
  metrics.row_gap = scaled(state, 10);
  metrics.cap_height = line_height(dc, state.cap != nullptr ? state.cap : state.style.detail) + scaled(state, 11);
  metrics.cap_padding = scaled(state, 9);
  metrics.cap_gap = scaled(state, 4);
  metrics.radius = scaled(state, 8);
  metrics.plus_width = static_cast<int>(text_size(dc, state.style.detail, L"+").cx);
  return metrics;
}

int cap_width(HDC dc, const PanelState& state, const Metrics& metrics, const std::wstring& text) {
  const int measured = static_cast<int>(text_size(dc, state.cap, text).cx) + 2 * metrics.cap_padding;
  return std::max(metrics.cap_height, measured); // a single key letter sits in a square cap
}

int caps_width(HDC dc, const PanelState& state, const Metrics& metrics, const gui::KeyChord& chord) {
  const auto caps = gui::key_caps(chord);
  int width = 0;
  for (std::size_t index = 0; index < caps.size(); ++index) {
    if (index != 0)
      width += 2 * metrics.cap_gap + metrics.plus_width;
    width += cap_width(dc, state, metrics, wide(caps[index]));
  }
  return width;
}

void draw_caps(HDC dc, const PanelState& state, const Metrics& metrics, const gui::KeyChord& chord, int x, int y) {
  const int depth = std::max(2, scaled(state, 3));
  const auto caps = gui::key_caps(chord);
  for (std::size_t index = 0; index < caps.size(); ++index) {
    if (index != 0) {
      const RECT plus{x + metrics.cap_gap, y, x + metrics.cap_gap + metrics.plus_width,
                      y + metrics.cap_height - depth};
      draw_text(dc, state.style.detail, themed(RGB(126, 164, 153)), L"+", plus, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
      x += 2 * metrics.cap_gap + metrics.plus_width;
    }
    const std::wstring text = wide(caps[index]);
    const int width = cap_width(dc, state, metrics, text);
    // The cap's lower edge, then its face above it.
    const RECT edge{x, y + depth, x + width, y + metrics.cap_height};
    round_box(dc, edge, themed(RGB(9, 27, 27)), themed(RGB(9, 27, 27)), metrics.radius);
    const RECT face{x, y, x + width, y + metrics.cap_height - depth};
    round_box(dc, face, themed(RGB(31, 68, 61)), themed(RGB(84, 124, 115)), metrics.radius);
    draw_text(dc, state.cap, themed(RGB(242, 248, 245)), text, face, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    x += width;
  }
}

// One group's card at (left, top), width wide. Returns its height; draws it when draw is set.
int card(HDC dc, const PanelState& state, const Metrics& metrics, gui::ShortcutGroup group, int left, int top,
         int width, bool draw) {
  const auto shortcuts = gui::shortcuts_in_group(group);
  const std::wstring title = wide(gui::shortcut_group_title(group));
  const std::wstring note = wide(gui::shortcut_group_note(group));
  const int inner = std::max(scaled(state, 80), width - 2 * metrics.padding);
  int caps_column = 0;
  for (const auto* shortcut : shortcuts)
    caps_column = std::max(caps_column, caps_width(dc, state, metrics, shortcut->chord));
  caps_column = std::min(caps_column, inner / 2);
  const int text_left = left + metrics.padding + caps_column + scaled(state, 14);
  const int text_width = std::max(scaled(state, 60), left + width - metrics.padding - text_left);

  const int title_height = line_height(dc, state.style.title);
  const int note_height = wrapped_height(dc, state.style.detail, note, inner);
  const int label_height = line_height(dc, state.style.label);
  const int label_offset = std::max(0, (metrics.cap_height - label_height) / 2 - scaled(state, 1));
  const int header = metrics.padding + title_height + scaled(state, 3) + note_height + scaled(state, 14);

  std::vector<int> row_heights;
  std::vector<int> detail_heights;
  int height = header;
  for (const auto* shortcut : shortcuts) {
    const int detail = wrapped_height(dc, state.style.detail, wide(shortcut->detail), text_width);
    const int row = std::max(metrics.cap_height, label_offset + label_height + scaled(state, 2) + detail);
    detail_heights.push_back(detail);
    row_heights.push_back(row);
    height += row + metrics.row_gap;
  }
  height += metrics.padding - metrics.row_gap;
  if (!draw)
    return height;

  const RECT box{left, top, left + width, top + height};
  round_box(dc, box, themed(RGB(18, 48, 49)), themed(RGB(43, 86, 78)), scaled(state, 14));
  const RECT title_box{left + metrics.padding, top + metrics.padding, left + width - metrics.padding,
                       top + metrics.padding + title_height};
  draw_text(dc, state.style.title, themed(RGB(114, 224, 106)), title, title_box, DT_LEFT | DT_SINGLELINE);
  const RECT note_box{title_box.left, title_box.bottom + scaled(state, 3), title_box.right,
                      title_box.bottom + scaled(state, 3) + note_height};
  draw_text(dc, state.style.detail, themed(RGB(165, 188, 178)), note, note_box, DT_LEFT | DT_WORDBREAK);

  int y = top + header;
  for (std::size_t index = 0; index < shortcuts.size(); ++index) {
    const auto* shortcut = shortcuts[index];
    if (index != 0)
      horizontal_rule(dc, left + metrics.padding, left + width - metrics.padding, y - metrics.row_gap / 2 - 1,
                      themed(RGB(34, 70, 64)));
    draw_caps(dc, state, metrics, shortcut->chord, left + metrics.padding, y);
    const RECT label{text_left, y + label_offset, left + width - metrics.padding, y + label_offset + label_height};
    draw_text(dc, state.style.label, themed(RGB(244, 249, 246)), wide(shortcut->label), label,
              DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
    const RECT detail{text_left, label.bottom + scaled(state, 2), left + width - metrics.padding,
                      label.bottom + scaled(state, 2) + detail_heights[index]};
    draw_text(dc, state.style.detail, themed(RGB(176, 196, 188)), wide(shortcut->detail), detail,
              DT_LEFT | DT_WORDBREAK);
    y += row_heights[index] + metrics.row_gap;
  }
  return height;
}

// Lays out every card for this width, and draws them scrolled by `scroll` when draw is set.
// Returns the height the content needs.
int layout_cards(HDC dc, const PanelState& state, int width, bool draw, int scroll) {
  const Metrics metrics = metrics_for(dc, state);
  const int usable = std::max(scaled(state, 120), width - 2 * metrics.gap);
  const std::size_t columns = usable >= scaled(state, 760) ? 2U : 1U;
  const int column_width = (usable - static_cast<int>(columns - 1U) * metrics.gap) / static_cast<int>(columns);
  const auto arranged = gui::arrange_shortcut_groups(columns);
  int tallest = 0;
  for (std::size_t column = 0; column < arranged.size(); ++column) {
    const int left = metrics.gap + static_cast<int>(column) * (column_width + metrics.gap);
    int y = metrics.gap;
    for (const gui::ShortcutGroup group : arranged[column])
      y += card(dc, state, metrics, group, left, y - scroll, column_width, draw) + metrics.gap;
    tallest = std::max(tallest, y);
  }
  return tallest;
}

void relayout(HWND window, PanelState& state) {
  RECT client{};
  GetClientRect(window, &client);
  HDC dc = GetDC(window);
  if (dc == nullptr)
    return;
  const int content = layout_cards(dc, state, static_cast<int>(client.right), false, 0);
  ReleaseDC(window, dc);
  scroller_update(window, state.scroller, content);
}

// The shortcuts as plain text: the window's name for screen readers and UI automation.
std::wstring plain_text() {
  std::wstring text;
  for (const gui::ShortcutGroup group : gui::kShortcutGroups) {
    text += wide(gui::shortcut_group_title(group)) + L"\n";
    for (const auto* shortcut : gui::shortcuts_in_group(group))
      text += wide(gui::chord_text(shortcut->chord)) + L"  " + wide(shortcut->label) + L"\n";
  }
  return text;
}

LRESULT CALLBACK panel_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
  if (message == WM_NCCREATE) {
    const auto* create = reinterpret_cast<const CREATESTRUCTW*>(lparam);
    SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    return DefWindowProcW(window, message, wparam, lparam);
  }
  PanelState* state = state_of(window);
  if (state == nullptr)
    return DefWindowProcW(window, message, wparam, lparam);
  if (scroller_message(window, state->scroller, message, wparam, scaled(*state, 40)))
    return 0;
  switch (message) {
  case WM_ERASEBKGND:
    return 1;
  case WM_PAINT:
    buffered_paint(window, themed(RGB(18, 30, 28)), [&](HDC dc, const RECT& client) {
      layout_cards(dc, *state, static_cast<int>(client.right), true, state->scroller.position);
      if (GetFocus() == window) {
        HBRUSH focus = CreateSolidBrush(themed(RGB(101, 215, 98)));
        FrameRect(dc, &client, focus);
        DeleteObject(focus);
      }
    });
    return 0;
  case WM_SIZE:
    relayout(window, *state);
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_GETDLGCODE:
    return DLGC_WANTARROWS;
  case WM_LBUTTONDOWN:
    SetFocus(window);
    return 0;
  case WM_SETFOCUS:
  case WM_KILLFOCUS:
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_NCDESTROY:
    if (state->cap != nullptr)
      DeleteObject(state->cap);
    delete state;
    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
    return DefWindowProcW(window, message, wparam, lparam);
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

HWND create_shortcuts_panel(HWND parent, HINSTANCE instance, const ShortcutsPanelStyle& style) {
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.style = CS_HREDRAW | CS_VREDRAW;
    description.lpfnWndProc = &panel_proc;
    description.hInstance = instance;
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    description.lpszClassName = kClassName;
    if (RegisterClassW(&description) == 0)
      return nullptr;
    registered = true;
  }
  auto* state = new PanelState();
  state->style = style;
  rebuild_cap_font(*state);
  HWND panel = CreateWindowExW(0, kClassName, plain_text().c_str(), WS_CHILD | WS_TABSTOP | WS_VSCROLL, 0, 0, 0, 0,
                               parent, nullptr, instance, state);
  if (panel == nullptr) {
    if (state->cap != nullptr)
      DeleteObject(state->cap);
    delete state;
  }
  return panel;
}

void set_shortcuts_panel_style(HWND panel, const ShortcutsPanelStyle& style) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->style = style;
  rebuild_cap_font(*state);
  relayout(panel, *state);
  InvalidateRect(panel, nullptr, FALSE);
}
