// A quick tool's report: the headline in its tone's colours with the notes under it, then a card
// per section with a label column and wrapped values.

#include "report_panel.hpp"

#include "panel_drawing.hpp"
#include "ui_theme.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <cmath>
#include <optional>
#include <string>
#include <vector>

namespace {

namespace gui = support_assist::gui;
using namespace panel_drawing;

constexpr wchar_t kClassName[] = L"SupportAssistReportPanel";

struct PanelState {
  ReportPanelStyle style;
  std::optional<gui::QuickToolReport> report;
  std::wstring empty_text;
  Scroller scroller;
};

PanelState* state_of(HWND window) {
  return reinterpret_cast<PanelState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

int scaled(const PanelState& state, int pixels) {
  return MulDiv(pixels, state.style.scale_percent, 100);
}

std::wstring (*text_filter)(std::wstring_view) = nullptr;

std::wstring wide(std::string_view text) {
  std::wstring converted = support_assist::wide_from_utf8_lossy(text);
  return text_filter != nullptr ? text_filter(converted) : converted;
}

struct ToneColours {
  COLORREF fill;
  COLORREF border;
  COLORREF text;
};

ToneColours headline_colours(gui::ReportTone tone) {
  switch (tone) {
  case gui::ReportTone::good: return {themed(RGB(20, 64, 46)), themed(RGB(46, 120, 80)), themed(RGB(150, 236, 160))};
  case gui::ReportTone::attention:
    return {themed(RGB(70, 54, 20)), themed(RGB(130, 100, 40)), themed(RGB(255, 213, 128))};
  case gui::ReportTone::problem: return {themed(RGB(78, 30, 32)), themed(RGB(150, 60, 60)), themed(RGB(255, 160, 160))};
  case gui::ReportTone::normal:
  case gui::ReportTone::quiet: break;
  }
  return {themed(RGB(18, 48, 49)), themed(RGB(43, 86, 78)), themed(RGB(244, 249, 246))};
}

COLORREF value_colour(gui::ReportTone tone) {
  switch (tone) {
  case gui::ReportTone::good: return themed(RGB(126, 224, 130));
  case gui::ReportTone::attention: return themed(RGB(255, 199, 91));
  case gui::ReportTone::problem: return themed(RGB(255, 120, 120));
  case gui::ReportTone::quiet: return themed(RGB(150, 172, 165));
  case gui::ReportTone::normal: break;
  }
  return themed(RGB(225, 236, 231));
}

// Lays the report out at this width, drawing it scrolled by `scroll` when draw is set. Returns the
// height the content needs.
int layout_report(HDC dc, const PanelState& state, int width, bool draw, int scroll) {
  const int gap = scaled(state, 12);
  const int padding = scaled(state, 14);
  const int row_gap = scaled(state, 7);
  const int radius = scaled(state, 14);
  const int card_width = std::max(scaled(state, 120), width - 2 * gap);
  const int inner = card_width - 2 * padding;
  const int left = gap;
  int y = gap;

  if (!state.report) {
    if (draw && !state.empty_text.empty()) {
      const int height = wrapped_height(dc, state.style.text, state.empty_text, inner);
      const RECT box{left + padding, gap * 2 - scroll, left + card_width - padding, gap * 2 + height - scroll};
      draw_text(dc, state.style.text, themed(RGB(165, 188, 178)), state.empty_text, box, DT_CENTER | DT_WORDBREAK);
    }
    return gap * 3;
  }
  const gui::QuickToolReport& report = *state.report;

  // The headline, with the notes under it; a report without either starts at its first section.
  if (!report.headline.empty() || !report.notes.empty()) {
    const ToneColours colours = headline_colours(report.headline_tone);
    const std::wstring headline = wide(report.headline);
    const int headline_height = wrapped_height(dc, state.style.headline, headline, inner);
    std::vector<int> note_heights;
    int height = padding + headline_height + padding;
    for (const std::string& note : report.notes) {
      note_heights.push_back(wrapped_height(dc, state.style.caption, wide(note), inner));
      height += scaled(state, 4) + note_heights.back();
    }
    if (draw) {
      const int top = y - scroll;
      round_box(dc, RECT{left, top, left + card_width, top + height}, colours.fill, colours.border, radius);
      RECT line{left + padding, top + padding, left + card_width - padding, top + padding + headline_height};
      draw_text(dc, state.style.headline, colours.text, headline, line, DT_LEFT | DT_WORDBREAK);
      int note_top = line.bottom;
      for (std::size_t index = 0; index < report.notes.size(); ++index) {
        note_top += scaled(state, 4);
        const RECT note{left + padding, note_top, left + card_width - padding, note_top + note_heights[index]};
        draw_text(dc, state.style.caption, themed(RGB(214, 228, 222)), wide(report.notes[index]), note,
                  DT_LEFT | DT_WORDBREAK);
        note_top += note_heights[index];
      }
    }
    y += height + gap;
  }

  for (const gui::ReportSection& section : report.sections) {
    const std::wstring title = wide(section.title);
    const int title_height = line_height(dc, state.style.title);
    int label_column = 0;
    for (const gui::ReportRow& row : section.rows) {
      if (!row.label.empty())
        label_column = std::max(label_column, static_cast<int>(text_size(dc, state.style.caption, wide(row.label)).cx));
    }
    label_column = std::min(label_column, inner * 38 / 100);
    const int value_left = label_column > 0 ? label_column + scaled(state, 14) : 0;
    std::vector<int> heights;
    std::vector<int> value_heights;
    const int bar_height = scaled(state, 8);
    const int bar_gap = scaled(state, 5);
    int height = padding + title_height + scaled(state, 10);
    for (const gui::ReportRow& row : section.rows) {
      const int value_width = row.label.empty() ? inner : inner - value_left;
      const int value_height = wrapped_height(dc, state.style.text, wide(row.value), value_width) +
                               (row.bar >= 0.0 ? bar_gap + bar_height : 0);
      value_heights.push_back(value_height);
      const int label_height = row.label.empty() ? 0 : wrapped_height(dc, state.style.caption, wide(row.label), label_column);
      heights.push_back(std::max(value_height, label_height));
      height += heights.back() + row_gap;
    }
    const int note_height = wrapped_height(dc, state.style.caption, wide(section.note), inner);
    if (note_height > 0)
      height += scaled(state, 2) + note_height;
    height += padding - (section.rows.empty() ? 0 : row_gap);

    if (draw) {
      const int top = y - scroll;
      round_box(dc, RECT{left, top, left + card_width, top + height}, themed(RGB(18, 48, 49)),
                themed(RGB(43, 86, 78)), radius);
      const RECT title_box{left + padding, top + padding, left + card_width - padding, top + padding + title_height};
      draw_text(dc, state.style.title, themed(RGB(114, 224, 106)), title, title_box, DT_LEFT | DT_SINGLELINE);
      int row_top = title_box.bottom + scaled(state, 10);
      for (std::size_t index = 0; index < section.rows.size(); ++index) {
        const gui::ReportRow& row = section.rows[index];
        if (index != 0)
          horizontal_rule(dc, left + padding, left + card_width - padding, row_top - row_gap / 2 - 1,
                          themed(RGB(34, 70, 64)));
        if (!row.label.empty()) {
          const RECT label{left + padding, row_top + scaled(state, 1), left + padding + label_column,
                           row_top + heights[index]};
          draw_text(dc, state.style.caption, themed(RGB(165, 188, 178)), wide(row.label), label, DT_LEFT | DT_WORDBREAK);
        }
        const int value_x = left + padding + (row.label.empty() ? 0 : value_left);
        const RECT value{value_x, row_top, left + card_width - padding, row_top + heights[index]};
        draw_text(dc, state.style.text, value_colour(row.tone), wide(row.value), value, DT_LEFT | DT_WORDBREAK);
        if (row.bar >= 0.0) {
          // The track, then the share filled in the tone's colour.
          const int bar_top = row_top + value_heights[index] - bar_height;
          const int bar_right = left + card_width - padding;
          round_box(dc, RECT{value_x, bar_top, bar_right, bar_top + bar_height}, themed(RGB(13, 31, 33)),
                    themed(RGB(34, 70, 64)), bar_height);
          const double share = std::clamp(row.bar, 0.0, 1.0);
          const int filled = value_x + static_cast<int>(std::lround(static_cast<double>(bar_right - value_x) * share));
          const COLORREF fill = row.tone == gui::ReportTone::attention ? themed(RGB(255, 199, 91)) : themed(RGB(85, 190, 88));
          if (share > 0.0)
            round_box(dc, RECT{value_x, bar_top, std::max(filled, value_x + bar_height), bar_top + bar_height}, fill, fill,
                      bar_height);
        }
        row_top += heights[index] + row_gap;
      }
      if (note_height > 0) {
        const int note_top = row_top - (section.rows.empty() ? 0 : row_gap) + scaled(state, 2);
        const RECT note{left + padding, note_top, left + card_width - padding, note_top + note_height};
        draw_text(dc, state.style.caption, themed(RGB(165, 188, 178)), wide(section.note), note, DT_LEFT | DT_WORDBREAK);
      }
    }
    y += height + gap;
  }
  return y;
}

void relayout(HWND window, PanelState& state) {
  RECT client{};
  GetClientRect(window, &client);
  HDC dc = GetDC(window);
  if (dc == nullptr)
    return;
  const int content = layout_report(dc, state, static_cast<int>(client.right), false, 0);
  ReleaseDC(window, dc);
  scroller_update(window, state.scroller, content);
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
      layout_report(dc, *state, static_cast<int>(client.right), true, state->scroller.position);
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
    delete state;
    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
    return DefWindowProcW(window, message, wparam, lparam);
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

HWND create_report_panel(HWND parent, HINSTANCE instance, const ReportPanelStyle& style) {
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
  HWND panel = CreateWindowExW(0, kClassName, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL, 0, 0, 0, 0,
                               parent, nullptr, instance, state);
  if (panel == nullptr)
    delete state;
  return panel;
}

void set_report_panel_style(HWND panel, const ReportPanelStyle& style) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->style = style;
  relayout(panel, *state);
  InvalidateRect(panel, nullptr, FALSE);
}

void set_report_panel_report(HWND panel, const support_assist::gui::QuickToolReport& report) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->report = report;
  state->scroller.position = 0;
  // The report as plain text is the panel's name, for screen readers and UI automation.
  SetWindowTextW(panel, wide(support_assist::gui::report_text(report)).c_str());
  relayout(panel, *state);
  InvalidateRect(panel, nullptr, FALSE);
}

void set_report_panel_text_filter(std::wstring (*filter)(std::wstring_view)) {
  text_filter = filter;
}

void set_report_panel_empty(HWND panel, const std::wstring& text) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->report.reset();
  state->empty_text = text;
  state->scroller.position = 0;
  SetWindowTextW(panel, text.c_str());
  relayout(panel, *state);
  InvalidateRect(panel, nullptr, FALSE);
}
