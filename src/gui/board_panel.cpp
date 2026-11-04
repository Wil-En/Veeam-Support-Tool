// The status board: tiles with a caption, a value in its tone, a detail, an optional case status
// pill and a link, laid out in groups, then a row of chips. Hover and keyboard focus draw the
// accent border; the whole tile is the click target.

#include "board_panel.hpp"

#include "panel_drawing.hpp"
#include "ui_theme.hpp"

#include "support_assist/strings.hpp"

#include <windowsx.h>

#include <algorithm>
#include <cstdlib>
#include <limits>

namespace {

namespace gui = support_assist::gui;
using namespace panel_drawing;

constexpr wchar_t kClassName[] = L"SupportAssistBoardPanel";

struct PanelState {
  BoardPanelStyle style;
  BoardContent content;
  HFONT value_font = nullptr;
  HFONT compact_value_font = nullptr;
  Scroller scroller;
  std::vector<RECT> items; // in content coordinates, tiles then chips
  std::vector<RECT> group_captions;
  std::vector<std::pair<RECT, std::wstring>> chip_captions;
  std::vector<char> shrunk; // per group: drawn compact to fit a short panel
  int layout_width = -1;
  int layout_height = -1;
  int hover = -1;
  int focus = -1;
  int pressed = -1;
  bool tracking = false;
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

void make_value_fonts(PanelState& state) {
  for (HFONT* font : {&state.value_font, &state.compact_value_font}) {
    if (*font != nullptr)
      DeleteObject(*font);
    *font = nullptr;
  }
  if (state.style.heading == nullptr)
    return;
  LOGFONTW base{};
  if (GetObjectW(state.style.heading, sizeof(base), &base) == 0)
    return;
  LOGFONTW large = base;
  large.lfHeight = MulDiv(base.lfHeight, 165, 100);
  large.lfWeight = FW_SEMIBOLD;
  state.value_font = CreateFontIndirectW(&large);
  LOGFONTW medium = base;
  medium.lfHeight = MulDiv(base.lfHeight, 135, 100);
  medium.lfWeight = FW_SEMIBOLD;
  state.compact_value_font = CreateFontIndirectW(&medium);
}

std::size_t tile_count(const PanelState& state) {
  std::size_t count = 0;
  for (const BoardGroup& group : state.content.groups)
    count += group.tiles.size();
  return count;
}

const gui::BoardTile* tile_at(const PanelState& state, int index) {
  int remaining = index;
  for (const BoardGroup& group : state.content.groups) {
    if (remaining < static_cast<int>(group.tiles.size()))
      return &group.tiles[static_cast<std::size_t>(remaining)];
    remaining -= static_cast<int>(group.tiles.size());
  }
  return nullptr;
}

bool actionable(const PanelState& state, int index) {
  if (index < 0 || index >= static_cast<int>(state.items.size()))
    return false;
  const gui::BoardTile* tile = tile_at(state, index);
  return tile == nullptr || tile->action != gui::BoardAction::none; // chips always act
}

struct Metrics {
  int padding = 0;
  int gap = 0;
  int caption = 0;
  int value = 0;
  int compact_value = 0;
  int text = 0;
  int tile = 0;
  int compact_tile = 0;
  int chip = 0;
};

// Whether a group draws compact: by its content, or shrunk to fit a short panel.
bool group_compact(const PanelState& state, std::size_t index) {
  return state.content.groups[index].compact || (index < state.shrunk.size() && state.shrunk[index] != 0);
}

Metrics measure(HDC dc, const PanelState& state) {
  Metrics metrics;
  metrics.padding = scaled(state, 14);
  metrics.gap = scaled(state, 12);
  metrics.caption = line_height(dc, state.style.caption);
  metrics.value = line_height(dc, state.value_font != nullptr ? state.value_font : state.style.heading);
  metrics.compact_value =
      line_height(dc, state.compact_value_font != nullptr ? state.compact_value_font : state.style.heading);
  metrics.text = line_height(dc, state.style.text);
  metrics.tile = metrics.padding * 2 + metrics.caption + scaled(state, 6) + metrics.value + scaled(state, 6) +
                 metrics.text * 2 + scaled(state, 6) + metrics.caption;
  metrics.compact_tile = scaled(state, 10) * 2 + metrics.caption + scaled(state, 3) + metrics.compact_value +
                         scaled(state, 3) + metrics.caption;
  metrics.chip = metrics.text + scaled(state, 14);
  return metrics;
}

// Places every item for this width; returns the content height.
int layout_items(HDC dc, PanelState& state, int width) {
  const Metrics metrics = measure(dc, state);
  state.items.clear();
  state.group_captions.clear();
  int y = 0;
  for (std::size_t group_index = 0; group_index < state.content.groups.size(); ++group_index) {
    const BoardGroup& group = state.content.groups[group_index];
    const bool compact = group_compact(state, group_index);
    if (!group.caption.empty()) {
      state.group_captions.push_back(RECT{0, y, width, y + metrics.caption});
      y += metrics.caption + scaled(state, 6);
    } else {
      state.group_captions.push_back(RECT{0, y, 0, y});
    }
    // Fewer columns when the tiles would be too narrow to read.
    int columns = std::max(1, group.columns);
    while (columns > 1 &&
           (width - metrics.gap * (columns - 1)) / columns < scaled(state, compact ? 120 : 200))
      --columns;
    const int tile_width = (width - metrics.gap * (columns - 1)) / columns;
    // A group with no links or pills needs no line for them.
    const bool bare = std::none_of(group.tiles.begin(), group.tiles.end(), [](const gui::BoardTile& tile) {
      return !tile.link.empty() || !tile.pill.empty();
    });
    const int height = compact ? metrics.compact_tile : metrics.tile - (bare ? metrics.caption + scaled(state, 6) : 0);
    for (std::size_t index = 0; index < group.tiles.size(); ++index) {
      const int column = static_cast<int>(index) % columns;
      const int row = static_cast<int>(index) / columns;
      const int left = column * (tile_width + metrics.gap);
      const int top = y + row * (height + metrics.gap);
      state.items.push_back(RECT{left, top, left + tile_width, top + height});
    }
    const int rows = (static_cast<int>(group.tiles.size()) + columns - 1) / columns;
    if (rows > 0)
      y += rows * height + (rows - 1) * metrics.gap;
    y += metrics.gap + scaled(state, 4);
  }

  state.chip_captions.clear();
  if (!state.content.chips.empty()) {
    // A chip starts a new row when it asks to or when it does not fit beside the chips before it;
    // right-aligned chips fill their row from the right end.
    const int gap = scaled(state, 8);
    int left = 0;
    int right = width;
    int row_height = 0;
    bool first = true;
    for (const BoardChip& chip : state.content.chips) {
      int chip_width = text_size(dc, state.style.text, chip.label).cx + scaled(state, chip.primary ? 32 : 20);
      if (!chip.key.empty())
        chip_width += text_size(dc, state.style.caption, chip.key).cx + scaled(state, 12);
      chip_width = std::min(chip_width, std::max(1, width));
      const int note_width =
          chip.primary && !chip.note.empty() ? text_size(dc, state.style.caption, chip.note).cx + scaled(state, 16) : 0;
      const int height = chip.primary ? metrics.chip + scaled(state, 6) : metrics.chip;
      const bool fits = chip.right ? right - chip_width >= left : left + chip_width + note_width <= right;
      if (first || chip.new_row || !fits) {
        if (!first)
          y += row_height + gap;
        if (chip.new_row && !chip.row_caption.empty()) {
          if (!first)
            y += scaled(state, 6);
          state.chip_captions.push_back({RECT{0, y, width, y + metrics.caption}, chip.row_caption});
          y += metrics.caption + scaled(state, 6);
        }
        left = 0;
        right = width;
        row_height = 0;
        first = false;
      }
      const int top = y + (chip.primary ? 0 : scaled(state, 3));
      if (chip.right) {
        state.items.push_back(RECT{right - chip_width, top, right, top + height});
        right -= chip_width + gap;
      } else {
        state.items.push_back(RECT{left, top, left + chip_width, top + height});
        left += chip_width + gap + note_width;
      }
      row_height = std::max(row_height, top - y + height);
    }
    y += row_height + scaled(state, 6);
  }
  state.layout_width = width;
  return y;
}

// Places every item for this size. While the content is taller than the panel, the groups that
// allow it draw compact, the lowest first. Returns the content height.
int layout_to_fit(HDC dc, PanelState& state, int width, int height) {
  state.shrunk.assign(state.content.groups.size(), 0);
  int content = layout_items(dc, state, width);
  for (std::size_t index = state.content.groups.size(); index-- > 0 && height > 0 && content > height;) {
    const BoardGroup& group = state.content.groups[index];
    if (!group.compact_when_short || group.compact)
      continue;
    state.shrunk[index] = 1;
    content = layout_items(dc, state, width);
  }
  state.layout_height = height;
  return content;
}

COLORREF value_colour(gui::ReportTone tone) {
  switch (tone) {
  case gui::ReportTone::attention: return themed(RGB(255, 199, 91));
  case gui::ReportTone::problem: return themed(RGB(255, 120, 120));
  case gui::ReportTone::quiet: return themed(RGB(150, 172, 165));
  case gui::ReportTone::good:
  case gui::ReportTone::normal: break;
  }
  return themed(RGB(114, 224, 106));
}

COLORREF border_colour(const gui::BoardTile& tile) {
  if (tile.highlight)
    return themed(RGB(101, 215, 98));
  switch (tile.tone) {
  case gui::ReportTone::attention: return themed(RGB(191, 137, 52));
  case gui::ReportTone::problem: return themed(RGB(196, 76, 82));
  default: return themed(RGB(43, 86, 78));
  }
}

std::pair<COLORREF, COLORREF> pill_colours_for(const PanelState& state, const std::string& status) {
  if (state.content.pill_colours)
    return state.content.pill_colours(status);
  return {themed(RGB(74, 52, 16)), themed(RGB(255, 199, 91))};
}

COLORREF darker(COLORREF colour, int percent) {
  return RGB(GetRValue(colour) * percent / 100, GetGValue(colour) * percent / 100, GetBValue(colour) * percent / 100);
}

void draw_tile(HDC dc, const PanelState& state, const Metrics& metrics, const gui::BoardTile& tile, RECT box,
               bool compact, bool hot, bool focused) {
  const int radius = scaled(state, 14);
  if (tile.selected) {
    // Pressed in: the selected-row fill, a shadow inside the top and left edges that fades into it,
    // the accent border, and the content a step lower and to the right.
    const COLORREF fill = themed(RGB(25, 74, 60));
    round_box(dc, box, fill, themed(RGB(85, 190, 88)), radius);
    const int inset = radius / 2 + 1;
    const int depth = std::max(3, scaled(state, 4));
    for (int step = 0; step < depth; ++step) {
      HPEN pen = CreatePen(PS_SOLID, 1, darker(fill, 35 + step * 55 / depth));
      const HGDIOBJ previous_pen = SelectObject(dc, pen);
      MoveToEx(dc, box.left + inset, box.top + 1 + step, nullptr);
      LineTo(dc, box.right - inset, box.top + 1 + step);
      MoveToEx(dc, box.left + 1 + step, box.top + inset, nullptr);
      LineTo(dc, box.left + 1 + step, box.bottom - inset);
      SelectObject(dc, previous_pen);
      DeleteObject(pen);
    }
    OffsetRect(&box, std::max(1, scaled(state, 1)), std::max(1, scaled(state, 2)));
  } else {
    round_box(dc, box, themed(RGB(18, 48, 49)), hot ? themed(RGB(85, 190, 88)) : border_colour(tile), radius);
  }
  if (focused) {
    RECT ring = box;
    InflateRect(&ring, -1, -1);
    HPEN pen = CreatePen(PS_SOLID, 2, themed(RGB(101, 215, 98)));
    const HGDIOBJ previous_pen = SelectObject(dc, pen);
    const HGDIOBJ previous_brush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    RoundRect(dc, ring.left, ring.top, ring.right, ring.bottom, radius, radius);
    SelectObject(dc, previous_brush);
    SelectObject(dc, previous_pen);
    DeleteObject(pen);
  }
  const int padding = compact ? scaled(state, 10) : metrics.padding;
  const int left = box.left + padding;
  const int right = box.right - padding;
  int y = box.top + padding;
  // The caption line; a compact tile draws its pill at the right end of it.
  RECT caption_box{left, y, right, y + metrics.caption};
  if (compact && !tile.pill.empty()) {
    const auto colours = pill_colours_for(state, tile.pill);
    const std::wstring pill = wide(tile.pill);
    const int pill_width =
        std::min((right - left) * 2 / 3, static_cast<int>(text_size(dc, state.style.caption, pill).cx) + scaled(state, 14));
    const RECT pill_box{right - pill_width, y - scaled(state, 1), right, y + metrics.caption + scaled(state, 1)};
    round_box(dc, pill_box, colours.first, colours.first, pill_box.bottom - pill_box.top);
    draw_text(dc, state.style.caption, colours.second, pill, pill_box,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
    caption_box.right = pill_box.left - scaled(state, 6);
  }
  draw_text(dc, state.style.caption, tile.selected ? themed(RGB(116, 218, 112)) : themed(RGB(165, 188, 178)),
            wide(tile.caption), caption_box, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
  y += metrics.caption + scaled(state, compact ? 3 : 6);
  const HFONT value_font = compact ? (state.compact_value_font != nullptr ? state.compact_value_font : state.style.heading)
                                   : (state.value_font != nullptr ? state.value_font : state.style.heading);
  const int value_height = compact ? metrics.compact_value : metrics.value;
  draw_text(dc, value_font, value_colour(tile.tone), wide(tile.value), RECT{left, y, right, y + value_height},
            DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
  y += value_height + scaled(state, compact ? 3 : 6);

  if (compact) {
    draw_text(dc, state.style.caption, themed(RGB(196, 214, 207)), wide(tile.detail),
              RECT{left, y, right, y + metrics.caption}, DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
    return;
  }

  const bool has_pill = !tile.pill.empty();
  const int detail_lines = has_pill ? 1 : 2;
  draw_text(dc, state.style.text, themed(RGB(214, 228, 222)), wide(tile.detail),
            RECT{left, y, right, y + metrics.text * detail_lines},
            DT_LEFT | DT_WORDBREAK | DT_EDITCONTROL | DT_END_ELLIPSIS);
  y += metrics.text * detail_lines + scaled(state, 4);
  if (has_pill) {
    const auto colours = pill_colours_for(state, tile.pill);
    const std::wstring pill = wide(tile.pill);
    const int pill_width = std::min(right - left, static_cast<int>(text_size(dc, state.style.caption, pill).cx) + scaled(state, 16));
    const int pill_height = metrics.caption + scaled(state, 4);
    const RECT pill_box{left, y, left + pill_width, y + pill_height};
    round_box(dc, pill_box, colours.first, colours.first, pill_height);
    draw_text(dc, state.style.caption, colours.second, pill, pill_box, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
  }
  if (!tile.link.empty()) {
    draw_text(dc, state.style.caption, themed(RGB(116, 218, 112)), wide(tile.link) + L" ›",
              RECT{left, box.bottom - padding - metrics.caption, right, box.bottom - padding},
              DT_RIGHT | DT_SINGLELINE | DT_END_ELLIPSIS);
  }
}

void draw_chip(HDC dc, const PanelState& state, const BoardChip& chip, const RECT& box, bool hot, bool focused) {
  const int radius = box.bottom - box.top;
  const COLORREF fill = chip.primary ? themed(RGB(25, 74, 60)) : themed(RGB(18, 48, 49));
  const COLORREF border = focused || hot ? themed(RGB(101, 215, 98))
                          : chip.primary ? themed(RGB(85, 190, 88))
                                         : themed(RGB(74, 105, 99));
  round_box(dc, box, fill, border, chip.primary ? scaled(state, 8) : radius);
  RECT label = box;
  label.left += scaled(state, chip.primary ? 16 : 10);
  draw_text(dc, state.style.text, chip.primary ? themed(RGB(150, 236, 160)) : themed(RGB(224, 236, 230)),
            chip.label, label, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  if (!chip.key.empty()) {
    const SIZE key_size = text_size(dc, state.style.caption, chip.key);
    const int key_width = key_size.cx + scaled(state, 8);
    const int key_height = key_size.cy + scaled(state, 2);
    const int key_left = box.right - scaled(state, 6) - key_width;
    const int key_top = box.top + (box.bottom - box.top - key_height) / 2;
    const RECT key_box{key_left, key_top, key_left + key_width, key_top + key_height};
    round_box(dc, key_box, themed(RGB(28, 63, 59)), themed(RGB(74, 105, 99)), scaled(state, 5));
    draw_text(dc, state.style.caption, themed(RGB(196, 214, 207)), chip.key, key_box,
              DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  }
  if (chip.primary && !chip.note.empty()) {
    RECT note{box.right + scaled(state, 12), box.top, box.right + scaled(state, 12) + 4000, box.bottom};
    draw_text(dc, state.style.caption, themed(RGB(196, 214, 207)), chip.note, note,
              DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  }
}

void relayout(HWND window, PanelState& state) {
  RECT client{};
  GetClientRect(window, &client);
  HDC dc = GetDC(window);
  if (dc == nullptr)
    return;
  const int content = layout_to_fit(dc, state, static_cast<int>(client.right), static_cast<int>(client.bottom));
  ReleaseDC(window, dc);
  scroller_update(window, state.scroller, content);
}

int hit_test(const PanelState& state, POINT point) {
  point.y += state.scroller.position;
  for (std::size_t index = 0; index < state.items.size(); ++index) {
    if (PtInRect(&state.items[index], point) != FALSE)
      return static_cast<int>(index);
  }
  return -1;
}

void activate(HWND window, int index) {
  if (index >= 0)
    PostMessageW(GetParent(window), kBoardActivateMessage, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(window));
}

void ensure_visible(HWND window, PanelState& state, int index) {
  if (index < 0 || index >= static_cast<int>(state.items.size()))
    return;
  const RECT& box = state.items[static_cast<std::size_t>(index)];
  const int view = client_height(window);
  if (box.top < state.scroller.position)
    scroller_to(window, state.scroller, box.top);
  else if (box.bottom > state.scroller.position + view)
    scroller_to(window, state.scroller, box.bottom - view);
}

// The nearest actionable item from `from` in a direction: 0 left, 1 right, 2 up, 3 down.
int neighbour(const PanelState& state, int from, int direction) {
  const int count = static_cast<int>(state.items.size());
  if (count == 0)
    return -1;
  if (from < 0) {
    for (int index = 0; index < count; ++index) {
      if (actionable(state, index))
        return index;
    }
    return -1;
  }
  if (direction < 2) {
    for (int index = from + (direction == 0 ? -1 : 1); index >= 0 && index < count; index += direction == 0 ? -1 : 1) {
      if (actionable(state, index))
        return index;
    }
    return from;
  }
  const RECT& current = state.items[static_cast<std::size_t>(from)];
  const int centre = (current.left + current.right) / 2;
  int best = from;
  long long best_score = std::numeric_limits<long long>::max();
  for (int index = 0; index < count; ++index) {
    if (index == from || !actionable(state, index))
      continue;
    const RECT& box = state.items[static_cast<std::size_t>(index)];
    const bool beyond = direction == 2 ? box.bottom <= current.top : box.top >= current.bottom;
    if (!beyond)
      continue;
    const long long dy = direction == 2 ? current.top - box.bottom : box.top - current.bottom;
    const long long dx = std::llabs(static_cast<long long>((box.left + box.right) / 2 - centre));
    const long long score = dy * 4 + dx;
    if (score < best_score) {
      best_score = score;
      best = index;
    }
  }
  return best;
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
  if (message != WM_KEYDOWN && scroller_message(window, state->scroller, message, wparam, scaled(*state, 40)))
    return 0;
  switch (message) {
  case WM_ERASEBKGND:
    return 1;
  case WM_PAINT:
    buffered_paint(window, themed(RGB(7, 24, 26)), [&](HDC dc, const RECT& client) {
      if (state->layout_width != client.right || state->layout_height != client.bottom)
        layout_to_fit(dc, *state, static_cast<int>(client.right), static_cast<int>(client.bottom));
      const Metrics metrics = measure(dc, *state);
      const int scroll = state->scroller.position;
      int index = 0;
      for (std::size_t group_index = 0; group_index < state->content.groups.size(); ++group_index) {
        const BoardGroup& group = state->content.groups[group_index];
        if (!group.caption.empty() && group_index < state->group_captions.size()) {
          RECT caption = state->group_captions[group_index];
          OffsetRect(&caption, 0, -scroll);
          draw_text(dc, state->style.caption, themed(RGB(165, 188, 178)), group.caption, caption,
                    DT_LEFT | DT_SINGLELINE | DT_BOTTOM);
        }
        for (const gui::BoardTile& tile : group.tiles) {
          if (static_cast<std::size_t>(index) >= state->items.size())
            break;
          RECT box = state->items[static_cast<std::size_t>(index)];
          OffsetRect(&box, 0, -scroll);
          const bool hot = index == state->hover && tile.action != gui::BoardAction::none;
          draw_tile(dc, *state, metrics, tile, box, group_compact(*state, group_index), hot,
                    index == state->focus && GetFocus() == window);
          ++index;
        }
      }
      for (const auto& [where, text] : state->chip_captions) {
        RECT caption = where;
        OffsetRect(&caption, 0, -scroll);
        draw_text(dc, state->style.caption, themed(RGB(165, 188, 178)), text, caption,
                  DT_LEFT | DT_SINGLELINE | DT_BOTTOM);
      }
      for (const BoardChip& chip : state->content.chips) {
        if (static_cast<std::size_t>(index) >= state->items.size())
          break;
        RECT box = state->items[static_cast<std::size_t>(index)];
        OffsetRect(&box, 0, -scroll);
        draw_chip(dc, *state, chip, box, index == state->hover, index == state->focus && GetFocus() == window);
        ++index;
      }
    });
    return 0;
  case WM_SIZE:
    relayout(window, *state);
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_MOUSEMOVE: {
    if (!state->tracking) {
      TRACKMOUSEEVENT track{sizeof(track), TME_LEAVE, window, 0};
      TrackMouseEvent(&track);
      state->tracking = true;
    }
    const int hit = hit_test(*state, POINT{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
    if (hit != state->hover) {
      state->hover = hit;
      InvalidateRect(window, nullptr, FALSE);
    }
    return 0;
  }
  case WM_MOUSELEAVE:
    state->tracking = false;
    if (state->hover != -1) {
      state->hover = -1;
      InvalidateRect(window, nullptr, FALSE);
    }
    return 0;
  case WM_SETCURSOR:
    if (LOWORD(lparam) == HTCLIENT && actionable(*state, state->hover)) {
      SetCursor(LoadCursorW(nullptr, IDC_HAND));
      return TRUE;
    }
    break;
  case WM_LBUTTONDOWN:
    SetFocus(window);
    state->pressed = hit_test(*state, POINT{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
    if (actionable(*state, state->pressed)) {
      state->focus = state->pressed;
      InvalidateRect(window, nullptr, FALSE);
    }
    return 0;
  case WM_LBUTTONUP: {
    const int hit = hit_test(*state, POINT{GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam)});
    if (hit == state->pressed && actionable(*state, hit))
      activate(window, hit);
    state->pressed = -1;
    return 0;
  }
  case WM_GETDLGCODE:
    return DLGC_WANTARROWS;
  case WM_KEYDOWN: {
    int next = state->focus;
    switch (wparam) {
    case VK_LEFT: next = neighbour(*state, state->focus, 0); break;
    case VK_RIGHT: next = neighbour(*state, state->focus, 1); break;
    case VK_UP: next = neighbour(*state, state->focus, 2); break;
    case VK_DOWN: next = neighbour(*state, state->focus, 3); break;
    case VK_RETURN:
    case VK_SPACE:
      if (actionable(*state, state->focus))
        activate(window, state->focus);
      return 0;
    default:
      return scroller_message(window, state->scroller, message, wparam, scaled(*state, 40)) ? 0
                                                                                               : DefWindowProcW(window, message, wparam, lparam);
    }
    if (next != state->focus) {
      state->focus = next;
      ensure_visible(window, *state, next);
      InvalidateRect(window, nullptr, FALSE);
    }
    return 0;
  }
  case WM_SETFOCUS:
    if (!actionable(*state, state->focus))
      state->focus = neighbour(*state, -1, 1);
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_KILLFOCUS:
    InvalidateRect(window, nullptr, FALSE);
    return 0;
  case WM_NCDESTROY:
    for (HFONT font : {state->value_font, state->compact_value_font}) {
      if (font != nullptr)
        DeleteObject(font);
    }
    delete state;
    SetWindowLongPtrW(window, GWLP_USERDATA, 0);
    return DefWindowProcW(window, message, wparam, lparam);
  default:
    break;
  }
  return DefWindowProcW(window, message, wparam, lparam);
}

} // namespace

HWND create_board_panel(HWND parent, HINSTANCE instance, const BoardPanelStyle& style) {
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
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
  make_value_fonts(*state);
  HWND panel = CreateWindowExW(0, kClassName, L"", WS_CHILD | WS_TABSTOP | WS_VSCROLL, 0, 0, 0, 0, parent, nullptr,
                               instance, state);
  if (panel == nullptr) {
    for (HFONT font : {state->value_font, state->compact_value_font}) {
      if (font != nullptr)
        DeleteObject(font);
    }
    delete state;
  }
  return panel;
}

void set_board_panel_style(HWND panel, const BoardPanelStyle& style) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->style = style;
  make_value_fonts(*state);
  state->layout_width = -1;
  relayout(panel, *state);
  InvalidateRect(panel, nullptr, FALSE);
}

void set_board_panel_content(HWND panel, BoardContent content) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return;
  state->content = std::move(content);
  state->layout_width = -1;
  state->hover = -1;
  if (state->focus >= static_cast<int>(tile_count(*state) + state->content.chips.size()))
    state->focus = -1;
  relayout(panel, *state);
  // The board as text, for screen readers and UI automation.
  std::wstring text;
  for (const BoardGroup& group : state->content.groups) {
    for (const auto& tile : group.tiles)
      text += wide(tile.caption) + L": " + wide(tile.value) + L". " + wide(tile.detail) + L"\n";
  }
  SetWindowTextW(panel, text.c_str());
  InvalidateRect(panel, nullptr, FALSE);
}

int board_panel_content_height(HWND panel, int width) {
  PanelState* state = panel != nullptr ? state_of(panel) : nullptr;
  if (state == nullptr)
    return 0;
  HDC dc = GetDC(panel);
  if (dc == nullptr)
    return 0;
  const int height = layout_items(dc, *state, width);
  ReleaseDC(panel, dc);
  return height;
}
