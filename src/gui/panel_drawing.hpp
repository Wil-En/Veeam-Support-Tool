#pragma once

// GDI helpers the custom-drawn panels share (shortcuts_panel.cpp, report_panel.cpp): text
// measured and drawn in a given font, and rounded boxes.

#include <winsock2.h>
#include <windows.h>

#include <algorithm>
#include <string>

namespace panel_drawing {

inline SIZE text_size(HDC dc, HFONT font, const std::wstring& text) {
  const HGDIOBJ previous = SelectObject(dc, font);
  SIZE size{};
  GetTextExtentPoint32W(dc, text.c_str(), static_cast<int>(text.size()), &size);
  SelectObject(dc, previous);
  return size;
}

inline int line_height(HDC dc, HFONT font) {
  TEXTMETRICW metrics{};
  const HGDIOBJ previous = SelectObject(dc, font);
  GetTextMetricsW(dc, &metrics);
  SelectObject(dc, previous);
  return static_cast<int>(metrics.tmHeight);
}

inline int wrapped_height(HDC dc, HFONT font, const std::wstring& text, int width) {
  if (text.empty())
    return 0;
  const HGDIOBJ previous = SelectObject(dc, font);
  RECT box{0, 0, std::max(1, width), 0};
  DrawTextW(dc, text.c_str(), -1, &box, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX | DT_EDITCONTROL);
  SelectObject(dc, previous);
  return static_cast<int>(box.bottom - box.top);
}

inline void draw_text(HDC dc, HFONT font, COLORREF color, const std::wstring& text, RECT box, UINT format) {
  const HGDIOBJ previous = SelectObject(dc, font);
  SetTextColor(dc, color);
  DrawTextW(dc, text.c_str(), -1, &box, format | DT_NOPREFIX);
  SelectObject(dc, previous);
}

inline void round_box(HDC dc, const RECT& box, COLORREF fill, COLORREF border, int radius) {
  HBRUSH brush = CreateSolidBrush(fill);
  HPEN pen = CreatePen(PS_SOLID, 1, border);
  const HGDIOBJ previous_brush = SelectObject(dc, brush);
  const HGDIOBJ previous_pen = SelectObject(dc, pen);
  RoundRect(dc, box.left, box.top, box.right, box.bottom, radius, radius);
  SelectObject(dc, previous_brush);
  SelectObject(dc, previous_pen);
  DeleteObject(brush);
  DeleteObject(pen);
}

inline void horizontal_rule(HDC dc, int left, int right, int y, COLORREF color) {
  HPEN pen = CreatePen(PS_SOLID, 1, color);
  const HGDIOBJ previous = SelectObject(dc, pen);
  MoveToEx(dc, left, y, nullptr);
  LineTo(dc, right, y);
  SelectObject(dc, previous);
  DeleteObject(pen);
}

// Vertical scrolling of a custom-drawn panel: its WS_VSCROLL bar, the wheel, and the arrow, page,
// Home and End keys.
struct Scroller {
  int position = 0;
  int content = 0; // the content's height
};

inline int client_height(HWND window) {
  RECT client{};
  GetClientRect(window, &client);
  return static_cast<int>(client.bottom);
}

inline void scroller_update(HWND window, Scroller& scroller, int content_height) {
  scroller.content = content_height;
  const int page = client_height(window);
  scroller.position = std::clamp(scroller.position, 0, std::max(0, scroller.content - page));
  SCROLLINFO info{};
  info.cbSize = sizeof(info);
  info.fMask = SIF_RANGE | SIF_PAGE | SIF_POS;
  info.nMin = 0;
  info.nMax = std::max(0, scroller.content - 1);
  info.nPage = static_cast<UINT>(std::max(0, page));
  info.nPos = scroller.position;
  SetScrollInfo(window, SB_VERT, &info, TRUE);
}

inline void scroller_to(HWND window, Scroller& scroller, int position) {
  const int limit = std::max(0, scroller.content - client_height(window));
  const int next = std::clamp(position, 0, limit);
  if (next == scroller.position)
    return;
  scroller.position = next;
  SetScrollPos(window, SB_VERT, scroller.position, TRUE);
  InvalidateRect(window, nullptr, FALSE);
}

// Handles the scrolling messages; true when the message was one of them.
inline bool scroller_message(HWND window, Scroller& scroller, UINT message, WPARAM wparam, int line) {
  const int page = client_height(window);
  switch (message) {
  case WM_VSCROLL: {
    SCROLLINFO info{};
    info.cbSize = sizeof(info);
    info.fMask = SIF_ALL;
    GetScrollInfo(window, SB_VERT, &info);
    int position = scroller.position;
    switch (LOWORD(wparam)) {
    case SB_LINEUP: position -= line; break;
    case SB_LINEDOWN: position += line; break;
    case SB_PAGEUP: position -= page; break;
    case SB_PAGEDOWN: position += page; break;
    case SB_THUMBTRACK:
    case SB_THUMBPOSITION: position = info.nTrackPos; break;
    case SB_TOP: position = 0; break;
    case SB_BOTTOM: position = scroller.content; break;
    default: break;
    }
    scroller_to(window, scroller, position);
    return true;
  }
  case WM_MOUSEWHEEL:
    // With nothing to scroll, the wheel is left to DefWindowProc, which hands it to the parent.
    if (scroller.content <= page)
      return false;
    scroller_to(window, scroller, scroller.position - GET_WHEEL_DELTA_WPARAM(wparam) / WHEEL_DELTA * line * 3 / 2);
    return true;
  case WM_KEYDOWN:
    switch (wparam) {
    case VK_UP: scroller_to(window, scroller, scroller.position - line); return true;
    case VK_DOWN: scroller_to(window, scroller, scroller.position + line); return true;
    case VK_PRIOR: scroller_to(window, scroller, scroller.position - page); return true;
    case VK_NEXT: scroller_to(window, scroller, scroller.position + page); return true;
    case VK_HOME: scroller_to(window, scroller, 0); return true;
    case VK_END: scroller_to(window, scroller, scroller.content); return true;
    default: return false;
    }
  default:
    return false;
  }
}

// Paints through a memory bitmap the size of the client area, so a repaint does not flicker.
template <typename Paint> void buffered_paint(HWND window, COLORREF background, Paint paint) {
  PAINTSTRUCT paint_info{};
  HDC target = BeginPaint(window, &paint_info);
  RECT client{};
  GetClientRect(window, &client);
  if (client.right > 0 && client.bottom > 0) {
    HDC memory = CreateCompatibleDC(target);
    HBITMAP bitmap = CreateCompatibleBitmap(target, client.right, client.bottom);
    const HGDIOBJ previous_bitmap = SelectObject(memory, bitmap);
    HBRUSH fill = CreateSolidBrush(background);
    FillRect(memory, &client, fill);
    DeleteObject(fill);
    SetBkMode(memory, TRANSPARENT);
    paint(memory, client);
    BitBlt(target, 0, 0, client.right, client.bottom, memory, 0, 0, SRCCOPY);
    SelectObject(memory, previous_bitmap);
    DeleteObject(bitmap);
    DeleteDC(memory);
  }
  EndPaint(window, &paint_info);
}

} // namespace panel_drawing
