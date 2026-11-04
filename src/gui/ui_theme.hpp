#pragma once

// The colour scheme the Windows edition draws in (Settings > General > Colour scheme).
//
// Every colour in the frontend is written in the Veeam Green palette and passed through themed()
// where it is used, so a scheme needs no second palette: gui_shared/color_scheme.hpp derives each
// colour. The log viewer and the Remote terminal keep their own dark palettes in every scheme, as
// code views and terminals usually do.

#include "color_scheme.hpp"

// Winsock2 before windows.h, as app_window.hpp requires of every GUI translation unit.
#include <winsock2.h>
#include <windows.h>
#include <uxtheme.h>

#include <algorithm>
#include <unordered_map>
#include <utility>
#include <vector>

namespace sat_theme {

inline support_assist::gui::ColorScheme& scheme() {
  static support_assist::gui::ColorScheme current = support_assist::gui::ColorScheme::veeam_green;
  return current;
}

// Colours shown under the current or an earlier scheme, back to the Veeam Green colour each came
// from, so a control that holds a colour of its own can be re-coloured when the scheme changes.
inline std::unordered_map<COLORREF, COLORREF>& shown_to_base() {
  static std::unordered_map<COLORREF, COLORREF> map;
  return map;
}

inline COLORREF base_of(COLORREF shown) {
  const auto found = shown_to_base().find(shown);
  return found == shown_to_base().end() ? shown : found->second;
}

// Controls given the application's control theme, and whether each is a combo box, so a scheme
// change can give them the other one.
inline std::vector<std::pair<HWND, bool>>& themed_controls() {
  static std::vector<std::pair<HWND, bool>> controls;
  return controls;
}

}  // namespace sat_theme

// A Veeam Green colour in the current scheme.
inline COLORREF themed(COLORREF color) {
  const auto current = sat_theme::scheme();
  if (current == support_assist::gui::ColorScheme::veeam_green)
    return color;
  const auto mapped = support_assist::gui::scheme_color(
      {GetRValue(color), GetGValue(color), GetBValue(color)}, current);
  const COLORREF shown = RGB(mapped.red, mapped.green, mapped.blue);
  sat_theme::shown_to_base().try_emplace(shown, color);
  return shown;
}

inline bool themed_is_light() {
  return support_assist::gui::color_scheme_is_light(sat_theme::scheme());
}

// The DWMWA_USE_IMMERSIVE_DARK_MODE value for a window's title bar.
inline BOOL themed_title_bar_dark() { return themed_is_light() ? FALSE : TRUE; }

// Scroll bars, buttons and list chrome: the dark control theme on the dark schemes, the standard
// one on Light.
inline void apply_control_theme(HWND control, bool combo = false) {
  if (control == nullptr)
    return;
  const wchar_t* name = combo ? (themed_is_light() ? L"CFD" : L"DarkMode_CFD")
                              : (themed_is_light() ? L"Explorer" : L"DarkMode_Explorer");
  SetWindowTheme(control, name, nullptr);
  auto& controls = sat_theme::themed_controls();
  if (std::none_of(controls.begin(), controls.end(),
                   [control](const auto& entry) { return entry.first == control; }))
    controls.emplace_back(control, combo);
}

// A brush in the current scheme for a Veeam Green colour, for WM_CTLCOLOR* replies that must
// outlive the message. One brush per colour, kept for the life of the process.
inline HBRUSH themed_brush(COLORREF base) {
  static std::unordered_map<COLORREF, HBRUSH> brushes;
  const COLORREF shown = themed(base);
  const auto found = brushes.find(shown);
  if (found != brushes.end())
    return found->second;
  HBRUSH brush = CreateSolidBrush(shown);
  brushes.emplace(shown, brush);
  return brush;
}
