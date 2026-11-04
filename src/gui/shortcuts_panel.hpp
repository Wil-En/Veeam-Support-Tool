#pragma once

// Settings > Keyboard Shortcuts on Windows: a scrolling panel that draws each shortcut group from
// gui_shared/keyboard_shortcuts.hpp as a card, with each shortcut's keys drawn as key caps beside
// its name and a line of detail.

#include <winsock2.h>
#include <windows.h>

struct ShortcutsPanelStyle {
  HFONT title = nullptr;  // a group's title
  HFONT label = nullptr;  // a shortcut's name
  HFONT detail = nullptr; // the line under it and the group's note; the key caps use it in semibold
  int scale_percent = 100;
};

HWND create_shortcuts_panel(HWND parent, HINSTANCE instance, const ShortcutsPanelStyle& style);
// New fonts or text scale. Call before the previous fonts are deleted.
void set_shortcuts_panel_style(HWND panel, const ShortcutsPanelStyle& style);
