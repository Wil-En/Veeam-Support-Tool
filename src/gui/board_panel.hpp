#pragma once

// The status board on Windows: groups of tiles from gui_shared/home_board.hpp and rows of link
// chips, drawn in one control. Home uses it in both roles and the Tools pages for their category
// tiles. A click, Enter or Space on an item posts kBoardActivateMessage to the parent with the
// item's index: the tiles in reading order across the groups, then the chips.

#include "home_board.hpp"

#include <winsock2.h>
#include <windows.h>

#include <functional>
#include <string>
#include <utility>
#include <vector>

struct BoardPanelStyle {
  HFONT caption = nullptr; // captions and chip keys
  HFONT text = nullptr;    // details and chips
  HFONT heading = nullptr; // group captions; values use a larger face derived from it
  int scale_percent = 100;
};

struct BoardGroup {
  std::wstring caption; // "THIS MACHINE'S HEALTH"; empty for none
  int columns = 3;
  bool compact = false; // caption, value and one line, with the pill beside the caption
  std::vector<support_assist::gui::BoardTile> tiles;
  bool compact_when_short = false; // compact while the content is taller than the panel
};

// Chips run left to right and wrap when a row is full.
struct BoardChip {
  std::wstring label;
  std::wstring key;  // drawn in a small key cap after the label: "F2"
  std::wstring note; // drawn after a primary chip
  bool primary = false;
  bool right = false;       // at the right end of its row
  bool new_row = false;     // starts a new row
  std::wstring row_caption; // drawn above a row that starts here
};

struct BoardContent {
  std::vector<BoardGroup> groups;
  std::vector<BoardChip> chips;
  // A case status's pill colours: fill, then text.
  std::function<std::pair<COLORREF, COLORREF>(const std::string& status)> pill_colours;
};

inline constexpr UINT kBoardActivateMessage = WM_APP + 60; // wparam: item index; lparam: the panel

HWND create_board_panel(HWND parent, HINSTANCE instance, const BoardPanelStyle& style);
void set_board_panel_style(HWND panel, const BoardPanelStyle& style);
void set_board_panel_content(HWND panel, BoardContent content);
// The height the content needs at this width, for the parent's layout.
int board_panel_content_height(HWND panel, int width);
