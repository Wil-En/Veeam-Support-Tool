#pragma once

// The keyboard shortcuts of both editions (docs/PROPOSAL_5.x_CHECKS.md section 9).
//
// - Main-window keys: each edition maps a key press through main_window_command() (the Windows
//   message loop; the Qt menu actions and shortcuts).
// - Log viewer and Remote terminal keys: handled by those views, listed here as they behave.
// - Settings > Keyboard Shortcuts draws the groups below on both editions, and
//   tools/test_navigation_parity.py checks both editions dispatch every main-window command.
// While the Remote (SSH) terminal has focus, main-window keys go to the remote program, and each
// terminal sends F1 to F12 as xterm does.

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

enum class ShortcutGroup { anywhere, quick_tools, log_viewer, remote_terminal, fields_and_tables };

enum class ShortcutCommand {
  // Dispatched by the main window of each edition.
  help,
  refresh,
  jump_to,
  full_screen,
  text_larger,
  text_smaller,
  text_reset,
  name_check,
  local_port_checker,
  time_check,
  file_lock_check,
  volume_check,
  service_watch,
  file_transfer_calculator,
  // A window without a key: opened from its Tools card.
  object_storage_check,
  // Handled where they apply, listed for the page and the guides.
  viewer_find,
  viewer_next_match,
  viewer_previous_match,
  viewer_close_find,
  viewer_go_to_line,
  viewer_next_issue,
  viewer_previous_issue,
  viewer_mark_all,
  viewer_clear_marks,
  viewer_add_to_case,
  viewer_top,
  viewer_bottom,
  terminal_copy,
  terminal_paste,
  terminal_interrupt,
  next_field,
  previous_field,
  submit_field,
  clear_filter,
  select_all,
  copy,
  paste,
};

enum class KeyName {
  none, f1, f2, f3, f4, f5, f6, f7, f8, f9, f10, f11, f12,
  a, b, c, f, g, k, m, v, zero, plus, minus,
  escape, tab, enter, home, end, up, down,
};

struct KeyChord {
  KeyName key = KeyName::none;
  bool ctrl = false;
  bool shift = false;
  bool alt = false;
};

inline constexpr KeyChord chord(KeyName key, bool ctrl = false, bool shift = false, bool alt = false) {
  KeyChord made;
  made.key = key;
  made.ctrl = ctrl;
  made.shift = shift;
  made.alt = alt;
  return made;
}

struct KeyboardShortcut {
  ShortcutCommand command;
  ShortcutGroup group;
  KeyChord chord;
  std::string_view label;
  std::string_view detail;
  bool main_window = false; // dispatched from the main window's key handling
};

inline std::string_view key_name_text(KeyName key) {
  switch (key) {
  case KeyName::f1: return "F1";
  case KeyName::f2: return "F2";
  case KeyName::f3: return "F3";
  case KeyName::f4: return "F4";
  case KeyName::f5: return "F5";
  case KeyName::f6: return "F6";
  case KeyName::f7: return "F7";
  case KeyName::f8: return "F8";
  case KeyName::f9: return "F9";
  case KeyName::f10: return "F10";
  case KeyName::f11: return "F11";
  case KeyName::f12: return "F12";
  case KeyName::a: return "A";
  case KeyName::b: return "B";
  case KeyName::c: return "C";
  case KeyName::f: return "F";
  case KeyName::g: return "G";
  case KeyName::k: return "K";
  case KeyName::m: return "M";
  case KeyName::v: return "V";
  case KeyName::zero: return "0";
  case KeyName::plus: return "+";
  case KeyName::minus: return "-";
  case KeyName::escape: return "Esc";
  case KeyName::tab: return "Tab";
  case KeyName::enter: return "Enter";
  case KeyName::home: return "Home";
  case KeyName::end: return "End";
  case KeyName::up: return "Up";
  case KeyName::down: return "Down";
  case KeyName::none: break;
  }
  return "";
}

// The keys to draw, in the order they are pressed: {"Ctrl", "Shift", "M"}.
inline std::vector<std::string> key_caps(const KeyChord& chord) {
  std::vector<std::string> caps;
  if (chord.ctrl)
    caps.emplace_back("Ctrl");
  if (chord.alt)
    caps.emplace_back("Alt");
  if (chord.shift)
    caps.emplace_back("Shift");
  caps.emplace_back(key_name_text(chord.key));
  return caps;
}

// "Ctrl+Shift+M", as menus and the guides write a key.
inline std::string chord_text(const KeyChord& chord) {
  std::string text;
  for (const std::string& cap : key_caps(chord))
    text += (text.empty() ? "" : "+") + cap;
  return text;
}

inline const std::vector<KeyboardShortcut>& keyboard_shortcuts() {
  using C = ShortcutCommand;
  using G = ShortcutGroup;
  using K = KeyName;
  static const std::vector<KeyboardShortcut> list{
      {C::help, G::anywhere, chord(K::f1), "Help for this page", "Opens the page's article in the Help window.", true},
      {C::refresh, G::anywhere, chord(K::f5), "Refresh", "Reloads the page in view.", true},
      {C::jump_to, G::anywhere, chord(K::k, true), "Jump To",
       "Finds a page, a tool, a case or a command as you type.", true},
      {C::full_screen, G::anywhere, chord(K::f11), "Full screen", "Fills the screen; press it again to return.", true},
      {C::text_larger, G::anywhere, chord(K::plus, true), "Larger text", "Ctrl+= works too. Up to 200%.", true},
      {C::text_smaller, G::anywhere, chord(K::minus, true), "Smaller text", "Down to 70%.", true},
      {C::text_reset, G::anywhere, chord(K::zero, true), "Text at 100%", "Puts the text scale back.", true},

      {C::name_check, G::quick_tools, chord(K::f2), "Name Check",
       "What a name resolves to here, and where the answer came from.", true},
      {C::local_port_checker, G::quick_tools, chord(K::f6), "Local Port Checker",
       "Ports on this machine: the process on each, and the firewall's verdict.", true},
      {C::time_check, G::quick_tools, chord(K::f7), "Time Check",
       "This clock against its time source, and a timestamp converter.", true},
      {C::file_lock_check, G::quick_tools, chord(K::f8), "File Lock Check",
       "Which process holds a file open, or anything under a folder.", true},
      {C::volume_check, G::quick_tools, chord(K::f9), "Volume Check",
       "Every volume, what it sits on, and whether Fast Clone can work there.", true},
      {C::file_transfer_calculator, G::quick_tools, chord(K::f10), "File Transfer Calculator",
       "How long a transfer takes over a link, worked out step by step, with text for an email.", true},
      {C::service_watch, G::quick_tools, chord(K::f12), "Service and Process Watch",
       "Veeam's services and processes as they start, stop and end, with their ports.", true},

      {C::viewer_find, G::log_viewer, chord(K::f, true), "Find", "Opens the find box.", false},
      {C::viewer_next_match, G::log_viewer, chord(K::f3), "Next match", "Enter in the find box does the same.", false},
      {C::viewer_previous_match, G::log_viewer, chord(K::f3, false, true), "Previous match",
       "Shift+Enter in the find box does the same.", false},
      {C::viewer_close_find, G::log_viewer, chord(K::escape), "Close find", "Closes the find box.", false},
      {C::viewer_go_to_line, G::log_viewer, chord(K::g, true), "Go to line", "Moves to a line number.", false},
      {C::viewer_next_issue, G::log_viewer, chord(K::down, false, false, true), "Next error or warning",
       "Steps to the next line marked as an error or a warning.", false},
      {C::viewer_previous_issue, G::log_viewer, chord(K::up, false, false, true), "Previous error or warning",
       "Steps back to the previous one.", false},
      {C::viewer_mark_all, G::log_viewer, chord(K::m, true), "Mark this value",
       "Marks every occurrence of the value at the cursor. A double-click does the same.", false},
      {C::viewer_clear_marks, G::log_viewer, chord(K::m, true, true), "Clear marks", "Removes the marks.", false},
      {C::viewer_add_to_case, G::log_viewer, chord(K::b, true), "Add to case", "Adds the line to the active case.", false},
      {C::viewer_top, G::log_viewer, chord(K::home, true), "Start of the log", "Moves to the first line.", false},
      {C::viewer_bottom, G::log_viewer, chord(K::end, true), "End of the log", "Moves to the last line.", false},

      {C::terminal_copy, G::remote_terminal, chord(K::c, true, true), "Copy", "Copies the selected text.", false},
      {C::terminal_paste, G::remote_terminal, chord(K::v, true, true), "Paste",
       "Types the clipboard into the remote program.", false},
      {C::terminal_interrupt, G::remote_terminal, chord(K::c, true), "Interrupt",
       "Sent to the remote program, as in any terminal.", false},

      {C::next_field, G::fields_and_tables, chord(K::tab), "Next field", "Moves to the next control.", false},
      {C::previous_field, G::fields_and_tables, chord(K::tab, false, true), "Previous field",
       "Moves to the previous control.", false},
      {C::submit_field, G::fields_and_tables, chord(K::enter), "Run or go",
       "Runs the command, or opens the path, typed in the field.", false},
      {C::clear_filter, G::fields_and_tables, chord(K::escape), "Clear the filter",
       "Empties the filter box that has the focus.", false},
      {C::select_all, G::fields_and_tables, chord(K::a, true), "Select all", "Every row of a table, or all the text.",
       false},
      {C::copy, G::fields_and_tables, chord(K::c, true), "Copy",
       "The selected rows with their column headers, or the selected text.", false},
      {C::paste, G::fields_and_tables, chord(K::v, true), "Paste", "Into the field that has the focus.", false},
  };
  return list;
}

inline constexpr ShortcutGroup kShortcutGroups[] = {ShortcutGroup::anywhere, ShortcutGroup::quick_tools,
                                                    ShortcutGroup::log_viewer, ShortcutGroup::remote_terminal,
                                                    ShortcutGroup::fields_and_tables};

inline std::string_view shortcut_group_title(ShortcutGroup group) {
  switch (group) {
  case ShortcutGroup::anywhere: return "Anywhere in SAT";
  case ShortcutGroup::quick_tools: return "Quick tools";
  case ShortcutGroup::log_viewer: return "Log viewer";
  case ShortcutGroup::remote_terminal: return "Remote (SSH) terminal";
  case ShortcutGroup::fields_and_tables: return "Fields and tables";
  }
  return "";
}

inline std::string_view shortcut_group_note(ShortcutGroup group) {
  switch (group) {
  case ShortcutGroup::anywhere: return "In every SAT window.";
  case ShortcutGroup::quick_tools:
    return "Each opens its tool in a window of its own, in both roles, or brings that window to the front.";
  case ShortcutGroup::log_viewer: return "In a log opened from Log Review, Search Existing Logs or File Browser.";
  case ShortcutGroup::remote_terminal:
    return "While the terminal has the focus, every other key, function keys and Ctrl+K included, goes to the "
           "remote program.";
  case ShortcutGroup::fields_and_tables: return "Wherever there is a field, a list or a table.";
  }
  return "";
}

inline std::vector<const KeyboardShortcut*> shortcuts_in_group(ShortcutGroup group) {
  std::vector<const KeyboardShortcut*> found;
  for (const KeyboardShortcut& shortcut : keyboard_shortcuts()) {
    if (shortcut.group == group)
      found.push_back(&shortcut);
  }
  return found;
}

// The groups split into columns, each group to the column that is shortest so far, measured in
// rows (a group's title counts as two), so both editions lay the page out the same way.
inline std::vector<std::vector<ShortcutGroup>> arrange_shortcut_groups(std::size_t columns) {
  columns = std::max<std::size_t>(1, columns);
  std::vector<std::vector<ShortcutGroup>> arranged(columns);
  std::vector<std::size_t> heights(columns, 0);
  for (const ShortcutGroup group : kShortcutGroups) {
    const auto shortest = static_cast<std::size_t>(std::min_element(heights.begin(), heights.end()) - heights.begin());
    arranged[shortest].push_back(group);
    heights[shortest] += shortcuts_in_group(group).size() + 2;
  }
  return arranged;
}

// The main-window command a key press means, or none. Ctrl with the + key counts with or without
// Shift, so Ctrl+= on a US keyboard and the keypad's + both enlarge the text.
inline std::optional<ShortcutCommand> main_window_command(KeyName key, bool ctrl, bool shift, bool alt) {
  for (const KeyboardShortcut& shortcut : keyboard_shortcuts()) {
    if (!shortcut.main_window || shortcut.chord.key != key || shortcut.chord.ctrl != ctrl ||
        shortcut.chord.alt != alt)
      continue;
    if (key != KeyName::plus && shortcut.chord.shift != shift)
      continue;
    return shortcut.command;
  }
  return std::nullopt;
}

inline const KeyboardShortcut* shortcut_for(ShortcutCommand command) {
  for (const KeyboardShortcut& shortcut : keyboard_shortcuts()) {
    if (shortcut.command == command)
      return &shortcut;
  }
  return nullptr;
}

// "Ctrl+K" for a command, for menu labels; empty when it has no key.
inline std::string shortcut_text(ShortcutCommand command) {
  const KeyboardShortcut* shortcut = shortcut_for(command);
  return shortcut == nullptr ? std::string() : chord_text(shortcut->chord);
}

// What xterm sends for F1 to F12, so a remote program (htop, mc) receives the key.
inline std::string function_key_sequence(int number) {
  switch (number) {
  case 1: return "\x1bOP";
  case 2: return "\x1bOQ";
  case 3: return "\x1bOR";
  case 4: return "\x1bOS";
  case 5: return "\x1b[15~";
  case 6: return "\x1b[17~";
  case 7: return "\x1b[18~";
  case 8: return "\x1b[19~";
  case 9: return "\x1b[20~";
  case 10: return "\x1b[21~";
  case 11: return "\x1b[23~";
  case 12: return "\x1b[24~";
  default: return {};
  }
}

} // namespace support_assist::gui
