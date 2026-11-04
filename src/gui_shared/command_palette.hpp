#pragma once

// Jump To (Ctrl+K), shared by both GUIs: pages, tools, cases and a few commands, found by typing
// part of a name. Each edition fills the entries from its own navigation, card lists and case list;
// the matching and the order are here, so the same words find the same thing on both.

#include "keyboard_shortcuts.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace support_assist::gui {

enum class PaletteKind { page, tool, case_workspace, command };

struct PaletteEntry {
  PaletteKind kind = PaletteKind::page;
  std::string title;     // what the row says
  std::string detail;    // where it lives: a tool's page, a case's folder
  std::string keywords;  // other words that find it
  int page = 0;          // the edition's own page value
  int mode = -1;         // a tool's operation mode
  std::size_t index = 0; // the edition's own handle: a card, a case or a command
};

inline std::string palette_kind_label(PaletteKind kind) {
  switch (kind) {
  case PaletteKind::page:
    return "Page";
  case PaletteKind::tool:
    return "Tool";
  case PaletteKind::case_workspace:
    return "Case";
  case PaletteKind::command:
    return "Command";
  }
  return {};
}

// The row as the list shows it: the name, then what it is and where it lives.
inline std::string palette_row_text(const PaletteEntry& entry) {
  std::string text = entry.title + "    " + palette_kind_label(entry.kind);
  if (!entry.detail.empty())
    text += ": " + entry.detail;
  return text;
}

namespace palette_detail {

inline std::string fold(std::string_view text) {
  std::string folded;
  folded.reserve(text.size());
  for (const char character : text)
    folded += (character >= 'A' && character <= 'Z') ? static_cast<char>(character - 'A' + 'a')
                                                     : character;
  return folded;
}

inline std::vector<std::string> words(std::string_view query) {
  std::vector<std::string> found;
  std::string word;
  for (const char character : query) {
    if (character == ' ' || character == '\t') {
      if (!word.empty())
        found.push_back(fold(word));
      word.clear();
    } else {
      word += character;
    }
  }
  if (!word.empty())
    found.push_back(fold(word));
  return found;
}

inline bool starts_word(const std::string& text, std::size_t at) {
  if (at == 0)
    return true;
  const char before = text[at - 1];
  return before == ' ' || before == '-' || before == '/' || before == '(' || before == '_' ||
         before == '.' || before == ':';
}

}  // namespace palette_detail

// How well an entry answers the query: 0 when it does not, higher is better. Every word typed must
// appear in the title, the detail or the keywords. A title that starts with the first word ranks
// highest, then a title word that starts with a typed word, then a match anywhere.
inline int palette_score(const PaletteEntry& entry, std::string_view query) {
  const std::vector<std::string> typed = palette_detail::words(query);
  if (typed.empty())
    return 1;
  const std::string title = palette_detail::fold(entry.title);
  const std::string rest = palette_detail::fold(entry.detail + " " + entry.keywords);
  int score = 1;
  for (std::size_t index = 0; index < typed.size(); ++index) {
    const std::string& word = typed[index];
    std::size_t at = title.find(word);
    if (at == std::string::npos) {
      if (rest.find(word) == std::string::npos)
        return 0;
      continue;
    }
    score += 2;
    if (at == 0) {
      score += index == 0 ? 10 : 4;
      continue;
    }
    // A later occurrence may start a word even when the first does not.
    bool word_start = false;
    for (; at != std::string::npos && !word_start; at = title.find(word, at + 1))
      word_start = palette_detail::starts_word(title, at);
    if (word_start)
      score += 5;
  }
  return score;
}

// The entries that answer the query, best first. Equal scores keep kind order (pages, tools,
// cases, commands) and then the order the entries were given in. At most `limit`.
inline std::vector<std::size_t> palette_matches(const std::vector<PaletteEntry>& entries,
                                                std::string_view query,
                                                std::size_t limit = 60) {
  std::vector<std::pair<int, std::size_t>> scored;
  for (std::size_t index = 0; index < entries.size(); ++index) {
    const int score = palette_score(entries[index], query);
    if (score > 0)
      scored.emplace_back(score, index);
  }
  std::stable_sort(scored.begin(), scored.end(), [&](const auto& left, const auto& right) {
    if (left.first != right.first)
      return left.first > right.first;
    return static_cast<int>(entries[left.second].kind) <
           static_cast<int>(entries[right.second].kind);
  });
  std::vector<std::size_t> order;
  for (std::size_t index = 0; index < scored.size() && index < limit; ++index)
    order.push_back(scored[index].second);
  return order;
}

// The commands both editions offer, in this order. The edition runs one by its index here.
enum class PaletteCommand {
  running_jobs,
  settings,
  user_guide,
  reset_panes,
  refresh,
  name_check,
  local_port_checker,
  time_check,
  file_lock_check,
  volume_check,
  service_watch,
  file_transfer_calculator,
};

// The quick tool a command opens, as keyboard_shortcuts.hpp names it; nullopt for the others.
inline std::optional<ShortcutCommand> palette_quick_tool(PaletteCommand command) {
  switch (command) {
  case PaletteCommand::name_check: return ShortcutCommand::name_check;
  case PaletteCommand::local_port_checker: return ShortcutCommand::local_port_checker;
  case PaletteCommand::time_check: return ShortcutCommand::time_check;
  case PaletteCommand::file_lock_check: return ShortcutCommand::file_lock_check;
  case PaletteCommand::volume_check: return ShortcutCommand::volume_check;
  case PaletteCommand::service_watch: return ShortcutCommand::service_watch;
  case PaletteCommand::file_transfer_calculator: return ShortcutCommand::file_transfer_calculator;
  case PaletteCommand::running_jobs:
  case PaletteCommand::settings:
  case PaletteCommand::user_guide:
  case PaletteCommand::reset_panes:
  case PaletteCommand::refresh: break;
  }
  return std::nullopt;
}

inline std::vector<PaletteEntry> palette_commands() {
  const std::tuple<PaletteCommand, const char*, const char*> commands[] = {
      {PaletteCommand::running_jobs, "Running Jobs", "sessions progress cancel"},
      {PaletteCommand::settings, "Settings", "preferences options colour color scheme font keyboard shortcuts keys"},
      {PaletteCommand::user_guide, "User Guide", "help documentation"},
      {PaletteCommand::reset_panes, "Reset Pane Layout", "dividers layout"},
      {PaletteCommand::refresh, "Refresh", "reload"},
      {PaletteCommand::name_check, "", "dns resolve nslookup host reverse ptr hosts file"},
      {PaletteCommand::local_port_checker, "", "ports listening netstat firewall listener process"},
      {PaletteCommand::time_check, "", "ntp sntp clock skew kerberos time zone timestamp convert"},
      {PaletteCommand::file_lock_check, "", "locked open handle in use process holds"},
      {PaletteCommand::volume_check, "", "refs xfs fast clone block cloning file system cluster size dedup"},
      {PaletteCommand::service_watch, "", "services processes monitor started stopped ended"},
      {PaletteCommand::file_transfer_calculator, "",
       "transfer time bandwidth throughput link speed gigabit terabyte mtu jumbo email estimate"},
  };
  std::vector<PaletteEntry> entries;
  for (const auto& [command, title, keywords] : commands) {
    PaletteEntry entry;
    entry.kind = PaletteKind::command;
    entry.title = title;
    entry.keywords = keywords;
    if (const auto tool = palette_quick_tool(command)) {
      if (const KeyboardShortcut* shortcut = shortcut_for(*tool)) {
        entry.title = std::string(shortcut->label);
        entry.detail = "Quick tool, " + chord_text(shortcut->chord);
      }
    }
    entry.index = static_cast<std::size_t>(command);
    entries.push_back(std::move(entry));
  }
  return entries;
}

}  // namespace support_assist::gui
