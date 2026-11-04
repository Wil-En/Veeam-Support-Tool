#pragma once

// SAT's visual identity, expressed for Qt.
//
// Every value here is copied from the Windows frontend so the Linux edition is recognisably the
// same product. The source of truth is SAT-v0.4.8-src/src/gui/app_window.cpp; the line references
// are given so a future change on Windows can be mirrored here instead of guessed at.
//
//   create_brushes()            background RGB(7,24,26)   panel RGB(10,38,39)   input RGB(22,42,44)
//                               accent RGB(85,190,88)     selected RGB(25,74,60) card RGB(18,48,49)
//   draw_navigation_item()      selected text RGB(128,228,122), item text RGB(223,235,229),
//                               section text RGB(126,164,153), 5px accent bar on the selected row
//   draw_card()                 border RGB(43,86,78), focus border RGB(101,215,98),
//                               badge text RGB(6,28,25), title RGB(244,249,246),
//                               description RGB(176,196,188), chevron RGB(116,218,112)
//   handle_control_color()      headings RGB(114,224,106), brand title RGB(248,252,250),
//                               subtitles RGB(165,188,178), body RGB(224,236,230),
//                               review badge RGB(114,224,106) on card, execution badge
//                               RGB(255,199,91) on RGB(74,52,16)
//
// SAT is green on near-black. An earlier revision of this file used the teal constants from the log
// viewer's ListView colouring, which produced a window that did not look like the product at all.
//
// Colour schemes (Settings > General > Colour scheme): the palette below is Veeam Green, the one
// every screen is written in. apply_color_scheme() points each name at its value in another scheme,
// derived by gui_shared/color_scheme.hpp as on Windows, and stylesheet() maps its colours the same
// way. The terminal keeps its dark palette in every scheme.

#include "color_scheme.hpp"

#include <QBrush>
#include <QColor>
#include <QRegularExpression>
#include <QString>
#include <QTableWidget>
#include <QWidget>

#include <array>
#include <iterator>
#include <optional>
#include <string>

namespace support_assist::gui::theme {

// The Veeam Green palette.
namespace veeam_green {
inline constexpr const char* background = "#07181A";
inline constexpr const char* panel = "#0A2627";
inline constexpr const char* input = "#162A2C";
inline constexpr const char* accent = "#55BE58";
inline constexpr const char* selected = "#194A3C";
inline constexpr const char* card = "#123031";
inline constexpr const char* card_border = "#2B564E";
inline constexpr const char* card_focus_border = "#65D762";

inline constexpr const char* heading = "#72E06A";
inline constexpr const char* nav_text = "#DFEBE5";
inline constexpr const char* nav_text_selected = "#80E47A";
inline constexpr const char* nav_child_text = "#C1D8CF";
inline constexpr const char* nav_hover = "#0E3030";
inline constexpr const char* nav_section = "#7EA499";
inline constexpr const char* brand_title = "#F8FCFA";
inline constexpr const char* subtitle = "#A5BCB2";
inline constexpr const char* body = "#E0ECE6";
inline constexpr const char* card_title = "#F4F9F6";
inline constexpr const char* card_description = "#B0C4BC";
inline constexpr const char* badge_text = "#061C19";
inline constexpr const char* chevron = "#74DA70";

inline constexpr const char* warning = "#FFC75B";
inline constexpr const char* warning_fill = "#4A3410";
inline constexpr const char* error = "#FF7070";
}  // namespace veeam_green

// The palette in the scheme in force. Each name holds its Veeam Green value until
// apply_color_scheme() points it at the value for another scheme.
inline const char* background = veeam_green::background;
inline const char* panel = veeam_green::panel;
inline const char* input = veeam_green::input;
inline const char* accent = veeam_green::accent;
inline const char* selected = veeam_green::selected;
inline const char* card = veeam_green::card;
inline const char* card_border = veeam_green::card_border;
inline const char* card_focus_border = veeam_green::card_focus_border;

inline const char* heading = veeam_green::heading;
inline const char* nav_text = veeam_green::nav_text;
inline const char* nav_text_selected = veeam_green::nav_text_selected;
inline const char* nav_child_text = veeam_green::nav_child_text;
inline const char* nav_hover = veeam_green::nav_hover;
inline const char* nav_section = veeam_green::nav_section;
inline const char* brand_title = veeam_green::brand_title;
inline const char* subtitle = veeam_green::subtitle;
inline const char* body = veeam_green::body;
inline const char* card_title = veeam_green::card_title;
inline const char* card_description = veeam_green::card_description;
inline const char* badge_text = veeam_green::badge_text;
inline const char* chevron = veeam_green::chevron;

inline const char* warning = veeam_green::warning;
inline const char* warning_fill = veeam_green::warning_fill;
inline const char* error = veeam_green::error;

inline ColorScheme& current_scheme() {
  static ColorScheme scheme = ColorScheme::veeam_green;
  return scheme;
}

// A Veeam Green "#RRGGBB" in the scheme in force.
inline QString themed_hex(const char* veeam_green_hex) {
  return QString::fromStdString(scheme_hex(veeam_green_hex, current_scheme()));
}

// A Veeam Green colour in the scheme in force.
inline QColor themed_color(const QColor& color) {
  const SchemeRgb mapped = scheme_color({static_cast<std::uint8_t>(color.red()),
                                         static_cast<std::uint8_t>(color.green()),
                                         static_cast<std::uint8_t>(color.blue())},
                                        current_scheme());
  return QColor(mapped.red, mapped.green, mapped.blue, color.alpha());
}

// Points every palette name at its value in `scheme`.
inline void apply_color_scheme(ColorScheme scheme) {
  current_scheme() = scheme;
  struct Entry {
    const char** name;
    const char* base;
  };
  static const Entry entries[] = {
      {&background, veeam_green::background},
      {&panel, veeam_green::panel},
      {&input, veeam_green::input},
      {&accent, veeam_green::accent},
      {&selected, veeam_green::selected},
      {&card, veeam_green::card},
      {&card_border, veeam_green::card_border},
      {&card_focus_border, veeam_green::card_focus_border},
      {&heading, veeam_green::heading},
      {&nav_text, veeam_green::nav_text},
      {&nav_text_selected, veeam_green::nav_text_selected},
      {&nav_child_text, veeam_green::nav_child_text},
      {&nav_hover, veeam_green::nav_hover},
      {&nav_section, veeam_green::nav_section},
      {&brand_title, veeam_green::brand_title},
      {&subtitle, veeam_green::subtitle},
      {&body, veeam_green::body},
      {&card_title, veeam_green::card_title},
      {&card_description, veeam_green::card_description},
      {&badge_text, veeam_green::badge_text},
      {&chevron, veeam_green::chevron},
      {&warning, veeam_green::warning},
      {&warning_fill, veeam_green::warning_fill},
      {&error, veeam_green::error},
  };
  static std::array<std::string, std::size(entries)> storage;
  for (std::size_t index = 0; index < std::size(entries); ++index) {
    storage[index] = scheme_hex(entries[index].base, scheme);
    *entries[index].name = storage[index].c_str();
  }
}

// The Veeam Green colour that `shown` stands for in `scheme`: any colour when `scheme` is Veeam
// Green, a colour of the designed palette otherwise. Empty when it cannot be told.
inline std::optional<SchemeRgb> base_of_shown(SchemeRgb shown, ColorScheme scheme) {
  if (scheme == ColorScheme::veeam_green) {
    return shown;
  }
  std::optional<SchemeRgb> found;
  for (const auto& entry : color_scheme_detail::kDesigned) {
    const SchemeRgb value = scheme == ColorScheme::dark ? entry.dark : entry.light;
    if (!(value == shown)) {
      continue;
    }
    if (found.has_value() && !(*found == entry.veeam_green)) {
      return std::nullopt;
    }
    found = entry.veeam_green;
  }
  return found;
}

// A colour drawn in `from`, as `to` draws it. A colour that cannot be traced back is left as it is.
inline QColor rescheme_color(const QColor& color, ColorScheme from, ColorScheme to) {
  const auto base = base_of_shown({static_cast<std::uint8_t>(color.red()),
                                   static_cast<std::uint8_t>(color.green()),
                                   static_cast<std::uint8_t>(color.blue())},
                                  from);
  if (!base.has_value()) {
    return color;
  }
  const SchemeRgb mapped = scheme_color(*base, to);
  return QColor(mapped.red, mapped.green, mapped.blue, color.alpha());
}

// Every "#RRGGBB" in a stylesheet, from one scheme to another.
inline QString rescheme_sheet(const QString& sheet, ColorScheme from, ColorScheme to) {
  static const QRegularExpression hex(QStringLiteral("#[0-9A-Fa-f]{6}(?![0-9A-Fa-f])"));
  QString mapped;
  qsizetype last = 0;
  auto matches = hex.globalMatch(sheet);
  while (matches.hasNext()) {
    const auto match = matches.next();
    mapped += sheet.mid(last, match.capturedStart() - last);
    const QColor original(match.captured());
    const QColor changed = rescheme_color(original, from, to);
    mapped += changed == original ? match.captured() : changed.name(QColor::HexRgb).toUpper();
    last = match.capturedEnd();
  }
  mapped += sheet.mid(last);
  return mapped;
}

// Re-colours a widget and everything in it that was drawn in `from`: inline stylesheets and the
// colours set on table cells. A new colour scheme keeps the open session tabs, which hold the
// engineer's results, and re-colours them this way instead of building them again.
inline void rescheme_widget_tree(QWidget* root, ColorScheme from, ColorScheme to) {
  if (root == nullptr || from == to) {
    return;
  }
  QList<QWidget*> widgets = root->findChildren<QWidget*>();
  widgets.prepend(root);
  for (QWidget* widget : widgets) {
    const QString sheet = widget->styleSheet();
    if (!sheet.isEmpty()) {
      const QString mapped = rescheme_sheet(sheet, from, to);
      if (mapped != sheet) {
        widget->setStyleSheet(mapped);
      }
    }
    auto* table = qobject_cast<QTableWidget*>(widget);
    if (table == nullptr) {
      continue;
    }
    for (int row = 0; row < table->rowCount(); ++row) {
      for (int column = 0; column < table->columnCount(); ++column) {
        QTableWidgetItem* cell = table->item(row, column);
        if (cell == nullptr) {
          continue;
        }
        if (cell->foreground().style() != Qt::NoBrush) {
          cell->setForeground(rescheme_color(cell->foreground().color(), from, to));
        }
        if (cell->background().style() != Qt::NoBrush) {
          cell->setBackground(rescheme_color(cell->background().color(), from, to));
        }
      }
    }
  }
}

// Application-wide stylesheet. Qt's default light palette makes SAT look like a different product,
// and a support engineer moving between a Windows and a Linux workstation should not have to
// re-learn what they are looking at. Written in Veeam Green; every colour in it is then mapped to
// the scheme in force.
inline QString stylesheet() {
  namespace base = veeam_green;
  const QString written =
      QString(
          // Chrome
          "QMainWindow, QWidget { background: %1; color: %10; }"
          "QMenuBar { background: %1; color: %10; border-bottom: 1px solid %7; }"
          "QMenuBar::item:selected { background: %5; color: %9; }"
          "QMenu { background: %2; color: %10; border: 1px solid %7; }"
          "QMenu::item { padding: 5px 22px 5px 18px; }"
          "QMenu::item:selected { background: %5; color: %9; }"
          // Disabled entries still have to be readable: the universal row menu deliberately
          // SHOWS the commands that need an open case, so an engineer learns the menu is the
          // same everywhere. Illegible grey would defeat the point of showing them.
          "QMenu::item:disabled { color: #7E9A93; }"
          "QMenu::separator { height: 1px; background: %7; margin: 4px 0; }"
          "QStatusBar { background: %2; color: %8; border-top: 1px solid %7; }"
          "QStatusBar::item { border: 0; }"

          // Sidebar navigation. The selected row carries a 5px accent bar down its left edge,
          // exactly as draw_navigation_item() paints it on Windows; the transparent border on
          // unselected rows keeps the text from shifting when selection moves.
          "QListWidget#navigation { background: %2; border: 0; outline: none; }"
          "QListWidget#navigation::item {"
          "  color: %3; padding: 11px 12px 11px 19px;"
          "  border-left: 5px solid transparent; }"
          "QListWidget#navigation::item:selected {"
          "  background: %5; color: %9; border-left: 5px solid %4; }"
          "QListWidget#navigation::item:hover:!selected { background: #0E3030; }"

          // Content
          "QLabel { color: %10; background: transparent; }"
          "QLabel[role=\"brand\"] { color: %11; }"
          "QLabel[role=\"subtitle\"], QLabel[muted=\"true\"] { color: %8; }"
          "QLabel[role=\"heading\"], QLabel[role=\"title\"] { color: %9; }"
          "QLabel[role=\"warning\"] { color: %12; }"
          // Help articles read as a document, so they need a heading weight between the section
          // heading and body text, and a body colour that is legible for paragraphs rather than
          // the muted tone used for one-line captions.
          "QLabel[role=\"subheading\"] { color: %9; font-weight: 600; }"
          "QLabel[role=\"body\"] { color: %2; }"

          "QFrame#rule { background: %7; border: 0; max-height: 1px; }"

          // Data surfaces
          "QTableView, QTreeView, QPlainTextEdit, QTextEdit {"
          "  background: %6; color: %10; border: 1px solid %7;"
          "  selection-background-color: %5; selection-color: %9;"
          "  gridline-color: %7; alternate-background-color: #163A3A; }"
          "QHeaderView::section { background: %6; color: %8;"
          "  border: 0; border-right: 1px solid %7; border-bottom: 1px solid %7;"
          "  padding: 5px 8px; }"

          // Controls
          "QPushButton { background: #14312F; color: %10; border: 1px solid #4A6963;"
          "  padding: 5px 14px; }"
          "QPushButton:hover { background: #1F4A3E; border-color: %4; }"
          "QPushButton:disabled { background: #112122; color: #849790; border-color: #304240; }"
          // A button with a menu carries its own arrow in its label ("More  ▾"), so the
          // style's second arrow in the corner is hidden.
          "QPushButton::menu-indicator { image: none; width: 0px; }"
          // A checkbox with no styled indicator renders as bare text on this palette, which is
          // why "Fast index first" looked like a static line rather than a control.
          "QCheckBox { color: %10; spacing: 8px; background: transparent; }"
          "QCheckBox::indicator { width: 14px; height: 14px;"
          "  border: 1px solid #4A6963; background: #162A2C; }"
          "QCheckBox::indicator:hover { border-color: %4; }"
          "QCheckBox::indicator:checked { background: %4; border-color: %4; }"
          "QCheckBox::indicator:disabled { border-color: #304240; background: #112122; }"

          "QLineEdit, QComboBox { background: #162A2C; color: #ECF4F0;"
          "  border: 1px solid #4A6963; padding: 4px 6px; }"
          "QComboBox::drop-down { border: 0; width: 18px; }"
          "QComboBox QAbstractItemView { background: #162A2C; color: #ECF4F0;"
          "  selection-background-color: %5; selection-color: %9; }"

          "QScrollBar:vertical { background: %1; width: 12px; margin: 0; }"
          "QScrollBar::handle:vertical { background: #2C4A46; min-height: 26px; border-radius: 3px; }"
          "QScrollBar::handle:vertical:hover { background: #3C6058; }"
          "QScrollBar:horizontal { background: %1; height: 12px; margin: 0; }"
          "QScrollBar::handle:horizontal { background: #2C4A46; min-width: 26px; border-radius: 3px; }"
          "QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }"
          "QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }"

          "QSplitter::handle { background: %7; width: 1px; }")
          .arg(base::background)         // %1
          .arg(base::panel)              // %2
          .arg(base::nav_text)           // %3
          .arg(base::accent)             // %4
          .arg(base::selected)           // %5
          .arg(base::card)               // %6
          .arg(base::card_border)        // %7
          .arg(base::subtitle)           // %8
          .arg(base::nav_text_selected)  // %9
          .arg(base::body)               // %10
          .arg(base::brand_title)        // %11
          .arg(base::warning);           // %12
  if (current_scheme() == ColorScheme::veeam_green) {
    return written;
  }
  static const QRegularExpression hex(QStringLiteral("#[0-9A-Fa-f]{6}"));
  QString mapped;
  qsizetype copied = 0;
  for (auto match = hex.globalMatch(written); match.hasNext();) {
    const auto found = match.next();
    mapped += written.mid(copied, found.capturedStart() - copied);
    mapped += themed_hex(found.captured().toLatin1().constData());
    copied = found.capturedEnd();
  }
  mapped += written.mid(copied);
  return mapped;
}

}  // namespace support_assist::gui::theme
