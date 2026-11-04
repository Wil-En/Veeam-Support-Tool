#pragma once

// The status board on Linux: groups of tiles from gui_shared/home_board.hpp and rows of link
// chips, as src/gui/board_panel.cpp draws them on Windows. Home uses it in both roles and the Tools
// pages for their category tiles. A click, Enter or Space on an item calls the activation callback
// with the item's index: the tiles in reading order across the groups, then the chips.
//
// Free of Q_OBJECT, as terminal_view.hpp is.

#include "home_board.hpp"
#include "quick_tools_qt.hpp"
#include "sat_theme.hpp"

#include <QEnterEvent>
#include <QEvent>
#include <QPointer>
#include <QFontMetrics>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QPushButton>
#include <QResizeEvent>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace sat_qt {

namespace board {
namespace sg = support_assist::gui;
namespace theme = support_assist::gui::theme;

// Empties a layout: its widgets are deleted later, its nested layouts with them. A nested layout
// is its own layout item (item->layout() returns the item), so it is deleted once, as the item.
// A taken widget is hidden at once: deleted later, it would otherwise still paint where it was,
// under the widgets that replace it, until the event loop deletes it.
inline void clear_layout(QLayout* layout) {
  while (QLayoutItem* item = layout->takeAt(0)) {
    if (QWidget* widget = item->widget()) {
      widget->hide();
      widget->deleteLater();
    }
    if (QLayout* inner = item->layout())
      clear_layout(inner);
    delete item;
  }
}

struct Group {
  QString caption; // "THIS MACHINE'S HEALTH"; empty for none
  int columns = 3;
  bool compact = false; // caption, value and one line, with the pill beside the caption
  std::vector<sg::BoardTile> tiles;
  bool compact_when_short = false; // compact while the board is taller than the view it fits
};

// Chips run left to right and wrap when a row is full.
struct Chip {
  QString label;
  QString key;  // drawn in a key cap after the label: "F2"
  QString note; // drawn after a primary chip
  bool primary = false;
  bool right = false;   // at the right end of its row
  bool new_row = false; // starts a new row
  QString row_caption;  // drawn above a row that starts here
};

// A case status's pill colours as "#RRGGBB": fill, then text.
using PillColours = std::function<std::pair<QString, QString>(const std::string& status)>;

inline QString border_hex(const sg::BoardTile& tile) {
  if (tile.highlight || tile.selected)
    return theme::themed_hex(theme::veeam_green::card_focus_border);
  switch (tile.tone) {
  case sg::ReportTone::attention: return theme::themed_hex("#BF8934");
  case sg::ReportTone::problem: return theme::themed_hex("#C44C52");
  default: return theme::themed_hex(theme::veeam_green::card_border);
  }
}

inline QString value_hex(sg::ReportTone tone) {
  switch (tone) {
  case sg::ReportTone::attention: return theme::themed_hex("#FFC75B");
  case sg::ReportTone::problem: return theme::themed_hex("#FF7878");
  case sg::ReportTone::quiet: return theme::themed_hex("#96ACA5");
  case sg::ReportTone::good:
  case sg::ReportTone::normal: break;
  }
  return theme::themed_hex(theme::veeam_green::heading);
}

inline std::pair<QString, QString> pill_colours_for(const PillColours& pill_colours, const std::string& status) {
  if (pill_colours)
    return pill_colours(status);
  return {theme::themed_hex("#4A3410"), theme::themed_hex("#FFC75B")};
}

inline QLabel* pill_label(const std::string& status, const PillColours& pill_colours) {
  const auto colours = pill_colours_for(pill_colours, status);
  auto* pill = new QLabel(QString::fromStdString(status));
  pill->setStyleSheet(QStringLiteral("QLabel { background: %1; color: %2; border-radius: 9px; padding: 1px 9px; }")
                          .arg(colours.first, colours.second));
  return pill;
}

// A tile: the whole frame is the click target, with hover and focus drawn in the accent. A
// selected tile (a filter that is on) is drawn pressed in.
class Tile : public QFrame {
public:
  Tile(const sg::BoardTile& tile, bool compact, const PillColours& pill_colours, std::function<void()> activate)
      : activate_(std::move(activate)), actionable_(tile.action != sg::BoardAction::none), pressed_(tile.selected) {
    setObjectName(QStringLiteral("boardTile"));
    setAttribute(Qt::WA_Hover);
    setFocusPolicy(actionable_ ? Qt::StrongFocus : Qt::NoFocus);
    if (actionable_)
      setCursor(Qt::PointingHandCursor);
    const QString border = border_hex(tile);
    const QString accent = theme::themed_hex(theme::veeam_green::accent);
    const QString focus = theme::themed_hex(theme::veeam_green::card_focus_border);
    if (pressed_) {
      // The selected-row fill inside the accent border; paintEvent adds the inset shadow.
      setStyleSheet(QStringLiteral("QFrame#boardTile { background: %1; border: 1px solid %2; border-radius: 12px; }")
                        .arg(theme::themed_hex(theme::veeam_green::selected), accent));
    } else {
      setStyleSheet(QStringLiteral("QFrame#boardTile { background: %1; border: 1px solid %2; border-radius: 12px; }"
                                   "QFrame#boardTile:hover { border: 1px solid %3; }"
                                   "QFrame#boardTile:focus { border: 2px solid %4; }")
                        .arg(theme::themed_hex(theme::veeam_green::card), border, actionable_ ? accent : border, focus));
    }
    auto* layout = new QVBoxLayout(this);
    const int padding = compact ? 10 : 14;
    // Pressed in: the content sits a step lower.
    layout->setContentsMargins(padding, padding - 2 + (pressed_ ? 2 : 0), padding, padding - 2 - (pressed_ ? 2 : 0));
    layout->setSpacing(compact ? 2 : 4);
    auto* caption = quick::styled_label(QString::fromStdString(tile.caption),
                                        pressed_ ? theme::themed_hex(theme::veeam_green::chevron)
                                                 : theme::themed_hex(theme::veeam_green::subtitle),
                                        0.85);
    if (compact && !tile.pill.empty()) {
      // A compact tile carries its pill at the right end of the caption line.
      auto* row = new QHBoxLayout();
      row->setSpacing(6);
      row->addWidget(caption, 1);
      row->addWidget(pill_label(tile.pill, pill_colours));
      layout->addLayout(row);
    } else {
      layout->addWidget(caption);
    }
    auto* value = quick::styled_label(QString::fromStdString(tile.value), value_hex(tile.tone), compact ? 1.3 : 1.6, true);
    value->setWordWrap(false);
    layout->addWidget(value);
    auto* detail = quick::styled_label(QString::fromStdString(tile.detail), theme::themed_hex("#D6E4DE"),
                                       compact ? 0.85 : 0.95);
    detail->setWordWrap(!compact);
    if (compact) {
      // One line: its full text would set the column's width, so it takes the width it is given and
      // ends in an ellipsis there (resizeEvent), with the whole line in its tooltip.
      detail->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
      detail->setToolTip(detail->text());
      elided_ = detail;
      full_detail_ = detail->text();
    }
    layout->addWidget(detail);
    if (!tile.pill.empty() && !compact) {
      auto* row = new QHBoxLayout();
      row->addWidget(pill_label(tile.pill, pill_colours));
      row->addStretch(1);
      layout->addLayout(row);
    }
    layout->addStretch(1);
    // A compact tile is its link: the health strip draws none, as on Windows.
    if (!tile.link.empty() && !compact) {
      auto* link = quick::styled_label(QString::fromStdString(tile.link) + QStringLiteral(" ›"),
                                       theme::themed_hex(theme::veeam_green::chevron), 0.85);
      link->setAlignment(Qt::AlignRight);
      layout->addWidget(link);
    }
    // The whole tile takes the click, not the labels in it.
    for (QLabel* label : findChildren<QLabel*>())
      label->setAttribute(Qt::WA_TransparentForMouseEvents);
    setAccessibleName(QString::fromStdString(tile.caption + ": " + tile.value + ". " + tile.detail));
  }

  bool pressed() const { return pressed_; }

protected:
  void paintEvent(QPaintEvent* event) override {
    QFrame::paintEvent(event);
    if (!pressed_)
      return;
    // Pressed in: a shadow inside the top and left edges that fades into the fill, darker than the
    // fill in every scheme, as the Windows board draws it.
    QPainter painter(this);
    const QColor fill(theme::themed_hex(theme::veeam_green::selected));
    constexpr int depth = 4;
    constexpr int inset = 8;
    for (int step = 0; step < depth; ++step) {
      painter.setPen(QPen(fill.darker(100 * 100 / (35 + step * 55 / depth)), 1));
      painter.drawLine(inset, 1 + step, width() - inset, 1 + step);
      painter.drawLine(1 + step, inset, 1 + step, height() - inset);
    }
  }
  void mouseReleaseEvent(QMouseEvent* event) override {
    if (actionable_ && event->button() == Qt::LeftButton && rect().contains(event->position().toPoint()))
      activate_();
    QFrame::mouseReleaseEvent(event);
  }
  void keyPressEvent(QKeyEvent* event) override {
    if (actionable_ && (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter ||
                        event->key() == Qt::Key_Space)) {
      activate_();
      return;
    }
    QFrame::keyPressEvent(event);
  }
  // The layout has placed the children by now; the one-line detail fits the width it was given.
  void resizeEvent(QResizeEvent* event) override {
    QFrame::resizeEvent(event);
    if (elided_ != nullptr)
      elided_->setText(elided_->fontMetrics().elidedText(full_detail_, Qt::ElideRight, std::max(0, elided_->width())));
  }

private:
  std::function<void()> activate_;
  bool actionable_ = false;
  bool pressed_ = false;
  QLabel* elided_ = nullptr; // a compact tile's one-line detail
  QString full_detail_;
};

inline QPushButton* make_chip(const Chip& chip, std::function<void()> activate) {
  auto* button = new QPushButton();
  button->setCursor(Qt::PointingHandCursor);
  auto* row = new QHBoxLayout(button);
  row->setContentsMargins(chip.primary ? 16 : 10, 0, 6, 0);
  row->setSpacing(8);
  auto* label = new QLabel(chip.label);
  label->setAttribute(Qt::WA_TransparentForMouseEvents);
  label->setStyleSheet(QStringLiteral("color: %1; background: transparent;")
                           .arg(chip.primary ? theme::themed_hex("#96ECA0") : theme::themed_hex(theme::veeam_green::body)));
  row->addWidget(label);
  if (!chip.key.isEmpty()) {
    auto* key = quick::key_cap(chip.key);
    key->setAttribute(Qt::WA_TransparentForMouseEvents);
    row->addWidget(key);
  }
  const int height = label->sizeHint().height() + (chip.primary ? 18 : 12);
  button->setFixedHeight(height);
  button->setMinimumWidth(row->sizeHint().width() + (chip.primary ? 16 : 8));
  button->setStyleSheet(QStringLiteral("QPushButton { background: %1; border: 1px solid %2; border-radius: %3px; }"
                                       "QPushButton:hover, QPushButton:focus { border: 1px solid %4; }")
                            .arg(chip.primary ? theme::themed_hex(theme::veeam_green::selected)
                                              : theme::themed_hex(theme::veeam_green::card),
                                 chip.primary ? theme::themed_hex(theme::veeam_green::accent) : theme::themed_hex("#4A6963"))
                            .arg(chip.primary ? 8 : height / 2)
                            .arg(theme::themed_hex(theme::veeam_green::card_focus_border)));
  QObject::connect(button, &QPushButton::clicked, button, [activate]() { activate(); });
  button->setAccessibleName(chip.label + (chip.key.isEmpty() ? QString() : QStringLiteral(" (") + chip.key + QStringLiteral(")")));
  return button;
}

} // namespace board

class BoardView : public QWidget {
public:
  using Activate = std::function<void(int index)>;

  explicit BoardView(Activate activate, QWidget* parent = nullptr) : QWidget(parent), activate_(std::move(activate)) {
    setObjectName(QStringLiteral("boardView"));
    setStyleSheet(QStringLiteral("QWidget#boardView { background: transparent; }"));
    layout_ = new QVBoxLayout(this);
    layout_->setContentsMargins(0, 0, 0, 0);
    layout_->setSpacing(12);
  }

  // Rebuilt only when what it shows changed, so a periodic refresh keeps the keyboard focus.
  void set_content(std::vector<board::Group> groups, std::vector<board::Chip> chips, board::PillColours pill_colours) {
    const QString signature = signature_of(groups, chips);
    pill_colours_ = std::move(pill_colours);
    if (signature == signature_ && !groups_.empty())
      return;
    signature_ = signature;
    groups_ = std::move(groups);
    chips_ = std::move(chips);
    shrunk_.assign(groups_.size(), 0);
    built_level_ = 0;
    measured_.clear();
    rebuild();
    fit();
  }

  // The view whose height the board fits: while the board is taller, the groups that allow it show
  // compact, the lowest first, as the Windows board does.
  void fit_to(QWidget* view) {
    fit_view_ = view;
    if (view != nullptr)
      view->installEventFilter(this);
  }

  // The tile captions as drawn, " (pressed)" after a pressed-in tile, for the self-check.
  QStringList captions() const {
    QStringList found;
    for (const board::Group& group : groups_)
      for (const auto& tile : group.tiles)
        found << QString::fromStdString(tile.caption) + (tile.selected ? QStringLiteral(" (pressed)") : QString());
    return found;
  }

  // How many groups show compact to fit the view they sit in.
  int compact_to_fit() const { return built_level_; }
  // The fit as measured: the view's height and the board's height at each level, for the self-check.
  QString fit_state() const {
    QString text = QStringLiteral("view %1, width %2, level %3:").arg(fit_view_.isNull() ? -1 : fit_view_->height()).arg(width()).arg(built_level_);
    for (const auto& [level, height] : measured_)
      text += QStringLiteral(" %1=%2").arg(level).arg(height);
    return text;
  }

  // The chip labels as drawn, for the self-check.
  QStringList chip_labels() const {
    QStringList found;
    for (const board::Chip& chip : chips_)
      found << chip.label;
    return found;
  }

protected:
  void resizeEvent(QResizeEvent* event) override {
    QWidget::resizeEvent(event);
    if (columns_signature() != built_signature_ || chip_rows() != built_rows_)
      rebuild();
    fit();
  }

  bool eventFilter(QObject* watched, QEvent* event) override {
    if (watched == fit_view_.data() && event->type() == QEvent::Resize)
      fit();
    return QWidget::eventFilter(watched, event);
  }

private:
  static QString signature_of(const std::vector<board::Group>& groups, const std::vector<board::Chip>& chips) {
    QString text;
    for (const board::Group& group : groups) {
      text += group.caption + QLatin1Char('\x1f') + QString::number(group.columns) + (group.compact ? QStringLiteral("c") : QString());
      for (const auto& tile : group.tiles) {
        text += QString::fromStdString(tile.caption + '\x1f' + tile.value + '\x1f' + tile.detail + '\x1f' + tile.pill + '\x1f' +
                                       tile.link) +
                QString::number(static_cast<int>(tile.tone)) + (tile.highlight ? QStringLiteral("h") : QString()) +
                (tile.selected ? QStringLiteral("s") : QString());
      }
      text += QLatin1Char('\x1e');
    }
    for (const board::Chip& chip : chips)
      text += chip.label + QLatin1Char('\x1f') + chip.key + QLatin1Char('\x1f') + chip.note + QLatin1Char('\x1f') +
              chip.row_caption + (chip.new_row ? QStringLiteral("n") : QString()) +
              (chip.right ? QStringLiteral("r") : QString());
    return text;
  }

  // The row each chip sits in at this width: a chip starts a row when it asks to or when it does
  // not fit beside the chips before it, as the Windows board lays them out.
  std::vector<int> chip_rows() const {
    std::vector<int> rows;
    const QFontMetrics metrics(font());
    const int available = std::max(1, width());
    int row = -1;
    int used = 0;
    for (const board::Chip& chip : chips_) {
      int chip_width = metrics.horizontalAdvance(chip.label) + (chip.primary ? 40 : 26);
      if (!chip.key.isEmpty())
        chip_width += metrics.horizontalAdvance(chip.key) + 24;
      if (chip.primary && !chip.note.isEmpty())
        chip_width += metrics.horizontalAdvance(chip.note) + 16;
      if (row < 0 || chip.new_row || used + chip_width > available) {
        ++row;
        used = 0;
      }
      used += chip_width + 8;
      rows.push_back(row);
    }
    return rows;
  }

  // Fewer columns when the tiles would be too narrow to read, as on Windows.
  int columns_for(const board::Group& group) const {
    const int available = std::max(1, width());
    const int minimum = fontMetrics().averageCharWidth() * (group.compact ? 17 : 28);
    int columns = std::max(1, group.columns);
    while (columns > 1 && (available - 12 * (columns - 1)) / columns < minimum)
      --columns;
    return columns;
  }

  std::vector<int> columns_signature() const {
    std::vector<int> signature;
    for (const board::Group& group : groups_)
      signature.push_back(columns_for(group));
    return signature;
  }

  int shrinkable_count() const {
    int count = 0;
    for (const board::Group& group : groups_)
      count += group.compact_when_short && !group.compact ? 1 : 0;
    return count;
  }

  // Builds with the lowest `level` groups that allow it shown compact.
  void build_at(int level) {
    shrunk_.assign(groups_.size(), 0);
    int left = level;
    for (std::size_t index = groups_.size(); index-- > 0 && left > 0;) {
      if (groups_[index].compact_when_short && !groups_[index].compact) {
        shrunk_[index] = 1;
        --left;
      }
    }
    built_level_ = level;
    rebuild();
  }

  // The height the board needs at a level, measured from a build at that level.
  int measured_height(int level) {
    const auto found = measured_.find(level);
    if (found != measured_.end())
      return found->second;
    if (built_level_ != level)
      build_at(level);
    ensurePolished();
    const int height = layout_->hasHeightForWidth() ? layout_->totalHeightForWidth(width())
                                                    : layout_->totalSizeHint().height();
    measured_[level] = height;
    return height;
  }

  // The fewest compact groups that fit the view; all of them when nothing fits.
  void fit() {
    if (fitting_ || fit_view_.isNull() || groups_.empty())
      return;
    const int levels = shrinkable_count();
    if (levels == 0)
      return;
    fitting_ = true;
    if (width() != measured_width_) {
      measured_.clear();
      measured_width_ = width();
    }
    const int available = fit_view_->height();
    int chosen = levels;
    for (int level = 0; level <= levels; ++level) {
      if (measured_height(level) <= available) {
        chosen = level;
        break;
      }
    }
    if (chosen != built_level_)
      build_at(chosen);
    fitting_ = false;
  }

  void rebuild() {
    board::clear_layout(layout_);
    built_signature_ = columns_signature();
    built_rows_ = chip_rows();
    int index = 0;
    for (std::size_t group_index = 0; group_index < groups_.size(); ++group_index) {
      const board::Group& group = groups_[group_index];
      auto* section = new QWidget();
      section->setObjectName(QStringLiteral("boardSection"));
      section->setStyleSheet(QStringLiteral("QWidget#boardSection { background: transparent; }"));
      auto* section_layout = new QVBoxLayout(section);
      section_layout->setContentsMargins(0, 0, 0, 0);
      section_layout->setSpacing(6);
      if (!group.caption.isEmpty())
        section_layout->addWidget(quick::styled_label(group.caption, board::theme::themed_hex(board::theme::veeam_green::subtitle), 0.85));
      auto* grid = new QGridLayout();
      grid->setSpacing(12);
      const int columns = built_signature_[group_index];
      for (int column = 0; column < columns; ++column)
        grid->setColumnStretch(column, 1);
      for (std::size_t tile_index = 0; tile_index < group.tiles.size(); ++tile_index) {
        const int item = index++;
        const bool compact = group.compact || (group_index < shrunk_.size() && shrunk_[group_index] != 0);
        auto* tile = new board::Tile(group.tiles[tile_index], compact, pill_colours_,
                                     [this, item]() { activate_(item); });
        grid->addWidget(tile, static_cast<int>(tile_index) / columns, static_cast<int>(tile_index) % columns);
      }
      section_layout->addLayout(grid);
      layout_->addWidget(section);
    }
    QHBoxLayout* row = nullptr;
    bool right_started = false;
    const auto finish_row = [&]() {
      if (row != nullptr && !right_started)
        row->addStretch(1);
    };
    for (std::size_t chip_index = 0; chip_index < chips_.size(); ++chip_index) {
      const board::Chip& chip = chips_[chip_index];
      const int item = index++;
      if (row == nullptr || built_rows_[chip_index] != built_rows_[chip_index - 1]) {
        finish_row();
        if (chip.new_row && !chip.row_caption.isEmpty())
          layout_->addWidget(quick::styled_label(chip.row_caption, board::theme::themed_hex(board::theme::veeam_green::subtitle), 0.85));
        row = new QHBoxLayout();
        row->setSpacing(8);
        right_started = false;
        layout_->addLayout(row);
      }
      if (chip.right && !right_started) {
        row->addStretch(1);
        right_started = true;
      }
      row->addWidget(board::make_chip(chip, [this, item]() { activate_(item); }));
      if (chip.primary && !chip.note.isEmpty()) {
        auto* note = quick::styled_label(chip.note, board::theme::themed_hex("#C4D6CF"), 0.9);
        note->setWordWrap(false);
        row->addWidget(note);
      }
    }
    finish_row();
  }

  Activate activate_;
  QVBoxLayout* layout_ = nullptr;
  std::vector<board::Group> groups_;
  std::vector<board::Chip> chips_;
  board::PillColours pill_colours_;
  std::vector<int> built_signature_;
  std::vector<int> built_rows_;
  QString signature_;
  QPointer<QWidget> fit_view_;
  std::vector<char> shrunk_; // per group: shown compact to fit the view
  int built_level_ = 0;
  std::map<int, int> measured_; // level -> height, at measured_width_
  int measured_width_ = -1;
  bool fitting_ = false;
};

} // namespace sat_qt
