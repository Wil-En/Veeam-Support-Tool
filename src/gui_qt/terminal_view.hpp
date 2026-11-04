#pragma once

// The terminal view for the Linux Remote page.
//
// It renders support_assist::TerminalScreen and nothing else: no transport, no session, no policy.
// TerminalScreen was written platform-neutral for exactly this - the Windows edition paints the
// same model through GDI - so the two editions share the escape-sequence handling and differ only
// in how pixels reach the screen.
//
// Deliberately free of Q_OBJECT. It raises no signals of its own; the page supplies callbacks, so
// there is nothing for moc to generate and no vtable surprise if this header is included twice.

#include "quick_tools_qt.hpp"
#include "support_assist/terminal_screen.hpp"

#include <QApplication>
#include <QClipboard>
#include <QColor>
#include <QContextMenuEvent>
#include <QFont>
#include <QFontMetrics>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QWheelEvent>
#include <QWidget>

#include <algorithm>
#include <functional>

namespace sat_qt {

// The same 16 colours the Windows terminal uses, so a log read on Linux looks like the same log
// read on Windows rather than like a different product.
inline const std::array<QColor, 16>& ansi_palette() {
  static const std::array<QColor, 16> palette{{
      QColor(38, 44, 45),    QColor(224, 108, 117), QColor(140, 214, 158), QColor(229, 192, 123),
      QColor(122, 174, 226), QColor(198, 155, 222), QColor(120, 205, 205), QColor(200, 210, 206),
      QColor(92, 102, 103),  QColor(240, 138, 145), QColor(160, 232, 178), QColor(245, 212, 148),
      QColor(150, 194, 240), QColor(216, 180, 236), QColor(150, 226, 226), QColor(236, 244, 240),
  }};
  return palette;
}

class TerminalView : public QWidget {
public:
  explicit TerminalView(QWidget* parent = nullptr) : QWidget(parent) {
    setFocusPolicy(Qt::StrongFocus);
    setAttribute(Qt::WA_OpaquePaintEvent);
    setCursor(Qt::IBeamCursor);
    QFont font(QStringLiteral("monospace"));
    font.setStyleHint(QFont::TypeWriter);
    font.setPointSize(10);
    setFont(font);
    recompute_metrics();
  }

  // The page owns the screen and the session; this only draws what it is pointed at.
  void set_screen(support_assist::TerminalScreen* screen) {
    screen_ = screen;
    scroll_offset_ = 0;
    has_selection_ = false;
    selecting_ = false;
    update();
  }

  // Called with the bytes a keystroke should send. The view knows nothing about the transport.
  void set_input_handler(std::function<void(const std::string&)> handler) {
    send_ = std::move(handler);
  }
  // Called when the visible grid changes size, so the far end can be told.
  void set_resize_handler(std::function<void(int, int)> handler) {
    resized_ = std::move(handler);
  }

  int columns() const {
    return std::max(20, (width() - 2 * kPadding) / std::max(1, cell_width_));
  }
  int rows() const {
    return std::max(4, (height() - 2 * kPadding) / std::max(1, cell_height_));
  }

  // Positive scrolls back into history, negative returns toward live.
  void scroll_by(int rows_to_move) {
    if (screen_ == nullptr)
      return;
    const int history = static_cast<int>(screen_->scrollback().size());
    const int wanted = std::clamp(scroll_offset_ + rows_to_move, 0, history);
    if (wanted == scroll_offset_)
      return;
    scroll_offset_ = wanted;
    // Scrolling renumbers which rows are visible, so a selection taken before it no longer points
    // at the text it was taken from.
    has_selection_ = false;
    selecting_ = false;
    update();
  }
  int scroll_offset() const { return scroll_offset_; }
  void scroll_to_live() { scroll_by(-scroll_offset_); }

protected:
  void paintEvent(QPaintEvent*) override {
    QPainter painter(this);
    painter.fillRect(rect(), QColor(12, 26, 27));
    if (screen_ == nullptr) {
      painter.setPen(QColor(176, 196, 188));
      painter.drawText(rect(), Qt::AlignCenter,
                       QStringLiteral("Not connected. Enter a host and select Connect."));
      return;
    }
    painter.setFont(font());

    const auto& history = screen_->scrollback();
    const int history_rows = static_cast<int>(history.size());
    const int offset = std::clamp(scroll_offset_, 0, history_rows);
    static const support_assist::TerminalCell blank{};
    const auto cell_at = [&](int row, int column) -> const support_assist::TerminalCell& {
      const int index = row - offset;
      if (index >= 0)
        return screen_->cell(index, column);
      const int history_index = history_rows + index;
      if (history_index < 0 || history_index >= history_rows)
        return blank;
      const auto& line = history[static_cast<std::size_t>(history_index)];
      if (column < 0 || column >= static_cast<int>(line.size()))
        return blank;
      return line[static_cast<std::size_t>(column)];
    };

    const auto& palette = ansi_palette();
    for (int row = 0; row < screen_->rows(); ++row) {
      int column = 0;
      while (column < screen_->columns()) {
        const auto& first = cell_at(row, column);
        const bool first_selected = cell_selected(row, column);
        QString run;
        int span = 0;
        // Draw runs that share attributes (and selection state) in one call rather than a glyph
        // at a time.
        while (column + span < screen_->columns()) {
          const auto& cell = cell_at(row, column + span);
          if (cell.foreground != first.foreground || cell.background != first.background ||
              cell.bold != first.bold || cell.inverse != first.inverse ||
              cell.underline != first.underline ||
              cell_selected(row, column + span) != first_selected) {
            break;
          }
          run.append(cell.glyph < 0x10000 ? QChar(static_cast<char16_t>(cell.glyph))
                                          : QChar(u'?'));
          ++span;
        }
        if (span == 0)
          break;

        QColor foreground = first.foreground >= 0
                                ? palette[static_cast<std::size_t>(first.foreground)]
                                : QColor(220, 228, 224);
        QColor background = first.background >= 0
                                ? palette[static_cast<std::size_t>(first.background)]
                                : QColor(12, 26, 27);
        if (first.inverse)
          std::swap(foreground, background);
        if (first_selected) {
          background = QColor(52, 84, 110);
          foreground = QColor(236, 244, 240);
        }

        const QRect area(kPadding + column * cell_width_, kPadding + row * cell_height_,
                         span * cell_width_, cell_height_);
        if (background != QColor(12, 26, 27))
          painter.fillRect(area, background);

        QFont run_font = font();
        run_font.setBold(first.bold);
        run_font.setUnderline(first.underline);
        painter.setFont(run_font);
        painter.setPen(foreground);
        painter.drawText(area, Qt::AlignLeft | Qt::AlignVCenter, run);
        column += span;
      }
    }

    // The caret only means anything at the live bottom; drawing it while scrolled back would point
    // at a line the shell is not writing to.
    if (offset == 0 && screen_->cursor_visible() && hasFocus()) {
      const QRect caret(kPadding + screen_->cursor_column() * cell_width_,
                        kPadding + screen_->cursor_row() * cell_height_, 2, cell_height_);
      painter.fillRect(caret, QColor(101, 205, 175));
    }
  }

  void resizeEvent(QResizeEvent*) override {
    if (resized_)
      resized_(columns(), rows());
  }

  void wheelEvent(QWheelEvent* event) override {
    // Three rows per notch, the usual step.
    const int notches = event->angleDelta().y() / 120;
    scroll_by(notches * 3);
    event->accept();
  }

  // Selection is held in visible-row space, so anything that renumbers the grid clears it.
  bool cell_selected(int row, int column) const {
    if (!has_selection_)
      return false;
    int top_row = sel_anchor_row_, top_column = sel_anchor_column_;
    int bottom_row = sel_row_, bottom_column = sel_column_;
    if (bottom_row < top_row || (bottom_row == top_row && bottom_column < top_column)) {
      std::swap(top_row, bottom_row);
      std::swap(top_column, bottom_column);
    }
    if (row < top_row || row > bottom_row)
      return false;
    if (top_row == bottom_row)
      return column >= top_column && column < bottom_column;
    if (row == top_row)
      return column >= top_column;
    if (row == bottom_row)
      return column < bottom_column;
    return true;
  }

  void clear_selection() {
    if (has_selection_ || selecting_) {
      has_selection_ = false;
      selecting_ = false;
      update();
    }
  }

  void select_all() {
    if (screen_ == nullptr)
      return;
    sel_anchor_row_ = 0;
    sel_anchor_column_ = 0;
    sel_row_ = screen_->rows() - 1;
    sel_column_ = screen_->columns();
    has_selection_ = true;
    update();
  }

  QString selected_text() const {
    if (!has_selection_ || screen_ == nullptr)
      return {};
    int top_row = sel_anchor_row_, top_column = sel_anchor_column_;
    int bottom_row = sel_row_, bottom_column = sel_column_;
    if (bottom_row < top_row || (bottom_row == top_row && bottom_column < top_column)) {
      std::swap(top_row, bottom_row);
      std::swap(top_column, bottom_column);
    }
    QString text;
    for (int row = top_row; row <= bottom_row; ++row) {
      const int from = (row == top_row) ? top_column : 0;
      const int to = (row == bottom_row) ? bottom_column : screen_->columns();
      QString line;
      for (int column = from; column < to; ++column) {
        const auto& cell = visible_cell(row, column);
        line.append(cell.glyph < 0x10000 ? QChar(static_cast<char16_t>(cell.glyph)) : QChar(u'?'));
      }
      while (line.endsWith(QChar(u' ')))
        line.chop(1);
      text += line;
      if (row != bottom_row)
        text += QStringLiteral("\n");
    }
    return text;
  }

  void copy_selection() {
    const QString text = selected_text();
    if (!text.isEmpty())
      QApplication::clipboard()->setText(text);
  }

  // A PTY takes CR for Enter, so a pasted block runs line by line.
  void paste_clipboard() {
    if (!send_)
      return;
    QString text = QApplication::clipboard()->text();
    if (text.isEmpty())
      return;
    text.replace(QStringLiteral("\r\n"), QStringLiteral("\r"));
    text.replace(QChar(u'\n'), QChar(u'\r'));
    const QByteArray utf8 = text.toUtf8();
    scroll_to_live();
    send_(std::string(utf8.constData(), static_cast<std::size_t>(utf8.size())));
  }

  void mousePressEvent(QMouseEvent* event) override {
    if (event->button() != Qt::LeftButton || screen_ == nullptr) {
      QWidget::mousePressEvent(event);
      return;
    }
    setFocus(Qt::MouseFocusReason);
    point_to_cell(event->pos(), sel_anchor_row_, sel_anchor_column_);
    sel_row_ = sel_anchor_row_;
    sel_column_ = sel_anchor_column_;
    selecting_ = true;
    has_selection_ = false;
    update();
  }

  void mouseMoveEvent(QMouseEvent* event) override {
    if (!selecting_) {
      QWidget::mouseMoveEvent(event);
      return;
    }
    point_to_cell(event->pos(), sel_row_, sel_column_);
    has_selection_ = (sel_row_ != sel_anchor_row_ || sel_column_ != sel_anchor_column_);
    update();
  }

  void mouseReleaseEvent(QMouseEvent* event) override {
    selecting_ = false;
    QWidget::mouseReleaseEvent(event);
  }

  void contextMenuEvent(QContextMenuEvent* event) override {
    QMenu menu(this);
    QAction* copy = menu.addAction(QStringLiteral("Copy\tCtrl+Shift+C"));
    copy->setEnabled(has_selection_);
    QAction* paste = menu.addAction(QStringLiteral("Paste\tCtrl+Shift+V"));
    paste->setEnabled(static_cast<bool>(send_));
    menu.addSeparator();
    QAction* all = menu.addAction(QStringLiteral("Select All"));
    QAction* chosen = menu.exec(event->globalPos());
    if (chosen == copy)
      copy_selection();
    else if (chosen == paste)
      paste_clipboard();
    else if (chosen == all)
      select_all();
  }

  // While the terminal has the focus, the main-window keys (gui_shared/keyboard_shortcuts.hpp) and
  // every function key go to the remote program: Ctrl+K erases to the end of the line in a shell,
  // and F2 or F10 mean something to mc and htop.
  bool event(QEvent* event) override {
    if (event->type() == QEvent::ShortcutOverride) {
      const auto* key = static_cast<QKeyEvent*>(event);
      const auto name = quick::key_name_for_qt(key->key());
      const bool function_key = key->key() >= Qt::Key_F1 && key->key() <= Qt::Key_F12;
      if (function_key || support_assist::gui::main_window_command(
                              name, (key->modifiers() & Qt::ControlModifier) != 0,
                              (key->modifiers() & Qt::ShiftModifier) != 0,
                              (key->modifiers() & Qt::AltModifier) != 0)) {
        event->accept();
        return true;
      }
    }
    return QWidget::event(event);
  }

  void keyPressEvent(QKeyEvent* event) override {
    // Clipboard first, so plain Ctrl+C stays the terminal interrupt. Copy works with no session.
    const bool control = (event->modifiers() & Qt::ControlModifier) != 0;
    const bool shift = (event->modifiers() & Qt::ShiftModifier) != 0;
    if (control && shift && event->key() == Qt::Key_C) {
      copy_selection();
      event->accept();
      return;
    }
    if ((control && shift && event->key() == Qt::Key_V) ||
        (shift && event->key() == Qt::Key_Insert)) {
      paste_clipboard();
      event->accept();
      return;
    }
    if (!send_) {
      QWidget::keyPressEvent(event);
      return;
    }
    clear_selection();
    // Typing returns to the live bottom, or the engineer's own keystrokes land somewhere they
    // cannot see them.
    scroll_to_live();

    const std::string bytes = encode(event);
    if (bytes.empty()) {
      QWidget::keyPressEvent(event);
      return;
    }
    send_(bytes);
    event->accept();
  }

private:
  static constexpr int kPadding = 6;

  void recompute_metrics() {
    const QFontMetrics metrics(font());
    cell_width_ = std::max(1, metrics.horizontalAdvance(QLatin1Char('M')));
    cell_height_ = std::max(1, metrics.height());
  }

  // Only what a support engineer reaching for a shell actually presses. Anything unmapped falls
  // through to the widget rather than being sent as a guess.
  static std::string encode(QKeyEvent* event) {
    const bool control = (event->modifiers() & Qt::ControlModifier) != 0;
    switch (event->key()) {
    case Qt::Key_Return:
    case Qt::Key_Enter:
      return "\r";
    case Qt::Key_Backspace:
      return "\x7f";
    case Qt::Key_Tab:
      return "\t";
    case Qt::Key_Escape:
      return "\x1b";
    case Qt::Key_Up:
      return "\x1b[A";
    case Qt::Key_Down:
      return "\x1b[B";
    case Qt::Key_Right:
      return "\x1b[C";
    case Qt::Key_Left:
      return "\x1b[D";
    case Qt::Key_Home:
      return "\x1b[H";
    case Qt::Key_End:
      return "\x1b[F";
    case Qt::Key_PageUp:
      return "\x1b[5~";
    case Qt::Key_PageDown:
      return "\x1b[6~";
    case Qt::Key_Delete:
      return "\x1b[3~";
    default:
      break;
    }
    if (event->key() >= Qt::Key_F1 && event->key() <= Qt::Key_F12)
      return support_assist::gui::function_key_sequence(event->key() - Qt::Key_F1 + 1);
    if (control && event->key() >= Qt::Key_A && event->key() <= Qt::Key_Z) {
      // Ctrl+C and friends. This is the whole reason a terminal beats a command box: a runaway
      // `tail -f` has to be interruptible.
      return std::string(1, static_cast<char>(event->key() - Qt::Key_A + 1));
    }
    const QString text = event->text();
    if (text.isEmpty())
      return {};
    const QByteArray utf8 = text.toUtf8();
    return std::string(utf8.constData(), static_cast<std::size_t>(utf8.size()));
  }

  // One visible cell, resolved through the scrollback exactly as the paint loop does, so copied
  // text matches what is on screen.
  const support_assist::TerminalCell& visible_cell(int row, int column) const {
    static const support_assist::TerminalCell blank{};
    if (screen_ == nullptr)
      return blank;
    const auto& history = screen_->scrollback();
    const int history_rows = static_cast<int>(history.size());
    const int offset = std::clamp(scroll_offset_, 0, history_rows);
    const int index = row - offset;
    if (index >= 0) {
      if (index >= screen_->rows() || column < 0 || column >= screen_->columns())
        return blank;
      return screen_->cell(index, column);
    }
    const int history_index = history_rows + index;
    if (history_index < 0 || history_index >= history_rows)
      return blank;
    const auto& line = history[static_cast<std::size_t>(history_index)];
    if (column < 0 || column >= static_cast<int>(line.size()))
      return blank;
    return line[static_cast<std::size_t>(column)];
  }

  void point_to_cell(const QPoint& position, int& row, int& column) const {
    if (screen_ == nullptr) {
      row = 0;
      column = 0;
      return;
    }
    row = std::clamp((position.y() - kPadding) / std::max(1, cell_height_), 0,
                     screen_->rows() - 1);
    column = std::clamp((position.x() - kPadding) / std::max(1, cell_width_), 0,
                        screen_->columns());
  }

  support_assist::TerminalScreen* screen_ = nullptr;
  std::function<void(const std::string&)> send_;
  std::function<void(int, int)> resized_;
  int cell_width_ = 8;
  int cell_height_ = 16;
  int scroll_offset_ = 0;
  bool selecting_ = false;
  bool has_selection_ = false;
  int sel_anchor_row_ = 0;
  int sel_anchor_column_ = 0;
  int sel_row_ = 0;
  int sel_column_ = 0;
};

} // namespace sat_qt
