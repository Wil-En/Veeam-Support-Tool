#pragma once

// The quick tools' windows on Linux: Name Check (F2), Local Port Checker (F6), Time Check (F7),
// File Lock Check (F8), Volume Check (F9) and Service and Process Watch (F12), as
// src/gui/quick_tools.cpp draws them on Windows. Each check runs on a worker thread; the result is
// a gui_shared/quick_tool_reports.hpp report drawn by ReportView. Also here: the key mapping for
// gui_shared/keyboard_shortcuts.hpp and the Settings > Keyboard Shortcuts page.
//
// Free of Q_OBJECT, as terminal_view.hpp is: every connection is a lambda.

#include "keyboard_shortcuts.hpp"
#include "quick_tool_guides.hpp"
#include "quick_tool_output.hpp"
#include "quick_tool_reports.hpp"
#include "sat_theme.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/file_lock.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/local_ports.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/network.hpp"
#include "support_assist/object_storage.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/process_logs.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/tool_results.hpp"
#include "support_assist/veeam_watch.hpp"
#include "support_assist/volume_check.hpp"

#include <cmath>
#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QCloseEvent>
#include <QProgressBar>
#include <QClipboard>
#include <QAbstractItemView>
#include <QComboBox>
#include <QMenu>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QMimeData>
#include <QPointer>
#include <QPushButton>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShortcut>
#include <QSpinBox>
#include <QSysInfo>
#include <QTableWidget>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace sat_qt {

namespace quick {
namespace sg = support_assist::gui;
namespace theme = support_assist::gui::theme;

// The check again, a moment after a listener starts or stops, so its row shows it.
constexpr int kRecheckDelayMs = 1500;

inline QString qt_text(const std::string& text) {
  return QString::fromStdString(text);
}

// ------------------------------------------------------------------ keys

// The shortcut key a Qt key code is, for main_window_command() and the terminal.
inline sg::KeyName key_name_for_qt(int key) {
  using K = sg::KeyName;
  if (key >= Qt::Key_F1 && key <= Qt::Key_F12)
    return static_cast<K>(static_cast<int>(K::f1) + (key - Qt::Key_F1));
  switch (key) {
  case Qt::Key_A: return K::a;
  case Qt::Key_B: return K::b;
  case Qt::Key_C: return K::c;
  case Qt::Key_F: return K::f;
  case Qt::Key_G: return K::g;
  case Qt::Key_K: return K::k;
  case Qt::Key_M: return K::m;
  case Qt::Key_V: return K::v;
  case Qt::Key_0: return K::zero;
  case Qt::Key_Plus:
  case Qt::Key_Equal: return K::plus;
  case Qt::Key_Minus: return K::minus;
  case Qt::Key_Escape: return K::escape;
  case Qt::Key_Tab: return K::tab;
  case Qt::Key_Return:
  case Qt::Key_Enter: return K::enter;
  case Qt::Key_Home: return K::home;
  case Qt::Key_End: return K::end;
  case Qt::Key_Up: return K::up;
  case Qt::Key_Down: return K::down;
  default: return K::none;
  }
}

inline int qt_key_for(sg::KeyName key) {
  using K = sg::KeyName;
  if (static_cast<int>(key) >= static_cast<int>(K::f1) && static_cast<int>(key) <= static_cast<int>(K::f12))
    return Qt::Key_F1 + (static_cast<int>(key) - static_cast<int>(K::f1));
  switch (key) {
  case K::a: return Qt::Key_A;
  case K::b: return Qt::Key_B;
  case K::c: return Qt::Key_C;
  case K::f: return Qt::Key_F;
  case K::g: return Qt::Key_G;
  case K::k: return Qt::Key_K;
  case K::m: return Qt::Key_M;
  case K::v: return Qt::Key_V;
  case K::zero: return Qt::Key_0;
  case K::plus: return Qt::Key_Plus;
  case K::minus: return Qt::Key_Minus;
  case K::escape: return Qt::Key_Escape;
  case K::tab: return Qt::Key_Tab;
  case K::enter: return Qt::Key_Return;
  case K::home: return Qt::Key_Home;
  case K::end: return Qt::Key_End;
  case K::up: return Qt::Key_Up;
  case K::down: return Qt::Key_Down;
  default: return 0;
  }
}

// The key sequences for a chord. Ctrl with + also answers as Ctrl+=, the unshifted key on a US
// keyboard, as main_window_command() does.
inline QList<QKeySequence> key_sequences(const sg::KeyChord& chord) {
  QList<QKeySequence> sequences;
  const int key = qt_key_for(chord.key);
  if (key == 0)
    return sequences;
  int modifiers = 0;
  if (chord.ctrl)
    modifiers |= Qt::CTRL;
  if (chord.shift)
    modifiers |= Qt::SHIFT;
  if (chord.alt)
    modifiers |= Qt::ALT;
  sequences << QKeySequence(modifiers | key);
  if (chord.key == sg::KeyName::plus)
    sequences << QKeySequence(modifiers | Qt::Key_Equal);
  return sequences;
}

// ------------------------------------------------------------------ report view

inline QString tone_text_hex(sg::ReportTone tone) {
  switch (tone) {
  case sg::ReportTone::good: return theme::themed_hex("#7EE082");
  case sg::ReportTone::attention: return theme::themed_hex("#FFC75B");
  case sg::ReportTone::problem: return theme::themed_hex("#FF7878");
  case sg::ReportTone::quiet: return theme::themed_hex("#96ACA5");
  case sg::ReportTone::normal: break;
  }
  return theme::themed_hex("#E1ECE7");
}

struct HeadlineColours {
  QString fill;
  QString border;
  QString text;
};

inline HeadlineColours headline_colours(sg::ReportTone tone) {
  switch (tone) {
  case sg::ReportTone::good:
    return {theme::themed_hex("#14402E"), theme::themed_hex("#2E7850"), theme::themed_hex("#96ECA0")};
  case sg::ReportTone::attention:
    return {theme::themed_hex("#463614"), theme::themed_hex("#826428"), theme::themed_hex("#FFD580")};
  case sg::ReportTone::problem:
    return {theme::themed_hex("#4E1E20"), theme::themed_hex("#963C3C"), theme::themed_hex("#FFA0A0")};
  case sg::ReportTone::normal:
  case sg::ReportTone::quiet: break;
  }
  return {theme::themed_hex(theme::veeam_green::card), theme::themed_hex(theme::veeam_green::card_border),
          theme::themed_hex(theme::veeam_green::card_title)};
}

inline QFrame* rounded_card(const QString& fill, const QString& border) {
  auto* card = new QFrame();
  card->setObjectName(QStringLiteral("quickCard"));
  card->setStyleSheet(QStringLiteral("QFrame#quickCard { background: %1; border: 1px solid %2; border-radius: 12px; }")
                          .arg(fill, border));
  return card;
}

inline QLabel* styled_label(const QString& text, const QString& colour, qreal scale = 1.0, bool bold = false) {
  auto* label = new QLabel(text);
  label->setWordWrap(true);
  label->setTextInteractionFlags(Qt::TextSelectableByMouse);
  label->setStyleSheet(QStringLiteral("color: %1; background: transparent;").arg(colour));
  QFont font = label->font();
  if (scale != 1.0)
    font.setPointSizeF(font.pointSizeF() * scale);
  font.setBold(bold);
  label->setFont(font);
  return label;
}

// A quick tool's report: the headline card in its tone's colours with the notes under it, then a
// card per section with a label column and wrapped values.
class ReportView : public QScrollArea {
public:
  explicit ReportView(QWidget* parent = nullptr) : QScrollArea(parent) {
    setWidgetResizable(true);
    setFrameShape(QFrame::NoFrame);
    show_empty(QString());
  }

  void show_empty(const QString& text) {
    auto* body = fresh_body();
    auto* label = styled_label(text, theme::themed_hex(theme::veeam_green::subtitle));
    label->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    body->addWidget(label);
    body->addStretch(1);
    present(body);
    setAccessibleDescription(text);
  }

#ifdef SUPPORT_ASSIST_UI_SELFCHECK
  // Labels drawn shorter than a line of their text: a report squeezed instead of scrolled.
  int selfcheck_squeezed_labels() const {
    int squeezed = 0;
    if (widget() != nullptr) {
      for (const QLabel* label : widget()->findChildren<QLabel*>()) {
        if (label->isVisible() && !label->text().isEmpty() && label->height() < label->fontMetrics().height())
          ++squeezed;
      }
    }
    return squeezed;
  }
#endif

  void show_report(const sg::QuickToolReport& report) {
    auto* body = fresh_body();
    // A report without a headline or notes starts at its first section.
    if (!report.headline.empty() || !report.notes.empty()) {
      const HeadlineColours colours = headline_colours(report.headline_tone);
      auto* headline = rounded_card(colours.fill, colours.border);
      auto* headline_layout = new QVBoxLayout(headline);
      headline_layout->setContentsMargins(14, 12, 14, 12);
      headline_layout->setSpacing(4);
      headline_layout->addWidget(styled_label(qt_text(report.headline), colours.text, 1.2, true));
      for (const std::string& note : report.notes)
        headline_layout->addWidget(styled_label(qt_text(note), theme::themed_hex("#D6E4DE"), 0.9));
      body->addWidget(headline);
    }

    for (const sg::ReportSection& section : report.sections) {
      auto* card = rounded_card(theme::themed_hex(theme::veeam_green::card),
                                theme::themed_hex(theme::veeam_green::card_border));
      auto* card_layout = new QVBoxLayout(card);
      card_layout->setContentsMargins(14, 12, 14, 12);
      card_layout->setSpacing(8);
      card_layout->addWidget(styled_label(qt_text(section.title), theme::themed_hex(theme::veeam_green::heading),
                                          1.1, true));
      auto* grid = new QGridLayout();
      grid->setHorizontalSpacing(14);
      grid->setVerticalSpacing(5);
      grid->setColumnStretch(1, 1);
      int grid_row = 0;
      for (std::size_t index = 0; index < section.rows.size(); ++index) {
        const sg::ReportRow& row = section.rows[index];
        if (index != 0) {
          auto* rule = new QFrame();
          rule->setObjectName(QStringLiteral("rule"));
          rule->setFixedHeight(1);
          grid->addWidget(rule, grid_row++, 0, 1, 2);
        }
        QWidget* value = styled_label(qt_text(row.value), tone_text_hex(row.tone));
        if (row.bar >= 0.0) {
          // The value with a bar under it: the share filled in the tone's colour.
          auto* cell = new QWidget();
          cell->setStyleSheet(QStringLiteral("background: transparent;"));
          auto* cell_layout = new QVBoxLayout(cell);
          cell_layout->setContentsMargins(0, 0, 0, 0);
          cell_layout->setSpacing(5);
          cell_layout->addWidget(value);
          auto* bar = new QProgressBar();
          bar->setRange(0, 1000);
          bar->setValue(static_cast<int>(std::lround(std::clamp(row.bar, 0.0, 1.0) * 1000.0)));
          bar->setTextVisible(false);
          bar->setFixedHeight(8);
          bar->setStyleSheet(
              QStringLiteral("QProgressBar { background: %1; border: 1px solid %2; border-radius: 4px; }"
                             "QProgressBar::chunk { background: %3; border-radius: 4px; }")
                  .arg(theme::themed_hex("#0D1F21"), theme::themed_hex("#22463F"),
                       row.tone == sg::ReportTone::attention ? theme::themed_hex("#FFC75B") : theme::themed_hex("#55BE58")));
          cell_layout->addWidget(bar);
          value = cell;
        }
        if (row.label.empty()) {
          grid->addWidget(value, grid_row++, 0, 1, 2);
          continue;
        }
        auto* label = styled_label(qt_text(row.label), theme::themed_hex(theme::veeam_green::subtitle), 0.9);
        label->setMaximumWidth(260);
        grid->addWidget(label, grid_row, 0, Qt::AlignTop);
        grid->addWidget(value, grid_row++, 1);
      }
      card_layout->addLayout(grid);
      if (!section.note.empty())
        card_layout->addWidget(styled_label(qt_text(section.note), theme::themed_hex(theme::veeam_green::subtitle), 0.9));
      body->addWidget(card);
    }
    body->addStretch(1);
    present(body);
    // The report as plain text, for screen readers.
    setAccessibleDescription(qt_text(sg::report_text(report)));
  }

private:
  // A new body, filled before it is set: children added to a body already on screen are shown a
  // pass of the event loop later, and until then the scroll area sizes the body without them, so
  // the cards are squeezed to the view instead of scrolling.
  static QVBoxLayout* fresh_body() {
    auto* body = new QWidget();
    auto* layout = new QVBoxLayout(body);
    layout->setContentsMargins(4, 4, 4, 4);
    layout->setSpacing(12);
    return layout;
  }

  void present(QVBoxLayout* body) {
    setWidget(body->parentWidget()); // deletes the previous one and shows this one
    setWidgetResizable(true);        // measures it again, now that its children are shown
  }
};

// ------------------------------------------------------------------ Settings > Keyboard Shortcuts

inline QLabel* key_cap(const QString& text) {
  auto* cap = new QLabel(text);
  cap->setAlignment(Qt::AlignCenter);
  cap->setMinimumWidth(26);
  cap->setStyleSheet(QStringLiteral("QLabel { background: %1; color: %2; border: 1px solid %3; "
                                    "border-bottom: 3px solid %4; border-radius: 5px; padding: 1px 7px; "
                                    "font-weight: 600; }")
                         .arg(theme::themed_hex("#1C3F3B"), theme::themed_hex(theme::veeam_green::card_title),
                              theme::themed_hex("#4A6963"), theme::themed_hex(theme::veeam_green::card_border)));
  return cap;
}

// Every key SAT answers, as cards grouped by where the keys work, in one or two columns as the
// Windows page lays them out (arrange_shortcut_groups).
class ShortcutsPage : public QScrollArea {
public:
  explicit ShortcutsPage(QWidget* parent = nullptr) : QScrollArea(parent) {
    setWidgetResizable(true);
    setFrameShape(QFrame::NoFrame);
    rebuild(1);
  }

protected:
  void resizeEvent(QResizeEvent* event) override {
    QScrollArea::resizeEvent(event);
    const int wanted = viewport()->width() >= fontMetrics().averageCharWidth() * 108 ? 2 : 1;
    if (wanted != columns_)
      rebuild(wanted);
  }

private:
  void rebuild(int columns) {
    columns_ = columns;
    auto* body = new QWidget();
    auto* row = new QHBoxLayout(body);
    row->setContentsMargins(4, 4, 4, 4);
    row->setSpacing(12);
    for (const auto& column : sg::arrange_shortcut_groups(static_cast<std::size_t>(columns))) {
      auto* stack = new QVBoxLayout();
      stack->setSpacing(12);
      for (const sg::ShortcutGroup group : column)
        stack->addWidget(group_card(group));
      stack->addStretch(1);
      row->addLayout(stack, 1);
    }
    setWidget(body);
  }

  // A plain holder inside a card; the application stylesheet would paint it in the page colour.
  static QWidget* transparent_row() {
    auto* row = new QWidget();
    row->setObjectName(QStringLiteral("cardRow"));
    row->setStyleSheet(QStringLiteral("QWidget#cardRow { background: transparent; }"));
    return row;
  }

  static QFrame* group_card(sg::ShortcutGroup group) {
    auto* card = rounded_card(theme::themed_hex(theme::veeam_green::card),
                              theme::themed_hex(theme::veeam_green::card_border));
    auto* layout = new QVBoxLayout(card);
    layout->setContentsMargins(14, 12, 14, 12);
    layout->setSpacing(6);
    layout->addWidget(styled_label(qt_text(std::string(sg::shortcut_group_title(group))),
                                   theme::themed_hex(theme::veeam_green::heading), 1.15, true));
    layout->addWidget(styled_label(qt_text(std::string(sg::shortcut_group_note(group))),
                                   theme::themed_hex(theme::veeam_green::subtitle), 0.9));
    auto* grid = new QGridLayout();
    grid->setHorizontalSpacing(16);
    grid->setVerticalSpacing(6);
    grid->setColumnStretch(1, 1);
    int grid_row = 0;
    const auto shortcuts = sg::shortcuts_in_group(group);
    for (std::size_t index = 0; index < shortcuts.size(); ++index) {
      const sg::KeyboardShortcut& shortcut = *shortcuts[index];
      if (index != 0) {
        auto* rule = new QFrame();
        rule->setObjectName(QStringLiteral("rule"));
        rule->setFixedHeight(1);
        grid->addWidget(rule, grid_row++, 0, 1, 2);
      }
      auto* caps = transparent_row();
      auto* caps_row = new QHBoxLayout(caps);
      caps_row->setContentsMargins(0, 0, 0, 0);
      caps_row->setSpacing(4);
      const auto keys = sg::key_caps(shortcut.chord);
      for (std::size_t key = 0; key < keys.size(); ++key) {
        if (key != 0)
          caps_row->addWidget(styled_label(QStringLiteral("+"), theme::themed_hex(theme::veeam_green::subtitle), 0.85));
        caps_row->addWidget(key_cap(qt_text(keys[key])));
      }
      caps_row->addStretch(1);
      grid->addWidget(caps, grid_row, 0, Qt::AlignTop);
      auto* text = transparent_row();
      auto* text_column = new QVBoxLayout(text);
      text_column->setContentsMargins(0, 0, 0, 0);
      text_column->setSpacing(1);
      text_column->addWidget(styled_label(qt_text(std::string(shortcut.label)),
                                          theme::themed_hex(theme::veeam_green::card_title)));
      text_column->addWidget(styled_label(qt_text(std::string(shortcut.detail)),
                                          theme::themed_hex(theme::veeam_green::subtitle), 0.9));
      grid->addWidget(text, grid_row++, 1);
    }
    layout->addLayout(grid);
    return card;
  }

  int columns_ = 0;
};

// ------------------------------------------------------------------ the tool windows

// What a tool window needs from the main window.
struct QuickToolHost {
  std::function<std::optional<support_assist::CaseWorkspace>()> active_case;
  std::function<void(const QString& tool, const QString& result, const QString& detail)> activity;
  std::function<void(const QString& host)> open_remote_port_checker;
  std::function<void(sg::ShortcutCommand tool, const QString& subject)> open_tool;
  std::function<bool()> casework; // Engineer Review, where there are cases and #note
  std::function<void(const sg::QuickToolOutput& output)> keep_output;
  std::function<std::filesystem::path()> tools_folder; // where SAT keeps third-party tools, for iPerf3
  std::function<void(const std::filesystem::path& log, std::uint64_t line)> open_log; // SAT's viewer at a line
};

inline QString tool_title(sg::ShortcutCommand tool) {
  if (tool == sg::ShortcutCommand::object_storage_check)
    return QStringLiteral("Object Storage Check");
  const sg::KeyboardShortcut* shortcut = sg::shortcut_for(tool);
  return shortcut == nullptr ? QString() : qt_text(std::string(shortcut->label));
}

inline bool is_quick_tool(sg::ShortcutCommand command) {
  switch (command) {
  case sg::ShortcutCommand::name_check:
  case sg::ShortcutCommand::local_port_checker:
  case sg::ShortcutCommand::time_check:
  case sg::ShortcutCommand::file_lock_check:
  case sg::ShortcutCommand::volume_check:
  case sg::ShortcutCommand::service_watch:
  case sg::ShortcutCommand::file_transfer_calculator:
  case sg::ShortcutCommand::object_storage_check: return true;
  default: return false;
  }
}

// The result a worker hands back.
struct Outcome {
  std::optional<sg::QuickToolReport> report;
  std::optional<support_assist::PortCheckResult> ports;
  std::optional<support_assist::WatchSnapshot> snapshot;
  std::optional<std::vector<support_assist::VolumeInfo>> volumes; // Volume Check's list
  std::string resolved_address; // Name Check: the first address the name resolved to
  std::string error;
  std::string activity_result;
  std::string activity_detail;
  std::string result_json; // the raw result, kept as the run's output on a Customer / Lab machine
  bool quiet = false; // the check run again for a listener: no activity line
  // Time Check's converter: a log's own clock, read from the path given.
  std::shared_ptr<const support_assist::LogClock> log_clock;
  std::string log_path;
  // The Object Storage Check: the storage's clock against this machine's, when it was read.
  std::optional<double> clock_offset_seconds;
  // The File Transfer Calculator's network test.
  bool transfer_measure = false;
  std::optional<support_assist::TransferSpeed> transfer_speed;
  bool transfer_ipv6 = false;
  // Watch's Its log: the logs written near the moment a process ended.
  std::optional<std::vector<support_assist::LogWrittenNear>> logs_near;
  std::int64_t logs_near_at = 0;
  std::string logs_near_name;
};

// What one listener event shows in the connections list.
struct ListenerEvent {
  QString time; // a connection's clock time, UTC
  QString peer; // its address and port
  QString what; // a connection, a datagram, a SAT probe
  std::string time_utc; // the connection's time in full, for the run's output
};

// "2026-09-29T14:05:31.123Z" -> "14:05:31".
inline QString clock_of(const std::string& iso) {
  const std::size_t at = iso.find('T');
  return qt_text(at == std::string::npos ? iso : iso.substr(at + 1, 8));
}

// "4:05" from a count of seconds.
inline QString minutes_seconds(long long seconds) {
  seconds = std::max(0LL, seconds);
  return QStringLiteral("%1:%2").arg(seconds / 60).arg(seconds % 60, 2, 10, QLatin1Char('0'));
}

// Stops a Quick scan away from the GUI thread: Packet Monitor and packet sockets take a moment.
inline void stop_scan_in_background(std::unique_ptr<support_assist::QuickScan> scan) {
  if (scan)
    std::thread([owned = std::move(scan)]() mutable { owned->stop(); }).detach();
}

class QuickToolWindow : public QWidget {
public:
  // Embedded, the tool is a task's view in the main window's session tabs rather than a window.
  QuickToolWindow(sg::ShortcutCommand command, QuickToolHost host, QWidget* parent, bool embedded = false)
      : QWidget(parent, embedded ? Qt::Widget : Qt::Window), tool_(command), host_(std::move(host)) {
    setWindowTitle(tool_title(command));
    setAttribute(Qt::WA_DeleteOnClose);
    const bool wide = command == sg::ShortcutCommand::local_port_checker || command == sg::ShortcutCommand::service_watch ||
                      command == sg::ShortcutCommand::volume_check ||
                      command == sg::ShortcutCommand::object_storage_check ||
                      command == sg::ShortcutCommand::file_transfer_calculator;
    // The Local Port Checker carries the listener's panel beside its table. A task's view takes the
    // size of its tab.
    if (!embedded)
      resize(command == sg::ShortcutCommand::local_port_checker         ? 1240
           : command == sg::ShortcutCommand::file_transfer_calculator ? 1140
           : wide                                                      ? 1000
           : command == sg::ShortcutCommand::file_lock_check ||
                   command == sg::ShortcutCommand::time_check
               ? 900
               : 780,
           command == sg::ShortcutCommand::object_storage_check ||
                   command == sg::ShortcutCommand::file_transfer_calculator
               ? 900
           : wide ? 760
           : command == sg::ShortcutCommand::time_check          ? 920
                                                                 : 660);

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 12, 12, 12);
    layout->setSpacing(8);
    auto* input_row = new QHBoxLayout();
    input_row->setSpacing(8);
    layout->addLayout(input_row);
    input_ = new QLineEdit();
    const auto add_input = [&](const QString& label, const QString& cue) {
      auto* caption = new QLabel(label);
      caption->setMinimumWidth(command == sg::ShortcutCommand::time_check ? 150 : 120);
      input_row->addWidget(caption);
      input_->setPlaceholderText(cue);
      input_row->addWidget(input_, 1);
    };
    const auto add_button = [&](QHBoxLayout* row, const QString& text) {
      auto* button = new QPushButton(text);
      row->addWidget(button);
      return button;
    };

    switch (command) {
    case sg::ShortcutCommand::name_check:
      add_input(QStringLiteral("Name or address"), QStringLiteral("vbr01, vbr01.corp.example.com or 10.0.4.21"));
      run_ = add_button(input_row, QStringLiteral("Check"));
      link_ = add_button(input_row, QStringLiteral("Remote Port Checker..."));
      break;
    case sg::ShortcutCommand::time_check:
      add_input(QStringLiteral("Time server"), QStringLiteral("empty: the configured time source"));
      run_ = add_button(input_row, QStringLiteral("Check"));
      break;
    case sg::ShortcutCommand::file_lock_check:
      add_input(QStringLiteral("File or folder"),
                QStringLiteral("/mnt/backups/Job/Job.vbk, or a folder for every file under it"));
      browse_ = add_button(input_row, QStringLiteral("File..."));
      folder_browse_ = add_button(input_row, QStringLiteral("Folder..."));
      run_ = add_button(input_row, QStringLiteral("Check"));
      break;
    case sg::ShortcutCommand::volume_check:
      add_input(QStringLiteral("Folder"), QStringLiteral("optional: /mnt/backups, for its own compression and encryption"));
      browse_ = add_button(input_row, QStringLiteral("Browse..."));
      run_ = add_button(input_row, QStringLiteral("Check"));
      link_ = add_button(input_row, QStringLiteral("Open the guide"));
      link_->setEnabled(false);
      break;
    case sg::ShortcutCommand::local_port_checker: {
      add_input(QStringLiteral("Ports"), QStringLiteral("6162, 2500-2510"));
      tcp_ = new QCheckBox(QStringLiteral("TCP"));
      tcp_->setChecked(true);
      udp_ = new QCheckBox(QStringLiteral("UDP"));
      input_row->addWidget(tcp_);
      input_row->addWidget(udp_);
      run_ = add_button(input_row, QStringLiteral("Check"));
      auto* second = new QHBoxLayout();
      second->setSpacing(8);
      layout->addLayout(second);
      preset_ = new QComboBox();
      preset_->addItem(QStringLiteral("A Veeam role's ports..."));
      presets_ = support_assist::port_presets();
      for (const auto& preset : presets_)
        preset_->addItem(qt_text(preset.name));
      preset_->setMinimumWidth(300);
      second->addWidget(preset_);
      second->addSpacing(8);
      second->addWidget(new QLabel(QStringLiteral("Process")));
      process_ = new QLineEdit();
      process_->setPlaceholderText(QStringLiteral("veeamagent or a PID"));
      second->addWidget(process_, 1);
      process_run_ = add_button(second, QStringLiteral("Its ports"));
      break;
    }
    case sg::ShortcutCommand::object_storage_check: {
      // Where the bucket is, then how to sign in and what to trust, then the product its permissions
      // are compared with.
      input_->setPlaceholderText(QStringLiteral("veeam-backups"));
      run_ = new QPushButton(QStringLiteral("Check"));
      link_ = new QPushButton(QStringLiteral("Time Check..."));
      link_->setEnabled(false);
      auto* grid = new QGridLayout();
      grid->setHorizontalSpacing(8);
      grid->setVerticalSpacing(8);
      const auto caption = [](const QString& text) {
        auto* label = new QLabel(text);
        label->setMinimumWidth(120);
        return label;
      };
      storage_preset_ = new QComboBox();
      for (const auto& preset : support_assist::object_storage_catalog().presets) {
        if (preset.later)
          continue;
        storage_presets_.push_back(preset);
        storage_preset_->addItem(qt_text(preset.name));
      }
      endpoint_ = new QLineEdit();
      // The provider's regions to pick from; any other can be typed.
      region_ = new QComboBox();
      region_->setEditable(true);
      region_->setInsertPolicy(QComboBox::NoInsert);
      region_->setMinimumWidth(170);
      // This machine's certificate store is checked always; a certificate file or a fingerprint can
      // trust the storage's certificate as well.
      trust_ = new QComboBox();
      trust_->addItems({QStringLiteral("This machine's certificate store"),
                        QStringLiteral("A certificate file (PEM, CRT or CER)"), QStringLiteral("A SHA-256 fingerprint")});
      certificate_open_ = new QPushButton(QStringLiteral("Open..."));
      product_ = new QComboBox();
      for (const auto& product : support_assist::object_storage_catalog().permissions) {
        product_ids_.push_back(product.id);
        product_->addItem(qt_text(product.product));
      }
      product_->view()->setMinimumWidth(480);
      addressing_ = new QComboBox();
      addressing_->addItems({QStringLiteral("The preset's"), QStringLiteral("Virtual-hosted"), QStringLiteral("Path style")});
      access_ = new QLineEdit();
      access_->setPlaceholderText(QStringLiteral("Optional: the access key Veeam uses"));
      secret_ = new QLineEdit();
      secret_->setEchoMode(QLineEdit::Password);
      secret_->setPlaceholderText(QStringLiteral("kept for this session only"));
      fingerprint_ = new QLineEdit();
      fingerprint_->setPlaceholderText(QStringLiteral("Optional: a self-signed certificate's SHA-256 fingerprint"));
      const auto with_button = [](QWidget* field, QWidget* button) {
        auto* line = new QHBoxLayout();
        line->setSpacing(8);
        line->addWidget(field, 1);
        line->addWidget(button);
        return line;
      };
      // Storage | Region and Addressing.
      auto* region_row = new QHBoxLayout();
      region_row->setSpacing(8);
      region_row->addWidget(region_);
      region_row->addSpacing(8);
      region_row->addWidget(new QLabel(QStringLiteral("Addressing")));
      region_row->addWidget(addressing_, 1);
      grid->addWidget(caption(QStringLiteral("Storage")), 0, 0);
      grid->addWidget(storage_preset_, 0, 1);
      grid->addWidget(caption(QStringLiteral("Region")), 0, 2);
      grid->addLayout(region_row, 0, 3);
      // Bucket | Endpoint and Check.
      grid->addWidget(caption(QStringLiteral("Bucket")), 1, 0);
      grid->addWidget(input_, 1, 1);
      grid->addWidget(caption(QStringLiteral("Endpoint")), 1, 2);
      grid->addLayout(with_button(endpoint_, run_), 1, 3);
      // The keys.
      grid->addWidget(caption(QStringLiteral("Access key")), 2, 0);
      grid->addWidget(access_, 2, 1);
      grid->addWidget(caption(QStringLiteral("Secret key")), 2, 2);
      grid->addWidget(secret_, 2, 3);
      // Certificate | the file or fingerprint and Open...
      grid->addWidget(caption(QStringLiteral("Certificate")), 3, 0);
      grid->addWidget(trust_, 3, 1);
      grid->addLayout(with_button(fingerprint_, certificate_open_), 3, 2, 1, 2);
      // Compare with | Time Check.
      auto* time_row = new QHBoxLayout();
      time_row->addStretch(1);
      time_row->addWidget(link_);
      grid->addWidget(caption(QStringLiteral("Compare with")), 4, 0);
      grid->addWidget(product_, 4, 1);
      grid->addLayout(time_row, 4, 2, 1, 2);
      grid->setColumnStretch(1, 1);
      grid->setColumnStretch(3, 1);
      layout->addLayout(grid);
      // Tab follows the rows.
      QWidget* order[] = {storage_preset_, region_, addressing_, input_, endpoint_, run_, access_, secret_,
                          trust_, fingerprint_, certificate_open_, product_, link_};
      for (std::size_t index = 1; index < std::size(order); ++index)
        QWidget::setTabOrder(order[index - 1], order[index]);
      // The certificate store needs nothing more; a file is typed or opened; a fingerprint is typed.
      const auto trust_chosen = [this](int choice) {
        fingerprint_->clear();
        fingerprint_->setPlaceholderText(
            choice == 1   ? QStringLiteral("/etc/ssl/storage.crt: the storage's certificate or the CA that issued it")
            : choice == 2 ? QStringLiteral("AB:CD:EF:...: the SHA-256 fingerprint of the storage's certificate")
                          : QStringLiteral("Nothing to enter: the store is checked on every connection"));
        // The store needs nothing more, so the field and Open... show only for a file or a fingerprint.
        fingerprint_->setVisible(choice != 0);
        certificate_open_->setVisible(choice == 1);
      };
      connect(trust_, qOverload<int>(&QComboBox::currentIndexChanged), this, trust_chosen);
      trust_chosen(0);
      connect(certificate_open_, &QPushButton::clicked, this, [this]() {
        const QString chosen = QFileDialog::getOpenFileName(
            this, QStringLiteral("Open the storage's certificate"), QString(),
            QStringLiteral("Certificates (*.crt *.pem *.cer *.der);;All files (*)"));
        if (!chosen.isEmpty())
          fingerprint_->setText(chosen);
      });
      // The endpoint's hint follows the region.
      const auto region_changed = [this](const QString& typed) {
        const int index = storage_preset_->currentIndex();
        if (index < 0 || static_cast<std::size_t>(index) >= storage_presets_.size())
          return;
        const auto& preset = storage_presets_[static_cast<std::size_t>(index)];
        std::string region = support_assist::trim(typed.toStdString());
        if (region.empty())
          region = preset.default_region;
        std::string endpoint = preset.endpoint;
        for (std::size_t at = endpoint.find("{region}"); at != std::string::npos; at = endpoint.find("{region}"))
          endpoint.replace(at, 8U, region);
        endpoint_->setPlaceholderText(preset.endpoint.empty() ? QStringLiteral("s3.example.com or 10.0.4.30:9000")
                                                              : QStringLiteral("empty: ") + qt_text(endpoint));
      };
      // A new preset brings its own regions and its default.
      const auto preset_chosen = [this, region_changed](int index) {
        if (index < 0 || static_cast<std::size_t>(index) >= storage_presets_.size())
          return;
        const auto& preset = storage_presets_[static_cast<std::size_t>(index)];
        region_->clear();
        for (const std::string& region : preset.regions)
          region_->addItem(qt_text(region));
        region_->setEditText(qt_text(preset.default_region));
        region_changed(region_->currentText());
      };
      connect(storage_preset_, qOverload<int>(&QComboBox::currentIndexChanged), this, preset_chosen);
      connect(region_, &QComboBox::editTextChanged, this, region_changed);
      preset_chosen(0);
      for (QLineEdit* field : {endpoint_, access_, secret_, fingerprint_, region_->lineEdit()})
        connect(field, &QLineEdit::returnPressed, this, [this]() { run(Command::run); });
      break;
    }
    case sg::ShortcutCommand::file_transfer_calculator: {
      // Manual, or Live test: this machine's adapter, a network test and a storage result.
      mode_enter_ = new QPushButton(QStringLiteral("Manual"));
      mode_measure_ = new QPushButton(QStringLiteral("Live test"));
      auto* modes = new QButtonGroup(this);
      modes->setExclusive(true);
      // The chosen mode drawn pressed in, as the Windows edition's push-like radio buttons are.
      const QString pressed = QStringLiteral("QPushButton:checked { background: %1; color: %2; border-color: %3; }")
                                  .arg(theme::themed_hex("#224E3A"), theme::themed_hex("#96E2B2"),
                                       theme::themed_hex(theme::veeam_green::card_border));
      for (QPushButton* button : {mode_enter_, mode_measure_}) {
        button->setCheckable(true);
        button->setStyleSheet(pressed);
        button->setMinimumWidth(140);
        modes->addButton(button);
        input_row->addWidget(button);
      }
      mode_enter_->setChecked(true);
      input_row->addStretch(1);
      const auto label_of = [](const QString& text, int width) {
        auto* label = new QLabel(text);
        label->setMinimumWidth(width);
        return label;
      };
      const auto choice = [](const QStringList& items, int chosen, bool editable) {
        auto* box = new QComboBox();
        box->addItems(items);
        box->setEditable(editable);
        if (editable)
          box->setInsertPolicy(QComboBox::NoInsert);
        box->setCurrentIndex(chosen);
        return box;
      };

      auto* figures = new QHBoxLayout();
      figures->setSpacing(8);
      figures->addWidget(label_of(QStringLiteral("Data to move"), 110));
      input_->setPlaceholderText(QStringLiteral("such as 20"));
      input_->setMaximumWidth(100);
      figures->addWidget(input_);
      QStringList size_units;
      for (const char* unit : support_assist::kTransferSizeUnits)
        size_units.push_back(QString::fromUtf8(unit));
      size_unit_ = choice(size_units, support_assist::kTransferSizeUnitChosen, false);
      figures->addWidget(size_unit_);
      figures->addSpacing(8);
      figures->addWidget(label_of(QStringLiteral("Link speed"), 90));
      link_speed_ = new QLineEdit();
      link_speed_->setPlaceholderText(QStringLiteral("such as 10"));
      link_speed_->setMaximumWidth(100);
      figures->addWidget(link_speed_);
      link_unit_ = choice({QStringLiteral("Mb/s"), QStringLiteral("Gb/s")}, 1, false);
      figures->addWidget(link_unit_);
      figures->addSpacing(8);
      figures->addWidget(label_of(QStringLiteral("Packet size"), 90));
      mtu_ = choice({QStringLiteral("1500 (standard)"), QStringLiteral("9000 (jumbo)")}, 0, true);
      mtu_->setMinimumWidth(160);
      figures->addWidget(mtu_);
      figures->addStretch(1);
      run_ = add_button(figures, QStringLiteral("Calculate"));
      layout->addLayout(figures);

      auto* shares = new QHBoxLayout();
      shares->setSpacing(8);
      // Hover help on the two percentages, as rich text so a long tip wraps.
      const auto tip = [](const std::string& text) {
        return QStringLiteral("<p>") + QString::fromUtf8(text.c_str()).toHtmlEscaped() + QStringLiteral("</p>");
      };
      const QString share_help = tip(support_assist::gui::transfer_usable_bandwidth_help());
      const QString reduced_help = tip(support_assist::gui::transfer_compression_help());
      auto* share_label = label_of(QStringLiteral("Link throttle"), 130);
      share_label_ = share_label;
      shares->addWidget(share_label);
      share_ = new QLineEdit(QStringLiteral("100"));
      share_->setMaximumWidth(64);
      shares->addWidget(share_);
      auto* share_suffix = new QLabel(QStringLiteral("% of the link"));
      share_suffix_ = share_suffix;
      shares->addWidget(share_suffix);
      for (QWidget* widget : {static_cast<QWidget*>(share_label), static_cast<QWidget*>(share_),
                              static_cast<QWidget*>(share_suffix)})
        widget->setToolTip(share_help);
      shares->addSpacing(16);
      auto* reduced_label = label_of(QStringLiteral("Compression"), 150);
      shares->addWidget(reduced_label);
      reduced_ = new QLineEdit(QStringLiteral("100"));
      reduced_->setMaximumWidth(64);
      shares->addWidget(reduced_);
      auto* reduced_suffix = new QLabel(QStringLiteral("% left to send"));
      shares->addWidget(reduced_suffix);
      for (QWidget* widget : {static_cast<QWidget*>(reduced_label), static_cast<QWidget*>(reduced_),
                              static_cast<QWidget*>(reduced_suffix)})
        widget->setToolTip(reduced_help);
      shares->addStretch(1);
      layout->addLayout(shares);

      // Manual: the network's speed as a test elsewhere measured it.
      manual_box_ = new QWidget();
      auto* speeds = new QHBoxLayout(manual_box_);
      speeds->setContentsMargins(0, 0, 0, 0);
      speeds->setSpacing(8);
      speeds->addWidget(label_of(QStringLiteral("Network speed"), 130));
      network_speed_edit_ = new QLineEdit();
      network_speed_edit_->setPlaceholderText(QStringLiteral("Optional: such as 6, from iPerf3"));
      speeds->addWidget(network_speed_edit_, 1);
      network_unit_ = choice(speed_units(), kUnitGigabits, false);
      speeds->addWidget(network_unit_);
      layout->addWidget(manual_box_);

      measure_box_ = new QWidget();
      auto* measure_rows = new QVBoxLayout(measure_box_);
      measure_rows->setContentsMargins(0, 0, 0, 0);
      measure_rows->setSpacing(8);
      auto* adapter_row = new QHBoxLayout();
      adapter_row->setSpacing(8);
      adapter_row->addWidget(label_of(QStringLiteral("Adapter"), 130));
      adapter_ = new QComboBox();
      adapter_->view()->setMinimumWidth(760);
      adapter_row->addWidget(adapter_, 1);
      adapter_refresh_ = add_button(adapter_row, QStringLiteral("Refresh"));
      measure_rows->addLayout(adapter_row);
      auto* test_row = new QHBoxLayout();
      test_row->setSpacing(8);
      test_row->addWidget(label_of(QStringLiteral("Network test to"), 130));
      test_host_ = new QLineEdit();
      test_host_->setPlaceholderText(QStringLiteral("repo01 or 10.0.4.21"));
      test_host_->setMinimumWidth(200);
      test_row->addWidget(test_host_);
      test_row->addWidget(new QLabel(QStringLiteral("Port")));
      test_port_ = new QLineEdit(QStringLiteral("2500"));
      test_port_->setMaximumWidth(70);
      test_row->addWidget(test_port_);
      test_row->addWidget(new QLabel(QStringLiteral("Using")));
      using_ = choice({QStringLiteral("SAT listener"), QStringLiteral("iPerf3, 1 stream"), QStringLiteral("iPerf3, 4 streams")},
                      0, false);
      test_row->addWidget(using_);
      test_row->addWidget(new QLabel(QStringLiteral("Send")));
      send_size_ = choice({QStringLiteral("1 GB"), QStringLiteral("4 GB"), QStringLiteral("8 GB")}, 0, false);
      test_row->addWidget(send_size_);
      test_row->addStretch(1);
      measure_ = add_button(test_row, QStringLiteral("Measure"));
      measure_rows->addLayout(test_row);
      layout->addWidget(measure_box_);
      measure_box_->hide();

      // Storage speed, in both modes: typed, or in Live test filled from a Disk Speed Test's result.json,
      // with which figure to take beside it.
      storage_row_ = new QHBoxLayout();
      storage_row_->setSpacing(8);
      storage_row_->addWidget(label_of(QStringLiteral("Storage speed"), 130));
      storage_speed_edit_ = new QLineEdit();
      storage_speed_edit_->setPlaceholderText(storage_cue(false));
      storage_speed_edit_->setMinimumWidth(200);
      storage_row_->addWidget(storage_speed_edit_, 1);
      storage_unit_ = choice(speed_units(), kUnitMegabytes, false);
      storage_row_->addWidget(storage_unit_);
      storage_text_ = new QLabel(storage_helper());
      storage_text_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
      storage_row_->addWidget(storage_text_, 0);
      open_result_ = add_button(storage_row_, QStringLiteral("Open a result..."));
      clear_result_ = add_button(storage_row_, QStringLiteral("Clear"));
      clear_result_->setEnabled(false);
      layout->addLayout(storage_row_);
      for (QWidget* live : {static_cast<QWidget*>(storage_text_), static_cast<QWidget*>(open_result_),
                            static_cast<QWidget*>(clear_result_)})
        live->hide();

      connect(mode_enter_, &QPushButton::clicked, this, [this]() { transfer_mode(false); });
      connect(mode_measure_, &QPushButton::clicked, this, [this]() { transfer_mode(true); });
      connect(adapter_, qOverload<int>(&QComboBox::activated), this, [this](int) {
        transfer_apply_adapter();
        transfer_recalculate();
      });
      connect(adapter_refresh_, &QPushButton::clicked, this, [this]() { transfer_fill_adapters(); });
      connect(using_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        // iPerf3 listens on 5201 unless told otherwise; SAT's listener on the port chosen, 2500 here.
        if (index >= 1 && test_port_->text() == QStringLiteral("2500"))
          test_port_->setText(QStringLiteral("5201"));
        else if (index == 0 && test_port_->text() == QStringLiteral("5201"))
          test_port_->setText(QStringLiteral("2500"));
        send_size_->setEnabled(index == 0);
      });
      connect(measure_, &QPushButton::clicked, this, [this]() { transfer_measure_clicked(); });
      connect(test_host_, &QLineEdit::returnPressed, this, [this]() { transfer_measure_clicked(); });
      connect(open_result_, &QPushButton::clicked, this, [this]() { transfer_open_result(); });
      connect(clear_result_, &QPushButton::clicked, this, [this]() {
        storage_speed_.reset();
        storage_filled_.clear();
        storage_speed_edit_->clear();
        storage_text_->setText(storage_helper());
        clear_result_->setEnabled(false);
        transfer_recalculate();
      });
      connect(storage_speed_edit_, &QLineEdit::textEdited, this, [this](const QString& typed) {
        // A figure typed over the opened one replaces it.
        if (storage_speed_ && typed != storage_filled_) {
          storage_speed_.reset();
          storage_filled_.clear();
          storage_text_->setText(storage_helper());
        }
        clear_result_->setEnabled(!typed.isEmpty());
      });
      for (QLineEdit* field : {link_speed_, share_, reduced_, network_speed_edit_, storage_speed_edit_})
        connect(field, &QLineEdit::returnPressed, this, [this]() { run(Command::run); });
      connect(network_unit_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { transfer_recalculate(); });
      connect(storage_unit_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int index) {
        // Another unit for an opened figure makes it a figure of the engineer's own.
        if (storage_speed_ && index != kUnitMegabytes) {
          storage_speed_.reset();
          storage_filled_.clear();
          storage_text_->setText(storage_helper());
        }
        transfer_recalculate();
      });
      break;
    }
    case sg::ShortcutCommand::service_watch:
      add_input(QStringLiteral("Names that hold"), QStringLiteral("veeam"));
      input_->setText(QStringLiteral("veeam"));
      run_ = add_button(input_row, QStringLiteral("Start watching"));
      link_ = add_button(input_row, QStringLiteral("Its ports..."));
      link_->setEnabled(false);
      log_link_ = add_button(input_row, QStringLiteral("Its log..."));
      log_link_->setEnabled(false);
      break;
    default:
      break;
    }
    run_->setDefault(true);

    if (command == sg::ShortcutCommand::local_port_checker) {
      // The table and the selected port's detail on the left, the listener's panel on the right.
      auto* columns = new QHBoxLayout();
      columns->setSpacing(16);
      layout->addLayout(columns, 1);
      auto* left = new QVBoxLayout();
      left->setSpacing(8);
      columns->addLayout(left, 1);
      table_ = make_table({QStringLiteral("Port"), QStringLiteral("Protocol"), QStringLiteral("Verdict"),
                           QStringLiteral("Listening on"), QStringLiteral("Process"), QStringLiteral("Firewall")},
                          {70, 90, 170, 200, 250});
      left->addWidget(table_, 45);
      report_ = new ReportView();
      left->addWidget(report_, 55);

      auto* side = rounded_card(theme::themed_hex("#10262A"), theme::themed_hex(theme::veeam_green::card_border));
      side->setMinimumWidth(320);
      side->setMaximumWidth(400);
      columns->addWidget(side, 0);
      auto* panel = new QVBoxLayout(side);
      panel->setContentsMargins(12, 12, 12, 12);
      panel->setSpacing(6);
      side_title_ = styled_label(QStringLiteral("LISTENER"), theme::themed_hex(theme::veeam_green::card_title), 1.0, true);
      side_clock_ = styled_label(QStringLiteral("Not running"), theme::themed_hex("#E1ECE7"), 1.35, true);
      side_left_ = styled_label(QString(), theme::themed_hex("#96ACA5"));
      side_progress_ = new QProgressBar();
      side_progress_->setTextVisible(false);
      side_progress_->setFixedHeight(6);
      side_progress_->setStyleSheet(
          QStringLiteral("QProgressBar { background: %1; border: none; border-radius: 3px; }"
                         "QProgressBar::chunk { background: %2; border-radius: 3px; }")
              .arg(theme::themed_hex("#0D1F21"), theme::themed_hex("#55BE58")));
      side_progress_->hide();
      panel->addWidget(side_title_);
      panel->addWidget(side_clock_);
      panel->addWidget(side_left_);
      panel->addWidget(side_progress_);
      auto* minutes_row = new QHBoxLayout();
      auto* minutes_caption = new QLabel(QStringLiteral("Minutes"));
      minutes_caption->setMinimumWidth(64);
      minutes_row->addWidget(minutes_caption);
      minutes_ = new QSpinBox();
      minutes_->setRange(1, 60);
      minutes_->setValue(5);
      minutes_row->addWidget(minutes_);
      minutes_row->addStretch(1);
      panel->addLayout(minutes_row);
      auto* banner_row = new QHBoxLayout();
      auto* banner_caption = new QLabel(QStringLiteral("Banner"));
      banner_caption->setMinimumWidth(64);
      banner_row->addWidget(banner_caption);
      banner_ = new QLineEdit(qt_text(std::string(support_assist::kDefaultListenerBanner)));
      banner_->setPlaceholderText(QStringLiteral("sent to each TCP connection; empty sends none"));
      banner_row->addWidget(banner_, 1);
      panel->addLayout(banner_row);
      quick_scan_ = new QCheckBox(QStringLiteral("Quick scan"));
      {
        const auto support = support_assist::quick_scan_support();
        scan_available_ = support.available;
        scan_unavailable_ = support.reason;
      }
      quick_scan_->setEnabled(scan_available_);
      panel->addWidget(quick_scan_);
      scan_reading_ = styled_label(
          scan_available_ ? QStringLiteral("While the listener runs, Quick scan counts the attempts that arrive at the "
                                           "port and where they come from, against those that reach the listener. The "
                                           "capture stays in memory.")
                          : qt_text(scan_unavailable_),
          theme::themed_hex("#96ACA5"), 0.95);
      panel->addWidget(scan_reading_);
      auto* buttons = new QHBoxLayout();
      listen_start_ = add_button(buttons, QStringLiteral("Start listener"));
      listen_stop_ = add_button(buttons, QStringLiteral("Stop"));
      buttons->addStretch(1);
      listen_stop_->hide();
      listen_start_->setEnabled(false);
      panel->addLayout(buttons);
      listen_status_ = styled_label(
          QStringLiteral("Choose a port nothing listens on, then Start listener: the other machine can test the path "
                         "with the Remote Port Checker before the real service runs."),
          theme::themed_hex("#D6E4DE"));
      panel->addWidget(listen_status_);
      connections_ = make_table({QStringLiteral("Time"), QStringLiteral("From"), QStringLiteral("What happened")},
                                {64, 130});
      connections_->setSelectionMode(QAbstractItemView::NoSelection);
      panel->addWidget(connections_, 1);
    } else if (command == sg::ShortcutCommand::service_watch) {
      table_ = make_table({QStringLiteral("Kind"), QStringLiteral("Name"), QStringLiteral("State"), QStringLiteral("PID"),
                           QStringLiteral("Started"), QStringLiteral("Listening on")},
                          {80, 280, 110, 80, 200});
      events_ = make_table({QStringLiteral("Seen"), QStringLiteral("What changed")}, {200});
      // The guide shows where the two lists go once watching starts.
      report_ = new ReportView();
      layout->addWidget(report_, 100);
      layout->addWidget(table_, 55);
      layout->addWidget(events_, 45);
      table_->hide();
      events_->hide();
    } else if (command == sg::ShortcutCommand::volume_check) {
      // The volumes above, the chosen one's details below.
      QStringList headings;
      for (const std::string& title : sg::volume_columns())
        headings << qt_text(title);
      table_ = make_table(headings, {110, 110, 110, 200, 80, 110, 140});
      layout->addWidget(table_, 42);
      report_ = new ReportView();
      layout->addWidget(report_, 58);
    } else if (command == sg::ShortcutCommand::file_transfer_calculator) {
      auto* columns = new QHBoxLayout();
      columns->setSpacing(12);
      report_ = new ReportView();
      columns->addWidget(report_, 3);
      auto* side = new QVBoxLayout();
      side->setSpacing(8);
      side_report_ = new ReportView();
      side_report_->show_empty(QStringLiteral("The speeds, the email text and the terms show here after Calculate."));
      side->addWidget(side_report_, 1);
      email_ = new QPushButton(QStringLiteral("Copy for email"));
      email_->setEnabled(false);
      side->addWidget(email_);
      columns->addLayout(side, 2);
      layout->addLayout(columns, 6);
      connect(email_, &QPushButton::clicked, this, [this]() { copy_email(); });
    } else {
      report_ = new ReportView();
      layout->addWidget(report_, 6);
    }
    if (command == sg::ShortcutCommand::time_check) {
      // Under its heading: the timestamp and Convert, the log it came from and Log..., then Written
      // in and Show in.
      layout->addWidget(styled_label(QStringLiteral("LOG TIMESTAMP CONVERTER"),
                                     theme::themed_hex(theme::veeam_green::heading), 1.0, true));
      auto* timestamp_row = new QHBoxLayout();
      timestamp_row->setSpacing(8);
      auto* caption = new QLabel(QStringLiteral("Timestamp from a log"));
      caption->setMinimumWidth(150);
      timestamp_row->addWidget(caption);
      convert_input_ = new QLineEdit();
      convert_input_->setPlaceholderText(
          QStringLiteral("[29.09.2026 12:15:47.134], a whole line, 1694788094 or 638303848944280000"));
      timestamp_row->addWidget(convert_input_, 1);
      auto* convert = add_button(timestamp_row, QStringLiteral("Convert"));
      layout->addLayout(timestamp_row);

      auto* log_row = new QHBoxLayout();
      log_row->setSpacing(8);
      auto* log_caption = new QLabel(QStringLiteral("Log file"));
      log_caption->setMinimumWidth(150);
      log_row->addWidget(log_caption);
      log_input_ = new QLineEdit();
      log_input_->setPlaceholderText(QStringLiteral("Optional: the log it came from, for the log's own UTC offset"));
      log_row->addWidget(log_input_, 1);
      auto* log_browse = add_button(log_row, QStringLiteral("Log..."));
      layout->addLayout(log_row);

      auto* zones_row = new QHBoxLayout();
      zones_row->setSpacing(8);
      auto* written_caption = new QLabel(QStringLiteral("Written in"));
      written_caption->setMinimumWidth(150);
      zones_row->addWidget(written_caption);
      // From the log file, a zone from the list with its daylight saving dates, or a UTC offset typed in.
      offset_ = new QComboBox();
      offset_->setEditable(true);
      offset_->setInsertPolicy(QComboBox::NoInsert);
      offset_->addItem(qt_text(std::string(support_assist::kFromLogFile)));
      for (const auto& zone : support_assist::named_time_zones())
        offset_->addItem(qt_text(zone.name));
      offset_->view()->setMinimumWidth(440);
      offset_->setMinimumWidth(200);
      const auto here = support_assist::read_time_zone();
      const auto* named = support_assist::find_named_time_zone(here.name);
      offset_->setEditText(
          qt_text(named != nullptr ? named->name : support_assist::format_utc_offset(here.utc_offset_minutes)));
      offset_->lineEdit()->setPlaceholderText(QStringLiteral("A zone or UTC-05:00"));
      zones_row->addWidget(offset_, 1);
      zones_row->addWidget(new QLabel(QStringLiteral("Show in")));
      // The same moment in another zone, such as another machine's.
      show_in_ = new QComboBox();
      show_in_->setEditable(true);
      show_in_->setInsertPolicy(QComboBox::NoInsert);
      for (const auto& zone : support_assist::named_time_zones())
        show_in_->addItem(qt_text(zone.name));
      show_in_->view()->setMinimumWidth(440);
      show_in_->setMinimumWidth(200);
      show_in_->setEditText(QString());
      show_in_->lineEdit()->setPlaceholderText(QStringLiteral("Optional: another zone"));
      zones_row->addWidget(show_in_, 1);
      layout->addLayout(zones_row);

      convert_report_ = new ReportView();
      convert_report_->show_empty(QStringLiteral(
          "Paste a time or a whole line from a log and press Convert. Choose the log it came from, or drop it here, "
          "to read the log's own UTC offset; otherwise set the zone it was written in."));
      layout->addWidget(convert_report_, 4);
      connect(convert, &QPushButton::clicked, this, [this]() { convert_timestamp(); });
      for (QLineEdit* field : {convert_input_, log_input_, offset_->lineEdit(), show_in_->lineEdit()})
        connect(field, &QLineEdit::returnPressed, this, [this]() { convert_timestamp(); });
      connect(log_browse, &QPushButton::clicked, this, [this]() {
        const QString chosen =
            QFileDialog::getOpenFileName(this, QStringLiteral("Choose the log"), clean_path(log_input_->text()));
        if (!chosen.isEmpty()) {
          log_input_->setText(chosen);
          read_log_file(!convert_input_->text().trimmed().isEmpty());
        }
      });
      setAcceptDrops(true);
    }
    // The calculator opens in Manual, so its guide shows Manual's entries.
    if (report_ != nullptr)
      report_->show_report(sg::quick_tool_guide_report(
          tool_, tool_ == sg::ShortcutCommand::file_transfer_calculator ? sg::kTransferModeManual : ""));

    auto* bottom = new QHBoxLayout();
    bottom->setSpacing(8);
    status_ = new QLabel();
    status_->setProperty("role", "subtitle");
    bottom->addWidget(status_, 1);
    // The Local Port Checker's rows as CSV, or its result as the JSON the CLI prints with --json.
    if (command == sg::ShortcutCommand::local_port_checker) {
      export_ = add_button(bottom, QStringLiteral("Export\u2026"));
      export_->setEnabled(false);
    }
    copy_ = add_button(bottom, QStringLiteral("Copy"));
    note_ = add_button(bottom, QStringLiteral("Add to #note"));
    copy_->setEnabled(false);
    note_->setEnabled(false);
    // #note belongs to a case, and cases are Engineer Review's.
    note_->setVisible(!host_.casework || host_.casework());
    layout->addLayout(bottom);
    if (command == sg::ShortcutCommand::service_watch)
      status_->setText(QStringLiteral("Press Start watching. Every 2 seconds the list is read again and changes are "
                                      "listed below."));

    connect(run_, &QPushButton::clicked, this, [this]() { run(Command::run); });
    connect(input_, &QLineEdit::returnPressed, this, [this]() { run(Command::run); });
    // A new name has not been checked yet.
    connect(input_, &QLineEdit::textChanged, this, [this](const QString&) { resolved_address_.clear(); });
    if (browse_ != nullptr)
      connect(browse_, &QPushButton::clicked, this, [this]() { browse(false); });
    if (folder_browse_ != nullptr)
      connect(folder_browse_, &QPushButton::clicked, this, [this]() { browse(true); });
    if (link_ != nullptr)
      connect(link_, &QPushButton::clicked, this, [this]() { follow_link(); });
    if (process_run_ != nullptr) {
      connect(process_run_, &QPushButton::clicked, this, [this]() { run(Command::process); });
      connect(process_, &QLineEdit::returnPressed, this, [this]() { run(Command::process); });
      connect(preset_, qOverload<int>(&QComboBox::currentIndexChanged), this, [this](int) { run(Command::preset); });
      connect(listen_start_, &QPushButton::clicked, this, [this]() { start_listener(); });
      connect(listen_stop_, &QPushButton::clicked, this, [this]() {
        if (listener_)
          listener_->cancel();
      });
    }
    if (table_ != nullptr)
      connect(table_, &QTableWidget::itemSelectionChanged, this, [this]() { row_selected(); });
    if (log_link_ != nullptr) {
      connect(events_, &QTableWidget::itemSelectionChanged, this,
              [this]() { log_link_->setEnabled(selected_ended_event() != nullptr); });
      connect(log_link_, &QPushButton::clicked, this, [this]() { find_its_log(); });
    }
    connect(copy_, &QPushButton::clicked, this, [this]() { copy_result(); });
    if (export_ != nullptr)
      connect(export_, &QPushButton::clicked, this, [this]() { export_ports(); });
    connect(note_, &QPushButton::clicked, this, [this]() { add_to_note(); });
    // Escape closes a quick tool's window; a task's view closes with its session tab.
    if (!embedded)
      connect(new QShortcut(QKeySequence(Qt::Key_Escape), this), &QShortcut::activated, this, [this]() { close(); });

    watch_timer_ = new QTimer(this);
    watch_timer_->setInterval(2000);
    connect(watch_timer_, &QTimer::timeout, this, [this]() { watch_tick(); });
    countdown_timer_ = new QTimer(this);
    countdown_timer_->setInterval(1000);
    connect(countdown_timer_, &QTimer::timeout, this, [this]() { show_countdown(); });
    // While a port check's result is shown, the sockets and the firewall are read again every 5
    // seconds, so a port opened or a rule added later shows without another check.
    live_check_timer_ = new QTimer(this);
    live_check_timer_->setInterval(5000);
    connect(live_check_timer_, &QTimer::timeout, this, [this]() { recheck_ports(); });

    input_->setFocus();
    if (command == sg::ShortcutCommand::time_check || command == sg::ShortcutCommand::volume_check)
      QTimer::singleShot(0, this, [this]() { run(Command::run); });
  }

  ~QuickToolWindow() override {
    if (listener_)
      listener_->cancel();
    if (transfer_cancel_)
      transfer_cancel_->cancel();
    stop_scan_in_background(std::move(scan_));
  }

  sg::ShortcutCommand tool() const { return tool_; }

#ifdef SUPPORT_ASSIST_UI_SELFCHECK
  // Runs the tool's main check on `text` (the ports, for the Local Port Checker).
  // The File Transfer Calculator: figures typed and calculated, then Live test and a network test.
  void selfcheck_transfer(const QString& size, const QString& link) {
    input_->setText(size);
    link_speed_->setText(link);
    run(Command::run);
  }
  void selfcheck_transfer_measure(const QString& host, int port) {
    transfer_mode(true);
    test_host_->setText(host);
    test_port_->setText(QString::number(port));
    run(Command::measure);
  }
  std::size_t selfcheck_adapter_count() const { return adapters_.size(); }
  // The Object Storage Check against a stand-in: on-site storage at the endpoint, its certificate
  // trusted by fingerprint, the test keys, and the product to compare with.
  void selfcheck_object_storage(const QString& endpoint, const QString& fingerprint, const QString& access,
                                const QString& secret, int product) {
    for (std::size_t index = 0; index < storage_presets_.size(); ++index) {
      if (storage_presets_[index].id == "on-site")
        storage_preset_->setCurrentIndex(static_cast<int>(index));
    }
    endpoint_->setText(endpoint);
    input_->setText(QStringLiteral("veeam-test"));
    access_->setText(access);
    secret_->setText(secret);
    trust_->setCurrentIndex(2);
    fingerprint_->setText(fingerprint);
    product_->setCurrentIndex(product);
    run(Command::run);
  }
  QString selfcheck_report_text() const { return last_report_ ? qt_text(sg::report_text(*last_report_)) : QString(); }
  QString selfcheck_email() const {
    return estimate_ ? qt_text(sg::file_transfer_email_text(*estimate_)) : QString();
  }
  void selfcheck_run(const QString& text) {
    input_->setText(text);
    run(Command::run);
  }
  bool selfcheck_busy() const { return running_ || watch_busy_ || reading_log_; }
  bool selfcheck_has_result() const {
    return last_report_.has_value() || ports_.has_value() || snapshot_.has_value();
  }
  QString selfcheck_headline() const {
    return last_report_ ? qt_text(last_report_->headline) : status_->text();
  }
  int selfcheck_table_rows() const { return table_ == nullptr ? -1 : table_->rowCount(); }
  int selfcheck_squeezed_report() const { return report_ == nullptr ? 0 : report_->selfcheck_squeezed_labels(); }
  // The Local Port Checker's listener, on the port selected after a check.
  bool selfcheck_start_listener() {
    if (listen_start_ == nullptr || !listen_start_->isEnabled())
      return false;
    start_listener();
    return listener_ != nullptr;
  }
  void selfcheck_stop_listener() {
    if (listener_)
      listener_->cancel();
  }
  bool selfcheck_listening() const { return listener_ != nullptr; }
  int selfcheck_connections() const { return connections_ == nullptr ? -1 : connections_->rowCount(); }
  QString selfcheck_panel() const {
    return side_title_ == nullptr ? QString()
                                  : side_title_->text() + QStringLiteral(" | ") + side_clock_->text() +
                                        QStringLiteral(" | ") + side_left_->text();
  }
  QString selfcheck_listener_row() const {
    const QTableWidgetItem* verdict = listener_row_ < 0 ? nullptr : table_->item(listener_row_, 2);
    return verdict == nullptr ? QString() : verdict->text();
  }
  // Time Check's converter: the zones listed, and the UTC a timestamp converts to from `written_in`.
  int selfcheck_zone_count() const { return offset_ == nullptr ? -1 : offset_->count() - 1; }
  // The converter with a log: the log read on its worker, Written in after it, and a time converted
  // with the log's own clock and shown in another zone ("headline | Shown in").
  void selfcheck_read_log(const QString& file) {
    if (log_input_ == nullptr)
      return;
    log_input_->setText(file);
    read_log_file(false);
  }
  QString selfcheck_written_in() const { return offset_ == nullptr ? QString() : offset_->currentText(); }
  QString selfcheck_convert_shown(const QString& timestamp, const QString& show_in) {
    if (convert_input_ == nullptr || show_in_ == nullptr)
      return {};
    convert_input_->setText(timestamp);
    show_in_->setEditText(show_in);
    convert_timestamp();
    if (!last_report_)
      return status_->text();
    QString shown;
    for (const auto& section : last_report_->sections) {
      for (const auto& row : section.rows) {
        if (row.label == "Shown in")
          shown = qt_text(row.value);
      }
    }
    return qt_text(last_report_->headline) + QStringLiteral(" | ") + shown;
  }
  QString selfcheck_convert(const QString& timestamp, const QString& written_in) {
    if (convert_input_ == nullptr || offset_ == nullptr)
      return {};
    convert_input_->setText(timestamp);
    offset_->setEditText(written_in);
    convert_timestamp();
    return last_report_ ? qt_text(last_report_->headline) : status_->text();
  }
#endif

  // A hand-off from another tool: the subject goes in the tool's field and the check runs.
  void run_subject(const QString& subject) {
    if (subject.isEmpty())
      return;
    if (tool_ == sg::ShortcutCommand::local_port_checker) {
      process_->setText(subject);
      run(Command::process);
    } else {
      input_->setText(subject);
      run(Command::run);
    }
  }

private:
  enum class Command { run, process, preset, measure };


  static QTableWidget* make_table(const QStringList& headings, const std::vector<int>& widths) {
    auto* table = new QTableWidget(0, static_cast<int>(headings.size()));
    table->setHorizontalHeaderLabels(headings);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setShowGrid(false);
    table->setWordWrap(false);
    for (std::size_t column = 0; column < widths.size(); ++column)
      table->setColumnWidth(static_cast<int>(column), widths[column]);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
  }

  static void set_row(QTableWidget* table, int row, const QStringList& cells) {
    for (int column = 0; column < cells.size(); ++column) {
      auto* item = new QTableWidgetItem(cells[column]);
      item->setToolTip(cells[column]);
      table->setItem(row, column, item);
    }
  }

  void set_status(const QString& text) { status_->setText(text); }

  void activity(const QString& result, const QString& detail) {
    if (host_.activity)
      host_.activity(tool_title(tool_), result, detail);
  }

  bool case_active() const { return host_.active_case && host_.active_case().has_value(); }

  // Runs work on a worker; done() runs on the GUI thread if the window is still open.
  template <typename Work> void in_background(Work work) {
    QPointer<QuickToolWindow> self(this);
    std::thread([self, work]() mutable {
      auto outcome = std::make_shared<Outcome>();
      try {
        *outcome = work();
      } catch (const std::exception& failure) {
        outcome->error = failure.what();
      }
      QMetaObject::invokeMethod(
          qApp,
          [self, outcome]() {
            if (!self.isNull())
              self->finished(std::move(*outcome));
          },
          Qt::QueuedConnection);
    }).detach();
  }

  void run(Command command) {
    if (running_)
      return;
    const std::string input = support_assist::trim(input_->text().toStdString());
    switch (tool_) {
    case sg::ShortcutCommand::name_check:
      if (input.empty()) {
        set_status(QStringLiteral("Type a name or an address first."));
        return;
      }
      running_ = true;
      set_status(QStringLiteral("Checking %1...").arg(qt_text(input)));
      in_background([input]() {
        Outcome outcome;
        support_assist::CancellationSource cancel;
        const auto result = support_assist::check_name(input, cancel.token());
        outcome.report = sg::name_check_report(result);
        outcome.result_json = support_assist::tool_json::name_check(result);
        outcome.report->checked_unix_millis = support_assist::unix_millis_now();
        outcome.resolved_address = result.is_address ? input
                                   : result.addresses.empty() ? std::string()
                                                              : result.addresses.front();
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = input;
        return outcome;
      });
      return;
    case sg::ShortcutCommand::object_storage_check: {
      const int chosen = storage_preset_->currentIndex();
      if (chosen < 0 || static_cast<std::size_t>(chosen) >= storage_presets_.size())
        return;
      support_assist::ObjectStorageOptions options;
      options.target.preset = storage_presets_[static_cast<std::size_t>(chosen)].id;
      options.target.bucket = input;
      options.target.endpoint = support_assist::trim(endpoint_->text().toStdString());
      options.target.region = support_assist::trim(region_->currentText().toStdString());
      const int product = product_->currentIndex();
      if (product >= 0 && static_cast<std::size_t>(product) < product_ids_.size())
        options.product = product_ids_[static_cast<std::size_t>(product)];
      const int style = addressing_->currentIndex();
      options.target.addressing = style == 1 ? "virtual-hosted" : style == 2 ? "path" : "";
      const std::string certificate = support_assist::trim(clean_path(fingerprint_->text()).toStdString());
      if (trust_->currentIndex() == 1)
        options.target.certificate_file = certificate;
      else if (trust_->currentIndex() == 2)
        options.target.pinned_sha256 = certificate;
      if (trust_->currentIndex() != 0 && certificate.empty()) {
        set_status(trust_->currentIndex() == 1 ? QStringLiteral("Open the certificate file, or type its path.")
                                               : QStringLiteral("Type the SHA-256 fingerprint."));
        return;
      }
      const auto endpoint = support_assist::resolve_object_storage_endpoint(options.target);
      if (!endpoint.ok()) {
        set_status(qt_text(endpoint.error().message));
        return;
      }
      support_assist::ObjectStorageCredentials keys;
      keys.access_key = support_assist::trim(access_->text().toStdString());
      keys.secret_key = secret_->text().toStdString();
      if (!keys.access_key.empty() && !keys.secret_key.empty()) {
        options.credentials = keys;
        const auto estimate = support_assist::estimate_object_storage_check(options.target);
        if (estimate.needs_agreement) {
          options.accept_cost =
              QMessageBox::question(this, QStringLiteral("Object Storage Check"),
                                    qt_text(estimate.text) + QStringLiteral("\n\nSend the signed reads?"),
                                    QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes;
          if (!options.accept_cost)
            options.credentials.reset();
        }
      }
      running_ = true;
      set_status(QStringLiteral("Checking %1...").arg(qt_text(endpoint.value().request_host)));
      in_background([options]() {
        Outcome outcome;
        support_assist::CancellationSource cancel;
        auto result = support_assist::check_object_storage(options, cancel.token());
        if (!result.ok()) {
          outcome.error = result.error().message;
          return outcome;
        }
        outcome.report = sg::object_storage_report(result.value());
        outcome.result_json = support_assist::tool_json::object_storage(result.value());
        outcome.clock_offset_seconds = result.value().clock_offset_seconds;
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = result.value().endpoint.request_host;
        return outcome;
      });
      return;
    }
    case sg::ShortcutCommand::file_transfer_calculator: {
      if (command == Command::measure) {
        // The network test on a worker: SAT's listener, or an iPerf3 server, on the port given.
        const std::string host = support_assist::trim(test_host_->text().toStdString());
        if (host.empty()) {
          set_status(QStringLiteral("Type the machine to test to first."));
          return;
        }
        bool port_ok = false;
        const int port = test_port_->text().trimmed().toInt(&port_ok);
        if (!port_ok || port < 1 || port > 65535) {
          set_status(QStringLiteral("The port is a number from 1 to 65535."));
          return;
        }
        const int using_index = using_->currentIndex();
        const int send_index = send_size_->currentIndex();
        const std::uint64_t bytes = (send_index == 2 ? 8ULL : send_index == 1 ? 4ULL : 1ULL) << 30U;
        const std::filesystem::path tools = host_.tools_folder ? host_.tools_folder() : std::filesystem::path();
        auto cancel = std::make_shared<support_assist::CancellationSource>();
        transfer_cancel_ = cancel;
        running_ = true;
        measure_->setText(QStringLiteral("Stop"));
        set_status((using_index >= 1 ? QStringLiteral("iPerf3 to ") : QStringLiteral("Sending to SAT's listener on ")) +
                   qt_text(host) + QStringLiteral(", port ") + QString::number(port) + QStringLiteral("..."));
        const auto port_number = static_cast<std::uint16_t>(port);
        in_background([host, port_number, bytes, using_index, cancel, tools]() {
          Outcome outcome;
          outcome.transfer_measure = true;
          outcome.activity_detail = host + ":" + std::to_string(port_number);
          if (using_index >= 1) {
            support_assist::IperfTransferOptions iperf;
            iperf.host = host;
            iperf.port = port_number;
            iperf.streams = using_index == 2 ? 4 : 1;
            iperf.tools_folder = tools;
            auto speed = support_assist::run_iperf3_transfer_test(iperf, cancel->token());
            if (!speed.ok()) {
              outcome.error = speed.error().message;
              return outcome;
            }
            outcome.activity_result =
                support_assist::transfer_rate_text(speed.value().bytes_per_second) + ", " + speed.value().detail;
            outcome.transfer_speed = speed.value();
            return outcome;
          }
          support_assist::TransferTestOptions test;
          test.host = host;
          test.port = port_number;
          test.bytes = bytes;
          auto measured = support_assist::run_transfer_test(test, cancel->token());
          if (!measured.ok()) {
            outcome.error = measured.error().message;
            return outcome;
          }
          if (measured.value().cancelled) {
            outcome.error = "The network test stopped before it finished.";
            return outcome;
          }
          support_assist::TransferSpeed speed;
          speed.name = "Network test to " + host;
        speed.phrase = "the network test to " + host;
          speed.detail = measured.value().answered_by + ", one connection, " +
                         support_assist::link_speed_text(measured.value().bytes_per_second * 8.0);
          speed.bytes_per_second = measured.value().bytes_per_second;
          outcome.activity_result = support_assist::transfer_rate_text(speed.bytes_per_second) + ", " + speed.detail;
          outcome.transfer_speed = std::move(speed);
          outcome.transfer_ipv6 = measured.value().ipv6;
          return outcome;
        });
        return;
      }
      support_assist::TransferInputs inputs;
      QString problem;
      if (!transfer_read_inputs(inputs, problem)) {
        set_status(problem);
        return;
      }
      auto estimate = support_assist::estimate_transfer(inputs);
      if (!estimate.ok()) {
        set_status(qt_text(estimate.error().message));
        return;
      }
      transfer_show(estimate.value(), false);
      return;
    }
    case sg::ShortcutCommand::time_check:
      running_ = true;
      set_status(QStringLiteral("Asking the time source..."));
      in_background([input]() {
        Outcome outcome;
        support_assist::CancellationSource cancel;
        const auto result = support_assist::check_time(input, cancel.token());
        outcome.report = sg::time_check_report(result);
        outcome.result_json = support_assist::tool_json::time_check(result);
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = result.sntp.server;
        return outcome;
      });
      return;
    case sg::ShortcutCommand::file_lock_check: {
      if (input.empty()) {
        set_status(QStringLiteral("Choose a file or a folder first."));
        return;
      }
      // A folder: the folder and everything under it.
      const bool folder = QFileInfo(qt_text(input)).isDir();
      running_ = true;
      set_status(folder ? QStringLiteral("Checking every file under %1...").arg(qt_text(input))
                        : QStringLiteral("Checking..."));
      in_background([input, folder, self = QPointer<QuickToolWindow>(this)]() {
        Outcome outcome;
        if (folder) {
          support_assist::CancellationSource cancel;
          // The rows found so far reach the window while the walk runs.
          const auto stream = [self](const support_assist::FolderLockResult& partial) {
            auto report = std::make_shared<sg::QuickToolReport>(sg::folder_lock_progress_report(partial));
            QMetaObject::invokeMethod(
                qApp,
                [self, report]() {
                  if (!self.isNull())
                    self->show_partial(*report);
                },
                Qt::QueuedConnection);
          };
          auto result = support_assist::find_folder_holders(input, cancel.token(),
                                                            support_assist::kFolderLockMaxEntries, stream);
          if (!result.ok()) {
            outcome.error = result.error().message;
            return outcome;
          }
          outcome.report = sg::folder_lock_report(result.value());
          outcome.result_json = support_assist::tool_json::folder_lock(result.value());
          outcome.report->checked_unix_millis = support_assist::unix_millis_now();
          outcome.activity_result = outcome.report->headline;
          outcome.activity_detail = input;
          return outcome;
        }
        auto result = support_assist::find_file_holders(input);
        if (!result.ok()) {
          outcome.error = result.error().message;
          return outcome;
        }
        outcome.report = sg::file_lock_report(result.value());
        outcome.result_json = support_assist::tool_json::file_lock(result.value());
        outcome.report->checked_unix_millis = support_assist::unix_millis_now();
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = input;
        return outcome;
      });
      return;
    }
    case sg::ShortcutCommand::volume_check: {
      // Every volume, read again each time; with a folder, that folder too.
      running_ = true;
      set_status(input.empty() ? QStringLiteral("Reading the volumes...")
                               : QStringLiteral("Checking %1...").arg(qt_text(input)));
      in_background([input]() {
        Outcome outcome;
        auto volumes = support_assist::list_volumes();
        if (volumes.ok())
          outcome.volumes = std::move(volumes.value());
        const std::string listed_json =
            outcome.volumes ? support_assist::tool_json::volumes(*outcome.volumes) : std::string("[]");
        if (input.empty()) {
          if (!volumes.ok()) {
            outcome.error = volumes.error().message;
            return outcome;
          }
          const auto listed = outcome.volumes->size();
          outcome.activity_result = std::to_string(listed) + (listed == 1 ? " volume" : " volumes");
          outcome.result_json = "{\"volumes\":" + listed_json + "}";
          return outcome;
        }
        auto result = support_assist::check_volume(input);
        if (!result.ok()) {
          outcome.error = result.error().message;
          return outcome;
        }
        outcome.report = sg::volume_report(result.value());
        outcome.result_json =
            "{\"folder\":" + support_assist::tool_json::volume(result.value()) + ",\"volumes\":" + listed_json + "}";
        outcome.report->checked_unix_millis = support_assist::unix_millis_now();
        outcome.activity_result = outcome.report->headline;
        outcome.activity_detail = input;
        return outcome;
      });
      return;
    }
    case sg::ShortcutCommand::local_port_checker: {
      std::vector<std::uint16_t> tcp_ports;
      std::vector<std::uint16_t> udp_ports;
      support_assist::PortQueryExtras extras;
      std::string process;
      std::string detail;
      if (command == Command::preset) {
        const int selection = preset_->currentIndex();
        if (selection <= 0 || static_cast<std::size_t>(selection) > presets_.size())
          return;
        const auto& preset = presets_[static_cast<std::size_t>(selection - 1)];
        support_assist::preset_ports(preset, tcp_ports, udp_ports);
        extras = support_assist::preset_extras(preset);
        detail = "role " + preset.name;
      } else if (command == Command::process) {
        process = support_assist::trim(process_->text().toStdString());
        if (process.empty()) {
          set_status(QStringLiteral("Type a process name or a PID first."));
          return;
        }
        detail = "process " + process;
      } else {
        auto ports = support_assist::parse_port_list(input);
        if (!ports.ok()) {
          set_status(qt_text(ports.error().message));
          return;
        }
        if (!tcp_->isChecked() && !udp_->isChecked()) {
          set_status(QStringLiteral("Tick TCP, UDP or both."));
          return;
        }
        if (tcp_->isChecked())
          tcp_ports = ports.value();
        if (udp_->isChecked())
          udp_ports = ports.value();
        detail = "ports " + input;
      }
      checked_tcp_ = tcp_ports;
      checked_udp_ = udp_ports;
      checked_extras_ = extras;
      checked_process_ = process;
      has_check_ = true;
      live_check_timer_->start();
      running_ = true;
      set_status(QStringLiteral("Reading this machine's sockets and firewall..."));
      in_background([tcp_ports, udp_ports, extras, process, detail]() {
        Outcome outcome;
        auto result = process.empty() ? support_assist::check_local_ports(tcp_ports, udp_ports, extras)
                                       : support_assist::check_process_ports(process);
        if (!result.ok()) {
          outcome.error = result.error().message;
          return outcome;
        }
        outcome.ports = std::move(result.value());
        outcome.activity_result = std::to_string(outcome.ports->rows.size()) + " port(s) checked";
        outcome.activity_detail = detail;
        outcome.result_json = support_assist::tool_json::port_check(*outcome.ports);
        return outcome;
      });
      return;
    }
    case sg::ShortcutCommand::service_watch:
      if (watching_) {
        watching_ = false;
        watch_timer_->stop();
        run_->setText(QStringLiteral("Start watching"));
        set_status(QStringLiteral("Stopped. %1 change(s) seen.").arg(static_cast<qulonglong>(watch_events_.size())));
        activity(QStringLiteral("Stopped"), QStringLiteral("%1: %2 change(s)")
                                                .arg(qt_text(input))
                                                .arg(static_cast<qulonglong>(watch_events_.size())));
        if (snapshot_)
          keep_output(watch_output(input));
        return;
      }
      watching_ = true;
      snapshot_.reset();
      watch_events_.clear();
      events_->setRowCount(0);
      report_->hide();
      table_->show();
      events_->show();
      run_->setText(QStringLiteral("Stop watching"));
      set_status(QStringLiteral("Reading services and processes..."));
      activity(QStringLiteral("Started"), qt_text(input));
      watch_timer_->start();
      watch_tick();
      return;
    default:
      return;
    }
  }

  void watch_tick() {
    if (watch_busy_)
      return;
    watch_busy_ = true;
    const std::string filter = support_assist::trim(input_->text().toStdString());
    in_background([filter]() {
      Outcome outcome;
      outcome.snapshot = support_assist::take_watch_snapshot(filter);
      return outcome;
    });
  }

  // A report of work still running; the final result follows.
  void show_partial(const sg::QuickToolReport& report) {
    if (!running_)
      return;
    report_->show_report(report);
    set_status(qt_text(report.headline));
  }

  void finished(Outcome outcome) {
    if (outcome.log_clock) {
      // A path changed while this one was read: the newer read answers.
      if (outcome.log_path != log_clock_path_.toStdString())
        return;
      reading_log_ = false;
      log_clock_ = outcome.log_clock;
      // A log that ties its clock to UTC is read by it.
      if (support_assist::summarize_log_clock(*log_clock_).tied)
        offset_->setEditText(qt_text(std::string(support_assist::kFromLogFile)));
      const bool convert_now =
          convert_after_read_ && !convert_input_->text().trimmed().isEmpty() && log_clock_->error.empty();
      convert_after_read_ = false;
      if (convert_now) {
        convert_timestamp();
        return;
      }
      const auto report = sg::log_clock_report(*log_clock_);
      convert_report_->show_report(report);
      last_report_ = report;
      set_status(qt_text(report.headline));
      copy_->setEnabled(true);
      note_->setEnabled(case_active());
      return;
    }
    if (outcome.snapshot) {
      watch_busy_ = false;
      if (watching_)
        fill_watch(*outcome.snapshot);
      return;
    }
    if (outcome.logs_near) {
      log_link_->setEnabled(true);
      choose_log(*outcome.logs_near, outcome.logs_near_at, outcome.logs_near_name);
      return;
    }
    if (outcome.transfer_measure) {
      running_ = false;
      transfer_cancel_.reset();
      measure_->setText(QStringLiteral("Measure"));
      if (!outcome.error.empty()) {
        set_status(qt_text(outcome.error));
        activity(QStringLiteral("Network test failed"), qt_text(outcome.error));
        return;
      }
      network_speed_ = outcome.transfer_speed;
      network_ipv6_ = outcome.transfer_ipv6;
      activity(qt_text(outcome.activity_result), qt_text(outcome.activity_detail));
      // The calculation again with the measured speed, kept as this run's output.
      support_assist::TransferInputs inputs;
      QString problem;
      if (!transfer_read_inputs(inputs, problem)) {
        set_status(QStringLiteral("Measured ") + qt_text(outcome.activity_result) + QStringLiteral(". ") + problem);
        return;
      }
      auto estimate = support_assist::estimate_transfer(inputs);
      if (estimate.ok())
        transfer_show(estimate.value(), true);
      return;
    }
    running_ = false;
    if (outcome.volumes) {
      volumes_ = std::move(*outcome.volumes);
      volumes_read_unix_millis_ = support_assist::unix_millis_now();
      fill_volumes();
      copy_->setEnabled(!volumes_.empty());
      note_->setEnabled(!volumes_.empty() && case_active());
    }
    if (!outcome.error.empty()) {
      set_status(qt_text(outcome.error));
      if (!outcome.quiet)
        activity(QStringLiteral("Failed"), qt_text(outcome.error));
      return;
    }
    if (tool_ == sg::ShortcutCommand::volume_check && !outcome.report) {
      // A new list: the guide again until a volume is chosen.
      last_report_.reset();
      report_->show_report(sg::quick_tool_guide_report(tool_));
      link_->setEnabled(false);
      set_status(qt_text(outcome.activity_result) + QStringLiteral(". Choose one for its details."));
      activity(qt_text(outcome.activity_result), QString());
      const auto listed = sg::volumes_report(volumes_);
      keep_output(sg::quick_tool_output_of(tool_title(tool_).toStdString(), outcome.result_json, listed));
      return;
    }
    if (outcome.ports) {
      ports_ = std::move(outcome.ports);
      if (export_ != nullptr)
        export_->setEnabled(true);
      fill_ports();
      QString status = qt_text(outcome.activity_result) + QStringLiteral(", ") +
                       qt_text(sg::report_detail::utc_text(ports_->checked_unix_millis));
      if (!ports_->sockets_note.empty())
        status += QStringLiteral(". ") + qt_text(ports_->sockets_note);
      set_status(status);
      if (outcome.quiet)
        return;
    } else if (outcome.report) {
      report_->show_report(*outcome.report);
      last_report_ = *outcome.report;
      resolved_address_ = outcome.resolved_address;
      set_status(qt_text(outcome.report->headline));
      copy_->setEnabled(true);
      note_->setEnabled(case_active());
      if (tool_ == sg::ShortcutCommand::volume_check)
        link_->setEnabled(has_guide_row(*outcome.report));
      if (tool_ == sg::ShortcutCommand::object_storage_check)
        link_->setEnabled(outcome.clock_offset_seconds && std::fabs(*outcome.clock_offset_seconds) >= 60.0);
    }
    activity(qt_text(outcome.activity_result), qt_text(outcome.activity_detail));
    if (outcome.report) {
      keep_output(sg::quick_tool_output_of(tool_title(tool_).toStdString(), outcome.result_json, *outcome.report));
    } else if (ports_) {
      keep_output({tool_title(tool_).toStdString(), outcome.result_json, sg::port_check_text(*ports_),
                   outcome.activity_result, sg::ReportTone::normal});
    }
  }

  void keep_output(const sg::QuickToolOutput& output) {
    if (host_.keep_output)
      host_.keep_output(output);
  }

public:
  // Add to #note shows where there are cases: Engineer Review.
  void set_casework(bool casework) {
    note_->setVisible(casework);
  }

private:

  static bool has_guide_row(const sg::QuickToolReport& report) {
    for (const auto& section : report.sections)
      for (const auto& row : section.rows)
        if (row.label == "Guide")
          return true;
    return false;
  }

  // Volume Check's table from the last list, its Fast Clone column in the tone of its verdict.
  void fill_volumes() {
    const QSignalBlocker quiet(table_); // a new list selects nothing
    table_->setRowCount(static_cast<int>(volumes_.size()));
    for (std::size_t index = 0; index < volumes_.size(); ++index) {
      QStringList cells;
      for (const std::string& cell : sg::volume_row(volumes_[index]))
        cells << qt_text(cell);
      set_row(table_, static_cast<int>(index), cells);
      const auto tone = sg::report_detail::fast_clone_tone(volumes_[index].fast_clone_state);
      if (QTableWidgetItem* verdict = table_->item(static_cast<int>(index), 7); verdict != nullptr && tone != sg::ReportTone::normal)
        verdict->setForeground(QColor(tone_text_hex(tone)));
    }
    table_->clearSelection();
  }

  void fill_ports() {
    table_->setRowCount(0);
    if (!ports_)
      return;
    table_->setRowCount(static_cast<int>(ports_->rows.size()));
    for (std::size_t index = 0; index < ports_->rows.size(); ++index) {
      const auto& row = ports_->rows[index];
      QString owner;
      if (!row.state.owners.empty()) {
        const auto& first = row.state.owners.front();
        owner = first.pid == 0 ? QStringLiteral("not readable by this account")
                               : QStringLiteral("%1 (PID %2)").arg(qt_text(first.process_name)).arg(first.pid);
      }
      const QString firewall = row.firewall.mixed ? QStringLiteral("differs by profile")
                                                  : qt_text(support_assist::to_string(row.firewall.decision));
      set_row(table_, static_cast<int>(index),
              {qt_text(support_assist::port_label(row)), qt_text(support_assist::to_string(row.state.protocol)),
               qt_text(support_assist::to_string(row.verdict)),
               qt_text(sg::report_detail::joined(row.state.listen_addresses)), owner, firewall});
      if (QTableWidgetItem* verdict = table_->item(static_cast<int>(index), 2)) {
        const auto tone = sg::report_detail::tone_of(row.verdict);
        if (tone != sg::ReportTone::normal)
          verdict->setForeground(QColor(tone_text_hex(tone)));
      }
    }
    // The listener's port shows SAT listening, with the time left.
    listener_row_ = -1;
    for (std::size_t index = 0; listener_ && index < ports_->rows.size(); ++index) {
      const auto& row = ports_->rows[index];
      if (row.state.port == listener_port_ && (row.state.protocol == support_assist::PortProtocol::udp) == listener_udp_) {
        listener_row_ = static_cast<int>(index);
        show_listener_row();
      }
    }
    // The port chosen before, when the table is filled again.
    int chosen = 0;
    for (std::size_t index = 0; index < ports_->rows.size(); ++index) {
      if (ports_->rows[index].state.port == selected_port_ && ports_->rows[index].state.protocol == selected_protocol_)
        chosen = static_cast<int>(index);
    }
    if (!ports_->rows.empty())
      table_->selectRow(chosen);
    else
      row_selected();
  }

  // The listener's row: SAT listening, and the time left in the Process column.
  void show_listener_row() {
    if (listener_row_ < 0 || !listener_)
      return;
    const auto left = std::chrono::duration_cast<std::chrono::seconds>(listener_until_ - std::chrono::steady_clock::now());
    if (QTableWidgetItem* verdict = table_->item(listener_row_, 2)) {
      verdict->setText(QStringLiteral("SAT listening"));
      verdict->setForeground(QColor(tone_text_hex(sg::ReportTone::good)));
    }
    if (QTableWidgetItem* process = table_->item(listener_row_, 4))
      process->setText(QStringLiteral("SAT listener, %1 left").arg(minutes_seconds(left.count())));
  }

  // The check again, with what it read last, so the listener's row comes and goes.
  void recheck_ports() {
    if (!has_check_ || running_)
      return;
    running_ = true;
    const auto tcp_ports = checked_tcp_;
    const auto udp_ports = checked_udp_;
    const auto extras = checked_extras_;
    const std::string process = checked_process_;
    in_background([tcp_ports, udp_ports, extras, process]() {
      Outcome outcome;
      outcome.quiet = true;
      auto result = process.empty() ? support_assist::check_local_ports(tcp_ports, udp_ports, extras)
                                    : support_assist::check_process_ports(process);
      if (!result.ok()) {
        outcome.error = result.error().message;
        return outcome;
      }
      outcome.ports = std::move(result.value());
      outcome.activity_result = std::to_string(outcome.ports->rows.size()) + " port(s) checked";
      return outcome;
    });
  }

  void row_selected() {
    const int row = table_->currentRow();
    if (tool_ == sg::ShortcutCommand::service_watch) {
      link_->setEnabled(row >= 0);
      return;
    }
    if (tool_ == sg::ShortcutCommand::volume_check) {
      if (row < 0 || static_cast<std::size_t>(row) >= volumes_.size() || table_->selectedItems().isEmpty())
        return;
      auto report = sg::volume_report(volumes_[static_cast<std::size_t>(row)]);
      report.checked_unix_millis = volumes_read_unix_millis_;
      report_->show_report(report);
      link_->setEnabled(has_guide_row(report));
      set_status(qt_text(report.headline));
      last_report_ = std::move(report);
      copy_->setEnabled(true);
      note_->setEnabled(case_active());
      return;
    }
    if (!ports_ || row < 0 || static_cast<std::size_t>(row) >= ports_->rows.size()) {
      report_->show_report(sg::quick_tool_guide_report(tool_));
      listen_start_->setEnabled(false);
      last_report_.reset();
      return;
    }
    const auto& port_row = ports_->rows[static_cast<std::size_t>(row)];
    selected_port_ = port_row.state.port;
    selected_protocol_ = port_row.state.protocol;
    auto report = sg::port_detail_report(port_row, ports_->firewall);
    report.checked_unix_millis = ports_->checked_unix_millis;
    const bool free_port = !port_row.state.found;
    if (free_port) {
      // The firewall's verdict for SAT's own listener here, which can differ from its verdict for
      // the Veeam program that uses the port.
      const auto verdict = support_assist::evaluate_inbound(ports_->firewall, port_row.state.protocol,
                                                            port_row.state.port,
                                                            support_assist::current_executable_path(), "");
      sg::ReportSection listener{"A listener from SAT on this port", {}, {}};
      for (const auto& profile : verdict.per_profile)
        listener.rows.push_back({profile.profile, support_assist::to_string(profile.decision) + ": " + profile.because,
                                 sg::report_detail::tone_of(profile.decision)});
      if (verdict.per_profile.empty())
        listener.rows.push_back({"Firewall", support_assist::to_string(verdict.decision) +
                                                 (verdict.note.empty() ? std::string() : ": " + verdict.note),
                                 sg::report_detail::tone_of(verdict.decision)});
      report.sections.push_back(std::move(listener));
    }
    report_->show_report(report);
    last_report_ = report;
    listen_start_->setEnabled(free_port && !listener_);
    copy_->setEnabled(true);
    note_->setEnabled(case_active());
  }

  // The selected change when it is a process or service that ended or restarted. The newest change
  // is the list's first row and the vector's last entry.
  const support_assist::WatchEvent* selected_ended_event() const {
    if (events_ == nullptr)
      return nullptr;
    const auto selected = events_->selectionModel()->selectedRows();
    if (selected.isEmpty())
      return nullptr;
    const auto row = static_cast<std::size_t>(selected.front().row());
    if (row >= watch_events_.size())
      return nullptr;
    const auto& event = watch_events_[watch_events_.size() - 1U - row];
    return event.change == support_assist::WatchChange::ended || event.change == support_assist::WatchChange::restarted
               ? &event
               : nullptr;
  }

  // Its log: the Veeam logs written in the 2 minutes before the snapshot that saw the process end.
  void find_its_log() {
    const support_assist::WatchEvent* event = selected_ended_event();
    if (event == nullptr)
      return;
    log_link_->setEnabled(false);
    set_status(QStringLiteral("Looking for the Veeam logs written before %1 ended...").arg(qt_text(event->item.name)));
    const std::int64_t at = event->at_unix_millis;
    const std::string name = event->item.name;
    in_background([at, name]() {
      Outcome outcome;
      outcome.logs_near = support_assist::logs_written_near(support_assist::veeam_log_folders(), at);
      outcome.logs_near_at = at;
      outcome.logs_near_name = name;
      return outcome;
    });
  }

  // A menu of the logs at the button; the chosen one opens in the viewer at the line written nearest
  // before the process ended.
  void choose_log(const std::vector<support_assist::LogWrittenNear>& logs, std::int64_t at, const std::string& name) {
    if (logs.empty()) {
      set_status(QStringLiteral("No Veeam log was written in the 2 minutes before %1 ended.").arg(qt_text(name)));
      return;
    }
    set_status(QStringLiteral("%1 Veeam log(s) written in the 2 minutes before %2 ended. Choose one to open it at that time.")
                   .arg(static_cast<qulonglong>(logs.size()))
                   .arg(qt_text(name)));
    QMenu menu(this);
    for (std::size_t index = 0; index < logs.size(); ++index) {
      const std::string written = sg::report_detail::utc_text(logs[index].written_unix_millis);
      QAction* action = menu.addAction(qt_text(support_assist::path_to_utf8(logs[index].path.filename())) +
                                       QStringLiteral("    ") +
                                       qt_text(written.size() > 19U ? written.substr(11, 8) + " UTC" : written));
      action->setData(static_cast<qulonglong>(index));
    }
    QAction* chosen = menu.exec(log_link_->mapToGlobal(QPoint(0, log_link_->height())));
    if (chosen == nullptr)
      return;
    const auto& log = logs[static_cast<std::size_t>(chosen->data().toULongLong())];
    const std::uint64_t line =
        support_assist::log_line_before(log.path, at, support_assist::read_time_zone().utc_offset_minutes);
    if (host_.open_log)
      host_.open_log(log.path, line);
    activity(QStringLiteral("Opened its log"),
             qt_text(name + ": " + support_assist::path_to_utf8(log.path.filename()) + ", line " + std::to_string(line)));
  }

  void fill_watch(const support_assist::WatchSnapshot& snapshot) {
    if (snapshot_) {
      for (auto& event : support_assist::diff_watch(*snapshot_, snapshot)) {
        events_->insertRow(0);
        set_row(events_, 0, {qt_text(sg::report_detail::utc_text(event.at_unix_millis)), qt_text(event.text)});
        if (event.change == support_assist::WatchChange::ended ||
            event.change == support_assist::WatchChange::restarted)
          activity(QStringLiteral("Changed"), qt_text(event.text));
        watch_events_.push_back(std::move(event));
      }
    }
    std::string selected_key;
    const int selected = table_->currentRow();
    if (selected >= 0 && snapshot_ && static_cast<std::size_t>(selected) < snapshot_->items.size()) {
      const auto& item = snapshot_->items[static_cast<std::size_t>(selected)];
      selected_key = item.name + "|" + std::to_string(item.pid);
    }
    table_->setUpdatesEnabled(false);
    table_->setRowCount(static_cast<int>(snapshot.items.size()));
    std::size_t services = 0;
    int reselect = -1;
    for (std::size_t index = 0; index < snapshot.items.size(); ++index) {
      const auto& entry = snapshot.items[index];
      const bool service = entry.kind == support_assist::WatchKind::service;
      if (service)
        ++services;
      QString name = qt_text(entry.name);
      if (service && !entry.display_name.empty() && entry.display_name != entry.name)
        name = qt_text(entry.display_name) + QStringLiteral(" (") + name + QStringLiteral(")");
      set_row(table_, static_cast<int>(index),
              {service ? QStringLiteral("Service") : QStringLiteral("Process"), name, qt_text(entry.state),
               entry.pid == 0 ? QString() : QString::number(entry.pid),
               qt_text(sg::report_detail::utc_text(entry.started_unix_millis)), qt_text(entry.listening)});
      if (!selected_key.empty() && entry.name + "|" + std::to_string(entry.pid) == selected_key)
        reselect = static_cast<int>(index);
    }
    if (reselect >= 0)
      table_->selectRow(reselect);
    table_->setUpdatesEnabled(true);
    set_status(QStringLiteral("%1 service(s) and %2 process(es), read %3; %4 change(s) seen%5")
                   .arg(static_cast<qulonglong>(services))
                   .arg(static_cast<qulonglong>(snapshot.items.size() - services))
                   .arg(qt_text(sg::report_detail::utc_text(snapshot.taken_unix_millis)))
                   .arg(static_cast<qulonglong>(watch_events_.size()))
                   .arg(snapshot.note.empty() ? QString() : QStringLiteral(". ") + qt_text(snapshot.note)));
    snapshot_ = snapshot;
    copy_->setEnabled(true);
    note_->setEnabled(case_active() && !watch_events_.empty());
  }

  void start_listener() {
    const int row = table_->currentRow();
    if (!ports_ || row < 0 || static_cast<std::size_t>(row) >= ports_->rows.size() || listener_)
      return;
    const auto& port_row = ports_->rows[static_cast<std::size_t>(row)];
    const int minutes = minutes_->value();
    auto cancel = std::make_shared<support_assist::CancellationSource>();
    listener_ = cancel;
    listener_port_ = port_row.state.port;
    listener_udp_ = port_row.state.protocol == support_assist::PortProtocol::udp;
    listener_until_ = std::chrono::steady_clock::now() + std::chrono::minutes(minutes);
    listener_connections_ = 0;
    const std::uint16_t port = listener_port_;
    const bool udp = listener_udp_;
    const std::string banner = banner_->text().toStdString();
    QPointer<QuickToolWindow> self(this);
    const auto post_done = [self](QString text) {
      QMetaObject::invokeMethod(
          qApp,
          [self, text]() {
            if (!self.isNull())
              self->listener_ended(text);
          },
          Qt::QueuedConnection);
    };
    const auto post_connection = [self](const std::string& at, const std::string& peer, const std::string& what) {
      ListenerEvent event{clock_of(at), qt_text(peer), qt_text(what), at};
      QMetaObject::invokeMethod(
          qApp,
          [self, event]() {
            if (!self.isNull())
              self->listener_event(event);
          },
          Qt::QueuedConnection);
    };
    std::thread([cancel, port, udp, minutes, banner, post_done, post_connection]() {
      QString failure;
      if (udp) {
        support_assist::UdpListenerOptions options;
        options.port = port;
        options.duration = std::chrono::seconds(minutes * 60);
        options.accept_multiple = true;
        auto result = support_assist::listen_udp(
            options, cancel->token(), {}, [&](const support_assist::UdpReceivedDatagram& datagram) {
              post_connection(datagram.received_utc,
                              datagram.remote_address + ":" + std::to_string(datagram.remote_port),
                              datagram.sat_probe ? "SAT probe, answered" : "Datagram");
            });
        if (!result.ok())
          failure = qt_text(result.error().message);
      } else {
        support_assist::TcpListenerOptions options;
        options.port = port;
        options.duration = std::chrono::seconds(minutes * 60);
        options.accept_multiple = true;
        options.banner = banner;
        auto result = support_assist::listen_tcp(
            options, cancel->token(), {},
            [&](support_assist::TcpListenerEventKind kind, const support_assist::TcpAcceptedConnection& connection) {
              if (kind != support_assist::TcpListenerEventKind::updated) // after the SAT exchange, so it can be named
                return;
              post_connection(connection.accepted_utc,
                              connection.remote_address + ":" + std::to_string(connection.remote_port),
                              support_assist::describe_listener_connection(connection));
            });
        if (!result.ok())
          failure = qt_text(result.error().message);
      }
      post_done(failure);
    }).detach();

    listen_start_->hide();
    listen_stop_->show();
    minutes_->setEnabled(false);
    banner_->setEnabled(false);
    quick_scan_->setEnabled(false);
    listener_started_ = std::chrono::steady_clock::now();
    listener_started_unix_millis_ = support_assist::unix_millis_now();
    listener_arrivals_.clear();
    listener_minutes_ = minutes;
    const QString protocol_name = udp ? QStringLiteral("UDP") : QStringLiteral("TCP");
    side_title_->setText(QStringLiteral("SAT LISTENING ON %1 %2").arg(protocol_name).arg(port));
    side_progress_->setRange(0, minutes * 60);
    side_progress_->setValue(0);
    side_progress_->show();
    connections_->setRowCount(0);
    listen_status_->setText(QStringLiteral("On the other machine, run the Remote Port Checker to this machine's "
                                           "address, %1 port %2.")
                                .arg(protocol_name)
                                .arg(port));
    const bool scan_wanted = scan_available_ && quick_scan_->isChecked();
    if (scan_wanted) {
      scan_reading_->setText(QStringLiteral("Quick scan is starting..."));
      const auto scan_protocol = udp ? support_assist::PortProtocol::udp : support_assist::PortProtocol::tcp;
      std::thread([self, port, scan_protocol]() {
        auto started = std::make_shared<support_assist::Result<std::unique_ptr<support_assist::QuickScan>>>(
            support_assist::QuickScan::start(port, scan_protocol));
        QMetaObject::invokeMethod(
            qApp,
            [self, started]() {
              std::unique_ptr<support_assist::QuickScan> scan;
              if (started->ok())
                scan = std::move(started->value());
              if (self.isNull()) {
                stop_scan_in_background(std::move(scan));
                return;
              }
              self->scan_started(std::move(scan), started->ok() ? std::string() : started->error().message);
            },
            Qt::QueuedConnection);
      }).detach();
    }
    countdown_timer_->start();
    show_listener();
    QTimer::singleShot(kRecheckDelayMs, this, [this]() { recheck_ports(); });
    activity(QStringLiteral("Listener started"),
             QStringLiteral("%1%2 for %3 min%4")
                 .arg(port)
                 .arg(udp ? QStringLiteral("/UDP") : QStringLiteral("/TCP"))
                 .arg(minutes)
                 .arg(scan_wanted ? QStringLiteral(", with Quick scan") : QString()));
  }

  void scan_started(std::unique_ptr<support_assist::QuickScan> scan, const std::string& error) {
    if (!error.empty()) {
      scan_reading_->setText(QStringLiteral("Quick scan did not start: ") + qt_text(error));
      activity(QStringLiteral("Quick scan failed"), qt_text(error));
      return;
    }
    if (!listener_) {
      // The listener ended while the scan was starting.
      stop_scan_in_background(std::move(scan));
      return;
    }
    scan_ = std::move(scan);
    scan_reading_->setText(QStringLiteral("Quick scan: counting what arrives at the port."));
    activity(QStringLiteral("Quick scan started"),
             QStringLiteral("%1%2").arg(listener_port_).arg(listener_udp_ ? QStringLiteral("/UDP") : QStringLiteral("/TCP")));
  }

  // The panel while the listener runs: time active and left, the bar, and Quick scan's reading.
  void show_listener() {
    const auto now = std::chrono::steady_clock::now();
    const auto active = std::chrono::duration_cast<std::chrono::seconds>(now - listener_started_);
    const auto left = std::chrono::duration_cast<std::chrono::seconds>(listener_until_ - now);
    side_clock_->setText(QStringLiteral("Active ") + minutes_seconds(active.count()));
    side_left_->setText(QStringLiteral("%1 left of %2:00, %3 %4")
                            .arg(minutes_seconds(left.count()))
                            .arg(listener_minutes_)
                            .arg(listener_connections_)
                            .arg(listener_udp_ ? QStringLiteral("datagram(s)") : QStringLiteral("connection(s)")));
    side_progress_->setValue(static_cast<int>(std::clamp<long long>(active.count(), 0, listener_minutes_ * 60LL)));
    show_listener_row();
    if (scan_)
      scan_reading_->setText(qt_text("Quick scan: " + sg::quick_scan_summary(scan_->counts(),
                                                                             static_cast<std::size_t>(listener_connections_))));
  }

  void show_countdown() {
    if (listener_)
      show_listener();
  }

  void listener_event(const ListenerEvent& event) {
    ++listener_connections_;
    connections_->insertRow(0);
    set_row(connections_, 0, {event.time, event.peer, event.what});
    listener_arrivals_.push_back({event.time_utc, event.peer.toStdString(), event.what.toStdString()});
    show_listener();
  }

  void listener_ended(const QString& error) {
    countdown_timer_->stop();
    if (!error.isEmpty() || listener_)
      show_listener();
    listener_.reset();
    listener_row_ = -1;
    listen_stop_->hide();
    listen_start_->show();
    side_progress_->hide();
    minutes_->setEnabled(true);
    banner_->setEnabled(true);
    quick_scan_->setEnabled(scan_available_);
    side_title_->setText(QStringLiteral("LISTENER"));
    side_clock_->setText(error.isEmpty() ? QStringLiteral("Stopped") : QStringLiteral("Did not start"));
    if (error.isEmpty()) {
      const auto ran =
          std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - listener_started_);
      side_left_->setText(QStringLiteral("Ran %1, %2 %3")
                              .arg(minutes_seconds(ran.count()))
                              .arg(listener_connections_)
                              .arg(listener_udp_ ? QStringLiteral("datagram(s)") : QStringLiteral("connection(s)")));
    } else {
      side_left_->clear();
    }
    // The run as it is kept on a Customer / Lab machine.
    const support_assist::ListenerRunRecord run = listener_record(error.toStdString());
    // Quick scan's last reading comes back from its worker.
    if (scan_) {
      scan_reading_->setText(QStringLiteral("Quick scan is stopping..."));
      QPointer<QuickToolWindow> self(this);
      const auto reached = static_cast<std::size_t>(listener_connections_);
      std::thread([self, reached, owned = std::move(scan_)]() mutable {
        owned->stop();
        const QString reading = qt_text("Quick scan: " + sg::quick_scan_summary(owned->counts(), reached));
        QMetaObject::invokeMethod(
            qApp,
            [self, reading]() {
              if (self.isNull())
                return;
              self->scan_reading_->setText(reading);
              self->activity(QStringLiteral("Quick scan"), reading);
            },
            Qt::QueuedConnection);
      }).detach();
    }
    QTimer::singleShot(kRecheckDelayMs, this, [this]() { recheck_ports(); });
    // The rules that name SAT's executable.
    QStringList rules;
    if (auto firewall = support_assist::read_firewall(); firewall.ok()) {
      for (const auto& rule :
           support_assist::rules_for_program(firewall.value(), support_assist::current_executable_path()))
        rules << qt_text(rule.name) + (rule.allow ? QStringLiteral(" (allow)") : QStringLiteral(" (block)"));
    }
    const QString protocol = listener_udp_ ? QStringLiteral("/UDP") : QStringLiteral("/TCP");
    QString text = error.isEmpty()
                       ? QStringLiteral("The listener on %1%2 stopped after %3 %4.")
                             .arg(listener_port_)
                             .arg(protocol)
                             .arg(listener_connections_)
                             .arg(listener_udp_ ? QStringLiteral("datagram(s)") : QStringLiteral("connection(s)"))
                       : QStringLiteral("The listener did not start: ") + error;
    if (!rules.isEmpty())
      text += QStringLiteral(" Firewall rules for %1: %2.")
                  .arg(QFileInfo(QCoreApplication::applicationFilePath()).fileName(),
                       rules.join(QStringLiteral(", ")));
    listen_status_->setText(text);
    activity(error.isEmpty() ? QStringLiteral("Listener stopped") : QStringLiteral("Listener failed"),
             QStringLiteral("%1%2: %3")
                 .arg(listener_port_)
                 .arg(protocol)
                 .arg(error.isEmpty() ? QStringLiteral("%1 seen").arg(listener_connections_) : error));
    keep_output(listener_output(run, text.toStdString()));
    row_selected();
  }

  // A watch as it is kept when it stops, by Stop or by closing the window.
  sg::QuickToolOutput watch_output(const std::string& filter) const {
    std::string report = "Service and Process Watch: " + filter + "\n";
    for (const auto& event : watch_events_)
      report += sg::report_detail::utc_text(event.at_unix_millis) + "  " + event.text + "\n";
    return {"Service and Process Watch", support_assist::tool_json::watch(filter, *snapshot_, watch_events_), report,
            std::to_string(watch_events_.size()) + " change(s) seen", sg::ReportTone::normal};
  }

  // The listener's run as it is kept, with Quick scan's count as the listener ended.
  support_assist::ListenerRunRecord listener_record(const std::string& error) const {
    support_assist::ListenerRunRecord run;
    run.port = listener_port_;
    run.protocol = listener_udp_ ? support_assist::PortProtocol::udp : support_assist::PortProtocol::tcp;
    run.minutes = listener_minutes_;
    run.started_unix_millis = listener_started_unix_millis_;
    run.ended_unix_millis = support_assist::unix_millis_now();
    run.arrivals = listener_arrivals_;
    run.error = error;
    if (scan_) {
      run.scanned = true;
      run.scan = scan_->counts();
    }
    return run;
  }

  static sg::QuickToolOutput listener_output(const support_assist::ListenerRunRecord& run, const std::string& text) {
    std::string report = text;
    for (const auto& arrival : run.arrivals)
      report += "\n" + arrival.time_utc + "  " + arrival.peer + "  " + arrival.what;
    return {"Local Port Checker Listener", support_assist::tool_json::listener_run(run), report, text,
            run.error.empty() ? sg::ReportTone::normal : sg::ReportTone::attention};
  }

protected:
  // A log dropped on Time Check goes in Log file and is read for its own clock.
  void dragEnterEvent(QDragEnterEvent* event) override {
    if (tool_ == sg::ShortcutCommand::time_check && event->mimeData()->hasUrls())
      event->acceptProposedAction();
  }
  void dropEvent(QDropEvent* event) override {
    if (tool_ != sg::ShortcutCommand::time_check || !event->mimeData()->hasUrls())
      return;
    const QList<QUrl> urls = event->mimeData()->urls();
    if (urls.isEmpty() || !urls.front().isLocalFile())
      return;
    log_input_->setText(urls.front().toLocalFile());
    read_log_file(!convert_input_->text().trimmed().isEmpty());
    event->acceptProposedAction();
  }

  // Closing the window ends a watch or a listener; its run is kept as Stop keeps it.
  void closeEvent(QCloseEvent* event) override {
    if (watching_ && snapshot_)
      keep_output(watch_output(support_assist::trim(input_->text().toStdString())));
    if (listener_) {
      const auto run = listener_record("");
      keep_output(listener_output(run, "The listener on " + std::to_string(run.port) + (listener_udp_ ? "/UDP" : "/TCP") +
                                           " stopped when its window closed, after " +
                                           std::to_string(run.arrivals.size()) +
                                           (listener_udp_ ? " datagram(s)." : " connection(s).")));
    }
    QWidget::closeEvent(event);
  }

private:

  // The File Transfer Calculator's Storage speed: its cue in each mode, and in Live test the figure a Disk
  // Speed Test result gives.
  static QString storage_cue(bool measuring) {
    return measuring ? QStringLiteral("Optional: such as 520")
                     : QStringLiteral("Optional: such as 520, from a Disk Speed Test");
  }
  // The units a speed takes, in the order its drop-down lists them; an opened result is in MB/s.
  static constexpr int kUnitMegabytes = 0;
  static constexpr int kUnitGigabits = 3;
  static QStringList speed_units() {
    return {QStringLiteral("MB/s"), QStringLiteral("GB/s"), QStringLiteral("Mb/s"), QStringLiteral("Gb/s")};
  }
  static QString storage_helper() {
    return QStringLiteral("A Disk Speed Test's Writes on a repository, Reads on a source");
  }

  // Manual takes the network's and the storage's speed typed in; Live test measures them here, with
  // this machine's adapter, the network test and a storage result.
  void transfer_mode(bool measuring) {
    measuring_ = measuring;
    if (measuring && adapters_.empty())
      transfer_fill_adapters();
    mode_enter_->setChecked(!measuring);
    mode_measure_->setChecked(measuring);
    measure_box_->setVisible(measuring);
    manual_box_->setVisible(!measuring);
    // Live test: the chosen adapter's link speed and packet size are the figures; Manual types them.
    for (QWidget* figure : {static_cast<QWidget*>(link_speed_), static_cast<QWidget*>(link_unit_),
                            static_cast<QWidget*>(mtu_)})
      figure->setEnabled(true);
    if (measuring)
      transfer_apply_adapter();
    // Link throttle is Manual's: in Live test the network test measures what the link gives.
    for (QWidget* manual : {share_label_, static_cast<QWidget*>(share_), share_suffix_})
      manual->setVisible(!measuring);
    // Storage speed is in both modes; Live test adds Open a result beside it.
    for (QWidget* live : {static_cast<QWidget*>(storage_text_), static_cast<QWidget*>(open_result_),
                          static_cast<QWidget*>(clear_result_)})
      live->setVisible(measuring);
    storage_row_->setStretchFactor(storage_speed_edit_, measuring ? 0 : 1);
    storage_row_->setStretchFactor(storage_text_, measuring ? 1 : 0);
    storage_speed_edit_->setPlaceholderText(storage_cue(measuring));
    transfer_recalculate();
  }

  // This machine's adapters, the first one up with a speed and an address chosen.
  void transfer_fill_adapters() {
    adapter_->clear();
    adapters_.clear();
    auto listed = support_assist::list_network_adapters();
    if (!listed.ok()) {
      set_status(qt_text(listed.error().message));
      return;
    }
    int chosen = -1;
    for (const auto& adapter : listed.value()) {
      if (adapter.loopback)
        continue;
      if (chosen < 0 && adapter.up && adapter.link_bits_per_second > 0U && !adapter.addresses.empty())
        chosen = static_cast<int>(adapters_.size());
      adapters_.push_back(adapter);
      adapter_->addItem(qt_text(support_assist::network_adapter_label(adapter) +
                                (adapter.description.empty() ? std::string() : "   " + adapter.description)));
    }
    if (chosen >= 0) {
      adapter_->setCurrentIndex(chosen);
      transfer_apply_adapter();
    }
  }

  // The chosen adapter's link speed and packet size fill the figures.
  void transfer_apply_adapter() {
    const int chosen = adapter_->currentIndex();
    if (chosen < 0 || static_cast<std::size_t>(chosen) >= adapters_.size())
      return;
    const auto& adapter = adapters_[static_cast<std::size_t>(chosen)];
    if (adapter.link_bits_per_second > 0U) {
      const std::string speed = support_assist::link_speed_text(static_cast<double>(adapter.link_bits_per_second));
      link_speed_->setText(qt_text(speed.substr(0, speed.find(' '))));
      link_unit_->setCurrentIndex(adapter.link_bits_per_second >= 1000000000ULL ? 1 : 0);
    }
    if (adapter.mtu == 1500U)
      mtu_->setCurrentIndex(0);
    else if (adapter.mtu == 9000U)
      mtu_->setCurrentIndex(1);
    else if (adapter.mtu >= 576U && adapter.mtu <= 9216U)
      mtu_->setEditText(QString::number(adapter.mtu));
    // The adapter's figures show as its own; one it does not report stays open to type.
    link_speed_->setEnabled(adapter.link_bits_per_second == 0U);
    link_unit_->setEnabled(adapter.link_bits_per_second == 0U);
    mtu_->setEnabled(!(adapter.mtu >= 576U && adapter.mtu <= 9216U));
  }

  // The figures as typed, with the measured speeds when measuring. An empty share or reduction is 100%.
  bool transfer_read_inputs(support_assist::TransferInputs& inputs, QString& problem) const {
    const auto field = [](const QString& text) { return support_assist::trim(text.toStdString()); };
    auto size = support_assist::parse_data_size(field(input_->text()), size_unit_->currentText().toStdString());
    if (!size.ok()) {
      problem = qt_text(size.error().message);
      return false;
    }
    inputs.size_bytes = size.value();
    auto link = support_assist::parse_link_speed(field(link_speed_->text()), link_unit_->currentText().toStdString());
    if (!link.ok()) {
      problem = qt_text(link.error().message);
      return false;
    }
    inputs.link_bits_per_second = link.value();
    auto mtu = support_assist::parse_mtu(field(mtu_->currentText()));
    if (!mtu.ok()) {
      problem = qt_text(mtu.error().message);
      return false;
    }
    inputs.mtu = mtu.value();
    if (!measuring_ && !field(share_->text()).empty()) {
      auto share = support_assist::parse_percent(field(share_->text()), "Link throttle");
      if (!share.ok()) {
        problem = qt_text(share.error().message);
        return false;
      }
      inputs.share_percent = share.value();
    }
    if (!field(reduced_->text()).empty()) {
      auto reduced = support_assist::parse_percent(field(reduced_->text()), "Compression");
      if (!reduced.ok()) {
        problem = qt_text(reduced.error().message);
        return false;
      }
      inputs.reduced_to_percent = reduced.value();
    }
    if (!measuring_ && !field(network_speed_edit_->text()).empty()) {
      // Manual: the network speed a test elsewhere measured, typed in with its unit.
      auto network = support_assist::parse_byte_rate(field(network_speed_edit_->text()),
                                                     network_unit_->currentText().toStdString());
      if (!network.ok()) {
        problem = qt_text(network.error().message);
        return false;
      }
      inputs.network_bytes_per_second = network.value();
    }
    // The storage speed: the opened result while the field still holds what it filled in, in MB/s,
    // otherwise the figure typed, in the unit chosen.
    const std::string storage_typed = field(storage_speed_edit_->text());
    if (storage_speed_ && storage_typed == field(storage_filled_) && storage_unit_->currentIndex() == kUnitMegabytes) {
      inputs.measured.push_back(*storage_speed_);
    } else if (!storage_typed.empty()) {
      auto storage = support_assist::parse_byte_rate(storage_typed, storage_unit_->currentText().toStdString());
      if (!storage.ok()) {
        problem = qt_text(storage.error().message);
        return false;
      }
      inputs.storage_bytes_per_second = storage.value();
    }
    if (measuring_) {
      const int chosen = adapter_->currentIndex();
      if (chosen >= 0 && static_cast<std::size_t>(chosen) < adapters_.size())
        inputs.link_name = adapters_[static_cast<std::size_t>(chosen)].name;
      if (network_speed_) {
        inputs.measured.push_back(*network_speed_);
        if (network_ipv6_)
          inputs.ip = support_assist::TransferIp::ipv6;
      }
    }
    return true;
  }

  // The estimate in the report; a measured one is kept as the run's output.
  void transfer_show(const support_assist::TransferEstimate& estimate, bool keep) {
    auto report = sg::file_transfer_report(estimate);
    report.checked_unix_millis = support_assist::unix_millis_now();
    report_->show_report(report);
    side_report_->show_report(sg::file_transfer_side_report(estimate));
    // Copy and #note take every section, the side's too.
    report = sg::file_transfer_full_report(estimate);
    report.checked_unix_millis = support_assist::unix_millis_now();
    last_report_ = report;
    estimate_ = estimate;
    set_status(qt_text(report.headline));
    copy_->setEnabled(true);
    email_->setEnabled(true);
    note_->setEnabled(case_active());
    // Every estimate shown goes into the history once, however it was asked for.
    if (report.headline != transfer_recorded_) {
      transfer_recorded_ = report.headline;
      activity(QStringLiteral("Calculated"), qt_text(report.headline));
    }
    if (keep)
      keep_output(sg::quick_tool_output_of(tool_title(tool_).toStdString(),
                                           support_assist::tool_json::file_transfer(estimate), report));
  }

  // A new adapter, mode or storage result calculates again once the figures are there.
  // With figures to work from the result shows; without them, the mode's guide.
  void transfer_recalculate() {
    if (!input_->text().trimmed().isEmpty() && !link_speed_->text().trimmed().isEmpty()) {
      run(Command::run);
      return;
    }
    last_report_.reset();
    report_->show_report(sg::quick_tool_guide_report(tool_, measuring_ ? sg::kTransferModeLive : sg::kTransferModeManual));
  }

  void transfer_measure_clicked() {
    if (transfer_cancel_) {
      transfer_cancel_->cancel();
      set_status(QStringLiteral("Stopping the network test..."));
      return;
    }
    run(Command::measure);
  }

  void transfer_open_result() {
    const QString chosen = QFileDialog::getOpenFileName(this, QStringLiteral("Open a Disk Speed Test result"), QString(),
                                                        QStringLiteral("Disk Speed Test result (*.json);;All files (*)"));
    if (chosen.isEmpty())
      return;
    std::ifstream file(support_assist::path_from_utf8(chosen.toStdString()), std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    auto speed = support_assist::storage_speed_from_result(text);
    if (!speed.ok()) {
      set_status(qt_text(speed.error().message));
      return;
    }
    // The figure goes into Storage speed; where it came from shows beside it.
    storage_speed_ = speed.value();
    storage_filled_ = qt_text(support_assist::transfer_rate_figure(speed.value().bytes_per_second));
    storage_speed_edit_->setText(storage_filled_);
    {
      // Filling in the unit is not the engineer's choice of another one.
      const QSignalBlocker quiet(storage_unit_);
      storage_unit_->setCurrentIndex(kUnitMegabytes);
    }
    storage_text_->setText(qt_text(speed.value().name + ", from the result.json: " + speed.value().detail));
    clear_result_->setEnabled(true);
    transfer_recalculate();
  }

  void copy_email() {
    if (!estimate_)
      return;
    QApplication::clipboard()->setText(qt_text(sg::file_transfer_email_text(*estimate_)));
    set_status(QStringLiteral("Email text copied."));
  }

  // A path as typed, or as a file manager copies it, in quotes.
  static QString clean_path(const QString& typed) {
    QString path = typed.trimmed();
    while (path.startsWith(QLatin1Char('"')) || path.startsWith(QLatin1Char('\'')))
      path.remove(0, 1);
    while (path.endsWith(QLatin1Char('"')) || path.endsWith(QLatin1Char('\'')))
      path.chop(1);
    return path.trimmed();
  }

  // Reads the log in Log file for its own clock on a worker; Convert runs when it is back if asked.
  void read_log_file(bool convert_after) {
    const QString path = clean_path(log_input_->text());
    if (path.isEmpty())
      return;
    reading_log_ = true;
    convert_after_read_ = convert_after;
    log_clock_.reset();
    log_clock_path_ = path;
    set_status(QStringLiteral("Reading the log's own clock: %1").arg(path));
    const std::string key = path.toStdString();
    in_background([key]() {
      Outcome outcome;
      outcome.log_clock = std::make_shared<const support_assist::LogClock>(
          support_assist::read_log_clock(support_assist::path_from_utf8(key)));
      outcome.log_path = key;
      return outcome;
    });
  }

  void convert_timestamp() {
    const std::string text = support_assist::trim(convert_input_->text().toStdString());
    const QString log_path = clean_path(log_input_->text());
    // A log named and not yet read, or changed since, is read first; Convert follows.
    if (!log_path.isEmpty() && log_path != log_clock_path_) {
      read_log_file(!text.empty());
      return;
    }
    if (reading_log_) {
      convert_after_read_ = !text.empty();
      set_status(QStringLiteral("Reading the log's own clock first..."));
      return;
    }
    if (text.empty()) {
      set_status(QStringLiteral("Paste a time or a whole line from a log first."));
      return;
    }
    const auto converted = support_assist::convert_with_choices(
        text, support_assist::read_zone_choice(offset_->currentText().toStdString()),
        log_path.isEmpty() ? nullptr : log_clock_.get(),
        support_assist::read_zone_choice(show_in_->currentText().toStdString()));
    const auto report = sg::time_conversion_report(text, converted);
    convert_report_->show_report(report);
    last_report_ = report;
    set_status(qt_text(report.headline));
    activity(QStringLiteral("Converted"), qt_text(report.headline));
    copy_->setEnabled(true);
    note_->setEnabled(case_active());
  }

  void browse(bool folder) {
    const QString chosen =
        folder || tool_ == sg::ShortcutCommand::volume_check
            ? QFileDialog::getExistingDirectory(this, QStringLiteral("Choose a folder"), input_->text())
            : QFileDialog::getOpenFileName(this, QStringLiteral("Choose a file"), input_->text());
    if (!chosen.isEmpty()) {
      input_->setText(chosen);
      run(Command::run);
    }
  }

  void follow_link() {
    if (tool_ == sg::ShortcutCommand::name_check) {
      // The address the name resolved to; the name itself until it has been checked.
      if (host_.open_remote_port_checker)
        host_.open_remote_port_checker(resolved_address_.empty() ? input_->text().trimmed()
                                                                 : qt_text(resolved_address_));
    } else if (tool_ == sg::ShortcutCommand::volume_check && last_report_) {
      for (const auto& section : last_report_->sections) {
        for (const auto& row : section.rows) {
          const std::size_t at = row.value.find("https://");
          if (row.label == "Guide" && at != std::string::npos)
            QDesktopServices::openUrl(QUrl(qt_text(row.value.substr(at))));
        }
      }
    } else if (tool_ == sg::ShortcutCommand::object_storage_check) {
      if (host_.open_tool)
        host_.open_tool(sg::ShortcutCommand::time_check, QString());
    } else if (tool_ == sg::ShortcutCommand::service_watch && snapshot_) {
      const int row = table_->currentRow();
      if (row >= 0 && static_cast<std::size_t>(row) < snapshot_->items.size()) {
        const auto& entry = snapshot_->items[static_cast<std::size_t>(row)];
        if (entry.pid == 0)
          set_status(QStringLiteral("That service is not running, so it holds no ports."));
        else if (host_.open_tool)
          host_.open_tool(sg::ShortcutCommand::local_port_checker, QString::number(entry.pid));
      }
    }
  }

  // The ports to a file the engineer names: CSV (the rows) or JSON (the result, as `network ports --json`).
  void export_ports() {
    if (!ports_)
      return;
    QString selected;
    QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Export the ports"),
                                                QStringLiteral("local-port-check.csv"),
                                                QStringLiteral("CSV (*.csv);;JSON (*.json)"), &selected);
    if (path.isEmpty())
      return;
    const bool json = selected.startsWith(QStringLiteral("JSON")) || path.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive);
    if (json && !path.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive))
      path += QStringLiteral(".json");
    if (!json && !path.endsWith(QStringLiteral(".csv"), Qt::CaseInsensitive))
      path += QStringLiteral(".csv");
    const std::string content =
        json ? support_assist::tool_json::port_check(*ports_) : sg::port_check_csv(*ports_);
    QFile file(path);
    const bool written = file.open(QIODevice::WriteOnly | QIODevice::Truncate) &&
                         file.write(content.data(), static_cast<qint64>(content.size())) ==
                             static_cast<qint64>(content.size());
    set_status(written ? QStringLiteral("Exported to %1").arg(path) : QStringLiteral("Could not write %1").arg(path));
  }

  void copy_result() {
    std::string text;
    if (tool_ == sg::ShortcutCommand::local_port_checker && ports_) {
      text = sg::port_check_text(*ports_);
      if (last_report_)
        text += "\n" + sg::report_text(*last_report_);
    } else if (tool_ == sg::ShortcutCommand::service_watch && snapshot_) {
      text = "Service and Process Watch: " + input_->text().toStdString() + "\n";
      for (const auto& item : snapshot_->items)
        text += std::string(item.kind == support_assist::WatchKind::service ? "service" : "process") + "\t" +
                item.name + "\t" + item.state + "\t" + std::to_string(item.pid) + "\t" +
                sg::report_detail::utc_text(item.started_unix_millis) + "\t" + item.listening + "\n";
      if (!watch_events_.empty())
        text += "\nChanges\n";
      for (const auto& event : watch_events_)
        text += sg::report_detail::utc_text(event.at_unix_millis) + "  " + event.text + "\n";
    } else if (last_report_) {
      text = sg::report_text(*last_report_);
    } else if (tool_ == sg::ShortcutCommand::volume_check && !volumes_.empty()) {
      auto report = sg::volumes_report(volumes_);
      report.checked_unix_millis = volumes_read_unix_millis_;
      text = sg::report_text(report);
    }
    if (!text.empty()) {
      QApplication::clipboard()->setText(qt_text(text));
      set_status(QStringLiteral("Copied."));
    }
  }

  void add_to_note() {
    if (!host_.active_case)
      return;
    const auto workspace = host_.active_case();
    if (!workspace)
      return;
    sg::QuickToolReport report;
    if (tool_ == sg::ShortcutCommand::service_watch) {
      report.tool = "Service and Process Watch";
      report.subject = input_->text().toStdString();
      report.headline = std::to_string(watch_events_.size()) + " change(s) seen";
      report.checked_unix_millis = support_assist::unix_millis_now();
      sg::ReportSection section{"Changes", {}, {}};
      for (const auto& event : watch_events_)
        section.rows.push_back({sg::report_detail::utc_text(event.at_unix_millis), event.text, sg::ReportTone::normal});
      report.sections.push_back(std::move(section));
    } else if (last_report_) {
      report = *last_report_;
    } else if (tool_ == sg::ShortcutCommand::volume_check && !volumes_.empty()) {
      report = sg::volumes_report(volumes_);
      report.checked_unix_millis = volumes_read_unix_millis_;
    } else {
      return;
    }
    const auto written = sg::add_quick_tool_report_to_note(*workspace, report, QSysInfo::machineHostName().toStdString());
    if (written == sg::NoteWrite::added) {
      set_status(QStringLiteral("Added to #note."));
      activity(QStringLiteral("Added to #note"), qt_text(report.headline));
    } else {
      set_status(written == sg::NoteWrite::already_there ? QStringLiteral("This result is in #note already.")
                                                        : QStringLiteral("#note could not be written."));
    }
  }

  sg::ShortcutCommand tool_;
  QuickToolHost host_;
  QLineEdit* input_ = nullptr;
  // The Object Storage Check's fields.
  QComboBox* storage_preset_ = nullptr;
  QLineEdit* endpoint_ = nullptr;
  QComboBox* region_ = nullptr;
  QComboBox* trust_ = nullptr;            // the certificate store, a certificate file or a fingerprint
  QPushButton* certificate_open_ = nullptr;
  QComboBox* product_ = nullptr;          // the product the key's permissions are compared with
  std::vector<std::string> product_ids_;  // in its list's order
  QComboBox* addressing_ = nullptr;
  QLineEdit* access_ = nullptr;
  QLineEdit* secret_ = nullptr;
  QLineEdit* fingerprint_ = nullptr;
  std::vector<support_assist::ObjectStoragePreset> storage_presets_;
  // The File Transfer Calculator's fields.
  QPushButton* mode_enter_ = nullptr;
  QPushButton* mode_measure_ = nullptr;
  QComboBox* size_unit_ = nullptr;
  QLineEdit* link_speed_ = nullptr;
  QComboBox* link_unit_ = nullptr;
  QComboBox* mtu_ = nullptr;
  QLineEdit* share_ = nullptr;
  QLineEdit* reduced_ = nullptr;
  QWidget* manual_box_ = nullptr; // Manual: the network's and the storage's speed, typed in
  QLineEdit* network_speed_edit_ = nullptr;
  QLineEdit* storage_speed_edit_ = nullptr;
  QComboBox* network_unit_ = nullptr;
  QComboBox* storage_unit_ = nullptr;
  QWidget* measure_box_ = nullptr;
  QComboBox* adapter_ = nullptr;
  QPushButton* adapter_refresh_ = nullptr;
  QLineEdit* test_host_ = nullptr;
  QLineEdit* test_port_ = nullptr;
  QComboBox* using_ = nullptr;
  QComboBox* send_size_ = nullptr;
  QPushButton* measure_ = nullptr;
  QLabel* storage_text_ = nullptr;
  QPushButton* open_result_ = nullptr;
  QPushButton* clear_result_ = nullptr;
  QPushButton* email_ = nullptr;
  ReportView* side_report_ = nullptr; // the speeds, the email text and the terms
  bool measuring_ = false;
  std::vector<support_assist::NetworkAdapter> adapters_;
  std::optional<support_assist::TransferSpeed> network_speed_;
  bool network_ipv6_ = false;
  std::optional<support_assist::TransferSpeed> storage_speed_; // opened from a result.json
  QString storage_filled_;                                     // what Open a result put in the field
  QHBoxLayout* storage_row_ = nullptr;
  std::optional<support_assist::TransferEstimate> estimate_;
  std::shared_ptr<support_assist::CancellationSource> transfer_cancel_; // set while the network test runs
  QPushButton* run_ = nullptr;
  QPushButton* browse_ = nullptr;
  QPushButton* folder_browse_ = nullptr; // File Lock Check: a folder, for everything under it
  QPushButton* link_ = nullptr;
  QPushButton* log_link_ = nullptr; // Watch: the logs written when the selected change's process ended
  QWidget* share_label_ = nullptr;   // the calculator's Link throttle, Manual only
  std::string transfer_recorded_;    // the last estimate written to the history
  QWidget* share_suffix_ = nullptr;
  QPushButton* copy_ = nullptr;
  QPushButton* note_ = nullptr;
  QPushButton* export_ = nullptr; // the Local Port Checker only
  QLabel* status_ = nullptr;
  ReportView* report_ = nullptr;
  // Local Port Checker
  QCheckBox* tcp_ = nullptr;
  QCheckBox* udp_ = nullptr;
  QComboBox* preset_ = nullptr;
  QLineEdit* process_ = nullptr;
  QPushButton* process_run_ = nullptr;
  QTableWidget* table_ = nullptr;
  QPushButton* listen_start_ = nullptr;
  QPushButton* listen_stop_ = nullptr;
  QSpinBox* minutes_ = nullptr;
  QLineEdit* banner_ = nullptr;
  QLabel* listen_status_ = nullptr;
  // The listener's panel: its state, Quick scan and each connection.
  QLabel* side_title_ = nullptr;
  QLabel* side_clock_ = nullptr;
  QLabel* side_left_ = nullptr;
  QProgressBar* side_progress_ = nullptr;
  QCheckBox* quick_scan_ = nullptr;
  QLabel* scan_reading_ = nullptr;
  QTableWidget* connections_ = nullptr;
  // Time Check's converter
  QLineEdit* convert_input_ = nullptr;
  QLineEdit* log_input_ = nullptr;
  QComboBox* offset_ = nullptr;
  QComboBox* show_in_ = nullptr;
  ReportView* convert_report_ = nullptr;
  // The log Written in's From the log file reads, once read, and the path it was read from.
  std::shared_ptr<const support_assist::LogClock> log_clock_;
  QString log_clock_path_;
  bool reading_log_ = false;
  bool convert_after_read_ = false;
  // Service and Process Watch
  QTableWidget* events_ = nullptr;
  QTimer* watch_timer_ = nullptr;
  QTimer* countdown_timer_ = nullptr;

  bool running_ = false;
  std::optional<sg::QuickToolReport> last_report_;
  std::string resolved_address_;
  std::optional<support_assist::PortCheckResult> ports_;
  std::vector<support_assist::PortPreset> presets_;
  std::optional<support_assist::WatchSnapshot> snapshot_;
  std::vector<support_assist::WatchEvent> watch_events_;
  std::vector<support_assist::VolumeInfo> volumes_; // Volume Check's list, in the table's order
  std::int64_t volumes_read_unix_millis_ = 0;
  bool watching_ = false;
  bool watch_busy_ = false;
  std::shared_ptr<support_assist::CancellationSource> listener_;
  std::chrono::steady_clock::time_point listener_until_{};
  std::uint16_t listener_port_ = 0;
  bool listener_udp_ = false;
  int listener_connections_ = 0;
  std::chrono::steady_clock::time_point listener_started_{};
  std::int64_t listener_started_unix_millis_ = 0;
  std::vector<support_assist::ListenerRunRecord::Arrival> listener_arrivals_; // the run as it is kept
  int listener_minutes_ = 0;
  int listener_row_ = -1; // the table row of the listener's port, -1 when not shown
  std::uint16_t selected_port_ = 0;
  support_assist::PortProtocol selected_protocol_ = support_assist::PortProtocol::tcp;
  // The last check, run again when a listener starts or stops.
  std::vector<std::uint16_t> checked_tcp_;
  std::vector<std::uint16_t> checked_udp_;
  support_assist::PortQueryExtras checked_extras_;
  std::string checked_process_;
  bool has_check_ = false;
  QTimer* live_check_timer_ = nullptr;
  // Quick scan, while the listener runs.
  std::unique_ptr<support_assist::QuickScan> scan_;
  bool scan_available_ = false;
  std::string scan_unavailable_;
};

} // namespace quick

using quick::QuickToolHost;
using quick::QuickToolWindow;
using quick::ShortcutsPage;

} // namespace sat_qt
