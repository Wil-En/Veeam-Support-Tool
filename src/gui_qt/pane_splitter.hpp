#pragma once

// Draggable, collapsible dividers between the panes of the review pages: Log Review, Environment
// Review, Health Monitor and Case Dashboard.
//
// The Windows edition draws its own bars (src/gui/pane_splits.cpp). Qt has QSplitter, so this is
// the layer that gives it the same behaviour and the same storage: a divider holds at a pane's
// minimum and collapses the pane once dragged past half of it, a double-click brings a collapsed
// pane back or returns the divider to its default, and positions are kept in ui-settings.ini under
// [Panes] with the keys and the integer form the Windows edition writes.
//
// Free of Q_OBJECT, like terminal_view.hpp: the behaviour comes from virtual overrides and lambdas,
// so there is nothing for moc to generate.

#include "sat_theme.hpp"

#include <QColor>
#include <QEnterEvent>
#include <QEvent>
#include <QList>
#include <QMetaType>
#include <QMouseEvent>
#include <QPainter>
#include <QSettings>
#include <QSplitter>
#include <QSplitterHandle>
#include <QString>
#include <QStringList>
#include <QVariant>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace sat_qt {

class PaneSplitter;

// Where every divider position is kept. The main window points it at ui-settings.ini at start-up.
class PaneLayoutStore {
public:
  static PaneLayoutStore& instance() {
    static PaneLayoutStore store;
    return store;
  }

  // read_file names the ini to read. write_file names the ini to write and creates its folder, or
  // returns an empty string when this copy writes nothing: a portable copy not yet used on the
  // machine it is running on, or a session without an engineer licence. Positions are then kept
  // for the session only.
  void configure(std::function<QString()> read_file, std::function<QString()> write_file) {
    read_file_ = std::move(read_file);
    write_file_ = std::move(write_file);
  }

  // Divider positions as fractions of the span, or empty when nothing usable is stored.
  std::vector<double> load(const QString& key, std::size_t dividers) const {
    QStringList parts;
    if (const auto kept = session_.find(key); kept != session_.end()) {
      parts = kept->second.split(QLatin1Char(','), Qt::SkipEmptyParts);
    } else {
      if (!read_file_ || ignore_file_) {
        return {};
      }
      const QString file = read_file_();
      if (file.isEmpty()) {
        return {};
      }
      const QSettings settings(file, QSettings::IniFormat);
      const QVariant stored = settings.value(QStringLiteral("Panes/") + key);
      // Written as "3100,6600". QSettings reads an unquoted comma list back as a string list.
      parts = stored.userType() == QMetaType::QStringList
                  ? stored.toStringList()
                  : stored.toString().split(QLatin1Char(','), Qt::SkipEmptyParts);
    }
    if (static_cast<std::size_t>(parts.size()) != dividers) {
      return {};
    }
    // A value that does not fit this group, out of range or out of order as a hand-edited file
    // can be, leaves the defaults in place.
    std::vector<double> bounds;
    double previous = 0.0;
    for (const QString& part : parts) {
      bool ok = false;
      const double bound = part.trimmed().toInt(&ok) / kStoredScale;
      if (!ok || bound < previous || bound > 1.0) {
        return {};
      }
      bounds.push_back(bound);
      previous = bound;
    }
    return bounds;
  }

  // Stored as hundredths of a percent, so the text never carries a locale's decimal separator.
  void save(const QString& key, const std::vector<double>& bounds) {
    QStringList parts;
    for (const double bound : bounds) {
      parts << QString::number(static_cast<int>(std::lround(std::clamp(bound, 0.0, 1.0) *
                                                            kStoredScale)));
    }
    const QString file = write_file_ ? write_file_() : QString();
    if (file.isEmpty()) {
      session_[key] = parts.join(QLatin1Char(','));
      return;
    }
    QSettings settings(file, QSettings::IniFormat);
    settings.setValue(QStringLiteral("Panes/") + key, parts.join(QLatin1Char(',')));
    settings.sync();
  }

  void add(PaneSplitter* splitter) { live_.push_back(splitter); }
  void remove(PaneSplitter* splitter) {
    live_.erase(std::remove(live_.begin(), live_.end(), splitter), live_.end());
  }

  // View > Reset Pane Layout: every open page back to its defaults, and every stored position
  // dropped so pages built later start from their defaults too.
  inline void reset_all();

  // Writes the positions kept for the session, once there is somewhere to write them: an engineer
  // licence activated during the session.
  void persist_session() {
    const QString file = write_file_ ? write_file_() : QString();
    if (file.isEmpty() || session_.empty()) {
      return;
    }
    QSettings settings(file, QSettings::IniFormat);
    for (const auto& [key, value] : session_) {
      settings.setValue(QStringLiteral("Panes/") + key, value);
    }
    settings.sync();
    session_.clear();
  }

  static constexpr double kStoredScale = 10000.0;

private:
  std::function<QString()> read_file_;
  std::function<QString()> write_file_;
  std::vector<PaneSplitter*> live_;
  // Positions kept for this session when nothing is written, and whether a reset in such a session
  // means the file's positions no longer apply.
  std::map<QString, QString> session_;
  bool ignore_file_ = false;
};

class PaneSplitter : public QSplitter {
public:
  // defaults: where each divider sits until the engineer moves it, as a fraction of the span.
  PaneSplitter(Qt::Orientation orientation, QString key, std::vector<double> defaults,
               QWidget* parent = nullptr)
      : QSplitter(orientation, parent), key_(std::move(key)), defaults_(std::move(defaults)) {
    setChildrenCollapsible(true);
    setOpaqueResize(true);
    // The width of the gap the panes sat apart by before the dividers existed.
    setHandleWidth(10);
    PaneLayoutStore::instance().add(this);
    connect(this, &QSplitter::splitterMoved, this, [this](int, int) {
      if (!applying_) {
        capture();
      }
    });
  }

  ~PaneSplitter() override { PaneLayoutStore::instance().remove(this); }

  PaneSplitter(const PaneSplitter&) = delete;
  PaneSplitter& operator=(const PaneSplitter&) = delete;

  // Adds a pane. minimum is the smallest useful size along the split, in pixels; a collapsible pane
  // dragged below half of it collapses. A pane that holds the page's controls, or that nothing
  // would replace, is added with collapsible false and its divider holds at the minimum instead.
  void add_pane(QWidget* pane, int minimum, bool collapsible = true) {
    if (orientation() == Qt::Horizontal) {
      pane->setMinimumWidth(minimum);
    } else {
      pane->setMinimumHeight(minimum);
    }
    addWidget(pane);
    setCollapsible(count() - 1, collapsible);
    shares_.clear();
  }

  // Double-click on a divider. A collapsed pane on either side comes back at the size it had;
  // otherwise the two panes return to their default proportion.
  void toggle(int handle_index) {
    ensure_model();
    const int after = handle_index;
    int before = handle_index - 1;
    while (before >= 0 && widget(before)->isHidden()) {
      --before;
    }
    if (before < 0 || after >= count() || widget(after)->isHidden()) {
      return;
    }
    const auto b = static_cast<std::size_t>(before);
    const auto a = static_cast<std::size_t>(after);
    const std::vector<double> preset = shares_from_bounds(default_bounds());
    const double pair = shares_[b] + shares_[a];
    const double preset_pair = preset[b] + preset[a];
    const auto default_split = [&](std::size_t pane) {
      return preset_pair > kEdge ? pair * preset[pane] / preset_pair : pair / 2.0;
    };
    const bool before_collapsed = shares_[b] <= kEdge;
    const bool after_collapsed = shares_[a] <= kEdge;
    if (pair <= kEdge) {
      // Both panes collapsed against a third: the group starts again from its defaults.
      shares_ = preset;
    } else if (before_collapsed || after_collapsed) {
      const std::size_t collapsed = before_collapsed ? b : a;
      const std::size_t other = before_collapsed ? a : b;
      double wanted = remembered_[collapsed];
      if (wanted <= kEdge || wanted >= pair - kEdge) {
        wanted = default_split(collapsed);
      }
      shares_[collapsed] = wanted;
      shares_[other] = pair - wanted;
    } else {
      shares_[b] = default_split(b);
      shares_[a] = pair - shares_[b];
    }
    remember();
    apply();
    dirty_ = true;
    persist();
  }

  void reset_to_defaults() {
    shares_ = shares_from_bounds(default_bounds());
    remembered_ = shares_;
    apply();
  }

  // Called when a drag ends, so a move is written once rather than on every pixel.
  void persist() {
    if (!dirty_) {
      return;
    }
    dirty_ = false;
    PaneLayoutStore::instance().save(key_, bounds_from_shares());
  }

protected:
  QSplitterHandle* createHandle() override;

  bool event(QEvent* event) override {
    const bool handled = QSplitter::event(event);
    switch (event->type()) {
    case QEvent::Show:
    case QEvent::ShowToParent:
    case QEvent::LayoutRequest: {
      // A pane was shown or hidden. The visible panes are laid out from their proportions again,
      // so a pane that returns gets its own size back rather than whatever Qt last gave it.
      const bool rebuilt = ensure_model();
      if (rebuilt || visibility_signature() != applied_signature_) {
        apply();
      }
      break;
    }
    default:
      break;
    }
    return handled;
  }

private:
  // A divider this close to a neighbour, as a fraction of the span, counts as collapsed.
  static constexpr double kEdge = 0.0005;
  // setSizes() takes relative weights. A large span keeps every share above the panes' minimums,
  // so Qt distributes the real span in proportion instead of raising small values to a minimum.
  static constexpr double kVirtualSpan = 100000.0;

  std::vector<double> default_bounds() const {
    const auto panes = static_cast<std::size_t>(std::max(count(), 1));
    if (defaults_.size() + 1 == panes) {
      return defaults_;
    }
    std::vector<double> even;
    for (std::size_t index = 1; index < panes; ++index) {
      even.push_back(static_cast<double>(index) / static_cast<double>(panes));
    }
    return even;
  }

  std::vector<double> shares_from_bounds(const std::vector<double>& bounds) const {
    std::vector<double> shares;
    double previous = 0.0;
    for (std::size_t index = 0; index <= bounds.size(); ++index) {
      const double bound = index < bounds.size() ? bounds[index] : 1.0;
      shares.push_back(std::max(0.0, bound - previous));
      previous = std::max(previous, bound);
    }
    return shares;
  }

  std::vector<double> bounds_from_shares() const {
    std::vector<double> bounds;
    double running = 0.0;
    for (std::size_t index = 0; index + 1 < shares_.size(); ++index) {
      running += shares_[index];
      bounds.push_back(std::clamp(running, 0.0, 1.0));
    }
    return bounds;
  }

  // Builds the proportions from what is stored, or the defaults, once the panes are all added.
  // Returns true when it did.
  bool ensure_model() {
    const auto panes = static_cast<std::size_t>(count());
    if (panes == 0 || shares_.size() == panes) {
      return false;
    }
    std::vector<double> bounds;
    if (defaults_.size() + 1 == panes) {
      bounds = PaneLayoutStore::instance().load(key_, defaults_.size());
    }
    if (bounds.empty()) {
      bounds = default_bounds();
    }
    shares_ = shares_from_bounds(bounds);
    remembered_ = shares_from_bounds(default_bounds());
    remember();
    return true;
  }

  void remember() {
    for (std::size_t index = 0; index < shares_.size(); ++index) {
      if (shares_[index] > kEdge) {
        remembered_[index] = shares_[index];
      }
    }
  }

  unsigned long long visibility_signature() const {
    unsigned long long signature = 0;
    for (int index = 0; index < count() && index < 64; ++index) {
      if (!widget(index)->isHidden()) {
        signature |= 1ULL << index;
      }
    }
    return signature;
  }

  void apply() {
    ensure_model();
    QList<int> values;
    for (const double share : shares_) {
      values << (share <= kEdge ? 0 : static_cast<int>(std::lround(share * kVirtualSpan)));
    }
    applying_ = true;
    setSizes(values);
    applying_ = false;
    applied_signature_ = visibility_signature();
  }

  // After a drag: the visible panes share out what they held between them, in proportion to the
  // sizes they now have. A hidden pane keeps its share for when it is shown again.
  void capture() {
    ensure_model();
    const QList<int> current = sizes();
    double held = 0.0;
    double hidden = 0.0;
    double pixels = 0.0;
    for (int index = 0; index < count(); ++index) {
      const double share = shares_[static_cast<std::size_t>(index)];
      if (widget(index)->isHidden()) {
        hidden += share;
        continue;
      }
      held += share;
      pixels += current.value(index);
    }
    if (pixels <= 0.0) {
      return;
    }
    if (held <= kEdge) {
      held = std::max(kEdge, 1.0 - hidden);
    }
    for (int index = 0; index < count(); ++index) {
      if (!widget(index)->isHidden()) {
        shares_[static_cast<std::size_t>(index)] = held * current.value(index) / pixels;
      }
    }
    double total = 0.0;
    for (const double share : shares_) {
      total += share;
    }
    if (total > 0.0) {
      for (double& share : shares_) {
        share /= total;
      }
    }
    remember();
    dirty_ = true;
  }

  QString key_;
  std::vector<double> defaults_;
  // Each pane's share of the span, summing to 1, hidden panes included.
  std::vector<double> shares_;
  // The last share each pane had before it collapsed, for the double-click restore.
  std::vector<double> remembered_;
  unsigned long long applied_signature_ = 0;
  bool applying_ = false;
  bool dirty_ = false;
};

// The bar between two panes. It paints the same two states as the Windows bars: three dots while
// idle, and an accent line while it is under the pointer or being dragged.
class PaneHandle : public QSplitterHandle {
public:
  PaneHandle(Qt::Orientation orientation, PaneSplitter* owner)
      : QSplitterHandle(orientation, owner), owner_(owner) {}

protected:
  void paintEvent(QPaintEvent*) override {
    QPainter painter(this);
    painter.setPen(Qt::NoPen);
    const bool active = hot_ || pressed_;
    // The app's accent, as the progress bar uses, and a muted green for the idle dots.
    painter.setBrush(active ? support_assist::gui::theme::themed_color(QColor(0x55, 0xBE, 0x58))
                           : support_assist::gui::theme::themed_color(QColor(0x3A, 0x68, 0x5E)));
    const QRect area = rect();
    const QPoint middle = area.center();
    const bool side_by_side = orientation() == Qt::Horizontal;
    if (active) {
      painter.drawRect(side_by_side ? QRect(middle.x() - 1, area.top(), 2, area.height())
                                    : QRect(area.left(), middle.y() - 1, area.width(), 2));
      return;
    }
    for (int dot = -1; dot <= 1; ++dot) {
      const QPoint at = side_by_side ? QPoint(middle.x(), middle.y() + dot * 7)
                                     : QPoint(middle.x() + dot * 7, middle.y());
      painter.drawRect(QRect(at.x() - 1, at.y() - 1, 3, 3));
    }
  }

  void enterEvent(QEnterEvent* event) override {
    hot_ = true;
    update();
    QSplitterHandle::enterEvent(event);
  }

  void leaveEvent(QEvent* event) override {
    hot_ = false;
    update();
    QSplitterHandle::leaveEvent(event);
  }

  void mousePressEvent(QMouseEvent* event) override {
    if (event->button() == Qt::LeftButton) {
      pressed_ = true;
      update();
    }
    QSplitterHandle::mousePressEvent(event);
  }

  void mouseReleaseEvent(QMouseEvent* event) override {
    QSplitterHandle::mouseReleaseEvent(event);
    if (event->button() == Qt::LeftButton) {
      pressed_ = false;
      update();
      owner_->persist();
    }
  }

  void mouseDoubleClickEvent(QMouseEvent* event) override {
    if (event->button() == Qt::LeftButton) {
      owner_->toggle(owner_->indexOf(this));
    }
  }

private:
  PaneSplitter* owner_;
  bool hot_ = false;
  bool pressed_ = false;
};

inline QSplitterHandle* PaneSplitter::createHandle() {
  return new PaneHandle(orientation(), this);
}

inline void PaneLayoutStore::reset_all() {
  session_.clear();
  const QString file = write_file_ ? write_file_() : QString();
  if (!file.isEmpty()) {
    QSettings settings(file, QSettings::IniFormat);
    settings.remove(QStringLiteral("Panes"));
    settings.sync();
  } else {
    ignore_file_ = true;
  }
  for (PaneSplitter* splitter : live_) {
    splitter->reset_to_defaults();
  }
}

}  // namespace sat_qt
