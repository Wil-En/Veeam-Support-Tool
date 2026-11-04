// Draggable, collapsible dividers between the panes of the review pages (Log Review, Environment
// Review, Health Monitor, Case Dashboard) and of the two-pane pages (Integrations, File Browser,
// Remote).
//
// A page's layout asks place_split for its panes instead of using fixed percentages. The bars sit on
// bare parent background between the child windows, so the parent hit-tests them. Positions are
// fractions of the span, so they survive a window resize,
// and they are written to ui-settings.ini as integers so the text never carries a locale's decimal
// separator. Kept out of app_window.cpp, which is already past 35,000 lines.

#include "app_window.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <string>

namespace {

// Stored as hundredths of a percent.
constexpr double kStoredScale = 10000.0;
// A divider this close to a neighbour, as a fraction of the span, counts as collapsed.
constexpr double kEdge = 0.0005;
// The app's accent, as used by the progress bar, for the divider under the pointer or being dragged.
constexpr COLORREF kDividerActive = RGB(85, 190, 88);
constexpr COLORREF kDividerIdle = RGB(58, 104, 94);

}  // namespace

void AppWindow::init_splits() {
  // collapsible: per pane, empty for all. A pane that holds the page's controls, or that nothing
  // would replace, is left out, and its divider holds at the pane's minimum instead.
  const auto define = [this](SplitId id, const wchar_t* key, bool side_by_side,
                             std::vector<double> defaults, std::vector<int> minimums,
                             std::vector<bool> collapsible = {}) {
    SplitGroup& group = splits_[static_cast<std::size_t>(id)];
    group.key = key;
    group.side_by_side = side_by_side;
    group.defaults = defaults;
    group.bounds = defaults;
    group.restore = std::move(defaults);
    if (collapsible.empty())
      collapsible.assign(minimums.size(), true);
    group.collapsible = std::move(collapsible);
    group.minimums = std::move(minimums);
  };
  // The defaults reproduce the proportions these pages used before the dividers existed.
  define(SplitId::log_review_columns, L"LogReviewColumns", true, {1.0 / 3.0, 2.0 / 3.0},
         {170, 170, 170});
  define(SplitId::log_review_rows, L"LogReviewRows", false, {0.31, 0.66}, {90, 110, 70});
  define(SplitId::environment_columns, L"EnvironmentColumns", true, {0.43}, {220, 220});
  define(SplitId::environment_rows, L"EnvironmentRows", false, {0.62}, {120, 70});
  define(SplitId::health_rows, L"HealthRows", false, {0.46}, {100, 100});
  define(SplitId::health_top, L"HealthTop", true, {0.5}, {200, 200});
  define(SplitId::health_bottom, L"HealthBottom", true, {0.5}, {200, 200});
  define(SplitId::case_rows, L"CaseRows", false, {0.22}, {70, 110});
  define(SplitId::case_columns, L"CaseColumns", true, {0.5}, {220, 220});
  // A folded Tools table and its selected row: the table keeps most of the height.
  define(SplitId::tool_result_rows, L"ToolResultRows", false, {0.62}, {120, 80}, {false, false});
  // The Integrations detail carries the tool's action buttons; its minimum is set from the
  // current text scale by the layout, since the buttons are measured with it.
  define(SplitId::integration_columns, L"IntegrationsColumns", true, {0.55}, {300, 560},
         {false, false});
  // The folder tree can be put away like a sidebar; the folder's contents cannot.
  define(SplitId::explorer_columns, L"ExplorerColumns", true, {0.30}, {200, 260}, {true, false});
  // The Remote file pane carries Download and Upload, and the terminal is what the page is for, so
  // neither side collapses.
  define(SplitId::remote_columns, L"RemoteColumns", true, {0.24}, {240, 320}, {false, false});
  // The Case Manager: the case list over the editor (or the New Case form, which needs 190 pixels);
  // in the editor, Status, Save and Case notes beside Next steps over Selected case.
  define(SplitId::case_manager_rows, L"CaseManagerRows", false, {0.5}, {90, 190}, {false, false});
  define(SplitId::case_manager_columns, L"CaseManagerColumns", true, {0.5}, {260, 220}, {false, false});
  define(SplitId::case_manager_right, L"CaseManagerRight", false, {0.45}, {60, 70});
}

std::vector<int> AppWindow::split_offsets(const SplitGroup& group) const {
  std::vector<int> offsets;
  offsets.reserve(group.bounds.size());
  int previous = 0;
  for (const double bound : group.bounds) {
    const int offset = std::clamp(static_cast<int>(std::lround(bound * group.usable)), previous,
                                  std::max(previous, group.usable));
    offsets.push_back(offset);
    previous = offset;
  }
  // A pane that does not collapse is never drawn below its minimum while the pane beside it can
  // give the room, as Qt's splitter behaves. The stored position is left as it is.
  for (std::size_t bar = 0; bar < offsets.size(); ++bar) {
    const int low = bar == 0 ? 0 : offsets[bar - 1];
    const int high = bar + 1 < offsets.size() ? offsets[bar + 1] : group.usable;
    const int min_before = group.collapsible[bar] ? 0 : group.minimums[bar];
    const int min_after = group.collapsible[bar + 1] ? 0 : group.minimums[bar + 1];
    if (high - offsets[bar] < min_after)
      offsets[bar] = std::max(low, high - min_after);
    if (offsets[bar] - low < min_before)
      offsets[bar] = std::min(high, low + min_before);
  }
  return offsets;
}

std::vector<AppWindow::SplitPane> AppWindow::place_split(SplitId id, int start, int length,
                                                        int cross_start, int cross_length,
                                                        int bar) {
  SplitGroup& group = splits_[static_cast<std::size_t>(id)];
  const int bars = static_cast<int>(group.bounds.size());
  group.start = start;
  group.bar = bar;
  group.usable = std::max(0, length - bars * bar);
  group.area = group.side_by_side
                   ? RECT{start, cross_start, start + length, cross_start + cross_length}
                   : RECT{cross_start, start, cross_start + cross_length, start + length};
  group.placed = true;
  const std::vector<int> offsets = split_offsets(group);
  std::vector<SplitPane> panes;
  panes.reserve(offsets.size() + 1);
  int previous = 0;
  for (int index = 0; index <= bars; ++index) {
    const int end = index < bars ? offsets[static_cast<std::size_t>(index)] : group.usable;
    panes.push_back({start + previous + index * bar, std::max(0, end - previous)});
    previous = end;
  }
  return panes;
}

RECT AppWindow::split_bar_rect(std::size_t group_index, std::size_t bar_index) const {
  const SplitGroup& group = splits_[group_index];
  const std::vector<int> offsets = split_offsets(group);
  const int at = group.start + offsets[bar_index] + static_cast<int>(bar_index) * group.bar;
  return group.side_by_side ? RECT{at, group.area.top, at + group.bar, group.area.bottom}
                            : RECT{group.area.left, at, group.area.right, at + group.bar};
}

bool AppWindow::split_hit(int x, int y, int& group_out, int& bar_out) const {
  const POINT point{x, y};
  for (std::size_t group = 0; group < splits_.size(); ++group) {
    if (!splits_[group].placed || splits_[group].bar <= 0)
      continue;
    for (std::size_t bar = 0; bar < splits_[group].bounds.size(); ++bar) {
      const RECT rect = split_bar_rect(group, bar);
      if (PtInRect(&rect, point) != FALSE) {
        group_out = static_cast<int>(group);
        bar_out = static_cast<int>(bar);
        return true;
      }
    }
  }
  return false;
}

void AppWindow::split_relayout() {
  RECT client{};
  GetClientRect(window_, &client);
  layout(client.right, client.bottom);
  // The bars moved with the panes. WS_CLIPCHILDREN keeps this to the bare background they sit on.
  InvalidateRect(window_, nullptr, TRUE);
}

void AppWindow::split_drag_to(int x, int y) {
  if (split_drag_group_ < 0)
    return;
  SplitGroup& group = splits_[static_cast<std::size_t>(split_drag_group_)];
  const auto bar = static_cast<std::size_t>(split_drag_bar_);
  if (group.usable <= 0)
    return;
  const std::vector<int> offsets = split_offsets(group);
  const int low = bar == 0 ? 0 : offsets[bar - 1];
  const int high = bar + 1 < offsets.size() ? offsets[bar + 1] : group.usable;
  const int pointer = group.side_by_side ? x : y;
  int offset = std::clamp(
      pointer - split_drag_grab_ - group.start - static_cast<int>(bar) * group.bar, low, high);
  // A divider holds at a pane's minimum, and once dragged past half of it a collapsible pane
  // collapses.
  const int min_before = group.minimums[bar];
  const int min_after = group.minimums[bar + 1];
  if (offset - low < min_before)
    offset = group.collapsible[bar] && offset - low < min_before / 2
                 ? low
                 : std::min(high, low + min_before);
  if (high - offset < min_after)
    offset = group.collapsible[bar + 1] && high - offset < min_after / 2
                 ? high
                 : std::max(low, high - min_after);
  const double position = static_cast<double>(offset) / static_cast<double>(group.usable);
  if (std::abs(position - group.bounds[bar]) < 1e-9)
    return;
  // A press that moved the divider was a drag, so the next press starts a new click rather than
  // completing a double-click.
  split_last_click_group_ = -1;
  group.bounds[bar] = position;
  if (offset != low && offset != high)
    group.restore[bar] = position;
  split_relayout();
}

void AppWindow::split_toggle(int group_index, int bar_index) {
  SplitGroup& group = splits_[static_cast<std::size_t>(group_index)];
  const auto bar = static_cast<std::size_t>(bar_index);
  const double low = bar == 0 ? 0.0 : group.bounds[bar - 1];
  const double high = bar + 1 < group.bounds.size() ? group.bounds[bar + 1] : 1.0;
  const auto at_edge = [low, high](double value) {
    return value <= low + kEdge || value >= high - kEdge;
  };
  // Collapsed: bring the pane back to where it was. Otherwise: reset this divider.
  const bool collapsed = at_edge(group.bounds[bar]);
  double target = collapsed ? group.restore[bar] : group.defaults[bar];
  if (at_edge(target))
    target = group.defaults[bar];
  group.bounds[bar] = std::clamp(target, low, high);
  if (!at_edge(group.bounds[bar]))
    group.restore[bar] = group.bounds[bar];
  split_relayout();
  save_ui_settings();
}

void AppWindow::split_set_hot(int group, int bar) {
  if (group == split_hot_group_ && bar == split_hot_bar_)
    return;
  const auto repaint = [this](int g, int b) {
    if (g < 0 || b < 0 || !splits_[static_cast<std::size_t>(g)].placed)
      return;
    const RECT rect = split_bar_rect(static_cast<std::size_t>(g), static_cast<std::size_t>(b));
    InvalidateRect(window_, &rect, TRUE);
  };
  repaint(split_hot_group_, split_hot_bar_);
  split_hot_group_ = group;
  split_hot_bar_ = bar;
  repaint(group, bar);
  if (group >= 0) {
    // Moving onto a child window or off the window clears the highlight.
    TRACKMOUSEEVENT track{};
    track.cbSize = sizeof(track);
    track.dwFlags = TME_LEAVE;
    track.hwndTrack = window_;
    TrackMouseEvent(&track);
  }
}

void AppWindow::paint_split_grips(HDC dc) const {
  // Three dots at the middle of each bar mark it as something to drag without drawing a line
  // through the page. The bar under the pointer, or being dragged, shows as an accent line.
  for (std::size_t group_index = 0; group_index < splits_.size(); ++group_index) {
    const SplitGroup& group = splits_[group_index];
    if (!group.placed || group.bar <= 0)
      continue;
    for (std::size_t bar = 0; bar < group.bounds.size(); ++bar) {
      const int g = static_cast<int>(group_index);
      const int b = static_cast<int>(bar);
      const bool active = (g == split_drag_group_ && b == split_drag_bar_) ||
                          (g == split_hot_group_ && b == split_hot_bar_);
      const RECT rect = split_bar_rect(group_index, bar);
      const HBRUSH brush = CreateSolidBrush(active ? themed(kDividerActive) : themed(kDividerIdle));
      const int middle_x = (rect.left + rect.right) / 2;
      const int middle_y = (rect.top + rect.bottom) / 2;
      if (active) {
        RECT line = rect;
        if (group.side_by_side) {
          line.left = middle_x - 1;
          line.right = middle_x + 1;
        } else {
          line.top = middle_y - 1;
          line.bottom = middle_y + 1;
        }
        FillRect(dc, &line, brush);
      } else {
        for (int dot = -1; dot <= 1; ++dot) {
          const RECT pip = group.side_by_side
                               ? RECT{middle_x - 1, middle_y + dot * 7 - 1, middle_x + 2,
                                      middle_y + dot * 7 + 2}
                               : RECT{middle_x + dot * 7 - 1, middle_y - 1, middle_x + dot * 7 + 2,
                                      middle_y + 2};
          FillRect(dc, &pip, brush);
        }
      }
      DeleteObject(brush);
    }
  }
}

void AppWindow::reset_pane_layout() {
  for (SplitGroup& group : splits_) {
    group.bounds = group.defaults;
    group.restore = group.defaults;
  }
  split_relayout();
  save_ui_settings();
}

void AppWindow::load_splits(const std::filesystem::path& path) {
  for (SplitGroup& group : splits_) {
    wchar_t text[256] = {};
    GetPrivateProfileStringW(L"Panes", group.key, L"", text, 256, path.c_str());
    std::vector<double> values;
    std::wstringstream stream{std::wstring{text}};
    std::wstring token;
    while (std::getline(stream, token, L','))
      values.push_back(_wtoi(token.c_str()) / kStoredScale);
    // A value that does not fit this group - wrong count, out of range or out of order, as a
    // hand-edited file can be - leaves the defaults in place.
    bool valid = values.size() == group.bounds.size();
    double previous = 0.0;
    for (std::size_t pane = 0; valid && pane <= values.size(); ++pane) {
      const double value = pane < values.size() ? values[pane] : 1.0;
      valid = value >= previous && value <= 1.0 &&
              (group.collapsible[pane] || value - previous > kEdge);
      previous = value;
    }
    if (!valid)
      continue;
    group.bounds = values;
    for (std::size_t bar = 0; bar < values.size(); ++bar) {
      const double low = bar == 0 ? 0.0 : values[bar - 1];
      const double high = bar + 1 < values.size() ? values[bar + 1] : 1.0;
      if (values[bar] > low + kEdge && values[bar] < high - kEdge)
        group.restore[bar] = values[bar];
    }
  }
}

void AppWindow::save_splits(const std::filesystem::path& path) const {
  for (const SplitGroup& group : splits_) {
    std::wstring text;
    for (std::size_t bar = 0; bar < group.bounds.size(); ++bar) {
      if (bar > 0)
        text += L',';
      text += std::to_wstring(static_cast<int>(std::lround(group.bounds[bar] * kStoredScale)));
    }
    WritePrivateProfileStringW(L"Panes", group.key, text.c_str(), path.c_str());
  }
}
