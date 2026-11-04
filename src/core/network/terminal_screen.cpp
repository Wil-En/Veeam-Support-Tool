#include "support_assist/terminal_screen.hpp"

#include <algorithm>
#include <cstdlib>

namespace support_assist {
namespace {

// Enough history for an engineer to scroll back through a long tail without the process growing
// without bound on a session left open all afternoon.
constexpr std::size_t kMaximumScrollbackRows = 5000;

constexpr int kTabStop = 8;

int parameter_or(const std::vector<int>& parameters, std::size_t index, int fallback) {
  if (index >= parameters.size())
    return fallback;
  // A zero parameter means "default" for nearly every CSI that takes a count, and treating it as a
  // literal zero moves the cursor nowhere and makes output look frozen.
  return parameters[index] == 0 ? fallback : parameters[index];
}

} // namespace

TerminalScreen::TerminalScreen(int columns, int rows)
    : columns_(std::max(1, columns)), rows_(std::max(1, rows)) {
  grid_.assign(static_cast<std::size_t>(rows_),
               std::vector<TerminalCell>(static_cast<std::size_t>(columns_), TerminalCell{}));
}

TerminalCell TerminalScreen::blank() const {
  // A blank inherits the current background so that an erase after a colour change fills with that
  // colour, which is how a full-screen application paints its backdrop.
  TerminalCell cell;
  cell.background = pen_.background;
  return cell;
}

const TerminalCell& TerminalScreen::cell(int row, int column) const {
  static const TerminalCell empty{};
  if (row < 0 || row >= rows_ || column < 0 || column >= columns_)
    return empty;
  return grid_[static_cast<std::size_t>(row)][static_cast<std::size_t>(column)];
}

void TerminalScreen::clamp_cursor() {
  cursor_column_ = std::clamp(cursor_column_, 0, columns_ - 1);
  cursor_row_ = std::clamp(cursor_row_, 0, rows_ - 1);
}

void TerminalScreen::resize(int columns, int rows) {
  columns = std::max(1, columns);
  rows = std::max(1, rows);
  if (columns == columns_ && rows == rows_)
    return;

  // Keep the bottom of the screen when shrinking. An engineer watching output cares about the most
  // recent lines; discarding those and keeping the top would throw away what they are reading.
  std::vector<std::vector<TerminalCell>> resized(
      static_cast<std::size_t>(rows),
      std::vector<TerminalCell>(static_cast<std::size_t>(columns), TerminalCell{}));
  const int copy_rows = std::min(rows, rows_);
  const int copy_columns = std::min(columns, columns_);
  for (int row = 0; row < copy_rows; ++row) {
    const int source_row = rows_ - copy_rows + row;
    for (int column = 0; column < copy_columns; ++column) {
      resized[static_cast<std::size_t>(row)][static_cast<std::size_t>(column)] =
          grid_[static_cast<std::size_t>(source_row)][static_cast<std::size_t>(column)];
    }
  }
  grid_ = std::move(resized);
  cursor_row_ -= (rows_ - copy_rows);
  columns_ = columns;
  rows_ = rows;
  clamp_cursor();
  ++revision_;
}

void TerminalScreen::scroll_up() {
  if (grid_.empty())
    return;
  scrollback_.push_back(std::move(grid_.front()));
  if (scrollback_.size() > kMaximumScrollbackRows)
    scrollback_.erase(scrollback_.begin());
  grid_.erase(grid_.begin());
  grid_.emplace_back(static_cast<std::size_t>(columns_), blank());
}

void TerminalScreen::line_feed() {
  if (cursor_row_ + 1 >= rows_)
    scroll_up();
  else
    ++cursor_row_;
}

void TerminalScreen::carriage_return() { cursor_column_ = 0; }

void TerminalScreen::backspace() {
  if (cursor_column_ > 0)
    --cursor_column_;
}

void TerminalScreen::tab() {
  const int next = ((cursor_column_ / kTabStop) + 1) * kTabStop;
  cursor_column_ = std::min(next, columns_ - 1);
}

void TerminalScreen::put(char32_t glyph) {
  // Wrap before writing, not after: a glyph arriving with the cursor already past the last column
  // belongs on the next line.
  if (cursor_column_ >= columns_) {
    cursor_column_ = 0;
    line_feed();
  }
  TerminalCell cell = pen_;
  cell.glyph = glyph;
  grid_[static_cast<std::size_t>(cursor_row_)][static_cast<std::size_t>(cursor_column_)] = cell;
  ++cursor_column_;
}

void TerminalScreen::erase_in_line(int mode) {
  auto& row = grid_[static_cast<std::size_t>(cursor_row_)];
  const int from = mode == 0 ? cursor_column_ : 0;
  const int to = mode == 1 ? cursor_column_ + 1 : columns_;
  for (int column = std::max(0, from); column < std::min(columns_, to); ++column)
    row[static_cast<std::size_t>(column)] = blank();
}

void TerminalScreen::erase_in_display(int mode) {
  const int from_row = mode == 0 ? cursor_row_ : 0;
  const int to_row = mode == 1 ? cursor_row_ + 1 : rows_;
  if (mode == 0)
    erase_in_line(0);
  if (mode == 1)
    erase_in_line(1);
  for (int row = from_row; row < std::min(rows_, to_row); ++row) {
    if ((mode == 0 && row == cursor_row_) || (mode == 1 && row == cursor_row_))
      continue;
    std::fill(grid_[static_cast<std::size_t>(row)].begin(),
              grid_[static_cast<std::size_t>(row)].end(), blank());
  }
}

void TerminalScreen::apply_graphic_rendition(const std::vector<int>& parameters) {
  if (parameters.empty()) {
    pen_ = TerminalCell{};
    return;
  }
  for (std::size_t index = 0; index < parameters.size(); ++index) {
    const int code = parameters[index];
    if (code == 0) {
      pen_ = TerminalCell{};
    } else if (code == 1) {
      pen_.bold = true;
    } else if (code == 4) {
      pen_.underline = true;
    } else if (code == 7) {
      pen_.inverse = true;
    } else if (code == 22) {
      pen_.bold = false;
    } else if (code == 24) {
      pen_.underline = false;
    } else if (code == 27) {
      pen_.inverse = false;
    } else if (code >= 30 && code <= 37) {
      pen_.foreground = static_cast<std::int8_t>(code - 30);
    } else if (code == 39) {
      pen_.foreground = -1;
    } else if (code >= 40 && code <= 47) {
      pen_.background = static_cast<std::int8_t>(code - 40);
    } else if (code == 49) {
      pen_.background = -1;
    } else if (code >= 90 && code <= 97) {
      pen_.foreground = static_cast<std::int8_t>(code - 90 + 8);
    } else if (code >= 100 && code <= 107) {
      pen_.background = static_cast<std::int8_t>(code - 100 + 8);
    } else if ((code == 38 || code == 48) && index + 1 < parameters.size()) {
      // 256-colour and truecolour selectors. The palette here is 16 entries, so the extended colour
      // is consumed and the nearest basic slot kept rather than leaving the parameters to be
      // misread as separate attributes - which is what paints a log listing entirely magenta.
      const bool foreground = code == 38;
      const int selector = parameters[index + 1];
      if (selector == 5 && index + 2 < parameters.size()) {
        const int value = parameters[index + 2];
        const std::int8_t basic = static_cast<std::int8_t>(value < 16 ? value : (value % 8));
        if (foreground) pen_.foreground = basic; else pen_.background = basic;
        index += 2;
      } else if (selector == 2 && index + 4 < parameters.size()) {
        index += 4;
      } else {
        index += 1;
      }
    }
  }
}

void TerminalScreen::execute_csi(char final_byte,
                                 const std::vector<int>& parameters,
                                 bool private_marker) {
  switch (final_byte) {
  case 'A': cursor_row_ -= parameter_or(parameters, 0, 1); break;
  case 'B': cursor_row_ += parameter_or(parameters, 0, 1); break;
  case 'C': cursor_column_ += parameter_or(parameters, 0, 1); break;
  case 'D': cursor_column_ -= parameter_or(parameters, 0, 1); break;
  case 'E': cursor_row_ += parameter_or(parameters, 0, 1); cursor_column_ = 0; break;
  case 'F': cursor_row_ -= parameter_or(parameters, 0, 1); cursor_column_ = 0; break;
  case 'G': cursor_column_ = parameter_or(parameters, 0, 1) - 1; break;
  case 'H':
  case 'f':
    cursor_row_ = parameter_or(parameters, 0, 1) - 1;
    cursor_column_ = parameter_or(parameters, 1, 1) - 1;
    break;
  case 'J': erase_in_display(parameters.empty() ? 0 : parameters[0]); break;
  case 'K': erase_in_line(parameters.empty() ? 0 : parameters[0]); break;
  case 'L': {
    // Insert lines at the cursor, pushing the rest down. `less` and `top` rely on this.
    const int count = std::min(parameter_or(parameters, 0, 1), rows_ - cursor_row_);
    for (int index = 0; index < count; ++index) {
      grid_.insert(grid_.begin() + cursor_row_,
                   std::vector<TerminalCell>(static_cast<std::size_t>(columns_), blank()));
      grid_.pop_back();
    }
    break;
  }
  case 'M': {
    const int count = std::min(parameter_or(parameters, 0, 1), rows_ - cursor_row_);
    for (int index = 0; index < count; ++index) {
      grid_.erase(grid_.begin() + cursor_row_);
      grid_.emplace_back(static_cast<std::size_t>(columns_), blank());
    }
    break;
  }
  case 'P': {
    // Delete characters, pulling the remainder of the line left.
    auto& row = grid_[static_cast<std::size_t>(cursor_row_)];
    const int count = std::min(parameter_or(parameters, 0, 1), columns_ - cursor_column_);
    row.erase(row.begin() + cursor_column_, row.begin() + cursor_column_ + count);
    row.resize(static_cast<std::size_t>(columns_), blank());
    break;
  }
  case 'X': {
    auto& row = grid_[static_cast<std::size_t>(cursor_row_)];
    const int count = std::min(parameter_or(parameters, 0, 1), columns_ - cursor_column_);
    for (int index = 0; index < count; ++index)
      row[static_cast<std::size_t>(cursor_column_ + index)] = blank();
    break;
  }
  case 'd': cursor_row_ = parameter_or(parameters, 0, 1) - 1; break;
  case 'm': apply_graphic_rendition(parameters); break;
  case 'h':
    if (private_marker && !parameters.empty() && parameters[0] == 25)
      cursor_visible_ = true;
    break;
  case 'l':
    if (private_marker && !parameters.empty() && parameters[0] == 25)
      cursor_visible_ = false;
    break;
  case 's': saved_column_ = cursor_column_; saved_row_ = cursor_row_; break;
  case 'u': cursor_column_ = saved_column_; cursor_row_ = saved_row_; break;
  default:
    // Unknown sequences are dropped rather than printed. Printing them is what fills a log listing
    // with stray bracket-question-mark noise.
    break;
  }
  clamp_cursor();
}

void TerminalScreen::write(std::string_view bytes) {
  if (bytes.empty())
    return;

  std::string pending = std::move(utf8_pending_);
  utf8_pending_.clear();
  pending.append(bytes);

  std::size_t index = 0;
  while (index < pending.size()) {
    const unsigned char byte = static_cast<unsigned char>(pending[index]);

    switch (state_) {
    case State::ground:
      if (byte == 0x1B) {
        state_ = State::escape;
        ++index;
        continue;
      }
      if (byte == '\r') { carriage_return(); ++index; continue; }
      if (byte == '\n') { line_feed(); ++index; continue; }
      if (byte == '\b') { backspace(); ++index; continue; }
      if (byte == '\t') { tab(); ++index; continue; }
      if (byte == 0x07) { ++index; continue; }   // bell: nothing to show
      if (byte < 0x20) { ++index; continue; }    // other control bytes are not printable

      // UTF-8. A sequence cut by a read boundary is carried to the next write rather than being
      // rendered as replacement characters.
      {
        int extra = 0;
        char32_t code = byte;
        if (byte >= 0xF0) { extra = 3; code = byte & 0x07U; }
        else if (byte >= 0xE0) { extra = 2; code = byte & 0x0FU; }
        else if (byte >= 0xC0) { extra = 1; code = byte & 0x1FU; }
        if (index + static_cast<std::size_t>(extra) >= pending.size() && extra > 0) {
          utf8_pending_.assign(pending, index, pending.size() - index);
          index = pending.size();
          continue;
        }
        for (int step = 1; step <= extra; ++step) {
          code = (code << 6) |
                 (static_cast<unsigned char>(pending[index + static_cast<std::size_t>(step)]) & 0x3FU);
        }
        put(code);
        index += static_cast<std::size_t>(extra) + 1U;
        continue;
      }

    case State::escape:
      if (byte == '[') { state_ = State::csi; parameter_text_.clear(); csi_private_ = false; ++index; continue; }
      if (byte == ']') { state_ = State::osc; osc_text_.clear(); ++index; continue; }
      if (byte == '(' || byte == ')') { state_ = State::charset; ++index; continue; }
      if (byte == '7') { saved_column_ = cursor_column_; saved_row_ = cursor_row_; state_ = State::ground; ++index; continue; }
      if (byte == '8') { cursor_column_ = saved_column_; cursor_row_ = saved_row_; state_ = State::ground; ++index; continue; }
      if (byte == 'M') { if (cursor_row_ > 0) --cursor_row_; state_ = State::ground; ++index; continue; }
      state_ = State::ground;
      ++index;
      continue;

    case State::charset:
      state_ = State::ground;
      ++index;
      continue;

    case State::csi:
      if (byte == '?' || byte == '>' || byte == '<') { csi_private_ = true; ++index; continue; }
      if ((byte >= '0' && byte <= '9') || byte == ';' || byte == ':') {
        parameter_text_.push_back(static_cast<char>(byte));
        ++index;
        continue;
      }
      if (byte >= 0x40 && byte <= 0x7E) {
        std::vector<int> parameters;
        std::string current;
        for (char character : parameter_text_) {
          if (character == ';' || character == ':') {
            parameters.push_back(current.empty() ? 0 : std::atoi(current.c_str()));
            current.clear();
          } else {
            current.push_back(character);
          }
        }
        if (!current.empty() || !parameter_text_.empty())
          parameters.push_back(current.empty() ? 0 : std::atoi(current.c_str()));
        execute_csi(static_cast<char>(byte), parameters, csi_private_);
        state_ = State::ground;
        ++index;
        continue;
      }
      ++index;
      continue;

    case State::osc:
      // Terminated by BEL or ST (ESC backslash). Used for the window title.
      if (byte == 0x07) {
        const std::size_t separator = osc_text_.find(';');
        if (separator != std::string::npos) {
          const std::string code = osc_text_.substr(0, separator);
          if (code == "0" || code == "2")
            title_ = osc_text_.substr(separator + 1);
        }
        state_ = State::ground;
        ++index;
        continue;
      }
      if (byte == 0x1B) {
        // Peek for the backslash; if the buffer ends here, carry it.
        if (index + 1 >= pending.size()) {
          utf8_pending_.assign(pending, index, pending.size() - index);
          index = pending.size();
          continue;
        }
        state_ = State::ground;
        index += 2;
        continue;
      }
      osc_text_.push_back(static_cast<char>(byte));
      ++index;
      continue;
    }
  }
  ++revision_;
}

} // namespace support_assist
