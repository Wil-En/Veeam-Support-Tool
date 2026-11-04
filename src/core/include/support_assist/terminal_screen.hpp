#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace support_assist {

// A terminal screen: the grid a remote shell believes it is writing to.
//
// This is deliberately free of any GUI and of any transport. It takes bytes and maintains a grid of
// cells, so it can be unit tested against recorded output without a window or a network, which is
// the only practical way to get escape-sequence handling right.
//
// The scope is a support engineer reading logs over SSH - tail, ls, cat, grep, less, dmesg, the
// output of a Veeam service command. That needs cursor movement, erase, colour and scrolling. It
// does not need the whole of xterm, and pretending otherwise would be a much larger thing than was
// asked for.

struct TerminalCell {
  char32_t glyph = U' ';
  // Index into the 16-colour palette, or -1 for the screen default. Kept as an index rather than an
  // RGB value so the frontend owns the palette and the model stays presentation-neutral.
  std::int8_t foreground = -1;
  std::int8_t background = -1;
  bool bold = false;
  bool underline = false;
  bool inverse = false;
};

class TerminalScreen {
public:
  TerminalScreen(int columns, int rows);

  // Feed bytes straight from the channel. Any amount, split anywhere: a partial escape sequence at
  // the end of one read is held and completed by the next, which is the normal case on a network.
  void write(std::string_view bytes);

  void resize(int columns, int rows);

  int columns() const noexcept { return columns_; }
  int rows() const noexcept { return rows_; }
  int cursor_column() const noexcept { return cursor_column_; }
  int cursor_row() const noexcept { return cursor_row_; }
  bool cursor_visible() const noexcept { return cursor_visible_; }

  // Row 0 is the top of the visible screen.
  const TerminalCell& cell(int row, int column) const;

  // Lines that have scrolled off the top, oldest first. Bounded; a long-running tail must not grow
  // without limit.
  const std::vector<std::vector<TerminalCell>>& scrollback() const noexcept { return scrollback_; }

  // The title an application set with OSC 0/2, if any.
  const std::string& title() const noexcept { return title_; }

  // Incremented on every change, so a frontend can repaint only when something actually happened
  // rather than on a timer.
  std::uint64_t revision() const noexcept { return revision_; }

private:
  void put(char32_t glyph);
  void line_feed();
  void carriage_return();
  void backspace();
  void tab();
  void scroll_up();
  void erase_in_display(int mode);
  void erase_in_line(int mode);
  void apply_graphic_rendition(const std::vector<int>& parameters);
  void execute_csi(char final_byte, const std::vector<int>& parameters, bool private_marker);
  void clamp_cursor();
  TerminalCell blank() const;

  int columns_;
  int rows_;
  int cursor_column_ = 0;
  int cursor_row_ = 0;
  int saved_column_ = 0;
  int saved_row_ = 0;
  bool cursor_visible_ = true;
  std::uint64_t revision_ = 0;

  TerminalCell pen_{};
  std::vector<std::vector<TerminalCell>> grid_;
  std::vector<std::vector<TerminalCell>> scrollback_;
  std::string title_;

  // Parser state. Held across write() calls because a sequence can straddle a read boundary.
  enum class State { ground, escape, csi, osc, charset };
  State state_ = State::ground;
  std::string parameter_text_;
  std::string osc_text_;
  bool csi_private_ = false;

  // Partial UTF-8 sequence carried between writes, for the same reason.
  std::string utf8_pending_;
};

} // namespace support_assist
