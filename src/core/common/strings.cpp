#include "support_assist/strings.hpp"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <sstream>
#ifdef _WIN32
#include <windows.h>
#endif
namespace support_assist {
std::string trim(std::string_view text) {
  std::size_t first = 0;
  while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first])) != 0)
    ++first;
  std::size_t last = text.size();
  while (last > first && std::isspace(static_cast<unsigned char>(text[last - 1])) != 0)
    --last;
  return std::string(text.substr(first, last - first));
}
std::string ascii_lower(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}
std::string ascii_upper(std::string_view text) {
  std::string out(text);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::toupper(c));
  });
  return out;
}
std::vector<std::string> split(std::string_view text, char delimiter) {
  std::vector<std::string> result;
  std::size_t start = 0;
  while (start <= text.size()) {
    const auto end = text.find(delimiter, start);
    result.emplace_back(
        text.substr(start, end == std::string_view::npos ? text.size() - start : end - start));
    if (end == std::string_view::npos)
      break;
    start = end + 1;
  }
  return result;
}
std::string hex_encode(const void* data, std::size_t size, std::size_t max_bytes) {
  const auto* bytes = static_cast<const unsigned char*>(data);
  const auto count = std::min(size, max_bytes);
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (std::size_t i = 0; i < count; ++i)
    out << std::setw(2) << static_cast<unsigned int>(bytes[i]);
  if (count < size)
    out << "...";
  return out.str();
}
std::string json_escape(std::string_view text) {
  std::ostringstream out;
  for (char raw : text) {
    const auto c = static_cast<unsigned char>(raw);
    switch (c) {
    case '"':
      out << "\\\"";
      break;
    case '\\':
      out << "\\\\";
      break;
    case '\b':
      out << "\\b";
      break;
    case '\f':
      out << "\\f";
      break;
    case '\n':
      out << "\\n";
      break;
    case '\r':
      out << "\\r";
      break;
    case '\t':
      out << "\\t";
      break;
    default:
      if (c < 0x20)
        out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
            << static_cast<unsigned int>(c) << std::dec;
      else
        out << static_cast<char>(c);
    }
  }
  return out.str();
}
std::string html_escape(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (char c : text) {
    switch (c) {
    case '&':
      out += "&amp;";
      break;
    case '<':
      out += "&lt;";
      break;
    case '>':
      out += "&gt;";
      break;
    case '"':
      out += "&quot;";
      break;
    case '\'':
      out += "&#39;";
      break;
    default:
      out.push_back(c);
      break;
    }
  }
  return out;
}
std::string csv_escape(std::string_view text, bool neutralize_formula) {
  std::string value(text);
  if (neutralize_formula && !value.empty()) {
    const char c = value.front();
    if (c == '=' || c == '+' || c == '-' || c == '@' || c == '\t' || c == '\r')
      value.insert(value.begin(), '\'');
  }
  bool quote = value.find_first_of(",\"\r\n") != std::string::npos;
  if (!quote)
    return value;
  std::string out = "\"";
  for (char c : value) {
    if (c == '"')
      out += "\"\"";
    else
      out.push_back(c);
  }
  out += '"';
  return out;
}
#ifdef _WIN32
std::string utf8_from_wide(std::wstring_view text) {
  if (text.empty())
    return {};
  const int size = WideCharToMultiByte(CP_UTF8,
                                       WC_ERR_INVALID_CHARS,
                                       text.data(),
                                       static_cast<int>(text.size()),
                                       nullptr,
                                       0,
                                       nullptr,
                                       nullptr);
  if (size <= 0)
    return {};
  std::string out(static_cast<std::size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8,
                          WC_ERR_INVALID_CHARS,
                          text.data(),
                          static_cast<int>(text.size()),
                          out.data(),
                          size,
                          nullptr,
                          nullptr) == 0)
    return {};
  return out;
}
std::wstring wide_from_utf8(std::string_view text) {
  if (text.empty())
    return {};
  const int size = MultiByteToWideChar(
      CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
  if (size <= 0)
    return {};
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  if (MultiByteToWideChar(CP_UTF8,
                          MB_ERR_INVALID_CHARS,
                          text.data(),
                          static_cast<int>(text.size()),
                          out.data(),
                          size) == 0)
    return {};
  return out;
}

std::wstring wide_from_utf8_lossy(std::string_view text) {
  if (text.empty())
    return {};
  // No MB_ERR_INVALID_CHARS: undecodable bytes become U+FFFD instead of discarding the document.
  const int size = MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                                       nullptr, 0);
  if (size <= 0)
    return {};
  std::wstring out(static_cast<std::size_t>(size), L'\0');
  if (MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), out.data(),
                          size) <= 0)
    return {};
  return out;
}
#endif

std::string path_to_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
  // Never call path::string() here: MSVC routes it through the ANSI code page and throws
  // std::system_error for any character it cannot map. Convert from the native wide form instead,
  // which is lossless for every valid path.
  return utf8_from_wide(path.wstring());
#else
  // POSIX paths are already bytes; on Linux and macOS this is exactly path::string().
  return path.string();
#endif
}

std::string generic_path_to_utf8(const std::filesystem::path& path) {
#ifdef _WIN32
  return utf8_from_wide(path.generic_wstring());
#else
  return path.generic_string();
#endif
}

std::filesystem::path path_from_utf8(std::string_view text) {
#ifdef _WIN32
  const std::wstring wide = wide_from_utf8(text);
  if (!wide.empty() || text.empty())
    return std::filesystem::path(wide);
#endif
  return std::filesystem::path(std::string(text));
}
} // namespace support_assist

namespace support_assist {

std::vector<std::string> align_tab_columns(const std::vector<std::string>& lines,
                                           std::size_t maximum_column_width,
                                           std::size_t column_gap) {
  std::vector<std::vector<std::string>> rows;
  rows.reserve(lines.size());
  std::vector<std::size_t> widths;
  bool any_tabs = false;

  for (const auto& line : lines) {
    std::vector<std::string> fields;
    std::size_t start = 0;
    for (;;) {
      const std::size_t tab = line.find('\t', start);
      fields.push_back(line.substr(start, tab == std::string::npos ? std::string::npos : tab - start));
      if (tab == std::string::npos)
        break;
      start = tab + 1U;
      any_tabs = true;
    }
    // Only fields that precede another field participate in width measurement; the trailing field
    // is never padded and must not widen the table.
    for (std::size_t column = 0; column + 1U < fields.size(); ++column) {
      if (widths.size() <= column)
        widths.push_back(0);
      widths[column] = std::max(widths[column], std::min(fields[column].size(), maximum_column_width));
    }
    rows.push_back(std::move(fields));
  }

  if (!any_tabs)
    return lines;

  std::vector<std::string> rendered;
  rendered.reserve(rows.size());
  for (const auto& fields : rows) {
    std::string row;
    for (std::size_t column = 0; column < fields.size(); ++column) {
      row += fields[column];
      if (column + 1U < fields.size()) {
        const std::size_t width = column < widths.size() ? widths[column] : fields[column].size();
        if (fields[column].size() < width)
          row.append(width - fields[column].size(), ' ');
        row.append(column_gap, ' ');
      }
    }
    rendered.push_back(std::move(row));
  }
  return rendered;
}

} // namespace support_assist

namespace support_assist {
namespace {

// A PowerShell Format-Table rule line: runs of '-' separated by single spaces, nothing else.
bool is_rule_line(std::string_view line) {
  bool saw_dash = false;
  for (const char character : line) {
    if (character == '-') {
      saw_dash = true;
    } else if (character != ' ' && character != '\t' && character != '\r') {
      return false;
    }
  }
  return saw_dash;
}

// Column spans taken from the rule line. Each run of dashes is one column; the final column runs to
// end-of-line so a wide trailing value is never clipped.
std::vector<std::pair<std::size_t, std::size_t>> rule_columns(std::string_view rule) {
  std::vector<std::pair<std::size_t, std::size_t>> spans;
  std::size_t index = 0;
  while (index < rule.size()) {
    while (index < rule.size() && rule[index] != '-')
      ++index;
    if (index >= rule.size())
      break;
    const std::size_t start = index;
    while (index < rule.size() && rule[index] == '-')
      ++index;
    spans.emplace_back(start, index - start);
  }
  return spans;
}

std::string slice(std::string_view line, std::size_t start, std::size_t length, bool last) {
  if (start >= line.size())
    return {};
  const std::size_t available = line.size() - start;
  return std::string(trim(line.substr(start, last ? available : std::min(length, available))));
}

} // namespace

ParsedTable parse_collected_table(const std::vector<std::string>& lines) {
  ParsedTable table;

  // --- Format-Table: header, rule, rows -------------------------------------------------
  for (std::size_t index = 0; index + 1U < lines.size(); ++index) {
    if (trim(lines[index]).empty() || !is_rule_line(lines[index + 1U]))
      continue;
    const auto spans = rule_columns(lines[index + 1U]);
    if (spans.size() < 2U)
      break;
    // A column runs from where its rule segment starts to where the NEXT one starts - not for the
    // length of the dashes. PowerShell sizes the rule to the HEADER, so a value wider than its
    // header (an interface alias, a long path) overflows the dashes while still sitting inside its
    // column. Slicing by dash length would cut those values in half.
    const auto column_extent = [&](std::size_t column) {
      const std::size_t start = spans[column].first;
      const std::size_t next = column + 1U < spans.size() ? spans[column + 1U].first
                                                          : std::string::npos;
      return std::pair<std::size_t, std::size_t>{
          start, next == std::string::npos ? std::string::npos : next - start};
    };

    for (std::size_t column = 0; column < spans.size(); ++column) {
      const auto [start, length] = column_extent(column);
      std::string name = slice(lines[index], start, length, column + 1U == spans.size());
      table.headers.push_back(name.empty() ? "Column " + std::to_string(column + 1U) : name);
    }
    for (std::size_t row = index + 2U; row < lines.size(); ++row) {
      if (trim(lines[row]).empty()) {
        table.group_breaks.push_back(table.rows.size());
        continue;
      }
      std::vector<std::string> values;
      values.reserve(spans.size());
      for (std::size_t column = 0; column < spans.size(); ++column) {
        const auto [start, length] = column_extent(column);
        values.push_back(slice(lines[row], start, length, column + 1U == spans.size()));
      }
      table.rows.push_back(std::move(values));
    }
    table.tabular = !table.rows.empty();
    if (table.tabular)
      return table;
    table = ParsedTable{};
    break;
  }

  // --- Tab-separated records ------------------------------------------------------------
  const bool any_tabs = std::any_of(lines.begin(), lines.end(), [](const std::string& line) {
    return line.find('\t') != std::string::npos;
  });
  if (any_tabs) {
    std::size_t widest = 0;
    for (const auto& line : lines) {
      if (trim(line).empty()) {
        table.group_breaks.push_back(table.rows.size());
        continue;
      }
      std::vector<std::string> values;
      std::size_t start = 0;
      for (;;) {
        const std::size_t tab = line.find('\t', start);
        values.push_back(std::string(trim(
            line.substr(start, tab == std::string::npos ? std::string::npos : tab - start))));
        if (tab == std::string::npos)
          break;
        start = tab + 1U;
      }
      widest = std::max(widest, values.size());
      table.rows.push_back(std::move(values));
    }
    for (std::size_t column = 0; column < widest; ++column)
      table.headers.push_back("Field " + std::to_string(column + 1U));
    table.tabular = !table.rows.empty();
    return table;
  }

  // --- Format-List: "Name : Value" blocks ------------------------------------------------
  std::size_t pair_lines = 0;
  std::size_t content_lines = 0;
  for (const auto& line : lines) {
    if (trim(line).empty())
      continue;
    ++content_lines;
    const std::size_t separator = line.find(" : ");
    if (separator != std::string::npos && !trim(line.substr(0, separator)).empty())
      ++pair_lines;
  }
  // Two thirds is deliberately loose: a Format-List block can carry continuation lines for a long
  // value, and those legitimately have no separator.
  if (content_lines != 0U && pair_lines * 3U >= content_lines * 2U) {
    table.headers = {"Property", "Value"};
    for (const auto& line : lines) {
      if (trim(line).empty()) {
        table.group_breaks.push_back(table.rows.size());
        continue;
      }
      const std::size_t separator = line.find(" : ");
      if (separator == std::string::npos) {
        // Continuation of the previous value rather than a new property.
        if (!table.rows.empty())
          table.rows.back()[1] += " " + std::string(trim(line));
        else
          table.rows.push_back({std::string(trim(line)), ""});
        continue;
      }
      table.rows.push_back({std::string(trim(line.substr(0, separator))),
                            std::string(trim(line.substr(separator + 3U)))});
    }
    table.tabular = !table.rows.empty();
    return table;
  }

  return table;
}

namespace {
// Appends one Unicode code point as UTF-8.
void append_code_point(std::string& out, std::uint32_t code_point) {
  if (code_point < 0x80U) {
    out.push_back(static_cast<char>(code_point));
  } else if (code_point < 0x800U) {
    out.push_back(static_cast<char>(0xC0U | (code_point >> 6)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else if (code_point < 0x10000U) {
    out.push_back(static_cast<char>(0xE0U | (code_point >> 12)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  } else {
    out.push_back(static_cast<char>(0xF0U | (code_point >> 18)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 12) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | ((code_point >> 6) & 0x3FU)));
    out.push_back(static_cast<char>(0x80U | (code_point & 0x3FU)));
  }
}

// Reads "_xHHHH_" at `position`. Returns false when the text there is not such an escape.
bool read_hex_escape(std::string_view text, std::size_t position, std::uint32_t& value) {
  if (position + 7U > text.size()) return false;
  if (text[position] != '_' || (text[position + 1U] != 'x' && text[position + 1U] != 'X')) return false;
  if (text[position + 6U] != '_') return false;
  std::uint32_t parsed = 0U;
  for (std::size_t index = position + 2U; index < position + 6U; ++index) {
    const char digit = text[index];
    parsed <<= 4;
    if (digit >= '0' && digit <= '9') parsed |= static_cast<std::uint32_t>(digit - '0');
    else if (digit >= 'a' && digit <= 'f') parsed |= static_cast<std::uint32_t>(digit - 'a' + 10);
    else if (digit >= 'A' && digit <= 'F') parsed |= static_cast<std::uint32_t>(digit - 'A' + 10);
    else return false;
  }
  value = parsed;
  return true;
}

// Decodes the XML entities PowerShell emits plus PowerShell's own _xHHHH_ escapes.
std::string decode_clixml_text(std::string_view text) {
  std::string out;
  out.reserve(text.size());
  for (std::size_t index = 0; index < text.size();) {
    std::uint32_t unit = 0U;
    if (read_hex_escape(text, index, unit)) {
      index += 7U;
      // A non-BMP character is serialized as a surrogate pair of escapes; recombine it, or the
      // output carries two replacement characters where one emoji or CJK extension belongs.
      if (unit >= 0xD800U && unit <= 0xDBFFU) {
        std::uint32_t low = 0U;
        if (read_hex_escape(text, index, low) && low >= 0xDC00U && low <= 0xDFFFU) {
          index += 7U;
          unit = 0x10000U + ((unit - 0xD800U) << 10) + (low - 0xDC00U);
        } else {
          unit = 0xFFFDU;
        }
      } else if (unit >= 0xDC00U && unit <= 0xDFFFU) {
        unit = 0xFFFDU;
      }
      append_code_point(out, unit);
      continue;
    }
    if (text[index] == '&') {
      const std::size_t semicolon = text.find(';', index);
      if (semicolon != std::string_view::npos && semicolon - index <= 10U) {
        const std::string_view entity = text.substr(index + 1U, semicolon - index - 1U);
        bool handled = true;
        if (entity == "lt") out.push_back('<');
        else if (entity == "gt") out.push_back('>');
        else if (entity == "amp") out.push_back('&');
        else if (entity == "quot") out.push_back('"');
        else if (entity == "apos") out.push_back('\'');
        else if (entity.size() > 1U && entity.front() == '#') {
          const bool hex = entity[1] == 'x' || entity[1] == 'X';
          const std::string_view digits = entity.substr(hex ? 2U : 1U);
          std::uint32_t parsed = 0U;
          handled = !digits.empty();
          for (const char digit : digits) {
            if (hex && std::isxdigit(static_cast<unsigned char>(digit)) != 0) {
              parsed = parsed * 16U + static_cast<std::uint32_t>(
                  digit <= '9' ? digit - '0' : (std::tolower(static_cast<unsigned char>(digit)) - 'a' + 10));
            } else if (!hex && digit >= '0' && digit <= '9') {
              parsed = parsed * 10U + static_cast<std::uint32_t>(digit - '0');
            } else {
              handled = false;
              break;
            }
          }
          if (handled) append_code_point(out, parsed);
        } else {
          handled = false;
        }
        if (handled) {
          index = semicolon + 1U;
          continue;
        }
      }
    }
    out.push_back(text[index]);
    ++index;
  }
  return out;
}
} // namespace

std::string decode_powershell_clixml(std::string_view text) {
  if (text.find("<Objs") == std::string_view::npos) return std::string(text);

  std::string out;
  out.reserve(text.size() / 2U);
  std::size_t index = 0;
  bool decoded_any = false;
  while (index < text.size()) {
    const std::size_t open = text.find("<S", index);
    if (open == std::string_view::npos) break;
    // "<S" must begin an element, not merely prefix a longer tag name such as <Str>.
    const std::size_t after = open + 2U;
    if (after >= text.size() || (text[after] != '>' && text[after] != ' ')) {
      index = open + 2U;
      continue;
    }
    const std::size_t tag_end = text.find('>', open);
    if (tag_end == std::string_view::npos) break;
    const std::size_t close = text.find("</S>", tag_end);
    if (close == std::string_view::npos) break;

    // Progress records are UI bookkeeping, never a message an engineer needs.
    const std::string_view attributes = text.substr(open, tag_end - open);
    if (attributes.find("\"progress\"") == std::string_view::npos &&
        attributes.find("\"Progress\"") == std::string_view::npos) {
      out += decode_clixml_text(text.substr(tag_end + 1U, close - tag_end - 1U));
      decoded_any = true;
    }
    index = close + 4U;
  }
  if (!decoded_any) return std::string(text);

  // PowerShell terminates every record with CRLF; leave the interior alone and trim the tail so the
  // message does not arrive with blank lines hanging off it.
  while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == ' '))
    out.pop_back();
  return out;
}

} // namespace support_assist
