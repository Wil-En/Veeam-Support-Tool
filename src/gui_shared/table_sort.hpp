#pragma once

// Sorting a table by a column on both editions: in a numeric column a cell that starts with a number
// (after a word such as "RX" or "Used") sorts by its value with its unit applied (B to TiB, b/s to
// Gb/s, ms), any other cell by its text, ignoring case.

#include <cctype>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

namespace support_assist::gui {

inline std::optional<double> table_cell_number(std::string_view text) {
  std::size_t at = 0;
  while (at < text.size() && !std::isdigit(static_cast<unsigned char>(text[at])))
    ++at;
  if (at == text.size())
    return std::nullopt;
  std::string digits;
  while (at < text.size() &&
         (std::isdigit(static_cast<unsigned char>(text[at])) || text[at] == '.' || text[at] == ',')) {
    if (text[at] != ',')
      digits += text[at];
    ++at;
  }
  double value = std::strtod(digits.c_str(), nullptr);
  while (at < text.size() && text[at] == ' ')
    ++at;
  std::string unit;
  while (at < text.size() && std::isalpha(static_cast<unsigned char>(text[at])))
    unit += static_cast<char>(std::tolower(static_cast<unsigned char>(text[at++])));
  const double kib = 1024.0;
  if (unit == "kib" || unit == "kb" || unit == "k")
    value *= kib;
  else if (unit == "mib" || unit == "mb" || unit == "m")
    value *= kib * kib;
  else if (unit == "gib" || unit == "gb" || unit == "g")
    value *= kib * kib * kib;
  else if (unit == "tib" || unit == "tb" || unit == "t")
    value *= kib * kib * kib * kib;
  return value;
}

// `numeric` is false for a column of names, which sorts by its text even where a name holds a
// number ("Ethernet 3", "Samsung SSD 970"). The default reads numbers, as the two-argument form
// always did.
inline bool table_cell_less(std::string_view left, std::string_view right, bool numeric = true) {
  if (numeric) {
    const auto a = table_cell_number(left);
    const auto b = table_cell_number(right);
    if (a && b && *a != *b)
      return *a < *b;
    if (a.has_value() != b.has_value())
      return a.has_value();
  }
  const std::size_t length = left.size() < right.size() ? left.size() : right.size();
  for (std::size_t index = 0; index < length; ++index) {
    const int x = std::tolower(static_cast<unsigned char>(left[index]));
    const int y = std::tolower(static_cast<unsigned char>(right[index]));
    if (x != y)
      return x < y;
  }
  return left.size() < right.size();
}

} // namespace support_assist::gui
