#pragma once

// Shared pieces of the command line Show CLI prints for a Log Review, so both editions spell the
// same form the same way.

#include <cctype>
#include <string>
#include <string_view>

namespace support_assist::gui {

// The --date-order value for the review form's "Ambiguous date order" text: mdy, dmy, system or
// iso. Empty for Auto, which is the command line's default, and for text the review itself refuses.
inline std::string cli_date_order_token(std::string_view label) {
  std::string folded;
  for (const char character : label) {
    if (!std::isspace(static_cast<unsigned char>(character)))
      folded.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(character))));
  }
  if (folded == "mdy" || folded == "month/day/year")
    return "mdy";
  if (folded == "dmy" || folded == "day/month/year")
    return "dmy";
  if (folded == "locale" || folded == "system")
    return "system";
  if (folded == "iso" || folded == "iso-only")
    return "iso";
  return {};
}

// Whether the assumed UTC offset field changes anything: blank and 0 are the command line's
// default, so the option is left out for them.
inline bool cli_offset_is_set(std::string_view minutes) {
  std::string trimmed;
  for (const char character : minutes) {
    if (!std::isspace(static_cast<unsigned char>(character)))
      trimmed.push_back(character);
  }
  return !trimmed.empty() && trimmed != "0" && trimmed != "+0" && trimmed != "-0";
}

}  // namespace support_assist::gui
