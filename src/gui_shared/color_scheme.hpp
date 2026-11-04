#pragma once

// The colour schemes both editions offer, chosen in Settings > General.
//
// Every screen is drawn in the Veeam Green palette. The other schemes are derived from it one
// colour at a time, so a new screen needs no second palette:
//
//   Veeam Green  the palette as drawn: green on near-black.
//   Dark         neutral greys for the green-tinted surfaces, borders and text. The colours that
//                carry meaning keep their hue: the green accent, the severity reds and ambers, and
//                the informational cyan.
//   Light        white and light-grey surfaces with dark text. Bright text colours are held dark
//                enough to read on white.
//
// The main surfaces, text colours, accents and severity colours have a designed Dark and Light
// value in the table below; any other colour goes through the same rule the table follows.

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <string>
#include <string_view>

namespace support_assist::gui {

enum class ColorScheme { veeam_green, dark, light };

// What the engineer chose. match_system resolves to Dark or Light from the operating system.
enum class ColorSchemeChoice { veeam_green, dark, light, match_system };

struct SchemeRgb {
  std::uint8_t red = 0;
  std::uint8_t green = 0;
  std::uint8_t blue = 0;
  constexpr bool operator==(const SchemeRgb&) const = default;
};

inline ColorScheme resolve_color_scheme(ColorSchemeChoice choice, bool system_prefers_dark) {
  switch (choice) {
  case ColorSchemeChoice::dark:
    return ColorScheme::dark;
  case ColorSchemeChoice::light:
    return ColorScheme::light;
  case ColorSchemeChoice::match_system:
    return system_prefers_dark ? ColorScheme::dark : ColorScheme::light;
  case ColorSchemeChoice::veeam_green:
    break;
  }
  return ColorScheme::veeam_green;
}

// The value written to ui-settings.ini ([Appearance] ColorScheme).
inline std::string_view color_scheme_choice_token(ColorSchemeChoice choice) {
  switch (choice) {
  case ColorSchemeChoice::dark:
    return "dark";
  case ColorSchemeChoice::light:
    return "light";
  case ColorSchemeChoice::match_system:
    return "system";
  case ColorSchemeChoice::veeam_green:
    break;
  }
  return "veeam-green";
}

inline ColorSchemeChoice parse_color_scheme_choice(std::string_view token) {
  if (token == "dark")
    return ColorSchemeChoice::dark;
  if (token == "light")
    return ColorSchemeChoice::light;
  if (token == "system")
    return ColorSchemeChoice::match_system;
  return ColorSchemeChoice::veeam_green;
}

// The choices in the order Settings lists them.
inline constexpr std::array<ColorSchemeChoice, 4> kColorSchemeChoices{
    ColorSchemeChoice::veeam_green, ColorSchemeChoice::dark, ColorSchemeChoice::light,
    ColorSchemeChoice::match_system};

inline std::string_view color_scheme_choice_label(ColorSchemeChoice choice, bool windows) {
  switch (choice) {
  case ColorSchemeChoice::dark:
    return "Dark";
  case ColorSchemeChoice::light:
    return "Light";
  case ColorSchemeChoice::match_system:
    return windows ? "Match Windows" : "Match system";
  case ColorSchemeChoice::veeam_green:
    break;
  }
  return "Veeam Green";
}

inline bool color_scheme_is_light(ColorScheme scheme) { return scheme == ColorScheme::light; }

namespace color_scheme_detail {

struct Hsl {
  double hue = 0.0;         // degrees
  double saturation = 0.0;  // 0..1
  double lightness = 0.0;   // 0..1
};

inline Hsl to_hsl(SchemeRgb color) {
  const double red = color.red / 255.0;
  const double green = color.green / 255.0;
  const double blue = color.blue / 255.0;
  const double high = std::max({red, green, blue});
  const double low = std::min({red, green, blue});
  Hsl result;
  result.lightness = (high + low) / 2.0;
  const double range = high - low;
  if (range <= 0.0)
    return result;
  result.saturation = result.lightness > 0.5 ? range / (2.0 - high - low) : range / (high + low);
  if (high == red)
    result.hue = 60.0 * std::fmod((green - blue) / range + 6.0, 6.0);
  else if (high == green)
    result.hue = 60.0 * ((blue - red) / range + 2.0);
  else
    result.hue = 60.0 * ((red - green) / range + 4.0);
  return result;
}

inline SchemeRgb from_hsl(Hsl value) {
  const double chroma = (1.0 - std::fabs(2.0 * value.lightness - 1.0)) * value.saturation;
  const double sector = std::fmod(value.hue / 60.0, 6.0);
  const double second = chroma * (1.0 - std::fabs(std::fmod(sector, 2.0) - 1.0));
  double red = 0.0;
  double green = 0.0;
  double blue = 0.0;
  if (sector < 1.0) {
    red = chroma;
    green = second;
  } else if (sector < 2.0) {
    red = second;
    green = chroma;
  } else if (sector < 3.0) {
    green = chroma;
    blue = second;
  } else if (sector < 4.0) {
    green = second;
    blue = chroma;
  } else if (sector < 5.0) {
    red = second;
    blue = chroma;
  } else {
    red = chroma;
    blue = second;
  }
  const double offset = value.lightness - chroma / 2.0;
  const auto channel = [offset](double part) {
    return static_cast<std::uint8_t>(std::clamp(std::lround((part + offset) * 255.0), 0L, 255L));
  };
  return {channel(red), channel(green), channel(blue)};
}

struct Designed {
  SchemeRgb veeam_green;
  SchemeRgb dark;
  SchemeRgb light;
};

// Designed values for the colours every page is built from. Surfaces lighten as they rise (page,
// panel, then cards, inputs and lists) in both Dark and Light, which a plain lightness flip cannot
// give.
inline constexpr Designed kDesigned[] = {
    // Surfaces
    {{7, 24, 26}, {24, 24, 27}, {241, 243, 245}},      // page background
    {{10, 38, 39}, {31, 31, 35}, {233, 236, 239}},     // sidebar, menus, status bar
    {{13, 31, 33}, {30, 30, 34}, {255, 255, 255}},     // lists, tables and documents
    {{12, 26, 27}, {26, 26, 29}, {250, 251, 252}},     // console output
    {{5, 12, 13}, {20, 20, 23}, {250, 251, 252}},      // local shell output
    {{18, 48, 49}, {37, 37, 42}, {255, 255, 255}},     // cards
    {{22, 42, 44}, {40, 40, 45}, {255, 255, 255}},     // inputs
    {{17, 33, 34}, {33, 33, 37}, {246, 247, 249}},     // disabled inputs
    {{25, 74, 60}, {44, 60, 50}, {219, 240, 224}},     // selected row
    {{20, 49, 47}, {46, 46, 52}, {246, 247, 248}},     // buttons
    {{31, 74, 62}, {58, 58, 65}, {227, 236, 230}},     // button hover
    {{14, 48, 48}, {40, 40, 45}, {225, 229, 233}},     // navigation hover
    // Borders and rules
    {{43, 86, 78}, {70, 70, 78}, {205, 210, 215}},     // card border, rules
    {{74, 105, 99}, {92, 92, 100}, {188, 194, 200}},   // control border
    {{48, 66, 64}, {60, 60, 66}, {214, 218, 222}},     // disabled border
    {{58, 104, 94}, {84, 84, 92}, {196, 201, 206}},    // divider dots
    // Text
    {{225, 236, 231}, {231, 231, 234}, {27, 30, 34}},  // body text
    {{224, 236, 230}, {230, 230, 233}, {28, 31, 35}},  // body text
    {{236, 244, 240}, {238, 238, 241}, {22, 25, 29}},  // input text
    {{244, 249, 246}, {242, 242, 245}, {18, 21, 25}},  // card titles
    {{248, 252, 250}, {245, 245, 248}, {15, 18, 22}},  // brand title
    {{223, 235, 229}, {226, 226, 230}, {32, 35, 39}},  // navigation text
    {{165, 188, 178}, {168, 168, 176}, {92, 98, 106}}, // subtitles
    {{176, 196, 188}, {176, 176, 184}, {86, 92, 100}}, // card descriptions
    {{183, 204, 196}, {182, 182, 190}, {82, 88, 96}},  // card captions
    {{126, 164, 153}, {138, 138, 148}, {104, 110, 118}}, // navigation sections
    {{132, 151, 144}, {130, 130, 138}, {130, 135, 142}}, // disabled text
    {{126, 154, 147}, {130, 130, 138}, {130, 135, 142}}, // disabled menu text
    {{6, 28, 25}, {20, 20, 23}, {255, 255, 255}},      // text on the accent badge
    // Accent
    {{85, 190, 88}, {85, 190, 88}, {32, 140, 58}},     // accent
    {{114, 224, 106}, {114, 224, 106}, {26, 122, 48}}, // headings
    {{128, 228, 122}, {128, 228, 122}, {22, 110, 42}}, // selected navigation text
    {{116, 218, 112}, {116, 218, 112}, {30, 128, 52}}, // chevrons
    {{101, 215, 98}, {101, 215, 98}, {38, 150, 62}},   // focus border
    {{101, 205, 175}, {101, 205, 175}, {18, 128, 100}}, // remote accent
    // Severity text
    {{255, 199, 91}, {255, 199, 91}, {156, 98, 0}},    // warning
    {{255, 190, 91}, {255, 190, 91}, {150, 94, 0}},    // warning value
    {{255, 177, 77}, {255, 177, 77}, {160, 90, 0}},    // warning emphasis
    {{255, 112, 112}, {255, 112, 112}, {186, 30, 36}}, // error
    {{255, 133, 133}, {255, 133, 133}, {176, 32, 38}}, // critical value
    {{140, 208, 211}, {140, 208, 211}, {0, 108, 122}}, // informational
    {{146, 219, 224}, {146, 219, 224}, {0, 104, 118}}, // informational value
    {{151, 231, 169}, {151, 231, 169}, {28, 118, 56}}, // healthy value
    {{196, 202, 203}, {196, 202, 203}, {82, 88, 94}},  // unknown value
    // Severity fills and borders
    {{61, 29, 31}, {66, 34, 36}, {253, 232, 232}},     // critical fill
    {{196, 76, 82}, {196, 76, 82}, {200, 64, 70}},     // critical border
    {{59, 45, 27}, {64, 52, 32}, {255, 243, 220}},     // warning fill
    {{74, 52, 16}, {78, 58, 22}, {255, 236, 204}},     // warning badge fill
    {{191, 137, 52}, {191, 137, 52}, {186, 126, 36}},  // warning border
    {{18, 48, 43}, {32, 48, 38}, {230, 245, 235}},     // healthy fill
    {{57, 135, 88}, {57, 135, 88}, {44, 140, 84}},     // healthy border
    {{22, 49, 54}, {28, 44, 50}, {228, 242, 246}},     // informational fill
    {{59, 125, 134}, {59, 125, 134}, {44, 122, 136}},  // informational border
    {{38, 44, 45}, {44, 44, 49}, {238, 239, 241}},     // unknown fill
};

}  // namespace color_scheme_detail

// A colour of the Veeam Green palette, in `scheme`.
inline SchemeRgb scheme_color(SchemeRgb color, ColorScheme scheme) {
  using namespace color_scheme_detail;
  if (scheme == ColorScheme::veeam_green)
    return color;
  for (const auto& entry : kDesigned) {
    if (entry.veeam_green == color)
      return scheme == ColorScheme::dark ? entry.dark : entry.light;
  }

  Hsl value = to_hsl(color);
  // The green-tinted greys (surfaces, borders and text) become neutral; a colour that carries
  // meaning (the accent, severity, informational cyan) keeps its hue.
  const bool green_family = value.hue >= 140.0 && value.hue <= 210.0;
  const bool tinted_grey =
      value.saturation < 0.25 || value.lightness < 0.36 || value.lightness > 0.80;
  if ((green_family && tinted_grey) || value.saturation < 0.12) {
    value.hue = 220.0;
    value.saturation = std::min(value.saturation, 0.06);
  }
  if (scheme == ColorScheme::light) {
    // Dark grounds become light grounds, and light text becomes dark text. A colour that was bright
    // on the dark ground is text or an accent, so it is held dark enough to read on white.
    const double inverted = 1.0 - value.lightness;
    value.lightness = value.lightness >= 0.45 ? std::min(inverted, 0.40) : inverted;
  }
  return from_hsl(value);
}

// "#RRGGBB" for style sheets.
inline std::string scheme_hex(std::string_view veeam_green_hex, ColorScheme scheme) {
  const auto nibble = [](char digit) -> int {
    if (digit >= '0' && digit <= '9')
      return digit - '0';
    if (digit >= 'a' && digit <= 'f')
      return digit - 'a' + 10;
    if (digit >= 'A' && digit <= 'F')
      return digit - 'A' + 10;
    return 0;
  };
  if (veeam_green_hex.size() != 7 || veeam_green_hex.front() != '#')
    return std::string(veeam_green_hex);
  const auto byte = [&](std::size_t at) {
    return static_cast<std::uint8_t>(nibble(veeam_green_hex[at]) * 16 +
                                     nibble(veeam_green_hex[at + 1]));
  };
  const SchemeRgb mapped = scheme_color({byte(1), byte(3), byte(5)}, scheme);
  static constexpr char kDigits[] = "0123456789ABCDEF";
  std::string text = "#";
  for (const std::uint8_t part : {mapped.red, mapped.green, mapped.blue}) {
    text.push_back(kDigits[part >> 4]);
    text.push_back(kDigits[part & 0x0F]);
  }
  return text;
}

}  // namespace support_assist::gui
