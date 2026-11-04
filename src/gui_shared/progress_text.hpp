#pragma once

// The line a progress report shows on the status bar, the same on both editions. A tool download
// and a remote transfer read as bytes against the file's size, an extract as a file count; every
// other report as its phase, what it is on, how far it is (with the percent and the time left
// when the total is known), its rate and how long it has run.

#include "support_assist/progress.hpp"
#include "support_assist/system_health.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace support_assist::gui {

// 1,234,567
inline std::string progress_count(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (int index = static_cast<int>(digits.size()) - 3; index > 0; index -= 3)
    digits.insert(static_cast<std::size_t>(index), ",");
  return digits;
}

// 45 s, 3 min 05 s, 1 h 02 min
inline std::string progress_duration(double seconds) {
  const auto whole = static_cast<std::uint64_t>(seconds < 0.0 ? 0.0 : seconds + 0.5);
  char text[32] = {};
  if (whole < 60U)
    std::snprintf(text, sizeof(text), "%llu s", static_cast<unsigned long long>(whole));
  else if (whole < 3600U)
    std::snprintf(text, sizeof(text), "%llu min %02llu s", static_cast<unsigned long long>(whole / 60U),
                  static_cast<unsigned long long>(whole % 60U));
  else
    std::snprintf(text, sizeof(text), "%llu h %02llu min", static_cast<unsigned long long>(whole / 3600U),
                  static_cast<unsigned long long>((whole % 3600U) / 60U));
  return text;
}

// The part done of a known total, whole percent, never above 100 while the work runs.
inline int progress_percent_of(std::uint64_t processed, std::uint64_t total) {
  if (total == 0U)
    return -1;
  if (processed >= total)
    return 100;
  return static_cast<int>(processed * 100U / total);
}

// "1,234 of 5,000 (24%)"
inline std::string progress_share(std::uint64_t processed, std::uint64_t total) {
  return progress_count(processed) + " of " + progress_count(total) + " (" +
         std::to_string(progress_percent_of(processed, total)) + "%)";
}

// "about 2 min 10 s left", from the pace so far; empty until a tenth is done or when the total is
// not known.
inline std::string progress_time_left(std::uint64_t processed, std::uint64_t total, double elapsed_seconds) {
  if (total == 0U || processed == 0U || processed >= total || processed * 10U < total || elapsed_seconds <= 0.0)
    return {};
  const double left = elapsed_seconds * static_cast<double>(total - processed) / static_cast<double>(processed);
  return "about " + progress_duration(left) + " left";
}

// The percent a progress line shows as "(37%)", or -1 when it shows none. Both editions read it to
// fill the running bar, which runs as a busy bar otherwise.
inline int progress_percent(std::string_view text) {
  std::size_t at = text.rfind("%)");
  while (at != std::string_view::npos && at > 0) {
    std::size_t start = at;
    while (start > 0 && text[start - 1] >= '0' && text[start - 1] <= '9')
      --start;
    if (start < at && at - start <= 3 && start > 0 && text[start - 1] == '(') {
      const int value = std::stoi(std::string(text.substr(start, at - start)));
      return value > 100 ? 100 : value;
    }
    at = text.rfind("%)", at - 1);
  }
  return -1;
}

inline std::string progress_event_text(const ProgressEvent& event) {
  if (event.phase == "optional-tool-download") {
    std::string text =
        "Downloading " + event.current_scope + ": " + format_health_bytes(event.processed);
    if (event.total != 0U)
      text += " of " + format_health_bytes(event.total) + " (" +
              std::to_string(progress_percent_of(event.processed, event.total)) + "%)";
    if (event.items_per_second > 0.0)
      text += " at " + format_health_rate(event.items_per_second);
    return text;
  }
  if (event.phase == "optional-tool-extract")
    return "Extracting " + std::to_string(event.processed) + " file(s): " + event.current_scope;
  if (event.phase == "ssh-upload" || event.phase == "ssh-upload-scp" ||
      event.phase == "ssh-download") {
    std::string text = std::string(event.phase == "ssh-download" ? "Downloading " : "Uploading ") +
                       event.current_scope + ": " + format_health_bytes(event.processed);
    if (event.total != 0U) {
      text += " of " + format_health_bytes(event.total);
      if (event.processed <= event.total)
        text += " (" + std::to_string(progress_percent_of(event.processed, event.total)) + "%)";
    }
    return text;
  }

  std::string text = event.phase.empty() ? std::string("Working") : event.phase;
  if (!event.current_scope.empty())
    text += ": " + event.current_scope;
  if (event.total != 0U) {
    text += " | " + progress_share(event.processed, event.total);
  } else if (event.processed != 0U) {
    text += " | " + progress_count(event.processed) + " done";
  }
  if (event.errors != 0U)
    text += " | " + progress_count(event.errors) + " not read";
  if (event.items_per_second >= 1.0)
    text += " | " + progress_count(static_cast<std::uint64_t>(event.items_per_second)) + "/s";
  if (event.elapsed_seconds > 0.0) {
    text += " | " + progress_duration(event.elapsed_seconds);
    const std::string left = progress_time_left(event.processed, event.total, event.elapsed_seconds);
    if (!left.empty())
      text += ", " + left;
  }
  return text;
}

}  // namespace support_assist::gui
