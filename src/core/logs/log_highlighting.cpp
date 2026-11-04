#include "support_assist/log_highlighting.hpp"

#include <algorithm>
#include <array>
#include <cwctype>
#include <optional>
#include <string>
#include <string_view>

namespace support_assist {
namespace {

std::wstring fold(std::wstring_view value) {
  std::wstring output(value);
  std::transform(output.begin(), output.end(), output.begin(), [](wchar_t character) {
    return static_cast<wchar_t>(std::towlower(static_cast<wint_t>(character)));
  });
  return output;
}

bool token_character(wchar_t value) {
  return std::iswalnum(static_cast<wint_t>(value)) != 0 || value == L'_';
}

bool bounded(std::wstring_view line, std::size_t start, std::size_t length) {
  const bool left = start == 0 || !token_character(line[start - 1]);
  const std::size_t end = start + length;
  const bool right = end >= line.size() || !token_character(line[end]);
  return left && right;
}

void add_span(LogLineHighlight& result,
              std::size_t start,
              std::size_t length,
              LogHighlightKind kind,
              int priority) {
  if (length == 0)
    return;
  result.spans.push_back(LogHighlightSpan{start, length, kind, priority});
}

std::optional<std::size_t> find_phrase(std::wstring_view original,
                                       std::wstring_view folded,
                                       std::wstring_view phrase,
                                       std::size_t offset = 0,
                                       bool require_bounds = true) {
  const std::wstring folded_phrase = fold(phrase);
  std::size_t position = folded.find(folded_phrase, offset);
  while (position != std::wstring_view::npos) {
    if (!require_bounds || bounded(original, position, phrase.size()))
      return position;
    position = folded.find(folded_phrase, position + 1);
  }
  return std::nullopt;
}

void add_all_phrases(LogLineHighlight& result,
                     std::wstring_view original,
                     std::wstring_view folded,
                     std::wstring_view phrase,
                     LogHighlightKind kind,
                     int priority,
                     bool require_bounds = true) {
  const std::wstring folded_phrase = fold(phrase);
  std::size_t offset = 0;
  while (offset < folded.size()) {
    const std::size_t position = folded.find(folded_phrase, offset);
    if (position == std::wstring_view::npos)
      break;
    if (!require_bounds || bounded(original, position, phrase.size()))
      add_span(result, position, phrase.size(), kind, priority);
    offset = position + std::max<std::size_t>(1, phrase.size());
  }
}

struct SeverityMatch {
  LogLineSeverity severity = LogLineSeverity::unknown;
  std::size_t start = 0;
  std::size_t length = 0;
};

std::optional<SeverityMatch> explicit_severity(std::wstring_view original,
                                                std::wstring_view folded) {
  struct Candidate {
    std::wstring_view text;
    LogLineSeverity severity;
  };
  constexpr std::array<Candidate, 14> candidates{{
      {L"fatal (", LogLineSeverity::critical},
      {L"critical (", LogLineSeverity::critical},
      {L"error (", LogLineSeverity::error},
      {L"warning (", LogLineSeverity::warning},
      {L"warn (", LogLineSeverity::warning},
      {L"info (", LogLineSeverity::information},
      {L"information (", LogLineSeverity::information},
      {L"debug (", LogLineSeverity::information},
      {L"trace (", LogLineSeverity::information},
      {L"|fatal|", LogLineSeverity::critical},
      {L"|error|", LogLineSeverity::error},
      {L"|err|", LogLineSeverity::error},
      {L"|warning|", LogLineSeverity::warning},
      {L"|warn|", LogLineSeverity::warning},
  }};

  std::optional<SeverityMatch> best;
  for (const auto& candidate : candidates) {
    const std::size_t position = folded.find(candidate.text);
    if (position == std::wstring_view::npos)
      continue;
    std::size_t length = candidate.text.size();
    if (candidate.text.back() == L'(') {
      const std::size_t close = original.find(L')', position + candidate.text.size());
      if (close != std::wstring_view::npos && close - position <= 32)
        length = close - position + 1;
    }
    if (!best || position < best->start)
      best = SeverityMatch{candidate.severity, position, length};
  }

  for (std::wstring_view marker : {L"|info|", L"|debug|", L"|trace|"}) {
    const std::size_t position = folded.find(marker);
    if (position != std::wstring_view::npos && (!best || position < best->start))
      best = SeverityMatch{LogLineSeverity::information, position, marker.size()};
  }

  struct CompactPipeCandidate {
    std::wstring_view text;
    LogLineSeverity severity;
  };
  constexpr std::array<CompactPipeCandidate, 8> compact{{
      {L"fatal|", LogLineSeverity::critical},
      {L"error|", LogLineSeverity::error},
      {L"err|", LogLineSeverity::error},
      {L"warning|", LogLineSeverity::warning},
      {L"warn|", LogLineSeverity::warning},
      {L"info|", LogLineSeverity::information},
      {L"debug|", LogLineSeverity::information},
      {L"trace|", LogLineSeverity::information},
  }};
  for (const auto& candidate : compact) {
    std::size_t position = folded.find(candidate.text);
    while (position != std::wstring_view::npos) {
      const bool left_boundary = position == 0 || folded[position - 1] == L'|' ||
                                 std::iswspace(static_cast<wint_t>(folded[position - 1])) != 0;
      if (left_boundary) {
        if (!best || position < best->start)
          best = SeverityMatch{candidate.severity, position, candidate.text.size()};
        break;
      }
      position = folded.find(candidate.text, position + 1);
    }
  }
  return best;
}

std::optional<SeverityMatch> inferred_severity(std::wstring_view original,
                                                std::wstring_view folded) {
  struct Candidate {
    std::wstring_view text;
    LogLineSeverity severity;
  };
  constexpr std::array<Candidate, 23> candidates{{
      {L"unhandled exception", LogLineSeverity::critical},
      {L"access violation", LogLineSeverity::critical},
      {L"fatal", LogLineSeverity::critical},
      {L"critical", LogLineSeverity::critical},
      {L"connection refused", LogLineSeverity::error},
      {L"access denied", LogLineSeverity::error},
      {L"unable to", LogLineSeverity::error},
      {L"cannot", LogLineSeverity::error},
      {L"timed out", LogLineSeverity::error},
      {L"timeout", LogLineSeverity::error},
      {L"exception", LogLineSeverity::error},
      {L"aborted", LogLineSeverity::error},
      {L"failure", LogLineSeverity::error},
      {L"failed", LogLineSeverity::error},
      {L"error", LogLineSeverity::error},
      {L"err", LogLineSeverity::error},
      {L"retrying", LogLineSeverity::warning},
      {L"degraded", LogLineSeverity::warning},
      {L"fallback", LogLineSeverity::warning},
      {L"skipped", LogLineSeverity::warning},
      {L"unavailable", LogLineSeverity::warning},
      {L"warning", LogLineSeverity::warning},
      {L"warn", LogLineSeverity::warning},
  }};
  for (const auto& candidate : candidates) {
    const auto position = find_phrase(original, folded, candidate.text);
    if (position)
      return SeverityMatch{candidate.severity, *position, candidate.text.size()};
  }
  return std::nullopt;
}

bool is_hex(wchar_t value) {
  return (value >= L'0' && value <= L'9') || (value >= L'a' && value <= L'f') ||
         (value >= L'A' && value <= L'F');
}

bool valid_guid(std::wstring_view candidate) {
  if (candidate.size() != 36 || candidate[8] != L'-' || candidate[13] != L'-' ||
      candidate[18] != L'-' || candidate[23] != L'-') {
    return false;
  }
  for (std::size_t index = 0; index < candidate.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23)
      continue;
    if (!is_hex(candidate[index]))
      return false;
  }
  return true;
}

bool valid_ipv4(std::wstring_view candidate) {
  int parts = 0;
  std::size_t start = 0;
  while (start < candidate.size()) {
    const std::size_t dot = candidate.find(L'.', start);
    const std::size_t end = dot == std::wstring_view::npos ? candidate.size() : dot;
    if (end == start || end - start > 3)
      return false;
    int value = 0;
    for (std::size_t index = start; index < end; ++index) {
      if (std::iswdigit(static_cast<wint_t>(candidate[index])) == 0)
        return false;
      value = value * 10 + static_cast<int>(candidate[index] - L'0');
    }
    if (value > 255)
      return false;
    ++parts;
    if (dot == std::wstring_view::npos)
      break;
    start = dot + 1;
  }
  return parts == 4;
}

bool path_terminator(wchar_t value) {
  return value == L'\r' || value == L'\n' || value == L'\t' || value == L'"' ||
         value == L'\'' || value == L']' || value == L')' || value == L'|' ||
         value == L';' || value == L',';
}

std::size_t message_start_after(const std::optional<SeverityMatch>& severity,
                                std::wstring_view line) {
  if (!severity)
    return 0;
  std::size_t start = severity->start + severity->length;
  while (start < line.size() && std::iswspace(static_cast<wint_t>(line[start])) != 0)
    ++start;
  return start;
}

} // namespace

LogLineHighlight analyze_veeam_log_line(std::wstring_view line) {
  LogLineHighlight result;
  const std::wstring folded_storage = fold(line);
  const std::wstring_view folded(folded_storage);

  const std::size_t timestamp_open = line.find(L'[');
  const std::size_t timestamp_close = timestamp_open == std::wstring_view::npos
                                          ? std::wstring_view::npos
                                          : line.find(L']', timestamp_open + 1);
  if (timestamp_open != std::wstring_view::npos && timestamp_close != std::wstring_view::npos &&
      timestamp_close - timestamp_open >= 10 && timestamp_close - timestamp_open <= 48) {
    add_span(result,
             timestamp_open,
             timestamp_close - timestamp_open + 1,
             LogHighlightKind::timestamp,
             100);
  }

  const std::size_t thread_open =
      line.find(L'<', timestamp_close == std::wstring_view::npos ? 0 : timestamp_close + 1);
  const std::size_t thread_close = thread_open == std::wstring_view::npos
                                       ? std::wstring_view::npos
                                       : line.find(L'>', thread_open + 1);
  if (thread_open != std::wstring_view::npos && thread_close != std::wstring_view::npos &&
      thread_close - thread_open <= 18) {
    add_span(result,
             thread_open,
             thread_close - thread_open + 1,
             LogHighlightKind::thread_id,
             100);
  }

  // Thread ids named inside the message, not just the prefix column.
  //
  // Veeam logs say "thread id: 7224, parent id: 8592" in the text while the prefix column carries
  // the thread that wrote the line. Marking both means the id in the sentence takes the same colour
  // as the column, so an engineer can see at a glance which thread spawned which.
  for (const std::wstring_view marker : {std::wstring_view(L"thread id:"),
                                         std::wstring_view(L"parent id:"),
                                         std::wstring_view(L"thread id "),
                                         std::wstring_view(L"parent id ")}) {
    std::size_t at = folded.find(marker);
    while (at != std::wstring::npos) {
      std::size_t digit = at + marker.size();
      while (digit < line.size() && std::iswspace(static_cast<wint_t>(line[digit])) != 0)
        ++digit;
      std::size_t end = digit;
      while (end < line.size() && std::iswdigit(static_cast<wint_t>(line[end])) != 0)
        ++end;
      if (end > digit)
        add_span(result, digit, end - digit, LogHighlightKind::thread_id, 540);
      at = folded.find(marker, at + marker.size());
    }
  }

  const auto explicit_match = explicit_severity(line, folded);
  const auto chosen_match = explicit_match ? explicit_match : inferred_severity(line, folded);
  if (chosen_match) {
    result.severity = chosen_match->severity;
    result.explicit_severity = explicit_match.has_value();
    add_span(result,
             chosen_match->start,
             chosen_match->length,
             LogHighlightKind::severity,
             1000);
  }

  const std::size_t message_start = message_start_after(explicit_match, line);
  std::wstring_view message = line.substr(message_start);
  while (!message.empty() && std::iswspace(static_cast<wint_t>(message.front())) != 0)
    message.remove_prefix(1);
  const std::wstring folded_message_storage = fold(message);
  const std::wstring_view folded_message(folded_message_storage);
  result.stack_continuation = folded_message.starts_with(L"at ") ||
                              folded_message.starts_with(L"--- end of") ||
                              folded_message.starts_with(L"caused by:") ||
                              folded_message.starts_with(L"innerexception:");
  if (result.stack_continuation && !message.empty()) {
    const std::size_t actual_start = static_cast<std::size_t>(message.data() - line.data());
    add_span(result, actual_start, message.size(), LogHighlightKind::stack_frame, 80);
  }

  std::size_t component_search =
      timestamp_close == std::wstring_view::npos ? 0 : timestamp_close + 1;
  while (component_search < line.size()) {
    const std::size_t open = line.find(L'[', component_search);
    if (open == std::wstring_view::npos)
      break;
    const std::size_t close = line.find(L']', open + 1);
    if (close == std::wstring_view::npos)
      break;
    const std::wstring_view candidate = line.substr(open + 1, close - open - 1);
    if (!candidate.empty() && candidate.size() <= 96 &&
        candidate.find(L':') == std::wstring_view::npos && !valid_guid(candidate)) {
      add_span(result, open, close - open + 1, LogHighlightKind::component, 300);
      break;
    }
    component_search = close + 1;
  }

  const bool negative_line = result.severity == LogLineSeverity::critical ||
                             result.severity == LogLineSeverity::error ||
                             result.severity == LogLineSeverity::warning;
  const bool failed_status = folded.find(L"status: 'failed'") != std::wstring_view::npos ||
                             folded.find(L"status: \"failed\"") != std::wstring_view::npos;
  if (!negative_line && !failed_status) {
    for (std::wstring_view phrase : {L"completed successfully", L"successfully", L"successful",
                                     L"status: 'success'", L"status: \"success\"", L"success",
                                     L"cleaned"}) {
      add_all_phrases(result, line, folded, phrase, LogHighlightKind::success, 250);
    }
  }

  for (std::wstring_view phrase : {L"starting new log", L"starting job mode", L"starting backup",
                                   L"job session started", L"task session started",
                                   L"creating vss snapshot", L"creating restore point",
                                   L"finalizing backup"}) {
    add_all_phrases(result, line, folded, phrase, LogHighlightKind::lifecycle, 180);
  }

  for (std::wstring_view phrase : {L"machinename:", L"machine name:", L"hostname:",
                                   L"host name:", L"ipaddresses:", L"ip addresses:",
                                   L"operating system:", L"os:", L"file version:",
                                   L"assembly version:", L"product version:", L"job id:",
                                   L"session id:", L"task session id:", L"restore point id:",
                                   L"backup job name:", L"job name:", L"local folder:",
                                   L"included items:", L"excluded items:", L"repository:",
                                   L"backup file:", L"destination"}) {
    add_all_phrases(result,
                    line,
                    folded,
                    phrase,
                    LogHighlightKind::metadata_label,
                    170,
                    false);
  }

  for (std::wstring_view phrase : {L"file level backup", L"volume level backup",
                                   L"entire computer", L"synthetic full", L"active full",
                                   L"incremental", L"full", L"protection group",
                                   L"snapshot set", L"database"}) {
    add_all_phrases(result, line, folded, phrase, LogHighlightKind::backup_concept, 140);
  }

  for (std::wstring_view prefix : {L"https://", L"http://", L"ftp://", L"ftps://", L"mailto:"}) {
    std::size_t position = folded.find(prefix);
    while (position != std::wstring_view::npos) {
      std::size_t end = position + prefix.size();
      while (end < line.size() && std::iswspace(static_cast<wint_t>(line[end])) == 0 && line[end] != L')' &&
             line[end] != L']') {
        ++end;
      }
      add_span(result, position, end - position, LogHighlightKind::url, 500);
      position = folded.find(prefix, end);
    }
  }

  for (std::size_t index = 0; index + 2 < line.size(); ++index) {
    const bool drive = std::iswalpha(static_cast<wint_t>(line[index])) != 0 && line[index + 1] == L':' &&
                       (line[index + 2] == L'\\' || line[index + 2] == L'/');
    const bool unc = line[index] == L'\\' && line[index + 1] == L'\\';
    if (!drive && !unc)
      continue;
    std::size_t end = index + (drive ? 3 : 2);
    while (end < line.size() && !path_terminator(line[end]))
      ++end;
    while (end > index && (std::iswspace(static_cast<wint_t>(line[end - 1])) != 0 || line[end - 1] == L'.'))
      --end;
    add_span(result, index, end - index, LogHighlightKind::path, 600);
    index = end > 0 ? end - 1 : end;
  }

  for (std::size_t index = 0; index + 36 <= line.size(); ++index) {
    const std::wstring_view candidate = line.substr(index, 36);
    if (valid_guid(candidate)) {
      add_span(result, index, 36, LogHighlightKind::guid, 550);
      index += 35;
    }
  }

  for (std::size_t index = 0; index < line.size(); ++index) {
    if (std::iswdigit(static_cast<wint_t>(line[index])) == 0)
      continue;
    std::size_t end = index;
    while (end < line.size() &&
           (std::iswdigit(static_cast<wint_t>(line[end])) != 0 || line[end] == L'.')) {
      ++end;
    }
    const std::wstring_view candidate = line.substr(index, end - index);
    if (valid_ipv4(candidate))
      add_span(result, index, candidate.size(), LogHighlightKind::ip_address, 550);
    if (end > index)
      index = end - 1;
  }

  std::wstring_view trimmed = line;
  while (!trimmed.empty() && std::iswspace(static_cast<wint_t>(trimmed.front())) != 0)
    trimmed.remove_prefix(1);
  const std::size_t separator_count =
      static_cast<std::size_t>(std::count(trimmed.begin(), trimmed.end(), L'=')) +
      static_cast<std::size_t>(std::count(trimmed.begin(), trimmed.end(), L'-'));
  result.heading = separator_count >= 8;
  if (result.heading) {
    add_span(result,
             static_cast<std::size_t>(trimmed.data() - line.data()),
             trimmed.size(),
             LogHighlightKind::heading,
             50);
  }

  std::stable_sort(result.spans.begin(), result.spans.end(),
                   [](const LogHighlightSpan& left, const LogHighlightSpan& right) {
                     if (left.priority != right.priority)
                       return left.priority < right.priority;
                     if (left.start != right.start)
                       return left.start < right.start;
                     return left.length < right.length;
                   });
  return result;
}

} // namespace support_assist
