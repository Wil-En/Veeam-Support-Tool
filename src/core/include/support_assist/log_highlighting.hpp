#pragma once

#include <cstddef>
#include <string_view>
#include <vector>

namespace support_assist {

enum class LogLineSeverity {
  unknown,
  information,
  warning,
  error,
  critical,
};

enum class LogHighlightKind {
  timestamp,
  thread_id,
  severity,
  component,
  stack_frame,
  success,
  lifecycle,
  metadata_label,
  backup_concept,
  url,
  path,
  guid,
  ip_address,
  heading,
};

struct LogHighlightSpan {
  std::size_t start = 0;
  std::size_t length = 0;
  LogHighlightKind kind = LogHighlightKind::metadata_label;
  int priority = 0;
};

struct LogLineHighlight {
  LogLineSeverity severity = LogLineSeverity::unknown;
  bool explicit_severity = false;
  bool stack_continuation = false;
  bool heading = false;
  std::vector<LogHighlightSpan> spans;
};

LogLineHighlight analyze_veeam_log_line(std::wstring_view line);

} // namespace support_assist
