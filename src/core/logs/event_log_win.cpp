#include "support_assist/log_search.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <windows.h>
#include <winevt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

class EventHandle {
public:
  explicit EventHandle(EVT_HANDLE value = nullptr) : value_(value) {}
  ~EventHandle() {
    if (value_)
      EvtClose(value_);
  }
  EventHandle(const EventHandle&) = delete;
  EventHandle& operator=(const EventHandle&) = delete;
  EventHandle(EventHandle&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
  EventHandle& operator=(EventHandle&& other) noexcept {
    if (this != &other) {
      if (value_)
        EvtClose(value_);
      value_ = std::exchange(other.value_, nullptr);
    }
    return *this;
  }
  EVT_HANDLE get() const noexcept {
    return value_;
  }

private:
  EVT_HANDLE value_ = nullptr;
};

Error event_error(std::string operation, DWORD code, std::string source = {}) {
  Error error;
  error.component = "WindowsEventLog";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.native_code = code;
  error.message = "Windows Event Log API returned error " + std::to_string(code);
  error.recoverable = true;
  error.elevation_may_help = code == ERROR_ACCESS_DENIED;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

Result<std::wstring> render_xml(EVT_HANDLE event) {
  DWORD used = 0;
  DWORD properties = 0;
  EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &properties);
  const DWORD first_error = GetLastError();
  if (first_error != ERROR_INSUFFICIENT_BUFFER) {
    return Result<std::wstring>::failure(event_error("EvtRender XML size", first_error));
  }
  std::vector<wchar_t> buffer((used + sizeof(wchar_t) - 1) / sizeof(wchar_t));
  if (!EvtRender(nullptr, event, EvtRenderEventXml, used, buffer.data(), &used, &properties)) {
    return Result<std::wstring>::failure(event_error("EvtRender XML", GetLastError()));
  }
  return Result<std::wstring>::success(std::wstring(buffer.data()));
}

std::wstring xml_element(std::wstring_view xml, std::wstring_view name) {
  const std::wstring opening = L"<" + std::wstring(name);
  const auto start_tag = xml.find(opening);
  if (start_tag == std::wstring_view::npos)
    return {};
  const auto content_start = xml.find(L'>', start_tag);
  if (content_start == std::wstring_view::npos)
    return {};
  const std::wstring closing = L"</" + std::wstring(name) + L">";
  const auto content_end = xml.find(closing, content_start + 1);
  if (content_end == std::wstring_view::npos)
    return {};
  return std::wstring(xml.substr(content_start + 1, content_end - content_start - 1));
}

std::wstring
xml_attribute(std::wstring_view xml, std::wstring_view element, std::wstring_view attribute) {
  const auto element_start = xml.find(L"<" + std::wstring(element));
  if (element_start == std::wstring_view::npos)
    return {};
  const auto element_end = xml.find(L'>', element_start);
  if (element_end == std::wstring_view::npos)
    return {};
  const std::wstring key = std::wstring(attribute) + L"='";
  auto value_start = xml.find(key, element_start);
  wchar_t quote = L'\'';
  std::size_t prefix = key.size();
  if (value_start == std::wstring_view::npos || value_start > element_end) {
    const std::wstring double_key = std::wstring(attribute) + L"=\"";
    value_start = xml.find(double_key, element_start);
    quote = L'\"';
    prefix = double_key.size();
  }
  if (value_start == std::wstring_view::npos || value_start > element_end)
    return {};
  value_start += prefix;
  const auto value_end = xml.find(quote, value_start);
  if (value_end == std::wstring_view::npos || value_end > element_end)
    return {};
  return std::wstring(xml.substr(value_start, value_end - value_start));
}

Result<std::wstring> formatted_message(EVT_HANDLE event, std::wstring_view provider) {
  EventHandle metadata(
      EvtOpenPublisherMetadata(nullptr, std::wstring(provider).c_str(), nullptr, 0, 0));
  if (!metadata.get())
    return Result<std::wstring>::failure(
        event_error("EvtOpenPublisherMetadata", GetLastError(), utf8_from_wide(provider)));
  DWORD used = 0;
  EvtFormatMessage(metadata.get(), event, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &used);
  const DWORD first_error = GetLastError();
  if (first_error != ERROR_INSUFFICIENT_BUFFER) {
    return Result<std::wstring>::failure(
        event_error("EvtFormatMessage size", first_error, utf8_from_wide(provider)));
  }
  std::vector<wchar_t> buffer(used);
  if (!EvtFormatMessage(metadata.get(),
                        event,
                        0,
                        0,
                        nullptr,
                        EvtFormatMessageEvent,
                        used,
                        buffer.data(),
                        &used)) {
    return Result<std::wstring>::failure(
        event_error("EvtFormatMessage", GetLastError(), utf8_from_wide(provider)));
  }
  return Result<std::wstring>::success(std::wstring(buffer.data()));
}

std::string severity_from_level(int level) {
  switch (level) {
  case 1:
    return "critical";
  case 2:
    return "error";
  case 3:
    return "warning";
  case 4:
    return "information";
  case 5:
    return "verbose";
  default:
    return "unknown";
  }
}

bool allowed_severity(const std::vector<std::string>& configured, std::string_view actual) {
  if (configured.empty())
    return true;
  const auto folded = ascii_lower(actual);
  return std::any_of(configured.begin(), configured.end(), [&](const std::string& item) {
    return ascii_lower(item) == folded;
  });
}

// The query for a channel. With event ids and a time window the log service does the selecting,
// so SAT does not render every event of a large log. The query language allows 20 expressions, so
// more than 15 event ids are left to the filters in search_windows_event_log.
std::wstring channel_query(const WindowsEventLogSearchOptions& options) {
  constexpr std::size_t kMaximumQueryEventIds = 15U;
  std::string conditions;
  if (!options.event_ids.empty() && options.event_ids.size() <= kMaximumQueryEventIds) {
    conditions = "(";
    for (std::size_t index = 0; index < options.event_ids.size(); ++index)
      conditions += (index == 0 ? "EventID=" : " or EventID=") + std::to_string(options.event_ids[index]);
    conditions += ")";
  }
  std::string window;
  if (options.from_utc_ms)
    window += "@SystemTime>='" + iso8601_from_unix_millis(*options.from_utc_ms) + "'";
  if (options.to_utc_ms) {
    window += std::string(window.empty() ? "" : " and ") + "@SystemTime<='" +
              iso8601_from_unix_millis(*options.to_utc_ms) + "'";
  }
  if (!window.empty())
    conditions += std::string(conditions.empty() ? "" : " and ") + "TimeCreated[" + window + "]";
  if (conditions.empty())
    return L"*";
  return wide_from_utf8("*[System[" + conditions + "]]");
}

bool contains_query(std::string_view text, std::string_view query, bool case_sensitive) {
  if (query.empty())
    return true;
  if (case_sensitive)
    return text.find(query) != std::string_view::npos;
  return ascii_lower(text).find(ascii_lower(query)) != std::string::npos;
}

} // namespace

Result<std::uint64_t> search_windows_event_log(const WindowsEventLogSearchOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress,
                                               const LogMatchCallback& callback) {
  const std::wstring channel = wide_from_utf8(options.channel);
  const std::wstring selection = channel_query(options);
  constexpr DWORD kQueryFlags = EvtQueryChannelPath | EvtQueryReverseDirection;
  EventHandle query(EvtQuery(nullptr, channel.c_str(), selection.c_str(), kQueryFlags));
  if (!query.get() && selection != L"*") {
    // A query the log service refuses falls back to the whole channel, which is filtered below.
    query = EventHandle(EvtQuery(nullptr, channel.c_str(), L"*", kQueryFlags));
  }
  if (!query.get()) {
    return Result<std::uint64_t>::failure(event_error("EvtQuery", GetLastError(), options.channel));
  }

  const auto started = std::chrono::steady_clock::now();
  std::uint64_t processed = 0;
  std::uint64_t matches = 0;
  std::array<EVT_HANDLE, 32> events{};
  while (!cancel.is_cancelled() && matches < options.maximum_results) {
    DWORD returned = 0;
    if (!EvtNext(
            query.get(), static_cast<DWORD>(events.size()), events.data(), 1000, 0, &returned)) {
      const DWORD code = GetLastError();
      if (code == ERROR_NO_MORE_ITEMS)
        break;
      if (code == ERROR_TIMEOUT)
        continue;
      return Result<std::uint64_t>::failure(event_error("EvtNext", code, options.channel));
    }
    // Every handle EvtNext returned is closed when the batch goes out of scope, whichever way the
    // loop below ends.
    std::vector<EventHandle> batch;
    batch.reserve(returned);
    for (DWORD index = 0; index < returned; ++index) {
      batch.emplace_back(events[index]);
      events[index] = nullptr;
    }
    bool finished = false;
    for (EventHandle& event : batch) {
      ++processed;
      auto xml = render_xml(event.get());
      if (!xml.ok())
        continue;
      const std::wstring provider_wide = xml_attribute(xml.value(), L"Provider", L"Name");
      const std::wstring event_id_wide = xml_element(xml.value(), L"EventID");
      const std::wstring level_wide = xml_element(xml.value(), L"Level");
      const std::wstring record_wide = xml_element(xml.value(), L"EventRecordID");
      const std::wstring time_wide = xml_attribute(xml.value(), L"TimeCreated", L"SystemTime");
      std::uint32_t event_id = 0;
      int level = 0;
      std::uint64_t record_id = 0;
      try {
        if (!event_id_wide.empty())
          event_id = static_cast<std::uint32_t>(std::stoul(event_id_wide));
        if (!level_wide.empty())
          level = std::stoi(level_wide);
        if (!record_wide.empty())
          record_id = std::stoull(record_wide);
      } catch (...) {
        continue;
      }
      // The channel is read newest first, so the first event older than the window ends the search.
      auto timestamp = parse_timestamp(utf8_from_wide(time_wide), DateOrder::iso_only);
      if (timestamp) {
        if (options.from_utc_ms && timestamp->unix_millis < *options.from_utc_ms) {
          finished = true;
          break;
        }
        if (options.to_utc_ms && timestamp->unix_millis > *options.to_utc_ms)
          continue;
      }
      if (!options.event_ids.empty() &&
          std::find(options.event_ids.begin(), options.event_ids.end(), event_id) ==
              options.event_ids.end()) {
        continue;
      }
      const std::string severity = severity_from_level(level);
      if (!allowed_severity(options.severities, severity))
        continue;
      auto message = formatted_message(event.get(), provider_wide);
      const std::string rendered =
          message.ok() ? utf8_from_wide(message.value()) : utf8_from_wide(xml.value());
      if (!contains_query(rendered, options.query, options.case_sensitive))
        continue;

      LogMatch match;
      match.source_path = "Windows Event Log: " + options.channel;
      match.line_number = record_id;
      match.severity = severity;
      match.timestamp_original = utf8_from_wide(time_wide);
      if (timestamp) {
        match.timestamp_utc_ms = timestamp->unix_millis;
        match.timestamp_format = timestamp->format;
        match.timestamp_confidence = timestamp->confidence;
      }
      match.matching_line = rendered;
      match.signature =
          "event-id:" + std::to_string(event_id) + ";provider:" + utf8_from_wide(provider_wide);
      if (auto status = callback(match); !status.ok()) {
        return Result<std::uint64_t>::failure(status.error());
      }
      ++matches;
      if (matches >= options.maximum_results)
        break;
    }
    if (finished)
      break;
    if (progress) {
      const double elapsed =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
      progress(ProgressEvent{"windows-event-log",
                             options.channel,
                             processed,
                             0,
                             elapsed,
                             elapsed > 0.0 ? processed / elapsed : 0.0});
    }
  }
  return Result<std::uint64_t>::success(matches);
}

} // namespace support_assist
