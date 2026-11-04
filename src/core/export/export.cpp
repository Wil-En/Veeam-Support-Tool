#include "support_assist/export.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include "support_assist/version.hpp"
namespace support_assist {
Result<ExportFormat> parse_export_format(std::string_view t) {
  auto x = ascii_lower(t);
  if (x == "text" || x == "txt")
    return Result<ExportFormat>::success(ExportFormat::text);
  if (x == "json")
    return Result<ExportFormat>::success(ExportFormat::json);
  if (x == "csv")
    return Result<ExportFormat>::success(ExportFormat::csv);
  if (x == "html" || x == "htm")
    return Result<ExportFormat>::success(ExportFormat::html);
  Error e;
  e.component = "Export";
  e.operation = "parse format";
  e.message = "Unsupported export format";
  return Result<ExportFormat>::failure(std::move(e));
}
DiffWriter::DiffWriter(std::ofstream s, ExportFormat f, std::string t)
    : stream_(std::move(s)), format_(f), title_(std::move(t)) {
  if (format_ == ExportFormat::json)
    stream_ << "{\"product\":\"" << kProductName << "\",\"version\":\"" << kVersion
            << "\",\"generated_utc\":\"" << utc_now_iso8601() << "\",\"changes\":[";
  else if (format_ == ExportFormat::csv)
    stream_ << "change,category,identity,old_path,new_path,before,after,confidence,reason\r\n";
  else if (format_ == ExportFormat::html)
    stream_
        << "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
           "content=\"width=device-width,initial-scale=1\"><title>"
        << html_escape(title_)
        << "</title><style>body{font-family:Segoe "
           "UI,Arial,sans-serif;margin:2rem;color:#1f2328}table{border-collapse:collapse;width:100%"
           ";font-size:14px}th,td{border:1px solid "
           "#d0d7de;padding:.45rem;vertical-align:top}th{background:#f6f8fa;position:sticky;top:0}."
           "added{background:#dafbe1}.removed{background:#ffebe9}.modified{background:#fff8c5}code{"
           "white-space:pre-wrap;word-break:break-word}</style></head><body><h1>"
        << html_escape(title_) << "</h1><p>Generated " << html_escape(utc_now_iso8601())
        << " by " << kProductName << ' ' << kVersion
        << ".</p><table><thead><tr><th>Change</th><th>Category</th><th>Identity</th><th>Before</"
           "th><th>After</th><th>Reason</th><th>Confidence</th></tr></thead><tbody>";
}
DiffWriter::~DiffWriter() {
  if (stream_.is_open() && !finished_)
    finish();
}
DiffWriter::DiffWriter(DiffWriter&&) noexcept = default;
DiffWriter& DiffWriter::operator=(DiffWriter&&) noexcept = default;
Result<DiffWriter>
DiffWriter::open(const std::filesystem::path& p, ExportFormat f, std::string title) {
  std::ofstream s(p, std::ios::binary | std::ios::trunc);
  if (!s) {
    Error e;
    e.component = "Export";
    e.operation = "open";
    e.source = path_to_utf8(p);
    e.message = "Unable to create export";
    e.timestamp_utc = utc_now_iso8601();
    e.correlation_id = make_uuid_v4();
    return Result<DiffWriter>::failure(std::move(e));
  }
  return Result<DiffWriter>::success(DiffWriter(std::move(s), f, std::move(title)));
}
Status DiffWriter::write(const DiffRecord& r) {
  if (!stream_ || finished_) {
    Error e;
    e.component = "Export";
    e.operation = "write";
    e.message = "Writer is closed";
    return Status::failure(std::move(e));
  }
  auto k = to_string(r.kind);
  switch (format_) {
  case ExportFormat::text:
    stream_ << k << " | " << r.category << " | " << r.identity << "\n  before: " << r.before_summary
            << "\n  after:  " << r.after_summary << "\n  reason: " << r.reason << " (confidence "
            << r.confidence << ")\n";
    break;
  case ExportFormat::csv:
    stream_ << csv_escape(k) << ',' << csv_escape(r.category) << ',' << csv_escape(r.identity)
            << ',' << csv_escape(r.old_path) << ',' << csv_escape(r.new_path) << ','
            << csv_escape(r.before_summary) << ',' << csv_escape(r.after_summary) << ','
            << r.confidence << ',' << csv_escape(r.reason) << "\r\n";
    break;
  case ExportFormat::json:
    if (!first_)
      stream_ << ',';
    stream_ << "{\"change\":\"" << json_escape(k) << "\",\"category\":\"" << json_escape(r.category)
            << "\",\"identity\":\"" << json_escape(r.identity) << "\",\"old_path\":\""
            << json_escape(r.old_path) << "\",\"new_path\":\"" << json_escape(r.new_path)
            << "\",\"before\":\"" << json_escape(r.before_summary) << "\",\"after\":\""
            << json_escape(r.after_summary) << "\",\"confidence\":" << r.confidence
            << ",\"reason\":\"" << json_escape(r.reason) << "\"}";
    first_ = false;
    break;
  case ExportFormat::html:
    stream_ << "<tr class=\"" << html_escape(k) << "\"><td>" << html_escape(k) << "</td><td>"
            << html_escape(r.category) << "</td><td><code>" << html_escape(r.identity)
            << "</code></td><td><code>" << html_escape(r.before_summary) << "</code></td><td><code>"
            << html_escape(r.after_summary) << "</code></td><td>" << html_escape(r.reason)
            << "</td><td>" << r.confidence << "</td></tr>";
    break;
  }
  if (stream_)
    return Status::success();
  Error e;
  e.component = "Export";
  e.operation = "write";
  e.message = "Output stream failure";
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return Status::failure(std::move(e));
}
Status DiffWriter::finish() {
  if (finished_)
    return Status::success();
  if (format_ == ExportFormat::json)
    stream_ << "]}\n";
  else if (format_ == ExportFormat::html)
    stream_ << "</tbody></table></body></html>";
  stream_.flush();
  finished_ = true;
  if (!stream_) {
    Error e;
    e.component = "Export";
    e.operation = "finish";
    e.message = "Output stream failure";
    e.timestamp_utc = utc_now_iso8601();
    e.correlation_id = make_uuid_v4();
    return Status::failure(std::move(e));
  }
  return Status::success();
}
Status
export_log_matches(const std::filesystem::path& p, ExportFormat f, const std::vector<LogMatch>& m) {
  auto w = DiffWriter::open(p, f, std::string(kProductName) + " Log Search");
  if (!w.ok())
    return Status::failure(w.error());
  for (const auto& x : m) {
    DiffRecord d;
    d.kind = ChangeKind::modified;
    d.category = "log_match";
    d.identity = x.source_path + ":" + std::to_string(x.line_number);
    d.before_summary = x.before.empty() ? "" : x.before.back();
    d.after_summary = x.matching_line;
    d.reason = x.severity + (x.timestamp_ambiguous ? "; ambiguous timestamp" : "");
    auto s = w.value().write(d);
    if (!s.ok())
      return s;
  }
  return w.value().finish();
}
} // namespace support_assist
