#include "support_assist/log_search.hpp"
#include "support_assist/secure_temp.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string_view>
#ifdef SUPPORT_ASSIST_HAS_RE2
#include <re2/re2.h>
#endif
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
#include <archive.h>
#include <archive_entry.h>
#endif
namespace support_assist {
namespace {
enum class Encoding { utf8, utf16le, utf16be };
class LineReader {
public:
  LineReader(const std::filesystem::path& p, std::size_t limit)
      : in_(p, std::ios::binary), limit_(limit) {
    unsigned char b[3]{};
    in_.read(reinterpret_cast<char*>(b), 3);
    auto n = in_.gcount();
    if (n >= 2 && b[0] == 0xff && b[1] == 0xfe) {
      enc_ = Encoding::utf16le;
      in_.clear();
      in_.seekg(2);
    } else if (n >= 2 && b[0] == 0xfe && b[1] == 0xff) {
      enc_ = Encoding::utf16be;
      in_.clear();
      in_.seekg(2);
    } else {
      enc_ = Encoding::utf8;
      in_.clear();
      in_.seekg(n >= 3 && b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf ? 3 : 0);
    }
  }
  bool good() const {
    return in_.good();
  }
  Result<bool> next(std::string& out) {
    out.clear();
    if (enc_ == Encoding::utf8) {
      if (!std::getline(in_, out)) {
        if (in_.eof())
          return Result<bool>::success(false);
        return Result<bool>::failure(err("read line"));
      }
      if (!out.empty() && out.back() == '\r')
        out.pop_back();
      if (out.size() > limit_)
        return Result<bool>::failure(err("line exceeds configured limit"));
      return Result<bool>::success(true);
    }
    std::u16string wide;
    for (;;) {
      char raw[2];
      in_.read(raw, 2);
      if (in_.gcount() == 0 && in_.eof()) {
        if (wide.empty())
          return Result<bool>::success(false);
        break;
      }
      if (in_.gcount() != 2)
        return Result<bool>::failure(err("truncated UTF-16 code unit"));
      unsigned char a = static_cast<unsigned char>(raw[0]), b = static_cast<unsigned char>(raw[1]);
      char16_t ch = enc_ == Encoding::utf16le ? static_cast<char16_t>(a | (b << 8))
                                              : static_cast<char16_t>((a << 8) | b);
      if (ch == u'\n')
        break;
      if (ch != u'\r')
        wide.push_back(ch);
      if (wide.size() * 2 > limit_)
        return Result<bool>::failure(err("line exceeds configured limit"));
    }
    for (std::size_t i = 0; i < wide.size(); ++i) {
      std::uint32_t cp = wide[i];
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (i + 1 < wide.size()) {
          const auto lo = static_cast<std::uint32_t>(wide[i + 1]);
          if (lo >= 0xdc00 && lo <= 0xdfff) {
            ++i;
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
          } else
            cp = 0xfffd;
        } else
          cp = 0xfffd;
      } else if (cp >= 0xdc00 && cp <= 0xdfff)
        cp = 0xfffd;
      if (cp <= 0x7f)
        out.push_back(static_cast<char>(cp));
      else if (cp <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
      } else if (cp <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
      } else {
        out.push_back(static_cast<char>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3f)));
      }
    }
    return Result<bool>::success(true);
  }

private:
  Error err(std::string op) const {
    Error e;
    e.component = "LogReader";
    e.operation = std::move(op);
    e.message = "Unable to read input";
    e.timestamp_utc = utc_now_iso8601();
    e.correlation_id = make_uuid_v4();
    return e;
  }
  std::ifstream in_;
  Encoding enc_ = Encoding::utf8;
  std::size_t limit_;
};
std::string severity_of(std::string_view l) {
  auto x = ascii_lower(l);
  if (x.find("fatal") != std::string::npos || x.find("error") != std::string::npos ||
      x.find("exception") != std::string::npos)
    return "error";
  if (x.find("warn") != std::string::npos)
    return "warning";
  if (x.find("debug") != std::string::npos || x.find("trace") != std::string::npos)
    return "debug";
  return "information";
}
bool severity_allowed(const std::vector<std::string>& allowed, std::string_view s) {
  if (allowed.empty())
    return true;
  auto x = ascii_lower(s);
  return std::any_of(
      allowed.begin(), allowed.end(), [&](const std::string& a) { return ascii_lower(a) == x; });
}
bool date_allowed(const LogSearchOptions& o, const std::optional<ParsedTime>& t) {
  if (!o.from_utc_ms && !o.to_utc_ms)
    return true;
  if (!t)
    return false;
  if (o.from_utc_ms &&
      (o.inclusive_start ? t->unix_millis < *o.from_utc_ms : t->unix_millis <= *o.from_utc_ms))
    return false;
  if (o.to_utc_ms &&
      (o.inclusive_end ? t->unix_millis > *o.to_utc_ms : t->unix_millis >= *o.to_utc_ms))
    return false;
  return true;
}
bool wildcard(std::string_view p, std::string_view s) {
  std::size_t pi = 0, si = 0, star = std::string_view::npos, mark = 0;
  while (si < s.size()) {
    if (pi < p.size() && (p[pi] == '?' || std::tolower(static_cast<unsigned char>(p[pi])) ==
                                              std::tolower(static_cast<unsigned char>(s[si])))) {
      ++pi;
      ++si;
    } else if (pi < p.size() && p[pi] == '*') {
      star = pi++;
      mark = si;
    } else if (star != std::string_view::npos) {
      pi = star + 1;
      si = ++mark;
    } else
      return false;
  }
  while (pi < p.size() && p[pi] == '*')
    ++pi;
  return pi == p.size();
}
bool path_allowed(const LogSearchOptions& o, const std::filesystem::path& p) {
  if (o.filename_patterns.empty())
    return true;
  auto n = support_assist::path_to_utf8(p.filename());
  return std::any_of(o.filename_patterns.begin(),
                     o.filename_patterns.end(),
                     [&](const std::string& pat) { return wildcard(pat, n); });
}
struct Pending {
  LogMatch match;
  std::size_t remaining = 0;
};
Result<std::uint64_t> search_file(const std::filesystem::path& p,
                                  const LogSearchOptions& o,
                                  const CancellationToken& cancel,
                                  const LogMatchCallback& cb,
                                  std::string_view display_source = {}) {
  LineReader rd(p, o.maximum_line_bytes);
  if (!rd.good()) {
    Error e;
    e.component = "LogSearch";
    e.operation = "open";
    e.source = path_to_utf8(p);
    e.message = "Cannot open file";
    return Result<std::uint64_t>::failure(std::move(e));
  }
#ifdef SUPPORT_ASSIST_HAS_RE2
  std::unique_ptr<RE2> re;
  if (o.mode == SearchMode::regular_expression) {
    RE2::Options opt;
    opt.set_case_sensitive(o.case_sensitive);
    opt.set_log_errors(false);
    re = std::make_unique<RE2>(o.query, opt);
    if (!re->ok()) {
      Error e;
      e.component = "LogSearch";
      e.operation = "compile regex";
      e.message = re->error();
      return Result<std::uint64_t>::failure(std::move(e));
    }
  }
#else
  if (o.mode == SearchMode::regular_expression) {
    Error e;
    e.component = "LogSearch";
    e.operation = "compile regex";
    e.message = "This build does not include RE2. Rebuild with SUPPORT_ASSIST_ENABLE_RE2=ON.";
    return Result<std::uint64_t>::failure(std::move(e));
  }
#endif
  std::deque<std::string> prev;
  std::vector<Pending> pending;
  std::uint64_t line_no = 0, count = 0;
  std::string line;
  for (;;) {
    if (cancel.is_cancelled())
      break;
    auto nr = rd.next(line);
    if (!nr.ok())
      return Result<std::uint64_t>::failure(nr.error());
    if (!nr.value())
      break;
    ++line_no;
    for (auto it = pending.begin(); it != pending.end();) {
      if (it->remaining > 0) {
        it->match.after.push_back(line);
        --it->remaining;
      }
      if (it->remaining == 0) {
        auto s = cb(it->match);
        if (!s.ok())
          return Result<std::uint64_t>::failure(s.error());
        ++count;
        it = pending.erase(it);
      } else
        ++it;
    }
    bool hit = false;
    if (o.query.empty())
      hit = true;
    else if (o.mode == SearchMode::literal) {
      auto hay = o.case_sensitive ? line : ascii_lower(line);
      auto needle = o.case_sensitive ? o.query : ascii_lower(o.query);
      hit = hay.find(needle) != std::string::npos;
    }
#ifdef SUPPORT_ASSIST_HAS_RE2
    else
      hit = RE2::PartialMatch(line, *re);
#endif
    if (hit) {
      auto sev = severity_of(line);
      auto parsed = parse_timestamp(line, o.date_order, o.assumed_timezone_offset_minutes);
      if (severity_allowed(o.severities, sev) && date_allowed(o, parsed)) {
        LogMatch m;
        m.source_path = display_source.empty() ? path_to_utf8(p) : std::string(display_source);
        m.line_number = line_no;
        m.severity = sev;
        m.matching_line = line;
        m.before.assign(prev.begin(), prev.end());
        if (parsed) {
          m.timestamp_original = parsed ? parsed->original_text : std::string{};
          m.timestamp_utc_ms = parsed->unix_millis;
          m.timestamp_format = parsed->format;
          m.timestamp_ambiguous = parsed->ambiguous;
          m.timestamp_confidence = parsed->confidence;
        }
        Pending x{std::move(m), o.context_after};
        if (x.remaining == 0) {
          auto s = cb(x.match);
          if (!s.ok())
            return Result<std::uint64_t>::failure(s.error());
          ++count;
        } else
          pending.push_back(std::move(x));
        if (count + pending.size() >= o.maximum_results)
          break;
      }
    }
    prev.push_back(line);
    while (prev.size() > o.context_before)
      prev.pop_front();
  }
  for (auto& x : pending) {
    auto s = cb(x.match);
    if (!s.ok())
      return Result<std::uint64_t>::failure(s.error());
    ++count;
  }
  return Result<std::uint64_t>::success(count);
}

bool is_archive_path(const std::filesystem::path& path) {
  const auto extension = ascii_lower(support_assist::path_to_utf8(path.extension()));
  return extension == ".zip" || extension == ".7z" || extension == ".tar" || extension == ".gz" ||
         extension == ".tgz" || extension == ".bz2" || extension == ".xz";
}

#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
class ArchiveReader {
public:
  ArchiveReader() : value_(archive_read_new()) {}
  ~ArchiveReader() {
    if (value_)
      archive_read_free(value_);
  }
  ArchiveReader(const ArchiveReader&) = delete;
  ArchiveReader& operator=(const ArchiveReader&) = delete;
  archive* get() const noexcept {
    return value_;
  }

private:
  archive* value_ = nullptr;
};

Error archive_error(std::string operation, const std::filesystem::path& source, archive* reader) {
  Error error;
  error.component = "LogArchive";
  error.operation = std::move(operation);
  error.source = path_to_utf8(source);
  error.message = reader && archive_error_string(reader) ? archive_error_string(reader)
                                                         : "Archive processing failed";
  error.recoverable = true;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

Result<std::uint64_t> search_archive(const std::filesystem::path& archive_path,
                                     std::string_view display_prefix,
                                     const LogSearchOptions& options,
                                     const CancellationToken& cancel,
                                     const LogMatchCallback& callback,
                                     std::uint32_t depth,
                                     std::uint64_t& expanded_total,
                                     std::uint64_t& entry_total) {
  if (depth > options.maximum_archive_depth) {
    return Result<std::uint64_t>::success(0);
  }
  ArchiveReader reader;
  if (!reader.get())
    return Result<std::uint64_t>::failure(archive_error("allocate reader", archive_path, nullptr));
  archive_read_support_filter_all(reader.get());
  archive_read_support_format_all(reader.get());
#ifdef _WIN32
  if (archive_read_open_filename_w(reader.get(), archive_path.wstring().c_str(), 1024 * 128) !=
      ARCHIVE_OK) {
#else
  if (archive_read_open_filename(reader.get(), archive_path.string().c_str(), 1024 * 128) !=
      ARCHIVE_OK) {
#endif
    return Result<std::uint64_t>::failure(
        archive_error("open archive", archive_path, reader.get()));
  }

  std::uint64_t matches = 0;
  archive_entry* entry = nullptr;
  while (!cancel.is_cancelled()) {
    const int next = archive_read_next_header(reader.get(), &entry);
    if (next == ARCHIVE_EOF)
      break;
    if (next != ARCHIVE_OK)
      return Result<std::uint64_t>::failure(
          archive_error("read entry header", archive_path, reader.get()));
    ++entry_total;
    if (entry_total > options.maximum_archive_entries) {
      return Result<std::uint64_t>::failure(
          archive_error("enforce archive entry limit", archive_path, reader.get()));
    }
    if (archive_entry_filetype(entry) != AE_IFREG) {
      archive_read_data_skip(reader.get());
      continue;
    }
    const char* raw_name = archive_entry_pathname_utf8(entry);
    if (!raw_name)
      raw_name = archive_entry_pathname(entry);
    const std::filesystem::path entry_name =
        raw_name ? std::filesystem::path(raw_name) : std::filesystem::path("unnamed-entry");
    const auto declared_size = archive_entry_size(entry);
    if (declared_size > 0 &&
        static_cast<std::uint64_t>(declared_size) >
            options.maximum_archive_expanded_bytes -
                std::min(expanded_total, options.maximum_archive_expanded_bytes)) {
      return Result<std::uint64_t>::failure(
          archive_error("enforce expansion limit", archive_path, reader.get()));
    }

    // SAT-SEC-03: this file receives decompressed customer log content. Create it exclusively
    // with owner-only permissions in the SAT-owned per-user temporary directory rather than
    // opening a predictable path in the shared system temporary root with std::ofstream, which
    // neither requests exclusive creation nor refuses to follow a pre-created symlink.
    auto temporary_file = create_secure_temp_file("support-assist-archive", ".tmp");
    if (!temporary_file.ok())
      return Result<std::uint64_t>::failure(temporary_file.error());
    const auto temporary = temporary_file.value().path();
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output)
      return Result<std::uint64_t>::failure(
          archive_error("create temporary entry", archive_path, reader.get()));
    std::vector<char> buffer(128U * 1024U);
    for (;;) {
      const la_ssize_t read = archive_read_data(reader.get(), buffer.data(), buffer.size());
      if (read == 0)
        break;
      if (read < 0) {
        output.close();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return Result<std::uint64_t>::failure(
            archive_error("read entry data", archive_path, reader.get()));
      }
      expanded_total += static_cast<std::uint64_t>(read);
      if (expanded_total > options.maximum_archive_expanded_bytes) {
        output.close();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return Result<std::uint64_t>::failure(
            archive_error("enforce expansion limit", archive_path, reader.get()));
      }
      output.write(buffer.data(), read);
      if (!output) {
        output.close();
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        return Result<std::uint64_t>::failure(
            archive_error("write temporary entry", archive_path, reader.get()));
      }
    }
    output.close();

    const std::string display = std::string(display_prefix) + "!" + support_assist::generic_path_to_utf8(entry_name);
    Result<std::uint64_t> searched = Result<std::uint64_t>::success(0);
    if (options.search_archives && is_archive_path(entry_name) &&
        depth < options.maximum_archive_depth) {
      searched = search_archive(
          temporary, display, options, cancel, callback, depth + 1, expanded_total, entry_total);
    } else if (path_allowed(options, entry_name)) {
      searched = search_file(temporary, options, cancel, callback, display);
    }
    std::error_code ignored;
    std::filesystem::remove(temporary, ignored);
    if (!searched.ok())
      return searched;
    matches += searched.value();
    if (matches >= options.maximum_results)
      break;
  }
  return Result<std::uint64_t>::success(matches);
}
#endif
} // namespace
Result<std::uint64_t> search_logs(const LogSearchOptions& o,
                                  const CancellationToken& cancel,
                                  ProgressCallback progress,
                                  const LogMatchCallback& cb) {
  auto start = std::chrono::steady_clock::now();
  std::vector<std::filesystem::path> files;
  for (const auto& s : o.sources) {
    std::error_code ec;
    if (std::filesystem::is_regular_file(s, ec)) {
      if (path_allowed(o, s) || (o.search_archives && is_archive_path(s)))
        files.push_back(s);
    } else if (std::filesystem::is_directory(s, ec)) {
      if (o.recursive) {
        for (std::filesystem::recursive_directory_iterator
                 it(s, std::filesystem::directory_options::skip_permission_denied, ec),
             end;
             it != end;
             it.increment(ec)) {
          if (cancel.is_cancelled())
            break;
          if (ec) {
            ec.clear();
            continue;
          }
          if (it->is_regular_file(ec) &&
              (path_allowed(o, it->path()) || (o.search_archives && is_archive_path(it->path()))))
            files.push_back(it->path());
        }
      } else {
        for (std::filesystem::directory_iterator
                 it(s, std::filesystem::directory_options::skip_permission_denied, ec),
             end;
             it != end;
             it.increment(ec))
          if (!ec && it->is_regular_file(ec) &&
              (path_allowed(o, it->path()) || (o.search_archives && is_archive_path(it->path()))))
            files.push_back(it->path());
      }
    }
  }
  std::uint64_t total = 0, errors = 0, done = 0;
  for (const auto& f : files) {
    if (cancel.is_cancelled())
      break;
    Result<std::uint64_t> r = Result<std::uint64_t>::success(0);
#ifdef SUPPORT_ASSIST_HAS_LIBARCHIVE
    if (o.search_archives && is_archive_path(f)) {
      std::uint64_t expanded = 0, entries = 0;
      r = search_archive(f, path_to_utf8(f), o, cancel, cb, 1, expanded, entries);
    } else
      r = search_file(f, o, cancel, cb);
#else
    r = search_file(f, o, cancel, cb);
#endif
    if (r.ok())
      total += r.value();
    else
      ++errors;
    ++done;
    if (progress) {
      auto elapsed =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
      progress(ProgressEvent{"log-search",
                             path_to_utf8(f),
                             done,
                             errors,
                             elapsed,
                             elapsed > 0 ? static_cast<double>(done) / elapsed : 0});
    }
    if (total >= o.maximum_results)
      break;
  }
  return Result<std::uint64_t>::success(total);
}
std::vector<std::filesystem::path> discover_veeam_sources() {
  std::vector<std::filesystem::path> out;
#ifdef _WIN32
  wchar_t* program_data = nullptr;
  std::size_t program_data_length = 0;
  const errno_t environment_result =
      _wdupenv_s(&program_data, &program_data_length, L"PROGRAMDATA");
  if (environment_result == 0 && program_data != nullptr) {
    const std::filesystem::path base(program_data);
    out.emplace_back(base / L"Veeam");
    out.emplace_back(base / L"Veeam Endpoint Backup");
  }
  std::free(program_data);
#endif
  return out;
}
} // namespace support_assist
