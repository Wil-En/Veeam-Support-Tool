#include "support_assist/case_report.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string_view>

namespace support_assist {
namespace {
Error report_error(const std::filesystem::path& path, std::string message) {
  Error error;
  error.operation = "write case PDF report";
  error.component = "CaseReport";
  error.source = path_to_utf8(path);
  error.message = std::move(message);
  return error;
}

std::string pdf_escape(std::string_view input) {
  std::string out;
  out.reserve(input.size() + 16U);
  for (unsigned char ch : input) {
    if (ch == '\\' || ch == '(' || ch == ')') {
      out.push_back('\\');
      out.push_back(static_cast<char>(ch));
    } else if (ch == '\r' || ch == '\n' || ch == '\t') {
      out.push_back(' ');
    } else if (ch >= 32U && ch < 127U) {
      out.push_back(static_cast<char>(ch));
    } else {
      // Base Helvetica cannot safely render UTF-8. Preserve layout and avoid
      // emitting malformed strings; source paths remain readable for normal
      // Windows/ASCII case data and unsupported glyphs become '?'.
      out.push_back('?');
    }
  }
  return out;
}

std::vector<std::string> wrap_line(std::string_view line, std::size_t width) {
  if (line.empty())
    return {std::string{}};
  std::vector<std::string> wrapped;
  std::string remaining(line);
  while (remaining.size() > width) {
    std::size_t split = remaining.rfind(' ', width);
    if (split == std::string::npos || split < width / 3U)
      split = width;
    wrapped.push_back(remaining.substr(0, split));
    std::size_t next = split;
    while (next < remaining.size() && remaining[next] == ' ')
      ++next;
    remaining.erase(0, next);
  }
  wrapped.push_back(std::move(remaining));
  return wrapped;
}

struct PageText {
  std::vector<std::pair<bool, std::string>> lines; // bold, text
};

std::vector<PageText> paginate(const PdfReportDocument& document) {
  constexpr std::size_t kBodyWidth = 92;
  constexpr std::size_t kLinesPerPage = 49;
  std::vector<PageText> pages(1);
  auto push = [&](bool bold, std::string text) {
    if (pages.back().lines.size() >= kLinesPerPage)
      pages.emplace_back();
    pages.back().lines.emplace_back(bold, std::move(text));
  };

  push(true, document.title.empty() ? "Support Assist Tool Case Report" : document.title);
  if (!document.subtitle.empty())
    push(false, document.subtitle);
  push(false, "");
  for (const auto& section : document.sections) {
    if (!pages.back().lines.empty() && pages.back().lines.size() + 3U >= kLinesPerPage)
      pages.emplace_back();
    push(true, section.heading);
    if (section.lines.empty())
      push(false, "No retained evidence for this section.");
    for (const auto& line : section.lines) {
      for (auto& wrapped : wrap_line(line, kBodyWidth))
        push(false, std::move(wrapped));
    }
    push(false, "");
  }
  return pages;
}
} // namespace

Status write_pdf_report(const std::filesystem::path& output_path,
                        const PdfReportDocument& document) {
  if (output_path.empty())
    return Status::failure(report_error(output_path, "Output path is empty"));

  std::error_code error;
  if (!output_path.parent_path().empty())
    std::filesystem::create_directories(output_path.parent_path(), error);
  if (error)
    return Status::failure(report_error(output_path, error.message()));

  const auto pages = paginate(document);
  const int page_count = static_cast<int>(pages.size());
  // Object layout: 1 catalog, 2 pages root, 3 regular font, 4 bold font,
  // then two objects per page: page + content.
  const int first_page_object = 5;
  const int object_count = 4 + page_count * 2;
  std::vector<std::string> objects(static_cast<std::size_t>(object_count + 1));
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";

  std::ostringstream kids;
  kids << "[";
  for (int index = 0; index < page_count; ++index)
    kids << ' ' << (first_page_object + index * 2) << " 0 R";
  kids << " ]";
  objects[2] = "<< /Type /Pages /Count " + std::to_string(page_count) + " /Kids " + kids.str() + " >>";
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";
  objects[4] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>";

  for (int page_index = 0; page_index < page_count; ++page_index) {
    const int page_object = first_page_object + page_index * 2;
    const int content_object = page_object + 1;
    std::ostringstream stream;
    stream << "BT\n/F1 9 Tf\n54 742 Td\n12 TL\n";
    bool current_bold = false;
    for (const auto& [bold, text] : pages[static_cast<std::size_t>(page_index)].lines) {
      if (bold != current_bold) {
        stream << (bold ? "/F2 10 Tf\n" : "/F1 9 Tf\n");
        current_bold = bold;
      }
      stream << '(' << pdf_escape(text) << ") Tj\n0 -12 Td\n";
    }
    stream << "ET\n";
    const std::string body = stream.str();
    objects[content_object] = "<< /Length " + std::to_string(body.size()) + " >>\nstream\n" + body + "endstream";
    objects[page_object] =
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        "/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents " +
        std::to_string(content_object) + " 0 R >>";
  }

  std::ofstream output(output_path, std::ios::binary | std::ios::trunc);
  if (!output)
    return Status::failure(report_error(output_path, "Could not create PDF file"));
  output << "%PDF-1.4\n%SAT\n";
  std::vector<std::streamoff> offsets(static_cast<std::size_t>(object_count + 1), 0);
  for (int object = 1; object <= object_count; ++object) {
    offsets[static_cast<std::size_t>(object)] = output.tellp();
    output << object << " 0 obj\n" << objects[static_cast<std::size_t>(object)] << "\nendobj\n";
  }
  const std::streamoff xref = output.tellp();
  output << "xref\n0 " << (object_count + 1) << "\n";
  output << "0000000000 65535 f \n";
  for (int object = 1; object <= object_count; ++object)
    output << std::setw(10) << std::setfill('0') << offsets[static_cast<std::size_t>(object)] << " 00000 n \n";
  output << "trailer\n<< /Size " << (object_count + 1) << " /Root 1 0 R >>\nstartxref\n"
         << xref << "\n%%EOF\n";
  if (!output)
    return Status::failure(report_error(output_path, "Failed while writing PDF file"));
  return Status::success();
}

} // namespace support_assist
