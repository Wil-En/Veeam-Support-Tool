// Pending restart, the parts every platform shares: version order, the rename list, and the event
// XML readers.
#include "support_assist/pending_restart.hpp"

#include "support_assist/strings.hpp"

#include <cctype>

namespace support_assist {
namespace restart_detail {
namespace {

bool is_digit(char c) { return c >= '0' && c <= '9'; }
bool is_letter(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }

std::string xml_unescape(std::string_view text) {
  std::string out;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] != '&') {
      out += text[i];
      continue;
    }
    const std::size_t end = text.find(';', i);
    if (end == std::string_view::npos) {
      out += text[i];
      continue;
    }
    const std::string_view entity = text.substr(i + 1, end - i - 1);
    if (entity == "amp")
      out += '&';
    else if (entity == "lt")
      out += '<';
    else if (entity == "gt")
      out += '>';
    else if (entity == "quot")
      out += '"';
    else if (entity == "apos")
      out += '\'';
    else {
      out += text.substr(i, end - i + 1);
    }
    i = end;
  }
  return out;
}

} // namespace

int compare_versions(std::string_view a, std::string_view b) {
  std::size_t i = 0;
  std::size_t j = 0;
  for (;;) {
    while (i < a.size() && !is_digit(a[i]) && !is_letter(a[i]))
      ++i;
    while (j < b.size() && !is_digit(b[j]) && !is_letter(b[j]))
      ++j;
    if (i >= a.size() || j >= b.size())
      break;
    const bool numeric = is_digit(a[i]);
    if (numeric != is_digit(b[j]))
      return numeric ? 1 : -1; // a number sorts after letters
    std::size_t i_end = i;
    std::size_t j_end = j;
    while (i_end < a.size() && (numeric ? is_digit(a[i_end]) : is_letter(a[i_end])))
      ++i_end;
    while (j_end < b.size() && (numeric ? is_digit(b[j_end]) : is_letter(b[j_end])))
      ++j_end;
    std::string_view left = a.substr(i, i_end - i);
    std::string_view right = b.substr(j, j_end - j);
    if (numeric) {
      while (left.size() > 1 && left.front() == '0')
        left.remove_prefix(1);
      while (right.size() > 1 && right.front() == '0')
        right.remove_prefix(1);
      if (left.size() != right.size())
        return left.size() < right.size() ? -1 : 1;
    }
    if (const int order = left.compare(right); order != 0)
      return order < 0 ? -1 : 1;
    i = i_end;
    j = j_end;
  }
  const bool a_left = i < a.size();
  const bool b_left = j < b.size();
  return a_left == b_left ? 0 : (a_left ? 1 : -1);
}

std::string newest_version(const std::vector<std::string>& versions) {
  std::string newest;
  for (const std::string& version : versions) {
    if (newest.empty() || compare_versions(version, newest) > 0)
      newest = version;
  }
  return newest;
}

std::vector<std::pair<std::string, std::string>> rename_pairs(const std::vector<std::string>& values) {
  // Windows prefixes an entry with flags: "!" (replace) and "*" with a number, before "\??\".
  const auto clean = [](std::string text) {
    while (!text.empty() && (text.front() == '!' || text.front() == '*')) {
      std::size_t end = 1;
      if (text.front() == '*') {
        while (end < text.size() && is_digit(text[end]))
          ++end;
      }
      text.erase(0, end);
    }
    if (text.rfind("\\??\\", 0) == 0)
      text.erase(0, 4);
    return text;
  };
  std::vector<std::pair<std::string, std::string>> pairs;
  for (std::size_t i = 0; i < values.size(); i += 2) {
    const std::string source = clean(values[i]);
    const std::string target = i + 1 < values.size() ? clean(values[i + 1]) : std::string();
    if (!source.empty())
      pairs.emplace_back(source, target);
  }
  return pairs;
}

std::string event_value(std::string_view xml, std::string_view name) {
  for (const char quote : {'\'', '"'}) {
    const std::string attribute = "<Data Name=" + std::string(1, quote) + std::string(name) + std::string(1, quote) + ">";
    const std::size_t at = xml.find(attribute);
    if (at != std::string_view::npos) {
      const std::size_t start = at + attribute.size();
      const std::size_t end = xml.find("</Data>", start);
      if (end != std::string_view::npos)
        return xml_unescape(xml.substr(start, end - start));
    }
  }
  const std::string open = "<" + std::string(name) + ">";
  const std::size_t at = xml.find(open);
  if (at == std::string_view::npos)
    return {};
  const std::size_t start = at + open.size();
  const std::size_t end = xml.find("</" + std::string(name) + ">", start);
  return end == std::string_view::npos ? std::string() : xml_unescape(xml.substr(start, end - start));
}

std::vector<std::string> event_data(std::string_view xml) {
  std::vector<std::string> values;
  std::size_t at = 0;
  while ((at = xml.find("<Data", at)) != std::string_view::npos) {
    const std::size_t close = xml.find('>', at);
    if (close == std::string_view::npos)
      break;
    if (xml[close - 1] == '/') { // <Data/>
      values.emplace_back();
      at = close + 1;
      continue;
    }
    const std::size_t end = xml.find("</Data>", close);
    if (end == std::string_view::npos)
      break;
    values.push_back(xml_unescape(xml.substr(close + 1, end - close - 1)));
    at = end + 7;
  }
  return values;
}

} // namespace restart_detail
} // namespace support_assist
