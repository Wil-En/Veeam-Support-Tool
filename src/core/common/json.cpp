// JSON reader for SAT's data files: recursive descent over the whole text, with a depth limit.
#include "support_assist/json.hpp"

#include <charconv>
#include <cstdint>

namespace support_assist {
namespace {

constexpr int kMaxDepth = 64;

const JsonValue& null_value() {
  static const JsonValue value;
  return value;
}

const std::vector<JsonValue>& no_items() {
  static const std::vector<JsonValue> items;
  return items;
}

const std::vector<std::pair<std::string, JsonValue>>& no_members() {
  static const std::vector<std::pair<std::string, JsonValue>> members;
  return members;
}

void append_utf8(std::string& out, std::uint32_t code) {
  if (code < 0x80) {
    out += static_cast<char>(code);
  } else if (code < 0x800) {
    out += static_cast<char>(0xC0U | (code >> 6U));
    out += static_cast<char>(0x80U | (code & 0x3FU));
  } else if (code < 0x10000) {
    out += static_cast<char>(0xE0U | (code >> 12U));
    out += static_cast<char>(0x80U | ((code >> 6U) & 0x3FU));
    out += static_cast<char>(0x80U | (code & 0x3FU));
  } else {
    out += static_cast<char>(0xF0U | (code >> 18U));
    out += static_cast<char>(0x80U | ((code >> 12U) & 0x3FU));
    out += static_cast<char>(0x80U | ((code >> 6U) & 0x3FU));
    out += static_cast<char>(0x80U | (code & 0x3FU));
  }
}

class Parser {
public:
  explicit Parser(std::string_view text) : text_(text) {}

  Result<JsonValue> document() {
    skip_space();
    JsonValue value;
    if (!parse_value(value, 0))
      return failure();
    skip_space();
    if (at_ != text_.size()) {
      message_ = "text after the end of the document";
      return failure();
    }
    return Result<JsonValue>::success(std::move(value));
  }

private:
  Result<JsonValue> failure() const {
    Error error;
    error.component = "data";
    error.operation = "read JSON";
    error.message = message_ + " at byte " + std::to_string(at_);
    return Result<JsonValue>::failure(error);
  }

  void skip_space() {
    while (at_ < text_.size() && (text_[at_] == ' ' || text_[at_] == '\t' || text_[at_] == '\n' || text_[at_] == '\r'))
      ++at_;
  }

  bool literal(std::string_view word) {
    if (text_.substr(at_, word.size()) != word) {
      message_ = "an unknown word";
      return false;
    }
    at_ += word.size();
    return true;
  }

  bool parse_value(JsonValue& value, int depth) {
    if (depth > kMaxDepth) {
      message_ = "nesting deeper than " + std::to_string(kMaxDepth);
      return false;
    }
    if (at_ >= text_.size()) {
      message_ = "the document ends early";
      return false;
    }
    const char c = text_[at_];
    if (c == '{')
      return parse_object(value, depth);
    if (c == '[')
      return parse_array(value, depth);
    if (c == '"') {
      std::string text;
      if (!parse_string(text))
        return false;
      value = JsonValue::make_string(std::move(text));
      return true;
    }
    if (c == 't') {
      value = JsonValue::make_bool(true);
      return literal("true");
    }
    if (c == 'f') {
      value = JsonValue::make_bool(false);
      return literal("false");
    }
    if (c == 'n') {
      value = JsonValue::make_null();
      return literal("null");
    }
    return parse_number(value);
  }

  bool parse_object(JsonValue& value, int depth) {
    ++at_; // {
    std::vector<std::pair<std::string, JsonValue>> members;
    skip_space();
    if (at_ < text_.size() && text_[at_] == '}') {
      ++at_;
      value = JsonValue::make_object(std::move(members));
      return true;
    }
    for (;;) {
      skip_space();
      if (at_ >= text_.size() || text_[at_] != '"') {
        message_ = "a member name was expected";
        return false;
      }
      std::string key;
      if (!parse_string(key))
        return false;
      skip_space();
      if (at_ >= text_.size() || text_[at_] != ':') {
        message_ = "':' was expected";
        return false;
      }
      ++at_;
      skip_space();
      JsonValue member;
      if (!parse_value(member, depth + 1))
        return false;
      members.emplace_back(std::move(key), std::move(member));
      skip_space();
      if (at_ < text_.size() && text_[at_] == ',') {
        ++at_;
        continue;
      }
      if (at_ < text_.size() && text_[at_] == '}') {
        ++at_;
        value = JsonValue::make_object(std::move(members));
        return true;
      }
      message_ = "',' or '}' was expected";
      return false;
    }
  }

  bool parse_array(JsonValue& value, int depth) {
    ++at_; // [
    std::vector<JsonValue> items;
    skip_space();
    if (at_ < text_.size() && text_[at_] == ']') {
      ++at_;
      value = JsonValue::make_array(std::move(items));
      return true;
    }
    for (;;) {
      skip_space();
      JsonValue item;
      if (!parse_value(item, depth + 1))
        return false;
      items.push_back(std::move(item));
      skip_space();
      if (at_ < text_.size() && text_[at_] == ',') {
        ++at_;
        continue;
      }
      if (at_ < text_.size() && text_[at_] == ']') {
        ++at_;
        value = JsonValue::make_array(std::move(items));
        return true;
      }
      message_ = "',' or ']' was expected";
      return false;
    }
  }

  bool hex4(std::uint32_t& code) {
    if (at_ + 4 > text_.size()) {
      message_ = "a \\u escape ends early";
      return false;
    }
    code = 0;
    for (int i = 0; i < 4; ++i) {
      const char c = text_[at_++];
      code <<= 4U;
      if (c >= '0' && c <= '9')
        code |= static_cast<std::uint32_t>(c - '0');
      else if (c >= 'a' && c <= 'f')
        code |= static_cast<std::uint32_t>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        code |= static_cast<std::uint32_t>(c - 'A' + 10);
      else {
        message_ = "a \\u escape holds a character that is not hexadecimal";
        return false;
      }
    }
    return true;
  }

  bool parse_string(std::string& out) {
    ++at_; // opening quote
    while (at_ < text_.size()) {
      const char c = text_[at_++];
      if (c == '"')
        return true;
      if (static_cast<unsigned char>(c) < 0x20) {
        message_ = "a control character inside a string";
        return false;
      }
      if (c != '\\') {
        out += c;
        continue;
      }
      if (at_ >= text_.size())
        break;
      const char escape = text_[at_++];
      switch (escape) {
      case '"': out += '"'; break;
      case '\\': out += '\\'; break;
      case '/': out += '/'; break;
      case 'b': out += '\b'; break;
      case 'f': out += '\f'; break;
      case 'n': out += '\n'; break;
      case 'r': out += '\r'; break;
      case 't': out += '\t'; break;
      case 'u': {
        std::uint32_t code = 0;
        if (!hex4(code))
          return false;
        if (code >= 0xD800 && code <= 0xDBFF) {
          std::uint32_t low = 0;
          if (at_ + 2 > text_.size() || text_[at_] != '\\' || text_[at_ + 1] != 'u') {
            message_ = "a surrogate pair is incomplete";
            return false;
          }
          at_ += 2;
          if (!hex4(low) || low < 0xDC00 || low > 0xDFFF) {
            message_ = "a surrogate pair is incomplete";
            return false;
          }
          code = 0x10000U + ((code - 0xD800U) << 10U) + (low - 0xDC00U);
        } else if (code >= 0xDC00 && code <= 0xDFFF) {
          message_ = "a lone surrogate";
          return false;
        }
        append_utf8(out, code);
        break;
      }
      default:
        message_ = "an unknown escape";
        return false;
      }
    }
    message_ = "a string is not closed";
    return false;
  }

  bool parse_number(JsonValue& value) {
    const std::size_t start = at_;
    if (at_ < text_.size() && text_[at_] == '-')
      ++at_;
    if (at_ >= text_.size() || text_[at_] < '0' || text_[at_] > '9') {
      message_ = "a value was expected";
      return false;
    }
    if (text_[at_] == '0') {
      ++at_;
    } else {
      while (at_ < text_.size() && text_[at_] >= '0' && text_[at_] <= '9')
        ++at_;
    }
    if (at_ < text_.size() && text_[at_] == '.') {
      ++at_;
      const std::size_t digits = at_;
      while (at_ < text_.size() && text_[at_] >= '0' && text_[at_] <= '9')
        ++at_;
      if (at_ == digits) {
        message_ = "a number has no digits after its point";
        return false;
      }
    }
    if (at_ < text_.size() && (text_[at_] == 'e' || text_[at_] == 'E')) {
      ++at_;
      if (at_ < text_.size() && (text_[at_] == '+' || text_[at_] == '-'))
        ++at_;
      const std::size_t digits = at_;
      while (at_ < text_.size() && text_[at_] >= '0' && text_[at_] <= '9')
        ++at_;
      if (at_ == digits) {
        message_ = "a number has no exponent digits";
        return false;
      }
    }
    double number = 0.0;
    const auto converted = std::from_chars(text_.data() + start, text_.data() + at_, number);
    if (converted.ec != std::errc() || converted.ptr != text_.data() + at_) {
      message_ = "a number could not be read";
      return false;
    }
    value = JsonValue::make_number(number);
    return true;
  }

  std::string_view text_;
  std::size_t at_ = 0;
  std::string message_;
};

} // namespace

JsonValue JsonValue::make_bool(bool value) {
  JsonValue json;
  json.kind_ = Kind::boolean;
  json.boolean_ = value;
  return json;
}

JsonValue JsonValue::make_number(double value) {
  JsonValue json;
  json.kind_ = Kind::number;
  json.number_ = value;
  return json;
}

JsonValue JsonValue::make_string(std::string value) {
  JsonValue json;
  json.kind_ = Kind::string;
  json.string_ = std::move(value);
  return json;
}

JsonValue JsonValue::make_array(std::vector<JsonValue> items) {
  JsonValue json;
  json.kind_ = Kind::array;
  json.items_ = std::make_shared<std::vector<JsonValue>>(std::move(items));
  return json;
}

JsonValue JsonValue::make_object(std::vector<std::pair<std::string, JsonValue>> members) {
  JsonValue json;
  json.kind_ = Kind::object;
  json.members_ = std::make_shared<std::vector<std::pair<std::string, JsonValue>>>(std::move(members));
  return json;
}

std::string JsonValue::as_string(std::string fallback) const {
  return kind_ == Kind::string ? string_ : fallback;
}

double JsonValue::as_number(double fallback) const {
  return kind_ == Kind::number ? number_ : fallback;
}

bool JsonValue::as_bool(bool fallback) const {
  return kind_ == Kind::boolean ? boolean_ : fallback;
}

const JsonValue& JsonValue::operator[](std::string_view key) const {
  if (kind_ != Kind::object || !members_)
    return null_value();
  for (const auto& [name, value] : *members_) {
    if (name == key)
      return value;
  }
  return null_value();
}

bool JsonValue::has(std::string_view key) const {
  if (kind_ != Kind::object || !members_)
    return false;
  for (const auto& member : *members_) {
    if (member.first == key)
      return true;
  }
  return false;
}

const std::vector<std::pair<std::string, JsonValue>>& JsonValue::members() const {
  return kind_ == Kind::object && members_ ? *members_ : no_members();
}

const std::vector<JsonValue>& JsonValue::items() const {
  return kind_ == Kind::array && items_ ? *items_ : no_items();
}

std::vector<std::string> JsonValue::string_items() const {
  std::vector<std::string> values;
  for (const JsonValue& item : items()) {
    if (item.is_string())
      values.push_back(item.as_string());
  }
  return values;
}

Result<JsonValue> parse_json(std::string_view text) {
  // A UTF-8 byte order mark, as some editors save one, is not part of the document.
  if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF && static_cast<unsigned char>(text[1]) == 0xBB &&
      static_cast<unsigned char>(text[2]) == 0xBF)
    text.remove_prefix(3);
  return Parser(text).document();
}

} // namespace support_assist
