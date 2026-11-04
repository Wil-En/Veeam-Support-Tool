#pragma once

// A small JSON reader for SAT's own data files (config/checks/*.json, embedded at build time):
// strict RFC 8259 syntax, UTF-8 in and out, numbers read without the C locale (Qt sets it on
// Linux), and a nesting limit so a damaged file cannot exhaust the stack.

#include "support_assist/error.hpp"

#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

class JsonValue {
public:
  enum class Kind { null, boolean, number, string, array, object };

  JsonValue() = default;

  [[nodiscard]] Kind kind() const { return kind_; }
  [[nodiscard]] bool is_null() const { return kind_ == Kind::null; }
  [[nodiscard]] bool is_object() const { return kind_ == Kind::object; }
  [[nodiscard]] bool is_array() const { return kind_ == Kind::array; }
  [[nodiscard]] bool is_string() const { return kind_ == Kind::string; }
  [[nodiscard]] bool is_number() const { return kind_ == Kind::number; }
  [[nodiscard]] bool is_bool() const { return kind_ == Kind::boolean; }

  // Typed reads that fall back when the value is of another kind or absent.
  [[nodiscard]] std::string as_string(std::string fallback = {}) const;
  [[nodiscard]] double as_number(double fallback = 0.0) const;
  [[nodiscard]] bool as_bool(bool fallback = false) const;

  // Object member by key; a null value when absent or when this is not an object.
  [[nodiscard]] const JsonValue& operator[](std::string_view key) const;
  [[nodiscard]] bool has(std::string_view key) const;
  [[nodiscard]] const std::vector<std::pair<std::string, JsonValue>>& members() const;
  // Array items; empty when this is not an array.
  [[nodiscard]] const std::vector<JsonValue>& items() const;
  // A string array, skipping items of other kinds.
  [[nodiscard]] std::vector<std::string> string_items() const;

  static JsonValue make_null() { return JsonValue(); }
  static JsonValue make_bool(bool value);
  static JsonValue make_number(double value);
  static JsonValue make_string(std::string value);
  static JsonValue make_array(std::vector<JsonValue> items);
  static JsonValue make_object(std::vector<std::pair<std::string, JsonValue>> members);

private:
  Kind kind_ = Kind::null;
  bool boolean_ = false;
  double number_ = 0.0;
  std::string string_;
  std::shared_ptr<std::vector<JsonValue>> items_;
  std::shared_ptr<std::vector<std::pair<std::string, JsonValue>>> members_;
};

// Parses a whole document. The error names the byte offset of the first problem.
Result<JsonValue> parse_json(std::string_view text);

} // namespace support_assist
