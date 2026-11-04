#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace support_assist {
enum class Severity { info, warning, error, fatal };

struct Error {
  std::string component;
  std::string operation;
  std::string source;
  std::int64_t native_code = 0;
  std::int64_t hresult = 0;
  int sqlite_code = 0;
  std::string message;
  Severity severity = Severity::error;
  bool recoverable = false;
  bool elevation_may_help = false;
  bool skipped = false;
  std::string timestamp_utc;
  std::string correlation_id;
};

std::string to_string(Severity value);
std::string describe_error(const Error& error);

class Status {
public:
  Status() = default;
  static Status success() {
    return Status();
  }
  static Status failure(Error error) {
    return Status(std::move(error));
  }
  [[nodiscard]] bool ok() const noexcept {
    return !error_.has_value();
  }
  [[nodiscard]] const Error& error() const {
    return error_.value();
  }

private:
  explicit Status(Error error) : error_(std::move(error)) {}
  std::optional<Error> error_;
};

template <typename T> class Result {
public:
  static Result success(T value) {
    return Result(std::move(value));
  }
  static Result failure(Error error) {
    return Result(std::move(error));
  }
  [[nodiscard]] bool ok() const noexcept {
    return std::holds_alternative<T>(data_);
  }
  [[nodiscard]] T& value() {
    return std::get<T>(data_);
  }
  [[nodiscard]] const T& value() const {
    return std::get<T>(data_);
  }
  [[nodiscard]] Error& error() {
    return std::get<Error>(data_);
  }
  [[nodiscard]] const Error& error() const {
    return std::get<Error>(data_);
  }

private:
  explicit Result(T value) : data_(std::move(value)) {}
  explicit Result(Error error) : data_(std::move(error)) {}
  std::variant<T, Error> data_;
};
} // namespace support_assist
