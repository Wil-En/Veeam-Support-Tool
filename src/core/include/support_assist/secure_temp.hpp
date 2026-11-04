#pragma once

// SAT-SEC-03 / SAT-SEC-05: security primitives for temporary files and randomness.
//
// SAT extracts customer log content out of case bundles into temporary files. Before 0.4.x-dev.7
// those files were created with std::ofstream at a path under the shared system temporary
// directory. That has two problems on a multi-user Linux or macOS host:
//
//   * std::ofstream does not request exclusive creation and follows an existing symlink, so a
//     pre-created link at the target path redirects the write;
//   * the file inherits the process umask, which commonly leaves customer log content
//     world-readable.
//
// These helpers create temporary files with O_CREAT | O_EXCL | O_NOFOLLOW and mode 0600 on POSIX,
// and CREATE_NEW with an owner-only DACL on Windows.

#include "support_assist/error.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// Cryptographically secure random bytes from the operating system. Fails rather than falling back
// to a weaker source. Use this for security tokens; make_uuid_v4() remains appropriate for
// non-security identifiers.
Result<std::vector<std::uint8_t>> secure_random_bytes(std::size_t count);

// Lowercase hexadecimal encoding of secure_random_bytes(byte_count).
Result<std::string> secure_random_hex(std::size_t byte_count);

// A temporary file that is removed when the object is destroyed unless release() is called.
class SecureTempFile {
public:
  SecureTempFile() = default;
  explicit SecureTempFile(std::filesystem::path path) : path_(std::move(path)), owned_(true) {}
  SecureTempFile(const SecureTempFile&) = delete;
  SecureTempFile& operator=(const SecureTempFile&) = delete;
  SecureTempFile(SecureTempFile&& other) noexcept { *this = std::move(other); }
  SecureTempFile& operator=(SecureTempFile&& other) noexcept {
    if (this != &other) {
      reset();
      path_ = std::move(other.path_);
      owned_ = other.owned_;
      other.owned_ = false;
    }
    return *this;
  }
  ~SecureTempFile() { reset(); }

  [[nodiscard]] const std::filesystem::path& path() const { return path_; }
  [[nodiscard]] bool valid() const { return owned_ && !path_.empty(); }

  // Stop owning the file so it survives destruction.
  std::filesystem::path release() {
    owned_ = false;
    return path_;
  }

  // Delete the file now, if still owned.
  void reset();

private:
  std::filesystem::path path_;
  bool owned_ = false;
};

// Create an empty temporary file that only the current user can read or write.
// `prefix` and `extension` are sanitised; the unpredictable component is generated internally.
// When `directory` is empty a SAT-owned per-user directory under the system temporary directory
// is used in preference to the shared temporary root.
Result<SecureTempFile> create_secure_temp_file(std::string_view prefix,
                                               std::string_view extension = ".tmp",
                                               const std::filesystem::path& directory = {});

// The SAT-owned per-user temporary directory, created with owner-only permissions on demand.
Result<std::filesystem::path> secure_temp_directory();

} // namespace support_assist
