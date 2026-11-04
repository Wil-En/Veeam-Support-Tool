#include "support_assist/filesystem.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"

#include <openssl/evp.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <vector>

namespace support_assist {
namespace {

Error hash_error(std::string operation,
                 const std::filesystem::path& path,
                 std::int64_t code,
                 std::string message) {
  Error error;
  error.component = "Hash";
  error.operation = std::move(operation);
  error.source = path.string();
  error.native_code = code;
  error.message = std::move(message);
  error.recoverable = true;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

struct FileCloser {
  void operator()(std::FILE* file) const noexcept {
    if (file != nullptr)
      std::fclose(file);
  }
};

struct DigestCloser {
  void operator()(EVP_MD_CTX* context) const noexcept {
    if (context != nullptr)
      EVP_MD_CTX_free(context);
  }
};

} // namespace

Result<std::string> hash_file_sha256(const std::filesystem::path& path,
                                     const CancellationToken& cancel) {
  // Opened non-blocking and checked on the descriptor itself: a FIFO or a device would otherwise
  // hold the read open with no way to cancel it, and a check made on the path before opening can be
  // raced by swapping the file.
  const int descriptor = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
  if (descriptor < 0) {
    return Result<std::string>::failure(
        hash_error("open file", path, errno, "Could not open file for SHA-256 hashing"));
  }
  struct stat details {};
  if (::fstat(descriptor, &details) != 0 || !S_ISREG(details.st_mode)) {
    const int code = errno;
    ::close(descriptor);
    return Result<std::string>::failure(
        hash_error("open file", path, code, "Only a regular file can be hashed"));
  }
  const int flags = ::fcntl(descriptor, F_GETFL);
  if (flags >= 0)
    static_cast<void>(::fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK));
  std::unique_ptr<std::FILE, FileCloser> file(::fdopen(descriptor, "rb"));
  if (!file) {
    const int code = errno;
    ::close(descriptor);
    return Result<std::string>::failure(
        hash_error("open file", path, code, "Could not open file for SHA-256 hashing"));
  }

  std::unique_ptr<EVP_MD_CTX, DigestCloser> digest(EVP_MD_CTX_new());
  if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1) {
    return Result<std::string>::failure(
        hash_error("initialize SHA-256", path, 0, "OpenSSL could not initialize SHA-256"));
  }

  std::vector<unsigned char> buffer(1024U * 1024U);
  for (;;) {
    if (cancel.is_cancelled()) {
      return Result<std::string>::failure(
          hash_error("hash cancelled", path, ECANCELED, "SHA-256 hashing was cancelled"));
    }
    const std::size_t read = std::fread(buffer.data(), 1U, buffer.size(), file.get());
    if (read != 0U && EVP_DigestUpdate(digest.get(), buffer.data(), read) != 1) {
      return Result<std::string>::failure(
          hash_error("update SHA-256", path, 0, "OpenSSL could not update SHA-256"));
    }
    if (read < buffer.size()) {
      if (std::ferror(file.get()) != 0) {
        return Result<std::string>::failure(
            hash_error("read file", path, errno, "Could not read file for SHA-256 hashing"));
      }
      break;
    }
  }

  std::array<unsigned char, EVP_MAX_MD_SIZE> output{};
  unsigned int length = 0;
  if (EVP_DigestFinal_ex(digest.get(), output.data(), &length) != 1 || length != 32U) {
    return Result<std::string>::failure(
        hash_error("finish SHA-256", path, 0, "OpenSSL could not finalize SHA-256"));
  }
  return Result<std::string>::success(hex_encode(output.data(), length));
}

} // namespace support_assist
