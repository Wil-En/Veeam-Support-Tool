#include "support_assist/filesystem.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/uuid.hpp"
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <vector>

namespace support_assist {
namespace {
class Handle {
public:
  explicit Handle(HANDLE h = INVALID_HANDLE_VALUE) : h_(h) {}
  ~Handle() {
    if (h_ != INVALID_HANDLE_VALUE && h_ != nullptr)
      CloseHandle(h_);
  }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  HANDLE get() const noexcept {
    return h_;
  }

private:
  HANDLE h_;
};
class AlgHandle {
public:
  ~AlgHandle() {
    if (h_)
      BCryptCloseAlgorithmProvider(h_, 0);
  }
  BCRYPT_ALG_HANDLE* put() {
    return &h_;
  }
  BCRYPT_ALG_HANDLE get() const {
    return h_;
  }

private:
  BCRYPT_ALG_HANDLE h_ = nullptr;
};
class HashHandle {
public:
  ~HashHandle() {
    if (h_)
      BCryptDestroyHash(h_);
  }
  BCRYPT_HASH_HANDLE* put() {
    return &h_;
  }
  BCRYPT_HASH_HANDLE get() const {
    return h_;
  }

private:
  BCRYPT_HASH_HANDLE h_ = nullptr;
};
Error hash_error(std::string operation, const std::filesystem::path& path, std::int64_t code) {
  Error e;
  e.component = "Hash";
  e.operation = std::move(operation);
  e.source = utf8_from_wide(path.native());
  e.native_code = code;
  e.message = "SHA-256 operation failed";
  e.recoverable = true;
  e.timestamp_utc = utc_now_iso8601();
  e.correlation_id = make_uuid_v4();
  return e;
}
} // namespace
Result<std::string> hash_file_sha256(const std::filesystem::path& path,
                                     const CancellationToken& cancel) {
  Handle file(CreateFileW(path.c_str(),
                          GENERIC_READ,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          nullptr,
                          OPEN_EXISTING,
                          FILE_FLAG_SEQUENTIAL_SCAN,
                          nullptr));
  if (file.get() == INVALID_HANDLE_VALUE)
    return Result<std::string>::failure(hash_error("open file", path, GetLastError()));
  AlgHandle algorithm;
  NTSTATUS status =
      BCryptOpenAlgorithmProvider(algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (status < 0)
    return Result<std::string>::failure(hash_error("open SHA-256 provider", path, status));
  DWORD object_size = 0, hash_size = 0, bytes = 0;
  status = BCryptGetProperty(algorithm.get(),
                             BCRYPT_OBJECT_LENGTH,
                             reinterpret_cast<PUCHAR>(&object_size),
                             sizeof(object_size),
                             &bytes,
                             0);
  if (status < 0)
    return Result<std::string>::failure(hash_error("query hash object size", path, status));
  status = BCryptGetProperty(algorithm.get(),
                             BCRYPT_HASH_LENGTH,
                             reinterpret_cast<PUCHAR>(&hash_size),
                             sizeof(hash_size),
                             &bytes,
                             0);
  if (status < 0)
    return Result<std::string>::failure(hash_error("query hash length", path, status));
  std::vector<UCHAR> object(object_size), digest(hash_size);
  HashHandle hash;
  status = BCryptCreateHash(
      algorithm.get(), hash.put(), object.data(), static_cast<ULONG>(object.size()), nullptr, 0, 0);
  if (status < 0)
    return Result<std::string>::failure(hash_error("create hash", path, status));
  std::vector<UCHAR> buffer(1024 * 1024);
  for (;;) {
    if (cancel.is_cancelled()) {
      Error e = hash_error("hash cancelled", path, ERROR_CANCELLED);
      return Result<std::string>::failure(std::move(e));
    }
    DWORD read = 0;
    if (!ReadFile(file.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
      return Result<std::string>::failure(hash_error("read file", path, GetLastError()));
    if (read == 0)
      break;
    status = BCryptHashData(hash.get(), buffer.data(), read, 0);
    if (status < 0)
      return Result<std::string>::failure(hash_error("update hash", path, status));
  }
  status = BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0);
  if (status < 0)
    return Result<std::string>::failure(hash_error("finish hash", path, status));
  return Result<std::string>::success(hex_encode(digest.data(), digest.size()));
}
} // namespace support_assist
