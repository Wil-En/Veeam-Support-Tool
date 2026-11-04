#include "support_assist/secure_temp.hpp"

#include "support_assist/strings.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#include <sddl.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#include <cerrno>
#include <cstdio>
#endif

namespace support_assist {
namespace {

Error temp_error(std::string operation, std::string detail, int native = 0) {
  Error error;
  error.component = "secure-temp";
  error.operation = std::move(operation);
  error.message = std::move(detail);
  error.native_code = native;
  return error;
}

// Keep only characters that are safe in a file name on every supported platform.
std::string safe_token(std::string_view value, std::string_view fallback) {
  std::string output;
  output.reserve(value.size());
  for (const char character : value) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (std::isalnum(code) != 0 || character == '-' || character == '_')
      output.push_back(character);
  }
  if (output.size() > 48U)
    output.resize(48U);
  return output.empty() ? std::string(fallback) : output;
}

std::string safe_extension(std::string_view value) {
  if (value.empty())
    return ".tmp";
  std::string output;
  output.reserve(value.size() + 1U);
  if (value.front() != '.')
    output.push_back('.');
  for (const char character : value) {
    const unsigned char code = static_cast<unsigned char>(character);
    if (std::isalnum(code) != 0 || character == '.')
      output.push_back(character);
  }
  return output.size() <= 1U ? ".tmp" : output;
}

} // namespace

void SecureTempFile::reset() {
  if (owned_ && !path_.empty()) {
    std::error_code ignored;
    std::filesystem::remove(path_, ignored);
  }
  owned_ = false;
  path_.clear();
}

Result<std::vector<std::uint8_t>> secure_random_bytes(std::size_t count) {
  std::vector<std::uint8_t> buffer(count);
  if (count == 0U)
    return Result<std::vector<std::uint8_t>>::success(std::move(buffer));

#if defined(_WIN32)
  const NTSTATUS status = BCryptGenRandom(nullptr, buffer.data(),
                                          static_cast<ULONG>(buffer.size()),
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  if (status < 0) {
    return Result<std::vector<std::uint8_t>>::failure(
        temp_error("generate secure random bytes",
                   "BCryptGenRandom did not return success", static_cast<int>(status)));
  }
  return Result<std::vector<std::uint8_t>>::success(std::move(buffer));
#else
  std::size_t filled = 0;
#if defined(__linux__)
  while (filled < buffer.size()) {
    const ssize_t written = ::getrandom(buffer.data() + filled, buffer.size() - filled, 0);
    if (written < 0) {
      if (errno == EINTR)
        continue;
      break;  // Fall through to /dev/urandom.
    }
    filled += static_cast<std::size_t>(written);
  }
  if (filled == buffer.size())
    return Result<std::vector<std::uint8_t>>::success(std::move(buffer));
#endif
  // getrandom() is unavailable on macOS and on older Linux kernels.
  const int descriptor = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return Result<std::vector<std::uint8_t>>::failure(
        temp_error("generate secure random bytes", "/dev/urandom could not be opened", errno));
  }
  while (filled < buffer.size()) {
    const ssize_t read_bytes = ::read(descriptor, buffer.data() + filled, buffer.size() - filled);
    if (read_bytes <= 0) {
      if (read_bytes < 0 && errno == EINTR)
        continue;
      ::close(descriptor);
      return Result<std::vector<std::uint8_t>>::failure(
          temp_error("generate secure random bytes", "/dev/urandom returned no data", errno));
    }
    filled += static_cast<std::size_t>(read_bytes);
  }
  ::close(descriptor);
  return Result<std::vector<std::uint8_t>>::success(std::move(buffer));
#endif
}

Result<std::string> secure_random_hex(std::size_t byte_count) {
  auto bytes = secure_random_bytes(byte_count);
  if (!bytes.ok())
    return Result<std::string>::failure(bytes.error());
  std::string output;
  output.reserve(byte_count * 2U);
  for (const std::uint8_t value : bytes.value()) {
    output.push_back("0123456789abcdef"[(value >> 4U) & 0x0FU]);
    output.push_back("0123456789abcdef"[value & 0x0FU]);
  }
  return Result<std::string>::success(std::move(output));
}

Result<std::filesystem::path> secure_temp_directory() {
  std::error_code error;
  const auto base = std::filesystem::temp_directory_path(error);
  if (error) {
    return Result<std::filesystem::path>::failure(
        temp_error("resolve temporary directory", error.message(), error.value()));
  }
#if defined(_WIN32)
  const std::filesystem::path directory = base / "SupportAssistTool";
#else
  // Include the uid so two engineers on the same host cannot collide or read each other's data.
  const std::filesystem::path directory =
      base / ("support-assist-tool-" + std::to_string(static_cast<unsigned long>(::getuid())));
#endif
  std::filesystem::create_directories(directory, error);
  if (error && !std::filesystem::is_directory(directory)) {
    return Result<std::filesystem::path>::failure(
        temp_error("create temporary directory", error.message(), error.value()));
  }
#if !defined(_WIN32)
  // Owner-only. If this cannot be enforced, fail rather than silently widening exposure.
  if (::chmod(directory.c_str(), S_IRWXU) != 0) {
    return Result<std::filesystem::path>::failure(
        temp_error("restrict temporary directory",
                   "Could not set owner-only permissions on the SAT temporary directory", errno));
  }
  struct ::stat info {};
  if (::lstat(directory.c_str(), &info) != 0 || S_ISLNK(info.st_mode) ||
      info.st_uid != ::getuid()) {
    return Result<std::filesystem::path>::failure(
        temp_error("verify temporary directory",
                   "The SAT temporary directory is a link or is not owned by the current user"));
  }
#endif
  return Result<std::filesystem::path>::success(directory);
}

Result<SecureTempFile> create_secure_temp_file(std::string_view prefix,
                                               std::string_view extension,
                                               const std::filesystem::path& directory) {
  std::filesystem::path target_directory = directory;
  if (target_directory.empty()) {
    auto owned = secure_temp_directory();
    if (!owned.ok())
      return Result<SecureTempFile>::failure(owned.error());
    target_directory = owned.value();
  }

  const std::string name_prefix = safe_token(prefix, "support-assist");
  const std::string name_extension = safe_extension(extension);

  // Retry a small number of times so an unlucky collision is not a hard failure, while a
  // persistent failure (a hostile directory, a full filesystem) still surfaces.
  for (int attempt = 0; attempt < 8; ++attempt) {
    auto suffix = secure_random_hex(16U);
    if (!suffix.ok())
      return Result<SecureTempFile>::failure(suffix.error());
    const std::filesystem::path candidate =
        target_directory / (name_prefix + "-" + suffix.value() + name_extension);

#if defined(_WIN32)
    // CREATE_NEW fails if the file exists. Deny sharing and inherit the directory's owner-only
    // ACL rather than constructing a DACL for every file.
    const HANDLE handle = ::CreateFileW(candidate.wstring().c_str(), GENERIC_WRITE, 0, nullptr,
                                        CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if (handle != INVALID_HANDLE_VALUE) {
      ::CloseHandle(handle);
      return Result<SecureTempFile>::success(SecureTempFile(candidate));
    }
    const DWORD last_error = ::GetLastError();
    if (last_error != ERROR_FILE_EXISTS && last_error != ERROR_ALREADY_EXISTS) {
      return Result<SecureTempFile>::failure(
          temp_error("create temporary file", "CreateFileW could not create the temporary file",
                     static_cast<int>(last_error)));
    }
#else
    // O_EXCL defeats a pre-created file, O_NOFOLLOW defeats a pre-created symlink, and 0600
    // keeps extracted customer content private regardless of umask.
    const int descriptor =
        ::open(candidate.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (descriptor >= 0) {
      ::close(descriptor);
      return Result<SecureTempFile>::success(SecureTempFile(candidate));
    }
    if (errno != EEXIST) {
      return Result<SecureTempFile>::failure(
          temp_error("create temporary file",
                     "The temporary file could not be created exclusively", errno));
    }
#endif
  }

  return Result<SecureTempFile>::failure(
      temp_error("create temporary file",
                 "A unique temporary file name could not be created after repeated attempts"));
}

} // namespace support_assist
