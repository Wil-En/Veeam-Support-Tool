#include "support_assist/aws_sigv4.hpp"

#include "support_assist/strings.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <ctime>

namespace support_assist {
namespace {

std::string hex(const unsigned char* data, std::size_t length) {
  static constexpr char digits[] = "0123456789abcdef";
  std::string text;
  text.reserve(length * 2U);
  for (std::size_t index = 0; index < length; ++index) {
    text.push_back(digits[data[index] >> 4U]);
    text.push_back(digits[data[index] & 0x0FU]);
  }
  return text;
}

// "  a   b " -> "a b", as the canonical headers want each value.
std::string collapse_spaces(std::string_view value) {
  std::string text;
  bool space = false;
  for (const char character : trim(value)) {
    if (character == ' ' || character == '\t') {
      space = true;
      continue;
    }
    if (space && !text.empty())
      text.push_back(' ');
    space = false;
    text.push_back(character);
  }
  return text;
}

} // namespace

std::string sha256_hex(std::string_view data) {
  unsigned char digest[EVP_MAX_MD_SIZE] = {};
  unsigned int length = 0;
  if (EVP_Digest(data.data(), data.size(), digest, &length, EVP_sha256(), nullptr) != 1)
    return {};
  return hex(digest, length);
}

std::string hmac_sha256(std::string_view key, std::string_view data) {
  unsigned char digest[EVP_MAX_MD_SIZE] = {};
  unsigned int length = 0;
  if (HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), reinterpret_cast<const unsigned char*>(data.data()),
           data.size(), digest, &length) == nullptr)
    return {};
  return std::string(reinterpret_cast<const char*>(digest), length);
}

std::string sigv4_uri_encode(std::string_view text, bool keep_slash) {
  static constexpr char digits[] = "0123456789ABCDEF";
  std::string encoded;
  for (const char raw : text) {
    const auto character = static_cast<unsigned char>(raw);
    const bool unreserved = (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
                            (character >= '0' && character <= '9') || character == '-' || character == '_' ||
                            character == '.' || character == '~';
    if (unreserved || (keep_slash && character == '/')) {
      encoded.push_back(raw);
      continue;
    }
    encoded.push_back('%');
    encoded.push_back(digits[character >> 4U]);
    encoded.push_back(digits[character & 0x0FU]);
  }
  return encoded;
}

std::string sigv4_timestamp_now() {
  const std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  std::tm utc{};
#ifdef _WIN32
  gmtime_s(&utc, &now);
#else
  gmtime_r(&now, &utc);
#endif
  char text[32] = {};
  std::strftime(text, sizeof(text), "%Y%m%dT%H%M%SZ", &utc);
  return text;
}

SigV4Signature sign_sigv4(const SigV4Request& request, const SigV4Credentials& credentials,
                          std::string_view region, std::string_view service, std::string_view timestamp) {
  SigV4Signature signature;
  // The query: each name and value encoded, sorted by name, then by value.
  std::vector<std::pair<std::string, std::string>> query;
  for (const auto& [name, value] : request.query)
    query.emplace_back(sigv4_uri_encode(name, false), sigv4_uri_encode(value, false));
  std::sort(query.begin(), query.end());
  std::string canonical_query;
  for (const auto& [name, value] : query)
    canonical_query += (canonical_query.empty() ? "" : "&") + name + "=" + value;
  // The headers: names in lower case, values trimmed, sorted by name.
  std::vector<std::pair<std::string, std::string>> headers;
  for (const auto& [name, value] : request.headers)
    headers.emplace_back(ascii_lower(trim(name)), collapse_spaces(value));
  std::sort(headers.begin(), headers.end());
  std::string canonical_headers;
  for (const auto& [name, value] : headers) {
    canonical_headers += name + ":" + value + "\n";
    signature.signed_headers += (signature.signed_headers.empty() ? "" : ";") + name;
  }
  signature.canonical_request = request.method + "\n" + request.canonical_uri + "\n" + canonical_query + "\n" +
                                canonical_headers + "\n" + signature.signed_headers + "\n" + request.payload_sha256;
  const std::string date(timestamp.substr(0, 8));
  const std::string scope = date + "/" + std::string(region) + "/" + std::string(service) + "/aws4_request";
  signature.string_to_sign = "AWS4-HMAC-SHA256\n" + std::string(timestamp) + "\n" + scope + "\n" +
                             sha256_hex(signature.canonical_request);
  const std::string date_key = hmac_sha256("AWS4" + credentials.secret_key, date);
  const std::string region_key = hmac_sha256(date_key, region);
  const std::string service_key = hmac_sha256(region_key, service);
  const std::string signing_key = hmac_sha256(service_key, "aws4_request");
  const std::string raw = hmac_sha256(signing_key, signature.string_to_sign);
  signature.signature = hex(reinterpret_cast<const unsigned char*>(raw.data()), raw.size());
  signature.authorization = "AWS4-HMAC-SHA256 Credential=" + credentials.access_key + "/" + scope +
                            ", SignedHeaders=" + signature.signed_headers + ", Signature=" + signature.signature;
  return signature;
}

} // namespace support_assist
