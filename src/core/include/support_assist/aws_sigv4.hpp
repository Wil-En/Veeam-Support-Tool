#pragma once

// AWS Signature Version 4, which Amazon S3 and most S3-compatible storage accept: the canonical
// request, the string to sign, the signing key and the Authorization header, with HMAC-SHA256 and
// SHA-256 from OpenSSL. The secret key signs; it is never sent.

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct SigV4Request {
  std::string method = "GET";
  std::string canonical_uri = "/";  // the path, already encoded once ("/bucket/")
  std::vector<std::pair<std::string, std::string>> query;    // names and values, not yet encoded
  std::vector<std::pair<std::string, std::string>> headers;  // host and the x-amz headers to sign
  std::string payload_sha256;       // the body's SHA-256 in hex; the empty body's for a GET
};

struct SigV4Credentials {
  std::string access_key;
  std::string secret_key;
  std::string session_token;  // a temporary key's token; empty otherwise
};

struct SigV4Signature {
  std::string canonical_request;
  std::string string_to_sign;
  std::string signed_headers;
  std::string signature;      // hex
  std::string authorization;  // the Authorization header's value
};

// The SHA-256 of an empty body, as S3 asks for on a GET.
inline constexpr std::string_view kEmptyPayloadSha256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

std::string sha256_hex(std::string_view data);
// Raw bytes.
std::string hmac_sha256(std::string_view key, std::string_view data);
// RFC 3986 unreserved characters kept, everything else %XX; '/' kept only when keep_slash.
std::string sigv4_uri_encode(std::string_view text, bool keep_slash);
// UTC now as SigV4 writes it: 20260928T143000Z.
std::string sigv4_timestamp_now();

SigV4Signature sign_sigv4(const SigV4Request& request, const SigV4Credentials& credentials,
                          std::string_view region, std::string_view service, std::string_view timestamp);

} // namespace support_assist
