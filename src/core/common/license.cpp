#include "support_assist/license.hpp"

#include <array>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

namespace support_assist {
namespace {

// The engineer-licence signing public key (ECDSA P-256). The matching private key is kept by
// whoever issues licences and never ships; only this public half is embedded, so possessing the binary does
// not let anyone mint a licence. Rotating the key means replacing this block and re-issuing.
const char kEngineerPublicKeyPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJHUkpe35S2UIXQRRSR4Bq71CVtjg\n"
    "HnTA4cTHe2Q2PyDe332cvACV7aDVtNs4ZW1WwfZKVt4Yy5B/3+XRwwCZHw==\n"
    "-----END PUBLIC KEY-----\n";

constexpr char kSignatureMarker[] = "---SIGNATURE---";

std::string trim(const std::string& value) {
  const auto first = value.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = value.find_last_not_of(" \t\r\n");
  return value.substr(first, last - first + 1);
}

// Minimal, self-contained base64 decoder (the signature is base64 in the licence file). Avoids the
// padding quirks of EVP_DecodeBlock and keeps the verifier free of OpenSSL base64 state.
std::vector<unsigned char> base64_decode(const std::string& input) {
  static constexpr std::array<signed char, 256> table = [] {
    std::array<signed char, 256> t{};
    for (auto& value : t)
      value = -1;
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (int i = 0; i < 64; ++i)
      t[static_cast<unsigned char>(alphabet[i])] = static_cast<signed char>(i);
    return t;
  }();

  std::vector<unsigned char> output;
  int accumulator = 0;
  int bits = 0;
  for (char character : input) {
    if (character == '=' || character == '\n' || character == '\r' || character == ' ' ||
        character == '\t')
      continue;
    const signed char value = table[static_cast<unsigned char>(character)];
    if (value < 0)
      return {};  // an invalid character means a malformed signature
    accumulator = (accumulator << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      output.push_back(static_cast<unsigned char>((accumulator >> bits) & 0xFF));
    }
  }
  return output;
}

// Read "key":"value" from the small JSON token. The token is our own controlled format, so a plain
// search is sufficient and avoids pulling in a JSON dependency.
bool read_json_string(const std::string& json, const std::string& key, std::string& out) {
  const std::string needle = "\"" + key + "\"";
  auto position = json.find(needle);
  if (position == std::string::npos)
    return false;
  position = json.find(':', position + needle.size());
  if (position == std::string::npos)
    return false;
  position = json.find('"', position);
  if (position == std::string::npos)
    return false;
  const auto end = json.find('"', position + 1);
  if (end == std::string::npos)
    return false;
  out = json.substr(position + 1, end - position - 1);
  return true;
}

struct KeyHandle {
  EVP_PKEY* value = nullptr;
  ~KeyHandle() {
    if (value != nullptr)
      EVP_PKEY_free(value);
  }
};

struct DigestContext {
  EVP_MD_CTX* value = EVP_MD_CTX_new();
  ~DigestContext() {
    if (value != nullptr)
      EVP_MD_CTX_free(value);
  }
};

bool signature_is_valid(const std::string& payload, const std::vector<unsigned char>& signature) {
  if (signature.empty())
    return false;
  BIO* bio = BIO_new_mem_buf(kEngineerPublicKeyPem, -1);
  if (bio == nullptr)
    return false;
  KeyHandle key;
  key.value = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
  BIO_free(bio);
  if (key.value == nullptr)
    return false;
  DigestContext context;
  if (context.value == nullptr)
    return false;
  if (EVP_DigestVerifyInit(context.value, nullptr, EVP_sha256(), nullptr, key.value) != 1)
    return false;
  const int result = EVP_DigestVerify(
      context.value, signature.data(), signature.size(),
      reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
  return result == 1;
}

} // namespace

std::string engineer_license_filename() {
  return "sat-engineer-license.key";
}

EngineerLicense verify_engineer_license_file(const std::filesystem::path& path) {
  EngineerLicense license;
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    license.detail = "No licence file present.";
    return license;
  }
  std::stringstream buffer;
  buffer << input.rdbuf();
  const std::string content = buffer.str();

  const auto marker = content.find(kSignatureMarker);
  if (marker == std::string::npos) {
    license.detail = "The licence file is malformed (no signature).";
    return license;
  }

  // The signed bytes are exactly the payload, without the trailing newline that separates it from
  // the signature marker.
  std::size_t payload_end = marker;
  if (payload_end > 0 && content[payload_end - 1] == '\n')
    --payload_end;
  const std::string payload = content.substr(0, payload_end);
  const std::string signature_text = trim(content.substr(marker + std::string(kSignatureMarker).size()));
  const std::vector<unsigned char> signature = base64_decode(signature_text);

  if (!signature_is_valid(payload, signature)) {
    license.detail = "The licence signature did not verify.";
    return license;
  }

  std::string edition;
  if (!read_json_string(payload, "edition", edition) || edition != "engineer") {
    license.detail = "The licence does not grant engineer mode.";
    return license;
  }
  read_json_string(payload, "issued_to", license.issued_to);
  read_json_string(payload, "issued", license.issued);
  license.valid = true;
  license.detail = "valid";
  return license;
}

EngineerLicense find_engineer_license(const std::filesystem::path& executable_directory) {
  const std::filesystem::path candidate = executable_directory / engineer_license_filename();
  std::error_code error;
  if (std::filesystem::exists(candidate, error))
    return verify_engineer_license_file(candidate);
  EngineerLicense license;
  license.detail = "No licence file present.";
  return license;
}

} // namespace support_assist
