#pragma once

// One HTTPS request over the TLS library SAT already carries (OpenSSL), for the Object Storage
// Check: TLS 1.2 or later; the certificate checked against the system's trust store (Windows' own
// certificate store on Windows) and the name the request is for, against a SHA-256 fingerprint the
// engineer accepted for the session, or against a certificate file the engineer chose. A request is
// sent only over a trusted connection; a handshake on its own reports the certificate either way.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/network.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct HttpsRequest {
  std::string host;             // where to connect: a name or an address
  std::uint16_t port = 443;
  std::string server_name;      // the name the certificate must carry, and the SNI; the host when empty
  std::string method = "GET";
  std::string target = "/";     // the path and query, already encoded
  std::vector<std::pair<std::string, std::string>> headers;  // sent after Host
  std::string pinned_sha256;    // a certificate the engineer accepted for this session
  // A certificate file's contents (PEM, one or more, or one DER certificate): the server's own
  // certificate, or a CA that issued it.
  std::string trusted_certificates;
  bool handshake_only = false;  // connect and read the certificate; send nothing
  std::chrono::milliseconds timeout{15000};
  std::size_t max_body_bytes = 1024U * 1024U;
};

struct HttpsResponse {
  std::string connected_address;
  std::string tls_version;
  double connect_ms = 0.0;
  double tls_ms = 0.0;
  double request_ms = 0.0;
  TlsCertificateInfo certificate;  // the names, the dates and the fingerprints
  bool name_matches = false;       // the certificate carries the name asked for
  bool trusted = false;            // by the system's trust store, or by the pinned fingerprint
  bool pinned = false;             // trusted because its fingerprint was accepted
  bool file_trusted = false;       // trusted by the certificate file chosen
  std::string trust_detail;
  bool request_sent = false;
  int status = 0;
  std::vector<std::pair<std::string, std::string>> headers;  // names in lower case
  std::string body;
  bool body_truncated = false;
  std::uint64_t bytes_received = 0;

  // A header's value; empty when it is not there.
  std::string header(std::string_view name) const;
};

Result<HttpsResponse> https_request(const HttpsRequest& request, const CancellationToken& cancel);

} // namespace support_assist
