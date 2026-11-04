#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

struct TcpPortTestOptions {
  std::string host;
  std::uint16_t port = 2500;
  std::chrono::milliseconds timeout{5000};
  // Optional explicit local source binding. Used by interface/VLAN/team route
  // diagnostics so the operating system is asked to originate the connection
  // from a specific IP-bearing interface rather than its normal default route.
  std::string source_address;
  std::string source_interface;
  // A normal service receives only a TCP connect/close. When the peer first
  // identifies itself as a SAT listener, the tester can safely perform the
  // SAT handshake and optional volatile payload verification.
  bool detect_sat_listener = true;
  std::uint64_t sat_payload_bytes = 50ULL * 1024ULL * 1024ULL;
  // A floor, not the whole budget: test_tcp_port() extends it in proportion to the payload,
  // because a flat minute cannot move a gigabyte over anything but a fast LAN.
  std::chrono::milliseconds sat_payload_timeout{60000};
  // Test both address families: after one family connects, the test goes on to the other
  // family's addresses. The SAT payload is sent over the first connection only.
  bool both_families = true;
  // Report where a host name's addresses came from first (the hosts file or a DNS server). This
  // sends a few DNS queries, so the interface matrix asks once.
  bool describe_name_source = true;
};

struct TcpEndpointAttempt {
  std::string address;
  std::string address_family;
  std::string source_address;
  std::string source_interface;
  std::string local_address;
  bool connected = false;
  std::int64_t native_code = 0;
  std::string message;
  double elapsed_ms = 0.0;
  bool sat_listener_detected = false;
  bool sat_handshake_completed = false;
  bool sat_payload_validated = false;
  std::string sat_test_id;
  std::string peer_banner;
  std::uint64_t sat_payload_bytes = 0;
  std::string sat_payload_sha256;
  double sat_payload_seconds = 0.0;
  double sat_payload_bits_per_second = 0.0;
};

struct TcpPortTestResult {
  std::string host;
  std::uint16_t port = 0;
  bool connected = false;
  std::string connected_address;
  double elapsed_ms = 0.0;
  bool dns_lookup_required = true;
  std::string canonical_name;
  std::vector<std::string> resolved_addresses;
  std::string name_source; // "hosts file (...)", "DNS server 10.0.0.1 (Ethernet0)"; empty for an address
  std::vector<TcpEndpointAttempt> attempts;
};


struct NetworkInterfaceInfo {
  std::string name;
  std::string description;
  std::string address;
  std::string address_family;
  unsigned int prefix_length = 0;
  std::string gateway;
  bool up = false;
  bool loopback = false;
  bool virtual_interface = false;
  bool vlan_interface = false;
  bool team_or_bond = false;
  bool diagnostic_default = false;
  std::vector<std::string> members;
};

struct InterfaceTcpTestResult {
  NetworkInterfaceInfo interface;
  TcpPortTestResult test;
};

Result<std::vector<NetworkInterfaceInfo>> enumerate_network_interfaces();
Result<std::vector<InterfaceTcpTestResult>> test_tcp_across_interfaces(
    const TcpPortTestOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {},
    bool include_virtual_or_special = false);


enum class UdpProbeMode { generic_datagram, sat_listener };

struct UdpPortTestOptions {
  std::string host;
  std::uint16_t port = 2500;
  std::chrono::milliseconds timeout{2000};
  std::string source_address;
  std::string source_interface;
  UdpProbeMode mode = UdpProbeMode::generic_datagram;
  bool describe_name_source = true;
};

struct UdpEndpointAttempt {
  std::string address;
  std::string address_family;
  std::string source_address;
  std::string source_interface;
  std::string local_address;
  bool datagram_sent = false;
  bool response_received = false;
  bool sat_acknowledged = false;
  std::string sat_test_id;
  std::int64_t native_code = 0;
  double elapsed_ms = 0.0;
  std::string message;
};

struct UdpPortTestResult {
  std::string host;
  std::uint16_t port = 0;
  bool dns_lookup_required = true;
  std::string canonical_name;
  std::vector<std::string> resolved_addresses;
  std::string name_source;
  std::vector<UdpEndpointAttempt> attempts;
};

struct UdpListenerOptions {
  std::uint16_t port = 2500;
  std::chrono::seconds duration{30};
  bool accept_multiple = true;
  bool enable_sat_protocol = true;
};

struct UdpReceivedDatagram {
  std::string local_address;
  std::uint16_t local_port = 0;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string received_utc;
  std::uint64_t bytes = 0;
  bool sat_probe = false;
  bool sat_ack_sent = false;
  std::string sat_test_id;
};

struct UdpListenerResult {
  std::uint16_t port = 0;
  bool timed_out = false;
  bool cancelled = false;
  std::vector<UdpReceivedDatagram> datagrams;
};

using UdpListenerEventCallback = std::function<void(const UdpReceivedDatagram&)>;

struct InterfaceUdpTestResult {
  NetworkInterfaceInfo interface;
  UdpPortTestResult test;
};

Result<UdpPortTestResult> test_udp_port(const UdpPortTestOptions& options,
                                        const CancellationToken& cancel,
                                        ProgressCallback progress = {});
Result<UdpListenerResult> listen_udp(const UdpListenerOptions& options,
                                     const CancellationToken& cancel,
                                     ProgressCallback progress = {},
                                     UdpListenerEventCallback event_callback = {});
Result<std::vector<InterfaceUdpTestResult>> test_udp_across_interfaces(
    const UdpPortTestOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {},
    bool include_virtual_or_special = false);

// The default banner a TCP listener sends to each connection, so a client can tell SAT's listener
// from the service that uses the port. %port% becomes the port listened on; an empty banner
// sends none.
inline constexpr std::string_view kDefaultListenerBanner = "SAT - listening on %port%";
std::string expand_listener_banner(std::string_view banner, std::uint16_t port);

struct TcpListenerOptions {
  std::uint16_t port = 2500;
  std::chrono::seconds duration{30};
  std::string banner{kDefaultListenerBanner};
  bool accept_multiple = false;
  bool enable_sat_protocol = true;
  // The largest payload a listener will accept. Sized so the tester's own MiB field can ask
  // for a gigabyte-scale transfer - the point of that field is a rough bandwidth figure -
  // while still refusing an absurd request outright.
  std::uint64_t max_sat_payload_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
};

struct TcpAcceptedConnection {
  std::string local_address;
  std::uint16_t local_port = 0;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string accepted_utc;
  bool sat_probe = false;
  bool sat_payload_validated = false;
  std::string sat_test_id;
  std::uint64_t sat_payload_bytes = 0;
  bool banner_sent = false;
  std::string banner;
  std::string sat_payload_sha256;
  double sat_payload_seconds = 0.0;
  // A File Transfer Calculator test (SAT-THROUGHPUT/1): the bytes are counted and timed, not hashed.
  bool sat_throughput = false;
};

// What a listener saw on one connection, for its list: "SAT probe, test 1f3c...", "Throughput test,
// 4 GB in 5.5 s (6.25 Gb/s)" or "Connection".
std::string describe_listener_connection(const TcpAcceptedConnection& connection);

struct TcpListenerResult {
  std::uint16_t port = 0;
  bool timed_out = false;
  bool cancelled = false;
  std::vector<TcpAcceptedConnection> connections;
};

enum class TcpListenerEventKind { accepted, updated };
using TcpListenerEventCallback =
    std::function<void(TcpListenerEventKind, const TcpAcceptedConnection&)>;

enum class TlsProbeVersion {
  automatic,
  tls12_only,
  tls13_only,
};

struct TlsCertificateInfo {
  std::string subject;
  std::string issuer;
  std::vector<std::string> subject_alt_names;
  std::string valid_from;
  std::string valid_until;
  std::string sha1_thumbprint;
  std::string sha256_fingerprint;
  bool hostname_checked = false;
  bool hostname_matches = false;
  bool system_trust_checked = false;
  bool system_trusted = false;
  std::string system_trust_detail;
  bool expected_fingerprint_provided = false;
  bool expected_fingerprint_matches = false;
};

struct TlsProbeOptions {
  std::string host;
  std::uint16_t port = 2500;
  std::string server_name;
  std::string source_address;
  std::string source_interface;
  std::string expected_fingerprint;
  std::chrono::milliseconds timeout{10000};
  TlsProbeVersion version = TlsProbeVersion::automatic;
  bool check_system_trust = true;
};

struct TlsProbeResult {
  std::string host;
  std::uint16_t port = 0;
  std::string connected_address;
  std::string source_address;
  std::string source_interface;
  std::string local_address;
  std::string requested_server_name;
  bool tcp_connected = false;
  bool client_hello_observed = false;
  bool server_hello_observed = false;
  bool server_requested_client_certificate = false;
  std::size_t client_hello_bytes = 0;
  std::size_t server_hello_bytes = 0;
  std::vector<std::string> offered_versions;
  std::vector<std::string> offered_cipher_suites;
  std::string negotiated_version;
  std::string negotiated_cipher_suite;
  bool negotiated_cipher_was_offered = false;
  bool handshake_completed = false;
  std::string failure_stage;
  std::string failure_reason;
  double tcp_elapsed_ms = 0.0;
  double tls_elapsed_ms = 0.0;
  TlsCertificateInfo certificate;
};

struct InterfaceTlsTestResult {
  NetworkInterfaceInfo interface;
  TlsProbeResult test;
};

struct TcpThroughputOptions {
  bool server = false;
  std::string host;
  std::uint16_t port = 2500;
  std::uint64_t transfer_bytes = 1024ULL * 1024ULL * 1024ULL;
  std::size_t buffer_bytes = 256U * 1024U;
  std::chrono::milliseconds connect_timeout{10000};
  std::chrono::milliseconds idle_timeout{30000};
};

struct TcpThroughputResult {
  bool server = false;
  std::string peer_address;
  std::string direction;
  bool protocol_verified = false;
  std::uint16_t port = 0;
  std::uint64_t transferred_bytes = 0;
  double elapsed_seconds = 0.0;
  double bits_per_second = 0.0;
  bool cancelled = false;
};

Result<std::uint64_t> parse_transfer_size(std::string_view value);
std::string format_transfer_rate(double bits_per_second);

Result<TcpPortTestResult> test_tcp_port(const TcpPortTestOptions& options,
                                        const CancellationToken& cancel,
                                        ProgressCallback progress = {});

Result<TcpListenerResult> listen_tcp(const TcpListenerOptions& options,
                                     const CancellationToken& cancel,
                                     ProgressCallback progress = {},
                                     TcpListenerEventCallback event_callback = {});

Result<TlsProbeResult> test_tls_handshake(const TlsProbeOptions& options,
                                          const CancellationToken& cancel,
                                          ProgressCallback progress = {});
Result<std::vector<InterfaceTlsTestResult>> test_tls_across_interfaces(
    const TlsProbeOptions& options,
    const CancellationToken& cancel,
    ProgressCallback progress = {},
    bool include_virtual_or_special = false);

Result<TcpThroughputResult> run_tcp_throughput(const TcpThroughputOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress = {});

// The File Transfer Calculator's network test: SAT-THROUGHPUT/1 to a SAT listener (the Local Port
// Checker's, or the TCP / UDP Listener) or to Network Tools' throughput server, on the port given.
// Generated bytes are sent and timed until the other end has every one; nothing is written there.
struct TransferTestOptions {
  std::string host;
  std::uint16_t port = 2500;
  std::uint64_t bytes = 1024ULL * 1024ULL * 1024ULL;
  std::chrono::milliseconds connect_timeout{10000};
  std::chrono::milliseconds idle_timeout{30000};
};

struct TransferTestResult {
  std::string host;
  std::string peer_address; // the address and port connected to
  bool ipv6 = false;
  std::string answered_by;  // "SAT listener" or "SAT throughput server"
  std::uint64_t bytes = 0;
  double seconds = 0.0;
  double bytes_per_second = 0.0;
  bool cancelled = false;
};

inline constexpr std::uint64_t kTransferTestMaxBytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;

Result<TransferTestResult> run_transfer_test(const TransferTestOptions& options, const CancellationToken& cancel,
                                             ProgressCallback progress = {});

// A network adapter as the calculator lists it: its link speed, MTU, addresses and error counts.
struct NetworkAdapter {
  std::string name;        // "Ethernet 2", "eth0"
  std::string description; // "Intel(R) Ethernet Controller X710 for 10GbE SFP+"
  std::vector<std::string> addresses;
  std::uint64_t link_bits_per_second = 0; // 0 when the adapter does not report one
  std::uint32_t mtu = 0;
  bool up = false;
  bool loopback = false;
  bool virtual_adapter = false;
  std::uint64_t receive_errors = 0;
  std::uint64_t send_errors = 0;
  std::uint64_t receive_discards = 0;
  std::uint64_t send_discards = 0;
};

Result<std::vector<NetworkAdapter>> list_network_adapters();
// "Ethernet 2 · 10 Gb/s · MTU 1500 · 10.0.4.10"
std::string network_adapter_label(const NetworkAdapter& adapter);


struct LocalTcpPortState {
  std::uint16_t port = 0;
  bool available = false;
  std::int64_t native_code = 0;
  std::uint32_t owner_process_id = 0;
  std::string owner_process_name;
  std::string detail;
};

Result<LocalTcpPortState> inspect_local_tcp_listener_port(std::uint16_t port);

struct RpcConnectivityOptions {
  std::string host;
  std::uint16_t port = 135;
  std::chrono::milliseconds timeout{5000};
  std::string source_address;
  std::string source_interface;
};

struct RpcConnectivityResult {
  std::string host;
  std::uint16_t port = 135;
  std::string connected_address;
  std::string local_address;
  std::string source_interface;
  bool tcp_connected = false;
  bool rpc_bind_sent = false;
  bool bind_ack_received = false;
  bool endpoint_mapper_accepted = false;
  std::uint16_t rpc_context_result = 0xFFFFU;
  std::uint16_t rpc_reject_reason = 0U;
  double elapsed_ms = 0.0;
  std::string failure_stage;
  std::string detail;
};

Result<RpcConnectivityResult> test_rpc_endpoint_mapper(const RpcConnectivityOptions& options,
                                                       const CancellationToken& cancel,
                                                       ProgressCallback progress = {});

struct GrpcConnectivityOptions {
  std::string host;
  std::uint16_t port = 2500;
  std::chrono::milliseconds timeout{5000};
  std::string source_address;
  std::string source_interface;
  bool use_tls = false;
  std::string server_name;
};

struct GrpcConnectivityResult {
  std::string host;
  std::uint16_t port = 0;
  std::string connected_address;
  std::string local_address;
  std::string source_interface;
  bool tcp_connected = false;
  bool tls_requested = false;
  bool tls_completed = false;
  std::string tls_version;
  std::string tls_cipher;
  std::string alpn_protocol;
  bool http2_preface_sent = false;
  bool server_settings_received = false;
  bool http2_ping_acknowledged = false;
  bool sat_peer_verified = false;
  std::string sat_test_id;
  double elapsed_ms = 0.0;
  std::string failure_stage;
  std::string detail;
  // With TLS, the certificate the server presented (subject, issuer, validity, SHA-256).
  bool certificate_read = false;
  TlsCertificateInfo certificate;
  // When the HTTP/2 stage fails on what the peer sent: its first bytes in hex, and what they look
  // like ("an HTTP/1.x response", "a TLS record", "an SSH banner", "binary data that is not HTTP/2").
  std::string first_bytes;
  std::string first_bytes_look;
};

Result<GrpcConnectivityResult> test_grpc_connectivity(const GrpcConnectivityOptions& options,
                                                      const CancellationToken& cancel,
                                                      ProgressCallback progress = {});

struct GrpcListenerOptions {
  std::uint16_t port = 2500;
  std::chrono::seconds duration{30};
  bool accept_multiple = true;
};

struct GrpcAcceptedConnection {
  std::string local_address;
  std::uint16_t local_port = 0;
  std::string remote_address;
  std::uint16_t remote_port = 0;
  std::string accepted_utc;
  bool http2_preface_received = false;
  bool client_settings_received = false;
  bool server_settings_sent = false;
  bool ping_received = false;
  bool ping_ack_sent = false;
  bool sat_peer_verified = false;
  std::string sat_test_id;
  std::string detail;
};

struct GrpcListenerResult {
  std::uint16_t port = 0;
  bool timed_out = false;
  bool cancelled = false;
  std::vector<GrpcAcceptedConnection> connections;
};

enum class GrpcListenerEventKind { accepted, updated };
using GrpcListenerEventCallback =
    std::function<void(GrpcListenerEventKind, const GrpcAcceptedConnection&)>;

Result<GrpcListenerResult> listen_grpc_transport(const GrpcListenerOptions& options,
                                                 const CancellationToken& cancel,
                                                 ProgressCallback progress = {},
                                                 GrpcListenerEventCallback event_callback = {});

} // namespace support_assist
