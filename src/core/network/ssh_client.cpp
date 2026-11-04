#include "support_assist/ssh_client.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/debug_log.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <thread>

#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
#include <libssh2.h>
#include <libssh2_sftp.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
#endif

namespace support_assist {
namespace {

Error ssh_error(std::string operation, std::string message, std::int64_t native = 0) {
  Error error;
  error.component = "SSH";
  error.operation = std::move(operation);
  error.message = std::move(message);
  error.native_code = native;
  error.recoverable = true;
  return error;
}

// Accepts every form an engineer might paste in: the OpenSSH "SHA256:base64" string, bare base64,
// colon-separated hex from older tooling, or raw hex. Comparing the DECODED 32 bytes rather than
// the text is what makes all of those equivalent to the same fingerprint.
std::vector<unsigned char> fingerprint_bytes(std::string value) {
  value.erase(std::remove_if(value.begin(), value.end(), [](char ch) {
                return ch == ':' || ch == '-' || ch == ' ' || ch == '\t' || ch == '\r' ||
                       ch == '\n';
              }),
              value.end());
  // Drop a leading algorithm label such as "SHA256" once the separators are gone.
  const std::string lowered = ascii_lower(value);
  if (lowered.rfind("sha256", 0) == 0) {
    value = value.substr(6);
  }

  const auto is_hex = [](const std::string& text) {
    return text.size() == 64U && text.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos;
  };
  std::vector<unsigned char> bytes;
  if (is_hex(value)) {
    bytes.reserve(32);
    for (std::size_t index = 0; index + 1U < value.size(); index += 2U) {
      bytes.push_back(static_cast<unsigned char>(std::stoul(value.substr(index, 2), nullptr, 16)));
    }
    return bytes;
  }

  // Otherwise treat it as base64, padded or not.
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned int accumulator = 0;
  int bits = 0;
  for (const char ch : value) {
    if (ch == '=') {
      break;
    }
    const char* position = std::strchr(kAlphabet, ch);
    if (position == nullptr) {
      return {};  // Not a recognised fingerprint format; refuse rather than guess.
    }
    accumulator = (accumulator << 6) | static_cast<unsigned int>(position - kAlphabet);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push_back(static_cast<unsigned char>((accumulator >> bits) & 0xFFU));
    }
  }
  return bytes;
}

bool fingerprints_match(const std::string& left, const std::string& right) {
  const auto left_bytes = fingerprint_bytes(left);
  const auto right_bytes = fingerprint_bytes(right);
  if (left_bytes.empty() || right_bytes.empty()) {
    return false;
  }
  return left_bytes == right_bytes;
}

#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
struct LibsshLifetime {
  LibsshLifetime() : ok(libssh2_init(0) == 0) {}
  ~LibsshLifetime() { if (ok) libssh2_exit(); }
  bool ok = false;
};

LibsshLifetime& libssh_lifetime() {
  static LibsshLifetime lifetime;
  return lifetime;
}

#ifdef _WIN32
using NativeSocket = SOCKET;
constexpr NativeSocket invalid_socket = INVALID_SOCKET;
void close_socket(NativeSocket socket) {
  if (socket != INVALID_SOCKET)
    closesocket(socket);
}
// Winsock initialisation, owned by exactly one object at a time.
//
// The move constructor and move assignment below clear the source's flag explicitly rather than
// relying on the implicit (copying) move: otherwise a moved-from instance would still believe it
// owns Winsock and call WSACleanup again on destruction. WSAStartup is reference counted, so an
// extra cleanup drops the count, and once it reaches zero every socket in the process stops working.
//
// This matters because ssh_open_shell keeps its session alive after returning, unlike the other SSH
// entry points, whose ConnectedSession - and its WsaLifetime - is destroyed before the call returns.
struct WsaLifetime {
  WsaLifetime() {
    WSADATA data{};
    ok = WSAStartup(MAKEWORD(2, 2), &data) == 0;
  }
  WsaLifetime(const WsaLifetime&) = delete;
  WsaLifetime& operator=(const WsaLifetime&) = delete;
  WsaLifetime(WsaLifetime&& other) noexcept : ok(other.ok) { other.ok = false; }
  WsaLifetime& operator=(WsaLifetime&& other) noexcept {
    if (this != &other) {
      if (ok) WSACleanup();
      ok = other.ok;
      other.ok = false;
    }
    return *this;
  }
  ~WsaLifetime() {
    if (ok) WSACleanup();
  }
  bool ok = false;
};
#else
using NativeSocket = int;
constexpr NativeSocket invalid_socket = -1;
void close_socket(NativeSocket socket) {
  if (socket >= 0)
    close(socket);
}
struct WsaLifetime { bool ok = true; };
#endif

struct SocketCloser {
  void operator()(NativeSocket* value) const {
    if (value != nullptr) {
      close_socket(*value);
      delete value;
    }
  }
};
using SocketPtr = std::unique_ptr<NativeSocket, SocketCloser>;

struct SessionCloser {
  void operator()(LIBSSH2_SESSION* value) const {
    if (value != nullptr) {
      libssh2_session_disconnect(value, "Support Assist Tool session closed");
      libssh2_session_free(value);
    }
  }
};
using SessionPtr = std::unique_ptr<LIBSSH2_SESSION, SessionCloser>;

struct SftpCloser {
  void operator()(LIBSSH2_SFTP* value) const {
    if (value != nullptr)
      libssh2_sftp_shutdown(value);
  }
};
using SftpPtr = std::unique_ptr<LIBSSH2_SFTP, SftpCloser>;

struct SftpHandleCloser {
  void operator()(LIBSSH2_SFTP_HANDLE* value) const {
    if (value != nullptr)
      libssh2_sftp_close_handle(value);
  }
};
using SftpHandlePtr = std::unique_ptr<LIBSSH2_SFTP_HANDLE, SftpHandleCloser>;

struct ChannelCloser {
  void operator()(LIBSSH2_CHANNEL* value) const {
    if (value != nullptr) {
      libssh2_channel_close(value);
      libssh2_channel_free(value);
    }
  }
};
using ChannelPtr = std::unique_ptr<LIBSSH2_CHANNEL, ChannelCloser>;

// A failure that has libssh2's error code should carry libssh2's words too.
//
// The context argument says which operation was attempted, which the library does not know. It
// must not stand in for the library's own description: an invented message reads as a diagnosis
// and is believed even when it misidentifies the real cause.
Error ssh_library_error(LIBSSH2_SESSION* session, std::string operation, std::string context) {
  char* detail = nullptr;
  int detail_length = 0;
  int code = 0;
  if (session != nullptr)
    code = libssh2_session_last_error(session, &detail, &detail_length, 0);
  std::string message = std::move(context);
  if (detail != nullptr && detail_length > 0)
    message += ": " + std::string(detail, static_cast<std::size_t>(detail_length));
  return ssh_error(std::move(operation), std::move(message), code);
}

struct ConnectedSession {
  WsaLifetime network;
  SocketPtr socket;
  SessionPtr session;
  SshHostKeyInfo host_key;
};

std::string hostkey_algorithm(LIBSSH2_SESSION* session) {
  size_t length = 0;
  int type = 0;
  static_cast<void>(libssh2_session_hostkey(session, &length, &type));
  switch (type) {
  case LIBSSH2_HOSTKEY_TYPE_RSA: return "RSA";
#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_256
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: return "ECDSA-P256";
#endif
#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_384
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: return "ECDSA-P384";
#endif
#ifdef LIBSSH2_HOSTKEY_TYPE_ECDSA_521
  case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return "ECDSA-P521";
#endif
#ifdef LIBSSH2_HOSTKEY_TYPE_ED25519
  case LIBSSH2_HOSTKEY_TYPE_ED25519: return "ED25519";
#endif
  default: return "Unknown";
  }
}

// The fingerprint an engineer is asked to VERIFY, so it has to be in the form every other tool
// prints. OpenSSH, ssh-keygen -l, PuTTY and the server administrator reading it down the phone all
// use "SHA256:" followed by unpadded base64. Raw hex encodes the same 32 bytes but is impractical
// to compare by eye, which can make a matching host key look like a mismatch.
std::string sha256_fingerprint(LIBSSH2_SESSION* session) {
  const auto* digest = reinterpret_cast<const unsigned char*>(
      libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA256));
  if (digest == nullptr)
    return {};
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string encoded;
  encoded.reserve(44);
  for (std::size_t index = 0; index < 32U; index += 3U) {
    const unsigned int byte0 = digest[index];
    const unsigned int byte1 = index + 1U < 32U ? digest[index + 1U] : 0U;
    const unsigned int byte2 = index + 2U < 32U ? digest[index + 2U] : 0U;
    const unsigned int triple = (byte0 << 16) | (byte1 << 8) | byte2;
    encoded.push_back(kAlphabet[(triple >> 18) & 0x3FU]);
    encoded.push_back(kAlphabet[(triple >> 12) & 0x3FU]);
    if (index + 1U < 32U)
      encoded.push_back(kAlphabet[(triple >> 6) & 0x3FU]);
    if (index + 2U < 32U)
      encoded.push_back(kAlphabet[triple & 0x3FU]);
  }
  // Unpadded, as OpenSSH prints it.
  return "SHA256:" + encoded;
}

// Keyboard-interactive responder.
//
// The method PuTTY and OpenSSH fall back to when a server disables PasswordAuthentication but keeps
// KbdInteractiveAuthentication - the common modern default on RHEL/Ubuntu with PAM.
//
// thread_local, not a file static: SSH work runs on worker threads and two connections must not
// share one password pointer. libssh2 takes ownership of each response and frees it, so the text
// is duplicated with malloc rather than new.
thread_local const std::string* keyboard_interactive_password = nullptr;

void keyboard_interactive_responder(const char* /*name*/, int /*name_length*/,
                                    const char* /*instruction*/, int /*instruction_length*/,
                                    int prompt_count, const LIBSSH2_USERAUTH_KBDINT_PROMPT* /*prompts*/,
                                    LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                                    void** /*abstract*/) {
  if (keyboard_interactive_password == nullptr || responses == nullptr)
    return;
  // Answer every prompt with the supplied password. A server that asks something else - a token
  // code, for example - simply fails authentication, which is the honest outcome; SAT has nothing
  // else to offer and must not invent an answer.
  for (int index = 0; index < prompt_count; ++index) {
    const std::size_t size = keyboard_interactive_password->size();
    char* answer = static_cast<char*>(std::malloc(size + 1U));
    if (answer == nullptr) {
      responses[index].text = nullptr;
      responses[index].length = 0;
      continue;
    }
    std::memcpy(answer, keyboard_interactive_password->c_str(), size);
    answer[size] = '\0';
    responses[index].text = answer;
    responses[index].length = static_cast<unsigned int>(size);
  }
}

Result<ConnectedSession> connect_session(const SshConnectionOptions& options,
                                         const CancellationToken& cancel,
                                         bool authenticate) {
  // SSH failures are the hardest thing to work remotely: the engineer sees one line in the GUI and
  // the cause is three round trips earlier. Host and port only - never the user name, password or
  // key passphrase.
  DebugScope scope("SSH", "connect " + options.host + ":" + std::to_string(options.port) +
                              (authenticate ? " (authenticated)" : " (probe)"));
  if (!libssh_lifetime().ok)
    return Result<ConnectedSession>::failure(ssh_error("initialize", "libssh2 initialization failed"));
  if (options.host.empty())
    return Result<ConnectedSession>::failure(ssh_error("connect", "SSH host is required"));
  if (authenticate && options.username.empty())
    return Result<ConnectedSession>::failure(ssh_error("authenticate", "SSH username is required"));
  if (cancel.is_cancelled())
    return Result<ConnectedSession>::failure(ssh_error("connect", "SSH operation was cancelled"));

  ConnectedSession connected;
  if (!connected.network.ok)
    return Result<ConnectedSession>::failure(ssh_error("Winsock startup", "Could not initialize the socket subsystem"));

  addrinfo hints{};
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;
  addrinfo* raw = nullptr;
  const std::string service = std::to_string(options.port);
  const int resolve = getaddrinfo(options.host.c_str(), service.c_str(), &hints, &raw);
  if (resolve != 0)
    return Result<ConnectedSession>::failure(ssh_error("resolve", "Could not resolve SSH host " + options.host, resolve));
  std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addresses(raw, &freeaddrinfo);

  // The key exchange against a current OpenSSH (10.2 in testing) fails now and then with "Unable to
  // exchange encryption keys", LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE: 3 probes in 400 failed, and with
  // this retry none in 1,000. The server logs nothing, and the next connection succeeds. Nothing
  // has been sent to the host at that point, so that one failure is retried once on a new
  // connection. A method mismatch (LIBSSH2_ERROR_KEX_FAILURE) would fail again and is not retried.
  for (int attempt = 1;; ++attempt) {
    for (addrinfo* current = addresses.get(); current != nullptr; current = current->ai_next) {
      if (cancel.is_cancelled()) break;
      NativeSocket candidate = socket(current->ai_family, current->ai_socktype, current->ai_protocol);
      if (candidate == invalid_socket) continue;
      if (::connect(candidate, current->ai_addr, static_cast<int>(current->ai_addrlen)) == 0) {
        connected.socket.reset(new NativeSocket(candidate));
        break;
      }
      close_socket(candidate);
    }
    if (!connected.socket)
      return Result<ConnectedSession>::failure(ssh_error("connect", "Could not connect to SSH endpoint " + options.host + ":" + service));

    LIBSSH2_SESSION* raw_session = libssh2_session_init();
    if (raw_session == nullptr)
      return Result<ConnectedSession>::failure(ssh_error("session", "libssh2 could not allocate an SSH session"));
    connected.session.reset(raw_session);
    libssh2_session_set_blocking(connected.session.get(), 1);
    libssh2_session_set_timeout(connected.session.get(), static_cast<long>(std::max<std::uint32_t>(1U, options.timeout_seconds) * 1000U));
    const int handshake = libssh2_session_handshake(connected.session.get(), *connected.socket);
    if (handshake == 0)
      break;
    if (handshake == LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE && attempt == 1 && !cancel.is_cancelled()) {
      write_debug_log(DebugLevel::warning, "SSH",
                      "Key exchange failed; connecting again once: " +
                          ssh_library_error(connected.session.get(), "handshake", "").message);
      connected.session.reset();
      connected.socket.reset();
      continue;
    }
    return Result<ConnectedSession>::failure(ssh_library_error(connected.session.get(), "handshake", "SSH transport handshake failed"));
  }

  connected.host_key.fingerprint_sha256 = sha256_fingerprint(connected.session.get());
  connected.host_key.algorithm = hostkey_algorithm(connected.session.get());
  if (connected.host_key.fingerprint_sha256.empty())
    return Result<ConnectedSession>::failure(ssh_error("host key", "Could not calculate the remote SSH host-key SHA-256 fingerprint"));

  if (!options.expected_host_key_sha256.empty() &&
      !fingerprints_match(options.expected_host_key_sha256,
                          connected.host_key.fingerprint_sha256)) {
    return Result<ConnectedSession>::failure(
        ssh_error("host key", "SSH host-key mismatch. Expected " + options.expected_host_key_sha256 +
                                  " but received " + connected.host_key.fingerprint_sha256));
  }

  if (!authenticate)
    return Result<ConnectedSession>::success(std::move(connected));
  if (options.expected_host_key_sha256.empty())
    return Result<ConnectedSession>::failure(
        ssh_error("host key", "The SSH host key has not been trusted yet. Remote SHA-256 fingerprint: " +
                                  connected.host_key.fingerprint_sha256));

  if (options.private_key_path.empty() && options.password.empty()) {
    return Result<ConnectedSession>::failure(
        ssh_error("authenticate", "Provide a password or private key for SSH authentication"));
  }

  // Ask the server what it will accept before trying anything.
  //
  // Without this SAT attempted password authentication against servers that do not offer it -
  // PasswordAuthentication no with KbdInteractiveAuthentication yes is the common modern default -
  // and reported a bare libssh2 code. PuTTY and OpenSSH succeed there because they fall back to
  // keyboard-interactive, which is why "other tools connect from the same machine".
  std::string offered;
  if (const char* list = libssh2_userauth_list(
          connected.session.get(), options.username.c_str(),
          static_cast<unsigned int>(options.username.size()));
      list != nullptr) {
    offered = list;
  }
  const auto server_offers = [&](std::string_view method) {
    // An empty list means the server did not answer the query; try anyway rather than refuse.
    return offered.empty() || offered.find(method) != std::string::npos;
  };

  int authentication = -1;
  std::string attempted;
  const auto note_attempt = [&](std::string_view method) {
    if (!attempted.empty())
      attempted += ", ";
    attempted += std::string(method);
  };

  if (!options.private_key_path.empty() && server_offers("publickey")) {
    // A key path that does not exist is not an authentication failure, and reporting it as one
    // sends the engineer to check the account and the server. This cost a round trip when a key
    // under %TEMP% was removed by Windows disk cleanup between one run and the next: SAT reported
    // "authentication failed" about a file that was no longer there.
    std::error_code key_error;
    if (!std::filesystem::exists(options.private_key_path, key_error) || key_error) {
      return Result<ConnectedSession>::failure(ssh_error(
          "authenticate",
          "The private key file was not found: " + path_to_utf8(options.private_key_path)));
    }
    note_attempt("publickey");
    const std::string key = path_to_utf8(options.private_key_path);
    authentication = libssh2_userauth_publickey_fromfile_ex(
        connected.session.get(), options.username.c_str(), static_cast<unsigned int>(options.username.size()),
        nullptr, key.c_str(), options.private_key_passphrase.empty() ? nullptr : options.private_key_passphrase.c_str());
  }

  if (authentication != 0 && !options.password.empty() && server_offers("password")) {
    note_attempt("password");
    authentication = libssh2_userauth_password_ex(
        connected.session.get(), options.username.c_str(), static_cast<unsigned int>(options.username.size()),
        options.password.c_str(), static_cast<unsigned int>(options.password.size()), nullptr);
  }

  if (authentication != 0 && !options.password.empty() && server_offers("keyboard-interactive")) {
    note_attempt("keyboard-interactive");
    keyboard_interactive_password = &options.password;
    authentication = libssh2_userauth_keyboard_interactive_ex(
        connected.session.get(), options.username.c_str(),
        static_cast<unsigned int>(options.username.size()), &keyboard_interactive_responder);
    keyboard_interactive_password = nullptr;
  }

  if (authentication != 0) {
    // Name what was tried and what the server said it accepts. A bare code sent an engineer looking
    // at credentials when the method was the problem.
    std::string message = "SSH authentication failed";
    if (!attempted.empty())
      message += ". SAT tried: " + attempted;
    else
      message += ". SAT had no credential matching a method this server accepts";
    if (!offered.empty())
      message += ". The server accepts: " + offered;

    // The method matched and the credential was still refused, which is a different problem from
    // offering a method the server does not want - and the first thing to check is the one a
    // Windows engineer will not think of. Linux user names are case sensitive; Windows ones are
    // not, so "Wilow" reaches a server whose account is "wilow" and fails here with the key
    // perfectly valid.
    const bool method_was_accepted =
        !attempted.empty() && !offered.empty() &&
        offered.find(attempted.substr(0, attempted.find(','))) != std::string::npos;
    if (method_was_accepted) {
      message += ". The method was accepted and the credential refused, so check the user name "
                 "matches the account on the host exactly - Linux user names are case sensitive - "
                 "and that this account is the one holding the key or password";
    }
    return Result<ConnectedSession>::failure(ssh_error("authenticate", message, authentication));
  }
  return Result<ConnectedSession>::success(std::move(connected));
}

Result<SftpPtr> open_sftp(LIBSSH2_SESSION* session) {
  LIBSSH2_SFTP* raw = libssh2_sftp_init(session);
  if (raw != nullptr)
    return Result<SftpPtr>::success(SftpPtr(raw));

  // Report what libssh2 actually said. Claiming "the remote SSH service did not provide an SFTP
  // subsystem" for every failure is wrong and actively misleading: a server that WinSCP connects to
  // over SFTP on the same port plainly has the subsystem, and the real cause was something else
  // entirely - a channel/window failure, an EAGAIN on a blocking session, or an auth-scope problem.
  // The engineer needs the true reason, not a guess.
  char* detail = nullptr;
  int detail_length = 0;
  const int code = libssh2_session_last_error(session, &detail, &detail_length, 0);
  std::string message = "Could not open an SFTP session";
  if (detail != nullptr && detail_length > 0)
    message += ": " + std::string(detail, static_cast<std::size_t>(detail_length));
  if (code == LIBSSH2_ERROR_SFTP_PROTOCOL)
    message += " (the host answered, but refused the SFTP subsystem)";
  else if (code == LIBSSH2_ERROR_CHANNEL_FAILURE)
    message += " (the host refused to open the channel; sshd may forbid the subsystem for this user)";
  message += " [libssh2 error " + std::to_string(code) + "]";
  write_debug_log(DebugLevel::error, "SSH", "SFTP init failed: " + message);
  return Result<SftpPtr>::failure(ssh_error("SFTP", std::move(message), code));
}

std::string join_remote(std::string_view parent, std::string_view name) {
  std::string result(parent);
  if (result.empty()) result = "/";
  if (result.size() > 1U && result.back() == '/') result.pop_back();
  if (result != "/") result += '/';
  result += name;
  return result;
}

// Runs one command on a session that is ALREADY connected and authenticated.
//
// Every public entry point used to call connect_session() for itself, so browsing a directory whose
// host offers no SFTP subsystem opened two full SSH connections back to back: one for the SFTP
// attempt and a second for the `ls` fallback. That is what put a repeated "Host key received" entry
// in the activity log for a single click, and it doubles the authentication load on a host that may
// rate-limit connections. The session is the expensive resource; a channel is not.
Result<SshCommandResult> execute_on_session(LIBSSH2_SESSION* session,
                                            std::string_view command,
                                            const CancellationToken& cancel,
                                            ProgressCallback progress) {
  if (command.empty()) return Result<SshCommandResult>::failure(ssh_error("execute", "Remote command is empty"));
  ChannelPtr channel(libssh2_channel_open_session(session));
  if (!channel) {
    char* detail = nullptr;
    int detail_length = 0;
    const int code = libssh2_session_last_error(session, &detail, &detail_length, 0);
    std::string message = "Could not open an SSH command channel";
    if (detail != nullptr && detail_length > 0)
      message += ": " + std::string(detail, static_cast<std::size_t>(detail_length));
    message += " [libssh2 error " + std::to_string(code) + "]";
    return Result<SshCommandResult>::failure(ssh_error("execute", std::move(message), code));
  }
  const std::string command_text(command);
  const int started = libssh2_channel_exec(channel.get(), command_text.c_str());
  if (started != 0) return Result<SshCommandResult>::failure(ssh_library_error(session, "execute", "Remote command could not be started"));
  SshCommandResult result;
  std::array<char, 16 * 1024> buffer{};
  while (!cancel.is_cancelled()) {
    bool read_any = false;
    const auto out = libssh2_channel_read(channel.get(), buffer.data(), buffer.size());
    if (out > 0) {
      result.standard_output.append(buffer.data(), static_cast<std::size_t>(out));
      read_any = true;
    } else if (out < 0 && out != LIBSSH2_ERROR_EAGAIN) {
      return Result<SshCommandResult>::failure(ssh_library_error(session, "execute", "Reading remote command output failed"));
    }
    const auto err = libssh2_channel_read_stderr(channel.get(), buffer.data(), buffer.size());
    if (err > 0) {
      result.standard_error.append(buffer.data(), static_cast<std::size_t>(err));
      read_any = true;
    } else if (err < 0 && err != LIBSSH2_ERROR_EAGAIN) {
      return Result<SshCommandResult>::failure(ssh_library_error(session, "execute", "Reading remote command error output failed"));
    }
    if (progress && read_any)
      progress(ProgressEvent{"ssh-command", command_text,
                             result.standard_output.size() + result.standard_error.size(), 0, 0.0, 0.0, 0});
    if (libssh2_channel_eof(channel.get()) != 0) break;
    if (!read_any) std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (cancel.is_cancelled()) return Result<SshCommandResult>::failure(ssh_error("execute", "Remote command was cancelled"));
  libssh2_channel_wait_closed(channel.get());
  result.exit_status = libssh2_channel_get_exit_status(channel.get());
  return Result<SshCommandResult>::success(std::move(result));
}

// Directory listing over the shell, used when the host offers no SFTP subsystem.
//
// A Veeam hardened repository routinely disables SFTP in sshd_config while keeping an interactive
// shell, and that is exactly the host an engineer needs to browse. Refusing outright made the
// Explorer useless on the machines it matters most for. `ls -lA --time-style=+%s` gives type, size
// and mtime in one parseable pass and exists on every supported Linux repository host.
Result<std::vector<SftpEntry>> list_directory_via_shell(LIBSSH2_SESSION* session,
                                                        const std::string& path,
                                                        const CancellationToken& cancel) {
  // Single-quote the path and escape embedded quotes so a directory name cannot break out of the
  // command. The path comes from the engineer, but it is still untrusted text.
  std::string quoted;
  quoted.reserve(path.size() + 2U);
  quoted.push_back('\'');
  for (const char c : path) {
    if (c == '\'') quoted += "'\\''";
    else quoted.push_back(c);
  }
  quoted.push_back('\'');

  auto listing = execute_on_session(
      session, "LC_ALL=C ls -lA --time-style=+%s -- " + quoted + " 2>/dev/null", cancel, nullptr);
  if (!listing.ok())
    return Result<std::vector<SftpEntry>>::failure(listing.error());

  std::vector<SftpEntry> entries;
  std::istringstream stream(listing.value().standard_output);
  std::string line;
  while (std::getline(stream, line) && entries.size() < 20000U) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty() || line.rfind("total ", 0) == 0) continue;
    // <perms> <links> <owner> <group> <size> <epoch> <name...>
    std::istringstream fields(line);
    std::string permissions, links, owner, group, size_text, epoch;
    if (!(fields >> permissions >> links >> owner >> group >> size_text >> epoch)) continue;
    std::string name;
    std::getline(fields, name);
    while (!name.empty() && name.front() == ' ') name.erase(name.begin());
    if (name.empty() || name == "." || name == "..") continue;
    // `ls -l` renders symlinks as "link -> target"; keep the link's own name.
    if (const auto arrow = name.find(" -> "); arrow != std::string::npos) name.resize(arrow);

    SftpEntry entry;
    entry.name = name;
    entry.path = join_remote(path, name);
    entry.directory = !permissions.empty() && permissions.front() == 'd';
    entry.symlink = !permissions.empty() && permissions.front() == 'l';
    try { entry.size = static_cast<std::uint64_t>(std::stoull(size_text)); } catch (...) { entry.size = 0U; }
    try { entry.modified_unix = static_cast<std::int64_t>(std::stoll(epoch)); } catch (...) { entry.modified_unix = 0; }
    entries.push_back(std::move(entry));
  }
  return Result<std::vector<SftpEntry>>::success(std::move(entries));
}

// One SFTP directory listing, folders first.
Result<std::vector<SftpEntry>> read_sftp_directory(LIBSSH2_SFTP* sftp, const std::string& path,
                                                   const CancellationToken& cancel) {
  SftpHandlePtr directory(libssh2_sftp_opendir(sftp, path.c_str()));
  if (!directory)
    return Result<std::vector<SftpEntry>>::failure(ssh_error("list directory", "Could not open remote directory " + path));

  std::vector<SftpEntry> entries;
  std::array<char, 4096> name{};
  while (!cancel.is_cancelled() && entries.size() < 20000U) {
    LIBSSH2_SFTP_ATTRIBUTES attributes{};
    const int count = libssh2_sftp_readdir_ex(directory.get(), name.data(), name.size(), nullptr, 0, &attributes);
    if (count <= 0) break;
    const std::string entry_name(name.data(), static_cast<std::size_t>(count));
    if (entry_name == "." || entry_name == "..") continue;
    SftpEntry entry;
    entry.name = entry_name;
    entry.path = join_remote(path, entry_name);
    if ((attributes.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0U) {
      entry.permissions = static_cast<std::uint32_t>(attributes.permissions & 0xFFFFFFFFUL);
      entry.directory = LIBSSH2_SFTP_S_ISDIR(attributes.permissions) != 0;
#ifdef LIBSSH2_SFTP_S_ISLNK
      entry.symlink = LIBSSH2_SFTP_S_ISLNK(attributes.permissions) != 0;
#endif
    }
    if ((attributes.flags & LIBSSH2_SFTP_ATTR_SIZE) != 0U)
      entry.size = static_cast<std::uint64_t>(attributes.filesize);
    if ((attributes.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) != 0U)
      entry.modified_unix = static_cast<std::uint64_t>(attributes.mtime);
    entries.push_back(std::move(entry));
  }
  if (cancel.is_cancelled())
    return Result<std::vector<SftpEntry>>::failure(ssh_error("list directory", "SSH directory listing was cancelled"));
  std::stable_sort(entries.begin(), entries.end(), [](const SftpEntry& left, const SftpEntry& right) {
    if (left.directory != right.directory) return left.directory;
    return ascii_lower(left.name) < ascii_lower(right.name);
  });
  return Result<std::vector<SftpEntry>>::success(std::move(entries));
}
#endif

} // namespace

bool ssh_available() noexcept {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  return true;
#else
  return false;
#endif
}

Result<SshHostKeyInfo> ssh_probe_host_key(const SshConnectionOptions& options,
                                          const CancellationToken& cancel) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  auto connected = connect_session(options, cancel, false);
  if (!connected.ok()) return Result<SshHostKeyInfo>::failure(connected.error());
  return Result<SshHostKeyInfo>::success(connected.value().host_key);
#else
  static_cast<void>(options); static_cast<void>(cancel);
  return Result<SshHostKeyInfo>::failure(ssh_error("probe", "SSH/SFTP support is unavailable in this build"));
#endif
}

Result<std::vector<SftpEntry>> ssh_list_directory(const SshConnectionOptions& options,
                                                   std::string_view remote_path,
                                                   const CancellationToken& cancel) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok()) return Result<std::vector<SftpEntry>>::failure(connected.error());
  auto sftp_result = open_sftp(connected.value().session.get());
  if (!sftp_result.ok()) {
    // No SFTP subsystem. Fall back to the shell rather than failing the browse outright.
    const std::string path = remote_path.empty() ? "/" : std::string(remote_path);
    auto shell_listing = list_directory_via_shell(connected.value().session.get(), path, cancel);
    if (shell_listing.ok()) return shell_listing;
    return Result<std::vector<SftpEntry>>::failure(sftp_result.error());
  }
  SftpPtr sftp = std::move(sftp_result.value());
  const std::string path = remote_path.empty() ? "/" : std::string(remote_path);
  return read_sftp_directory(sftp.get(), path, cancel);
#else
  static_cast<void>(options); static_cast<void>(remote_path); static_cast<void>(cancel);
  return Result<std::vector<SftpEntry>>::failure(ssh_error("list directory", "SSH/SFTP support is unavailable in this build"));
#endif
}

Result<std::vector<SftpEntry>> ssh_list_nearest_directory(const SshConnectionOptions& options,
                                                          std::string_view remote_path,
                                                          std::string& listed_path,
                                                          const CancellationToken& cancel) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok()) return Result<std::vector<SftpEntry>>::failure(connected.error());
  // No SFTP subsystem: each folder is listed through the shell instead, as ssh_list_directory does.
  auto sftp_result = open_sftp(connected.value().session.get());
  std::string path = remote_path.empty() ? "/" : std::string(remote_path);
  Error first_error;
  bool failed = false;
  for (;;) {
    auto listed = sftp_result.ok()
                      ? read_sftp_directory(sftp_result.value().get(), path, cancel)
                      : list_directory_via_shell(connected.value().session.get(), path, cancel);
    if (listed.ok()) {
      listed_path = path;
      return listed;
    }
    if (!failed) {
      first_error = listed.error();
      failed = true;
    }
    const std::string parent = ssh_parent_directory(path);
    if (cancel.is_cancelled() || parent == path)
      return Result<std::vector<SftpEntry>>::failure(first_error);
    path = parent;
  }
#else
  static_cast<void>(options); static_cast<void>(remote_path); static_cast<void>(listed_path);
  static_cast<void>(cancel);
  return Result<std::vector<SftpEntry>>::failure(ssh_error("list directory", "SSH/SFTP support is unavailable in this build"));
#endif
}

std::string ssh_parent_directory(std::string_view remote_path) {
  std::string path(remote_path);
  while (path.size() > 1U && path.back() == '/')
    path.pop_back();
  const std::size_t cut = path.find_last_of('/');
  if (cut == std::string::npos || cut == 0U)
    return "/";
  return path.substr(0, cut);
}

Status ssh_download_file(const SshConnectionOptions& options,
                         std::string_view remote_path,
                         const std::filesystem::path& local_path,
                         const CancellationToken& cancel,
                         ProgressCallback progress) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok()) return Status::failure(connected.error());
  const std::string remote(remote_path);
  auto sftp_result = open_sftp(connected.value().session.get());
  if (!sftp_result.ok()) {
    // Upload already falls back to SCP when the SFTP subsystem is refused; download did not, so a
    // hardened repository that permits SCP and a shell could receive files but never hand any
    // back. Pulling logs off the box is the whole point of reaching it, so the fallback has to
    // exist on both directions.
    libssh2_struct_stat stat{};
    LIBSSH2_CHANNEL* raw =
        libssh2_scp_recv2(connected.value().session.get(), remote.c_str(), &stat);
    if (raw == nullptr)
      return Status::failure(sftp_result.error());
    ChannelPtr channel(raw);

    std::error_code scp_error;
    std::filesystem::create_directories(local_path.parent_path(), scp_error);
    std::filesystem::path scp_temporary = local_path;
    scp_temporary += L".sat-download-part";
    scp_error.clear();
    std::filesystem::remove(scp_temporary, scp_error);
    std::ofstream scp_output(scp_temporary, std::ios::binary | std::ios::trunc);
    if (!scp_output)
      return Status::failure(ssh_error("download", "Could not create temporary local file " +
                                                       path_to_utf8(scp_temporary)));

    const auto expected = static_cast<std::uint64_t>(stat.st_size);
    std::uint64_t received = 0;
    std::array<char, 64 * 1024> scp_buffer{};
    while (received < expected && !cancel.is_cancelled()) {
      const auto want = static_cast<std::size_t>(
          std::min<std::uint64_t>(scp_buffer.size(), expected - received));
      const auto count = libssh2_channel_read(channel.get(), scp_buffer.data(), want);
      if (count < 0) {
        scp_output.close();
        std::filesystem::remove(scp_temporary, scp_error);
        return Status::failure(ssh_error("download", "SCP read failed", static_cast<int>(count)));
      }
      if (count == 0)
        break;
      scp_output.write(scp_buffer.data(), count);
      if (!scp_output) {
        // Completeness was measured against bytes read off the socket, not bytes committed to
        // disk: a full local volume let every read succeed while the write silently failed, and a
        // truncated .sat-download-part was then renamed over local_path as if whole. The SFTP
        // branch below already checks the stream after each write; the SCP fallback must too.
        scp_output.close();
        std::filesystem::remove(scp_temporary, scp_error);
        return Status::failure(
            ssh_error("download", "Writing the temporary local file failed; nothing was kept"));
      }
      received += static_cast<std::uint64_t>(count);
      if (progress) progress(ProgressEvent{"ssh-download", remote, received, 0, 0.0, 0.0, expected});
    }
    scp_output.close();
    if (!scp_output) {
      std::filesystem::remove(scp_temporary, scp_error);
      return Status::failure(
          ssh_error("download", "Flushing the temporary local file failed; nothing was kept"));
    }
    if (cancel.is_cancelled() || received != expected) {
      std::filesystem::remove(scp_temporary, scp_error);
      return Status::failure(ssh_error(
          "download", cancel.is_cancelled()
                          ? "SSH download was cancelled; the partial local file was removed"
                          : "SCP transfer ended before the whole file arrived; nothing was kept"));
    }
    scp_error.clear();
    std::filesystem::remove(local_path, scp_error);
    scp_error.clear();
    std::filesystem::rename(scp_temporary, local_path, scp_error);
    if (scp_error)
      return Status::failure(
          ssh_error("download", "Could not commit downloaded file: " + scp_error.message()));
    return Status::success();
  }
  SftpPtr sftp = std::move(sftp_result.value());
  SftpHandlePtr file(libssh2_sftp_open(sftp.get(), remote.c_str(), LIBSSH2_FXF_READ, 0));
  if (!file) return Status::failure(ssh_error("download", "Could not open remote file " + remote));
  std::error_code error;
  std::filesystem::create_directories(local_path.parent_path(), error);
  if (error) return Status::failure(ssh_error("download", "Could not create local destination directory: " + error.message()));
  std::filesystem::path temporary = local_path;
  temporary += L".sat-download-part";
  std::filesystem::remove(temporary, error);
  error.clear();
  std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
  if (!output) return Status::failure(ssh_error("download", "Could not create temporary local file " + path_to_utf8(temporary)));
  const auto cleanup = [&] {
    output.close();
    std::error_code cleanup_error;
    std::filesystem::remove(temporary, cleanup_error);
  };
  // The size the server reports, so progress can read as a share of the file.
  std::uint64_t expected = 0;
  LIBSSH2_SFTP_ATTRIBUTES attributes{};
  if (libssh2_sftp_fstat(file.get(), &attributes) == 0 &&
      (attributes.flags & LIBSSH2_SFTP_ATTR_SIZE) != 0)
    expected = attributes.filesize;
  std::array<char, 64 * 1024> buffer{};
  std::uint64_t total = 0;
  while (!cancel.is_cancelled()) {
    const auto count = libssh2_sftp_read(file.get(), buffer.data(), buffer.size());
    if (count == 0) break;
    if (count < 0) {
      cleanup();
      return Status::failure(ssh_library_error(connected.value().session.get(), "download",
                                               "SFTP read failed"));
    }
    output.write(buffer.data(), count);
    if (!output) {
      cleanup();
      return Status::failure(ssh_error("download", "Writing the temporary local file failed"));
    }
    total += static_cast<std::uint64_t>(count);
    if (progress) progress(ProgressEvent{"ssh-download", remote, total, 0, 0.0, 0.0, expected});
  }
  if (cancel.is_cancelled()) {
    cleanup();
    return Status::failure(ssh_error("download", "SSH download was cancelled; the partial local file was removed"));
  }
  output.close();
  if (!output) {
    cleanup();
    return Status::failure(ssh_error("download", "Flushing the temporary local file failed"));
  }
  std::filesystem::remove(local_path, error);
  error.clear();
  std::filesystem::rename(temporary, local_path, error);
  if (error) {
    cleanup();
    return Status::failure(ssh_error("download", "Could not commit downloaded file: " + error.message()));
  }
  return Status::success();
#else
  static_cast<void>(options); static_cast<void>(remote_path); static_cast<void>(local_path); static_cast<void>(cancel); static_cast<void>(progress);
  return Status::failure(ssh_error("download", "SSH/SFTP support is unavailable in this build"));
#endif
}

Status ssh_upload_file(const SshConnectionOptions& options,
                       const std::filesystem::path& local_path,
                       std::string_view remote_path,
                       const CancellationToken& cancel,
                       ProgressCallback progress) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  std::ifstream input(local_path, std::ios::binary);
  if (!input) return Status::failure(ssh_error("upload", "Could not open local file " + path_to_utf8(local_path)));
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok()) return Status::failure(connected.error());
  auto sftp_result = open_sftp(connected.value().session.get());
  if (!sftp_result.ok()) {
    // Hardened repositories commonly disable the SFTP subsystem while keeping SCP and a shell.
    // libssh2 speaks SCP directly, so upload the file that way rather than refusing.
    input.clear();
    input.seekg(0, std::ios::end);
    const auto total = static_cast<std::uint64_t>(input.tellg());
    input.seekg(0, std::ios::beg);
    const std::string scp_remote(remote_path);
    LIBSSH2_CHANNEL* raw = libssh2_scp_send64(connected.value().session.get(), scp_remote.c_str(),
                                              0644, static_cast<libssh2_int64_t>(total), 0, 0);
    if (raw == nullptr)
      return Status::failure(ssh_error(
          "upload",
          "The remote host provides neither an SFTP subsystem nor SCP. Enable one, or use Remote "
          "Shell to move the file."));
    ChannelPtr channel(raw);
    std::array<char, 32768> buffer{};
    std::uint64_t sent = 0;
    while (input.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || input.gcount() > 0) {
      if (cancel.is_cancelled())
        return Status::failure(ssh_error("upload", "Upload cancelled"));
      std::size_t remaining = static_cast<std::size_t>(input.gcount());
      const char* cursor = buffer.data();
      while (remaining > 0) {
        const auto written = libssh2_channel_write(channel.get(), cursor, remaining);
        if (written < 0)
          return Status::failure(ssh_error("upload", "SCP write failed", static_cast<int>(written)));
        cursor += written;
        remaining -= static_cast<std::size_t>(written);
        sent += static_cast<std::uint64_t>(written);
      }
      if (progress) progress(ProgressEvent{"ssh-upload-scp", scp_remote, sent, 0, 0.0, 0.0, total});
    }
    libssh2_channel_send_eof(channel.get());
    libssh2_channel_wait_eof(channel.get());
    libssh2_channel_wait_closed(channel.get());
    return Status::success();
  }
  SftpPtr sftp = std::move(sftp_result.value());
  const std::string remote(remote_path);
  const std::string temporary = remote + ".sat-upload-" +
      std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
  const auto cleanup_remote = [&] { static_cast<void>(libssh2_sftp_unlink(sftp.get(), temporary.c_str())); };
  SftpHandlePtr file(libssh2_sftp_open(sftp.get(), temporary.c_str(),
                                      LIBSSH2_FXF_WRITE | LIBSSH2_FXF_CREAT | LIBSSH2_FXF_TRUNC,
                                      0600));
  if (!file) return Status::failure(ssh_error("upload", "Could not create temporary remote upload file"));
  std::error_code size_error;
  const std::uint64_t local_size = std::filesystem::file_size(local_path, size_error);
  const std::uint64_t expected = size_error ? 0U : local_size;
  std::array<char, 64 * 1024> buffer{};
  std::uint64_t total = 0;
  while (!cancel.is_cancelled() && input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const std::streamsize got = input.gcount();
    if (got <= 0) break;
    std::streamsize offset = 0;
    while (offset < got && !cancel.is_cancelled()) {
      const auto written = libssh2_sftp_write(file.get(), buffer.data() + offset,
                                               static_cast<std::size_t>(got - offset));
      if (written < 0) {
        file.reset();
        cleanup_remote();
        return Status::failure(ssh_library_error(connected.value().session.get(), "upload",
                                                 "SFTP write failed"));
      }
      offset += written;
      total += static_cast<std::uint64_t>(written);
      if (progress) progress(ProgressEvent{"ssh-upload", remote, total, 0, 0.0, 0.0, expected});
    }
  }
  if (input.bad()) {
    file.reset();
    cleanup_remote();
    return Status::failure(ssh_error("upload", "Reading the local upload source failed"));
  }
  if (cancel.is_cancelled()) {
    file.reset();
    cleanup_remote();
    return Status::failure(ssh_error("upload", "SSH upload was cancelled; the temporary remote file was removed"));
  }
  file.reset();
  const long rename_flags = LIBSSH2_SFTP_RENAME_OVERWRITE | LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE;
  int renamed = libssh2_sftp_rename_ex(sftp.get(), temporary.c_str(), static_cast<unsigned int>(temporary.size()),
                                       remote.c_str(), static_cast<unsigned int>(remote.size()), rename_flags);
  if (renamed != 0) {
    // Some servers reject ATOMIC/NATIVE flags even though ordinary rename works.
    renamed = libssh2_sftp_rename_ex(sftp.get(), temporary.c_str(), static_cast<unsigned int>(temporary.size()),
                                     remote.c_str(), static_cast<unsigned int>(remote.size()),
                                     LIBSSH2_SFTP_RENAME_OVERWRITE);
  }
  if (renamed != 0) {
    // SFTP version 3 defines rename as FAILING when the destination exists, and OpenSSH's server
    // implements exactly that - it ignores the OVERWRITE flag rather than honouring it. Without
    // this step SAT can upload a file once and never replace it, which is precisely what an
    // engineer does when they correct a script or re-send a tool.
    //
    // Removing the destination first is the standard fallback. It gives up atomicity for a moment,
    // so it is the LAST resort, after both flag-based attempts: on a server that does support
    // atomic rename we never reach here.
    libssh2_sftp_unlink_ex(sftp.get(), remote.c_str(), static_cast<unsigned int>(remote.size()));
    renamed = libssh2_sftp_rename_ex(sftp.get(), temporary.c_str(),
                                     static_cast<unsigned int>(temporary.size()), remote.c_str(),
                                     static_cast<unsigned int>(remote.size()),
                                     LIBSSH2_SFTP_RENAME_OVERWRITE);
  }
  if (renamed != 0) {
    cleanup_remote();
    return Status::failure(ssh_library_error(
        connected.value().session.get(), "upload",
        "The upload completed but the temporary remote file could not be committed"));
  }
  return Status::success();
#else
  static_cast<void>(options); static_cast<void>(local_path); static_cast<void>(remote_path); static_cast<void>(cancel); static_cast<void>(progress);
  return Status::failure(ssh_error("upload", "SSH/SFTP support is unavailable in this build"));
#endif
}

Result<SshCommandResult> ssh_execute_command(const SshConnectionOptions& options,
                                             std::string_view command,
                                             const CancellationToken& cancel,
                                             ProgressCallback progress) {
#ifdef SUPPORT_ASSIST_HAS_LIBSSH2
  if (command.empty()) return Result<SshCommandResult>::failure(ssh_error("execute", "Remote command is empty"));
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok()) return Result<SshCommandResult>::failure(connected.error());
  return execute_on_session(connected.value().session.get(), command, cancel, std::move(progress));
#else
  static_cast<void>(options); static_cast<void>(command); static_cast<void>(cancel); static_cast<void>(progress);
  return Result<SshCommandResult>::failure(ssh_error("execute", "SSH/SFTP support is unavailable in this build"));
#endif
}

// --- Interactive shell -------------------------------------------------------------------------

#ifdef SUPPORT_ASSIST_HAS_LIBSSH2

struct SshShell {
  // Order matters: the channel must be released before the session, and the session before the
  // socket. Declaring them in this order makes destruction correct without a hand-written dtor.
  ConnectedSession connection;
  ChannelPtr channel;
  bool finished = false;
};

Result<std::shared_ptr<SshShell>> ssh_open_shell(const SshConnectionOptions& options,
                                                 int columns,
                                                 int rows,
                                                 const CancellationToken& cancel) {
  auto connected = connect_session(options, cancel, true);
  if (!connected.ok())
    return Result<std::shared_ptr<SshShell>>::failure(connected.error());

  auto shell = std::make_shared<SshShell>();
  shell->connection = std::move(connected.value());

  LIBSSH2_CHANNEL* raw = libssh2_channel_open_session(shell->connection.session.get());
  if (raw == nullptr) {
    // Report what libssh2 actually said. "Refused a session channel" was a guess, and it sent this
    // in the wrong direction once already: the same server accepted the channel from the Linux
    // build and not the Windows one, which no error code alone would have explained.
    char* detail = nullptr;
    int detail_length = 0;
    const int code = libssh2_session_last_error(shell->connection.session.get(), &detail,
                                                &detail_length, 0);
    std::string message = "Could not open a session channel";
    if (detail != nullptr && detail_length > 0)
      message += ": " + std::string(detail, static_cast<std::size_t>(detail_length));
    return Result<std::shared_ptr<SshShell>>::failure(ssh_error("open shell", message, code));
  }
  shell->channel = ChannelPtr(raw);

  // Ask for a PTY. Without one an interactive shell produces no prompt and pagers refuse to run,
  // which is the whole point of this channel rather than an exec channel.
  const int pty = libssh2_channel_request_pty_ex(
      shell->channel.get(), "xterm-256color", 14U, nullptr, 0U,
      std::max(1, columns), std::max(1, rows), 0, 0);
  if (pty != 0) {
    return Result<std::shared_ptr<SshShell>>::failure(
        ssh_library_error(shell->connection.session.get(), "open shell", "The remote host refused a pseudo-terminal"));
  }

  const int started = libssh2_channel_shell(shell->channel.get());
  if (started != 0) {
    return Result<std::shared_ptr<SshShell>>::failure(
        ssh_library_error(shell->connection.session.get(), "open shell", "The remote host refused to start a shell"));
  }

  // Non-blocking from here. The caller polls on its own thread and must never stall the UI waiting
  // for output that may not come until someone types.
  libssh2_session_set_blocking(shell->connection.session.get(), 0);
  return Result<std::shared_ptr<SshShell>>::success(std::move(shell));
}

Result<std::string> ssh_shell_read(SshShell& shell) {
  if (shell.channel == nullptr)
    return Result<std::string>::failure(ssh_error("read shell", "The shell channel is closed"));

  std::string output;
  std::array<char, 16384> buffer{};
  for (;;) {
    const ssize_t read = libssh2_channel_read(shell.channel.get(), buffer.data(), buffer.size());
    if (read > 0) {
      output.append(buffer.data(), static_cast<std::size_t>(read));
      continue;
    }
    if (read == LIBSSH2_ERROR_EAGAIN)
      break;                       // nothing more right now, which is the normal idle case
    if (read == 0) {
      if (libssh2_channel_eof(shell.channel.get()) != 0)
        shell.finished = true;
      break;
    }
    // A real error ends the session rather than being retried forever.
    shell.finished = true;
    break;
  }
  return Result<std::string>::success(std::move(output));
}

Status ssh_shell_write(SshShell& shell, std::string_view bytes) {
  if (shell.channel == nullptr)
    return Status::failure(ssh_error("write shell", "The shell channel is closed"));
  std::size_t written = 0;
  while (written < bytes.size()) {
    const ssize_t wrote = libssh2_channel_write(shell.channel.get(), bytes.data() + written,
                                                bytes.size() - written);
    if (wrote == LIBSSH2_ERROR_EAGAIN)
      continue;                    // the socket is momentarily full; keystrokes are tiny
    if (wrote < 0) {
      shell.finished = true;
      return Status::failure(ssh_error("write shell", "Could not send to the remote shell",
                                       static_cast<std::int64_t>(wrote)));
    }
    written += static_cast<std::size_t>(wrote);
  }
  return Status::success();
}

Status ssh_shell_resize(SshShell& shell, int columns, int rows) {
  if (shell.channel == nullptr)
    return Status::failure(ssh_error("resize shell", "The shell channel is closed"));
  const int result = libssh2_channel_request_pty_size_ex(
      shell.channel.get(), std::max(1, columns), std::max(1, rows), 0, 0);
  if (result != 0 && result != LIBSSH2_ERROR_EAGAIN) {
    return Status::failure(
        ssh_library_error(shell.connection.session.get(), "resize shell", "The remote host refused the new terminal size"));
  }
  return Status::success();
}

bool ssh_shell_connected(const SshShell& shell) {
  return shell.channel != nullptr && !shell.finished;
}

void ssh_shell_close(SshShell& shell) {
  if (shell.channel != nullptr) {
    libssh2_channel_close(shell.channel.get());
    shell.channel.reset();
  }
  shell.finished = true;
}

#else

struct SshShell {
  bool finished = true;
};

Result<std::shared_ptr<SshShell>> ssh_open_shell(const SshConnectionOptions&, int, int,
                                                 const CancellationToken&) {
  return Result<std::shared_ptr<SshShell>>::failure(
      ssh_error("open shell", "SSH support is unavailable in this build"));
}

Result<std::string> ssh_shell_read(SshShell&) {
  return Result<std::string>::failure(ssh_error("read shell", "SSH support is unavailable in this build"));
}

Status ssh_shell_write(SshShell&, std::string_view) {
  return Status::failure(ssh_error("write shell", "SSH support is unavailable in this build"));
}

Status ssh_shell_resize(SshShell&, int, int) {
  return Status::failure(ssh_error("resize shell", "SSH support is unavailable in this build"));
}

bool ssh_shell_connected(const SshShell&) { return false; }

void ssh_shell_close(SshShell&) {}

#endif

} // namespace support_assist
