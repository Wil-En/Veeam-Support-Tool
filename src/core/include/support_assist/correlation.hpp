#pragma once

#include "support_assist/error.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// Cross-machine, cross-file run correlation.
//
// The problem this solves is the one an engineer solves by hand today: a single backup run leaves
// evidence in different files on different machines, joined only through identifiers that appear in
// different shapes in each. A managed SQL plug-in run writes typed key/value blocks; the VBR service
// writes the same jobSessionId in prose; the data mover leg writes no labelled key at all and can
// only be reached through a free-text GUID, a PID, a peer address, or its job directory.
//
// Vocabulary and shapes below are taken from the real bundles in Logs-Parsing/logs and recorded in
// the correlation model document under docs/ - not inferred.

enum class IdentityKind {
  job_id,             // the job definition
  job_session_id,     // THE RUN - the primary correlation anchor
  command_id,         // one action inside a run (start, stop, retry)
  plugin_manager_id,  // plug-in manager instance on the application host
  channel_id,         // plug-in <-> manager transport channel
  backup_id,
  vbr_id,
  agent_session,      // data mover client session, free-text only
  process_id,         // PID, reachable from Global\VeeamAgent<PID>
  peer_address,       // ip[:port] observed on a connection
  unknown
};

std::string to_string(IdentityKind value);

// How strongly an edge is believed. An exact identifier match and a time-window inference must never
// be presented to an engineer as the same thing.
enum class CorrelationConfidence {
  exact,     // the same identifier value appears on both sides
  strong,    // a documented structural relationship, e.g. a job directory naming its job and host
  inferred   // reconstructed from time window, peer address or PID proximity
};

std::string to_string(CorrelationConfidence value);

struct IdentityRef {
  IdentityKind kind = IdentityKind::unknown;
  std::string value;
  std::string source_path;
  std::uint64_t line_number = 0;
  std::int64_t timestamp_utc_ms = 0;
  std::string machine;
};

// One believed relationship between two identifiers, carrying why it is believed.
struct CorrelationEdge {
  IdentityKind from_kind = IdentityKind::unknown;
  std::string from_value;
  IdentityKind to_kind = IdentityKind::unknown;
  std::string to_value;
  CorrelationConfidence confidence = CorrelationConfidence::inferred;
  // Human-readable justification, shown next to the edge so an inferred link can be judged.
  std::string basis;
  std::string source_path;
  std::uint64_t line_number = 0;
};

// Everything known about one run, assembled across every file and machine that touched it.
struct CorrelatedRun {
  std::string job_session_id;
  std::string job_id;
  std::vector<std::string> machines;
  std::vector<IdentityRef> identities;
  std::vector<CorrelationEdge> edges;
  std::int64_t first_seen_utc_ms = 0;
  std::int64_t last_seen_utc_ms = 0;
  std::size_t exact_edges = 0;
  std::size_t inferred_edges = 0;
};

struct CorrelationGraph {
  std::vector<CorrelatedRun> runs;
  // Identifiers seen that never reached a run. Kept visible rather than dropped: an identifier with
  // no owning run is usually service-scoped, which is itself the answer to "why is this not
  // correlated" instead of an unexplained zero.
  std::vector<IdentityRef> unattached;
};

// Extracts Veeam's typed key/value blocks: "(EGuid) jobSessionId={...};" and the same for
// (EDateTime)/(EBoolean). Key matching is case-insensitive with an alias table, because the same
// corpus writes both jobId and JobId, and both jobSessionId and SessionId.
std::vector<IdentityRef> extract_typed_identities(std::string_view line);

// Extracts identifiers that appear only in prose. This is the data-mover leg: agent logs carry
// "client session ({guid})", "Global\VeeamAgent<PID>", "LOG: Initializing log file for process with
// PID <n>" and peer addresses. Any extractor built solely on key=value misses this leg entirely,
// which is exactly the evidence a cross-machine story depends on.
std::vector<IdentityRef> extract_freetext_identities(std::string_view line);

// Normalises an identifier key to its canonical kind. Returns unknown for keys SAT does not model.
IdentityKind identity_kind_for_key(std::string_view key);

// Builds the run graph from identities gathered across every parsed file.
CorrelationGraph build_correlation_graph(std::vector<IdentityRef> identities);

} // namespace support_assist
