#pragma once

#include "support_assist/cancellation.hpp"
#include "support_assist/correlation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"
#include "support_assist/time.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

enum class ParserConfidence { verified, probable, unconfirmed };

// Adding a profile is a contract: every switch over this enum must answer for it, and the
// answers must come from documented Veeam behaviour rather than from the SQL plug-in by
// analogy. The database plug-ins do NOT share a job-start shape - only Microsoft SQL runs a
// Veeam executable that states the whole backup on one line. Oracle RMAN is driven by an RMAN
// script, SAP HANA and SAP MaxDB by Backint, SAP on Oracle by BRTools/RMAN_UTIL, and Db2 by a
// native "db2 backup db" command. See docs/reference for the per-plug-in citations.
enum class VeeamReviewProfile {
  automatic,
  vaw,
  vbr,
  sql_plugin,
  rman_plugin,
  sap_hana_plugin,
  sap_oracle_plugin,
  sap_maxdb_plugin,
  db2_plugin,
  generic
};

// Stages of the story a run tells, in the order they occur. Only Info lines that advance the story
// earn a stage; everything else is inventory or chatter and stays out of the narrative.
//
// The vocabulary that maps onto each stage is PER PRODUCT, because no single set of strings covers
// them. VAW announces "Starting job." and "Connecting to agent '<host>' ('<ip:port>')"; the SQL
// plug-in announces "Start recovery manager cmdline --backup --full ..." and carries its settings as
// an XML/JSON-shaped payload; VBR speaks in job/task sessions and repositories. Treating them alike
// is exactly what produces a useless timeline.
enum class VeeamStoryStage {
  none,
  job_start,         // the run began, and under what command/mode
  settings,          // the settings the run used
  connection,        // who connected to what, with host/IP and port where the log gives it
  snapshot,          // snapshot/VSS request and the provider actually used
  guest_processing,  // application-aware work: SQL/Exchange/AD/truncation
  transfer,          // data movement and sizing
  job_end            // terminal result, including who stopped it
};

std::string to_string(VeeamStoryStage value);

// Classifies a log message into a story stage for the given product profile. Returns `none` for the
// overwhelming majority of lines, which is the point: a story is what survives the filter.
VeeamStoryStage classify_story_stage(std::string_view message, VeeamReviewProfile profile);


enum class VeeamEvidenceRole {
  manifest,
  service,
  scheduler,
  vaw_management,
  job,
  task,
  protection_group_rescan,
  source_data_mover,
  target_data_mover,
  data_mover_server,
  data_mover_repair,
  data_mover_check,
  repository_operation,
  rpc_control,
  plugin,
  setup,
  system,
  // Console/tray UI logs. These record what a PERSON did in the product interface - started,
  // stopped or retried a job, changed a setting, signed in. They are the only evidence that
  // explains an operator-caused outcome, such as a source machine reporting "backup cancelled"
  // because someone pressed Stop on the backup server. Without this role that human action is
  // invisible and the cancellation looks like a product fault.
  user_interface,
  // Output written by SAT's own Customer/Lab tools and collected into the bundle under
  // [BundlePaths] Tools=. Evidence SAT itself produced.
  tool_output,
  // Guest-processing / application-aware artifacts. KB1789 enumerates this family by name:
  // VeeamGuestHelper, VeeamGuestIndexer, VeeamVixProxy, VeeamVssSupport. Application-aware
  // failures (VSS, truncation, indexing) surface here rather than in the job log, so filing
  // them as generic evidence loses the distinction the Veeam documentation draws.
  guest_processing,
  // Scale-out backup repository tier activity. KB4463 names the artifacts granular SOBR log
  // collection expects: SOBR_Offload_*, SOBR_Archival_*, EvacuateBackupsJob, RTS.ResourcesUsage,
  // DatabaseResynchronizer, ResourceScan.
  sobr_tier,
  // Configuration database backup/restore and pre-execution checks. Distinct from a customer
  // backup job: a configuration backup failing is a VBR-maintenance problem, not a protected
  // workload problem.
  configuration_backup,
  // Restore-side operations: file-level recovery, instant recovery, mount and guest catalog
  // search. Separating these keeps a restore failure from being read as a backup failure.
  restore_operation,
  // Public-cloud plug-in platform services (Azure, GCP, RHV and similar appliance services).
  cloud_plugin,
  other
};

std::string to_string(ParserConfidence value);
std::string to_string(VeeamReviewProfile value);
std::string to_string(VeeamEvidenceRole value);
VeeamEvidenceRole classify_veeam_evidence_role(std::string_view source_path);

// What an event BELONGS to. The story of a run is assembled across every log that touches that run
// - a managed VAW job draws lines from the agent's own logs AND from the VBR server's logs - so
// "which file did this come from" is the wrong grouping. This is the right one.
//
// Equally important is the other direction: a large share of real cases are NOT about a run at all.
// Adding a machine to a protection group fails, a managed server cannot be added, a repository
// rescan fails. Those must be reachable on their own instead of being hidden inside, or wrongly
// attributed to, a backup run.
enum class VeeamEventScope {
  job_run,         // belongs to a specific backup/plug-in run, wherever the line was logged
  infrastructure,  // protection groups, managed servers, repositories, deployment - no owning run
  service,         // service lifecycle and background activity - no owning run by nature
  unknown
};

// The infrastructure operation an event belongs to, when it is not run-scoped. This is what lets an
// engineer ask "show me the protection group rescan failures" without wading through backup runs.
enum class VeeamInfrastructureOperation {
  none,
  protection_group,      // membership, configuration, rescan of a protection group
  managed_server,        // adding/removing/connecting a managed server or its components
  repository,            // repository add, rescan, maintenance, extent operations
  agent_deployment,      // pushing or upgrading agent/transport components
  configuration_backup,  // VBR configuration backup and restore
  licensing
};

std::string to_string(VeeamEventScope value);
std::string to_string(VeeamInfrastructureOperation value);

// Classifies scope from the message and the role of the log that produced it. `has_run_context` is
// true when the parser already bound this line to a job session, which is the strongest signal.
VeeamEventScope classify_event_scope(std::string_view message,
                                     VeeamEvidenceRole role,
                                     bool has_run_context);

VeeamInfrastructureOperation classify_infrastructure_operation(std::string_view message,
                                                               VeeamEvidenceRole role);

Result<VeeamReviewProfile> parse_veeam_review_profile(std::string_view value);

struct ReviewEvidence {
  std::string value;
  std::string source_path;
  std::filesystem::path materialized_path;
  std::uint64_t line_number = 0;
  ParserConfidence confidence = ParserConfidence::unconfirmed;
  std::string raw_line;
};

struct VeeamMachineSummary {
  std::optional<ReviewEvidence> machine_name;
  std::optional<ReviewEvidence> host_name;
  std::optional<ReviewEvidence> primary_ip;
  std::optional<ReviewEvidence> operating_system;
  std::optional<ReviewEvidence> cpu_logical_processors;
  std::optional<ReviewEvidence> product_version;
  std::optional<ReviewEvidence> assembly_version;
  std::optional<ReviewEvidence> management_mode;
  std::optional<ReviewEvidence> management_server;
  // Every account the plug-in ran under, taken from the account directories the logs sit in.
  // A list, not one value: a single collection routinely holds both an interactive user and the
  // computer account, and reporting only the first implies all the work ran as that identity.
  std::vector<ReviewEvidence> plugin_accounts;
  std::optional<ReviewEvidence> culture;
  std::optional<ReviewEvidence> utc_time;
  std::optional<ReviewEvidence> private_fix;
  std::vector<ReviewEvidence> license_modes;
  std::vector<ReviewEvidence> alternate_ip_addresses;
};

struct VeeamRawEvidence {
  std::string source_path;
  std::filesystem::path materialized_path;
  std::uint64_t line_number = 0;
  std::string timestamp_original;
  std::optional<std::int64_t> timestamp_utc_ms;
  VeeamEvidenceRole role = VeeamEvidenceRole::other;
  std::string category;
  std::string rule_id;
  std::string raw_line;
};

// The six busy percentages a PEX record carries, in field order. The highest of them is the
// bottleneck the sample is reporting.
//
// The aliases are the words support uses with a customer. An engineer says "the bottleneck is the
// network"; the field that says so is the source WRITE percentage, not a field named network.
enum class VeeamPexStage {
  source_read,
  source_processing,
  source_write,
  target_read,
  target_processing,
  target_write
};

inline constexpr std::size_t kVeeamPexStageCount = 6U;

// Busy percentages start at field 6 and run in stage order.
inline constexpr std::size_t veeam_pex_stage_field(VeeamPexStage stage) {
  return 6U + static_cast<std::size_t>(stage);
}

inline constexpr const char* veeam_pex_stage_label(VeeamPexStage stage) {
  switch (stage) {
    case VeeamPexStage::source_read: return "Source read busy";
    case VeeamPexStage::source_processing: return "Source processing busy";
    case VeeamPexStage::source_write: return "Source write busy";
    case VeeamPexStage::target_read: return "Target read busy";
    case VeeamPexStage::target_processing: return "Target processing busy";
    case VeeamPexStage::target_write: return "Target write busy";
  }
  return "";
}

// The customer-facing word, where support has one. Target read and target processing have no
// established alias, so they are reported under their own names rather than an invented one.
inline constexpr const char* veeam_pex_stage_alias(VeeamPexStage stage) {
  switch (stage) {
    case VeeamPexStage::source_read: return "Source";
    case VeeamPexStage::source_processing: return "Proxy";
    case VeeamPexStage::source_write: return "Network";
    case VeeamPexStage::target_read: return "";
    case VeeamPexStage::target_processing: return "";
    case VeeamPexStage::target_write: return "Target";
  }
  return "";
}

// What the percentage measures. These are the definitions from the support reference, kept
// faithful so a SAT report and a support conversation describe the same thing.
inline constexpr const char* veeam_pex_stage_meaning(VeeamPexStage stage) {
  switch (stage) {
    case VeeamPexStage::source_read:
      return "the agent machine reading from the source disk";
    case VeeamPexStage::source_processing:
      return "the agent machine processing the read data, compressing it and packaging it for the network upload";
    case VeeamPexStage::source_write:
      return "the upload on the network being completed";
    case VeeamPexStage::target_read:
      return "the target downloading from the network";
    case VeeamPexStage::target_processing:
      return "the target re-assembling the transferred packets into blocks, and then into backup files";
    case VeeamPexStage::target_write:
      return "the target writing the backup to the destination";
  }
  return "";
}

// One PEX record: a per-volume transfer performance sample emitted while data moves.
//
// Observed shape, semicolon delimited, from real VAW logs:
//   --pex:88;23380053983232;91219820544;23288818434048;91219820544;71796262544;37;33;98;28;33;93;134322847869720000
//
//   [0]  percent of the disk processed
//   [1]  disk / volume total bytes   <- stable for the life of that volume transfer, so this is
//                                       what identifies the volume when sampling
//   [2]  bytes processed
//   [3]  not yet identified
//   [4]  not yet identified          <- equals [2] in every sample seen so far
//   [5]  not yet identified
//   [6]  source read busy %          - "Source"
//   [7]  source processing busy %    - "Proxy"
//   [8]  source write busy %         - "Network"
//   [9]  target read busy %
//   [10] target processing busy %
//   [11] target write busy %         - "Target"
//   [12] timestamp (.NET ticks)
//
// Product-owner supplied. Fields 6-8 are the source leg and 9-11 the target leg, each read then
// process then write; the highest of the six is the bottleneck. Fields 3-5 remain unidentified and
// are not guessed at: the accessors return nullopt rather than invent a meaning.
struct VeeamPexSample {
  VeeamRawEvidence evidence;
  std::vector<std::string> fields;

  std::optional<std::string> field(std::size_t index) const {
    if (index >= fields.size() || fields[index].empty()) return std::nullopt;
    return fields[index];
  }
  std::optional<std::string> percent_complete() const { return field(0); }
  std::optional<std::string> volume_total_bytes() const { return field(1); }
  std::optional<std::string> bytes_processed() const { return field(2); }

  std::optional<std::string> busy_percent_text(VeeamPexStage stage) const {
    return field(veeam_pex_stage_field(stage));
  }

  // The parsed busy percentage, or nullopt when the field is absent or is not a plain number. A
  // value above 100 is returned as read rather than clamped, because a clamp would hide a log
  // worth looking at behind a plausible number.
  std::optional<int> busy_percent(VeeamPexStage stage) const {
    const auto text = busy_percent_text(stage);
    if (!text) return std::nullopt;
    int value = 0;
    for (const char character : *text) {
      if (character < '0' || character > '9') return std::nullopt;
      value = value * 10 + (character - '0');
      if (value > 1000000) return std::nullopt;
    }
    return value;
  }

  // The stage with the highest busy percentage: the bottleneck this sample reports. A tie resolves
  // to the earliest stage in the pipeline, because that is the one the others are waiting on.
  std::optional<VeeamPexStage> bottleneck() const {
    std::optional<VeeamPexStage> highest;
    int best = -1;
    for (std::size_t index = 0; index < kVeeamPexStageCount; ++index) {
      const auto stage = static_cast<VeeamPexStage>(index);
      const auto value = busy_percent(stage);
      if (!value) continue;
      if (*value > best) {
        best = *value;
        highest = stage;
      }
    }
    return highest;
  }
};

// What the samples in one run say about where the job spent its time.
struct VeeamPexStageStatistics {
  std::size_t samples = 0;             // samples in which this stage reported a readable percentage
  int peak = 0;                        // highest busy percentage seen
  std::uint64_t total = 0;             // sum of the readable percentages, for the mean
  std::size_t bottleneck_samples = 0;  // samples in which this stage was the highest

  std::optional<int> mean_percent() const {
    if (samples == 0U) return std::nullopt;
    const auto count = static_cast<std::uint64_t>(samples);
    return static_cast<int>((total + count / 2U) / count);
  }
};

struct VeeamPexSummary {
  std::size_t samples = 0;         // PEX records seen
  std::size_t rated_samples = 0;   // records that carried at least one readable busy percentage
  std::array<VeeamPexStageStatistics, kVeeamPexStageCount> stages{};
  std::optional<VeeamPexStage> dominant;  // the stage that was the bottleneck in the most samples

  const VeeamPexStageStatistics& stage(VeeamPexStage value) const {
    return stages[static_cast<std::size_t>(value)];
  }
};

// Reduce a set of PEX records to per-stage statistics and the stage that was the bottleneck most
// often. Records carrying no readable percentage are counted in samples but not in rated_samples,
// so a run of unparsable records reads as unparsable rather than as a healthy job.
inline VeeamPexSummary summarize_pex(const std::vector<VeeamPexSample>& samples) {
  VeeamPexSummary summary;
  summary.samples = samples.size();
  for (const auto& sample : samples) {
    bool rated = false;
    for (std::size_t index = 0; index < kVeeamPexStageCount; ++index) {
      const auto value = sample.busy_percent(static_cast<VeeamPexStage>(index));
      if (!value) continue;
      rated = true;
      auto& statistics = summary.stages[index];
      ++statistics.samples;
      statistics.total += static_cast<std::uint64_t>(*value);
      if (*value > statistics.peak) statistics.peak = *value;
    }
    if (!rated) continue;
    ++summary.rated_samples;
    if (const auto stage = sample.bottleneck())
      ++summary.stages[static_cast<std::size_t>(*stage)].bottleneck_samples;
  }
  std::size_t best = 0;
  for (std::size_t index = 0; index < kVeeamPexStageCount; ++index) {
    if (summary.stages[index].bottleneck_samples > best) {
      best = summary.stages[index].bottleneck_samples;
      summary.dominant = static_cast<VeeamPexStage>(index);
    }
  }
  return summary;
}

struct VeeamDiskExtentEvidence {
  VeeamRawEvidence evidence;
  std::uint64_t disk_number = 0;
  std::uint64_t offset_bytes = 0;
  std::uint64_t length_bytes = 0;
};

struct VeeamVssProviderInfo {
  std::string provider_id;
  std::string name;
  std::string type;
  std::vector<VeeamRawEvidence> evidence;
};

struct VeeamVolumeSnapshotInfo {
  std::string volume_id;
  std::string mount_point;
  std::string file_system;
  std::string dos_name;
  std::uint64_t explicit_size_bytes = 0;
  std::string requested_provider_id;
  std::string used_provider_id;
  std::string used_provider_name;
  std::string used_provider_type;
  bool included_in_snapshot = false;
  std::vector<VeeamDiskExtentEvidence> extents;
  std::vector<VeeamRawEvidence> evidence;
};

struct VeeamTimelineEvent {
  VeeamRawEvidence evidence;
  std::string machine_key;
  std::string job_run_key;
};

struct VeeamJobSettings {
  std::string backup_mode;
  std::string job_description;
  std::vector<std::string> included_items;
  std::vector<std::string> excluded_items;
  std::string destination_type;
  std::string destination_path;
  // Human-facing VAW destination facts from the Job Settings block.  These
  // must not be replaced by later internal repository serialization strings.
  std::string backup_server;
  std::string backup_repository;
  std::string retention;
  std::string compression;
  std::string storage_optimization;
  std::string encryption;
  std::string gfs;
  std::string backup_cache;
  std::string schedule;
  std::string created_by;
  std::string created_at;
  std::string vss_snapshot;
  std::string application_processing;
  std::string guest_indexing;
  std::string script_processing;
  std::string command_line;
  // Exact, bounded, human-readable settings block retained from the source log.
  std::string settings_source_path;
  std::filesystem::path settings_materialized_path;
  std::uint64_t settings_start_line = 0;
  std::uint64_t settings_end_line = 0;
  std::vector<std::string> settings_lines;
  std::string source_backup_mode;
  std::string repository_operation;
  std::string resulting_backup_type;
  std::string task_total_size;
};

// The real schedule.
//
// It is not in the job settings block. VAW logs it as [WakeupManager] waitable timers and a
// [Scheduler] line in the service log, and in test 07 those said "daily at 12:24 PM" while the
// settings block still read "Backup is not scheduled to run automatically" because that file had
// not been rewritten for a day.
struct VeeamScheduleInfo {
  bool scheduler_seen = false;
  // Next fire time as the product wrote it, e.g. "8/27/2026 12:24 PM".
  std::string next_run_original;
  std::string last_timer_expiry_original;
  std::uint32_t timer_expiry_count = 0;
  std::string source_path;
  std::uint64_t line_number = 0;
};

// One observed lifetime of the agent job process.
struct VeeamAgentLifecycle {
  std::string started_original;
  std::string stopped_original;
  std::optional<std::int64_t> started_utc_ms;
  std::optional<std::int64_t> stopped_utc_ms;
  std::string source_path;
  std::uint64_t start_line = 0;
  std::uint64_t stop_line = 0;
};

// What the service itself is doing, independent of any job.
//
// When no job run is failing, this shows what the service itself is doing, which the run views
// do not.
struct VeeamServiceActivity {
  std::uint32_t service_start_count = 0;
  std::string first_service_start_original;
  std::string last_service_start_original;
  // Agent job process boundaries, oldest first.
  std::vector<VeeamAgentLifecycle> agent_runs;
  // Findings that belong to no job run at all, counted by component.
  std::vector<std::pair<std::string, std::uint32_t>> standalone_errors_by_component;
  std::uint32_t standalone_error_count = 0;
  std::uint32_t standalone_warning_count = 0;
  // Components that only ever produced findings outside a job run.
  std::vector<std::string> service_only_components;
};

// A "Starting job ... by user, mode: 'X'" line.
//
// These live in the SERVICE log while sessions are tracked in the JOB log, so the trigger cannot be
// assigned to a session where it is read - it has to be correlated afterwards by job id and time.
struct VeeamRunTrigger {
  std::string job_id;
  std::string trigger;   // "user" or "scheduled"
  std::string job_mode;
  std::string detail;
  std::optional<std::int64_t> utc_ms;
};

struct VeeamMachineRecord {
  std::string key;
  std::string display_name;
  // Role of the machine that owns the supplied log source. For VBR this is
  // normally the Backup Server; protected workloads and infrastructure named
  // inside jobs are related entities, not additional source machines.
  std::string role;
  VeeamMachineSummary summary;
  std::vector<std::string> source_paths;
};

struct VeeamJobSession {
  std::string run_kind = "job";
  // Component that actually performed this run, e.g. "VBR", "Repo", "SOBR", "SQL-Plugin".
  // A run is not always a backup job: a SOBR offload is a task owned by the repository with no job
  // behind it at all, and attributing it to whatever agent happened to be installed on that server
  // is how a tiering failure ends up filed under an agent.
  std::string component_tag;
  bool index_only = false;
  bool protection_group_rescan = false;
  std::string protection_group_name;
  std::string run_key;
  std::string machine_key;
  std::string machine_name;
  std::string job_name;
  std::string job_id;
  std::string session_id;
  std::string task_session_id;
  std::string job_mode;
  std::string job_type;
  std::string status;
  std::string restore_point_id;
  std::string restore_point_type;
  std::string backup_file;
  // How this run was started: "user", "scheduled", "retry" or empty when no evidence was found.
  std::string trigger;
  // The line the trigger came from, so the claim is checkable.
  std::string trigger_detail;
  // Last session state seen for this run. "WaitingRepository" says it never reached the source.
  std::string last_state;
  // A run with a start and no completion is still going.
  bool running = false;
  // Latest progress observed for THIS run, not a sample from some other one.
  std::uint32_t progress_percent = 0;
  std::uint64_t progress_bytes_done = 0;
  std::uint64_t progress_bytes_total = 0;
  std::uint64_t progress_used_done = 0;
  std::uint64_t progress_used_total = 0;
  bool progress_seen = false;
  // "Full" or "Incremental", from the target file extension.
  std::string backup_type;
  // The restore point this one chains onto, from Target.PrevLinks.
  std::string previous_backup_file;
  std::string source_path;
  std::filesystem::path materialized_path;
  std::uint64_t start_line = 0;
  std::uint64_t completion_line = 0;
  std::string start_timestamp_original;
  std::string completion_timestamp_original;
  std::optional<std::int64_t> start_utc_ms;
  std::optional<std::int64_t> completion_utc_ms;
  VeeamJobSettings settings;
  std::vector<VeeamPexSample> pex_samples;
  std::vector<VeeamRawEvidence> volume_evidence;
  std::vector<VeeamDiskExtentEvidence> disk_extents;
  std::vector<VeeamVolumeSnapshotInfo> snapshot_volumes;
  std::vector<VeeamVssProviderInfo> vss_providers;
  std::string used_vss_provider_id;
  std::string used_vss_provider_name;
  std::string used_vss_provider_type;
  std::vector<VeeamRawEvidence> management_events;
};

struct VeeamIncidentLocation {
  std::string machine_key;
  std::string machine_name;
  // Component whose log this line came from. One incident can span components - a job fails on the
  // backup server because its target data mover failed on the repository - so the tag belongs on
  // the LOCATION, not on the incident.
  std::string component_tag;
  std::string explicit_job_run_key;
  std::vector<std::string> correlated_job_run_keys;
  std::string explicit_job_id;
  std::string explicit_session_id;
  std::string source_path;
  std::filesystem::path materialized_path;
  std::uint64_t line_number = 0;
  std::uint64_t byte_offset = 0;
  std::string timestamp_original;
  std::optional<std::int64_t> timestamp_utc_ms;
  std::string thread_or_task;
  std::vector<std::string> before;
  std::vector<std::string> lines;
  std::vector<std::string> after;
};

// One Veeam component proven present by the evidence in a bundle.
//
// SAT is a Veeam tool, not an agent tool. A support bundle routinely carries several components at
// once - a backup server that also hosts a repository, a repository that happens to have an agent
// installed, a database server running a plug-in - and picking a single "product" to represent all
// of it is what produced findings like a SOBR offload failure being reported under "Veeam Agent for
// Microsoft Windows" merely because an agent could be installed on that repository.
//
// Components are therefore PLURAL and INDEPENDENT. Each is listed with the machine it belongs to,
// so tasks and jobs can be attributed to the component that actually performed them.
//
// Presence requires structural evidence - a service log, a data-mover log, a plug-in log directory.
// A component being NAMED in someone else's log is not presence: a managed agent mentions its
// backup server constantly, and a job names the repository it writes to.
struct VeeamComponentPresence {
  // Short tag used to attribute jobs and tasks, e.g. "VBR", "VAW", "Repo", "SQL-Plugin".
  std::string tag;
  std::string display_name;
  // Owning machine, when the evidence identified one.
  std::string machine_key;
  std::string machine_name;
  std::size_t evidence_files = 0;
  ParserConfidence confidence = ParserConfidence::unconfirmed;
  // A few representative paths, capped - enough to justify the claim without listing a bundle.
  std::vector<std::string> example_paths;
};

struct VeeamBundleSummary {
  std::string key;
  std::string source_path;
  std::string display_name;
  std::string primary_machine_key;
  std::string primary_machine_name;
  std::string primary_machine_role;
  std::string manifest_profile;
  std::string product_type;
  std::string product_version;
  ParserConfidence product_confidence = ParserConfidence::unconfirmed;
  std::uint64_t source_bytes = 0;
  std::string source_fingerprint;
  std::uint64_t candidate_files = 0;
  std::uint64_t indexed_files = 0;
  std::uint64_t deferred_files = 0;
};

struct VeeamJobEvidenceGroup {
  std::string bundle_key;
  std::string machine_key;
  std::string machine_name;
  std::string job_name;
  std::string category;
  bool protection_group_rescan = false;
  std::string protection_group_name;
  std::uint64_t candidate_files = 0;
  std::uint64_t indexed_files = 0;
  std::uint64_t deferred_files = 0;
  std::uint64_t total_bytes = 0;
  std::vector<std::string> workloads;
  std::vector<std::string> source_paths;
  std::vector<std::string> run_keys;
};

struct VeeamReviewedFile {
  std::string source_path;
  VeeamEvidenceRole role = VeeamEvidenceRole::other;
  std::uint64_t size_bytes = 0;
  std::uint64_t lines_scanned = 0;
  double elapsed_seconds = 0.0;
  std::string error;
  bool cache_reused = false;
};

struct VeeamEvidenceRoleSummary {
  VeeamEvidenceRole role = VeeamEvidenceRole::other;
  std::uint64_t candidate_files = 0;
  std::uint64_t scanned_files = 0;
  std::uint64_t deferred_files = 0;
  std::uint64_t total_bytes = 0;
};

struct VeeamIncident {
  std::string id;
  std::string signature;
  std::string severity;
  std::string component;
  std::string summary;
  // Set when this entry is a story event rather than a problem: the run started, connected,
  // requested a snapshot, moved data, finished. `none` for errors, warnings and query matches.
  VeeamStoryStage story_stage = VeeamStoryStage::none;
  std::uint64_t occurrences = 0;
  std::string first_timestamp_original;
  std::string last_timestamp_original;
  std::optional<std::int64_t> first_utc_ms;
  std::optional<std::int64_t> last_utc_ms;
  std::vector<VeeamIncidentLocation> locations;
  // Total occurrences remains authoritative. Noisy logs retain a bounded set
  // of navigable source locations per file so one repeated warning cannot
  // consume gigabytes of memory or turn report generation into an OOM event.
  std::uint64_t locations_omitted = 0;
  std::vector<std::string> machine_keys;
  std::vector<std::string> job_run_keys;
};

struct VeeamLogReviewOptions {
  std::vector<std::filesystem::path> sources;
  VeeamReviewProfile profile = VeeamReviewProfile::automatic;
  // Recommended default: build a machine/job/run index from high-value logs first.
  // A later deep review can use selected_run_key and the same source list.
  bool fast_index_first = true;
  bool one_source_one_primary_machine = true;
  std::string selected_run_key;
  std::string selected_job_name_hint;
  std::string selected_source_path_hint;
  std::filesystem::path output_path; // empty: default_review_output_directory()
  bool recursive = true;
  bool search_archives = true;
  bool include_warnings = true;
  // Keeps the handful of Info lines that tell the story of a run - it started, it connected to
  // <host>:<port>, it requested a snapshot with this VSS provider, it moved this much, it finished
  // with this result (and, when someone stopped it, who). Errors and warnings alone say what broke
  // but never what was happening, which is the context an engineer reconstructs by hand today.
  // Bounded by classify_story_stage(), which returns a stage for only a few lines per run.
  bool include_story_events = true;
  bool include_informational_query_matches = false;
  std::string informational_query;
  bool case_sensitive_query = false;
  std::optional<std::int64_t> from_utc_ms;
  std::optional<std::int64_t> to_utc_ms;
  DateOrder date_order = DateOrder::automatic;
  int assumed_timezone_offset_minutes = 0;
  std::size_t context_before = 5;
  std::size_t context_after = 5;
  std::size_t maximum_incidents = 100000;
  // Retain full before/after context only for the first few occurrences of a
  // repeated signature. Every occurrence keeps its timestamp, path, line and
  // incident line so source navigation remains complete without multiplying
  // memory use for noisy logs.
  std::size_t maximum_context_locations_per_incident = 5;
  // Applied per explicit session/job identifier, or per UTC hour when a log
  // has no identifier. This preserves evidence from later runs in one noisy
  // service log instead of allowing the first run to consume the whole cap.
  std::size_t maximum_locations_per_incident_per_file = 250;
  // The human-readable report is intentionally bounded. All grouped counts and
  // source locations remain in the result model and GUI; very large timelines
  // are summarized rather than producing multi-gigabyte text reports.
  std::size_t maximum_report_timeline_occurrences = 25000;
  // Detailed source-context rendering is independently bounded. The complete
  // structured incident model remains available to the GUI/case store.
  std::size_t maximum_report_detailed_incidents = 250;
  // Diagnostic payloads (for example PostgreSQL script bodies emitted at Error
  // severity) may be attached to a root event, but one incident must not retain
  // an unbounded script dump.
  std::size_t maximum_incident_lines = 200;
  std::size_t maximum_line_bytes = 4 * 1024 * 1024;
  // Safety limits are separate per archive and across the whole review. Large
  // support cases commonly contain several multi-gigabyte bundles; a single
  // global 4 GiB ceiling would reject legitimate four-machine cases.
  std::uint64_t maximum_archive_expanded_bytes = 8ULL * 1024ULL * 1024ULL * 1024ULL;
  std::uint64_t maximum_total_archive_expanded_bytes = 32ULL * 1024ULL * 1024ULL * 1024ULL;
  std::uint64_t maximum_archive_entries = 100000;
  std::uint64_t maximum_total_archive_entries = 400000;
  // Zero selects a conservative automatic worker count. One forces deterministic
  // single-file parsing for troubleshooting. File results are always merged in
  // source-path order, regardless of worker completion order.
  std::size_t worker_count = 0;
  bool use_persistent_parser_cache = true;
  std::filesystem::path parser_cache_directory;
  std::size_t maximum_structured_timeline_events = 50000;
  std::size_t maximum_raw_evidence_per_run = 20000;
  // Include a small orchestration window around a structured job run when
  // correlating service/UI log errors to that run.
  std::int64_t job_window_lead_ms = 5LL * 60LL * 1000LL;
  std::int64_t job_window_tail_ms = 10LL * 60LL * 1000LL;
  // An incomplete run has no trustworthy completion boundary. Never allow the
  // legacy 24-hour fallback to absorb unrelated service/control-plane events.
  std::int64_t incomplete_run_tail_ms = 30LL * 60LL * 1000LL;
};

struct VeeamLogReviewResult {
  std::string product_type = "Veeam product logs";
  ParserConfidence product_confidence = ParserConfidence::unconfirmed;
  std::string parser_profile = "Veeam Agent for Microsoft Windows (VAW) - Initial Sample Profile";
  std::string parser_scope_note;
  // Legacy primary-machine view retained for existing callers. For bundles with
  // multiple endpoints, use machines and machine_key fields instead.
  VeeamMachineSummary machine;
  std::vector<VeeamBundleSummary> bundles;
  // Every component the evidence proves present, not one elected winner.
  std::vector<VeeamComponentPresence> components;
  std::vector<VeeamMachineRecord> machines;
  std::vector<VeeamJobSession> job_sessions;
  std::vector<VeeamJobEvidenceGroup> job_evidence_groups;
  std::vector<VeeamIncident> incidents;
  // Identifiers observed while parsing, and the run graph assembled from them. A run's evidence is
  // spread across different files on different machines and joined only through these identifiers,
  // so they are gathered during the single pass over the logs rather than by re-reading afterwards.
  std::vector<IdentityRef> correlation_identities;
  CorrelationGraph correlation;
  std::vector<VeeamRunTrigger> run_triggers;
  VeeamScheduleInfo schedule_info;
  VeeamServiceActivity service_activity;
  // Job configuration as logged over time, oldest first, so a changed target or retention is
  // visible. In test 04 a configuration change was what FIXED the case and it appeared nowhere.
  std::vector<VeeamJobSettings> configuration_history;
  std::vector<VeeamReviewedFile> reviewed_files;
  std::vector<VeeamEvidenceRoleSummary> evidence_roles;
  std::vector<VeeamTimelineEvent> timeline_events;
  std::filesystem::path report_path;
  std::filesystem::path cache_directory;
  std::filesystem::path cache_index_path;
  // Evidence files present in the tree that the review did not open: archives nested inside the
  // bundle, which a directory review deliberately leaves alone so it matches an outer-ZIP review.
  // Counted so the report can say so rather than implying the bundle was read whole.
  std::uint64_t nested_archives_skipped = 0;
  // The other files in the evidence the review does not read, by kind ("crash dump", "Windows event
  // log") with their count, in the order the report names them.
  std::vector<std::pair<std::string, std::uint64_t>> files_not_read;
  std::uint64_t files_discovered = 0;
  std::uint64_t files_deferred = 0;
  std::uint64_t files_scanned = 0;
  std::uint64_t lines_scanned = 0;
  std::uint64_t input_bytes = 0;
  std::uint64_t parse_errors = 0;
  // Applied only to source timestamps that do not carry an explicit UTC offset.
  int assumed_timezone_offset_minutes = 0;
  std::size_t workers_used = 1;
  double elapsed_seconds = 0.0;
  double discovery_seconds = 0.0;
  double archive_seconds = 0.0;
  double parse_seconds = 0.0;
  double merge_seconds = 0.0;
  double correlation_seconds = 0.0;
  double finalization_seconds = 0.0;
  double serialization_seconds = 0.0;
  // Compatibility alias for callers that still display the old report phase.
  double report_seconds = 0.0;
  std::size_t maximum_report_timeline_occurrences = 25000;
  std::size_t maximum_report_detailed_incidents = 250;
  std::size_t report_detailed_incidents = 0;
  bool report_incidents_truncated = false;
  std::size_t report_timeline_occurrences = 0;
  bool report_timeline_truncated = false;
  double files_per_second = 0.0;
  double lines_per_second = 0.0;
  bool fast_index_used = false;
  bool persistent_cache_enabled = false;
  std::uint64_t parser_cache_hits = 0;
  VeeamReviewProfile profile_used = VeeamReviewProfile::automatic;
  std::vector<std::filesystem::path> input_sources;
  bool cancelled = false;
};

using ReviewConsoleCallback = std::function<void(std::string_view)>;

Result<VeeamLogReviewResult> review_veeam_logs(const VeeamLogReviewOptions& options,
                                               const CancellationToken& cancel,
                                               ProgressCallback progress = {},
                                               ReviewConsoleCallback console = {});

// Where a review writes its report and parser cache when no output path is given: SAT's own
// Log-Collections/Log-Review folder beside the executable, never a folder beside the logs.
std::filesystem::path default_review_output_directory();

std::string veeam_ticket_evidence_path(std::string_view source_path);
std::string build_veeam_ticket_note(const VeeamLogReviewResult& review,
                                    std::string_view machine_key,
                                    std::string_view run_key,
                                    std::string_view issue);

Status write_veeam_log_review_report(const VeeamLogReviewResult& review,
                                     const std::filesystem::path& output_path);

const VeeamMachineRecord* find_veeam_machine(const VeeamLogReviewResult& review,
                                             std::string_view machine_key);
const VeeamJobSession* find_veeam_job_run(const VeeamLogReviewResult& review,
                                          std::string_view run_key);
bool veeam_location_matches_run(const VeeamIncidentLocation& location,
                                const VeeamJobSession& run,
                                const VeeamLogReviewOptions& options = {});
std::vector<const VeeamIncident*> filter_veeam_incidents(
    const VeeamLogReviewResult& review,
    std::string_view machine_key,
    std::string_view run_key,
    const VeeamLogReviewOptions& options = {});

} // namespace support_assist
