#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
namespace support_assist {
enum class SnapshotKind { registry, filesystem, logs, combined };
enum class SnapshotState { creating, complete, cancelled, failed };
enum class RegistryView { native, view32, view64, both };
enum class ChangeKind {
  added,
  removed,
  modified,
  renamed,
  moved,
  metadata_changed,
  access_changed,
  inferred_rename,
  type_changed
};

std::string to_string(SnapshotKind value);
std::string to_string(SnapshotState value);
std::string to_string(RegistryView value);
std::string to_string(ChangeKind value);

struct SnapshotMetadata {
  std::string id;
  SnapshotKind kind = SnapshotKind::combined;
  SnapshotState state = SnapshotState::creating;
  std::string application_version;
  int schema_version = 1;
  std::string created_start_utc;
  std::string created_end_utc;
  std::string machine_name;
  std::string os_name;
  std::string os_version;
  // Human-readable distribution or product name, when the platform publishes one:
  // PRETTY_NAME from /etc/os-release on Linux, the product name on macOS. Empty on Windows, where
  // os_name/os_version already carry it. Added rather than overloading os_name so existing readers
  // of environment.log keep working.
  std::string os_distribution;
  std::string architecture;
  std::string timezone;
  std::string user_scope;
  bool elevated = false;
  std::string enabled_privileges;
  std::string options_json;
  std::string source_filesystem;
  std::uint64_t object_count = 0;
  std::uint64_t error_count = 0;
};

struct RegistryScopeConfig {
  std::string snapshot_id;
  std::uint32_t ordinal = 0;
  std::string hive;
  std::string subkey;
  RegistryView view = RegistryView::both;
};

struct FilesystemScanConfig {
  std::string snapshot_id;
  std::string root_path;
  std::vector<std::string> exclusions;
  bool follow_reparse_points = false;
  std::uint32_t maximum_depth = 1024;
  std::uint64_t maximum_objects = 100000000;
  std::string hash_mode = "none";
  std::uint64_t hash_size_limit = 64ULL * 1024ULL * 1024ULL;
  std::vector<std::string> hash_extensions;
  bool capture_streams = false;
  bool capture_file_identity = true;
  bool hydrate_cloud_files = false;
};

struct RegistryKeyRecord {
  std::string snapshot_id;
  std::string hive;
  std::string relative_path;
  RegistryView view = RegistryView::native;
  std::string key_name;
  std::int64_t last_write_100ns = 0;
  std::string class_name;
  int access_result = 0;
  std::string enumeration_error;
};

struct RegistryValueRecord {
  std::string snapshot_id;
  std::string hive;
  std::string relative_path;
  RegistryView view = RegistryView::native;
  std::string value_name;
  bool is_default = false;
  std::uint32_t type = 0;
  std::vector<std::byte> raw_data;
  std::string display_data;
  std::string data_hash;
  bool display_truncated = false;
};

struct FilesystemRecord {
  std::string snapshot_id;
  std::string relative_path;
  std::string source_path;
  std::string object_type;
  std::uint64_t size = 0;
  std::uint64_t allocation_size = 0;
  std::uint32_t attributes = 0;
  std::int64_t creation_100ns = 0;
  std::int64_t access_100ns = 0;
  std::int64_t write_100ns = 0;
  std::int64_t change_100ns = 0;
  std::uint64_t volume_serial = 0;
  std::string file_id_hex;
  bool reparse_point = false;
  std::uint32_t reparse_tag = 0;
  std::uint32_t hard_link_count = 0;
  std::string streams_json;
  int access_result = 0;
  std::string enumeration_error;
  std::string content_hash;
  std::string hash_algorithm;
  std::string hash_status;
  bool case_sensitive_directory = false;
};

struct DiffRecord {
  ChangeKind kind = ChangeKind::modified;
  std::string category;
  std::string identity;
  std::string old_path;
  std::string new_path;
  std::string before_summary;
  std::string after_summary;
  double confidence = 1.0;
  std::string reason;
};

struct LogMatch {
  std::string source_path;
  std::uint64_t line_number = 0;
  std::string severity;
  std::string timestamp_original;
  std::optional<std::int64_t> timestamp_utc_ms;
  std::string timestamp_format;
  bool timestamp_ambiguous = false;
  double timestamp_confidence = 0.0;
  std::vector<std::string> before;
  std::string matching_line;
  std::vector<std::string> after;
  std::string signature;
};
} // namespace support_assist
