#pragma once

// The Object Storage Check (experimental): an S3-compatible bucket as Veeam reaches it.
//
// First the checks that send no request to the storage: the endpoint's name and addresses, TCP 443,
// the TLS version, the certificate's names and its trust, which addressing style can work, and the
// proxy this machine has set. Then, with the engineer's keys, and with their agreement to the
// estimate on an endpoint that bills requests, four signed reads: the bucket's region (with the
// clock from the answer's Date header and the sign-in), versioning, Object Lock with its default
// retention, and lifecycle rules, held against the Veeam guide's rules for immutable buckets. It
// writes nothing.
//
// The presets and the guide's rules are config/checks/object-storage.json; the prices behind the
// estimate are object-storage-prices.json. The keys are the caller's for the session; nothing here
// stores them.

#include "support_assist/cancellation.hpp"
#include "support_assist/error.hpp"
#include "support_assist/progress.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {

struct ObjectStoragePreset {
  std::string id;
  std::string name;
  std::string endpoint;        // with {region}; empty: the engineer types it
  std::string addressing;      // virtual-hosted or path
  std::string default_region;
  std::string prices;          // the entry in object-storage-prices.json
  std::string bucket_reads;    // the price class of a bucket-configuration read: read or list
  std::string immutability;    // the guide's rules that apply: s3, or none
  bool later = false;          // listed, not yet checked (Azure, Google)
  std::vector<std::string> regions; // offered in the Region list; any other can be typed
};

// A product's permissions from its own guide: vbr-13, vbr-12, vaw-13, val-13, vb365-8.
struct ObjectStoragePermissions {
  std::string id;
  std::string product;
  std::string source;
  std::string build;
  std::string reviewed;
  std::string standard_note;
  std::vector<std::string> standard;
  std::vector<std::string> immutability;
  std::vector<std::string> archiving;
};

struct ObjectStorageCatalog {
  std::vector<ObjectStoragePreset> presets;
  int request_cap = 25;
  std::string reviewed;
  std::string immutability_source;
  std::string immutability_build;
  std::string immutability_reviewed;
  std::vector<std::string> immutability_rules;
  std::vector<ObjectStoragePermissions> permissions;
};

const ObjectStorageCatalog& object_storage_catalog();
const ObjectStoragePreset* find_object_storage_preset(std::string_view id);
// A product's permissions by id; the first product when the id is empty or unknown.
const ObjectStoragePermissions* find_object_storage_permissions(std::string_view id);

struct ObjectStoragePrices {
  std::string name;
  std::string billing;   // per-request, none or unknown
  std::string currency;
  std::string basis;
  std::string free;
  std::string checked;
  double read_per_1000 = 0.0;
  double list_per_1000 = 0.0;
};

std::optional<ObjectStoragePrices> object_storage_prices(std::string_view provider);

struct ObjectStorageTarget {
  std::string preset = "amazon-s3";
  std::string endpoint;       // host or host:port; the preset's endpoint for the region when empty
  std::string region;         // the preset's default region when empty
  std::string bucket;
  std::string addressing;     // virtual-hosted or path; the preset's when empty
  std::string pinned_sha256;  // a certificate the engineer accepted for this session
  // A certificate file the engineer chose (.crt, .pem or .cer): the server's own certificate, or a CA
  // that issued it. This machine's certificate store is checked either way.
  std::string certificate_file;
};

struct ObjectStorageCredentials {
  std::string access_key;
  std::string secret_key;
  std::string session_token;
};

// Where the requests go, worked out from the target and its preset.
struct ObjectStorageEndpoint {
  std::string host;            // the endpoint
  std::uint16_t port = 443;
  std::string region;
  std::string addressing;
  std::string request_host;    // the bucket's virtual-hosted name, or the endpoint for path style
  std::string bucket_path;     // "/" for virtual-hosted, "/bucket/" for path style
};

Result<ObjectStorageEndpoint> resolve_object_storage_endpoint(const ObjectStorageTarget& target);

// The signed requests a run sends to the storage: four reads of the bucket's settings (region,
// versioning, Object Lock, lifecycle), then three listings that return at most one name each and
// prove s3:ListBucket, s3:ListBucketVersions and s3:ListBucketMultipartUploads.
inline constexpr int kObjectStorageSignedReads = 4;
inline constexpr int kObjectStorageListings = 3;

// What the signed requests cost, before they run.
struct ObjectStorageEstimate {
  int requests = kObjectStorageSignedReads + kObjectStorageListings;
  std::string billing;            // per-request, none or unknown
  double cost = 0.0;
  std::string currency = "USD";
  std::string provider;           // the price list's name
  std::string checked;            // when its prices were confirmed
  std::string free;               // a free allowance it has
  std::string endpoint;
  bool needs_agreement = false;   // a billed or unpriced endpoint asks first
  std::string text;               // the warning, as the window and the command line show it
};

ObjectStorageEstimate estimate_object_storage_check(const ObjectStorageTarget& target);

enum class ObjectCheckState { pass, attention, fail, not_checked, info };

struct ObjectCheckRow {
  std::string section;
  std::string label;
  std::string value;
  ObjectCheckState state = ObjectCheckState::info;
};

// One permission a product needs, and what the run learned of it: from AWS IAM's policy simulator
// (Amazon S3, free), from a signed read or listing that it allows, or not at all (SAT writes
// nothing, so a write permission is known only from IAM).
enum class PermissionState { allowed, denied, not_checked };

struct ObjectPermission {
  std::string action; // "s3:PutObject"
  std::string group;  // standard, immutability or archiving
  PermissionState state = PermissionState::not_checked;
  std::string text;   // how it is known, or why not
};

struct ObjectStorageResult {
  std::string preset;              // the preset's name
  ObjectStorageEndpoint endpoint;
  std::string bucket;
  std::string headline;
  std::vector<ObjectCheckRow> rows;
  bool signed_reads = false;       // the signed reads ran
  std::string identity;            // the key's identity as AWS STS gives it; empty elsewhere
  bool iam_answered = false;       // AWS IAM's policy simulator answered for the key
  int iam_requests = 0;            // requests to AWS STS and IAM, which bill nothing
  std::string product;             // the product the permissions were held against
  std::vector<ObjectPermission> permissions;
  int requests = 0;
  std::uint64_t bytes_read = 0;
  double estimated_cost = 0.0;
  std::string currency = "USD";
  std::optional<double> clock_offset_seconds;
  std::int64_t started_unix_millis = 0;
  std::int64_t ended_unix_millis = 0;
};

struct ObjectStorageOptions {
  ObjectStorageTarget target;
  std::optional<ObjectStorageCredentials> credentials;  // none: only the checks without requests
  bool accept_cost = false;  // agreed to the estimate of a billed or unpriced endpoint
  std::string product;       // the permissions to hold the key against; the first product when empty
};

Result<ObjectStorageResult> check_object_storage(const ObjectStorageOptions& options, const CancellationToken& cancel,
                                                 ProgressCallback progress = {});

// The keys for the command line, from SAT_S3_ACCESS_KEY, SAT_S3_SECRET_KEY and SAT_S3_SESSION_TOKEN;
// none when either key is not set.
std::optional<ObjectStorageCredentials> object_storage_credentials_from_environment();

namespace object_storage_detail {
// The text of the first <tag>...</tag> in an XML answer.
std::string xml_text(std::string_view xml, std::string_view tag);
// How many <tag> elements an XML answer holds.
std::size_t xml_count(std::string_view xml, std::string_view tag);
// "Wed, 28 Sep 2026 14:30:00 GMT" as Unix seconds.
std::optional<std::int64_t> http_date_unix(std::string_view date);
// IAM SimulatePrincipalPolicy's answer as (action, decision) pairs: allowed, explicitDeny, implicitDeny.
std::vector<std::pair<std::string, std::string>> simulation_decisions(std::string_view xml);
// The IAM entity STS GetCallerIdentity's ARN stands for, to simulate: a user as it is, an assumed
// role as its role. Empty for the root user and for identities IAM cannot simulate.
std::string policy_source_arn(std::string_view caller_arn);
// s3:ListAllMyBuckets is the account's, the bucket's own actions the bucket's, the rest its objects'.
enum class ActionScope { account, bucket, object };
ActionScope action_scope(std::string_view action);
} // namespace object_storage_detail

} // namespace support_assist
