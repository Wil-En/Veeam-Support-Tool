#include "support_assist/object_storage.hpp"

#include "support_assist/aws_sigv4.hpp"
#include "support_assist/data_files.hpp"
#include "support_assist/https_request.hpp"
#include "support_assist/json.hpp"
#include "support_assist/network.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <utility>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#endif

namespace support_assist {
namespace {

Error storage_error(std::string operation, std::string source, std::string message) {
  Error error;
  error.component = "ObjectStorageCheck";
  error.operation = std::move(operation);
  error.source = std::move(source);
  error.message = std::move(message);
  return error;
}

ObjectStorageCatalog load_catalog() {
  ObjectStorageCatalog catalog;
  const JsonValue& data = data_file("object-storage.json");
  catalog.reviewed = data["reviewed"].as_string();
  catalog.request_cap = static_cast<int>(data["request_cap"].as_number(25.0));
  for (const JsonValue& item : data["presets"].items()) {
    ObjectStoragePreset preset;
    preset.id = item["id"].as_string();
    preset.name = item["name"].as_string();
    preset.endpoint = item["endpoint"].as_string();
    preset.addressing = item["addressing"].as_string("path");
    preset.default_region = item["default_region"].as_string("us-east-1");
    preset.prices = item["prices"].as_string();
    preset.bucket_reads = item["bucket_reads"].as_string("read");
    preset.immutability = item["immutability"].as_string();
    preset.later = item["later"].as_bool();
    preset.regions = item["regions"].string_items();
    if (!preset.id.empty())
      catalog.presets.push_back(std::move(preset));
  }
  const JsonValue& s3 = data["immutability"]["s3"];
  catalog.immutability_source = s3["source"].as_string();
  catalog.immutability_build = s3["build"].as_string();
  catalog.immutability_reviewed = s3["reviewed"].as_string();
  catalog.immutability_rules = s3["rules"].string_items();
  for (const JsonValue& item : data["permissions"].items()) {
    ObjectStoragePermissions permissions;
    permissions.id = item["id"].as_string();
    permissions.product = item["product"].as_string();
    permissions.source = item["source"].as_string();
    permissions.build = item["build"].as_string();
    permissions.reviewed = item["reviewed"].as_string();
    permissions.standard_note = item["standard_note"].as_string();
    permissions.standard = item["standard"].string_items();
    permissions.immutability = item["immutability"].string_items();
    permissions.archiving = item["archiving"].string_items();
    catalog.permissions.push_back(std::move(permissions));
  }
  return catalog;
}

std::string replace_text(std::string text, std::string_view from, std::string_view to) {
  for (std::size_t at = text.find(from); at != std::string::npos; at = text.find(from, at + to.size()))
    text.replace(at, from.size(), to);
  return text;
}

// A cost with two significant digits: "$0.0000016".
std::string money(double cost, const std::string& currency) {
  const std::string sign = currency == "USD" || currency.empty() ? "$" : currency + " ";
  if (cost <= 0.0)
    return sign + "0";
  const int decimals = std::clamp(1 - static_cast<int>(std::floor(std::log10(cost))), 2, 12);
  char text[64] = {};
  std::snprintf(text, sizeof(text), "%.*f", decimals, cost);
  return sign + text;
}

bool bucket_name_ok(const std::string& bucket, bool virtual_hosted) {
  if (bucket.size() < 3U || bucket.size() > 63U)
    return false;
  for (const char character : bucket) {
    const bool lower = (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
                       character == '.' || character == '-';
    const bool path_only = (character >= 'A' && character <= 'Z') || character == '_';
    if (!lower && !(path_only && !virtual_hosted))
      return false;
  }
  return std::isalnum(static_cast<unsigned char>(bucket.front())) != 0 &&
         std::isalnum(static_cast<unsigned char>(bucket.back())) != 0;
}

std::string environment_value(const char* name) {
#ifdef _WIN32
  char* value = nullptr;
  std::size_t length = 0;
  std::string text;
  if (_dupenv_s(&value, &length, name) == 0 && value != nullptr)
    text = value;
  std::free(value);
  return text;
#else
  const char* value = std::getenv(name);
  return value == nullptr ? std::string() : std::string(value);
#endif
}

// The proxy this machine has set, as text; empty when none.
std::string proxy_text() {
  std::string text;
  for (const char* name : {"HTTPS_PROXY", "https_proxy"}) {
    const std::string value = environment_value(name);
    if (!value.empty()) {
      text = std::string(name) + " " + value;
      break;
    }
  }
#ifdef _WIN32
  WINHTTP_PROXY_INFO machine{};
  if (WinHttpGetDefaultProxyConfiguration(&machine) != FALSE) {
    if (machine.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY && machine.lpszProxy != nullptr)
      text += std::string(text.empty() ? "" : "; ") + "WinHTTP " + utf8_from_wide(machine.lpszProxy);
    if (machine.lpszProxy != nullptr)
      GlobalFree(machine.lpszProxy);
    if (machine.lpszProxyBypass != nullptr)
      GlobalFree(machine.lpszProxyBypass);
  }
  WINHTTP_CURRENT_USER_IE_PROXY_CONFIG user{};
  if (WinHttpGetIEProxyConfigForCurrentUser(&user) != FALSE) {
    if (user.lpszProxy != nullptr)
      text += std::string(text.empty() ? "" : "; ") + "Internet Options " + utf8_from_wide(user.lpszProxy);
    if (user.lpszAutoConfigUrl != nullptr)
      text += std::string(text.empty() ? "" : "; ") + "automatic configuration " + utf8_from_wide(user.lpszAutoConfigUrl);
    for (LPWSTR value : {user.lpszProxy, user.lpszProxyBypass, user.lpszAutoConfigUrl}) {
      if (value != nullptr)
        GlobalFree(value);
    }
  }
#endif
  return text;
}

std::string seconds_text(double seconds) {
  const long long whole = std::llround(std::fabs(seconds));
  if (whole >= 120)
    return std::to_string(whole / 60) + " min " + std::to_string(whole % 60) + " s";
  return std::to_string(whole) + " s";
}

// Days since 1970-01-01 for a civil date.
std::int64_t days_from_civil(std::int64_t year, unsigned month, unsigned day) {
  year -= month <= 2 ? 1 : 0;
  const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
  const auto year_of_era = static_cast<unsigned>(year - era * 400);
  const unsigned shifted = month > 2 ? month - 3U : month + 9U;
  const unsigned day_of_year = (153U * shifted + 2U) / 5U + day - 1U;
  const unsigned day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
  return era * 146097 + static_cast<std::int64_t>(day_of_era) - 719468;
}

// One answer to a signed GET.
struct SignedAnswer {
  bool sent = false;
  std::string transport_error;
  int status = 0;
  std::string body;
  std::string code;
  std::string message;
  std::string date;
  std::string region;
  std::uint64_t bytes = 0;
};

// A GET signed with AWS SigV4: to the storage (s3, with its payload hash header), or to AWS STS or
// IAM. The query is sent as it is signed, each name and value encoded; an empty value is sent as the
// name alone, as S3's subresources are.
SignedAnswer send_signed_get(const std::string& host, std::uint16_t port, const std::string& path,
                             const std::vector<std::pair<std::string, std::string>>& query,
                             const std::string& region, const std::string& service, const SigV4Credentials& signer,
                             bool s3, const std::string& pinned_sha256, const std::string& trusted_certificates,
                             const CancellationToken& cancel) {
  SignedAnswer answer;
  const std::string timestamp = sigv4_timestamp_now();
  const std::string host_header = host + (port == 443 ? "" : ":" + std::to_string(port));
  SigV4Request request;
  request.method = "GET";
  request.canonical_uri = path;
  request.query = query;
  request.headers = {{"host", host_header}, {"x-amz-date", timestamp}};
  if (s3)
    request.headers.emplace_back("x-amz-content-sha256", std::string(kEmptyPayloadSha256));
  if (!signer.session_token.empty())
    request.headers.emplace_back("x-amz-security-token", signer.session_token);
  request.payload_sha256 = std::string(kEmptyPayloadSha256);
  const SigV4Signature signature = sign_sigv4(request, signer, region, service, timestamp);
  HttpsRequest http;
  http.host = host;
  http.port = port;
  http.server_name = host;
  http.target = path;
  for (std::size_t index = 0; index < query.size(); ++index) {
    http.target += (index == 0 ? "?" : "&") + sigv4_uri_encode(query[index].first, false);
    if (!query[index].second.empty())
      http.target += "=" + sigv4_uri_encode(query[index].second, false);
  }
  http.headers = {{"x-amz-date", timestamp}, {"Authorization", signature.authorization}};
  if (s3)
    http.headers.emplace_back("x-amz-content-sha256", std::string(kEmptyPayloadSha256));
  if (!signer.session_token.empty())
    http.headers.emplace_back("x-amz-security-token", signer.session_token);
  http.pinned_sha256 = pinned_sha256;
  http.trusted_certificates = trusted_certificates;
  http.max_body_bytes = 256U * 1024U;
  auto response = https_request(http, cancel);
  if (!response.ok()) {
    answer.transport_error = response.error().message;
    return answer;
  }
  answer.sent = true;
  answer.bytes = response.value().bytes_received;
  answer.status = response.value().status;
  answer.body = response.value().body;
  answer.date = response.value().header("date");
  answer.region = response.value().header("x-amz-bucket-region");
  answer.code = object_storage_detail::xml_text(answer.body, "Code");
  answer.message = object_storage_detail::xml_text(answer.body, "Message");
  if (answer.region.empty())
    answer.region = object_storage_detail::xml_text(answer.body, "Region");
  return answer;
}

// Why a permission was not checked, by what it would take.
std::string unchecked_reason(const std::string& action) {
  if (action == "s3:ListAllMyBuckets")
    return "Not checked: it lists every bucket the key can see, which Veeam uses only to offer the bucket in a list";
  const bool writes = action.find(":Put") != std::string::npos || action.find(":Delete") != std::string::npos ||
                      action == "s3:AbortMultipartUpload" || action == "s3:RestoreObject";
  if (writes)
    return "Not checked: it is a write, and SAT writes nothing";
  if (action.find(":GetObject") != std::string::npos || action == "s3:ListMultipartUploadParts")
    return "Not checked: it reads a backup object, which SAT does not open";
  return "Not checked";
}

} // namespace

namespace object_storage_detail {

std::string xml_text(std::string_view xml, std::string_view tag) {
  const std::string open = "<" + std::string(tag);
  for (std::size_t at = xml.find(open); at != std::string_view::npos; at = xml.find(open, at + 1U)) {
    const std::size_t after = at + open.size();
    if (after >= xml.size() || (xml[after] != '>' && xml[after] != ' ' && xml[after] != '/'))
      continue;
    const std::size_t close_bracket = xml.find('>', after);
    if (close_bracket == std::string_view::npos)
      return {};
    if (xml[close_bracket - 1U] == '/')
      return {};
    const std::size_t end = xml.find("</" + std::string(tag) + ">", close_bracket);
    if (end == std::string_view::npos)
      return {};
    return trim(xml.substr(close_bracket + 1U, end - close_bracket - 1U));
  }
  return {};
}

std::size_t xml_count(std::string_view xml, std::string_view tag) {
  const std::string open = "<" + std::string(tag);
  std::size_t count = 0;
  for (std::size_t at = xml.find(open); at != std::string_view::npos; at = xml.find(open, at + 1U)) {
    const std::size_t after = at + open.size();
    if (after < xml.size() && (xml[after] == '>' || xml[after] == ' '))
      ++count;
  }
  return count;
}

std::optional<std::int64_t> http_date_unix(std::string_view date) {
  // "Wed, 28 Sep 2026 14:30:00 GMT"
  const auto parts = split(trim(date), ' ');
  if (parts.size() < 5U)
    return std::nullopt;
  static constexpr const char* months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
  unsigned month = 0;
  for (unsigned index = 0; index < 12U; ++index) {
    if (parts[2] == months[index])
      month = index + 1U;
  }
  const auto clock = split(parts[4], ':');
  if (month == 0U || clock.size() != 3U)
    return std::nullopt;
  const int day = std::atoi(parts[1].c_str());
  const int year = std::atoi(parts[3].c_str());
  if (day < 1 || day > 31 || year < 1970)
    return std::nullopt;
  const std::int64_t days = days_from_civil(year, month, static_cast<unsigned>(day));
  return days * 86400 + std::atoi(clock[0].c_str()) * 3600 + std::atoi(clock[1].c_str()) * 60 +
         std::atoi(clock[2].c_str());
}

std::vector<std::pair<std::string, std::string>> simulation_decisions(std::string_view xml) {
  std::vector<std::pair<std::string, std::string>> decisions;
  constexpr std::string_view open_action = "<EvalActionName>";
  constexpr std::string_view open_decision = "<EvalDecision>";
  std::size_t at = xml.find(open_action);
  while (at != std::string_view::npos) {
    const std::size_t action_end = xml.find("</EvalActionName>", at);
    if (action_end == std::string_view::npos)
      break;
    const std::string action = trim(xml.substr(at + open_action.size(), action_end - at - open_action.size()));
    const std::size_t next = xml.find(open_action, action_end);
    const std::size_t decision_at = xml.find(open_decision, action_end);
    if (decision_at != std::string_view::npos && (next == std::string_view::npos || decision_at < next)) {
      const std::size_t decision_end = xml.find("</EvalDecision>", decision_at);
      if (decision_end == std::string_view::npos)
        break;
      decisions.emplace_back(action, trim(xml.substr(decision_at + open_decision.size(),
                                                     decision_end - decision_at - open_decision.size())));
    }
    at = next;
  }
  return decisions;
}

std::string policy_source_arn(std::string_view caller_arn) {
  const std::string arn = trim(caller_arn);
  // arn:aws:iam::123456789012:user/path/name, arn:aws:sts::123456789012:assumed-role/Role/session
  const auto parts = split(arn, ':');
  if (parts.size() < 6U || parts[0] != "arn")
    return {};
  std::string resource = parts[5];
  for (std::size_t index = 6; index < parts.size(); ++index)
    resource += ":" + parts[index];
  if (parts[2] == "iam" && resource.rfind("user/", 0) == 0)
    return arn;
  if (parts[2] == "sts" && resource.rfind("assumed-role/", 0) == 0) {
    const std::string rest = resource.substr(std::string_view("assumed-role/").size());
    const std::size_t slash = rest.find('/');
    return "arn:" + parts[1] + ":iam::" + parts[4] + ":role/" + (slash == std::string::npos ? rest : rest.substr(0, slash));
  }
  return {};
}

ActionScope action_scope(std::string_view action) {
  if (action == "s3:ListAllMyBuckets")
    return ActionScope::account;
  static constexpr std::string_view kBucketActions[] = {
      "s3:ListBucket",          "s3:GetBucketLocation",       "s3:GetBucketVersioning",
      "s3:GetBucketObjectLockConfiguration", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads",
      "s3:GetLifecycleConfiguration"};
  for (const std::string_view bucket_action : kBucketActions) {
    if (action == bucket_action)
      return ActionScope::bucket;
  }
  return ActionScope::object;
}

} // namespace object_storage_detail

const ObjectStorageCatalog& object_storage_catalog() {
  static const ObjectStorageCatalog catalog = load_catalog();
  return catalog;
}

const ObjectStoragePermissions* find_object_storage_permissions(std::string_view id) {
  const auto& products = object_storage_catalog().permissions;
  if (products.empty())
    return nullptr;
  const auto found = std::find_if(products.begin(), products.end(),
                                  [&](const ObjectStoragePermissions& product) { return product.id == id; });
  return found == products.end() ? &products.front() : &*found;
}

const ObjectStoragePreset* find_object_storage_preset(std::string_view id) {
  const auto& presets = object_storage_catalog().presets;
  const auto found = std::find_if(presets.begin(), presets.end(),
                                  [&](const ObjectStoragePreset& preset) { return preset.id == id; });
  return found == presets.end() ? nullptr : &*found;
}

std::optional<ObjectStoragePrices> object_storage_prices(std::string_view provider) {
  if (provider.empty())
    return std::nullopt;
  const JsonValue& entry = data_file("object-storage-prices.json")["providers"][std::string(provider)];
  if (!entry.has("name"))
    return std::nullopt;
  ObjectStoragePrices prices;
  prices.name = entry["name"].as_string();
  prices.billing = entry["billing"].as_string("unknown");
  prices.currency = entry["currency"].as_string("USD");
  prices.basis = entry["basis"].as_string();
  prices.free = entry["free"].as_string();
  prices.checked = entry["checked"].as_string();
  prices.read_per_1000 = entry["per_1000"]["read"].as_number();
  prices.list_per_1000 = entry["per_1000"]["list"].as_number();
  return prices;
}

Result<ObjectStorageEndpoint> resolve_object_storage_endpoint(const ObjectStorageTarget& target) {
  const ObjectStoragePreset* preset = find_object_storage_preset(target.preset);
  if (preset == nullptr)
    return Result<ObjectStorageEndpoint>::failure(
        storage_error("read the target", target.preset, "There is no object storage preset named \"" + target.preset + "\"."));
  if (preset->later)
    return Result<ObjectStorageEndpoint>::failure(
        storage_error("read the target", preset->name, preset->name + " is not checked yet."));
  ObjectStorageEndpoint endpoint;
  endpoint.region = trim(target.region).empty() ? preset->default_region : trim(target.region);
  endpoint.addressing = trim(target.addressing).empty() ? preset->addressing : ascii_lower(trim(target.addressing));
  if (endpoint.addressing != "virtual-hosted" && endpoint.addressing != "path")
    return Result<ObjectStorageEndpoint>::failure(storage_error(
        "read the target", target.addressing, "Addressing is virtual-hosted or path."));
  std::string text = trim(target.endpoint);
  if (text.empty()) {
    if (preset->endpoint.empty())
      return Result<ObjectStorageEndpoint>::failure(storage_error(
          "read the target", preset->name, "Enter the endpoint, such as s3.example.com or 10.0.4.30:9000."));
    text = replace_text(preset->endpoint, "{region}", endpoint.region);
  }
  for (const char* scheme : {"https://", "HTTPS://"}) {
    if (text.rfind(scheme, 0) == 0)
      text = text.substr(std::string_view(scheme).size());
  }
  if (text.rfind("http://", 0) == 0)
    return Result<ObjectStorageEndpoint>::failure(
        storage_error("read the target", text, "The check uses HTTPS only."));
  while (!text.empty() && text.back() == '/')
    text.pop_back();
  if (text.find('/') != std::string::npos || text.empty())
    return Result<ObjectStorageEndpoint>::failure(
        storage_error("read the target", text, "The endpoint is a host name or address, with a port when it is not 443."));
  // host, host:port, [v6] or [v6]:port
  std::string port_text;
  if (text.front() == '[') {
    const std::size_t close = text.find(']');
    if (close == std::string::npos)
      return Result<ObjectStorageEndpoint>::failure(storage_error("read the target", text, "The IPv6 address has no closing ]."));
    endpoint.host = text.substr(1U, close - 1U);
    if (close + 1U < text.size() && text[close + 1U] == ':')
      port_text = text.substr(close + 2U);
  } else {
    const std::size_t colon = text.rfind(':');
    if (colon != std::string::npos && text.find(':') == colon) {
      endpoint.host = text.substr(0, colon);
      port_text = text.substr(colon + 1U);
    } else {
      endpoint.host = text;
    }
  }
  if (!port_text.empty()) {
    const int port = std::atoi(port_text.c_str());
    if (port <= 0 || port > 65535 || port_text.find_first_not_of("0123456789") != std::string::npos)
      return Result<ObjectStorageEndpoint>::failure(storage_error("read the target", text, "The port is 1 to 65535."));
    endpoint.port = static_cast<std::uint16_t>(port);
  }
  const std::string bucket = trim(target.bucket);
  const bool virtual_hosted = endpoint.addressing == "virtual-hosted";
  if (!bucket_name_ok(bucket, virtual_hosted))
    return Result<ObjectStorageEndpoint>::failure(storage_error(
        "read the target", bucket,
        "A bucket name is 3 to 63 characters: lowercase letters, digits, dots and hyphens, starting and ending "
        "with a letter or a digit."));
  endpoint.request_host = virtual_hosted ? bucket + "." + endpoint.host : endpoint.host;
  endpoint.bucket_path = virtual_hosted ? "/" : "/" + bucket + "/";
  return Result<ObjectStorageEndpoint>::success(std::move(endpoint));
}

ObjectStorageEstimate estimate_object_storage_check(const ObjectStorageTarget& target) {
  ObjectStorageEstimate estimate;
  const ObjectStoragePreset* preset = find_object_storage_preset(target.preset);
  const auto endpoint = resolve_object_storage_endpoint(target);
  estimate.endpoint = endpoint.ok() ? endpoint.value().request_host : trim(target.endpoint);
  std::string sends = "The check sends " + std::to_string(estimate.requests) + " signed requests to " +
                      estimate.endpoint + ": " + std::to_string(kObjectStorageSignedReads) +
                      " reads of the bucket's settings, and " + std::to_string(kObjectStorageListings) +
                      " listings that return at most one name each. It writes nothing.";
  if (preset != nullptr && preset->id == "amazon-s3")
    sends += " It also asks AWS STS and IAM, which bill nothing, who the key is and what it may do.";
  const auto prices = preset != nullptr ? object_storage_prices(preset->prices) : std::nullopt;
  if (!prices || prices->billing == "unknown") {
    estimate.billing = "unknown";
    estimate.needs_agreement = true;
    estimate.provider = prices ? prices->name : std::string();
    estimate.text = "SAT has no prices for this endpoint. On-site storage bills nothing; a cloud service may bill "
                    "each request, usually a fraction of a cent per thousand. " + sends;
    return estimate;
  }
  estimate.provider = prices->name;
  estimate.checked = prices->checked;
  estimate.free = prices->free;
  estimate.currency = prices->currency;
  estimate.billing = prices->billing;
  if (prices->billing == "none") {
    estimate.text = prices->name + " bills no requests. " + sends;
    return estimate;
  }
  const double read_per_1000 = preset->bucket_reads == "list" ? prices->list_per_1000 : prices->read_per_1000;
  estimate.cost = (read_per_1000 * kObjectStorageSignedReads + prices->list_per_1000 * kObjectStorageListings) / 1000.0;
  estimate.needs_agreement = true;
  estimate.text = "Requests to " + prices->name + " are billed. " + sends + " At " + prices->name +
                  "'s published prices that is about " + money(estimate.cost, estimate.currency) +
                  ", a fraction of a cent" + (prices->free.empty() ? "" : ", and " + prices->free) +
                  ". The estimate uses the prices in SAT's data file, checked " + prices->checked +
                  "; an agreement with " + prices->name + " may differ.";
  return estimate;
}

std::optional<ObjectStorageCredentials> object_storage_credentials_from_environment() {
  ObjectStorageCredentials credentials;
  credentials.access_key = environment_value("SAT_S3_ACCESS_KEY");
  credentials.secret_key = environment_value("SAT_S3_SECRET_KEY");
  credentials.session_token = environment_value("SAT_S3_SESSION_TOKEN");
  if (credentials.access_key.empty() || credentials.secret_key.empty())
    return std::nullopt;
  return credentials;
}

Result<ObjectStorageResult> check_object_storage(const ObjectStorageOptions& options, const CancellationToken& cancel,
                                                 ProgressCallback progress) {
  const auto resolved = resolve_object_storage_endpoint(options.target);
  if (!resolved.ok())
    return Result<ObjectStorageResult>::failure(resolved.error());
  const ObjectStorageCatalog& catalog = object_storage_catalog();
  const ObjectStoragePreset& preset = *find_object_storage_preset(options.target.preset);
  ObjectStorageResult result;
  result.preset = preset.name;
  result.endpoint = resolved.value();
  result.bucket = trim(options.target.bucket);
  result.started_unix_millis = unix_millis_now();
  const auto step = [&](const std::string& what) {
    if (!progress)
      return;
    ProgressEvent event;
    event.phase = "Object Storage Check";
    event.current_scope = what;
    event.processed = static_cast<std::uint64_t>(result.requests);
    progress(event);
  };
  const auto row = [&](const char* section, std::string label, std::string value, ObjectCheckState state) {
    result.rows.push_back({section, std::move(label), std::move(value), state});
  };
  const std::string endpoint_text =
      result.endpoint.host + (result.endpoint.port == 443 ? "" : ":" + std::to_string(result.endpoint.port));
  const char* reach = "Reach (no requests)";
  row(reach, "Endpoint", endpoint_text + ", region " + result.endpoint.region, ObjectCheckState::info);
  // The certificate file chosen, read once for every request to the storage.
  std::string trusted_certificates;
  if (const std::string certificate_file = trim(options.target.certificate_file); !certificate_file.empty()) {
    std::ifstream file(path_from_utf8(certificate_file), std::ios::binary);
    trusted_certificates.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    row(reach, "Certificate file",
        trusted_certificates.empty() ? certificate_file + " could not be read" : certificate_file,
        trusted_certificates.empty() ? ObjectCheckState::fail : ObjectCheckState::info);
  }

  // The name, its addresses and TCP.
  step("DNS and TCP " + std::to_string(result.endpoint.port));
  TcpPortTestOptions tcp;
  tcp.host = result.endpoint.host;
  tcp.port = result.endpoint.port;
  tcp.timeout = std::chrono::milliseconds(5000);
  tcp.detect_sat_listener = false;
  tcp.both_families = false;
  auto connected = test_tcp_port(tcp, cancel);
  if (!connected.ok() || !connected.value().connected) {
    const std::string why = connected.ok() ? (connected.value().attempts.empty() ? "no address answered"
                                                                                  : connected.value().attempts.back().message)
                                           : connected.error().message;
    if (connected.ok() && connected.value().resolved_addresses.empty())
      row(reach, "Addresses", "The name does not resolve: " + why, ObjectCheckState::fail);
    else
      row(reach, "TCP " + std::to_string(result.endpoint.port), "No connection: " + why, ObjectCheckState::fail);
    result.headline = "No connection to " + endpoint_text;
    result.ended_unix_millis = unix_millis_now();
    return Result<ObjectStorageResult>::success(std::move(result));
  }
  {
    const TcpPortTestResult& value = connected.value();
    std::string addresses;
    for (const std::string& address : value.resolved_addresses)
      addresses += (addresses.empty() ? "" : ", ") + address;
    if (addresses.empty())
      addresses = value.connected_address;
    row(reach, "Addresses", addresses + (value.name_source.empty() ? "" : " (from " + value.name_source + ")"),
        ObjectCheckState::pass);
    char elapsed[32] = {};
    std::snprintf(elapsed, sizeof(elapsed), "%.1f ms", value.elapsed_ms);
    row(reach, "TCP " + std::to_string(result.endpoint.port), "Connected to " + value.connected_address + " in " + elapsed,
        ObjectCheckState::pass);
  }

  // TLS and the certificate, for the endpoint and, virtual-hosted, for the bucket's own name.
  const auto handshake = [&](const std::string& name) {
    HttpsRequest probe;
    probe.host = name;
    probe.port = result.endpoint.port;
    probe.server_name = name;
    probe.handshake_only = true;
    probe.pinned_sha256 = options.target.pinned_sha256;
    probe.trusted_certificates = trusted_certificates;
    probe.timeout = std::chrono::milliseconds(10000);
    return https_request(probe, cancel);
  };
  step("TLS handshake with " + result.endpoint.host);
  const auto endpoint_tls = handshake(result.endpoint.host);
  if (!endpoint_tls.ok()) {
    row(reach, "TLS", endpoint_tls.error().message, ObjectCheckState::fail);
    result.headline = "No TLS connection to " + endpoint_text;
    result.ended_unix_millis = unix_millis_now();
    return Result<ObjectStorageResult>::success(std::move(result));
  }
  const HttpsResponse& tls = endpoint_tls.value();
  {
    char timing[48] = {};
    std::snprintf(timing, sizeof(timing), " in %.1f ms", tls.tls_ms);
    row(reach, "TLS", tls.tls_version + timing, ObjectCheckState::pass);
    const TlsCertificateInfo& certificate = tls.certificate;
    row(reach, "Certificate", certificate.subject + ", issued by " + certificate.issuer + ", valid until " +
                                  certificate.valid_until,
        ObjectCheckState::info);
    row(reach, "Trust", tls.trust_detail, tls.trusted ? ObjectCheckState::pass : ObjectCheckState::fail);
    row(reach, "SHA-256 fingerprint", certificate.sha256_fingerprint, ObjectCheckState::info);
  }
  const bool virtual_hosted = result.endpoint.addressing == "virtual-hosted";
  bool request_name_ready = false;
  if (virtual_hosted) {
    step("TLS handshake with " + result.endpoint.request_host);
    const auto bucket_tls = handshake(result.endpoint.request_host);
    if (!bucket_tls.ok()) {
      row(reach, "Virtual-hosted name", result.endpoint.request_host + ": " + bucket_tls.error().message,
          ObjectCheckState::fail);
    } else if (!bucket_tls.value().name_matches) {
      row(reach, "Virtual-hosted name",
          result.endpoint.request_host + " answers, and its certificate does not carry that name" +
              (result.bucket.find('.') != std::string::npos ? " (a dot in the bucket name breaks a wildcard name)" : ""),
          ObjectCheckState::fail);
    } else {
      request_name_ready = bucket_tls.value().trusted;
      row(reach, "Virtual-hosted name",
          result.endpoint.request_host + " resolves and its certificate carries the name",
          bucket_tls.value().trusted ? ObjectCheckState::pass : ObjectCheckState::attention);
    }
    row(reach, "Path style", tls.name_matches ? "The endpoint's certificate carries " + result.endpoint.host
                                              : "The endpoint's certificate does not carry " + result.endpoint.host,
        tls.name_matches ? ObjectCheckState::info : ObjectCheckState::attention);
  } else {
    request_name_ready = tls.trusted && tls.name_matches;
    row(reach, "Path style",
        tls.name_matches ? "The certificate carries " + result.endpoint.host
                         : "The certificate does not carry " + result.endpoint.host,
        tls.name_matches ? ObjectCheckState::pass : ObjectCheckState::fail);
  }
  const std::string proxy = proxy_text();
  row(reach, "Proxy", proxy.empty() ? "None set; the check connects directly" : proxy + "; the check connects directly",
      ObjectCheckState::info);

  // The signed requests.
  const char* signed_section = "Signed reads";
  const ObjectStorageEstimate estimate = estimate_object_storage_check(options.target);
  result.currency = estimate.currency;
  const ObjectStoragePermissions* chosen = find_object_storage_permissions(options.product);
  if (chosen != nullptr)
    result.product = chosen->product;
  // What the run learns of each permission: a read's or a listing's answer, and IAM's decision.
  std::map<std::string, PermissionState> proofs;
  std::map<std::string, std::string> decisions;
  bool keys_accepted = false;
  bool root_keys = false;
  bool lock_enabled = false;
  std::string iam_note;
  if (!options.credentials || trim(options.credentials->access_key).empty() || options.credentials->secret_key.empty()) {
    row(signed_section, "Signed reads", "Not run: enter the access key and the secret key Veeam uses to run them",
        ObjectCheckState::not_checked);
  } else if (estimate.needs_agreement && !options.accept_cost) {
    row(signed_section, "Signed reads", "Not run: " + estimate.text, ObjectCheckState::not_checked);
  } else if (!request_name_ready) {
    row(signed_section, "Signed reads",
        "Not run: they need a trusted certificate that carries " + result.endpoint.request_host +
            ": by this machine's certificate store, by a certificate file chosen, or by its SHA-256 fingerprint "
            "accepted for the session",
        ObjectCheckState::not_checked);
  } else {
    result.signed_reads = true;
    const ObjectStorageCredentials& credentials = *options.credentials;
    const SigV4Credentials signer{trim(credentials.access_key), credentials.secret_key, trim(credentials.session_token)};
    using Answer = SignedAnswer;
    const auto signed_query = [&](const std::vector<std::pair<std::string, std::string>>& query,
                                  const std::string& what) {
      if (result.requests >= catalog.request_cap) {
        Answer capped;
        capped.transport_error = "The request cap of " + std::to_string(catalog.request_cap) + " is reached";
        return capped;
      }
      step("Signed request: " + what);
      ++result.requests;
      Answer answer = send_signed_get(result.endpoint.request_host, result.endpoint.port, result.endpoint.bucket_path,
                                      query, result.endpoint.region, "s3", signer, true, options.target.pinned_sha256,
                                      trusted_certificates, cancel);
      result.bytes_read += answer.bytes;
      return answer;
    };
    const auto signed_get = [&](const std::string& subresource) { return signed_query({{subresource, ""}}, subresource); };
    // A read's answer proves its permission either way; another answer proves nothing.
    const auto prove = [&](const std::string& action, const Answer& answer, bool allowed) {
      if (allowed)
        proofs[action] = PermissionState::allowed;
      else if (answer.sent && answer.code == "AccessDenied")
        proofs[action] = PermissionState::denied;
    };
    // An answer that stops the signed reads: the key is not known, the secret does not match, the
    // clock is too far off, or the bucket is not there.
    const auto stops = [&](const Answer& answer) {
      if (!answer.sent) {
        row(signed_section, "Signed read", answer.transport_error, ObjectCheckState::fail);
        return true;
      }
      if (answer.code == "InvalidAccessKeyId") {
        row(signed_section, "Sign-in", "The access key is not known to this endpoint", ObjectCheckState::fail);
        return true;
      }
      if (answer.code == "SignatureDoesNotMatch") {
        row(signed_section, "Sign-in", "The secret key does not match the access key", ObjectCheckState::fail);
        return true;
      }
      if (answer.code == "RequestTimeTooSkewed") {
        row(signed_section, "Clock",
            "This machine's clock differs from the storage's by more than the 15 minutes a signature allows",
            ObjectCheckState::fail);
        return true;
      }
      if (answer.code == "NoSuchBucket" || (answer.status == 404 && answer.code.empty())) {
        row(signed_section, "Bucket", "No bucket named " + result.bucket + " at this endpoint", ObjectCheckState::fail);
        return true;
      }
      return false;
    };

    Answer location = signed_get("location");
    // A bucket in another region answers with that region; ask once more there.
    const bool moved = location.sent && !location.region.empty() && location.region != result.endpoint.region &&
                       (location.status == 301 || location.code == "AuthorizationHeaderMalformed" ||
                        location.code == "PermanentRedirect" || location.code == "IllegalLocationConstraintException");
    if (moved) {
      row(signed_section, "Region",
          "The bucket is in " + location.region + ", not " + result.endpoint.region + " as entered",
          ObjectCheckState::attention);
      ObjectStorageTarget retarget = options.target;
      retarget.region = location.region;
      const auto again = resolve_object_storage_endpoint(retarget);
      if (again.ok() && (trim(options.target.endpoint).empty() || again.value().host == result.endpoint.host)) {
        result.endpoint = again.value();
        location = signed_get("location");
      }
    }
    if (location.sent && !location.date.empty()) {
      if (const auto server = object_storage_detail::http_date_unix(location.date)) {
        const double offset = static_cast<double>(*server) - static_cast<double>(unix_millis_now()) / 1000.0;
        result.clock_offset_seconds = offset;
        const double size = std::fabs(offset);
        const std::string how = size < 1.0 ? "The storage's clock agrees with this machine's"
                                            : "The storage's clock is " + seconds_text(offset) +
                                                  (offset > 0 ? " ahead of" : " behind") + " this machine's";
        row(signed_section, "Clock",
            how + (size >= 60.0 ? "; a signature fails past 15 minutes" : ""),
            size < 60.0 ? ObjectCheckState::pass : size < 900.0 ? ObjectCheckState::attention : ObjectCheckState::fail);
      }
    }
    if (!stops(location)) {
      keys_accepted = true;
      prove("s3:GetBucketLocation", location, location.status == 200);
      if (location.status == 200) {
        std::string bucket_region = object_storage_detail::xml_text(location.body, "LocationConstraint");
        if (bucket_region.empty())
          bucket_region = "us-east-1";
        else if (bucket_region == "EU")
          bucket_region = "eu-west-1";
        row(signed_section, "Sign-in", "The keys are accepted", ObjectCheckState::pass);
        if (!moved)
          row(signed_section, "Region",
              bucket_region == result.endpoint.region || preset.default_region == "auto"
                  ? bucket_region
                  : "The bucket reports " + bucket_region + "; " + result.endpoint.region + " was entered",
              bucket_region == result.endpoint.region || preset.default_region == "auto" ? ObjectCheckState::pass
                                                                                          : ObjectCheckState::attention);
      } else if (location.code == "AccessDenied") {
        row(signed_section, "Sign-in", "Signed in; the key may not read the bucket's region (s3:GetBucketLocation)",
            ObjectCheckState::attention);
      } else {
        row(signed_section, "Region", "HTTP " + std::to_string(location.status) + " " + location.code + ": " + location.message,
            ObjectCheckState::attention);
      }

      const bool judge = preset.immutability == "s3";
      bool versioning_enabled = false;
      const Answer versioning = signed_get("versioning");
      if (!stops(versioning)) {
        prove("s3:GetBucketVersioning", versioning, versioning.status == 200);
        if (versioning.status == 200) {
          const std::string status = object_storage_detail::xml_text(versioning.body, "Status");
          versioning_enabled = status == "Enabled";
          row(signed_section, "Versioning",
              status.empty() ? "Never enabled" : status,
              versioning_enabled || !judge ? ObjectCheckState::pass : ObjectCheckState::attention);
        } else {
          row(signed_section, "Versioning",
              versioning.code == "AccessDenied" ? "The key may not read it (s3:GetBucketVersioning)"
                                                : "HTTP " + std::to_string(versioning.status) + " " + versioning.code,
              ObjectCheckState::not_checked);
        }
      }
      const Answer lock = signed_get("object-lock");
      if (!stops(lock)) {
        const bool not_configured = lock.code == "ObjectLockConfigurationNotFoundError" || lock.status == 404;
        prove("s3:GetBucketObjectLockConfiguration", lock, lock.status == 200 || not_configured);
        if (lock.status == 200) {
          lock_enabled = object_storage_detail::xml_text(lock.body, "ObjectLockEnabled") == "Enabled";
          row(signed_section, "Object Lock", lock_enabled ? "Enabled" : "Not enabled",
              lock_enabled || !judge ? ObjectCheckState::pass : ObjectCheckState::attention);
          const std::string mode = object_storage_detail::xml_text(lock.body, "Mode");
          if (!mode.empty()) {
            const std::string days = object_storage_detail::xml_text(lock.body, "Days");
            const std::string years = object_storage_detail::xml_text(lock.body, "Years");
            row(signed_section, "Default retention",
                mode + ", " + (days.empty() ? years + " years" : days + " days") +
                    ": Veeam's guide asks for it off, as Veeam sets each object's retention itself",
                judge ? ObjectCheckState::fail : ObjectCheckState::info);
          } else if (lock_enabled) {
            row(signed_section, "Default retention", "Off", ObjectCheckState::pass);
          }
        } else if (not_configured) {
          row(signed_section, "Object Lock", "Not enabled: the bucket cannot hold immutable backups",
              judge ? ObjectCheckState::attention : ObjectCheckState::info);
        } else {
          row(signed_section, "Object Lock",
              lock.code == "AccessDenied" ? "The key may not read it (s3:GetBucketObjectLockConfiguration)"
                                          : "HTTP " + std::to_string(lock.status) + " " + lock.code,
              ObjectCheckState::not_checked);
        }
      }
      const Answer lifecycle = signed_get("lifecycle");
      if (!stops(lifecycle)) {
        const bool none = lifecycle.code == "NoSuchLifecycleConfiguration" || lifecycle.status == 404;
        prove("s3:GetLifecycleConfiguration", lifecycle, lifecycle.status == 200 || none);
        if (lifecycle.status == 200) {
          const std::size_t rules = object_storage_detail::xml_count(lifecycle.body, "Rule");
          row(signed_section, "Lifecycle rules",
              std::to_string(rules) + (rules == 1U ? " rule" : " rules") +
                  ": Veeam's guide does not support lifecycle rules on its immutable buckets",
              judge && lock_enabled ? ObjectCheckState::fail : ObjectCheckState::attention);
        } else if (none) {
          row(signed_section, "Lifecycle rules", "None", ObjectCheckState::pass);
        } else {
          row(signed_section, "Lifecycle rules",
              lifecycle.code == "AccessDenied"
                  ? "The key may not read them (s3:GetLifecycleConfiguration); check them in the storage's console"
                  : "HTTP " + std::to_string(lifecycle.status) + " " + lifecycle.code,
              ObjectCheckState::not_checked);
        }
      }
      if (judge && versioning_enabled && lock_enabled)
        row(signed_section, "Immutability",
            "Versioning and Object Lock are on; they must not be switched on or off while the bucket is in use",
            ObjectCheckState::info);

      // Three listings, each returning at most one name, prove the listing permissions.
      const struct {
        const char* action;
        std::vector<std::pair<std::string, std::string>> query;
      } listings[] = {
          {"s3:ListBucket", {{"list-type", "2"}, {"max-keys", "1"}}},
          {"s3:ListBucketVersions", {{"versions", ""}, {"max-keys", "1"}}},
          {"s3:ListBucketMultipartUploads", {{"uploads", ""}, {"max-uploads", "1"}}},
      };
      for (const auto& listing : listings) {
        const Answer answer = signed_query(listing.query, listing.action);
        if (answer.sent)
          prove(listing.action, answer, answer.status == 200);
      }

      // Amazon S3: who the key is (AWS STS), then what its IAM policies allow (IAM's policy simulator).
      // Both are free and need nothing from the bucket.
      if (preset.id == "amazon-s3") {
        const auto aws_query = [&](const std::string& host, const std::string& service,
                                   const std::vector<std::pair<std::string, std::string>>& query) {
          ++result.iam_requests;
          return send_signed_get(host, 443, "/", query, "us-east-1", service, signer, false, std::string(),
                                 std::string(), cancel);
        };
        step("Who the key is: AWS STS");
        const Answer caller =
            aws_query("sts.amazonaws.com", "sts", {{"Action", "GetCallerIdentity"}, {"Version", "2011-06-15"}});
        if (caller.sent && caller.status == 200)
          result.identity = object_storage_detail::xml_text(caller.body, "Arn");
        if (result.identity.empty()) {
          iam_note = "AWS STS did not say who the key is" +
                     (caller.sent ? ": " + caller.code + (caller.message.empty() ? "" : ", " + caller.message)
                                  : ": " + caller.transport_error);
        } else if (result.identity.rfind("arn:aws:", 0) != 0) {
          iam_note = "AWS IAM's policy simulator is asked only for the standard AWS partition";
        } else if (result.identity.size() >= 5U && result.identity.compare(result.identity.size() - 5U, 5U, ":root") == 0) {
          root_keys = true;
        } else if (const std::string source = object_storage_detail::policy_source_arn(result.identity); source.empty()) {
          iam_note = "AWS IAM's policy simulator cannot simulate this kind of identity";
        } else {
          // Every action any listed product needs, simulated once per scope.
          std::set<std::string> wanted;
          for (const ObjectStoragePermissions& product : catalog.permissions) {
            for (const auto* list : {&product.standard, &product.immutability, &product.archiving})
              wanted.insert(list->begin(), list->end());
          }
          const std::string bucket_arn = "arn:aws:s3:::" + result.bucket;
          const std::pair<object_storage_detail::ActionScope, std::string> scopes[] = {
              {object_storage_detail::ActionScope::account, "*"},
              {object_storage_detail::ActionScope::bucket, bucket_arn},
              {object_storage_detail::ActionScope::object, bucket_arn + "/*"},
          };
          for (const auto& [scope, resource] : scopes) {
            std::vector<std::pair<std::string, std::string>> query{
                {"Action", "SimulatePrincipalPolicy"}, {"Version", "2010-05-08"}, {"PolicySourceArn", source}};
            int member = 0;
            for (const std::string& action : wanted) {
              if (object_storage_detail::action_scope(action) == scope)
                query.emplace_back("ActionNames.member." + std::to_string(++member), action);
            }
            if (member == 0)
              continue;
            query.emplace_back("ResourceArns.member.1", resource);
            step("What the key may do: AWS IAM's policy simulator");
            const Answer simulated = aws_query("iam.amazonaws.com", "iam", query);
            if (!simulated.sent || simulated.status != 200) {
              iam_note = simulated.sent && simulated.code == "AccessDenied"
                             ? "AWS IAM answered AccessDenied: the key may not use iam:SimulatePrincipalPolicy on itself"
                             : "AWS IAM's policy simulator did not answer" +
                                   (simulated.sent ? ": " + simulated.code : ": " + simulated.transport_error);
              decisions.clear();
              break;
            }
            for (const auto& [action, decision] : object_storage_detail::simulation_decisions(simulated.body))
              decisions[action] = decision;
          }
          result.iam_answered = !decisions.empty();
        }
      }
    }
    result.estimated_cost = estimate.billing == "per-request"
                                ? estimate.cost * static_cast<double>(result.requests) /
                                      static_cast<double>(std::max(1, estimate.requests))
                                : 0.0;
    char kilobytes[32] = {};
    std::snprintf(kilobytes, sizeof(kilobytes), "%.1f KB", static_cast<double>(result.bytes_read) / 1024.0);
    row(signed_section, "Requests",
        std::to_string(result.requests) + (result.requests == 1 ? " signed request, " : " signed requests, ") +
            kilobytes + " read, nothing written" +
            (estimate.billing == "per-request"
                 ? "; about " + money(result.estimated_cost, result.currency) + " at " + estimate.provider +
                       "'s prices checked " + estimate.checked
                 : estimate.billing == "none" ? "; no request fees" : "; no prices for this endpoint") +
            (result.iam_requests > 0
                 ? "; " + std::to_string(result.iam_requests) + " to AWS STS and IAM, which bill nothing"
                 : ""),
        ObjectCheckState::info);
  }

  // The key's permissions, held against the chosen product's list and then every listed product's.
  const auto permission_of = [&](const std::string& action, std::string& how) {
    if (root_keys) {
      how = "Allowed: these are the AWS account's root user keys, which IAM allows everything";
      return PermissionState::allowed;
    }
    const auto proof = proofs.find(action);
    const auto decision = decisions.find(action);
    const bool simulated = decision != decisions.end();
    if (proof != proofs.end() && proof->second == PermissionState::allowed) {
      how = simulated && decision->second != "allowed"
                ? "Allowed: a read worked, though the key's IAM policies do not allow it (a bucket policy grants it)"
            : simulated ? "Allowed: IAM allows it, and a read worked"
                        : "Allowed: a read worked";
      return PermissionState::allowed;
    }
    if (proof != proofs.end()) {
      how = simulated && decision->second == "allowed"
                ? "Denied: a read answered AccessDenied, though the key's IAM policies allow it (a bucket policy "
                  "or an organization policy denies it)"
                : "Denied: a read answered AccessDenied";
      return PermissionState::denied;
    }
    if (simulated) {
      if (decision->second == "allowed") {
        how = "Allowed by the key's IAM policies";
        return PermissionState::allowed;
      }
      how = decision->second == "explicitDeny" ? "Denied by a Deny statement in the key's IAM policies"
                                               : "Not allowed: no statement in the key's IAM policies allows it";
      return PermissionState::denied;
    }
    how = unchecked_reason(action);
    return PermissionState::not_checked;
  };
  const auto joined = [](const std::vector<std::string>& actions) {
    std::string out;
    for (const std::string& action : actions)
      out += (out.empty() ? "" : ", ") + action;
    return out;
  };
  const char* guide = "Veeam's guide";
  if (keys_accepted && chosen != nullptr) {
    const std::string permissions_section = "Permissions: " + chosen->product;
    if (!result.identity.empty())
      row(permissions_section.c_str(), "Signed in as", result.identity, ObjectCheckState::info);
    // Where AWS IAM was asked and did not answer, that is worth a look; elsewhere the reads are all there is.
    if (!iam_note.empty())
      row(permissions_section.c_str(), "AWS IAM", iam_note + ". The reads and listings above prove what they touched",
          ObjectCheckState::attention);
    else
      row(permissions_section.c_str(), "Known from",
          root_keys             ? std::string("The keys are the AWS account's root user's")
          : result.iam_answered ? std::string("AWS IAM's policy simulator, from the key's own policies, and the reads "
                                              "and listings above; a bucket policy can allow or deny more")
                                : std::string("The reads and listings above; a write is known only from the storage's "
                                              "own policy tools"),
          ObjectCheckState::info);
    if (!chosen->standard_note.empty())
      row(permissions_section.c_str(), "Note", chosen->standard_note, ObjectCheckState::info);
    row(permissions_section.c_str(), "Source",
        chosen->source + (chosen->build.empty() ? "" : ", build " + chosen->build), ObjectCheckState::info);
    const auto group_rows = [&](const std::vector<std::string>& actions, const std::string& group,
                                const std::string& section) {
      for (const std::string& action : actions) {
        ObjectPermission permission;
        permission.action = action;
        permission.group = group;
        permission.state = permission_of(action, permission.text);
        ObjectCheckState state = ObjectCheckState::not_checked;
        if (permission.state == PermissionState::allowed)
          state = ObjectCheckState::pass;
        else if (permission.state == PermissionState::denied)
          state = group == "standard" || (group == "immutability" && lock_enabled) ? ObjectCheckState::fail
                                                                                   : ObjectCheckState::attention;
        row(section.c_str(), action, permission.text, state);
        result.permissions.push_back(std::move(permission));
      }
    };
    group_rows(chosen->standard, "standard", permissions_section);
    if (!chosen->immutability.empty())
      group_rows(chosen->immutability, "immutability", "With immutability");
    if (!chosen->archiving.empty())
      group_rows(chosen->archiving, "archiving", "Archive tier");

    // Every listed product, held against what is known.
    const char* products = "Veeam products";
    for (const ObjectStoragePermissions& product : catalog.permissions) {
      std::vector<std::string> needed = product.standard;
      needed.insert(needed.end(), product.immutability.begin(), product.immutability.end());
      std::vector<std::string> missing;
      std::size_t unknown = 0;
      for (const std::string& action : needed) {
        std::string ignored;
        const PermissionState state = permission_of(action, ignored);
        if (state == PermissionState::denied)
          missing.push_back(action);
        else if (state == PermissionState::not_checked)
          ++unknown;
      }
      std::string value;
      ObjectCheckState state = ObjectCheckState::pass;
      if (!missing.empty()) {
        value = "Not allowed: " + joined(missing);
        state = ObjectCheckState::attention;
      } else if (unknown == 0U) {
        value = "Everything its guide lists is allowed, with immutability";
      } else {
        value = std::to_string(needed.size() - unknown) + " of " + std::to_string(needed.size()) + " known allowed; " +
                std::to_string(unknown) + " not checked";
        state = ObjectCheckState::not_checked;
      }
      if (unknown > 0U && !missing.empty())
        value += "; " + std::to_string(unknown) + " not checked";
      row(products, product.product, value, state);
    }
  } else if (chosen != nullptr) {
    row(guide, "Permissions", chosen->product + ": " + joined(chosen->standard) +
                                  (chosen->standard_note.empty() ? "" : ". " + chosen->standard_note),
        ObjectCheckState::info);
    if (!chosen->immutability.empty())
      row(guide, "With immutability", joined(chosen->immutability), ObjectCheckState::info);
    if (!chosen->archiving.empty())
      row(guide, "Archive tier", joined(chosen->archiving), ObjectCheckState::info);
    row(guide, "Source", chosen->source + (chosen->build.empty() ? "" : ", build " + chosen->build),
        ObjectCheckState::info);
  }

  // What Veeam's guide asks of an immutable bucket, for reference.
  if (preset.immutability == "s3") {
    std::string rules;
    for (const std::string& rule : catalog.immutability_rules)
      rules += (rules.empty() ? "" : " ") + rule;
    row(guide, "Immutable buckets", rules + " (" + catalog.immutability_source + ", build " + catalog.immutability_build +
                                        ")",
        ObjectCheckState::info);
  }

  // The headline: the first problem, then the first thing to look at, then the state.
  int problems = 0;
  int attention = 0;
  const ObjectCheckRow* first_problem = nullptr;
  const ObjectCheckRow* first_attention = nullptr;
  for (const ObjectCheckRow& entry : result.rows) {
    if (entry.state == ObjectCheckState::fail) {
      ++problems;
      if (first_problem == nullptr)
        first_problem = &entry;
    } else if (entry.state == ObjectCheckState::attention) {
      ++attention;
      if (first_attention == nullptr)
        first_attention = &entry;
    }
  }
  if (first_problem != nullptr)
    result.headline = std::to_string(problems) + (problems == 1 ? " problem: " : " problems, first: ") +
                      first_problem->label;
  else if (first_attention != nullptr)
    result.headline = std::to_string(attention) + (attention == 1 ? " to look at: " : " to look at, first: ") +
                      first_attention->label;
  else
    result.headline = result.signed_reads ? "Reached and signed in; the settings read match Veeam's guide"
                                          : "Reached " + result.endpoint.request_host + " over TLS with a trusted certificate";
  result.ended_unix_millis = unix_millis_now();
  return Result<ObjectStorageResult>::success(std::move(result));
}

} // namespace support_assist
