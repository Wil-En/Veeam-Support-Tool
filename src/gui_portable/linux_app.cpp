#include "portable_app.hpp"
#include "portable_capabilities.hpp"

#include "support_assist/case_review_store.hpp"
#include "support_assist/case_workspace.hpp"
#include "support_assist/case_report.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/sql_tools.hpp"
#include "support_assist/ssh_client.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/network.hpp"
#include "support_assist/process.hpp"
#include "support_assist/time.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/universal_collection.hpp"
#include "support_assist/veeam_log_review.hpp"
#include "support_assist/version.hpp"

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#ifdef Status
#undef Status
#endif

#include <algorithm>
#include <array>
#include <cctype>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

// SAT Linux parity workspace: shared SAT navigation/workflows with explicit Linux capability states.
// SAT portable engineer parity workspace: Linux preserves the Windows SAT information architecture wherever the shared core supports it.
namespace support_assist::gui {
namespace {

enum class Page {
  home,
  case_workspace,
  environment,
  health,
  log_review,
  explorer,
  tools,
  network_tools,
  sql_tools,
  vss_tools,
  registry_tools,
  filesystem_tools,
  wmi_tools,
  vbr_tools,
  host_tools,
  guided,
  gather,
  third_party,
  diagnostics,
  recent_activity,
  help
};

enum class ExplorerSortColumn { name, type, size, modified };

struct PortableActivityRecord {
  std::string timestamp;
  std::string tool;
  std::string result;
  std::string detail;
};

struct PortableCaseDashboard {
  bool loaded = false;
  std::string case_id;
  std::string title;
  std::string engineer;
  std::string review_state = "No saved review";
  std::string updated_utc;
  std::size_t machines = 0;
  std::size_t runs = 0;
  std::size_t errors = 0;
  std::size_t warnings = 0;
  std::size_t bookmarks = 0;
  std::size_t note_selections = 0;
  std::vector<std::string> machine_rows;
  std::vector<std::string> run_rows;
  std::vector<std::string> finding_rows;
};

struct PortableExplorerEntry {
  std::filesystem::path path;
  std::string name;
  bool directory = false;
  std::uint64_t size = 0;
  std::uint64_t modified_unix = 0;
};

struct App {
  Display* display = nullptr;
  Window window{};
  GC gc{};
  XFontStruct* font = nullptr;
  Atom wm_delete{};
  int width = 1180;
  int height = 760;
  Page page = Page::home;
  bool execution_host_enabled = false;
  std::vector<PortableActivityRecord> activity;
  PortableCaseDashboard case_dashboard;
  std::optional<SystemHealthSnapshot> health_snapshot;
  std::mutex mutex;
  std::string body;
  std::string status = "Ready";
  std::atomic_bool dirty{true};
  std::atomic_bool busy{false};
  std::atomic_bool environment_busy{false};
  std::atomic_bool closing{false};
  std::array<std::string, 7> environment_card_values{{"Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting", "Waiting"}};
  std::array<std::string, 7> environment_card_details{};
  int environment_selected_card = -1;
  CancellationSource cancellation;
  std::thread worker;
  std::vector<ProductDefinition> gather_products;
  std::vector<bool> gather_product_selected;
  std::vector<bool> gather_product_detected;
  bool gather_third_party = true;

  // Network Tools form. The current Linux edition keeps tool categories separate
  // so the Tools landing page remains a catalog rather than one mixed form.
  std::array<std::string, 5> network_fields{{"127.0.0.1", "2500", "", "", ""}};
  int active_network_field = -1;
  bool network_all_interfaces = false;
  bool network_sat_payload = true;
  bool network_tls_compare = false;
  int network_tool_view = 0; // 0 catalog, 1 connectivity, 2 listeners, 3 TLS, 4 throughput

  // Portable SQL Tools: same permission-script and native ODBC/SQLCMD workflow as Windows.
  std::array<std::string, 5> sql_fields{{"", "master", "", "", ""}}; // server, database, principal, connection string, output script
  int active_sql_field = -1;
  bool sql_trusted_connection = true;
  bool sql_include_database_permissions = true;

  // Filesystem Change fields. These use the shared snapshot/scanner engine;
  // POSIX exclusions and SHA-256 are real current capabilities rather than CLI-only switches.
  std::array<std::string, 4> filesystem_fields{{"", "", "", ""}}; // root, output, baseline, other
  int active_filesystem_field = -1;
  bool filesystem_hash_sha256 = true;

  // Portable Log Review and Case Workspace fields. These drive the same shared
  // parser/case APIs as Windows rather than shelling out to the CLI.
  std::array<std::string, 2> review_fields{{"", ""}}; // source, optional case root
  int active_review_field = -1;
  bool review_full_scan = false;
  std::array<std::string, 4> case_fields{{"", "", "", ""}}; // parent/root, id, title, engineer
  int active_case_field = -1;
  PortableCaseCatalog case_catalog;
  bool case_selector_open = false;
  std::string active_case_root;
  bool delete_case_armed = false;

  // Explorer parity: bounded local Veeam/case/SAT roots plus Linux-native SSH/SFTP.
  int explorer_tab = 0; // 0 Local, 1 SSH/SFTP, 3 Remote Console
  std::vector<std::filesystem::path> explorer_roots;
  std::filesystem::path explorer_current_path;
  std::vector<PortableExplorerEntry> explorer_entries;
  int explorer_selected = -1;
  std::size_t explorer_local_scroll = 0;
  ExplorerSortColumn explorer_sort_column = ExplorerSortColumn::name;
  bool explorer_sort_ascending = true;
  std::filesystem::path explorer_last_selected_local;
  std::string explorer_local_path_field;
  bool active_explorer_local_path = false;
  std::set<std::filesystem::path> explorer_marked_paths;
  std::array<std::string, 5> explorer_ssh_fields{{"", "22", "", "", "/var/log/VeeamBackup"}};
  int active_explorer_ssh_field = -1;
  std::string explorer_ssh_fingerprint;
  bool explorer_ssh_trusted = false;
  bool explorer_ssh_connected = false;
  std::vector<SftpEntry> explorer_ssh_entries;
  int explorer_ssh_selected = -1;
  std::size_t explorer_ssh_scroll = 0;
  ExplorerSortColumn explorer_ssh_sort_column = ExplorerSortColumn::name;
  bool explorer_ssh_sort_ascending = true;
  std::string explorer_ssh_machine_name;
  int explorer_console_target = 0; // 0 local Bash, 1 SSH
  std::string explorer_console_command;
  int active_explorer_console_field = -1;
};

void set_body(App& app, std::string body, std::string status = "Ready");
void refresh_case_dashboard(App& app);
void ensure_explorer_roots(App& app);

constexpr int kSidebar = 230;
constexpr int kHeader = 72;

struct NavItem { std::string label; Page page; bool child = false; bool section = false; };

std::vector<NavItem> navigation_items(const App& app) {
  std::vector<NavItem> items{
      {"Home", Page::home},
      {"Case Dashboard", Page::case_workspace},
      {"Environment Review", Page::environment},
      {"Health Monitor", Page::health},
      {"Log Review", Page::log_review},
      {"File Browser", Page::explorer}};
  if (app.execution_host_enabled) {
    items.push_back({"Tools", Page::tools});
    items.push_back({"EXECUTION CATEGORIES", Page::tools, false, true});
    items.push_back({"  Log Collection", Page::gather, true});
    items.push_back({"  Guided Diagnostics", Page::guided, true});
    items.push_back({"  Network Tools", Page::network_tools, true});
    items.push_back({"  SQL Tools", Page::sql_tools, true});
    items.push_back({"  VSS Tools", Page::vss_tools, true});
    items.push_back({"  Registry Tools", Page::registry_tools, true});
    items.push_back({"  Filesystem Change", Page::filesystem_tools, true});
    items.push_back({"  WMI Diagnostics", Page::wmi_tools, true});
    items.push_back({"  VBR Diagnostics", Page::vbr_tools, true});
    items.push_back({"  Linux Host Diagnostics", Page::host_tools, true});
    items.push_back({"Third Party Integrations", Page::third_party});
    items.push_back({"Diagnostics", Page::diagnostics});
  }
  items.push_back({"Recent Activity", Page::recent_activity});
  items.push_back({"Help / About", Page::help});
  return items;
}

std::string page_title(Page page) {
  switch (page) {
  case Page::home: return "Support Assist Tool";
  case Page::health: return "Health Monitor";
  case Page::environment: return "Environment Review";
  case Page::gather: return "Universal Log Gathering";
  case Page::log_review: return "Unified Veeam Log Review";
  case Page::explorer: return "Veeam & Case Explorer";
  case Page::case_workspace: return "Case Dashboard";
  case Page::tools: return "Tools";
  case Page::network_tools: return "Network Tools";
  case Page::sql_tools: return "SQL Tools";
  case Page::vss_tools: return "VSS Tools";
  case Page::registry_tools: return "Registry Tools";
  case Page::filesystem_tools: return "Filesystem Change";
  case Page::wmi_tools: return "WMI Diagnostics";
  case Page::vbr_tools: return "VBR Diagnostics";
  case Page::host_tools: return "Linux Host Diagnostics";
  case Page::guided: return "Guided Diagnostics";
  case Page::third_party: return "Third Party Integrations";
  case Page::diagnostics: return "Diagnostics";
  case Page::recent_activity: return "Recent Activity";
  case Page::help: return "Help / About";
  }
  return "Support Assist Tool";
}

std::filesystem::path default_collection_root() {
  if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0')
    return std::filesystem::path(home) / "Log-Collections";
  return std::filesystem::current_path() / "Log-Collections";
}

bool portable_native_odbc_available() noexcept {
#ifdef SUPPORT_ASSIST_HAS_NATIVE_ODBC
  return true;
#else
  return false;
#endif
}

std::filesystem::path portable_state_directory() {
  if (const char* state = std::getenv("XDG_STATE_HOME"); state != nullptr && *state != '\0')
    return std::filesystem::path(state) / "SupportAssistTool";
  if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0')
    return std::filesystem::path(home) / ".local" / "state" / "SupportAssistTool";
  return std::filesystem::current_path() / "ApplicationLogs";
}

void sync_active_case_root(App& app) {
  const auto* active = app.case_catalog.active();
  app.active_case_root = active == nullptr ? std::string{} : active->root.string();
  app.review_fields[1] = app.active_case_root;
}

void load_portable_cases(App& app) {
  std::vector<std::filesystem::path> seeds;
  std::error_code error;
  const auto current = std::filesystem::current_path(error);
  if (!error) seeds.push_back(current / "Cases");
  seeds.push_back(portable_state_directory() / "Cases");
  app.case_catalog = load_portable_case_catalog(portable_state_directory(), seeds);
  sync_active_case_root(app);
}

void activate_portable_case(App& app, int index) {
  set_portable_active_case(app.case_catalog, index, portable_state_directory());
  sync_active_case_root(app);
  refresh_case_dashboard(app);
  ensure_explorer_roots(app);
}

bool portable_prior_sat_state() {
  std::error_code error;
  if (std::filesystem::exists(portable_state_directory(), error)) return true;
  error.clear();
  const auto current = std::filesystem::current_path(error);
  if (error) return false;
  for (const auto* name : {"ApplicationLogs", "Logs", "State", "Cases"}) {
    error.clear();
    if (std::filesystem::exists(current / name, error)) return true;
  }
  return false;
}

std::string clean_activity_text(std::string value) {
  for (char& ch : value) {
    if (ch == '\t' || ch == '\r' || ch == '\n') ch = ' ';
  }
  if (value.size() > 512U) value.resize(512U);
  return value;
}

void load_portable_activity(App& app) {
  app.activity.clear();
  std::ifstream input(portable_state_directory() / "activity.tsv", std::ios::binary);
  if (!input) return;
  std::string line;
  while (std::getline(input, line)) {
    std::array<std::string,4> fields{};
    std::size_t start = 0;
    for (std::size_t i=0;i<fields.size();++i) {
      const auto tab = line.find('\t', start);
      fields[i] = line.substr(start, tab == std::string::npos ? std::string::npos : tab-start);
      if (tab == std::string::npos) break;
      start = tab + 1U;
    }
    if (!fields[0].empty()) app.activity.push_back({fields[0],fields[1],fields[2],fields[3]});
  }
  if (app.activity.size() > 100U)
    app.activity.erase(app.activity.begin(), app.activity.end()-100);
  std::reverse(app.activity.begin(), app.activity.end());
}

void append_portable_activity(App& app, std::string tool, std::string result, std::string detail) {
  PortableActivityRecord record{utc_now_iso8601(), clean_activity_text(std::move(tool)),
                                clean_activity_text(std::move(result)), clean_activity_text(std::move(detail))};
  {
    std::lock_guard lock(app.mutex);
    app.activity.insert(app.activity.begin(), record);
    if (app.activity.size() > 100U) app.activity.resize(100U);
  }
  std::error_code error;
  std::filesystem::create_directories(portable_state_directory(), error);
  if (error) return;
  std::ofstream output(portable_state_directory() / "activity.tsv", std::ios::binary | std::ios::app);
  if (output) output << record.timestamp << '\t' << record.tool << '\t' << record.result << '\t' << record.detail << '\n';
}

std::uint64_t file_time_to_unix(std::filesystem::file_time_type value) {
  using namespace std::chrono;
  const auto adjusted = time_point_cast<seconds>(value - std::filesystem::file_time_type::clock::now() + system_clock::now());
  const auto seconds_since_epoch = duration_cast<seconds>(adjusted.time_since_epoch()).count();
  return seconds_since_epoch > 0 ? static_cast<std::uint64_t>(seconds_since_epoch) : 0U;
}

std::string format_unix_time(std::uint64_t value) {
  if (value == 0U) return "Unknown";
  const std::time_t raw = static_cast<std::time_t>(value);
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &raw);
#else
  localtime_r(&raw, &tm);
#endif
  std::ostringstream output;
  output << std::put_time(&tm, "%Y-%m-%d %H:%M");
  return output.str();
}

std::string format_size(std::uint64_t bytes) {
  static constexpr std::array<const char*,5> units{{"B","KB","MB","GB","TB"}};
  double value = static_cast<double>(bytes);
  std::size_t unit = 0;
  while (value >= 1024.0 && unit + 1U < units.size()) { value /= 1024.0; ++unit; }
  std::ostringstream output;
  if (unit == 0U) output << static_cast<std::uint64_t>(value) << ' ' << units[unit];
  else output << std::fixed << std::setprecision(value >= 10.0 ? 1 : 2) << value << ' ' << units[unit];
  return output.str();
}

void refresh_case_dashboard(App& app) {
  PortableCaseDashboard dashboard;
  if (app.active_case_root.empty()) { app.case_dashboard = std::move(dashboard); return; }
  auto workspace = open_case_workspace(app.active_case_root);
  if (!workspace.ok()) { app.case_dashboard = std::move(dashboard); return; }
  dashboard.loaded = true;
  dashboard.case_id = workspace.value().case_id;
  dashboard.title = workspace.value().title;
  dashboard.engineer = workspace.value().engineer;

  auto state = load_case_review_state(workspace.value());
  if (state.ok()) {
    dashboard.review_state = state.value().fast_index ? "INDEXED: PRELIMINARY" : "FULLY ANALYZED";
    dashboard.updated_utc = state.value().updated_utc;
  }
  auto bookmarks = load_case_evidence_bookmarks(workspace.value());
  if (bookmarks.ok()) {
    dashboard.bookmarks = bookmarks.value().size();
    dashboard.note_selections = static_cast<std::size_t>(std::count_if(bookmarks.value().begin(), bookmarks.value().end(),
      [](const auto& item){ return item.include_in_note; }));
  }
  auto review = load_case_review_model(workspace.value());
  if (review.ok()) {
    dashboard.machines = review.value().machines.size();
    dashboard.runs = review.value().job_sessions.size();
    for (const auto& incident : review.value().incidents) {
      if (incident.severity == "error") ++dashboard.errors;
      else if (incident.severity == "warning") ++dashboard.warnings;
    }
    for (const auto& machine : review.value().machines) {
      if (dashboard.machine_rows.size() >= 8U) break;
      std::string row = machine.display_name.empty() ? machine.key : machine.display_name;
      if (!machine.role.empty()) row += ": " + machine.role;
      dashboard.machine_rows.push_back(std::move(row));
    }
    for (auto it = review.value().job_sessions.rbegin(); it != review.value().job_sessions.rend() && dashboard.run_rows.size() < 8U; ++it) {
      std::string row = it->machine_name.empty() ? it->machine_key : it->machine_name;
      row += " | " + (it->job_name.empty() ? (it->job_type.empty() ? "Related activity" : it->job_type) : it->job_name);
      if (!it->status.empty()) row += " | " + it->status;
      dashboard.run_rows.push_back(std::move(row));
    }
    for (const auto& incident : review.value().incidents) {
      if (dashboard.finding_rows.size() >= 8U) break;
      if (incident.severity != "error" && incident.severity != "warning") continue;
      std::string row = "[" + incident.severity + "] " + incident.summary;
      if (incident.occurrences > 1U) row += " (x" + std::to_string(incident.occurrences) + ")";
      dashboard.finding_rows.push_back(std::move(row));
    }
  }
  app.case_dashboard = std::move(dashboard);
}

void refresh_health_snapshot(App& app) {
  SystemHealthSampler sampler;
  static_cast<void>(sampler.sample({true,true,true,true,true}));
  std::this_thread::sleep_for(std::chrono::milliseconds(180));
  auto snapshot = sampler.sample({true,true,true,true,true});
  if (snapshot.ok()) {
    app.health_snapshot = std::move(snapshot.value());
    set_body(app, "Health Monitor refreshed. Select findings in the dashboard below for investigation context.", "Health snapshot refreshed");
  } else {
    app.health_snapshot.reset();
    set_body(app, "Health sample failed: " + describe_error(snapshot.error()), "Health sample failed");
  }
}


std::filesystem::path weak_canonical_or_normal(const std::filesystem::path& value) {
  std::error_code error;
  auto canonical = std::filesystem::weakly_canonical(value, error);
  return error ? value.lexically_normal() : canonical;
}

bool path_is_under(const std::filesystem::path& root, const std::filesystem::path& candidate) {
  const auto root_norm = weak_canonical_or_normal(root);
  const auto candidate_norm = weak_canonical_or_normal(candidate);
  auto r = root_norm.begin();
  auto c = candidate_norm.begin();
  for (; r != root_norm.end(); ++r, ++c) {
    if (c == candidate_norm.end() || *r != *c) return false;
  }
  return true;
}

void ensure_explorer_roots(App& app) {
  std::vector<std::filesystem::path> candidates{
      "/var/log/VeeamBackup", "/var/log/veeam", "/opt/veeam", "/etc/veeam",
      default_collection_root()};
  if (!app.active_case_root.empty()) candidates.emplace_back(app.active_case_root);
  app.explorer_roots.clear();
  for (const auto& candidate : candidates) {
    std::error_code error;
    if (!std::filesystem::exists(candidate, error) || error) continue;
    const auto canonical = weak_canonical_or_normal(candidate);
    if (canonical.empty() || canonical == canonical.root_path()) continue;
    if (std::find(app.explorer_roots.begin(), app.explorer_roots.end(), canonical) == app.explorer_roots.end())
      app.explorer_roots.push_back(canonical);
  }
  if (app.explorer_current_path.empty() && !app.explorer_roots.empty())
    app.explorer_current_path = app.explorer_roots.front();
}

bool portable_explorer_allowed(App& app, const std::filesystem::path& candidate) {
  ensure_explorer_roots(app);
  const auto canonical = weak_canonical_or_normal(candidate);
  for (const auto& root : app.explorer_roots)
    if (path_is_under(root, canonical)) return true;
  return false;
}

void refresh_local_explorer(App& app) {
  ensure_explorer_roots(app);
  if (app.explorer_current_path.empty() || !portable_explorer_allowed(app, app.explorer_current_path)) {
    if (!app.explorer_roots.empty()) app.explorer_current_path = app.explorer_roots.front();
  }
  app.explorer_entries.clear();
  app.explorer_selected = -1;
  app.explorer_local_path_field = app.explorer_current_path.string();
  if (app.explorer_current_path.empty()) return;
  std::error_code error;
  for (std::filesystem::directory_iterator it(app.explorer_current_path,
       std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) {
    PortableExplorerEntry entry;
    entry.path = weak_canonical_or_normal(it->path());
    if (!portable_explorer_allowed(app, entry.path)) continue;
    entry.name = it->path().filename().string();
    std::error_code type_error;
    entry.directory = it->is_directory(type_error) && !type_error;
    if (!entry.directory) {
      std::error_code size_error;
      entry.size = it->file_size(size_error);
      if (size_error) entry.size = 0;
    }
    std::error_code modified_error;
    const auto modified = it->last_write_time(modified_error);
    if (!modified_error) entry.modified_unix = file_time_to_unix(modified);
    app.explorer_entries.push_back(std::move(entry));
  }
  const auto column = app.explorer_sort_column;
  const bool ascending = app.explorer_sort_ascending;
  std::stable_sort(app.explorer_entries.begin(), app.explorer_entries.end(), [column,ascending](const auto& a, const auto& b) {
    if (a.directory != b.directory) return a.directory > b.directory;
    int compare = 0;
    switch (column) {
    case ExplorerSortColumn::name: compare = a.name.compare(b.name); break;
    case ExplorerSortColumn::type: compare = std::string(a.directory ? "Folder" : "File").compare(b.directory ? "Folder" : "File"); break;
    case ExplorerSortColumn::size: compare = a.size < b.size ? -1 : (a.size > b.size ? 1 : 0); break;
    case ExplorerSortColumn::modified: compare = a.modified_unix < b.modified_unix ? -1 : (a.modified_unix > b.modified_unix ? 1 : 0); break;
    }
    if (compare == 0) compare = a.name.compare(b.name);
    return ascending ? compare < 0 : compare > 0;
  });
  if (app.explorer_local_scroll >= app.explorer_entries.size()) app.explorer_local_scroll = 0;
}

std::optional<SshConnectionOptions> portable_ssh_options(App& app, bool require_credentials) {
  SshConnectionOptions options;
  options.host = app.explorer_ssh_fields[0];
  try {
    const auto port = std::stoul(app.explorer_ssh_fields[1]);
    if (port == 0 || port > 65535) return std::nullopt;
    options.port = static_cast<std::uint16_t>(port);
  } catch (...) { return std::nullopt; }
  options.username = app.explorer_ssh_fields[2];
  options.password = app.explorer_ssh_fields[3];
  if (options.host.empty() || (require_credentials && (options.username.empty() || options.password.empty())))
    return std::nullopt;
  if (require_credentials) {
    if (!app.explorer_ssh_trusted || app.explorer_ssh_fingerprint.empty()) return std::nullopt;
    options.expected_host_key_sha256 = app.explorer_ssh_fingerprint;
  }
  return options;
}

void start_portable_ssh_probe(App& app) {
  if (app.busy.exchange(true)) return;
  auto options = portable_ssh_options(app, false);
  if (!options) { app.busy=false; set_body(app, "Enter a valid SSH host and port.", "SSH host/port required"); return; }
  app.explorer_ssh_trusted = false;
  app.explorer_ssh_connected = false;
  app.explorer_ssh_fingerprint.clear();
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker = std::thread([&app, options=*options] {
    auto result = ssh_probe_host_key(options, app.cancellation.token());
    if (result.ok()) {
      { std::lock_guard lock(app.mutex); app.explorer_ssh_fingerprint=result.value().fingerprint_sha256; }
      set_body(app, "SSH host key probed.\nAlgorithm: " + result.value().algorithm + "\nSHA-256: " + result.value().fingerprint_sha256 +
                    "\n\nVerify this fingerprint out-of-band, then select Trust displayed key for this session.", "SSH host key requires verification");
    } else set_body(app, "SSH host-key probe failed:\n" + describe_error(result.error()), "SSH probe failed");
    app.busy=false; app.dirty=true;
  });
}

void start_portable_ssh_list(App& app) {
  if (app.busy.exchange(true)) return;
  auto options = portable_ssh_options(app, true);
  if (!options) { app.busy=false; set_body(app, "Probe and trust the SSH host key, then enter user and session-only password.", "SSH authentication required"); return; }
  const auto remote_path = app.explorer_ssh_fields[4].empty() ? "/" : app.explorer_ssh_fields[4];
  const auto sort_column = app.explorer_ssh_sort_column;
  const bool sort_ascending = app.explorer_ssh_sort_ascending;
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker = std::thread([&app, options=*options, remote_path, sort_column, sort_ascending] {
    auto result=ssh_list_directory(options,remote_path,app.cancellation.token());
    if (result.ok()) {
      auto entries = std::move(result.value());
      std::stable_sort(entries.begin(), entries.end(), [sort_column,sort_ascending](const auto& a, const auto& b) {
        if (a.directory != b.directory) return a.directory > b.directory;
        int compare = 0;
        switch (sort_column) {
        case ExplorerSortColumn::name: compare = a.name.compare(b.name); break;
        case ExplorerSortColumn::type: compare = std::string(a.directory ? "Folder" : "File").compare(b.directory ? "Folder" : "File"); break;
        case ExplorerSortColumn::size: compare = a.size < b.size ? -1 : (a.size > b.size ? 1 : 0); break;
        case ExplorerSortColumn::modified: compare = a.modified_unix < b.modified_unix ? -1 : (a.modified_unix > b.modified_unix ? 1 : 0); break;
        }
        if (compare == 0) compare = a.name.compare(b.name);
        return sort_ascending ? compare < 0 : compare > 0;
      });
      { std::lock_guard lock(app.mutex); app.explorer_ssh_entries=std::move(entries); app.explorer_ssh_selected=-1; app.explorer_ssh_scroll=0; app.explorer_ssh_connected=true; }
      auto hostname = ssh_execute_command(options,"hostname",app.cancellation.token());
      if (hostname.ok()) {
        std::string name = hostname.value().standard_output;
        while (!name.empty() && (name.back()=='\r' || name.back()=='\n' || name.back()==' ' || name.back()=='\t')) name.pop_back();
        if (!name.empty()) { std::lock_guard lock(app.mutex); app.explorer_ssh_machine_name = name; }
      }
      append_portable_activity(app, "Explorer SSH/SFTP", "Connected / browsed", options.host);
      set_body(app, "SSH/SFTP session authenticated. Remote directory loaded.", "SSH/SFTP connected");
    } else { app.explorer_ssh_connected=false; append_portable_activity(app, "Explorer SSH/SFTP", "Browse failed", describe_error(result.error())); set_body(app,"SSH/SFTP failed:\n"+describe_error(result.error()),"SSH/SFTP failed"); }
    app.busy=false; app.dirty=true;
  });
}

void start_portable_ssh_download(App& app) {
  if (app.busy.exchange(true)) return;
  auto options=portable_ssh_options(app,true);
  if (!options || app.explorer_ssh_selected<0 || static_cast<std::size_t>(app.explorer_ssh_selected)>=app.explorer_ssh_entries.size()) {
    app.busy=false; set_body(app,"Select a remote file after connecting.","SFTP download requires a file"); return;
  }
  const auto entry=app.explorer_ssh_entries[static_cast<std::size_t>(app.explorer_ssh_selected)];
  if (entry.directory || app.explorer_current_path.empty() || !portable_explorer_allowed(app,app.explorer_current_path)) {
    app.busy=false; set_body(app,"Choose an approved local Explorer destination and a remote file.","SFTP download blocked"); return;
  }
  const auto local=app.explorer_current_path/entry.name;
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker=std::thread([&app,options=*options,remote=entry.path,local] {
    auto result=ssh_download_file(options,remote,local,app.cancellation.token());
    if (result.ok()) set_body(app,"Downloaded to approved local root:\n"+local.string(),"SFTP download complete");
    else set_body(app,"SFTP download failed:\n"+describe_error(result.error()),"SFTP download failed");
    app.busy=false; app.dirty=true;
  });
}

void start_portable_ssh_upload(App& app) {
  if (app.busy.exchange(true)) return;
  auto options=portable_ssh_options(app,true);
  const auto local=app.explorer_last_selected_local;
  std::error_code error;
  if (!options || local.empty() || !portable_explorer_allowed(app,local) || !std::filesystem::is_regular_file(local,error) || error) {
    app.busy=false; set_body(app,"Select an approved local file and connect SSH/SFTP first.","SFTP upload blocked"); return;
  }
  auto remote=app.explorer_ssh_fields[4].empty()?std::string("/tmp"):app.explorer_ssh_fields[4];
  if (remote.back() != '/') remote.push_back('/');
  remote += local.filename().string();
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker=std::thread([&app,options=*options,local,remote] {
    auto result=ssh_upload_file(options,local,remote,app.cancellation.token());
    if (result.ok()) set_body(app,"Uploaded approved local file:\n"+local.string()+"\n-> "+remote,"SFTP upload complete");
    else set_body(app,"SFTP upload failed:\n"+describe_error(result.error()),"SFTP upload failed");
    app.busy=false; app.dirty=true;
  });
}

void start_portable_ssh_command(App& app) {
  if (app.busy.exchange(true)) return;
  auto options=portable_ssh_options(app,true);
  const auto command=app.explorer_console_command;
  if (!options || command.empty()) { app.busy=false; set_body(app,"Connect SSH/SFTP and enter a command.","Remote command required"); return; }
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker=std::thread([&app,options=*options,command] {
    auto result=ssh_execute_command(options,command,app.cancellation.token());
    if (result.ok()) {
      std::ostringstream out; out<<"ssh> [command text not retained in activity]\nExit: "<<result.value().exit_status<<"\n\n"<<result.value().standard_output;
      if (!result.value().standard_error.empty()) out<<"\nSTDERR\n"<<result.value().standard_error;
      set_body(app,out.str(),"SSH command complete");
    } else set_body(app,"SSH command failed:\n"+describe_error(result.error()),"SSH command failed");
    app.busy=false; app.dirty=true;
  });
}

void start_portable_local_command(App& app) {
  if (!app.execution_host_enabled) {
    set_body(app, "Local shell execution is available only in Customer / Lab execution-host mode.", "Execution host required");
    return;
  }
  if (app.busy.exchange(true)) return;
  const auto command = app.explorer_console_command;
  if (command.empty()) { app.busy=false; set_body(app,"Enter a local shell command.","Command required"); return; }
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker = std::thread([&app,command] {
    ProcessOptions options;
    options.executable = "/bin/bash";
    options.arguments = {"-lc", command};
    options.timeout = std::chrono::minutes(5);
    options.maximum_output_bytes = 4U * 1024U * 1024U;
    auto result = run_process_capture(options, app.cancellation.token());
    if (result.ok()) {
      std::ostringstream out;
      out << "local$ [command text not retained in activity]\nExit: " << result.value().exit_code << "\n\n" << result.value().output;
      if (!result.value().standard_error.empty()) out << "\nSTDERR\n" << result.value().standard_error;
      append_portable_activity(app, "Explorer Local Console", result.value().exit_code == 0 ? "Command completed" : "Command returned non-zero",
                               "Local Bash command text not retained");
      set_body(app,out.str(),result.value().exit_code == 0 ? "Local command complete" : "Local command completed with errors");
    } else {
      append_portable_activity(app, "Explorer Local Console", "Command failed", describe_error(result.error()));
      set_body(app,"Local command failed:\n"+describe_error(result.error()),"Local command failed");
    }
    app.busy=false; app.dirty=true;
  });
}


std::string home_text(const App& app) {
  const auto products = detect_products(native_product_discovery_context());
  std::ostringstream output;
  output << "Support Assist Tool " << kVersion << "\n\n"
         << "Workspace Role: " << (app.execution_host_enabled ? "Customer / Lab Execution Host" : "Engineer Review") << "\n"
         << "Active Case: " << (app.active_case_root.empty() ? "No Case" : app.active_case_root) << "\n"
         << "Detected Veeam products/roles on this host: " << products.size() << "\n\n"
         << kVersion << " cross-platform contract\n"
         << "Windows and Linux use the same first-class SAT workspaces and workflow language. Platform-specific technologies remain explicit rather than disappearing.\n\n"
         << (app.execution_host_enabled
              ? "Local execution tools are enabled for this session. Use Tools for read-only/bounded diagnostics and collection.\n"
              : "Engineer Review is the safe startup role. Enable Customer / Lab mode only when SAT is running on the machine being diagnosed.\n");
  return output.str();
}

std::string network_tools_text() {
  std::ostringstream output;
  output << "NETWORK TOOLS: LINUX\n\n"
         << "The category exposes the same individually named portable diagnostics as the Windows catalog. "
            "Windows-only transports stay visible with a reason instead of disappearing.\n\n";
  for (const auto& item : portable_network_tool_actions(PortablePlatform::linux)) {
    output << item.name << ": " << capability_state_label(item.state, PortablePlatform::linux) << "\n"
           << "  " << item.detail << "\n\n";
  }
  return output.str();
}

std::string tools_text() {
  std::ostringstream output;
  output << "TOOLS: PLATFORM CAPABILITY CATALOG\n\n"
         << "Linux keeps the same SAT tool organization as Windows. Capabilities that are Windows-specific or not yet portable remain visible with an explicit reason.\n\n";
  for (const auto& capability : linux_capability_catalog(ssh_available(), portable_native_odbc_available())) {
    output << capability.name << ": " << capability_state_label(capability.state) << "\n"
           << "  " << capability.detail << "\n\n";
  }
  return output.str();
}


std::string third_party_text() {
  std::ostringstream output;
  output << "THIRD PARTY INTEGRATIONS\n\n";
  const auto tools = inspect_external_tools();
  if (tools.empty()) {
    output << "No optional integrations are defined for this build.\n";
  } else {
    for (const auto& tool : tools) {
      output << tool.definition.name << ": " << to_string(tool.availability) << "\n"
             << "  " << tool.definition.description << "\n";
      if (!tool.detail.empty()) output << "  " << tool.detail << "\n";
      if (tool.definition.windows_only) output << "  Windows-only integration; shown on Linux so the capability difference is explicit.\n";
      output << "\n";
    }
  }
  return output.str();
}

std::string diagnostics_text(const App& app) {
  const auto products = detect_products(native_product_discovery_context());
  std::ostringstream output;
  output << "DIAGNOSTICS\n\n"
         << "Build: " << kBuildRevision << "\n"
         << "Platform: Linux\n"
         << "Workspace Role: " << (app.execution_host_enabled ? "Customer / Lab Execution Host" : "Engineer Review") << "\n"
         << "SSH/SFTP backend: " << (ssh_available() ? "Available" : "Unavailable: build without libssh2") << "\n"
         << "Detected Veeam roles: " << products.size() << "\n"
         << "State directory: " << portable_state_directory().string() << "\n"
         << "Collection root: " << default_collection_root().string() << "\n\n"
         << "Platform differences are reported in Tools rather than silently removing categories.";
  return output.str();
}

std::string recent_activity_text(App& app) {
  std::vector<PortableActivityRecord> activity;
  {
    std::lock_guard lock(app.mutex);
    activity = app.activity;
  }
  std::ostringstream output;
  output << "RECENT ACTIVITY\n\n";
  if (activity.empty()) {
    output << "No activity has been recorded by this Linux SAT installation yet.\n";
    return output.str();
  }
  const auto limit = std::min<std::size_t>(activity.size(), 25U);
  for (std::size_t i=0;i<limit;++i) {
    const auto& record = activity[i];
    output << record.timestamp << " | " << record.tool << " | " << record.result << "\n";
    if (!record.detail.empty()) output << "  " << record.detail << "\n";
  }
  return output.str();
}


std::string sql_tools_text() {
  std::ostringstream output;
  output << "SQL TOOLS\n\n"
         << "Generate Permission Script creates a reviewable diagnostic script without connecting to SQL Server. "
         << "Run Permission Diagnostic uses native ODBC when available and can fall back to an installed SQLCMD.\n\n"
         << "Native ODBC backend: " << (portable_native_odbc_available() ? "Available" : "Not compiled: script generation/SQLCMD fallback still available") << "\n"
         << "Credentials and connection strings are session-only input and are not written to Recent Activity or tool reports.";
  return output.str();
}

std::string platform_not_applicable_text(std::string_view feature, std::string_view reason,
                                         std::string_view alternative) {
  std::ostringstream output;
  output << feature << "\n\nNot applicable on Linux.\n\n" << reason;
  if (!alternative.empty()) output << "\n\nLinux workflow: " << alternative;
  return output.str();
}

std::string filesystem_tools_text() {
  return "FILESYSTEM CHANGE\n\nLinux/macOS filesystem baselines support recursive scanning, wildcard exclusions and real SHA-256 hashing. "
         "Windows-only alternate-data-stream, cloud hydration and Windows file-ID options are not exposed here.\n\n"
         "The CLI reference documents capture and compare workflows in depth; GUI capture/compare fields use the same shared scanner and snapshot schema.";
}

std::string host_tools_text() {
  return "LINUX HOST DIAGNOSTICS\n\nRead-only host diagnostics include OS/kernel, CPU/memory, systemd services, package inventory, "
         "network interfaces/MTU/routes, storage/mounts, process state, OpenSSL/TLS context and detected Veeam product roles.\n\n"
         "Environment Review provides the structured dashboard view of the same safe host context.";
}

std::filesystem::path portable_tool_output_directory() {
  return default_collection_root() / "Tools";
}

std::string safe_tool_name(std::string value) {
  for (char& ch : value) {
    const unsigned char u = static_cast<unsigned char>(ch);
    if (!std::isalnum(u) && ch != '-' && ch != '_') ch = '-';
  }
  while (!value.empty() && value.back() == '-') value.pop_back();
  return value.empty() ? "tool" : value;
}

void write_portable_tool_output(std::string_view tool, std::string_view text) {
  std::error_code error;
  const auto root = portable_tool_output_directory() / safe_tool_name(std::string(tool));
  std::filesystem::create_directories(root, error);
  if (error) return;
  std::string stamp = utc_now_iso8601();
  for (char& ch : stamp) if (ch == ':' || ch == '.' || ch == 'T' || ch == 'Z') ch = '-';
  const auto path = root / (stamp + "-" + safe_tool_name(std::string(tool)) + ".log");
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) return;
  output << "Support Assist Tool " << kVersion << " " << kReleaseChannel << "\n"
         << "Build: " << kBuildRevision << "\n"
         << "Tool: " << tool << "\n"
         << "Captured UTC: " << utc_now_iso8601() << "\n\n" << text << "\n";
}

void start_filesystem_operation(App& app, bool compare) {
  if (app.busy) return;
  const auto root = app.filesystem_fields[0];
  const auto output = app.filesystem_fields[1];
  const auto baseline = app.filesystem_fields[2];
  const auto other = app.filesystem_fields[3];
  if ((!compare && (root.empty() || output.empty())) ||
      (compare && (baseline.empty() || other.empty()))) {
    set_body(app,
             compare ? "Filesystem compare requires both Baseline and Other snapshot paths."
                     : "Filesystem baseline requires Root path and Output .satsnap path.",
             "Filesystem Change: input required");
    return;
  }
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.busy = true;
  app.worker = std::thread([&app, compare, root, output, baseline, other] {
    if (!compare) {
      auto store = SnapshotStore::create(output);
      if (!store.ok()) {
        set_body(app, "Unable to create baseline: " + describe_error(store.error()), "Filesystem Change: failed");
        app.busy = false; return;
      }
      FilesystemScanOptions options;
      options.root = root;
      options.capture_streams = false;
      options.capture_file_identity = false;
      options.hydrate_cloud_files = false;
      options.hash_mode = app.filesystem_hash_sha256 ? HashMode::all : HashMode::none;
      auto metadata = make_snapshot_metadata(SnapshotKind::filesystem, root,
                                             app.filesystem_hash_sha256 ? "{\"hash\":\"all\"}" : "{\"hash\":\"none\"}");
      if (auto st = store.value().begin_snapshot(metadata); !st.ok()) {
        set_body(app, "Unable to begin baseline: " + describe_error(st.error()), "Filesystem Change: failed");
        app.busy = false; return;
      }
      FilesystemScanConfig config;
      config.snapshot_id = metadata.id;
      config.root_path = root;
      config.hash_mode = app.filesystem_hash_sha256 ? "all" : "none";
      config.capture_streams = false;
      config.capture_file_identity = false;
      config.hydrate_cloud_files = false;
      static_cast<void>(store.value().set_filesystem_scan_config(config));
      auto scan = scan_filesystem(store.value(), metadata.id, options, app.cancellation.token(),
        [&app](const ProgressEvent& event) {
          std::ostringstream line;
          line << "Filesystem Change\n\n" << event.phase;
          if (!event.current_scope.empty()) line << "\n" << event.current_scope;
          if (event.processed || event.total) line << "\nProgress: " << event.processed << " / " << event.total;
          if (event.errors) line << "\nErrors: " << event.errors;
          set_body(app, line.str(), "Filesystem Change: running");
        });
      if (!scan.ok()) {
        static_cast<void>(store.value().finish_snapshot(metadata.id, SnapshotState::failed, 0, 1));
        set_body(app, "Filesystem baseline failed: " + describe_error(scan.error()), "Filesystem Change: failed");
      } else {
        const auto state = scan.value().cancelled ? SnapshotState::cancelled : SnapshotState::complete;
        static_cast<void>(store.value().finish_snapshot(metadata.id, state, scan.value().objects, scan.value().errors));
        std::ostringstream done;
        done << "Filesystem baseline " << (state == SnapshotState::complete ? "complete" : "cancelled")
             << "\n\nSnapshot: " << output << "\nSnapshot ID: " << metadata.id
             << "\nObjects: " << scan.value().objects << "\nErrors: " << scan.value().errors
             << "\nHash mode: " << (app.filesystem_hash_sha256 ? "SHA-256 (all files)" : "None");
        set_body(app, done.str(), "Filesystem Change: complete");
      }
    } else {
      auto before = SnapshotStore::open(baseline, true);
      auto after = SnapshotStore::open(other, true);
      if (!before.ok() || !after.ok()) {
        set_body(app, "Unable to open one or both snapshots for comparison.", "Filesystem Change: failed");
        app.busy = false; return;
      }
      auto before_id = before.value().latest_complete_snapshot_id();
      auto after_id = after.value().latest_complete_snapshot_id();
      if (!before_id.ok() || !after_id.ok()) {
        set_body(app, "Unable to resolve snapshot IDs for comparison.", "Filesystem Change: failed");
        app.busy = false; return;
      }
      std::ostringstream report;
      std::uint64_t shown = 0;
      auto result = compare_filesystem(baseline, before_id.value(), other, after_id.value(), {},
        [&report, &shown](const DiffRecord& diff) {
          if (shown++ < 500U) report << to_string(diff.kind) << "\t" << (diff.new_path.empty() ? diff.old_path : diff.new_path) << "\n";
          return Status::success();
        });
      if (!result.ok()) set_body(app, "Filesystem compare failed: " + describe_error(result.error()), "Filesystem Change: failed");
      else {
        std::ostringstream done;
        done << "Filesystem comparison complete\n\nDifferences: " << result.value() << "\n\n" << report.str();
        if (shown > 500U) done << "\n... detail display bounded to first 500 differences; full snapshots remain intact.\n";
        set_body(app, done.str(), "Filesystem Change: complete");
      }
    }
    app.busy = false;
  });
}

std::string guided_text() {
  const auto available = available_guided_diagnostics(native_product_discovery_context());
  std::ostringstream output;
  output << "Guided Diagnostics available for detected local Veeam roles\n\n";
  if (available.empty()) {
    output << "No product-specific Guided Diagnostic is applicable to the Veeam roles detected on this Linux host.\n";
  } else {
    for (const auto& item : available)
      output << "  - " << item.display_name << "\n    " << item.description << "\n    Reference: " << item.kb_id << " | " << item.reference_url << "\n";
  }
  output << "\nGuided Diagnostics are Customer/Lab execution-host tests. Unsupported platform diagnostics are not listed.";
  return output.str();
}
std::string case_text(const App& app) {
  std::ostringstream output;
  output << "Case Dashboard\n\n"
         << "Create or open a SAT case with the native Linux GUI. The workspace uses the same SQLite review store, "
         << "evidence model, reports and parser cache as Windows.\n\n"
         << "Parent / Existing Case Root: " << (app.case_fields[0].empty() ? "(enter a path above)" : app.case_fields[0]) << "\n"
         << "Case ID: " << (app.case_fields[1].empty() ? "(required to create)" : app.case_fields[1]) << "\n"
         << "Title: " << (app.case_fields[2].empty() ? "(optional)" : app.case_fields[2]) << "\n"
         << "Engineer: " << (app.case_fields[3].empty() ? "(optional)" : app.case_fields[3]) << "\n\n"
         << "Active portable case: " << (app.active_case_root.empty() ? "No Case" : app.active_case_root) << "\n\n"
         << "A Log Review started with this active case saves the structured review model and review state into that case. "
         << "No-Case review remains available for quick Customer/Lab analysis.";
  return output.str();
}

std::vector<std::filesystem::path> detected_local_log_sources() {
  const auto context = native_product_discovery_context();
  const auto detected = detect_products(context);
  std::vector<std::filesystem::path> sources;
  for (const auto& product : detected) {
    for (const auto& rule : product.definition.log_paths) {
      if (rule.third_party || rule.sensitive_by_nature) continue;
      const auto path = resolve_catalog_path(context, rule.path);
      std::error_code error;
      if (std::filesystem::exists(path, error) && !error) sources.push_back(path);
    }
  }
  std::sort(sources.begin(), sources.end());
  sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
  return sources;
}

std::string review_landing_text(const App& app) {
  const auto local = detected_local_log_sources();
  std::ostringstream output;
  output << "Unified Veeam Log Review\n\n"
         << "Auto Detect is the normal review path. Enter a ZIP, file or directory above, or use Detect Local Logs on a "
         << "Customer/Lab host to populate the source from installed Veeam product roles.\n\n"
         << "Review depth: " << (app.review_full_scan ? "Full Review" : "Fast Index (preliminary)") << "\n"
         << "Case: " << (app.review_fields[1].empty() ? (app.active_case_root.empty() ? "No Case" : app.active_case_root) : app.review_fields[1]) << "\n"
         << "Detected local Veeam log roots: " << local.size() << "\n";
  for (const auto& path : local) output << "  - " << path.string() << "\n";
  if (local.empty()) output << "  (none found on this host)\n";
  return output.str();
}

std::string format_portable_review_summary(const VeeamLogReviewResult& result) {
  std::size_t errors = 0;
  std::size_t warnings = 0;
  for (const auto& incident : result.incidents) {
    if (incident.severity == "error") ++errors;
    else if (incident.severity == "warning") ++warnings;
  }
  std::ostringstream output;
  output << "Unified Veeam Log Review completed\n\n"
         << "Profile: " << to_string(result.profile_used) << "\n"
         << "Product summary: " << result.product_type << "\n"
         << "Confidence: " << to_string(result.product_confidence) << "\n"
         << "Review state: " << (result.fast_index_used ? "INDEXED: PRELIMINARY" : "FULLY ANALYZED: FULL REVIEW COMPLETE") << "\n"
         << "Files: " << result.files_scanned << " scanned / " << result.files_discovered << " discovered"
         << " / " << result.files_deferred << " deferred\n"
         << "Machines: " << result.machines.size() << "\n"
         << "Structured jobs/activities: " << result.job_sessions.size() << "\n"
         << "Grouped findings: " << errors << " errors / " << warnings << " warnings\n"
         << "Parse errors: " << result.parse_errors << "\n\n";
  if (!result.bundles.empty()) {
    output << "Detected sources/products\n";
    for (const auto& bundle : result.bundles) {
      output << "  - " << (bundle.primary_machine_name.empty() ? bundle.display_name : bundle.primary_machine_name)
             << " | " << (bundle.product_type.empty() ? "Unidentified Veeam product" : bundle.product_type);
      if (!bundle.product_version.empty()) output << " " << bundle.product_version;
      output << "\n";
    }
    output << "\n";
  }
  if (!result.incidents.empty()) {
    output << "Highest-value grouped findings (first 20)\n";
    const std::size_t limit = std::min<std::size_t>(20U, result.incidents.size());
    for (std::size_t index = 0; index < limit; ++index) {
      const auto& incident = result.incidents[index];
      output << "  [" << incident.severity << "] " << incident.summary;
      if (incident.occurrences > 1U) output << " (x" << incident.occurrences << ")";
      if (!incident.component.empty()) output << " | " << incident.component;
      output << "\n";
    }
  }
  if (!result.report_path.empty()) output << "\nReport: " << result.report_path.string() << "\n";
  return output.str();
}

std::string help_text() {
  std::ostringstream output;
  output << "Build " << kBuildRevision << "\n\n"
         << "Linux: CMake/Ninja + X11 development headers.\n"
         << "macOS: CMake/Ninja or Xcode generator + Apple Clang/Cocoa.\n"
         << "Windows: Visual Studio 2022/MSVC + vcpkg static dependencies.\n\n"
         << "The same executable starts this GUI with no arguments and uses CLI mode when arguments are supplied.\n"
         << "See docs/CLI_REFERENCE.md, docs/CROSS_PLATFORM_BUILD.md and docs/UNIVERSAL_LOG_COLLECTION.md in the source package.";
  return output.str();
}

void set_body(App& app, std::string body, std::string status) {
  std::lock_guard lock(app.mutex);
  app.body = std::move(body);
  app.status = std::move(status);
  app.dirty = true;
}

void set_environment_card(App& app, std::size_t index, std::string value, std::string detail) {
  if (index >= app.environment_card_values.size()) return;
  std::lock_guard lock(app.mutex);
  app.environment_card_values[index] = std::move(value);
  app.environment_card_details[index] = std::move(detail);
  app.dirty = true;
}


std::string capture_linux_command(std::string_view command,
                                  const CancellationToken& cancel,
                                  std::chrono::milliseconds timeout = std::chrono::seconds(20)) {
  ProcessOptions options;
  options.executable = "/bin/sh";
  options.arguments = {"-c", std::string(command)};
  options.timeout = timeout;
  options.maximum_output_bytes = 4U * 1024U * 1024U;
  auto result = run_process_capture(options, cancel, {});
  if (!result.ok())
    return "Unavailable: " + describe_error(result.error());
  std::string output = result.value().output;
  if (!result.value().standard_error.empty()) {
    if (!output.empty() && output.back() != '\n') output.push_back('\n');
    output += result.value().standard_error;
  }
  if (output.empty())
    output = result.value().exit_code == 0 ? "(no entries)" : "Unavailable (exit " + std::to_string(result.value().exit_code) + ")";
  return output;
}

void start_environment_refresh(App& app) {
  if (app.busy.exchange(true)) {
    set_body(app, "Environment Review refresh is waiting for the currently running SAT operation to finish.",
             "Another operation is active");
    return;
  }
  app.environment_busy = true;
  app.environment_selected_card = -1;
  {
    std::lock_guard lock(app.mutex);
    for (auto& value : app.environment_card_values) value = "Waiting";
    for (auto& detail : app.environment_card_details) detail.clear();
  }
  app.cancellation = CancellationSource{};
  if (app.worker.joinable()) app.worker.join();
  set_body(app,
           "LINUX ENVIRONMENT REVIEW\n\nCollecting read-only platform information...\n\n"
           "[running] System / OS\n[waiting] Veeam products\n[waiting] Services\n[waiting] Installed software\n"
           "[waiting] Network / MTU / routes\n[waiting] TLS / certificates\n[waiting] Storage",
           "Environment Review: starting");
  app.worker = std::thread([&app]() {
    const auto token = app.cancellation.token();
    std::ostringstream report;
    report << "LINUX ENVIRONMENT REVIEW\n"
           << "Support Assist Tool " << kVersion << " | Build " << kBuildRevision << "\n"
           << "Captured UTC: " << utc_now_iso8601() << "\n\n";

    auto stage = [&](std::string_view name) {
      set_body(app, report.str() + "\n[running] " + std::string(name) + "\n",
               "Environment Review: " + std::string(name));
    };
    auto section = [&](std::size_t card, std::string_view title, std::string content) {
      report << "== " << title << " ==\n" << content;
      if (content.empty() || content.back() != '\n') report << '\n';
      report << '\n';
      set_environment_card(app, card, "Complete", std::string(title) + "\n\n" + content);
      set_body(app, report.str(), "Environment Review: " + std::string(title) + " complete");
    };

    stage("System / OS");
    // Retained RC2 capability wording: this is the Native Linux edition, not a Windows-emulation collector.
    section(0, "System / OS", capture_linux_command(
        "printf 'Hostname: '; hostname 2>/dev/null; "
        "printf 'Kernel: '; uname -srmo 2>/dev/null; "
        "printf 'Architecture: '; uname -m 2>/dev/null; "
        "printf 'Boot ID: '; cat /proc/sys/kernel/random/boot_id 2>/dev/null; "
        "printf '\\nOS release:\\n'; cat /etc/os-release 2>/dev/null; "
        "printf '\\nCPU summary:\\n'; lscpu 2>/dev/null | sed -n '1,24p'; "
        "printf '\\nMemory summary:\\n'; grep -E '^(MemTotal|MemAvailable|SwapTotal|SwapFree):' /proc/meminfo 2>/dev/null",
        token));
    if (token.is_cancelled()) goto finished;

    stage("Veeam products");
    section(1, "Veeam products / roles", format_detected_products_report(detect_products(native_product_discovery_context())));
    if (token.is_cancelled()) goto finished;

    stage("Services");
    section(2, "Services", capture_linux_command(
        "if command -v systemctl >/dev/null 2>&1; then "
        "systemctl list-units --type=service --all --no-pager --no-legend 2>&1 | LC_ALL=C sort; "
        "printf '\\nService enablement:\\n'; systemctl list-unit-files --type=service --no-pager --no-legend 2>&1 | LC_ALL=C sort; "
        "else printf 'systemctl not available\\n'; fi", token));
    if (token.is_cancelled()) goto finished;

    stage("Installed software");
    section(3, "Installed software", capture_linux_command(
        "if command -v dpkg-query >/dev/null 2>&1; then "
        "dpkg-query -W -f='${Package}\\t${Version}\\t${Architecture}\\n' 2>/dev/null | LC_ALL=C sort -f; "
        "elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n' 2>/dev/null | LC_ALL=C sort -f; "
        "else printf 'No supported package inventory command found\\n'; fi", token, std::chrono::seconds(30)));
    if (token.is_cancelled()) goto finished;

    stage("Network / MTU / routes");
    section(4, "Network adapters / MTU / addresses / routes", capture_linux_command(
        "if command -v ip >/dev/null 2>&1; then "
        "printf '%s\\n' '-- Links / MTU --'; ip -details -statistics link show 2>&1; "
        "printf '%s\\n' '-- Addresses --'; ip -details address show 2>&1; "
        "printf '%s\\n' '-- Routes --'; ip route show table all 2>&1; "
        "printf '%s\\n' '-- Policy rules --'; ip rule show 2>&1; "
        "else printf 'iproute2 is not available\\n'; fi; "
        "printf '%s\\n' '-- DNS --'; cat /etc/resolv.conf 2>/dev/null", token));
    if (token.is_cancelled()) goto finished;

    stage("TLS / certificates");
    section(5, "TLS / certificate context", capture_linux_command(
        "printf '%s\\n' '-- OpenSSL --'; openssl version -a 2>&1 || true; "
        "printf '%s\\n' '-- Supported cipher list --'; openssl ciphers -v 'ALL:eNULL' 2>&1 || true; "
        "printf '%s\\n' '-- Veeam-named public certificate files (metadata only; private keys are not read) --'; "
        "find /etc/veeam /opt/veeam /var/lib/veeam -xdev -type f \\( -iname '*veeam*.crt' -o -iname '*veeam*.cer' -o -iname '*veeam*.pem' \\) -print 2>/dev/null | LC_ALL=C sort | head -200",
        token));
    if (token.is_cancelled()) goto finished;

    stage("Storage");
    section(6, "Storage / mounts", capture_linux_command(
        "printf '%s\\n' '-- Filesystems --'; df -hT 2>&1; "
        "printf '%s\\n' '-- Block devices --'; lsblk -o NAME,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,MODEL,SERIAL,ROTA,RO 2>&1",
        token));

finished:
    if (token.is_cancelled()) {
      report << "Environment Review cancelled by user. Completed sections above remain valid evidence.\n";
      append_portable_activity(app,"Environment Review","Cancelled","Completed sections retained");
      set_body(app, report.str(), "Environment Review cancelled");
    } else {
      report << "Collection complete. All commands above are read-only observations.\n";
      append_portable_activity(app,"Environment Review","Completed","Linux environment snapshot");
      set_body(app, report.str(), "Environment Review complete");
    }
    app.environment_busy = false;
    app.busy = false;
    app.dirty = true;
  });
}

void refresh_gather_products(App& app) {
  const auto detected = detect_products(native_product_discovery_context());
  app.gather_products = product_catalog(native_host_platform());
  app.gather_product_selected.assign(app.gather_products.size(), false);
  app.gather_product_detected.assign(app.gather_products.size(), false);
  for (std::size_t index = 0; index < app.gather_products.size(); ++index) {
    const bool found = std::any_of(detected.begin(), detected.end(), [&](const auto& product) {
      return product.definition.id == app.gather_products[index].id;
    });
    app.gather_product_detected[index] = found;
    app.gather_product_selected[index] = found;
  }
}

std::vector<std::string> selected_gather_product_ids(const App& app) {
  std::vector<std::string> selected;
  for (std::size_t index = 0;
       index < app.gather_products.size() && index < app.gather_product_selected.size(); ++index) {
    if (app.gather_product_selected[index])
      selected.push_back(app.gather_products[index].id);
  }
  return selected;
}

void update_page(App& app, bool force_health = false) {
  if (app.busy) return;
  switch (app.page) {
  case Page::home:
    set_body(app, home_text(app));
    break;
  case Page::environment:
    start_environment_refresh(app);
    break;
  case Page::health:
    if (force_health || !app.health_snapshot.has_value()) refresh_health_snapshot(app);
    else set_body(app, "Health Monitor uses the same dashboard structure on Windows and Linux; metrics underneath are platform-native.");
    break;
  case Page::gather:
    if (app.gather_products.empty()) refresh_gather_products(app);
    set_body(app, "Collection root: " + default_collection_root().string() +
                  "\nDetected products are checked by default. Select additional known product roles only when their logs belong to this host.\n"
                  "Third-party collection is bounded to operational/error logs and excludes database payloads and home directories.");
    break;
  case Page::log_review:
    set_body(app, review_landing_text(app));
    break;
  case Page::explorer:
    ensure_explorer_roots(app);
    refresh_local_explorer(app);
    set_body(app, "Explorer uses the same Local / SSH-SFTP / Remote Console workspace language as Windows.");
    break;
  case Page::case_workspace:
    refresh_case_dashboard(app);
    set_body(app, case_text(app));
    break;
  case Page::tools:
    set_body(app, tools_text());
    break;
  case Page::network_tools:
    set_body(app, network_tools_text());
    break;
  case Page::sql_tools:
    set_body(app, sql_tools_text());
    break;
  case Page::vss_tools:
    set_body(app, platform_not_applicable_text(
                      "VSS TOOLS",
                      "Microsoft Volume Shadow Copy Service is a Windows snapshot technology.",
                      "Use native filesystem/storage health, snapshot-capable storage tooling and "
                      "Veeam Agent for Linux diagnostics where applicable."));
    break;
  case Page::registry_tools:
    set_body(app, platform_not_applicable_text("REGISTRY TOOLS", "The Windows Registry does not exist on Linux.", "Use Filesystem Change plus Linux Host Diagnostics for /etc, systemd and application configuration evidence."));
    break;
  case Page::filesystem_tools:
    set_body(app, filesystem_tools_text());
    break;
  case Page::wmi_tools:
    set_body(app, platform_not_applicable_text("WMI DIAGNOSTICS", "Windows Management Instrumentation is Windows-specific.", "Linux Host Diagnostics uses procfs, sysfs, systemd, package and network interfaces."));
    break;
  case Page::vbr_tools:
    set_body(app, platform_not_applicable_text(
                      "VBR DIAGNOSTICS",
                      "A local Veeam Backup & Replication server role is Windows-based.",
                      "Use Log Review, Environment Review, SSH/SFTP and portable network diagnostics "
                      "against collected/remote VBR evidence."));
    break;
  case Page::host_tools:
    set_body(app, host_tools_text());
    break;
  case Page::guided:
    set_body(app, guided_text());
    break;
  case Page::third_party:
    set_body(app, third_party_text());
    break;
  case Page::diagnostics:
    set_body(app, diagnostics_text(app));
    break;
  case Page::recent_activity:
    set_body(app, recent_activity_text(app));
    break;
  case Page::help:
    set_body(app, help_text());
    break;
  }
}

void draw_text(Display* display, Drawable drawable, GC gc, int x, int y, const std::string& text, int max_width, int line_height) {
  int cursor_y = y;
  std::istringstream lines(text);
  std::string line;
  while (std::getline(lines, line)) {
    std::string remaining = line;
    if (remaining.empty()) { cursor_y += line_height; continue; }
    while (!remaining.empty()) {
      std::size_t take = remaining.size();
      const std::size_t approximate_columns = static_cast<std::size_t>(std::max(8, max_width / 8));
      if (take > approximate_columns) {
        take = approximate_columns;
        const auto space = remaining.rfind(' ', take - 1U);
        if (space != std::string::npos && space != 0U) take = space;
      }
      XDrawString(display, drawable, gc, x, cursor_y, remaining.c_str(), static_cast<int>(take));
      remaining.erase(0, take);
      while (!remaining.empty() && remaining.front() == ' ') remaining.erase(remaining.begin());
      cursor_y += line_height;
      if (cursor_y > 710) return;
    }
  }
}

void draw_button(App& app, int x, int y, int w, int h, const std::string& label, bool selected = false) {
  const unsigned long background = selected ? 0x3b5f8aUL : 0x252a30UL;
  XSetForeground(app.display, app.gc, background);
  XFillRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0xd8dde5UL);
  XDrawRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XDrawString(app.display, app.window, app.gc, x + 12, y + 24, label.c_str(), static_cast<int>(label.size()));
}

void draw_metric_card(App& app, int x, int y, int w, int h,
                      const std::string& title, const std::string& value) {
  XSetForeground(app.display, app.gc, 0x18302fUL);
  XFillRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0x3b6b62UL);
  XDrawRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0xb9d6cfUL);
  XDrawString(app.display, app.window, app.gc, x + 10, y + 20, title.c_str(), static_cast<int>(title.size()));
  XSetForeground(app.display, app.gc, 0xf0f5f3UL);
  std::string shown = value.size() > 32U ? value.substr(0, 29U) + "..." : value;
  XDrawString(app.display, app.window, app.gc, x + 10, y + 47, shown.c_str(), static_cast<int>(shown.size()));
}

void draw_capability_card(App& app, int x, int y, int w, int h,
                          const PortableCapability& capability) {
  unsigned long border = 0x5d6773UL;
  unsigned long background = 0x22272eUL;
  if (capability.state == PortableCapabilityState::available) { border = 0x3b6b62UL; background = 0x18302fUL; }
  else if (capability.state == PortableCapabilityState::not_applicable) { border = 0x59616aUL; background = 0x20242aUL; }
  else if (capability.state == PortableCapabilityState::requires_dependency) { border = 0x8a7040UL; background = 0x30291eUL; }
  XSetForeground(app.display, app.gc, background);
  XFillRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, border);
  XDrawRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0xf0f5f3UL);
  XDrawString(app.display, app.window, app.gc, x+10, y+20, capability.name.c_str(), static_cast<int>(capability.name.size()));
  const std::string state = capability_state_label(capability.state);
  XSetForeground(app.display, app.gc, capability.state == PortableCapabilityState::available ? 0xb9d6cfUL : 0xb9c0c8UL);
  XDrawString(app.display, app.window, app.gc, x+10, y+40, state.c_str(), static_cast<int>(state.size()));
  std::string detail = capability.detail;
  const std::size_t max_chars = static_cast<std::size_t>(std::max(18, w/8 - 4));
  if (detail.size() > max_chars) detail = detail.substr(0,max_chars > 3 ? max_chars-3 : max_chars) + "...";
  XSetForeground(app.display, app.gc, 0x9fa8b3UL);
  XDrawString(app.display, app.window, app.gc, x+10, y+61, detail.c_str(), static_cast<int>(detail.size()));
}

void draw_list_panel(App& app, int x, int y, int w, int h, const std::string& title,
                     const std::vector<std::string>& rows, const std::string& empty_text) {
  XSetForeground(app.display, app.gc, 0x20252bUL);
  XFillRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0x46505aUL);
  XDrawRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), static_cast<unsigned int>(h));
  XSetForeground(app.display, app.gc, 0xb9d6cfUL);
  XDrawString(app.display, app.window, app.gc, x+10, y+20, title.c_str(), static_cast<int>(title.size()));
  XSetForeground(app.display, app.gc, 0xdce2e8UL);
  if (rows.empty()) {
    XDrawString(app.display, app.window, app.gc, x+10, y+44, empty_text.c_str(), static_cast<int>(empty_text.size()));
    return;
  }
  int row_y = y + 44;
  const int max_rows = std::max(1, (h-52)/20);
  for (int i=0;i<max_rows && static_cast<std::size_t>(i)<rows.size();++i) {
    std::string row = rows[static_cast<std::size_t>(i)];
    const std::size_t max_chars = static_cast<std::size_t>(std::max(18, w/8 - 4));
    if (row.size() > max_chars) row = row.substr(0,max_chars > 3 ? max_chars-3 : max_chars) + "...";
    XDrawString(app.display, app.window, app.gc, x+10, row_y, row.c_str(), static_cast<int>(row.size()));
    row_y += 20;
  }
}

void draw_checkbox(App& app, int x, int y, int w, const std::string& label, bool checked) {
  constexpr int box = 16;
  XSetForeground(app.display, app.gc, 0xd8dde5UL);
  XDrawRectangle(app.display, app.window, app.gc, x, y, box, box);
  if (checked) {
    XDrawLine(app.display, app.window, app.gc, x + 3, y + 8, x + 7, y + 13);
    XDrawLine(app.display, app.window, app.gc, x + 7, y + 13, x + 14, y + 3);
  }
  XDrawString(app.display, app.window, app.gc, x + box + 8, y + 13, label.c_str(),
              static_cast<int>(label.size()));
  (void)w;
}

void draw_text_field(App& app, int x, int y, int w, const std::string& label,
                     const std::string& value, bool active) {
  XSetForeground(app.display, app.gc, 0xb9c0c8UL);
  XDrawString(app.display, app.window, app.gc, x, y - 6, label.c_str(), static_cast<int>(label.size()));
  XSetForeground(app.display, app.gc, active ? 0x3b5f8aUL : 0x252a30UL);
  XFillRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), 28U);
  XSetForeground(app.display, app.gc, 0xd8dde5UL);
  XDrawRectangle(app.display, app.window, app.gc, x, y, static_cast<unsigned int>(w), 28U);
  std::string shown = value;
  if (shown.size() > 54U) shown = shown.substr(shown.size() - 54U);
  XDrawString(app.display, app.window, app.gc, x + 8, y + 19, shown.c_str(), static_cast<int>(shown.size()));
}

void paint(App& app) {
  XSetForeground(app.display, app.gc, 0x171a1fUL);
  XFillRectangle(app.display, app.window, app.gc, 0, 0, static_cast<unsigned int>(app.width), static_cast<unsigned int>(app.height));
  XSetForeground(app.display, app.gc, 0x20252bUL);
  XFillRectangle(app.display, app.window, app.gc, 0, 0, kSidebar, static_cast<unsigned int>(app.height));
  XSetForeground(app.display, app.gc, 0x2c323aUL);
  XFillRectangle(app.display, app.window, app.gc, kSidebar, 0, static_cast<unsigned int>(app.width-kSidebar), kHeader);
  XSetForeground(app.display, app.gc, 0xf2f5f7UL);
  const std::string title = page_title(app.page);
  XDrawString(app.display, app.window, app.gc, kSidebar + 24, 42, title.c_str(), static_cast<int>(title.size()));
  const std::string version_label = "Support Assist Tool " + std::string(kVersion);
  XDrawString(app.display, app.window, app.gc, 16, 38, version_label.c_str(), static_cast<int>(version_label.size()));
  const std::string role_label = app.execution_host_enabled ? "Customer / Lab" : "Engineer Review";
  const int role_w = 150;
  const int role_x = std::max(kSidebar + 660, app.width - role_w - 24);
  const int case_w = 300;
  const int case_x = std::max(kSidebar + 330, role_x - case_w - 12);
  std::string case_label = "Active Case: " + app.case_catalog.active_label();
  if (case_label.size() > 42U) case_label = case_label.substr(0, 39U) + "...";
  draw_button(app, case_x, 19, case_w, 34, case_label, app.case_selector_open);
  draw_button(app, role_x, 19, role_w, 34, role_label, app.execution_host_enabled);
  if (app.case_selector_open) {
    const int row_h = 30;
    const int max_rows = 9;
    const int rows = std::min(max_rows, static_cast<int>(app.case_catalog.cases.size()) + 1);
    XSetForeground(app.display, app.gc, 0x15191eUL);
    XFillRectangle(app.display, app.window, app.gc, case_x, 55, case_w, static_cast<unsigned int>(rows * row_h + 4));
    draw_button(app, case_x + 2, 57, case_w - 4, row_h - 2, "(No active case)", app.case_catalog.active_index < 0);
    for (int i = 1; i < rows; ++i) {
      const auto& workspace = app.case_catalog.cases[static_cast<std::size_t>(i - 1)];
      std::string label = workspace.case_id;
      if (!workspace.title.empty()) label += ": " + workspace.title;
      if (label.size() > 42U) label = label.substr(0, 39U) + "...";
      draw_button(app, case_x + 2, 57 + i * row_h, case_w - 4, row_h - 2, label, app.case_catalog.active_index == i - 1);
    }
  }
  int nav_y = 82;
  for (const auto& item : navigation_items(app)) {
    if (item.section) {
      XSetForeground(app.display, app.gc, 0x7f8a96UL);
      XDrawString(app.display, app.window, app.gc, 18, nav_y + 16, item.label.c_str(), static_cast<int>(item.label.size()));
      nav_y += 22;
      continue;
    }
    const int height = item.child ? 24 : 30;
    draw_button(app, item.child ? 26 : 16, nav_y, item.child ? 188 : 198, height, item.label, app.page == item.page);
    nav_y += height + 3;
  }

  if (app.page == Page::health) draw_button(app, kSidebar+24, 88, 170, 36, "Refresh Health");
  if (app.page == Page::environment)
    draw_button(app, kSidebar+24, 88, 210, 36, app.environment_busy ? "Cancel Environment" : (app.busy ? "SAT Busy" : "Refresh Environment"));
  int body_y = 154;
  if (app.page == Page::home) {
    const auto products = detect_products(native_product_discovery_context());
    const int available = app.width - kSidebar - 54;
    const int gap = 10;
    const int card_w = std::max(210, (available - 2*gap) / 3);
    draw_metric_card(app, kSidebar+24, 96, card_w, 72, "Workspace Role",
                     app.execution_host_enabled ? "Customer / Lab" : "Engineer Review");
    draw_metric_card(app, kSidebar+24+card_w+gap, 96, card_w, 72, "Active Case",
                     app.active_case_root.empty() ? "No Case" : app.case_dashboard.case_id.empty() ? "Active" : app.case_dashboard.case_id);
    draw_metric_card(app, kSidebar+24+2*(card_w+gap), 96, card_w, 72, "Detected Products",
                     std::to_string(products.size()) + " local role(s)");
    draw_metric_card(app, kSidebar+24, 180, card_w, 72, "Health",
                     app.health_snapshot.has_value() ? std::to_string(app.health_snapshot->findings.size()) + " finding(s)" : "Not sampled");
    draw_metric_card(app, kSidebar+24+card_w+gap, 180, card_w, 72, "Recent Activity",
                     std::to_string(app.activity.size()) + " record(s)");
    draw_metric_card(app, kSidebar+24+2*(card_w+gap), 180, card_w, 72, "Platform Contract",
                     "Windows / Linux parity");
    draw_button(app, kSidebar+24, 266, 245, 34,
                app.execution_host_enabled ? "Return to Engineer Review" : "Enable Customer / Lab Tools");
    draw_button(app, kSidebar+279, 266, 170, 34, "Open Case Dashboard");
    draw_button(app, kSidebar+459, 266, 150, 34, "Open Log Review");
    body_y = 334;
  }
  if (app.page == Page::health && app.health_snapshot.has_value()) {
    const auto& snapshot=*app.health_snapshot;
    const int available=app.width-kSidebar-54, gap=10;
    const int card_w=(available-3*gap)/4;
    const std::string cpu=snapshot.cpu_load_available ? (std::to_string(static_cast<int>(snapshot.cpu_load_percent))+"%") : "Unavailable";
    const std::string memory=std::to_string(static_cast<int>(snapshot.memory_load_percent))+"%";
    draw_metric_card(app,kSidebar+24,138,card_w,70,"CPU",cpu);
    draw_metric_card(app,kSidebar+24+card_w+gap,138,card_w,70,"MEMORY",memory);
    draw_metric_card(app,kSidebar+24+2*(card_w+gap),138,card_w,70,"VOLUMES",std::to_string(snapshot.volumes.size()));
    draw_metric_card(app,kSidebar+24+3*(card_w+gap),138,card_w,70,"FINDINGS",std::to_string(snapshot.findings.size()));
    std::vector<std::string> findings, volumes, adapters;
    for (const auto& finding : snapshot.findings) {
      findings.push_back("["+to_string(finding.severity)+"] "+finding.component+": "+finding.summary);
      if (findings.size()>=8U) break;
    }
    for (const auto& volume : snapshot.volumes) {
      std::string row=volume.root_path;
      if (volume.capacity_available && volume.total_bytes>0U) {
        const auto used=volume.total_bytes-volume.free_bytes;
        row += " | " + format_size(used) + " / " + format_size(volume.total_bytes);
      }
      volumes.push_back(std::move(row));
      if (volumes.size()>=8U) break;
    }
    for (const auto& adapter : snapshot.network_adapters) {
      adapters.push_back(adapter.name+" | "+adapter.operational_status);
      if (adapters.size()>=8U) break;
    }
    const int panel_y=220, panel_w=(available-2*gap)/3;
    draw_list_panel(app,kSidebar+24,panel_y,panel_w,240,"Health Findings",findings,"No threshold findings");
    draw_list_panel(app,kSidebar+24+panel_w+gap,panel_y,panel_w,240,"Volumes / Capacity",volumes,"No volume data");
    draw_list_panel(app,kSidebar+24+2*(panel_w+gap),panel_y,panel_w,240,"Network Adapters",adapters,"No adapter data");
    body_y=490;
  }
  if (app.page == Page::log_review) {
    draw_text_field(app, kSidebar+24, 112, 610, "Log bundle / directory / file",
                    app.review_fields[0], app.active_review_field == 0);
    draw_text_field(app, kSidebar+24, 166, 610, "Case root (optional; blank = No Case)",
                    app.review_fields[1], app.active_review_field == 1);
    draw_checkbox(app, kSidebar+654, 172, 210, "Full Review", app.review_full_scan);
    draw_button(app, kSidebar+24, 210, 150, 34, app.busy ? "Reviewing..." : "Review Source");
    draw_button(app, kSidebar+184, 210, 190, 34, "Detect Local Logs");
    draw_button(app, kSidebar+384, 210, 140, 34, "Use Active Case");
    if (app.busy) draw_button(app, kSidebar+534, 210, 90, 34, "Cancel");
    body_y = 274;
  }
  if (app.page == Page::case_workspace) {
    draw_text_field(app, kSidebar+24, 104, 410, "Parent directory / Existing case root",
                    app.case_fields[0], app.active_case_field == 0);
    draw_text_field(app, kSidebar+450, 104, 170, "Case ID",
                    app.case_fields[1], app.active_case_field == 1);
    draw_text_field(app, kSidebar+24, 154, 410, "Case title",
                    app.case_fields[2], app.active_case_field == 2);
    draw_text_field(app, kSidebar+450, 154, 240, "Engineer",
                    app.case_fields[3], app.active_case_field == 3);
    draw_button(app, kSidebar+704, 104, 120, 30, "Create Case");
    draw_button(app, kSidebar+704, 142, 120, 30, "Register / Open");
    draw_button(app, kSidebar+834, 104, 110, 30, "Use No Case");
    draw_button(app, kSidebar+834, 142, 110, 30, "Refresh");
    draw_button(app, kSidebar+24, 190, 145, 30, "Load Saved Review");
    draw_button(app, kSidebar+177, 190, 145, 30, "Review New Logs");
    draw_button(app, kSidebar+330, 190, 125, 30, "Note Review");
    draw_button(app, kSidebar+463, 190, 125, 30, "PDF Master");
    draw_button(app, kSidebar+596, 190, 135, 30, app.delete_case_armed ? "Confirm Delete" : "Delete Active");

    if (app.case_dashboard.loaded) {
      const int available = app.width-kSidebar-54, gap=8;
      const int card_w = std::max(145,(available-5*gap)/6);
      const int card_y = 234;
      draw_metric_card(app,kSidebar+24,card_y,card_w,68,"CASE",app.case_dashboard.case_id.empty()?"Active":app.case_dashboard.case_id);
      draw_metric_card(app,kSidebar+24+(card_w+gap),card_y,card_w,68,"SYSTEMS",std::to_string(app.case_dashboard.machines));
      draw_metric_card(app,kSidebar+24+2*(card_w+gap),card_y,card_w,68,"RUNS",std::to_string(app.case_dashboard.runs));
      draw_metric_card(app,kSidebar+24+3*(card_w+gap),card_y,card_w,68,"FINDINGS",std::to_string(app.case_dashboard.errors)+" E / "+std::to_string(app.case_dashboard.warnings)+" W");
      draw_metric_card(app,kSidebar+24+4*(card_w+gap),card_y,card_w,68,"EVIDENCE",std::to_string(app.case_dashboard.bookmarks)+" bookmarks");
      draw_metric_card(app,kSidebar+24+5*(card_w+gap),card_y,card_w,68,"REVIEW",app.case_dashboard.review_state);
      const int panel_y=318, panel_gap=10;
      const int panel_w=(available-2*panel_gap)/3;
      draw_list_panel(app,kSidebar+24,panel_y,panel_w,230,"Systems / Components",app.case_dashboard.machine_rows,"No structured systems yet");
      draw_list_panel(app,kSidebar+24+panel_w+panel_gap,panel_y,panel_w,230,"Jobs / Activities / Runs",app.case_dashboard.run_rows,"No structured runs yet");
      draw_list_panel(app,kSidebar+24+2*(panel_w+panel_gap),panel_y,panel_w,230,"Errors / Warnings",app.case_dashboard.finding_rows,"No grouped findings yet");
      body_y = 574;
    } else {
      body_y = 234;
    }
  }
  if (app.page == Page::network_tools) {
    draw_button(app, kSidebar+24, 90, 155, 32, "Connectivity", app.network_tool_view==0);
    draw_button(app, kSidebar+187, 90, 135, 32, "Listeners", app.network_tool_view==1);
    draw_button(app, kSidebar+330, 90, 155, 32, "TLS Handshake", app.network_tool_view==2);
    draw_button(app, kSidebar+493, 90, 155, 32, "Throughput", app.network_tool_view==3);
    draw_text_field(app, kSidebar+24, 142, 250, "Target host / IP", app.network_fields[0], app.active_network_field == 0);
    draw_text_field(app, kSidebar+290, 142, 100, "Port", app.network_fields[1], app.active_network_field == 1);
    draw_text_field(app, kSidebar+406, 142, 200, "Source IP (optional)", app.network_fields[2], app.active_network_field == 2);
    draw_text_field(app, kSidebar+622, 142, 240, "TLS SNI (optional)", app.network_fields[3], app.active_network_field == 3);
    draw_text_field(app, kSidebar+24, 196, 420, "Expected cert SHA-1/SHA-256 (optional)", app.network_fields[4], app.active_network_field == 4);
    draw_checkbox(app, kSidebar+462, 202, 220, "Test all usable interfaces", app.network_all_interfaces);
    if (app.network_tool_view == 0) {
      draw_checkbox(app, kSidebar+690, 202, 220, "50 MiB SAT payload", app.network_sat_payload);
      draw_button(app, kSidebar+24, 240, 130, 34, "Interfaces");
      draw_button(app, kSidebar+164, 240, 130, 34, "TCP Test");
      draw_button(app, kSidebar+304, 240, 130, 34, "UDP Test");
    } else if (app.network_tool_view == 1) {
      draw_button(app, kSidebar+24, 240, 150, 34, "TCP Listener");
      draw_button(app, kSidebar+184, 240, 150, 34, "UDP Listener");
    } else if (app.network_tool_view == 2) {
      draw_checkbox(app, kSidebar+690, 202, 180, "Compare TLS 1.2/1.3", app.network_tls_compare);
      draw_button(app, kSidebar+24, 240, 150, 34, "Run TLS Test");
    } else {
      draw_button(app, kSidebar+24, 240, 190, 34, "Throughput Client");
      draw_button(app, kSidebar+224, 240, 190, 34, "Throughput Server");
    }
    if (app.busy) draw_button(app, kSidebar+840, 240, 90, 34, "Cancel");
    body_y = 302;
  }
  if (app.page == Page::sql_tools) {
    draw_text_field(app, kSidebar+24, 112, 300, "SQL Server / instance", app.sql_fields[0], app.active_sql_field==0);
    draw_text_field(app, kSidebar+340, 112, 180, "Database", app.sql_fields[1], app.active_sql_field==1);
    draw_text_field(app, kSidebar+536, 112, 300, "Principal", app.sql_fields[2], app.active_sql_field==2);
    draw_text_field(app, kSidebar+24, 166, 500, "ODBC connection string (optional)", app.sql_fields[3], app.active_sql_field==3);
    draw_text_field(app, kSidebar+540, 166, 340, "Output .sql (optional)", app.sql_fields[4], app.active_sql_field==4);
    draw_checkbox(app, kSidebar+24, 210, 220, "Trusted / integrated auth", app.sql_trusted_connection);
    draw_checkbox(app, kSidebar+254, 210, 260, "Include database permissions", app.sql_include_database_permissions);
    draw_button(app, kSidebar+24, 244, 210, 34, "Generate Permission Script");
    draw_button(app, kSidebar+244, 244, 220, 34, app.busy ? "Running..." : "Run Permission Diagnostic");
    if (app.busy) draw_button(app, kSidebar+474, 244, 90, 34, "Cancel");
    body_y=310;
  }
  if (app.page == Page::filesystem_tools) {
    draw_text_field(app, kSidebar+24, 112, 420, "Root path", app.filesystem_fields[0], app.active_filesystem_field == 0);
    draw_text_field(app, kSidebar+460, 112, 420, "Output .satsnap", app.filesystem_fields[1], app.active_filesystem_field == 1);
    draw_text_field(app, kSidebar+24, 166, 420, "Baseline .satsnap", app.filesystem_fields[2], app.active_filesystem_field == 2);
    draw_text_field(app, kSidebar+460, 166, 420, "Other .satsnap", app.filesystem_fields[3], app.active_filesystem_field == 3);
    draw_checkbox(app, kSidebar+24, 210, 250, "SHA-256 all files", app.filesystem_hash_sha256);
    draw_button(app, kSidebar+290, 202, 170, 34, app.busy ? "Working..." : "Capture Baseline");
    draw_button(app, kSidebar+472, 202, 180, 34, app.busy ? "Working..." : "Compare Snapshots");
    if (app.busy) draw_button(app, kSidebar+664, 202, 90, 34, "Cancel");
    body_y = 270;
  }
  if (app.page == Page::tools) {
    const auto capabilities = linux_capability_catalog(ssh_available(), portable_native_odbc_available());
    const int available = app.width-kSidebar-54;
    const int columns = available >= 900 ? 3 : 2;
    const int gap=10;
    const int card_w=(available-gap*(columns-1))/columns;
    for (std::size_t i=0;i<capabilities.size();++i) {
      const int row=static_cast<int>(i)/columns, col=static_cast<int>(i)%columns;
      draw_capability_card(app,kSidebar+24+col*(card_w+gap),96+row*82,card_w,72,capabilities[i]);
    }
    const int rows=(static_cast<int>(capabilities.size())+columns-1)/columns;
    body_y=96+rows*82+18;
  }
  if (app.page == Page::guided) {
    const auto available=available_guided_diagnostics(native_product_discovery_context());
    int y=96;
    for(const auto& item:available){
      const bool runnable=item.id=="managed-server-connectivity" || item.id=="veeam-secure-channel";
      draw_button(app,kSidebar+24,y,320,34,item.display_name,runnable);
      XSetForeground(app.display, app.gc, 0xb9c0c8UL);
      std::string detail=item.kb_id+": "+item.description; if(detail.size()>90U)detail.resize(90U);
      XDrawString(app.display,app.window,app.gc,kSidebar+356,y+22,detail.c_str(),static_cast<int>(detail.size()));
      y+=44;
      if(y>360)break;
    }
    body_y=std::max(410,y+14);
  }
  if (app.page == Page::explorer) {
    std::string ssh_machine_name;
    std::string ssh_fingerprint;
    {
      std::lock_guard lock(app.mutex);
      ssh_machine_name = app.explorer_ssh_machine_name;
      ssh_fingerprint = app.explorer_ssh_fingerprint;
    }
    draw_button(app, kSidebar+24, 88, 110, 34, "Local", app.explorer_tab == 0);
    draw_button(app, kSidebar+144, 88, 130, 34, "SSH / SFTP", app.explorer_tab == 1);
    draw_button(app, kSidebar+284, 88, 160, 34, "Remote Console", app.explorer_tab == 3);
    if (app.explorer_tab == 0) {
      if (app.explorer_roots.empty()) ensure_explorer_roots(app);
      if (app.explorer_entries.empty() && !app.explorer_current_path.empty()) refresh_local_explorer(app);
      draw_text_field(app, kSidebar+24, 140, app.width-kSidebar-190, "Approved location", app.explorer_local_path_field, app.active_explorer_local_path);
      draw_button(app, app.width-150, 140, 110, 28, "Go / Refresh");
      const int left_x=kSidebar+24, left_w=250, right_x=left_x+266, right_w=app.width-right_x-30;
      const int panel_y=188, panel_h=std::max(280,app.height-panel_y-92);
      XSetForeground(app.display, app.gc, 0x46505aUL);
      XDrawRectangle(app.display, app.window, app.gc, left_x, panel_y, left_w, panel_h);
      XDrawRectangle(app.display, app.window, app.gc, right_x, panel_y, right_w, panel_h);
      XSetForeground(app.display, app.gc, 0xb9d6cfUL);
      const std::string roots_title="Veeam locations / SAT cases";
      XDrawString(app.display, app.window, app.gc,left_x+8,panel_y+20,roots_title.c_str(),static_cast<int>(roots_title.size()));
      const int root_rows=std::max(1,(panel_h-38)/28);
      for (std::size_t i=0;i<app.explorer_roots.size() && static_cast<int>(i)<root_rows;++i) {
        std::string label=app.explorer_roots[i].string(); if (label.size()>28U) label="..."+label.substr(label.size()-25U);
        draw_button(app,left_x+8,panel_y+28+static_cast<int>(i)*28,left_w-16,24,label,app.explorer_current_path==app.explorer_roots[i]);
      }
      const int header_y=panel_y+6;
      const int name_w=std::max(180,right_w*42/100), type_w=std::max(90,right_w*16/100), size_w=std::max(90,right_w*15/100);
      const int modified_w=right_w-name_w-type_w-size_w-12;
      draw_button(app,right_x+4,header_y,name_w,26,"Name",app.explorer_sort_column==ExplorerSortColumn::name);
      draw_button(app,right_x+4+name_w,header_y,type_w,26,"Type",app.explorer_sort_column==ExplorerSortColumn::type);
      draw_button(app,right_x+4+name_w+type_w,header_y,size_w,26,"Size",app.explorer_sort_column==ExplorerSortColumn::size);
      draw_button(app,right_x+4+name_w+type_w+size_w,header_y,modified_w,26,"Date modified",app.explorer_sort_column==ExplorerSortColumn::modified);
      const int row_y=header_y+32, row_h=24;
      const int visible=std::max(1,(panel_h-70)/row_h);
      const std::size_t begin=std::min(app.explorer_local_scroll,app.explorer_entries.size());
      const std::size_t finish=std::min(app.explorer_entries.size(),begin+static_cast<std::size_t>(visible));
      for (std::size_t i=begin;i<finish;++i) {
        const auto& e=app.explorer_entries[i];
        const int visual=static_cast<int>(i-begin);
        const bool selected=static_cast<int>(i)==app.explorer_selected;
        if (selected) { XSetForeground(app.display,app.gc,0x31557dUL); XFillRectangle(app.display,app.window,app.gc,right_x+4,row_y+visual*row_h,right_w-8,row_h-1); }
        XSetForeground(app.display,app.gc,0xdce2e8UL);
        const std::string icon=e.directory?"[DIR]":"[FILE]";
        std::string name=icon+" "+e.name; if(name.size()>38U) name=name.substr(0,35U)+"...";
        const std::string type=e.directory?"Folder":"File";
        const std::string size=e.directory?"":format_size(e.size);
        const std::string modified=format_unix_time(e.modified_unix);
        XDrawString(app.display,app.window,app.gc,right_x+10,row_y+17+visual*row_h,name.c_str(),static_cast<int>(name.size()));
        XDrawString(app.display,app.window,app.gc,right_x+8+name_w,row_y+17+visual*row_h,type.c_str(),static_cast<int>(type.size()));
        XDrawString(app.display,app.window,app.gc,right_x+8+name_w+type_w,row_y+17+visual*row_h,size.c_str(),static_cast<int>(size.size()));
        XDrawString(app.display,app.window,app.gc,right_x+8+name_w+type_w+size_w,row_y+17+visual*row_h,modified.c_str(),static_cast<int>(modified.size()));
      }
      draw_button(app,right_x,panel_y+panel_h+10,140,32,"Open / Enter");
      draw_button(app,right_x+150,panel_y+panel_h+10,160,32,"Mark / Unmark");
      draw_button(app,right_x+320,panel_y+panel_h+10,120,32,"Parent");
      body_y=app.height-52;
    } else if (app.explorer_tab == 1) {
      draw_text_field(app,kSidebar+24,140,200,"Host",app.explorer_ssh_fields[0],app.active_explorer_ssh_field==0);
      draw_text_field(app,kSidebar+234,140,75,"Port",app.explorer_ssh_fields[1],app.active_explorer_ssh_field==1);
      draw_text_field(app,kSidebar+319,140,160,"User",app.explorer_ssh_fields[2],app.active_explorer_ssh_field==2);
      draw_text_field(app,kSidebar+489,140,200,"Password (session only)",std::string(app.explorer_ssh_fields[3].size(),'*'),app.active_explorer_ssh_field==3);
      draw_text_field(app,kSidebar+24,192,465,"Remote path",app.explorer_ssh_fields[4],app.active_explorer_ssh_field==4);
      draw_button(app,kSidebar+499,192,100,28,"Probe key");
      draw_checkbox(app,kSidebar+609,199,260,"Trust displayed key this session",app.explorer_ssh_trusted);
      draw_button(app,kSidebar+24,230,110,30,app.explorer_ssh_connected?"Refresh":"Connect");
      draw_button(app,kSidebar+144,230,110,30,"Disconnect");
      const std::string remote_label=ssh_machine_name.empty()?"Remote Files":ssh_machine_name+" (SSH)";
      const int total_w=app.width-kSidebar-54, transfer_w=96, gap=10;
      const int pane_w=(total_w-transfer_w-2*gap)/2;
      const int left_x=kSidebar+24, transfer_x=left_x+pane_w+gap, right_x=transfer_x+transfer_w+gap;
      const int panel_y=282, panel_h=std::max(260,app.height-panel_y-78);
      draw_list_panel(app,left_x,panel_y,pane_w,panel_h,"Local Files: "+app.explorer_current_path.string(),{},"");
      draw_list_panel(app,right_x,panel_y,pane_w,panel_h,remote_label+": "+app.explorer_ssh_fields[4],{},"");
      const int header_h=28,row_h=23;
      XSetForeground(app.display,app.gc,0x252a30UL); XFillRectangle(app.display,app.window,app.gc,left_x+4,panel_y+28,pane_w-8,header_h);
      XFillRectangle(app.display,app.window,app.gc,right_x+4,panel_y+28,pane_w-8,header_h);
      XSetForeground(app.display,app.gc,0xb9d6cfUL);
      const std::string local_header="Name                         Size        Modified";
      const std::string remote_header="Name                         Size        Modified";
      XDrawString(app.display,app.window,app.gc,left_x+8,panel_y+47,local_header.c_str(),static_cast<int>(local_header.size()));
      XDrawString(app.display,app.window,app.gc,right_x+8,panel_y+47,remote_header.c_str(),static_cast<int>(remote_header.size()));
      const int visible=std::max(1,(panel_h-70)/row_h);
      const std::size_t lbegin=std::min(app.explorer_local_scroll,app.explorer_entries.size());
      const std::size_t lend=std::min(app.explorer_entries.size(),lbegin+static_cast<std::size_t>(visible));
      for(std::size_t i=lbegin;i<lend;++i){
        const auto& e=app.explorer_entries[i]; const int visual=static_cast<int>(i-lbegin); const int yy=panel_y+64+visual*row_h;
        if(static_cast<int>(i)==app.explorer_selected){XSetForeground(app.display,app.gc,0x31557dUL);XFillRectangle(app.display,app.window,app.gc,left_x+4,yy-15,pane_w-8,row_h-1);} XSetForeground(app.display,app.gc,0xdce2e8UL);
        std::ostringstream row; row<<std::left<<std::setw(29)<<((e.directory?"[DIR] ":"[FILE] ")+e.name).substr(0,28)<<std::setw(12)<<(e.directory?"":format_size(e.size))<<format_unix_time(e.modified_unix);
        const auto text=row.str();XDrawString(app.display,app.window,app.gc,left_x+8,yy,text.c_str(),static_cast<int>(text.size()));
      }
      std::vector<SftpEntry> entries; { std::lock_guard lock(app.mutex); entries=app.explorer_ssh_entries; }
      const std::size_t rbegin=std::min(app.explorer_ssh_scroll,entries.size());
      const std::size_t rend=std::min(entries.size(),rbegin+static_cast<std::size_t>(visible));
      for(std::size_t i=rbegin;i<rend;++i){
        const auto& e=entries[i]; const int visual=static_cast<int>(i-rbegin); const int yy=panel_y+64+visual*row_h;
        if(static_cast<int>(i)==app.explorer_ssh_selected){XSetForeground(app.display,app.gc,0x31557dUL);XFillRectangle(app.display,app.window,app.gc,right_x+4,yy-15,pane_w-8,row_h-1);} XSetForeground(app.display,app.gc,0xdce2e8UL);
        std::ostringstream row; row<<std::left<<std::setw(29)<<((e.directory?"[DIR] ":"[FILE] ")+e.name).substr(0,28)<<std::setw(12)<<(e.directory?"":format_size(e.size))<<format_unix_time(e.modified_unix);
        const auto text=row.str();XDrawString(app.display,app.window,app.gc,right_x+8,yy,text.c_str(),static_cast<int>(text.size()));
      }
      draw_button(app,transfer_x,panel_y+84,transfer_w,34,"Upload ->");
      draw_button(app,transfer_x,panel_y+128,transfer_w,34,"<- Download");
      draw_button(app,transfer_x,panel_y+190,transfer_w,30,"Local Up");
      draw_button(app,transfer_x,panel_y+228,transfer_w,30,"Remote Up");
      std::string fp=ssh_fingerprint.empty()?"Host key not probed":"SHA-256 "+ssh_fingerprint;
      if(fp.size()>72U) fp=fp.substr(0,69U)+"...";
      XSetForeground(app.display,app.gc,0x9fa8b3UL); XDrawString(app.display,app.window,app.gc,kSidebar+270,251,fp.c_str(),static_cast<int>(fp.size()));
      body_y=app.height-52;
    } else {
      const std::string local_label="Local host (Bash)";
      const std::string ssh_label=ssh_machine_name.empty()?"SSH target":ssh_machine_name+" (SSH)";
      draw_button(app,kSidebar+24,138,180,32,local_label,app.explorer_console_target==0);
      draw_button(app,kSidebar+214,138,210,32,ssh_label,app.explorer_console_target==1);
      draw_text_field(app,kSidebar+24,192,app.width-kSidebar-220,"Command",app.explorer_console_command,app.active_explorer_console_field==0);
      draw_button(app,app.width-176,192,136,28,app.busy?"Running...":"Run Command");
      XSetForeground(app.display,app.gc,0x050607UL);
      XFillRectangle(app.display,app.window,app.gc,kSidebar+24,242,static_cast<unsigned int>(app.width-kSidebar-54),static_cast<unsigned int>(std::max(160,app.height-300)));
      XSetForeground(app.display,app.gc,0x394149UL);
      XDrawRectangle(app.display,app.window,app.gc,kSidebar+24,242,static_cast<unsigned int>(app.width-kSidebar-54),static_cast<unsigned int>(std::max(160,app.height-300)));
      body_y=268;
    }
  }
  if (app.page == Page::environment) {
    static constexpr std::array<const char*,7> names{{"System", "Veeam Products", "Services", "Installed Software", "Network", "TLS / Security", "Storage"}};
    const int available = app.width - kSidebar - 54;
    const int columns = available >= 900 ? 4 : 2;
    const int gap = 10;
    const int card_w = (available - gap * (columns - 1)) / columns;
    for (std::size_t i=0;i<names.size();++i) {
      const int row=static_cast<int>(i)/columns, col=static_cast<int>(i)%columns;
      std::string value;
      { std::lock_guard lock(app.mutex); value=app.environment_card_values[i]; }
      draw_metric_card(app, kSidebar+24+col*(card_w+gap), 138+row*82, card_w, 72, names[i], value);
    }
    const int rows=(static_cast<int>(names.size())+columns-1)/columns;
    body_y=138+rows*82+18;
  }
  if (app.page == Page::gather) {
    draw_button(app, kSidebar+24, 88, 220, 36, app.busy ? "Gathering..." : "Gather Support Bundle");
    draw_button(app, kSidebar+256, 88, 150, 36, "Refresh Detection");
    if (app.busy) draw_button(app, kSidebar+418, 88, 100, 36, "Cancel");
    const int columns = app.width - kSidebar >= 820 ? 2 : 1;
    const int column_width = std::max(300, (app.width - kSidebar - 70) / columns);
    int max_row = 0;
    for (std::size_t index = 0; index < app.gather_products.size(); ++index) {
      const int column = static_cast<int>(index % static_cast<std::size_t>(columns));
      const int row = static_cast<int>(index / static_cast<std::size_t>(columns));
      max_row = std::max(max_row, row);
      std::string label = app.gather_products[index].display_name;
      label += app.gather_product_detected[index] ? " [detected]" : " [not detected]";
      draw_checkbox(app, kSidebar + 24 + column * column_width, 142 + row * 28,
                    column_width - 12, label, app.gather_product_selected[index]);
    }
    const int third_party_y = 142 + (app.gather_products.empty() ? 0 : (max_row + 1) * 28) + 4;
    draw_checkbox(app, kSidebar + 24, third_party_y, app.width - kSidebar - 54,
                  "Include sanitized third-party operational/error logs", app.gather_third_party);
    body_y = third_party_y + 42;
  }
  std::string body, status;
  { std::lock_guard lock(app.mutex); body = app.body; status = app.status; }
  XSetForeground(app.display, app.gc, 0xdce2e8UL);
  draw_text(app.display, app.window, app.gc, kSidebar+24, body_y, body, app.width-kSidebar-54, 18);
  XSetForeground(app.display, app.gc, 0x2c323aUL);
  XFillRectangle(app.display, app.window, app.gc, kSidebar, app.height-34, static_cast<unsigned int>(app.width-kSidebar), 34);
  XSetForeground(app.display, app.gc, 0xb9c0c8UL);
  XDrawString(app.display, app.window, app.gc, kSidebar+18, app.height-12, status.c_str(), static_cast<int>(status.size()));
  XFlush(app.display);
}

bool inside(int x, int y, int bx, int by, int bw, int bh) { return x >= bx && x < bx+bw && y >= by && y < by+bh; }

void start_gather(App& app) {
  if (app.busy.exchange(true)) return;
  app.cancellation = CancellationSource{};
  const auto selected_products = selected_gather_product_ids(app);
  const bool include_third_party = app.gather_third_party;
  const std::vector<std::filesystem::path> marked_paths(app.explorer_marked_paths.begin(), app.explorer_marked_paths.end());
  set_body(app, "Starting universal support collection...", "Gathering support bundle");
  if (app.worker.joinable()) app.worker.join();
  app.worker = std::thread([&app, selected_products, include_third_party, marked_paths]() {
    UniversalCollectionOptions options;
    options.output_root = default_collection_root();
    options.tool_output_directory = portable_tool_output_directory();
    options.include_tool_output_logs = true;
    options.cleanup_tool_output_after_archive = true;
    options.include_third_party_error_logs = include_third_party;
    options.include_platform_context = true;
    options.create_archive = true;
    options.product_selection_explicit = true;
    options.selected_product_ids = selected_products;
    options.additional_sources = marked_paths;
    auto result = collect_universal_support_bundle(
        options, app.cancellation.token(), [&](const ProgressEvent& event) {
          if (!event.current_scope.empty())
            set_body(app, "Working on:\n  " + event.current_scope, event.phase);
        });
    if (result.ok()) {
      std::ostringstream text;
      text << "Universal support collection completed.\n\nCollection:\n  "
           << result.value().logs.collection_directory.string()
           << "\nArchive:\n  "
           << (result.value().logs.archive_path.empty()
                   ? "(archive unavailable)"
                   : result.value().logs.archive_path.string())
           << "\nSelected/detected Veeam products/roles: "
           << result.value().detected_products.size()
           << "\nSanitized third-party error logs: "
           << result.value().third_party_files.size() << "\n";
      for (const auto& warning : result.value().warnings)
        text << "\nWarning: " << warning;
      append_portable_activity(app,"Log Collection",app.cancellation.is_cancelled()?"Cancelled":"Completed",result.value().logs.archive_path.string());
      set_body(app, text.str(),
               app.cancellation.is_cancelled() ? "Collection cancelled" : "Collection complete");
    } else {
      append_portable_activity(app,"Log Collection","Failed",describe_error(result.error()));
      set_body(app, "Collection failed:\n" + describe_error(result.error()), "Collection failed");
    }
    app.busy = false;
    app.dirty = true;
  });
}

std::optional<std::uint16_t> parse_port_field(const std::string& text) {
  try {
    const unsigned long value = std::stoul(text);
    if (value == 0UL || value > 65535UL) return std::nullopt;
    return static_cast<std::uint16_t>(value);
  } catch (...) {
    return std::nullopt;
  }
}

void start_network_operation(App& app, int operation) {
  if (app.busy.exchange(true)) return;
  app.cancellation = CancellationSource{};
  const auto fields = app.network_fields;
  const bool all_interfaces = app.network_all_interfaces;
  const bool sat_payload = app.network_sat_payload;
  const bool compare_tls = app.network_tls_compare;
  const auto port = parse_port_field(fields[1]);
  if (!port.has_value()) {
    app.busy = false;
    set_body(app, "Port must be a number from 1 through 65535.", "Invalid port");
    return;
  }
  if (app.worker.joinable()) app.worker.join();
  set_body(app, "Starting network diagnostic...", "Running");
  app.worker = std::thread([&app, fields, all_interfaces, sat_payload, compare_tls, port, operation]() {
    const auto progress = [&app](const ProgressEvent& event) {
      if (!event.current_scope.empty()) set_body(app, "Working on:\n  " + event.current_scope, event.phase);
    };
    std::ostringstream out;
    std::string title = "Network Diagnostic";
    bool ok = true;
    if (operation == 0) {
      title = "Network Interfaces";
      auto interfaces = enumerate_network_interfaces();
      if (!interfaces.ok()) { out << describe_error(interfaces.error()); ok = false; }
      else {
        out << "Usable local interfaces\n\n";
        for (const auto& item : interfaces.value()) {
          out << item.name << " | " << item.address << "/" << item.prefix_length
              << " | " << item.address_family << " | " << (item.up ? "UP" : "DOWN");
          if (item.vlan_interface) out << " | VLAN";
          if (item.team_or_bond) out << " | TEAM/BOND";
          if (item.virtual_interface) out << " | VIRTUAL";
          if (item.loopback) out << " | LOOPBACK";
          if (!item.gateway.empty()) out << " | gateway " << item.gateway;
          if (!item.members.empty()) {
            out << " | members ";
            for (std::size_t i=0;i<item.members.size();++i) { if (i) out << ','; out << item.members[i]; }
          }
          out << "\n";
        }
      }
    } else if (operation == 1 || operation == 6) {
      title = operation == 6 ? "Managed Server Connectivity" : "TCP Connectivity Test";
      TcpPortTestOptions options;
      options.host = fields[0]; options.port = *port; options.source_address = fields[2];
      options.sat_payload_bytes = sat_payload ? 50ULL*1024ULL*1024ULL : 0ULL;
      if (all_interfaces) {
        auto matrix = test_tcp_across_interfaces(options, app.cancellation.token(), progress, false);
        if (!matrix.ok()) { out << describe_error(matrix.error()); ok = false; }
        else for (const auto& item : matrix.value()) {
          out << item.interface.name << " [" << item.interface.address << "]\n";
          for (const auto& a : item.test.attempts)
            out << "  " << a.address << " | " << (a.connected?"CONNECTED":"FAILED") << " | " << a.message
                << (a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id)
                << (a.sat_payload_validated?" | 50 MiB payload VERIFIED":"") << "\n";
        }
      } else {
        auto result = test_tcp_port(options, app.cancellation.token(), progress);
        if (!result.ok()) { out << describe_error(result.error()); ok = false; }
        else for (const auto& a : result.value().attempts)
          out << a.address << " | " << (a.connected?"CONNECTED":"FAILED") << " | " << a.message
              << (a.local_address.empty()?"":" | source "+a.local_address)
              << (a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id)
              << (a.sat_payload_validated?" | payload VERIFIED":"") << "\n";
      }
    } else if (operation == 2) {
      title = "TCP Listener";
      TcpListenerOptions options; options.port=*port; options.duration=std::chrono::seconds(30); options.accept_multiple=true;
      auto result = listen_tcp(options, app.cancellation.token(), progress);
      if (!result.ok()) { out << describe_error(result.error()); ok=false; }
      else {
        out << "TCP listener port " << result.value().port << "\n";
        for (const auto& c : result.value().connections)
          out << c.remote_address << ':' << c.remote_port << " -> " << c.local_address << ':' << c.local_port
              << (c.sat_test_id.empty()?"":" | Test ID "+c.sat_test_id)
              << (c.sat_payload_validated?" | payload VERIFIED":"") << "\n";
        if (result.value().cancelled) out << "Cancelled\n";
        else if (result.value().timed_out) out << "Listener duration completed\n";
      }
    } else if (operation == 3) {
      title = "UDP Connectivity Test";
      UdpPortTestOptions options; options.host=fields[0]; options.port=*port; options.source_address=fields[2]; options.mode=UdpProbeMode::sat_listener;
      if (all_interfaces) {
        auto matrix = test_udp_across_interfaces(options, app.cancellation.token(), progress, false);
        if (!matrix.ok()) { out << describe_error(matrix.error()); ok=false; }
        else for (const auto& item : matrix.value()) {
          out << item.interface.name << " [" << item.interface.address << "]\n";
          for (const auto& a : item.test.attempts)
            out << "  " << a.address << " | " << (a.sat_acknowledged?"VERIFIED":"NO ACK / INDETERMINATE")
                << " | " << a.message << (a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id) << "\n";
        }
      } else {
        auto result = test_udp_port(options, app.cancellation.token(), progress);
        if (!result.ok()) { out << describe_error(result.error()); ok=false; }
        else for (const auto& a : result.value().attempts)
          out << a.address << " | " << (a.sat_acknowledged?"VERIFIED":"NO ACK / INDETERMINATE")
              << " | " << a.message << (a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id) << "\n";
      }
    } else if (operation == 4) {
      title = "UDP Listener";
      UdpListenerOptions options; options.port=*port; options.duration=std::chrono::seconds(30);
      auto result = listen_udp(options, app.cancellation.token(), progress);
      if (!result.ok()) { out << describe_error(result.error()); ok=false; }
      else {
        out << "UDP listener port " << result.value().port << "\n";
        for (const auto& d : result.value().datagrams)
          out << d.remote_address << ':' << d.remote_port << " -> " << d.local_address << ':' << d.local_port
              << " | bytes " << d.bytes << (d.sat_test_id.empty()?"":" | Test ID "+d.sat_test_id)
              << (d.sat_ack_sent?" | ACK sent":"") << "\n";
      }
    } else if (operation == 8 || operation == 9) {
      title = operation == 8 ? "Network Throughput Client" : "Network Throughput Server";
      TcpThroughputOptions options;
      options.server = operation == 9;
      options.host = fields[0];
      options.port = *port;
      options.transfer_bytes = 1024ULL * 1024ULL * 1024ULL;
      auto result = run_tcp_throughput(options, app.cancellation.token(), progress);
      if (!result.ok()) {
        out << describe_error(result.error());
        ok = false;
      } else {
        const auto& value = result.value();
        out << (value.server ? "SERVER" : "CLIENT") << " | peer " << value.peer_address
            << " | port " << value.port << " | bytes " << value.transferred_bytes
            << " | " << format_transfer_rate(value.bits_per_second)
            << " | protocol " << (value.protocol_verified ? "VERIFIED" : "UNVERIFIED") << "\n";
        if (value.cancelled) out << "Cancelled\n";
      }
    } else if (operation == 5 || operation == 7) {
      title = operation == 7 ? "Veeam Secure Channel Test" : "TLS Handshake Test";
      const auto write_tls_result = [&](std::string_view label, const TlsProbeResult& v,
                                        std::string_view interface_label) {
        out << label;
        if (!interface_label.empty()) out << " | " << interface_label;
        out << " | " << (v.handshake_completed?"HANDSHAKE COMPLETE":"HANDSHAKE FINDING")
            << " | " << v.local_address << " -> " << v.connected_address
            << " | " << v.negotiated_version << " | " << v.negotiated_cipher_suite << "\n"
            << "  cert subject: " << v.certificate.subject << "\n"
            << "  cert issuer: " << v.certificate.issuer << "\n"
            << "  SHA-256: " << v.certificate.sha256_fingerprint << "\n";
        if (v.certificate.expected_fingerprint_provided)
          out << "  expected identity: " << (v.certificate.expected_fingerprint_matches?"VERIFIED":"MISMATCH") << "\n";
        else out << "  expected identity: OBSERVED ONLY\n";
        if (!v.handshake_completed) out << "  failure: " << v.failure_stage << " | " << v.failure_reason << "\n";
        if (v.server_requested_client_certificate) out << "  server requested client certificate\n";
      };
      const auto run_tls = [&](TlsProbeVersion version, std::string_view label) {
        TlsProbeOptions options; options.host=fields[0]; options.port=*port; options.source_address=fields[2];
        options.server_name=fields[3]; options.expected_fingerprint=fields[4]; options.version=version;
        if (all_interfaces) {
          auto matrix=test_tls_across_interfaces(options,app.cancellation.token(),progress,false);
          if (!matrix.ok()) { out << label << " | " << describe_error(matrix.error()) << "\n"; ok=false; return; }
          for (const auto& item : matrix.value())
            write_tls_result(label,item.test,item.interface.name+" ["+item.interface.address+"]");
          return;
        }
        auto result=test_tls_handshake(options,app.cancellation.token(),progress);
        if (!result.ok()) { out << label << " | " << describe_error(result.error()) << "\n"; ok=false; return; }
        write_tls_result(label,result.value(),{});
      };
      if (compare_tls) { run_tls(TlsProbeVersion::tls12_only,"TLS 1.2 only"); run_tls(TlsProbeVersion::tls13_only,"TLS 1.3 only"); }
      else run_tls(TlsProbeVersion::automatic,"TLS automatic");
      out << "\nCurrent Veeam cipher/protocol reference:\n  https://helpcenter.veeam.com/docs/vbr/userguide/cipher_suites_protocols.html?ver=13\n"
          << "Refer to the current Veeam guide for cipher and protocol interpretation.\n";
    }
    const std::string text=out.str();
    write_portable_tool_output(title,text);
    append_portable_activity(app,title,app.cancellation.is_cancelled()?"Cancelled":(ok?"Completed":"Completed with finding/error"),"Linux execution host diagnostic");
    set_body(app,text,app.cancellation.is_cancelled()?"Cancellation requested":(ok?"Completed":"Completed with finding/error"));
    app.busy=false; app.dirty=true;
  });
}

std::vector<std::filesystem::path> review_sources_from_field(const std::string& value) {
  std::vector<std::filesystem::path> sources;
  std::size_t start = 0;
  while (start <= value.size()) {
    const auto end = value.find(';', start);
    std::string item = value.substr(start, end == std::string::npos ? std::string::npos : end - start);
    const auto first = item.find_first_not_of(" \t\r\n");
    const auto last = item.find_last_not_of(" \t\r\n");
    if (first != std::string::npos)
      sources.emplace_back(item.substr(first, last - first + 1U));
    if (end == std::string::npos) break;
    start = end + 1U;
  }
  return sources;
}

void start_log_review(App& app, bool use_detected_local_sources) {
  if (app.busy.exchange(true)) return;
  app.cancellation = CancellationSource{};
  std::vector<std::filesystem::path> sources = use_detected_local_sources
      ? detected_local_log_sources()
      : review_sources_from_field(app.review_fields[0]);
  if (sources.empty()) {
    app.busy = false;
    set_body(app,
             use_detected_local_sources
                 ? "No local Veeam product log roots were detected on this host. Enter a bundle, file or directory manually."
                 : "Enter a log bundle, file or directory before starting Log Review.",
             "No review source");
    return;
  }
  const std::string case_root = app.review_fields[1].empty()
                                    ? app.active_case_root
                                    : app.review_fields[1];
  const bool full_scan = app.review_full_scan;
  if (app.worker.joinable()) app.worker.join();
  set_body(app, "Starting Unified Veeam Log Review...", full_scan ? "Running Full Review" : "Running Fast Index");
  app.worker = std::thread([&app, sources = std::move(sources), case_root, full_scan]() {
    VeeamLogReviewOptions options;
    options.sources = sources;
    options.profile = VeeamReviewProfile::automatic;
    options.fast_index_first = !full_scan;
    std::optional<CaseWorkspace> workspace;
    if (!case_root.empty()) {
      auto opened = open_case_workspace(case_root);
      if (!opened.ok()) {
        set_body(app, "Could not open case:\n" + describe_error(opened.error()), "Case open failed");
        app.busy = false;
        app.dirty = true;
        return;
      }
      workspace = opened.value();
      options.output_path = workspace->parsed / "reports";
      options.parser_cache_directory = workspace->parser_cache;
    } else {
      options.output_path = default_collection_root() / "Review-Reports";
    }
    auto review = review_veeam_logs(options, app.cancellation.token(), [&](const ProgressEvent& event) {
      std::ostringstream text;
      text << (full_scan ? "Full Review" : "Fast Index") << "\n\n";
      if (!event.current_scope.empty()) text << "Working on:\n  " << event.current_scope << "\n";
      text << "Processed: " << event.processed << " | Errors: " << event.errors;
      if (event.items_per_second > 0.0) text << " | " << std::fixed << std::setprecision(1) << event.items_per_second << " items/s";
      text << "\n";
      set_body(app, text.str(), event.phase.empty() ? "Reviewing logs" : event.phase);
    });
    if (!review.ok()) {
      set_body(app, "Log Review failed:\n" + describe_error(review.error()), "Review failed");
      app.busy = false;
      app.dirty = true;
      return;
    }
    std::string summary = format_portable_review_summary(review.value());
    if (workspace) {
      const auto model_saved = save_case_review_model(*workspace, review.value());
      CaseReviewState state;
      state.profile = to_string(review.value().profile_used);
      state.fast_index = review.value().fast_index_used;
      state.updated_utc = utc_now_iso8601();
      for (const auto& source : review.value().input_sources) state.sources.push_back(source.string());
      for (const auto& bundle : review.value().bundles) {
        CaseReviewSource source;
        source.path = bundle.source_path;
        source.requested_profile = "automatic";
        source.detected_profile = bundle.manifest_profile;
        source.product_type = bundle.product_type;
        source.product_version = bundle.product_version;
        source.source_owner = bundle.primary_machine_name;
        state.source_profiles.push_back(std::move(source));
      }
      const auto state_saved = save_case_review_state(*workspace, std::move(state));
      summary += "\nCase persistence\n  Review model: ";
      summary += model_saved.ok() ? "saved" : "FAILED: " + describe_error(model_saved.error());
      summary += "\n  Review state: ";
      summary += state_saved.ok() ? "saved" : "FAILED: " + describe_error(state_saved.error());
      summary += "\n  Case: " + workspace->root.string() + "\n";
    } else {
      summary += "\nReview context: No Case (quick review; case state was not persisted).\n";
    }
    write_portable_tool_output("Unified-Log-Review", summary);
    append_portable_activity(app,"Unified Log Review",app.cancellation.is_cancelled()?"Cancelled":"Completed",case_root.empty()?"No Case":case_root);
    // Case Dashboard refreshes when opened; worker threads do not mutate dashboard/UI model state.
    set_body(app, summary, app.cancellation.is_cancelled() ? "Review cancelled" : "Review complete");
    app.busy = false;
    app.dirty = true;
  });
}



void start_portable_sql_operation(App& app, bool run_diagnostic) {
  if (app.busy.exchange(true)) return;
  const auto fields = app.sql_fields;
  const bool trusted = app.sql_trusted_connection;
  const bool include_db = app.sql_include_database_permissions;
  if (fields[2].empty()) {
    app.busy = false;
    set_body(app, "SQL Tools requires a principal name.", "Principal required");
    return;
  }
  if (run_diagnostic && fields[0].empty()) {
    app.busy = false;
    set_body(app, "Run Permission Diagnostic requires a SQL Server / instance.", "Server required");
    return;
  }
  if (app.worker.joinable()) app.worker.join();
  app.cancellation = CancellationSource{};
  app.worker = std::thread([&app, fields, trusted, include_db, run_diagnostic] {
    SqlPermissionOptions options;
    options.server = fields[0];
    options.database = fields[1].empty() ? "master" : fields[1];
    options.principal = fields[2];
    options.trusted_connection = trusted;
    options.include_database_permissions = include_db;
    options.connection_string = fields[3];
    if (!fields[4].empty()) options.output_file = fields[4];
    if (!run_diagnostic) {
      auto written = write_sql_permission_script(options);
      if (!written.ok()) {
        set_body(app, "SQL permission script failed: " + describe_error(written.error()), "SQL Tools failed");
      } else {
        const std::string text = "SQL permission diagnostic script created:\n" + written.value().string();
        write_portable_tool_output("SQL-Permission-Script", text);
        append_portable_activity(app, "SQL Tools", "Permission script created", written.value().string());
        set_body(app, text, "SQL script created");
      }
      app.busy = false;
      app.dirty = true;
      return;
    }
    auto result = run_sql_permission_diagnostic(options, app.cancellation.token(),
      [&app](const ProgressEvent& event) {
        set_body(app, event.current_scope.empty() ? event.phase : event.phase + "\n" + event.current_scope,
                 "SQL Tools: running");
      });
    if (!result.ok()) {
      set_body(app, "SQL permission diagnostic failed:\n" + describe_error(result.error()), "SQL Tools failed");
      append_portable_activity(app, "SQL Tools", "Failed", result.error().message);
    } else {
      std::ostringstream output;
      output << result.value().output;
      if (!result.value().standard_error.empty()) output << "\nSTDERR:\n" << result.value().standard_error;
      const std::string text = output.str();
      write_portable_tool_output("SQL-Permission-Diagnostic", text);
      append_portable_activity(app, "SQL Tools", result.value().exit_code == 0 ? "Completed" : "Completed with finding/error", "Permission diagnostic");
      set_body(app, text, result.value().exit_code == 0 ? "SQL diagnostic complete" : "SQL diagnostic returned findings");
    }
    app.busy = false;
    app.dirty = true;
  });
}

void show_portable_case_note(App& app) {
  const auto* workspace = app.case_catalog.active();
  if (workspace == nullptr) {
    set_body(app, "Select an active case before opening Note Review.", "No active case");
    return;
  }
  auto review = load_case_review_model(*workspace);
  if (!review.ok()) {
    set_body(app, "The active case does not contain a saved structured review yet.", "No saved review");
    return;
  }
  std::string note = build_veeam_ticket_note(review.value(), {}, {}, "Review selected case evidence and findings");
  auto bookmarks = load_case_evidence_bookmarks(*workspace);
  if (bookmarks.ok()) {
    note += "\nSelected Evidence:\n";
    std::size_t shown = 0;
    for (const auto& item : bookmarks.value()) {
      if (!item.include_in_note) continue;
      note += "- " + (item.title.empty() ? item.scope_key : item.title) + " | " + item.source_path + "\n";
      if (++shown >= 40U) { note += "- ... additional selected evidence retained in case\n"; break; }
    }
  }
  set_body(app, std::move(note), "Case Note Review");
}

void write_portable_case_pdf(App& app) {
  const auto* workspace = app.case_catalog.active();
  if (workspace == nullptr) {
    set_body(app, "Select an active case before creating a PDF report.", "No active case");
    return;
  }
  refresh_case_dashboard(app);
  PdfReportDocument document;
  document.title = "Support Assist Tool Case Report";
  document.subtitle = workspace->case_id + (workspace->title.empty() ? std::string{} : ": " + workspace->title);
  PdfReportSection summary;
  summary.heading = "Case Summary";
  summary.lines = {
      "Engineer: " + workspace->engineer,
      "Review state: " + app.case_dashboard.review_state,
      "Systems/components: " + std::to_string(app.case_dashboard.machines),
      "Runs: " + std::to_string(app.case_dashboard.runs),
      "Findings: " + std::to_string(app.case_dashboard.errors) + " errors / " + std::to_string(app.case_dashboard.warnings) + " warnings",
      "Bookmarks: " + std::to_string(app.case_dashboard.bookmarks),
      "#note selections: " + std::to_string(app.case_dashboard.note_selections)};
  document.sections.push_back(std::move(summary));
  if (!app.case_dashboard.machine_rows.empty()) document.sections.push_back({"Systems / Components", app.case_dashboard.machine_rows});
  if (!app.case_dashboard.run_rows.empty()) document.sections.push_back({"Recent Jobs / Activities / Runs", app.case_dashboard.run_rows});
  if (!app.case_dashboard.finding_rows.empty()) document.sections.push_back({"Errors / Warnings", app.case_dashboard.finding_rows});
  const auto output = workspace->reports / (workspace->case_id + "-case-report.pdf");
  auto status = write_pdf_report(output, document);
  if (!status.ok()) set_body(app, "PDF report failed: " + describe_error(status.error()), "PDF failed");
  else set_body(app, "Case PDF created:\n" + output.string(), "PDF report created");
}

void delete_portable_active_case(App& app) {
  const auto* active = app.case_catalog.active();
  if (active == nullptr) {
    set_body(app, "Select an active case before deleting a workspace.", "No active case");
    return;
  }
  if (!app.delete_case_armed) {
    app.delete_case_armed = true;
    set_body(app,
             "Delete is armed for case " + active->case_id +
                 ".\n\nClick Confirm Delete on the Case Dashboard to permanently remove the case "
                 "workspace and its evidence. Any other navigation/action cancels the confirmation.",
             "Delete confirmation required");
    return;
  }
  const auto root = active->root;
  std::error_code error;
  std::filesystem::remove_all(root, error);
  if (error) {
    app.delete_case_armed = false;
    set_body(app, "Could not delete case workspace:\n" + error.message(), "Delete failed");
    return;
  }
  app.case_catalog.cases.erase(app.case_catalog.cases.begin() + app.case_catalog.active_index);
  app.case_catalog.active_index = -1;
  save_portable_case_catalog(app.case_catalog, portable_state_directory());
  sync_active_case_root(app);
  refresh_case_dashboard(app);
  app.delete_case_armed = false;
  set_body(app, "Case workspace deleted: " + root.string(), "Case deleted");
}

void create_or_open_case(App& app, bool create_new) {
  if (app.busy) return;
  if (app.case_fields[0].empty()) {
    set_body(app, "Enter a parent directory for Create Case, or an existing case root for Open Existing.", "Case path required");
    return;
  }
  if (create_new) {
    if (app.case_fields[1].empty()) {
      set_body(app, "Case ID is required when creating a new case.", "Case ID required");
      return;
    }
    CaseWorkspaceOptions options;
    options.parent_directory = app.case_fields[0];
    options.case_id = app.case_fields[1];
    options.title = app.case_fields[2];
    options.engineer = app.case_fields[3];
    auto created = create_case_workspace(options);
    if (!created.ok()) {
      set_body(app, "Case creation failed:\n" + describe_error(created.error()), "Case creation failed");
      return;
    }
    register_portable_case(app.case_catalog, std::move(created.value()), portable_state_directory());
  } else {
    auto opened = open_case_workspace(app.case_fields[0]);
    if (!opened.ok()) {
      set_body(app, "Could not open case:\n" + describe_error(opened.error()), "Case open failed");
      return;
    }
    register_portable_case(app.case_catalog, std::move(opened.value()), portable_state_directory());
  }
  sync_active_case_root(app);
  set_body(app, case_text(app), create_new ? "Case created and activated" : "Case opened and activated");
}

void click(App& app, int x, int y, unsigned int button = Button1) {
  int nav_y = 82;
  for (const auto& item : navigation_items(app)) {
    if (item.section) { nav_y += 22; continue; }
    const int height = item.child ? 24 : 30;
    const int bx = item.child ? 26 : 16;
    const int bw = item.child ? 188 : 198;
    if (inside(x,y,bx,nav_y,bw,height)) { app.page=item.page; update_page(app); app.dirty=true; return; }
    nav_y += height + 3;
  }
  const int role_x = std::max(kSidebar + 660, app.width - 174);
  const int case_x = std::max(kSidebar + 330, role_x - 312);
  if (inside(x, y, case_x, 19, 300, 34)) {
    app.case_selector_open = !app.case_selector_open;
    app.dirty = true;
    return;
  }
  if (app.case_selector_open) {
    const int row_h = 30;
    const int rows = std::min(9, static_cast<int>(app.case_catalog.cases.size()) + 1);
    if (inside(x, y, case_x, 55, 300, rows * row_h + 4)) {
      const int row = std::clamp((y - 57) / row_h, 0, rows - 1);
      activate_portable_case(app, row == 0 ? -1 : row - 1);
      app.case_selector_open = false;
      append_portable_activity(app, "Case", row == 0 ? "No Case selected" : "Activated", app.active_case_root);
      update_page(app);
      app.dirty = true;
      return;
    }
    app.case_selector_open = false;
  }
  if (inside(x,y,role_x,19,150,34)) {
    app.execution_host_enabled = !app.execution_host_enabled;
    append_portable_activity(app,"Workspace Role",app.execution_host_enabled?"Customer / Lab enabled":"Engineer Review enabled","Session-only role change");
    if (!app.execution_host_enabled &&
        (app.page == Page::tools || app.page == Page::network_tools ||
         app.page == Page::sql_tools || app.page == Page::vss_tools ||
         app.page == Page::registry_tools || app.page == Page::filesystem_tools ||
         app.page == Page::wmi_tools || app.page == Page::vbr_tools || app.page == Page::host_tools ||
         app.page == Page::guided || app.page == Page::gather ||
         app.page == Page::third_party || app.page == Page::diagnostics)) {
      app.page = Page::home;
    }
    update_page(app); app.dirty=true; return;
  }
  if (app.page == Page::home) {
    if (inside(x, y, kSidebar + 24, 266, 245, 34)) {
      app.execution_host_enabled = !app.execution_host_enabled;
      append_portable_activity(
          app, "Workspace Role",
          app.execution_host_enabled ? "Customer / Lab enabled" : "Engineer Review enabled",
          "Session-only role change");
      update_page(app);
      app.dirty = true;
      return;
    }
    if (inside(x,y,kSidebar+279,266,170,34)) { app.page=Page::case_workspace; update_page(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+459,266,150,34)) { app.page=Page::log_review; update_page(app); app.dirty=true; return; }
  }
  if (app.page == Page::health && inside(x,y,kSidebar+24,88,170,36)) { update_page(app,true); return; }
  if (app.page == Page::environment && inside(x,y,kSidebar+24,88,210,36)) {
    if (app.environment_busy) {
      app.cancellation.cancel();
      set_body(app, "Cancelling Environment Review after the current read-only query...", "Cancellation requested");
    } else if (app.busy) {
      set_body(app, "Another Support Assist Tool operation is currently active. Finish or cancel it before refreshing Environment Review.", "SAT is busy");
    } else {
      start_environment_refresh(app);
    }
    return;
  }
  if (app.page == Page::log_review) {
    const std::array<std::pair<int,int>,2> fields{{{kSidebar+24,112},{kSidebar+24,166}}};
    for (std::size_t i=0;i<fields.size();++i) {
      if (inside(x,y,fields[i].first,fields[i].second,610,28)) { app.active_review_field=static_cast<int>(i); app.dirty=true; return; }
    }
    if (inside(x,y,kSidebar+654,172,210,22)) { app.review_full_scan=!app.review_full_scan; app.dirty=true; return; }
    if (app.busy && inside(x,y,kSidebar+534,210,90,34)) { app.cancellation.cancel(); set_body(app,"Cancelling Log Review...","Cancellation requested"); return; }
    if (!app.busy && inside(x,y,kSidebar+24,210,150,34)) { start_log_review(app,false); return; }
    if (!app.busy && inside(x,y,kSidebar+184,210,190,34)) { start_log_review(app,true); return; }
    if (!app.busy && inside(x,y,kSidebar+384,210,140,34)) { app.review_fields[1]=app.active_case_root; update_page(app); app.dirty=true; return; }
  }
  if (app.page == Page::case_workspace) {
    const std::array<std::pair<int,int>,4> fields{{{kSidebar+24,104},{kSidebar+450,104},{kSidebar+24,154},{kSidebar+450,154}}};
    const std::array<int,4> widths{{410,170,410,240}};
    for (std::size_t i=0;i<fields.size();++i) {
      if (inside(x,y,fields[i].first,fields[i].second,widths[i],28)) { app.active_case_field=static_cast<int>(i); app.dirty=true; return; }
    }
    if (inside(x,y,kSidebar+704,104,120,30)) { create_or_open_case(app,true); refresh_case_dashboard(app); append_portable_activity(app,"Case","Created / activated",app.active_case_root); app.dirty=true; return; }
    if (inside(x,y,kSidebar+704,142,120,30)) { create_or_open_case(app,false); refresh_case_dashboard(app); append_portable_activity(app,"Case","Opened / activated",app.active_case_root); app.dirty=true; return; }
    if (inside(x, y, kSidebar + 834, 104, 110, 30)) {
      set_portable_active_case(app.case_catalog, -1, portable_state_directory());
      sync_active_case_root(app);
      refresh_case_dashboard(app);
      set_body(app, case_text(app), "No Case active");
      append_portable_activity(app, "Case", "No Case selected", "");
      app.dirty = true;
      return;
    }
    if (inside(x,y,kSidebar+834,142,110,30)) { app.delete_case_armed=false; refresh_case_dashboard(app); set_body(app,case_text(app),"Case Dashboard refreshed"); app.dirty=true; return; }
    if (inside(x,y,kSidebar+24,190,145,30)) {
      app.delete_case_armed=false;
      const auto* workspace=app.case_catalog.active();
      if(workspace==nullptr) set_body(app,"Select an active case first.","No active case");
      else {
        auto review = load_case_review_model(*workspace);
        if (!review.ok())
          set_body(app, "No saved structured review is available in the active case.", "No saved review");
        else
          set_body(app, format_portable_review_summary(review.value()), "Saved review loaded");
      }
      app.dirty=true; return;
    }
    if (inside(x,y,kSidebar+177,190,145,30)) { app.delete_case_armed=false; app.page=Page::log_review; app.review_fields[1]=app.active_case_root; update_page(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+330,190,125,30)) { app.delete_case_armed=false; show_portable_case_note(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+463,190,125,30)) { app.delete_case_armed=false; write_portable_case_pdf(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+596,190,135,30)) { delete_portable_active_case(app); app.dirty=true; return; }
  }
  if (app.page == Page::network_tools) {
    if (inside(x,y,kSidebar+24,90,155,32)) { app.network_tool_view=0; app.dirty=true; return; }
    if (inside(x,y,kSidebar+187,90,135,32)) { app.network_tool_view=1; app.dirty=true; return; }
    if (inside(x,y,kSidebar+330,90,155,32)) { app.network_tool_view=2; app.dirty=true; return; }
    if (inside(x,y,kSidebar+493,90,155,32)) { app.network_tool_view=3; app.dirty=true; return; }
    const std::array<std::pair<int,int>,5> fields{{{kSidebar+24,142},{kSidebar+290,142},{kSidebar+406,142},{kSidebar+622,142},{kSidebar+24,196}}};
    const std::array<int,5> widths{{250,100,200,240,420}};
    for (std::size_t i=0;i<fields.size();++i) {
      if (inside(x,y,fields[i].first,fields[i].second,widths[i],28)) { app.active_network_field=static_cast<int>(i); app.dirty=true; return; }
    }
    if (inside(x,y,kSidebar+462,202,220,22)) { app.network_all_interfaces=!app.network_all_interfaces; app.dirty=true; return; }
    if (app.network_tool_view==0 && inside(x,y,kSidebar+690,202,220,22)) { app.network_sat_payload=!app.network_sat_payload; app.dirty=true; return; }
    if (app.network_tool_view==2 && inside(x,y,kSidebar+690,202,180,22)) { app.network_tls_compare=!app.network_tls_compare; app.dirty=true; return; }
    if (app.busy && inside(x,y,kSidebar+840,240,90,34)) { app.cancellation.cancel(); set_body(app,"Cancelling current network diagnostic...","Cancellation requested"); return; }
    if (!app.busy) {
      if (app.network_tool_view==0) {
        if (inside(x,y,kSidebar+24,240,130,34)) { start_network_operation(app,0); return; }
        if (inside(x,y,kSidebar+164,240,130,34)) { start_network_operation(app,1); return; }
        if (inside(x,y,kSidebar+304,240,130,34)) { start_network_operation(app,3); return; }
      } else if (app.network_tool_view==1) {
        if (inside(x,y,kSidebar+24,240,150,34)) { start_network_operation(app,2); return; }
        if (inside(x,y,kSidebar+184,240,150,34)) { start_network_operation(app,4); return; }
      } else if (app.network_tool_view==2) {
        if (inside(x,y,kSidebar+24,240,150,34)) { start_network_operation(app,5); return; }
      } else {
        if (inside(x,y,kSidebar+24,240,190,34)) { start_network_operation(app,8); return; }
        if (inside(x,y,kSidebar+224,240,190,34)) { start_network_operation(app,9); return; }
      }
    }
  }
  if (app.page == Page::sql_tools) {
    const std::array<std::pair<int,int>,5> fields{{{kSidebar+24,112},{kSidebar+340,112},{kSidebar+536,112},{kSidebar+24,166},{kSidebar+540,166}}};
    const std::array<int,5> widths{{300,180,300,500,340}};
    for(std::size_t i=0;i<fields.size();++i) if(inside(x,y,fields[i].first,fields[i].second,widths[i],28)){ app.active_sql_field=static_cast<int>(i); app.dirty=true; return; }
    if(inside(x,y,kSidebar+24,210,220,22)){app.sql_trusted_connection=!app.sql_trusted_connection;app.dirty=true;return;}
    if(inside(x,y,kSidebar+254,210,260,22)){app.sql_include_database_permissions=!app.sql_include_database_permissions;app.dirty=true;return;}
    if(!app.busy && inside(x,y,kSidebar+24,244,210,34)){start_portable_sql_operation(app,false);return;}
    if(!app.busy && inside(x,y,kSidebar+244,244,220,34)){start_portable_sql_operation(app,true);return;}
    if(app.busy && inside(x,y,kSidebar+474,244,90,34)){app.cancellation.cancel();set_body(app,"Cancelling SQL diagnostic...","Cancellation requested");return;}
  }
  if (app.page == Page::filesystem_tools) {
    const std::array<std::pair<int,int>,4> fields{{{kSidebar+24,112},{kSidebar+460,112},{kSidebar+24,166},{kSidebar+460,166}}};
    const std::array<int,4> widths{{420,420,420,420}};
    for (std::size_t i=0;i<fields.size();++i) {
      if (inside(x,y,fields[i].first,fields[i].second,widths[i],28)) { app.active_filesystem_field=static_cast<int>(i); app.dirty=true; return; }
    }
    if (inside(x,y,kSidebar+24,210,250,22) && !app.busy) { app.filesystem_hash_sha256=!app.filesystem_hash_sha256; app.dirty=true; return; }
    if (app.busy && inside(x,y,kSidebar+664,202,90,34)) { app.cancellation.cancel(); set_body(app,"Cancelling filesystem operation...","Cancellation requested"); return; }
    if (!app.busy && inside(x,y,kSidebar+290,202,170,34)) { start_filesystem_operation(app,false); return; }
    if (!app.busy && inside(x,y,kSidebar+472,202,180,34)) { start_filesystem_operation(app,true); return; }
  }
  if (app.page == Page::guided) {
    const auto available=available_guided_diagnostics(native_product_discovery_context());
    int row_y=96;
    for(const auto& item:available){
      if(inside(x,y,kSidebar+24,row_y,320,34)){
        if (item.id == "managed-server-connectivity") {
          app.page = Page::network_tools;
          app.network_tool_view = 0;
          set_body(app,
                   "Managed Server Connectivity uses the portable TCP/interface diagnostic. Enter the "
                   "target managed host and Veeam service port, then run TCP Test. Per KB2065 the "
                   "first port to check is 6160, the Veeam Installer Service.",
                   "Guided Diagnostic");
          app.dirty = true;
          return;
        }
        if (item.id == "veeam-secure-channel") {
          app.page = Page::network_tools;
          app.network_tool_view = 2;
          set_body(app,
                   "Veeam Secure Channel uses the portable TLS diagnostic. Enter the target/FQDN, port "
                   "and optional expected certificate fingerprint, then run TLS Test.",
                   "Guided Diagnostic");
          app.dirty = true;
          return;
        }
        set_body(app,
                 item.display_name +
                     " is documented for this platform/role but does not yet require a separate execution "
                     "form.\n\n" +
                     item.description + "\nReference: " + item.reference_url,
                 "Guided Diagnostic information");
        app.dirty = true;
        return;
      }
      row_y+=44;if(row_y>360)break;
    }
  }
  if (app.page == Page::tools) {
    const auto capabilities=linux_capability_catalog(ssh_available(), portable_native_odbc_available());
    const int available=app.width-kSidebar-54;
    const int columns=available>=900?3:2;
    const int gap=10;
    const int card_w=(available-gap*(columns-1))/columns;
    for(std::size_t i=0;i<capabilities.size();++i){
      const int row=static_cast<int>(i)/columns,col=static_cast<int>(i)%columns;
      if(!inside(x,y,kSidebar+24+col*(card_w+gap),96+row*82,card_w,72)) continue;
      const auto& c=capabilities[i];
      if(c.state!=PortableCapabilityState::available){ set_body(app,c.name+": "+capability_state_label(c.state)+"\n\n"+c.detail,"Capability information"); app.dirty=true; return; }
      if(c.id=="host") app.page=Page::host_tools;
      else if(c.id=="guided") app.page=Page::guided;
      else if(c.id=="collection") app.page=Page::gather;
      else if(c.id=="network") app.page=Page::network_tools;
      else if(c.id=="sql") app.page=Page::sql_tools;
      else if(c.id=="filesystem") app.page=Page::filesystem_tools;
      else if(c.id=="ssh") { app.page=Page::explorer; app.explorer_tab=1; }
      else return;
      update_page(app); app.dirty=true; return;
    }
  }
  if (app.page == Page::explorer) {
    if (inside(x,y,kSidebar+24,88,110,34)) { app.explorer_tab=0; refresh_local_explorer(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+144,88,130,34)) { app.explorer_tab=1; refresh_local_explorer(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+284,88,160,34)) { app.explorer_tab=3; app.dirty=true; return; }
    if (app.explorer_tab == 0) {
      if (inside(x,y,kSidebar+24,140,app.width-kSidebar-190,28)) { app.active_explorer_local_path=true; app.dirty=true; return; }
      if (inside(x,y,app.width-150,140,110,28)) {
        const std::filesystem::path requested=app.explorer_local_path_field;
        std::error_code error;
        if (portable_explorer_allowed(app,requested) && std::filesystem::is_directory(requested,error) && !error) {
          app.explorer_current_path=weak_canonical_or_normal(requested); app.explorer_local_scroll=0; refresh_local_explorer(app);
          set_body(app,"Local Explorer refreshed.","Explorer ready");
        } else {
          app.explorer_local_path_field=app.explorer_current_path.string();
          set_body(app,"Blocked path. Local Explorer is confined to approved Veeam, tracked-case and SAT roots.","Explorer safe-root boundary");
        }
        app.dirty=true; return;
      }
      const int left_x=kSidebar+24,left_w=250,right_x=left_x+266,right_w=app.width-right_x-30;
      const int panel_y=188,panel_h=std::max(280,app.height-panel_y-92);
      const int root_rows=std::max(1,(panel_h-38)/28);
      for (std::size_t i=0;i<app.explorer_roots.size() && static_cast<int>(i)<root_rows;++i) {
        if (inside(x,y,left_x+8,panel_y+28+static_cast<int>(i)*28,left_w-16,24)) {
          app.explorer_current_path=app.explorer_roots[i]; app.explorer_local_scroll=0; refresh_local_explorer(app); app.dirty=true; return;
        }
      }
      const int header_y=panel_y+6;
      const int name_w=std::max(180,right_w*42/100),type_w=std::max(90,right_w*16/100),size_w=std::max(90,right_w*15/100);
      const int modified_w=right_w-name_w-type_w-size_w-12;
      const auto apply_sort = [&](ExplorerSortColumn column) {
        if (app.explorer_sort_column == column) {
          app.explorer_sort_ascending = !app.explorer_sort_ascending;
        } else {
          app.explorer_sort_column = column;
          app.explorer_sort_ascending = true;
        }
        refresh_local_explorer(app);
        app.dirty = true;
      };
      if(inside(x,y,right_x+4,header_y,name_w,26)){apply_sort(ExplorerSortColumn::name);return;}
      if(inside(x,y,right_x+4+name_w,header_y,type_w,26)){apply_sort(ExplorerSortColumn::type);return;}
      if(inside(x,y,right_x+4+name_w+type_w,header_y,size_w,26)){apply_sort(ExplorerSortColumn::size);return;}
      if(inside(x,y,right_x+4+name_w+type_w+size_w,header_y,modified_w,26)){apply_sort(ExplorerSortColumn::modified);return;}
      const int row_y=header_y+32,row_h=24,visible=std::max(1,(panel_h-70)/row_h);
      if(inside(x,y,right_x,row_y,right_w,panel_h-50) && button==Button4){ if(app.explorer_local_scroll>0) --app.explorer_local_scroll; app.dirty=true; return; }
      if(inside(x,y,right_x,row_y,right_w,panel_h-50) && button==Button5){ if(app.explorer_local_scroll+static_cast<std::size_t>(visible)<app.explorer_entries.size()) ++app.explorer_local_scroll; app.dirty=true; return; }
      const std::size_t begin=std::min(app.explorer_local_scroll,app.explorer_entries.size());
      const std::size_t finish=std::min(app.explorer_entries.size(),begin+static_cast<std::size_t>(visible));
      for(std::size_t i=begin;i<finish;++i){
        const int visual=static_cast<int>(i-begin);
        if(inside(x,y,right_x+4,row_y+visual*row_h,right_w-8,row_h-1)){ app.explorer_selected=static_cast<int>(i); app.explorer_last_selected_local=app.explorer_entries[i].path; app.dirty=true; return; }
      }
      if (inside(x,y,right_x,panel_y+panel_h+10,140,32) && app.explorer_selected>=0 && static_cast<std::size_t>(app.explorer_selected)<app.explorer_entries.size()) {
        const auto entry=app.explorer_entries[static_cast<std::size_t>(app.explorer_selected)];
        if (entry.directory) { app.explorer_current_path=entry.path; app.explorer_local_scroll=0; refresh_local_explorer(app); }
        else set_body(app,"Selected local evidence:\n"+entry.path.string()+"\nUse Log Review for structured analysis or Mark for collection for the support bundle.","Explorer file selected");
        app.dirty=true; return;
      }
      if (inside(x,y,right_x+150,panel_y+panel_h+10,160,32) && app.explorer_selected>=0 && static_cast<std::size_t>(app.explorer_selected)<app.explorer_entries.size()) {
        const auto path=weak_canonical_or_normal(app.explorer_entries[static_cast<std::size_t>(app.explorer_selected)].path);
        if (app.explorer_marked_paths.contains(path)) app.explorer_marked_paths.erase(path); else app.explorer_marked_paths.insert(path);
        app.dirty=true; return;
      }
      if (inside(x,y,right_x+320,panel_y+panel_h+10,120,32)) {
        const auto parent=app.explorer_current_path.parent_path();
        if (!parent.empty() && portable_explorer_allowed(app,parent)) { app.explorer_current_path=parent; app.explorer_local_scroll=0; refresh_local_explorer(app); }
        else set_body(app,"Parent navigation stopped at the approved Explorer root.","Explorer safe-root boundary");
        app.dirty=true; return;
      }
    } else if (app.explorer_tab == 1) {
      const std::array<std::pair<int,int>,5> fields{{{kSidebar+24,140},{kSidebar+234,140},{kSidebar+319,140},{kSidebar+489,140},{kSidebar+24,192}}};
      const std::array<int,5> widths{{200,75,160,200,465}};
      for(std::size_t i=0;i<fields.size();++i) if(inside(x,y,fields[i].first,fields[i].second,widths[i],28)){ app.active_explorer_ssh_field=static_cast<int>(i); app.dirty=true; return; }
      if(inside(x,y,kSidebar+499,192,100,28)&&!app.busy){start_portable_ssh_probe(app);return;}
      if(inside(x,y,kSidebar+609,199,260,22)&&!app.explorer_ssh_fingerprint.empty()){app.explorer_ssh_trusted=!app.explorer_ssh_trusted;app.dirty=true;return;}
      if(inside(x,y,kSidebar+24,230,110,30)&&!app.busy){start_portable_ssh_list(app);return;}
      if (inside(x, y, kSidebar + 144, 230, 110, 30)) {
        std::fill(app.explorer_ssh_fields[3].begin(), app.explorer_ssh_fields[3].end(), '\0');
        app.explorer_ssh_fields[3].clear();
        app.explorer_ssh_connected = false;
        app.explorer_ssh_trusted = false;
        {
          std::lock_guard lock(app.mutex);
          app.explorer_ssh_fingerprint.clear();
          app.explorer_ssh_machine_name.clear();
          app.explorer_ssh_entries.clear();
        }
        append_portable_activity(
            app, "Explorer SSH/SFTP", "Disconnected", "Session credentials cleared");
        set_body(app, "SSH/SFTP session state and password cleared.", "SSH disconnected");
        app.dirty = true;
        return;
      }
      const int total_w=app.width-kSidebar-54,transfer_w=96,gap=10,pane_w=(total_w-transfer_w-2*gap)/2;
      const int left_x=kSidebar+24,transfer_x=left_x+pane_w+gap,right_x=transfer_x+transfer_w+gap,panel_y=282,panel_h=std::max(260,app.height-panel_y-78),row_h=23;
      const int visible=std::max(1,(panel_h-70)/row_h);
      if(inside(x,y,left_x,panel_y,pane_w,panel_h)&&button==Button4){if(app.explorer_local_scroll>0)--app.explorer_local_scroll;app.dirty=true;return;}
      if(inside(x,y,left_x,panel_y,pane_w,panel_h)&&button==Button5){if(app.explorer_local_scroll+static_cast<std::size_t>(visible)<app.explorer_entries.size())++app.explorer_local_scroll;app.dirty=true;return;}
      if(inside(x,y,right_x,panel_y,pane_w,panel_h)&&button==Button4){if(app.explorer_ssh_scroll>0)--app.explorer_ssh_scroll;app.dirty=true;return;}
      if (inside(x, y, right_x, panel_y, pane_w, panel_h) && button == Button5) {
        std::lock_guard lock(app.mutex);
        if (app.explorer_ssh_scroll + static_cast<std::size_t>(visible) <
            app.explorer_ssh_entries.size()) {
          ++app.explorer_ssh_scroll;
        }
        app.dirty = true;
        return;
      }
      const std::size_t lbegin=std::min(app.explorer_local_scroll,app.explorer_entries.size()),lend=std::min(app.explorer_entries.size(),lbegin+static_cast<std::size_t>(visible));
      for (std::size_t i = lbegin; i < lend; ++i) {
        const int visual = static_cast<int>(i - lbegin);
        if (inside(x, y, left_x + 4, panel_y + 49 + visual * row_h, pane_w - 8, row_h)) {
          app.explorer_selected = static_cast<int>(i);
          app.explorer_last_selected_local = app.explorer_entries[i].path;
          app.dirty = true;
          return;
        }
      }
      std::vector<SftpEntry> entries;{std::lock_guard lock(app.mutex);entries=app.explorer_ssh_entries;}
      const std::size_t rbegin=std::min(app.explorer_ssh_scroll,entries.size()),rend=std::min(entries.size(),rbegin+static_cast<std::size_t>(visible));
      for(std::size_t i=rbegin;i<rend;++i){const int visual=static_cast<int>(i-rbegin);if(inside(x,y,right_x+4,panel_y+49+visual*row_h,pane_w-8,row_h)){app.explorer_ssh_selected=static_cast<int>(i);app.dirty=true;return;}}
      if(inside(x,y,transfer_x,panel_y+84,transfer_w,34)&&!app.busy){start_portable_ssh_upload(app);return;}
      if(inside(x,y,transfer_x,panel_y+128,transfer_w,34)&&!app.busy){start_portable_ssh_download(app);return;}
      if(inside(x,y,transfer_x,panel_y+190,transfer_w,30)){
        const auto parent=app.explorer_current_path.parent_path();if(!parent.empty()&&portable_explorer_allowed(app,parent)){app.explorer_current_path=parent;app.explorer_local_scroll=0;refresh_local_explorer(app);}app.dirty=true;return;}
      if(inside(x,y,transfer_x,panel_y+228,transfer_w,30)&&app.explorer_ssh_connected&&!app.busy){
        std::filesystem::path remote=app.explorer_ssh_fields[4];auto parent=remote.parent_path();app.explorer_ssh_fields[4]=parent.empty()?"/":parent.string();start_portable_ssh_list(app);return;}
      if (app.explorer_selected >= 0 &&
          static_cast<std::size_t>(app.explorer_selected) < app.explorer_entries.size() &&
          app.explorer_entries[static_cast<std::size_t>(app.explorer_selected)].directory &&
          inside(x, y, left_x, panel_y + 49, pane_w, panel_h - 49) && button == Button2) {
        app.explorer_current_path =
            app.explorer_entries[static_cast<std::size_t>(app.explorer_selected)].path;
        refresh_local_explorer(app);
        app.dirty = true;
        return;
      }
      if (app.explorer_ssh_selected >= 0 &&
          static_cast<std::size_t>(app.explorer_ssh_selected) < entries.size() &&
          entries[static_cast<std::size_t>(app.explorer_ssh_selected)].directory &&
          inside(x, y, right_x, panel_y + 49, pane_w, panel_h - 49) && button == Button2 &&
          !app.busy) {
        app.explorer_ssh_fields[4] =
            entries[static_cast<std::size_t>(app.explorer_ssh_selected)].path;
        start_portable_ssh_list(app);
        return;
      }
    } else if (app.explorer_tab == 3) {
      if(inside(x,y,kSidebar+24,138,180,32)){app.explorer_console_target=0;app.dirty=true;return;}
      if(inside(x,y,kSidebar+214,138,210,32)){app.explorer_console_target=1;app.dirty=true;return;}
      if(inside(x,y,kSidebar+24,192,app.width-kSidebar-220,28)){app.active_explorer_console_field=0;app.dirty=true;return;}
      if(inside(x,y,app.width-176,192,136,28)&&!app.busy){if(app.explorer_console_target==0)start_portable_local_command(app);else start_portable_ssh_command(app);return;}
    }
  }
  if (app.page == Page::environment && !app.environment_busy) {
    static constexpr std::size_t count=7U;
    const int available = app.width - kSidebar - 54;
    const int columns = available >= 900 ? 4 : 2;
    const int gap = 10;
    const int card_w = (available - gap * (columns - 1)) / columns;
    for (std::size_t i=0;i<count;++i) {
      const int row=static_cast<int>(i)/columns, col=static_cast<int>(i)%columns;
      if (inside(x,y,kSidebar+24+col*(card_w+gap),138+row*82,card_w,72)) {
        std::string detail;
        { std::lock_guard lock(app.mutex); detail=app.environment_card_details[i]; app.environment_selected_card=static_cast<int>(i); }
        if (!detail.empty()) set_body(app, detail, "Environment Review: selected category detail");
        return;
      }
    }
  }
  if (app.page == Page::gather) {
    if (inside(x,y,kSidebar+24,88,220,36) && !app.busy) { start_gather(app); return; }
    if (inside(x,y,kSidebar+256,88,150,36) && !app.busy) { refresh_gather_products(app); update_page(app); app.dirty=true; return; }
    if (inside(x,y,kSidebar+418,88,100,36) && app.busy) { app.cancellation.cancel(); set_body(app,"Cancelling current collection...","Cancellation requested"); return; }
    if (!app.busy) {
      const int columns = app.width - kSidebar >= 820 ? 2 : 1;
      const int column_width = std::max(300, (app.width - kSidebar - 70) / columns);
      int max_row = 0;
      for (std::size_t index = 0; index < app.gather_products.size(); ++index) {
        const int column = static_cast<int>(index % static_cast<std::size_t>(columns));
        const int row = static_cast<int>(index / static_cast<std::size_t>(columns));
        max_row = std::max(max_row, row);
        if (inside(x, y, kSidebar + 24 + column * column_width, 142 + row * 28, column_width - 12, 22)) {
          app.gather_product_selected[index] = !app.gather_product_selected[index];
          app.dirty = true;
          return;
        }
      }
      const int third_party_y = 142 + (app.gather_products.empty() ? 0 : (max_row + 1) * 28) + 4;
      if (inside(x, y, kSidebar + 24, third_party_y, app.width - kSidebar - 54, 22)) {
        app.gather_third_party = !app.gather_third_party;
        app.dirty = true;
        return;
      }
    }
  }
}

} // namespace

int run_portable_gui() {
  App app;
  app.display = XOpenDisplay(nullptr);
  if (app.display == nullptr) {
    // Headless Linux remains fully usable through the CLI.
    return 2;
  }
  const int screen = DefaultScreen(app.display);
  app.window = XCreateSimpleWindow(app.display, RootWindow(app.display, screen), 60, 60,
                                   static_cast<unsigned int>(app.width), static_cast<unsigned int>(app.height),
                                   0, BlackPixel(app.display,screen), BlackPixel(app.display,screen));
  const std::string window_title = std::string(kProductName) + " " + std::string(kVersion);
  XStoreName(app.display, app.window, window_title.c_str());
  XSelectInput(app.display, app.window, ExposureMask | ButtonPressMask | StructureNotifyMask | KeyPressMask);
  app.wm_delete = XInternAtom(app.display, "WM_DELETE_WINDOW", False);
  XSetWMProtocols(app.display, app.window, &app.wm_delete, 1);
  app.gc = XCreateGC(app.display, app.window, 0, nullptr);
  app.font = XLoadQueryFont(app.display, "fixed");
  if (app.font != nullptr) XSetFont(app.display, app.gc, app.font->fid);
  XMapWindow(app.display, app.window);
  // Match the Windows session-only startup policy: a pristine copy opens as a
  // Customer/Lab execution host, while any existing SAT state defaults safely
  // to Engineer Review. The role is never persisted as an execution permission.
  app.execution_host_enabled = !portable_prior_sat_state();
  load_portable_activity(app);
  load_portable_cases(app);
  refresh_case_dashboard(app);
  refresh_gather_products(app);
  update_page(app);

  while (!app.closing) {
    while (XPending(app.display) > 0) {
      XEvent event{}; XNextEvent(app.display, &event);
      if (event.type == Expose) app.dirty=true;
      // Defensive only. `dirty` starts true, but XMapWindow is asynchronous, so that first paint can
      // be issued before the window exists on screen and be discarded; the initial paint then depends
      // entirely on Expose arriving. MapNotify is guaranteed whenever StructureNotifyMask is selected,
      // so honouring it removes that dependency on any server.
      //
      // NOT a fix for the "runs but no GUI under WSLg" report: measured under WSLg/XWayland, Expose IS
      // delivered and the window paints identically with and without this line (44 distinct colours
      // sampled either way). That root cause is still unidentified. Do not cite this as the remedy.
      else if (event.type == MapNotify) app.dirty=true;
      else if (event.type == ConfigureNotify) { app.width=event.xconfigure.width; app.height=event.xconfigure.height; app.dirty=true; }
      else if (event.type == ButtonPress) click(app,event.xbutton.x,event.xbutton.y,event.xbutton.button);
      else if (event.type == ClientMessage && static_cast<Atom>(event.xclient.data.l[0]) == app.wm_delete) app.closing=true;
      else if (event.type == KeyPress) {
        KeySym key{};
        char buffer[32]{};
        const int count = XLookupString(&event.xkey, buffer, static_cast<int>(sizeof(buffer)), &key, nullptr);
        const bool shift_tab = (event.xkey.state & ShiftMask) != 0U;
        if (app.page == Page::log_review && app.active_review_field >= 0 && app.active_review_field < 2) {
          auto& field=app.review_fields[static_cast<std::size_t>(app.active_review_field)];
          if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
          if (key == XK_Tab) { app.active_review_field=shift_tab?(app.active_review_field+1)%2:(app.active_review_field+1)%2; app.dirty=true; continue; }
          if (key == XK_Return || key == XK_KP_Enter) { app.active_review_field=-1; app.dirty=true; continue; }
          if (count > 0) {
            for (int i=0;i<count && field.size()<1023U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch >= 32U && ch < 127U) field.push_back(static_cast<char>(ch)); }
            app.dirty=true; continue;
          }
        }
        if (app.page == Page::case_workspace && app.active_case_field >= 0 && app.active_case_field < 4) {
          auto& field=app.case_fields[static_cast<std::size_t>(app.active_case_field)];
          if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
          if (key == XK_Tab) { app.active_case_field=shift_tab?(app.active_case_field+3)%4:(app.active_case_field+1)%4; app.dirty=true; continue; }
          if (key == XK_Return || key == XK_KP_Enter) { app.active_case_field=-1; app.dirty=true; continue; }
          if (count > 0) {
            for (int i=0;i<count && field.size()<1023U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch >= 32U && ch < 127U) field.push_back(static_cast<char>(ch)); }
            app.dirty=true; continue;
          }
        }
        if (app.page == Page::sql_tools && app.active_sql_field >= 0 && app.active_sql_field < 5) {
          auto& field=app.sql_fields[static_cast<std::size_t>(app.active_sql_field)];
          if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
          if (key == XK_Tab) { app.active_sql_field=shift_tab?(app.active_sql_field+4)%5:(app.active_sql_field+1)%5; app.dirty=true; continue; }
          if (key == XK_Return || key == XK_KP_Enter) { app.active_sql_field=-1; app.dirty=true; continue; }
          if (count > 0) {
            for (int i=0;i<count && field.size()<2047U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch >= 32U && ch < 127U) field.push_back(static_cast<char>(ch)); }
            app.dirty=true; continue;
          }
        }
        if (app.page == Page::filesystem_tools && app.active_filesystem_field >= 0 && app.active_filesystem_field < 4) {
          auto& field=app.filesystem_fields[static_cast<std::size_t>(app.active_filesystem_field)];
          if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
          if (key == XK_Tab) { app.active_filesystem_field=shift_tab?(app.active_filesystem_field+3)%4:(app.active_filesystem_field+1)%4; app.dirty=true; continue; }
          if (key == XK_Return || key == XK_KP_Enter) { app.active_filesystem_field=-1; app.dirty=true; continue; }
          if (count > 0) {
            for (int i=0;i<count && field.size()<1023U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch >= 32U && ch < 127U) field.push_back(static_cast<char>(ch)); }
            app.dirty=true; continue;
          }
        }
        if (app.page == Page::network_tools && app.active_network_field >= 0 && app.active_network_field < 5) {
          auto& field=app.network_fields[static_cast<std::size_t>(app.active_network_field)];
          if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
          if (key == XK_Tab) { app.active_network_field=shift_tab?(app.active_network_field+4)%5:(app.active_network_field+1)%5; app.dirty=true; continue; }
          if (key == XK_Return || key == XK_KP_Enter) { app.active_network_field=-1; app.dirty=true; continue; }
          if (count > 0) {
            for (int i=0;i<count && field.size()<255U;++i) {
              const unsigned char ch=static_cast<unsigned char>(buffer[i]);
              if (ch >= 32U && ch < 127U) field.push_back(static_cast<char>(ch));
            }
            app.dirty=true; continue;
          }
        }
        if (app.page == Page::explorer) {
          if (app.explorer_tab == 0 && app.active_explorer_local_path) {
            auto& field=app.explorer_local_path_field;
            if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
            if (key == XK_Tab) { app.active_explorer_local_path=false; app.dirty=true; continue; }
            if (key == XK_Return || key == XK_KP_Enter) { app.active_explorer_local_path=false; app.dirty=true; continue; }
            if (count > 0) { for (int i=0;i<count && field.size()<2047U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch>=32U && ch<127U) field.push_back(static_cast<char>(ch)); } app.dirty=true; continue; }
          }
          if (app.explorer_tab == 1 && app.active_explorer_ssh_field >= 0 && app.active_explorer_ssh_field < 5) {
            auto& field=app.explorer_ssh_fields[static_cast<std::size_t>(app.active_explorer_ssh_field)];
            if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
            if (key == XK_Tab) { app.active_explorer_ssh_field=shift_tab?(app.active_explorer_ssh_field+4)%5:(app.active_explorer_ssh_field+1)%5; app.dirty=true; continue; }
            if (key == XK_Return || key == XK_KP_Enter) { app.active_explorer_ssh_field=-1; app.dirty=true; continue; }
            if (count > 0) { for (int i=0;i<count && field.size()<1023U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch>=32U && ch<127U) field.push_back(static_cast<char>(ch)); } app.dirty=true; continue; }
          }
          if (app.explorer_tab == 3 && app.active_explorer_console_field == 0) {
            auto& field=app.explorer_console_command;
            if (key == XK_BackSpace || key == XK_Delete) { if (!field.empty()) field.pop_back(); app.dirty=true; continue; }
            if (key == XK_Tab) { app.active_explorer_console_field=-1; app.dirty=true; continue; }
            if (key == XK_Return || key == XK_KP_Enter) {
              app.active_explorer_console_field = -1;
              if (!app.busy) {
                if (app.explorer_console_target == 0) {
                  start_portable_local_command(app);
                } else {
                  start_portable_ssh_command(app);
                }
              }
              app.dirty = true;
              continue;
            }
            if (count > 0) { for (int i=0;i<count && field.size()<4095U;++i) { const unsigned char ch=static_cast<unsigned char>(buffer[i]); if (ch>=32U && ch<127U) field.push_back(static_cast<char>(ch)); } app.dirty=true; continue; }
          }
        }
        if (key == XK_Escape) app.closing=true;
        if (key == XK_F5) {
          if (app.page == Page::gather) refresh_gather_products(app);
          update_page(app,app.page==Page::health);
        }
      }
    }
    if (app.dirty.exchange(false)) paint(app);
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  app.cancellation.cancel();
  if (app.worker.joinable()) app.worker.join();
  std::fill(app.explorer_ssh_fields[3].begin(), app.explorer_ssh_fields[3].end(), '\0');
  app.explorer_ssh_fields[3].clear();
  if (app.font != nullptr) XFreeFont(app.display, app.font);
  XFreeGC(app.display, app.gc); XDestroyWindow(app.display, app.window); XCloseDisplay(app.display);
  return 0;
}

} // namespace support_assist::gui
