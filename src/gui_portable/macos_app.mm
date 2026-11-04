#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <dispatch/dispatch.h>

#include "portable_app.hpp"
#include "portable_capabilities.hpp"
#include "support_assist/case_review_store.hpp"
#include "support_assist/case_workspace.hpp"
#include "support_assist/case_report.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/filesystem.hpp"
#include "support_assist/snapshot_store.hpp"
#include "support_assist/network.hpp"
#include "support_assist/process.hpp"
#include "support_assist/ssh_client.hpp"
#include "support_assist/sql_tools.hpp"
#include "support_assist/tool_catalog.hpp"
#include "support_assist/time.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/universal_collection.hpp"
#include "support_assist/veeam_log_review.hpp"
#include "support_assist/version.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <optional>
#include <set>
#include <sstream>
#include <thread>
#include <vector>

// SAT macOS portable engineer parity workspace: native AppKit shell with shared SAT case, review, collection, tools and Explorer workflows.
namespace {

enum PortablePage : NSInteger {
  PageHome=0, PageCases=1, PageEnvironment=2, PageHealth=3, PageLogReview=4, PageExplorer=5,
  PageTools=6, PageGather=7, PageGuided=8, PageNetwork=9, PageSql=10, PageVss=11,
  PageRegistry=12, PageFilesystem=13, PageWmi=14, PageVbr=15, PageHost=16,
  PageThirdParty=17, PageDiagnostics=18, PageRecent=19, PageHelp=20
};

NSString* ns_string(const std::string& value) {
  return [NSString stringWithUTF8String:value.c_str()];
}

std::filesystem::path default_collection_root() {
  NSString* home = NSHomeDirectory();
  return std::filesystem::path([[home stringByAppendingPathComponent:@"Log-Collections"] UTF8String]);
}

std::filesystem::path portable_state_directory() {
  NSString* home = NSHomeDirectory();
  return std::filesystem::path([[home stringByAppendingPathComponent:@"Library/Application Support/SupportAssistTool"] UTF8String]);
}

bool portable_native_odbc_available() noexcept {
#ifdef SUPPORT_ASSIST_HAS_NATIVE_ODBC
  return true;
#else
  return false;
#endif
}

bool portable_prior_sat_state() {
  std::error_code error;
  if (std::filesystem::exists(portable_state_directory(), error)) return true;
  const auto current = std::filesystem::current_path(error);
  if (error) return false;
  for (const auto* name : {"ApplicationLogs", "Logs", "State", "Cases"}) {
    error.clear(); if (std::filesystem::exists(current / name, error)) return true;
  }
  return false;
}

std::filesystem::path portable_tool_output_directory() {
  return default_collection_root() / "Tools";
}

std::string safe_tool_name(std::string value) {
  for (char& ch : value) {
    const unsigned char u = static_cast<unsigned char>(ch);
    if (!std::isalnum(u) && ch != '-' && ch != '_') ch = '-';
  }
  return value.empty() ? "tool" : value;
}

void write_portable_tool_output(std::string_view tool, std::string_view text) {
  std::error_code error;
  const auto root = portable_tool_output_directory() / safe_tool_name(std::string(tool));
  std::filesystem::create_directories(root, error);
  if (error) return;
  std::string stamp = support_assist::utc_now_iso8601();
  for (char& ch : stamp) if (ch == ':' || ch == '.' || ch == 'T' || ch == 'Z') ch = '-';
  std::ofstream output(root / (stamp + "-" + safe_tool_name(std::string(tool)) + ".log"),
                       std::ios::binary | std::ios::trunc);
  if (output) output << "Support Assist Tool " << support_assist::kVersion << " " << support_assist::kReleaseChannel
                     << "\nBuild: " << support_assist::kBuildRevision << "\nTool: " << tool
                     << "\nCaptured UTC: " << support_assist::utc_now_iso8601() << "\n\n" << text << "\n";
}

std::string home_text() {
  const auto products = support_assist::detect_products(support_assist::native_product_discovery_context());
  std::ostringstream output;
  output << "Support Assist Tool " << support_assist::kVersion << " " << support_assist::kReleaseChannel
         << "\n\n"
         << "Native macOS GUI backed by the same SupportAssistCore used by Windows and Linux.\n"
         << "Detected Veeam products/roles: " << products.size() << "\n\n"
         << "Use Environment Review for product detection, Health Monitor for native system telemetry, and Gather Logs for the privacy-bounded universal support bundle.\n\n"
         << "SAT does not collect database data files, backup payloads, repositories, home directories, environment dumps or process command lines.";
  return output.str();
}

std::string health_text() {
  support_assist::SystemHealthSampler sampler;
  static_cast<void>(sampler.sample({true,true,true,true,true}));
  std::this_thread::sleep_for(std::chrono::milliseconds(180));
  auto result = sampler.sample({true,true,true,true,true});
  return result.ok() ? support_assist::format_system_health_report(result.value())
                     : "Health sample failed: " + support_assist::describe_error(result.error());
}

std::vector<std::filesystem::path> detected_local_log_sources() {
  const auto context = support_assist::native_product_discovery_context();
  const auto detected = support_assist::detect_products(context);
  std::vector<std::filesystem::path> sources;
  for (const auto& product : detected) {
    for (const auto& rule : product.definition.log_paths) {
      if (rule.third_party || rule.sensitive_by_nature) continue;
      const auto path = support_assist::resolve_catalog_path(context, rule.path);
      std::error_code error;
      if (std::filesystem::exists(path, error) && !error) sources.push_back(path);
    }
  }
  std::sort(sources.begin(), sources.end());
  sources.erase(std::unique(sources.begin(), sources.end()), sources.end());
  return sources;
}

std::string format_portable_review_summary(const support_assist::VeeamLogReviewResult& result) {
  std::size_t errors = 0;
  std::size_t warnings = 0;
  for (const auto& incident : result.incidents) {
    if (incident.severity == "error") ++errors;
    else if (incident.severity == "warning") ++warnings;
  }
  std::ostringstream output;
  output << "Unified Veeam Log Review completed\n\n"
         << "Profile: " << support_assist::to_string(result.profile_used) << "\n"
         << "Product summary: " << result.product_type << "\n"
         << "Confidence: " << support_assist::to_string(result.product_confidence) << "\n"
         << "Review state: " << (result.fast_index_used ? "INDEXED: PRELIMINARY" : "FULLY ANALYZED: FULL REVIEW COMPLETE") << "\n"
         << "Files: " << result.files_scanned << " scanned / " << result.files_discovered << " discovered / " << result.files_deferred << " deferred\n"
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


std::string portable_case_dashboard_text(const support_assist::CaseWorkspace* workspace) {
  if (workspace == nullptr)
    return "Case Dashboard\n\nNo active case. Use the Active Case selector to switch a registered case, or create/register a case below.";
  std::ostringstream output;
  output << "CASE DASHBOARD\n\nCase: " << workspace->case_id;
  if (!workspace->title.empty()) output << ": " << workspace->title;
  output << "\nEngineer: " << workspace->engineer << "\n";
  auto state=support_assist::load_case_review_state(*workspace);
  if(state.ok()) output << "Review: " << (state.value().fast_index?"INDEXED: PRELIMINARY":"FULLY ANALYZED") << " | " << state.value().updated_utc << "\n";
  auto review=support_assist::load_case_review_model(*workspace);
  auto bookmarks=support_assist::load_case_evidence_bookmarks(*workspace);
  std::size_t noteSelections=0;
  if(bookmarks.ok()) noteSelections=static_cast<std::size_t>(std::count_if(bookmarks.value().begin(),bookmarks.value().end(),[](const auto& item){return item.include_in_note;}));
  if(review.ok()){
    std::size_t errors=0,warnings=0;
    for(const auto& incident:review.value().incidents){if(incident.severity=="error")++errors;else if(incident.severity=="warning")++warnings;}
    output << "Systems/components: " << review.value().machines.size() << "\nJobs/activities/runs: " << review.value().job_sessions.size()
           << "\nFindings: " << errors << " errors / " << warnings << " warnings\n";
    output << "Evidence: " << (bookmarks.ok()?bookmarks.value().size():0U) << " bookmarks / " << noteSelections << " #note selections\n\nSYSTEMS / COMPONENTS\n";
    std::size_t shown=0; for(const auto& machine:review.value().machines){output<<"- "<<(machine.display_name.empty()?machine.key:machine.display_name);if(!machine.role.empty())output<<": "<<machine.role;output<<"\n";if(++shown>=10U)break;}
    output << "\nRECENT JOBS / ACTIVITIES / RUNS\n";
    shown=0; for(auto it=review.value().job_sessions.rbegin();it!=review.value().job_sessions.rend()&&shown<10U;++it,++shown){output<<"- "<<(it->machine_name.empty()?it->machine_key:it->machine_name)<<" | "<<(it->job_name.empty()?it->job_type:it->job_name)<<" | "<<it->status<<"\n";}
    output << "\nERRORS / WARNINGS\n";
    shown=0; for(const auto& incident:review.value().incidents){if(incident.severity!="error"&&incident.severity!="warning")continue;output<<"- ["<<incident.severity<<"] "<<incident.summary<<"\n";if(++shown>=12U)break;}
  } else {
    output << "No saved structured review yet. Use Review New Logs or Load Saved Review after analysis.\n";
  }
  return output.str();
}

std::string macos_tools_text() {
  const auto capabilities=support_assist::gui::macos_capability_catalog(support_assist::ssh_available(), portable_native_odbc_available());
  std::ostringstream output;
  output << "TOOLS: macOS\n\nThe catalog mirrors the Windows product structure. Platform differences are explicit rather than silently missing.\n\n";
  std::string category;
  for(const auto& item:capabilities){
    if(item.category!=category){category=item.category;output<<category<<"\n";}
    output<<"  "<<item.name<<": "<<support_assist::gui::capability_state_label(item.state,support_assist::gui::PortablePlatform::macos)<<"\n    "<<item.detail<<"\n";
  }
  return output.str();
}


std::string macos_network_catalog_text() {
  std::ostringstream output;
  output << "NETWORK TOOLS: macOS\n\n";
  for (const auto& item : support_assist::gui::portable_network_tool_actions(support_assist::gui::PortablePlatform::macos)) {
    output << item.name << ": "
           << support_assist::gui::capability_state_label(item.state, support_assist::gui::PortablePlatform::macos)
           << "\n  " << item.detail << "\n\n";
  }
  return output.str();
}

std::string macos_platform_not_applicable_text(std::string_view feature,
                                                std::string_view reason,
                                                std::string_view alternative) {
  std::ostringstream output;
  output << feature << "\n\nNot applicable on macOS.\n\n" << reason;
  if (!alternative.empty()) output << "\n\nmacOS workflow: " << alternative;
  return output.str();
}

std::string macos_third_party_text() {
  std::ostringstream output;
  output << "THIRD PARTY INTEGRATIONS: macOS\n\n";
  const auto tools = support_assist::inspect_external_tools();
  for (const auto& tool : tools) {
    output << tool.definition.name << ": " << support_assist::to_string(tool.availability) << "\n"
           << "  " << tool.definition.description << "\n";
    if (tool.definition.windows_only) output << "  Not applicable on macOS (Windows integration).\n";
    else if (!tool.detail.empty()) output << "  " << tool.detail << "\n";
    output << "\n";
  }
  if (tools.empty()) output << "No optional integrations are defined for this build.\n";
  return output.str();
}

std::string macos_diagnostics_text(bool execution_host_enabled) {
  const auto products = support_assist::detect_products(support_assist::native_product_discovery_context());
  std::ostringstream output;
  output << "DIAGNOSTICS: macOS\n\n"
         << "System Information\n"
         << "  Platform: macOS\n"
         << "  Build: " << support_assist::kBuildRevision << "\n"
         << "  Workspace Role: " << (execution_host_enabled ? "Customer / Lab Execution Host" : "Engineer Review") << "\n"
         << "  State directory: " << portable_state_directory().string() << "\n"
         << "  Collection root: " << default_collection_root().string() << "\n\n"
         << "Products and Integrations\n"
         << "  Detected Veeam product/role count: " << products.size() << "\n"
         << "  SSH/SFTP backend: " << (support_assist::ssh_available() ? "Available" : "Unavailable: build without libssh2") << "\n"
         << "  Native ODBC backend: " << (portable_native_odbc_available() ? "Available" : "Unavailable: SQL script generation/fallback remains") << "\n\n"
         << "SAT Self-Test\n"
         << "  Core startup: PASS\n"
         << "  Case/catalog state path: " << portable_state_directory().string() << "\n"
         << "  Use the build/test scripts for compiler, unit-test, CTest and package-integrity gates.\n";
  return output.str();
}

std::string macos_host_diagnostics_text() {
  support_assist::ProcessOptions options;
  options.executable = "/bin/zsh";
  options.arguments = {"-lc",
    "printf '%s\\n' '-- macOS --'; sw_vers 2>&1; "
    "printf '%s\\n' '-- Kernel --'; uname -a 2>&1; "
    "printf '%s\\n' '-- Hardware --'; sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>&1; "
    "printf '%s\\n' '-- Filesystems --'; df -h 2>&1; "
    "printf '%s\\n' '-- Network --'; ifconfig 2>&1; "
    "printf '%s\\n' '-- Routes --'; netstat -rn 2>&1; "
    "printf '%s\\n' '-- TLS --'; openssl version -a 2>&1 || true"};
  options.timeout = std::chrono::seconds(20);
  options.maximum_output_bytes = 2U * 1024U * 1024U;
  auto result = support_assist::run_process_capture(options, {});
  std::ostringstream output;
  output << "macOS HOST DIAGNOSTICS\n\nRead-only native host context. SAT does not change network, security, package, service or certificate state.\n\n";
  if (result.ok()) output << result.value().output;
  else output << "Host diagnostic command failed: " << support_assist::describe_error(result.error()) << "\n";
  output << "\n-- Detected Veeam products / roles --\n"
         << support_assist::format_detected_products_report(support_assist::detect_products(support_assist::native_product_discovery_context()));
  return output.str();
}

std::string macos_local_explorer_text(const std::filesystem::path& root) {
  std::ostringstream output;
  output << "LOCAL FILES\n\nPath: " << root.string() << "\n\n";
  std::error_code kind_error;
  if(std::filesystem::is_regular_file(root,kind_error)){
    output << "Selected file\n  Name: " << root.filename().string() << "\n  Size: " << std::filesystem::file_size(root,kind_error) << " bytes\n\nUse Mark/Unmark to include this approved local file in Universal Log Collection, or choose Browse to move to another path.";
    return output.str();
  }
  output
         << std::left << std::setw(36) << "Name" << std::setw(14) << "Type" << std::setw(14) << "Size" << "Date modified\n"
         << std::string(86, '-') << "\n";
  std::error_code error;
  if (root.has_parent_path()) output << std::left << std::setw(36) << ".." << std::setw(14) << "Folder" << std::setw(14) << "" << "\n";
  std::vector<std::filesystem::directory_entry> entries;
  for (std::filesystem::directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, error), end;
       !error && it != end; it.increment(error)) entries.push_back(*it);
  if (error) return output.str() + "\nUnable to enumerate: " + error.message();
  std::stable_sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
    std::error_code ea, eb;
    const bool da=a.is_directory(ea), db=b.is_directory(eb);
    if(da!=db) return da>db;
    return a.path().filename().string() < b.path().filename().string();
  });
  std::size_t shown=0;
  for (const auto& entry : entries) {
    std::error_code e;
    const bool directory=entry.is_directory(e);
    std::uint64_t size=0;
    if(!directory){e.clear();size=entry.file_size(e);if(e)size=0;}
    std::string name=entry.path().filename().string(); if(name.size()>34U)name=name.substr(0,31U)+"...";
    output << std::left << std::setw(36) << name << std::setw(14) << (directory?"Folder":"File") << std::setw(14) << (directory?std::string{}:std::to_string(size)) << "\n";
    if(++shown>=500U){output<<"\n... view bounded to first 500 entries\n";break;}
  }
  return output.str();
}

std::string sanitize_activity_field(std::string value) {
  for(char& ch:value) if(ch=='\t'||ch=='\r'||ch=='\n') ch=' ';
  if(value.size()>400U)value.resize(400U);
  return value;
}

void append_macos_activity(std::string_view tool, std::string_view result, std::string_view detail={}) {
  std::error_code error;
  const auto state=portable_state_directory();
  std::filesystem::create_directories(state,error); if(error)return;
  std::ofstream out(state/"activity.tsv",std::ios::binary|std::ios::app); if(!out)return;
  out << sanitize_activity_field(support_assist::utc_now_iso8601()) << '\t'
      << sanitize_activity_field(std::string(tool)) << '\t'
      << sanitize_activity_field(std::string(result)) << '\t'
      << sanitize_activity_field(std::string(detail)) << '\n';
}

std::string macos_recent_activity_text() {
  std::ifstream in(portable_state_directory()/"activity.tsv",std::ios::binary);
  std::vector<std::string> lines; std::string line;
  while(std::getline(in,line)){if(!line.empty()&&line.back()=='\r')line.pop_back();if(!line.empty())lines.push_back(line);}
  std::ostringstream output; output << "RECENT ACTIVITY\n\n";
  if(lines.empty()){output<<"No activity has been recorded by this macOS SAT installation yet.\n";return output.str();}
  std::size_t count=0;
  for(auto it=lines.rbegin();it!=lines.rend()&&count<50U;++it,++count){
    std::string display=*it; std::replace(display.begin(),display.end(),'\t',' '); output<<display<<"\n";
  }
  return output.str();
}

} // namespace

@interface SATPortableDelegate : NSObject <NSApplicationDelegate>
@end

@implementation SATPortableDelegate {
  NSWindow* _window;
  NSTextView* _text;
  NSPopUpButton* _activeCasePopup;
  NSButton* _roleButton;
  NSMutableArray<NSButton*>* _navButtons;
  NSPopUpButton* _toolCategory;
  NSPopUpButton* _explorerTab;
  NSTextField* _explorerPath;
  NSButton* _explorerBrowse;
  NSButton* _explorerMark;
  NSTextField* _sshHost;
  NSTextField* _sshPort;
  NSTextField* _sshUser;
  NSSecureTextField* _sshPassword;
  NSTextField* _sshRemotePath;
  NSButton* _sshProbe;
  NSButton* _sshConnect;
  NSButton* _sshUpload;
  NSButton* _sshDownload;
  NSPopUpButton* _consoleTarget;
  NSTextField* _consoleCommand;
  NSButton* _consoleRun;
  NSTextField* _sqlServer;
  NSTextField* _sqlDatabase;
  NSTextField* _sqlPrincipal;
  NSTextField* _sqlConnection;
  NSTextField* _sqlOutput;
  NSButton* _sqlTrusted;
  NSButton* _sqlDatabasePermissions;
  NSButton* _sqlRun;
  NSTextField* _fsRoot;
  NSTextField* _fsOutput;
  NSTextField* _fsBaseline;
  NSTextField* _fsOther;
  NSButton* _fsHash;
  NSButton* _fsCapture;
  NSButton* _fsCompare;
  NSTextField* _status;
  NSButton* _action;
  NSButton* _cancelButton;
  NSButton* _refreshProducts;
  NSButton* _thirdPartyCheck;
  NSTextField* _gatherHeading;
  NSScrollView* _scroll;
  NSPopUpButton* _networkOperation;
  NSTextField* _networkHost;
  NSTextField* _networkPort;
  NSTextField* _networkSource;
  NSTextField* _networkSni;
  NSTextField* _networkFingerprint;
  NSButton* _networkAllInterfaces;
  NSButton* _networkPayload;
  NSButton* _networkTlsCompare;
  NSTextField* _reviewSource;
  NSTextField* _reviewCase;
  NSButton* _reviewFullScan;
  NSButton* _reviewBrowse;
  NSButton* _reviewDetectLocal;
  NSTextField* _caseParent;
  NSTextField* _caseId;
  NSTextField* _caseTitle;
  NSTextField* _caseEngineer;
  NSButton* _caseOpen;
  NSButton* _caseNoCase;
  NSButton* _caseLoadSaved;
  NSButton* _caseNote;
  NSButton* _casePdf;
  NSButton* _caseDelete;
  BOOL _caseDeleteArmed;
  NSMutableArray<NSButton*>* _productChecks;
  std::vector<support_assist::ProductDefinition> _gatherProducts;
  PortablePage _page;
  support_assist::CancellationSource _cancel;
  BOOL _busy;
  BOOL _executionHostEnabled;
  support_assist::gui::PortableCaseCatalog _caseCatalog;
  std::string _activeCaseRoot;
  std::string _sshFingerprint;
  bool _sshTrusted;
  std::set<std::filesystem::path> _markedPaths;
}

- (void)setBody:(std::string)body status:(std::string)status {
  [_text setString:ns_string(body)];
  [_status setStringValue:ns_string(status)];
}

- (void)syncActiveCase {
  const auto* active = _caseCatalog.active();
  _activeCaseRoot = active == nullptr ? std::string{} : active->root.string();
  if (_reviewCase != nil) [_reviewCase setStringValue:ns_string(_activeCaseRoot)];
  if (_activeCasePopup != nil) {
    [_activeCasePopup removeAllItems];
    [_activeCasePopup addItemWithTitle:@"(No active case)"];
    for (const auto& workspace : _caseCatalog.cases) {
      std::string label = workspace.case_id;
      if (!workspace.title.empty()) label += ": " + workspace.title;
      [_activeCasePopup addItemWithTitle:ns_string(label)];
    }
    [_activeCasePopup selectItemAtIndex:_caseCatalog.active_index < 0 ? 0 : _caseCatalog.active_index + 1];
  }
}

- (void)loadPortableCases {
  std::vector<std::filesystem::path> seeds;
  std::error_code error;
  const auto current = std::filesystem::current_path(error);
  if (!error) seeds.push_back(current / "Cases");
  seeds.push_back(portable_state_directory() / "Cases");
  _caseCatalog = support_assist::gui::load_portable_case_catalog(portable_state_directory(), seeds);
  [self syncActiveCase];
}

- (void)activeCaseChanged:(id)sender {
  (void)sender;
  const NSInteger selected = [_activeCasePopup indexOfSelectedItem];
  support_assist::gui::set_portable_active_case(_caseCatalog, selected <= 0 ? -1 : static_cast<int>(selected - 1), portable_state_directory());
  [self syncActiveCase];
  [self setBody:_activeCaseRoot.empty() ? "No Case is active. Review and diagnostic workflows remain available where case persistence is optional."
                                           : "Active case changed to:\n" + _activeCaseRoot
             status:_activeCaseRoot.empty() ? "No active case" : "Active case changed"];
  if (_page == PageCases) [self showPage:PageCases];
}

- (void)roleClicked:(id)sender {
  (void)sender;
  if (_busy) return;
  _executionHostEnabled = !_executionHostEnabled;
  [_roleButton setTitle:_executionHostEnabled ? @"Customer / Lab" : @"Engineer Review"];
  [self rebuildNavigation];
  if (!_executionHostEnabled && (_page == PageTools || _page == PageGather || _page == PageGuided ||
      _page == PageNetwork || _page == PageSql || _page == PageVss || _page == PageRegistry ||
      _page == PageFilesystem || _page == PageWmi || _page == PageVbr || _page == PageHost ||
      _page == PageThirdParty || _page == PageDiagnostics)) {
    [self showPage:PageHome];
  }
}

- (void)rebuildNavigation {
  for (NSButton* button in _navButtons) [button removeFromSuperview];
  [_navButtons removeAllObjects];
  struct Entry { const char* label; PortablePage page; bool child; };
  std::vector<Entry> entries = {
    {"Home",PageHome,false},{"Case Dashboard",PageCases,false},{"Environment Review",PageEnvironment,false},
    {"Health Monitor",PageHealth,false},{"Log Review",PageLogReview,false},{"Explorer",PageExplorer,false}
  };
  if (_executionHostEnabled) {
    const std::vector<Entry> execution = {
      {"Tools",PageTools,false},{"  Log Collection",PageGather,true},{"  Guided Diagnostics",PageGuided,true},
      {"  Network Tools",PageNetwork,true},{"  SQL Tools",PageSql,true},{"  VSS Tools",PageVss,true},
      {"  Registry Tools",PageRegistry,true},{"  Filesystem Change",PageFilesystem,true},
      {"  WMI Diagnostics",PageWmi,true},{"  VBR Diagnostics",PageVbr,true},{"  macOS Host Diagnostics",PageHost,true},
      {"Third Party Integrations",PageThirdParty,false},{"Diagnostics",PageDiagnostics,false}
    };
    entries.insert(entries.end(), execution.begin(), execution.end());
  }
  entries.push_back({"Recent Activity",PageRecent,false});
  entries.push_back({"Help / About",PageHelp,false});
  NSView* content=[_window contentView];
  CGFloat y=700.0;
  for(const auto& entry:entries){
    const CGFloat h=entry.child?24.0:30.0;
    NSButton* button=[[NSButton alloc] initWithFrame:NSMakeRect(entry.child?28:18,y,entry.child?180:190,h)];
    [button setTitle:ns_string(entry.label)]; [button setTag:entry.page]; [button setTarget:self]; [button setAction:@selector(navClicked:)];
    [button setBezelStyle:NSBezelStyleTexturedRounded];
    [content addSubview:button]; [_navButtons addObject:button];
    y-=h+3.0;
  }
}

- (void)hideReviewControls {
  for (NSView* view in @[_reviewSource,_reviewCase,_reviewFullScan,_reviewBrowse,_reviewDetectLocal])
    [view setHidden:YES];
}

- (void)showReviewControls {
  for (NSView* view in @[_reviewSource,_reviewCase,_reviewFullScan,_reviewBrowse,_reviewDetectLocal])
    [view setHidden:NO];
  [_scroll setFrame:NSMakeRect(230,80,870,500)];
}

- (void)hideCaseControls {
  for (NSView* view in @[_caseParent,_caseId,_caseTitle,_caseEngineer,_caseOpen,_caseNoCase,_caseLoadSaved,_caseNote,_casePdf,_caseDelete])
    [view setHidden:YES];
}

- (void)showCaseControls {
  for (NSView* view in @[_caseParent,_caseId,_caseTitle,_caseEngineer,_caseOpen,_caseNoCase,_caseLoadSaved,_caseNote,_casePdf,_caseDelete])
    [view setHidden:NO];
  [_scroll setFrame:NSMakeRect(230,80,870,470)];
}

- (void)hideParityControls {
  for (NSView* view in @[_toolCategory,_explorerTab,_explorerPath,_explorerBrowse,_explorerMark,_sshHost,_sshPort,_sshUser,_sshPassword,
                         _sshRemotePath,_sshProbe,_sshConnect,_sshUpload,_sshDownload,_consoleTarget,_consoleCommand,_consoleRun,
                         _sqlServer,_sqlDatabase,_sqlPrincipal,_sqlConnection,_sqlOutput,_sqlTrusted,_sqlDatabasePermissions,_sqlRun,
                         _fsRoot,_fsOutput,_fsBaseline,_fsOther,_fsHash,_fsCapture,_fsCompare])
    [view setHidden:YES];
}

- (void)showToolCatalogControls {
  [_toolCategory setHidden:NO];
  [_toolCategory removeAllItems];
  const auto capabilities=support_assist::gui::macos_capability_catalog(support_assist::ssh_available(), portable_native_odbc_available());
  for(const auto& capability:capabilities){
    std::string label=capability.name+": "+support_assist::gui::capability_state_label(capability.state,support_assist::gui::PortablePlatform::macos);
    [_toolCategory addItemWithTitle:ns_string(label)];
  }
  [_scroll setFrame:NSMakeRect(230,80,870,520)];
}

- (void)showSqlControls {
  for(NSView* view in @[_sqlServer,_sqlDatabase,_sqlPrincipal,_sqlConnection,_sqlOutput,_sqlTrusted,_sqlDatabasePermissions,_sqlRun]) [view setHidden:NO];
  [_scroll setFrame:NSMakeRect(230,80,870,430)];
}

- (void)showFilesystemControls {
  for(NSView* view in @[_fsRoot,_fsOutput,_fsBaseline,_fsOther,_fsHash,_fsCapture,_fsCompare]) [view setHidden:NO];
  [_scroll setFrame:NSMakeRect(230,80,870,420)];
}

- (void)showExplorerControls {
  [_explorerTab setHidden:NO];
  const NSInteger tab=[_explorerTab indexOfSelectedItem];
  if(tab==0){
    [_explorerPath setHidden:NO]; [_explorerBrowse setHidden:NO]; [_explorerMark setHidden:NO];
  } else if(tab==1){
    for(NSView* view in @[_sshHost,_sshPort,_sshUser,_sshPassword,_sshRemotePath,_sshProbe,_sshConnect,_sshUpload,_sshDownload]) [view setHidden:NO];
  } else if(tab==3){
    for(NSView* view in @[_consoleTarget,_consoleCommand,_consoleRun]) [view setHidden:NO];
    if(support_assist::ssh_available()) for(NSView* view in @[_sshHost,_sshPort,_sshUser,_sshPassword,_sshProbe]) [view setHidden:NO];
  }
  [_scroll setFrame:NSMakeRect(230,80,870,430)];
}

- (void)hideNetworkControls {
  for (NSView* view in @[_networkOperation,_networkHost,_networkPort,_networkSource,_networkSni,_networkFingerprint,
                         _networkAllInterfaces,_networkPayload,_networkTlsCompare])
    [view setHidden:YES];
  [_scroll setFrame:NSMakeRect(230,80,870,650)];
}

- (void)showNetworkControls:(BOOL)guided {
  for (NSView* view in @[_networkOperation,_networkHost,_networkPort,_networkSource,_networkSni,_networkFingerprint,
                         _networkAllInterfaces,_networkPayload,_networkTlsCompare])
    [view setHidden:NO];
  [_networkOperation removeAllItems];
  if (guided) {
    const auto available=support_assist::available_guided_diagnostics(support_assist::native_product_discovery_context());
    for (const auto& item : available) {
      if (item.id=="managed-server-connectivity" || item.id=="veeam-secure-channel")
        [_networkOperation addItemWithTitle:ns_string(item.display_name)];
    }
    if ([_networkOperation numberOfItems] == 0)
      [_networkOperation addItemWithTitle:@"No applicable network Guided Diagnostic"];
  } else {
    [_networkOperation addItemsWithTitles:@[@"Network Interfaces",@"TCP Connectivity Test",@"TCP Listener",@"UDP Connectivity Test",@"UDP Listener",@"TLS Handshake Test",@"Throughput Client",@"Throughput Server"]];
  }
  [_scroll setFrame:NSMakeRect(230,80,870,390)];
}

- (void)hideGatherControls {
  [_refreshProducts setHidden:YES];
  [_thirdPartyCheck setHidden:YES];
  [_gatherHeading setHidden:YES];
  for (NSButton* button in _productChecks)
    [button setHidden:YES];
  [_scroll setFrame:NSMakeRect(230,80,870,650)];
}

- (void)refreshGatherProducts {
  const auto detected = support_assist::detect_products(support_assist::native_product_discovery_context());
  _gatherProducts = support_assist::product_catalog(support_assist::native_host_platform());
  for (NSButton* button in _productChecks)
    [button removeFromSuperview];
  [_productChecks removeAllObjects];

  NSView* content = [_window contentView];
  const NSInteger columns = 2;
  const CGFloat columnWidth = 415.0;
  for (std::size_t index = 0; index < _gatherProducts.size(); ++index) {
    const bool found = std::any_of(detected.begin(), detected.end(), [&](const auto& product) {
      return product.definition.id == _gatherProducts[index].id;
    });
    const NSInteger column = static_cast<NSInteger>(index % static_cast<std::size_t>(columns));
    const NSInteger row = static_cast<NSInteger>(index / static_cast<std::size_t>(columns));
    NSButton* check = [[NSButton alloc] initWithFrame:NSMakeRect(245 + column * columnWidth,
                                                                  610 - row * 30,
                                                                  columnWidth - 12, 24)];
    [check setButtonType:NSSwitchButton];
    std::string label = _gatherProducts[index].display_name;
    label += found ? " [detected]" : " [not detected]";
    [check setTitle:ns_string(label)];
    [check setState:found ? NSControlStateValueOn : NSControlStateValueOff];
    [check setTag:static_cast<NSInteger>(index)];
    [check setTarget:self];
    [check setAction:@selector(productClicked:)];
    [content addSubview:check];
    [_productChecks addObject:check];
  }
}

- (std::vector<std::string>)selectedGatherProductIds {
  std::vector<std::string> selected;
  for (NSButton* button in _productChecks) {
    const NSInteger index = [button tag];
    if ([button state] == NSControlStateValueOn && index >= 0 &&
        static_cast<std::size_t>(index) < _gatherProducts.size())
      selected.push_back(_gatherProducts[static_cast<std::size_t>(index)].id);
  }
  return selected;
}

- (void)showGatherControls {
  [_gatherHeading setHidden:NO];
  [_refreshProducts setHidden:NO];
  [_thirdPartyCheck setHidden:NO];
  for (NSButton* button in _productChecks)
    [button setHidden:NO];
  const NSInteger rows = static_cast<NSInteger>((_gatherProducts.size() + 1U) / 2U);
  const CGFloat bottom = std::max<CGFloat>(310.0, 575.0 - static_cast<CGFloat>(rows) * 30.0);
  [_thirdPartyCheck setFrame:NSMakeRect(245, bottom, 600, 24)];
  [_scroll setFrame:NSMakeRect(230,80,870,std::max<CGFloat>(180.0, bottom - 100.0))];
}

- (void)productClicked:(id)sender {
  (void)sender;
}

- (void)refreshProductsClicked:(id)sender {
  (void)sender;
  if (_busy) return;
  [self refreshGatherProducts];
  [self showGatherControls];
  [self setBody:"Product detection refreshed. Detected products are checked by default; non-detected catalog roles remain explicit opt-in choices." status:"Product detection refreshed"];
}

- (void)showPage:(PortablePage)page {
  _page = page;
  [_action setHidden:YES];
  [_cancelButton setHidden:YES];
  [self hideGatherControls];
  [self hideNetworkControls];
  [self hideReviewControls];
  [self hideCaseControls];
  [self hideParityControls];
  if (page != PageCases) { _caseDeleteArmed=NO; [_caseDelete setTitle:@"Delete Active"]; }
  [_scroll setFrame:NSMakeRect(230,80,870,650)];

  switch (page) {
    case PageHome: {
      std::ostringstream body; body << home_text() << "\n\nActive Case: " << (_caseCatalog.active()==nullptr?"No Case":_caseCatalog.active_label())
        << "\nWorkspace Role: " << (_executionHostEnabled?"Customer / Lab Execution Host":"Engineer Review");
      [self setBody:body.str() status:"Ready"];
      break;
    }
    case PageCases:
      [_action setTitle:@"Create Case"]; [_action setHidden:NO]; [self showCaseControls];
      [self setBody:portable_case_dashboard_text(_caseCatalog.active()) status:_caseCatalog.active()==nullptr?"No active case":"Case dashboard"];
      break;
    case PageHealth:
      [_action setTitle:@"Refresh Health"]; [_action setHidden:NO];
      [self setBody:"Health Monitor uses native macOS telemetry through the shared SAT health model. Refresh to collect CPU, memory/swap, filesystems, network and top-process observations." status:"Ready"];
      break;
    case PageEnvironment:
      [_action setTitle:@"Refresh Environment"]; [_action setHidden:NO];
      [self setBody:support_assist::format_detected_products_report(support_assist::detect_products(support_assist::native_product_discovery_context())) status:"Ready"];
      break;
    case PageLogReview: {
      [_action setTitle:@"Review Source"]; [_action setHidden:NO]; [self showReviewControls];
      const auto local=detected_local_log_sources(); std::ostringstream body;
      body << "Unified Veeam Log Review\n\nAuto Detect is the normal review path. Choose a ZIP, directory or log file, or use Detect Local Logs on this Customer/Lab host.\n"
           << "Detected local Veeam log roots: " << local.size() << "\nActive case: " << (_activeCaseRoot.empty()?"No Case":_activeCaseRoot) << "\n";
      [self setBody:body.str() status:"Ready"];
      break;
    }
    case PageExplorer:
      [self showExplorerControls];
      [self explorerTabChanged:nil];
      break;
    case PageTools:
      [_action setTitle:@"Open Selected Category"]; [_action setHidden:NO]; [self showToolCatalogControls];
      [self setBody:macos_tools_text() status:"Tool catalog"];
      break;
    case PageGather: {
      [_action setTitle:@"Gather Support Bundle"]; [_action setHidden:NO];
      if(_gatherProducts.empty()) [self refreshGatherProducts]; [self showGatherControls];
      [self setBody:"Universal Log Collection\n\nDetected products are checked by default. The checklist is exact: unchecked products are not silently added back. Third-party collection remains bounded to operational/error evidence and excludes database payloads, repositories and home directories." status:"Ready"];
      break;
    }
    case PageGuided: {
      [_action setTitle:@"Run Guided Diagnostic"]; [_action setHidden:NO]; [self showNetworkControls:YES];
      const auto available=support_assist::available_guided_diagnostics(support_assist::native_product_discovery_context());
      std::ostringstream body; body << "GUIDED DIAGNOSTICS: macOS\n\n";
      for(const auto& item:available) body << "- " << item.display_name << "\n  " << item.description << "\n  Reference: " << item.kb_id << " | " << item.reference_url << "\n";
      if(available.empty()) body << "No product-specific Guided Diagnostic is applicable to the detected local Veeam roles.\n";
      [self setBody:body.str() status:"Ready"];
      break;
    }
    case PageNetwork:
      [_action setTitle:@"Run Network Tool"]; [_action setHidden:NO]; [self showNetworkControls:NO];
      [self setBody:macos_network_catalog_text() status:"Network Tools"];
      break;
    case PageSql:
      [_action setTitle:@"Generate Permission Script"]; [_action setHidden:NO]; [self showSqlControls];
      [self setBody:"SQL TOOLS: macOS\n\nGenerate a reviewable permission script without connecting, or run the diagnostic using native ODBC when compiled/available. SQLCMD can remain an optional installed fallback. Credentials/connection strings are session-only and are not written to Recent Activity." status:"Ready"];
      break;
    case PageVss:
      [self setBody:macos_platform_not_applicable_text("VSS TOOLS","Microsoft Volume Shadow Copy Service is a Windows technology.","Use APFS/filesystem/storage context, Veeam Agent for Mac product diagnostics, and collected Veeam evidence.") status:"Not applicable on macOS"];
      break;
    case PageRegistry:
      [self setBody:macos_platform_not_applicable_text("REGISTRY TOOLS","The Windows Registry does not exist on macOS.","Use Filesystem Change plus macOS Host Diagnostics for plist, launchd and application configuration evidence.") status:"Not applicable on macOS"];
      break;
    case PageFilesystem:
      [self showFilesystemControls];
      [self setBody:"FILESYSTEM CHANGE: macOS\n\nCapture a recursive SAT baseline and compare later snapshots using the shared scanner/schema. SHA-256 hashing is optional. Windows-specific streams/file-ID/cloud-hydration controls are not exposed." status:"Ready"];
      break;
    case PageWmi:
      [self setBody:macos_platform_not_applicable_text("WMI DIAGNOSTICS","Windows Management Instrumentation is Windows-specific.","macOS Host Diagnostics uses native system APIs/commands and Environment Review for equivalent host context.") status:"Not applicable on macOS"];
      break;
    case PageVbr:
      [self setBody:macos_platform_not_applicable_text("VBR DIAGNOSTICS","A local Veeam Backup & Replication server role is Windows-based.","Use Log Review, Environment Review, SSH/SFTP and portable network/TLS diagnostics against VBR evidence or remote endpoints.") status:"Not applicable on macOS"];
      break;
    case PageHost:
      [_action setTitle:@"Refresh Host Diagnostics"]; [_action setHidden:NO];
      [self setBody:"macOS Host Diagnostics\n\nRefresh for read-only OS/kernel, hardware, storage, network/routes, TLS/OpenSSL and detected Veeam product context." status:"Ready"];
      break;
    case PageThirdParty:
      [_action setTitle:@"Refresh Integrations"]; [_action setHidden:NO];
      [self setBody:macos_third_party_text() status:"Third Party Integrations"];
      break;
    case PageDiagnostics:
      [_action setTitle:@"Refresh Self-Test"]; [_action setHidden:NO];
      [self setBody:macos_diagnostics_text(_executionHostEnabled) status:"Diagnostics"];
      break;
    case PageRecent:
      [self setBody:macos_recent_activity_text() status:"Recent Activity"];
      break;
    case PageHelp: {
      const std::string helpText =
          "HELP / ABOUT\n\n" + std::string(support_assist::kProductName) + " " +
          std::string(support_assist::kVersion) +
          " uses the same case/review/collection/tool model across Windows, Linux and macOS. "
          "Platform-specific technologies remain explicit instead of disappearing.\n\n"
          "Build and deployment: macOS must be compiled/linked with Apple Clang on a Mac. "
          "See docs/CROSS_PLATFORM_BUILD.md and docs/user-guide/Support-Assist-Tool-User-Guide.html.";
      [self setBody:helpText status:"Ready"];
      break;
    }
  }
}

- (void)navClicked:(id)sender { if (!_busy) [self showPage:(PortablePage)[sender tag]]; }

- (void)explorerTabChanged:(id)sender {
  (void)sender;
  if (_page != PageExplorer) return;
  [self hideParityControls]; [self showExplorerControls];
  const NSInteger tab=[_explorerTab indexOfSelectedItem];
  if(tab==0){
    if([[_explorerPath stringValue] length]==0){
      if(!_activeCaseRoot.empty()) [_explorerPath setStringValue:ns_string(_activeCaseRoot)];
      else [_explorerPath setStringValue:[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Application Support/Veeam"]];
    }
    const std::filesystem::path path=[[_explorerPath stringValue] UTF8String];
    [self setBody:macos_local_explorer_text(path) status:"Local Files"];
  } else if(tab==1){
    [self setBody:"SSH / SFTP\n\nLocal Files and Remote Files use the same session-only trust/credential boundary as Windows/Linux. Probe the host key first, independently verify the SHA-256 fingerprint, then Connect. Remote path can be a directory for listing/upload or a file for Download." status:support_assist::ssh_available()?"SSH/SFTP ready":"SSH/SFTP backend unavailable"];
  } else if(tab==2){
    [self setBody:"WINDOWS REMOTE FILES\n\nNot available. Use SSH/SFTP where the target supports SSH." status:"Not available"];
  } else {
    [_consoleTarget removeAllItems];
    if(_executionHostEnabled) [_consoleTarget addItemWithTitle:@"Local host (zsh)"];
    if(_sshTrusted && [[_sshHost stringValue] length]>0){NSString* title=[NSString stringWithFormat:@"%@ (SSH)",[_sshHost stringValue]];[_consoleTarget addItemWithTitle:title];}
    if([_consoleTarget numberOfItems]==0) [_consoleTarget addItemWithTitle:@"No execution target available"];
    [self setBody:"REMOTE CONSOLE\n\nLocal zsh is available only in Customer/Lab execution-host mode. SSH console becomes available after explicit host-key probe/trust. Command text is not written to Recent Activity or tool reports." status:"Console ready"];
  }
}

- (void)browseExplorerPath:(id)sender {
  (void)sender; if(_busy)return;
  NSOpenPanel* panel=[NSOpenPanel openPanel]; [panel setCanChooseFiles:YES]; [panel setCanChooseDirectories:YES]; [panel setAllowsMultipleSelection:NO];
  if([panel runModal]==NSModalResponseOK){NSURL* url=[[panel URLs] firstObject];if(url!=nil){[_explorerPath setStringValue:[url path]];[self explorerTabChanged:nil];}}
}

- (void)markExplorerPath:(id)sender {
  (void)sender; const std::filesystem::path path=[[_explorerPath stringValue] UTF8String]; if(path.empty()){[self setBody:"Choose a local file or directory first." status:"No local path"];return;}
  if(_markedPaths.contains(path)){_markedPaths.erase(path);[_explorerMark setTitle:@"Mark for Collection"];[self setBody:macos_local_explorer_text(path)+"\n\nCollection mark removed." status:"Unmarked"];}
  else{_markedPaths.insert(path);[_explorerMark setTitle:@"Unmark"];[self setBody:macos_local_explorer_text(path)+"\n\nMarked for Universal Log Collection under Additional/Local with source provenance retained." status:"Marked for collection"];}
}

- (support_assist::SshConnectionOptions)currentSshOptions:(BOOL)requireTrust {
  support_assist::SshConnectionOptions options;
  options.host=[[_sshHost stringValue] UTF8String];
  try{const auto p=std::stoul([[_sshPort stringValue] UTF8String]);options.port=(p>0&&p<=65535)?static_cast<std::uint16_t>(p):22;}catch(...){options.port=22;}
  options.username=[[_sshUser stringValue] UTF8String]; options.password=[[_sshPassword stringValue] UTF8String];
  if(requireTrust && _sshTrusted) options.expected_host_key_sha256=_sshFingerprint;
  return options;
}

- (void)sshProbeClicked:(id)sender {
  (void)sender; if(_busy||!support_assist::ssh_available())return;
  auto options=[self currentSshOptions:NO]; if(options.host.empty()){[self setBody:"Enter an SSH host first." status:"SSH host required"];return;}
  _busy=YES; _cancel=support_assist::CancellationSource{}; auto token=_cancel.token(); __weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
    auto result=support_assist::ssh_probe_host_key(options,token); std::string body,status; std::string fp;
    if(result.ok()){fp=result.value().fingerprint_sha256;body="SSH host key probe\n\nAlgorithm: "+result.value().algorithm+"\nSHA-256: "+fp+"\n\nIndependently verify this fingerprint, then choose Connect to trust it for this SAT session only.";status="Host key probed";}
    else{body="SSH host-key probe failed:\n"+support_assist::describe_error(result.error());status="SSH probe failed";}
    dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;strong->_sshFingerprint=fp;strong->_sshTrusted=false;[strong setBody:body status:status];}});
  });
}

- (void)sshConnectClicked:(id)sender {
  (void)sender; if(_busy||!support_assist::ssh_available())return;
  if(_sshFingerprint.empty()){[self setBody:"Probe and independently verify the SSH host key before connecting." status:"Host-key verification required"];return;}
  _sshTrusted=true; auto options=[self currentSshOptions:YES]; std::string remote=[[_sshRemotePath stringValue] UTF8String];if(remote.empty())remote=".";
  _busy=YES; _cancel=support_assist::CancellationSource{}; auto token=_cancel.token(); __weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
    auto listed=support_assist::ssh_list_directory(options,remote,token); std::ostringstream body; std::string status;
    if(!listed.ok()){body<<"SSH/SFTP connection failed:\n"<<support_assist::describe_error(listed.error());status="SFTP failed";}
    else{body<<"REMOTE FILES: "<<options.host<<"\n\nPath: "<<remote<<"\n\n"<<std::left<<std::setw(36)<<"Name"<<std::setw(12)<<"Type"<<"Size\n"<<std::string(64,'-')<<"\n";for(const auto& e:listed.value())body<<std::left<<std::setw(36)<<e.name<<std::setw(12)<<(e.directory?"Folder":"File")<<(e.directory?std::string{}:std::to_string(e.size))<<"\n";status="SFTP connected";}
    const std::string bodyText=body.str();
    dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;if(listed.ok()){append_macos_activity("SSH / SFTP","Connected/listed",options.host);[strong->_consoleTarget removeAllItems];if(strong->_executionHostEnabled)[strong->_consoleTarget addItemWithTitle:@"Local host (zsh)"];[strong->_consoleTarget addItemWithTitle:[NSString stringWithFormat:@"%@ (SSH)",[strong->_sshHost stringValue]]];}[strong setBody:bodyText status:status];}});
  });
}

- (void)sshUploadClicked:(id)sender {
  (void)sender; if(_busy||!_sshTrusted)return;
  NSOpenPanel* panel=[NSOpenPanel openPanel];[panel setCanChooseFiles:YES];[panel setCanChooseDirectories:NO];[panel setAllowsMultipleSelection:NO];if([panel runModal]!=NSModalResponseOK)return;
  const std::filesystem::path local=[[[[panel URLs] firstObject] path] UTF8String]; std::string remote=[[_sshRemotePath stringValue] UTF8String];if(remote.empty()||remote==".")remote="./"+local.filename().string();else if(!remote.empty()&&remote.back()=='/')remote+=local.filename().string();
  auto options=[self currentSshOptions:YES];_busy=YES;_cancel=support_assist::CancellationSource{};auto token=_cancel.token();__weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{auto result=support_assist::ssh_upload_file(options,local,remote,token);std::string body=result.ok()?"Upload complete:\n"+local.string()+"\n→ "+remote:"Upload failed:\n"+support_assist::describe_error(result.error());dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;if(result.ok())append_macos_activity("SSH / SFTP","Upload complete",local.filename().string()+" -> "+options.host);[strong setBody:body status:result.ok()?"Upload complete":"Upload failed"];}});});
}

- (void)sshDownloadClicked:(id)sender {
  (void)sender; if(_busy||!_sshTrusted)return; std::string remote=[[_sshRemotePath stringValue] UTF8String];if(remote.empty()||remote=="."){[self setBody:"Enter the remote file path to download." status:"Remote file required"];return;}
  NSSavePanel* panel=[NSSavePanel savePanel];[panel setNameFieldStringValue:ns_string(std::filesystem::path(remote).filename().string())];if([panel runModal]!=NSModalResponseOK)return;const std::filesystem::path local=[[[panel URL] path] UTF8String];
  auto options=[self currentSshOptions:YES];_busy=YES;_cancel=support_assist::CancellationSource{};auto token=_cancel.token();__weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{auto result=support_assist::ssh_download_file(options,remote,local,token);std::string body=result.ok()?"Download complete:\n"+remote+"\n→ "+local.string():"Download failed:\n"+support_assist::describe_error(result.error());dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;if(result.ok())append_macos_activity("SSH / SFTP","Download complete",std::filesystem::path(remote).filename().string()+" <- "+options.host);[strong setBody:body status:result.ok()?"Download complete":"Download failed"];}});});
}

- (void)consoleRunClicked:(id)sender {
  (void)sender;if(_busy)return;const std::string command=[[_consoleCommand stringValue] UTF8String];if(command.empty()){[self setBody:"Enter a command." status:"Command required"];return;}NSString* selected=[_consoleTarget titleOfSelectedItem];if(selected==nil||[selected hasPrefix:@"No execution"]){[self setBody:"No console execution target is available." status:"No target"];return;}
  _busy=YES;_cancel=support_assist::CancellationSource{};auto token=_cancel.token();const bool local=[selected hasPrefix:@"Local host"];auto ssh=[self currentSshOptions:YES];__weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{std::string body,status;if(local){support_assist::ProcessOptions options;options.executable="/bin/zsh";options.arguments={"-lc",command};options.timeout=std::chrono::minutes(5);options.maximum_output_bytes=4U*1024U*1024U;auto r=support_assist::run_process_capture(options,token);if(r.ok()){body="local$ [command text intentionally not retained]\nExit: "+std::to_string(r.value().exit_code)+"\n\n"+r.value().output;if(!r.value().standard_error.empty())body+="\nSTDERR\n"+r.value().standard_error;status="Local command complete";append_macos_activity("Explorer Local Console",r.value().exit_code==0?"Command completed":"Command returned non-zero","Local zsh command text not retained");}else{body="Local command failed:\n"+support_assist::describe_error(r.error());status="Local command failed";}}else{auto r=support_assist::ssh_execute_command(ssh,command,token);if(r.ok()){body="ssh> [command text not retained]\nExit: "+std::to_string(r.value().exit_status)+"\n\n"+r.value().standard_output;if(!r.value().standard_error.empty())body+="\nSTDERR\n"+r.value().standard_error;status="SSH command complete";append_macos_activity("Explorer SSH Console",r.value().exit_status==0?"Command completed":"Command returned non-zero",ssh.host+"; command text not retained");}else{body="SSH command failed:\n"+support_assist::describe_error(r.error());status="SSH command failed";}}dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;[strong setBody:body status:status];}});});
}

- (void)runSqlPermissionDiagnostic:(BOOL)runDiagnostic {
  if(_busy)return;
  support_assist::SqlPermissionOptions options;
  options.server=[[_sqlServer stringValue] UTF8String]; options.database=[[_sqlDatabase stringValue] UTF8String]; if(options.database.empty())options.database="master";
  options.principal=[[_sqlPrincipal stringValue] UTF8String]; options.connection_string=[[_sqlConnection stringValue] UTF8String];
  options.trusted_connection=[_sqlTrusted state]==NSControlStateValueOn; options.include_database_permissions=[_sqlDatabasePermissions state]==NSControlStateValueOn;
  const std::string output=[[_sqlOutput stringValue] UTF8String]; if(!output.empty())options.output_file=output;
  if(options.principal.empty()){[self setBody:"SQL Tools requires a principal name." status:"Principal required"];return;}
  if(!runDiagnostic){
    auto written=support_assist::write_sql_permission_script(options);
    if(!written.ok()) [self setBody:"SQL permission script failed:\n"+support_assist::describe_error(written.error()) status:"SQL Tools failed"];
    else {const std::string body="SQL permission diagnostic script created:\n"+written.value().string();write_portable_tool_output("SQL-Permission-Script",body);append_macos_activity("SQL Tools","Permission script created",written.value().string());[self setBody:body status:"SQL script created"];}
    return;
  }
  if(options.server.empty()){[self setBody:"Run Permission Diagnostic requires a SQL Server / instance." status:"Server required"];return;}
  _busy=YES;_cancel=support_assist::CancellationSource{};auto token=_cancel.token();__weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
    auto result=support_assist::run_sql_permission_diagnostic(options,token);std::string body,status;
    if(!result.ok()){body="SQL permission diagnostic failed:\n"+support_assist::describe_error(result.error());status="SQL Tools failed";append_macos_activity("SQL Tools","Failed",result.error().message);}
    else{body=result.value().output;if(!result.value().standard_error.empty())body+="\nSTDERR:\n"+result.value().standard_error;status=result.value().exit_code==0?"SQL diagnostic complete":"SQL diagnostic returned findings";write_portable_tool_output("SQL-Permission-Diagnostic",body);append_macos_activity("SQL Tools",result.value().exit_code==0?"Completed":"Completed with finding/error","Permission diagnostic");}
    dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;[strong setBody:body status:status];}});
  });
}

- (void)runFilesystemOperation:(BOOL)compare {
  if(_busy)return;
  const std::string root=[[_fsRoot stringValue] UTF8String], output=[[_fsOutput stringValue] UTF8String], baseline=[[_fsBaseline stringValue] UTF8String], other=[[_fsOther stringValue] UTF8String];
  if((!compare&&(root.empty()||output.empty()))||(compare&&(baseline.empty()||other.empty()))){[self setBody:compare?"Filesystem compare requires both Baseline and Other .satsnap paths.":"Filesystem baseline requires Root path and Output .satsnap path." status:"Filesystem input required"];return;}
  const bool hash=[_fsHash state]==NSControlStateValueOn;_busy=YES;_cancel=support_assist::CancellationSource{};auto token=_cancel.token();__weak SATPortableDelegate* weakSelf=self;
  dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
    std::string body,status;
    if(!compare){
      auto store=support_assist::SnapshotStore::create(output);
      if(!store.ok()){body="Unable to create baseline: "+support_assist::describe_error(store.error());status="Filesystem Change failed";}
      else{
        support_assist::FilesystemScanOptions options; options.root=root; options.capture_streams=false; options.capture_file_identity=false; options.hydrate_cloud_files=false; options.hash_mode=hash?support_assist::HashMode::all:support_assist::HashMode::none;
        auto metadata=support_assist::make_snapshot_metadata(support_assist::SnapshotKind::filesystem,root,hash?"{\"hash\":\"all\"}":"{\"hash\":\"none\"}");
        auto begin=store.value().begin_snapshot(metadata);
        if(!begin.ok()){body="Unable to begin baseline: "+support_assist::describe_error(begin.error());status="Filesystem Change failed";}
        else{
          support_assist::FilesystemScanConfig config;config.snapshot_id=metadata.id;config.root_path=root;config.hash_mode=hash?"all":"none";config.capture_streams=false;config.capture_file_identity=false;config.hydrate_cloud_files=false;static_cast<void>(store.value().set_filesystem_scan_config(config));
          auto scan=support_assist::scan_filesystem(store.value(),metadata.id,options,token,{});
          if(!scan.ok()){static_cast<void>(store.value().finish_snapshot(metadata.id,support_assist::SnapshotState::failed,0,1));body="Filesystem baseline failed: "+support_assist::describe_error(scan.error());status="Filesystem Change failed";}
          else{const auto state=scan.value().cancelled?support_assist::SnapshotState::cancelled:support_assist::SnapshotState::complete;static_cast<void>(store.value().finish_snapshot(metadata.id,state,scan.value().objects,scan.value().errors));std::ostringstream out;out<<"Filesystem baseline "<<(state==support_assist::SnapshotState::complete?"complete":"cancelled")<<"\n\nSnapshot: "<<output<<"\nSnapshot ID: "<<metadata.id<<"\nObjects: "<<scan.value().objects<<"\nErrors: "<<scan.value().errors<<"\nHash mode: "<<(hash?"SHA-256 (all files)":"None");body=out.str();status="Filesystem Change complete";append_macos_activity("Filesystem Change","Baseline captured",output);}
        }
      }
    } else {
      auto before=support_assist::SnapshotStore::open(baseline,true), after=support_assist::SnapshotStore::open(other,true);
      if(!before.ok()||!after.ok()){body="Unable to open one or both filesystem snapshots.";status="Filesystem Change failed";}
      else{auto beforeId=before.value().latest_complete_snapshot_id(),afterId=after.value().latest_complete_snapshot_id();if(!beforeId.ok()||!afterId.ok()){body="Unable to resolve snapshot IDs for comparison.";status="Filesystem Change failed";}else{std::ostringstream report;std::uint64_t shown=0;auto result=support_assist::compare_filesystem(baseline,beforeId.value(),other,afterId.value(),{},[&](const support_assist::DiffRecord& diff){if(shown++<500U)report<<support_assist::to_string(diff.kind)<<"\\t"<<(diff.new_path.empty()?diff.old_path:diff.new_path)<<"\\n";return support_assist::Status::success();});if(!result.ok()){body="Filesystem compare failed: "+support_assist::describe_error(result.error());status="Filesystem Change failed";}else{std::ostringstream done;done<<"Filesystem comparison complete\n\nDifferences: "<<result.value()<<"\n\n"<<report.str();if(shown>500U)done<<"\n... detail view bounded to first 500 differences; snapshots remain intact.\n";body=done.str();status="Filesystem Change complete";append_macos_activity("Filesystem Change","Comparison complete",std::to_string(result.value())+" differences");}}}
    }
    dispatch_async(dispatch_get_main_queue(), ^{SATPortableDelegate* strong=weakSelf;if(strong){strong->_busy=NO;[strong setBody:body status:status];}});
  });
}

- (void)sqlRunClicked:(id)sender { (void)sender; [self runSqlPermissionDiagnostic:YES]; }

- (void)filesystemCaptureClicked:(id)sender { (void)sender; [self runFilesystemOperation:NO]; }
- (void)filesystemCompareClicked:(id)sender { (void)sender; [self runFilesystemOperation:YES]; }

- (void)browseReviewSource:(id)sender {
  (void)sender;
  if (_busy) return;
  NSOpenPanel* panel = [NSOpenPanel openPanel];
  [panel setCanChooseFiles:YES];
  [panel setCanChooseDirectories:YES];
  [panel setAllowsMultipleSelection:NO];
  if ([panel runModal] == NSModalResponseOK) {
    NSURL* url = [[panel URLs] firstObject];
    if (url != nil) [_reviewSource setStringValue:[url path]];
  }
}

- (void)detectLocalReviewSources:(id)sender {
  (void)sender;
  if (_busy) return;
  const auto sources = detected_local_log_sources();
  if (sources.empty()) {
    [self setBody:"No local Veeam product log roots were detected on this Mac. Choose a bundle, directory or file manually." status:"No local review source"];
    return;
  }
  std::ostringstream joined;
  for (std::size_t index=0; index<sources.size(); ++index) {
    if (index != 0U) joined << ';';
    joined << sources[index].string();
  }
  [_reviewSource setStringValue:ns_string(joined.str())];
  [self setBody:"Detected local Veeam product log roots were added to the review source field." status:"Local sources detected"];
}

- (void)openExistingCase:(id)sender {
  (void)sender;
  if (_busy) return;
  const std::string root=[[_caseParent stringValue] UTF8String];
  auto opened=support_assist::open_case_workspace(root);
  if (!opened.ok()) { [self setBody:"Could not open case:\n" + support_assist::describe_error(opened.error()) status:"Case open failed"]; return; }
  support_assist::gui::register_portable_case(_caseCatalog,std::move(opened.value()),portable_state_directory());
  [self syncActiveCase];
  append_macos_activity("Case Dashboard","Case registered/activated",_activeCaseRoot);
  [self showPage:PageCases];
}

- (void)useNoCase:(id)sender {
  (void)sender;
  if (_busy) return;
  support_assist::gui::set_portable_active_case(_caseCatalog,-1,portable_state_directory());
  [self syncActiveCase];
  append_macos_activity("Case Dashboard","No Case selected","");
  [self setBody:"No Case is active. Log Review remains available for quick review without persisted case state." status:"No Case active"];
}

- (void)loadSavedCaseReview:(id)sender {
  (void)sender;
  const auto* workspace=_caseCatalog.active();
  if(workspace==nullptr){[self setBody:"Select an active case first." status:"No active case"];return;}
  auto review=support_assist::load_case_review_model(*workspace);
  if(!review.ok()){[self setBody:"No saved structured review exists in the active case yet." status:"No saved review"];return;}
  [self setBody:format_portable_review_summary(review.value()) status:"Saved review loaded"];
  append_macos_activity("Case Dashboard","Loaded saved review",workspace->case_id);
}

- (void)openCaseNote:(id)sender {
  (void)sender;
  const auto* workspace=_caseCatalog.active();
  if(workspace==nullptr){[self setBody:"Select an active case before opening Note Review." status:"No active case"];return;}
  auto review=support_assist::load_case_review_model(*workspace);
  if(!review.ok()){[self setBody:"The active case does not contain a saved structured review yet." status:"No saved review"];return;}
  std::string note=support_assist::build_veeam_ticket_note(review.value(),{}, {},"Review selected case evidence and findings");
  auto bookmarks=support_assist::load_case_evidence_bookmarks(*workspace);
  if(bookmarks.ok()){
    note+="\nSelected Evidence:\n"; std::size_t shown=0;
    for(const auto& item:bookmarks.value()){
      if(!item.include_in_note)continue;
      note+="- "+(item.title.empty()?item.scope_key:item.title)+" | "+item.source_path+"\n";
      if(++shown>=40U){note+="- ... additional selected evidence retained in case\n";break;}
    }
  }
  [self setBody:note status:"Note Review"];
  append_macos_activity("Case Dashboard","Opened Note Review",workspace->case_id);
}

- (void)createCasePdf:(id)sender {
  (void)sender;
  const auto* workspace=_caseCatalog.active();
  if(workspace==nullptr){[self setBody:"Select an active case before creating a PDF report." status:"No active case"];return;}
  auto review=support_assist::load_case_review_model(*workspace);
  support_assist::PdfReportDocument document;
  document.title="Support Assist Tool Case Report";
  document.subtitle=workspace->case_id+(workspace->title.empty()?std::string{}:": "+workspace->title);
  support_assist::PdfReportSection summary; summary.heading="Case Summary";
  summary.lines={"Engineer: "+workspace->engineer,"Generated: "+support_assist::utc_now_iso8601()};
  if(review.ok()){
    std::size_t errors=0,warnings=0; for(const auto& i:review.value().incidents){if(i.severity=="error")++errors;else if(i.severity=="warning")++warnings;}
    summary.lines.push_back("Systems/components: "+std::to_string(review.value().machines.size()));
    summary.lines.push_back("Jobs/activities/runs: "+std::to_string(review.value().job_sessions.size()));
    summary.lines.push_back("Findings: "+std::to_string(errors)+" errors / "+std::to_string(warnings)+" warnings");
  } else summary.lines.push_back("Review: no saved structured review");
  document.sections.push_back(std::move(summary));
  const auto output=workspace->reports/(workspace->case_id+"-case-report.pdf");
  auto status=support_assist::write_pdf_report(output,document);
  if(!status.ok()) [self setBody:"PDF report failed:\n"+support_assist::describe_error(status.error()) status:"PDF failed"];
  else { [self setBody:"Case PDF created:\n"+output.string() status:"PDF report created"]; append_macos_activity("Case Dashboard","PDF report created",output.string()); }
}

- (void)deleteActiveCase:(id)sender {
  (void)sender;
  const auto* workspace=_caseCatalog.active();
  if(workspace==nullptr){[self setBody:"Select an active case before deleting a workspace." status:"No active case"];return;}
  if(!_caseDeleteArmed){_caseDeleteArmed=YES;[_caseDelete setTitle:@"Confirm Delete"];[self setBody:"Delete is armed for case "+workspace->case_id+". Click Confirm Delete to permanently remove the case workspace and its evidence." status:"Delete confirmation required"];return;}
  const auto root=workspace->root; std::error_code error; std::filesystem::remove_all(root,error);
  _caseDeleteArmed=NO; [_caseDelete setTitle:@"Delete Active"];
  if(error){[self setBody:"Could not delete case workspace:\n"+error.message() status:"Delete failed"];return;}
  _caseCatalog.cases.erase(_caseCatalog.cases.begin()+_caseCatalog.active_index); _caseCatalog.active_index=-1;
  support_assist::gui::save_portable_case_catalog(_caseCatalog,portable_state_directory()); [self syncActiveCase];
  append_macos_activity("Case Dashboard","Case deleted",root.string()); [self showPage:PageCases];
}

- (void)actionClicked:(id)sender {
  (void)sender;
  if (_busy) return;
  if (_page == PageHealth) {
    [self setBody:health_text() status:"Health snapshot refreshed"];
  } else if (_page == PageEnvironment) {
    const std::string report=macos_host_diagnostics_text(); write_portable_tool_output("Environment-Review",report); append_macos_activity("Environment Review","Completed","macOS environment snapshot");
    [self setBody:report status:"Environment Review refreshed"];
  } else if (_page == PageCases) {
    const std::string parent=[[_caseParent stringValue] UTF8String];
    const std::string caseId=[[_caseId stringValue] UTF8String];
    if (parent.empty() || caseId.empty()) { [self setBody:"Parent directory and Case ID are required to create a case." status:"Case input required"]; return; }
    support_assist::CaseWorkspaceOptions options; options.parent_directory=parent; options.case_id=caseId;
    options.title=[[_caseTitle stringValue] UTF8String]; options.engineer=[[_caseEngineer stringValue] UTF8String];
    auto created=support_assist::create_case_workspace(options);
    if(!created.ok()){[self setBody:"Case creation failed:\n"+support_assist::describe_error(created.error()) status:"Case creation failed"];return;}
    support_assist::gui::register_portable_case(_caseCatalog,std::move(created.value()),portable_state_directory());
    [self syncActiveCase]; append_macos_activity("Case Dashboard","Case created",_activeCaseRoot);
    [self showPage:PageCases];
  } else if (_page == PageLogReview) {
    std::string sourceText=[[_reviewSource stringValue] UTF8String];
    std::vector<std::filesystem::path> sources; std::size_t start=0;
    while(start<=sourceText.size()){const auto end=sourceText.find(';',start);std::string item=sourceText.substr(start,end==std::string::npos?std::string::npos:end-start);if(!item.empty())sources.emplace_back(item);if(end==std::string::npos)break;start=end+1U;}
    if(sources.empty()){[self setBody:"Choose a log bundle, directory or file, or use Detect Local Logs." status:"No review source"];return;}
    std::string caseRoot=[[_reviewCase stringValue] UTF8String]; if(caseRoot.empty())caseRoot=_activeCaseRoot;
    const bool full=[_reviewFullScan state]==NSControlStateValueOn;
    _busy=YES; _cancel=support_assist::CancellationSource{}; [_action setEnabled:NO]; [_cancelButton setHidden:NO];
    support_assist::CancellationToken token=_cancel.token(); __weak SATPortableDelegate* weakSelf=self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
      support_assist::VeeamLogReviewOptions options; options.sources=sources; options.profile=support_assist::VeeamReviewProfile::automatic; options.fast_index_first=!full;
      std::optional<support_assist::CaseWorkspace> workspace;
      if(!caseRoot.empty()){auto opened=support_assist::open_case_workspace(caseRoot);if(!opened.ok()){const std::string message="Could not open case:\n"+support_assist::describe_error(opened.error());dispatch_async(dispatch_get_main_queue(),^{SATPortableDelegate* strongSelf=weakSelf;if(strongSelf!=nil){[strongSelf setBody:message status:"Case open failed"];strongSelf->_busy=NO;[strongSelf->_action setEnabled:YES];[strongSelf->_cancelButton setHidden:YES];}});return;}workspace=opened.value();options.output_path=workspace->parsed/"reports";options.parser_cache_directory=workspace->parser_cache;}else options.output_path=default_collection_root()/"Review-Reports";
      auto review=support_assist::review_veeam_logs(options,token);
      std::string body; std::string status;
      if(!review.ok()){body="Log Review failed:\n"+support_assist::describe_error(review.error());status="Review failed";}
      else{body=format_portable_review_summary(review.value());status=token.is_cancelled()?"Review cancelled":"Review complete";if(workspace){const auto model=support_assist::save_case_review_model(*workspace,review.value());support_assist::CaseReviewState state;state.profile=support_assist::to_string(review.value().profile_used);state.fast_index=review.value().fast_index_used;state.updated_utc=support_assist::utc_now_iso8601();for(const auto&src:review.value().input_sources)state.sources.push_back(src.string());for(const auto&bundle:review.value().bundles){support_assist::CaseReviewSource source;source.path=bundle.source_path;source.requested_profile="automatic";source.detected_profile=bundle.manifest_profile;source.product_type=bundle.product_type;source.product_version=bundle.product_version;source.source_owner=bundle.primary_machine_name;state.source_profiles.push_back(std::move(source));}const auto saved=support_assist::save_case_review_state(*workspace,std::move(state));body+="\nCase persistence\n  Review model: "+std::string(model.ok()?"saved":"FAILED")+"\n  Review state: "+std::string(saved.ok()?"saved":"FAILED")+"\n  Case: "+workspace->root.string()+"\n";}else body+="\nReview context: No Case (quick review; case state was not persisted).\n";write_portable_tool_output("Unified-Log-Review",body);append_macos_activity("Unified Log Review",token.is_cancelled()?"Cancelled":"Completed",caseRoot.empty()?"No Case":caseRoot);}
      dispatch_async(dispatch_get_main_queue(),^{SATPortableDelegate* strongSelf=weakSelf;if(strongSelf!=nil){[strongSelf setBody:body status:status];strongSelf->_busy=NO;[strongSelf->_action setEnabled:YES];[strongSelf->_cancelButton setHidden:YES];}});
    });
  } else if (_page == PageTools) {
    const NSInteger index=[_toolCategory indexOfSelectedItem];
    const auto capabilities=support_assist::gui::macos_capability_catalog(support_assist::ssh_available(),portable_native_odbc_available());
    if(index<0||static_cast<std::size_t>(index)>=capabilities.size())return; const auto& c=capabilities[static_cast<std::size_t>(index)];
    if(c.state!=support_assist::gui::PortableCapabilityState::available){[self setBody:c.name+": "+support_assist::gui::capability_state_label(c.state,support_assist::gui::PortablePlatform::macos)+"\n\n"+c.detail status:"Capability information"];return;}
    if(c.id=="collection")[self showPage:PageGather]; else if(c.id=="guided")[self showPage:PageGuided]; else if(c.id=="network")[self showPage:PageNetwork];
    else if(c.id=="sql")[self showPage:PageSql]; else if(c.id=="filesystem")[self showPage:PageFilesystem]; else if(c.id=="host")[self showPage:PageHost];
    else if(c.id=="ssh"){[self showPage:PageExplorer];[_explorerTab selectItemAtIndex:1];[self explorerTabChanged:nil];}
  } else if (_page == PageSql) {
    [self runSqlPermissionDiagnostic:NO];
  } else if (_page == PageHost) {
    const std::string report=macos_host_diagnostics_text(); write_portable_tool_output("macOS-Host-Diagnostics",report); append_macos_activity("macOS Host Diagnostics","Completed",""); [self setBody:report status:"Host diagnostics refreshed"];
  } else if (_page == PageThirdParty) {
    [self setBody:macos_third_party_text() status:"Integrations refreshed"];
  } else if (_page == PageDiagnostics) {
    [self setBody:macos_diagnostics_text(_executionHostEnabled) status:"SAT Self-Test refreshed"];
  } else if (_page == PageNetwork || _page == PageGuided) {
    const std::string operation=[[_networkOperation titleOfSelectedItem] UTF8String];
    if (operation.find("No applicable") != std::string::npos) { [self setBody:"No applicable Guided Diagnostic is available for the detected local products." status:"Not applicable"]; return; }
    const std::string host=[[_networkHost stringValue] UTF8String];
    const std::string portText=[[_networkPort stringValue] UTF8String];
    const std::string source=[[_networkSource stringValue] UTF8String];
    const std::string sni=[[_networkSni stringValue] UTF8String];
    const std::string fingerprint=[[_networkFingerprint stringValue] UTF8String];
    unsigned long parsedPort=0; try { parsedPort=std::stoul(portText); } catch (...) { parsedPort=0; }
    if (parsedPort==0 || parsedPort>65535UL) { [self setBody:"Port must be 1-65535." status:"Invalid input"]; return; }
    const std::uint16_t port=static_cast<std::uint16_t>(parsedPort);
    const bool all=[_networkAllInterfaces state]==NSControlStateValueOn;
    const bool payload=[_networkPayload state]==NSControlStateValueOn;
    const bool compare=[_networkTlsCompare state]==NSControlStateValueOn;
    _busy=YES; _cancel=support_assist::CancellationSource{}; [_action setEnabled:NO]; [_cancelButton setHidden:NO];
    support_assist::CancellationToken token=_cancel.token(); __weak SATPortableDelegate* weakSelf=self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0), ^{
      std::ostringstream out; bool ok=true;
      if (operation=="Network Interfaces") {
        auto result=support_assist::enumerate_network_interfaces();
        if (!result.ok()) { out << support_assist::describe_error(result.error()); ok=false; }
        else for (const auto& item:result.value()) out << item.name << " | " << item.address << '/' << item.prefix_length << " | " << item.address_family << (item.gateway.empty()?"":" | gateway "+item.gateway) << "\n";
      } else if (operation=="TCP Connectivity Test" || operation=="Managed Server Connectivity") {
        support_assist::TcpPortTestOptions options; options.host=host; options.port=port; options.source_address=source; options.sat_payload_bytes=payload?50ULL*1024ULL*1024ULL:0ULL;
        if (all) { auto result=support_assist::test_tcp_across_interfaces(options,token,{},false); if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;} else for(const auto& item:result.value()){out<<item.interface.name<<" ["<<item.interface.address<<"]\n";for(const auto&a:item.test.attempts)out<<"  "<<a.address<<" | "<<(a.connected?"CONNECTED":"FAILED")<<" | "<<a.message<<(a.sat_payload_validated?" | 50 MiB payload VERIFIED":"")<<"\n";} }
        else { auto result=support_assist::test_tcp_port(options,token); if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;} else for(const auto&a:result.value().attempts)out<<a.address<<" | "<<(a.connected?"CONNECTED":"FAILED")<<" | "<<a.message<<(a.sat_payload_validated?" | payload VERIFIED":"")<<"\n"; }
      } else if (operation=="TCP Listener") {
        support_assist::TcpListenerOptions options; options.port=port; options.duration=std::chrono::seconds(30); options.accept_multiple=true;
        auto result=support_assist::listen_tcp(options,token); if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;} else for(const auto&c:result.value().connections)out<<c.remote_address<<':'<<c.remote_port<<" -> "<<c.local_address<<':'<<c.local_port<<(c.sat_test_id.empty()?"":" | Test ID "+c.sat_test_id)<<(c.sat_payload_validated?" | payload VERIFIED":"")<<"\n";
      } else if (operation=="UDP Connectivity Test") {
        support_assist::UdpPortTestOptions options; options.host=host; options.port=port; options.source_address=source; options.mode=support_assist::UdpProbeMode::sat_listener;
        if (all) {
          auto result=support_assist::test_udp_across_interfaces(options,token,{},false);
          if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;}
          else for(const auto& item:result.value()){
            out<<item.interface.name<<" ["<<item.interface.address<<"]\n";
            for(const auto&a:item.test.attempts)out<<"  "<<a.address<<" | "<<(a.sat_acknowledged?"VERIFIED":"NO ACK / INDETERMINATE")<<" | "<<a.message<<(a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id)<<"\n";
          }
        } else {
          auto result=support_assist::test_udp_port(options,token); if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;} else for(const auto&a:result.value().attempts)out<<a.address<<" | "<<(a.sat_acknowledged?"VERIFIED":"NO ACK / INDETERMINATE")<<" | "<<a.message<<(a.sat_test_id.empty()?"":" | Test ID "+a.sat_test_id)<<"\n";
        }
      } else if (operation=="UDP Listener") {
        support_assist::UdpListenerOptions options; options.port=port; options.duration=std::chrono::seconds(30);
        auto result=support_assist::listen_udp(options,token); if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;} else for(const auto&d:result.value().datagrams)out<<d.remote_address<<':'<<d.remote_port<<" -> "<<d.local_address<<':'<<d.local_port<<(d.sat_ack_sent?" | ACK sent":"")<<"\n";
      } else if (operation=="Throughput Client" || operation=="Throughput Server") {
        support_assist::TcpThroughputOptions options; options.server=operation=="Throughput Server"; options.host=host; options.port=port; options.transfer_bytes=1024ULL*1024ULL*1024ULL;
        auto result=support_assist::run_tcp_throughput(options,token);
        if(!result.ok()){out<<support_assist::describe_error(result.error());ok=false;}
        else{const auto& value=result.value();out<<(value.server?"SERVER":"CLIENT")<<" | peer "<<value.peer_address<<" | port "<<value.port<<" | bytes "<<value.transferred_bytes<<" | "<<support_assist::format_transfer_rate(value.bits_per_second)<<" | protocol "<<(value.protocol_verified?"VERIFIED":"UNVERIFIED")<<"\n";if(value.cancelled)out<<"Cancelled\n";}
      } else {
        const auto writeTls=[&](std::string_view label,const support_assist::TlsProbeResult&v,std::string_view interfaceLabel){out<<label;if(!interfaceLabel.empty())out<<" | "<<interfaceLabel;out<<" | "<<(v.handshake_completed?"COMPLETE":"FINDING")<<" | "<<v.local_address<<" -> "<<v.connected_address<<" | "<<v.negotiated_version<<" | "<<v.negotiated_cipher_suite<<"\n  Subject: "<<v.certificate.subject<<"\n  SHA-256: "<<v.certificate.sha256_fingerprint<<"\n  Expected: "<<(v.certificate.expected_fingerprint_provided?(v.certificate.expected_fingerprint_matches?"VERIFIED":"MISMATCH"):"OBSERVED ONLY")<<"\n";if(!v.handshake_completed)out<<"  Failure: "<<v.failure_stage<<" | "<<v.failure_reason<<"\n";};
        const auto runTls=[&](support_assist::TlsProbeVersion version,std::string_view label){support_assist::TlsProbeOptions options;options.host=host;options.port=port;options.source_address=source;options.server_name=sni;options.expected_fingerprint=fingerprint;options.version=version;if(all){auto matrix=support_assist::test_tls_across_interfaces(options,token,{},false);if(!matrix.ok()){out<<label<<" | "<<support_assist::describe_error(matrix.error())<<"\n";ok=false;return;}for(const auto&item:matrix.value())writeTls(label,item.test,item.interface.name+" ["+item.interface.address+"]");return;}auto result=support_assist::test_tls_handshake(options,token);if(!result.ok()){out<<label<<" | "<<support_assist::describe_error(result.error())<<"\n";ok=false;return;}writeTls(label,result.value(),{});};
        if(compare){runTls(support_assist::TlsProbeVersion::tls12_only,"TLS 1.2 only");runTls(support_assist::TlsProbeVersion::tls13_only,"TLS 1.3 only");}else runTls(support_assist::TlsProbeVersion::automatic,"TLS automatic");
        out << "Current Veeam cipher/protocol reference: https://helpcenter.veeam.com/docs/vbr/userguide/cipher_suites_protocols.html?ver=13\nSAT never reads/copies a Veeam private key.\n";
      }
      const std::string text=out.str(); write_portable_tool_output(operation,text); append_macos_activity(operation,ok?"Completed":"Completed with finding/error",host);
      dispatch_async(dispatch_get_main_queue(), ^{ SATPortableDelegate* strongSelf=weakSelf; if(strongSelf!=nil){[strongSelf setBody:text status:(ok?"Completed":"Completed with finding/error")];strongSelf->_busy=NO;[strongSelf->_action setEnabled:YES];[strongSelf->_cancelButton setHidden:YES];} });
    });
  } else if (_page == PageGather) {
    _busy = YES;
    _cancel = support_assist::CancellationSource{};
    const std::vector<std::string> selectedProducts = [self selectedGatherProductIds];
    const bool includeThirdParty = [_thirdPartyCheck state] == NSControlStateValueOn;
    const std::vector<std::filesystem::path> markedPaths(_markedPaths.begin(),_markedPaths.end());
    [_action setEnabled:NO]; [_refreshProducts setEnabled:NO]; [_thirdPartyCheck setEnabled:NO];
    for (NSButton* button in _productChecks) [button setEnabled:NO];
    [_cancelButton setHidden:NO];
    [self setBody:"Starting universal support collection..." status:"Gathering support bundle"];
    support_assist::CancellationToken token = _cancel.token();
    __weak SATPortableDelegate* weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
      support_assist::UniversalCollectionOptions options;
      options.output_root = default_collection_root();
      options.tool_output_directory = portable_tool_output_directory();
      options.include_tool_output_logs = true;
      options.cleanup_tool_output_after_archive = true;
      options.create_archive = true;
      options.include_platform_context = true;
      options.include_third_party_error_logs = includeThirdParty;
      options.product_selection_explicit = true;
      options.selected_product_ids = selectedProducts;
      options.additional_sources = markedPaths;
      auto result = support_assist::collect_universal_support_bundle(options, token);
      std::string body;
      std::string status;
      if (result.ok()) {
        std::ostringstream text;
        text << "Universal support collection completed.\n\nCollection:\n  " << result.value().logs.collection_directory.string()
             << "\nArchive:\n  " << (result.value().logs.archive_path.empty()?"(archive unavailable)":result.value().logs.archive_path.string())
             << "\nSelected/detected Veeam products/roles: " << result.value().detected_products.size()
             << "\nSanitized third-party error logs: " << result.value().third_party_files.size();
        body = text.str(); status = token.is_cancelled()?"Collection cancelled":"Collection complete"; append_macos_activity("Universal Log Collection",token.is_cancelled()?"Cancelled":"Completed",result.value().logs.archive_path.string());
      } else { body = "Collection failed:\n" + support_assist::describe_error(result.error()); status = "Collection failed"; append_macos_activity("Universal Log Collection","Failed",result.error().message); }
      dispatch_async(dispatch_get_main_queue(), ^{
        SATPortableDelegate* strongSelf = weakSelf;
        if (strongSelf != nil) {
          [strongSelf setBody:body status:status];
          strongSelf->_busy = NO;
          [strongSelf->_action setEnabled:YES];
          [strongSelf->_refreshProducts setEnabled:YES];
          [strongSelf->_thirdPartyCheck setEnabled:YES];
          for (NSButton* button in strongSelf->_productChecks) [button setEnabled:YES];
          [strongSelf->_cancelButton setHidden:YES];
        }
      });
    });
  }
}

- (void)cancelClicked:(id)sender { (void)sender; if (_busy) { _cancel.cancel(); [_status setStringValue:@"Cancellation requested"]; } }

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  (void)notification;
  [NSApp setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua]];
  NSRect frame=NSMakeRect(0,0,1280,820);
  _window=[[NSWindow alloc] initWithContentRect:frame styleMask:(NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable|NSWindowStyleMaskMiniaturizable) backing:NSBackingStoreBuffered defer:NO];
  const std::string windowTitle=std::string(support_assist::kProductName)+" "+std::string(support_assist::kVersion);
  [_window setTitle:ns_string(windowTitle)]; [_window center]; NSView* content=[_window contentView];

  _navButtons=[[NSMutableArray alloc] init]; _productChecks=[[NSMutableArray alloc] init]; _caseDeleteArmed=NO; _sshTrusted=false;
  _executionHostEnabled=!portable_prior_sat_state();

  NSTextField* identity=[[NSTextField alloc] initWithFrame:NSMakeRect(18,780,200,24)];
  [identity setStringValue:ns_string(std::string(support_assist::kProductName) + " " + std::string(support_assist::kVersion))]; [identity setEditable:NO]; [identity setBordered:NO]; [identity setDrawsBackground:NO]; [identity setTextColor:[NSColor labelColor]]; [content addSubview:identity];
  _roleButton=[[NSButton alloc] initWithFrame:NSMakeRect(18,744,190,28)]; [_roleButton setTitle:_executionHostEnabled?@"Customer / Lab":@"Engineer Review"]; [_roleButton setTarget:self]; [_roleButton setAction:@selector(roleClicked:)]; [content addSubview:_roleButton];
  NSTextField* caseLabel=[[NSTextField alloc] initWithFrame:NSMakeRect(230,780,82,22)]; [caseLabel setStringValue:@"Active Case"]; [caseLabel setEditable:NO]; [caseLabel setBordered:NO]; [caseLabel setDrawsBackground:NO]; [content addSubview:caseLabel];
  _activeCasePopup=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(312,776,520,28) pullsDown:NO]; [_activeCasePopup setTarget:self]; [_activeCasePopup setAction:@selector(activeCaseChanged:)]; [content addSubview:_activeCasePopup];

  _scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(230,80,1030,680)]; [_scroll setHasVerticalScroller:YES]; [_scroll setHasHorizontalScroller:YES];
  _text=[[NSTextView alloc] initWithFrame:[[_scroll contentView] bounds]]; [_text setEditable:NO]; [_text setFont:[NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]]; [_text setTextColor:[NSColor textColor]]; [_text setBackgroundColor:[NSColor textBackgroundColor]]; [_scroll setDocumentView:_text]; [content addSubview:_scroll];

  _gatherHeading=[[NSTextField alloc] initWithFrame:NSMakeRect(245,700,600,24)]; [_gatherHeading setStringValue:@"Veeam products / roles to collect"]; [_gatherHeading setEditable:NO]; [_gatherHeading setBordered:NO]; [_gatherHeading setDrawsBackground:NO]; [content addSubview:_gatherHeading];
  _refreshProducts=[[NSButton alloc] initWithFrame:NSMakeRect(450,28,160,36)]; [_refreshProducts setTitle:@"Refresh Detection"]; [_refreshProducts setTarget:self]; [_refreshProducts setAction:@selector(refreshProductsClicked:)]; [content addSubview:_refreshProducts];
  _thirdPartyCheck=[[NSButton alloc] initWithFrame:NSMakeRect(245,600,650,24)]; [_thirdPartyCheck setButtonType:NSSwitchButton]; [_thirdPartyCheck setTitle:@"Include sanitized third-party operational/error logs"]; [_thirdPartyCheck setState:NSControlStateValueOn]; [content addSubview:_thirdPartyCheck];

  _networkOperation=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(245,700,280,28) pullsDown:NO]; [content addSubview:_networkOperation];
  _networkHost=[[NSTextField alloc] initWithFrame:NSMakeRect(535,700,220,26)]; [_networkHost setPlaceholderString:@"Target host/IP"]; [_networkHost setStringValue:@"127.0.0.1"]; [content addSubview:_networkHost];
  _networkPort=[[NSTextField alloc] initWithFrame:NSMakeRect(765,700,90,26)]; [_networkPort setPlaceholderString:@"Port"]; [_networkPort setStringValue:@"2500"]; [content addSubview:_networkPort];
  _networkSource=[[NSTextField alloc] initWithFrame:NSMakeRect(865,700,250,26)]; [_networkSource setPlaceholderString:@"Source IP (optional)"]; [content addSubview:_networkSource];
  _networkSni=[[NSTextField alloc] initWithFrame:NSMakeRect(245,662,280,26)]; [_networkSni setPlaceholderString:@"TLS SNI/FQDN (optional)"]; [content addSubview:_networkSni];
  _networkFingerprint=[[NSTextField alloc] initWithFrame:NSMakeRect(535,662,400,26)]; [_networkFingerprint setPlaceholderString:@"Expected public cert SHA-1/SHA-256 (optional)"]; [content addSubview:_networkFingerprint];
  _networkAllInterfaces=[[NSButton alloc] initWithFrame:NSMakeRect(245,628,210,24)]; [_networkAllInterfaces setButtonType:NSSwitchButton]; [_networkAllInterfaces setTitle:@"Test all usable interfaces"]; [content addSubview:_networkAllInterfaces];
  _networkPayload=[[NSButton alloc] initWithFrame:NSMakeRect(465,628,220,24)]; [_networkPayload setButtonType:NSSwitchButton]; [_networkPayload setTitle:@"50 MiB SAT payload"]; [_networkPayload setState:NSControlStateValueOn]; [content addSubview:_networkPayload];
  _networkTlsCompare=[[NSButton alloc] initWithFrame:NSMakeRect(695,628,220,24)]; [_networkTlsCompare setButtonType:NSSwitchButton]; [_networkTlsCompare setTitle:@"Compare TLS 1.2 / 1.3"]; [content addSubview:_networkTlsCompare];

  _reviewSource=[[NSTextField alloc] initWithFrame:NSMakeRect(245,700,650,26)]; [_reviewSource setPlaceholderString:@"Log bundle / directory / file; semicolon separates multiple sources"]; [content addSubview:_reviewSource];
  _reviewCase=[[NSTextField alloc] initWithFrame:NSMakeRect(245,662,650,26)]; [_reviewCase setPlaceholderString:@"Case root (optional; blank = Active Case / No Case)"]; [content addSubview:_reviewCase];
  _reviewFullScan=[[NSButton alloc] initWithFrame:NSMakeRect(910,662,150,24)]; [_reviewFullScan setButtonType:NSSwitchButton]; [_reviewFullScan setTitle:@"Full Review"]; [content addSubview:_reviewFullScan];
  _reviewBrowse=[[NSButton alloc] initWithFrame:NSMakeRect(905,700,110,26)]; [_reviewBrowse setTitle:@"Browse..."]; [_reviewBrowse setTarget:self]; [_reviewBrowse setAction:@selector(browseReviewSource:)]; [content addSubview:_reviewBrowse];
  _reviewDetectLocal=[[NSButton alloc] initWithFrame:NSMakeRect(1025,700,120,26)]; [_reviewDetectLocal setTitle:@"Detect Local"]; [_reviewDetectLocal setTarget:self]; [_reviewDetectLocal setAction:@selector(detectLocalReviewSources:)]; [content addSubview:_reviewDetectLocal];

  _caseParent=[[NSTextField alloc] initWithFrame:NSMakeRect(245,700,520,26)]; [_caseParent setPlaceholderString:@"Parent directory (create) or existing case root (register)"]; [content addSubview:_caseParent];
  _caseId=[[NSTextField alloc] initWithFrame:NSMakeRect(775,700,180,26)]; [_caseId setPlaceholderString:@"Case ID"]; [content addSubview:_caseId];
  _caseTitle=[[NSTextField alloc] initWithFrame:NSMakeRect(245,662,520,26)]; [_caseTitle setPlaceholderString:@"Case title (optional)"]; [content addSubview:_caseTitle];
  _caseEngineer=[[NSTextField alloc] initWithFrame:NSMakeRect(775,662,280,26)]; [_caseEngineer setPlaceholderString:@"Engineer (optional)"]; [content addSubview:_caseEngineer];
  _caseOpen=[[NSButton alloc] initWithFrame:NSMakeRect(450,28,130,36)]; [_caseOpen setTitle:@"Register Case"]; [_caseOpen setTarget:self]; [_caseOpen setAction:@selector(openExistingCase:)]; [content addSubview:_caseOpen];
  _caseNoCase=[[NSButton alloc] initWithFrame:NSMakeRect(590,28,105,36)]; [_caseNoCase setTitle:@"Use No Case"]; [_caseNoCase setTarget:self]; [_caseNoCase setAction:@selector(useNoCase:)]; [content addSubview:_caseNoCase];
  _caseLoadSaved=[[NSButton alloc] initWithFrame:NSMakeRect(705,28,130,36)]; [_caseLoadSaved setTitle:@"Load Saved Review"]; [_caseLoadSaved setTarget:self]; [_caseLoadSaved setAction:@selector(loadSavedCaseReview:)]; [content addSubview:_caseLoadSaved];
  _caseNote=[[NSButton alloc] initWithFrame:NSMakeRect(845,28,95,36)]; [_caseNote setTitle:@"Note Review"]; [_caseNote setTarget:self]; [_caseNote setAction:@selector(openCaseNote:)]; [content addSubview:_caseNote];
  _casePdf=[[NSButton alloc] initWithFrame:NSMakeRect(950,28,95,36)]; [_casePdf setTitle:@"PDF Master"]; [_casePdf setTarget:self]; [_casePdf setAction:@selector(createCasePdf:)]; [content addSubview:_casePdf];
  _caseDelete=[[NSButton alloc] initWithFrame:NSMakeRect(1055,28,120,36)]; [_caseDelete setTitle:@"Delete Active"]; [_caseDelete setTarget:self]; [_caseDelete setAction:@selector(deleteActiveCase:)]; [content addSubview:_caseDelete];

  _toolCategory=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(245,700,600,28) pullsDown:NO]; [content addSubview:_toolCategory];

  _explorerTab=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(245,700,230,28) pullsDown:NO]; [_explorerTab addItemsWithTitles:@[@"Local",@"SSH / SFTP",@"Windows Remote",@"Remote Console"]]; [_explorerTab setTarget:self]; [_explorerTab setAction:@selector(explorerTabChanged:)]; [content addSubview:_explorerTab];
  _explorerPath=[[NSTextField alloc] initWithFrame:NSMakeRect(485,700,550,26)]; [_explorerPath setPlaceholderString:@"Approved local/case/Veeam path"]; [content addSubview:_explorerPath];
  _explorerBrowse=[[NSButton alloc] initWithFrame:NSMakeRect(1045,700,110,26)]; [_explorerBrowse setTitle:@"Browse..."]; [_explorerBrowse setTarget:self]; [_explorerBrowse setAction:@selector(browseExplorerPath:)]; [content addSubview:_explorerBrowse];
  _explorerMark=[[NSButton alloc] initWithFrame:NSMakeRect(1045,662,160,26)]; [_explorerMark setTitle:@"Mark for Collection"]; [_explorerMark setTarget:self]; [_explorerMark setAction:@selector(markExplorerPath:)]; [content addSubview:_explorerMark];
  _sshHost=[[NSTextField alloc] initWithFrame:NSMakeRect(485,700,200,26)]; [_sshHost setPlaceholderString:@"SSH host"]; [content addSubview:_sshHost];
  _sshPort=[[NSTextField alloc] initWithFrame:NSMakeRect(695,700,70,26)]; [_sshPort setStringValue:@"22"]; [_sshPort setPlaceholderString:@"Port"]; [content addSubview:_sshPort];
  _sshUser=[[NSTextField alloc] initWithFrame:NSMakeRect(775,700,170,26)]; [_sshUser setPlaceholderString:@"Username"]; [content addSubview:_sshUser];
  _sshPassword=[[NSSecureTextField alloc] initWithFrame:NSMakeRect(955,700,200,26)]; [_sshPassword setPlaceholderString:@"Password (session only)"]; [content addSubview:_sshPassword];
  _sshRemotePath=[[NSTextField alloc] initWithFrame:NSMakeRect(485,662,470,26)]; [_sshRemotePath setStringValue:@"."]; [_sshRemotePath setPlaceholderString:@"Remote directory/file"]; [content addSubview:_sshRemotePath];
  _sshProbe=[[NSButton alloc] initWithFrame:NSMakeRect(965,662,90,26)]; [_sshProbe setTitle:@"Probe Key"]; [_sshProbe setTarget:self]; [_sshProbe setAction:@selector(sshProbeClicked:)]; [content addSubview:_sshProbe];
  _sshConnect=[[NSButton alloc] initWithFrame:NSMakeRect(1065,662,90,26)]; [_sshConnect setTitle:@"Connect/List"]; [_sshConnect setTarget:self]; [_sshConnect setAction:@selector(sshConnectClicked:)]; [content addSubview:_sshConnect];
  _sshUpload=[[NSButton alloc] initWithFrame:NSMakeRect(485,626,110,26)]; [_sshUpload setTitle:@"Upload →"]; [_sshUpload setTarget:self]; [_sshUpload setAction:@selector(sshUploadClicked:)]; [content addSubview:_sshUpload];
  _sshDownload=[[NSButton alloc] initWithFrame:NSMakeRect(605,626,110,26)]; [_sshDownload setTitle:@"← Download"]; [_sshDownload setTarget:self]; [_sshDownload setAction:@selector(sshDownloadClicked:)]; [content addSubview:_sshDownload];
  _consoleTarget=[[NSPopUpButton alloc] initWithFrame:NSMakeRect(485,662,280,28) pullsDown:NO]; [content addSubview:_consoleTarget];
  _consoleCommand=[[NSTextField alloc] initWithFrame:NSMakeRect(485,626,550,26)]; [_consoleCommand setPlaceholderString:@"Command (not persisted)"]; [content addSubview:_consoleCommand];
  _consoleRun=[[NSButton alloc] initWithFrame:NSMakeRect(1045,626,110,26)]; [_consoleRun setTitle:@"Run Command"]; [_consoleRun setTarget:self]; [_consoleRun setAction:@selector(consoleRunClicked:)]; [content addSubview:_consoleRun];

  _sqlServer=[[NSTextField alloc] initWithFrame:NSMakeRect(245,700,310,26)]; [_sqlServer setPlaceholderString:@"SQL Server / instance"]; [content addSubview:_sqlServer];
  _sqlDatabase=[[NSTextField alloc] initWithFrame:NSMakeRect(565,700,180,26)]; [_sqlDatabase setStringValue:@"master"]; [_sqlDatabase setPlaceholderString:@"Database"]; [content addSubview:_sqlDatabase];
  _sqlPrincipal=[[NSTextField alloc] initWithFrame:NSMakeRect(755,700,300,26)]; [_sqlPrincipal setPlaceholderString:@"Principal to inspect"]; [content addSubview:_sqlPrincipal];
  _sqlConnection=[[NSTextField alloc] initWithFrame:NSMakeRect(245,662,810,26)]; [_sqlConnection setPlaceholderString:@"Optional ODBC connection string (session only)"]; [content addSubview:_sqlConnection];
  _sqlOutput=[[NSTextField alloc] initWithFrame:NSMakeRect(245,624,610,26)]; [_sqlOutput setPlaceholderString:@"Optional output .sql path"]; [content addSubview:_sqlOutput];
  _sqlTrusted=[[NSButton alloc] initWithFrame:NSMakeRect(865,624,180,24)]; [_sqlTrusted setButtonType:NSSwitchButton]; [_sqlTrusted setTitle:@"Trusted connection"]; [_sqlTrusted setState:NSControlStateValueOn]; [content addSubview:_sqlTrusted];
  _sqlDatabasePermissions=[[NSButton alloc] initWithFrame:NSMakeRect(245,590,220,24)]; [_sqlDatabasePermissions setButtonType:NSSwitchButton]; [_sqlDatabasePermissions setTitle:@"Include database permissions"]; [_sqlDatabasePermissions setState:NSControlStateValueOn]; [content addSubview:_sqlDatabasePermissions];
  _sqlRun=[[NSButton alloc] initWithFrame:NSMakeRect(475,584,210,32)]; [_sqlRun setTitle:@"Run Permission Diagnostic"]; [_sqlRun setTarget:self]; [_sqlRun setAction:@selector(sqlRunClicked:)]; [content addSubview:_sqlRun];

  _fsRoot=[[NSTextField alloc] initWithFrame:NSMakeRect(245,700,470,26)]; [_fsRoot setPlaceholderString:@"Root path"]; [content addSubview:_fsRoot];
  _fsOutput=[[NSTextField alloc] initWithFrame:NSMakeRect(725,700,470,26)]; [_fsOutput setPlaceholderString:@"Output .satsnap"]; [content addSubview:_fsOutput];
  _fsBaseline=[[NSTextField alloc] initWithFrame:NSMakeRect(245,662,470,26)]; [_fsBaseline setPlaceholderString:@"Baseline .satsnap"]; [content addSubview:_fsBaseline];
  _fsOther=[[NSTextField alloc] initWithFrame:NSMakeRect(725,662,470,26)]; [_fsOther setPlaceholderString:@"Other .satsnap"]; [content addSubview:_fsOther];
  _fsHash=[[NSButton alloc] initWithFrame:NSMakeRect(245,628,190,24)]; [_fsHash setButtonType:NSSwitchButton]; [_fsHash setTitle:@"SHA-256 all files"]; [content addSubview:_fsHash];
  _fsCapture=[[NSButton alloc] initWithFrame:NSMakeRect(445,620,150,32)]; [_fsCapture setTitle:@"Capture Baseline"]; [_fsCapture setTarget:self]; [_fsCapture setAction:@selector(filesystemCaptureClicked:)]; [content addSubview:_fsCapture];
  _fsCompare=[[NSButton alloc] initWithFrame:NSMakeRect(605,620,170,32)]; [_fsCompare setTitle:@"Compare Snapshots"]; [_fsCompare setTarget:self]; [_fsCompare setAction:@selector(filesystemCompareClicked:)]; [content addSubview:_fsCompare];

  _action=[[NSButton alloc] initWithFrame:NSMakeRect(230,28,210,36)]; [_action setTarget:self]; [_action setAction:@selector(actionClicked:)]; [content addSubview:_action];
  _cancelButton=[[NSButton alloc] initWithFrame:NSMakeRect(1180,28,80,36)]; [_cancelButton setTitle:@"Cancel"]; [_cancelButton setTarget:self]; [_cancelButton setAction:@selector(cancelClicked:)]; [_cancelButton setHidden:YES]; [content addSubview:_cancelButton];
  _status=[[NSTextField alloc] initWithFrame:NSMakeRect(450,34,720,24)]; [_status setEditable:NO]; [_status setBordered:NO]; [_status setDrawsBackground:NO]; [content addSubview:_status];

  [self loadPortableCases]; [self rebuildNavigation]; [self syncActiveCase]; [self showPage:PageHome];
  [_window makeKeyAndOrderFront:nil]; [NSApp activateIgnoringOtherApps:YES];
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)sender { (void)sender; return YES; }
@end

namespace support_assist::gui {
int run_portable_gui() {
  @autoreleasepool {
    NSApplication* app = [NSApplication sharedApplication];
    SATPortableDelegate* delegate = [[SATPortableDelegate alloc] init];
    [app setDelegate:delegate];
    [app setActivationPolicy:NSApplicationActivationPolicyRegular];
    [app run];
  }
  return 0;
}
} // namespace support_assist::gui
