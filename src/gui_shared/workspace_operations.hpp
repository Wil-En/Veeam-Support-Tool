#pragma once

// The operation form: what an SAT tool session actually is.
//
// A card does not "do a thing". It opens a SESSION, and every session has the same anatomy, which
// the Windows frontend builds out of one fixed set of controls reconfigured per operation:
//
//   [IDLE x]                                  <- session tab, carrying the run state
//   Operation   [ Create case workspace   v]  <- mode selector; one session can switch operation
//   <intro>                                   <- what this operation does
//   Parent folder   Case ID      Case title   <- fields, three to a row, label above field
//   [__________]    [_________]  [_________]
//   [x] Create standard logs, captures, ...   <- the option checkbox
//        [Create and activate] [Show CLI] [Cancel]
//   <context help>
//   CASE WORKSPACE CREATED                    <- result caption
//   | Workspace | Path | Purpose | Status |   <- result columns, per operation
//
// Reference: AppWindow::select_page() (titles, breadcrumbs, mode lists),
// AppWindow::configure_controls_for_mode() (labels, buttons, columns) and AppWindow::describe_mode()
// (intro text, placeholders, tooltips) in SAT-v0.4.8-src/src/gui/app_window.cpp. Every string below
// is the product's own, so an engineer moving between the Windows and Linux editions reads the same
// words in the same places.
//
// Modal dialogs are NOT how SAT asks for input. An earlier revision of the Qt frontend put New Case
// in a QDialog, which looked reasonable and was wrong: it broke the session model, lost the
// operation selector, lost Show CLI, and had nowhere to render the result table.
//
// Windows-only pages (VSS Tools, Registry Change, WMI Diagnostics, VBR Diagnostics) are absent, and
// so are the individual Windows-only operations inside pages that do exist.

#include "workspace_view_model.hpp"
#include "sql_tools_run.hpp"
#include "system_differences_run.hpp"
#include "host_checks_form.hpp"
#include "support_assist/network.hpp"
#include "scenario_form.hpp"

#include <string>
#include <vector>

namespace support_assist::gui {

// What a field's Browse button picks.
enum class BrowseKind { folder, open_file, save_file };

// Host Diagnostics' Unix sockets (Linux), Windows' Named Pipes mode number.
inline constexpr int kUnixSocketsMode = 29;

struct OperationField {
  std::string label;
  // Pre-filled VALUE, as AppWindow::configure_controls_for_mode() sets with set_control_text().
  // Distinct from the placeholder: this is text the engineer can run with or edit, not a hint.
  std::string default_value;
  // Greyed example text, from the Windows `cues` array.
  std::string placeholder;
  // Hover explanation, from the Windows `tips` array.
  std::string tooltip;
  // Fields that name a folder or a file carry a Browse button.
  bool browse = false;
  BrowseKind browse_kind = BrowseKind::folder;
  // The file type a file Browse offers first, such as "satsnap"; empty for any file.
  std::string browse_extension;

  // Explicit constructor rather than aggregate initialisation. GCC rejects an aggregate initialiser
  // that omits a trailing member under -Werror=missing-field-initializers, and MSVC accepts it
  // silently - so every definition below would have to spell out fields it does not care about, or
  // the Linux build breaks. Defaults belong here instead.
  OperationField(std::string label_value = {}, std::string placeholder_value = {},
                 std::string tooltip_value = {}, bool browse_value = false,
                 std::string default_text = {}, BrowseKind kind = BrowseKind::folder,
                 std::string extension = {})
      : label(std::move(label_value)), default_value(std::move(default_text)),
        placeholder(std::move(placeholder_value)), tooltip(std::move(tooltip_value)),
        browse(browse_value), browse_kind(kind), browse_extension(std::move(extension)) {}
};

// A checkbox on the operation form. Several operations have more than one - Log Review carries both
// "Fast index first" and "Treat each source bundle as one primary machine" - so this is a list, not
// the single label an earlier revision assumed.
struct OperationOption {
  std::string label;
  bool checked = true;
  // What it does, as its hover help; the label is only its name.
  std::string tooltip;

  OperationOption(std::string label_value = {}, bool checked_value = true, std::string tooltip_value = {})
      : label(std::move(label_value)), checked(checked_value), tooltip(std::move(tooltip_value)) {}
};

inline constexpr const char* kFastIndexFirstHelp =
    "Recommended. Indexes the identity, service, job and rescan logs first, which answers most cases quickly; clear it for the complete review of every log.";

// A button beside an operation's own (System Differences' Compare and Open beside Capture): its label
// and the mode it runs on the same form.
struct OperationExtraAction {
  std::string label;
  int mode = 0;
};

struct OperationDefinition {
  // Matches the Windows mode number so a defect reported against one edition is findable in the
  // other.
  int mode = 0;
  std::string title;
  std::string intro;
  std::string action_label;
  std::vector<OperationField> fields;
  // Empty when the operation has no checkboxes.
  std::vector<OperationOption> options;
  std::vector<std::string> columns;
  std::string result_caption;
  // The CLI verb this form emits through Show CLI. Empty means the operation has no command-line
  // equivalent, and Show CLI must say so rather than emit a partial command.
  std::string cli_verb;
  // False means the Qt frontend cannot run it yet. The operation is still listed, so the catalog
  // matches the Windows edition, and says which phase builds it.
  bool implemented = false;
  // The line under the buttons. Windows uses it for the operation's own working notes, such as how
  // to copy rows out of the result grid. Last so existing definitions need not mention it.
  std::string context_help;
  // Buttons beside the action button, each running another mode on this form's fields.
  std::vector<OperationExtraAction> extra_actions;

  // See the note on OperationField: an explicit constructor keeps the definitions below readable
  // without tripping -Werror=missing-field-initializers on the trailing members.
  OperationDefinition(int mode_value = 0, std::string title_value = {}, std::string intro_value = {},
                      std::string action_value = {}, std::vector<OperationField> fields_value = {},
                      std::vector<OperationOption> options_value = {},
                      std::vector<std::string> columns_value = {},
                      std::string caption_value = {}, std::string cli_value = {},
                      bool implemented_value = false, std::string help_value = {})
      : mode(mode_value), title(std::move(title_value)), intro(std::move(intro_value)),
        action_label(std::move(action_value)), fields(std::move(fields_value)),
        options(std::move(options_value)), columns(std::move(columns_value)),
        result_caption(std::move(caption_value)), cli_verb(std::move(cli_value)),
        implemented(implemented_value), context_help(std::move(help_value)) {}
};

// The page heading, as AppWindow::select_page() sets it.
inline std::string page_title(WorkspacePage page) {
  // A Tools category: its name from the table, in capitals.
  if (const auto category = tool_category_of_page(page)) {
    std::string title(tool_category_title(*category));
    for (char& character : title) {
      if (character >= 'a' && character <= 'z')
        character = static_cast<char>(character - 'a' + 'A');
    }
    return title;
  }
  switch (page) {
  case WorkspacePage::home:
    return "WELCOME BACK";
  case WorkspacePage::case_manager:
    return "CASE MANAGER";
  case WorkspacePage::case_dashboard:
    return "CASE DASHBOARD";
  case WorkspacePage::environment_review:
    return "ENVIRONMENT REVIEW";
  case WorkspacePage::note_review:
    return "NOTE REVIEW";
  case WorkspacePage::recent_activity:
    return "RECENT ACTIVITY";
  case WorkspacePage::health_monitor:
    return "HEALTH MONITOR";
  case WorkspacePage::tools:
    return "TOOLS";
  case WorkspacePage::log_review:
    return "LOG REVIEW";
  case WorkspacePage::explorer:
    return "VEEAM & CASE FILE BROWSER";
  case WorkspacePage::remote:
    return "REMOTE CONSOLE";
  case WorkspacePage::tool_manager:
    return "INTEGRATIONS";
  case WorkspacePage::diagnostics:
    return "DIAGNOSTICS";
  case WorkspacePage::help:
    return "HELP / ABOUT";
  default:
    return {};
  }
}

// The breadcrumb trail. It is a PATH, not the page name: an engineer three levels into the tool
// catalog needs to see how they got there. The text is AppWindow::configure_page()'s, held to it by
// tools/test_navigation_parity.py.
inline std::string page_breadcrumb(WorkspacePage page,
                                   WorkspaceRole role = WorkspaceRole::engineer_review) {
  // A Tools category: under Tools, by the name in the table.
  if (const auto category = tool_category_of_page(page))
    return "Home  >  Tools  >  " + std::string(tool_category_title(*category));
  switch (page) {
  case WorkspacePage::home:
    return "Home";
  case WorkspacePage::case_manager:
    return "Home  >  Case Manager";
  case WorkspacePage::case_dashboard:
    return "Home  >  Case Dashboard";
  case WorkspacePage::environment_review:
    // Customer / Lab opens it from Home on the live host; Engineer Review reaches it from a case.
    return role == WorkspaceRole::customer_lab ? "Home  >  Environment Review"
                                               : "Home  >  Case Dashboard  >  Environment Review";
  case WorkspacePage::note_review:
    return "Home  >  Case Dashboard  >  Note Review";
  case WorkspacePage::recent_activity:
    return "Home  >  Recent Activity";
  case WorkspacePage::health_monitor:
    return "Home  >  Health Monitor";
  case WorkspacePage::tools:
    return "Home  >  Tools";
  case WorkspacePage::log_review:
    return "Home  >  Log Review";
  case WorkspacePage::explorer:
    return "Home  >  File Browser";
  case WorkspacePage::remote:
    return "Home  >  Remote";
  case WorkspacePage::tool_manager:
    return "Home  >  Integrations";
  case WorkspacePage::diagnostics:
    return "Home  >  Diagnostics";
  case WorkspacePage::help:
    return "Home  >  Help / About";
  default:
    return {};
  }
}

namespace detail {

inline std::vector<std::string> columns(std::string a, std::string b, std::string c,
                                        std::string d) {
  return {std::move(a), std::move(b), std::move(c), std::move(d)};
}

inline OperationField host_field() {
  return {"Host", "localhost", "Endpoint hostname or address to test.", false, "localhost"};
}

inline OperationField port_field() {
  return {"Port", "2500", "TCP or UDP port on the target endpoint.", false, "2500"};
}

inline OperationField timeout_field() {
  return {"Timeout ms", "5000", "How long to wait before the attempt is treated as a failure.",
          false, "5000"};
}

} // namespace detail

// The operations a workspace offers, in the order the Operation selector lists them.
// System Differences' Files page: one form holding every field, with Capture (the action button),
// Compare and Open. Capture uses the folder, the capture file and the contents choice; Compare the
// capture file and Compare with; Load the capture file.
inline OperationDefinition files_differences_operation() {
  OperationDefinition files(
      kDifferencesCapture, "File Differences",
      "Capture records a folder's files and folders as they are now. Make the change, or wait for it, then "
      "Compare the capture with now or with a second capture. Open shows what a capture file holds, with the "
      "compares kept in it.",
      "Capture",
      {{"Folder to look at", "Example: /opt/veeam", "Everything under this folder is captured.", true, "",
        BrowseKind::folder},
       {"Capture file", "Example: before.satsnap",
        "Written by Capture (an existing file is replaced after a question), read by Compare and Open. "
        "Compare captures first when the file is not there yet.", true, "",
        BrowseKind::save_file, "satsnap"},
       {"Compare file contents", kContentsNever,
        "Never compares names, sizes and times. Files up to 64 MB and All files also read each file, "
        "which finds a change that left its size and times alone.",
        false, kContentsNever},
       {"Compare with", kCompareWithNow,
        "Now reads the folder again with the same settings; or choose a second capture file.", false,
        kCompareWithNow, BrowseKind::open_file, "satsnap"}},
      {}, detail::columns("Item", "Path", "Reason or size", "Detail"), "SYSTEM DIFFERENCES", "files baseline", true);
  files.extra_actions = {{"Compare", kDifferencesCompare}, {"Open", kDifferencesLoad}};
  return files;
}

inline std::vector<OperationDefinition> page_operations(WorkspacePage page, WorkspaceRole role) {
  using detail::columns;
  static_cast<void>(role);

  switch (page) {
  case WorkspacePage::home:
    return {
        {0, "Toolbox overview",
         "Review the available support modules and their privilege requirements.", "Refresh", {}, {}, columns("Module", "Purpose", "Privilege", "State"), "TOOLBOX CAPABILITIES", "",
         false},
        {1, "Create case workspace",
         "Create a case workspace with predictable folders for collected logs, captures, reports "
         "and baselines.",
         "Create and activate",
         {{"Parent folder", "Example: /home/engineer/SupportCases",
           "Parent directory where the new case folder will be created.", true},
          {"Case ID", "Example: CASE-2026-0042",
           "Unique case or ticket identifier used as the workspace folder name.", false},
          {"Case title", "Example: VAW backup failure",
           "Readable case title shown in workspace metadata.", false},
          {"Support engineer", "Engineer name", "Engineer responsible for the review.", false}},
         {{"Create standard logs, captures, reports, baselines, notes and tools folders", true}},
         columns("Workspace", "Path", "Purpose", "Status"), "CASE WORKSPACE CREATED", "case", true},
        {2, "Manage cases", "Review the case workspaces discovered beside the active case.",
         "Refresh case list", {}, {},
         columns("Case ID", "Title", "Engineer", "Workspace path"), "CASE WORKSPACES", "case", true},
        {3, "Delete active case",
         "Permanently delete the active case workspace and every file beneath it.",
         "Delete active case", {}, {},
         columns("Case", "Title", "Engineer", "Workspace path"), "CASE DELETED", "case", true},
        // The Windows Case Notes form: what the note is about, then observations, hypothesis, next
        // action and the engineer's own notes. Save stores the note when any of the four is filled
        // in, and lists every note the case holds either way.
        {4, "Case notes",
         "Record observations, a hypothesis and the next action for the active case, and review "
         "the notes it holds.",
         "Save / refresh notes",
         {{"Scope type", "Case or Job run", "What the note is about: the whole case, or one job run.",
           false},
          {"Scope key", "Case ID or run key", "The case ID, or the key of the job run.", false},
          {"Observations", "", "What the evidence shows.", false},
          {"Hypothesis", "", "What you think is causing it.", false},
          {"Next action", "", "What happens next, and who does it.", false},
          {"Engineer notes", "", "Anything else to keep with the case.", false}},
         {}, columns("Scope", "Subject", "Updated", "Notes"), "CASE NOTES", "", false},
        {5, "Register existing case",
         "Register cases that already exist on disk. Accepts a single case folder, a folder "
         "containing several case folders, or an old SAT case-catalog.txt to import. Cases "
         "already registered are kept.",
         "Register and activate",
         {{"Case folder, parent folder, or case-catalog.txt",
           "Example: /home/engineer/SupportCases  (or a single case, or case-catalog.txt)",
           "A case workspace, a folder holding several of them, or a previous SAT case journal. "
           "A case ID that is already registered from another location is kept and labelled "
           "(COPY2) rather than replacing the one you have.", true}},
         {}, columns("Case ID", "Title", "Engineer", "Workspace path"), "CASE REGISTERED",
         "case", true}};

  case WorkspacePage::case_manager:
    // One operation, because the page IS the operation: it lists every case and acts on the one
    // selected. The old flow spread this across five drop-down entries on Home.
    return {{0, "All cases",
             "Every case workspace SAT can see, with the actions that apply to the selected one.",
             "Refresh", {}, {},
             columns("Case ID", "Description", "Engineer", "Created / workspace"),
             "CASES", "cases", true}};

  case WorkspacePage::case_dashboard:
    return {{0, "Case overview",
             "Review the active case as systems, components, jobs, runs and findings.", "Refresh",
             {}, {}, columns("Case", "Machines", "Jobs", "Findings"), "CASE OVERVIEW", "case",
             true}};

  case WorkspacePage::environment_review:
    return {{0, "Case environment",
             "Review the active case as one Veeam environment: source owners, workloads, products, "
             "infrastructure and observed relationships.",
             "Refresh environment", {}, {},
             columns("Environment", "Relationship", "Observed value", "Evidence"),
             "CASE ENVIRONMENT", "", true}};

  case WorkspacePage::note_review:
    return {{0, "Case note preview", "Preview the note this case would produce.",
             "Save / refresh notes", {}, {},
             columns("Section", "Subject", "State", "Details"), "CASE NOTE", "", false}};

  case WorkspacePage::recent_activity:
    return {
        {0, "Recent activity",
         "Recent Activity records starts, completions, failures and cancellation requests from this "
         "installation.",
         "Refresh", {}, {}, columns("Time", "Tool", "Result", "Details"), "RECENT ACTIVITY", "",
         true,
         "It is an operator convenience record, not a replacement for the exported case report."},
        {1, "Load archived activity (bundle folder or ZIP)",
         "Open a collected activity record read-only, without changing the live activity log.",
         "Open Read-Only",
         {{"Collected bundle folder or Activity TSV", "Example: /home/engineer/Downloads/bundle",
           "A collected support bundle folder, ZIP, or an Activity TSV exported from another host.",
           true}},
         {}, columns("Time", "Tool", "Result", "Details"), "ARCHIVED ACTIVITY", "", false},
        {2, "Tool evidence timeline",
         "Read back the structured artifacts SAT wrote for each tool run - what ran, on which "
         "host, what it concluded and every finding row - so Customer / Lab output can be "
         "reviewed and quoted instead of retyped.",
         "Load evidence",
         {{"Artifact folder", "Example: /home/engineer/Downloads/bundle/Tools",
           "A collected Tools folder, or leave blank for this installation's own tool output.",
           true}},
         {}, columns("Time", "Tool", "Result", "Details"), "TOOL EVIDENCE TIMELINE", "", false}};

  case WorkspacePage::health_monitor:
    return {
        {0, "Live health overview",
         "Review CPU, memory, storage, network and process health for this host.", "Refresh now",
         {}, {}, columns("Status", "Component", "Current", "Details"), "SYSTEM HEALTH", "health",
         true},
        {1, "Export health report",
         "Write a point-in-time health report the engineer can attach to the case or hand to "
         "another host to read back.",
         "Export report",
         {{"Report file", "Example: system-health.txt",
           "Where the health report is written. Blank writes it into the active case.", true}},
         {}, columns("Status", "Component", "Current", "Details"), "SYSTEM HEALTH", "health",
         false},
        {2, "Load health report",
         "Read a health report captured on another host - a customer machine SAT ran on once - "
         "and review it here with the same status evaluation.",
         "Load report",
         {{"Report file", "Example: system-health.txt",
           "A health report exported by SAT on this or another host.", true}},
         {}, columns("Status", "Component", "Current", "Details"), "SYSTEM HEALTH", "health",
         false}};

  case WorkspacePage::tools:
    return {{0, "Tool categories",
             "Browse the complete categorized diagnostic catalog for this host.", "Open category",
             {}, {}, columns("Category", "Purpose", "Access", "Status"), "TOOL CATEGORIES", "",
             false}};

  case WorkspacePage::network_tools:
    return {
        {0, "TCP connectivity test",
         "Test TCP reachability to a port on another host through one or more discovered local "
         "interfaces. Select the interface checkboxes SAT should originate from; if none is "
         "selected automatic routing is used. Where the name resolved from, one row each for IPv4 "
         "and IPv6, and each target IP are shown. A SAT listener can additionally verify an "
         "in-memory payload of a size you choose, which doubles as a rough bandwidth measurement.",
         "Test TCP",
         {{"Host", "Hostname or IP", "Target DNS name or IP address.", false, "localhost"},
          {"Port", "1-65535", "Destination TCP port.", false, "2500"},
          {"Timeout ms", "Milliseconds", "Maximum connection wait in milliseconds.", false,
           "5000"},
          {"Payload MiB", "MiB", "How much to send when payload validation is on. 1024 is a "
                                 "gigabyte. Ignored when the checkbox is clear.", false,
           "50"}},
         {{"Validate an in-memory payload when peer is a SAT listener", false},
          {"Test through each discovered local interface", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {25, "Local network interfaces",
         "List the discovered local interfaces SAT can originate a test from, including virtual, "
         "VLAN and bonded interfaces, so a routing question can be asked precisely.",
         "List interfaces", {}, {},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {1, "TCP listener",
         "Open a temporary TCP listener for controlled inbound connectivity testing.", "Listen",
         {{"Listen port", "Listen port", "Port this host will accept controlled probes on.", false,
           "2500"},
          {"Duration seconds", "Seconds", "How long the listener stays open.", false, "30"},
          {"Banner", "Text sent to each client",
           "Sent to each accepted client so the far end can confirm it reached SAT. %port% becomes "
           "the port; clear the field to send none.",
           false, std::string(support_assist::kDefaultListenerBanner)}},
         {{"Accept multiple connections until timeout", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {16, "UDP connectivity test",
         "Send a bounded UDP probe to a port on another host through the selected discovered local "
         "interfaces. Where the name resolved from, one row each for IPv4 and IPv6, and each target "
         "IP are shown. Generic UDP is indeterminate without a response; only a cooperating SAT UDP "
         "listener can acknowledge and verify the test.",
         "Test UDP",
         {{"Host", "Hostname or IP", "Target DNS name or IP address.", false, "localhost"},
          {"Port", "1-65535", "Destination UDP port.", false, "2500"},
          {"Timeout ms", "Milliseconds", "How long to wait for a response.", false, "2000"}},
         {{"Verify a cooperating SAT UDP listener (required for PASS)", false},
          {"Test through each discovered local interface", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {17, "UDP listener",
         "Open a temporary UDP listener. SAT probes are acknowledged with their Test ID; ordinary "
         "datagrams are recorded only as bounded endpoint/byte metadata.",
         "Listen UDP",
         {{"Listen port", "Listen port", "Port this host will accept controlled probes on.", false,
           "2500"},
          {"Duration seconds", "Seconds", "How long to keep listening.", false, "30"}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {18, "TLS handshake test",
         "Perform an explicit client-side TLS handshake through the selected discovered local "
         "interfaces without installing a SAT certificate. Report the connected IP, negotiated TLS "
         "metadata and server public certificate; optionally compare TLS 1.2 and 1.3.",
         "Test TLS",
         {{"Host", "Hostname or IP", "Endpoint to perform the handshake against.", false},
          {"Port", "Default 2500", "TLS port on the target endpoint.", false, "2500"},
          {"TLS server name / SNI (optional)", "Optional SNI/FQDN",
           "TLS server name and hostname-validation name when it differs from the host.", false},
          {"Expected SHA-1/SHA-256 fingerprint (optional)", "Optional expected fingerprint",
           "Compared against the certificate the server actually presents.", false}},
         {{"Compare TLS 1.2 and TLS 1.3 separately", false},
          {"Test through each discovered local interface", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {19, "Local loopback self-test",
         "Run a controlled local TCP/SAT self-test. SAT first verifies that the requested port is "
         "free. If any service already owns the port, SAT reports it and does not attempt to bind a "
         "temporary listener.",
         "Run loopback self-test",
         {{"Loopback port", "Default 2500", "Port used for the temporary local listener.", false,
           "2500"},
          {"Timeout ms", "Milliseconds", "Maximum wait for the local connection.", false, "5000"}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {20, "Windows RPC connectivity",
         "Validate Windows DCE/RPC connectivity by connecting to the Endpoint Mapper and requiring "
         "a valid RPC BIND_ACK. TCP reachability alone is reported separately and is not called RPC "
         "success.",
         "Test RPC",
         {{"Target host", "Hostname or IP", "Windows host to test.", false},
          {"RPC Endpoint Mapper port", "RPC requires 135", "Endpoint Mapper port on the target.",
           false, "135"},
          {"Timeout ms", "Milliseconds", "Maximum wait for the BIND_ACK exchange.", false, "5000"}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {21, "gRPC connectivity",
         "Validate the transport used by gRPC: TCP, optional TLS with ALPN h2, HTTP/2 "
         "preface/SETTINGS, and a bounded HTTP/2 PING. A cooperating SAT listener additionally "
         "provides positive SAT peer verification without invoking an application-specific gRPC "
         "method. Veeam's data ports (2500 to 3300, 6162) speak Veeam's own transport and stop at "
         "the SETTINGS stage; the Veeam Service Channel tests the channel Veeam's own processes use.",
         "Test gRPC transport",
         {{"Target host", "Hostname or IP", "Host exposing the gRPC transport.", false},
          {"Port", "Default 2500", "Port the gRPC transport listens on.", false, "2500"},
          {"TLS server name / SNI (optional)", "Optional TLS SNI/FQDN",
           "TLS server name presented when TLS is requested.", false}},
         {{"Use TLS and require ALPN h2", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {22, "gRPC listener",
         "Start a cooperating SAT HTTP/2 transport listener for two-endpoint gRPC connectivity "
         "testing. Incoming connections are reported live with the HTTP/2 and SAT verification "
         "stages.",
         "Listen for gRPC transport",
         {{"Listen port", "Default 2500", "Port this host will listen on.", false, "2500"},
          {"Duration seconds", "Seconds", "How long to keep listening.", false, "30"}},
         {{"Accept multiple connections until timeout", true}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {27, "Veeam Service Channel",
         "Tests the channel Veeam's own processes use to reach their service, layer by layer: the "
         "service, its named pipe and an HTTP/2 handshake on the pipe as this account (Windows), then "
         "the gRPC lines the product logged. No gRPC call is made and nothing is changed.",
         "Test channel",
         {{"Veeam product", "agent", "agent (Veeam Agent for Microsoft Windows) or vbr (Veeam Backup & Replication).",
           false, "agent"},
          {"Log folder", "Empty: the product's own folder", "A folder of the product's logs, such as a collected bundle's.",
           true},
          {"Hours", "24", "How far back the logs are read.", false, "24"}},
#ifdef _WIN32
         {{"Read the logs only", false, "Skips the service, pipe and handshake on this machine."}},
#else
         {},
#endif
         columns("Layer", "Check", "Details", "Status"), "SERVICE CHANNEL", "network", false},
        {24, "SMB connectivity test",
         "Verify TCP/445, SMB negotiation, path access and a bounded write/read/delete payload "
         "outside Veeam.",
         "Test SMB",
         {{"Target machine", "Hostname or IP", "Host exposing the administrative share.", false},
          {"Bounded test path", R"(C$\Windows\Veeam)",
           "Share-relative path used for the bounded write/read/delete test.", false,
           R"(C$\Windows\Veeam)"},
          {"TCP / SMB timeout ms", "Milliseconds", "Maximum wait for each SMB stage.", false,
           "5000"}},
         {{"Prompt for alternate credentials", false}},
         columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY", "network",
         false},
        {5, "Packet capture",
         "Capture network evidence into the case Log-Collections tree with the operating system's own "
         "capture; Stop capture converts it to PCAPNG.",
         "Start capture",
         {{"Output", "Automatic tool output",
           "SAT writes the capture into this run's Log-Collections/Tools output.", false},
          {"Address filter", "Optional IP filter", "Restrict the capture to one address.", false},
          {"Port filter", "Optional port filter", "Restrict the capture to one port.", false}},
         {}, columns("Capture", "Item", "Value", "State"), "PACKET CAPTURE STATUS", "network", false},
        {11, "iPerf client (optional)",
         "Run an optional iPerf client using an existing local copy. No dependency is downloaded or "
         "executed without confirmation.",
         "Run",
         {{"Server address", "Server hostname or IP", "iPerf server to measure against.", false},
          {"Port", "Default 2500", "Port the iPerf server accepts on.", false, "2500"},
          {"Transfer size", "Example: 1G", "How much data to move during the measurement.", false,
           "1G"},
          {"Optional tools folder", "Folder containing iPerf3",
           "Folder holding the approved local iPerf copy.", true}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {12, "iPerf one-shot server (optional)",
         "Run a single-use iPerf server for a controlled two-endpoint measurement.", "Listen once",
         {{"Port", "Default 2500", "Port the one-shot iPerf server accepts on.", false, "2500"},
          {"Optional tools folder", "Folder containing iPerf3",
           "Folder holding the approved local iPerf copy.", true}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {14, "Native throughput client",
         "Measure controlled TCP throughput to another toolkit endpoint.", "Run test",
         {{"Server address", "Server hostname or IP",
           "SAT endpoint acting as the throughput server.", false},
          {"Port", "Default 2500", "Port the throughput server accepts on.", false, "2500"},
          {"Transfer size", "Example: 1G", "How much data to move during the measurement.", false,
           "1G"}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false},
        {15, "Native throughput server",
         "Accept one controlled throughput run from another toolkit endpoint.", "Start server",
         {{"Listen port", "Listen port", "Port this host will accept the throughput run on.", false,
           "2500"},
          {"Connection timeout ms", "Milliseconds", "How long to wait for the peer.", false,
           "60000"},
          {"Idle timeout ms", "Milliseconds", "How long a stalled transfer is tolerated.", false,
           "30000"}},
         {}, columns("Protocol", "IP Address", "Details", "Result"), "LIVE RESULTS / HISTORY",
         "network", false}};

  case WorkspacePage::guided_diagnostics: {
    // One operation per scenario for this machine (support_assist/scenarios.hpp), its inputs the fields.
    std::vector<OperationDefinition> operations;
    for (const ScenarioDefinition& scenario : guided_scenarios_here()) {
      OperationDefinition operation{static_cast<int>(operations.size()), scenario.title, scenario_intro(scenario),
                                    "Run scenario", {}, {{"Keep going after a failure", false,
                                                          "Runs every step and lists each failure, the first one first."}},
                                    columns("Step", "Check", "Found", "Status"), "SCENARIO RESULT", "guided", false};
      for (const ScenarioInput& input : scenario.inputs)
        operation.fields.push_back({input.label, input.hint, input.label, false, input.default_value});
      operations.push_back(std::move(operation));
    }
    return operations;
  }

  case WorkspacePage::log_collection:
    return {
        {0, "Universal / detected products",
         "Detect Veeam products on this machine, select what belongs to the case scope, and gather "
         "the appropriate bounded logs and support context.",
         "Collect selected products",
         {{"Output folder", "Collection output folder", "Where the collected bundle is written.",
           true},
          {"Last X days (optional; blank = ALL)", "Last X days; blank = ALL",
           "Limit collected evidence to the most recent N days.", false}},
         {{"Create ZIP archive", true},
          {"Include sanitized third-party operational/error logs (SQL, PostgreSQL, Oracle, etc.)",
           true}},
         columns("Log operation", "Source / File", "Details", "Status"), "LOG COLLECTION",
         "logs gather", false},
        {1, "Custom paths",
         "Collect explicitly selected customer-approved files or folders when catalog paths are not "
         "sufficient.",
         "Collect custom paths",
         {{"Output folder", "Collection output folder", "Where the collected bundle is written.",
           true},
          {"Custom source paths (semicolon-separated)", "Optional source paths, separated by ;",
           "Explicit customer-approved sources to collect.", false},
          {"From date/time (optional)", "Optional start date/time",
           "Ignore evidence before this moment.", false},
          {"To date/time (optional)", "Optional end date/time",
           "Ignore evidence after this moment.", false}},
         {{"Create ZIP archive", true},
          {"Include bounded platform / system support context", true}},
         columns("Log operation", "Source / File", "Details", "Status"), "LOG COLLECTION",
         "logs gather", false}};

  case WorkspacePage::log_review: {
    // Every review action shares the same form: sources, output, an optional time window, the
    // date-order and offset controls that stop a mis-parsed timestamp becoming a wrong conclusion,
    // and the two indexing options.
    const std::vector<OperationField> review_fields{
        {"Log bundles / folders", "One or more folders/files/ZIPs separated by ;",
         "Evidence to index. Several sources may be reviewed together.", true},
        {"Report file or output folder", "Output folder or .txt report; empty: SAT's Log-Review folder",
         "Where the review report is written. Left empty, it goes to Log-Collections/Log-Review beside "
         "SAT.",
         true},
        {"From date/time (optional)", "Optional start date/time",
         "Ignore evidence before this moment.", false},
        {"To date/time (optional)", "Optional end date/time", "Ignore evidence after this moment.",
         false},
        // Free text with a default, matching the Windows control. The accepted vocabulary is the
        // one AppWindow parses: auto/automatic, mdy or month/day/year, dmy or day/month/year,
        // locale or system, iso or iso-only.
        {"Ambiguous date order", "Auto",
         "How to read dates that could be day-first or month-first. "
         "Auto, MDY, DMY, locale or ISO.", false, "Auto"},
        {"Assumed UTC offset minutes", "0",
         "Offset applied to timestamps that carry no timezone.", false, "0"}};
    const std::vector<OperationOption> review_options{
        {"Fast index first", true, kFastIndexFirstHelp},
        {"Treat each source bundle as one primary machine", true}};
    const auto review_columns =
        columns("Severity", "Time / Occurrences", "Component / Job", "Issue summary / Source");
    const std::string review_help =
        "Search Existing Logs searches files in place. Press Ctrl+A to select all rows, or select "
        "individual rows, then press Ctrl+C to copy the severity, source path, line number and "
        "matching text.";

    return {
        {0, "Search existing logs",
         "Search existing logs without collecting them again. Results retain source path, line "
         "number and matching text and can be selected with Ctrl+A and copied with Ctrl+C.",
         "Search logs",
         {{"Folder or file", "Folder or log file", "Evidence to search in place.", true},
          {"Search text", "Text or expression to find", "Text or expression to find.", false,
           "error"},
          {"Filename pattern", "Example: *.log", "Restrict the search to matching file names.",
           false, "*.log"}},
         {{"Case-sensitive search", false}},
         columns("Severity", "Source file", "Line", "Matching text"), "LOG SEARCH RESULTS",
         "logs review", false, review_help},
        {5, "Auto detect Veeam logs",
         "Discover the product/source profile for each supplied evidence source and review mixed "
         "product bundles without assuming one global parser.",
         "Index logs", review_fields, review_options, review_columns,
         "VEEAM LOG REVIEW DASHBOARD", "logs review", false, review_help},
        {1, "Review Veeam Agent for Microsoft Windows logs",
         "Review transferred Veeam Agent for Microsoft Windows evidence.", "Index logs",
         review_fields, review_options, review_columns, "VEEAM LOG REVIEW DASHBOARD",
         "logs review", false, review_help},
        {2, "Review Veeam Backup & Replication logs",
         "Review transferred Veeam Backup & Replication evidence. This profile can inherit the "
         "selected structured run window from another open review tab with a 5-minute lead and "
         "10-minute tail.",
         "Index logs", review_fields,
         // Mode 2 replaces the primary-machine option with the run-window limit, unchecked, and
         // mode 6 leaves the primary-machine option unchecked. Both match app_window.cpp ~10979.
         {{"Fast index first", true, kFastIndexFirstHelp},
          {"Limit to selected review run window (-5 / +10 min)", false}},
         review_columns, "VEEAM LOG REVIEW DASHBOARD", "logs review", false, review_help},
        {3, "Review Veeam Plug-In for Microsoft SQL Server logs",
         "Review transferred Veeam Plug-In for Microsoft SQL Server evidence.", "Index logs",
         review_fields, review_options, review_columns, "VEEAM LOG REVIEW DASHBOARD",
         "logs review", false, review_help},
        {4, "Review Veeam Plug-In for Oracle RMAN logs",
         "Review transferred Veeam Plug-In for Oracle RMAN evidence.", "Index logs", review_fields,
         review_options, review_columns, "VEEAM LOG REVIEW DASHBOARD", "logs review", false,
         review_help},
        {6, "Generic Parser",
         "For logs from several Veeam products, or from a product with no parser of its own.",
         "Index logs", review_fields,
         {{"Fast index first", true, kFastIndexFirstHelp},
          {"Treat each source bundle as one primary machine", false}},
         review_columns, "VEEAM LOG REVIEW DASHBOARD", "logs review", false, review_help}};
  }

  case WorkspacePage::sql_tools: {
    // The connection options every SQL check shares. On Linux integrated authentication needs a
    // Kerberos ticket, so a SQL login is the default there.
    const std::vector<OperationOption> connect{
#ifdef _WIN32
        {"Use logged-in user", true,
         "Connects as the account running SAT (Windows authentication). Clear it to be asked for a SQL login."},
#else
        {"Use logged-in user (Kerberos ticket)", false,
         "Connects with this session's Kerberos ticket. Clear it to be asked for a SQL login."},
#endif
        {"Trust the server certificate", false,
         "Accepts a certificate this machine does not trust, such as SQL Server's own self-signed one."}};
    const OperationField server{"SQL Server / instance", "SQLHOST01\\VEEAMSQL2016",
                                "The instance to check: this machine's, the configuration database's, or any name typed.",
                                false};
    // Last on every SQL operation, so the fields before it keep their places; picking one of this
    // machine's instances sets it.
    const OperationField engine{"Engine", "SQL Server", "SQL Server or PostgreSQL. Picking one of this machine's instances sets it.",
                                false, "SQL Server"};
    return {
        {0, "Permission check",
         "Checks an account's rights on the instance against Veeam's Permissions page: guest processing (sysadmin, "
         "or the minimal list) or the configuration database. Reads only.",
         "Run check",
         {server,
          {"Check against", kSqlGuestProcessing, "Guest processing, or Configuration database.", false,
           kSqlGuestProcessing},
          {"Configuration database", "VeeamBackup", "The configuration database's name, for that check.", false},
          {"Another account", "Empty: the account connecting",
           "Another login to look up in the catalog; needs VIEW ANY DEFINITION. Windows groups are not expanded.",
           false},
          engine},
         connect, columns("Area", "Check", "Details", "Status"), "SQL CHECK RESULTS", "sql", false},
        {1, "Server shape",
         "Reads whether the instance is a failover cluster instance and which availability groups, replicas, "
         "listeners and backup preferences it has, with what Veeam's guides say about each.",
         "Read shape", {server, engine}, connect, columns("Area", "Check", "Details", "Status"), "SQL CHECK RESULTS", "sql",
         false},
        {2, "Backups and log chain",
         "Reads msdb's backup history: who took each backup, backups outside Veeam that are not copy-only, log "
         "backups to NUL, gaps and restarts in the log chain, and databases that cannot take a log backup (KB2117, "
         "KB2027). Then the log chain itself, oldest first.",
         "Read backups",
         {server,
          {"Database", "Empty: every database", "One database, or every database except tempdb.", false},
          {"Days", "14", "How many days of backup history to read.", false, "14"}, engine},
         connect, columns("Database", "Check", "Details", "Status"), "SQL CHECK RESULTS", "sql", false},
        {3, "Database files and volumes",
         "Lists every database file and, when SAT runs on the SQL host, the volume it is on: kind, bus, file "
         "system and sector size.",
         "Read files", {server, engine}, connect, columns("Database", "File", "Details", "Status"), "SQL CHECK RESULTS", "sql",
         false},
        {4, "Read-only query",
         "Runs a query that reads data and lists what it returns. A query that changes data does not run; the database "
         "console is for those.",
         "Run query",
         {server,
          {"Database", "master", "The database the query runs in.", false, "master"},
          {"Query", "Databases", "A query that reads data, or one of the named queries by its name.", false}, engine},
         connect, columns("Row", "Column", "Value", "Status"), "SQL QUERY RESULTS", "sql", false}};
  }

  case WorkspacePage::filesystem_change:
    return {
        files_differences_operation()};

  case WorkspacePage::tool_manager:
    return {
        {0, "Inspect / use existing tools folder",
         "Inspect an approved third-party tools folder and report what is usable.",
         "Inspect / Use Folder",
         {{"Optional tools folder", "Example: /home/engineer/Tools",
           "Folder holding approved third-party tool copies.", true}},
         {}, columns("Tool", "Category", "Path / Source", "Status"),
         "INTEGRATIONS", "tools status", false},
        {1, "Acquire latest tool (managed or official page)",
         "Acquire an approved third-party tool copy for this host.", "Acquire Selected",
         {{"Optional tool", "", "Tool to acquire.", false}}, {},
         columns("Tool", "Category", "Path / Source", "Status"), "INTEGRATIONS",
         "tools status", false},
        {2, "Open official source page", "Open the vendor's official download page.",
         "Open Official Page", {{"Optional tool", "", "Tool whose official page to open.", false}},
         {}, columns("Tool", "Category", "Path / Source", "Status"),
         "INTEGRATIONS", "tools status", false},
        {3, "Remove Support Assist managed download",
         "Remove a tool copy that SAT downloaded and manages.", "Remove SAT-Managed Tool Copy",
         {{"Optional tool", "", "Tool copy to remove.", false}}, {},
         columns("Tool", "Category", "Path / Source", "Status"), "INTEGRATIONS",
         "tools status", false},
        // Engineer-configured tools. Explicit entries only: SAT never scans a folder for
        // executables and never registers one it was not given. See docs/REVIEW_MODS_PLUGINS.md
        // for why the drop-folder shape was rejected.
        {4, "List configured tools", "Show the external tools configured on this copy of SAT.",
         "List Configured Tools", {}, {},
         columns("Tool", "Executable", "Arguments", "Starts in"), "CONFIGURED TOOLS",
         "", false},
        {5, "Add a configured tool",
         "Point SAT at an executable and the argument line to run it with. Use {case}, {evidence} "
         "and {selected} to pass the paths already open.",
         "Add Tool",
         {{"Name", "Example: Other log parser", "How the entry is listed.", true},
          {"Executable", "Full path to the program", "The exact program this entry runs.", true, "",
           BrowseKind::open_file},
          {"Arguments", "Example: --input {evidence}",
           "Placeholders: {case} {evidence} {selected}.", false}},
         {}, columns("Tool", "Executable", "Arguments", "Starts in"), "CONFIGURED TOOLS",
         "", false},
        {6, "Run a configured tool",
         "Run a configured tool against the case and evidence currently open.", "Run Tool",
         {{"Name", "Name of the configured tool", "Which configured entry to run.", true}}, {},
         columns("Tool", "Executable", "Arguments", "Starts in"), "CONFIGURED TOOLS",
         "", false},
        {7, "Remove a configured tool", "Remove an entry. The program itself is left alone.",
         "Remove Tool",
         {{"Name", "Name of the configured tool", "Which configured entry to remove.", true}}, {},
         columns("Tool", "Executable", "Arguments", "Starts in"), "CONFIGURED TOOLS",
         "", false}};

  case WorkspacePage::diagnostics:
    // Windows Diagnostics also carries a "Windows System Tools" operation that launches MMC
    // consoles (services.msc, eventvwr.msc, certlm.msc and the rest). Every target is a Windows
    // console binary, so it is absent here for the same reason VSS Tools is - not reimplemented
    // with Linux lookalikes, which would be a different feature wearing the same name.
    return {
        {1, "System information", "Report operating system, hardware and runtime context.",
         "Refresh Information", {}, {}, columns("Category", "Property", "Value", "Source"),
         "SYSTEM INFORMATION", "diagnostics", true},
        {2, "Products and integrations inventory",
         "Report detected Veeam products and approved third-party tool copies.", "Refresh Inventory",
         {}, {}, columns("Type", "Product / Tool", "Path", "Version / Status"),
         "PRODUCTS AND INTEGRATIONS", "diagnostics", true},
        {3, "Products and integrations", "Report detected Veeam products and integrations.",
         "Refresh Information", {}, {},
         columns("Type", "Name / Location", "Full Path", "Size / Modified / Purpose"),
         "PRODUCTS AND INTEGRATIONS", "diagnostics", true},
        {4, "SAT Self-Test", "Verify this SAT copy can do what it claims on this host.", "Run",
         {}, {}, columns("Category", "Property", "Value", "Source"), "SAT SELF-TEST",
         "diagnostics", false}};

  case WorkspacePage::help:
    // The Windows Help selector lists seventeen articles. The four Windows-only ones (VSS
    // Diagnostic Lab, Registry Change, WMI, Import Previous SAT Data) are absent here: the first
    // three document technologies Linux does not have, and the fourth migrates a Windows-era
    // Logs/State layout that a Linux install never had.
    return {
        {0, "Getting started",
         "Workspace roles, navigation, sessions and the recommended support workflow.", "Show", {},
         {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         true},
        {1, "Home and case workspace", "How Home and the case workspace fit together.", "Show", {},
         {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         false},
        {2, "Health Monitor", "What Health Monitor reports and how to read it.", "Show", {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {3, "Tools Catalog and Categories", "How the execution catalog is organised.", "Show", {},
         {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         false},
        {4, "Log Collection", "How evidence is collected and bounded.", "Show", {}, {},
         columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {5, "Log Review", "How transferred Veeam evidence is indexed and reviewed.", "Show", {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {6, "SQL Tools", "Permission scripts and bounded read-only diagnostics.", "Show", {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {9, "System Differences", "Capture, make the change, then compare.", "Show", {}, {},
         columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {10, "Integrations", "Approved third-party tool copies.", "Show", {}, {},
         columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {11, "Diagnostics", "Application diagnostics and self-test.", "Show", {}, {},
         columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", false},
        {12, "Security, elevation and data",
         "Privilege escalation, evidence handling, privacy and customer-safe operation.", "Show",
         {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         true},
        {13, "Case Dashboard", "The case as systems, components, jobs, runs and findings.", "Show",
         {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         false},
        {14, "About This Build",
         "Application identity, version, build revision and display recovery.", "Show", {}, {},
         columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "", true},
        {16, "Archived Activity Viewer", "Opening a collected activity record read-only.", "Show",
         {}, {}, columns("Topic", "Action", "Location / Command", "Notes"), "HELP ARTICLE", "",
         false}};

  case WorkspacePage::explorer:
  case WorkspacePage::remote:
  case WorkspacePage::general_tools: {
    // Host Checks, a check box for each group this system runs, then Process inventory, the part
    // that is the same question on every host; it keeps the Windows columns so the two editions
    // read alike.
    std::vector<OperationOption> checks;
    for (const HostCheckGroup& group : host_check_groups_here())
      checks.push_back({host_check_label(group), true, group.description});
    std::vector<OperationDefinition> host{{kHostChecksMode, "Host Checks",
             "Read-only checks of what most often explains a failed snapshot or backup. Tick the checks to run.",
             "Run checks", {}, checks, columns("Group", "Check", "Detail", "Status"), "HOST CHECKS",
             "system host-checks", true},
            {13, "Process inventory",
             "List running processes with their identity, thread count and working set, so a "
             "hung or runaway Veeam component can be named precisely.",
             "Inventory", {}, {},
             columns("Process", "PID / Parent", "Threads / Working Set",
                     "Executable / Command Line"),
             "PROCESS INVENTORY", "", false}};
#ifdef __linux__
    // The Linux counterpart of Windows' Named Pipes: the Unix domain sockets, read from /proc.
    host.push_back({kUnixSocketsMode, "Unix sockets",
                    "List every Unix domain socket by path, with its type, whether it listens and the process "
                    "that holds it. Veeam's, PostgreSQL's and the system's own are marked. No socket is opened.",
                    "List sockets",
                    {{"Sockets shown", "Every socket, or Veeam sockets",
                      "Veeam sockets keeps the Veeam and database sockets and the sockets of Veeam programs.", false,
                      "Every socket"}},
                    {}, columns("Socket", "Instances", "Known as", "Service or process"), "UNIX SOCKETS",
                    "system pipes", true});
#endif
    return host;
  }

  case WorkspacePage::wmi_diagnostics:
  case WorkspacePage::vbr_diagnostics:
  case WorkspacePage::vss_tools:
  case WorkspacePage::registry_change:
    // Explorer is a file browser rather than an operation form, Help is a card wall of articles,
    // and the Windows-only pages never reach a portable frontend.
    return {};
  case WorkspacePage::storage_tools:
    // Storage Tools' cards open their own windows.
    return {};
  }
  return {};
}

// The caption on the operation selector. AppWindow::configure_mode() renames it per page, because
// "Operation" is wrong for a page whose selector chooses a help article or a review action.
inline std::string operation_selector_label(WorkspacePage page) {
  switch (page) {
  case WorkspacePage::help:
    return "Help article";
  case WorkspacePage::log_review:
    return "Review action";
  default:
    return "Operation";
  }
}

// The run state shown on a session tab, as AppWindow::tool_session_state_label() reports it.
enum class SessionState { idle, running, finished };

inline std::string session_state_label(SessionState state) {
  switch (state) {
  case SessionState::idle:
    return "IDLE";
  case SessionState::running:
    return "RUN";
  case SessionState::finished:
    return "FINISHED";
  }
  return "IDLE";
}

} // namespace support_assist::gui
