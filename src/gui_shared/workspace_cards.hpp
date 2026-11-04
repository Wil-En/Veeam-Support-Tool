#pragma once

// The card wall for every workspace, and the Help articles behind it.
//
// WHY THIS EXISTS SEPARATELY
//
// Every SAT workspace has the same anatomy: a wall of action cards, optionally split by ALL-CAPS
// section captions, where a card opens an operation that renders as a four-column rows table
// (Section / Heading / Explanation / Note). Home is not a special case - it is that pattern with
// navigation cards. Reproducing the anatomy is what makes the Linux edition look and behave like
// the product rather than like a different application with the same colours.
//
// The reference is AppWindow::cards_for_page() and AppWindow::run_help() in the Windows frontend.
// The copy below is the product's own wording, so both editions describe the same action in the
// same words. Where a card names a Windows-only mechanism it is either omitted (VSS, Registry, WMI,
// VBR) or its wording is corrected for the platform - never left claiming something Linux cannot do.
//
// `implemented` is the honest bit. A card that the Qt frontend cannot yet run is still SHOWN,
// because the catalog is what an engineer navigates by, but it reports its phase instead of
// pretending to work.

#include "host_checks_form.hpp"
#include "keyboard_shortcuts.hpp"
#include "portable_workspace_model.hpp"
#include "quick_tool_help.hpp"
#include "scenario_form.hpp"
#include "workspace_view_model.hpp"

#include <optional>
#include <string>
#include <vector>

namespace support_assist::gui {

struct PageCard {
  std::string badge;
  std::string title;
  std::string description;
  // The workspace the card belongs to. For navigation cards this is the page it opens.
  WorkspacePage page = WorkspacePage::home;
  // Operation mode within that page, matching the Windows mode numbers so the two editions stay
  // comparable when a defect is reported against one of them.
  int mode = 0;
  bool section_header = false;
  // False means the Qt frontend cannot run it yet. It is still listed; opening it says so.
  bool implemented = false;
};

inline PageCard card_section(std::string title) {
  PageCard card;
  card.title = std::move(title);
  card.section_header = true;
  return card;
}

// One row of a Help article, matching the Row shape every SAT operation produces.
struct ArticleRow {
  std::string section;
  std::string heading;
  std::string explanation;
  std::string note;
};

// Help article modes, matching AppWindow::help_topic_title().
//
// The per-page articles below are shared: F1 opens the article for the page in view on BOTH
// editions, and there is one copy of the words. getting_started, security and about stay separate
// per edition because their text names the platform (guide filename, privilege model, the
// Windows-only tool categories). Windows renders diagnostics from these rows and adds a row for the
// system tools on its File Browser page.
//
// Each Tools category has an article of its own. Guided Diagnostics, Network Tools and Host
// Diagnostics offer different tools on each edition, so their articles describe this edition's page.
//
// Absent here on purpose: 7 (VSS), 8 (Registry), 31 (WMI Diagnostics) and 32 (VBR Diagnostics)
// describe pages that exist only on Windows, so Linux never asks for them; 15 and 16 are
// operations, not articles.
enum class HelpTopic {
  getting_started = 0,
  home_and_cases = 1,
  health_monitor = 2,
  tools_catalog = 3,
  log_collection = 4,
  log_review = 5,
  sql_tools = 6,
  filesystem_change = 9,
  integrations = 10,
  diagnostics = 11,
  security = 12,
  case_dashboard = 13,
  about = 14,
  file_browser = 17,
  remote_ssh = 18,
  recent_activity = 19,
  storage_tools = 20,
  name_check = 21,
  local_port_checker = 22,
  time_check = 23,
  file_lock_check = 24,
  volume_check = 25,
  service_watch = 26,
  file_transfer_calculator = 27,
  object_storage_check = 28,
  guided_diagnostics = 29,
  network_tools = 30,
  host_diagnostics = 33
};

inline std::string help_topic_title(HelpTopic topic) {
  switch (topic) {
  case HelpTopic::getting_started:
    return "Getting Started";
  case HelpTopic::home_and_cases:
    return "Home and Case Workspace";
  case HelpTopic::health_monitor:
    return "Health Monitor";
  case HelpTopic::tools_catalog:
    return "Tools Catalog and Categories";
  case HelpTopic::log_collection:
    return "Log Collection";
  case HelpTopic::log_review:
    return "Log Review";
  case HelpTopic::sql_tools:
    return "SQL Tools";
  case HelpTopic::filesystem_change:
    return "System Differences";
  case HelpTopic::integrations:
    return "Integrations";
  case HelpTopic::diagnostics:
    return "Diagnostics";
  case HelpTopic::security:
    return "Security, Elevation and Data";
  case HelpTopic::case_dashboard:
    return "Case Dashboard";
  case HelpTopic::about:
    return "About Support Assist Tool";
  case HelpTopic::file_browser:
    return "File Browser";
  case HelpTopic::remote_ssh:
    return "Remote (SSH)";
  case HelpTopic::recent_activity:
    return "Recent Activity";
  case HelpTopic::storage_tools:
    return "Storage Tools";
  case HelpTopic::name_check:
    return "Name Check";
  case HelpTopic::local_port_checker:
    return "Local Port Checker";
  case HelpTopic::time_check:
    return "Time Check";
  case HelpTopic::file_lock_check:
    return "File Lock Check";
  case HelpTopic::volume_check:
    return "Volume Check";
  case HelpTopic::service_watch:
    return "Service and Process Watch";
  case HelpTopic::file_transfer_calculator:
    return "File Transfer Calculator";
  case HelpTopic::object_storage_check:
    return "Object Storage Check";
  case HelpTopic::guided_diagnostics:
    return "Guided Diagnostics";
  case HelpTopic::network_tools:
    return "Network Tools";
  case HelpTopic::host_diagnostics:
    return "Host Diagnostics";
  }
  return "Help";
}

// Whether this build carries the topic: Storage Tools holds only the Object Storage Check, which only
// test builds carry.
inline bool help_topic_built(HelpTopic topic) {
#ifdef SUPPORT_ASSIST_OBJECT_STORAGE_CHECK
  static_cast<void>(topic);
  return true;
#else
  return topic != HelpTopic::storage_tools && topic != HelpTopic::object_storage_check;
#endif
}

// The Help window's topic list, in the order Windows fills its dropdown
// (AppWindow::open_help_window). Security is folded into About on both editions. VSS Diagnostic Lab,
// Registry Change, WMI Diagnostics and VBR Diagnostics are Windows pages, Import Previous SAT Data
// migrates Windows-era state, and 16 opens an archived activity file rather than an article.
inline std::vector<HelpTopic> help_window_topics() {
  std::vector<HelpTopic> topics{
          HelpTopic::getting_started, HelpTopic::home_and_cases,    HelpTopic::health_monitor,
          HelpTopic::tools_catalog,   HelpTopic::log_collection,    HelpTopic::log_review,
          HelpTopic::sql_tools,       HelpTopic::filesystem_change, HelpTopic::integrations,
          HelpTopic::diagnostics,     HelpTopic::case_dashboard,    HelpTopic::about,
          HelpTopic::file_browser,    HelpTopic::remote_ssh,        HelpTopic::recent_activity,
          HelpTopic::storage_tools,
          HelpTopic::name_check,
          HelpTopic::local_port_checker,
          HelpTopic::time_check,
          HelpTopic::file_lock_check,
          HelpTopic::volume_check,
          HelpTopic::service_watch,
          HelpTopic::file_transfer_calculator,
          HelpTopic::object_storage_check,
          HelpTopic::guided_diagnostics,
          HelpTopic::network_tools,
          HelpTopic::host_diagnostics};
  std::erase_if(topics, [](HelpTopic topic) { return !help_topic_built(topic); });
  return topics;
}

// A quick tool's article: what it checks, then the full instructions for each way to use it.
inline std::vector<ArticleRow> quick_tool_article(ShortcutCommand tool) {
  const QuickToolGuide guide = quick_tool_guide(tool);
  std::vector<ArticleRow> rows{{"WHAT", "What it checks", guide.what, guide.tip}};
  for (const QuickToolGuideEntry& entry : guide.entries) {
    std::string section;
    for (const char character : entry.label)
      section.push_back(character >= 'a' && character <= 'z' ? static_cast<char>(character - 'a' + 'A') : character);
    rows.push_back({section, entry.label, entry.detail, entry.mode.empty() ? std::string() : entry.mode + " only."});
  }
  return rows;
}

// The article F1 opens from a quick tool's window.
inline std::optional<HelpTopic> quick_tool_help_topic(ShortcutCommand tool) {
  switch (tool) {
  case ShortcutCommand::name_check:
    return HelpTopic::name_check;
  case ShortcutCommand::local_port_checker:
    return HelpTopic::local_port_checker;
  case ShortcutCommand::time_check:
    return HelpTopic::time_check;
  case ShortcutCommand::file_lock_check:
    return HelpTopic::file_lock_check;
  case ShortcutCommand::volume_check:
    return HelpTopic::volume_check;
  case ShortcutCommand::service_watch:
    return HelpTopic::service_watch;
  case ShortcutCommand::file_transfer_calculator:
    return HelpTopic::file_transfer_calculator;
  case ShortcutCommand::object_storage_check:
    return HelpTopic::object_storage_check;
  default:
    return std::nullopt;
  }
}

// A quick tool's row in the article of the category that lists it: what it checks, and where its
// full instructions are.
inline ArticleRow category_quick_tool_row(ShortcutCommand tool) {
  const KeyboardShortcut* shortcut = shortcut_for(tool);
  const std::string key = shortcut_text(tool);
  return {"QUICK TOOL", shortcut != nullptr ? std::string(shortcut->label) : std::string(),
          quick_tool_guide(tool).what,
          "Opens in its own window" + (key.empty() ? std::string() : " with " + key) +
              ". F1 there opens its full article."};
}

// The Help page's card wall. Neither edition navigates to the page any more: help is the Help menu
// (User Guide, Getting Started, About SAT) and F1, which opens the current page's article in its
// own window. About SAT carries the security, elevation and data rows, so nothing here is reachable
// only through this wall. Import Previous SAT Data is absent because it migrates Windows-era
// Logs/State layouts that a Linux install does not have.
inline std::vector<PageCard> help_cards() {
  return {
      {"ABOUT", "About Support Assist Tool",
       "Application identity, version, build revision, executable role and display recovery.",
       WorkspacePage::help, static_cast<int>(HelpTopic::about), false, true},
      {"START", "Getting Started",
       "Workspace roles, navigation, sessions and the recommended support workflow. Press F1 on any "
       "page for help about that page.",
       WorkspacePage::help, static_cast<int>(HelpTopic::getting_started), false, true},
      {"SAFE", "Security, Elevation and Data",
       "Privilege escalation, evidence handling, privacy, and customer-safe operation.",
       WorkspacePage::help, static_cast<int>(HelpTopic::security), false, true},
  };
}

// `build_number` and `build_date` complete the About version line; the Windows edition renders
// About itself and calls this only for the shared topics, so it passes neither.
inline std::vector<ArticleRow> help_article(HelpTopic topic,
                                            const std::string& version,
                                            const std::string& channel,
                                            const std::string& build_revision,
                                            const std::string& executable,
                                            const std::string& product_name,
                                            int build_number = 0,
                                            const std::string& build_date = std::string()) {
  switch (topic) {
  case HelpTopic::getting_started:
    return {
        {"WORKFLOW", "Use a case workspace when the investigation needs persistence",
         "A case is optional. Create or register a case when logs, reports, notes, captures and "
         "baselines should remain together across sessions. Leave Active Case set to No active case "
         "for one-off diagnostics or reviews.",
         "Use a customer-approved evidence location and avoid collecting unrelated personal data."},
        {"WORKFLOW", "Choose the diagnostic area",
         "Use Health Monitor for a live overview, Log Review for transferred Veeam evidence, and "
         "Tools is the complete execution catalog, grouped by Log Collection, Guided Diagnostics, "
         "Network, SQL, Filesystem and host diagnostics. File Browser, Diagnostics and Integrations "
         "are separate application areas.",
         "VSS, Registry and WMI categories are Windows-only and are not present on Linux."},
        {"SESSIONS", "Multiple tool instances remain open",
         "Each open tool instance appears as its own tab, including duplicate instances of the same "
         "parser or diagnostic. Fifteen sessions are allowed by default; File > Settings > General > "
         "Maximum tool sessions can raise the limit to 30. Close Tool removes only the active "
         "session.",
         "Running operations must be cancelled before their tool tab can be closed."},
        {"DISPLAY", "Recover the entire interface with F5",
         "F5 recalculates layout and repaints the window and its controls.",
         "A redraw does not restart scans or discard results, column widths, selection or scroll "
         "position."}};
  case HelpTopic::security:
    return {
        {"ELEVATION", "Operation-specific privilege escalation",
         "SAT runs unprivileged. Only operations that genuinely require elevated rights request "
         "them, and ordinary browsing and analysis remain unprivileged.",
         "SAT runs without installation and leaves nothing behind when removed."},
        {"DATA", "Evidence handling",
         "Logs, packet captures, SQL output and process information may contain customer-sensitive "
         "content. Store artifacts only in the approved case workspace and review them before "
         "sharing.",
         ""},
        {"PRIVACY", "Review evidence before sharing",
         "Use the case workspace to keep collected artifacts together. Review logs, captures, "
         "reports and exported notes for customer-sensitive information before they are shared "
         "outside the case workflow.",
         ""}};
  case HelpTopic::home_and_cases:
    return {
        {"HOME", "System Health summary",
         "The compact home panel shows CPU, temperature, physical memory, commit and per-volume "
         "capacity or activity. Open Health Monitor for detailed paging, storage, NIC and process "
         "information.",
         "Unknown temperature or SMART data is not treated as healthy."},
        {"HOME", "Case workspaces and Active Case",
         "New Case creates Logs, Captures, Reports, Baselines, Notes and Third-Party folders. The "
         "Case Dashboard keeps New Case, Load Saved Review, Review New Logs / Append and Open Case "
         "Note visible; less-frequent re-analysis, folder, management and permanent deletion "
         "actions live under More.",
         "Parsing and diagnostics remain available with No active case selected."},
        {"HOME", "Recent Activity",
         "Shows starts, completions, failures and cancellation requests recorded by this "
         "installation. It is an operator convenience record, not a replacement for the exported "
         "case report.",
         ""},
        {"HOME", "Close",
         "The Close card exits the application. The card layout reserves enough height for every "
         "home action even when the health summary is expanded.",
         ""}};
  case HelpTopic::health_monitor:
    return {
        {"OVERVIEW", "Dashboard cards",
         "Overall Health, CPU/Temperature, Memory, Paging, Storage and Network/Top Process "
         "summarize the most important current measurements. Card colour reflects the highest "
         "active severity in that area.",
         ""},
        {"FINDINGS", "Active Findings",
         "Lists threshold findings with the observed value and an explanation of why the condition "
         "matters. Warnings use sustained pressure or a meaningful combination such as high disk "
         "active time plus latency. On Windows the System and Application logs are also read for "
         "disk and file-system problems in the last 7 days (bad blocks, controller errors, retried "
         "I/O, device resets, NTFS and ReFS corruption, chkdsk at startup), and for a desktop heap "
         "allocation failure since the last restart; each one found is a finding.",
         ""},
        {"STORAGE", "Storage and Device Health",
         "Volumes show capacity, the partition style (GPT or MBR), the sector size (with the physical "
         "size when it differs), the storage driver, throughput, active time, latency and queue "
         "depth. Physical devices show health, operational state and predictive failure when the "
         "controller exposes it.",
         "Unsupported SMART data appears as Unavailable rather than Healthy."},
        {"NETWORK", "Physical Network Adapters",
         "Shows operational state with the link speed and MTU, receive/transmit rates and new drops "
         "or errors. Quiet capture, "
         "QoS, filter, loopback and tunnel interfaces are hidden by default to keep the dashboard "
         "readable.",
         ""},
        {"PROCESSES", "Top Processes",
         "Shows up to 25 processes with CPU, private memory and read/write rates. Protected "
         "processes may expose only partial information.",
         ""}};
  case HelpTopic::tools_catalog:
    return {
        {"CATALOG", "Tools is the complete categorized catalog",
         "Scroll through section headers for Guided Diagnostics, Log Collection, Network, SQL, "
         "Filesystem and installed-product diagnostics. File Browser, Diagnostics and Integrations "
         "remain separate application areas.",
         "VSS, Registry and WMI categories are Windows-only and are not present on Linux."},
        {"CONNECTIVITY", "Network Tools",
         "The Remote and Local Port Checkers, Name Check, the File Transfer Calculator (F10), "
         "listeners, TLS, loopback, RPC, gRPC, SMB, packet capture and throughput are grouped under "
         "Network Tools rather than mixed into product diagnostics.",
         "The File Transfer Calculator works out a transfer's time from the link speed and the size, "
         "and can measure the network to SAT's listener on the other machine."},
        {"VBR", "VBR Diagnostics appears only on a VBR server",
         "Running VBR Jobs is exposed only when SAT positively identifies a local Veeam Backup & "
         "Replication installation. The shared Veeam Backup log folder is not an installation "
         "signal.",
         ""},
        {"CAPTURE", "Packet capture",
         "Start creates a capture through the supported platform backend. Status checks the current "
         "session. Stop closes it safely. Conversion to PCAPNG uses an approved converter when one "
         "is available.",
         "Packet captures may contain customer-sensitive traffic metadata."},
        {"THROUGHPUT", "iPerf and native throughput tests",
         "Client and one-shot server modes measure transport throughput. Use only on approved "
         "endpoints and ports; a throughput test generates significant network traffic.",
         ""},
        {"ARTICLES", "Each category has its own article",
         "Press F1 on a category's page for its article: each tool on the page, what it checks, its "
         "fields, what its results mean and what needs elevated rights.",
         ""},
        {"OUTPUT", "Last Tool Output",
         "Once a tool has run, Last Tool Output on the Tools page offers Prepare, which packages that "
         "run's output with its hostname, a manifest and SHA-256 hashes for the review workstation, "
         "and Delete, which removes that output once its evidence has been transferred.",
         "Universal Log Collection takes every tool output kept on this machine, so Prepare is for one "
         "tool's output on its own."}};
  case HelpTopic::log_collection:
    return {
        {"COLLECT", "Universal Veeam product collection",
         "Detected Veeam products are checked by default and can be selected together. "
         "Product-neutral shared Veeam roots are collected independently because multiple products "
         "can write there; their presence is never treated as VBR identity. The collector "
         "deduplicates overlapping physical paths, preserves product-role provenance, writes a "
         "manifest and can create a ZIP for transfer.",
         ""},
        {"CUSTOM", "Custom-path collection",
         "Use Custom Paths when the required evidence is outside a product profile. Enter only "
         "customer-approved files or folders and review the manifest before sharing the package.",
         ""},
        {"OUTPUT", "Collection output",
         "The result table lists copied, skipped and inaccessible items. Partial access failures do "
         "not erase files that were collected successfully.",
         ""}};
  case HelpTopic::log_review:
    return {
        {"PROFILES", "Unified Veeam Review is the normal parser path",
         "Use Auto Detect / Unified Veeam Review for normal work. It identifies Veeam Agent for "
         "Microsoft Windows, Veeam Agent for Linux, Veeam Agent for Mac, Veeam Agent for IBM AIX, "
         "Veeam Agent for Oracle Solaris, Veeam Backup & Replication and supported plug-in "
         "evidence. Explicit product profiles remain available for advanced troubleshooting; "
         "Generic Parser is the manual fallback.",
         ""},
        {"SOURCES", "Review several bundles together",
         "Add multiple folders, logs or ZIP bundles in one review. Veeam Agent for Microsoft "
         "Windows treats each source bundle as one primary endpoint by default so logs that omit "
         "machine identity do not create synthetic unknown machines.",
         ""},
        {"INDEX", "Indexed versus Full Review",
         "The state banner is authoritative. INDEXED: PRELIMINARY means the current source still "
         "has deferred evidence. Complete full review uses that same source and changes the banner "
         "to FULLY ANALYZED: FULL REVIEW COMPLETE. The primary action follows that state; "
         "run-specific deep scan, append, #note and bookmarking are kept under More.",
         ""},
        {"DASHBOARD", "Machine and Product / Selected Job Run dashboard",
         "The dashboard presents bundle scope, machine identity, product/version evidence, selected "
         "run, run window, job/workload evidence, and finding counts. Explicit session/job "
         "identifiers take priority over timestamp correlation.",
         ""},
        {"ISSUES", "Issue summary and source evidence",
         "Issues are grouped by signature without losing complete occurrence counts. Selecting a "
         "row shows chronological retained locations with the original bundle path and exact line; "
         "double-click opens the retained source line.",
         ""},
        {"SEARCH", "Search Existing Logs",
         "Search runs against existing files without collecting them again. Results include "
         "severity, full source path, line and matching text.",
         ""}};
  case HelpTopic::sql_tools:
    return {
        {"CONNECT", "Connecting",
         "Choose the server from this machine's instances or the configuration database's "
         "server, or type any name. Engine is SQL Server or PostgreSQL; choosing one of this "
         "machine's instances sets it. Use logged-in user connects as the account running SAT; clear "
         "it to be asked for a login, which is used for that run and not saved. Trust the server "
         "certificate accepts SQL Server's own self-signed certificate. Every check reads only.",
         ""},
        {"DATABASES", "Database lists",
         "Opening the Database or Configuration database list reads the databases the server "
         "accepts connections to, as the account running SAT, so it needs Use logged-in user. The "
         "list is kept for the session, so opening it again is immediate. A name can always be "
         "typed.",
         ""},
        {"POSTGRESQL", "PostgreSQL",
         "PostgreSQL runs through psql, found in the Tools folder, on the PATH or in the PostgreSQL "
         "install folders. The server is host or host:port, and this machine's servers are listed "
         "as host:port. A login is a role and its password, handed to psql for that run only. The "
         "same five checks run. The Permission check holds the role against the superuser "
         "requirement on Veeam's permissions page and reports the other role attributes as facts; "
         "Check against and Trust the server certificate are for SQL Server.",
         ""},
        {"PERMISSIONS", "Permission check",
         "Holds an account's rights against Veeam's Permissions page. Guest processing: sysadmin, "
         "or the minimal list (server roles, securables, and roles in model, master and msdb). "
         "Configuration database: CREATE ANY DATABASE for installation; db_datareader, db_datawriter "
         "and EXECUTE, or db_owner, for operation; db_owner for upgrade. Without Another account it "
         "checks the account connecting, counting its Windows groups; Another account reads that "
         "login's catalog rows, which needs VIEW ANY DEFINITION, and does not expand its groups.",
         "To check the account Veeam uses, run SAT as that account."},
        {"SHAPE", "Server shape",
         "Failover cluster instance and its nodes, availability groups with their replicas, roles, "
         "listeners, cluster and backup preference, and the databases this node is the preferred "
         "backup replica for. What Veeam's guides say about a shape shows beside it.",
         ""},
        {"BACKUPS", "Backups and log chain",
         "Reads msdb's backup history for the days chosen: full, copy-only full, differential and log "
         "backups and who took each (Veeam by the software, vendor id or device name it records; a VSS "
         "snapshot full as likely Veeam's where Veeam is present). A backup outside Veeam that is not "
         "copy-only, a log backup to NUL, a gap in the log chain, a restart, a restore and a database "
         "that cannot take a log backup each show as a finding (KB2117, KB2027).",
         ""},
        {"CHAIN", "The log chain",
         "Below the findings, LOG CHAIN lists every backup oldest first: the time, the backup (Full A, "
         "Log 1, Differential, Full, copy-only, Log to NUL) and what it is to the chain. OK is a log "
         "that follows the one before it. Base is the full a chain starts from; Base changed, a full "
         "that is not copy-only, so the logs after it depend on it. Lost is a log backup to NUL, whose "
         "range no restore can cross, and After loss a log after it. New chain is a full a chain "
         "starts again from after a gap, and Gap before a log that does not start where the one before "
         "it ended. Who took a backup is named where it changes.",
         ""},
        {"FILES", "Database files and volumes",
         "Lists every database file. On the SQL host each file's volume is classified: kind, bus, "
         "file system and sector size, with network shares, cluster shared volumes and removable "
         "drives marked.",
         ""},
        {"QUERY", "Read-only query",
         "Runs a query that reads data, typed or chosen from the named queries, and lists each value. A "
         "query that changes data does not run; the database console is for those.",
         ""}};
  case HelpTopic::filesystem_change:
    return {
#ifdef _WIN32
        {"HOW", "How it works",
         "A card per type, File Differences and Registry Differences, opens a page holding its fields and the Capture, Compare and "
         "Load buttons. Capture what is there, make the change or wait for it, then compare. A capture "
         "records each file and folder under one folder: its name, size, times, attributes and, if chosen, a "
         "SHA-256 of its contents. It records one moment. Run as administrator on a local NTFS volume, a "
         "capture reads the folder from the NTFS master file table, through NTFS, and records where the NTFS "
         "change journal stood; the compare then reads the journal to list files created and removed in "
         "between and files renamed, which two captures alone cannot show. Otherwise the folder is read "
         "folder by folder, and the result line says why.",
         "Without administrator the journal is not recorded, and the result line says so. Windows keeps a "
         "limited journal, so after a long time or much activity the part covering the capture may be "
         "overwritten; the result line says that too."},
#else
        {"HOW", "How it works",
         "The File Differences card opens a page holding Capture, Compare and Open. Capture what is there, make the "
         "change or wait for it, then compare. A capture records each file "
         "and folder under one folder: its name, size, times, attributes and, if chosen, a SHA-256 of its "
         "contents. It records one moment, so a file created and removed between the capture and the "
         "compare does not appear.",
         ""},
#endif
        {"CAPTURE", "Capture",
         "Folder to look at is where the capture starts; everything under it is included. Capture file is "
         "the .satsnap file it writes. A capture file holds one capture, so capturing to an existing file "
         "replaces it after a question. Compare file contents: Never compares names, sizes and times; Files "
         "up to 64 MB and All files also read each file, which finds a change that left its size and times "
         "alone.",
         "A whole volume takes far longer than a folder, and its capture file can reach several gigabytes. "
         "Places that need administrator rights are listed as Skipped; run SAT as administrator to include "
         "them. A cancelled capture is not kept, as it cannot be compared."},
        {"COMPARE", "Compare",
         "Capture file is the earlier capture; when it is not there yet, Compare takes the capture first. "
         "Compare with Now reads the same folder again with the same "
         "settings and in the way the capture was read; a second capture file compares the two captures "
         "instead. The result line counts what was added, removed, changed, and moved or renamed, and says "
         "when and where the capture was taken. Each row gives the reason and the values before and after. "
         "Every compare is kept in the capture file. Last-access time alone is not a difference, as reading "
         "a file changes it.",
         "Compare with Now writes a temporary capture to this machine's temporary folder, about the size of "
         "the first, and removes it afterwards. Cancel stops it at once."},
        {"OPEN", "Open",
         "Opens a capture file and lists what it holds: when, where and as which user it was taken, the "
         "folder, whether contents were compared, then the compares kept in it, newest first, each with its "
         "counts and rows, then each file and folder in path order with its size, last write time and, when "
         "contents were read, its SHA-256. The capture file is only read.",
         "The first 100,000 objects are listed; the result line gives the totals."},
#ifdef _WIN32
        {"REGISTRY", "Capture, compare and load the registry",
         "The Registry Differences card opens the same three buttons for the registry. Registry scope is the key the "
         "capture starts from, such as HKLM\\SOFTWARE\\Veeam, or a whole hive: HKLM, HKU, HKCR, HKCC or "
         "HKCU. Registry view chooses the 64-bit view, the 32-bit view or both. The compare works as it does "
         "for files: with Now, or with a second registry capture, and it is kept in the capture file. Load "
         "lists the kept compares, then each key and its values with their data.",
         ""},
#endif
    };
  case HelpTopic::storage_tools:
    return {
        {"DISK", "Disk Speed Test",
         "Measures how fast the storage behind a folder reads and writes, with Veeam's own access "
         "patterns from KB2014 (a backup's sequential writes, a merge's random reads and writes, a "
         "restore's reads) or settings of your own. A test that writes uses SAT's own test file in "
         "the folder and deletes it; a file you choose is only read. Used as says what the storage "
         "is, a backup repository or a backup source, and the result says what the figures mean for "
         "it.",
         "It opens from Integrations: DiskSpd's Run on Windows, fio's on Linux, fio from the "
         "distribution's packages. The test loads the storage while it runs."},
        {"OBJECT", "Object Storage Check (experimental)",
         "Checks an S3-compatible bucket the way Veeam reaches it: the endpoint's name and address, "
         "the TLS certificate and its names, the clock, the sign-in and region, and the immutability "
         "settings Veeam's guide requires. It writes nothing. It shows once Settings > General > "
         "Experimental turns it on.",
         "A cloud provider can bill each request at a fraction of a cent; the check shows its "
         "estimate before it sends any. The keys are kept for the session only."}};
  case HelpTopic::integrations:
    return {
        {"INSPECT", "Inspect Integrations",
         "Shows approved utilities found in the managed Tools folder or PATH, including version and "
         "source state.",
         ""},
        {"ACQUIRE", "Download Supported Tool",
         "Select an approved tool and managed destination. Packages with a maintained direct source "
         "are downloaded after explicit confirmation; otherwise the official publisher page opens.",
         ""},
        {"REMOVE", "Remove SAT-Managed Tool Copy",
         "Removes the copy downloaded below the Support Assist managed Tools folder.",
         ""},
        {"CONFIGURED", "Your own configured tools",
         "A configured tool is a program you already trust, launched against the case and evidence "
         "currently open. The placeholders {case}, {evidence} and {selected} are substituted when "
         "it runs. Entries are stored in configured-tools.tsv beside SAT's other state.",
         "A configured tool runs at SAT's own privilege level."}};
  case HelpTopic::diagnostics:
    return {
        {"PAGE", "One report",
         "The page reads all three when it opens and shows them as one report. Run again reads them "
         "again; Copy gives the report as text.",
         ""},
        {"HOST", "System Information",
         "Shows hostname, domain or workgroup join state, hardware identity, operating system and "
         "boot information from read-only sources.",
         ""},
        {"PRODUCTS", "Products and Integrations",
         "Detects installed Veeam products and the approved optional tools found in the managed "
         "Tools folder or on PATH.",
         ""},
        {"SELF-TEST", "SAT Self-Test",
         "Checks this copy of SAT: version and build, whether it can write to its temporary and "
         "case folders, and whether the bundled libraries still match their recorded SHA-256.",
         ""},
        {"BROWSE", "Files and case evidence", "File and case browsing is on the File Browser page.",
         ""}};
  case HelpTopic::case_dashboard:
    return {
        {"CASE", "Case Dashboard overview",
         "The selected case is shown as a case-wide Veeam topology. Cards summarize case identity, "
         "systems/components, backup runs, related activity, findings, case evidence and the last "
         "saved review.",
         ""},
        {"TOPOLOGY", "Source owners and related systems",
         "The System / Component selector includes source owners and related Veeam components or "
         "managed workloads from every structured parser. VBR manager logs keep the Backup Server "
         "as the source owner while repositories, plug-in hosts and protected workloads remain "
         "related entities.",
         ""},
        {"WORK", "System / Component to Job / Activity to Run",
         "Select a system or component, then a grouped Backup, Plug-in, Rescan or Activity item, "
         "then an exact run. All-runs selections show a summary and do not silently bind the first "
         "run.",
         ""},
        {"NOTES", "Case-owned notes",
         "Open Case Note uses the selected system/component as the note scope. Select ALL Systems / "
         "Components to open the Master Note. Only explicitly selected runs, error/warning evidence "
         "and Health Monitor items contribute parser-derived content.",
         ""},
        {"CONTINUE", "Continue or delete the case",
         "Load Saved Review reopens persisted parser data without rescanning. Review new logs / "
         "append merges later evidence. Delete Active Case permanently removes the case workspace "
         "and SAT references after confirmation and only when no busy operation is bound to the "
         "case.",
         ""}};
  case HelpTopic::file_browser:
    return {
        {"BROWSE", "Open Veeam and case evidence in place",
         "File Browser lists collected log bundles and the active case's evidence tree, read-only. "
         "Selecting a file makes it the {selected} target for a configured tool.",
         ""},
        {"LOCAL", "Local files and the console",
         "The Local Files tab browses the approved evidence roots. The Console tab runs a shell on "
         "this machine at SAT's own privilege level, next to the files being looked at. The session "
         "stays open between commands, so a folder change carries to the next one; Stop ends it "
         "and anything still running in it.",
         ""}};
  case HelpTopic::remote_ssh:
    return {
        {"CONNECT", "Connect to a lab or customer host over SSH",
         "Enter the host, port, user, and a session-only password or a private key with its "
         "passphrase, then press Connect. Pick a saved lab address from the Host list; favourites "
         "are managed in Settings > SSH Addresses (address only).",
         ""},
        {"HOST KEY", "Host key approval",
         "An unrecognised host key is shown for approval before the session authenticates. Compare "
         "the fingerprint against what the host is expected to present, then trust it for this "
         "session.",
         ""},
        {"TRANSFER", "Terminal and file transfer",
         "The terminal runs interactively; the file pane lists a remote path with sizes and dates "
         "and moves a file in either direction. A download opens in the open case's logs folder, "
         "and an upload asks before it replaces a file of the same name. Select with the mouse and "
         "use Ctrl+Shift+C and Ctrl+Shift+V to copy and paste. Credentials are held for the "
         "session only.",
         ""}};
  case HelpTopic::recent_activity:
    return {
        {"ACTIVITY", "What Recent Activity records",
         "Operation starts and outcomes from this installation, newest first. It is application "
         "activity rather than case evidence, and stays available in Customer / Lab with no case "
         "selected.",
         ""},
        {"SCOPE", "Per-case and application-wide entries",
         "An entry made while a case was active carries that case. Entries made with no case "
         "selected are still recorded against the installation.",
         ""},
        {"ARCHIVE", "Opening an archived activity file",
         "Archived Activity Viewer opens an activity.tsv from a collected bundle or an "
         "ApplicationLogs folder read-only, so a bundle's history can be read without disturbing "
         "the live record.",
         ""}};
  case HelpTopic::about: {
    // The rows of AppWindow::run_help() mode 14, with the security, elevation and data rows rolled
    // in, in the same order.
    std::vector<ArticleRow> rows{
        {"ABOUT", product_name,
         "Support Assist Tool combines case-centered Veeam log review, health review, evidence "
         "selection and focused host diagnostics in one application.",
         ""},
        {"EXECUTABLE", "Application",
         executable + " is the Support Assist Tool application. Operations that require additional "
                      "privileges can request them when needed.",
         ""}};
    for (const auto& row : help_article(HelpTopic::security, version, channel, build_revision,
                                        executable, product_name)) {
      rows.push_back(row);
    }
    rows.push_back({"DISPLAY", "F5 redraw",
                    "A complete redraw is available with F5. Ordinary redraws preserve tool-session "
                    "results and view state.",
                    ""});
    rows.push_back({"GUIDE", "HTML User Guide",
                    "Help > User Guide opens the guide shipped in the documents folder beside the "
                    "application, with feature guidance and task-oriented procedures, including "
                    "the Windows-only categories that do not apply on Linux.",
                    ""});
    if (build_number > 0) {
      const std::string full = version + "." + std::to_string(build_number);
      rows.push_back({"VERSION", "Version information",
                      "Version " + full + (build_date.empty() ? "" : " (built " + build_date + ")") +
                          ". Support detail: " + version + " " + channel + " build " +
                          build_revision + ". Include the full version " + full +
                          " when reporting an application issue.",
                      ""});
    } else {
      rows.push_back({"VERSION", "Version information",
                      "Version " + version + " " + channel + " | Build " + build_revision +
                          ". Include both the version and build revision when reporting an "
                          "application issue.",
                      ""});
    }
    return rows;
  }
  case HelpTopic::name_check:
    return quick_tool_article(ShortcutCommand::name_check);
  case HelpTopic::local_port_checker:
    return quick_tool_article(ShortcutCommand::local_port_checker);
  case HelpTopic::time_check:
    return quick_tool_article(ShortcutCommand::time_check);
  case HelpTopic::file_lock_check:
    return quick_tool_article(ShortcutCommand::file_lock_check);
  case HelpTopic::volume_check:
    return quick_tool_article(ShortcutCommand::volume_check);
  case HelpTopic::service_watch:
    return quick_tool_article(ShortcutCommand::service_watch);
  case HelpTopic::file_transfer_calculator:
    return quick_tool_article(ShortcutCommand::file_transfer_calculator);
  case HelpTopic::object_storage_check:
    return quick_tool_article(ShortcutCommand::object_storage_check);
  case HelpTopic::guided_diagnostics: {
    // One row per scenario this machine offers (support_assist/scenarios.hpp), after how the page works.
    std::vector<ArticleRow> rows{
        {"PAGE", "Scenarios",
         "Choose the scenario that matches the symptom, fill in what it asks for, and run it on the machine named "
         "under Run it on, once what is listed under Set up first is in place. Each step is one of SAT's read-only checks, in order, and the lists below say what each "
         "one reads or sends; a step that decides the case stops the run when it fails, and Keep going after a "
         "failure runs every step. Each step's row in the results says what was found, what it means in Veeam's "
         "terms, what to do next and the page it follows; the Result and Case note rows are the block for the case.",
         "Every step reads only; a fix it points to is made by the customer's administrator."}};
    for (const ScenarioDefinition& scenario : guided_scenarios_here()) {
      std::string inputs;
      for (const ScenarioInput& input : scenario.inputs)
        inputs += (inputs.empty() ? "" : ", ") + input.label;
      rows.push_back({"SCENARIO", scenario.title, scenario_article_text(scenario),
                      inputs.empty() ? std::string("It asks for nothing.") : "Fields: " + inputs + "."});
    }
    return rows;
  }
  case HelpTopic::network_tools: {
    std::vector<ArticleRow> rows{
        {"CONNECTIVITY", "Remote Port Checker",
         "Tests whether this machine reaches a port on another host: TCP connectivity test or UDP "
         "connectivity test in Operation. Fields: Host, Port, Timeout ms and, for TCP, Payload MiB. "
#ifdef _WIN32
         "Send from these adapters chooses the source adapters, and IPv4 and IPv6 the address "
         "families; with none ticked, Windows routes the test, and localhost takes the loopback path. "
#else
         "Test through each discovered local interface tests from each local address in turn; Local "
         "network interfaces lists them. "
#endif
         "The rows show where the name resolved from (SOURCE: the hosts file or a DNS server), a row "
         "each for IPv4 and IPv6, then each address tried with its result, CONNECTED or FAILED with "
         "the reason.",
         "A TCP connect proves the socket path. Against a SAT listener, Validate an in-memory payload "
         "sends Payload MiB and compares the byte count and SHA-256 at both ends. UDP has no "
         "handshake: with no answer a UDP row reads INDETERMINATE, and only a SAT UDP listener, with "
         "Verify a cooperating SAT UDP listener ticked, makes it VERIFIED."}};
    for (const ShortcutCommand tool : {ShortcutCommand::local_port_checker, ShortcutCommand::name_check,
                                       ShortcutCommand::file_transfer_calculator})
      rows.push_back(category_quick_tool_row(tool));
    const std::vector<ArticleRow> tools{
        {"PROTOCOLS", "TLS Handshake",
         "Performs a TLS handshake with a host and port: the TCP connection, HANDSHAKE PASS or FAILED "
         "with the version and cipher negotiated, and the certificate the server presents. Fields: "
         "Host, Port, TLS server name / SNI (optional), the name to check when it differs from the "
         "host, and Expected SHA-1/SHA-256 fingerprint (optional). Compare TLS 1.2 and TLS 1.3 "
         "separately tries each version on its own. The certificate rows read HOSTNAME MATCH or "
         "MISMATCH, TRUSTED or TRUST FINDING against the certificates this machine trusts, and "
         "VERIFIED or MISMATCH against the fingerprint given, OBSERVED with none.",
         "A version the server has turned off fails its own handshake: read the result against "
         "Veeam's current list of protocols and ciphers."},
        {"PROTOCOLS", "Windows RPC Connectivity",
         "Connects to the RPC Endpoint Mapper of a Windows host and asks for a DCE/RPC bind, which a "
         "working RPC service answers with BIND_ACK. Fields: Target host, RPC Endpoint Mapper port "
         "and Timeout ms; the port is 135. The TCP connection and the Endpoint Mapper's answer have "
         "rows of their own: VERIFIED needs the BIND_ACK, and a FAILURE STAGE row names where it "
         "stopped.",
         "A service reached through RPC then uses a dynamic port, which a firewall can still block "
         "after port 135 passes."},
        {"PROTOCOLS", "gRPC Connectivity",
         "Tests the transport gRPC runs on: TCP, then TLS offering h2 when Use TLS and require ALPN "
         "h2 is ticked, then the HTTP/2 preface, SETTINGS and a PING. Fields: Target host, Port and "
         "TLS server name / SNI (optional). Each layer has its row, and a FAILURE STAGE row names the "
         "first that failed. Against a SAT gRPC Listener, the result also confirms the SAT at the far "
         "end. With TLS it shows the server's certificate; when the peer answers with something that is "
         "not HTTP/2, a First bytes row shows what it sent. Veeam's data ports (2500 to 3300, 6162) speak "
         "Veeam's own transport and stop at SETTINGS.",
         "It tests the transport only; no application gRPC method is called."},
        {"PROTOCOLS", "Veeam Service Channel",
#ifdef _WIN32
         "Tests the channel Veeam Agent's tray, jobs and control panel use to reach the Veeam service, in "
         "layers: Service, the Veeam service; Named pipe, its pipe; HTTP/2 handshake, a handshake on the "
         "pipe as this account (SETTINGS and a PING; no gRPC call); Logs, the gRPC lines the product "
         "logged in the hours chosen. Fields: Veeam product, Log folder (another folder of its logs, such "
         "as a bundle's) and Hours; Read the logs only skips the service, pipe and handshake.",
#else
         "Reads a folder of Veeam Agent for Windows' logs, such as a bundle's Endpoint folder, for the "
         "gRPC lines of the channel its processes use to reach the Veeam service: service starts and "
         "stops, clients that could not connect (KB2127) and calls whose deadline passed. Fields: Veeam "
         "product, Log folder and Hours.",
#endif
         "The summary line is written for a case note."},
#ifdef _WIN32
        {"PROTOCOLS", "SMB Connectivity",
         "Tests SMB to a Windows machine outside Veeam: TCP 445, the SMB session with its dialect, "
         "signing and encryption, the path, then a small SAT file written, read back and deleted "
         "there. Fields: Target machine, Bounded test path and TCP / SMB timeout ms; the path is on "
         "C$, C$\\Windows\\Veeam to begin with. Prompt Windows for alternate credentials lets Windows "
         "ask for another account; otherwise the account SAT runs as is used. PROOF reads VERIFIED "
         "when every stage passed, and FAILURE STAGE names the first that did not.",
         "C$ admits only administrators of the target machine, so the account used must be one. "
         "Windows' own prompt takes the alternate password."},
#else
        {"PROTOCOLS", "SMB Connectivity",
         "Tests SMB to a Windows machine: TCP 445, the session, a path on the C$ share and a small "
         "file written, read back and deleted there.",
         "Windows only: on this edition its row reads NOT AVAILABLE."},
#endif
        {"LISTENERS", "TCP / UDP Listener",
         "Listens on this machine for a test from another: TCP listener or UDP listener in "
         "Operation. Fields: Listen port, Duration seconds and, for TCP, Banner, the text sent to "
         "each client, where %port% becomes the port. Accept multiple connections until timeout "
         "keeps a TCP listener open after the first. Each connection shows as it arrives, with its "
         "address; a SAT probe shows its Test ID, the same as on the sending machine, and a UDP probe "
         "is acknowledged.",
#ifdef _WIN32
         "The first time SAT listens on a network, Windows can ask whether to allow it, and the "
         "answer stays as a firewall rule. When the listener stops, FIREWALL rows list the rules that "
         "name SAT, to remove in Windows Defender Firewall after the test."},
#else
         "A port below 1024 needs SAT running as root."},
#endif
        {"LISTENERS", "Local Loopback Self-Test",
         "Tests this machine's own TCP path through a temporary SAT listener on the loopback "
         "address. Fields: Loopback port and Timeout ms. When something already listens on the "
         "port, the row names it and the test stops: choose a free port. A pass proves the local "
         "stack, not the path to another machine.",
         ""},
        {"LISTENERS", "gRPC Listener",
         "Runs a SAT HTTP/2 listener for gRPC Connectivity from another machine. Fields: Listen port "
         "and Duration seconds; Accept multiple connections until timeout keeps it open after the "
         "first. Each connection shows as it arrives, with its HTTP/2 and SAT stages.",
         ""},
#ifdef _WIN32
        {"CAPTURE", "Packet Capture",
         "Captures this machine's network traffic into the run's tool output under "
         "Log-Collections\\Tools, with pktmon, or with netsh trace when pktmon is missing or does not "
         "start. Fields: IP filter and Port filter, both optional. Start capture starts it, and a "
         "Packets so far row is updated every 5 seconds while it runs. Stop capture, the same "
         "button, ends it, converts it to PCAPNG beside the ETL file (pktmon first, etl2pcapng from "
         "Integrations when pktmon cannot read it) and writes the packets as text. The results list "
         "the notable events with their times: TCP retransmissions, duplicate ACKs, keep-alives, "
         "resets, zero windows and missing segments, and TLS handshake messages and alerts. A packet "
         "pktmon logs at several components counts once.",
         "Needs administrator. When SAT is not elevated it asks once, and that approval covers the "
         "start and the stop. A capture can hold customer traffic: review it before sharing."},
        {"CAPTURE", "Convert ETL to PCAPNG",
         "Converts an ETL capture, such as one from another machine, to PCAPNG for Wireshark. "
         "Fields: Input ETL, Output PCAPNG and Optional converter fallback folder, a folder holding "
         "etl2pcapng.",
         ""},
        {"PERFORMANCE", "Network Throughput",
         "Measures sustained TCP throughput between two SAT machines: Native throughput server on "
         "one, with Listen port, Connection timeout ms and Idle timeout ms, then Native throughput "
         "client on the other, with Server address, Port and Transfer size, such as 1G. The result "
         "shows the bytes moved, the time taken and the rate.",
         "iPerf client and iPerf one-shot server measure the same with iPerf3 from Integrations; "
         "Optional tools folder names a copy kept elsewhere. The test loads the network while it "
         "runs."},
        {"ADMIN", "What needs administrator",
         "Packet Capture, with one approval when SAT is not elevated, and Local Port Checker's Quick "
         "scan. SMB Connectivity needs an administrator of the target machine for C$. The other "
         "tools here run as a standard user.",
         ""}};
#else
        {"CAPTURE", "Packet Capture", "Captures this machine's network traffic into the run's tool output.",
         "This edition lists it without running it: it needs a capture helper this build does not "
         "carry."},
        {"PERFORMANCE", "Network Throughput",
         "Measures sustained TCP throughput between two SAT machines: Native throughput server on "
         "one, with Listen port, Connection timeout ms and Idle timeout ms, then Native throughput "
         "client on the other, with Server address, Port and Transfer size, such as 1G. The result "
         "shows the bytes moved, the time taken and the rate.",
         "iPerf client and iPerf one-shot server are listed without running on this edition. The test "
         "loads the network while it runs."},
        {"INTERFACES", "Local network interfaces",
         "Lists the local interfaces a test can start from, with their addresses, including virtual, "
         "VLAN and bonded ones.",
         ""},
        {"ROOT", "What needs root",
         "Local Port Checker's Quick scan, and a listener on a port below 1024. The other tools here "
         "run as an ordinary user.",
         ""}};
#endif
    rows.insert(rows.end(), tools.begin(), tools.end());
    return rows;
  }
  case HelpTopic::host_diagnostics: {
    std::vector<ArticleRow> rows;
    for (const ShortcutCommand tool : {ShortcutCommand::time_check, ShortcutCommand::file_lock_check,
                                       ShortcutCommand::volume_check, ShortcutCommand::service_watch})
      rows.push_back(category_quick_tool_row(tool));
#ifdef _WIN32
    rows.push_back(
        {"HOST CHECKS", "Host Checks",
         "Read-only checks of what most often explains a failed snapshot or backup, a check box each. Backup "
         "events counts volsnap 25 and 36, VSS 8193 and 12289, disk 129 and 153, and NTFS 55 and 98 in the "
         "System and Application logs over Days, with the newest event's own text, as an event id alone does "
         "not name the cause. Veeam drivers lists every Veeam driver with its state and how it starts, and the "
         "change tracking store. VSS shadow storage shows each volume's used, allocated and maximum shadow "
         "storage and its shadow copies; it needs administrator. .NET and TLS shows the .NET Framework release "
         "and the SchUseStrongCrypto, SystemDefaultTlsVersions and SCHANNEL protocol values, an absent value "
         "being the Windows default.",
         "Finding is something the logs or settings show; Information is what is there. Nothing is changed."});
    rows.push_back(
        {"PROCESSES", "Process Inventory",
         "One row per process running on this machine, read through WMI (Win32_Process): the name, PID and "
         "parent PID, thread count and working set, then the executable path and command line. It has no "
         "fields; the rows sort by any column.",
         "Without administrator, WMI often gives no path or command line for system processes and for other "
         "accounts' processes, which then read Executable path unavailable."});
    rows.push_back(
        {"PIPES", "Named Pipes",
         "Every named pipe in \\\\.\\pipe\\ on this machine, one per row: its name, its instances as current of "
         "maximum, what it is known as and its service or process. The pipes of Veeam products, SQL Server and "
         "PostgreSQL show their product, purpose and the service with its state; a pipe whose name carries a "
         "process ID, such as a .NET diagnostics port, shows that process and the service it runs. Pipes shown "
         "is Every pipe or Veeam pipes. The filter box narrows the rows by any text.",
         "The list is read by name only: no pipe is opened, connected to or waited on, so a pipe that takes "
         "one client at a time is left as it is. It needs no administrator. CLI: system pipes [--veeam]."});
    rows.push_back(
        {"INSTALLED SOFTWARE", "Installer Cache Check",
         "Lists what Windows Installer records of each installed product and whether the cached "
         "package it needs is still in C:\\Windows\\Installer, then checks an installer you have "
         "against them. UpgradeCode or product name is part of a name or publisher, or an "
         "UpgradeCode: Veeam, the default, lists every product Veeam installed, and an empty field "
         "lists every product. Installer, or a folder, to check (optional) takes an .msi, an .exe or "
         "a folder such as a mounted ISO. Each product shows its ProductCode, UpgradeCode, version, "
         "install date, original package, PackageCode, last used source and Cached package, PRESENT "
         "or MISSING, with each patch. An .msi checked reads MATCH when its PackageCode is a listed "
         "product's, the package Windows asks for, or DIFFERENT BUILD when only its ProductCode or "
         "UpgradeCode matches; every file checked shows its SHA-256.",
         "When a Cached package reads MISSING, uninstalling, repairing or upgrading the product asks "
         "for its original installer: Original package gives the file name. The check only reads "
         "and needs no administrator."});
    rows.push_back({"ELSEWHERE", "Process Inventory and Process Monitor",
                    "Process Inventory is on WMI Diagnostics. Process Monitor's capture is on "
                    "Integrations: Start capture and Stop capture beside Launch, with the administrator "
                    "approval Procmon needs.",
                    ""});
    rows.push_back({"ADMIN", "What needs administrator",
                    "Volume Check shows BitLocker, and Host Checks VSS shadow storage, only when SAT runs as "
                    "administrator. The other tools here run as a standard user.",
                    ""});
#else
    rows.push_back({"HOST CHECKS", "Host Checks",
                    "Read-only checks of what most often explains a failed snapshot or backup, a check box each. "
                    "Veeam drivers shows veeamsnap, blksnap and veeamblksnap: loaded and their version, installed "
                    "for this kernel, and what DKMS holds and has built for it, with the kernel headers when DKMS "
                    "is used. A module DKMS has not built for the running kernel is a Finding, as that is how it "
                    "goes missing after a kernel update. Kernel log counts the lines in kern.log or messages that "
                    "name blksnap, veeamsnap, an I/O error or a file system error, with the newest line.",
                    "The kernel log file is readable by root on most systems."});
    rows.push_back({"HOST CONTEXT", "Linux Host Diagnostics",
                    "Lists the 25 busiest processes, by CPU and then memory, read from /proc: name, PID, "
                    "threads, working set and CPU use, and the executable, so a hung or runaway Veeam "
                    "component can be named.",
                    "Another account's executable reads (path not readable) unless SAT runs as root."});
    rows.push_back({"ROOT", "What needs root",
                    "Linux Host Diagnostics shows other accounts' executables, File Lock Check "
                    "other accounts' programs, and Host Checks the kernel log, only when SAT runs as "
                    "root. The rest runs as an ordinary user.",
                    ""});
#endif
    return rows;
  }
  }
  return {};
}

// A help article as the Help window shows it on both editions: the title, then each row's heading
// with its explanation and note indented beneath. A topic with no rows (an operation rather than an
// article) shows its summary instead.
//
// Articles are prose. Forcing them into the four-column result grid - which an earlier revision of
// the Qt frontend did - turns a readable page into a table of sentence fragments.
inline std::string format_help_article(const std::string& title, const std::string& summary,
                                       const std::vector<ArticleRow>& rows) {
  std::string text = title + "\n\n";
  if (!summary.empty()) {
    text += summary + "\n\n";
  }
  for (const auto& row : rows) {
    if (!row.heading.empty()) {
      text += row.heading + "\n";
    }
    if (!row.explanation.empty()) {
      text += "    " + row.explanation + "\n";
    }
    if (!row.note.empty()) {
      text += "    Note: " + row.note + "\n";
    }
    text += "\n";
  }
  return text;
}

// The card wall for a workspace.
//
// Windows-only categories are absent rather than disabled, for the reason given on
// workspace_pages(). Cards whose wording named a Windows mechanism are reworded for the platform.
inline std::vector<PageCard> page_cards(WorkspacePage page, WorkspaceRole role) {
  switch (page) {
  case WorkspacePage::help:
    return help_cards();

  case WorkspacePage::log_collection:
    return {
        {"AUTO", "Universal Veeam Log Collection",
         "Detect Veeam products on this machine, select what belongs to the case scope, and gather "
         "the appropriate bounded logs and support context.",
         page, 0, false, false},
        {"CUSTOM", "Custom Paths",
         "Collect explicitly selected customer-approved files or folders when catalog paths are not "
         "sufficient.",
         page, 1, false, false}};

  case WorkspacePage::log_review:
    return {
        {"AUTO", "Auto Detect Veeam Logs (Recommended)",
         "Discover the product/source profile for each supplied evidence source and review mixed "
         "product bundles without assuming one global parser.",
         page, 5, false, false},
        {"FIND", "Search Existing Logs",
         "Search existing log files with copyable source path, line and matching text.", page, 0,
         false, false},
        {"VAW", "Review Veeam Agent for Microsoft Windows Logs",
         "Use the Veeam Agent for Microsoft Windows parser as an explicit source override.", page, 1,
         false, false},
        {"VBR", "Review Veeam Backup & Replication Logs",
         "Use the Veeam Backup & Replication parser as an explicit source override.", page, 2, false,
         false},
        {"SQL", "Review Veeam Plug-In for Microsoft SQL Server Logs",
         "Use the Microsoft SQL Server plug-in parser as an explicit source override.", page, 3,
         false, false},
        {"RMAN", "Review Veeam Plug-In for Oracle RMAN Logs",
         "Use the Oracle RMAN plug-in parser as an explicit source override.", page, 4, false,
         false},
        {"GENERIC", "Generic Parser",
         "For logs from several Veeam products, or from a product with no parser of its own.", page, 6,
         false, false}};

  case WorkspacePage::network_tools:
    return {
        card_section("CONNECTIVITY & PROTOCOLS"),
        {"NET", "Remote Port Checker",
         "Ports on another host: TCP or UDP over IPv4 and IPv6, where the name resolved from, "
         "source-interface routing and SAT-to-SAT verification.",
         page, 0, false, false},
        {"TLS", "TLS Handshake",
         "Validate TLS negotiation, certificate presentation and protocol details independently of "
         "the application.",
         page, 18, false, false},
        {"RPC", "Windows RPC Connectivity",
         "Validate TCP reachability and a DCE/RPC Endpoint Mapper exchange against a Windows host, "
         "instead of treating TCP/135 alone as RPC success.",
         page, 20, false, false},
        {"gRPC", "gRPC Connectivity",
         "Validate TCP, optional TLS/ALPN, HTTP/2 and gRPC transport behavior without requiring an "
         "application-specific service definition.",
         page, 21, false, false},
        {"VEEAM", "Veeam Service Channel",
         "The channel Veeam's own processes use to reach their service: the service, its pipe, an HTTP/2 "
         "handshake and the gRPC lines the product logged.",
         page, 27, false, false},
        {"SMB", "SMB Connectivity",
         "Verify TCP/445, SMB negotiation, path access and a bounded write/read/delete payload "
         "outside Veeam.",
         page, 24, false, false},
        card_section("LISTENERS & PEER TESTS"),
        {"LISTEN", "TCP / UDP Listener",
         "Listen for controlled inbound TCP or UDP probes and record live peer/test details for "
         "correlation.",
         page, 1, false, false},
        {"LOOP", "Local Loopback Self-Test",
         "Verify the local TCP loopback stack using a temporary SAT listener only when the "
         "requested port is free.",
         page, 19, false, false},
        {"gRPC", "gRPC Listener",
         "Run a cooperating SAT HTTP/2/gRPC transport listener for controlled two-endpoint case "
         "testing.",
         page, 22, false, false},
        card_section("CAPTURE & PERFORMANCE"),
        {"CAP", "Packet Capture",
         "Capture network evidence into the case Log-Collections tree using the platform's capture "
         "facility.",
         page, 5, false, false},
        {"RATE", "Network Throughput",
         "Measure controlled TCP throughput between two toolkit endpoints using the built-in "
         "client/server or an approved iPerf copy.",
         page, 14, false, false}};

  case WorkspacePage::sql_tools:
    return {
        {"PERM", "Permission check",
         "An account's rights against Veeam's Permissions page: guest processing or the "
         "configuration database.",
         page, 0, false, false},
        {"SHAPE", "Server shape", "Failover cluster instance, availability groups, replicas and backup preference.",
         page, 1, false, false},
        {"LOG", "Backups and log chain", "Whose backups msdb holds, and gaps or breaks in the log chain.", page, 2,
         false, false},
        {"FILES", "Database files", "Every database file and the volume it is on.", page, 3, false, false},
        {"QUERY", "Read-only query", "A query that reads data, typed or chosen from the named queries.", page, 4, false, false}};

  case WorkspacePage::storage_tools:
    // The Disk Speed Test opens from Integrations; each edition adds the Object Storage Check card
    // while Settings > General > Experimental is on.
    return {};

  case WorkspacePage::filesystem_change:
    // A card per type; each opens a page holding that type's Capture, Compare and Open.
    return {
        {"FILES", "File Differences",
         "Capture a folder's files and folders, compare the capture with now or with a second capture, "
         "and open a capture to see what it holds and the compares kept in it.",
         page, 0, false, false}};

  case WorkspacePage::tools: {
    // Tools is the complete sectioned execution catalog, assembled from the category pages exactly
    // as the Windows edition assembles it - minus the four Windows-only categories.
    std::vector<PageCard> cards;
    const auto append = [&cards](WorkspacePage source, std::vector<PageCard> from) {
      static_cast<void>(source);
      for (auto& card : from) {
        cards.push_back(std::move(card));
      }
    };
    // Each category this platform has, from the table, under its name in capitals; a category's
    // own section captions would nest inside Tools' captions.
    for (const ToolCategoryInfo& info : kToolCategoryTable) {
      if (!info.sidebar || info.windows_only)
        continue;
      std::string caption(info.title);
      for (char& character : caption) {
        if (character >= 'a' && character <= 'z')
          character = static_cast<char>(character - 'a' + 'A');
      }
      cards.push_back(card_section(caption));
      std::vector<PageCard> from;
      for (auto& card : page_cards(info.page, role)) {
        if (!card.section_header)
          from.push_back(std::move(card));
      }
      append(info.page, std::move(from));
    }
    return cards;
  }

  case WorkspacePage::general_tools:
    // Host Diagnostics. Each edition lists the quick checks above this (home_board.hpp
    // kQuickChecksSection).
    return {card_section("HOST CHECKS"),
            {"CHECK", "Host Checks",
             "Read-only checks of what most often explains a failed snapshot or backup: the Veeam snapshot "
             "module and the kernel log.",
             page, kHostChecksMode, false, true},
            card_section("HOST CONTEXT"),
            {"HOST", "Linux Host Diagnostics",
             "The running processes with their identity, thread count and working set, read from "
             "/proc, so a hung or runaway Veeam component can be named.",
             page, 13, false, true}};

  case WorkspacePage::diagnostics:
    return {
        {"HOST", "System Information",
         "Review hostname, join state, hardware, OS and boot information.", page, 1, false, true},
        {"APPS", "Products and Integrations",
         "Detect installed Veeam products and approved optional support tools.", page, 3, false,
         true},
        {"SELF", "SAT Self-Test",
         "Check this copy of SAT: version and build, whether it can write to its temporary and "
         "case folders, and whether the bundled libraries still match their recorded SHA-256.",
         page, 4, false, false}};

  case WorkspacePage::guided_diagnostics: {
    std::vector<PageCard> cards;
    const auto& scenarios = guided_scenarios_here();
    for (std::size_t index = 0; index < scenarios.size(); ++index)
      cards.push_back({"GUIDE", scenarios[index].title, scenarios[index].symptom, page, static_cast<int>(index), false, false});
    return cards;
  }

  case WorkspacePage::home:
  case WorkspacePage::case_manager:
  case WorkspacePage::case_dashboard:
  case WorkspacePage::environment_review:
  case WorkspacePage::note_review:
  case WorkspacePage::recent_activity:
  case WorkspacePage::health_monitor:
  case WorkspacePage::explorer:
  case WorkspacePage::remote:
  case WorkspacePage::tool_manager:
  case WorkspacePage::wmi_diagnostics:
  case WorkspacePage::vbr_diagnostics:
  case WorkspacePage::vss_tools:
  case WorkspacePage::registry_change:
    // Home is the status board (home_board.hpp). The review workspaces are driven by case data
    // rather than a card wall, and the Windows-only pages never reach a portable frontend.
    return {};
  }
  return {};
}

// The name an operation shows in its page's Tool list and its tab: the title of the card that opens
// it, the operation's own title when no card does.
inline std::string operation_display_name(WorkspacePage page, int mode, const std::string& title,
                                          WorkspaceRole role) {
  for (const PageCard& card : page_cards(page, role)) {
    if (!card.section_header && card.page == page && card.mode == mode && !card.title.empty())
      return card.title;
  }
  return title;
}

} // namespace support_assist::gui
