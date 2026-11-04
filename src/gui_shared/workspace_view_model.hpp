#pragma once

// Presentation-neutral description of the SAT workspace.
//
// WHY THIS EXISTS
//
// The Windows frontend is 28,000 lines with presentation and product decisions interleaved, so
// "which pages exist", "what columns does this table have" and "what can you do with a row" are
// answerable only by reading Win32 code. Every new frontend then re-derives those answers and
// drifts from the others, which is how Linux ended up missing whole workspaces and how the portable
// editions ended up offering tool categories that cannot run.
//
// This header states them once. A frontend binds to it and draws; it does not decide.
//
// It deliberately contains NO toolkit types - no HWND, no QWidget, no NSView - so it compiles and
// is unit-tested on every platform, including ones that cannot build the GUI at all.

#include "portable_workspace_model.hpp"

#include <array>
#include <cstddef>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist::gui {

// Every workspace the product can present. The Windows edition owns the reference set; portable
// editions expose the subset their platform supports.
enum class WorkspacePage {
  home,
  // Where an engineer picks a case; the dashboard is where they work it.
  case_manager,
  case_dashboard,
  environment_review,
  note_review,
  recent_activity,
  health_monitor,
  tools,
  general_tools,
  storage_tools,
  wmi_diagnostics,
  vbr_diagnostics,
  network_tools,
  guided_diagnostics,
  log_collection,
  log_review,
  explorer,
  // Connect to another machine: an interactive terminal and file transfer. Its own page, separate
  // from Explorer, rather than a property of an Explorer tab.
  remote,
  sql_tools,
  vss_tools,
  registry_change,
  filesystem_change,
  tool_manager,
  diagnostics,
  help
};

// ---------------------------------------------------------------------------------------------
// Tools categories
//
// The categories of the Tools page, in the order the sidebar, the Tools page and the category
// tiles list them. Both editions' sidebars, the pages list, the Customer / Lab rule, the Tools
// board, F1 and the navigation gate read this one table, so a new category is a row here, a page
// in each edition, its cards and its own F1 article. Last Tool Output is a tile and a section of the Tools page, never
// a sidebar row.
// ---------------------------------------------------------------------------------------------

enum class ToolCategory {
  log_collection,
  guided_diagnostics,
  network_tools,
  sql_tools,
  vss_tools,
  registry_change,
  filesystem_change,
  wmi_diagnostics,
  vbr_diagnostics,
  host_diagnostics,
  storage_tools,
  last_output,
};

struct ToolCategoryInfo {
  ToolCategory category;
  WorkspacePage page;         // the page it opens; the Tools page for Last Tool Output
  std::string_view title;
  std::string_view id;        // the page's stable id
  std::string_view cli_verb;  // the command line's twin; empty when there is none
  int help_mode;              // the category's own F1 article: a HelpTopic value, or Windows' 7, 8, 31, 32
  bool windows_only;          // VSS Tools, Registry Change, WMI Diagnostics, VBR Diagnostics
  bool sidebar;               // a row under Tools
};

inline constexpr ToolCategoryInfo kToolCategoryTable[] = {
    {ToolCategory::log_collection, WorkspacePage::log_collection, "Log Collection", "log-collection", "logs gather", 4, false, true},
    {ToolCategory::guided_diagnostics, WorkspacePage::guided_diagnostics, "Guided Diagnostics", "guided", "guided", 29, false, true},
    {ToolCategory::network_tools, WorkspacePage::network_tools, "Network Tools", "network", "network", 30, false, true},
    {ToolCategory::sql_tools, WorkspacePage::sql_tools, "SQL Tools", "sql-tools", "sql check", 6, false, true},
    {ToolCategory::vss_tools, WorkspacePage::vss_tools, "VSS Tools", "vss-tools", "", 7, true, true},
    {ToolCategory::registry_change, WorkspacePage::registry_change, "Registry Change", "registry-change", "", 8, true, false},
    {ToolCategory::filesystem_change, WorkspacePage::filesystem_change, "System Differences", "filesystem-change", "files baseline", 9, false, true},
    {ToolCategory::wmi_diagnostics, WorkspacePage::wmi_diagnostics, "WMI Diagnostics", "wmi-diagnostics", "", 31, true, true},
    {ToolCategory::vbr_diagnostics, WorkspacePage::vbr_diagnostics, "VBR Diagnostics", "vbr-diagnostics", "", 32, true, true},
    {ToolCategory::host_diagnostics, WorkspacePage::general_tools, "Host Diagnostics", "general-tools", "", 33, false, true},
    {ToolCategory::storage_tools, WorkspacePage::storage_tools, "Storage Tools", "storage-tools", "storage", 20, false, true},
    {ToolCategory::last_output, WorkspacePage::tools, "Last Tool Output", "last-output", "", 3, false, false},
};

// Every category, in the table's order.
inline constexpr auto kToolCategories = [] {
  std::array<ToolCategory, std::size(kToolCategoryTable)> categories{};
  for (std::size_t index = 0; index < categories.size(); ++index)
    categories[index] = kToolCategoryTable[index].category;
  return categories;
}();

inline constexpr const ToolCategoryInfo& tool_category_info(ToolCategory category) {
  for (const ToolCategoryInfo& info : kToolCategoryTable) {
    if (info.category == category)
      return info;
  }
  return kToolCategoryTable[0];
}

inline std::string_view tool_category_title(ToolCategory category) {
  return tool_category_info(category).title;
}

// The page a category opens. Last Tool Output is a section of the Tools page.
inline WorkspacePage tool_category_page(ToolCategory category) {
  return tool_category_info(category).page;
}

// The category a page shows, for its highlighted tile; none for the Tools page itself.
inline std::optional<ToolCategory> tool_category_of_page(WorkspacePage page) {
  // The registry's operations are on System Differences.
  if (page == WorkspacePage::registry_change)
    return ToolCategory::filesystem_change;
  for (const ToolCategoryInfo& info : kToolCategoryTable) {
    if (info.sidebar && info.page == page)
      return info.category;
  }
  return std::nullopt;
}

// Why a page is or is not offered on a platform.
enum class PageAvailability {
  // Present and usable.
  available,
  // The platform has no equivalent of the underlying technology. The page is NOT shown; the
  // Capability reference explains it. See portable_unavailable_technologies().
  not_applicable,
  // The platform could support it but something is missing (an ODBC driver manager, a build
  // without libssh2). The page IS shown and states what is missing, because that is actionable.
  requires_dependency
};

struct WorkspacePageInfo {
  WorkspacePage page = WorkspacePage::home;
  // Stable identifier, matching the CLI verb family where one exists.
  std::string id;
  std::string title;
  // Coarse category for reference material. See the note in workspace_pages(): this is not the
  // sidebar.
  std::string navigation_group;
  PageAvailability availability = PageAvailability::available;
  // Set when the page maps onto a CLI verb, which is what "Show CLI" emits. Empty means the page
  // has no command-line equivalent, and Show CLI must say so rather than emit a partial command.
  std::string cli_verb;
  std::string detail;
};

// Commands every table row offers, in every frontend.
//
// Windows had eleven list controls and three right-click handlers between them, so the same gesture
// worked on one page and did nothing on the next. Stating the set here is what stops each frontend
// inventing its own.
enum class RowCommand {
  copy_cell,
  copy_row,
  copy_all_rows,
  select_all,
  add_to_note,
  copy_log_path,
  open_in_viewer,
  reveal_in_file_manager
};

inline std::vector<RowCommand> universal_row_commands() {
  return {RowCommand::copy_cell,     RowCommand::copy_row,       RowCommand::copy_all_rows,
          RowCommand::select_all,    RowCommand::add_to_note,    RowCommand::copy_log_path,
          RowCommand::open_in_viewer, RowCommand::reveal_in_file_manager};
}

inline std::string row_command_label(RowCommand command, PortablePlatform platform) {
  switch (command) {
  case RowCommand::copy_cell:
    return "Copy cell";
  case RowCommand::copy_row:
    return "Copy row";
  case RowCommand::copy_all_rows:
    return "Copy all rows (with headers)";
  case RowCommand::select_all:
    return "Select all";
  case RowCommand::add_to_note:
    return "Add to #note";
  case RowCommand::copy_log_path:
    return "Copy log file path";
  case RowCommand::open_in_viewer:
    return "Open in log viewer";
  case RowCommand::reveal_in_file_manager:
    // Each platform has its own word for this and using the wrong one reads as a port rather than
    // a native application.
    return platform == PortablePlatform::macos ? "Reveal in Finder" : "Show containing folder";
  }
  return {};
}

// The workspace set for a platform.
//
// Windows-only pages are omitted from portable platforms rather than returned disabled: a page that
// can never run is not a page, and offering one teaches an engineer to click things that do
// nothing. portable_unavailable_technologies() carries the explanation instead.
inline std::vector<WorkspacePageInfo> workspace_pages(PortablePlatform platform,
                                                      bool ssh_available = true,
                                                      bool native_odbc_available = true) {
  const bool windows_only_supported = false;  // portable platforms only; Windows uses its own shell
  // Every member is initialised explicitly. A trailing omission compiles silently on MSVC and
  // is rejected by GCC under -Werror=missing-field-initializers, so the shared header has to
  // be complete or it breaks the very platforms it exists to serve.
  std::vector<WorkspacePageInfo> pages{
      {WorkspacePage::home, "home", "Home", "Overview", PageAvailability::available, "", ""},
      {WorkspacePage::case_manager, "cases", "Case Manager", "Overview", PageAvailability::available, "cases", ""},
      {WorkspacePage::case_dashboard, "case", "Case Dashboard", "Overview", PageAvailability::available, "case", ""},
      {WorkspacePage::log_review, "log-review", "Log Review", "Evidence", PageAvailability::available, "logs review", ""},
      {WorkspacePage::environment_review, "environment", "Environment Review", "Evidence", PageAvailability::available, "", ""},
      {WorkspacePage::note_review, "note-review", "Note Review", "Evidence", PageAvailability::available, "", ""},
      {WorkspacePage::recent_activity, "recent-activity", "Recent Activity", "Evidence", PageAvailability::available, "", ""},
      {WorkspacePage::explorer, "explorer", "File Browser", "Evidence", PageAvailability::available, "", ""},
      {WorkspacePage::remote, "remote", "Remote", "Evidence", PageAvailability::available, "", ""},
      {WorkspacePage::health_monitor, "health", "Health Monitor", "Diagnostics", PageAvailability::available, "health sample", ""},
      {WorkspacePage::tools, "tools", "Tools", "Tools", PageAvailability::available, "", ""}};
  // The Tools categories this platform has, from the one table.
  for (const ToolCategoryInfo& info : kToolCategoryTable) {
    if (!info.sidebar || info.windows_only)
      continue;
    pages.push_back({info.page, std::string(info.id), std::string(info.title), "Tools", PageAvailability::available,
                     std::string(info.cli_verb), ""});
  }
  pages.push_back({WorkspacePage::tool_manager, "tool-manager", "Integrations", "Tools", PageAvailability::available,
                   "tools status", ""});
  pages.push_back({WorkspacePage::diagnostics, "diagnostics", "Diagnostics", "Application",
                   PageAvailability::available, "diagnostics", ""});
  pages.push_back({WorkspacePage::help, "help", "Help / About", "Application", PageAvailability::available, "", ""});

  // Availability is decided after the list is built so the navigation order stays fixed. Appending
  // a page here instead would place it outside its own group and duplicate the group header.
  if (!native_odbc_available) {
    for (auto& page : pages) {
      if (page.page == WorkspacePage::sql_tools) {
        page.availability = PageAvailability::requires_dependency;
        page.detail =
            "Permission-script generation is available. Running a query natively needs an ODBC "
            "driver manager, which is not present on this machine.";
      }
    }
  }

  if (!ssh_available) {
    for (auto& page : pages) {
      if (page.page == WorkspacePage::explorer) {
        page.availability = PageAvailability::requires_dependency;
        page.detail = "Local browsing is available. Remote sessions need SSH support, which was not "
                      "compiled into this build.";
      }
    }
  }

  // NOTE: navigation_group is a coarse category label for reference material and search, NOT the
  // shape of the sidebar. The sidebar comes from navigation_items() below, which reproduces the
  // product's own role-driven navigation. Do not rebuild a menu out of these groups.
  static_cast<void>(platform);
  static_cast<void>(windows_only_supported);
  return pages;
}

// True when a page must never appear on a portable platform.
inline bool page_is_windows_only(WorkspacePage page) {
  return page == WorkspacePage::wmi_diagnostics || page == WorkspacePage::vss_tools ||
         page == WorkspacePage::registry_change || page == WorkspacePage::vbr_diagnostics;
}

// ---------------------------------------------------------------------------------------------
// Navigation
//
// SAT's sidebar is NOT a grouped list of every page. It is role-driven and mostly flat, and the
// reference implementation is AppWindow::rebuild_navigation() in the Windows frontend. Reproduced
// here so no frontend invents its own shape again - an earlier revision of this header grouped
// pages under OVERVIEW / EVIDENCE / DIAGNOSTICS / TOOLS / APPLICATION headings, which exists
// nowhere in the product. tools/test_navigation_parity.py compares this sidebar and
// go_menu_items() with the Windows source, so a change on one side fails the gate until the other
// follows.
//
// The two roles are a product concept, not a display option:
//
//   engineer_review  The support engineer's own workstation. Nothing is executed against a
//                    customer system, so the execution catalog is absent entirely.
//   customer_lab     SAT is running on the customer or lab machine. The execution catalog appears
//                    under an expandable Tools node, and casework (Case Manager, Case Dashboard)
//                    is hidden: that role runs tools and diagnostics on the machine, it does not
//                    manage or review cases. Session-only; never remembered across exits.
//
// Help is not a sidebar page on either edition: it is the Help menu and F1.
// ---------------------------------------------------------------------------------------------

enum class WorkspaceRole { engineer_review, customer_lab };

struct NavigationItem {
  WorkspacePage page = WorkspacePage::home;
  std::string title;
  // False for the caption rows. A caption is drawn and skipped, never opened.
  bool selectable = true;
  // Indented one level, under the Tools node.
  bool child = false;
  // An ALL-CAPS caption row rather than a workspace.
  bool section = false;
  // Carries the disclosure arrow that shows and hides its children.
  bool expandable = false;
};

// The sidebar for a platform and role.
//
// Windows-only execution tools (VSS, Registry Change, WMI, VBR Diagnostics) are absent on portable
// platforms rather than listed and disabled, for the reason given on workspace_pages().
inline std::vector<NavigationItem> navigation_items(PortablePlatform platform,
                                                    WorkspaceRole role,
                                                    bool tools_expanded = true,
                                                    bool local_vbr_server_available = false,
                                                    bool object_storage_enabled = true) {
  // PortablePlatform names only the portable frontends; Windows runs its own shell and does not
  // consume this header. The Windows-only execution tools in the reference implementation
  // (VSS Tools, Registry Change, WMI Diagnostics, VBR Diagnostics) therefore never appear here.
  static_cast<void>(local_vbr_server_available);
  static_cast<void>(platform);
  const bool execution = role == WorkspaceRole::customer_lab;
  std::vector<NavigationItem> items{{WorkspacePage::home, "Home", true, false, false, false}};
  if (!execution) {
    // Casework is Engineer Review only. Case Manager comes before Case Dashboard: picking the case
    // precedes working it.
    items.push_back({WorkspacePage::case_manager, "Case Manager", true, false, false, false});
    items.push_back({WorkspacePage::case_dashboard, "Case Dashboard", true, false, false, false});
  }
  // Environment Review and Log Review are available in both roles: case topology and a case's saved
  // review in Engineer Review, the live host and locally collected logs in Customer / Lab.
  items.push_back(
      {WorkspacePage::environment_review, "Environment Review", true, false, false, false});
  items.push_back({WorkspacePage::log_review, "Log Review", true, false, false, false});
  items.push_back({WorkspacePage::health_monitor, "Health Monitor", true, false, false, false});
  items.push_back({WorkspacePage::explorer, "File Browser", true, false, false, false});
  // Remote sits beside File Browser: a connection is its own workspace, not a tab inside the file
  // browser.
  items.push_back({WorkspacePage::remote, "Remote (SSH)", true, false, false, false});

  if (execution) {
    // Selectable as well as expandable: the row opens the Tools page, and opening it or any of its
    // categories shows the categories beneath it. Each category is a page of its own
    // (home_board.hpp ToolCategory).
    items.push_back({WorkspacePage::tools, "Tools", true, false, false, true});
    if (tools_expanded) {
      items.push_back({WorkspacePage::tools, "EXECUTION CATEGORIES", false, false, true, false});
      for (const ToolCategoryInfo& info : kToolCategoryTable) {
        // Storage Tools holds only the Object Storage Check, which Settings > General > Experimental adds.
        if (info.sidebar && !info.windows_only &&
            (info.category != ToolCategory::storage_tools || object_storage_enabled))
          items.push_back({info.page, std::string(info.title), true, true, false, false});
      }
    }
  }
  // Available in BOTH roles, so it sits outside the execution-host block above. The Configured
  // Tools actions - add a program, run it against the open case - apply on the Engineer Review
  // workstation as well as Customer / Lab; nothing on the page is specific to a customer machine.
  items.push_back(
      {WorkspacePage::tool_manager, "Integrations", true, false, false, false});

  items.push_back({WorkspacePage::recent_activity, "Recent Activity", true, false, false, false});
  // Diagnostics checks the machine SAT runs on, so it is a Customer / Lab page; it sits last.
  if (execution)
    items.push_back({WorkspacePage::diagnostics, "Diagnostics", true, false, false, false});
  return items;
}

// The Go menu, as AppWindow::build_main_menu() lists it: the same entries whatever the role, with
// the Windows mnemonics. Casework entries are greyed in Customer / Lab rather than removed, and
// Tools stays enabled in Engineer Review, where opening it says the tools need Customer / Lab.
struct GoMenuItem {
  WorkspacePage page = WorkspacePage::home;
  std::string label;
  // Greyed in Customer / Lab.
  bool casework = false;
};

inline std::vector<GoMenuItem> go_menu_items() {
  return {{WorkspacePage::home, "&Home", false},
          {WorkspacePage::case_manager, "Case &Manager", true},
          {WorkspacePage::case_dashboard, "Case &Dashboard", true},
          {WorkspacePage::environment_review, "&Environment Review", false},
          {WorkspacePage::health_monitor, "Health &Monitor", false},
          {WorkspacePage::log_review, "&Log Review", false},
          {WorkspacePage::explorer, "&File Browser", false},
          {WorkspacePage::remote, "&Remote (SSH)", false},
          {WorkspacePage::tools, "&Tools", false},
          {WorkspacePage::tool_manager, "&Integrations", false},
          {WorkspacePage::recent_activity, "Recent &Activity", false}};
}

// The pages a role cannot open, as AppWindow::select_page() refuses them. The execution catalog
// acts on the machine SAT runs on, so Engineer Review refuses it; casework is hidden in
// Customer / Lab, so a request for a case page goes to Home there.
inline bool page_requires_execution_host(WorkspacePage page) {
  return page == WorkspacePage::tools || page == WorkspacePage::diagnostics ||
         tool_category_of_page(page).has_value();
}

inline bool page_is_casework(WorkspacePage page) {
  return page == WorkspacePage::case_manager || page == WorkspacePage::case_dashboard ||
         page == WorkspacePage::note_review;
}

// The Tools categories: opening one of these shows the Tools group expanded, as Windows does.
inline bool page_is_tools_category(WorkspacePage page) {
  return page != WorkspacePage::tools && page != WorkspacePage::diagnostics &&
         page_requires_execution_host(page);
}

// ---------------------------------------------------------------------------------------------
// Home
//
// Home is the status board in both roles (home_board.hpp). What remains here is the action set
// Log Review's saved-review card and the Qt card handler still share.
// ---------------------------------------------------------------------------------------------

enum class HomeCardAction {
  // Opens a workspace.
  open_page,
  toggle_role,
  load_saved_review,
  exit_application
};


// The header badge's text. A click switches to the other role and a right-click opens the role
// menu with the licence, as AppWindow's badge does.
inline std::string workspace_role_badge(WorkspaceRole role) {
  return role == WorkspaceRole::customer_lab ? "CUSTOMER / LAB" : "ENGINEER REVIEW";
}

// ---------------------------------------------------------------------------------------------
// Shell behaviours
//
// The parts of SAT that belong to no single workspace. The keys are in keyboard_shortcuts.hpp, one
// list both editions dispatch from and Settings > Keyboard Shortcuts draws; the two affordances in
// the status bar are here. Reference implementation: the kStatusId NM_CLICK handler (Feedback,
// Debug) in the Windows frontend.
// ---------------------------------------------------------------------------------------------

// The status bar is not decoration. Both right-hand panes are controls, and an engineer who has
// used the Windows edition will click them.
enum class StatusBarCommand { feedback, toggle_debug_logging };

inline std::string status_bar_command_label(StatusBarCommand command, bool debug_enabled) {
  switch (command) {
  case StatusBarCommand::feedback:
    return "Feedback";
  case StatusBarCommand::toggle_debug_logging:
    return debug_enabled ? "Debug: On" : "Debug: Off";
  }
  return {};
}

// Where product feedback goes, defined once for every frontend. The address is kept encoded, so it is
// not plain text in the program or its source; feedback_address() decodes it when a licensed
// engineer sends feedback, and an unlicensed copy never calls it.
inline constexpr unsigned char kFeedbackAddressEncoded[] = {0x37, 0x16, 0xFB, 0x99, 0xBB, 0x94, 0x71,
                                                            0x56, 0x24, 0x31, 0xE3, 0xC3, 0xAB, 0x8A,
                                                            0x62, 0x4E, 0x64, 0x05, 0xE4, 0xCE, 0xB1};
inline std::string feedback_address() {
  // Read at run time, so the compiler cannot work the address out and store it as text.
  static volatile unsigned char seed = 0x5A;
  constexpr std::size_t length = sizeof(kFeedbackAddressEncoded);
  std::string address(length, '\0');
  for (std::size_t index = 0; index < length; ++index)
    address[length - 1 - index] = static_cast<char>(
        kFeedbackAddressEncoded[index] ^ static_cast<unsigned char>(seed + 31U * static_cast<unsigned>(index)));
  return address;
}
inline constexpr const char* kFeedbackSubject = "Support Tool (SAT) Feedback";
inline constexpr const char* kFeedbackBody =
    "Please describe the SAT behavior, the tool/workflow being used, and the expected result.";

// Shown after the diagnostic bundle is written. The Windows edition attaches it through Simple
// MAPI; no equivalent exists on Linux or macOS, and a mailto: URL cannot carry an attachment. The
// portable editions therefore write the bundle, name it, and ask the engineer to attach it - which
// is the honest version of the same workflow rather than a silently smaller one.
inline std::string feedback_bundle_note(const std::string& bundle_path) {
  return "A diagnostic bundle has been written for you to attach to the email:\n\n" + bundle_path +
         "\n\nIt contains SAT's own version, workspace mode and debug log - not raw customer log "
         "bundles. Attach it if the behaviour you are reporting is a fault; delete it afterwards.";
}

// Shown before debug logging is switched on. It is a disclosure, not a confirmation for its own
// sake: enabling it writes a file, and the engineer is told where before that happens.
inline std::string debug_logging_prompt(const std::string& log_path) {
  return "Enable diagnostic debug logging for this application session?\n\n"
         "Debug logging is off by default. It records application workflow and error details, not "
         "inspected log-file contents, unless a specific operation reports them.\n\n"
         "Debug logging is independent of case ownership and Workspace Role. Enabling it may create "
         "the diagnostics folder even when no case is open.\n\nFile: " +
         log_path;
}

} // namespace support_assist::gui
