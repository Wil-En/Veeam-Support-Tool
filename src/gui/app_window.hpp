#pragma once

#include "db_console_sql.hpp"
#include "result_table.hpp"
#include "support_assist/cancellation.hpp"
#include "support_assist/case_workspace.hpp"
#include "support_assist/configured_tools.hpp"
#include "support_assist/collected_evidence.hpp"
#include "support_assist/execution_artifact.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/tool_evidence.hpp"
#include "support_assist/network.hpp"
#include "support_assist/ssh_client.hpp"
#include "support_assist/terminal_screen.hpp"
#include "support_assist/archive_browser.hpp"
#include "support_assist/support_tools.hpp"
#include "support_assist/elevated.hpp"
#include "support_assist/local_shell.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/veeam_log_review.hpp"

// Winsock2 must precede Windows/IP Helper headers for the GUI translation
// units that consume IPv6 IP Helper tables. WIN32_LEAN_AND_MEAN is supplied
// by the SupportAssistTool target.
#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#include "checksum_set.hpp"
#include "command_palette.hpp"
#include "activity_view.hpp"
#include "field_choices.hpp"
#include "system_differences_run.hpp"
#include "quick_check_review.hpp"
#include "home_board.hpp"
#include "home_details.hpp"
#include "keyboard_shortcuts.hpp"
#include "quick_tool_reports.hpp"
#include "help_report.hpp"
#include "support_assist/process_logs.hpp"
#include "running_jobs.hpp"
#include "ui_theme.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace support_assist::gui::environment {
struct TopologyNode;
}
namespace support_assist {
struct WatchSnapshot;
}
namespace support_assist::gui {
struct QuickToolOutput;
}
struct QuickToolState;

class AppWindow {
public:
  explicit AppWindow(HINSTANCE instance);
  ~AppWindow();
  AppWindow(const AppWindow&) = delete;
  AppWindow& operator=(const AppWindow&) = delete;

  bool create(int show_command);
  int message_loop();
  // Files or folders dropped on the application itself arrive as launch arguments; they are handled
  // once the message loop runs, exactly as a drop on the window is (src/gui/file_drop.cpp).
  void queue_dropped_paths(std::vector<std::filesystem::path> paths);
  // A list view's header sends NM_CUSTOMDRAW to the list view itself, not to the window that owns
  // the list, so each list is subclassed to draw its header through paint_list_header.
  void theme_list_header(HWND list) const;

#ifdef SUPPORT_ASSIST_UI_SELFCHECK
  // Drives the application through every page and captures each one, for the user-guide figures
  // and for QA. Built only when SUPPORT_ASSIST_UI_SELFCHECK is on, which is never the case for a
  // shipped build.
  int run_screenshot_harness(const std::wstring& output_directory);
  // The harness's redaction for text a page draws itself (Home's machine tile).
  static std::wstring selfcheck_figure_text(std::wstring_view value);
  // Builds the drop Explorer sends and delivers it, so the harness exercises WM_DROPFILES itself.
  void selfcheck_send_drop(const std::vector<std::filesystem::path>& paths);
  // One visible direct child of the main window, as the QA sweep sees it.
  struct QaControlRecord {
    HWND handle = nullptr;
    RECT bounds{};
    std::wstring class_name;
    std::wstring text;
  };
  int run_ui_qa_sweep(const std::wstring& report_path);
  void selfcheck_collect_visible(std::vector<QaControlRecord>& controls) const;
  int selfcheck_report_overlaps(const std::wstring& label, std::wstring& report);
#endif

private:
#ifdef SUPPORT_ASSIST_UI_SELFCHECK
  void selfcheck_pump(int milliseconds);
  double selfcheck_wait_for_idle(int budget_milliseconds);
  void selfcheck_start_modal_guard();
  std::jthread selfcheck_modal_guard_;
  bool selfcheck_capture(const std::filesystem::path& path, HWND target = nullptr);
  // Text on screen under `root` that still names the signed-in account; empty when none does.
  std::wstring selfcheck_account_on_screen(HWND root) const;
  // Each figure that showed the account, with the text that named it.
  std::vector<std::wstring> selfcheck_account_leaks_;
public:
#endif

private:
  enum class WorkspaceRole { review_workstation, execution_host };
  enum class ExplorerTab { local = 0, ssh = 1, console = 3 };
  // Opaque forward declaration so members declared before the full Page enum (below) can take it.
  enum class Page;

  // Application menu bar: builds File/Edit/Go/View/Case/Tools/Settings/Help and routes
  // their commands. PrintWindow(PW_RENDERFULLCONTENT) in selfcheck_capture includes it, so the
  // screenshot harness photographs the bar for review.
  HMENU build_main_menu();
  void handle_main_menu_command(int command_id);
  void toggle_full_screen();
  bool full_screen_ = false;
  // Shown only in full screen, where the window has no title bar: returns to the window.
  HWND exit_full_screen_ = nullptr;
  WINDOWPLACEMENT saved_placement_{};
  LONG_PTR saved_window_style_ = 0;

  // In-app Settings window: one window with tabs (General, Custom Statuses, SSH Addresses, About),
  // edited inside the GUI and saved back, rather than by opening a raw file in an external editor.
  void open_settings_window();
  static LRESULT CALLBACK settings_window_proc(HWND window, UINT message, WPARAM wparam,
                                               LPARAM lparam);
  void settings_layout();
  void settings_show_active_tab();
  void settings_save_active_tab();
  void settings_confirm_saved(const std::wstring& message);
  void settings_add_status_row(const std::wstring& name, int color_index);
  void settings_clear_status_rows();
  void settings_restore_defaults();
  void draw_settings_tab(const DRAWITEMSTRUCT& draw) const;
  struct SettingsStatusRow {
    HWND color = nullptr;
    HWND name = nullptr;
    HWND remove = nullptr;
  };
  HWND settings_window_ = nullptr;
  HWND settings_tabs_ = nullptr;
  HWND settings_tips_ = nullptr;  // hover hints for the Settings dialog fields
  HWND settings_hint_ = nullptr;
  HWND settings_save_button_ = nullptr;
  HWND settings_defaults_button_ = nullptr;
  HWND settings_add_button_ = nullptr;
  HWND settings_about_ = nullptr;
  HWND settings_shortcuts_ = nullptr;  // Keyboard Shortcuts tab (shortcuts_panel.cpp)
  HWND settings_font_label_ = nullptr;
  HWND settings_font_edit_ = nullptr;   // a dropdown of installed OS fonts
  HWND settings_size_label_ = nullptr;
  HWND settings_size_edit_ = nullptr;
  HWND settings_scheme_label_ = nullptr;
  HWND settings_scheme_combo_ = nullptr;  // Veeam Green, Dark, Light or Match Windows
  HWND settings_size_spin_ = nullptr;   // up/down spinner buddied to the size edit
  HWND settings_eng_label_ = nullptr;
  HWND settings_eng_edit_ = nullptr;    // default engineer name
  HWND settings_path_label_ = nullptr;
  HWND settings_path_edit_ = nullptr;
  HWND settings_browse_button_ = nullptr;
  HWND settings_case_label_ = nullptr;
  HWND settings_case_edit_ = nullptr;        // [Paths] DefaultCaseRoot
  HWND settings_case_browse_ = nullptr;
  HWND settings_tools_label_ = nullptr;
  HWND settings_tools_edit_ = nullptr;       // [Paths] DefaultToolsFolder
  HWND settings_tools_browse_ = nullptr;
  HWND settings_sessions_label_ = nullptr;
  HWND settings_sessions_edit_ = nullptr;     // [Workspace] MaximumToolSessions
  HWND settings_sessions_spin_ = nullptr;
  HWND settings_experimental_check_ = nullptr;  // [Experimental] ObjectStorageCheck
  HWND settings_pane_label_ = nullptr;
  HWND settings_pane_edit_ = nullptr;         // [Remote] FilePanePercent
  HWND settings_pane_spin_ = nullptr;
  HWND settings_ssh_list_ = nullptr;
  HWND settings_ssh_host_edit_ = nullptr;
  HWND settings_ssh_add_ = nullptr;
  HWND settings_ssh_remove_ = nullptr;
  std::vector<SettingsStatusRow> settings_status_rows_;
  int settings_active_tab_ = 0;

  // F1 / Help-menu context help: a separate window (like modern apps) showing the article for the
  // current page, with a dropdown to pick any help section.
  void open_help_window(int mode);
  static LRESULT CALLBACK help_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  void help_window_layout();
  void help_load_article(int mode);
  static int help_mode_for_page(Page page);
  // The article for the window a key or WM_HELP came from: a quick tool's window or a task's view
  // opens that tool's article, the Run window, tool editor and database console their subject, an
  // operation's form on a Tools page that operation's own article (kOperationHelpMode), anything
  // else the page's article.
  int help_mode_for_window(HWND source);
  // The help mode of the article of the operation whose form is in view.
  static constexpr int kOperationHelpMode = -1;
  bool operation_help_available() const;
  HWND help_window_ = nullptr;
  HWND help_topics_combo_ = nullptr;
  // The article drawn as the cards are; the hidden edit keeps it as text for reading back.
  HWND help_report_ = nullptr;
  HWND help_text_ = nullptr;
  // The form in view as its card describes it (refresh_operation_guide), and its article.
  support_assist::gui::OperationGuideInput operation_guide_input_;
  support_assist::gui::QuickToolReport help_operation_report_;

  // The tabs Explorer shows, in order, each carrying the pane it selects.
  //
  // The pane used to be inferred from the tab's position - TabCtrl_GetCurSel() cast straight to
  // ExplorerTab. That held only while the strip listed all four panes in enum order. When the
  // remote tabs moved to the Remote page the strip dropped to one entry while the enum kept its
  // values, so ExplorerTab::console (3) had no index 3 and became unreachable: its controls were
  // still created, laid out and wired to a working handler, and impossible to select.
  //
  // Carrying the value here instead of inferring it means a tab can be added or removed without
  // silently pointing every later index at the wrong pane.
  struct ExplorerTabEntry {
    const wchar_t* label;
    ExplorerTab tab;
  };
  static const std::array<ExplorerTabEntry, 2>& explorer_tab_strip();
  enum class ExplorerSortColumn { name = 0, type = 1, size = 2, modified = 3 };
  enum class ConsoleTargetKind { local = 0, ssh = 1 };

  enum class Page {
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
    // A basic remote troubleshooting console: connect, an interactive terminal, move a file.
    // Deliberately separate from Explorer, where a connection was a property of a tab.
    remote,
    sql_tools,
    vss_tools,
    registry_change,
    filesystem_change,
    tool_manager,
    diagnostics,
    help
  };

  struct NavigationItem {
    std::wstring label;
    Page page = Page::home;
    bool selectable = true;
    bool child = false;
    bool section = false;
    bool expandable = false;
  };

  struct Card {
    std::wstring badge;
    std::wstring title;
    std::wstring description;
    Page destination = Page::home;
    int mode = 0;
    bool opens_page = false;
    bool closes_application = false;
    bool section_header = false;
    // Integrations catalogue only: the row's availability status ("Available", "Not present"),
    // drawn as a pill on the right of the card, and whether it reads as available.
    std::wstring status;
    bool status_available = false;
    // Tools only: a quick tool's card, which opens that tool's window instead of a session.
    std::optional<support_assist::gui::ShortcutCommand> quick_tool;
  };

  // One row of the Integrations catalogue: an optional tool from external_tool_catalog() or a
  // configured tool the engineer added. Drives the card row, the detail pane and the action buttons.
  struct IntegrationEntry {
    enum class Kind { optional_tool, configured_tool };
    // Catalogue sections, top to bottom: the engineer's own tools, tools that open their own window,
    // then command-line / assisted tools SAT drives.
    enum class Group { your_tools, launch, assisted, database };
    Kind kind = Kind::optional_tool;
    Group group = Group::assisted;
    std::wstring badge;
    std::wstring name;
    std::wstring subtitle;
    std::wstring status;
    bool available = false;
    std::string id;
    // Optional-tool detail.
    std::wstring source_url;
    std::wstring description;
    std::wstring detail_line;
    std::wstring native_alternative;
    std::wstring category;
    bool built_in = false;            // an in-box Windows tool (pktmon): nothing to acquire or remove
    bool automatic_download = false;  // SAT can fetch it directly; otherwise Acquire opens the page
    bool launches_gui = false;        // opens its own window when run
    bool managed_run = false;         // SAT runs it with a fixed command and collects the output
    std::wstring managed_run_arguments;
    bool managed_run_elevated = false;
    bool database_console = false;     // a DB client (sqlcmd/psql) opened as an interactive console
    bool detected_install = false;     // resolved from an existing system install, not the managed folder
    // Configured-tool detail.
    std::filesystem::path executable;
    std::wstring arguments;
    bool start_in_case_folder = true;
    // The program's own icon, extracted from the executable, shown in place of a generated badge.
    // Owned here: destroyed and re-extracted on every catalogue rebuild.
    HICON icon = nullptr;
  };

  struct HealthCardPresentation {
    std::wstring title;
    std::wstring value;
    std::wstring detail;
    support_assist::HealthSeverity severity = support_assist::HealthSeverity::unknown;
  };

  using Row = std::array<std::wstring, 4>;
  using ProgressSink = std::function<void(std::wstring)>;

  enum class ExplorerAsyncKind {
    ssh_probe, ssh_list, ssh_upload, ssh_download,
    console
  };

  struct ExplorerAsyncPayload {
    ExplorerAsyncKind kind = ExplorerAsyncKind::ssh_probe;
    bool success = false;
    std::wstring status;
    support_assist::SshHostKeyInfo ssh_host_key;
    std::wstring ssh_computer_name;
    std::vector<support_assist::SftpEntry> ssh_entries;
    std::wstring console_text;
    // True when SSH authentication succeeded and the host will run a command, even though file
    // browsing failed. A hardened repository with SFTP disabled and no SCP is still a machine an
    // engineer needs a shell on; gating Remote Shell behind a successful file listing made the
    // shell unreachable on exactly those hosts.
    bool ssh_shell_available = false;
  };

  struct OperationRequest {
    std::uint64_t session_id = 0;
    Page page = Page::home;
    int mode = 0;
    std::wstring primary;
    std::wstring secondary;
    std::wstring tertiary;
    std::wstring quaternary;
    std::wstring quinary;
    std::wstring senary;
    bool option_checked = false;
    bool mode_checked = false;
    bool network_ipv4_checked = true;
    bool network_ipv6_checked = true;
    std::string selected_machine_key;
    std::string selected_machine_name_hint;
    std::string selected_run_key;
    std::string selected_job_name_hint;
    std::filesystem::path active_case_root;
    std::string selected_source_path_hint;
    bool linked_vaw_window_resolved = false;
    bool force_full_review = false;
    bool append_to_case = false;
    std::vector<support_assist::CaseReviewSource> review_sources;
    std::string system_health_report;
    std::filesystem::path execution_artifact_root;
    std::vector<std::string> selected_product_ids;
    // Set on the UI thread before the worker starts. When true the collection is performed by an
    // elevated child SAT instead of in-process, so VSS state, minifilters and BCD are collected
    // rather than returning "Access is denied".
    bool elevate_collection = false;
    std::vector<std::filesystem::path> additional_collection_sources;
    std::vector<std::string> selected_interface_names;
    std::vector<std::string> selected_interface_addresses;
    std::optional<support_assist::PacketCaptureSession> packet_capture_session;
    std::shared_ptr<support_assist::PacketCaptureMonitor> capture_monitor;
    // The Universal Log Collection runs in the elevated helper (asked on the message thread).
    bool elevated_collection = false;
    // A System Differences files capture (or the read of this machine for a compare) is taken by the
    // elevated helper (asked on the message thread).
    bool elevated_capture = false;
    // SQL Tools without Use logged-in user: the SQL login asked for on the message thread. The
    // password lives here for the run only.
    std::string sql_login;
    std::string sql_password;
    // WMI's cluster test and custom query with Sign in set to Another account: the account asked for
    // on the message thread for another machine. The password lives here for the run only.
    std::string wmi_user;
    std::string wmi_password;
  };

  struct SourceLocation {
    std::filesystem::path materialized_path;
    std::wstring display_path;
    std::uint64_t line_number = 0;
    std::wstring title;
  };

  struct ModeOutputState {
    std::array<std::wstring, 4> columns{L"Category", L"Item", L"Details", L"Status"};
    std::vector<Row> rows;
    std::vector<SourceLocation> row_sources;
    std::vector<Row> last_run_rows;
    std::size_t current_run_row_start = 0;
    std::wstring status = L"Ready";
    int result_top_index = 0;
    int result_selected_index = -1;
  };

  struct ToolSession {
    std::uint64_t id = 0;
    // A task drawn by a view of its own (the Object Storage Check), shown below the session tabs in
    // place of the operation form and its results. Destroyed with the session.
    HWND embedded_view = nullptr;
    Page page = Page::home;
    int mode = 0;
    // Each operation in a multi-operation tool retains its own visible result/history.
    // Switching the operation combo must never display another operation's output.
    std::map<int, ModeOutputState> mode_outputs;
    // A grouped result table's window for its events groups ("last 7 days").
    std::string result_group_note;
    std::wstring title;
    std::wstring description;
    std::wstring primary;
    std::wstring secondary;
    std::wstring tertiary;
    std::wstring quaternary;
    std::wstring quinary;
    std::wstring senary;
    bool option_checked = false;
    bool mode_checked = false;
    bool network_ipv4_checked = true;
    bool network_ipv6_checked = true;
    bool busy = false;
    bool artifact_busy = false;
    bool artifact_failed = false;
    bool close_when_finished = false;
    bool completed = false;
    bool successful = false;
    // After a run on a Tools page the form folds to one summary line; Edit unfolds it.
    bool form_folded = false;
    support_assist::ExecutionStatus execution_status = support_assist::ExecutionStatus::completed;
    support_assist::DiagnosticStatus diagnostic_status = support_assist::DiagnosticStatus::neutral;
    std::optional<support_assist::ExecutionArtifactManifest> execution_artifact;
    std::optional<support_assist::PacketCaptureSession> packet_capture_session;
    // The running capture's counts and its stop, while this tab owns a capture.
    std::shared_ptr<support_assist::PacketCaptureMonitor> capture_monitor;
    // What the last run wrote (a collection's ZIP or folder); Open folder shows it.
    std::filesystem::path result_path;
    std::wstring status = L"Ready";
    std::array<std::wstring, 4> columns{L"Category", L"Item", L"Details", L"Status"};
    std::vector<Row> rows;
    std::vector<SourceLocation> row_sources;
    support_assist::CancellationSource cancellation;
    std::jthread worker;
    std::jthread artifact_worker;
    std::chrono::steady_clock::time_point started{};
    std::chrono::steady_clock::time_point state_changed = std::chrono::steady_clock::now();
    std::shared_ptr<support_assist::VeeamLogReviewResult> veeam_review;
    std::string selected_machine_key;
    std::string selected_job_name;
    std::string selected_job_kind;
    std::string selected_run_key;
    bool review_rescans_only = false;
    // Shows only evidence that belongs to NO backup run: service lifecycle and infrastructure work
    // such as adding a machine to a protection group, adding a managed server, or a repository
    // rescan. Those failures are a large share of real cases; every other review view is organised
    // around runs, and this evidence has none.
    bool review_non_run_only = false;
    std::vector<std::string> review_job_filter_names;
    std::vector<std::string> review_job_filter_kinds;
    std::string selected_job_name_hint;
    std::string selected_source_path_hint;
    bool linked_vaw_window_resolved = false;
    bool append_to_case = false;
    std::vector<support_assist::CaseReviewSource> review_sources;
    bool force_full_review_next = false;
    bool protect_case_review_on_completion = false;
    bool return_to_case_dashboard = false;
    // The engineer kept this review out of the active case ("No = review only" for a dropped
    // folder or a File Browser source). It is not bound to the case, so its result, report and
    // review state are not written there, including when it is run again from the same tab.
    bool review_only = false;
    // Workspace ownership is captured when the tab is created. It controls
    // visibility only; workers remain globally owned so switching case context
    // never stops or retargets background work.
    std::filesystem::path context_case_root;
    std::wstring context_case_id;
    // Case identity captured when this operation starts. Background completion
    // must never write into a different case selected while the worker runs.
    std::filesystem::path bound_case_root;
    std::wstring bound_case_id;
    std::vector<std::string> collection_product_ids;
    std::vector<unsigned char> collection_product_checked;
    std::vector<std::string> network_interface_names;
    std::vector<std::string> network_interface_addresses;
    std::vector<unsigned char> network_interface_checked;
    std::vector<support_assist::VbrRunningJob> vbr_running_jobs;
    std::vector<std::string> vbr_stop_requested_sessions;
    std::size_t current_run_row_start = 0;
    std::vector<Row> last_run_rows;
    std::array<int, 4> column_widths{170, 240, 360, 190};
    std::wstring columns_fitted_for;  // the rows and width column_widths were fitted to
    bool review_columns_initialized = false;
    int result_top_index = 0;
    int result_selected_index = -1;
    std::vector<std::size_t> review_row_incident_indices;
    // Parallel to review rows. The log-review gutter uses these flags to render
    // a direct bookmark affordance without changing the evidence data model.
    std::vector<unsigned char> review_row_bookmarkable;
    std::vector<unsigned char> review_row_bookmarked;
    // Numeric timestamp keys stay parallel to review rows so broad Log Review
    // tables can sort Date/Time correctly instead of lexicographically by the
    // human-readable month name. Unknown timestamps are std::nullopt.
    std::vector<std::optional<std::int64_t>> review_row_time_keys;
    int review_sort_column = 1;
    bool review_sort_ascending = false;
  };

  struct ActivityRecord {
    std::wstring timestamp;
    std::wstring tool;
    std::wstring result;
    std::wstring detail;
    std::wstring case_id;
  };

  struct ProgressPayload {
    std::uint64_t session_id = 0;
    std::wstring text;
  };

  struct LiveRowPayload {
    std::uint64_t session_id = 0;
    Row row{};
    bool replace_matching = false;
    // Replaces the row whose first two cells are the row's first and this; empty matches both of
    // the row's own.
    std::wstring replace_state;
  };

  struct EnvironmentProgressPayload {
    std::uint64_t generation = 0;
    int card_index = -1;
    HealthCardPresentation card;
    std::wstring detail;
    std::wstring status;
    std::wstring snapshot_text;
    std::wstring report_text;
    bool finished = false;
    bool failed = false;
  };

  struct CompletionPayload {
    bool success = false;
    std::wstring message;
    std::vector<Row> rows;
    std::uint64_t session_id = 0;
    std::vector<SourceLocation> row_sources;
    std::shared_ptr<support_assist::VeeamLogReviewResult> veeam_review;
    support_assist::ExecutionStatus execution_status = support_assist::ExecutionStatus::completed;
    support_assist::DiagnosticStatus diagnostic_status = support_assist::DiagnosticStatus::neutral;
    std::optional<support_assist::PacketCaptureSession> packet_capture_session;
    std::shared_ptr<support_assist::PacketCaptureMonitor> capture_monitor;
    std::filesystem::path result_path;
    std::vector<support_assist::VbrRunningJob> vbr_running_jobs;
    std::string vbr_stop_requested_session;
  };


  struct ArtifactCompletionPayload {
    std::uint64_t session_id = 0;
    bool success = false;
    std::wstring message;
    std::optional<support_assist::ExecutionArtifactManifest> artifact;
  };

  static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  LRESULT handle_message(UINT message, WPARAM wparam, LPARAM lparam);

  bool create_controls();
  void create_fonts();
  // The colour scheme Settings chose, resolved against Windows when it follows Windows, and the
  // step that re-colours every open window when it changes.
  support_assist::gui::ColorScheme configured_color_scheme() const;
  void apply_color_scheme();
  void reapply_ui_scale();  // recreate fonts at the current scale and re-apply them live
  // Cached UI text scale (percent), refreshed in create_fonts(). sx() scales a base pixel metric by
  // it, so the always-visible chrome and card grids grow with the text rather than clipping it.
  int ui_scale_percent_ = 100;
  int sx(int pixels) const { return MulDiv(pixels, ui_scale_percent_, 100); }
  void create_brushes();
  void destroy_gdi_objects() noexcept;
  void apply_dark_title_bar() const;
  void paint_background(HDC dc) const;
  void force_visual_refresh(bool announce);
  void refresh_entire_gui(bool manual);
  void layout(int width, int height);
  void layout_card_menu(int content_left, int content_top, int content_width, int content_height,
                        bool lightweight_scroll = false);
  void scroll_general_tools_catalog(int delta_pixels);
  void layout_operation(int content_left, int content_top, int content_width, int content_height);
  void layout_health_dashboard(int content_left, int content_top, int content_width, int content_height);
  void layout_case_dashboard(int content_left, int content_top, int content_width, int content_height);
  void layout_case_manager(int content_left, int content_top, int content_width, int content_height);
  void layout_environment_review(int content_left, int content_top, int content_width, int content_height);
  void layout_explorer(int content_left, int content_top, int content_width, int content_height);
  void layout_log_review_dashboard(int content_left, int content_top, int content_width, int content_height);

  void rebuild_navigation();
  // Opens or closes the Tools group without changing page: the arrow beside Tools, or Left / Right
  // on its row.
  void set_tools_group_open(bool open);
  static LRESULT CALLBACK navigation_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                          UINT_PTR subclass, DWORD_PTR data);
  static LRESULT CALLBACK tab_strip_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam,
                                         UINT_PTR subclass, DWORD_PTR data);
  bool is_general_tools_child(Page page) const noexcept;
  bool execution_host_enabled() const noexcept;
  bool page_requires_execution_host(Page page) const noexcept;
  bool local_vbr_server_available() const;
  std::wstring workspace_role_label() const;
  void set_workspace_role(WorkspaceRole role);
  void apply_workspace_role(WorkspaceRole role);
  bool workspace_role_has_blockers() const noexcept;
  std::wstring workspace_role_blocker_tree() const;
  bool request_close_all_for_workspace_switch(WorkspaceRole role);
  void complete_pending_workspace_role_switch_if_ready();
  void toggle_workspace_role();
  void show_workspace_role_context_menu(POINT screen_point);
  // Engineer mode is licence-gated: the build runs Customer / Lab by default and only unlocks the
  // Engineer Review Workstation role when a valid signed licence is present beside the executable.
  void load_engineer_license();
  bool engineer_mode_unlocked() const noexcept { return engineer_unlocked_; }
  void prompt_activate_engineer_license();
  // Without a licence a tool is placed by hand: its official page opens and a prompt names the
  // folder to place it in.
  void show_manual_tool_placement(const std::string& tool_id);
  void prepare_last_execution_artifact();
  void delete_last_execution_artifact();
  std::filesystem::path customer_tool_output_directory() const;
  void write_customer_tool_output_log(const ToolSession& session) const;
  void start_execution_artifact_finalization(ToolSession& session);
  void select_page(Page page);
  void show_page_menu();
  void open_card(std::size_t index);
  static std::wstring help_topic_title(int mode);
  void rebuild_cards();
  // True when the active case already carries a parsed review model.
  bool case_has_saved_review() const;
  std::vector<Card> cards_for_page(Page page) const;
  void update_card_buttons();
  bool card_shown(std::size_t index) const;
  RECT card_full_rect(std::size_t index, RECT client) const;
  void update_control_visibility();
  void commit_visual_state(bool update_now = true);
  void draw_card(const DRAWITEMSTRUCT& draw) const;
  void draw_navigation(const DRAWITEMSTRUCT& draw) const;
  void draw_combo(const DRAWITEMSTRUCT& draw) const;
  void draw_tool_tab(const DRAWITEMSTRUCT& draw) const;
  void draw_explorer_tab(const DRAWITEMSTRUCT& draw) const;
  void draw_explorer_button(const DRAWITEMSTRUCT& draw) const;
  void draw_health_card(const DRAWITEMSTRUCT& draw) const;
  void draw_case_card(const DRAWITEMSTRUCT& draw) const;
  void draw_review_card(const DRAWITEMSTRUCT& draw) const;
  HBRUSH handle_control_color(HDC dc, HWND control, UINT message) const;

  void configure_page();
  void configure_mode();
  void populate_collection_product_checks();
  void save_collection_product_checks(ToolSession& session) const;
  void populate_host_check_boxes();
  // Log Collection's products and Host Checks' groups use the same check boxes.
  static bool session_uses_check_boxes(const ToolSession& session);
  std::vector<std::string> selected_collection_product_ids() const;
  void populate_network_interface_checks();
  void save_network_interface_checks(ToolSession& session) const;
  void reset_tool_output();
  void show_rows(const ToolSession& session);
  static support_assist::gui::ResultLayout result_layout_of(Page page, int mode);
  std::vector<support_assist::gui::FormSummaryField> form_fields_now() const;
  LRESULT draw_result_section_row(const NMLVCUSTOMDRAW& draw, std::size_t item,
                                  const support_assist::gui::ResultTableRow& row);
  std::wstring detected_local_veeam_log_sources() const;
  void set_mode_items(const std::vector<std::wstring>& items, int selection = 0,
                      const std::vector<int>& values = std::vector<int>());
  void select_mode_value(int value);
  int selected_mode() const;
  std::wstring mode_title_now() const;
  void configure_columns(const std::array<std::wstring, 4>& names);
  void start_operation();
  void cancel_operation();
  void browse_primary();
  void browse_secondary();
  void browse_tertiary();
  void browse_quaternary();
  void browse_quinary();
  void browse_senary();
  void browse_field(int slot);
  void publish_progress(std::uint64_t session_id, std::wstring text) const;
  // Right-click menu shared by every table in the product. Specialised menus still win where a
  // table has one; this is what everything else answers with.
  bool is_list_view_control(HWND control) const;
  void show_universal_grid_context_menu(HWND list, POINT point);
  void publish_live_row(std::uint64_t session_id, Row row, bool replace_matching = false,
                        std::wstring replace_state = {}) const;
  // The folded form of a Tools page (gui_shared/tool_output.hpp).
  static bool form_folds_after_run(Page page) noexcept;
  bool tools_form_folded() const;
  void fold_form();
  void unfold_form();
  void sync_form_fold();
  void update_tool_row_detail();
  // A Tools run's progress as the status line and as live rows in its table.
  std::function<void(const support_assist::ProgressEvent&)> live_progress_sink(const OperationRequest& request,
                                                                                const ProgressSink& progress) const;
  void publish_completion(std::uint64_t session_id,
                          bool success,
                          std::wstring message,
                          std::vector<Row> rows,
                          std::vector<SourceLocation> row_sources,
                          std::shared_ptr<support_assist::VeeamLogReviewResult> veeam_review,
                          support_assist::ExecutionStatus execution_status,
                          support_assist::DiagnosticStatus diagnostic_status,
                          std::optional<support_assist::PacketCaptureSession> packet_capture_session,
                          std::shared_ptr<support_assist::PacketCaptureMonitor> capture_monitor = {},
                          std::filesystem::path result_path = {}) const;
  std::wstring control_text(HWND control) const;
  void set_control_text(HWND control, std::wstring_view value) const;

  ToolSession* active_session() noexcept;
  const ToolSession* active_session() const noexcept;
  ToolSession* find_session(std::uint64_t id) noexcept;
  std::wstring active_case_context_key() const;
  std::wstring session_context_key(const ToolSession& session) const;
  bool session_matches_active_case_context(const ToolSession& session) const;
  int global_session_index_from_visible_tab(int visible_index) const;
  int visible_tab_index_from_global_session(int global_index) const;
  void activate_session_group_for_active_case();
  void save_active_session();
  void save_active_mode_output(ToolSession& session);
  void restore_active_mode_output(ToolSession& session, int mode);
  void activate_session(int index);
  bool create_tool_session(const Card& card);
  bool session_has_active_capture(const ToolSession& session) const noexcept;
  void close_active_session();
  void request_close_session(int index);
  void close_session_now(int index);
  RECT tool_tab_close_rect(int index) const;
  std::wstring tool_session_state_label(const ToolSession& session) const;
  void update_tool_tabs();
  void update_session_controls();
  void update_running_indicator();
  void show_progress_status();
  void show_progress_share(const std::wstring& status);
  void flush_progress_status();
  int fit_review_state_banner(int width);
  OperationRequest capture_request() const;
  CompletionPayload execute_operation(const OperationRequest& request,
                                      const support_assist::CancellationToken& token,
                                      const ProgressSink& progress);
  void show_direct_page(Page page);
  void open_selected_source();
  void show_selected_result_detail();
  void show_source_context_menu(HWND source_control, POINT screen_point);
  void stop_selected_vbr_job();
  void copy_selected_vbr_job_details();
  void sort_vbr_jobs_by_column(int column);
  void show_tool_tab_context_menu(POINT screen_point);
  void show_health_context_menu(HWND source_control, POINT screen_point);
  void show_dashboard_card_context_menu(HWND source_control, POINT screen_point);
  void show_case_summary_context_menu(HWND source_control, POINT screen_point);
  void show_health_dashboard_detail(std::size_t card_index);
  void show_review_dashboard_detail(std::size_t card_index);
  void populate_review_filters();
  void populate_review_job_filter();
  void populate_review_run_filter();
  void apply_review_filters();
  void render_veeam_review(ToolSession& session);
  void sort_review_results_by_column(int column);
  void sort_review_job_by_column(int column);
  void sort_review_components_by_column(int column);
  void update_review_detail();
  void update_review_dashboard(ToolSession& session);
  void copy_review_ticket_note();
  void bookmark_review_evidence(bool include_in_note = false);
  void toggle_selected_run_for_note();
  void toggle_case_run_for_note(std::string_view run_key);
  bool selected_run_is_in_note(std::string_view run_key) const;
  void start_review_reanalysis();
  void append_review_logs();
  void show_review_more_menu();
  bool copy_list_view_selection(HWND list);
  bool copy_list_view_all(HWND list);
  bool copy_text_to_clipboard(std::wstring_view text) const;
  void render_help_detail(const ToolSession& session);
  void save_result_view_state(ToolSession& session);
  void restore_result_view_state(const ToolSession& session);
  void render_health_monitor();
  const std::vector<support_assist::gui::QuickCheckHealthRow>&
  health_quick_check_rows(const support_assist::SystemHealthSnapshot& snapshot);
  void load_saved_health_snapshot();
  void show_live_health_snapshot();
  void toggle_health_row_note(HWND source_control);
  bool activate_diagnostic_selection();
  int selected_result_index() const;

  void create_tooltip_support();
  void add_tooltip(HWND control, std::wstring text);
  void update_context_help();
  void update_field_guidance();
  // A Tools operation's hint card (gui_shared/operation_guide.hpp), shown in the results area
  // until the operation has results.
  void refresh_operation_guide(const std::wstring& intro, const std::array<std::wstring, 6>& tips,
                               const std::array<std::wstring, 6>& cues);
  bool operation_guide_wanted() const;
  void sync_operation_guide();
  void set_edit_cue(HWND control, std::wstring_view text) const;
  std::wstring tooltip_for_control(HWND control) const;

  std::filesystem::path executable_path() const;
  std::filesystem::path executable_directory() const;
  std::wstring build_cli_command(const OperationRequest& request) const;
  void show_cli_command();
  bool confirm_collection_elevation();
  bool confirm_capture_elevation(const OperationRequest& request);
  void open_result_path();
  std::filesystem::path state_data_directory(std::wstring_view child = {}) const;
  std::filesystem::path legacy_logs_directory(std::wstring_view child = {}) const;
  std::filesystem::path execution_artifact_directory() const;
  // Where a tool's output belongs: the active case's logs when an engineer has one selected,
  // otherwise (no case, or Customer / Lab mode) the transferable Log-Collections tree.
  std::filesystem::path current_case_log_root_for_tools() const;
  void migrate_legacy_internal_state();
  // Engineer-configured external tools. Beside SAT's other state, so nothing is written
  // outside the executable's own folder.
  // Runs `work` on a worker thread while the message loop keeps running, so a long action started
  // from a button repaints instead of going grey and being labelled "Not Responding".
  //
  // Input to the window is disabled for the duration. The pump keeps every control live, and
  // without this an engineer could start a second write into the folder the first one is still
  // filling. Restored on every path out, including an exception thrown by the work itself.
  //
  // Not a parallelism change: one worker, so the window survives. Nothing here alters how many
  // cores a parse uses.
  template <typename Work>
  auto run_keeping_ui_alive(const wchar_t* what, Work&& work) -> decltype(work()) {
    using Value = decltype(work());
    set_status_message(what);
    const HCURSOR previous = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
    const BOOL was_enabled = IsWindowEnabled(window_);
    EnableWindow(window_, FALSE);

    std::optional<Value> captured;
    std::exception_ptr failure;
    std::atomic<bool> finished{false};
    {
      std::jthread worker([&]() {
        try {
          captured.emplace(work());
        } catch (...) {
          failure = std::current_exception();
        }
        finished.store(true, std::memory_order_release);
      });

      MSG message{};
      while (!finished.load(std::memory_order_acquire)) {
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE) != FALSE) {
          TranslateMessage(&message);
          DispatchMessageW(&message);
        }
        // Idle rather than spin: this thread exists to paint, not to compete with the worker for a
        // core on the two-core lab VM the guide talks about.
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 15, QS_ALLINPUT);
      }
    }

    EnableWindow(window_, was_enabled);
    SetCursor(previous);
    if (failure)
      std::rethrow_exception(failure);
    return std::move(*captured);
  }

  std::filesystem::path configured_tools_path() const;
  // Names of the configured tools, for the Run/Remove dropdown.
  std::vector<std::wstring> configured_tool_names() const;
  // Writes the starter case-status and external-tool files if they are absent. Never
  // overwrites: an engineer's edits outrank a default.
  void seed_editable_state_files() const;
  std::filesystem::path case_catalog_path() const;
  void load_case_catalog();
  void save_case_catalog() const;
  void refresh_case_combo();
  CompletionPayload run_case_manager();
  const support_assist::CaseWorkspace* case_manager_row(int row) const;
  void case_manager_switch_to(const support_assist::CaseWorkspace& workspace);
  void case_manager_delete(const support_assist::CaseWorkspace& workspace);
  void show_case_manager_menu(POINT screen, int row);
  void render_case_manager();
  void render_case_manager_summary();
  void update_case_manager_buttons();
  const support_assist::CaseWorkspace* case_manager_selected() const;
  void open_register_case_tool();
  void draw_case_manager_card(const DRAWITEMSTRUCT& draw) const;
  void refresh_case_manager_cards();
  void case_manager_show_form(bool open);
  void case_manager_create_from_form();
  void case_manager_save_edits();
  void case_manager_load_edits();
  void case_manager_selection_changed();
  LRESULT case_manager_status_cell(NMLVCUSTOMDRAW& draw);
  void register_case_workspace(const support_assist::CaseWorkspace& workspace);
  const support_assist::CaseWorkspace* active_case() const noexcept;
  void activate_case_from_combo();
  // Home's Recent cases: the active case is recorded as opened now (support_assist/recent_cases.hpp).
  void note_active_case_opened();
  bool activate_case_from_result();
  void delete_active_case();
  void open_case_dashboard();
  void open_environment_review();
  // keep_shown: leave the page as it is when it already shows what it would render, so opening
  // it again neither collects this host nor reads the case model again. Refresh passes false.
  void render_environment_review(bool keep_shown = false);
  // What render_environment_review would show now: an import, this host, or the case as its
  // saved model stands.
  std::wstring environment_view_key() const;
  void render_explorer();
  void refresh_explorer_roots();
  void navigate_explorer(const std::filesystem::path& path);
  void navigate_transfer_local(const std::filesystem::path& path);
  void populate_explorer_directory();
  void populate_transfer_local_list();
  void populate_ssh_file_list();
  void sort_explorer_view(HWND list, int column);
  void update_explorer_sort_indicator(HWND list, ExplorerSortColumn column, bool ascending);
  void refresh_console_targets();
  void update_console_target_controls();
  void populate_explorer_tree_children(HTREEITEM item);
  // Whole-machine access for the transfer panes.
  //
  // Evidence browsing is deliberately confined to approved Veeam/SAT/case roots so a review cannot
  // wander the disk. The SSH/SFTP and remote-file transfer panes are a different job: an engineer
  // needs to push an arbitrary file - a collector binary, a script, a fix - onto a customer machine
  // and pull arbitrary output back. Confining those panes to Veeam paths made the feature unusable
  // for its actual purpose. Transfers may address the whole local filesystem; the approved-root
  // rule still governs evidence browsing and archive traversal.
  static bool explorer_transfer_path_allowed(const std::filesystem::path& path);
  bool explorer_path_allowed(const std::filesystem::path& path,
                             std::filesystem::path* matched_root = nullptr) const;
  void set_explorer_tab(ExplorerTab tab);
  void refresh_explorer_tab_visibility();
  // Remote console control identifiers. Declared here rather than in the anonymous namespace of
  // app_window.cpp because the page lives in its own translation unit.
  // The channel is polled rather than waited on: a shell produces output when it feels like it.
  static constexpr UINT_PTR kRemoteTimerId = 41;
  // Drains the persistent local shell into the Explorer console pane.
  static constexpr UINT_PTR kLocalShellTimerId = 42;
  static constexpr int kRemoteHostId = 6200;
  static constexpr int kRemotePortId = 6210;
  static constexpr int kRemoteUserId = 6201;
  static constexpr int kRemotePasswordId = 6202;
  static constexpr int kRemoteKeyId = 6203;
  static constexpr int kRemoteConnectId = 6204;
  static constexpr int kRemoteDisconnectId = 6205;
  static constexpr int kRemotePathId = 6206;
  static constexpr int kRemoteFilesId = 6207;
  static constexpr int kRemoteDownloadId = 6208;
  static constexpr int kRemoteUploadId = 6209;
  static constexpr int kRemoteKeyBrowseId = 6211;
  static constexpr int kRemoteKeyPassphraseId = 6212;

  void refresh_ssh_directory();

  // --- Remote console ---------------------------------------------------------------------
  void create_remote_controls();
  void layout_remote(int content_left, int content_top, int content_width, int content_height);
  void show_remote_controls(bool visible);
  void populate_remote_favourites();
  void rescale_remote_terminal_font();
  void remote_connect();
  void remote_disconnect(const wchar_t* reason);
  void remote_pump();                       // drain the channel into the screen; called on a timer

  // The Explorer console keeps ONE shell open rather than spawning a process per command,
  // so `cd`, environment variables and anything waiting on an answer survive between
  // commands. Output arrives whenever the shell produces it, so it is drained on a timer
  // rather than awaited.
  // Appends without re-reading the pane. Rebuilding the whole transcript per chunk is O(n^2)
  // and a streaming command produces a lot of chunks.
  void append_console_text(const std::wstring& text);
  void local_shell_pump();
  bool ensure_local_shell();
  void close_local_shell();
  // Stop: ends the session and anything still running in it; the next command starts a new one.
  void stop_local_shell();
  std::shared_ptr<support_assist::LocalShell> local_shell_;
  // Which shell the open session runs, so a change in the Shell list starts a new session there.
  bool local_shell_cmd_ = false;

public:
  // Called from the terminal window procedure, which is a free function in its own translation
  // unit and cannot reach private members. Nothing else should call these.
  void paint_remote_terminal(HDC device, const RECT& area);
  // Terminal selection and clipboard. Copy/paste use Ctrl+Shift+C/V and a right-click menu so plain
  // Ctrl+C stays the interrupt key a terminal needs.
  bool remote_point_to_cell(int x, int y, int& row, int& col) const;
  wchar_t remote_visible_glyph(int visible_row, int col) const;
  bool remote_cell_selected(int row, int col) const;
  void remote_terminal_mouse_down(int x, int y);
  void remote_terminal_mouse_move(int x, int y);
  void remote_terminal_mouse_up();
  void remote_show_terminal_menu(int screen_x, int screen_y);
  void remote_copy_selection();
  void remote_paste_clipboard();
  void remote_select_all();
  void remote_send_key(WPARAM key, bool control_down, bool shift_down);
  void remote_send_text(std::wstring_view text);
  void remote_recompute_geometry();
  // Scroll the terminal view back through history. Positive scrolls back, negative forward.
  void remote_scroll_by(int rows);
  // Called from the path box subclass, which is a free function in another translation unit.
  void remote_refresh_files();

private:
  void remote_transfer(bool upload);
  support_assist::ProgressCallback remote_transfer_progress();
  // Where a download opens: the open case's logs folder, or empty with no case.
  std::filesystem::path remote_download_folder() const;
  void browse_remote_key();
  // Double-click, or Download on a folder: enter a directory, or pull a file.
  void remote_open_selected();
  bool remote_confirm_write(const std::wstring& what);
  // One place for status: the bottom line and the console narrative always agree.
  void remote_note(const std::wstring& text);
  // Shows the fingerprint and asks yes/no, the way every other SSH client does.
  bool confirm_ssh_host_key();
  void probe_or_connect_ssh();
  void ssh_transfer(bool upload);
  void run_remote_console_command();
  void clear_remote_credentials();
  void navigate_archive(const std::filesystem::path& archive, std::string virtual_path);
  void populate_archive_directory();
  void preview_archive_member(std::string_view member_path);
  void preview_local_log(const std::filesystem::path& path);
  void analyze_explorer_path(const std::filesystem::path& path);
  bool is_browsable_archive(const std::filesystem::path& path) const;
  void toggle_explorer_collection_mark(const std::filesystem::path& path);
  void launch_explorer_system_tool(std::size_t index);
  void show_explorer_context_menu(HWND source_control, POINT screen_point);
  void start_live_environment_refresh();
  void show_environment_card_detail(std::size_t card_index);
  void draw_environment_card(const DRAWITEMSTRUCT& draw) const;
  void load_environment_snapshot_file();
  // Rebuild both documents from a raw log collection and render them through these same pages.
  // `from_archive` chooses the file picker rather than the folder picker; the core
  // resolves either kind of path.
  void load_collection_evidence(bool for_health, bool from_archive = false);
  // Reads the saved reconstruction out of the active case.
  void open_saved_collection_evidence(bool for_health);
  // True when the active case holds a saved reconstruction of that kind.
  // The machines imported into the active case that carry the document asked for.
  std::vector<support_assist::ImportedMachine> imported_machines_for(bool for_health) const;
  // Opens one machine's saved environment or health document.
  void open_imported_machine(const support_assist::ImportedMachine& machine, bool for_health);
  // Reopens the evidence already imported into the active case.
  void restore_imported_evidence();
  bool saved_collection_evidence_available(bool for_health) const;
  // Drops the Open menu under its button and runs whatever was chosen.
  void show_open_evidence_menu(bool for_health);
  void populate_environment_topology_from_case(const support_assist::VeeamLogReviewResult& review);
  void populate_environment_topology_from_snapshot(std::wstring_view snapshot, bool with_quick_checks = false);
  void append_environment_quick_checks(support_assist::gui::environment::TopologyNode& root) const;
  void fill_environment_topology(const support_assist::gui::environment::TopologyNode& root);
  void populate_vss_volume_combo();
  std::wstring build_live_environment_summary();
  std::string build_environment_review_text() const;
  void export_case_pdf(bool master_report);
  void open_note_review();
  void open_note_review_for_scope(std::string scope_key);
  void refresh_note_review();
  void refresh_note_review_scope();
  std::string build_active_case_note_text(std::string_view scope_key = std::string_view()) const;
  void copy_note_review();
  void save_note_review_snapshot();
  void open_new_case_tool();
  void show_case_more_menu();
  // Reads Customer/Lab tool artifacts into the active case, identified by machine and
  // ordered in UTC, and writes them in note-ready form.
  void load_case_tool_evidence();
  // Recent Activity: pick a collected bundle folder, ZIP or Activity TSV and open it read-only.
  void load_archived_activity();
  void render_case_dashboard();
  // The case's review model, kept for Case Dashboard and Environment Review and read again only
  // when the case or its saved model changes; nullptr when the case has none.
  const support_assist::VeeamLogReviewResult* cached_case_review(const support_assist::CaseWorkspace& workspace);
  void drop_cached_case_review();
  void show_case_dashboard_detail(std::size_t card_index);
  void refresh_case_dashboard_machine();
  void refresh_case_dashboard_job();
  void refresh_case_dashboard_run();
  void copy_case_job_settings();
  void load_case_review_into_workspace();
  void open_case_review_parser(bool append_new_logs);
  void open_active_case_folder();
  void persist_review_to_case(const std::filesystem::path& case_root,
                              const support_assist::VeeamLogReviewResult& review);
  void persist_review_state_to_case(const std::filesystem::path& case_root,
                                    const ToolSession& session) const;
  void resume_last_case_review();
  void apply_default_values();
  void populate_external_tool_combo();

  void load_activity();
  void append_activity(std::wstring tool, std::wstring result, std::wstring detail,
                       std::wstring case_id = L"");
  void save_activity_record(const ActivityRecord& record) const;
  void render_activity();
  // Recent Activity's own layout: its line and Load archived activity, the tiles, then the table.
  void layout_recent_activity(int left, int top, int width, int height);
  void rebuild_activity_board(const support_assist::gui::ActivityCounts& counts);
  void activity_board_activated(int index);
  LRESULT activity_result_cell(NMLVCUSTOMDRAW& draw);
  void fit_health_columns();
  // A report list's columns sized to what they hold, the spare width to the widest (autosize_report_columns).
  static void fit_report_columns(HWND list);

  void start_system_health_monitor();
  void update_system_health_controls();
  void toggle_system_health_panel();
  void toggle_debug_logging();
  void update_debug_status();
  void update_workspace_role_badge();
  void launch_feedback_email();
  void set_status_message(std::wstring_view text) const;
  void load_ui_settings();
  void save_ui_settings() const;
  std::filesystem::path ui_settings_path() const;
  std::filesystem::path effective_ui_settings_path() const;
  std::filesystem::path default_collections_folder() const;
  std::filesystem::path default_case_root() const;
  std::filesystem::path default_tools_folder() const;
  std::wstring default_engineer_name() const;
  int ui_text_scale_percent() const;
  void set_text_scale(int percent);
  std::filesystem::path user_guide_path() const;
  std::filesystem::path ssh_addresses_path() const;
  std::vector<std::wstring> load_ssh_addresses() const;

  CompletionPayload run_home(const OperationRequest& request);
  CompletionPayload run_general_tools(const OperationRequest& request,
                                      const support_assist::CancellationToken& token,
                                      const ProgressSink& progress);
  CompletionPayload run_guided_diagnostics(const OperationRequest& request,
                                              const support_assist::CancellationToken& token,
                                              const ProgressSink& progress);
  CompletionPayload run_log_collection(const OperationRequest& request,
                                       const support_assist::CancellationToken& token,
                                       const ProgressSink& progress);
  bool ask_sql_login(std::string& login, std::string& password, support_assist::SqlEngine engine);
  bool ask_wmi_account(const std::wstring& machine, std::string& user, std::string& password);
  CompletionPayload run_sql_tools(const OperationRequest& request,
                                  const support_assist::CancellationToken& token,
                                  const ProgressSink& progress);
  CompletionPayload run_vss_tools(const OperationRequest& request,
                                  const support_assist::CancellationToken& token,
                                  const ProgressSink& progress);
  CompletionPayload run_tool_manager(const OperationRequest& request,
                                     const support_assist::CancellationToken& token,
                                     const ProgressSink& progress);
  CompletionPayload run_registry(const OperationRequest& request,
                                 const support_assist::CancellationToken& token,
                                 const ProgressSink& progress);
  CompletionPayload run_registry_compare_live(const std::filesystem::path& baseline,
                                              const support_assist::CancellationToken& token,
                                              const ProgressSink& progress);
  CompletionPayload run_filesystem(const OperationRequest& request,
                                   const support_assist::CancellationToken& token,
                                   const ProgressSink& progress);
  // System Differences' rows and result line as a completion, and a registry compare's.
  static CompletionPayload differences_payload(const support_assist::gui::DifferencesOutcome& outcome);
  static CompletionPayload registry_compare_payload(const std::filesystem::path& before, const std::string& before_id,
                                                    const std::filesystem::path& after, const std::string& after_id,
                                                    bool now, const support_assist::CancellationToken& token);
  CompletionPayload run_diagnostics(const OperationRequest& request);
  CompletionPayload run_help(const OperationRequest& request);

  HINSTANCE instance_ = nullptr;
  HWND window_ = nullptr;
  HWND navigation_ = nullptr;
  HWND brand_title_ = nullptr;
  HWND brand_subtitle_ = nullptr;
  HWND breadcrumb_ = nullptr;
  HWND title_ = nullptr;
  HWND section_rule_ = nullptr;
  HWND back_ = nullptr;
  HWND tool_tabs_ = nullptr;
  HWND close_tool_ = nullptr;
  HWND workspace_role_badge_ = nullptr;
  HWND active_case_label_ = nullptr;
  HWND active_case_combo_ = nullptr;
  std::array<HWND, 64> card_buttons_{};
  HWND card_scrollbar_ = nullptr;
  HWND mode_label_ = nullptr;
  HWND mode_combo_ = nullptr;
  HWND primary_label_ = nullptr;
  HWND primary_edit_ = nullptr;
  HWND primary_browse_ = nullptr;
  HWND secondary_label_ = nullptr;
  HWND secondary_edit_ = nullptr;
  HWND secondary_browse_ = nullptr;
  HWND tertiary_label_ = nullptr;
  HWND tertiary_edit_ = nullptr;
  HWND tertiary_browse_ = nullptr;
  HWND quaternary_label_ = nullptr;
  HWND quaternary_edit_ = nullptr;
  HWND quaternary_browse_ = nullptr;
  HWND quinary_label_ = nullptr;
  HWND quinary_edit_ = nullptr;
  HWND quinary_browse_ = nullptr;
  HWND senary_label_ = nullptr;
  HWND senary_edit_ = nullptr;
  HWND senary_browse_ = nullptr;
  HWND form_intro_ = nullptr;
  HWND tool_combo_ = nullptr;
  std::vector<std::wstring> vss_volume_values_;
  HWND collection_products_label_ = nullptr;
  std::array<HWND, 12> collection_product_checks_{};
  HWND network_interfaces_label_ = nullptr;
  HWND network_ipv4_check_ = nullptr;
  HWND network_ipv6_check_ = nullptr;
  std::array<HWND, 12> network_interface_checks_{};
  std::vector<std::string> network_interface_names_;
  std::vector<std::string> network_interface_addresses_;
  std::vector<support_assist::NetworkInterfaceInfo> network_interface_inventory_;
  HWND option_check_ = nullptr;
  HWND mode_check_ = nullptr;
  HWND action_ = nullptr;
  // System Differences: one page per type with Compare and Load beside Capture (action_). A button
  // sets the operation the request runs (-1: the page's own, Capture).
  HWND differences_compare_ = nullptr;
  HWND differences_load_ = nullptr;
  // The folded form: its summary line and Edit, and the form controls folding hid.
  HWND form_summary_ = nullptr;
  // The newest run's RUN line above a result table (gui_shared/result_table.hpp take_current_run).
  HWND run_header_ = nullptr;
  HFONT run_header_font_ = nullptr;      // bold, a step larger than ui_font_
  HFONT run_header_font_base_ = nullptr; // the ui_font_ it was made from
  std::wstring run_header_text_;
  HWND form_edit_ = nullptr;
  std::vector<HWND> folded_controls_;
  // The operations' own titles, in the Tool list's order; the list shows their cards' names.
  std::vector<std::wstring> mode_titles_;
  int differences_action_ = -1;
  HWND reset_output_ = nullptr;
  HWND cancel_ = nullptr;
  HWND progress_ = nullptr;
  HWND elapsed_ = nullptr;
  HWND context_help_ = nullptr;
  HWND output_label_ = nullptr;
  HWND results_ = nullptr;
  HWND detail_view_ = nullptr;
  HWND review_state_banner_ = nullptr;
  HWND review_machine_label_ = nullptr;
  HWND review_machine_combo_ = nullptr;
  HWND review_job_filter_label_ = nullptr;
  HWND review_job_filter_combo_ = nullptr;
  HWND review_run_label_ = nullptr;
  HWND review_run_combo_ = nullptr;
  std::array<HWND, 6> review_dashboard_cards_{};
  std::array<HealthCardPresentation, 6> review_card_presentations_{};
  HWND review_identity_label_ = nullptr;
  HWND review_identity_ = nullptr;
  HWND review_job_label_ = nullptr;
  HWND review_job_ = nullptr;
  int review_job_sort_column_ = 1;
  bool review_job_sort_ascending_ = false;
  HWND review_components_label_ = nullptr;
  HWND review_components_ = nullptr;
  int review_components_sort_column_ = 2;
  bool review_components_sort_ascending_ = false;
  HWND review_note_ = nullptr;
  HWND review_bookmark_ = nullptr;
  HWND review_reanalyze_ = nullptr;
  HWND review_append_ = nullptr;
  HWND review_more_ = nullptr;
  HWND status_ = nullptr;
  // When the status line last showed a progress report, and whether a newer one is waiting for the
  // next repaint. See show_progress_status().
  std::chrono::steady_clock::time_point status_painted_at_{};
  bool status_flush_pending_ = false;
  HWND tooltip_ = nullptr;
  HWND case_dashboard_heading_ = nullptr;
  HWND case_dashboard_subtitle_ = nullptr;
  HWND case_machine_label_ = nullptr;
  HWND case_machine_combo_ = nullptr;
  HWND case_run_label_ = nullptr;
  HWND case_run_combo_ = nullptr;
  HWND case_session_label_ = nullptr;
  HWND case_session_combo_ = nullptr;
  HWND case_copy_settings_ = nullptr;
  // Six describe the parsed log model; the last two say whether this case holds a rebuilt
  // environment or health snapshot, and open it.
  std::array<HWND, 8> case_dashboard_cards_{};
  // Sized WITH case_dashboard_cards_ above. These are parallel arrays indexed by the same
  // number, and growing one without the other writes past the end of this on every repaint -
  // which is what took the Case Dashboard out the first time the card count changed.
  std::array<HealthCardPresentation, 8> case_card_presentations_{};
  HWND case_machine_summary_label_ = nullptr;
  HWND case_machine_summary_ = nullptr;
  HWND case_review_summary_label_ = nullptr;
  HWND case_review_summary_ = nullptr;
  HWND case_evidence_summary_label_ = nullptr;
  HWND case_evidence_summary_ = nullptr;
  HWND case_new_ = nullptr;
  HWND case_load_review_ = nullptr;
  HWND case_append_logs_ = nullptr;
  HWND case_reanalyze_ = nullptr;
  HWND case_notes_button_ = nullptr;
  HWND case_pdf_selected_ = nullptr;
  HWND case_pdf_master_ = nullptr;
  HWND case_open_folder_ = nullptr;
  HWND case_more_ = nullptr;
  HWND case_manager_heading_ = nullptr;
  HWND case_manager_subtitle_ = nullptr;
  HWND case_manager_new_ = nullptr;
  HWND case_manager_register_ = nullptr;
  HWND case_manager_open_ = nullptr;
  HWND case_manager_note_ = nullptr;
  HWND case_manager_pdf_ = nullptr;
  HWND case_manager_folder_ = nullptr;
  HWND case_manager_delete_button_ = nullptr;
  HWND case_manager_refresh_ = nullptr;
  HWND case_manager_summary_label_ = nullptr;
  HWND case_manager_summary_ = nullptr;
  // Queue metrics across the top, drawn with the Case Dashboard's card renderer.
  std::array<HWND, 6> case_manager_cards_{};
  std::array<HealthCardPresentation, 6> case_manager_card_presentations_{};
  // The editor beside the list: working a case should not mean leaving the page.
  HWND case_manager_status_label_ = nullptr;
  HWND case_manager_status_combo_ = nullptr;
  HWND case_manager_next_label_ = nullptr;
  HWND case_manager_next_edit_ = nullptr;
  HWND case_manager_notes_label_ = nullptr;
  HWND case_manager_notes_edit_ = nullptr;
  HWND case_manager_save_ = nullptr;
  // The inline New Case form, shown in place of the editor rather than on another page.
  bool case_manager_form_open_ = false;
  // Set only by the screenshot harness, so its discovered cases are not re-read away.
  bool selfcheck_cases_override_ = false;
  // Carries the Case Manager row height only; attached to the shared table on entry, detached on
  // the way out so no other page inherits it.
  HIMAGELIST case_manager_row_metrics_ = nullptr;
  // The selected case, held as its root path. A virtual list view loses item state whenever the
  // row count is set, so the row index is not somewhere a selection can live.
  std::filesystem::path case_manager_selected_root_;
  HWND case_manager_form_parent_label_ = nullptr;
  HWND case_manager_form_parent_edit_ = nullptr;
  HWND case_manager_form_browse_ = nullptr;
  HWND case_manager_form_id_label_ = nullptr;
  HWND case_manager_form_id_edit_ = nullptr;
  HWND case_manager_form_title_label_ = nullptr;
  HWND case_manager_form_title_edit_ = nullptr;
  HWND case_manager_form_engineer_label_ = nullptr;
  HWND case_manager_form_engineer_edit_ = nullptr;
  HWND case_manager_form_folders_ = nullptr;
  HWND case_manager_form_create_ = nullptr;
  HWND case_manager_form_cancel_ = nullptr;
  HWND environment_heading_ = nullptr;
  HWND environment_subtitle_ = nullptr;
  HWND environment_text_ = nullptr;
  HWND environment_topology_ = nullptr;
  HWND environment_details_ = nullptr;
  std::array<HWND, 8> environment_cards_{};

  // Integrations (Page::tool_manager) master/detail. The catalogue rows reuse the owner-draw cards
  // (left column); the detail pane and action buttons are these controls.
  std::vector<IntegrationEntry> integration_entries_;
  int integration_selected_ = -1;
  // A managed run (VSS Trace) in progress: the tool id being traced and its elevated process handle,
  // so the Run button flips to Stop and Stop ends it.
  std::string integration_run_active_id_;
  HANDLE integration_run_process_ = nullptr;
  // Process Monitor's capture started from Integrations, while it runs: the owned session that
  // proves which Procmon process Stop capture ends. Exit stops it first.
  std::optional<support_assist::ProcmonSession> integration_procmon_;
  bool integration_procmon_stopping_ = false;
  // The VSS writers listed this session (name, class id), for the snapshot test's picker.
  std::vector<std::pair<std::wstring, std::wstring>> known_vss_writers_;
  HWND integration_detail_ = nullptr;      // right-hand property/detail pane
  HWND integration_desc_label_ = nullptr;  // "Description" caption over the editable strip
  HWND integration_desc_edit_ = nullptr;   // editable description strip for a configured tool
  HWND integration_add_ = nullptr;         // header: add a configured tool
  HWND integration_open_folder_ = nullptr; // header: open the managed tools folder
  HWND integration_refresh_ = nullptr;     // header: re-detect
  HWND integration_action_ = nullptr;      // Run (configured) / Acquire (optional)
  HWND integration_secondary_ = nullptr;   // Open publisher (optional) / Edit (configured)
  HWND integration_remove_ = nullptr;      // Remove copy / Remove entry
  HWND integration_file_location_ = nullptr;  // open the tool's folder in File Explorer

  // Guided-run window: a per-tool parameter form + live output for the Assisted command-line tools
  // (iPerf3, SQLCMD, ETL2PCAPNG). A separate top-level window; one is reused across tools. Output is
  // polled from the child's stdout/stderr pipe on a timer (no worker thread) into the pane and a log.
  HWND run_window_ = nullptr;
  HWND run_window_tips_ = nullptr;  // tooltip control; per-field hint text set in run_window_populate
  HWND run_title_label_ = nullptr;
  HWND run_summary_label_ = nullptr;
  std::array<HWND, 12> run_field_labels_{};
  std::array<HWND, 12> run_field_inputs_{};  // EDIT for a free-text/number/path field
  std::array<HWND, 12> run_field_combos_{};  // COMBOBOX for a choice field (shown in place of the edit)
  HWND run_output_ = nullptr;               // read-only pane, live command output
  HWND run_go_ = nullptr;                   // Run / Stop
  HWND run_cli_ = nullptr;                  // CLI: SAT's own command and the tool's command line
  HWND run_close_ = nullptr;
  HWND run_preset_label_ = nullptr;
  HWND run_preset_ = nullptr;     // worked examples: a preset fills the fields
  HWND run_help_ = nullptr;       // what the field in focus means, or what the chosen preset does
  HWND run_result_ = nullptr;     // a storage test's result, as a report
  HWND run_view_ = nullptr;       // Full output / Result
  bool run_show_output_ = false;  // the full output is in view rather than the result
  bool run_applying_preset_ = false;  // a preset is filling the fields, not the engineer
  std::string run_tool_id_;
  std::filesystem::path run_executable_;
  std::filesystem::path run_log_path_;
  HANDLE run_process_ = nullptr;
  HANDLE run_pipe_read_ = nullptr;
  // Packet Monitor (pktmon) capture: an elevated start -> reproduce -> stop -> convert flow. pktmon
  // exits immediately (the capture runs in the kernel), so it is not a held child but a tracked state.
  bool pktmon_capture_active_ = false;
  std::filesystem::path pktmon_capture_dir_;
  // The storage test (DiskSpd) runs through the Disk Speed Test engine on a worker; Stop cancels it
  // and the engine removes SAT's test file.
  std::shared_ptr<support_assist::CancellationSource> run_speed_cancel_;
  std::thread run_speed_thread_;
  bool run_speed_running_ = false;
  int run_progress_start_ = -1;  // where the running test's progress line starts in the output
  // Database console: an interactive terminal-style window that drives sqlcmd / psql, styled like the
  // Remote (SSH) console. Reuses the run-window pipe pattern but keeps the child's stdin open so
  // queries can be sent to a persistent session.
  HWND db_console_ = nullptr;
  HWND db_conn_label_ = nullptr;
  HWND db_server_ = nullptr;
  HWND db_port_ = nullptr;
  HWND db_database_ = nullptr;
  HWND db_auth_ = nullptr;       // combo: Trusted / SQL login (sqlcmd) or Password (psql)
  HWND db_user_ = nullptr;
  HWND db_password_ = nullptr;
  HWND db_connect_ = nullptr;
  HWND db_find_ = nullptr; // SQL Server: the instances the host's SQL Server Browser lists
  // Over Server, Port, Database, Sign in with, User and Password.
  std::array<HWND, 6> db_field_labels_{};
  // The query builder's field labels: Statement, Table, Where column, Compare, Value, Order by, Direction.
  std::array<HWND, 7> db_qb_labels_{};
  std::wstring db_asked_server_;  // the Server text whose instances were last asked for
  // The TCP port of each instance Find instances listed, by its place in the Server list.
  std::vector<std::wstring> db_found_ports_;
  HWND db_output_ = nullptr;     // read-only transcript pane
  HWND db_input_ = nullptr;      // the query the engineer types
  // The divider between the transcript and the query: its height, and the drag in progress.
  int db_input_height_ = 0;
  bool db_divider_dragging_ = false;
  RECT db_divider_{};
  HWND db_send_ = nullptr;
  HWND db_save_ = nullptr;
  // Query builder (compose a SELECT/DELETE, or paste a custom query).
  HWND db_qb_label_ = nullptr;
  HWND db_qb_mode_ = nullptr;
  HWND db_qb_scan_ = nullptr;
  HWND db_qb_table_ = nullptr;     // combo: tables scanned from the live schema
  HWND db_qb_field_ = nullptr;     // combo: columns of the chosen table
  HWND db_qb_operator_ = nullptr;  // combo: = <> > < >= <= LIKE
  HWND db_qb_value_ = nullptr;     // combo: distinct values of the chosen column (editable)
  HWND db_qb_orderby_ = nullptr;   // combo: order-by column
  HWND db_qb_orderdir_ = nullptr;  // combo: ASC / DESC
  HWND db_qb_insert_ = nullptr;
  HWND db_console_tips_ = nullptr;  // tooltip control owning hover hints for the db-console fields
  // (schema, table_name) for each table from the last Scan, so the builder can qualify + quote it.
  std::vector<std::pair<std::wstring, std::wstring>> db_qb_tables_;
  HFONT db_console_font_ = nullptr;
  std::string db_tool_id_;
  std::filesystem::path db_executable_;
  std::filesystem::path db_log_path_;
  HANDLE db_process_ = nullptr;
  HANDLE db_pipe_read_ = nullptr;
  HANDLE db_pipe_write_ = nullptr;  // child stdin, kept open for the interactive session
  // Configured-tool editor: a small dialog to add or edit one of the engineer's own tools - name
  // (defaults to the program name, editable), program (browse), arguments and a description. Replaces
  // the inline description strip; Save writes to the configured-tools file by id.
  HWND edit_window_ = nullptr;
  HWND edit_window_tips_ = nullptr;  // hover hints for the configured-tool editor fields
  HWND edit_name_ = nullptr;
  HWND edit_program_ = nullptr;
  HWND edit_program_browse_ = nullptr;
  HWND edit_arguments_ = nullptr;
  HWND edit_description_ = nullptr;
  HWND edit_save_ = nullptr;
  HWND edit_cancel_ = nullptr;
  std::array<HWND, 4> edit_field_labels_{};
  std::string edit_tool_id_;  // empty when adding a new tool
  void open_tool_editor(const IntegrationEntry* entry);
  void tool_editor_layout();
  void tool_editor_save();
  static LRESULT CALLBACK edit_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  // SQL Tools' Read-only query: Edit query... beside Query opens a window to type or paste the query.
  // Run query checks it with the read-only guard, puts it in the Query field on one line and runs it.
  HWND query_editor_ = nullptr;
  HWND query_editor_label_ = nullptr;
  HWND query_editor_text_ = nullptr;
  HWND query_editor_note_ = nullptr;  // why the typed query was not run
  HWND query_editor_run_ = nullptr;
  HWND query_editor_cancel_ = nullptr;
  std::wstring query_editor_field_;      // the Query field's text when the window opened
  std::wstring query_editor_statement_;  // that field's statement, as the window first showed it
  void open_sql_query_editor();
  void sql_query_editor_layout();
  void sql_query_editor_run();
  static LRESULT CALLBACK sql_query_editor_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);

  void open_run_window(const IntegrationEntry& entry);
  void run_window_populate();
  void run_window_layout();
  void run_window_toggle();  // Run when idle, Stop when running
  void run_window_pktmon_toggle();  // pktmon: Run starts an elevated capture, Stop stops + converts
  int run_elevated_command(const std::wstring& command_line, const std::filesystem::path& working);
  void run_window_begin();
  void run_window_end(bool terminated);
  void run_window_poll();  // timer: drain the pipe, detect exit
  void run_window_append(const std::string& utf8_chunk);
  void run_window_append_utf8(const std::string& text);  // SAT's own text, which is UTF-8
  std::string run_window_value(const std::string& key);  // a field's value by its profile key
  void run_window_show_cli();      // CLI: SAT's own command and the tool's command line
  void run_window_speed_toggle();  // the storage test: Run plans, asks and starts it; Stop cancels
  void run_window_progress(const std::string& line);  // the running test's progress line
  void run_window_apply_preset();             // the chosen preset's values into the fields
  void run_window_show_help(HWND focus);      // the help line for the field in focus
  void run_window_set_view(bool output);      // a storage test: the result, or the full output
  static LRESULT CALLBACK run_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  // Database console.
  void open_db_console(const IntegrationEntry& entry);
  void db_console_layout();
  void db_console_connect();
  void db_console_disconnect(bool terminated);
  void db_console_send_current();
  void db_console_drain();  // read-only pipe drain; safe to call from disconnect (no exit detection)
  void db_console_poll();   // drain + detect child exit (poll timer only)
  void db_console_discover_servers();    // sqlcmd -L: fill the server combo with network instances
  void db_console_find_instances();
  // VSS Tools' test snapshot: the writers it includes, ticked from the ones Enumerate writers found.
  void choose_vss_writers();
  void show_integration_card_menu(std::size_t card_index, POINT point);
  void integration_update_tool();
  void watch_tools_folder();
  int form_intro_height(int width) const;
  void remember_vss_writers(const std::vector<Row>& rows);
  // A field with a fixed set of values (gui_shared/field_choices.hpp): its Browse slot reads
  // Choose... and opens them in a menu.
  void refresh_slot_choices();
  bool offer_slot_choices(std::size_t slot);
  // A field with a list shows a drop-down in its place: editable (slot_combos_) or, for a fixed
  // set, a list (slot_lists_). The slot's edit stays the field's value and is kept in step.
  std::array<HWND, 6> slot_combos_{};
  std::array<HWND, 6> slot_lists_{};
  std::array<bool, 6> slot_fixed_{};
  bool syncing_slot_ = false;
  // Set while list_sql_databases opens a Database list again after its read: the list's own
  // CBN_DROPDOWN then starts no second read.
  bool database_list_opening_ = false;
  std::size_t database_list_reads_ = 0;
  std::array<HWND, 6> slot_edits() const;
  void fill_slot_dropdown(std::size_t slot);
  void slot_dropdown_changed(std::size_t slot, bool fixed, int notification);
  void sync_slot_dropdown_from_edit(std::size_t slot);
  // An editable drop-down that was moved or resized completes its text to the matching list item and
  // selects it; this puts the field's value back, unselected.
  void restore_slot_combo_text(std::size_t slot);
  // SQL Tools: the field slot that carries a label, if the page shows one.
  std::optional<std::size_t> slot_with_label(const wchar_t* label) const;
  // A pick in the instance list sets the Engine field; a new engine gives Database and Query the
  // starting values of that engine.
  void sql_tools_field_picked(std::size_t slot, const std::string& value);
  void sql_tools_engine_changed(support_assist::SqlEngine engine);
  // The Database fields: opening one offers the databases already listed for the server in the form,
  // or lists them (list_sql_databases) when the server has not been read yet.
  void sql_tools_database_dropdown(std::size_t slot);
  void list_sql_databases(std::size_t slot);
  void choose_smb_share(HWND edit, RECT button, std::wstring host);
  std::array<std::vector<support_assist::gui::FieldChoice>, 6> slot_choices_;      // the typed host's SQL Server Browser: its instances and ports
  void db_console_update_auth_fields();  // grey out user/password when the "current user" mode is chosen
  void db_console_append(const std::string& utf8_chunk);
  void db_console_save_output();
  void db_console_insert_built_query();
  // The guided query wizard: scan the live schema into the dropdowns (tables -> columns -> values).
  // SQL is built by the shared support_assist::gui::dbsql module (gui_shared/db_console_sql.hpp);
  // introspect takes UTF-8 SQL and runs it through the client, parsing clean stdout rows.
  support_assist::gui::dbsql::Engine db_console_engine() const;
  std::vector<std::wstring> db_console_introspect(const std::string& sql);
  void db_console_scan_tables();
  void db_console_list_databases();
  void db_console_port_of_named_instance();
  void db_console_scan_columns();
  void db_console_scan_values();
  std::wstring db_console_quote_ident(const std::wstring& ident) const;  // engine-correct quoting
  std::wstring db_console_table_schema() const;     // schema of the selected table (from last scan)
  std::wstring db_console_qualified_table() const;  // schema.table, quoted for the engine
  static LRESULT CALLBACK db_console_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);

  void rebuild_integration_catalogue();
  void render_integration_detail();
  void integration_run_action(int which);  // 0=primary 1=secondary 2=remove 3=add 4=open-folder
  // Register a configured tool from a program path, then re-detect and re-render. Split out of the
  // Add flow so the screenshot harness can exercise it without a file dialog.
  void integration_add_program(const std::wstring& program);
  // Save the inline description strip to the selected configured tool's notes.
  void integration_save_description();
  // Managed run (VSS Trace): start the tool elevated with its fixed command, writing the trace under
  // Log-Collections; stop it (clean Ctrl+C attempt, then terminate). Path is per-host under the tool.
  void integration_start_trace(const IntegrationEntry& entry);
  void integration_stop_trace();
  std::filesystem::path integration_trace_log_path(const IntegrationEntry& entry) const;
  // Process Monitor's capture (Start capture / Stop capture): Procmon runs hidden with a backing
  // .pml under the tools output, through the owned-session API so Stop ends only the process SAT
  // started. integration_stop_procmon returns true when no SAT-owned capture is left running.
  static bool is_procmon_capture(const IntegrationEntry& entry) noexcept;
  bool integration_procmon_running() const noexcept;
  void integration_start_procmon(const IntegrationEntry& entry);
  bool integration_stop_procmon();
  void integration_launch(const IntegrationEntry& entry);
  // The inline per-row action a catalogue card exposes: "Run" for a configured tool, "Acquire" or
  // "Update" for an optional one. Returns false for a card that carries no inline action; on true it
  // fills the button label and whether it is enabled. Kept beside draw_card and open_card so the
  // rectangle drawn is the exact rectangle hit-tested.
  bool integration_card_action(std::size_t card_index, std::wstring& label, bool& enabled) const;
  std::array<HealthCardPresentation, 8> environment_card_presentations_{};
  std::array<std::wstring, 8> environment_card_details_{};
  std::optional<std::size_t> last_environment_card_open_index_;
  std::chrono::steady_clock::time_point last_environment_card_open_time_{};
  std::unordered_map<HTREEITEM, std::wstring> environment_topology_details_;
  HWND explorer_heading_ = nullptr;
  HWND explorer_subtitle_ = nullptr;
  HWND explorer_tabs_ = nullptr;
  ExplorerTab explorer_tab_ = ExplorerTab::local;
  HWND explorer_system_tools_label_ = nullptr;
  std::array<HWND, 6> explorer_system_tool_buttons_{};
  HWND explorer_location_label_ = nullptr;
  HWND explorer_location_ = nullptr;
  HWND explorer_go_ = nullptr;
  HWND explorer_refresh_ = nullptr;
  HWND explorer_tree_ = nullptr;
  HWND explorer_list_ = nullptr;
  HWND explorer_status_ = nullptr;
  ExplorerSortColumn explorer_local_sort_column_ = ExplorerSortColumn::name;
  bool explorer_local_sort_ascending_ = true;
  std::unordered_map<HTREEITEM, std::filesystem::path> explorer_tree_paths_;
  std::vector<std::filesystem::path> explorer_list_paths_;
  std::vector<bool> explorer_list_directories_;
  std::filesystem::path explorer_current_path_;
  std::filesystem::path explorer_current_safe_root_;
  std::filesystem::path explorer_last_selected_local_path_;
  std::vector<std::filesystem::path> explorer_safe_roots_;
  std::set<std::filesystem::path> explorer_marked_paths_;
  std::unordered_map<HTREEITEM, std::filesystem::path> explorer_tree_safe_roots_;
  std::unordered_set<HTREEITEM> explorer_tree_loaded_;
  bool explorer_archive_mode_ = false;
  std::filesystem::path explorer_archive_path_;
  std::string explorer_archive_virtual_path_;
  std::vector<support_assist::ArchiveBrowserEntry> explorer_archive_entries_;

  HWND explorer_transfer_local_label_ = nullptr;
  HWND explorer_transfer_remote_label_ = nullptr;
  HWND explorer_transfer_local_path_ = nullptr;
  HWND explorer_transfer_local_go_ = nullptr;
  HWND explorer_transfer_local_refresh_ = nullptr;
  HWND explorer_transfer_local_list_ = nullptr;
  std::vector<std::filesystem::path> explorer_transfer_local_paths_;
  std::vector<bool> explorer_transfer_local_directories_;
  ExplorerSortColumn explorer_transfer_local_sort_column_ = ExplorerSortColumn::name;
  bool explorer_transfer_local_sort_ascending_ = true;

  std::array<HWND, 4> explorer_ssh_labels_{};
  HWND explorer_ssh_host_ = nullptr;
  HWND explorer_ssh_port_ = nullptr;
  HWND explorer_ssh_user_ = nullptr;
  HWND explorer_ssh_password_ = nullptr;
  HWND explorer_ssh_key_ = nullptr;
  HWND explorer_ssh_probe_ = nullptr;
  HWND explorer_ssh_trust_ = nullptr;
  HWND explorer_ssh_fingerprint_ = nullptr;
  HWND explorer_ssh_path_ = nullptr;
  HWND explorer_ssh_refresh_ = nullptr;
  HWND explorer_ssh_upload_ = nullptr;
  HWND explorer_ssh_download_ = nullptr;
  HWND explorer_ssh_disconnect_ = nullptr;
  HWND explorer_ssh_list_ = nullptr;
  HWND explorer_ssh_status_ = nullptr;
  support_assist::SshConnectionOptions explorer_ssh_options_;
  std::vector<support_assist::SftpEntry> explorer_ssh_entries_;
  // --- Remote console state ---------------------------------------------------------------
  HWND remote_host_ = nullptr;
  HWND remote_port_ = nullptr;
  HWND remote_user_ = nullptr;
  HWND remote_password_ = nullptr;
  HWND remote_key_ = nullptr;
  HWND remote_key_browse_ = nullptr;
  HWND remote_key_passphrase_ = nullptr;
  HWND remote_connect_button_ = nullptr;
  HWND remote_disconnect_button_ = nullptr;
  HWND remote_terminal_ = nullptr;
  HWND remote_files_ = nullptr;
  HWND remote_path_ = nullptr;
  HWND remote_download_ = nullptr;
  HWND remote_upload_ = nullptr;
  HWND remote_status_ = nullptr;
  std::vector<HWND> remote_labels_;
  // What connecting is doing, shown large in the console area until the shell takes it over. The
  // one-line status at the bottom keeps the same text, so nothing is lost when it is replaced.
  std::vector<std::wstring> remote_progress_;

  std::shared_ptr<support_assist::SshShell> remote_shell_;
  std::unique_ptr<support_assist::TerminalScreen> remote_screen_;
  support_assist::SshConnectionOptions remote_options_;
  std::vector<support_assist::SftpEntry> remote_entries_;
  bool remote_connected_ = false;
  // The listing shows a parent row unless it is at /, so every index into remote_entries_ has to
  // account for it. Kept as state rather than recomputed, so the row offset cannot disagree with
  // what was actually drawn.
  bool remote_at_root_ = false;
  bool remote_busy_ = false;
  // Answered once at connect. SAT cannot tell a lab box from a customer's production server; the
  // operator can, and the operator supplied the credentials.
  bool remote_customer_machine_ = false;
  std::uint64_t remote_painted_revision_ = 0;
  UINT_PTR remote_timer_ = 0;
  HFONT remote_terminal_font_ = nullptr;
  int remote_cell_width_ = 8;
  int remote_cell_height_ = 16;
  // Rows scrolled back from the live bottom. TerminalScreen already keeps the history; without
  // this the paint loop only ever drew the visible screen, so everything that scrolled off the
  // top was held in memory and unreachable.
  int remote_scroll_offset_ = 0;
  // Terminal text selection, in visible-row / column space. Cleared when the screen scrolls or new
  // output arrives. Drives the highlight in the paint loop and the Copy action.
  bool remote_selecting_ = false;
  bool remote_has_selection_ = false;
  int remote_sel_anchor_row_ = 0;
  int remote_sel_anchor_col_ = 0;
  int remote_sel_row_ = 0;
  int remote_sel_col_ = 0;

  // Draggable dividers between the panes of the review pages. Each group splits one span into
  // panes along one axis; `bounds` holds where its dividers sit, as ascending fractions of the
  // span. A page's layout calls place_split, which returns the panes and records where the bars
  // landed so the parent can hit-test them (the bars are bare parent background, like the Remote
  // band above). Dragging a divider to an edge collapses the pane beside it; double-clicking it
  // restores that pane, or resets the split when nothing is collapsed. Saved in [Panes].
  enum class SplitId : std::size_t {
    log_review_columns,  // Machine and Product | Machine Activity Timeline | Components with Findings
    log_review_rows,     // those tables | Issue Summary | finding detail
    environment_columns, // topology | details
    environment_rows,    // topology and details | Live View
    health_rows,         // Findings and Storage | Network and Processes
    health_top,          // Findings | Storage
    health_bottom,       // Network | Processes
    case_rows,           // selected evidence | machine and review summaries
    case_columns,        // machine summary | review summary
    integration_columns, // Integrations catalogue | selected tool detail
    explorer_columns,    // File Browser folder tree | folder contents
    remote_columns,      // Remote file pane | terminal
    case_manager_rows,   // Case Manager: the case list | the editor or the New Case form
    case_manager_columns, // Status, Save and Case notes | Next steps and Selected case
    case_manager_right,  // Next steps | Selected case
    tool_result_rows,    // a folded Tools table | its selected row in full
    count
  };
  struct SplitGroup {
    const wchar_t* key = L"";
    bool side_by_side = true;  // panes left to right, so the bars run top to bottom
    std::vector<double> bounds;
    std::vector<double> defaults;
    std::vector<double> restore;  // per divider: where it returns after a collapse
    std::vector<int> minimums;    // per pane, in pixels, while the pane is not collapsed
    std::vector<bool> collapsible; // per pane: whether dragging past half its minimum hides it
    int start = 0;                // where the span starts along the axis, client pixels
    int usable = 0;               // span length less the bars
    int bar = 0;                  // bar thickness
    RECT area{};                  // the whole group, for drawing and hit-testing the bars
    bool placed = false;          // laid out on the page now showing
  };
  struct SplitPane {
    int start;
    int size;
  };
  std::array<SplitGroup, static_cast<std::size_t>(SplitId::count)> splits_{};
  int split_drag_group_ = -1;
  int split_drag_bar_ = -1;
  int split_drag_grab_ = 0;  // pointer offset inside the bar when the drag began
  int split_hot_group_ = -1;
  int split_hot_bar_ = -1;
  DWORD split_last_click_time_ = 0;
  int split_last_click_group_ = -1;
  int split_last_click_bar_ = -1;
  void init_splits();
  std::vector<SplitPane> place_split(SplitId id, int start, int length, int cross_start,
                                     int cross_length, int bar);
  std::vector<int> split_offsets(const SplitGroup& group) const;
  RECT split_bar_rect(std::size_t group, std::size_t bar) const;
  bool split_hit(int x, int y, int& group, int& bar) const;
  void split_drag_to(int x, int y);
  void split_toggle(int group, int bar);
  void split_set_hot(int group, int bar);
  void split_relayout();
  void paint_split_grips(HDC dc) const;
  void reset_pane_layout();
  void load_splits(const std::filesystem::path& path);
  void save_splits(const std::filesystem::path& path) const;

  // Files and folders dropped on SAT (src/gui/file_drop.cpp). A file is read to show its SHA-256
  // in the checksum window; a folder is offered to Log Review. Nothing dropped is run or opened
  // with its own program.
  bool handle_file_drop_message(UINT message, WPARAM wparam, LPARAM lparam, LRESULT& result);
  void accept_dropped_paths(const std::vector<std::filesystem::path>& paths);
  void review_dropped_folders(const std::vector<std::filesystem::path>& folders);
  void add_checksum_files(const std::vector<std::filesystem::path>& files,
                          std::vector<support_assist::gui::ChecksumList> lists = {});
  void open_checksum_window();
  void layout_checksum_window();
  void show_checksum_row(std::size_t index, bool insert);
  void apply_checksum_result(std::uint64_t generation, std::size_t index, std::string sha256,
                             std::string error);
  void update_checksum_match();
  void update_checksum_summary();
  void copy_checksums(bool hashes_only);
  void stop_checksum_work();
  static LRESULT CALLBACK checksum_window_proc(HWND window, UINT message, WPARAM wparam,
                                               LPARAM lparam);
  HWND checksum_window_ = nullptr;
  HWND checksum_note_ = nullptr;
  HWND checksum_list_ = nullptr;
  HWND checksum_expected_label_ = nullptr;
  HWND checksum_expected_ = nullptr;
  HWND checksum_match_ = nullptr;
  HWND checksum_copy_ = nullptr;
  HWND checksum_copy_all_ = nullptr;
  HWND checksum_close_ = nullptr;
  // What the match line currently says, for its colour: 0 nothing, 1 a match, 2 no match, 3 not a
  // SHA-256 value.
  int checksum_match_state_ = 0;
  // The same for the line above the table once a checksum list has been dropped; -1 while it shows
  // the window's note.
  int checksum_note_state_ = -1;
  // Rows belong to the UI thread. The worker sees only the queue of (row, path) pairs, under the
  // mutex, and posts each result back tagged with the generation it was started for, so a result
  // that arrives after the window was closed is dropped.
  support_assist::gui::ChecksumSet checksum_set_;
  std::mutex checksum_mutex_;
  std::deque<std::pair<std::size_t, std::filesystem::path>> checksum_queue_;
  bool checksum_worker_busy_ = false;
  std::uint64_t checksum_generation_ = 1;
  support_assist::CancellationSource checksum_cancel_;
  std::jthread checksum_worker_;
  std::vector<std::filesystem::path> launch_dropped_paths_;

  // Running Jobs (src/gui/running_jobs_window.cpp): every session tab, in every case, with its
  // state and newest progress report. A row opens its session; a running job can be cancelled.
  std::vector<support_assist::gui::JobEntry> collect_jobs() const;
  void open_jobs_window();
  // The keys in gui_shared/keyboard_shortcuts.hpp, and the quick tools' windows
  // (src/gui/quick_tools.cpp): Name Check, Local Port Checker, Time Check, File Lock Check,
  // Volume Check and Service and Process Watch, one window each.
  bool run_shortcut_command(support_assist::gui::ShortcutCommand command, HWND source = nullptr);
  // A quick tool's window; with embedded, the tool's view as a child of the main window for a task's
  // session tab, returned unshown.
  HWND open_quick_tool(support_assist::gui::ShortcutCommand tool, const std::wstring& subject = L"",
                       bool embedded = false);
  // The Object Storage Check as a Storage Tools task, its view in a session tab.
  void open_object_storage_task();
  // The task view holding a control, or nullptr.
  HWND task_view_containing(HWND control) const;
  // Whether a quick tool's view is running its check, for its session tab's RUN.
  bool quick_tool_view_running(HWND view) const;
  // Watch's Its log: a menu of the logs written before a process ended, then the viewer at the line.
  void quick_tool_choose_log(QuickToolState& state, const std::vector<support_assist::LogWrittenNear>& logs,
                             std::int64_t at_unix_millis, const std::string& name);
  // A log in SAT's viewer at a line.
  void open_log_in_viewer(const std::filesystem::path& path, std::uint64_t line);
  // A Storage Tools card: 0 the Disk Speed Test, 1 the Object Storage Check.
  void open_storage_tool(int mode);
  // The Object Storage Check is experimental: shown once Settings > General turns it on.
  bool object_storage_enabled() const;
  bool is_quick_tool_window(HWND root) const;
  void quick_tools_after_rescale();
  void open_remote_port_checker(const std::wstring& host);
  void quick_tool_layout(QuickToolState& state);
  void quick_tool_fill_ports(QuickToolState& state);
  void quick_tool_port_selected(QuickToolState& state);
  void quick_tool_run(QuickToolState& state, int command);
  void quick_tool_watch_tick(QuickToolState& state);
  void quick_tool_fill_watch(QuickToolState& state, const support_assist::WatchSnapshot& snapshot);
  void quick_tool_start_listener(QuickToolState& state);
  void quick_tool_listener_ended(QuickToolState& state, const std::wstring& error);
  void quick_tool_keep_output(const support_assist::gui::QuickToolOutput& output);
  void quick_tools_role_changed();
  void quick_tool_show_listener(QuickToolState& state);
  void quick_tool_show_listener_row(QuickToolState& state);
  void quick_tool_recheck_ports(QuickToolState& state);
  void quick_tool_transfer_show(QuickToolState& state, const support_assist::TransferEstimate& estimate, bool keep);
  static LRESULT CALLBACK quick_tool_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam);
  std::array<HWND, 8> quick_tool_windows_{};
  // Home as a status board and the Tools categories' tiles (src/gui/home_page.cpp, drawn by
  // board_panel.cpp from gui_shared/home_board.hpp).
  void create_board_panels();
  // Diagnostics as one page (src/gui/diagnostics_page.cpp): the report, Run again and Copy.
  void create_diagnostics_page();
  void refresh_diagnostics_report();
  // The Veeam products in the registry's uninstall list: category, name, location, version.
  static std::vector<Row> installed_veeam_product_rows();
  bool handle_diagnostics_message(UINT message, WPARAM wparam, LPARAM lparam);
  bool handle_diagnostics_command(int id);
  void layout_diagnostics_page(int left, int top, int width, int height);
  HWND diagnostics_report_ = nullptr;
  HWND operation_guide_ = nullptr;
  HWND diagnostics_run_ = nullptr;
  HWND diagnostics_copy_ = nullptr;
  bool diagnostics_reading_ = false;
  std::optional<support_assist::gui::QuickToolReport> diagnostics_last_;
  std::jthread diagnostics_worker_;
  void rebuild_home_board();
  void home_board_activated(int index);
  void run_board_action(support_assist::gui::BoardAction action, support_assist::gui::WorkspacePage page,
                        support_assist::gui::ShortcutCommand tool, const std::string& target);
  void refresh_home_review_summary();
  void refresh_home_holdings();
  void refresh_home_restart();
  void refresh_home_products();
  void refresh_home_machine();
  void refresh_home_services();
  void rebuild_tools_board();
  void tools_board_activated(int index);
  void last_output_changed();
  // The guided diagnostics that apply here, and whether a local backup server runs here, each read
  // again at most every ten seconds (local_vbr_server_available()).
  const std::vector<support_assist::GuidedDiagnosticDefinition>& guided_diagnostics_here() const;
  mutable std::vector<support_assist::GuidedDiagnosticDefinition> guided_here_;
  mutable bool guided_read_ = false;
  mutable std::chrono::steady_clock::time_point guided_read_at_{};
  mutable bool vbr_server_read_ = false;
  mutable bool vbr_server_available_ = false;
  mutable std::chrono::steady_clock::time_point vbr_server_read_at_{};
  // The Tools categories (gui_shared/home_board.hpp): the ones this machine lists, each category's
  // cards with its section captions, and every tool card flat.
  std::vector<support_assist::gui::ToolCategory> listed_tool_categories() const;
  std::vector<Card> tool_category_cards(support_assist::gui::ToolCategory category) const;
  std::vector<Card> category_base_cards(Page page) const;
  std::vector<Card> all_tool_cards() const;
  static Page page_of_category(support_assist::gui::ToolCategory category);
  // The Windows page for a shared page; none for Help, which is a window.
  static std::optional<Page> page_of_workspace(support_assist::gui::WorkspacePage page);
  static std::optional<support_assist::gui::ToolCategory> category_of_page(Page page);
  static support_assist::gui::ToolCategory tool_card_category(const Card& card);
  // The pages whose cards scroll under a header row: Tools, its categories and Integrations.
  bool card_catalog_scrolls() const noexcept;
  bool shows_tools_board() const noexcept;
  void open_pending_restart_report();
  // A report in a window of its own (pending restart, Home's products and services).
  void open_report_window(const wchar_t* title, const support_assist::gui::QuickToolReport& report);
  bool handle_board_message(UINT message, WPARAM wparam, LPARAM lparam);
  HWND home_board_ = nullptr;
  HWND tools_board_ = nullptr;
  HWND activity_board_ = nullptr;
  // The tile in use on Recent Activity, and the outcome colour of each row the table holds.
  support_assist::gui::ActivityFilter activity_filter_ = support_assist::gui::ActivityFilter::all;
  std::vector<support_assist::gui::ReportTone> activity_row_tones_;
  std::vector<support_assist::gui::BoardTile> home_tiles_;
  std::vector<support_assist::gui::BoardLink> home_links_;
  support_assist::gui::CaseReviewSummary home_review_;
  std::filesystem::path home_review_root_;
  std::optional<std::filesystem::file_time_type> home_review_mtime_;
  bool home_review_loading_ = false;
  support_assist::gui::CaseHoldings home_holdings_;
  std::filesystem::path home_holdings_root_;
  std::chrono::steady_clock::time_point home_holdings_at_{};
  bool home_holdings_loading_ = false;
  std::optional<support_assist::PendingRestartResult> home_restart_;
  bool home_restart_loading_ = false;
  std::vector<support_assist::gui::FoundProduct> home_products_;
  std::vector<std::string> home_guided_;
  bool home_products_loading_ = false;
  bool home_products_read_ = false;
  // This machine, read once: its name, Windows version, account and time zone.
  bool home_machine_read_ = false;
  bool home_machine_loading_ = false;
  std::string home_machine_name_;
  std::string home_machine_os_;
  bool home_machine_elevated_ = false;
  int home_machine_utc_offset_ = 0;
  // Veeam's services, read again every half minute while Home shows.
  bool home_services_read_ = false;
  bool home_services_loading_ = false;
  std::size_t home_services_running_ = 0;
  std::vector<std::string> home_services_stopped_;
  std::chrono::steady_clock::time_point home_services_at_{};
  std::size_t collections_this_session_ = 0;
  std::int64_t last_collection_unix_millis_ = 0;
  std::vector<support_assist::gui::CategoryTile> tools_category_tiles_;
  unsigned home_board_ticks_ = 0;
  // Jump To (src/gui/command_palette_window.cpp): Ctrl+K finds a page, tool, case or command.
  std::vector<support_assist::gui::PaletteEntry> collect_palette_entries();
  void open_palette();
  void layout_palette();
  void refresh_palette_matches();
  void close_palette();
  void run_palette_row(int row);
  void open_user_guide();
  LRESULT paint_list_header(const NMHDR* header, LPARAM lparam) const;
  static LRESULT CALLBACK list_header_proc(HWND list, UINT message, WPARAM wparam, LPARAM lparam,
                                           UINT_PTR id, DWORD_PTR reference);
  static LRESULT CALLBACK palette_window_proc(HWND window, UINT message, WPARAM wparam,
                                              LPARAM lparam);
  static LRESULT CALLBACK palette_edit_proc(HWND window, UINT message, WPARAM wparam,
                                            LPARAM lparam, UINT_PTR id, DWORD_PTR reference);
  HWND palette_window_ = nullptr;
  HWND palette_edit_ = nullptr;
  HWND palette_list_ = nullptr;
  HWND palette_hint_ = nullptr;
  std::vector<support_assist::gui::PaletteEntry> palette_entries_;
  std::vector<Card> palette_cards_;
  // The entries the list shows, in list order.
  std::vector<std::size_t> palette_shown_;
  void layout_jobs_window();
  void refresh_jobs_window();
  void update_jobs_buttons();
  bool go_to_job(std::size_t key);
  void cancel_job(std::size_t key);
  static LRESULT CALLBACK jobs_window_proc(HWND window, UINT message, WPARAM wparam,
                                           LPARAM lparam);
  HWND jobs_window_ = nullptr;
  HWND jobs_summary_ = nullptr;
  HWND jobs_list_ = nullptr;
  HWND jobs_go_ = nullptr;
  HWND jobs_cancel_ = nullptr;
  HWND jobs_close_ = nullptr;
  // The rows as the list shows them, so a refresh repaints only what changed.
  std::vector<support_assist::gui::JobEntry> jobs_shown_;
  // Set while a dropped folder opens Log Review, so Auto Detect reviews that folder instead of
  // the local Veeam logs it looks for when a Customer / Lab host has no case.
  bool suppress_auto_local_review_ = false;

  bool explorer_ssh_host_key_probed_ = false;
  // Set when Connect started the probe itself, so the probe result raises the trust dialog and
  // continues rather than leaving the operator to tick a box and press Connect a second time.
  bool explorer_ssh_connect_after_trust_ = false;
  std::wstring explorer_ssh_host_key_algorithm_;
  bool explorer_ssh_connected_ = false;
  std::wstring explorer_ssh_machine_name_;
  ExplorerSortColumn explorer_ssh_sort_column_ = ExplorerSortColumn::name;
  bool explorer_ssh_sort_ascending_ = true;

  std::array<HWND, 2> explorer_console_labels_{};
  HWND explorer_console_target_ = nullptr;
  HWND explorer_console_shell_label_ = nullptr;
  HWND explorer_console_shell_ = nullptr;
  HWND explorer_console_elevated_ = nullptr;
  // States the account and elevation the local console will run as. SAT never elevates a
  // session itself, so this is what a command typed here will actually be able to do.
  HWND explorer_console_context_ = nullptr;
  HWND explorer_console_command_ = nullptr;
  HWND explorer_console_run_ = nullptr;
  HWND explorer_console_stop_ = nullptr;
  HWND explorer_console_output_ = nullptr;
  std::jthread explorer_worker_;
  support_assist::CancellationSource explorer_cancellation_;
  bool explorer_remote_busy_ = false;
  std::jthread environment_worker_;
  support_assist::CancellationSource environment_cancellation_;
  std::atomic_uint64_t environment_refresh_generation_{0};
  HWND environment_refresh_ = nullptr;
  HWND environment_load_ = nullptr;
  HWND environment_load_collection_ = nullptr;
  // Reopens the reconstruction already saved in the active case. Disabled when there is none.
  HWND environment_open_saved_ = nullptr;
  // One button for every way of opening something that is not the live machine, in place of three
  // side-by-side buttons for the same question.
  HWND environment_open_menu_ = nullptr;
  HWND environment_pdf_ = nullptr;
  HWND note_review_heading_ = nullptr;
  HWND note_review_status_ = nullptr;
  HWND note_review_scope_label_ = nullptr;
  HWND note_review_scope_combo_ = nullptr;
  HWND note_review_text_ = nullptr;
  HWND note_review_refresh_ = nullptr;
  HWND note_review_copy_ = nullptr;
  HWND note_review_save_ = nullptr;
  HWND health_snapshot_banner_ = nullptr;
  HWND health_load_snapshot_ = nullptr;
  HWND health_load_collection_ = nullptr;
  HWND health_open_saved_ = nullptr;
  HWND health_open_menu_ = nullptr;
  HWND health_live_snapshot_ = nullptr;
  HWND health_title_ = nullptr;
  HWND health_summary_ = nullptr;
  HWND health_volumes_ = nullptr;
  HWND health_note_ = nullptr;
  HWND health_toggle_ = nullptr;
  // Recent Activity: load a collected activity record from a bundle folder or ZIP.
  HWND activity_load_ = nullptr;
  HWND case_tool_evidence_ = nullptr;
  HWND show_cli_ = nullptr;
  HWND open_output_ = nullptr;
  bool open_output_available_ = false;
  // Real grid for collected sections that are genuinely tabular. A text pane cannot give resizable
  // or sortable columns, and long values inevitably run into the neighbouring column.
  HWND environment_detail_grid_ = nullptr;
  void present_environment_detail(const std::wstring& detail);
  bool show_cli_available_ = false;
  // Set while the command-line equivalent is displayed in the output pane, so it is shown on any
  // operation page - including one where nothing has run yet and the results list would be empty.
  // Cleared when the page changes or an operation starts.
  bool cli_output_active_ = false;
  // Recent Activity shows either this workstation's live record or an opened archive, never a
  // merge of the two. The live activity_ vector is left untouched while an archive is displayed.
  std::vector<Row> archived_activity_rows_;
  std::wstring archived_activity_source_;
  bool viewing_archived_activity_ = false;
  // Tool evidence review window: a separate top-level window opened from the parser, colour coded
  // by diagnostic outcome so a finding is visible without reading every row.
  void open_tool_evidence_window();
  bool load_tool_evidence_timeline();
  void populate_tool_evidence_list();
  void draw_tool_evidence_card(const DRAWITEMSTRUCT& draw);
  void add_tool_evidence_entry_to_note(std::size_t index);
  static LRESULT CALLBACK tool_evidence_window_proc(HWND window, UINT message, WPARAM wparam,
                                                    LPARAM lparam);
  HWND tool_evidence_window_ = nullptr;
  HWND tool_evidence_list_ = nullptr;
  std::vector<support_assist::ToolTimelineEntry> tool_evidence_timeline_;
  std::array<HWND, 6> health_dashboard_cards_{};
  std::array<HealthCardPresentation, 6> health_card_presentations_{};
  HWND health_findings_label_ = nullptr;
  HWND health_findings_ = nullptr;
  HWND health_storage_label_ = nullptr;
  HWND health_storage_ = nullptr;
  HWND health_network_label_ = nullptr;
  HWND health_network_ = nullptr;
  HWND health_processes_label_ = nullptr;
  HWND health_processes_ = nullptr;

  HFONT ui_font_ = nullptr;
  HFONT title_font_ = nullptr;
  HFONT heading_font_ = nullptr;
  HFONT card_font_ = nullptr;
  HFONT small_font_ = nullptr;
  HFONT mono_font_ = nullptr;
  HBRUSH background_brush_ = nullptr;
  HBRUSH panel_brush_ = nullptr;
  HBRUSH input_brush_ = nullptr;
  HBRUSH accent_brush_ = nullptr;
  HBRUSH selected_brush_ = nullptr;
  HBRUSH card_brush_ = nullptr;
  HICON app_icon_ = nullptr;
  HICON app_small_icon_ = nullptr;

  Page page_ = Page::home;
  bool menu_view_ = true;
  std::vector<Card> cards_;
  std::vector<NavigationItem> navigation_items_;
  bool general_tools_expanded_ = false;
  bool diagnostics_expanded_ = false;
  bool exit_when_idle_ = false;
  // Exit chosen with a packet capture left running: the exit no longer waits on the capture.
  bool exit_leaving_captures_ = false;
  // The tools folder's change notification while Integrations is shown.
  HANDLE tools_watch_ = nullptr;
  std::vector<support_assist::CaseWorkspace> cases_;
  int active_case_index_ = -1;
  std::vector<std::unique_ptr<ToolSession>> sessions_;
  std::vector<int> visible_session_indices_;
  std::map<std::wstring, std::uint64_t> last_active_session_by_context_;
  std::size_t maximum_tool_sessions_ = 15;
  WorkspaceRole workspace_role_ = WorkspaceRole::review_workstation;
  // Engineer mode licence state. Unlicensed builds are locked to Customer / Lab; a valid signed
  // licence beside the executable unlocks the Engineer Review Workstation role.
  bool engineer_unlocked_ = false;

  // Settings are read and written through these. Without an engineer licence nothing is written:
  // a change applies until SAT closes, so a support session on a customer machine leaves no
  // settings behind. The same holds for the case statuses, the SSH addresses and the configured
  // tools edited in that session.
  bool settings_persist() const { return engineer_unlocked_; }
  std::wstring read_setting(const wchar_t* section, const wchar_t* key,
                            const std::wstring& fallback) const;
  int read_setting_int(const wchar_t* section, const wchar_t* key, int fallback) const;
  void write_setting(const wchar_t* section, const wchar_t* key, const std::wstring& value);
  support_assist::Result<std::vector<support_assist::ConfiguredTool>> load_tools() const;
  support_assist::Status save_tools(const std::vector<support_assist::ConfiguredTool>& tools);
  // This session's unsaved values, keyed "Section/Key".
  std::map<std::wstring, std::wstring> session_settings_;
  std::optional<std::vector<std::wstring>> session_ssh_addresses_;
  std::optional<std::string> session_statuses_text_;
  void persist_session_changes();
  // The tool list is read and changed from the operation worker too.
  mutable std::mutex session_tools_mutex_;
  std::optional<std::vector<support_assist::ConfiguredTool>> session_tools_;
  std::wstring engineer_license_issued_to_;
  std::optional<support_assist::ExecutionArtifactManifest> last_execution_artifact_;
  std::optional<WorkspaceRole> pending_workspace_role_;
  int card_menu_scroll_offset_ = 0;
  int card_wheel_remainder_ = 0; // wheel movement not yet a whole pixel of card scroll
  RECT card_menu_area_{};        // the cards' area at the last full layout, reused by a scroll
  // On a scrolling card page, the cards the last layout placed in the view: only those are shown,
  // whatever else asks for the cards' visibility.
  std::vector<bool> card_in_view_;
  // A card at the edge of the view is sized to the part in view and drawn offset: its pixels cut
  // off at the top, and its whole height. Zero height: the card is whole.
  std::vector<int> card_hidden_top_;
  std::vector<int> card_full_height_;
  int card_menu_content_height_ = 0;
  int card_menu_view_height_ = 0;
  int active_session_index_ = -1;
  std::uint64_t next_session_id_ = 1;
  std::vector<ActivityRecord> activity_;
  std::shared_ptr<support_assist::VeeamLogReviewResult> case_dashboard_review_;
  std::filesystem::path case_dashboard_review_root_;
  std::optional<std::filesystem::file_time_type> case_dashboard_review_mtime_;
  std::filesystem::path environment_import_path_;
  std::wstring environment_import_text_;
  // environment_view_key() of what the Environment Review controls hold.
  std::wstring environment_shown_;
  // The last live collection's snapshot, so a kept quick check can join the tree without collecting again.
  std::wstring environment_live_snapshot_;
  support_assist::gui::QuickCheckHealthCache health_quick_checks_;
  std::string note_review_scope_key_;
  std::map<HWND, std::wstring> tooltip_texts_;
  std::unique_ptr<support_assist::SystemHealthSampler> health_sampler_;
  std::jthread health_worker_;
  mutable std::mutex health_mutex_;
  support_assist::SystemHealthSnapshot health_snapshot_;
  bool health_snapshot_available_ = false;
  support_assist::SystemHealthSnapshot saved_health_snapshot_;
  bool saved_health_snapshot_loaded_ = false;
  std::filesystem::path saved_health_snapshot_path_;
  int health_panel_height_ = 330;
  bool health_collapsed_ = false;
  bool health_splitter_dragging_ = false;
  int health_splitter_y_ = 0;

  mutable std::mutex rows_mutex_;
  // Filter as you type over the results table. The table is owner-data and rows_ keeps every row;
  // while a filter is typed the table shows the rows that contain it, in order, and
  // results_visible_ (under rows_mutex_) maps each shown row back to its place in rows_.
  HWND results_filter_ = nullptr;
  int text_scale_wheel_remainder_ = 0; // Ctrl and the wheel: the part of a notch not yet applied
  std::wstring results_filter_text_;
  std::vector<std::size_t> results_visible_;
  void set_results_count(std::size_t rows, DWORD flags);
  void apply_results_filter();
  void clear_results_filter();
  int result_display_index(int row) const;
  // The same filter over the Health Monitor tables, the File Browser list and the Environment
  // Review grid. Each box keeps the text it last applied and its table is filled with the rows that
  // contain it. health_table_rows_ keeps every row of the last sample, so typing refilters without
  // waiting for the next one; environment_detail_shown_ is the section in the grid.
  HWND health_filter_ = nullptr;
  HWND explorer_filter_ = nullptr;
  HWND environment_filter_ = nullptr;
  std::wstring health_filter_text_;
  std::wstring explorer_filter_text_;
  std::wstring environment_filter_text_;
  std::array<std::vector<Row>, 4> health_table_rows_{};
  std::wstring environment_detail_shown_;
  void apply_page_filter(HWND box);
  void fill_health_table(std::size_t table);
  void fit_health_columns(std::size_t table);
  // The column each Health Monitor table is sorted by (-1: as sampled) and its direction.
  struct HealthSort {
    int column = -1;
    bool ascending = true;
  };
  std::array<HealthSort, 4> health_sort_{};
  // A Health Monitor table whose columns the engineer has dragged keeps them: it is no longer fitted
  // to its text.
  std::array<bool, 4> health_columns_user_sized_{};
  std::wstring health_filter_summary() const;
  void clear_explorer_filter();
  std::vector<Row> rows_;
  // The result table built from a session's rows on the pages that keep runs or group checks
  // (gui_shared/result_table.hpp), a row per rows_ row; empty when rows_ are the session's own.
  std::vector<support_assist::gui::ResultTableRow> table_rows_;
  std::array<std::string, 4> table_headings_{};
  // A query grid's columns after the fourth, and the columns the list shows for it now.
  std::vector<std::string> table_extra_headings_;
  std::vector<std::wstring> query_columns_shown_;
  std::wstring query_columns_signature_;
  void sync_query_columns();
  // The results table's columns sized to what they hold, once per data set and table width; the
  // signature of what a table without a session was last fitted for.
  void fit_result_columns();
  std::wstring results_fitted_for_;
  bool row_detail_grown_ = false;
  std::array<std::wstring, 4> configured_columns_{};
  std::vector<int> mode_values_;
};
