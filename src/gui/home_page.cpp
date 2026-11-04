// Home as a status board in both roles, and the Tools categories' tiles, on Windows. The tiles and
// links come from gui_shared/home_board.hpp and are drawn by board_panel.cpp; this file gathers
// what they show and runs what they open. The saved review, the case's holdings, the products
// found, this machine, Veeam's services and the pending restart check are read on workers.

#include "app_window.hpp"

#include "board_panel.hpp"
#include "support_assist/recent_cases.hpp"
#include "home_board.hpp"
#include "quick_tool_reports.hpp"
#include "report_panel.hpp"
#include "scenario_form.hpp"

#include "support_assist/case_review_store.hpp"
#include "support_assist/guided_diagnostics.hpp"
#include "support_assist/pending_restart.hpp"
#include "support_assist/product_discovery.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_info.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/veeam_watch.hpp"

#include <dwmapi.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <thread>

// Case Manager's badge colours, {fill, text}, defined in app_window.cpp.
std::pair<COLORREF, COLORREF> case_status_badge_colours(support_assist::CaseStatusColor color);

namespace {

namespace gui = support_assist::gui;

constexpr UINT kHomeReviewMessage = WM_APP + 61;
constexpr UINT kHomeRestartMessage = WM_APP + 62;
constexpr UINT kHomeProductsMessage = WM_APP + 63;
constexpr UINT kHomeHoldingsMessage = WM_APP + 64;
constexpr UINT kHomeMachineMessage = WM_APP + 65;
constexpr UINT kHomeServicesMessage = WM_APP + 66;

// How often Home reads the case's holdings and Veeam's services again while it shows.
constexpr auto kHoldingsInterval = std::chrono::seconds(10);
constexpr auto kServicesInterval = std::chrono::seconds(30);

std::wstring widen(std::string_view text) {
  return support_assist::wide_from_utf8_lossy(text);
}

struct ReviewSummaryResult {
  std::filesystem::path root;
  std::optional<std::filesystem::file_time_type> modified;
  gui::CaseReviewSummary summary;
};

struct HoldingsResult {
  std::filesystem::path root;
  gui::CaseHoldings holdings;
};

struct ProductsResult {
  std::vector<gui::FoundProduct> products;
  std::vector<std::string> guided;
};

struct MachineResult {
  std::string name;
  std::string os;
  bool elevated = false;
  int utc_offset_minutes = 0;
};

struct ServicesResult {
  std::size_t running = 0;
  std::vector<std::string> not_running;
};

// The saved review model of a case, where this build and older ones keep it.
std::filesystem::path review_model_path(const support_assist::CaseWorkspace& workspace) {
  std::error_code error;
  const auto parsed = workspace.parsed / L"case-review-model.sat";
  if (std::filesystem::is_regular_file(parsed, error))
    return parsed;
  const auto legacy = workspace.root / L"case-review-model.sat";
  return std::filesystem::is_regular_file(legacy, error) ? legacy : std::filesystem::path();
}

// Posts a worker's result to the window; when the window has gone, the result is freed here.
template <typename Result> void post_result(HWND window, UINT message, std::unique_ptr<Result> result) {
  if (PostMessageW(window, message, 0, reinterpret_cast<LPARAM>(result.get())) != FALSE)
    result.release();
}

// The board's tiles and links as the panel draws them.
BoardContent board_content(const gui::HomeBoard& board) {
  BoardContent content;
  for (const gui::BoardSection& section : board.sections)
    content.groups.push_back(
        {widen(section.caption), section.columns, section.compact, section.tiles, section.compact_when_short});
  for (const gui::BoardLink& link : board.links)
    content.chips.push_back({widen(link.label), widen(link.key), widen(link.note), link.primary, link.right,
                             link.new_row, widen(link.row_caption)});
  content.pill_colours = [](const std::string& status) {
    return case_status_badge_colours(support_assist::case_status_color(status));
  };
  return content;
}

} // namespace

void AppWindow::create_board_panels() {
  const BoardPanelStyle style{small_font_, ui_font_, heading_font_, ui_scale_percent_};
  home_board_ = create_board_panel(window_, instance_, style);
  tools_board_ = create_board_panel(window_, instance_, style);
  activity_board_ = create_board_panel(window_, instance_, style);
  operation_guide_ = create_report_panel(
      window_, instance_, ReportPanelStyle{card_font_, heading_font_, ui_font_, small_font_, ui_scale_percent_});
  ShowWindow(operation_guide_, SW_HIDE);
}

// Recent Activity's tiles: the entries and the outcomes, the one in use pressed in.
void AppWindow::rebuild_activity_board(const gui::ActivityCounts& counts) {
  if (activity_board_ == nullptr)
    return;
  gui::HomeBoard board;
  board.sections.push_back(gui::activity_board(counts, activity_filter_));
  set_board_panel_content(activity_board_, board_content(board));
}

// A tile shows only its outcome; a second click on the tile in use shows every entry again.
void AppWindow::activity_board_activated(int index) {
  const gui::ActivityFilter chosen = gui::activity_filter_at(index);
  activity_filter_ = chosen == activity_filter_ ? gui::ActivityFilter::all : chosen;
  render_activity();
}

// ---------------------------------------------------------------------------------- Home workers

void AppWindow::refresh_home_review_summary() {
  const auto* workspace = active_case();
  if (workspace == nullptr || home_review_loading_)
    return;
  const auto model = review_model_path(*workspace);
  std::optional<std::filesystem::file_time_type> modified;
  if (!model.empty()) {
    std::error_code error;
    const auto time = std::filesystem::last_write_time(model, error);
    if (!error)
      modified = time;
  }
  if (home_review_root_ == workspace->root && home_review_mtime_ == modified)
    return;
  if (model.empty()) {
    home_review_root_ = workspace->root;
    home_review_mtime_ = modified;
    home_review_ = gui::CaseReviewSummary{};
    return;
  }
  home_review_loading_ = true;
  const support_assist::CaseWorkspace copy = *workspace;
  const HWND window = window_;
  std::thread([copy, modified, window]() {
    auto result = std::make_unique<ReviewSummaryResult>();
    result->root = copy.root;
    result->modified = modified;
    if (auto loaded = support_assist::load_case_review_model(copy); loaded.ok())
      result->summary = gui::summarize_case_review(
          loaded.value(), modified ? gui::board_detail::unix_millis_of(*modified) : 0);
    post_result(window, kHomeReviewMessage, std::move(result));
  }).detach();
}

void AppWindow::refresh_home_holdings() {
  const auto* workspace = active_case();
  if (workspace == nullptr || home_holdings_loading_)
    return;
  const auto now = std::chrono::steady_clock::now();
  if (home_holdings_root_ == workspace->root && now - home_holdings_at_ < kHoldingsInterval)
    return;
  home_holdings_loading_ = true;
  home_holdings_at_ = now;
  const support_assist::CaseWorkspace copy = *workspace;
  const HWND window = window_;
  std::thread([copy, window]() {
    auto result = std::make_unique<HoldingsResult>();
    result->root = copy.root;
    result->holdings = gui::read_case_holdings(copy);
    post_result(window, kHomeHoldingsMessage, std::move(result));
  }).detach();
}

void AppWindow::refresh_home_restart() {
  if (home_restart_ || home_restart_loading_)
    return;
  home_restart_loading_ = true;
  const HWND window = window_;
  std::thread([window]() {
    post_result(window, kHomeRestartMessage,
                std::make_unique<support_assist::PendingRestartResult>(support_assist::check_pending_restart()));
  }).detach();
}

void AppWindow::refresh_home_products() {
  if (home_products_read_ || home_products_loading_)
    return;
  home_products_loading_ = true;
  const HWND window = window_;
  std::thread([window]() {
    auto result = std::make_unique<ProductsResult>();
    const auto context = support_assist::native_product_discovery_context();
    for (const auto& product : support_assist::detect_products(context)) {
      if (product.signature_detected)
        result->products.push_back({product.definition.display_name, product.definition.role});
    }
    // The scenarios Guided Diagnostics offers on this machine.
    for (const auto& scenario : support_assist::gui::guided_scenarios_here())
      result->guided.push_back(scenario.title);
    post_result(window, kHomeProductsMessage, std::move(result));
  }).detach();
}

void AppWindow::refresh_home_machine() {
  if (home_machine_read_ || home_machine_loading_)
    return;
  home_machine_loading_ = true;
  const HWND window = window_;
  std::thread([window]() {
    auto result = std::make_unique<MachineResult>();
    const auto host = support_assist::make_snapshot_metadata(support_assist::SnapshotKind::combined, "home");
    result->name = host.machine_name;
    result->os = "Windows " + host.os_version + (host.architecture.empty() ? "" : " " + host.architecture);
    result->elevated = host.elevated;
    result->utc_offset_minutes = support_assist::read_time_zone().utc_offset_minutes;
    post_result(window, kHomeMachineMessage, std::move(result));
  }).detach();
}

void AppWindow::refresh_home_services() {
  if (home_services_loading_)
    return;
  const auto now = std::chrono::steady_clock::now();
  if (home_services_read_ && now - home_services_at_ < kServicesInterval)
    return;
  home_services_loading_ = true;
  home_services_at_ = now;
  const HWND window = window_;
  std::thread([window]() {
    auto result = std::make_unique<ServicesResult>();
    for (const auto& item : support_assist::take_watch_snapshot("veeam").items) {
      if (item.kind != support_assist::WatchKind::service)
        continue;
      if (item.state == "running")
        ++result->running;
      else
        result->not_running.push_back(item.name);
    }
    post_result(window, kHomeServicesMessage, std::move(result));
  }).detach();
}

bool AppWindow::handle_board_message(UINT message, WPARAM wparam, LPARAM lparam) {
  const auto refresh_home = [this]() {
    if (page_ == Page::home)
      rebuild_home_board();
  };
  switch (message) {
  case kBoardActivateMessage: {
    const auto panel = reinterpret_cast<HWND>(lparam);
    if (panel == home_board_)
      home_board_activated(static_cast<int>(wparam));
    else if (panel == tools_board_)
      tools_board_activated(static_cast<int>(wparam));
    else if (panel == activity_board_)
      activity_board_activated(static_cast<int>(wparam));
    return true;
  }
  case kHomeReviewMessage: {
    std::unique_ptr<ReviewSummaryResult> result(reinterpret_cast<ReviewSummaryResult*>(lparam));
    home_review_loading_ = false;
    home_review_root_ = result->root;
    home_review_mtime_ = result->modified;
    home_review_ = result->summary;
    refresh_home();
    return true;
  }
  case kHomeHoldingsMessage: {
    std::unique_ptr<HoldingsResult> result(reinterpret_cast<HoldingsResult*>(lparam));
    home_holdings_loading_ = false;
    home_holdings_root_ = result->root;
    home_holdings_ = std::move(result->holdings);
    refresh_home();
    return true;
  }
  case kHomeRestartMessage: {
    std::unique_ptr<support_assist::PendingRestartResult> result(
        reinterpret_cast<support_assist::PendingRestartResult*>(lparam));
    home_restart_loading_ = false;
    home_restart_ = std::move(*result);
    refresh_home();
    return true;
  }
  case kHomeProductsMessage: {
    std::unique_ptr<ProductsResult> result(reinterpret_cast<ProductsResult*>(lparam));
    home_products_loading_ = false;
    home_products_read_ = true;
    home_products_ = std::move(result->products);
    home_guided_ = std::move(result->guided);
    refresh_home();
    return true;
  }
  case kHomeMachineMessage: {
    std::unique_ptr<MachineResult> result(reinterpret_cast<MachineResult*>(lparam));
    home_machine_loading_ = false;
    home_machine_read_ = true;
    home_machine_name_ = std::move(result->name);
    home_machine_os_ = std::move(result->os);
    home_machine_elevated_ = result->elevated;
    home_machine_utc_offset_ = result->utc_offset_minutes;
    refresh_home();
    return true;
  }
  case kHomeServicesMessage: {
    std::unique_ptr<ServicesResult> result(reinterpret_cast<ServicesResult*>(lparam));
    home_services_loading_ = false;
    home_services_read_ = true;
    home_services_running_ = result->running;
    home_services_stopped_ = std::move(result->not_running);
    refresh_home();
    return true;
  }
  default:
    return false;
  }
}

// ---------------------------------------------------------------------------------- Home

void AppWindow::rebuild_home_board() {
  if (home_board_ == nullptr)
    return;
  gui::HomeBoard board;
  if (!execution_host_enabled()) {
    gui::EngineerBoardInput input;
    if (const auto* workspace = active_case()) {
      input.has_case = true;
      input.case_id = workspace->case_id;
      input.case_title = workspace->title;
      input.case_status = support_assist::case_status_or_default(*workspace);
      input.next_steps = workspace->next_steps;
      refresh_home_review_summary();
      refresh_home_holdings();
      if (home_review_root_ == workspace->root)
        input.review = home_review_;
      if (home_holdings_root_ == workspace->root)
        input.holdings = home_holdings_;
    }
    for (const auto& job : collect_jobs()) {
      if (job.state != gui::JobState::running && job.state != gui::JobState::cancelling &&
          job.state != gui::JobState::finalizing)
        continue;
      if (input.running_jobs++ == 0U)
        input.running_job = job.session + (job.progress.empty() ? std::string() : ", " + job.progress);
    }
    input.cases = cases_.size();
    for (const auto& option : support_assist::case_status_entries()) {
      gui::CaseStatusCount count{option.name, 0};
      for (const auto& workspace : cases_) {
        if (support_assist::ascii_lower(support_assist::case_status_or_default(workspace)) ==
            support_assist::ascii_lower(option.name))
          ++count.count;
      }
      input.statuses.push_back(std::move(count));
    }
    // The cases opened most recently, then the rest newest first.
    std::vector<support_assist::CaseWorkspace> by_created = cases_;
    std::stable_sort(by_created.begin(), by_created.end(), [](const auto& left, const auto& right) {
      return left.created_utc > right.created_utc;
    });
    const auto newest = support_assist::recent_case_order(
        by_created, support_assist::read_recent_cases(state_data_directory() / L"recent-cases.txt"));
    const auto* active = active_case();
    for (std::size_t index = 0; index < newest.size() && index < gui::kRecentCases; ++index) {
      const auto& workspace = *newest[index];
      input.recent.push_back({support_assist::path_to_utf8(workspace.root), workspace.case_id, workspace.title,
                              support_assist::case_status_or_default(workspace),
                              active != nullptr && active->root == workspace.root});
    }
    board = gui::engineer_home(input);
  } else {
    gui::LabBoardInput input;
    {
      std::scoped_lock lock(health_mutex_);
      if (health_snapshot_available_) {
        input.health = health_snapshot_;
        input.sampled = true;
      }
    }
    if (input.sampled)
      support_assist::evaluate_system_health(input.health);
    refresh_home_machine();
    refresh_home_products();
    refresh_home_services();
    refresh_home_restart();
    input.machine_read = home_machine_read_;
    input.machine_name = home_machine_name_;
#ifdef SUPPORT_ASSIST_UI_SELFCHECK
    input.machine_name = support_assist::utf8_from_wide(selfcheck_figure_text(widen(home_machine_name_)));
#endif
    input.os_text = home_machine_os_;
    input.windows = true;
    input.elevated = home_machine_elevated_;
    input.utc_offset_minutes = home_machine_utc_offset_;
    input.now_unix_millis = support_assist::unix_millis_now();
    input.products_read = home_products_read_;
    input.products = home_products_;
    input.guided = home_guided_;
    input.services_read = home_services_read_;
    input.services_running = home_services_running_;
    input.services_stopped = home_services_stopped_;
    input.collections = collections_this_session_;
    input.last_collection = gui::board_detail::last_at(last_collection_unix_millis_);
    if (last_execution_artifact_) {
      input.has_output = true;
      input.output_completed_utc = last_execution_artifact_->completed_utc;
      input.output_text = last_execution_artifact_->tool_name;
    }
    if (home_restart_) {
      input.restart_read = true;
      input.restart = *home_restart_;
      input.boot_unix_millis = home_restart_->boot_unix_millis;
    }
    board = gui::lab_home(input);
  }
  home_tiles_ = gui::board_tiles(board);
  home_links_ = board.links;
  set_board_panel_content(home_board_, board_content(board));
}

void AppWindow::home_board_activated(int index) {
  if (index < 0)
    return;
  const auto tile_count = static_cast<int>(home_tiles_.size());
  if (index < tile_count) {
    const auto& tile = home_tiles_[static_cast<std::size_t>(index)];
    run_board_action(tile.action, tile.page, tile.tool, tile.target);
    return;
  }
  const int link = index - tile_count;
  if (link < static_cast<int>(home_links_.size())) {
    const auto& chosen = home_links_[static_cast<std::size_t>(link)];
    run_board_action(chosen.action, chosen.page, chosen.tool, std::string());
  }
}

void AppWindow::run_board_action(gui::BoardAction action, gui::WorkspacePage page, gui::ShortcutCommand tool,
                                 const std::string& target) {
  switch (action) {
  case gui::BoardAction::open_page:
    if (page == gui::WorkspacePage::note_review)
      open_note_review();
    else if (const auto destination = page_of_workspace(page))
      select_page(*destination);
    return;
  case gui::BoardAction::open_dashboard: select_page(Page::case_dashboard); return;
  case gui::BoardAction::open_saved_review: resume_last_case_review(); return;
  case gui::BoardAction::open_note_review: open_note_review(); return;
  case gui::BoardAction::open_case: {
    const auto found = std::find_if(cases_.begin(), cases_.end(), [&](const auto& workspace) {
      return support_assist::path_to_utf8(workspace.root) == target;
    });
    if (found == cases_.end())
      return;
    const support_assist::CaseWorkspace chosen = *found;
    case_manager_switch_to(chosen);
    select_page(Page::case_dashboard);
    return;
  }
  case gui::BoardAction::new_case:
    select_page(Page::case_manager);
    if (page_ == Page::case_manager)
      case_manager_show_form(true);
    return;
  case gui::BoardAction::open_running_jobs: open_jobs_window(); return;
  case gui::BoardAction::collect_logs: {
    // The Universal Veeam Log Collection card, as the Log Collection page opens it.
    for (const Card& card : tool_category_cards(gui::ToolCategory::log_collection)) {
      if (!card.section_header && card.destination == Page::log_collection && card.mode == 0) {
        create_tool_session(card);
        return;
      }
    }
    select_page(Page::log_collection);
    return;
  }
  case gui::BoardAction::prepare_output: prepare_last_execution_artifact(); return;
  case gui::BoardAction::delete_output: delete_last_execution_artifact(); return;
  case gui::BoardAction::restart_details: open_pending_restart_report(); return;
  case gui::BoardAction::products_details: {
    auto products = support_assist::installed_veeam_products();
    open_report_window(L"Veeam products",
                       gui::veeam_products_report(products.ok() ? products.value()
                                                                : std::vector<support_assist::InstalledProduct>{}));
    return;
  }
  case gui::BoardAction::services_details:
    open_report_window(L"Veeam services", gui::veeam_services_report(support_assist::take_watch_snapshot("veeam")));
    return;
  case gui::BoardAction::quick_tool: open_quick_tool(tool); return;
  case gui::BoardAction::switch_role: toggle_workspace_role(); return;
  case gui::BoardAction::none: return;
  }
}

// The pending restart check as a report, in a window of its own.
void AppWindow::open_pending_restart_report() {
  if (home_restart_)
    open_report_window(L"Pending restart", gui::pending_restart_report(*home_restart_));
}

void AppWindow::open_report_window(const wchar_t* title, const gui::QuickToolReport& report) {
  static bool registered = false;
  if (!registered) {
    WNDCLASSW description{};
    description.style = CS_HREDRAW | CS_VREDRAW;
    description.lpfnWndProc = [](HWND window, UINT message, WPARAM wparam, LPARAM lparam) -> LRESULT {
      switch (message) {
      case WM_SIZE: {
        HWND panel = GetWindow(window, GW_CHILD);
        if (panel != nullptr)
          SetWindowPos(panel, nullptr, 12, 12, std::max(0, static_cast<int>(LOWORD(lparam)) - 24),
                       std::max(0, static_cast<int>(HIWORD(lparam)) - 24),
                       SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOCOPYBITS);
        return 0;
      }
      case WM_ERASEBKGND: {
        RECT client{};
        GetClientRect(window, &client);
        FillRect(reinterpret_cast<HDC>(wparam), &client, themed_brush(RGB(18, 30, 28)));
        return 1;
      }
      case WM_COMMAND:
        // Esc, through the dialog keys the message loop gives this window.
        if (LOWORD(wparam) == IDCANCEL) {
          DestroyWindow(window);
          return 0;
        }
        break;
      default:
        break;
      }
      return DefWindowProcW(window, message, wparam, lparam);
    };
    description.hInstance = instance_;
    description.lpszClassName = L"SupportAssistPendingRestartWindow";
    description.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    RegisterClassW(&description);
    registered = true;
  }
  HWND window = CreateWindowExW(WS_EX_CONTROLPARENT, L"SupportAssistPendingRestartWindow", title,
                                WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT, sx(720), sx(560),
                                window_, nullptr, instance_, nullptr);
  if (window == nullptr)
    return;
  const BOOL dark = themed_title_bar_dark();
  DwmSetWindowAttribute(window, 20, &dark, sizeof(dark));
  HWND panel = create_report_panel(window, instance_,
                                   ReportPanelStyle{card_font_, heading_font_, ui_font_, small_font_, ui_scale_percent_});
  set_report_panel_report(panel, report);
  RECT client{};
  GetClientRect(window, &client);
  MoveWindow(panel, 12, 12, client.right - 24, client.bottom - 24, TRUE);
  ShowWindow(window, SW_SHOWNORMAL);
  SetFocus(panel);
}

// ---------------------------------------------------------------------------------- Tools

// The last tool output came or went: the Last Tool Output tile and section, and Home's Last output
// and its Prepare and Delete links, follow at once.
void AppWindow::last_output_changed() {
  if (menu_view_ && (page_ == Page::tools || is_general_tools_child(page_))) {
    rebuild_tools_board();
    rebuild_cards();
    RECT client{};
    GetClientRect(window_, &client);
    layout(client.right, client.bottom);
  }
  if (menu_view_ && page_ == Page::home)
    rebuild_home_board();
}

// The category tiles above the Tools page and every category page, the page's own tile pressed in.
void AppWindow::rebuild_tools_board() {
  if (tools_board_ == nullptr)
    return;
  std::vector<std::pair<gui::ToolCategory, std::string>> cards;
  for (const Card& card : all_tool_cards()) {
    // The note that no guided diagnostic applies opens the page; it is not a tool.
    if (!card.opens_page)
      cards.emplace_back(tool_card_category(card), support_assist::utf8_from_wide(card.title));
  }
  tools_category_tiles_ = gui::category_tiles(cards, listed_tool_categories());
  gui::HomeBoard board;
  board.sections.push_back(gui::tools_board(tools_category_tiles_, category_of_page(page_)));
  set_board_panel_content(tools_board_, board_content(board));
}

void AppWindow::tools_board_activated(int index) {
  if (index < 0 || index >= static_cast<int>(tools_category_tiles_.size()))
    return;
  const auto category = tools_category_tiles_[static_cast<std::size_t>(index)].category;
  if (category == gui::ToolCategory::last_output) {
    // A section of the Tools page: the page scrolled to its end, where Prepare and Delete are.
    select_page(Page::tools);
    scroll_general_tools_catalog(card_menu_content_height_);
    return;
  }
  select_page(page_of_category(category));
}
