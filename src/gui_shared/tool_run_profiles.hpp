#pragma once

// The guided-run profiles both editions render are in core (support_assist/tool_run_profiles.hpp), so
// the command line runs the same mapping; these names keep them in the gui namespace.

#include "support_assist/tool_run_profiles.hpp"

namespace support_assist::gui {
using support_assist::build_tool_run_arguments;
using support_assist::command_line_text;
using support_assist::find_tool_run_profile;
using support_assist::speed_test_leftover_question;
using support_assist::storage_test_folder;
using support_assist::storage_test_options;
using support_assist::tool_run_cli_text;
using support_assist::tool_run_is_storage_test;
using support_assist::tool_run_profiles;
using support_assist::tool_run_sat_command;
using support_assist::ToolRunField;
using support_assist::ToolRunProfile;
} // namespace support_assist::gui
