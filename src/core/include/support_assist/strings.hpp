#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>
namespace support_assist {
// UTF-8 text for a path, safe on every platform.
//
// std::filesystem::path::string() on MSVC converts the native wide path through the ANSI code page
// and THROWS std::system_error("No mapping for the Unicode character exists in the target multi-byte
// code page") the moment a name contains a character ANSI cannot represent. Reading logs from a
// Linux repository or SOBR extent hits this routinely. Left uncaught, it reaches the engineer as
// "Unhandled operation error" and the review is lost. Use this wherever a path becomes TEXT -
// display, logging, keys, comparisons. Do NOT use it to feed narrow OS file APIs; pass the path
// itself and let the platform use its native wide call.
std::string path_to_utf8(const std::filesystem::path& path);
// The same with forward slashes. path::generic_string() goes through the ANSI code page on MSVC
// and throws exactly as path::string() does.
std::string generic_path_to_utf8(const std::filesystem::path& path);
// The reverse: a path from UTF-8 text, such as a command-line argument or a saved setting. A path
// built from a narrow string reads the ANSI code page on Windows, which loses any character outside
// it; this goes through UTF-16 there. Text that is not valid UTF-8 is taken as the platform reads it.
std::filesystem::path path_from_utf8(std::string_view text);
std::string trim(std::string_view text);
std::string ascii_lower(std::string_view text);
std::string ascii_upper(std::string_view text);
std::vector<std::string> split(std::string_view text, char delimiter);
std::string hex_encode(const void* data,
                       std::size_t size,
                       std::size_t max_bytes = static_cast<std::size_t>(-1));
// Renders tab-separated collected records as fixed-width columns.
//
// SAT's collectors emit one record per line with tab-separated fields. Presented verbatim the
// columns never line up, and output like a route table or a service inventory is read by scanning
// a column rather than a line. Column widths are measured across every supplied line and capped at
// `maximum_column_width` so one pathological value cannot push later columns off the pane;
// over-long cells keep their full text and run past their column rather than being truncated,
// because silently shortening an address or path in support evidence is worse than a ragged row.
// The final field is never padded, so a row copied into a note carries no trailing spaces.
//
// Lines containing no tab are returned unchanged, and a set with no tabs anywhere is passed
// through untouched.
std::vector<std::string> align_tab_columns(const std::vector<std::string>& lines,
                                           std::size_t maximum_column_width = 46U,
                                           std::size_t column_gap = 2U);

// One collected section parsed into real columns, so it can be presented as a grid rather than as
// pre-aligned text. Text alignment can only ever approximate a table: it cannot be resized, sorted
// or selected by column, and it breaks the moment a value is wider than expected.
struct ParsedTable {
  std::vector<std::string> headers;
  std::vector<std::vector<std::string>> rows;
  // Row indices that were blank lines in the source. PowerShell Format-List emits one record per
  // block separated by blank lines, and losing those boundaries runs one adapter's properties into
  // the next.
  std::vector<std::size_t> group_breaks;
  bool tabular = false;
};

// Recognises the three shapes SAT's collectors actually produce:
//
//  * PowerShell Format-Table - a header line followed by a "---- ----- ---" rule. The rule encodes
//    exact column boundaries, so it is used to split every following row. This is the only reliable
//    way to split fixed-width output whose values contain spaces.
//  * Tab-separated records, which the live-dashboard collectors emit.
//  * PowerShell Format-List - "Name : Value" pairs in blank-line-separated blocks, rendered as two
//    columns with the record boundaries preserved.
//
// Anything else returns tabular == false and should stay as text: systeminfo and route print are
// prose with embedded layout, and forcing them into columns would destroy them.
ParsedTable parse_collected_table(const std::vector<std::string>& lines);

// Turns PowerShell's CLIXML error stream back into the message a person can read.
//
// When PowerShell's stderr is redirected to a pipe rather than a console it serializes error
// records as CLIXML - "#< CLIXML" followed by an <Objs> document whose <S> elements carry the text
// with CRLF written as _x000D__x000A_. Captured that way and left undecoded, a failure reaches the
// engineer as raw XML instead of the failure reason.
//
// Text that is not CLIXML is returned unchanged, so this is safe to apply to any captured stderr.
std::string decode_powershell_clixml(std::string_view text);

std::string json_escape(std::string_view text);
std::string html_escape(std::string_view text);
std::string csv_escape(std::string_view text, bool neutralize_formula = true);
#ifdef _WIN32
std::string utf8_from_wide(std::wstring_view text);
std::wstring wide_from_utf8(std::string_view text);

// Lossy conversion for COLLECTED CONTENT that is displayed rather than acted upon.
//
// wide_from_utf8() uses MB_ERR_INVALID_CHARS and returns an empty string if a single byte is not
// valid UTF-8. That strictness is correct for paths and identifiers, where a mangled value must
// never be acted on silently. It is wrong for a collected artifact: environment.log embeds a
// Registry export that `reg export` writes in UTF-16, so a single embedded BOM can discard the
// entire document and leave the Environment Review import empty.
//
// This substitutes replacement characters for undecodable bytes so the readable remainder still
// reaches the engineer. Never use it for a path, a command or anything that will be executed.
std::wstring wide_from_utf8_lossy(std::string_view text);
#endif
} // namespace support_assist
