#pragma once

// The command lines the Windows Console builds for a local command: a command run elevated, through
// PowerShell, and a sat line typed in a Command Prompt session. Each layer is quoted for the parser
// that reads it, so the command arrives as it was typed and every command line is plain text.

#include <cstddef>
#include <string>
#include <string_view>

namespace support_assist::gui {

// PowerShell reads the typographic single quotes as quotes too.
inline bool is_powershell_single_quote(wchar_t ch) {
  return ch == L'\'' || ch == L'‘' || ch == L'’' || ch == L'‚' || ch == L'‛';
}

// A PowerShell single-quoted string holding the value as it is.
inline std::wstring powershell_literal(std::wstring_view value) {
  std::wstring result = L"'";
  for (const wchar_t ch : value) {
    result.push_back(ch);
    if (is_powershell_single_quote(ch))
      result.push_back(ch);
  }
  result.push_back(L'\'');
  return result;
}

// One argument, quoted as CommandLineToArgvW and the C runtime split a command line: each double
// quote escaped, and the backslashes before a double quote or the closing quote doubled.
inline std::wstring command_line_quoted(std::wstring_view value) {
  std::wstring result = L"\"";
  std::size_t backslashes = 0;
  for (const wchar_t ch : value) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    result.append(ch == L'"' ? backslashes * 2U + 1U : backslashes, L'\\');
    backslashes = 0;
    result.push_back(ch);
  }
  result.append(backslashes * 2U, L'\\');
  result.push_back(L'"');
  return result;
}

// A line for CMD: outside double quotes, a caret before & | < > and ^, which CMD removes again.
// Every double quote turns CMD's quoting on or off, the escaped ones of command_line_quoted too.
inline std::wstring cmd_escaped(std::wstring_view line) {
  std::wstring result;
  bool quoted = false;
  for (const wchar_t ch : line) {
    if (ch == L'"')
      quoted = !quoted;
    else if (!quoted && (ch == L'&' || ch == L'|' || ch == L'<' || ch == L'>' || ch == L'^'))
      result.push_back(L'^');
    result.push_back(ch);
  }
  return result;
}

// A CMD line split at its first &, |, < or > outside double quotes: the arguments before it, and the
// rest, which CMD applies itself. A handle number written against the operator, the 2 of 2>&1, goes
// with the rest.
struct CmdLineParts {
  std::wstring arguments;
  std::wstring rest;
};

inline CmdLineParts split_cmd_line(std::wstring_view line) {
  bool quoted = false;
  for (std::size_t index = 0; index < line.size(); ++index) {
    const wchar_t ch = line[index];
    if (ch == L'"') {
      quoted = !quoted;
      continue;
    }
    if (quoted)
      continue;
    if (ch == L'^') {
      ++index; // the next character as written
      continue;
    }
    if (ch == L'&' || ch == L'|' || ch == L'<' || ch == L'>') {
      std::size_t cut = index;
      if ((ch == L'<' || ch == L'>') && cut > 0 && line[cut - 1] >= L'0' && line[cut - 1] <= L'9' &&
          (cut == 1 || line[cut - 2] == L' ' || line[cut - 2] == L'\t'))
        --cut;
      return {std::wstring(line.substr(0, cut)), std::wstring(line.substr(cut))};
    }
  }
  return {std::wstring(line), {}};
}

// CMD's carets outside double quotes removed, as CMD removes them before a program reads its line.
// An escaped double quote stays, and does not turn quoting on or off.
inline std::wstring cmd_carets_removed(std::wstring_view text) {
  std::wstring result;
  bool quoted = false;
  for (std::size_t index = 0; index < text.size(); ++index) {
    const wchar_t ch = text[index];
    if (ch == L'"') {
      quoted = !quoted;
    } else if (ch == L'^' && !quoted) {
      if (index + 1 < text.size())
        result.push_back(text[++index]);
      continue;
    }
    result.push_back(ch);
  }
  return result;
}

inline std::wstring trimmed_blanks(std::wstring_view text) {
  const std::size_t first = text.find_first_not_of(L" \t");
  if (first == std::wstring_view::npos)
    return {};
  return std::wstring(text.substr(first, text.find_last_not_of(L" \t") - first + 1));
}

// The PowerShell script that runs a Console command elevated and writes what it printed to a file. The
// command is a string in the script, and becomes code only when it runs, so a command PowerShell cannot
// parse is reported in the output like any other error. Command Prompt receives the command after a
// space, so PowerShell always quotes it whole and cmd /s /c reads it as typed.
inline std::wstring elevated_console_script(std::wstring_view command, bool use_cmd, std::wstring_view output_path) {
  std::wstring script = L"$c=" + powershell_literal(command) + L";$ok=$true;try{";
  if (use_cmd)
    script += L"$o=& $env:ComSpec /d /s /c (' '+$c) 2>&1 | Out-String -Width 4096;$ok=($LASTEXITCODE -eq 0);";
  else
    script += L"$o=& ([scriptblock]::Create($c)) 2>&1 | Out-String -Width 4096;$ok=$?;";
  script += L"}catch{$o=$_ | Out-String -Width 4096;$ok=$false};[IO.File]::WriteAllText(" +
            powershell_literal(output_path) +
            L",[string]$o,(New-Object Text.UTF8Encoding($false)));if($ok){exit 0}else{exit 1}";
  return script;
}

// powershell.exe's parameters for that script, the script as one quoted argument.
inline std::wstring elevated_console_parameters(std::wstring_view command, bool use_cmd,
                                                std::wstring_view output_path) {
  return L"-NoLogo -NoProfile -NonInteractive -Command " +
         command_line_quoted(elevated_console_script(command, use_cmd, output_path));
}

// A sat line in a PowerShell session. PowerShell waits for a GUI-subsystem program and hands it the
// session's output only down a pipeline, hence Write-Output, and the call operator runs a quoted path.
inline std::wstring powershell_sat_line(std::wstring_view self, std::wstring_view arguments) {
  const std::wstring passed = trimmed_blanks(arguments);
  return L"& " + powershell_literal(self) + L" " + (passed.empty() ? std::wstring(L"--help") : passed) +
         L" | Write-Output";
}

// A sat line in a Command Prompt session. CMD hands a GUI-subsystem program no output handle and does
// not wait for it, so the line runs through PowerShell. After --% PowerShell passes the arguments to SAT
// as they were typed, so SAT reads them as it would from CMD, and the exit code comes back to CMD. What
// follows the arguments, such as a redirection or &&, stays with CMD.
inline std::wstring cmd_sat_line(std::wstring_view self, std::wstring_view arguments) {
  const CmdLineParts parts = split_cmd_line(arguments);
  std::wstring passed = trimmed_blanks(cmd_carets_removed(parts.arguments));
  if (passed.empty())
    passed = L"--help";
  const std::wstring script =
      L"& " + powershell_literal(self) + L" --% " + passed + L" | Write-Output; exit $LASTEXITCODE";
  std::wstring line = L"powershell -NoLogo -NoProfile -NonInteractive -Command " + cmd_escaped(command_line_quoted(script));
  if (!parts.rest.empty())
    line += L" " + parts.rest;
  return line;
}

} // namespace support_assist::gui
