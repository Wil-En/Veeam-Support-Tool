#pragma once

// The quick tools' results as a headline and sections of labelled rows, built once for both
// editions to draw, and the text for Copy and Add to #note.

#include "case_evidence.hpp"

#include "support_assist/disk_speed_test.hpp"
#include "support_assist/file_transfer.hpp"
#include "support_assist/object_storage.hpp"
#include "support_assist/file_lock.hpp"
#include "support_assist/name_check.hpp"
#include "support_assist/pending_restart.hpp"
#include "support_assist/port_check.hpp"
#include "support_assist/quick_scan.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/time_check.hpp"
#include "support_assist/veeam_watch.hpp"
#include "support_assist/volume_check.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace support_assist::gui {

enum class ReportTone { normal, good, attention, problem, quiet };

struct ReportRow {
  std::string label;
  std::string value;
  ReportTone tone = ReportTone::normal;
  double bar = -1.0; // a bar under the value, from 0 to 1 of the row's width; below 0 draws none
};

struct ReportSection {
  std::string title;
  std::vector<ReportRow> rows;
  std::string note;
};

struct QuickToolReport {
  std::string tool;
  std::string subject;
  std::string headline;
  ReportTone headline_tone = ReportTone::normal;
  std::vector<std::string> notes;
  std::vector<ReportSection> sections;
  std::int64_t checked_unix_millis = 0;
};

namespace report_detail {

inline std::string joined(const std::vector<std::string>& values, const char* separator = ", ") {
  std::string text;
  for (const std::string& value : values)
    text += (text.empty() ? "" : separator) + value;
  return text;
}

inline std::string utc_text(std::int64_t unix_millis) {
  return unix_millis > 0 ? time_check_detail::format_unix_millis(unix_millis, 0) + " UTC" : std::string();
}

inline std::string seconds_text(double milliseconds) {
  char text[48] = {};
  std::snprintf(text, sizeof(text), "%.3f s", std::fabs(milliseconds) / 1000.0);
  return text;
}

inline ReportTone tone_of(PortVerdict verdict) {
  switch (verdict) {
  case PortVerdict::open: return ReportTone::good;
  case PortVerdict::open_some_profiles:
  case PortVerdict::local_only: return ReportTone::attention;
  case PortVerdict::blocked_here:
  case PortVerdict::closed_and_blocked: return ReportTone::problem;
  case PortVerdict::closed:
  case PortVerdict::listening:
  case PortVerdict::not_listening: break;
  }
  return ReportTone::normal;
}

inline ReportTone tone_of(FirewallDecision decision) {
  switch (decision) {
  case FirewallDecision::allowed:
  case FirewallDecision::firewall_off: return ReportTone::good;
  case FirewallDecision::blocked: return ReportTone::problem;
  case FirewallDecision::not_evaluated: break;
  }
  return ReportTone::quiet;
}

inline std::string dns_answers_text(const std::vector<DnsAnswer>& answers) {
  if (answers.empty())
    return "not asked";
  std::string text;
  for (const DnsAnswer& answer : answers) {
    std::string part = to_string(answer.type) + " ";
    if (!answer.answered) {
      part += answer.error;
    } else if (answer.rcode != 0) {
      part += dns_detail::rcode_text(answer.rcode);
    } else {
      std::vector<std::string> values;
      for (const DnsRecord& record : answer.records) {
        if (record.type == answer.type)
          values.push_back(record.value);
      }
      part += values.empty() ? "none" : joined(values);
    }
    char elapsed[32] = {};
    std::snprintf(elapsed, sizeof(elapsed), " (%lld ms)", static_cast<long long>(std::llround(answer.elapsed_ms)));
    text += (text.empty() ? "" : "; ") + part + (answer.answered ? elapsed : "");
  }
  return text;
}

} // namespace report_detail

// Copy and #note text: the tool, the subject, the headline, the notes, then each section.
inline std::string report_text(const QuickToolReport& report) {
  std::ostringstream text;
  text << report.tool << (report.subject.empty() ? "" : ": " + report.subject) << "\n";
  if (report.checked_unix_millis > 0)
    text << "Checked " << report_detail::utc_text(report.checked_unix_millis) << "\n";
  text << report.headline << "\n";
  for (const std::string& note : report.notes)
    text << note << "\n";
  for (const ReportSection& section : report.sections) {
    text << "\n" << section.title << "\n";
    for (const ReportRow& row : section.rows)
      text << "  " << (row.label.empty() ? "" : row.label + ": ") << row.value << "\n";
    if (!section.note.empty())
      text << "  " << section.note << "\n";
  }
  return text.str();
}

inline QuickToolReport name_check_report(const NameCheckResult& result) {
  using report_detail::joined;
  QuickToolReport report;
  report.tool = "Name Check";
  report.subject = result.name;
  report.notes = result.notes;
  if (result.is_address) {
    const ReverseLookup* lookup = result.reverse.empty() ? nullptr : &result.reverse.front();
    report.headline = lookup != nullptr && !lookup->name.empty() ? result.name + " is " + lookup->name
                                                                  : result.name + " has no reverse record";
    report.headline_tone = lookup != nullptr && !lookup->name.empty() ? ReportTone::good : ReportTone::attention;
  } else if (result.addresses.empty()) {
    report.headline = result.name + " does not resolve here";
    report.headline_tone = ReportTone::problem;
  } else {
    report.headline = result.name + " resolves to " + joined(result.addresses);
    report.headline_tone = result.notes.empty() ? ReportTone::good : ReportTone::attention;
  }

  if (!result.is_address) {
    ReportSection summary{"Answer", {}, {}};
    if (!result.completed_name.empty())
      summary.rows.push_back({"Completed as", result.completed_name, ReportTone::normal});
    summary.rows.push_back({"Resolves to", result.addresses.empty() ? "nothing: " + result.resolver_error
                                                                    : joined(result.addresses),
                            result.addresses.empty() ? ReportTone::problem : ReportTone::normal});
    if (!result.source.empty())
      summary.rows.push_back({"Came from", result.source, ReportTone::normal});
    if (!result.aliases.empty())
      summary.rows.push_back({"Aliases", joined(result.aliases), ReportTone::normal});
    report.sections.push_back(std::move(summary));

    ReportSection servers{"DNS servers", {}, result.settings.note};
    for (const DnsServer& server : result.settings.servers) {
      std::vector<DnsAnswer> answers;
      for (const DnsAnswer& answer : result.per_server) {
        if (answer.server == server.address)
          answers.push_back(answer);
      }
      bool unanswered = !answers.empty();
      for (const DnsAnswer& answer : answers)
        unanswered = unanswered && !answer.answered;
      servers.rows.push_back({server.address + (server.interface_name.empty() ? "" : " (" + server.interface_name + ")"),
                              report_detail::dns_answers_text(answers),
                              unanswered ? ReportTone::attention : ReportTone::normal});
    }
    if (result.settings.servers.empty())
      servers.rows.push_back({"", "No DNS server is configured.", ReportTone::attention});
    report.sections.push_back(std::move(servers));
  }

  if (!result.reverse.empty()) {
    ReportSection reverse{"Reverse lookups", {}, {}};
    for (const ReverseLookup& lookup : result.reverse) {
      if (lookup.name.empty())
        reverse.rows.push_back({lookup.address, lookup.error, ReportTone::quiet});
      else
        reverse.rows.push_back({lookup.address,
                                lookup.name + (lookup.agrees ? ", which resolves back to it" : ", which resolves elsewhere"),
                                lookup.agrees ? ReportTone::good : ReportTone::attention});
    }
    report.sections.push_back(std::move(reverse));
  }

  ReportSection resolver{"This machine's resolver", {}, {}};
  resolver.rows.push_back({"Lookup order", result.settings.lookup_order, ReportTone::normal});
  if (!result.settings.search_suffixes.empty())
    resolver.rows.push_back({"Search suffixes", joined(result.settings.search_suffixes), ReportTone::normal});
  std::string hosts = result.settings.hosts_file;
  if (!result.is_address) {
    if (result.hosts_entries.empty()) {
      hosts += ": no entry for this name";
    } else {
      for (const HostsEntry& entry : result.hosts_entries)
        hosts += "; line " + std::to_string(entry.line_number) + ": " + entry.address;
    }
  }
  resolver.rows.push_back({"Hosts file", hosts, ReportTone::normal});
  report.sections.push_back(std::move(resolver));
  return report;
}

inline QuickToolReport time_check_report(const TimeCheckResult& result) {
  using report_detail::joined;
  QuickToolReport report;
  report.tool = "Time Check";
  report.subject = result.sntp.server;
  report.checked_unix_millis = result.checked_unix_millis;
  report.notes = result.notes;
  if (result.sntp.server.empty()) {
    report.headline = "No time server to compare with";
    report.headline_tone = ReportTone::attention;
  } else if (!result.sntp.answered) {
    report.headline = result.sntp.server + " did not answer: " + result.sntp.error;
    report.headline_tone = ReportTone::attention;
  }
  const std::string difference = report_detail::seconds_text(result.sntp.offset_ms) +
                                 (result.sntp.offset_ms >= 0 ? " behind " : " ahead of ") + result.sntp.server;
  if (result.sntp.answered) {
    report.headline = "This clock is " + difference;
    report.headline_tone = result.beyond_kerberos                        ? ReportTone::problem
                           : std::fabs(result.sntp.offset_ms) > 60000.0 ? ReportTone::attention
                                                                         : ReportTone::good;
  }

  ReportSection machine{"This machine", {}, {}};
  // The name Windows and Veeam's logs print, with the zone's own id.
  const NamedTimeZone* named = find_named_time_zone(result.zone.name);
  machine.rows.push_back({"Time zone", named != nullptr ? named->name + " (" + result.zone.name + ")" : result.zone.name,
                          ReportTone::normal});
  machine.rows.push_back({"UTC offset",
                          format_utc_offset(result.zone.utc_offset_minutes) +
                              (result.zone.daylight_saving_now ? ", daylight saving time now" : ""),
                          ReportTone::normal});
  report.sections.push_back(std::move(machine));

  ReportSection source{"Time source", {}, result.source.note};
  source.rows.push_back({"Service", result.source.service.empty() ? "none running" : result.source.service,
                         result.source.service.empty() ? ReportTone::attention : ReportTone::normal});
  if (!result.source.mode.empty())
    source.rows.push_back({"Synchronizes with", result.source.mode, ReportTone::normal});
  if (!result.source.servers.empty())
    source.rows.push_back({"Servers", joined(result.source.servers), ReportTone::normal});
  if (!result.source.domain_controller.empty())
    source.rows.push_back({"Domain controller", result.source.domain_controller, ReportTone::normal});
  report.sections.push_back(std::move(source));

  if (!result.sntp.server.empty()) {
    ReportSection answer{"Answer", {}, {}};
    answer.rows.push_back({"Asked", result.sntp.server + (result.sntp.address.empty() || result.sntp.address == result.sntp.server
                                                               ? ""
                                                               : " (" + result.sntp.address + ")"),
                           ReportTone::normal});
    if (result.sntp.answered) {
      answer.rows.push_back({"Difference", difference, report.headline_tone});
      answer.rows.push_back({"Round trip", std::to_string(std::llround(result.sntp.round_trip_ms)) + " ms",
                             ReportTone::normal});
      answer.rows.push_back({"Stratum", std::to_string(result.sntp.stratum) +
                                            (result.sntp.reference.empty() ? "" : ", reference " + result.sntp.reference),
                             ReportTone::normal});
    } else {
      answer.rows.push_back({"Answer", result.sntp.error, ReportTone::attention});
    }
    report.sections.push_back(std::move(answer));
  }
  return report;
}

inline QuickToolReport time_conversion_report(const std::string& input, const ConvertedTime& converted) {
  QuickToolReport report;
  report.tool = "Time Check converter";
  report.subject = input;
  if (!converted.ok) {
    report.headline = converted.error;
    report.headline_tone = ReportTone::attention;
    return report;
  }
  report.headline = converted.utc_text;
  report.headline_tone = ReportTone::good;
  ReportSection section{"Converted", {}, {}};
  for (auto& [label, value] : converted_time_rows(converted)) {
    const bool note = label == "Note";
    if (note)
      report.headline_tone = ReportTone::attention;
    section.rows.push_back({label, value, note ? ReportTone::attention : ReportTone::normal});
  }
  report.sections.push_back(std::move(section));
  return report;
}

// A storage test's result: the plain view first, with what it means, then the full results.
inline QuickToolReport speed_test_report(const DiskSpeedTestResult& result) {
  const SpeedTestSummary summary = summarize_speed_test(result);
  QuickToolReport report;
  report.tool = "Disk Speed Test"; // the engine shows in the full results' Ran row
  report.subject = result.file;
  report.checked_unix_millis = result.ended_unix_millis;
  report.headline = summary.headline;
  report.headline_tone = summary.stopped ? ReportTone::attention : ReportTone::good;
  // One point a line, each with a bullet, so what was done and what it means read apart.
  std::vector<std::string> points;
  for (const std::string& point : summary.plain_explanation)
    points.push_back("\xE2\x80\xA2 " + point);
  ReportSection plain{"Simple", {}, report_detail::joined(points, "\n")};
  for (const auto& [label, value] : summary.plain)
    plain.rows.push_back({label, value, ReportTone::normal});
  report.sections.push_back(std::move(plain));
  ReportSection full{"Full results", {}, report_detail::joined(summary.explanation, " ")};
  for (const auto& [label, value] : summary.rows)
    full.rows.push_back({label, value, ReportTone::normal});
  report.sections.push_back(std::move(full));
  return report;
}

// The Object Storage Check's result: a section for the checks without requests, one for the signed
// reads and one for what Veeam's guide asks, each row in the tone of its state.
inline QuickToolReport object_storage_report(const ObjectStorageResult& result) {
  QuickToolReport report;
  report.tool = "Object Storage Check";
  report.subject = result.endpoint.request_host.empty() ? result.endpoint.host : result.endpoint.request_host;
  report.checked_unix_millis = result.ended_unix_millis;
  report.headline = result.headline;
  bool problem = false;
  bool attention = false;
  for (const ObjectCheckRow& row : result.rows) {
    if (report.sections.empty() || report.sections.back().title != row.section)
      report.sections.push_back({row.section, {}, {}});
    ReportTone tone = ReportTone::normal;
    switch (row.state) {
    case ObjectCheckState::pass: tone = ReportTone::good; break;
    case ObjectCheckState::attention:
      tone = ReportTone::attention;
      attention = true;
      break;
    case ObjectCheckState::fail:
      tone = ReportTone::problem;
      problem = true;
      break;
    case ObjectCheckState::not_checked: tone = ReportTone::quiet; break;
    case ObjectCheckState::info: break;
    }
    report.sections.back().rows.push_back({row.label, row.value, tone});
  }
  report.headline_tone = problem ? ReportTone::problem : attention ? ReportTone::attention : ReportTone::good;
  return report;
}

// The File Transfer Calculator's estimate: the plain view, how it is worked out and other amounts at
// the same rate. The speeds, the email text and the terms are file_transfer_side_report's.
inline QuickToolReport file_transfer_report(const TransferEstimate& estimate) {
  QuickToolReport report;
  report.tool = "File Transfer Calculator";
  report.subject =
      transfer_size_text(estimate.inputs.size_bytes) + " over " + link_speed_text(estimate.inputs.link_bits_per_second);
  report.headline = estimate.headline;
  report.notes.push_back(estimate.summary);
  const auto rows_of = [](const std::vector<TransferRow>& rows) {
    std::vector<ReportRow> out;
    for (const TransferRow& row : rows)
      out.push_back({row.label, row.value, ReportTone::normal});
    return out;
  };
  report.sections.push_back({"Simple", rows_of(estimate.simple), {}});
  report.sections.push_back({"How it is worked out", rows_of(estimate.steps), {}});
  report.sections.push_back(
      {"Other amounts at " + plain_rate(estimate.rate_bytes_per_second / kTransferMiB), rows_of(estimate.other_sizes),
       estimate.jumbo_note});
  return report;
}

// Beside the estimate: each speed as a bar against the fastest, with its time (the link, the network
// test and the storage when measured), then the email text and the terms. No headline.
inline QuickToolReport file_transfer_side_report(const TransferEstimate& estimate) {
  QuickToolReport report;
  report.tool = "File Transfer Calculator";
  double fastest = 0.0;
  for (const TransferSpeedRow& row : estimate.speeds)
    fastest = std::max(fastest, row.speed.bytes_per_second);
  const bool several = estimate.speeds.size() > 1U;
  ReportSection speeds{several ? "Speeds" : "Speed", {}, several ? "The time uses the lowest of these speeds." : ""};
  for (const TransferSpeedRow& row : estimate.speeds)
    speeds.rows.push_back({row.speed.name,
                           transfer_rate_text(row.speed.bytes_per_second) + ", " + transfer_duration_text(row.seconds) +
                               (row.speed.detail.empty() ? std::string() : "\n" + row.speed.detail),
                           several && row.lowest ? ReportTone::attention : ReportTone::normal,
                           fastest > 0.0 ? row.speed.bytes_per_second / fastest : 0.0});
  report.sections.push_back(std::move(speeds));
  const TransferEmail email = transfer_email(estimate);
  report.sections.push_back({"Email text", {{"Subject", email.subject, ReportTone::normal}}, email.body});
  std::vector<ReportRow> terms;
  for (const TransferRow& row : estimate.terms)
    terms.push_back({row.label, row.value, ReportTone::normal});
  report.sections.push_back({"Terms", std::move(terms), {}});
  return report;
}

// Copy and #note take the estimate with its side: one report with every section.
inline QuickToolReport file_transfer_full_report(const TransferEstimate& estimate) {
  QuickToolReport report = file_transfer_report(estimate);
  for (ReportSection& section : file_transfer_side_report(estimate).sections)
    report.sections.push_back(std::move(section));
  return report;
}

// Copy for email: the subject, then the body.
inline std::string file_transfer_email_text(const TransferEstimate& estimate) {
  const TransferEmail email = transfer_email(estimate);
  return email.subject + "\n\n" + email.body + "\n";
}

// What a log records of its own clock, shown when the log is chosen.
inline QuickToolReport log_clock_report(const LogClock& clock) {
  const LogClockSummary summary = summarize_log_clock(clock);
  QuickToolReport report;
  report.tool = "Time Check converter";
  report.subject = clock.source;
  report.headline = summary.headline;
  report.headline_tone = summary.tied ? ReportTone::good : ReportTone::attention;
  report.notes = summary.notes;
  if (!summary.rows.empty()) {
    ReportSection section{"This log's clock", {}, {}};
    for (auto& [label, value] : summary.rows)
      section.rows.push_back({label, value, ReportTone::normal});
    report.sections.push_back(std::move(section));
  }
  return report;
}

inline QuickToolReport file_lock_report(const FileLockResult& result) {
  QuickToolReport report;
  report.tool = "File Lock Check";
  report.subject = result.file;
  report.headline = result.holders.empty() ? "No process holds it open"
                    : result.holders.size() == 1U
                        ? "1 process holds it open"
                        : std::to_string(result.holders.size()) + " processes hold it open";
  report.headline_tone = result.holders.empty() ? ReportTone::good : ReportTone::attention;
  if (!result.note.empty())
    report.notes.push_back(result.note);
  ReportSection held{"Held by", {}, {}};
  for (const FileHolder& holder : result.holders) {
    std::string value = holder.name.empty() ? "name not readable" : holder.name;
    if (!holder.services.empty())
      value += "; services: " + holder.services;
    if (holder.started_unix_millis > 0)
      value += "; started " + report_detail::utc_text(holder.started_unix_millis);
    if (!holder.path.empty())
      value += "; " + holder.path;
    held.rows.push_back({"PID " + std::to_string(holder.pid), value, ReportTone::normal});
  }
  if (!held.rows.empty())
    report.sections.push_back(std::move(held));
  ReportSection file{"File", {}, {}};
  file.rows.push_back({"Path", result.file, ReportTone::normal});
  file.rows.push_back({"Kind", result.is_directory ? "folder" : "file", ReportTone::normal});
  report.sections.push_back(std::move(file));
  return report;
}

// A folder and everything under it: each process holding something there, then what each holds.
inline QuickToolReport folder_lock_report(const FolderLockResult& result, std::size_t max_rows = 200) {
  QuickToolReport report;
  report.tool = "File Lock Check";
  report.subject = result.folder;
  const auto count = [](std::size_t value, const char* one, const char* many) {
    return std::to_string(value) + " " + (value == 1 ? one : many);
  };
  report.headline = result.held.empty() ? "Nothing under it is held open"
                                        : count(result.held.size(), "entry", "entries") + " held open by " +
                                              count(result.holders.size(), "process", "processes");
  report.headline_tone = result.held.empty() ? ReportTone::good : ReportTone::attention;
  report.notes.push_back("Checked " + count(result.files_checked, "file", "files") + " in " +
                         count(result.folders_checked, "folder", "folders") + ".");
  if (result.stopped_at_limit)
    report.notes.push_back("Stopped after " + std::to_string(result.files_checked + result.folders_checked) +
                           " entries. Check a folder further down for the rest.");
  if (!result.note.empty())
    report.notes.push_back(result.note);

  ReportSection holders{"Held by", {}, {}};
  for (const FileHolder& holder : result.holders) {
    std::size_t entries = 0;
    for (const HeldFile& held : result.held)
      entries += std::count(held.pids.begin(), held.pids.end(), holder.pid) > 0 ? 1U : 0U;
    std::string value = (holder.name.empty() ? std::string("name not readable") : holder.name) + "; holds " +
                        count(entries, "entry", "entries");
    if (!holder.services.empty())
      value += "; services: " + holder.services;
    if (!holder.path.empty())
      value += "; " + holder.path;
    holders.rows.push_back({"PID " + std::to_string(holder.pid), value, ReportTone::normal});
  }
  if (!holders.rows.empty())
    report.sections.push_back(std::move(holders));

  ReportSection files{"Held", {}, {}};
  for (const HeldFile& held : result.held) {
    if (files.rows.size() == max_rows) {
      files.note = "and " + std::to_string(result.held.size() - max_rows) + " more";
      break;
    }
    std::string relative = held.path;
    if (relative.size() > result.folder.size() && relative.compare(0, result.folder.size(), result.folder) == 0)
      relative = relative.substr(result.folder.size() + (result.folder.back() == '/' || result.folder.back() == '\\' ? 0 : 1));
    else if (relative == result.folder)
      relative = "this folder";
    std::string label = held.pids.size() == 1 ? "PID " : "PIDs ";
    for (std::size_t index = 0; index < held.pids.size(); ++index)
      label += (index == 0 ? "" : ", ") + std::to_string(held.pids[index]);
    files.rows.push_back({label, relative + (held.is_directory ? " (folder)" : ""), ReportTone::normal});
  }
  if (!files.rows.empty())
    report.sections.push_back(std::move(files));

  ReportSection folder{"Folder", {}, {}};
  folder.rows.push_back({"Path", result.folder, ReportTone::normal});
  report.sections.push_back(std::move(folder));
  return report;
}

// A folder walk still running: what it found so far, with the counts as the headline.
inline QuickToolReport folder_lock_progress_report(const FolderLockResult& result) {
  QuickToolReport report = folder_lock_report(result);
  report.headline = "Checking: " + std::to_string(result.files_checked) + " files in " +
                    std::to_string(result.folders_checked) + " folders so far, " + std::to_string(result.held.size()) +
                    (result.held.size() == 1U ? " entry held" : " entries held");
  report.headline_tone = result.held.empty() ? ReportTone::normal : ReportTone::attention;
  if (!report.notes.empty())
    report.notes.front() = "Still checking. The list grows as the walk goes on.";
  return report;
}

namespace report_detail {

inline std::string volume_name(const VolumeInfo& volume) {
  return !volume.mount_point.empty() ? volume.mount_point : volume.device.empty() ? "a volume" : volume.device;
}

inline std::string file_system_text(const VolumeInfo& volume) {
  if (volume.file_system.empty())
    return "not read";
  return volume.file_system + (volume.file_system_version.empty() ? "" : " " + volume.file_system_version);
}

// What the volume sits on, in a few words: "Internal disk (NVMe)", "iSCSI LUN 3, target 0".
inline std::string device_text(const VolumeInfo& volume) {
  if (volume.kind.empty())
    return volume.bus;
  std::string text = volume.kind;
  if (volume.kind.rfind("Internal", 0) == 0 && !volume.bus.empty())
    text += " (" + volume.bus + ")";
  if (!volume.lun.empty() && volume.kind.find("LUN") != std::string::npos)
    text += " " + volume.lun.substr(volume.lun.find(' ') + 1);
  if (volume.network_share && !volume.remote.empty())
    text += " " + volume.remote;
  return text;
}

inline std::string free_text(const VolumeInfo& volume) {
  if (volume.total_bytes == 0)
    return {};
  const auto percent = static_cast<int>(static_cast<double>(volume.free_bytes) * 100.0 /
                                        static_cast<double>(volume.total_bytes));
  return volume_detail::format_bytes(volume.free_bytes) + " (" + std::to_string(percent) + "%)";
}

inline std::string encryption_text(const VolumeInfo& volume) {
  if (!volume.encryption.empty())
    return volume.encryption;
  return volume.encryption_note.empty() ? std::string() : "not read";
}

inline std::string fast_clone_short(FastCloneState state) {
  switch (state) {
  case FastCloneState::can_work: return "can work";
  case FastCloneState::cannot_work: return "no";
  case FastCloneState::not_confirmed: return "not confirmed";
  case FastCloneState::depends_on_server: return "depends on the server";
  case FastCloneState::not_applicable: break;
  }
  return {};
}

inline ReportTone fast_clone_tone(FastCloneState state) {
  switch (state) {
  case FastCloneState::can_work: return ReportTone::good;
  case FastCloneState::cannot_work:
  case FastCloneState::not_confirmed: return ReportTone::attention;
  case FastCloneState::depends_on_server:
  case FastCloneState::not_applicable: break;
  }
  return ReportTone::normal;
}

inline std::string yes_no(bool value) { return value ? "yes" : "no"; }

} // namespace report_detail

// The volume list both editions draw: its column titles and one row per volume.
inline const std::vector<std::string>& volume_columns() {
  static const std::vector<std::string> columns = {"Volume", "Label", "File system", "On",
                                                   "Size",   "Free",  "Encryption",  "Fast Clone"};
  return columns;
}

inline std::vector<std::string> volume_row(const VolumeInfo& volume) {
  using namespace report_detail;
  return {volume.mount_point.empty() ? std::string("no mount point") : volume.mount_point,
          volume.label,
          file_system_text(volume),
          device_text(volume),
          volume.total_bytes == 0 ? std::string() : volume_detail::format_bytes(volume.total_bytes),
          free_text(volume),
          encryption_text(volume),
          fast_clone_short(volume.fast_clone_state)};
}

// One volume in full, and the folder checked on it when there is one.
inline QuickToolReport volume_report(const VolumeInfo& volume) {
  using namespace report_detail;
  QuickToolReport report;
  report.tool = "Volume Check";
  const std::string name = volume_name(volume);
  report.subject = volume.path.empty() ? name : volume.path;
  const bool fast_clone = volume.fast_clone_state != FastCloneState::not_applicable;
  switch (volume.fast_clone_state) {
  case FastCloneState::can_work: report.headline = "Fast Clone can work on " + name; break;
  case FastCloneState::cannot_work: report.headline = "No Fast Clone on " + name; break;
  case FastCloneState::not_confirmed: report.headline = "Fast Clone not confirmed on " + name; break;
  case FastCloneState::depends_on_server: report.headline = "Fast Clone on " + name + " depends on the server"; break;
  case FastCloneState::not_applicable:
    report.headline = name + ": " + file_system_text(volume) +
                      (device_text(volume).empty() ? std::string() : ", " + device_text(volume));
    break;
  }
  report.headline_tone = fast_clone_tone(volume.fast_clone_state);

  if (!volume.path.empty()) {
    ReportSection folder{"Folder", {}, {}};
    folder.rows.push_back({"Path", volume.path, ReportTone::normal});
    if (volume.folder_attributes_read) {
      folder.rows.push_back({"Compressed", yes_no(volume.folder_compressed), ReportTone::normal});
#ifdef _WIN32
      folder.rows.push_back({"Encrypted (EFS)", yes_no(volume.folder_encrypted), ReportTone::normal});
#else
      folder.rows.push_back({"Encrypted (fscrypt)", yes_no(volume.folder_encrypted), ReportTone::normal});
#endif
    } else {
      folder.rows.push_back({"Compressed, encrypted",
                             (volume.file_system.empty() ? std::string("this file system") : volume.file_system) +
                                 " does not report them",
                             ReportTone::quiet});
    }
    report.sections.push_back(std::move(folder));
  }

  if (fast_clone) {
    ReportSection clone{"Fast Clone", {}, {}};
    clone.rows.push_back({"", volume.fast_clone_text, fast_clone_tone(volume.fast_clone_state)});
    for (const std::string& note : volume.notes)
      clone.rows.push_back({"", note, ReportTone::attention});
    if (!volume.guide_url.empty())
      clone.rows.push_back({"Guide", volume.guide_title + ": " + volume.guide_url, ReportTone::quiet});
    report.sections.push_back(std::move(clone));
  }

  ReportSection device{"On", {}, {}};
  const auto add = [](ReportSection& section, const char* label, const std::string& value) {
    if (!value.empty())
      section.rows.push_back({label, value, ReportTone::normal});
  };
  add(device, "Kind", volume.kind);
  add(device, "Bus", volume.bus);
  add(device, "Disk", volume.disk);
  add(device, "Controller", volume.controller);
  add(device, "Driver", volume.driver);
  add(device, "LUN", volume.lun);
  add(device, volume.network_share ? "Share" : "Target", volume.remote);
  add(device, "Layers", joined(volume.layers, " > "));
  if (volume.removable)
    add(device, "Removable", "yes");
  if (!device.rows.empty())
    report.sections.push_back(std::move(device));

  ReportSection details{"Volume", {}, {}};
  add(details, "Mount points", volume.mount_points.empty() ? std::string("none") : joined(volume.mount_points));
  add(details, "Device", volume.device);
  add(details, "Label", volume.label);
  const bool refs_unversioned = ascii_lower(volume.file_system) == "refs" && volume.file_system_version.empty();
  add(details, "File system", file_system_text(volume) + (refs_unversioned ? ", version not reported" : ""));
  if (volume.cluster_size != 0)
    add(details, "Cluster or block size", volume_detail::format_bytes(volume.cluster_size));
  if (volume.total_bytes != 0)
    add(details, "Space",
        volume_detail::format_bytes(volume.free_bytes) + " free of " + volume_detail::format_bytes(volume.total_bytes));
  add(details, "Mount options", volume.mount_options);
  if (volume.read_only)
    add(details, "Read-only", "yes");
  if (!fast_clone) {
    for (const std::string& note : volume.notes)
      details.rows.push_back({"", note, ReportTone::attention});
  }
  report.sections.push_back(std::move(details));

  ReportSection protection{"Compression and encryption", {}, {}};
#ifdef _WIN32
  if (!volume.file_system.empty())
    add(protection, "Drive compressed", yes_no(volume.volume_compressed));
#else
  if (ascii_lower(volume.file_system) == "btrfs")
    add(protection, "Compressed (btrfs)", yes_no(volume.volume_compressed));
#endif
  if (!volume.encryption.empty())
    add(protection, "Encryption", volume.encryption);
  else if (!volume.encryption_note.empty())
    protection.rows.push_back({"Encryption", volume.encryption_note, ReportTone::quiet});
#ifdef _WIN32
  add(protection, "Data Deduplication", volume.deduplication_installed ? "installed on this server" : "not installed");
#endif
  if (!protection.rows.empty())
    report.sections.push_back(std::move(protection));
  return report;
}

// Every volume, for Copy and Add to #note before one is chosen.
inline QuickToolReport volumes_report(const std::vector<VolumeInfo>& volumes) {
  using namespace report_detail;
  QuickToolReport report;
  report.tool = "Volume Check";
  report.subject = "this machine's volumes";
  std::vector<std::string> fast_clone;
  for (const VolumeInfo& volume : volumes) {
    if (volume.fast_clone_state == FastCloneState::can_work)
      fast_clone.push_back(volume_name(volume));
  }
  report.headline = std::to_string(volumes.size()) + (volumes.size() == 1 ? " volume" : " volumes");
  if (!fast_clone.empty()) {
    report.headline += "; Fast Clone can work on " + joined(fast_clone);
    report.headline_tone = ReportTone::good;
  }
  ReportSection section{"Volumes", {}, {}};
  for (const VolumeInfo& volume : volumes) {
    std::vector<std::string> parts{file_system_text(volume)};
    if (!device_text(volume).empty())
      parts.push_back(device_text(volume));
    if (volume.total_bytes != 0)
      parts.push_back(volume_detail::format_bytes(volume.free_bytes) + " free of " +
                      volume_detail::format_bytes(volume.total_bytes));
    if (!encryption_text(volume).empty())
      parts.push_back(encryption_text(volume));
    if (volume.fast_clone_state != FastCloneState::not_applicable)
      parts.push_back("Fast Clone " + fast_clone_short(volume.fast_clone_state));
    section.rows.push_back({volume.mount_point.empty() ? volume.device : volume.mount_point +
                                                                             (volume.label.empty() ? "" : " (" + volume.label + ")"),
                            joined(parts), fast_clone_tone(volume.fast_clone_state)});
  }
  report.sections.push_back(std::move(section));
  return report;
}

inline QuickToolReport port_detail_report(const PortCheckRow& row, const FirewallSnapshot& firewall) {
  using report_detail::joined;
  QuickToolReport report;
  report.tool = "Local Port Checker";
  report.subject = port_label(row) + "/" + to_string(row.state.protocol);
  report.headline = report.subject + " " + to_string(row.verdict);
  report.headline_tone = report_detail::tone_of(row.verdict);
  report.notes.push_back(row.explanation);
  if (!row.firewall.note.empty())
    report.notes.push_back(row.firewall.note);

  ReportSection listening{"On this machine", {}, {}};
  listening.rows.push_back({"Listening",
                            row.state.listening ? "on " + joined(row.state.listen_addresses) + " (" +
                                                      to_string(row.state.scope) + ")"
                                                : row.state.found ? "no; connections only" : "no",
                            row.state.listening ? ReportTone::normal : ReportTone::quiet});
  if (row.state.connections > 0)
    listening.rows.push_back({"Connections", std::to_string(row.state.connections), ReportTone::normal});
  for (const LocalSocket& owner : row.state.owners) {
    if (owner.pid == 0) {
      listening.rows.push_back({"Process", "not readable by this account", ReportTone::quiet});
      continue;
    }
    listening.rows.push_back({"Process", (owner.process_name.empty() ? std::string("PID") : owner.process_name + ", PID") +
                                             " " + std::to_string(owner.pid) + " on " + owner.local_address,
                              ReportTone::normal});
    if (!owner.services.empty())
      listening.rows.push_back({"Services", owner.services, ReportTone::normal});
    if (!owner.process_path.empty())
      listening.rows.push_back({"Program", owner.process_path, ReportTone::quiet});
  }
  report.sections.push_back(std::move(listening));

  ReportSection wall{"Firewall" + (firewall.product.empty() ? std::string() : ": " + firewall.product), {},
                     firewall.readable ? std::string() : firewall.note};
  for (const FirewallProfileVerdict& profile : row.firewall.per_profile) {
    std::string label = profile.profile;
    if (!profile.networks.empty())
      label += " (" + joined(profile.networks) + ")";
    wall.rows.push_back({label, to_string(profile.decision) + ": " + profile.because,
                         report_detail::tone_of(profile.decision)});
  }
  report.sections.push_back(std::move(wall));
  return report;
}

inline QuickToolReport pending_restart_report(const PendingRestartResult& result) {
  QuickToolReport report;
  report.tool = "Pending restart";
  report.checked_unix_millis = unix_millis_now();
  report.headline = result.restart_needed ? "A restart is waiting"
                    : result.markers.empty() ? "No restart is waiting"
                                             : "No restart is waiting; files wait for the next start";
  report.headline_tone = result.restart_needed ? ReportTone::attention : ReportTone::good;
  if (result.boot_unix_millis > 0)
    report.notes.push_back("Last start " + report_detail::utc_text(result.boot_unix_millis));
  for (const RestartMarker& marker : result.markers) {
    ReportSection section{marker.name, {}, {}};
    section.rows.push_back({"", marker.meaning, marker.restart_needed ? ReportTone::attention : ReportTone::normal});
    if (marker.set_unix_millis > 0)
      section.rows.push_back({"Set", report_detail::utc_text(marker.set_unix_millis), ReportTone::normal});
    for (const std::string& detail : marker.details)
      section.rows.push_back({"", detail, ReportTone::quiet});
    for (const std::string& reason : marker.reasons)
      section.rows.push_back({"Cause", reason, ReportTone::normal});
    report.sections.push_back(std::move(section));
  }
  return report;
}

// The whole port table as text, for Copy.
inline std::string port_check_text(const PortCheckResult& result) {
  std::ostringstream text;
  text << "Local Port Checker\nChecked " << report_detail::utc_text(result.checked_unix_millis) << "\n";
  if (!result.firewall.product.empty())
    text << "Firewall: " << result.firewall.product << "\n";
  for (const PortCheckRow& row : result.rows) {
    text << port_label(row) << "/" << to_string(row.state.protocol) << "\t" << to_string(row.verdict);
    if (row.state.listening)
      text << "\t" << report_detail::joined(row.state.listen_addresses);
    if (!row.state.owners.empty() && row.state.owners.front().pid != 0)
      text << "\t" << row.state.owners.front().process_name << " (PID " << row.state.owners.front().pid << ")";
    text << "\n";
  }
  if (!result.firewall.note.empty())
    text << result.firewall.note << "\n";
  if (!result.sockets_note.empty())
    text << result.sockets_note << "\n";
  return text.str();
}

// The Local Port Checker's rows as CSV, for Export: one line per port with its verdict, where it
// listens, the program holding it, the firewall's answer and what another host sees.
inline std::string port_check_csv(const PortCheckResult& result) {
  const auto field = [](const std::string& text) {
    if (text.find_first_of(",\"\r\n") == std::string::npos)
      return text;
    std::string quoted = "\"";
    for (const char character : text) {
      if (character == '"')
        quoted += '"';
      quoted += character;
    }
    return quoted + "\"";
  };
  std::ostringstream csv;
  csv << "Port,Protocol,Verdict,Listening on,Program,PID,Firewall,Explanation\r\n";
  for (const PortCheckRow& row : result.rows) {
    const bool owner = !row.state.owners.empty() && row.state.owners.front().pid != 0;
    std::string firewall = row.firewall.mixed ? std::string("Mixed") : to_string(row.firewall.decision);
    csv << field(port_label(row)) << ',' << field(to_string(row.state.protocol)) << ','
        << field(to_string(row.verdict)) << ','
        << field(row.state.listening ? report_detail::joined(row.state.listen_addresses) : std::string()) << ','
        << field(owner ? row.state.owners.front().process_name : std::string()) << ','
        << (owner ? std::to_string(row.state.owners.front().pid) : std::string()) << ',' << field(firewall) << ','
        << field(row.explanation) << "\r\n";
  }
  return csv.str();
}

// A report as it reads in #note, in the file tool runs are added to.
inline std::string quick_tool_note_block(const QuickToolReport& report, const std::string& host) {
  std::ostringstream block;
  const std::int64_t when = report.checked_unix_millis > 0 ? report.checked_unix_millis : unix_millis_now();
  block << "  [" << report_detail::utc_text(when) << "] " << report.tool << "  |  " << host << "\n";
  std::istringstream lines(report_text(report));
  std::string line;
  bool first = true;
  while (std::getline(lines, line)) {
    if (first) { // the tool line is in the header already
      first = false;
      continue;
    }
    if (!line.empty())
      block << "    " << line << "\n";
  }
  block << "\n";
  return block.str();
}

inline NoteWrite add_quick_tool_report_to_note(const CaseWorkspace& workspace, const QuickToolReport& report,
                                               const std::string& host) {
  const std::string text = quick_tool_note_block(report, host);
  const std::filesystem::path destination = tool_evidence_note_path(workspace);
  {
    std::ifstream existing(destination, std::ios::binary);
    if (existing) {
      std::ostringstream buffer;
      buffer << existing.rdbuf();
      if (buffer.str().find(text) != std::string::npos)
        return NoteWrite::already_there;
    }
  }
  std::error_code error;
  std::filesystem::create_directories(destination.parent_path(), error);
  std::ofstream output(destination, std::ios::binary | std::ios::app);
  if (!output)
    return NoteWrite::failed;
  output << text;
  return output ? NoteWrite::added : NoteWrite::failed;
}

// The Quick scan's reading beside the listener's own count (PROPOSAL_5.x_CHECKS.md section 5.10):
// what arrived and from where, what reached the listener, and what was stopped on this machine.
inline std::string quick_scan_summary(const QuickScanCounts& counts, std::size_t reached) {
  std::string text;
  if (counts.attempts == 0) {
    text = reached == 0 ? "None arrived: stopped before this machine, or the other side sent nothing."
                        : std::to_string(reached) +
                              " reached the listener without passing a network adapter, as a test from this "
                              "machine to itself does.";
  } else {
    std::string from;
    for (std::size_t index = 0; index < counts.sources.size() && index < 3U; ++index)
      from += (index == 0U ? "" : ", ") + counts.sources[index].address + " (" +
              std::to_string(counts.sources[index].attempts) + ")";
    if (counts.more_sources || counts.sources.size() > 3U)
      from += " and others";
    text = std::to_string(counts.attempts) + " arrived from " + from + ". ";
    if (reached >= counts.attempts)
      text += std::to_string(reached) + " reached the listener.";
    else if (reached == 0)
      text += "None reached the listener: stopped on this machine.";
    else
      text += std::to_string(reached) + " reached the listener; " + std::to_string(counts.attempts - reached) +
              " stopped on this machine.";
  }
  if (!counts.note.empty())
    text += " " + counts.note;
  return text;
}

} // namespace support_assist::gui
