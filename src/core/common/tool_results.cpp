// The quick tools' results as JSON: what `--json` prints and what a GUI run keeps as result.json.
#include "support_assist/tool_results.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"

#include <sstream>

namespace support_assist {
namespace tool_json {
namespace {

const char* boolean(bool value) { return value ? "true" : "false"; }

std::string time_or_empty(std::int64_t unix_millis) {
  return unix_millis > 0 ? iso8601_from_unix_millis(unix_millis) : std::string();
}

std::string holder_json(const FileHolder& holder) {
  std::ostringstream out;
  out << "{\"pid\":" << holder.pid << ",\"name\":" << text(holder.name) << ",\"path\":" << text(holder.path)
      << ",\"services\":" << text(holder.services) << ",\"started_utc\":" << text(time_or_empty(holder.started_unix_millis))
      << "}";
  return out.str();
}

std::string watch_item(const WatchItem& item) {
  std::ostringstream out;
  out << "{\"kind\":" << text(item.kind == WatchKind::service ? "service" : "process") << ",\"name\":" << text(item.name)
      << ",\"display_name\":" << text(item.display_name) << ",\"state\":" << text(item.state) << ",\"pid\":" << item.pid
      << ",\"started_utc\":" << text(time_or_empty(item.started_unix_millis)) << ",\"path\":" << text(item.path)
      << ",\"listening\":" << text(item.listening) << "}";
  return out.str();
}

std::string change_name(WatchChange change) {
  switch (change) {
  case WatchChange::started: return "started";
  case WatchChange::ended: return "ended";
  case WatchChange::state_changed: return "state changed";
  case WatchChange::restarted: return "restarted";
  }
  return {};
}

} // namespace

std::string text(std::string_view value) { return "\"" + json_escape(value) + "\""; }

std::string list(const std::vector<std::string>& values) {
  std::string out = "[";
  for (std::size_t index = 0; index < values.size(); ++index)
    out += (index == 0 ? "" : ",") + text(values[index]);
  return out + "]";
}

std::string port_check(const PortCheckResult& result) {
  std::ostringstream out;
  out << "{\"checked_utc\":" << text(iso8601_from_unix_millis(result.checked_unix_millis))
      << ",\"firewall\":{\"product\":" << text(result.firewall.product)
      << ",\"readable\":" << boolean(result.firewall.readable) << ",\"note\":" << text(result.firewall.note)
      << "},\"sockets_note\":" << text(result.sockets_note) << ",\"ports\":[";
  for (std::size_t index = 0; index < result.rows.size(); ++index) {
    const PortCheckRow& row = result.rows[index];
    std::string held;
    for (const std::uint16_t port : row.held)
      held += (held.empty() ? "" : ",") + std::to_string(port);
    out << (index == 0 ? "" : ",") << "{\"port\":" << row.state.port << ",\"range\":" << text(row.range)
        << ",\"held\":[" << held << "],\"protocol\":"
        << text(to_string(row.state.protocol)) << ",\"verdict\":" << text(to_string(row.verdict))
        << ",\"explanation\":" << text(row.explanation) << ",\"found\":" << boolean(row.state.found)
        << ",\"listening\":" << boolean(row.state.listening) << ",\"scope\":" << text(to_string(row.state.scope))
        << ",\"addresses\":" << list(row.state.listen_addresses) << ",\"connections\":" << row.state.connections
        << ",\"owners\":[";
    for (std::size_t owner = 0; owner < row.state.owners.size(); ++owner) {
      const LocalSocket& socket = row.state.owners[owner];
      out << (owner == 0 ? "" : ",") << "{\"pid\":" << socket.pid << ",\"name\":" << text(socket.process_name)
          << ",\"path\":" << text(socket.process_path) << ",\"services\":" << text(socket.services)
          << ",\"address\":" << text(socket.local_address) << "}";
    }
    out << "],\"firewall\":[";
    for (std::size_t profile = 0; profile < row.firewall.per_profile.size(); ++profile) {
      const FirewallProfileVerdict& verdict = row.firewall.per_profile[profile];
      out << (profile == 0 ? "" : ",") << "{\"profile\":" << text(verdict.profile)
          << ",\"decision\":" << text(to_string(verdict.decision)) << ",\"because\":" << text(verdict.because)
          << ",\"networks\":" << list(verdict.networks) << "}";
    }
    out << "]}";
  }
  out << "]}";
  return out.str();
}

std::string name_check(const NameCheckResult& result) {
  std::ostringstream out;
  out << "{\"name\":" << text(result.name) << ",\"is_address\":" << boolean(result.is_address)
      << ",\"completed_name\":" << text(result.completed_name) << ",\"addresses\":" << list(result.addresses)
      << ",\"resolver_error\":" << text(result.resolver_error) << ",\"source\":" << text(result.source)
      << ",\"aliases\":" << list(result.aliases) << ",\"hosts_file\":" << text(result.settings.hosts_file)
      << ",\"lookup_order\":" << text(result.settings.lookup_order) << ",\"hosts_entries\":[";
  for (std::size_t index = 0; index < result.hosts_entries.size(); ++index)
    out << (index == 0 ? "" : ",") << "{\"address\":" << text(result.hosts_entries[index].address)
        << ",\"line\":" << result.hosts_entries[index].line_number << "}";
  out << "],\"dns\":[";
  for (std::size_t index = 0; index < result.per_server.size(); ++index) {
    const DnsAnswer& answer = result.per_server[index];
    std::vector<std::string> values;
    for (const DnsRecord& record : answer.records)
      values.push_back(to_string(record.type) + " " + record.value);
    out << (index == 0 ? "" : ",") << "{\"server\":" << text(answer.server) << ",\"type\":" << text(to_string(answer.type))
        << ",\"answered\":" << boolean(answer.answered)
        << ",\"result\":" << text(answer.answered ? dns_detail::rcode_text(answer.rcode) : answer.error)
        << ",\"records\":" << list(values) << ",\"ms\":" << static_cast<long long>(answer.elapsed_ms) << "}";
  }
  out << "],\"reverse\":[";
  for (std::size_t index = 0; index < result.reverse.size(); ++index) {
    const ReverseLookup& lookup = result.reverse[index];
    out << (index == 0 ? "" : ",") << "{\"address\":" << text(lookup.address) << ",\"name\":" << text(lookup.name)
        << ",\"agrees\":" << boolean(lookup.agrees) << ",\"error\":" << text(lookup.error) << "}";
  }
  out << "],\"notes\":" << list(result.notes) << "}";
  return out.str();
}

std::string time_check(const TimeCheckResult& result) {
  std::ostringstream out;
  out << "{\"checked_utc\":" << text(iso8601_from_unix_millis(result.checked_unix_millis))
      << ",\"zone\":" << text(result.zone.name) << ",\"utc_offset\":" << text(format_utc_offset(result.zone.utc_offset_minutes))
      << ",\"daylight_saving_now\":" << boolean(result.zone.daylight_saving_now)
      << ",\"service\":" << text(result.source.service) << ",\"mode\":" << text(result.source.mode)
      << ",\"servers\":" << list(result.source.servers)
      << ",\"domain_controller\":" << text(result.source.domain_controller) << ",\"asked\":" << text(result.sntp.server)
      << ",\"address\":" << text(result.sntp.address) << ",\"answered\":" << boolean(result.sntp.answered)
      << ",\"offset_ms\":" << result.sntp.offset_ms << ",\"round_trip_ms\":" << result.sntp.round_trip_ms
      << ",\"stratum\":" << result.sntp.stratum << ",\"error\":" << text(result.sntp.error)
      << ",\"beyond_kerberos\":" << boolean(result.beyond_kerberos) << ",\"notes\":" << list(result.notes)
      << ",\"source_note\":" << text(result.source.note) << "}";
  return out.str();
}

std::string converted_time(const ConvertedTime& converted) {
  std::ostringstream out;
  out << "{\"ok\":" << boolean(converted.ok) << ",\"format\":" << text(converted.format)
      << ",\"utc\":" << text(converted.utc_text) << ",\"here\":" << text(converted.local_text)
      << ",\"zone_in_text\":" << boolean(converted.zone_in_text)
      << ",\"source_offset\":" << text(format_utc_offset(converted.source_offset_minutes))
      << ",\"zone\":" << text(converted.zone_name) << ",\"there\":" << text(converted.zone_text)
      << ",\"note\":" << text(converted.zone_note) << ",\"written_in\":" << text(converted.written_in)
      << ",\"evidence\":" << text(converted.evidence) << ",\"zone_candidates\":" << list(converted.zone_candidates)
      << ",\"shown_in\":" << text(converted.shown_name) << ",\"shown\":" << text(converted.shown_text)
      << ",\"notes\":" << list(converted.notes) << ",\"error\":" << text(converted.error) << "}";
  return out.str();
}

std::string log_clock(const LogClock& clock) {
  std::ostringstream out;
  auto local = [](bool known, std::int64_t millis) {
    return known ? text(time_check_detail::format_unix_millis(millis, 0)) : std::string("null");
  };
  out << "{\"source\":" << text(clock.source) << ",\"machine\":" << text(clock.machine)
      << ",\"lines_read\":" << clock.lines_read << ",\"first_local\":" << local(clock.has_stamped_lines, clock.first_local_millis)
      << ",\"last_local\":" << local(clock.has_stamped_lines, clock.last_local_millis)
      << ",\"stopped_at_limit\":" << boolean(clock.stopped_at_limit) << ",\"anchors\":[";
  for (std::size_t index = 0; index < clock.anchors.size(); ++index) {
    const LogClockAnchor& anchor = clock.anchors[index];
    const char* source = anchor.source == LogClockSource::native_header   ? "native_header"
                         : anchor.source == LogClockSource::dotnet_header ? "dotnet_header"
                         : anchor.source == LogClockSource::offset_hours  ? "offset_hours"
                                                                          : "zone_name";
    out << (index == 0 ? "" : ",") << "{\"line\":" << anchor.line_number << ",\"source\":" << text(source)
        << ",\"text\":" << text(anchor.text) << ",\"local\":" << local(anchor.has_local_time, anchor.local_millis)
        << ",\"offset\":" << (anchor.offset_minutes ? text(format_utc_offset(*anchor.offset_minutes)) : std::string("null"))
        << ",\"daylight\":" << (anchor.daylight ? boolean(*anchor.daylight) : std::string("null"))
        << ",\"zone\":" << text(anchor.zone != nullptr ? anchor.zone->name : anchor.zone_text) << "}";
  }
  out << "],\"error\":" << text(clock.error) << "}";
  return out.str();
}

std::string file_lock(const FileLockResult& result) {
  std::ostringstream out;
  out << "{\"file\":" << text(result.file) << ",\"folder\":" << boolean(result.is_directory) << ",\"holders\":[";
  for (std::size_t index = 0; index < result.holders.size(); ++index)
    out << (index == 0 ? "" : ",") << holder_json(result.holders[index]);
  out << "],\"not_readable\":" << result.processes_not_readable << ",\"note\":" << text(result.note) << "}";
  return out.str();
}

std::string folder_lock(const FolderLockResult& result) {
  std::ostringstream out;
  out << "{\"folder\":" << text(result.folder) << ",\"files_checked\":" << result.files_checked
      << ",\"folders_checked\":" << result.folders_checked << ",\"not_checked\":" << result.not_checked
      << ",\"stopped_at_limit\":" << boolean(result.stopped_at_limit) << ",\"holders\":[";
  for (std::size_t index = 0; index < result.holders.size(); ++index)
    out << (index == 0 ? "" : ",") << holder_json(result.holders[index]);
  out << "],\"held\":[";
  for (std::size_t index = 0; index < result.held.size(); ++index) {
    const HeldFile& held = result.held[index];
    out << (index == 0 ? "" : ",") << "{\"path\":" << text(held.path) << ",\"folder\":" << boolean(held.is_directory)
        << ",\"pids\":[";
    for (std::size_t pid = 0; pid < held.pids.size(); ++pid)
      out << (pid == 0 ? "" : ",") << held.pids[pid];
    out << "]}";
  }
  out << "],\"not_readable\":" << result.processes_not_readable << ",\"note\":" << text(result.note) << "}";
  return out.str();
}

std::string volume(const VolumeInfo& info) {
  std::ostringstream out;
  out << "{\"path\":" << text(info.path) << ",\"mount_point\":" << text(info.mount_point)
      << ",\"mount_points\":" << list(info.mount_points) << ",\"device\":" << text(info.device)
      << ",\"label\":" << text(info.label) << ",\"file_system\":" << text(info.file_system)
      << ",\"file_system_version\":" << text(info.file_system_version) << ",\"cluster_size\":" << info.cluster_size
      << ",\"total_bytes\":" << info.total_bytes << ",\"free_bytes\":" << info.free_bytes
      << ",\"network_share\":" << boolean(info.network_share) << ",\"read_only\":" << boolean(info.read_only)
      << ",\"removable\":" << boolean(info.removable) << ",\"kind\":" << text(info.kind)
      << ",\"bus\":" << text(info.bus) << ",\"disk\":" << text(info.disk)
      << ",\"controller\":" << text(info.controller) << ",\"driver\":" << text(info.driver)
      << ",\"lun\":" << text(info.lun) << ",\"remote\":" << text(info.remote)
      << ",\"layers\":" << list(info.layers) << ",\"volume_compressed\":" << boolean(info.volume_compressed)
      << ",\"encryption\":" << text(info.encryption) << ",\"encryption_note\":" << text(info.encryption_note)
      << ",\"fast_clone\":" << boolean(info.fast_clone) << ",\"fast_clone_text\":" << text(info.fast_clone_text);
  if (!info.path.empty())
    out << ",\"folder_attributes_read\":" << boolean(info.folder_attributes_read)
        << ",\"folder_compressed\":" << boolean(info.folder_compressed)
        << ",\"folder_encrypted\":" << boolean(info.folder_encrypted);
  out << ",\"mount_options\":" << text(info.mount_options) << ",\"notes\":" << list(info.notes)
      << ",\"guide\":" << text(info.guide_url) << "}";
  return out.str();
}

std::string volumes(const std::vector<VolumeInfo>& all) {
  std::string out = "[";
  for (std::size_t index = 0; index < all.size(); ++index)
    out += (index == 0 ? "" : ",") + volume(all[index]);
  return out + "]";
}

std::string pending_restart(const PendingRestartResult& result) {
  std::ostringstream out;
  out << "{\"restart_needed\":" << boolean(result.restart_needed)
      << ",\"last_start_utc\":" << text(iso8601_from_unix_millis(result.boot_unix_millis)) << ",\"markers\":[";
  for (std::size_t index = 0; index < result.markers.size(); ++index) {
    const RestartMarker& marker = result.markers[index];
    out << (index == 0 ? "" : ",") << "{\"id\":" << text(marker.id) << ",\"name\":" << text(marker.name)
        << ",\"meaning\":" << text(marker.meaning) << ",\"restart_needed\":" << boolean(marker.restart_needed)
        << ",\"set_utc\":" << text(time_or_empty(marker.set_unix_millis)) << ",\"details\":" << list(marker.details)
        << ",\"reasons\":" << list(marker.reasons) << "}";
  }
  out << "]}";
  return out.str();
}

std::string installer_cache(const InstallerCacheResult& result) {
  const auto match_name = [](InstallerMatch match) {
    switch (match) {
    case InstallerMatch::package_code: return "package_code";
    case InstallerMatch::product_code: return "product_code";
    case InstallerMatch::upgrade_code: return "upgrade_code";
    case InstallerMatch::none: return "none";
    }
    return "none";
  };
  std::ostringstream out;
  out << "{\"searched\":" << text(result.searched) << ",\"installer_folder\":" << text(result.installer_folder)
      << ",\"installer_folder_exists\":" << boolean(result.installer_folder_exists)
      << ",\"cached_msi_files\":" << result.cached_msi_files << ",\"cached_msp_files\":" << result.cached_msp_files
      << ",\"cached_package_missing\":" << boolean(installer_cache_has_missing(result)) << ",\"products\":[";
  for (std::size_t index = 0; index < result.products.size(); ++index) {
    const InstallerCacheProduct& product = result.products[index];
    out << (index == 0 ? "" : ",") << "{\"product_code\":" << text(product.product_code)
        << ",\"upgrade_code\":" << text(product.upgrade_code) << ",\"name\":" << text(product.name)
        << ",\"version\":" << text(product.version) << ",\"listed_name\":" << text(product.listed_name)
        << ",\"listed_version\":" << text(product.listed_version) << ",\"install_date\":" << text(product.install_date)
        << ",\"context\":" << text(product.context) << ",\"package_name\":" << text(product.package_name)
        << ",\"package_code\":" << text(product.package_code) << ",\"last_used_source\":" << text(product.last_used_source)
        << ",\"install_location\":" << text(product.install_location) << ",\"local_package\":" << text(product.local_package)
        << ",\"local_package_exists\":" << boolean(product.local_package_exists)
        << ",\"main_program\":" << text(product.main_program)
        << ",\"main_program_version\":" << text(product.main_program_version)
        << ",\"from_registry\":" << list(product.from_registry) << ",\"found_by\":" << text(product.found_by)
        << ",\"patches\":[";
    for (std::size_t patch_index = 0; patch_index < product.patches.size(); ++patch_index) {
      const InstallerCachePatch& patch = product.patches[patch_index];
      out << (patch_index == 0 ? "" : ",") << "{\"patch_code\":" << text(patch.patch_code)
          << ",\"name\":" << text(patch.name) << ",\"state\":" << text(patch.state)
          << ",\"local_package\":" << text(patch.local_package)
          << ",\"local_package_exists\":" << boolean(patch.local_package_exists) << "}";
    }
    out << "]}";
  }
  out << "],\"checked_path\":" << text(result.checked_path) << ",\"checked_kind\":" << text(result.checked_kind)
      << ",\"folder_msi_found\":" << result.folder_msi_found
      << ",\"folder_limit_reached\":" << boolean(result.folder_limit_reached) << ",\"installers\":[";
  for (std::size_t index = 0; index < result.candidates.size(); ++index) {
    const InstallerCandidate& candidate = result.candidates[index];
    const bool matched = candidate.matched_product < result.products.size();
    out << (index == 0 ? "" : ",") << "{\"path\":" << text(path_to_utf8(candidate.path))
        << ",\"kind\":" << text(candidate.kind) << ",\"sha256\":" << text(candidate.sha256)
        << ",\"sha256_error\":" << text(candidate.sha256_error) << ",\"error\":" << text(candidate.error)
        << ",\"package_code\":" << text(candidate.package_code) << ",\"product_code\":" << text(candidate.product_code)
        << ",\"product_name\":" << text(candidate.product_name)
        << ",\"product_version\":" << text(candidate.product_version)
        << ",\"upgrade_code\":" << text(candidate.upgrade_code) << ",\"manufacturer\":" << text(candidate.manufacturer)
        << ",\"file_version\":" << text(candidate.file_version)
        << ",\"file_product_name\":" << text(candidate.file_product_name) << ",\"signer\":" << text(candidate.signer)
        << ",\"signature_trusted\":" << boolean(candidate.signature_trusted)
        << ",\"signature_note\":" << text(candidate.signature_note) << ",\"match\":" << text(match_name(candidate.match))
        << ",\"version_matches_product\":" << boolean(candidate.version_matches_product)
        << ",\"matched_product_code\":"
        << text(matched ? result.products[candidate.matched_product].product_code : std::string()) << "}";
  }
  out << "],\"notes\":" << list(result.notes) << ",\"summary\":" << text(installer_cache_summary(result)) << "}";
  return out.str();
}

std::string named_pipes(const NamedPipesResult& result) {
  std::ostringstream out;
  out << "{\"listed\":" << result.listed << ",\"known\":" << result.known << ",\"veeam\":" << result.veeam
      << ",\"veeam_only\":" << boolean(result.veeam_only) << ",\"sockets\":" << boolean(result.sockets)
      << ",\"listing_source\":" << text(result.listing_source)
      << ",\"pipes\":[";
  for (std::size_t index = 0; index < result.pipes.size(); ++index) {
    const NamedPipe& pipe = result.pipes[index];
    out << (index == 0 ? "" : ",") << "{\"name\":" << text(pipe.name) << ",\"instances\":" << pipe.instances
        << ",\"max_instances\":" << pipe.max_instances << ",\"known\":" << boolean(pipe.known)
        << ",\"category\":" << text(pipe.category) << ",\"product\":" << text(pipe.product)
        << ",\"purpose\":" << text(pipe.purpose) << ",\"service\":" << text(pipe.service)
        << ",\"service_state\":" << text(pipe.service_state) << ",\"service_pid\":" << pipe.service_pid
        << ",\"process_id\":" << pipe.process_id << ",\"process\":" << text(pipe.process_name)
        << ",\"process_path\":" << text(pipe.process_path) << ",\"process_service\":" << text(pipe.process_service)
        << ",\"veeam\":" << boolean(pipe.veeam) << ",\"listening\":" << boolean(pipe.listening)
        << ",\"socket_type\":" << text(pipe.socket_type) << ",\"other_holders\":" << pipe.other_holders << "}";
  }
  out << "],\"notes\":" << list(result.notes) << ",\"summary\":" << text(named_pipes_summary(result)) << "}";
  return out.str();
}

std::string wmi_health(const WmiHealthReport& report) {
  std::ostringstream out;
  out << "{\"machine\":" << text(report.machine) << ",\"this_machine\":" << boolean(report.this_machine)
      << ",\"elevated\":" << boolean(report.elevated) << ",\"cancelled\":" << boolean(report.cancelled)
      << ",\"finding\":" << boolean(wmi_health_has_finding(report)) << ",\"rows\":[";
  for (std::size_t index = 0; index < report.rows.size(); ++index) {
    const WmiHealthRow& row = report.rows[index];
    out << (index == 0 ? "" : ",") << "{\"stage\":" << text(row.stage) << ",\"finding\":" << text(row.finding)
        << ",\"detail\":" << text(row.detail) << ",\"status\":" << text(row.status) << "}";
  }
  out << "],\"summary\":" << text(wmi_health_summary(report)) << "}";
  return out.str();
}

std::string host_checks(const HostChecksReport& report) {
  std::ostringstream out;
  out << "{\"elevated\":" << boolean(report.elevated) << ",\"days\":" << report.days
      << ",\"finding\":" << boolean(host_checks_has_finding(report))
      << ",\"cancelled\":" << boolean(report.cancelled) << ",\"groups\":[";
  for (std::size_t index = 0; index < report.groups_run.size(); ++index)
    out << (index == 0 ? "" : ",") << text(report.groups_run[index]);
  out << "],\"rows\":[";
  for (std::size_t index = 0; index < report.rows.size(); ++index) {
    const HostCheckRow& row = report.rows[index];
    out << (index == 0 ? "" : ",") << "{\"group\":" << text(row.group) << ",\"check\":" << text(row.check)
        << ",\"detail\":" << text(row.detail) << ",\"status\":" << text(row.status)
        << ",\"source\":" << text(row.source) << "}";
  }
  out << "],\"summary\":" << text(host_checks_summary(report)) << "}";
  return out.str();
}

std::string watch(const std::string& filter, const WatchSnapshot& snapshot, const std::vector<WatchEvent>& events) {
  std::ostringstream out;
  out << "{\"filter\":" << text(filter) << ",\"read_utc\":" << text(time_or_empty(snapshot.taken_unix_millis))
      << ",\"note\":" << text(snapshot.note) << ",\"items\":[";
  for (std::size_t index = 0; index < snapshot.items.size(); ++index)
    out << (index == 0 ? "" : ",") << watch_item(snapshot.items[index]);
  out << "],\"changes\":[";
  for (std::size_t index = 0; index < events.size(); ++index) {
    const WatchEvent& event = events[index];
    out << (index == 0 ? "" : ",") << "{\"seen_utc\":" << text(time_or_empty(event.at_unix_millis))
        << ",\"change\":" << text(change_name(event.change)) << ",\"previous_state\":" << text(event.previous_state)
        << ",\"text\":" << text(event.text) << ",\"item\":" << watch_item(event.item) << "}";
  }
  out << "]}";
  return out.str();
}

std::string quick_scan(const QuickScanCounts& counts) {
  std::ostringstream out;
  out << "{\"attempts\":" << counts.attempts << ",\"sources\":[";
  for (std::size_t index = 0; index < counts.sources.size(); ++index)
    out << (index == 0 ? "" : ",") << "{\"address\":" << text(counts.sources[index].address)
        << ",\"attempts\":" << counts.sources[index].attempts << "}";
  out << "],\"more_sources\":" << boolean(counts.more_sources) << ",\"note\":" << text(counts.note) << "}";
  return out.str();
}

std::string listener_run(const ListenerRunRecord& run) {
  std::ostringstream out;
  out << "{\"port\":" << run.port << ",\"protocol\":" << text(to_string(run.protocol)) << ",\"minutes\":" << run.minutes
      << ",\"started_utc\":" << text(time_or_empty(run.started_unix_millis))
      << ",\"ended_utc\":" << text(time_or_empty(run.ended_unix_millis)) << ",\"error\":" << text(run.error)
      << ",\"arrivals\":[";
  for (std::size_t index = 0; index < run.arrivals.size(); ++index) {
    const auto& arrival = run.arrivals[index];
    out << (index == 0 ? "" : ",") << "{\"time_utc\":" << text(arrival.time_utc) << ",\"from\":" << text(arrival.peer)
        << ",\"what\":" << text(arrival.what) << "}";
  }
  out << "]";
  if (run.scanned)
    out << ",\"quick_scan\":" << quick_scan(run.scan);
  out << "}";
  return out.str();
}

std::string object_storage(const ObjectStorageResult& result) {
  const auto state = [](ObjectCheckState value) {
    switch (value) {
    case ObjectCheckState::pass: return "pass";
    case ObjectCheckState::attention: return "attention";
    case ObjectCheckState::fail: return "fail";
    case ObjectCheckState::not_checked: return "not_checked";
    case ObjectCheckState::info: break;
    }
    return "info";
  };
  std::ostringstream out;
  out << "{\"preset\":" << text(result.preset) << ",\"endpoint\":" << text(result.endpoint.host)
      << ",\"port\":" << result.endpoint.port << ",\"request_host\":" << text(result.endpoint.request_host)
      << ",\"region\":" << text(result.endpoint.region) << ",\"addressing\":" << text(result.endpoint.addressing)
      << ",\"bucket\":" << text(result.bucket) << ",\"headline\":" << text(result.headline)
      << ",\"signed_reads\":" << (result.signed_reads ? "true" : "false") << ",\"requests\":" << result.requests
      << ",\"bytes_read\":" << result.bytes_read << ",\"estimated_cost\":" << result.estimated_cost
      << ",\"currency\":" << text(result.currency) << ",\"clock_offset_seconds\":";
  if (result.clock_offset_seconds)
    out << *result.clock_offset_seconds;
  else
    out << "null";
  out << ",\"started_utc\":" << text(time_or_empty(result.started_unix_millis))
      << ",\"ended_utc\":" << text(time_or_empty(result.ended_unix_millis)) << ",\"rows\":[";
  for (std::size_t index = 0; index < result.rows.size(); ++index) {
    const ObjectCheckRow& row = result.rows[index];
    out << (index == 0 ? "" : ",") << "{\"section\":" << text(row.section) << ",\"label\":" << text(row.label)
        << ",\"value\":" << text(row.value) << ",\"state\":" << text(state(row.state)) << "}";
  }
  out << "]}";
  return out.str();
}

std::string file_transfer(const TransferEstimate& estimate) {
  const TransferInputs& inputs = estimate.inputs;
  const TransferEmail email = transfer_email(estimate);
  std::ostringstream out;
  out.precision(15); // byte counts in the trillions stay whole
  out << "{\"size_bytes\":" << inputs.size_bytes << ",\"link_bits_per_second\":" << inputs.link_bits_per_second
      << ",\"link\":" << text(inputs.link_name) << ",\"mtu\":" << inputs.mtu
      << ",\"ip\":" << text(inputs.ip == TransferIp::ipv6 ? "IPv6" : "IPv4")
      << ",\"tcp_timestamps\":" << boolean(inputs.tcp_timestamps) << ",\"share_percent\":" << inputs.share_percent
      << ",\"reduced_to_percent\":" << inputs.reduced_to_percent << ",\"efficiency\":" << estimate.efficiency
      << ",\"line_bytes_per_second\":" << estimate.line_bytes_per_second
      << ",\"data_bytes_per_second\":" << estimate.data_bytes_per_second << ",\"moved_bytes\":" << estimate.moved_bytes
      << ",\"rate_bytes_per_second\":" << estimate.rate_bytes_per_second << ",\"seconds\":" << estimate.seconds
      << ",\"jumbo_seconds\":";
  if (estimate.jumbo_seconds)
    out << *estimate.jumbo_seconds;
  else
    out << "null";
  out << ",\"headline\":" << text(estimate.headline) << ",\"speeds\":[";
  for (std::size_t index = 0; index < estimate.speeds.size(); ++index) {
    const TransferSpeedRow& row = estimate.speeds[index];
    out << (index == 0 ? "" : ",") << "{\"name\":" << text(row.speed.name) << ",\"detail\":" << text(row.speed.detail)
        << ",\"bytes_per_second\":" << row.speed.bytes_per_second << ",\"seconds\":" << row.seconds
        << ",\"lowest\":" << boolean(row.lowest) << "}";
  }
  out << "],\"email\":{\"subject\":" << text(email.subject) << ",\"body\":" << text(email.body) << "}}";
  return out.str();
}

std::string disk_speed_test(const DiskSpeedTestResult& result) {
  const auto optional_number = [](const std::optional<double>& value) {
    std::ostringstream number;
    if (value)
      number << *value;
    else
      number << "null";
    return number.str();
  };
  const auto figures = [&](const SpeedFigures& value) {
    std::ostringstream out;
    out << "{\"mib_per_second\":" << value.mib_per_second << ",\"iops\":" << value.iops << ",\"bytes\":" << value.bytes
        << ",\"average_latency_ms\":" << optional_number(value.average_latency_ms)
        << ",\"p99_latency_ms\":" << optional_number(value.p99_latency_ms) << "}";
    return out.str();
  };
  std::ostringstream out;
  out << "{\"test\":" << text(result.test_id) << ",\"name\":" << text(result.test_name)
      << ",\"simulates\":" << text(result.simulates) << ",\"engine\":" << text(result.engine)
      << ",\"engine_version\":" << text(result.engine_version) << ",\"command_line\":" << text(result.command_line)
      << ",\"file\":" << text(result.file) << ",\"created_file\":" << boolean(result.created_file)
      << ",\"file_removed\":" << boolean(result.file_removed) << ",\"file_bytes\":" << result.file_bytes
      << ",\"block_bytes\":" << result.block_bytes << ",\"seconds_requested\":" << result.seconds_requested
      << ",\"seconds_run\":" << result.seconds_run << ",\"cancelled\":" << boolean(result.cancelled)
      << ",\"divide_by\":" << result.divide_by << ",\"write_percent\":" << result.write_percent
      << ",\"random\":" << boolean(result.random) << ",\"threads\":" << result.threads
      << ",\"outstanding\":" << result.outstanding << ",\"caching\":" << boolean(result.caching)
      << ",\"role\":"
      << text(result.role == StorageRole::repository ? "repository"
              : result.role == StorageRole::source   ? "source"
                                                     : "other")
      << ",\"settings\":" << text(result.settings) << ",\"started_utc\":" << text(time_or_empty(result.started_unix_millis))
      << ",\"ended_utc\":" << text(time_or_empty(result.ended_unix_millis)) << ",\"total\":" << figures(result.total)
      << ",\"read\":" << figures(result.read) << ",\"write\":" << figures(result.write) << "}";
  return out.str();
}

} // namespace tool_json
} // namespace support_assist
