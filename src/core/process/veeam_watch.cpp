// Service and Process Watch, the parts every platform shares: the filter and the difference between
// two snapshots.
#include "support_assist/veeam_watch.hpp"

#include "support_assist/strings.hpp"

#include <cstdio>
#include <iterator>
#include <map>
#include <set>

namespace support_assist {
namespace {

std::string process_key(const WatchItem& item) {
  // A PID is reused; the PID with its start time names one process.
  return std::to_string(item.pid) + ":" + std::to_string(item.started_unix_millis);
}

std::string label(const WatchItem& item) {
  if (item.kind == WatchKind::service)
    return item.display_name.empty() || item.display_name == item.name ? item.name
                                                                        : item.display_name + " (" + item.name + ")";
  return item.name + " (PID " + std::to_string(item.pid) + ")";
}

} // namespace

namespace watch_detail {

bool matches(const WatchItem& item, const std::string& lowered_filter) {
  if (lowered_filter.empty())
    return true;
  return ascii_lower(item.name).find(lowered_filter) != std::string::npos ||
         ascii_lower(item.display_name).find(lowered_filter) != std::string::npos ||
         ascii_lower(item.path).find(lowered_filter) != std::string::npos;
}

std::string listening_text(const std::vector<LocalSocket>& sockets, std::uint32_t pid) {
  if (pid == 0)
    return {};
  std::set<std::uint16_t> tcp;
  std::set<std::uint16_t> udp;
  for (const LocalSocket& socket : sockets) {
    if (socket.pid != pid)
      continue;
    if (socket.protocol == PortProtocol::udp)
      udp.insert(socket.local_port);
    else if (socket.state == "LISTEN")
      tcp.insert(socket.local_port);
  }
  // 2500, 2501, 2502, 6162 -> "2500-2502, 6162"
  const auto runs = [](const std::set<std::uint16_t>& ports) {
    std::string text;
    for (auto at = ports.begin(); at != ports.end();) {
      auto last = at;
      while (std::next(last) != ports.end() && *std::next(last) == *last + 1)
        ++last;
      text += (text.empty() ? "" : ", ") + std::to_string(*at) + (last == at ? "" : "-" + std::to_string(*last));
      at = std::next(last);
    }
    return text;
  };
  std::string text;
  if (!tcp.empty())
    text = "TCP " + runs(tcp);
  if (!udp.empty())
    text += (text.empty() ? "UDP " : "; UDP ") + runs(udp);
  return text;
}

void add_listening_ports(WatchSnapshot& snapshot) {
  bool running = false;
  for (const WatchItem& item : snapshot.items)
    running = running || item.pid != 0;
  if (!running)
    return;
  const auto table = list_local_sockets();
  if (!table.ok())
    return;
  for (WatchItem& item : snapshot.items)
    item.listening = listening_text(table.value().sockets, item.pid);
}

} // namespace watch_detail

std::string format_duration(std::int64_t millis) {
  if (millis < 0)
    millis = 0;
  const std::int64_t seconds = millis / 1000;
  char text[48] = {};
  if (seconds < 60)
    std::snprintf(text, sizeof(text), "%lld s", static_cast<long long>(seconds));
  else if (seconds < 3600)
    std::snprintf(text, sizeof(text), "%lld min %02lld s", static_cast<long long>(seconds / 60),
                  static_cast<long long>(seconds % 60));
  else
    std::snprintf(text, sizeof(text), "%lld h %02lld min", static_cast<long long>(seconds / 3600),
                  static_cast<long long>((seconds / 60) % 60));
  return text;
}

std::vector<WatchEvent> diff_watch(const WatchSnapshot& before, const WatchSnapshot& after) {
  std::vector<WatchEvent> events;
  std::map<std::string, const WatchItem*> old_processes;
  std::map<std::string, const WatchItem*> old_services;
  for (const WatchItem& item : before.items)
    (item.kind == WatchKind::process ? old_processes[process_key(item)] : old_services[item.name]) = &item;
  std::map<std::string, const WatchItem*> new_processes;
  for (const WatchItem& item : after.items) {
    if (item.kind == WatchKind::process)
      new_processes[process_key(item)] = &item;
  }

  const auto add = [&](WatchChange change, const WatchItem& item, std::string previous, std::string text) {
    WatchEvent event;
    event.at_unix_millis = after.taken_unix_millis;
    event.change = change;
    event.item = item;
    event.previous_state = std::move(previous);
    event.text = std::move(text);
    events.push_back(std::move(event));
  };

  for (const WatchItem& item : after.items) {
    if (item.kind == WatchKind::process) {
      if (old_processes.count(process_key(item)) == 0)
        add(WatchChange::started, item, {}, label(item) + " started");
      continue;
    }
    const auto found = old_services.find(item.name);
    if (found == old_services.end()) {
      add(WatchChange::state_changed, item, {}, label(item) + " appeared, " + item.state);
      continue;
    }
    const WatchItem& old = *found->second;
    if (old.state != item.state) {
      add(WatchChange::state_changed, item, old.state, label(item) + ": " + old.state + " to " + item.state);
    } else if (old.pid != 0 && item.pid != 0 && old.pid != item.pid) {
      add(WatchChange::restarted, item, old.state,
          label(item) + " restarted (PID " + std::to_string(old.pid) + " to " + std::to_string(item.pid) + ")");
    }
  }
  for (const WatchItem& item : before.items) {
    if (item.kind != WatchKind::process || new_processes.count(process_key(item)) != 0)
      continue;
    std::string text = label(item) + " ended";
    if (item.started_unix_millis > 0)
      text += " after " + format_duration(after.taken_unix_millis - item.started_unix_millis);
    add(WatchChange::ended, item, "running", text);
  }
  return events;
}

} // namespace support_assist
