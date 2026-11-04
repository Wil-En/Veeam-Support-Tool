#pragma once

// The Environment Review's content, built once for both editions: the case topology, the tree the
// topology pane shows, the report text beneath it, the aligned rendering of a collected
// environment.log, and the table a selected section is shown as.
//
// UTF-8 in and out, no GUI types and "\n" line ends, so the Win32 tree view and the Qt tree widget
// show the same nodes with the same words. Each edition converts at its own edge: the Windows
// edition widens the text and uses "\r\n" for its edit controls.

#include "support_assist/case_workspace.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/system_health.hpp"
#include "support_assist/time.hpp"
#include "support_assist/veeam_log_review.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist::gui::environment {

// One system or component the case evidence shows, and the runs it takes part in.
struct CaseTopologyEntity {
  std::string key;
  std::string display_name;
  std::string role;
  std::string product;
  std::string source_owner_key;
  std::string source_owner_name;
  bool source_owner = false;
  std::vector<std::size_t> run_indices;
};

// One job or activity, and every run of it, in the order the case dashboard lists them.
struct CaseWorkItem {
  std::string key;
  std::string name;
  std::string category;
  std::vector<std::size_t> run_indices;
};

// A node of the topology pane. The detail is what the details pane shows when it is selected.
struct TopologyNode {
  std::string label;
  std::string detail;
  bool expanded = false;
  std::vector<TopologyNode> children;
};

// Characters rather than bytes, for padding and truncating text that may not be ASCII.
inline std::size_t utf8_length(std::string_view text) {
  std::size_t count = 0;
  for (const char byte : text) {
    if ((static_cast<unsigned char>(byte) & 0xC0U) != 0x80U)
      ++count;
  }
  return count;
}

// The first `characters` characters of text, never cutting a character in half.
inline std::string utf8_prefix(std::string_view text, std::size_t characters) {
  std::size_t seen = 0;
  for (std::size_t index = 0; index < text.size(); ++index) {
    if ((static_cast<unsigned char>(text[index]) & 0xC0U) != 0x80U) {
      if (seen == characters)
        return std::string(text.substr(0, index));
      ++seen;
    }
  }
  return std::string(text);
}

inline void append_unique_index(std::vector<std::size_t>& values, std::size_t value) {
  if (std::find(values.begin(), values.end(), value) == values.end())
    values.push_back(value);
}

inline std::string case_work_category(const VeeamJobSession& run) {
  if (run.protection_group_rescan || run.run_kind == "rescan" || run.run_kind == "rescan-index")
    return "Rescan";
  if (run.run_kind == "activity")
    return "Activity";
  const std::string type = ascii_lower(run.job_type + " " + run.job_name);
  if (type.find("plug-in") != std::string::npos || type.find("plugin") != std::string::npos ||
      type.find("sql") != std::string::npos || type.find("rman") != std::string::npos)
    return "Plug-in";
  return "Backup";
}

inline int case_work_category_order(std::string_view category) {
  if (category == "Backup")
    return 0;
  if (category == "Plug-in")
    return 1;
  if (category == "Rescan")
    return 2;
  return 3;
}

inline std::string product_name_for_machine_role(std::string_view role, std::string_view fallback) {
  if (role == "Backup Server")
    return "Veeam Backup & Replication";
  if (role == "Protected Machine - VAW")
    return "Veeam Agent for Microsoft Windows";
  if (role == "Protected Machine - VAL")
    return "Veeam Agent for Linux";
  if (role == "Protected Machine - VAM")
    return "Veeam Agent for Mac";
  if (role == "Protected Machine - AIX")
    return "Veeam Agent for IBM AIX";
  if (role == "Protected Machine - SOLARIS")
    return "Veeam Agent for Oracle Solaris";
  if (role == "SQL Plug-in Host")
    return "Veeam Plug-in for Microsoft SQL Server";
  if (role == "RMAN Plug-in Host")
    return "Veeam Plug-in for Oracle RMAN";
  return std::string(fallback.empty() ? std::string_view("Product not identified") : fallback);
}

inline std::string product_version_for_review_machine(const VeeamLogReviewResult& review,
                                                      const VeeamMachineRecord* machine) {
  if (machine == nullptr)
    return "Version not identified";
  for (const auto& bundle : review.bundles) {
    if (bundle.primary_machine_key == machine->key && !bundle.product_version.empty())
      return bundle.product_version;
  }
  if (machine->summary.product_version && !machine->summary.product_version->value.empty())
    return machine->summary.product_version->value;
  return "Version not identified";
}

inline std::string review_timestamp(const std::optional<std::int64_t>& utc_millis,
                                    std::string_view original) {
  if (utc_millis)
    return readable_utc_from_unix_millis(*utc_millis);
  return std::string(original.empty() ? std::string_view("Unknown time") : original);
}

inline std::vector<CaseTopologyEntity>
build_case_topology_entities(const VeeamLogReviewResult& review) {
  std::vector<CaseTopologyEntity> entities;
  std::map<std::string, std::size_t> by_name;

  const auto add_entity = [&](std::string name, std::string role, std::string product,
                              std::string source_owner_key, std::string source_owner_name,
                              bool source_owner,
                              std::optional<std::size_t> run_index) -> std::size_t {
    if (name.empty())
      name = "Unassigned evidence";
    const std::string folded = ascii_lower(name);
    const auto found = by_name.find(folded);
    if (found != by_name.end()) {
      auto& existing = entities[found->second];
      if (existing.role.empty() || (!existing.source_owner && source_owner))
        existing.role = std::move(role);
      if (existing.product.empty() || existing.product == "Product not identified")
        existing.product = std::move(product);
      if (existing.source_owner_key.empty())
        existing.source_owner_key = std::move(source_owner_key);
      if (existing.source_owner_name.empty())
        existing.source_owner_name = std::move(source_owner_name);
      existing.source_owner = existing.source_owner || source_owner;
      if (run_index)
        append_unique_index(existing.run_indices, *run_index);
      return found->second;
    }
    CaseTopologyEntity entity;
    entity.key = source_owner ? "machine:" + folded : "entity:" + folded;
    entity.display_name = std::move(name);
    entity.role = std::move(role);
    entity.product = std::move(product);
    entity.source_owner_key = std::move(source_owner_key);
    entity.source_owner_name = std::move(source_owner_name);
    entity.source_owner = source_owner;
    if (run_index)
      entity.run_indices.push_back(*run_index);
    by_name[folded] = entities.size();
    entities.push_back(std::move(entity));
    return entities.size() - 1U;
  };

  std::map<std::string, std::string> product_by_source_owner;
  for (const auto& bundle : review.bundles) {
    if (bundle.primary_machine_key.empty() || bundle.product_type.empty())
      continue;
    auto& product = product_by_source_owner[bundle.primary_machine_key];
    if (product.empty() || product == "Unknown")
      product = bundle.product_type;
  }

  for (const auto& machine : review.machines) {
    const std::string name = machine.display_name.empty() ? machine.key : machine.display_name;
    const std::string role = machine.role.empty() ? "Source Machine" : machine.role;
    const auto product_match = product_by_source_owner.find(machine.key);
    const std::string fallback_product = product_match != product_by_source_owner.end()
                                             ? product_match->second
                                             : review.product_type;
    const std::string product = product_name_for_machine_role(role, fallback_product);
    const std::size_t index = add_entity(name, role, product, machine.key, name, true, std::nullopt);
    entities[index].key = machine.key;
  }

  const auto source_name_for = [&](std::string_view key) -> std::string {
    const auto found =
        std::find_if(review.machines.begin(), review.machines.end(),
                     [&](const auto& machine) { return machine.key == key; });
    if (found == review.machines.end())
      return {};
    return found->display_name.empty() ? found->key : found->display_name;
  };

  std::map<std::string, std::size_t> run_by_key;
  for (std::size_t index = 0; index < review.job_sessions.size(); ++index) {
    const auto& run = review.job_sessions[index];
    if (!run.run_key.empty())
      run_by_key[run.run_key] = index;
    if (!run.machine_key.empty()) {
      const auto machine = std::find_if(entities.begin(), entities.end(), [&](const auto& entity) {
        return entity.source_owner && entity.key == run.machine_key;
      });
      if (machine != entities.end())
        append_unique_index(machine->run_indices, index);
    }
    const std::string owner_name = source_name_for(run.machine_key);
    if (!run.machine_name.empty() && ascii_lower(run.machine_name) != ascii_lower(owner_name))
      add_entity(run.machine_name, "Managed Workload", "Veeam-managed workload", run.machine_key,
                 owner_name, false, index);
    if (!run.settings.backup_server.empty())
      add_entity(run.settings.backup_server, "Backup Server", "Veeam Backup & Replication",
                 run.machine_key, owner_name, false, index);
    if (!run.settings.backup_repository.empty())
      add_entity(run.settings.backup_repository, "Repository", "Veeam Repository", run.machine_key,
                 owner_name, false, index);
  }

  for (const auto& machine : review.machines) {
    if (machine.summary.management_server && !machine.summary.management_server->value.empty()) {
      const std::string owner_name = machine.display_name.empty() ? machine.key : machine.display_name;
      add_entity(machine.summary.management_server->value, "Management Server",
                 "Veeam management infrastructure", machine.key, owner_name, false, std::nullopt);
    }
  }

  for (const auto& group : review.job_evidence_groups) {
    const std::string owner_name =
        !group.machine_name.empty() ? group.machine_name : source_name_for(group.machine_key);
    for (const auto& workload : group.workloads) {
      if (workload.empty())
        continue;
      const std::size_t entity_index =
          add_entity(workload, "Managed Workload", "Veeam-managed workload", group.machine_key,
                     owner_name, false, std::nullopt);
      for (const auto& run_key : group.run_keys) {
        const auto run = run_by_key.find(run_key);
        if (run != run_by_key.end())
          append_unique_index(entities[entity_index].run_indices, run->second);
      }
    }
  }

  std::stable_sort(entities.begin(), entities.end(), [](const auto& left, const auto& right) {
    if (left.source_owner != right.source_owner)
      return left.source_owner > right.source_owner;
    if (left.role != right.role)
      return left.role < right.role;
    return ascii_lower(left.display_name) < ascii_lower(right.display_name);
  });
  return entities;
}

inline std::vector<CaseWorkItem> build_case_work_items(const VeeamLogReviewResult& review,
                                                       const CaseTopologyEntity* entity) {
  std::vector<std::size_t> candidate_indices;
  if (entity == nullptr) {
    candidate_indices.resize(review.job_sessions.size());
    for (std::size_t index = 0; index < review.job_sessions.size(); ++index)
      candidate_indices[index] = index;
  } else {
    candidate_indices = entity->run_indices;
    if (candidate_indices.empty() && entity->source_owner) {
      for (std::size_t index = 0; index < review.job_sessions.size(); ++index) {
        if (review.job_sessions[index].machine_key == entity->key)
          candidate_indices.push_back(index);
      }
    }
  }

  std::vector<CaseWorkItem> items;
  std::map<std::string, std::size_t> by_key;
  for (const auto run_index : candidate_indices) {
    if (run_index >= review.job_sessions.size())
      continue;
    const auto& run = review.job_sessions[run_index];
    const std::string category = case_work_category(run);
    const std::string name = !run.job_name.empty()   ? run.job_name
                             : !run.job_type.empty() ? run.job_type
                                                     : "Unnamed activity";
    const std::string key = category + "|" + ascii_lower(name);
    const auto found = by_key.find(key);
    if (found == by_key.end()) {
      CaseWorkItem item;
      item.key = key;
      item.name = name;
      item.category = category;
      item.run_indices.push_back(run_index);
      by_key[key] = items.size();
      items.push_back(std::move(item));
    } else {
      append_unique_index(items[found->second].run_indices, run_index);
    }
  }
  for (auto& item : items) {
    std::stable_sort(item.run_indices.begin(), item.run_indices.end(),
                     [&](std::size_t left, std::size_t right) {
                       const auto& a = review.job_sessions[left];
                       const auto& b = review.job_sessions[right];
                       if (a.start_utc_ms && b.start_utc_ms && *a.start_utc_ms != *b.start_utc_ms)
                         return *a.start_utc_ms > *b.start_utc_ms;
                       if (a.start_utc_ms)
                         return true;
                       if (b.start_utc_ms)
                         return false;
                       return left < right;
                     });
  }
  std::stable_sort(items.begin(), items.end(), [](const auto& left, const auto& right) {
    const int left_order = case_work_category_order(left.category);
    const int right_order = case_work_category_order(right.category);
    if (left_order != right_order)
      return left_order < right_order;
    return ascii_lower(left.name) < ascii_lower(right.name);
  });
  return items;
}

// Tab-separated records as aligned columns, one line each.
inline std::string render_aligned_table(const std::vector<std::string>& lines) {
  std::string out;
  for (const auto& row : align_tab_columns(lines))
    out += row + "\n";
  return out;
}

// The topology of a case: the systems the evidence shows, grouped by what they do, the protection
// flows between them and the protection groups seen.
inline TopologyNode case_topology_tree(const VeeamLogReviewResult& review) {
  const auto topology = build_case_topology_entities(review);
  TopologyNode root;
  root.label = "Observed Veeam Environment";
  {
    std::ostringstream detail;
    detail << "Observed Veeam Environment\n\n"
           << "Systems / components: " << topology.size() << "\n"
           << "Structured runs: " << review.job_sessions.size() << "\n"
           << "Grouped findings: " << review.incidents.size() << "\n"
           << "Source bundles: " << review.bundles.size() << "\n"
           << "Reviewed files: " << review.reviewed_files.size() << "\n";
    root.detail = detail.str();
  }
  root.expanded = true;

  TopologyNode management{"Management / Control", {}, true, {}};
  TopologyNode workloads{"Protected Workloads / Plug-in Hosts", {}, true, {}};
  TopologyNode targets{"Repositories / Targets", {}, true, {}};
  TopologyNode other{"Other Components", {}, false, {}};
  TopologyNode flows_root{"Observed Protection Flows", {}, false, {}};
  TopologyNode groups{"Protection Groups / Rescans", {}, false, {}};

  std::ostringstream management_detail;
  std::ostringstream workloads_detail;
  std::ostringstream targets_detail;
  std::ostringstream other_detail;
  management_detail << "Management / Control\n\n";
  workloads_detail << "Protected Workloads / Plug-in Hosts\n\n";
  targets_detail << "Repositories / Targets\n\n";
  other_detail << "Other Components\n\n";

  for (const auto& entity : topology) {
    std::string label = entity.display_name;
    if (!entity.role.empty())
      label += "  [" + entity.role + "]";
    if (!entity.product.empty())
      label += " - " + entity.product;
    const std::string role = ascii_lower(entity.role + " " + entity.product);
    TopologyNode* parent = &other;
    std::ostringstream* category_detail = &other_detail;
    if (role.find("backup server") != std::string::npos ||
        role.find("management") != std::string::npos ||
        role.find("controller") != std::string::npos) {
      parent = &management;
      category_detail = &management_detail;
    } else if (role.find("repository") != std::string::npos ||
               role.find("target") != std::string::npos) {
      parent = &targets;
      category_detail = &targets_detail;
    } else if (role.find("protected") != std::string::npos ||
               role.find("agent") != std::string::npos ||
               role.find("plug-in") != std::string::npos ||
               role.find("plugin") != std::string::npos ||
               role.find("workload") != std::string::npos) {
      parent = &workloads;
      category_detail = &workloads_detail;
    }
    std::ostringstream detail;
    detail << "System / Component\n\nName: " << entity.display_name
           << "\nRole: " << (entity.role.empty() ? "Unclassified" : entity.role)
           << "\nProduct: " << (entity.product.empty() ? "Not resolved" : entity.product)
           << "\nSource owner: " << (entity.source_owner ? "Yes" : "No")
           << "\nKey: " << entity.key << "\n";
    parent->children.push_back({label, detail.str(), false, {}});
    *category_detail << "- " << label << "\n";
  }
  management.detail = management_detail.str();
  workloads.detail = workloads_detail.str();
  targets.detail = targets_detail.str();
  other.detail = other_detail.str();

  struct FlowAggregate {
    std::string server;
    std::string workload;
    std::string repository;
    std::set<std::string> jobs;
    std::set<std::string> evidence;
    std::size_t runs = 0U;
    std::optional<std::int64_t> last_seen;
    std::string last_seen_original;
  };
  std::map<std::string, FlowAggregate> flows;
  std::set<std::string> seen_groups;
  std::ostringstream group_detail;
  group_detail << "Protection Groups / Rescans\n\n";
  for (const auto& run : review.job_sessions) {
    if (run.protection_group_rescan || !run.protection_group_name.empty()) {
      const std::string group =
          run.protection_group_name.empty() ? run.job_name : run.protection_group_name;
      if (!group.empty() && seen_groups.insert(ascii_lower(group)).second) {
        groups.children.push_back({group, "Protection group / rescan\n\n" + group, false, {}});
        group_detail << "- " << group << "\n";
      }
    }
    const std::string server = run.settings.backup_server;
    const std::string repository = run.settings.backup_repository;
    const std::string workload = !run.machine_name.empty() ? run.machine_name : run.machine_key;
    if (server.empty() && repository.empty())
      continue;
    const std::string key = ascii_lower(server + "|" + workload + "|" + repository);
    auto& flow = flows[key];
    flow.server = server;
    flow.workload = workload.empty() ? "Unassigned workload" : workload;
    flow.repository = repository;
    ++flow.runs;
    if (!run.job_name.empty())
      flow.jobs.insert(run.job_name);
    if (!run.source_path.empty() && flow.evidence.size() < 16U)
      flow.evidence.insert(run.source_path);
    const auto observed = run.completion_utc_ms ? run.completion_utc_ms : run.start_utc_ms;
    if (observed && (!flow.last_seen || *observed > *flow.last_seen)) {
      flow.last_seen = observed;
      flow.last_seen_original =
          run.completion_utc_ms ? run.completion_timestamp_original : run.start_timestamp_original;
    }
  }
  groups.detail = group_detail.str();

  std::ostringstream flows_detail;
  flows_detail << "Observed Protection Flows\n\n";
  for (const auto& [key, flow] : flows) {
    static_cast<void>(key);
    std::string label;
    if (!flow.server.empty())
      label += flow.server + " -> ";
    label += flow.workload;
    if (!flow.repository.empty())
      label += " -> " + flow.repository;
    label += "  [" + std::to_string(flow.runs) + (flow.runs == 1U ? " run]" : " runs]");
    std::ostringstream detail;
    detail << "Observed Protection Flow\n\n"
           << "Management / control: "
           << (flow.server.empty() ? "Not explicitly observed" : flow.server) << "\n"
           << "Workload: " << flow.workload << "\n"
           << "Repository / target: "
           << (flow.repository.empty() ? "Not explicitly observed" : flow.repository) << "\n"
           << "Runs correlated: " << flow.runs << "\n";
    if (flow.last_seen || !flow.last_seen_original.empty())
      detail << "Last observed: " << review_timestamp(flow.last_seen, flow.last_seen_original)
             << "\n";
    if (!flow.jobs.empty()) {
      detail << "\nJobs / activities:\n";
      for (const auto& job : flow.jobs)
        detail << "- " << job << "\n";
    }
    if (!flow.evidence.empty()) {
      detail << "\nEvidence samples:\n";
      for (const auto& source : flow.evidence)
        detail << "- " << source << "\n";
    }
    TopologyNode node{label, detail.str(), false, {}};
    if (!flow.server.empty())
      node.children.push_back({"Management / control: " + flow.server, node.detail, false, {}});
    node.children.push_back({"Workload: " + flow.workload, node.detail, false, {}});
    if (!flow.repository.empty())
      node.children.push_back({"Backup data target: " + flow.repository, node.detail, false, {}});
    flows_root.children.push_back(std::move(node));
    flows_detail << "- " << label << "\n";
  }
  flows_root.detail = flows_detail.str();

  root.children.push_back(std::move(management));
  root.children.push_back(std::move(workloads));
  root.children.push_back(std::move(targets));
  root.children.push_back(std::move(other));
  root.children.push_back(std::move(flows_root));
  root.children.push_back(std::move(groups));
  return root;
}

// The topology of a collected machine snapshot (environment.log, from either edition): the machine,
// each collected category under it, and the retained values under each category.
inline TopologyNode snapshot_topology_tree(std::string_view snapshot) {
  struct SnapshotSection {
    std::string name;
    std::vector<std::string> lines;
    // The four-line preamble each collected command writes: Command/ExitCode/TimedOut/Cancelled.
    // It is provenance, not data, and left in `lines` it became tree rows and table columns
    // alongside the real output.
    std::vector<std::string> provenance;
  };
  std::vector<SnapshotSection> sections;
  std::vector<std::string> metadata;
  std::istringstream input{std::string(snapshot)};
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line.empty())
      continue;
    if (line.front() == '[' && line.back() == ']') {
      sections.push_back({line.substr(1U, line.size() - 2U), {}, {}});
    } else if (!sections.empty()) {
      if (line.starts_with("Command: ") || line.starts_with("ExitCode: ") ||
          line.starts_with("TimedOut: ") || line.starts_with("Cancelled: "))
        sections.back().provenance.push_back(line);
      else
        sections.back().lines.push_back(line);
    } else {
      metadata.push_back(line);
    }
  }

  TopologyNode root;
  root.label = "Collected Machine Snapshot";
  for (const auto& meta : metadata) {
    if (meta.rfind("Machine=", 0) == 0 && meta.size() > 8U) {
      root.label = meta.substr(8U);
      break;
    }
  }
  {
    std::ostringstream detail;
    detail << "Collected Machine Snapshot\n\n";
    for (const auto& meta : metadata)
      detail << meta << "\n";
    detail << "\nCategories: " << sections.size()
           << "\nSelect a category to show every retained value in the right pane.";
    root.detail = detail.str();
  }
  root.expanded = true;

  constexpr std::size_t maximum_tree_children_per_section = 1000U;
  for (const auto& section : sections) {
    std::ostringstream detail;
    detail << section.name << "\n" << std::string(utf8_length(section.name), '=') << "\n";
    // Collected lines stay tab separated, so the detail pane shows them as a grid
    // (environment_detail_table) whose columns fit their values; padded text broke on every long
    // value.
    for (const auto& value : section.lines)
      detail << value << "\n";
    if (section.lines.empty())
      detail << "No values were retained for this category.\n";
    // Provenance is kept and shown below the data, labelled, so an engineer can still see what
    // produced the section without it mixing into the table.
    if (!section.provenance.empty()) {
      detail << "\nHOW THIS WAS COLLECTED\n";
      for (const auto& value : section.provenance)
        detail << value << "\n";
    }

    TopologyNode section_node{section.name, detail.str(), false, {}};
    std::size_t shown = 0U;
    std::size_t entries = 0U;
    for (const auto& value : section.lines) {
      // The collector's names for its fields, not an entry.
      if (trim(value).rfind("Columns:", 0) == 0)
        continue;
      ++entries;
      if (shown >= maximum_tree_children_per_section)
        continue;
      std::string label = value;
      if (utf8_length(label) > 240U)
        label = utf8_prefix(label, 237U) + "...";
      section_node.children.push_back({std::move(label), section.name + "\n\n" + value, false, {}});
      ++shown;
    }
    if (entries > shown) {
      section_node.children.push_back(
          {"Additional entries: open this category for the complete list", section_node.detail,
           false, {}});
    }
    root.children.push_back(std::move(section_node));
  }
  return root;
}

// The report beneath the panes for a case with a saved review.
inline std::string case_environment_report(const CaseWorkspace& workspace,
                                           const VeeamLogReviewResult& review) {
  const auto topology = build_case_topology_entities(review);
  std::ostringstream out;
  out << "CASE ENVIRONMENT REVIEW\n"
      << "Case: " << workspace.case_id << "\n"
      << "Title: " << (workspace.title.empty() ? "(not set)" : workspace.title) << "\n"
      << "Parser profile: " << to_string(review.profile_used) << "\n"
      << "Systems/components: " << topology.size() << "\n"
      << "Structured runs: " << review.job_sessions.size() << "\n"
      << "Grouped findings: " << review.incidents.size() << "\n\n";

  std::map<std::string, const VeeamMachineRecord*> machine_by_key;
  for (const auto& machine : review.machines)
    machine_by_key[machine.key] = &machine;

  const auto evidence_value = [](const std::optional<ReviewEvidence>& value) {
    return value && !value->value.empty() ? value->value : std::string{};
  };

  out << "SOURCE OWNERS / PRIMARY VEEAM SYSTEMS\n";
  std::size_t source_owner_count = 0;
  for (const auto& entity : topology) {
    if (!entity.source_owner)
      continue;
    ++source_owner_count;
    out << "- " << entity.display_name;
    if (!entity.role.empty())
      out << " | " << entity.role;
    if (!entity.product.empty())
      out << " | " << entity.product;
    out << "\n";
    const auto machine = machine_by_key.find(entity.key);
    if (machine != machine_by_key.end()) {
      const auto& summary = machine->second->summary;
      const auto line = [&](std::string_view label, const std::string& value) {
        if (!value.empty())
          out << "    " << label << ": " << value << "\n";
      };
      line("Host", evidence_value(summary.host_name));
      line("Primary IP", evidence_value(summary.primary_ip));
      if (!summary.alternate_ip_addresses.empty()) {
        out << "    Other IPs: ";
        for (std::size_t i = 0; i < summary.alternate_ip_addresses.size(); ++i) {
          if (i)
            out << ", ";
          out << summary.alternate_ip_addresses[i].value;
        }
        out << "\n";
      }
      line("Operating system", evidence_value(summary.operating_system));
      line("Product version", product_version_for_review_machine(review, machine->second));
      line("Assembly version", evidence_value(summary.assembly_version));
      line("Management mode", evidence_value(summary.management_mode));
      line("Management server", evidence_value(summary.management_server));
      line("Private fix", evidence_value(summary.private_fix));
      if (!summary.license_modes.empty()) {
        out << "    License: ";
        for (std::size_t i = 0; i < summary.license_modes.size(); ++i) {
          if (i)
            out << ", ";
          out << summary.license_modes[i].value;
        }
        out << "\n";
      }
      out << "    Evidence sources: " << machine->second->source_paths.size() << "\n";
    }
    out << "    Related structured runs: " << entity.run_indices.size() << "\n";
  }
  if (source_owner_count == 0)
    out << "- No source-owner system was confidently identified.\n";

  out << "\nRELATED WORKLOADS / INFRASTRUCTURE\n";
  std::size_t related_count = 0;
  for (const auto& entity : topology) {
    if (entity.source_owner)
      continue;
    ++related_count;
    out << "- " << entity.display_name;
    if (!entity.role.empty())
      out << " | " << entity.role;
    if (!entity.product.empty())
      out << " | " << entity.product;
    if (!entity.source_owner_name.empty())
      out << " | Source owner: " << entity.source_owner_name;
    out << " | Runs: " << entity.run_indices.size() << "\n";
  }
  if (related_count == 0)
    out << "- No additional workload or infrastructure relationships were retained.\n";

  out << "\nJOB / ACTIVITY INVENTORY\n";
  const auto work = build_case_work_items(review, nullptr);
  for (const auto& item : work) {
    out << "- [" << item.category << "] " << item.name << " | " << item.run_indices.size()
        << (item.run_indices.size() == 1U ? " run" : " runs") << "\n";
    std::map<std::string, std::size_t> statuses;
    for (const auto index : item.run_indices) {
      if (index < review.job_sessions.size())
        ++statuses[review.job_sessions[index].status.empty() ? "Unknown"
                                                             : review.job_sessions[index].status];
    }
    if (!statuses.empty()) {
      out << "    Results: ";
      bool first = true;
      for (const auto& [status, count] : statuses) {
        if (!first)
          out << ", ";
        out << status << "=" << count;
        first = false;
      }
      out << "\n";
    }
  }
  if (work.empty())
    out << "- No structured jobs/activities retained.\n";

  out << "\nOBSERVED INFRASTRUCTURE RELATIONSHIPS\n";
  std::set<std::string> relationships;
  for (const auto& run : review.job_sessions) {
    const std::string workload =
        run.machine_name.empty() ? "Unassigned workload" : run.machine_name;
    if (!run.settings.backup_server.empty())
      relationships.insert(workload + " -> Backup Server: " + run.settings.backup_server);
    if (!run.settings.backup_repository.empty())
      relationships.insert(workload + " -> Repository: " + run.settings.backup_repository);
    if (!run.protection_group_name.empty())
      relationships.insert(workload + " -> Protection Group: " + run.protection_group_name);
  }
  for (const auto& relation : relationships)
    out << "- " << relation << "\n";
  if (relationships.empty())
    out << "- No additional relationship was explicitly observed in the current parser model.\n";

  out << "\nOVERVIEW - OBSERVED PROTECTION FLOW\n";
  const auto system_label = [&](std::string_view name, std::string_view key) {
    const VeeamMachineRecord* matched = nullptr;
    if (!key.empty()) {
      const auto found = machine_by_key.find(std::string(key));
      if (found != machine_by_key.end())
        matched = found->second;
    }
    if (matched == nullptr && !name.empty()) {
      const std::string folded = ascii_lower(name);
      for (const auto& candidate : review.machines) {
        const std::string display =
            candidate.display_name.empty() ? candidate.key : candidate.display_name;
        const std::string host = evidence_value(candidate.summary.host_name);
        if (ascii_lower(display) == folded || (!host.empty() && ascii_lower(host) == folded)) {
          matched = &candidate;
          break;
        }
      }
    }
    std::string label = !name.empty()        ? std::string(name)
                        : matched != nullptr ? (matched->display_name.empty()
                                                    ? matched->key
                                                    : matched->display_name)
                                             : "Unassigned system";
    if (matched != nullptr) {
      const std::string host = evidence_value(matched->summary.host_name);
      const std::string ip = evidence_value(matched->summary.primary_ip);
      std::vector<std::string> aliases;
      if (!host.empty() && ascii_lower(host) != ascii_lower(label))
        aliases.push_back("host=" + host);
      if (!ip.empty())
        aliases.push_back("ip=" + ip);
      for (const auto& alternate : matched->summary.alternate_ip_addresses) {
        if (!alternate.value.empty() && alternate.value != ip)
          aliases.push_back("ip=" + alternate.value);
      }
      if (!aliases.empty()) {
        label += " [";
        for (std::size_t index = 0; index < aliases.size(); ++index) {
          if (index != 0U)
            label += ", ";
          label += aliases[index];
        }
        label += "]";
      }
    }
    return label;
  };

  struct ObservedFlow {
    std::string key;
    std::string workload;
    std::string backup_server;
    std::string repository;
    std::string job;
    std::string transport;
    std::string source_path;
    std::optional<std::int64_t> last_seen;
    std::string last_seen_original;
  };
  std::map<std::string, ObservedFlow> flows;
  for (const auto& run : review.job_sessions) {
    const auto machine = machine_by_key.find(run.machine_key);
    const std::string workload_name =
        !run.machine_name.empty()        ? run.machine_name
        : machine != machine_by_key.end() ? (machine->second->display_name.empty()
                                                 ? machine->second->key
                                                 : machine->second->display_name)
                                          : "Unassigned workload";
    std::string backup_server = run.settings.backup_server;
    if (backup_server.empty() && machine != machine_by_key.end())
      backup_server = evidence_value(machine->second->summary.management_server);
    const std::string repository = run.settings.backup_repository;
    const std::string job = !run.job_name.empty()   ? run.job_name
                            : !run.job_type.empty() ? run.job_type
                                                    : run.run_kind;
    if (backup_server.empty() && repository.empty())
      continue;
    std::string transport;
    const std::string destination_type = ascii_lower(run.settings.destination_type);
    const std::string repository_operation = ascii_lower(run.settings.repository_operation);
    if (destination_type.find("gateway") != std::string::npos ||
        repository_operation.find("gateway") != std::string::npos)
      transport = "Gateway path observed";
    else if (destination_type.find("direct") != std::string::npos ||
             repository_operation.find("direct") != std::string::npos)
      transport = "Direct path observed";
    else
      transport = "Connection mode not identified";
    const std::string key =
        ascii_lower(backup_server + "|" + workload_name + "|" + repository + "|" + job);
    const auto observed = run.completion_utc_ms ? run.completion_utc_ms : run.start_utc_ms;
    auto& flow = flows[key];
    if (flow.key.empty() || (observed && (!flow.last_seen || *observed > *flow.last_seen))) {
      flow.key = key;
      flow.workload = system_label(workload_name, run.machine_key);
      flow.backup_server = backup_server.empty() ? std::string{} : system_label(backup_server, {});
      flow.repository = repository.empty() ? std::string{} : system_label(repository, {});
      flow.job = job;
      flow.transport = transport;
      flow.source_path = run.source_path;
      flow.last_seen = observed;
      flow.last_seen_original = run.completion_timestamp_original.empty()
                                    ? run.start_timestamp_original
                                    : run.completion_timestamp_original;
    }
  }
  if (flows.empty()) {
    out << "- No source-to-target protection path was explicitly resolved by the current parser "
           "model.\n";
  } else {
    std::vector<const ObservedFlow*> ordered;
    ordered.reserve(flows.size());
    for (const auto& [key, flow] : flows)
      ordered.push_back(&flow);
    std::stable_sort(ordered.begin(), ordered.end(), [](const auto* left, const auto* right) {
      if (left->last_seen && right->last_seen && *left->last_seen != *right->last_seen)
        return *left->last_seen > *right->last_seen;
      if (left->last_seen.has_value() != right->last_seen.has_value())
        return left->last_seen.has_value();
      return left->key < right->key;
    });
    for (const auto* flow : ordered) {
      out << "- Job / activity: " << (flow->job.empty() ? "Unnamed activity" : flow->job) << "\n";
      int order = 1;
      if (!flow->backup_server.empty())
        out << "    " << order++ << ". Management / control: " << flow->backup_server << " -> "
            << flow->workload << "\n";
      out << "    " << order++ << ". Workload execution: " << flow->workload << "\n";
      if (!flow->repository.empty())
        out << "    " << order++ << ". Backup data target: " << flow->workload << " -> "
            << flow->repository << "\n";
      out << "    Connection mode: " << flow->transport << "\n";
      if (flow->last_seen || !flow->last_seen_original.empty())
        out << "    Last observed: " << review_timestamp(flow->last_seen, flow->last_seen_original)
            << "\n";
      if (!flow->source_path.empty())
        out << "    Evidence: " << flow->source_path << "\n";
    }
  }

  out << "\nEVIDENCE SOURCES / PARSER OWNERSHIP\n";
  auto saved_state = load_case_review_state(workspace);
  if (saved_state.ok() && !saved_state.value().source_profiles.empty()) {
    for (const auto& source : saved_state.value().source_profiles) {
      out << "- " << source.path << "\n"
          << "    Requested parser: "
          << (source.requested_profile.empty() ? "automatic" : source.requested_profile) << "\n";
      if (!source.detected_profile.empty())
        out << "    Detected parser family: " << source.detected_profile << "\n";
      if (!source.product_type.empty())
        out << "    Product: " << source.product_type << "\n";
      if (!source.product_version.empty())
        out << "    Product version: " << source.product_version << "\n";
      if (!source.source_owner.empty())
        out << "    Source owner: " << source.source_owner << "\n";
    }
  } else {
    out << "- Legacy case state: source-specific parser ownership has not been recorded yet. "
           "Re-analyze or append evidence to populate it.\n";
  }

  out << "\nEVIDENCE COVERAGE\n"
      << "Reviewed files: " << review.reviewed_files.size() << "\n"
      << "Input sources: " << review.input_sources.size() << "\n";
  for (const auto& bundle : review.bundles) {
    out << "- " << (bundle.display_name.empty() ? bundle.source_path : bundle.display_name) << " | "
        << bundle.indexed_files << "/" << bundle.candidate_files << " indexed";
    if (bundle.deferred_files != 0U)
      out << " | " << bundle.deferred_files << " deferred";
    out << "\n";
  }
  return out.str();
}

// A Get-ComputerInfo memory field and the unit its raw value carries. The collected value is shown
// as-is with a readable size appended. Only fields whose unit is documented are listed; a field
// not here is left exactly as collected rather than converted on a guess.
inline std::string computerinfo_size_suffix(std::string_view key, std::string_view value) {
  struct SizeField {
    const char* name;
    std::uint64_t unit_bytes;
  };
  static const SizeField kFields[] = {
      {"CsTotalPhysicalMemory", 1ULL},
      {"CsPhysicallyInstalledMemory", 1024ULL},
      {"OsTotalVisibleMemorySize", 1024ULL},
      {"OsFreePhysicalMemory", 1024ULL},
      {"OsTotalVirtualMemorySize", 1024ULL},
      {"OsFreeVirtualMemory", 1024ULL},
      {"OsInUseVirtualMemory", 1024ULL},
      {"OsTotalSwapSpaceSize", 1024ULL},
      {"OsSizeStoredInPagingFiles", 1024ULL},
      {"OsFreeSpaceInPagingFiles", 1024ULL},
      {"OsMaxProcessMemorySize", 1024ULL},
  };
  std::uint64_t unit = 0;
  for (const auto& field : kFields) {
    if (key == field.name) {
      unit = field.unit_bytes;
      break;
    }
  }
  if (unit == 0 || value.empty())
    return {};
  std::uint64_t number = 0;
  for (const char character : value) {
    if (character < '0' || character > '9')
      return {};  // not a plain integer: left as collected
    number = number * 10U + static_cast<std::uint64_t>(character - '0');
  }
  return "  (" + format_health_bytes(number * unit) + ")";
}

// A "Name : value" line whose name is flush to the left margin. ipconfig's indented
// "   Field . . . : value" lines start with whitespace and are left for the tab aligner.
inline bool split_key_value_line(std::string_view line, std::string& key, std::string& value) {
  if (line.empty() || line.front() == ' ' || line.front() == '\t')
    return false;
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || colon == 0U)
    return false;
  std::string name(line.substr(0, colon));
  while (!name.empty() && name.back() == ' ')
    name.pop_back();
  if (name.empty() || utf8_length(name) > 48U)
    return false;
  const std::string_view rest = line.substr(colon + 1U);
  const std::size_t first = rest.find_first_not_of(' ');
  key = std::move(name);
  value = first == std::string_view::npos ? std::string() : std::string(rest.substr(first));
  return true;
}

// A block of "Name : value" rows with one aligned colon column, the collector's name padding
// removed, and a readable size appended to the memory fields. Get-ComputerInfo pads names to
// about 55 characters, which pushes every value far right and reports memory in bytes.
inline std::string render_key_value_block(const std::vector<std::string>& lines) {
  struct Row {
    bool is_pair = false;
    std::string key;
    std::string value;
    std::string raw;
  };
  std::vector<Row> rows;
  std::size_t width = 0;
  for (const auto& line : lines) {
    std::string key;
    std::string value;
    if (split_key_value_line(line, key, value)) {
      const std::string suffix = computerinfo_size_suffix(key, value);
      if (!suffix.empty())
        value += suffix;
      width = std::max(width, utf8_length(key));
      rows.push_back({true, std::move(key), std::move(value), {}});
    } else {
      rows.push_back({false, {}, {}, line});
    }
  }
  width = std::min<std::size_t>(width, 40U);
  std::string out;
  for (const auto& row : rows) {
    if (!row.is_pair) {
      out += row.raw + "\n";
      continue;
    }
    std::string key = row.key;
    const std::size_t length = utf8_length(key);
    if (length < width)
      key.append(width - length, ' ');
    out += key + " : " + row.value + "\n";
  }
  return out;
}

// A complete SAT_ENVIRONMENT_V2 snapshot, aligned section by section.
//
// A loaded environment.log is one long document of "[Section]" headers followed by tab-separated
// records. Widths are measured per section rather than across the whole file, because a route
// table and an installed-software list share no columns.
inline std::string render_aligned_snapshot(std::string_view snapshot) {
  std::string out;
  std::vector<std::string> pending;
  const auto flush = [&]() {
    if (pending.empty())
      return;
    std::size_t pairs = 0;
    for (const auto& candidate : pending) {
      std::string key;
      std::string value;
      if (split_key_value_line(candidate, key, value))
        ++pairs;
    }
    // A section that is mostly "Name : value" (Get-ComputerInfo, systeminfo, fsutil) renders as
    // an aligned key/value block; tab-separated tables (routes, services, software) keep the tab
    // aligner.
    if (pending.size() >= 3U && pairs * 100U >= pending.size() * 70U)
      out += render_key_value_block(pending);
    else
      out += render_aligned_table(pending);
    pending.clear();
  };

  std::istringstream input{std::string(snapshot)};
  std::string line;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    const bool header = line.size() >= 2U && line.front() == '[' && line.back() == ']';
    if (header || line.empty()) {
      flush();
      out += line + "\n";
      continue;
    }
    // "Columns:" followed by tab-separated names is the collector naming its own fields, written
    // by the Linux capture. The marker is dropped and the names align as the section's first row.
    const std::size_t columns_marker = line.find("Columns:");
    if (columns_marker != std::string::npos && line.find_first_not_of(' ') == columns_marker &&
        pending.empty()) {
      std::string names = line.substr(columns_marker + 8U);
      if (!names.empty() && names.front() == '\t')
        names.erase(names.begin());
      pending.push_back(names);
      continue;
    }
    pending.push_back(line);
  }
  flush();
  return out;
}

namespace detail_table {

// "ifIndex=14" and the like: a short name of letters, digits and a few marks, then "=".
inline bool keyed_segment(std::string_view segment, std::string& key, std::string& value) {
  const std::size_t equals = segment.find('=');
  if (equals == 0 || equals == std::string_view::npos)
    return false;
  const std::string name = trim(segment.substr(0, equals));
  if (name.empty() || name.size() > 32U)
    return false;
  for (const char character : name) {
    const auto byte = static_cast<unsigned char>(character);
    if (!((byte >= '0' && byte <= '9') || (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
          character == '_' || character == '-' || character == '.'))
      return false;
  }
  key = name;
  value = trim(segment.substr(equals + 1U));
  return true;
}

// A field split at ";" into its leading text and its "name=value" pairs, in order.
struct KeyedField {
  std::string text;
  std::vector<std::pair<std::string, std::string>> pairs;
};

inline KeyedField split_keyed_field(std::string_view field) {
  KeyedField split;
  while (!field.empty()) {
    const std::size_t semicolon = field.find(';');
    const std::string_view segment = field.substr(0, semicolon);
    std::string key;
    std::string value;
    if (keyed_segment(segment, key, value)) {
      split.pairs.emplace_back(std::move(key), std::move(value));
    } else {
      const std::string text = trim(segment);
      if (!text.empty())
        split.text += split.text.empty() ? text : "; " + text;
    }
    if (semicolon == std::string_view::npos)
      break;
    field.remove_prefix(semicolon + 1U);
  }
  return split;
}

inline std::string cell(const std::vector<std::string>& row, std::size_t column) {
  return column < row.size() ? row[column] : std::string();
}

// A column that says the same on every row (the record kind: Adapter, Route, Cipher Suite) carries
// nothing a row needs; with three rows or more it is left out, keeping at least two columns.
// Columns of "name=value" pairs stay, since one value on every row is still a finding.
inline void drop_repeated_columns(ParsedTable& table) {
  if (table.rows.size() < 3U)
    return;
  std::vector<bool> keep(table.headers.size(), true);
  std::size_t kept = table.headers.size();
  for (std::size_t column = 0; column < table.headers.size() && kept > 2U; ++column) {
    const std::string first = cell(table.rows.front(), column);
    bool same = true;
    for (const auto& row : table.rows) {
      const std::string value = cell(row, column);
      if (value != first || !split_keyed_field(value).pairs.empty()) {
        same = false;
        break;
      }
    }
    if (same) {
      keep[column] = false;
      --kept;
    }
  }
  if (kept == table.headers.size())
    return;
  ParsedTable reduced;
  reduced.group_breaks = table.group_breaks;
  reduced.tabular = table.tabular;
  for (std::size_t column = 0; column < table.headers.size(); ++column) {
    if (keep[column])
      reduced.headers.push_back(table.headers[column]);
  }
  for (const auto& row : table.rows) {
    std::vector<std::string> values;
    for (std::size_t column = 0; column < table.headers.size(); ++column) {
      if (keep[column])
        values.push_back(cell(row, column));
    }
    reduced.rows.push_back(std::move(values));
  }
  table = std::move(reduced);
}

// A column whose fields are mostly "name=value; name=value" becomes one column per name, after the
// field's own text when it has any.
inline void expand_keyed_columns(ParsedTable& table) {
  struct Plan {
    bool keyed = false;
    bool text = false;
    std::vector<std::string> keys;
  };
  std::vector<Plan> plans(table.headers.size());
  bool any = false;
  for (std::size_t column = 0; column < table.headers.size(); ++column) {
    std::size_t filled = 0;
    std::size_t keyed = 0;
    Plan& plan = plans[column];
    std::map<std::string, std::size_t> seen;
    for (const auto& row : table.rows) {
      const std::string value = cell(row, column);
      if (trim(value).empty())
        continue;
      ++filled;
      const KeyedField split = split_keyed_field(value);
      if (!split.pairs.empty())
        ++keyed;
      if (!split.text.empty())
        plan.text = true;
      for (const auto& [key, unused] : split.pairs) {
        static_cast<void>(unused);
        if (seen[key]++ == 0U)
          plan.keys.push_back(key);
      }
    }
    // The same names on most rows (an adapter's ifIndex, MAC, Link): a list of different settings,
    // one per row, stays one column.
    const bool shared = std::all_of(seen.begin(), seen.end(),
                                    [&](const auto& entry) { return entry.second * 2U >= keyed; });
    plan.keyed = filled != 0U && keyed * 10U >= filled * 8U && plan.keys.size() <= 16U && shared;
    any = any || plan.keyed;
  }
  if (!any)
    return;
  ParsedTable expanded;
  expanded.group_breaks = table.group_breaks;
  expanded.tabular = table.tabular;
  for (std::size_t column = 0; column < table.headers.size(); ++column) {
    const Plan& plan = plans[column];
    if (!plan.keyed || plan.text)
      expanded.headers.push_back(table.headers[column]);
    if (plan.keyed)
      expanded.headers.insert(expanded.headers.end(), plan.keys.begin(), plan.keys.end());
  }
  for (const auto& row : table.rows) {
    std::vector<std::string> values;
    for (std::size_t column = 0; column < table.headers.size(); ++column) {
      const Plan& plan = plans[column];
      const std::string value = cell(row, column);
      if (!plan.keyed) {
        values.push_back(value);
        continue;
      }
      const KeyedField split = split_keyed_field(value);
      if (plan.text)
        values.push_back(split.text);
      for (const auto& key : plan.keys) {
        std::string found;
        for (const auto& [name, pair_value] : split.pairs) {
          if (name == key) {
            found = pair_value;
            break;
          }
        }
        values.push_back(std::move(found));
      }
    }
    expanded.rows.push_back(std::move(values));
  }
  table = std::move(expanded);
}

// Generic names count the columns that remain: Field 1, Field 2, ...
inline void renumber_generic_headers(ParsedTable& table) {
  for (std::size_t column = 0; column < table.headers.size(); ++column) {
    std::string& header = table.headers[column];
    if (header.rfind("Field ", 0) == 0 && header.find_first_not_of("0123456789", 6U) == std::string::npos)
      header = "Field " + std::to_string(column + 1U);
  }
}

} // namespace detail_table

// A selected node's detail parsed as a table, for the grid that replaces the text pane when a
// section is genuinely tabular. The provenance footer is left out, the collector's own column names
// are used where it wrote them, and the section title and its underline are dropped.
inline ParsedTable environment_detail_table(std::string_view detail) {
  std::vector<std::string> lines;
  std::vector<std::string> collector_headers;
  std::istringstream input{std::string(detail)};
  std::string line;
  bool in_provenance = false;
  while (std::getline(input, line)) {
    if (!line.empty() && line.back() == '\r')
      line.pop_back();
    if (line == "HOW THIS WAS COLLECTED") {
      in_provenance = true;
      continue;
    }
    if (in_provenance)
      continue;
    const std::size_t columns_marker = line.find("Columns:");
    if (columns_marker != std::string::npos && line.find_first_not_of(' ') == columns_marker) {
      std::string_view names = std::string_view(line).substr(columns_marker + 8U);
      while (!names.empty()) {
        const std::size_t tab = names.find('\t');
        const std::string_view header = names.substr(0, tab);
        if (!header.empty())
          collector_headers.emplace_back(header);
        if (tab == std::string_view::npos)
          break;
        names.remove_prefix(tab + 1U);
      }
      continue;
    }
    lines.push_back(line);
  }
  if (lines.size() >= 2U && !lines[1].empty() &&
      lines[1].find_first_not_of('=') == std::string::npos) {
    lines.erase(lines.begin(), lines.begin() + 2);
  }
  auto table = parse_collected_table(lines);
  // Only as many as the parser found: a mismatch means the section changed shape, and a header
  // for a column that is not there would be worse than the generic name.
  for (std::size_t column = 0;
       column < collector_headers.size() && column < table.headers.size(); ++column) {
    table.headers[column] = collector_headers[column];
  }
  if (table.tabular) {
    detail_table::drop_repeated_columns(table);
    detail_table::expand_keyed_columns(table);
    detail_table::renumber_generic_headers(table);
  }
  return table;
}

}  // namespace support_assist::gui::environment
