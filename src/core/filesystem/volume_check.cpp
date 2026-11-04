// Volume Check, the parts every platform shares: the Fast Clone rules of the v13 guide, the readers
// for /proc/self/mountinfo, xfs_info's report and pci.ids, and the names of buses and disk kinds.
#include "support_assist/volume_check.hpp"

#include "support_assist/data_files.hpp"
#include "support_assist/strings.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <utility>

namespace support_assist {
namespace volume_detail {
namespace {

std::string unescape_mount(std::string_view text) {
  std::string out;
  for (std::size_t i = 0; i < text.size(); ++i) {
    if (text[i] == '\\' && i + 3 < text.size()) {
      const std::string_view digits = text.substr(i + 1, 3);
      if (digits.size() == 3 && digits.find_first_not_of("01234567") == std::string_view::npos) {
        out += static_cast<char>(std::strtol(std::string(digits).c_str(), nullptr, 8));
        i += 3;
        continue;
      }
    }
    out += text[i];
  }
  return out;
}

std::vector<std::string> fields_of(std::string_view line) {
  std::vector<std::string> fields;
  std::string current;
  for (const char c : line) {
    if (c == ' ') {
      if (!current.empty())
        fields.push_back(std::move(current));
      current.clear();
    } else {
      current += c;
    }
  }
  if (!current.empty())
    fields.push_back(std::move(current));
  return fields;
}

bool contains_path(const std::string& mount_point, const std::string& path) {
  if (mount_point == "/")
    return !path.empty() && path.front() == '/';
  return path == mount_point || (path.size() > mount_point.size() && path.compare(0, mount_point.size(), mount_point) == 0 &&
                                 path[mount_point.size()] == '/');
}

std::uint64_t value_after(std::string_view text, std::string_view key) {
  const std::size_t at = text.find(key);
  if (at == std::string_view::npos)
    return 0;
  return std::strtoull(std::string(text.substr(at + key.size(), 20)).c_str(), nullptr, 10);
}

bool starts_with(std::string_view text, std::string_view prefix) {
  return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

bool is_hex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }
bool is_digit(char c) { return std::isdigit(static_cast<unsigned char>(c)) != 0; }

// A path component that is a prefix followed by a digit: "usb2", "ata3", "session4".
bool has_numbered_component(std::string_view path, std::string_view prefix) {
  for (const std::string& component : split(path, '/')) {
    if (component.size() > prefix.size() && starts_with(component, prefix) && is_digit(component[prefix.size()]))
      return true;
  }
  return false;
}

// "0000:00:17.0"
bool is_pci_function(std::string_view text) {
  if (text.size() != 12 || text[4] != ':' || text[7] != ':' || text[10] != '.')
    return false;
  for (const std::size_t at : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U, 11U}) {
    if (!is_hex(text[at]))
      return false;
  }
  return true;
}

// "8:0:0:3"
bool is_scsi_address(std::string_view text) {
  int numbers = 0;
  bool in_number = false;
  for (const char c : text) {
    if (is_digit(c)) {
      if (!in_number)
        ++numbers;
      in_number = true;
    } else if (c == ':' && in_number) {
      in_number = false;
    } else {
      return false;
    }
  }
  return numbers == 4 && in_number;
}

} // namespace

std::vector<MountEntry> parse_mountinfo(std::string_view text) {
  std::vector<MountEntry> mounts;
  for (const std::string& line : split(text, '\n')) {
    const std::vector<std::string> fields = fields_of(line);
    if (fields.size() < 10)
      continue;
    std::size_t separator = 6;
    while (separator < fields.size() && fields[separator] != "-")
      ++separator;
    if (separator + 2 >= fields.size())
      continue;
    MountEntry entry;
    entry.major_minor = fields[2];
    entry.root = unescape_mount(fields[3]);
    entry.mount_point = unescape_mount(fields[4]);
    entry.options = fields[5];
    entry.file_system = fields[separator + 1];
    entry.source = unescape_mount(fields[separator + 2]);
    if (separator + 3 < fields.size())
      entry.super_options = fields[separator + 3];
    mounts.push_back(std::move(entry));
  }
  return mounts;
}

const MountEntry* mount_for(const std::vector<MountEntry>& mounts, const std::string& path) {
  const MountEntry* best = nullptr;
  for (const MountEntry& entry : mounts) {
    if (!contains_path(entry.mount_point, path))
      continue;
    if (best == nullptr || entry.mount_point.size() >= best->mount_point.size())
      best = &entry; // a later mount on the same point hides the earlier one
  }
  return best;
}

bool is_network_file_system(const std::string& file_system) {
  static const char* const kNetwork[] = {"nfs",        "nfs4",   "cifs",        "smb3",       "smbfs", "fuse.sshfs",
                                         "sshfs",      "9p",     "glusterfs",   "fuse.glusterfs", "ceph", "fuse.ceph",
                                         "afs",        "lustre", "beegfs",      "gpfs"};
  const std::string lower = ascii_lower(file_system);
  return std::find(std::begin(kNetwork), std::end(kNetwork), lower) != std::end(kNetwork);
}

std::vector<MountEntry> listed_mounts(const std::vector<MountEntry>& mounts) {
  // The latest mount on each mount point; an earlier one there is hidden.
  std::vector<MountEntry> visible;
  for (const MountEntry& entry : mounts) {
    const auto same_point = std::find_if(visible.begin(), visible.end(), [&](const MountEntry& other) {
      return other.mount_point == entry.mount_point;
    });
    if (same_point != visible.end())
      visible.erase(same_point);
    visible.push_back(entry);
  }
  std::vector<MountEntry> listed;
  for (const MountEntry& entry : visible) {
    const std::string file_system = ascii_lower(entry.file_system);
    const bool network = is_network_file_system(file_system);
    const bool block = starts_with(entry.source, "/dev/") && file_system != "squashfs";
    if (!network && !block && file_system != "zfs")
      continue;
    if (!network && entry.root != "/" && file_system != "btrfs")
      continue; // a folder of another mount, bound here
    // The same file system mounted in several places is one volume with several mount points.
    const auto same_volume = std::find_if(listed.begin(), listed.end(), [&](const MountEntry& other) {
      return !entry.major_minor.empty() && other.major_minor == entry.major_minor && other.root == entry.root;
    });
    if (same_volume != listed.end())
      continue;
    listed.push_back(entry);
  }
  std::sort(listed.begin(), listed.end(),
            [](const MountEntry& left, const MountEntry& right) { return left.mount_point < right.mount_point; });
  return listed;
}

XfsGeometry parse_xfs_info(std::string_view text) {
  XfsGeometry geometry;
  if (text.find("meta-data=") == std::string_view::npos)
    return geometry;
  geometry.read = true;
  geometry.crc = value_after(text, "crc=") == 1;
  geometry.reflink = value_after(text, "reflink=") == 1;
  for (const std::string& line : split(text, '\n')) {
    if (line.rfind("data", 0) == 0) {
      geometry.block_size = value_after(line, "bsize=");
      break;
    }
  }
  return geometry;
}

std::string format_bytes(std::uint64_t bytes) {
  static const char* const kUnits[] = {"bytes", "KB", "MB", "GB", "TB", "PB"};
  double value = static_cast<double>(bytes);
  std::size_t unit = 0;
  while (value >= 1024.0 && unit + 1 < sizeof(kUnits) / sizeof(kUnits[0])) {
    value /= 1024.0;
    ++unit;
  }
  char text[32] = {};
  if (unit == 0)
    std::snprintf(text, sizeof(text), "%llu bytes", static_cast<unsigned long long>(bytes));
  else
    std::snprintf(text, sizeof(text), "%.1f %s", value, kUnits[unit]);
  return text;
}

std::string storage_bus_name(int bus_type) {
  switch (bus_type) {
  case 1: return "SCSI";
  case 2: return "ATAPI";
  case 3: return "ATA";
  case 4: return "FireWire";
  case 5: return "SSA";
  case 6: return "Fibre Channel";
  case 7: return "USB";
  case 8: return "RAID";
  case 9: return "iSCSI";
  case 10: return "SAS";
  case 11: return "SATA";
  case 12: return "SD";
  case 13: return "MMC";
  case 14: return "Virtual";
  case 15: return "File-backed virtual";
  case 16: return "Storage Spaces";
  case 17: return "NVMe";
  case 18: return "Storage class memory";
  case 19: return "UFS";
  case 20: return "NVMe over Fabrics";
  default: return {};
  }
}

std::string sysfs_bus(std::string_view device_path) {
  const std::string path(device_path);
  if (path.find("/nvme-fabrics/") != std::string::npos)
    return "NVMe over Fabrics";
  if (has_numbered_component(path, "usb"))
    return "USB";
  if (path.find("/rport-") != std::string::npos)
    return "Fibre Channel";
  if (has_numbered_component(path, "session"))
    return "iSCSI";
  if (path.find("/end_device-") != std::string::npos)
    return "SAS";
  if (path.find("/nvme/") != std::string::npos || path.find("/nvme-subsystem/") != std::string::npos)
    return "NVMe";
  if (has_numbered_component(path, "ata"))
    return "SATA";
  if (has_numbered_component(path, "virtio"))
    return "virtio";
  // Hyper-V's VMBus: "MSFT1000:00" (its ACPI id) on current kernels, "VMBUS:00" on older ones.
  if (path.find("/MSFT1000:") != std::string::npos || path.find("/VMBUS:") != std::string::npos ||
      path.find("/vmbus") != std::string::npos)
    return "Hyper-V";
  if (path.find("/xen/") != std::string::npos || path.find("/vbd-") != std::string::npos)
    return "Xen";
  if (path.find("/mmc_host/") != std::string::npos || has_numbered_component(path, "mmc"))
    return "SD/MMC";
  if (path.find("/virtual/block/loop") != std::string::npos)
    return "loop";
  if (path.find("/virtual/block/md") != std::string::npos)
    return "md RAID";
  if (path.find("/virtual/block/nbd") != std::string::npos)
    return "NBD";
  if (path.find("/rbd/") != std::string::npos || path.find("/virtual/block/rbd") != std::string::npos)
    return "Ceph RBD";
  if (path.find("/virtual/block/zram") != std::string::npos)
    return "zram";
  if (has_numbered_component(path, "host"))
    return "SCSI";
  return {};
}

std::string sysfs_lun(std::string_view device_path) {
  std::string lun;
  for (const std::string& component : split(device_path, '/')) {
    if (is_scsi_address(component))
      lun = component.substr(component.rfind(':') + 1);
  }
  return lun;
}

std::string sysfs_component(std::string_view device_path, std::string_view prefix) {
  for (const std::string& component : split(device_path, '/')) {
    if (starts_with(component, prefix))
      return component;
  }
  return {};
}

std::string sysfs_pci_function(std::string_view device_path) {
  std::string function;
  for (const std::string& component : split(device_path, '/')) {
    if (is_pci_function(component))
      function = component;
  }
  return function;
}

std::string kind_for_bus(const std::string& bus, bool removable) {
  if (bus.empty())
    return {};
  if (bus == "USB")
    return removable ? "USB, removable" : "USB";
  if (bus == "iSCSI")
    return "iSCSI LUN";
  if (bus == "Fibre Channel")
    return "Fibre Channel LUN";
  if (bus == "SAS")
    return "SAS disk";
  if (bus == "NVMe over Fabrics")
    return "NVMe-oF namespace";
  if (bus == "Virtual")
    return "Virtual hard disk";
  if (bus == "File-backed virtual")
    return "Mounted image file";
  if (bus == "loop")
    return "Loop device";
  if (bus == "Storage Spaces")
    return "Storage Spaces";
  if (bus == "SD" || bus == "MMC" || bus == "SD/MMC")
    return "SD card";
  if (bus == "virtio" || bus == "Hyper-V" || bus == "Xen" || bus == "VMware")
    return "Virtual disk";
  if (bus == "NBD" || bus == "Ceph RBD")
    return "Network block device";
  if (bus == "md RAID")
    return "Software RAID";
  if (bus == "zram")
    return "Compressed RAM disk";
  if (bus == "FireWire")
    return "FireWire";
  return removable ? "Internal, removable" : "Internal disk";
}

std::string dm_layer(std::string_view uuid) {
  std::string_view rest = uuid;
  // "part1-mpath-..." is a partition of a multipath device.
  if (starts_with(rest, "part")) {
    const std::size_t dash = rest.find('-');
    if (dash != std::string_view::npos)
      rest = rest.substr(dash + 1);
  }
  if (starts_with(rest, "LVM-"))
    return "LVM";
  if (starts_with(rest, "CRYPT-LUKS1-"))
    return "dm-crypt (LUKS1)";
  if (starts_with(rest, "CRYPT-LUKS2-"))
    return "dm-crypt (LUKS2)";
  if (starts_with(rest, "CRYPT-"))
    return "dm-crypt";
  if (starts_with(rest, "mpath-"))
    return "multipath";
  if (starts_with(rest, "VDO-"))
    return "VDO";
  if (starts_with(rest, "stratis-"))
    return "Stratis";
  if (starts_with(rest, "INTEGRITY-"))
    return "dm-integrity";
  if (starts_with(rest, "DMRAID-"))
    return "dmraid";
  return "device mapper";
}

std::string pci_ids_name(std::string_view pci_ids, std::string_view vendor, std::string_view device) {
  if (vendor.size() != 4 || device.size() != 4)
    return {};
  const std::string vendor_key = "\n" + ascii_lower(vendor) + "  ";
  std::size_t at = pci_ids.find(vendor_key);
  if (at == std::string_view::npos)
    return {};
  at += 1;
  std::size_t end = pci_ids.find('\n', at);
  const std::string vendor_name = trim(pci_ids.substr(at + 6, end == std::string_view::npos ? 0 : end - at - 6));
  const std::string device_key = "\t" + ascii_lower(device) + "  ";
  while (end != std::string_view::npos) {
    at = end + 1;
    end = pci_ids.find('\n', at);
    const std::string_view line = pci_ids.substr(at, end == std::string_view::npos ? std::string_view::npos : end - at);
    if (line.empty() || line.front() == '#')
      continue;
    if (line.front() != '\t')
      break; // the next vendor
    if (starts_with(line, device_key))
      return vendor_name + " " + trim(line.substr(device_key.size()));
  }
  return vendor_name;
}

void assess_fast_clone(VolumeInfo& info) {
  const std::string file_system = ascii_lower(info.file_system);
  info.fast_clone = false;
  info.fast_clone_state = FastCloneState::not_applicable;
  info.fast_clone_text.clear();
  if (file_system == "refs") {
    const std::string refs = info.file_system_version.empty() ? std::string("ReFS") : "ReFS " + info.file_system_version;
    if (info.block_cloning) {
      info.fast_clone = true;
      info.fast_clone_state = FastCloneState::can_work;
      info.fast_clone_text = refs + " with block cloning: Fast Clone can work here.";
    } else {
      info.fast_clone_state = FastCloneState::cannot_work;
      info.fast_clone_text = refs + " without block cloning: Fast Clone needs ReFS 3.1 or later.";
    }
    if (info.cluster_size != 0 && info.cluster_size != 65536)
      info.notes.push_back("Cluster size " + format_bytes(info.cluster_size) +
                           ". The guide recommends ReFS formatted with 64 KB clusters for large data volumes.");
    if (info.deduplication_installed)
      info.notes.push_back("Data Deduplication is installed on this server. Fast Clone is not used on a volume "
                           "with deduplication enabled.");
  } else if (file_system == "xfs") {
    info.fast_clone_state = FastCloneState::cannot_work;
    if (!info.xfs_geometry_read) {
      info.fast_clone_state = FastCloneState::not_confirmed;
      info.fast_clone_text = "XFS, but its settings could not be read (xfs_info), so Fast Clone is not confirmed.";
    } else if (!info.reflink) {
      info.fast_clone_text = "XFS without reflink: Fast Clone needs a file system made with "
                             "mkfs.xfs -b size=4096 -m reflink=1,crc=1.";
    } else if (!info.crc) {
      info.fast_clone_text = "XFS without CRC: Fast Clone needs crc=1 with reflink=1.";
    } else if (info.cluster_size < 1024 || info.cluster_size > 4096) {
      info.fast_clone_text = "XFS with reflink, but a block size of " + format_bytes(info.cluster_size) +
                             "; Fast Clone needs 1 KB to 4 KB.";
    } else {
      info.fast_clone = true;
      info.fast_clone_state = FastCloneState::can_work;
      info.fast_clone_text = "XFS with reflink and CRC: Fast Clone can work here.";
    }
  } else if (file_system == "cifs" || file_system == "smb3" || file_system == "smbfs" ||
             (info.network_share && file_system != "nfs" && !is_network_file_system(file_system))) {
    info.fast_clone_state = FastCloneState::depends_on_server;
    info.fast_clone_text = "A network share: Fast Clone depends on the server behind it (SMB 3.1.1 and ReFS 3.1 or "
                           "later on a Windows server).";
  } else {
    return; // Fast Clone is a ReFS and XFS feature; nothing to say about this file system
  }
  const JsonValue& link = data_file("links.json")["links"]["vbr13-fast-clone"];
  info.guide_title = link["title"].as_string();
  info.guide_url = link["url"].as_string();
}

} // namespace volume_detail
} // namespace support_assist
