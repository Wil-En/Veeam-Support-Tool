// Volume Check on Linux. Each mounted block device and network file system from
// /proc/self/mountinfo, its size and block size (statvfs), for XFS the reflink, CRC and block size
// from xfs_info (started from its system path with the mount point as its only argument), and what
// it sits on from /sys: the device-mapper layers (LVM, dm-crypt, multipath) and md RAID down to the
// disk, the disk's bus, model and SCSI LUN, the iSCSI target or Fibre Channel port, the SCSI host's
// driver, and the PCI controller named from pci.ids when that file is present. A folder's
// compressed and encrypted attributes from statx.
#include "support_assist/volume_check.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/process.hpp"
#include "support_assist/strings.hpp"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#ifdef __linux__
#include <fcntl.h>
#include <sys/sysmacros.h>
#endif

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>

namespace support_assist {
namespace {

Error volume_error(const std::string& path, const std::string& message, std::int64_t code = 0) {
  Error error;
  error.component = "filesystem";
  error.operation = "read the volume";
  error.source = path;
  error.native_code = code;
  error.message = message;
  return error;
}

std::string read_text(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream text;
  text << input.rdbuf();
  return text.str();
}

// "vers=4.2" in "rw,vers=4.2,rsize=1048576" -> "4.2"
std::string option_value(const std::string& options, const std::string& name) {
  for (const std::string& option : split(options, ',')) {
    if (option.rfind(name + "=", 0) == 0)
      return option.substr(name.size() + 1);
  }
  return {};
}

bool has_option(const std::string& options, const std::string& name) {
  for (const std::string& option : split(options, ',')) {
    if (option == name || option.rfind(name + "=", 0) == 0)
      return true;
  }
  return false;
}

#ifdef __linux__
// The first line of a small /sys file, trimmed.
std::string read_line(const std::string& path) {
  std::ifstream input(path);
  std::string line;
  std::getline(input, line);
  return trim(line);
}

std::string real_path(const std::string& path) {
  char resolved[PATH_MAX] = {};
  return realpath(path.c_str(), resolved) == nullptr ? std::string() : std::string(resolved);
}

bool exists(const std::string& path) {
  struct stat info {};
  return stat(path.c_str(), &info) == 0;
}

std::string base_name(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string parent_of(const std::string& path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string::npos || slash == 0 ? std::string() : path.substr(0, slash);
}

// The part of a path up to and including the first component that starts with a prefix.
std::string path_through(const std::string& path, const std::string& prefix) {
  const std::size_t at = path.find("/" + prefix);
  if (at == std::string::npos)
    return {};
  const std::size_t end = path.find('/', at + 1);
  return path.substr(0, end == std::string::npos ? path.size() : end);
}

std::vector<std::string> directory_entries(const std::string& path) {
  std::vector<std::string> names;
  std::error_code error;
  for (std::filesystem::directory_iterator entry(path, error), end; !error && entry != end; entry.increment(error))
    names.push_back(entry->path().filename().string());
  std::sort(names.begin(), names.end());
  return names;
}
#endif

volume_detail::XfsGeometry xfs_geometry(const std::string& mount_point) {
  for (const char* candidate : {"/usr/sbin/xfs_info", "/sbin/xfs_info", "/usr/bin/xfs_info"}) {
    std::error_code error;
    const bool found = std::filesystem::is_regular_file(candidate, error);
    if (error || !found)
      continue;
    ProcessOptions options;
    options.executable = candidate;
    options.arguments = {mount_point};
    options.timeout = std::chrono::milliseconds(15000);
    options.maximum_output_bytes = 256U * 1024U;
    CancellationSource cancel;
    auto run = run_process_capture(options, cancel.token());
    if (run.ok() && run.value().exit_code == 0)
      return volume_detail::parse_xfs_info(run.value().output);
    break;
  }
  return {};
}

// pci.ids, read once for a list and only when a controller needs a name.
class PciNames {
public:
  std::string name(const std::string& vendor, const std::string& device) {
    if (!loaded_) {
      loaded_ = true;
      for (const char* candidate : {"/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids", "/usr/share/pci.ids"}) {
        text_ = read_text(candidate);
        if (!text_.empty())
          break;
      }
    }
    return volume_detail::pci_ids_name(text_, vendor, device);
  }

private:
  bool loaded_ = false;
  std::string text_;
};

#ifdef __linux__
std::string without_hex_prefix(const std::string& text) { return text.rfind("0x", 0) == 0 ? text.substr(2) : text; }

// The disk under a block device, through its device-mapper and md RAID layers.
struct DiskChain {
  std::string disk_path; // /sys/devices/.../block/sda
  std::vector<std::string> layers;
  std::string encryption;
};

void follow_to_disk(std::string device_path, DiskChain& chain, int depth) {
  if (depth > 8 || device_path.empty())
    return;
  if (exists(device_path + "/partition"))
    device_path = parent_of(device_path); // a partition's disk is the directory above it
  if (exists(device_path + "/dm/name")) {
    const std::string layer = volume_detail::dm_layer(read_line(device_path + "/dm/uuid"));
    chain.layers.push_back(layer);
    if (layer.rfind("dm-crypt", 0) == 0 && chain.encryption.empty())
      chain.encryption = layer;
    const std::vector<std::string> slaves = directory_entries(device_path + "/slaves");
    if (!slaves.empty())
      follow_to_disk(real_path(device_path + "/slaves/" + slaves.front()), chain, depth + 1);
    return;
  }
  if (exists(device_path + "/md")) {
    const std::vector<std::string> slaves = directory_entries(device_path + "/slaves");
    chain.layers.push_back("md RAID (" + std::to_string(slaves.size()) + " devices)");
    if (!slaves.empty())
      follow_to_disk(real_path(device_path + "/slaves/" + slaves.front()), chain, depth + 1);
    return;
  }
  chain.disk_path = device_path;
}

std::string block_device_path(const volume_detail::MountEntry& mount) {
  std::string major_minor = mount.major_minor;
  if (major_minor.empty() || major_minor.rfind("0:", 0) == 0) {
    // btrfs and others report an anonymous device here; the source names the block device.
    struct stat info {};
    if (stat(mount.source.c_str(), &info) != 0 || !S_ISBLK(info.st_mode))
      return {};
    major_minor = std::to_string(major(info.st_rdev)) + ":" + std::to_string(minor(info.st_rdev));
  }
  return real_path("/sys/dev/block/" + major_minor);
}

void read_disk(VolumeInfo& info, const DiskChain& chain, PciNames& pci_names) {
  const std::string& disk = chain.disk_path;
  info.layers = chain.layers;
  info.bus = volume_detail::sysfs_bus(disk);
  info.removable = read_line(disk + "/removable") == "1";
  std::string vendor = read_line(disk + "/device/vendor");
  if (vendor == "ATA")
    vendor.clear(); // libata's placeholder; the model names the disk
  const std::string model = read_line(disk + "/device/model");
  info.disk = trim(vendor + " " + (model.empty() ? read_line(disk + "/device/name") : model));
  info.logical_sector_bytes =
      static_cast<std::uint32_t>(std::strtoul(read_line(disk + "/queue/logical_block_size").c_str(), nullptr, 10));
  info.physical_sector_bytes =
      static_cast<std::uint32_t>(std::strtoul(read_line(disk + "/queue/physical_block_size").c_str(), nullptr, 10));
  // The partition table, as udev recorded it for the disk.
  {
    std::ifstream udev("/run/udev/data/b" + read_line(disk + "/dev"));
    std::string line;
    while (std::getline(udev, line)) {
      if (line.rfind("E:ID_PART_TABLE_TYPE=", 0) == 0) {
        const std::string type = line.substr(21);
        info.partition_style = type == "gpt" ? "GPT" : type == "dos" ? "MBR" : type;
        break;
      }
    }
  }

  const std::string name = base_name(disk);
  if (name.rfind("nvme", 0) == 0) {
    const std::string controller = name.substr(0, name.find('n', 4)); // "nvme0n1" -> "nvme0"
    const std::string transport = read_line("/sys/class/nvme/" + controller + "/transport");
    if (!transport.empty() && transport != "pcie") {
      info.bus = "NVMe over Fabrics";
      info.driver = "nvme-" + transport;
      const std::string address = read_line("/sys/class/nvme/" + controller + "/address");
      info.remote = read_line("/sys/class/nvme/" + controller + "/subsysnqn") +
                    (address.empty() ? std::string() : " (" + address + ")");
    }
  }
  const bool san = info.bus == "iSCSI" || info.bus == "Fibre Channel" || info.bus == "SAS";
  const std::string lun = volume_detail::sysfs_lun(disk);
  if (san && !lun.empty())
    info.lun = "LUN " + lun;
  const std::string session = volume_detail::sysfs_component(disk, "session");
  if (info.bus == "iSCSI" && session.size() > 7) {
    info.remote = read_line("/sys/class/iscsi_session/" + session + "/targetname");
    const std::string connection = "/sys/class/iscsi_connection/connection" + session.substr(7) + ":0";
    const std::string address = read_line(connection + "/persistent_address");
    if (!address.empty())
      info.remote += " at " + address + ":" + read_line(connection + "/persistent_port");
  } else if (info.bus == "Fibre Channel") {
    const std::string port = read_line("/sys/class/fc_remote_ports/" + volume_detail::sysfs_component(disk, "rport-") +
                                       "/port_name");
    if (!port.empty())
      info.remote = "target port " + port;
  }

  // The driver: the SCSI host's, else the driver bound to the virtio or PCI device above the disk.
  const std::string host = volume_detail::sysfs_component(disk, "host");
  if (info.driver.empty() && !host.empty())
    info.driver = read_line("/sys/class/scsi_host/" + host + "/proc_name");
  if (info.driver.empty()) {
    const std::string virtio = path_through(disk, "virtio");
    if (!virtio.empty())
      info.driver = base_name(real_path(virtio + "/driver"));
  }
  const std::string function = volume_detail::sysfs_pci_function(disk);
  if (!function.empty()) {
    const std::string pci = "/sys/bus/pci/devices/" + function;
    if (info.driver.empty())
      info.driver = base_name(real_path(pci + "/driver"));
    const std::string vendor_id = without_hex_prefix(read_line(pci + "/vendor"));
    const std::string device_id = without_hex_prefix(read_line(pci + "/device"));
    const std::string controller = pci_names.name(vendor_id, device_id);
    info.controller = controller.empty() ? "PCI device " + vendor_id + ":" + device_id + " at " + function
                                         : controller + " (" + function + ")";
  }
  // A virtual machine's SCSI controller names its hypervisor by its driver.
  if (info.bus == "SCSI") {
    if (info.driver.rfind("storvsc", 0) == 0)
      info.bus = "Hyper-V";
    else if (info.driver == "vmw_pvscsi")
      info.bus = "VMware";
    else if (info.driver == "virtio_scsi")
      info.bus = "virtio";
  }
  info.kind = volume_detail::kind_for_bus(info.bus, info.removable);
  if (std::find(info.layers.begin(), info.layers.end(), "multipath") != info.layers.end())
    info.kind += ", multipath";
}
#endif

void read_statvfs(VolumeInfo& info, const std::string& path) {
  struct statvfs stats {};
  if (statvfs(path.c_str(), &stats) == 0) {
    info.cluster_size = stats.f_bsize;
    info.total_bytes = static_cast<std::uint64_t>(stats.f_blocks) * stats.f_frsize;
    info.free_bytes = static_cast<std::uint64_t>(stats.f_bavail) * stats.f_frsize;
  }
}

VolumeInfo read_mount(const volume_detail::MountEntry& mount, PciNames& pci_names) {
  VolumeInfo info;
  info.mount_point = mount.mount_point;
  info.mount_points.push_back(mount.mount_point);
  info.file_system = mount.file_system;
  info.device = mount.source;
  info.mount_options = mount.options;
  info.read_only = mount.options.rfind("ro", 0) == 0 && (mount.options.size() == 2 || mount.options[2] == ',');
  const std::string file_system = ascii_lower(info.file_system);
  info.network_share = volume_detail::is_network_file_system(file_system);
  read_statvfs(info, mount.mount_point);
  if (info.network_share) {
    info.remote = mount.source;
    info.file_system_version = option_value(mount.super_options, "vers");
    if (file_system == "nfs" || file_system == "nfs4")
      info.kind = "NFS share";
    else if (file_system == "cifs" || file_system == "smb3" || file_system == "smbfs")
      info.kind = "SMB share";
    else
      info.kind = "Network file system (" + info.file_system + ")";
  } else if (file_system == "zfs") {
    info.kind = "ZFS dataset";
  } else {
#ifdef __linux__
    DiskChain chain;
    follow_to_disk(block_device_path(mount), chain, 0);
    if (!chain.disk_path.empty())
      read_disk(info, chain, pci_names);
    info.encryption = chain.encryption.empty() ? std::string("none (no dm-crypt layer)") : chain.encryption;
#else
    (void)pci_names;
#endif
  }
  if (file_system == "btrfs")
    info.volume_compressed = has_option(mount.super_options, "compress") || has_option(mount.super_options, "compress-force");
  if (file_system == "xfs") {
    const auto geometry = xfs_geometry(info.mount_point);
    info.xfs_geometry_read = geometry.read;
    info.reflink = geometry.reflink;
    info.crc = geometry.crc;
    if (geometry.block_size != 0)
      info.cluster_size = geometry.block_size;
  }
  volume_detail::assess_fast_clone(info);
  return info;
}

void read_folder(VolumeInfo& info, const std::string& path) {
#if defined(__linux__) && defined(STATX_ATTR_COMPRESSED) && defined(STATX_ATTR_ENCRYPTED)
  struct statx attributes {};
  if (statx(AT_FDCWD, path.c_str(), 0, STATX_BASIC_STATS, &attributes) != 0)
    return;
  // The mask says which attributes this file system reports at all.
  const auto reported = attributes.stx_attributes_mask & (STATX_ATTR_COMPRESSED | STATX_ATTR_ENCRYPTED);
  info.folder_attributes_read = reported != 0;
  info.folder_compressed = (attributes.stx_attributes & STATX_ATTR_COMPRESSED) != 0;
  info.folder_encrypted = (attributes.stx_attributes & STATX_ATTR_ENCRYPTED) != 0;
#else
  (void)info;
  (void)path;
#endif
}

std::vector<volume_detail::MountEntry> read_mounts() {
  return volume_detail::parse_mountinfo(read_text("/proc/self/mountinfo"));
}

} // namespace

Result<VolumeInfo> check_volume(const std::string& path) {
  if (trim(path).empty())
    return Result<VolumeInfo>::failure(volume_error(path, "no path was given"));
  char resolved[PATH_MAX] = {};
  if (realpath(trim(path).c_str(), resolved) == nullptr)
    return Result<VolumeInfo>::failure(volume_error(trim(path), "the path does not exist", errno));
  const std::string checked = resolved;
  const auto mounts = read_mounts();
  VolumeInfo info;
  PciNames pci_names;
  if (const auto* mount = volume_detail::mount_for(mounts, checked)) {
    info = read_mount(*mount, pci_names);
  } else {
    read_statvfs(info, checked);
    volume_detail::assess_fast_clone(info);
  }
  info.path = checked;
  struct statvfs stats {};
  if (statvfs(checked.c_str(), &stats) == 0) { // this folder's view of the space
    info.total_bytes = static_cast<std::uint64_t>(stats.f_blocks) * stats.f_frsize;
    info.free_bytes = static_cast<std::uint64_t>(stats.f_bavail) * stats.f_frsize;
  }
  read_folder(info, checked);
  return Result<VolumeInfo>::success(std::move(info));
}

Result<std::vector<VolumeInfo>> list_volumes() {
  const std::string text = read_text("/proc/self/mountinfo");
  if (text.empty())
    return Result<std::vector<VolumeInfo>>::failure(volume_error("/proc/self/mountinfo", "the mount table could not be read"));
  std::vector<VolumeInfo> volumes;
  PciNames pci_names;
  const auto mounts = volume_detail::parse_mountinfo(text);
  for (const auto& mount : volume_detail::listed_mounts(mounts)) {
    VolumeInfo info = read_mount(mount, pci_names);
    for (const auto& other : mounts) {
      // The same file system mounted elsewhere too.
      if (!mount.major_minor.empty() && other.major_minor == mount.major_minor && other.root == mount.root &&
          std::find(info.mount_points.begin(), info.mount_points.end(), other.mount_point) == info.mount_points.end())
        info.mount_points.push_back(other.mount_point);
    }
    volumes.push_back(std::move(info));
  }
  return Result<std::vector<VolumeInfo>>::success(std::move(volumes));
}

} // namespace support_assist
