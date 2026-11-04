#pragma once

// Volume Check (F9): every volume on this machine, what each one sits on (the disk's bus, its
// controller and driver, a SAN LUN, a network share), its compression and encryption, and whether
// Veeam's Fast Clone can work there, by the v13 guide's rules: ReFS block cloning on Windows (ReFS
// 3.1 or later, 64 KB clusters recommended, not with Windows deduplication), XFS with reflink and
// CRC on Linux (block size 1 KB to 4 KB). A folder's own compression and encryption, and the guide
// page from links.json (docs/PROPOSAL_5.x_CHECKS.md section 9). Read-only.

#include "support_assist/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace support_assist {

// Fast Clone applies only to ReFS, XFS and SMB shares; other file systems get no statement.
enum class FastCloneState { not_applicable, can_work, cannot_work, not_confirmed, depends_on_server };

struct VolumeInfo {
  std::string path;          // the folder checked, made absolute; empty in a list of volumes
  std::string mount_point;   // "D:\", "/mnt/backups"; empty for a volume with no mount point
  std::vector<std::string> mount_points; // Windows: every drive letter and mounted folder
  std::string device;        // volume GUID path or /dev/... device
  std::string label;
  std::string file_system;   // "ReFS", "NTFS", "xfs", "ext4", "nfs4"
  std::string file_system_version; // "3.14" for ReFS, when readable
  std::uint64_t cluster_size = 0;  // bytes: Windows cluster, Linux block size
  std::uint32_t logical_sector_bytes = 0;  // the disk's sector size as the system addresses it
  std::uint32_t physical_sector_bytes = 0; // the sector size the disk writes, 4096 on 512e disks
  std::string partition_style;             // "GPT", "MBR"; empty when not read
  std::uint64_t total_bytes = 0;
  std::uint64_t free_bytes = 0;    // available to this account
  bool network_share = false;
  bool read_only = false;
  bool removable = false;
  // What the volume sits on.
  std::string kind;          // "Internal disk", "USB", "iSCSI LUN", "Fibre Channel LUN", "SMB share", "NFS share"
  std::string bus;           // "NVMe", "SATA", "SAS", "USB", "iSCSI", "Fibre Channel", "virtio"
  std::string disk;          // the disk's vendor and model
  std::string controller;    // "Standard NVM Express Controller"; Linux: from pci.ids, or the PCI address
  std::string driver;        // "stornvme 10.0.26100.1150"; Linux: "ahci", "iscsi_tcp"
  std::string lun;           // "LUN 3" on iSCSI, Fibre Channel and SAS
  std::string remote;        // "\\nas01\backups", "nas01:/export/backups", an iSCSI target or FC port
  std::vector<std::string> layers; // Linux: LVM, dm-crypt, multipath, md RAID between the file system and the disk
  // Compression and encryption.
  bool volume_compressed = false;  // Windows: the root folder is compressed; Linux: btrfs compress option
  std::string encryption;          // "BitLocker on", "BitLocker off", "dm-crypt (LUKS2)", "none (no dm-crypt layer)"
  std::string encryption_note;     // why the encryption state was not read
  bool folder_compressed = false;  // the folder checked: NTFS compression, or the Linux compressed attribute
  bool folder_encrypted = false;   // the folder checked: EFS, or fscrypt
  bool folder_attributes_read = false;
  // Fast Clone.
  bool block_cloning = false;      // Windows reports block reference counting (ReFS)
  bool xfs_geometry_read = false;
  bool reflink = false;
  bool crc = false;
  bool fast_clone = false;         // the file system meets the guide's Fast Clone requirements
  FastCloneState fast_clone_state = FastCloneState::not_applicable;
  std::string fast_clone_text;     // empty when Fast Clone does not apply
  bool deduplication_installed = false; // Windows Data Deduplication on this server
  std::string mount_options;       // Linux
  std::vector<std::string> notes;
  std::string guide_title;
  std::string guide_url;
};

// The volume a folder is on, with the folder's own compression and encryption.
Result<VolumeInfo> check_volume(const std::string& path);
// Every volume: on Windows each local volume, with or without a mount point, and each mapped
// network drive; on Linux each mounted block device and network file system.
Result<std::vector<VolumeInfo>> list_volumes();

namespace volume_detail {
struct MountEntry {
  std::string mount_point;
  std::string file_system;
  std::string source;
  std::string options;       // this mount's options: "rw,relatime"
  std::string super_options; // the file system's: "rw,vers=4.2", "rw,compress=zstd:3"
  std::string root;        // the directory of the file system mounted here: "/" unless a bind mount
  std::string major_minor; // "8:1"; "0:52" for a file system with no block device
};
// /proc/self/mountinfo, with its octal escapes undone.
std::vector<MountEntry> parse_mountinfo(std::string_view text);
// The mount a path is on: the longest mount point that contains it, the latest one mounted.
const MountEntry* mount_for(const std::vector<MountEntry>& mounts, const std::string& path);
// The mounts Volume Check lists: block devices and network file systems, one per mount point,
// without bind mounts of a folder or the read-only images snaps are made of.
std::vector<MountEntry> listed_mounts(const std::vector<MountEntry>& mounts);
bool is_network_file_system(const std::string& file_system);
struct XfsGeometry {
  bool read = false;
  bool crc = false;
  bool reflink = false;
  std::uint64_t block_size = 0;
};
XfsGeometry parse_xfs_info(std::string_view text);
// Fast Clone verdict, text and notes from the fields a platform reader filled.
void assess_fast_clone(VolumeInfo& info);
std::string format_bytes(std::uint64_t bytes);
// Windows STORAGE_BUS_TYPE as a name: 7 -> "USB", 9 -> "iSCSI", 17 -> "NVMe".
std::string storage_bus_name(int bus_type);
// The bus a Linux block device sits on, from its /sys/devices path.
std::string sysfs_bus(std::string_view device_path);
// "8:0:0:3" in a /sys/devices path -> "3"; empty when the path has no SCSI address.
std::string sysfs_lun(std::string_view device_path);
// The component of a /sys/devices path that starts with a prefix: "session4", "rport-2:0-1".
std::string sysfs_component(std::string_view device_path, std::string_view prefix);
// The PCI function in a /sys/devices path nearest the disk: "0000:00:17.0".
std::string sysfs_pci_function(std::string_view device_path);
// What a kind of disk is called from its bus.
std::string kind_for_bus(const std::string& bus, bool removable);
// A device-mapper table's kind from its dm/uuid: "LVM-..." -> "LVM", "CRYPT-LUKS2-..." -> "dm-crypt (LUKS2)".
std::string dm_layer(std::string_view uuid);
// A device's name in the pci.ids database: "Intel Corporation Cannon Lake PCH SATA AHCI Controller".
std::string pci_ids_name(std::string_view pci_ids, std::string_view vendor, std::string_view device);
} // namespace volume_detail

} // namespace support_assist
