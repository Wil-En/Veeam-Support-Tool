// Volume Check on Windows. Each volume (FindFirstVolume) with its mount points, file system and
// flags (GetVolumeInformation: block reference counting is ReFS block cloning), cluster size, free
// space, the ReFS version where Windows reports it, and the root folder's compression. What it sits
// on: the disk behind it (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS), the disk's bus, model and SCSI
// address (IOCTL_STORAGE_QUERY_PROPERTY, IOCTL_SCSI_GET_ADDRESS) and the controller above the
// disk in the device tree with its driver (Configuration Manager). BitLocker from
// Win32_EncryptableVolume, which Windows answers only to an administrator. Mapped network drives
// from GetLogicalDrives and WNetGetConnection. All of it read-only, with query-only handles.
#include "support_assist/volume_check.hpp"

#include "support_assist/cancellation.hpp"
#include "support_assist/security.hpp"
#include "support_assist/strings.hpp"
#include "support_assist/wmi.hpp"

#include <windows.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <cfgmgr32.h>
#include <winnetwk.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <map>
#include <memory>
#include <optional>

namespace support_assist {
namespace {

// GUID_DEVINTERFACE_DISK and DEVPKEY_Device_InstanceId, as winioctl.h and devpkey.h define them.
const GUID kDiskInterface = {0x53f56307, 0xb6bf, 0x11d0, {0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}};
const DEVPROPKEY kInstanceIdKey = {{0x78c34fc8, 0x104a, 0x4aca, {0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57}}, 256};

Error volume_error(const std::string& path, const std::string& message, std::int64_t code = 0) {
  Error error;
  error.component = "filesystem";
  error.operation = "read the volume";
  error.source = path;
  error.native_code = code;
  error.message = message;
  return error;
}

struct HandleCloser {
  void operator()(HANDLE handle) const {
    if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
      CloseHandle(handle);
  }
};
using UniqueHandle = std::unique_ptr<void, HandleCloser>;

// A handle that can only ask a device about itself: no read or write access.
UniqueHandle open_for_query(const std::wstring& device) {
  HANDLE handle = CreateFileW(device.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                              OPEN_EXISTING, 0, nullptr);
  return UniqueHandle(handle == INVALID_HANDLE_VALUE ? nullptr : handle);
}

std::wstring without_trailing_backslash(std::wstring path) {
  if (!path.empty() && path.back() == L'\\')
    path.pop_back();
  return path;
}

std::string refs_version(const std::wstring& volume_device) {
  const UniqueHandle volume = open_for_query(volume_device);
  if (!volume)
    return {};
  REFS_VOLUME_DATA_BUFFER data{};
  DWORD returned = 0;
  if (DeviceIoControl(volume.get(), FSCTL_GET_REFS_VOLUME_DATA, nullptr, 0, &data, sizeof(data), &returned, nullptr) ==
      FALSE)
    return {};
  return std::to_string(data.MajorVersion) + "." + std::to_string(data.MinorVersion);
}

bool deduplication_installed() {
  HKEY key = nullptr;
  if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\ddpsvc", 0, KEY_READ, &key) !=
      ERROR_SUCCESS)
    return false;
  RegCloseKey(key);
  return true;
}

std::vector<DWORD> volume_disks(const std::wstring& volume_device) {
  std::vector<DWORD> disks;
  const UniqueHandle volume = open_for_query(volume_device);
  if (!volume)
    return disks;
  std::vector<unsigned char> buffer(sizeof(VOLUME_DISK_EXTENTS) + 15 * sizeof(DISK_EXTENT));
  DWORD returned = 0;
  if (DeviceIoControl(volume.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, nullptr, 0, buffer.data(),
                      static_cast<DWORD>(buffer.size()), &returned, nullptr) == FALSE)
    return disks;
  const auto* extents = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buffer.data());
  for (DWORD index = 0; index < extents->NumberOfDiskExtents && index < 16; ++index) {
    const DWORD disk = extents->Extents[index].DiskNumber;
    if (std::find(disks.begin(), disks.end(), disk) == disks.end())
      disks.push_back(disk);
  }
  return disks;
}

struct StorageFacts {
  bool read = false;
  int bus_type = 0;
  bool removable = false;
  std::string vendor;
  std::string product;
  bool has_address = false;
  SCSI_ADDRESS address{};
};

std::string descriptor_text(const std::vector<unsigned char>& buffer, DWORD offset) {
  if (offset == 0 || offset >= buffer.size())
    return {};
  const char* start = reinterpret_cast<const char*>(buffer.data() + offset);
  const std::size_t limit = buffer.size() - offset;
  std::size_t length = 0;
  while (length < limit && start[length] != '\0')
    ++length;
  return trim(std::string_view(start, length));
}

StorageFacts storage_facts(const std::wstring& device) {
  StorageFacts facts;
  const UniqueHandle handle = open_for_query(device);
  if (!handle)
    return facts;
  STORAGE_PROPERTY_QUERY query{};
  query.PropertyId = StorageDeviceProperty;
  query.QueryType = PropertyStandardQuery;
  std::vector<unsigned char> buffer(1024);
  DWORD returned = 0;
  if (DeviceIoControl(handle.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), buffer.data(),
                      static_cast<DWORD>(buffer.size()), &returned, nullptr) != FALSE &&
      returned >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
    const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
    facts.read = true;
    facts.bus_type = static_cast<int>(descriptor->BusType);
    facts.removable = descriptor->RemovableMedia != FALSE;
    facts.vendor = descriptor_text(buffer, descriptor->VendorIdOffset);
    facts.product = descriptor_text(buffer, descriptor->ProductIdOffset);
  }
  SCSI_ADDRESS address{};
  if (DeviceIoControl(handle.get(), IOCTL_SCSI_GET_ADDRESS, nullptr, 0, &address, sizeof(address), &returned,
                      nullptr) != FALSE) {
    facts.has_address = true;
    facts.address = address;
  }
  return facts;
}

std::string devnode_text(DEVINST node, ULONG property) {
  wchar_t text[512] = {};
  ULONG size = sizeof(text);
  ULONG type = 0;
  if (CM_Get_DevNode_Registry_PropertyW(node, property, &type, text, &size, 0) != CR_SUCCESS || type != REG_SZ)
    return {};
  text[511] = L'\0';
  std::string value = trim(utf8_from_wide(text));
  value.erase(std::unique(value.begin(), value.end(), [](char left, char right) { return left == ' ' && right == ' '; }),
              value.end()); // "WDC  WDS500G2B0A" as the device names itself
  return value;
}

std::string driver_version(const std::string& driver_key) {
  if (driver_key.empty())
    return {};
  const std::wstring key = L"SYSTEM\\CurrentControlSet\\Control\\Class\\" + wide_from_utf8(driver_key);
  wchar_t version[128] = {};
  DWORD size = sizeof(version);
  if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), L"DriverVersion", RRF_RT_REG_SZ, nullptr, version, &size) !=
      ERROR_SUCCESS)
    return {};
  return utf8_from_wide(version);
}

struct DiskNode {
  std::string name;        // the disk's own name in Device Manager
  std::string controller;  // the device above it
  std::string service;     // the controller's driver
  std::string version;     // that driver's version
};

// Each disk number's place in the device tree, read once for a list.
std::map<DWORD, DiskNode> disk_nodes() {
  std::map<DWORD, DiskNode> nodes;
  ULONG size = 0;
  if (CM_Get_Device_Interface_List_SizeW(&size, const_cast<GUID*>(&kDiskInterface), nullptr,
                                         CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS ||
      size == 0)
    return nodes;
  std::vector<wchar_t> list(size);
  if (CM_Get_Device_Interface_ListW(const_cast<GUID*>(&kDiskInterface), nullptr, list.data(), size,
                                    CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
    return nodes;
  for (const wchar_t* path = list.data(); *path != L'\0'; path += wcslen(path) + 1) {
    const UniqueHandle disk = open_for_query(path);
    if (!disk)
      continue;
    STORAGE_DEVICE_NUMBER number{};
    DWORD returned = 0;
    if (DeviceIoControl(disk.get(), IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &number, sizeof(number), &returned,
                        nullptr) == FALSE)
      continue;
    wchar_t instance[512] = {};
    ULONG instance_size = sizeof(instance);
    DEVPROPTYPE type = 0;
    if (CM_Get_Device_Interface_PropertyW(path, &kInstanceIdKey, &type, reinterpret_cast<PBYTE>(instance),
                                          &instance_size, 0) != CR_SUCCESS)
      continue;
    instance[511] = L'\0';
    DEVINST node = 0;
    if (CM_Locate_DevNodeW(&node, instance, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS)
      continue;
    DiskNode entry;
    entry.name = devnode_text(node, CM_DRP_FRIENDLYNAME);
    DEVINST parent = 0;
    if (CM_Get_Parent(&parent, node, 0) == CR_SUCCESS) {
      entry.controller = devnode_text(parent, CM_DRP_FRIENDLYNAME);
      if (entry.controller.empty())
        entry.controller = devnode_text(parent, CM_DRP_DEVICEDESC);
      entry.service = devnode_text(parent, CM_DRP_SERVICE);
      entry.version = driver_version(devnode_text(parent, CM_DRP_DRIVER));
    }
    nodes[number.DeviceNumber] = std::move(entry);
  }
  return nodes;
}

// BitLocker's state per volume GUID path, from Win32_EncryptableVolume.
struct BitLockerStates {
  std::map<std::string, std::string> by_volume; // lower-case "\\?\volume{...}\" -> "BitLocker on"
  std::string unavailable;                        // why no volume has a state
};

std::string bitlocker_text(const std::string& conversion, const std::string& protection) {
  if (conversion == "0")
    return "BitLocker off";
  if (conversion == "1")
    return protection == "1" ? "BitLocker on"
           : protection == "0" ? "BitLocker encrypted, protection off"
                               : "BitLocker encrypted, protection status unknown";
  if (conversion == "2")
    return "BitLocker encrypting";
  if (conversion == "3")
    return "BitLocker decrypting";
  if (conversion == "4")
    return "BitLocker encryption paused";
  if (conversion == "5")
    return "BitLocker decryption paused";
  return protection == "1" ? "BitLocker on" : protection == "0" ? "BitLocker protection off" : std::string();
}

BitLockerStates bitlocker_states() {
  BitLockerStates states;
  // Windows answers Win32_EncryptableVolume only to an administrator, and refuses anyone else after
  // a delay of seconds, so it is asked only when SAT runs elevated.
  const auto security = current_security_context();
  if (!security.ok() || !security.value().elevated) {
    states.unavailable = "Run SAT as administrator to read BitLocker.";
    return states;
  }
  WmiQueryOptions options;
  options.name_space = "root\\CIMV2\\Security\\MicrosoftVolumeEncryption";
  options.query = "SELECT DeviceID, ConversionStatus, ProtectionStatus FROM Win32_EncryptableVolume";
  CancellationSource cancel;
  const auto rows = query_wmi(options, cancel.token());
  if (!rows.ok()) {
    const auto code = static_cast<std::uint32_t>(rows.error().hresult);
    if (code == 0x80041003U || code == 0x80070005U)
      states.unavailable = "Run SAT as administrator to read BitLocker.";
    else if (code == 0x8004100EU)
      states.unavailable = "BitLocker is not installed.";
    else {
      char hex[16] = {};
      std::snprintf(hex, sizeof(hex), "0x%08X", static_cast<unsigned>(code));
      states.unavailable = "BitLocker could not be read: " + rows.error().message + " (" + hex + ")";
    }
    return states;
  }
  for (const WmiRow& row : rows.value()) {
    const auto value = [&](const char* name) {
      const auto found = row.values.find(name);
      return found == row.values.end() ? std::string() : found->second;
    };
    const std::string text = bitlocker_text(value("ConversionStatus"), value("ProtectionStatus"));
    if (!text.empty())
      states.by_volume[ascii_lower(value("DeviceID"))] = text;
  }
  return states;
}

// What a list reads once and every volume in it uses.
struct Context {
  std::map<DWORD, DiskNode> nodes = disk_nodes();
  BitLockerStates bitlocker = bitlocker_states();
  bool deduplication = deduplication_installed();
};

std::vector<std::string> mount_points_of(const std::wstring& volume_name) {
  std::vector<std::string> points;
  DWORD needed = 0;
  std::vector<wchar_t> buffer(MAX_PATH + 1);
  if (GetVolumePathNamesForVolumeNameW(volume_name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()),
                                       &needed) == FALSE) {
    if (GetLastError() != ERROR_MORE_DATA || needed == 0)
      return points;
    buffer.assign(needed, L'\0');
    if (GetVolumePathNamesForVolumeNameW(volume_name.c_str(), buffer.data(), static_cast<DWORD>(buffer.size()),
                                         &needed) == FALSE)
      return points;
  }
  for (const wchar_t* point = buffer.data(); *point != L'\0'; point += wcslen(point) + 1)
    points.push_back(utf8_from_wide(point));
  return points;
}

void read_file_system(VolumeInfo& info, const std::wstring& root) {
  wchar_t label[MAX_PATH + 1] = {};
  wchar_t file_system[MAX_PATH + 1] = {};
  DWORD serial = 0;
  DWORD max_component = 0;
  DWORD flags = 0;
  if (GetVolumeInformationW(root.c_str(), label, MAX_PATH + 1, &serial, &max_component, &flags, file_system,
                            MAX_PATH + 1) != FALSE) {
    info.label = utf8_from_wide(label);
    info.file_system = utf8_from_wide(file_system);
    info.block_cloning = (flags & FILE_SUPPORTS_BLOCK_REFCOUNTING) != 0;
    info.read_only = (flags & FILE_READ_ONLY_VOLUME) != 0;
    info.volume_compressed = (flags & FILE_VOLUME_IS_COMPRESSED) != 0;
  } else {
    const DWORD code = GetLastError();
    info.notes.push_back(code == ERROR_NOT_READY ? "No media in the drive."
                                                 : "Windows did not read this volume (error " + std::to_string(code) + ").");
  }
  DWORD sectors_per_cluster = 0;
  DWORD bytes_per_sector = 0;
  DWORD free_clusters = 0;
  DWORD total_clusters = 0;
  if (GetDiskFreeSpaceW(root.c_str(), &sectors_per_cluster, &bytes_per_sector, &free_clusters, &total_clusters) != FALSE) {
    info.cluster_size = static_cast<std::uint64_t>(sectors_per_cluster) * bytes_per_sector;
    info.logical_sector_bytes = bytes_per_sector;
  }
  ULARGE_INTEGER available{};
  ULARGE_INTEGER total{};
  ULARGE_INTEGER total_free{};
  if (GetDiskFreeSpaceExW(root.c_str(), &available, &total, &total_free) != FALSE) {
    info.free_bytes = available.QuadPart;
    info.total_bytes = total.QuadPart;
  }
  const DWORD attributes = GetFileAttributesW(root.c_str());
  if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_COMPRESSED) != 0)
    info.volume_compressed = true;
}

void read_device(VolumeInfo& info, const std::wstring& volume_device, const std::wstring& root, const Context& context) {
  const UINT drive_type = GetDriveTypeW(root.c_str());
  const std::vector<DWORD> disks = volume_disks(volume_device);
  StorageFacts facts;
  if (!disks.empty())
    facts = storage_facts(L"\\\\.\\PhysicalDrive" + std::to_wstring(disks.front()));
  if (!facts.read)
    facts = storage_facts(volume_device);
  if (facts.read) {
    info.bus = volume_detail::storage_bus_name(facts.bus_type);
    info.removable = facts.removable;
    info.disk = trim(facts.vendor + " " + facts.product);
    const bool san = facts.bus_type == BusTypeiScsi || facts.bus_type == BusTypeFibre || facts.bus_type == BusTypeSas;
    if (san && facts.has_address)
      info.lun = "LUN " + std::to_string(facts.address.Lun) + ", target " + std::to_string(facts.address.TargetId);
  }
  // The partition style and the sector sizes, asked of the volume, then of its first disk.
  if (const UniqueHandle volume = open_for_query(volume_device)) {
    PARTITION_INFORMATION_EX partition{};
    DWORD returned = 0;
    if (DeviceIoControl(volume.get(), IOCTL_DISK_GET_PARTITION_INFO_EX, nullptr, 0, &partition, sizeof(partition),
                        &returned, nullptr) != FALSE)
      info.partition_style = partition.PartitionStyle == PARTITION_STYLE_GPT   ? "GPT"
                             : partition.PartitionStyle == PARTITION_STYLE_MBR ? "MBR"
                                                                              : "";
  }
  const auto read_alignment = [&info](const std::wstring& device) {
    const UniqueHandle handle = open_for_query(device);
    if (!handle)
      return false;
    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageAccessAlignmentProperty;
    query.QueryType = PropertyStandardQuery;
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignment{};
    DWORD returned = 0;
    if (DeviceIoControl(handle.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query), &alignment, sizeof(alignment),
                        &returned, nullptr) == FALSE ||
        returned < sizeof(alignment) || alignment.BytesPerPhysicalSector == 0)
      return false;
    info.physical_sector_bytes = alignment.BytesPerPhysicalSector;
    if (info.logical_sector_bytes == 0)
      info.logical_sector_bytes = alignment.BytesPerLogicalSector;
    return true;
  };
  if (!read_alignment(volume_device) && !disks.empty())
    read_alignment(L"\\\\.\\PhysicalDrive" + std::to_wstring(disks.front()));
  info.kind = volume_detail::kind_for_bus(info.bus, info.removable);
  if (drive_type == DRIVE_CDROM)
    info.kind = "Optical drive";
  else if (drive_type == DRIVE_RAMDISK)
    info.kind = "RAM disk";
  if (!disks.empty()) {
    const auto node = context.nodes.find(disks.front());
    if (node != context.nodes.end()) {
      if (!node->second.name.empty())
        info.disk = node->second.name;
      info.controller = node->second.controller;
      info.driver = trim(node->second.service + " " + node->second.version);
      // A virtual machine's SCSI controller names its hypervisor by its driver.
      const std::string service = ascii_lower(node->second.service);
      if (info.bus == "SCSI" || info.bus == "SAS") {
        const std::string hypervisor = service == "storvsc"                        ? "Hyper-V"
                                       : service == "pvscsi"                       ? "VMware"
                                       : service == "vioscsi" || service == "viostor" ? "virtio"
                                                                                     : "";
        if (!hypervisor.empty()) {
          info.bus = hypervisor;
          info.kind = volume_detail::kind_for_bus(info.bus, info.removable);
        }
      }
      if (service == "mpio") {
        info.layers.push_back("multipath (MPIO)");
        info.kind += ", multipath";
      }
    }
    if (disks.size() > 1)
      info.layers.push_back("spans " + std::to_string(disks.size()) + " disks");
  }
}

void read_encryption(VolumeInfo& info, const std::string& volume_name, const Context& context) {
  const auto state = context.bitlocker.by_volume.find(ascii_lower(volume_name));
  if (state != context.bitlocker.by_volume.end())
    info.encryption = state->second;
  else if (!context.bitlocker.unavailable.empty())
    info.encryption_note = context.bitlocker.unavailable;
}

VolumeInfo read_volume(const std::wstring& volume_name, const Context& context) {
  VolumeInfo info;
  info.device = utf8_from_wide(volume_name);
  info.mount_points = mount_points_of(volume_name);
  if (!info.mount_points.empty())
    info.mount_point = info.mount_points.front();
  const std::wstring root = info.mount_point.empty() ? volume_name : wide_from_utf8(info.mount_point);
  const std::wstring device = without_trailing_backslash(volume_name);
  read_file_system(info, root);
  read_device(info, device, root, context);
  read_encryption(info, info.device, context);
  if (ascii_lower(info.file_system) == "refs")
    info.file_system_version = refs_version(device);
  info.deduplication_installed = context.deduplication;
  volume_detail::assess_fast_clone(info);
  return info;
}

VolumeInfo read_network_drive(const std::wstring& root) {
  VolumeInfo info;
  info.mount_point = utf8_from_wide(root);
  info.mount_points.push_back(info.mount_point);
  info.network_share = true;
  const std::wstring local = without_trailing_backslash(root);
  wchar_t remote[1024] = {};
  DWORD length = 1024;
  if (local.size() == 2 && WNetGetConnectionW(local.c_str(), remote, &length) == NO_ERROR)
    info.remote = utf8_from_wide(remote);
  else if (root.rfind(L"\\\\", 0) == 0)
    info.remote = utf8_from_wide(local);
  read_file_system(info, root);
  info.kind = ascii_lower(info.file_system) == "nfs" ? "NFS share" : "SMB share";
  volume_detail::assess_fast_clone(info);
  return info;
}

void read_folder(VolumeInfo& info, const std::filesystem::path& folder) {
  const DWORD attributes = GetFileAttributesW(folder.c_str());
  if (attributes == INVALID_FILE_ATTRIBUTES)
    return;
  info.folder_attributes_read = true;
  info.folder_compressed = (attributes & FILE_ATTRIBUTE_COMPRESSED) != 0;
  info.folder_encrypted = (attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0;
}

bool by_mount_point(const VolumeInfo& left, const VolumeInfo& right) {
  // Volumes with a mount point first, in order; then those without one.
  if (left.mount_point.empty() != right.mount_point.empty())
    return !left.mount_point.empty();
  return ascii_lower(left.mount_point.empty() ? left.device : left.mount_point) <
         ascii_lower(right.mount_point.empty() ? right.device : right.mount_point);
}

} // namespace

Result<VolumeInfo> check_volume(const std::string& path) {
  if (trim(path).empty())
    return Result<VolumeInfo>::failure(volume_error(path, "no path was given"));
  std::error_code error;
  const std::filesystem::path absolute = std::filesystem::absolute(path_from_utf8(trim(path)), error);
  if (error)
    return Result<VolumeInfo>::failure(volume_error(path, "the path is not valid"));
  const std::string checked = path_to_utf8(absolute);
  if (GetFileAttributesW(absolute.c_str()) == INVALID_FILE_ATTRIBUTES) {
    const DWORD code = GetLastError();
    if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND || code == ERROR_INVALID_NAME ||
        code == ERROR_BAD_NETPATH)
      return Result<VolumeInfo>::failure(volume_error(checked, "the path does not exist", code));
  }
  wchar_t root[MAX_PATH + 1] = {};
  if (GetVolumePathNameW(absolute.c_str(), root, MAX_PATH + 1) == FALSE) {
    const DWORD code = GetLastError();
    return Result<VolumeInfo>::failure(
        volume_error(checked, "Windows did not name the volume (error " + std::to_string(code) + ")", code));
  }
  wchar_t volume_name[MAX_PATH + 1] = {};
  VolumeInfo info;
  if (GetDriveTypeW(root) != DRIVE_REMOTE && std::wstring(root).rfind(L"\\\\", 0) != 0 &&
      GetVolumeNameForVolumeMountPointW(root, volume_name, MAX_PATH + 1) != FALSE) {
    const Context context;
    info = read_volume(volume_name, context);
    info.mount_point = utf8_from_wide(root); // the mount point this folder is under
  } else {
    info = read_network_drive(root);
  }
  info.path = checked;
  ULARGE_INTEGER available{};
  ULARGE_INTEGER total{};
  ULARGE_INTEGER total_free{};
  if (GetDiskFreeSpaceExW(absolute.c_str(), &available, &total, &total_free) != FALSE) {
    info.free_bytes = available.QuadPart; // this folder's view, with any quota
    info.total_bytes = total.QuadPart;
  }
  read_folder(info, absolute);
  return Result<VolumeInfo>::success(std::move(info));
}

Result<std::vector<VolumeInfo>> list_volumes() {
  std::vector<VolumeInfo> volumes;
  wchar_t name[MAX_PATH + 1] = {};
  HANDLE find = FindFirstVolumeW(name, MAX_PATH + 1);
  if (find == INVALID_HANDLE_VALUE) {
    const DWORD code = GetLastError();
    return Result<std::vector<VolumeInfo>>::failure(
        volume_error("", "Windows did not list the volumes (error " + std::to_string(code) + ")", code));
  }
  const Context context;
  do {
    volumes.push_back(read_volume(name, context));
  } while (FindNextVolumeW(find, name, MAX_PATH + 1) != FALSE);
  FindVolumeClose(find);
  const DWORD drives = GetLogicalDrives();
  for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
    if ((drives & (1U << (letter - L'A'))) == 0)
      continue;
    const std::wstring root = std::wstring(1, letter) + L":\\";
    if (GetDriveTypeW(root.c_str()) == DRIVE_REMOTE)
      volumes.push_back(read_network_drive(root));
  }
  std::stable_sort(volumes.begin(), volumes.end(), by_mount_point);
  return Result<std::vector<VolumeInfo>>::success(std::move(volumes));
}

} // namespace support_assist
