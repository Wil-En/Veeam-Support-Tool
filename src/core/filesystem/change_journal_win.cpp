// Reads the NTFS change journal of the volume holding a captured folder (Windows).
//
// The volume is opened for reading only. The journal is queried and read; it is never created,
// resized or deleted. Opening a volume needs administrator rights.
//
// Paths are matched without the volume (\Data\Watched), because Windows cannot name a volume that
// is mounted in a folder by a drive letter. The mount point is put back in front for display.

#include "support_assist/change_journal.hpp"

#include "support_assist/strings.hpp"
#include "support_assist/time.hpp"
#include "support_assist/usn.hpp"
#include "support_assist/uuid.hpp"

#include <windows.h>
#include <winioctl.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace support_assist {
namespace {

class Handle {
public:
  explicit Handle(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}
  ~Handle() {
    if (handle_ != INVALID_HANDLE_VALUE)
      CloseHandle(handle_);
  }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
  HANDLE get() const {
    return handle_;
  }
  bool valid() const {
    return handle_ != INVALID_HANDLE_VALUE;
  }

private:
  HANDLE handle_;
};

constexpr DWORD kShareAll = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

// What Windows says about an error code, without the closing full stop and line break.
std::string windows_error_text(DWORD code) {
  wchar_t* message = nullptr;
  const DWORD length = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                                          FORMAT_MESSAGE_IGNORE_INSERTS,
                                      nullptr, code, 0, reinterpret_cast<LPWSTR>(&message), 0, nullptr);
  std::string text;
  if (length > 0 && message != nullptr)
    text = utf8_from_wide(std::wstring_view(message, length));
  if (message != nullptr)
    LocalFree(message);
  while (!text.empty() && (text.back() == '\r' || text.back() == '\n' || text.back() == ' ' || text.back() == '.'))
    text.pop_back();
  if (text.empty())
    text = "Windows error " + std::to_string(code);
  return text;
}

Error journal_error(std::string operation, std::string message, DWORD code, bool elevation_may_help = false) {
  Error error;
  error.component = "ChangeJournal";
  error.operation = std::move(operation);
  error.native_code = code;
  error.message = std::move(message);
  error.recoverable = true;
  error.elevation_may_help = elevation_may_help;
  error.timestamp_utc = utc_now_iso8601();
  error.correlation_id = make_uuid_v4();
  return error;
}

// The volume holding a folder: its \\?\Volume{...}\ path, and the place it is mounted (a drive
// letter or a folder). Both are empty when the folder is not on a local volume that has them.
struct VolumeNames {
  std::wstring guid;
  std::wstring mount;
};

VolumeNames volume_of(const std::filesystem::path& folder, DWORD& code) {
  code = 0;
  VolumeNames names;
  const std::wstring input = folder.native();
  std::vector<wchar_t> mount(32768U, L'\0');
  if (!GetVolumePathNameW(input.c_str(), mount.data(), static_cast<DWORD>(mount.size()))) {
    code = GetLastError();
    return names;
  }
  wchar_t guid[64] = {};
  if (!GetVolumeNameForVolumeMountPointW(mount.data(), guid, 64)) {
    code = GetLastError();
    return names;
  }
  names.guid = guid;
  names.mount = mount.data();
  return names;
}

// The final path of an open handle without the volume (journal_path_form), empty when Windows
// cannot name it.
std::string final_path(HANDLE handle) {
  std::wstring buffer(512U, L'\0');
  for (int attempt = 0; attempt < 2; ++attempt) {
    const DWORD length = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                   FILE_NAME_NORMALIZED | VOLUME_NAME_NONE);
    if (length == 0)
      return {};
    if (length < buffer.size()) {
      buffer.resize(length);
      return journal_path_form(utf8_from_wide(buffer));
    }
    buffer.assign(static_cast<std::size_t>(length) + 1U, L'\0');
  }
  return {};
}

// The captured folder as the file system spells it and without the volume, so letter case matches
// the paths the journal resolves to.
std::string canonical_folder(const std::filesystem::path& folder, const std::string& mount) {
  Handle opened(CreateFileW(folder.c_str(), FILE_READ_ATTRIBUTES, kShareAll, nullptr, OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  if (opened.valid()) {
    std::string path = final_path(opened.get());
    if (!path.empty())
      return path;
  }
  const std::string typed = journal_path_form(path_to_utf8(folder));
  const std::string relative = journal_volume_relative(typed, mount);
  return relative.empty() ? typed : relative;
}

// The path, without the volume, of a folder that exists now; empty when it does not.
std::string live_folder_path(HANDLE volume_hint, std::uint64_t reference) {
  FILE_ID_DESCRIPTOR descriptor = {};
  descriptor.dwSize = sizeof(descriptor);
  descriptor.Type = FileIdType;
  descriptor.FileId.QuadPart = static_cast<LONGLONG>(reference);
  for (const DWORD access : {static_cast<DWORD>(FILE_READ_ATTRIBUTES), static_cast<DWORD>(0)}) {
    Handle opened(OpenFileById(volume_hint, &descriptor, access, kShareAll, nullptr, FILE_FLAG_BACKUP_SEMANTICS));
    if (opened.valid())
      return final_path(opened.get());
  }
  return {};
}

std::string with_thousands(std::uint64_t value) {
  std::string digits = std::to_string(value);
  for (int index = static_cast<int>(digits.size()) - 3; index > 0; index -= 3)
    digits.insert(static_cast<std::size_t>(index), ",");
  return digits;
}

using RecordHandler = std::function<void(const JournalRecord&)>;

struct ScanLimits {
  std::int64_t end = 0; // records at or after this USN are not read
  std::chrono::steady_clock::time_point deadline;
  std::uint64_t maximum_records = 0; // 0 for no limit
  std::string time_limit_text;
};

struct ScanOutcome {
  std::uint64_t records = 0;
  bool cut_short = false;
  std::string cut_short_reason;
  std::int64_t stop_usn = 0; // every record before this USN was handled
  std::int64_t reached_time = 0; // time of the last record handled
  bool cancelled = false;
};

// Reads the records from `from` up to the limits and hands each one over in USN order.
Result<ScanOutcome> scan_journal(HANDLE volume, std::uint64_t journal_id, std::int64_t from, const ScanLimits& limits,
                                 const CancellationToken& cancel, std::vector<unsigned char>& buffer,
                                 const RecordHandler& handle_record) {
  using Scan = Result<ScanOutcome>;
  ScanOutcome outcome;
  outcome.stop_usn = limits.end;
  std::int64_t cursor = from;
  bool finished = false;
  while (!finished && cursor < limits.end) {
    if (cancel.is_cancelled()) {
      outcome.cancelled = true;
      return Scan::success(std::move(outcome));
    }
    READ_USN_JOURNAL_DATA_V0 request = {};
    request.StartUsn = cursor;
    request.ReasonMask = 0xFFFFFFFFU;
    request.ReturnOnlyOnClose = 0;
    request.Timeout = 0;
    request.BytesToWaitFor = 0;
    request.UsnJournalID = journal_id;
    DWORD returned = 0;
    if (!DeviceIoControl(volume, FSCTL_READ_USN_JOURNAL, &request, sizeof(request), buffer.data(),
                         static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
      const DWORD code = GetLastError();
      if (code == ERROR_JOURNAL_ENTRY_DELETED) {
        return Scan::failure(journal_error(
            "read journal",
            "Windows has overwritten the part of the change journal that covers the capture, so files created and "
            "removed in between cannot be listed.",
            code));
      }
      if (code == ERROR_JOURNAL_DELETE_IN_PROGRESS || code == ERROR_JOURNAL_NOT_ACTIVE) {
        return Scan::failure(journal_error(
            "read journal",
            "The change journal was recreated after the capture, so files created and removed in between cannot be "
            "listed.",
            code));
      }
      return Scan::failure(
          journal_error("read journal", "The change journal could not be read: " + windows_error_text(code) + ".", code));
    }
    if (returned <= sizeof(std::int64_t))
      break;
    std::int64_t next = 0;
    std::memcpy(&next, buffer.data(), sizeof(next));
    const std::vector<JournalRecord> records = decode_usn_records(buffer.data() + sizeof(next), returned - sizeof(next));
    for (const JournalRecord& record : records) {
      if (record.usn >= limits.end) {
        finished = true;
        break;
      }
      ++outcome.records;
      outcome.reached_time = record.time_ticks;
      handle_record(record);
      if (limits.maximum_records != 0U && outcome.records >= limits.maximum_records) {
        outcome.cut_short = true;
        outcome.cut_short_reason = "the limit of " + with_thousands(limits.maximum_records) + " records";
        outcome.stop_usn = record.usn + 1;
        finished = true;
        break;
      }
      if (outcome.records % 1024U == 0U && std::chrono::steady_clock::now() > limits.deadline) {
        outcome.cut_short = true;
        outcome.cut_short_reason = limits.time_limit_text;
        outcome.stop_usn = record.usn + 1;
        finished = true;
        break;
      }
    }
    if (finished)
      break;
    if (next <= cursor)
      break;
    cursor = next;
    if (cursor < limits.end && std::chrono::steady_clock::now() > limits.deadline) {
      outcome.cut_short = true;
      outcome.cut_short_reason = limits.time_limit_text;
      outcome.stop_usn = cursor;
      break;
    }
  }
  return Scan::success(std::move(outcome));
}

} // namespace

ChangeJournalProbe probe_change_journal(const std::filesystem::path& folder) {
  ChangeJournalProbe probe;
  DWORD code = 0;
  const VolumeNames volume = volume_of(folder, code);
  if (volume.guid.empty()) {
    probe.reason = "The change journal is available for folders on local NTFS volumes.";
    return probe;
  }
  const auto state = query_usn_journal(std::filesystem::path(volume.guid));
  if (!state.ok()) {
    if (state.error().elevation_may_help) {
      probe.needs_administrator = true;
      probe.reason = "Reading the change journal needs administrator rights.";
    } else {
      probe.reason = "The change journal could not be opened: " +
                     windows_error_text(static_cast<DWORD>(state.error().native_code)) + ".";
    }
    return probe;
  }
  if (!state.value().eligible) {
    if (state.value().inactive) {
      probe.inactive = true;
      probe.reason = "The NTFS change journal is not active on this volume.";
    } else if (!state.value().filesystem.empty()) {
      probe.reason = "The change journal is read on NTFS volumes; this volume is " + state.value().filesystem + ".";
    } else {
      probe.reason = "The change journal is available for folders on local NTFS volumes.";
    }
    return probe;
  }
  probe.available = true;
  probe.mark.volume = utf8_from_wide(volume.guid);
  probe.mark.journal_id = state.value().journal_id;
  probe.mark.next_usn = state.value().next_usn;
  probe.mark.recorded_utc = utc_now_iso8601();
  return probe;
}

Result<ChangeJournalReadout> read_change_journal(const ChangeJournalWindow& window, const CancellationToken& cancel) {
  using Readout = Result<ChangeJournalReadout>;

  DWORD code = 0;
  const VolumeNames volume = volume_of(window.folder, code);
  if (volume.guid.empty()) {
    return Readout::failure(journal_error(
        "find volume", "The folder is not on a local volume, so the change journal cannot be read.", code));
  }
  if (!journal_path_equal(utf8_from_wide(volume.guid), window.start.volume)) {
    return Readout::failure(journal_error(
        "check volume",
        "The folder is not on the volume the capture was taken from, so the change journal cannot be read.", 0));
  }

  const auto state = query_usn_journal(std::filesystem::path(volume.guid));
  if (!state.ok()) {
    if (state.error().elevation_may_help) {
      return Readout::failure(
          journal_error("open volume", "Run SAT as administrator to read the change journal.", ERROR_ACCESS_DENIED, true));
    }
    const DWORD native = static_cast<DWORD>(state.error().native_code);
    return Readout::failure(
        journal_error("open volume", "The change journal could not be read: " + windows_error_text(native) + ".", native));
  }
  if (!state.value().eligible) {
    return Readout::failure(journal_error(
        "query journal",
        state.value().inactive ? "The NTFS change journal is not active on this volume, so files created and removed in "
                                 "between cannot be listed."
                               : "The change journal is read on NTFS volumes, so files created and removed in between "
                                 "cannot be listed.",
        0));
  }
  const UsnJournalState& journal = state.value();
  if (journal.journal_id != window.start.journal_id || window.start.next_usn > journal.next_usn) {
    return Readout::failure(journal_error(
        "check journal",
        "The change journal was recreated after the capture, so files created and removed in between cannot be listed.",
        0));
  }
  if (window.start.next_usn < journal.first_usn) {
    return Readout::failure(journal_error(
        "check journal",
        "Windows has overwritten the part of the change journal that covers the capture, so files created and removed in "
        "between cannot be listed.",
        0));
  }
  std::int64_t end = journal.next_usn;
  if (window.end_usn > 0 && window.end_usn < end)
    end = window.end_usn;

  std::wstring device = volume.guid;
  while (!device.empty() && device.back() == L'\\')
    device.pop_back();
  Handle volume_handle(CreateFileW(device.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   OPEN_EXISTING, 0, nullptr));
  if (!volume_handle.valid()) {
    code = GetLastError();
    if (code == ERROR_ACCESS_DENIED) {
      return Readout::failure(
          journal_error("open volume", "Run SAT as administrator to read the change journal.", code, true));
    }
    return Readout::failure(
        journal_error("open volume", "The change journal could not be read: " + windows_error_text(code) + ".", code));
  }
  Handle root_handle(CreateFileW(volume.guid.c_str(), FILE_READ_ATTRIBUTES, kShareAll, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  const HANDLE hint = root_handle.valid() ? root_handle.get() : volume_handle.get();

  const std::string mount = journal_path_form(utf8_from_wide(volume.mount));
  JournalAggregator aggregator(canonical_folder(window.folder, mount));
  JournalFolderNames folders([hint](std::uint64_t reference) { return live_folder_path(hint, reference); });
  std::vector<unsigned char> buffer(1U << 20U);
  const auto started = std::chrono::steady_clock::now();
  const std::string time_limit_text = "the time limit of " + std::to_string(window.maximum_seconds) + " seconds";
  ChangeJournalReadout readout;

  // The records of a folder removed in the window come after the records of its children, so the
  // window is read twice: the first pass learns where every folder sat, the second sums.
  ScanLimits first;
  first.end = end;
  first.deadline = started + std::chrono::milliseconds(static_cast<std::int64_t>(window.maximum_seconds) * 400);
  first.maximum_records = window.maximum_records;
  first.time_limit_text = time_limit_text;
  const auto noted = scan_journal(volume_handle.get(), window.start.journal_id, window.start.next_usn, first, cancel,
                                  buffer, [&folders](const JournalRecord& record) { folders.note(record); });
  if (!noted.ok())
    return Readout::failure(noted.error());
  if (noted.value().cancelled) {
    readout.cancelled = true;
    return Readout::success(std::move(readout));
  }

  ScanLimits second;
  second.end = noted.value().stop_usn;
  second.deadline = started + std::chrono::seconds(window.maximum_seconds);
  second.time_limit_text = time_limit_text;
  const auto summed = scan_journal(volume_handle.get(), window.start.journal_id, window.start.next_usn, second, cancel,
                                   buffer, [&folders, &aggregator](const JournalRecord& record) {
                                     aggregator.add(record, folders.path_of(record.parent_reference));
                                   });
  if (!summed.ok())
    return Readout::failure(summed.error());
  if (summed.value().cancelled) {
    readout.cancelled = true;
    return Readout::success(std::move(readout));
  }

  const ScanOutcome& cut = noted.value().cut_short ? noted.value() : summed.value();
  readout.cut_short = noted.value().cut_short || summed.value().cut_short;
  if (readout.cut_short) {
    readout.cut_short_reason = cut.cut_short_reason;
    readout.reached_time = cut.reached_time;
  }
  readout.records_read = summed.value().records;
  readout.changes = aggregator.changes();
  journal_show_volume_paths(readout.changes, mount);
  readout.records_inside = aggregator.records_inside();
  readout.unplaced = aggregator.unplaced();
  readout.dropped = aggregator.dropped();
  return Readout::success(std::move(readout));
}

} // namespace support_assist
