#pragma once

// What each quick tool does and how to use it, in two lengths: a short line per entry for the tool's
// own window, and the full instructions for its article in the Help window, which F1 opens from the
// tool. Each entry is labelled by what it covers (Manual, Live test, From a log), not numbered: most
// are different ways to use the tool rather than steps in a row.

#include "keyboard_shortcuts.hpp"

#include <string>
#include <vector>

namespace support_assist::gui {

struct QuickToolGuideEntry {
  std::string label;   // what the entry covers
  std::string snippet; // one short line, for the tool's window
  std::string detail;  // the full instructions, for the Help article
  std::string mode{};  // the tool mode it belongs to ("Manual", "Live test"); empty for every mode
};

inline constexpr const char* kTransferModeManual = "Manual";
inline constexpr const char* kTransferModeLive = "Live test";

struct QuickToolGuide {
  std::string what;                        // what the tool checks, in a sentence or two
  std::vector<QuickToolGuideEntry> entries;
  std::string tip;                         // one thing worth knowing; empty for none
};

// The File Transfer Calculator's two percentages: the hover help on their fields and their entries
// in the tool's article.
inline std::string transfer_usable_bandwidth_help() {
  return "How much of the link the Veeam job gets, in percent. Leave 100 when nothing else uses the link. "
         "Lower it when the link is shared, or when a Veeam network traffic rule throttles the job (in the "
         "Veeam console: main menu > Network Traffic Rules > Throttle network traffic to). A rule of 500 Mb/s "
         "on a 1 Gb/s link is 50; two jobs under that rule at once get 25 each. Manual only: in Live test, "
         "the network test measures what the link gives.";
}

inline std::string transfer_compression_help() {
  return "How much of the data is left to send after Veeam compresses it, in percent: 100 is no compression "
         "and gives the longest time. To find it, open a run of the job in the Veeam console (Home > Jobs, "
         "right-click the job > Statistics) and divide Transferred by Read: Read 800 GB and Transferred 400 GB "
         "is 50. Use a run like the transfer being estimated: a full run for a first copy, an incremental "
         "run for the daily changes.";
}

inline QuickToolGuide quick_tool_guide(ShortcutCommand tool) {
  switch (tool) {
  case ShortcutCommand::name_check:
    return {"What a name resolves to on this machine and where the answer came from first: the hosts file or "
            "which DNS server. Each DNS server this machine uses is asked on its own, so servers that disagree "
            "show, and each address is looked up in reverse.",
            {{"Check", "Type a name or an address and press Check.",
              "Type a short name, a full name or an address, such as vbr01 or vbr01.corp.example.com, and press "
              "Check or Enter. The result shows the answer from the hosts file, from each DNS server this "
              "machine uses, and the reverse lookup of each address."},
             {"A port", "Remote Port Checker tests a port on the address found.",
              "To test a port on the address it found, press Remote Port Checker. It opens with the address "
              "filled in."}},
            "Each question is one small packet to a DNS server this machine uses."};
  case ShortcutCommand::local_port_checker:
    return {"What listens on this machine's ports, which program owns each, and whether this machine's "
            "firewall lets connections in, read from this machine's socket tables and firewall rules.",
            {{"Ports", "Type ports or ranges, or pick a Veeam role, and press Check.",
              "Type the ports as a list or ranges (6162, 2500-2510), choose TCP, UDP or both, and press Check. "
              "Or pick a Veeam role's ports from the list, or type a process name or PID and press Its ports."},
             {"A row", "Choose a row for its program and the firewall's verdict.",
              "Choose a row to see the program that owns the port and the firewall's verdict for each network "
              "profile."},
             {"Listener", "Start listener holds a free port open for a test from the other machine.",
              "For a port nothing listens on, press Start listener in the panel on the right. The other machine "
              "can then test the path with the Remote Port Checker before the real service runs. Each "
              "connection shows in the panel as it arrives, and the port's row shows the listener."},
#ifdef _WIN32
             {"Quick scan", "Counts the attempts that reach the port and those that never reach the listener.",
              "Tick Quick scan before starting the listener to count the attempts that arrive at the port and "
              "those that never reach the listener. It needs SAT running as administrator."}},
#else
             {"Quick scan", "Counts the attempts that reach the port and those that never reach the listener.",
              "Tick Quick scan before starting the listener to count the attempts that arrive at the port and "
              "those that never reach the listener. It needs SAT running as root."}},
#endif
            "A test from this machine to itself goes around its own firewall. Only a test from the other machine "
            "proves the path between them."};
  case ShortcutCommand::time_check:
    return {"This machine's clock against its time source: the time zone, the configured source, and the "
            "difference one query to that source reads. Kerberos refuses sign-ins past a 5 minute difference.",
            {{"Clock", "Check asks the configured time source, or a time server you type.",
              "Press Check to ask the configured source, or type a time server first to ask that one. The "
              "result shows the zone, the source and the difference."},
             {"From a log", "Paste a timestamp or its line, choose its log, and press Convert.",
              "To read a time from a log, paste it or its whole line into Timestamp from a log, and choose the "
              "log it came from with Log..., or drop the log on this window. Written in turns to From the log "
              "file, and the offset comes from the log's own header (its UTC time or UTC offset) or the zone it "
              "names. Press Convert."},
             {"Written in", "For a log without its own clock, choose the zone it was written in.",
              "For a log with none of these, choose the zone it was written in from Written in, or type a UTC "
              "offset there."},
             {"Show in", "The same moment in another zone, such as another machine's.",
              "Show in gives the same moment in another zone, such as another machine's, to find the matching "
              "lines in that machine's logs."}},
            "The converter reads Veeam log line prefixes, Unix time, .NET ticks and Windows FILETIME values. A "
            "zone from the list applies its own daylight saving dates for the date read; a typed offset is "
            "used as it is. A header gives the offset when its process started, so a daylight saving change "
            "after it shows at the next header, and the result names the zones where that happened."};
  case ShortcutCommand::file_lock_check:
    return {"Which programs hold a file open, or anything under a folder, with each one's path, services and "
            "start time. Use it when a backup file, a VBK or a log cannot be moved, renamed or deleted, or a "
            "folder cannot be removed.",
            {{"A file", "Type the file's path or press File..., then Check.",
              "Type the file's full path, or press File... to choose it, and press Check or Enter."},
             {"A folder", "A folder checks every file and folder under it.",
              "For a folder and every file and folder under it, type the folder, or press Folder..., and press "
              "Check."}},
#ifdef _WIN32
            "To free the file, close the program listed or stop its service."};
#else
            "To free the file, close the program listed or stop its service. Other accounts' programs are listed "
            "when SAT runs as root."};
#endif
  case ShortcutCommand::volume_check:
    return {"Every volume on this machine and what it sits on: an internal disk with its controller and driver, a "
            "USB drive, an iSCSI or Fibre Channel LUN, or an SMB or NFS share. With each: the file system, free "
            "space, compression and encryption, and on ReFS and XFS whether Veeam's Fast Clone can work there.",
            {{"Volumes", "Choose a volume for its details.",
              "The list fills when the window opens. Choose a volume for its details."},
             {"A folder", "Type a folder or press Browse, then Check.",
              "To check one folder, type it in Folder or press Browse, then Check. The folder's own compression "
              "and encryption show with its volume."},
             {"Fast Clone", "Open the guide shows Veeam's Fast Clone page for ReFS or XFS.",
              "For a ReFS or XFS volume, Open the guide shows Veeam's Fast Clone page."}},
#ifdef _WIN32
            "BitLocker shows when SAT runs as administrator."};
#else
            "A volume on LVM, dm-crypt, multipath or md RAID shows each layer down to the disk."};
#endif
  case ShortcutCommand::service_watch:
    return {"Veeam's services and processes with the ports each one listens on, read again every 2 seconds while "
            "it watches, so what starts, ends or restarts during a job shows as it happens.",
            {{"Watch", "Leave veeam, or type part of a name, and press Start watching.",
              "Leave veeam in Names that hold, or type another part of a name, and press Start watching. Then "
              "start or retry the job."},
             {"Changes", "Each start, end or restart appears below with its time.",
              "Each change appears in the list below with its time. Add to #note keeps the list with the case."},
             {"Its log", "Choose an ended process below, then Its log for the logs written as it ended.",
              "Choose a process or service that ended or restarted in the list of changes and press Its log. It "
              "lists the Veeam logs written in the 2 minutes before the change was seen, newest first; the one "
              "chosen opens in SAT's viewer at the line written just before then. Veeam names its logs by job, "
              "task and service, so the list shows every log written then."}},
            "Its ports opens the Local Port Checker on the selected process."};
  case ShortcutCommand::file_transfer_calculator:
    return {"How long a transfer takes over a network link, worked out one step at a time: the link speed in "
            "bytes, less the Ethernet and TCP/IP overhead, per hour, then the size. Sizes are as Windows counts "
            "them (1 TB = 1,024 GB).",
            {{"Figures", "Type the data, the link's rated speed and the packet size, then press Calculate.",
              "Type the data to move with its unit (MB, GB, TB or PB), the link speed with its unit and the "
              "packet size, then press Calculate. Link throttle, Compression, Network speed and "
              "Storage speed can stay as they are.",
              kTransferModeManual},
             {"Link throttle", "How much of the link the Veeam job gets: 100 when nothing throttles or shares it.",
              transfer_usable_bandwidth_help(), kTransferModeManual},
             {"Network speed", "Optional: what a test between the two machines measured, such as iPerf3.",
              "Network speed takes what a test between the two machines measured, such as an iPerf3 run. It takes "
              "in everything between them, so it is often below the link. The direction does not change it.",
              kTransferModeManual},
             {"Storage speed", "Optional. Backup: the repository's writes. Restore: the slower of its reads and "
                               "production's writes.",
              "Storage speed takes a Disk Speed Test's result. A backup writes to the repository, so use its "
              "Writes; a restore reads from the repository and writes to production storage, so use the slower "
              "of the two. Each has its unit beside it.",
              kTransferModeManual},
             {"Adapter", "Choose this machine's adapter: its link speed and packet size fill in.",
              "Choose the adapter the transfer leaves this machine by. Its link speed and packet size fill the "
              "figures; type the data to move.",
              kTransferModeLive},
             {"Network test", "Start SAT's listener on the other machine (F6), type it and press Measure.",
              "Start SAT's listener on the other machine on the same port (Local Port Checker, F6), type that "
              "machine and press Measure. For a machine without SAT, start an iPerf3 server there and choose "
              "iPerf3 under Using. The test measures the network as it is now, with its other traffic, and "
              "sends generated data that neither machine keeps.",
              kTransferModeLive},
             {"Storage", "Type the Disk Speed Test's Writes (repository) or Reads (source), or open its result.",
              "Type the Disk Speed Test's Writes on the repository or its Reads on the source, or press Open a "
              "result... for the result.json it kept, on this machine or the other.",
              kTransferModeLive},
             {"Compression",
              "The data left after compression: Transferred \xC3\xB7 Read in the job's Statistics. 100 for "
              "none.",
              transfer_compression_help()},
             {"Result", "The time uses the lowest speed; Copy for email gives it as text.",
              "The time uses the lowest of the link and the speeds given. The side panel shows each speed as a "
              "bar, the email text and the terms. Copy for email gives the estimate and how it is worked out "
              "as text for an email; Copy and Add to #note take every section."}},
            ""};
  case ShortcutCommand::object_storage_check:
    return {"An S3-compatible bucket as Veeam reaches it: the endpoint's name and addresses, the TLS certificate "
            "and whether this machine trusts it, the clock, the sign-in and the region, the immutability settings "
            "Veeam's guide asks for, and the key's permissions held against a Veeam product's list. It writes "
            "nothing.",
            {{"Storage", "Choose the storage and its region, then type the bucket.",
              "Choose the storage and its region, then type the bucket, and the endpoint when the storage has "
              "none. Addressing keeps the preset's style unless the storage needs path style."},
             {"Check", "Check runs the checks that send nothing to the storage first.",
              "Press Check: the checks that send no request to the storage run first: the name, the addresses, "
              "the connection and the TLS certificate."},
             {"Keys", "With the keys, Check also sends seven signed requests.",
              "With the access key and the secret key Veeam uses, Check also sends seven signed requests: four "
              "reads of the bucket's settings and three listings that return at most one name each. On a "
              "service that bills requests, the estimate shows first. On Amazon S3, AWS STS and IAM, which bill "
              "nothing, say who the key is and what its policies allow."},
             {"Compare with", "The product whose permission list the key is held against.",
              "Compare with picks the product whose permission list the key is held against. Every listed "
              "product is compared at the end of the result."},
             {"Certificate", "This machine's store, a certificate file, or a SHA-256 fingerprint.",
              "This machine's certificate store is checked on every connection. Where it does not trust the "
              "storage's certificate, choose a certificate file (the storage's own certificate or the CA that "
              "issued it, as PEM, CRT or CER) and press Open..., or choose a SHA-256 fingerprint and type it. "
              "The result says which one trusted the certificate."}},
            "The keys stay in this task for the session only. Experimental: turned on in Settings > General."};
  default:
    return {};
  }
}

} // namespace support_assist::gui
