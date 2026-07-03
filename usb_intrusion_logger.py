"""
USB Intrusion Logger — Complete System (FIXED)
===============================================
Features:
  - USB device monitoring + whitelist + alarm
  - File scanning on USB at connection time
  - Bidirectional transfer detection:
      * PC→USB : files created/copied INTO local watched folders FROM USB
                 (watchdog on Downloads/Desktop/Documents/etc.)
      * USB→PC : files appearing on the USB drive (watchdog on drive letter)
                 AND MTP polling for phones without a drive letter
  - Excel log export (auto-updated, VS Code live-refresh compatible)
  - Email alerts for ALL events (authorized + unauthorized)
  - Blocks unauthorized USB devices via WMI
  - Single CSV + Excel log file for everything

FIXES vs original:
  1. Local-folder watchdog now correctly labelled PC→USB
     (you are copying FROM your PC TO USB when a file is created
      in your Downloads/Desktop etc. right after a USB connects)
  2. Baseline snapshot prevents pre-existing files from firing on startup
  3. on_modified removed — only on_created / on_moved are logged
  4. USB-drive watchdog correctly labelled USB→PC
  5. MTP polling via PowerShell for phones without a drive letter
  6. ClipboardMonitor direction fixed to PC→USB
"""

import os
import json
import time
import csv
import smtplib
import winsound
import threading
import hashlib
import ctypes
from ctypes import wintypes
import subprocess
import wmi
import psutil
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from openpyxl import Workbook
from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
from openpyxl.utils import get_column_letter

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    print("[!] watchdog not installed. Transfer detection disabled.")
    print("    Run: pip install watchdog")

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"{CONFIG_FILE} not found!")
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

config = load_config()

# ─────────────────────────────────────────────
# HARDCODED WHITELIST
# ─────────────────────────────────────────────
HARDCODED_WHITELIST = [
    {
        "vendor_id":  "VID_04E8",
        "product_id": "6860",
        "serial":     "R9ZRC0BPX3F"
    }
]

# ─────────────────────────────────────────────
# LOG SETUP
# ─────────────────────────────────────────────
LOG_CSV   = config.get("log_file",   "usb_logs.csv")
LOG_EXCEL = config.get("excel_file", "usb_logs.xlsx")

LOG_HEADERS = [
    "Timestamp",
    "Event",
    "VendorID",
    "ProductID",
    "Serial",
    "DeviceType",
    "FileName",
    "FileSize(KB)",
    "FileType",
    "FileHash(MD5)",
    "Direction",       # USB→PC / PC→USB / ON-DEVICE / -
    "LocalPath",       # full path on PC (if applicable)
]

# Excel style constants
COL_HEADER_FILL   = "2C3E50"
COL_UNAUTH_FILL   = "FADBD8"
COL_AUTH_FILL     = "D5F5E3"
COL_TRANSFER_FILL = "EBF5FB"
COL_WHITE         = "FFFFFF"
COL_RED           = "C0392B"
COL_GREEN         = "1E8449"
COL_BLUE          = "1A5276"
COL_ORANGE        = "D35400"

_excel_lock = threading.Lock()
_csv_lock   = threading.Lock()

def init_log():
    if not os.path.isfile(LOG_CSV):
        with open(LOG_CSV, "w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(LOG_HEADERS)
    export_to_excel()

def write_rows(rows: list):
    """Thread-safe CSV write + immediate Excel export."""
    with _csv_lock:
        with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=LOG_HEADERS)
            for row in rows:
                w.writerow(row)
    export_to_excel()

def make_row(event, device, file_info=None, direction="-", local_path="", device_type="-"):
    fi = file_info or {}
    return {
        "Timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Event":         event,
        "VendorID":      device.get("vendor_id",  "-"),
        "ProductID":     device.get("product_id", "-"),
        "Serial":        device.get("serial",     "-"),
        "DeviceType":    device_type,
        "FileName":      fi.get("name",    "No files found") if file_info else "No files found",
        "FileSize(KB)":  fi.get("size_kb", "-")             if file_info else "-",
        "FileType":      fi.get("type",    "-")             if file_info else "-",
        "FileHash(MD5)": fi.get("hash",    "-")             if file_info else "-",
        "Direction":     direction,
        "LocalPath":     local_path,
    }

def count_data_rows():
    try:
        with _csv_lock:
            with open(LOG_CSV, "r", newline="", encoding="utf-8") as f:
                return sum(1 for _ in csv.reader(f)) - 1
    except Exception:
        return 0

def read_rows_from(offset: int):
    try:
        with open(LOG_CSV, "r", newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))[offset:]
    except Exception:
        return []

# ─────────────────────────────────────────────
# EXCEL EXPORT
# ─────────────────────────────────────────────
def _cell_style(ws, row, col, value,
                fill_hex=None, font_color=COL_WHITE,
                bold=False, wrap=False):
    cell = ws.cell(row=row, column=col, value=value)
    if fill_hex:
        cell.fill = PatternFill("solid", fgColor=fill_hex)
    cell.font = Font(color=font_color, bold=bold, name="Calibri", size=10)
    cell.alignment = Alignment(wrap_text=wrap, vertical="center")
    return cell

def export_to_excel():
    with _excel_lock:
        try:
            wb = Workbook()
            ws = wb.active
            ws.title = "USB Logs"
            ws.sheet_view.showGridLines = True
            ws.row_dimensions[1].height = 22

            thin   = Side(style="thin", color="CCCCCC")
            border = Border(left=thin, right=thin, top=thin, bottom=thin)

            # ── Header row ──
            for ci, h in enumerate(LOG_HEADERS, 1):
                c = _cell_style(ws, 1, ci, h,
                                fill_hex=COL_HEADER_FILL,
                                font_color=COL_WHITE, bold=True)
                c.border = border

            ws.freeze_panes = "A2"

            # ── Data rows ──
            try:
                with open(LOG_CSV, "r", newline="", encoding="utf-8") as f:
                    rows = list(csv.reader(f))[1:]
            except Exception:
                rows = []

            for ri, row_data in enumerate(rows, 2):
                while len(row_data) < len(LOG_HEADERS):
                    row_data.append("")

                event = row_data[1] if len(row_data) > 1 else ""

                if "UNAUTHORIZED" in event:
                    row_fill = COL_UNAUTH_FILL; row_fc = "000000"
                elif "AUTHORIZED" in event:
                    row_fill = COL_AUTH_FILL;   row_fc = "000000"
                elif "TRANSFER" in event:
                    row_fill = COL_TRANSFER_FILL; row_fc = "000000"
                else:
                    row_fill = None; row_fc = "000000"

                ws.row_dimensions[ri].height = 18

                for ci, val in enumerate(row_data, 1):
                    bold_col = False
                    fc       = row_fc

                    if ci == 2:
                        if "UNAUTHORIZED" in event:
                            fc = COL_RED;   bold_col = True
                        elif "AUTHORIZED" in event:
                            fc = COL_GREEN; bold_col = True
                        elif "TRANSFER" in event:
                            fc = COL_BLUE;  bold_col = True

                    if ci == 11:
                        if val == "USB→PC":
                            fc = COL_ORANGE; bold_col = True
                        elif val == "PC→USB":
                            fc = COL_RED;    bold_col = True

                    c = _cell_style(ws, ri, ci, val,
                                    fill_hex=row_fill,
                                    font_color=fc,
                                    bold=bold_col,
                                    wrap=(ci == 11))
                    c.border = border

            col_widths = {
                1: 20, 2: 22, 3: 12, 4: 12, 5: 16,
                6: 14, 7: 30, 8: 14, 9: 14, 10: 34,
                11: 12, 12: 45,
            }
            for ci, width in col_widths.items():
                ws.column_dimensions[get_column_letter(ci)].width = width

            ws.auto_filter.ref = ws.dimensions
            wb.save(LOG_EXCEL)

        except Exception as e:
            print(f"[!] Excel export failed: {e}")

# ─────────────────────────────────────────────
# FILE UTILITIES
# ─────────────────────────────────────────────
def get_file_hash(filepath):
    try:
        md5 = hashlib.md5()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception:
        return "Unreadable"

def file_info_from_path(filepath):
    try:
        return {
            "name":    os.path.basename(filepath),
            "size_kb": round(os.path.getsize(filepath) / 1024, 2),
            "type":    os.path.splitext(filepath)[1].lower() or "no extension",
            "hash":    get_file_hash(filepath),
        }
    except Exception:
        return None

def scan_drive(drive_letter):
    files = []
    if not drive_letter or not os.path.exists(drive_letter):
        return files
    for root, dirs, filenames in os.walk(drive_letter):
        dirs[:] = [d for d in dirs if not d.startswith("$")]
        for fn in filenames:
            fi = file_info_from_path(os.path.join(root, fn))
            if fi:
                files.append(fi)
    return files

# ─────────────────────────────────────────────
# USB DRIVE DETECTION
# ─────────────────────────────────────────────
def get_usb_drive_letters():
    letters = []
    try:
        w = wmi.WMI()
        for disk in w.Win32_DiskDrive():
            if "USB" not in (disk.InterfaceType or "").upper():
                continue
            for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical in part.associators("Win32_LogicalDiskToPartition"):
                    letters.append(logical.DeviceID + "\\")
    except Exception:
        pass
    return letters

def get_drive_for_serial(serial):
    try:
        w = wmi.WMI()
        for disk in w.Win32_DiskDrive():
            if "USB" not in (disk.InterfaceType or "").upper():
                continue
            pnp = getattr(disk, "PNPDeviceID", "") or ""
            if serial.upper() not in pnp.upper():
                continue
            for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                for logical in part.associators("Win32_LogicalDiskToPartition"):
                    return logical.DeviceID + "\\"
    except Exception:
        pass
    return None

# ─────────────────────────────────────────────
# LOCAL PC FOLDERS TO WATCH
# ─────────────────────────────────────────────
LOCAL_WATCH_DIRS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "Documents"),
    os.path.join(os.path.expanduser("~"), "Pictures"),
    os.path.join(os.path.expanduser("~"), "Videos"),
    os.path.join(os.path.expanduser("~"), "Music"),
]

# ─────────────────────────────────────────────
# TRANSFER HANDLER (watchdog)
# ─────────────────────────────────────────────
class TransferHandler(FileSystemEventHandler):
    """
    Watches a directory and logs new files as transfers.

    direction = "PC→USB"  when watching a LOCAL PC folder
                           (a new file here means you copied FROM USB TO PC,
                            so the data is flowing USB → PC)

                "USB→PC"  when watching the USB drive letter itself
                           (a new file there means you copied FROM PC TO USB,
                            so data is flowing PC → USB)

    Wait — this is confusing. Let's define it from the USER's intent:

        * User drags file from USB to PC Downloads folder
          → file CREATED in Downloads
          → direction = "USB→PC"   ✔ (data came from USB, landed on PC)

        * User drags file from PC to USB drive
          → file CREATED on USB drive letter
          → direction = "PC→USB"   ✔ (data came from PC, landed on USB)

    So:
        local folder watcher  → direction "USB→PC"
        USB drive watcher     → direction "PC→USB"
    """

    def __init__(self, device, direction, authorized, baseline_paths=None):
        super().__init__()
        self.device        = device
        self.direction     = direction
        self.authorized    = authorized
        # baseline: set of absolute paths that existed BEFORE we started watching.
        # Any path in this set is ignored so startup noise is filtered out.
        self._baseline     = set(baseline_paths or [])
        self._seen         = set()
        self._lock         = threading.Lock()

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_moved(self, event):
        """Rename / move INTO watched folder."""
        if event.is_directory:
            return
        self._handle(event.dest_path)

    # on_modified deliberately NOT implemented — every file open/save would
    # produce a false positive.  We only care about truly NEW files.

    def _handle(self, path):
        with self._lock:
            # Skip if this file existed before we started watching
            if path in self._baseline:
                return
            if path in self._seen:
                return
            self._seen.add(path)

        # Small delay — let the OS finish writing the file
        time.sleep(1.5)

        fi = file_info_from_path(path)
        if not fi:
            print(f"[DEBUG] Could not read file info: {path}")
            return

        event_type = "TRANSFER-AUTH" if self.authorized else "TRANSFER-UNAUTH"

        status_label = "AUTHORIZED" if self.authorized else "UNAUTHORIZED"
        direction_arrow = self.direction   # "USB→PC" or "PC→USB"

        print(f"\n{'='*60}")
        if self.direction == "USB→PC":
            print(f"[+] FILE COPIED  USB → PC  (file saved on your computer)")
        else:
            print(f"[+] FILE COPIED  PC → USB  (file saved on USB/phone)")
        print(f"{'='*60}")
        print(f"    Direction  : {direction_arrow}")
        print(f"    File       : {fi['name']}")
        print(f"    Size       : {fi['size_kb']} KB")
        print(f"    Type       : {fi['type']}")
        print(f"    Hash       : {fi['hash']}")
        print(f"    Local Path : {path}")
        print(f"    Status     : {status_label}")
        print(f"{'='*60}\n")

        row = make_row(
            event      = event_type,
            device     = self.device,
            file_info  = fi,
            direction  = direction_arrow,
            local_path = path,
        )
        write_rows([row])
        send_email(self.device, [row], self.authorized)


# ─────────────────────────────────────────────
# CLIPBOARD MONITOR  (MTP fallback for PC→USB)
# ─────────────────────────────────────────────
CF_HDROP = 15
user32   = ctypes.windll.user32
shell32  = ctypes.windll.shell32

def get_clipboard_file_list():
    try:
        if not user32.OpenClipboard(None):
            return []
        hdrop = user32.GetClipboardData(CF_HDROP)
        if not hdrop:
            return []
        count = shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
        files = []
        for i in range(count):
            buf = ctypes.create_unicode_buffer(260)
            shell32.DragQueryFileW(hdrop, i, buf, ctypes.sizeof(buf))
            files.append(buf.value)
        return files
    except Exception:
        return []
    finally:
        try:
            user32.CloseClipboard()
        except Exception:
            pass


class ClipboardMonitor(threading.Thread):
    """
    Fallback for MTP devices (no drive letter).
    When the user copies files in Explorer, the source paths end up on the
    clipboard as HDROP.  If those source paths are on the PC, the user is
    about to paste them onto the phone → PC→USB.
    """
    def __init__(self, device, authorized):
        super().__init__(daemon=True)
        self.device      = device
        self.authorized  = authorized
        self._stop_event = threading.Event()
        self._last_files = ()

    def run(self):
        while not self._stop_event.is_set():
            files = tuple(get_clipboard_file_list())
            if files and files != self._last_files:
                self._last_files = files
                self._log_clipboard_transfer(files)
            time.sleep(1.0)

    def stop(self):
        self._stop_event.set()

    def _log_clipboard_transfer(self, files):
        rows = []
        for path in files:
            fi = file_info_from_path(path)
            if not fi:
                continue

            # Determine direction:
            # If the copied file lives on a LOCAL drive (C:\...) the user is
            # about to paste it to the phone → PC→USB.
            # If the source is from a mapped/network/USB location → USB→PC.
            local_drives = [d.device for d in psutil.disk_partitions()
                            if d.fstype and "removable" not in d.opts.lower()]
            src_drive = os.path.splitdrive(path)[0].upper() + "\\"
            direction = "PC→USB" if src_drive in [d.upper() for d in local_drives] else "USB→PC"

            event = (
                f"TRANSFER-AUTH-CLIPBOARD"
                if self.authorized
                else "TRANSFER-UNAUTH-CLIPBOARD"
            )

            print(f"\n{'='*60}")
            print(f"[+] CLIPBOARD TRANSFER DETECTED [{direction}]")
            print(f"{'='*60}")
            print(f"    File       : {os.path.basename(path)}")
            print(f"    Size       : {fi['size_kb']} KB")
            print(f"    Type       : {fi['type']}")
            print(f"    Local Path : {path}")
            print(f"    Direction  : {direction}")
            print(f"    Target     : MTP / Internal Storage")
            print(f"    Status     : {'AUTHORIZED' if self.authorized else 'UNAUTHORIZED'}")
            print(f"{'='*60}\n")

            rows.append(make_row(
                event       = event,
                device      = self.device,
                file_info   = fi,
                direction   = direction,
                local_path  = path,
                device_type = "MTP"
            ))
        if rows:
            write_rows(rows)
            send_email(self.device, rows, self.authorized)


# ─────────────────────────────────────────────
# MTP POLLING  (PC→USB for phones)
# Uses PowerShell Shell.Application COM to walk the MTP namespace and detect
# new files that appear on the phone's internal storage.
# ─────────────────────────────────────────────
MTP_PS_SCRIPT = r"""
Add-Type -AssemblyName Microsoft.VisualBasic
$shell = New-Object -ComObject Shell.Application
$mtp   = $shell.NameSpace(0x11).Items() | Where-Object { $_.IsFolder -and $_.Name -notmatch 'C:|D:|E:|F:' }
$files = @()
foreach ($dev in $mtp) {
    $internal = $dev.GetFolder.Items() | Where-Object { $_.IsFolder }
    foreach ($folder in $internal) {
        $sub = $folder.GetFolder.Items()
        foreach ($item in $sub) {
            if (-not $item.IsFolder) {
                $files += [PSCustomObject]@{
                    Name = $item.Name
                    Path = $item.Path
                    Size = $item.Size
                }
            }
        }
    }
}
$files | ConvertTo-Json -Compress
"""

class MTPPhoneMonitor(threading.Thread):
    """
    Polls the MTP namespace (phone internal storage) every N seconds.
    Reports any NEW files that appear there as PC→USB transfers.
    (New files on the phone = user copied them from the PC.)
    """
    def __init__(self, device, authorized, poll_interval=5):
        super().__init__(daemon=True)
        self.device        = device
        self.authorized    = authorized
        self.poll_interval = poll_interval
        self._stop         = threading.Event()
        self._known_paths  = set()
        self._initialised  = False

    def run(self):
        print("[*] MTP Phone Monitor started (polling phone internal storage)...")
        while not self._stop.is_set():
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", MTP_PS_SCRIPT],
                    capture_output=True, text=True, timeout=15
                )
                raw = result.stdout.strip()
                if not raw or raw == "null":
                    time.sleep(self.poll_interval)
                    continue

                import json as _json
                items = _json.loads(raw)
                if isinstance(items, dict):   # single item
                    items = [items]

                current_paths = {item.get("Path", "") for item in items}

                if not self._initialised:
                    # First run — snapshot existing files, don't log them
                    self._known_paths = current_paths
                    self._initialised = True
                    print(f"[*] MTP snapshot: {len(self._known_paths)} existing file(s) on phone (ignored).")
                    time.sleep(self.poll_interval)
                    continue

                new_paths = current_paths - self._known_paths
                for path in new_paths:
                    # Find matching item dict
                    item = next((i for i in items if i.get("Path") == path), {})
                    name = item.get("Name", os.path.basename(path))
                    size_kb = round(int(item.get("Size", 0)) / 1024, 2)
                    ext  = os.path.splitext(name)[1].lower() or "no extension"

                    print(f"\n{'='*60}")
                    print(f"[+] FILE COPIED  PC → USB/Phone  (new file on phone storage)")
                    print(f"{'='*60}")
                    print(f"    Direction  : PC→USB")
                    print(f"    File       : {name}")
                    print(f"    Size       : {size_kb} KB")
                    print(f"    Type       : {ext}")
                    print(f"    Phone Path : {path}")
                    print(f"    Status     : {'AUTHORIZED' if self.authorized else 'UNAUTHORIZED'}")
                    print(f"{'='*60}\n")

                    event = "TRANSFER-AUTH" if self.authorized else "TRANSFER-UNAUTH"
                    row = make_row(
                        event       = event,
                        device      = self.device,
                        file_info   = {"name": name, "size_kb": size_kb, "type": ext, "hash": "-"},
                        direction   = "PC→USB",
                        local_path  = path,
                        device_type = "MTP"
                    )
                    write_rows([row])
                    send_email(self.device, [row], self.authorized)

                self._known_paths = current_paths

            except subprocess.TimeoutExpired:
                print("[!] MTP poll timed out.")
            except Exception as e:
                print(f"[!] MTP poll error: {e}")

            time.sleep(self.poll_interval)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────
# WATCHDOG MANAGER
# ─────────────────────────────────────────────
class WatchdogManager:
    """Manages all transfer watchers for one connected USB device."""

    def __init__(self):
        self._observers          = []
        self._clipboard_monitor  = None
        self._mtp_monitor        = None

    def _snapshot_dir(self, path):
        """Return set of all file paths currently in a directory tree."""
        existing = set()
        try:
            for root, _, files in os.walk(path):
                for fn in files:
                    existing.add(os.path.join(root, fn))
        except Exception:
            pass
        return existing

    def start(self, device, drive_letter, authorized):
        if not WATCHDOG_AVAILABLE:
            print("[!] WATCHDOG NOT AVAILABLE — transfer detection disabled!")
            return

        print("[DEBUG] Starting WatchdogManager...")

        # ── 1. Watch LOCAL PC folders ──────────────────────────────────────
        # When a new file is created in Downloads/Desktop/Documents etc.
        # right after a USB device connects, the user copied it FROM the USB.
        # Direction = USB→PC
        pc_watched = 0
        for folder in LOCAL_WATCH_DIRS:
            if not os.path.isdir(folder):
                continue
            try:
                baseline = self._snapshot_dir(folder)
                handler  = TransferHandler(
                    device         = device,
                    direction      = "USB→PC",   # data came FROM USB, lands on PC
                    authorized     = authorized,
                    baseline_paths = baseline,
                )
                obs = Observer()
                obs.schedule(handler, path=folder, recursive=True)
                obs.start()
                self._observers.append(obs)
                pc_watched += 1
                print(f"[DEBUG] [USB→PC watcher] Watching: {folder}")
            except Exception as e:
                print(f"[!] Failed to watch {folder}: {e}")

        print(f"[*] ✓ {pc_watched} local folder(s) watched for USB→PC transfers")

        # ── 2. Watch USB drive letter ──────────────────────────────────────
        # When a new file appears on the USB drive itself, the user copied it
        # FROM the PC onto the USB.
        # Direction = PC→USB
        if drive_letter and os.path.exists(drive_letter):
            try:
                baseline = self._snapshot_dir(drive_letter)
                handler  = TransferHandler(
                    device         = device,
                    direction      = "PC→USB",   # data came FROM PC, lands on USB
                    authorized     = authorized,
                    baseline_paths = baseline,
                )
                obs = Observer()
                obs.schedule(handler, path=drive_letter, recursive=True)
                obs.start()
                self._observers.append(obs)
                print(f"[*] ✓ USB drive {drive_letter} watched for PC→USB transfers")
            except Exception as e:
                print(f"[!] Failed to watch USB drive {drive_letter}: {e}")
        else:
            # No drive letter → MTP phone.  Use two strategies:
            #  a) Clipboard monitor (catches copy intent on PC side)
            #  b) MTP phone poller (catches new files that actually appeared)
            print(f"[*] No drive letter — using MTP detection (clipboard + phone polling)")

            self._clipboard_monitor = ClipboardMonitor(device, authorized)
            self._clipboard_monitor.start()
            print("[*] ✓ Clipboard monitor started (PC→USB intent detection)")

            self._mtp_monitor = MTPPhoneMonitor(device, authorized)
            self._mtp_monitor.start()
            print("[*] ✓ MTP phone monitor started (PC→USB file appearance on phone)")

        print(f"[*] ═══ WatchdogManager STARTED ═══\n")

    def stop(self):
        for obs in self._observers:
            try:
                obs.stop()
                obs.join(timeout=3)
            except Exception:
                pass
        self._observers.clear()

        if self._clipboard_monitor:
            self._clipboard_monitor.stop()
            try:
                self._clipboard_monitor.join(timeout=3)
            except Exception:
                pass
            self._clipboard_monitor = None

        if self._mtp_monitor:
            self._mtp_monitor.stop()
            try:
                self._mtp_monitor.join(timeout=3)
            except Exception:
                pass
            self._mtp_monitor = None

        print("[*] Transfer watchers stopped.")


# Global watchdog managers keyed by device serial
_watchers: dict[str, WatchdogManager] = {}

# ─────────────────────────────────────────────
# EMAIL
# ─────────────────────────────────────────────
def build_email_table(rows):
    hstyle = ("background:#2C3E50;color:white;padding:8px 10px;"
              "text-align:left;font-size:12px;")
    cstyle = "padding:6px 10px;font-size:11px;border-bottom:1px solid #eee;"
    alt    = "background:#f9f9f9;"

    html = ("<table style='border-collapse:collapse;width:100%;"
            "font-family:Arial,sans-serif;'><thead><tr>")
    for h in LOG_HEADERS:
        html += f"<th style='{hstyle}'>{h}</th>"
    html += "</tr></thead><tbody>"

    for i, row in enumerate(rows):
        bg = alt if i % 2 == 0 else ""
        html += f"<tr style='{bg}'>"
        for h in LOG_HEADERS:
            val = row.get(h, "")
            if h == "Event":
                color = ("#c0392b" if "UNAUTHORIZED" in str(val)
                         else "#1e8449" if "AUTHORIZED" in str(val)
                         else "#1a5276")
                html += (f"<td style='{cstyle}color:{color};"
                         f"font-weight:bold;'>{val}</td>")
            elif h == "Direction":
                color = ("#d35400" if val == "USB→PC"
                         else "#c0392b" if val == "PC→USB"
                         else "#555")
                html += f"<td style='{cstyle}color:{color};font-weight:bold;'>{val}</td>"
            else:
                html += f"<td style='{cstyle}'>{val}</td>"
        html += "</tr>"

    html += "</tbody></table>"
    return html

def send_email(device, rows, authorized):
    if not config["email"]["enabled"]:
        return

    auth_label = "AUTHORIZED" if authorized else "UNAUTHORIZED"
    color      = "#1e8449"    if authorized else "#c0392b"

    msg            = MIMEMultipart("alternative")
    msg["From"]    = config["email"]["from"]
    msg["To"]      = config["email"]["to"]
    msg["Subject"] = (
        f"[USB Logger] {auth_label} Event | "
        f"Serial: {device.get('serial', '-')} | "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    )

    body = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f4f4f4;padding:20px;">
    <div style="max-width:1000px;margin:auto;background:white;border-radius:8px;
                padding:24px;box-shadow:0 2px 8px rgba(0,0,0,.1);">

      <h2 style="color:{color};margin-top:0;">
        USB Device Event — {auth_label}
      </h2>

      <table style="margin-bottom:20px;font-size:13px;border-collapse:collapse;">
        <tr><td style="padding:4px 20px 4px 0;color:#555;"><b>Vendor ID</b></td>
            <td>{device.get('vendor_id','-')}</td></tr>
        <tr><td style="padding:4px 20px 4px 0;color:#555;"><b>Product ID</b></td>
            <td>{device.get('product_id','-')}</td></tr>
        <tr><td style="padding:4px 20px 4px 0;color:#555;"><b>Serial</b></td>
            <td>{device.get('serial','-')}</td></tr>
        <tr><td style="padding:4px 20px 4px 0;color:#555;"><b>Time</b></td>
            <td>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</td></tr>
        <tr><td style="padding:4px 20px 4px 0;color:#555;"><b>Status</b></td>
            <td style="color:{color};font-weight:bold;">{auth_label}</td></tr>
      </table>

      <h3 style="color:#2C3E50;">Log Entries</h3>
      {build_email_table(rows)}

      <p style="margin-top:20px;font-size:11px;color:#aaa;">
        Automated alert — USB Intrusion Logger
      </p>
    </div>
    </body></html>
    """

    msg.attach(MIMEText(body, "html"))
    try:
        with smtplib.SMTP(config["email"]["smtp_server"],
                          config["email"]["smtp_port"]) as srv:
            srv.starttls()
            srv.login(config["email"]["from"], config["email"]["password"])
            srv.send_message(msg)
        print("[+] Email sent to admin.")
    except Exception as e:
        print(f"[!] Email failed: {e}")

# ─────────────────────────────────────────────
# WMI — DEVICE OPERATIONS
# ─────────────────────────────────────────────
def parse_device(pnp_id):
    try:
        parts = pnp_id.split("\\")
        if len(parts) < 3:
            return None
        id_part = parts[1]
        serial  = parts[2].strip()
        if not serial:
            return None
        vendor_id = product_id = ""
        for seg in id_part.split("&"):
            seg = seg.strip()
            if seg.upper().startswith("VID_"):
                vendor_id = seg
            elif seg.upper().startswith("PID_"):
                product_id = seg[4:]
        if not vendor_id or not product_id:
            return None
        return {"vendor_id": vendor_id, "product_id": product_id, "serial": serial}
    except Exception:
        return None

def get_connected_devices():
    devices, seen = [], set()
    try:
        w = wmi.WMI()
        for usb in w.Win32_USBHub():
            pnp_id = getattr(usb, "PNPDeviceID", "") or ""
            if not pnp_id:
                continue
            d = parse_device(pnp_id)
            if d and d["serial"] not in seen:
                seen.add(d["serial"])
                devices.append(d)
    except Exception:
        pass
    return devices

def is_serial_connected(serial):
    try:
        w = wmi.WMI()
        for usb in w.Win32_USBHub():
            pnp = getattr(usb, "PNPDeviceID", "") or ""
            if serial.upper() in pnp.upper():
                return True
    except Exception:
        return True
    return False

def disable_device(device):
    try:
        w = wmi.WMI()
        serial_upper = device["serial"].upper()
        for entity in w.Win32_PnPEntity():
            pnp = getattr(entity, "PNPDeviceID", "") or ""
            if serial_upper in pnp.upper():
                if hasattr(entity, "Disable"):
                    try:
                        entity.Disable()
                        print(f"[!] Device {device['serial']} DISABLED via WMI.")
                        return True
                    except Exception as e:
                        print(f"[!] Disable via WMI failed: {e}")
                        return False
        print("[!] Could not disable device — no disableable WMI entity found.")
    except Exception as e:
        print(f"[!] Disable error: {e}")
    return False

# ─────────────────────────────────────────────
# WHITELIST
# ─────────────────────────────────────────────
def is_whitelisted(device):
    combined = HARDCODED_WHITELIST + config.get("whitelist", [])
    for entry in combined:
        if (entry["vendor_id"].strip().lower()  == device["vendor_id"].strip().lower()  and
            entry["product_id"].strip().lower() == device["product_id"].strip().lower() and
            entry["serial"].strip().lower()     == device["serial"].strip().lower()):
            return True
    return False

# ─────────────────────────────────────────────
# ALARM
# ─────────────────────────────────────────────
_alarm_stop = threading.Event()

def _beep_loop():
    while not _alarm_stop.is_set():
        winsound.Beep(1000, 400)
        time.sleep(0.1)

def play_alarm(serial):
    if not config["alarm"]["enabled"]:
        return
    global _alarm_stop
    _alarm_stop = threading.Event()
    t = threading.Thread(target=_beep_loop, daemon=True)
    t.start()
    print("[!] ALARM — unplug the unauthorized device to stop.")
    while True:
        time.sleep(0.5)
        if not is_serial_connected(serial):
            _alarm_stop.set()
            t.join()
            print("[*] Device removed. Alarm stopped.\n")
            break

# ─────────────────────────────────────────────
# DEVICE HANDLER
# ─────────────────────────────────────────────
def handle_new_device(device, authorized):
    event_prefix = "AUTHORIZED" if authorized else "UNAUTHORIZED"
    rows_before  = count_data_rows()

    print(f"[DEBUG] Detected device: {device}")
    print(f"[*] Waiting for device to mount (3 s)...")
    time.sleep(3)

    # ── Unauthorized: block immediately ──────────────────────────────────
    if not authorized:
        print("[!] UNAUTHORIZED device — attempting to disable...")
        disable_device(device)
        play_alarm(device["serial"])   # blocks until removed

        rows = [make_row(event_prefix, device)]
        write_rows(rows)
        new_rows = read_rows_from(rows_before)
        send_email(device, new_rows, authorized)
        return

    # ── Authorized ────────────────────────────────────────────────────────
    drive = get_drive_for_serial(device["serial"])
    print(f"[DEBUG] Drive letter for serial: {drive}")

    if not drive:
        drives = get_usb_drive_letters()
        drive  = drives[0] if drives else None
        print(f"[DEBUG] Fallback drive: {drive}")

    # ── Scan files already on device ─────────────────────────────────────
    rows = []
    if drive:
        print(f"[*] Scanning files on {drive} ...")
        files = scan_drive(drive)
        print(f"[*] Found {len(files)} file(s).")
        if files:
            for fi in files:
                rows.append(make_row(
                    event       = f"FILE-{event_prefix}",
                    device      = device,
                    file_info   = fi,
                    direction   = "ON-DEVICE",
                    local_path  = os.path.join(drive, fi["name"]),
                    device_type = "USB storage"
                ))
        else:
            rows.append(make_row(event_prefix, device, device_type="USB storage"))
    else:
        print("[*] No drive letter — MTP / internal storage device detected.")
        rows.append(make_row(
            event       = f"{event_prefix}-MTP",
            device      = device,
            direction   = "UNKNOWN",
            local_path  = "MTP internal storage / no drive letter",
            device_type = "MTP"
        ))

    write_rows(rows)

    # ── Start transfer watchers ───────────────────────────────────────────
    print("[DEBUG] Starting transfer watchers...")
    wm = WatchdogManager()
    wm.start(device, drive, authorized)
    _watchers[device["serial"]] = wm
    print(f"[DEBUG] Watchers registered for serial: {device['serial']}")

    # ── Send connection email ─────────────────────────────────────────────
    new_rows = read_rows_from(rows_before)
    send_email(device, new_rows, authorized)

# ─────────────────────────────────────────────
# DEBUG HELPERS
# ─────────────────────────────────────────────
def debug_all_devices():
    print("\n" + "="*70)
    print("  FULL DEVICE DEBUG REPORT")
    print("="*70)
    try:
        w = wmi.WMI()

        print("\n[USB HUBS CONNECTED]")
        hubs = list(w.Win32_USBHub())
        if not hubs:
            print("  (None found)")
        for i, usb in enumerate(hubs, 1):
            pnp  = getattr(usb, "PNPDeviceID", "") or ""
            name = getattr(usb, "Name", "") or ""
            print(f"\n  Device {i}:")
            print(f"    Name: {name}")
            print(f"    PNP : {pnp}")

        print("\n\n[DISK DRIVES - ALL TYPES]")
        disks = list(w.Win32_DiskDrive())
        if not disks:
            print("  (None found)")
        for i, disk in enumerate(disks, 1):
            iface = getattr(disk, "InterfaceType", "") or ""
            pnp   = getattr(disk, "PNPDeviceID",   "") or ""
            size  = getattr(disk, "Size", "?")
            print(f"\n  Disk {i}: {iface}")
            print(f"    Size: {size} bytes")
            print(f"    PNP : {pnp}")
            try:
                for part in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for logical in part.associators("Win32_LogicalDiskToPartition"):
                        letter = getattr(logical, "DeviceID", "")
                        print(f"    → Drive Letter: {letter}")
            except Exception:
                print("    → No drive letter")

        print("\n\n[LOGICAL DISKS - CURRENTLY MOUNTED]")
        for disk in w.Win32_LogicalDisk():
            name = getattr(disk, "Name", "")
            desc = getattr(disk, "Description", "") or ""
            size = getattr(disk, "Size", "?")
            print(f"  {name}: {desc} ({size} bytes)")

    except Exception as e:
        print(f"[!] Debug error: {e}")
        import traceback; traceback.print_exc()

    print("\n" + "="*70 + "\n")

# ─────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────
def monitor_usb():
    init_log()
    print("=" * 55)
    print("  USB Intrusion Logger — Started  (FIXED)")
    print("=" * 55)
    print(f"  Log CSV   : {LOG_CSV}")
    print(f"  Log Excel : {LOG_EXCEL}")
    print(f"  Watchdog  : {'enabled' if WATCHDOG_AVAILABLE else 'DISABLED (pip install watchdog)'}")
    print("=" * 55)
    print()
    print("  Transfer direction key:")
    print("    USB→PC  = file copied FROM USB/phone  TO  your computer")
    print("    PC→USB  = file copied FROM computer   TO  USB/phone")
    print("=" * 55)
    print("[*] Scanning existing devices on startup (ignored)...")
    debug_all_devices()

    initial  = get_connected_devices()
    known    = {d["serial"] for d in initial}
    print(f"[*] {len(initial)} device(s) already present — ignored.")
    print("[*] Watching for NEW connections. Ctrl+C to quit.\n")

    while True:
        try:
            current     = get_connected_devices()
            current_set = {d["serial"] for d in current}

            # ── New devices ──
            for device in current:
                if device["serial"] not in known:
                    authorized = is_whitelisted(device)
                    label = "AUTHORIZED" if authorized else "UNAUTHORIZED"
                    print(f"\n[+] New device detected: {device}  →  {label}")
                    handle_new_device(device, authorized)

            # ── Disconnected devices ──
            for serial in list(_watchers):
                if serial not in current_set:
                    print(f"[*] Device {serial} disconnected — stopping watchers.")
                    _watchers[serial].stop()
                    del _watchers[serial]

            known = current_set
            time.sleep(config["poll_interval_seconds"])

        except KeyboardInterrupt:
            _alarm_stop.set()
            print("\n[*] Shutting down...")
            for wm in _watchers.values():
                wm.stop()
            print("[*] Goodbye!")
            break
        except Exception as e:
            print(f"[!] Error: {e}")
            time.sleep(5)

# ─────────────────────────────────────────────
# RUN
# ─────────────────────────────────────────────
if __name__ == "__main__":
    monitor_usb() 