# PersistMap - Windows Persistence Inventory
#
# Very conservative global settings. These defaults are tuned for
# performance and for staying "evidence first". Nothing here writes to
# the system.


APP_NAME = "PersistMap"
APP_VERSION = "1.0.0"
APP_SUBTITLE = "Windows Persistence Inventory"

# ---------------------------------------------------------------------------
# Registry Run Keys
# ---------------------------------------------------------------------------

REGISTRY_RUN_KEYS = [
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
]

# Software\WOW6432Node is only probed 64-bit-often; handled dynamically.
WOW64_NODE_PREFIX = r"Software\WOW6432Node"

# ---------------------------------------------------------------------------
# Startup folders
# ---------------------------------------------------------------------------

# These are resolved per-user / per-machine at runtime.
STARTUP_EXTENSIONS = {
    ".exe", ".com", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".lnk", ".url", ".scf", ".hta",
}

# ---------------------------------------------------------------------------
# Analysis: LOLBins
# ---------------------------------------------------------------------------

LOLBIN_NAMES = {
    "powershell.exe", "powershell_ise.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "certutil.exe", "msiexec.exe", "bitsadmin.exe",
    "cmstp.exe", "msbuild.exe", "csc.exe", "jsc.exe",
    "hh.exe", "msdt.exe", "forfiles.exe", "wmic.exe", "scriptrunner.exe",
    "control.exe", "schtasks.exe", "scrcons.exe", "mpcmdrun.exe",
}

# ---------------------------------------------------------------------------
# Analysis: suspicious argument substrings (case-insensitive)
# ---------------------------------------------------------------------------

SUSPICIOUS_COMMAND_TERMS = [
    "-enc", "-encodedcommand", "-enco", "encodedcommand",
    "hidden", "windowstyle", "executionpolicy bypass", "bypass",
    "iex", "invoke-expression", "frombase64string", "downloadstring",
    "webclient", "bitsadmin", "http://", "https://", "certutil",
    "wget ", "-decode", " -i ", "-e powershell", "mshta javascript:",
    "invoke-webrequest", "new-object net.webclient", "start-process -hidden",
    "powershell -w hidden", "-nop", "-noprofile", " -ep bypass",
    "regsvr32 /s", "rundll32 javascript:", "cmd /c ping", "-window hidden",
    "base64", "shikata", "amsi", "reflection.assembly.load",
]

# ---------------------------------------------------------------------------
# Analysis: suspicious path locations
# ---------------------------------------------------------------------------

SUSPICIOUS_PATH_WORDS = [
    "temp", "appdata", "programdata", "downloads", "public",
    "startup", "desktop", "spooldrv", "tmp", r"users\public",
    "recycle", "$recycle.bin", r"appdata\roaming", r"appdata\local",
]

# Environment variables that resolve to "user writable" locations.
USER_WRITABLE_ENVVARS = {
    "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "PUBLIC",
}

# Paths that should not normally host resident executables.
SUSPICIOUS_PATH_DIRS = [
    "%TEMP%", "%TMP%", "%APPDATA%", "%LOCALAPPDATA%",
    r"%USERPROFILE%\Downloads", "%PUBLIC%",
    "C:\\Users\\Public", "C:\\ProgramData",
]

# ---------------------------------------------------------------------------
# Risk engine weights
# ---------------------------------------------------------------------------

RISK_WEIGHT_MAX = 100.0

# Per-indicator point contributions (kept in one place so the score is explainable)
RISK_POINTS = {
    "unsigned": 15,
    "invalid_signature": 25,
    "user_writable_path": 20,
    "temp_path": 18,
    "missing_file": 25,
    "relative_path": 12,
    "unc_path": 8,
    "network_path": 12,
    "removable_path": 10,
    "unquoted_path": 5,
    "powerShell": 15,
    "cmd": 8,
    "encoded_command": 10,
    "download_cradle": 20,
    "remote_url": 15,
    "base64_content": 8,
    "obfuscation": 15,
    "lolbin_alone": 5,
    "lolbin_suspicious_args": 15,
    "script_file": 5,
    "system_user": 8,
    "privileged_task": 14,
    "wmi_subscription": 12,
    "runonce": 5,
    "multiple_entries_same_binary": 10,
}

# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------

RISK_LEVELS = [
    (0, "Low"),
    (21, "Medium"),
    (41, "Elevated"),
    (61, "High"),
    (81, "Critical", ),
]

# ---------------------------------------------------------------------------
# Scan callbacks (for UI status updates)
# ---------------------------------------------------------------------------

SCAN_PHASES = [
    "Collecting Registry...",
    "Collecting Startup...",
    "Collecting Scheduled Tasks...",
    "Collecting Services...",
    "Collecting WMI...",
    "Normalizing...",
    "Checking signatures...",
    "Correlating...",
    "Done",
]

# ---------------------------------------------------------------------------
# Report / misc
# ---------------------------------------------------------------------------

MAX_HASH_FILE_SIZE = 256 * 1024 * 1024  # 256 MB cap for hashing
SKIP_HASHING_EVERYTHING = True          # hash only flagged items by default

LOGS_DIR_NAME = "logs"
EXPORT_DEFAULT_DIRNAME = "exports"

# Timezone for display
TIMESTAMP_UNKNOWN = "Unknown"
TIMESTAMP_UNAVAILABLE = "Unavailable"