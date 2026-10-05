"""Enum definitions used across PersistMap."""

from enum import Enum


class Source(str, Enum):
    """Top-level persistence sources."""

    REGISTRY = "Registry"
    STARTUP = "Startup"
    SCHEDULED_TASK = "Scheduled Task"
    SERVICE = "Service"
    WMI = "WMI"

    def __str__(self) -> str:
        return self.value


class RegistryCategory(str, Enum):
    """Sub-category of a Registry run key entry."""

    RUN = "Run"
    RUNONCE = "RunOnce"

    def __str__(self) -> str:
        return self.value


class RiskLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    ELEVATED = "Elevated"
    HIGH = "High"
    CRITICAL = "Critical"

    def __str__(self) -> str:
        return self.value


class SignerStatus(str, Enum):
    SIGNED = "Signed"
    UNSIGNED = "Unsigned"
    INVALID = "Invalid"
    UNKNOWN = "Unknown"
    UNAVAILABLE = "Unavailable"  # e.g. no binary path to introspect

    def __str__(self) -> str:
        return self.value


class FileState(str, Enum):
    EXISTS = "Exists"
    MISSING = "Missing"
    NOT_APPLICABLE = "N/A"  # no file path in the artifact

    def __str__(self) -> str:
        return self.value


class EntryStatus(str, Enum):
    ACTIVE = "Active"
    DISABLED = "Disabled"
    STOPPED = "Stopped"
    RUNNING = "Running"
    UNKNOWN = "Unknown"
    UNAVAILABLE = "Unavailable"

    def __str__(self) -> str:
        return self.value


class CollectionStatus(str, Enum):
    """Per-source collection outcome."""

    COMPLETE = "Complete"
    PARTIAL = "Partial"
    ACCESS_DENIED = "Access Denied"
    UNAVAILABLE = "Unavailable"
    FAILED = "Failed"
    NOT_RUN = "Not Run"

    def __str__(self) -> str:
        return self.value


class IndicatorType(str, Enum):
    """Grouping tag for indicators (kept as str values)."""

    LOLBIN = "LOLBin"
    SCRIPT = "Script"
    ENCODED_COMMAND = "Encoded Command"
    DOWNLOAD_CRADLE = "Download Cradle"
    REMOTE_URL = "Remote URL"
    BASE64 = "Base64-like Content"
    OBFUSCATION = "Obfuscation Pattern"
    USER_WRITABLE_PATH = "User-Writable Path"
    TEMP_PATH = "Temp Path"
    UNC_PATH = "UNC Path"
    NETWORK_PATH = "Network Path"
    REMOVABLE_PATH = "Removable Path"
    MISSING_FILE = "Missing File"
    RELATIVE_PATH = "Relative Path"
    UNQUOTED_PATH = "Unquoted Path"
    UNSIGNED = "Unsigned"
    INVALID_SIGNATURE = "Invalid Signature"
    SYSTEM_USER = "System User"
    PRIVILEGED = "Privileged"
    WMI = "WMI Subscription"
    RUNONCE = "RunOnce"
    DUPLICATE_BINARY = "Duplicate Binary"

    def __str__(self) -> str:
        return self.value


DEFAULT_UNKNOWN = "Unknown"
DEFAULT_UNAVAILABLE = "Unavailable"
DEFAULT_NOT_REPORTED = "Not Reported"