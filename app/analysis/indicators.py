"""Detection engine (heuristics, never verdicts).

The engine adds explainable :class:`~app.models.entry.Indicator` objects to
each entry. Indicators carry:

* a machine ``tag`` (from IndicatorType)
* a human ``label``
* the triggering ``evidence`` snippet where relevant

No single indicator is treated as proof of maliciousness; the risk engine
turns the accumulated evidence into a score with reasons.
"""

from __future__ import annotations

import os
import re

import config
from app.models.entry import PersistenceEntry
from app.models.enums import IndicatorType
from app.utils import paths


class IndicatorEngine:
    """Stateless-ish engine; keeps no per-scan state between entries."""

    def __init__(self) -> None:
        self.lolbins = {name.lower() for name in config.LOLBIN_NAMES}
        self.terms = config.SUSPICIOUS_COMMAND_TERMS

    # ------------------------------------------------------------------
    def analyze(self, entry: PersistenceEntry) -> None:
        """Populate entry.indicators (appending; callers clear if needed)."""
        entry.indicators = []
        self._command_heuristics(entry)
        self._path_heuristics(entry)
        self._signer_heuristics(entry)
        self._source_heuristics(entry)
        self._dedupe(entry)

    # ------------------------------------------------------------------
    def _command_heuristics(self, entry: PersistenceEntry) -> None:
        cmd = entry.command or ""
        args = entry.arguments or ""
        full = " ".join(x for x in (cmd, args) if x).lower()
        exe_name = ""
        split = paths.split_command_line(cmd)
        if split:
            exe_name = paths.get_clean_basename(split[0]).lower()
        if not exe_name:
            exe_name = paths.get_clean_basename(cmd).lower()

        # --- LOLBin usage ---------------------------------------------
        is_lolbin = exe_name in self.lolbins
        if is_lolbin:
            label = exe_name.rsplit(".", 1)[0].capitalize()
            entry.add_indicator(f"{label} (LOLBin)", IndicatorType.LOLBIN.value,
                                evidence=cmd, points=None)

        suspicious_arg_hit = None
        for term in self.terms:
            if term in full:
                suspicious_arg_hit = term
                break
        if is_lolbin and suspicious_arg_hit:
            entry.add_indicator("Suspicious LOLBin usage",
                                IndicatorType.LOLBIN.value,
                                evidence=f"{exe_name} {suspicious_arg_hit}",
                                points=config.RISK_POINTS["lolbin_suspicious_args"])
        elif suspicious_arg_hit:
            entry.add_indicator("Suspicious arguments",
                                IndicatorType.OBFUSCATION.value,
                                evidence=suspicious_arg_hit,
                                points=config.RISK_POINTS["lolbin_suspicious_args"])

        # --- PowerShell ------------------------------------------------
        if exe_name in ("powershell.exe", "powershell_ise.exe", "pwsh.exe"):
            entry.add_indicator("PowerShell", IndicatorType.SCRIPT.value,
                                evidence=cmd, points=config.RISK_POINTS["powerShell"])
        # --- CMD --------------------------------------------------------
        if exe_name == "cmd.exe":
            entry.add_indicator("CMD", IndicatorType.SCRIPT.value,
                                evidence=cmd, points=config.RISK_POINTS["cmd"])

        # --- Encoded commands -------------------------------------------
        enc_patterns = [r"-en[\w]*\s", r"-?\s*encodedcommand", r"frombase64string",
                        r"-?\s*enc\s"]
        for pat in enc_patterns:
            if re.search(pat, full, re.IGNORECASE):
                entry.add_indicator("Encoded Command", IndicatorType.ENCODED_COMMAND.value,
                                    evidence="encoded command present",
                                    points=config.RISK_POINTS["encoded_command"])
                break

        # --- Download cradles ------------------------------------------
        cradle_patterns = [r"downloadstring", r"downloadfile", r"webclient",
                           r"invoke-webrequest", r"start-bits", r"bitsadmin",
                           r"\bwget\b", r"\bcurl\b", r"iwr\s", r"xmlhttp"]
        for pat in cradle_patterns:
            if re.search(pat, full, re.IGNORECASE):
                entry.add_indicator("Download Cradle", IndicatorType.DOWNLOAD_CRADLE.value,
                                    evidence=pat,
                                    points=config.RISK_POINTS["download_cradle"])
                break

        # --- Remote URLs -----------------------------------------------
        url_match = re.search(r"https?://[^\s\"']+", full, re.IGNORECASE)
        if url_match:
            entry.add_indicator("Remote URL", IndicatorType.REMOTE_URL.value,
                                evidence=url_match.group(0),
                                points=config.RISK_POINTS["remote_url"])

        # --- Base64-ish -------------------------------------------------
        for token in (cmd + " " + args).split():
            if paths.looks_like_base64(token):
                entry.add_indicator("Base64-like Content", IndicatorType.BASE64.value,
                                    evidence=token[:48],
                                    points=config.RISK_POINTS["base64_content"])
                break

        # --- Generic obfuscation ----------------------------------------
        obfuscated = self._looks_obfuscated(cmd + " " + args)
        if obfuscated:
            entry.add_indicator("Obfuscation Pattern", IndicatorType.OBFUSCATION.value,
                                evidence=obfuscated,
                                points=config.RISK_POINTS["obfuscation"])

        # --- Script files ----------------------------------------------
        ext = entry.file_extension or paths.file_extension(cmd)
        if paths.is_script_extension(ext):
            entry.add_indicator("Script File", IndicatorType.SCRIPT.value,
                                evidence=ext,
                                points=config.RISK_POINTS["script_file"])

    # ------------------------------------------------------------------
    def _path_heuristics(self, entry: PersistenceEntry) -> None:
        p = entry.path or entry.command
        if not p:
            return
        norm = paths.normalize_path(p)

        # --- missing ----------------------------------------------------
        concrete = paths.expand_env(norm)
        if (len(concrete) > 3 and (concrete[1:2] == ":" or concrete.startswith("\\\\"))
                and not concrete.startswith("%")):
            if os.path.basename(concrete) and not os.path.exists(concrete):
                entry.file_state = "Missing"
                entry.add_indicator("Missing File", IndicatorType.MISSING_FILE.value,
                                    evidence=norm,
                                    points=config.RISK_POINTS["missing_file"])

        # --- temp / user-writable locations -----------------------------
        lowered = norm.lower()
        if paths.in_temp_dir(norm):
            entry.add_indicator("Temp Path", IndicatorType.TEMP_PATH.value,
                                evidence=norm,
                                points=config.RISK_POINTS["temp_path"])
        if paths.in_user_writable_dir(norm) or (
                lowered.startswith("%appdata%") or lowered.startswith("%localappdata%")
                or lowered.startswith("%temp%") or lowered.startswith("%userprofile%")):
            entry.add_indicator("User-Writable Path", IndicatorType.USER_WRITABLE_PATH.value,
                                evidence=norm,
                                points=config.RISK_POINTS["user_writable_path"])

        # --- UNC / network / removable ----------------------------------
        if paths.is_unc_path(norm):
            entry.add_indicator("UNC Path", IndicatorType.UNC_PATH.value,
                                evidence=norm, points=config.RISK_POINTS["unc_path"])
        if paths.is_network_unc(norm):
            entry.add_indicator("Network Path", IndicatorType.NETWORK_PATH.value,
                                evidence=norm, points=config.RISK_POINTS["network_path"])
        if paths.is_removable_style(norm):
            entry.add_indicator("Removable Drive Path", IndicatorType.REMOVABLE_PATH.value,
                                evidence=norm, points=config.RISK_POINTS["removable_path"])

        # --- relative / unquoted ----------------------------------------
        if paths.is_relative_path(norm) and "\\" in norm:
            entry.add_indicator("Relative Path", IndicatorType.RELATIVE_PATH.value,
                                evidence=norm, points=config.RISK_POINTS["relative_path"])
        if paths.detect_unquoted_path(norm):
            entry.add_indicator("Unquoted Path", IndicatorType.UNQUOTED_PATH.value,
                                evidence=norm, points=config.RISK_POINTS["unquoted_path"])

    # ------------------------------------------------------------------
    def _signer_heuristics(self, entry: PersistenceEntry) -> None:
        status = str(entry.signer_status or "")
        if status == "Unsigned":
            entry.add_indicator("Unsigned", IndicatorType.UNSIGNED.value,
                                evidence=entry.path or entry.command,
                                points=config.RISK_POINTS["unsigned"])
        elif status == "Invalid":
            entry.add_indicator("Invalid Signature", IndicatorType.INVALID_SIGNATURE.value,
                                evidence=entry.path or entry.command,
                                points=config.RISK_POINTS["invalid_signature"])

    # ------------------------------------------------------------------
    def _source_heuristics(self, entry: PersistenceEntry) -> None:
        src = str(entry.source or "")
        user = str(entry.user or "").lower()
        status = str(entry.status or "").lower()

        if "system" in user or "local system" in user or "localsystem" in user:
            entry.add_indicator("System Account", IndicatorType.SYSTEM_USER.value,
                                evidence=user, points=config.RISK_POINTS["system_user"])

        if src == "Scheduled Task":
            if entry.architecture and "highest" in str(entry.architecture).lower():
                entry.add_indicator("Privileged Task (Highest)",
                                    IndicatorType.PRIVILEGED.value,
                                    evidence=str(entry.architecture),
                                    points=config.RISK_POINTS["privileged_task"])
            if "SYSTEM".lower() in user:
                pass  # already counted as System Account above

        if entry.category and "RunOnce" in str(entry.category):
            entry.add_indicator("RunOnce", IndicatorType.RUNONCE.value,
                                evidence=entry.category,
                                points=config.RISK_POINTS["runonce"])
        if src == "WMI":
            entry.add_indicator("WMI Event Subscription", IndicatorType.WMI.value,
                                evidence=entry.name, points=config.RISK_POINTS["wmi_subscription"])

    # ------------------------------------------------------------------
    @staticmethod
    def _looks_obfuscated(text: str) -> str:
        """Return a short description of obvious obfuscation, or ''."""
        lowered = text.lower()
        signs = []
        if "`" in text and ("$(" in text or "$env" in lowered):
            signs.append("powershell backtick escape")
        if re.search(r"\b(chr|char)\s*\(\s*\d", lowered):
            signs.append("chr() integer chain")
        if re.search(r"(?i)(\b0x[0-9a-f]{2}\b\s*[,+])", text):
            signs.append("hex byte sequence")
        if re.search(r"\b(join|concat)\s*\(['\"]", lowered):
            signs.append("string concat")
        if text.count("%") >= 4 and "%" in text:
            signs.append("cmd %VAR% chaining")
        return "; ".join(signs)

    # ------------------------------------------------------------------
    @staticmethod
    def _dedupe(entry: PersistenceEntry) -> None:
        seen: set[str] = set()
        kept = []
        for ind in entry.indicators:
            key = ind.tag + "|" + (ind.label or "")
            if key in seen:
                continue
            seen.add(key)
            kept.append(ind)
        entry.indicators = kept