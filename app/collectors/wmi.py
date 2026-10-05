"""WMI permanent event subscription collector.

Reads ``root\\subscription`` via PowerShell ``Get-WmiObject`` (encoded
command - no script file is written, no external service involved). Only
enumeration happens; nothing is created, altered or removed.

Data is joined as bindings -> consumers/filters so the analyst reliably
sees filter+consumer pairs plus orphaned objects.
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from typing import Callable, Optional

from app.models.enums import CollectionStatus, Source
from app.models.entry import PersistenceEntry, make_entry
from app.models.models import WmiSubscription

_PS_SCRIPT = r"""
$ErrorActionPreference = 'Continue'
function Emit($kind, $obj) {
  if ($null -eq $obj) { return }
  $json = $obj | ConvertTo-Json -Compress -Depth 6
  Write-Output ("__PM__" + $kind + "__" + $json)
}

function GetSid($sid) {
  if ($null -eq $sid) { return '' }
  try { return [Convert]::ToBase64String($sid) } catch { return '' }
}

$NS = 'root\subscription'

# --- Filters ---
try {
  Get-WmiObject -Namespace $NS -Class '__EventFilter' -ErrorAction Stop | ForEach-Object {
    Emit 'filter' ([pscustomobject]@{
      Name = [string]$_.Name
      Query = [string]$_.Query
      QueryLanguage = [string]$_.QueryLanguage
      EventNamespace = [string]$_.EventNamespace
      CreatorSID = GetSid $_.CreatorSID
      CreationDate = [string]$_.CreationDate
      __CLASS = [string]$_.__CLASS
    })
  }
} catch { Write-Output ("__PM__ERROR__filter__" + $_.Exception.Message) }

# --- Consumers ---
try {
  Get-WmiObject -Namespace $NS -Class '__EventConsumer' -ErrorAction Stop | ForEach-Object {
    $base = [pscustomobject]@{
      Name = [string]$_.Name
      CreatorSID = GetSid $_.CreatorSID
      CreationDate = [string]$_.CreationDate
      __CLASS = [string]$_.__CLASS
    }
    if ($_.__CLASS -eq 'CommandLineEventConsumer') {
      $base | Add-Member -NotePropertyName CommandLineTemplate -NotePropertyValue ([string]$_.CommandLineTemplate)
      $base | Add-Member -NotePropertyName ExecutablePath -NotePropertyValue ([string]$_.ExecutablePath)
      $base | Add-Member -NotePropertyName WorkingDirectory -NotePropertyValue ([string]$_.WorkingDirectory)
      $base | Add-Member -NotePropertyName UserName -NotePropertyValue ([string]$_.UserName)
      $base | Add-Member -NotePropertyName NumberOfArguments -NotePropertyValue ([string]$_.NumberOfArguments)
    } elseif ($_.__CLASS -eq 'ActiveScriptEventConsumer') {
      $base | Add-Member -NotePropertyName ScriptingEngine -NotePropertyValue ([string]$_.ScriptingEngine)
      $base | Add-Member -NotePropertyName ScriptText -NotePropertyValue ([string]$_.ScriptText)
      $base | Add-Member -NotePropertyName ScriptFilename -NotePropertyValue ([string]$_.ScriptFilename)
      $base | Add-Member -NotePropertyName UserName -NotePropertyValue ([string]$_.UserName)
    } elseif ($_.__CLASS -eq 'LogFileEventConsumer') {
      $base | Add-Member -NotePropertyName FileName -NotePropertyValue ([string]$_.FileName)
      $base | Add-Member -NotePropertyName Text -NotePropertyValue ([string]$_.Text)
    }
    Emit 'consumer' $base
  }
} catch { Write-Output ("__PM__ERROR__consumer__" + $_.Exception.Message) }

# --- Bindings ---
try {
  Get-WmiObject -Namespace $NS -Class '__FilterToConsumerBinding' -ErrorAction Stop | ForEach-Object {
    Emit 'binding' ([pscustomobject]@{
      Name = [string]$_.Name
      Filter = [string]$_.Filter
      Consumer = [string]$_.Consumer
      CreatorSID = GetSid $_.CreatorSID
      __CLASS = [string]$_.__CLASS
    })
  }
} catch { Write-Output ("__PM__ERROR__binding__" + $_.Exception.Message) }
"""

_REF_RE = re.compile(r':([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?="([^"]*)"\s*$')


def _powershell_json() -> list[tuple[str, dict]] | None:
    """Run the encoded powershell script, return [(kind, obj), ...]."""
    encoded = base64.b64encode(_PS_SCRIPT.encode("utf-16-le")).decode("ascii")
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
           "-EncodedCommand", encoded]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=180,
                              creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return None

    out = (proc.stdout or "") + (proc.stderr or "")
    results: list[tuple[str, dict]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("__PM__"):
            continue
        parts = line.split("__", 3)
        if len(parts) < 4:
            continue
        _, kind, _, payload = parts
        kind = kind.strip()
        if kind == "ERROR":
            results.append(("ERROR", {"class": payload.split(":", 1)[0], "message": payload}))
            continue
        if kind not in ("filter", "consumer", "binding"):
            continue
        try:
            obj = json.loads(payload)
        except (json.JSONDecodeError, TypeError):
            continue
        if isinstance(obj, dict):
            results.append((kind, obj))
    return results or None


def _parse_ref(ref_text: str) -> tuple[str, str]:
    """Extract (object_class, object_name) from a WMI __PATH reference."""
    if not ref_text:
        return "", ""
    m = _REF_RE.search(ref_text)
    if m:
        return m.group(1), m.group(3)
    return "", ""


def collect(progress: Optional[Callable[[str], None]] = None,
            errors: Optional[Callable[[str, str], None]] = None) -> tuple[list[PersistenceEntry], CollectionStatus, dict]:
    raw = _powershell_json()
    if raw is None:
        if errors:
            errors("WMI", "PowerShell unavailable or query failed; no WMI data collected.")
        return [], CollectionStatus.UNAVAILABLE, {"fetched": False}

    filters: dict[str, dict] = {}
    consumers: dict[str, dict] = {}
    bindings: list[dict] = []
    errors_found: list[str] = []

    for kind, obj in raw:
        if kind == "ERROR":
            errors_found.append(f"{obj.get('class', '')}: {obj.get('message', '')[:200]}")
        elif kind == "filter":
            filters[obj.get("Name", "")] = obj
        elif kind == "consumer":
            consumers[obj.get("Name", "")] = obj
        elif kind == "binding":
            bindings.append(obj)

    subscriptions = _join(filters, consumers, bindings)

    # Orphaned consumers/filters (no binding) still surface for completeness.
    bound_filter_names = {b.get("_filter_name", "") for b in bindings}
    bound_consumer_names = {b.get("_consumer_name", "") for b in bindings}
    for cname, consumer in consumers.items():
        if cname not in bound_consumer_names:
            subscriptions.append(_subscription_from(consumer, None))
    for fname, filt in filters.items():
        if fname not in bound_filter_names:
            subscriptions.append(_subscription_from(None, filt))

    entries = [_sub_to_entry(s) for s in subscriptions]

    status = CollectionStatus.COMPLETE if not errors_found else CollectionStatus.PARTIAL
    for msg in errors_found:
        if errors:
            errors("WMI", f"Partial - {msg}")

    meta = {"filters": len(filters), "consumers": len(consumers),
            "bindings": len(bindings), "subscriptions": len(subscriptions),
            "errors": len(errors_found)}
    return entries, status, meta


def _join(filters: dict, consumers: dict, bindings: list[dict]) -> list[WmiSubscription]:
    subs: list[WmiSubscription] = []
    for b in bindings:
        b["_filter_name"] = _parse_ref(b.get("Filter", ""))[1]
        b["_consumer_name"] = _parse_ref(b.get("Consumer", ""))[1]
        filt = filters.get(b["_filter_name"])
        consumer = consumers.get(b["_consumer_name"])
        subs.append(_subscription_from(consumer, filt))
    return subs


def _subscription_from(consumer: Optional[dict], filt: Optional[dict]) -> WmiSubscription:
    sub = WmiSubscription()
    if filt:
        sub.filter_name = filt.get("Name", "") or "Unknown"
        sub.query = filt.get("Query", "") or ""
        sub.namespace = filt.get("EventNamespace", "root\\subscription") or "root\\subscription"
        sub.raw_data["filter"] = filt
    if consumer:
        cls = consumer.get("__CLASS", "")
        sub.consumer_name = consumer.get("Name", "") or "Unknown"
        sub.consumer_type = cls or "Unknown"
        if cls == "CommandLineEventConsumer":
            sub.executable = consumer.get("ExecutablePath", "") or ""
            template = consumer.get("CommandLineTemplate", "") or ""
            if template:
                sub.command_line = template
            elif sub.executable:
                sub.command_line = f'"{sub.executable}"'.strip()
            sub.arguments = consumer.get("Arguments", "") or ""
            sub.user = consumer.get("UserName", "") or "Unknown"
        elif cls == "ActiveScriptEventConsumer":
            sub.script = consumer.get("ScriptText", "") or ""
            if not sub.script:
                sub.script = consumer.get("ScriptFilename", "") or ""
            sub.user = consumer.get("UserName", "") or "Unknown"
        elif cls == "LogFileEventConsumer":
            sub.arguments = consumer.get("FileName", "") or ""
        sub.raw_data["consumer"] = consumer
    if not sub.executable and sub.command_line:
        sub.executable = sub.command_line.split('"')[1] if '"' in sub.command_line else sub.command_line.split()[0]
    sub.name = " / ".join(x for x in (sub.consumer_name, sub.filter_name) if x)
    return sub


def _sub_to_entry(sub: WmiSubscription) -> PersistenceEntry:
    if sub.executable:
        command = sub.executable
        if sub.command_line:
            command = sub.command_line
        path = sub.executable or (sub.command_line.split('"')[1] if '"' in sub.command_line else sub.command_line.split()[0])
    elif sub.script:
        command = sub.script[:500]
        path = sub.raw_data.get("consumer", {}).get("ScriptFilename", "") or ""
    else:
        command = ""
        path = ""

    indicators_hint = "WMI"
    evidence = [
        f"Namespace: {sub.namespace}",
        f"Consumer: {sub.consumer_name} ({sub.consumer_type})",
        f"Filter: {sub.filter_name}",
    ]
    if sub.query:
        evidence.append(f"Query: {sub.query}")
    if sub.command_line:
        evidence.append(f"Command: {sub.command_line}")
    if sub.script:
        evidence.append("ScriptContent: stored in raw_data")

    entry = make_entry(
        source=Source.WMI,
        category="WMI Subscription",
        name=sub.name or f"{sub.consumer_name} / {sub.filter_name}".strip(" / "),
        path=path,
        command=command,
        arguments=sub.arguments,
        user=sub.user,
        status=sub.enabled,
        raw_data=sub.to_dict() | {"filter_raw": sub.raw_data.get("filter"),
                                   "consumer_raw": sub.raw_data.get("consumer")},
        evidence_raw=evidence,
    )
    if sub.script:
        entry.raw_data["script"] = sub.script
    return entry