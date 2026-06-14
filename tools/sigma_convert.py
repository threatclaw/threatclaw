#!/usr/bin/env python3
"""
SigmaHQ -> ThreatClaw rule converter.

Reads upstream Sigma YAML (one file or a directory) and emits ThreatClaw rule
YAML adapted to our multi-source ingestion model:

  - logsource categories/products are remapped to our active tag taxonomy
    (osquery.sysmon, osquery.powershell, syslog.tcp.*, opnsense.*, fortinet.*,
    proxmox.*, zeek.*, m365.*) as documented in internal/sigma-field-mapping.md
  - field names are rewritten to canonical paths per source (e.g. Sysmon
    `CommandLine` -> `data.CommandLine`, PowerShell `ScriptBlockText` ->
    `data.ScriptBlockText`)
  - unsupported features (|re, |base64offset, count() aggregations,
    near/timeframe) are detected and the rule is rejected with a reason

Usage:
  tools/sigma_convert.py <input> [--out rules/<pack>] [--report file.md]
                                 [--accept-only-active] [--dry-run]

`<input>` is a path to a single .yml/.yaml file or a directory. Directories
are walked recursively. Output is written to `--out` (default: rules/imported/).
Each accepted rule gets a `.yaml` rule file plus a `.test.yaml` skeleton
(empty positive/negative arrays, marked TODO) so the rule fails the test
gate until a fixture is added by hand.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    sys.stderr.write("pyyaml required: pip install pyyaml\n")
    sys.exit(2)


# ---------------------------------------------------------------------------
# Logsource mapping table
# ---------------------------------------------------------------------------
# Maps upstream (category, product, service) -> our (category, product, service).
# Tuple keys: None means "wildcard / not specified". Lookup order: most-specific
# first. The mapped values are what ThreatClaw's sigma_engine will use for the
# `tag.contains(category) && tag.contains(product)` filter.
LOGSOURCE_MAP: list[tuple[tuple, tuple]] = [
    # Windows Sysmon process creation, registry, file, network, image, process
    # access, pipe, WMI, DNS, etc. -- all land in osquery.sysmon channel.
    (("process_creation", "windows", None), ("osquery", "sysmon", None)),
    (("process_access", "windows", None),   ("osquery", "sysmon", None)),
    (("image_load", "windows", None),       ("osquery", "sysmon", None)),
    (("registry_event", "windows", None),   ("osquery", "sysmon", None)),
    (("registry_set", "windows", None),     ("osquery", "sysmon", None)),
    (("registry_add", "windows", None),     ("osquery", "sysmon", None)),
    (("registry_delete", "windows", None),  ("osquery", "sysmon", None)),
    (("registry_rename", "windows", None),  ("osquery", "sysmon", None)),
    (("file_event", "windows", None),       ("osquery", "sysmon", None)),
    (("file_change", "windows", None),      ("osquery", "sysmon", None)),
    (("file_delete", "windows", None),      ("osquery", "sysmon", None)),
    (("file_rename", "windows", None),      ("osquery", "sysmon", None)),
    (("file_access", "windows", None),      ("osquery", "sysmon", None)),
    (("network_connection", "windows", None), ("osquery", "sysmon", None)),
    (("create_remote_thread", "windows", None), ("osquery", "sysmon", None)),
    (("create_stream_hash", "windows", None), ("osquery", "sysmon", None)),
    (("dns_query", "windows", None),        ("osquery", "sysmon", None)),
    (("pipe_created", "windows", None),     ("osquery", "sysmon", None)),
    (("wmi_event", "windows", None),        ("osquery", "sysmon", None)),
    (("driver_load", "windows", None),      ("osquery", "sysmon", None)),
    (("raw_access_read", "windows", None),  ("osquery", "sysmon", None)),
    (("process_tampering", "windows", None), ("osquery", "sysmon", None)),
    (("sysmon_status", "windows", None),    ("osquery", "sysmon", None)),
    # Windows EventLog channels -- on cyb06 they're surfaced through Sysmon
    # / osquery; later when wazuh.* is active, the *product* filter still
    # matches because we set product=sysmon (tag matched: osquery.sysmon).
    (("ps_module", "windows", None),        ("osquery", "powershell", None)),
    (("ps_script", "windows", None),        ("osquery", "powershell", None)),
    (("ps_classic_start", "windows", None), ("osquery", "powershell", None)),
    (("ps_classic_provider_start", "windows", None), ("osquery", "powershell", None)),
    (("powershell", "windows", None),       ("osquery", "powershell", None)),
    (("powershell-classic", "windows", None), ("osquery", "powershell", None)),
    # Windows security/system/application channels -- routed to sysmon for
    # auth/account events on cyb06 (Wazuh duplicates these in production).
    ((None, "windows", "security"),         ("osquery", "sysmon", None)),
    ((None, "windows", "system"),           ("osquery", "sysmon", None)),
    ((None, "windows", "application"),      ("osquery", "sysmon", None)),
    ((None, "windows", "sysmon"),           ("osquery", "sysmon", None)),
    ((None, "windows", "taskscheduler"),    ("osquery", "sysmon", None)),
    ((None, "windows", "wmi"),              ("osquery", "sysmon", None)),
    ((None, "windows", "ntlm"),             ("osquery", "sysmon", None)),
    ((None, "windows", "appcrash"),         ("osquery", "sysmon", None)),
    ((None, "windows", "smbclient-security"), ("osquery", "sysmon", None)),
    # Generic windows without category -- fall back to sysmon. Imprecise but
    # body-scan fallback still does the right thing for common indicators.
    ((None, "windows", None),               ("osquery", "sysmon", None)),
    # Linux
    (("process_creation", "linux", None),   ("osquery", "linux_processes", None)),
    (("file_event", "linux", None),         ("syslog", None, None)),
    (("network_connection", "linux", None), ("syslog", None, None)),
    (("auditd", "linux", None),             ("syslog", None, None)),
    ((None, "linux", "auth"),               ("syslog", None, None)),
    ((None, "linux", "sshd"),               ("syslog", None, None)),
    ((None, "linux", "sudo"),               ("syslog", None, None)),
    ((None, "linux", "syslog"),             ("syslog", None, None)),
    ((None, "linux", "cron"),               ("syslog", None, None)),
    ((None, "linux", None),                 ("syslog", None, None)),
    # macOS
    (("process_creation", "macos", None),   ("syslog", None, None)),
    ((None, "macos", None),                 ("syslog", None, None)),
    # Cloud / identity
    ((None, "azure", "signinlogs"),         ("m365", "entra", "signin")),
    ((None, "azure", "auditlogs"),          ("m365", "entra", "audit")),
    ((None, "azure", "riskdetection"),      ("m365", "entra", "audit")),
    ((None, "azure", None),                 ("m365", "entra", None)),
    ((None, "m365", None),                  ("m365", None, None)),
    ((None, "okta", "okta"),                ("okta", None, None)),
    ((None, "okta", None),                  ("okta", None, None)),
    ((None, "aws", "cloudtrail"),           ("aws", "cloudtrail", None)),
    ((None, "aws", None),                   ("aws", None, None)),
    ((None, "gcp", None),                   ("gcp", None, None)),
    # Network / firewall
    ((None, "fortinet", None),              ("fortinet", None, None)),
    ((None, "fortigate", None),             ("fortinet", None, None)),
    ((None, "opnsense", None),              ("opnsense", None, None)),
    ((None, "pfsense", None),               ("opnsense", None, None)),
    ((None, "cisco", "asa"),                ("cisco", "asa", None)),
    ((None, "cisco", None),                 ("cisco", None, None)),
    ((None, "mikrotik", None),              ("mikrotik", None, None)),
    ((None, "zeek", None),                  ("zeek", None, None)),
    (("firewall", None, None),              ("syslog", None, None)),
    (("dns", None, None),                   ("opnsense", None, "dns")),
    (("proxy", None, None),                 ("syslog", None, None)),
    (("webserver", None, None),             ("syslog", None, None)),
    # Generic fallbacks
    (("network_connection", None, None),    ("syslog", None, None)),
    (("antivirus", None, None),             ("syslog", None, None)),
]


# ---------------------------------------------------------------------------
# Field name remapping per source
# ---------------------------------------------------------------------------
# Sysmon / Windows EventLog field -> osquery.sysmon canonical path.
SYSMON_FIELDS = {
    "CommandLine":          "data.CommandLine",
    "Image":                "data.Image",
    "ImageLoaded":          "data.ImageLoaded",
    "ParentImage":          "data.ParentImage",
    "ParentCommandLine":    "data.ParentCommandLine",
    "ParentProcessId":      "data.ParentProcessId",
    "ParentProcessGuid":    "data.ParentProcessGuid",
    "ParentUser":           "data.ParentUser",
    "OriginalFileName":     "data.OriginalFileName",
    "OriginalFilename":     "data.OriginalFileName",
    "Description":          "data.Description",
    "Product":              "data.Product",
    "Company":              "data.Company",
    "Hashes":               "data.Hashes",
    "User":                 "data.User",
    "ProcessId":            "data.ProcessId",
    "ProcessGuid":          "data.ProcessGuid",
    "TargetFilename":       "data.TargetFilename",
    "TargetImage":          "data.TargetImage",
    "SourceImage":          "data.SourceImage",
    "TargetObject":         "data.TargetObject",
    "Details":              "data.Details",
    "GrantedAccess":        "data.GrantedAccess",
    "CallTrace":            "data.CallTrace",
    "Signed":               "data.Signed",
    "SignatureStatus":      "data.SignatureStatus",
    "Signature":            "data.Signature",
    "DestinationIp":        "data.DestinationIp",
    "DestinationPort":      "data.DestinationPort",
    "DestinationHostname":  "data.DestinationHostname",
    "DestinationPortName":  "data.DestinationPortName",
    "SourceIp":             "data.SourceIp",
    "SourcePort":           "data.SourcePort",
    "SourceHostname":       "data.SourceHostname",
    "Protocol":             "data.Protocol",
    "Initiated":            "data.Initiated",
    "PipeName":             "data.PipeName",
    "QueryName":            "data.QueryName",
    "QueryResults":         "data.QueryResults",
    "QueryStatus":          "data.QueryStatus",
    "EventID":              "data.EventID",
    "EventType":            "data.EventType",
    "LogonId":              "data.LogonId",
    "IntegrityLevel":       "data.IntegrityLevel",
    "CurrentDirectory":     "data.CurrentDirectory",
    "TerminalSessionId":    "data.TerminalSessionId",
    "StartModule":          "data.StartModule",
    "StartFunction":        "data.StartFunction",
    "StartAddress":         "data.StartAddress",
    "Channel":              "channel",
    "Provider_Name":        "data.ProviderName",
    "ProviderName":         "data.ProviderName",
    "Task":                 "data.Task",
    "EventRecordID":        "data.EventRecordID",
    "Level":                "data.Level",
    "Keywords":             "data.Keywords",
    "RuleName":             "data.RuleName",
    "Service":              "data.Service",
    "ServiceName":          "data.ServiceName",
    "ServiceFileName":      "data.ServiceFileName",
    "ServiceType":          "data.ServiceType",
    "ServiceStartType":     "data.ServiceStartType",
    "TaskName":             "data.TaskName",
    "TaskContent":          "data.TaskContent",
    "AccountName":          "data.AccountName",
    "TargetUserName":       "data.TargetUserName",
    "SubjectUserName":      "data.SubjectUserName",
    "TargetDomainName":     "data.TargetDomainName",
    "SubjectDomainName":    "data.SubjectDomainName",
    "WorkstationName":      "data.WorkstationName",
    "IpAddress":            "data.IpAddress",
    "IpPort":               "data.IpPort",
    "LogonType":            "data.LogonType",
    "LogonProcessName":     "data.LogonProcessName",
    "AuthenticationPackageName": "data.AuthenticationPackageName",
    "FailureReason":        "data.FailureReason",
    "Status":               "data.Status",
    "SubStatus":            "data.SubStatus",
}

# PowerShell channel (osquery.powershell).
PSH_FIELDS = {
    "ScriptBlockText": "data.ScriptBlockText",
    "ScriptBlockId":   "data.ScriptBlockId",
    "Path":            "data.Path",
    "HostApplication": "data.HostApplication",
    "HostName":        "data.HostName",
    "HostVersion":     "data.HostVersion",
    "EngineVersion":   "data.EngineVersion",
    "User":            "data.User",
    "ConnectedUser":   "data.ConnectedUser",
    "CommandName":     "data.CommandName",
    "CommandType":     "data.CommandType",
    "Payload":         "data.Payload",
    "ContextInfo":     "data.ContextInfo",
    "MessageNumber":   "data.MessageNumber",
    "MessageTotal":    "data.MessageTotal",
}

# Unix syslog (top-level flat fields produced by fluent-bit).
SYSLOG_FIELDS = {
    "message":  "message",
    "Message":  "message",
    "hostname": "hostname",
    "Hostname": "hostname",
    "host":     "host",
    "ident":    "ident",
    "process":  "ident",
    "User":     "user",
    "user":     "user",
}

# Firewall: opnsense / pfsense / fortinet -- flat top-level fields.
FW_FIELDS = {
    "src_ip":    "src",
    "SrcIp":     "src",
    "SourceIp":  "src",
    "src":       "src",
    "dst_ip":    "dst",
    "DstIp":     "dst",
    "DestinationIp": "dst",
    "dst":       "dst",
    "dst_port":  "dst_port",
    "DstPort":   "dst_port",
    "DestinationPort": "dst_port",
    "src_port":  "src_port",
    "SrcPort":   "src_port",
    "SourcePort": "src_port",
    "protocol":  "proto",
    "proto":     "proto",
    "action":    "action",
    "Action":    "action",
    "interface": "interface",
    "msg":       "msg",
    "subtype":   "subtype",
}

# m365 / Entra / Exchange / Purview.
M365_FIELDS = {
    "Operation":           "data.operationName",
    "OperationName":       "data.operationName",
    "UserId":              "data.userPrincipalName",
    "UserPrincipalName":   "data.userPrincipalName",
    "ResultType":          "data.resultType",
    "ResultStatus":        "data.resultStatus",
    "ClientIP":            "data.ipAddress",
    "IpAddress":           "data.ipAddress",
    "ClientAppUsed":       "data.clientAppUsed",
    "AppDisplayName":      "data.appDisplayName",
    "AppId":               "data.appId",
    "ConditionalAccessStatus": "data.conditionalAccessStatus",
    "MfaDetail":           "data.mfaDetail",
    "DeviceDetail":        "data.deviceDetail",
    "Status":              "data.status",
    "TargetResources":     "data.targetResources",
    "InitiatedBy":         "data.initiatedBy",
}


def field_map_for(category: str | None, product: str | None) -> dict[str, str]:
    """Pick the right field map for a mapped logsource."""
    if product == "sysmon" or (category == "osquery" and product == "sysmon"):
        return SYSMON_FIELDS
    if product == "powershell" or (category == "osquery" and product == "powershell"):
        return PSH_FIELDS
    if product in {"opnsense", "fortinet", "pfsense", "cisco", "mikrotik"} or category in {"opnsense", "fortinet"}:
        return FW_FIELDS
    if category == "m365" or product in {"entra", "exchange", "purview"}:
        return M365_FIELDS
    return SYSLOG_FIELDS


# ---------------------------------------------------------------------------
# Modifier handling
# ---------------------------------------------------------------------------
SUPPORTED_MODS = {"contains", "startswith", "endswith", "all"}
# Modifiers we silently drop -- their effect is approximated by other matchers.
DROP_MODS = {"windash", "expand"}
# Modifiers that mean the rule can't be converted automatically.
REJECT_MODS = {"re", "base64", "base64offset", "cidr", "utf16", "utf16le", "utf16be", "wide"}


@dataclass
class ConversionReport:
    accepted: list[tuple[str, str]] = field(default_factory=list)
    rejected: list[tuple[str, str, str]] = field(default_factory=list)
    skipped:  list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        total = len(self.accepted) + len(self.rejected) + len(self.skipped)
        return (
            f"Total processed: {total}\n"
            f"Accepted:        {len(self.accepted)}\n"
            f"Rejected:        {len(self.rejected)}\n"
            f"Skipped:         {len(self.skipped)}\n"
        )


# ---------------------------------------------------------------------------
# Conversion
# ---------------------------------------------------------------------------
def map_logsource(ls: dict) -> tuple[dict, str] | tuple[None, str]:
    """
    Look up the upstream (category, product, service) in LOGSOURCE_MAP.
    Return (new_logsource_dict, source_kind_string) or (None, reason).
    """
    cat = ls.get("category")
    prod = ls.get("product")
    svc = ls.get("service")

    candidates = [
        (cat, prod, svc),
        (cat, prod, None),
        (cat, None, svc),
        (None, prod, svc),
        (cat, None, None),
        (None, prod, None),
        (None, None, svc),
    ]
    for cand in candidates:
        for src, tgt in LOGSOURCE_MAP:
            if src == cand:
                new = {}
                if tgt[0]:
                    new["category"] = tgt[0]
                if tgt[1]:
                    new["product"] = tgt[1]
                if tgt[2]:
                    new["service"] = tgt[2]
                kind = "/".join(filter(None, tgt))
                return new, kind
    return None, f"no logsource mapping for category={cat!r} product={prod!r} service={svc!r}"


def split_field_and_modifiers(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], parts[1:]


def remap_field_key(key: str, fmap: dict[str, str]) -> tuple[str | None, str | None]:
    """
    Rewrite a Sigma selection key (e.g. `CommandLine|contains|all`) to our
    target form, applying field renames and modifier whitelisting.

    Returns (new_key, reject_reason). If reject_reason is set the rule must
    be rejected as unsupported.
    """
    if not isinstance(key, str):
        return None, f"non-string selection key: {key!r}"

    field_name, mods = split_field_and_modifiers(key)

    for m in mods:
        if m in REJECT_MODS:
            return None, f"unsupported Sigma modifier |{m}"

    keep_mods = [m for m in mods if m not in DROP_MODS]
    for m in keep_mods:
        if m not in SUPPORTED_MODS:
            return None, f"unknown Sigma modifier |{m}"

    new_field = fmap.get(field_name, field_name)
    if keep_mods:
        return new_field + "|" + "|".join(keep_mods), None
    return new_field, None


def remap_detection(det: dict, fmap: dict[str, str]) -> tuple[dict | None, str | None]:
    """
    Walk every selection block (dict children of the detection node, excluding
    `condition` and `timeframe`) and rewrite each key. Return remapped dict or
    (None, reason).
    """
    new_det: dict[str, Any] = {}
    for block_name, block_val in det.items():
        if block_name == "condition":
            new_det[block_name] = block_val
            continue
        if block_name == "timeframe":
            return None, "aggregation/timeframe not supported by ThreatClaw engine yet"
        if not isinstance(block_val, dict):
            new_det[block_name] = block_val
            continue
        new_block: dict[str, Any] = {}
        for k, v in block_val.items():
            new_k, reason = remap_field_key(k, fmap)
            if reason:
                return None, reason
            new_block[new_k] = v
        new_det[block_name] = new_block
    return new_det, None


def check_condition(cond: Any) -> str | None:
    """
    Reject conditions that use features the ThreatClaw engine doesn't parse:
    - count() / near / by aggregations (no windowed eval today)
    - parenthesized grouping (engine uses a flat left-to-right split parser)
    A condition is normally a string like "selection and not filter".
    """
    if not isinstance(cond, str):
        return None
    low = cond.lower()
    if "count(" in low or "near " in low or "| count " in low or " by " in low:
        return f"unsupported aggregation in condition: {cond!r}"
    if "(" in cond or ")" in cond:
        return f"unsupported parenthesized grouping in condition: {cond!r}"
    return None


def convert_rule(rule: dict, source_path: Path) -> tuple[dict | None, str | None]:
    if "logsource" not in rule:
        return None, "missing logsource"
    if "detection" not in rule:
        return None, "missing detection"

    new_logsource, kind = map_logsource(rule["logsource"])
    if new_logsource is None:
        return None, kind

    fmap = field_map_for(new_logsource.get("category"), new_logsource.get("product"))

    new_detection, reason = remap_detection(rule["detection"], fmap)
    if reason:
        return None, reason

    cond_reason = check_condition(new_detection.get("condition"))
    if cond_reason:
        return None, cond_reason

    out = {
        "title":        rule.get("title", "untitled"),
        "id":           rule.get("id", ""),
        "status":       rule.get("status", "experimental"),
        "description":  rule.get("description", ""),
        "references":   rule.get("references", []),
        "author":       rule.get("author", "ThreatClaw (imported)"),
        "date":         rule.get("date", "2026-06-14"),
        "tags":         rule.get("tags", []),
        "logsource":    new_logsource,
        "detection":    new_detection,
    }
    if "falsepositives" in rule:
        out["falsepositives"] = rule["falsepositives"]
    if "level" in rule:
        out["level"] = rule["level"]
    return out, None


def slugify(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", name.lower()).strip("-")
    return s[:80] if len(s) > 80 else s


def emit_rule(rule: dict, out_dir: Path) -> Path:
    rid = rule.get("id") or slugify(rule.get("title", "rule"))
    safe = slugify(rid) or "rule"
    out_path = out_dir / f"{safe}.yaml"
    with out_path.open("w") as f:
        yaml.dump(rule, f, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)
    return out_path


def emit_test_skeleton(rule: dict, rule_path: Path) -> Path:
    """
    Emit a test fixture skeleton with empty positive/negative arrays so the
    test runner explicitly flags this rule as untested until a human adds a
    real fixture. The runner enforces every rule has a fixture.
    """
    test_path = rule_path.with_suffix("").with_suffix(".test.yaml")
    if test_path.suffix != ".yaml":
        test_path = rule_path.with_name(rule_path.stem + ".test.yaml")
    title = rule.get("title", "untitled")
    rid = rule.get("id", "")
    payload = {
        "rule":       rid,
        "title":      title,
        "positive":   [],
        "negative":   [],
        "notes":      "TODO: add at least one positive and one negative event fixture.",
    }
    with test_path.open("w") as f:
        yaml.dump(payload, f, sort_keys=False, default_flow_style=False, width=120, allow_unicode=True)
    return test_path


def walk_inputs(input_path: Path) -> list[Path]:
    if input_path.is_file():
        return [input_path]
    return sorted(p for p in input_path.rglob("*") if p.suffix in {".yml", ".yaml"})


def load_yaml_safe(path: Path) -> Any | None:
    try:
        with path.open("r") as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        sys.stderr.write(f"YAML parse error in {path}: {e}\n")
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", help="SigmaHQ rule file or directory")
    parser.add_argument("--out", default="rules/imported", help="output directory (default: rules/imported)")
    parser.add_argument("--report", default=None, help="write a markdown report of accepted/rejected rules")
    parser.add_argument("--accept-only-active", action="store_true",
                        help="reject rules whose mapped logsource is not a currently-active tag on cyb06")
    parser.add_argument("--dry-run", action="store_true", help="evaluate but do not write any files")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        sys.stderr.write(f"input not found: {input_path}\n")
        return 2

    out_dir = Path(args.out)
    if not args.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    active_tags = {"osquery.sysmon", "osquery.powershell", "syslog"}

    files = walk_inputs(input_path)
    if not files:
        sys.stderr.write(f"no yaml files under {input_path}\n")
        return 2

    report = ConversionReport()

    for path in files:
        data = load_yaml_safe(path)
        if data is None:
            report.skipped.append((str(path), "yaml parse error"))
            continue
        # SigmaHQ ships single-doc files. A list at top-level happens
        # occasionally for multi-doc; we conservatively skip those.
        if not isinstance(data, dict):
            report.skipped.append((str(path), "not a single-doc rule"))
            continue
        out, reason = convert_rule(data, path)
        if out is None:
            report.rejected.append((str(path), data.get("title", "?"), reason or "unknown"))
            continue
        if args.accept_only_active:
            mp = field_map_for(out["logsource"].get("category"), out["logsource"].get("product"))
            kind = out["logsource"].get("product") or out["logsource"].get("category")
            tag_kind = "osquery." + kind if kind in {"sysmon", "powershell"} else (kind or "")
            if not any(tag_kind.startswith(t) or t.startswith(tag_kind) for t in active_tags):
                report.rejected.append((str(path), data.get("title", "?"), f"target tag {tag_kind!r} inactive on cyb06"))
                continue
        if not args.dry_run:
            rule_path = emit_rule(out, out_dir)
            emit_test_skeleton(out, rule_path)
        report.accepted.append((str(path), out.get("id", "?")))

    print(report.summary())
    if report.rejected:
        print("\n# Rejected (first 20)")
        for path, title, reason in report.rejected[:20]:
            print(f"- {path}: {title} -- {reason}")

    if args.report:
        with open(args.report, "w") as f:
            f.write("# SigmaHQ -> ThreatClaw conversion report\n\n")
            f.write(report.summary())
            f.write("\n## Accepted\n\n")
            for path, rid in report.accepted:
                f.write(f"- `{rid}` -- {path}\n")
            f.write("\n## Rejected\n\n")
            for path, title, reason in report.rejected:
                f.write(f"- `{title}` ({path}) -- {reason}\n")
            f.write("\n## Skipped\n\n")
            for path, reason in report.skipped:
                f.write(f"- {path} -- {reason}\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
