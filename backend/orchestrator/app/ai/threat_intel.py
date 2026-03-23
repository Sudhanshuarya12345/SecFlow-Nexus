"""
Threat Intelligence Generator — SecFlow AI Module.

Makes three sequential structured calls to llama-3.3-70b-versatile (via Groq) to
produce SOC-ready threat intelligence artifacts from the completed pipeline output:

  Call 1 — Threat Summary
      Structured assessment: threat name, actor type, attack chain, IOC inventory,
      MITRE ATT&CK TTPs, confidence level, and full reasoning narrative.

  Call 2 — YARA Detection Rules
      2–5 YARA rules tailored to the specific indicators and strings found.
      Each rule includes a reasoning field citing the exact evidence that drove it.

  Call 3 — SIGMA Detection Rules
      2–4 SIGMA rules for SIEM/SOC deployment (Splunk, Elastic, Sentinel).
      Each rule targets a distinct log source and includes full reasoning.

Context construction:
  - All findings from every pipeline pass are included.
  - Ghidra decompilation output is capped at MAX_DECOMPILE_LINES (1000) lines.
  - All other evidence is included in full (JSON evidence is pretty-printed).
  - Finding evidence from previous passes is sent verbatim — no truncation
    except for decompile/disassembly code blobs.

All three calls use structured JSON output prompts so the model returns
machine-parseable output consistently throughout the project.
"""

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from openai import OpenAI

log = logging.getLogger("secflow.threat_intel")

_MODEL = "llama-3.3-70b-versatile"
_MAX_DECOMPILE_LINES = 1000  # Ghidra output cap — user-specified

# Hard cap on context chars sent to every Groq call.
# llama-3.3-70b-versatile TPM limit is 12 000; at ~4 chars/token this
# leaves ~3 000 tokens for the system prompt + response headroom.
# 8 000 tokens × 4 chars ≈ 32 000 chars sent in the user message.
_MAX_CONTEXT_CHARS = 16_000  # ~7-8k tokens (code/JSON tokenizes at ~2 chars/token)

_client: OpenAI | None = None


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _build_limits(*limits: int) -> tuple[int, ...]:
    ordered: list[int] = []
    for limit in limits:
        normalized = max(4000, int(limit))
        if normalized not in ordered:
            ordered.append(normalized)
    return tuple(ordered)


_SUMMARY_CONTEXT_LIMITS = _build_limits(
    _env_int("THREAT_INTEL_SUMMARY_CONTEXT_CHARS", 28000),
    _env_int("THREAT_INTEL_SUMMARY_RETRY_CONTEXT_CHARS", 18000),
    _env_int("THREAT_INTEL_SUMMARY_FINAL_CONTEXT_CHARS", 12000),
)
_RULE_CONTEXT_LIMITS = _build_limits(
    _env_int("THREAT_INTEL_RULE_CONTEXT_CHARS", 18000),
    _env_int("THREAT_INTEL_RULE_RETRY_CONTEXT_CHARS", 12000),
    _env_int("THREAT_INTEL_RULE_FINAL_CONTEXT_CHARS", 8000),
)
_RETRY_BASE_SECONDS = _env_int("THREAT_INTEL_RETRY_BASE_SECONDS", 2)
_RETRY_MAX_SECONDS = _env_int("THREAT_INTEL_RETRY_MAX_SECONDS", 8)

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
_FILE_RE = re.compile(
    r"\b[\w.-]+\.(?:exe|dll|docm|doc|xlsm|xls|pptm|ppt|js|vbs|ps1|bat|cmd|"
    r"zip|rar|7z|scr|hta|bin)\b",
    re.IGNORECASE,
)


def _error_snippet(err: Any, max_len: int = 220) -> str:
    text = str(err).replace("\n", " ").strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _append_error(existing: str | None, label: str, err: Any) -> str:
    item = f"{label}: {_error_snippet(err, max_len=300)}"
    return item if not existing else f"{existing} | {item}"


def _is_retryable_error(exc: Exception) -> bool:
    if isinstance(exc, json.JSONDecodeError):
        return True
    msg = str(exc).lower()
    retry_markers = (
        "429",
        "413",
        "rate limit",
        "rate_limit",
        "request too large",
        "timeout",
        "timed out",
        "temporarily unavailable",
        "connection reset",
        "did not include any valid rules",
    )
    return any(marker in msg for marker in retry_markers)


def _clip_context(context: str, max_chars: int) -> str:
    if len(context) <= max_chars:
        return context

    marker = (
        "\n[... context truncated to fit model token budget; "
        f"{len(context):,} -> {max_chars:,} chars ...]\n"
    )
    keep_head = int(max_chars * 0.65)
    keep_tail = max(0, max_chars - keep_head - len(marker))
    return context[:keep_head] + marker + context[-keep_tail:]


def _context_variants(context: str, limits: tuple[int, ...]) -> list[str]:
    variants: list[str] = []
    for limit in limits:
        clipped = _clip_context(context, limit)
        if clipped not in variants:
            variants.append(clipped)
    return variants or [context]


def _compact_context_for_rules(context: str) -> str:
    """
    Keep high-signal lines for rule generation to reduce token usage while
    preserving indicators and finding context.
    """
    signal_lines: list[str] = []
    for line in context.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        if (
            stripped.startswith("PASS ")
            or stripped.startswith("[")
            or stripped.startswith("Detail:")
            or stripped.startswith("Evidence:")
            or _URL_RE.search(stripped)
            or _IP_RE.search(stripped)
            or _DOMAIN_RE.search(stripped)
            or _HASH_RE.search(stripped)
            or _FILE_RE.search(stripped)
        ):
            signal_lines.append(line)

    compact = "\n".join(signal_lines)
    source = compact if compact else context
    return _clip_context(source, _RULE_CONTEXT_LIMITS[0])


def _dedupe(items: list[str], limit: int | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        cleaned = item.strip().strip("\"'`[](){}<>,; ")
        if not cleaned:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(cleaned)
        if limit is not None and len(out) >= limit:
            break
    return out


def _to_str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _extract_iocs_from_text(text: str) -> dict[str, list[str]]:
    urls = _dedupe(_URL_RE.findall(text), limit=25)
    ips = _dedupe(_IP_RE.findall(text), limit=25)

    url_domains: list[str] = []
    for url in urls:
        host = urlparse(url).hostname
        if host:
            url_domains.append(host)

    raw_domains = _DOMAIN_RE.findall(text)
    domains = _dedupe(url_domains + raw_domains, limit=30)

    hashes = _dedupe(
        [h for h in _HASH_RE.findall(text) if len(h) in (32, 40, 64)],
        limit=25,
    )
    file_names = _dedupe(_FILE_RE.findall(text), limit=25)

    return {
        "hashes": hashes,
        "ips": ips,
        "domains": domains,
        "urls": urls,
        "file_names": file_names,
    }


def _normalize_iocs(iocs: Any) -> dict[str, list[str]]:
    iocs_dict = iocs if isinstance(iocs, dict) else {}
    return {
        "hashes": _dedupe(_to_str_list(iocs_dict.get("hashes")), limit=25),
        "ips": _dedupe(_to_str_list(iocs_dict.get("ips")), limit=25),
        "domains": _dedupe(_to_str_list(iocs_dict.get("domains")), limit=30),
        "urls": _dedupe(_to_str_list(iocs_dict.get("urls")), limit=25),
        "file_names": _dedupe(_to_str_list(iocs_dict.get("file_names")), limit=25),
    }


def _merge_iocs(*sources: Any) -> dict[str, list[str]]:
    merged = {
        "hashes": [],
        "ips": [],
        "domains": [],
        "urls": [],
        "file_names": [],
    }
    for source in sources:
        normalized = _normalize_iocs(source)
        for key in merged:
            merged[key].extend(normalized[key])
    for key in merged:
        limit = 30 if key == "domains" else 25
        merged[key] = _dedupe(merged[key], limit=limit)
    return merged


def _normalize_threat_summary(payload: Any) -> dict[str, Any]:
    data = payload if isinstance(payload, dict) else {}
    return {
        "threat_name": str(data.get("threat_name") or "Analysis Unavailable"),
        "threat_actor_type": str(data.get("threat_actor_type") or "Unknown"),
        "attack_vector": str(data.get("attack_vector") or ""),
        "attack_chain": [str(v) for v in _to_str_list(data.get("attack_chain"))],
        "iocs": _normalize_iocs(data.get("iocs")),
        "mitre_ttps": data.get("mitre_ttps") if isinstance(data.get("mitre_ttps"), list) else [],
        "severity": str(data.get("severity") or "Medium"),
        "confidence": str(data.get("confidence") or "Medium"),
        "reasoning": str(data.get("reasoning") or ""),
    }


def _normalize_detection_payload(payload: Any, rule_type: str) -> dict[str, Any]:
    data = payload if isinstance(payload, dict) else {}
    rules_raw = data.get("rules")
    if not isinstance(rules_raw, list):
        rules_raw = []

    rules: list[dict[str, Any]] = []
    for idx, rule in enumerate(rules_raw, 1):
        if not isinstance(rule, dict):
            continue
        rule_text = str(rule.get("rule_text") or "").strip()
        if not rule_text:
            continue

        tags_raw = rule.get("tags")
        if isinstance(tags_raw, list):
            tags = [str(t) for t in tags_raw if str(t).strip()]
        elif isinstance(tags_raw, str) and tags_raw.strip():
            tags = [tags_raw.strip()]
        else:
            tags = []

        cleaned_rule: dict[str, Any] = {
            "rule_name": str(rule.get("rule_name") or f"{rule_type.lower()}_rule_{idx}"),
            "description": str(rule.get("description") or ""),
            "reasoning": str(rule.get("reasoning") or ""),
            "rule_text": rule_text,
            "tags": tags,
        }
        if rule_type == "SIGMA":
            cleaned_rule["log_source"] = str(rule.get("log_source") or "")
        rules.append(cleaned_rule)

    if not rules:
        raise ValueError(f"{rule_type} response did not include any valid rules")

    return {
        "reasoning": str(data.get("reasoning") or ""),
        "rules": rules,
        "total_rules": len(rules),
    }


def _collect_iocs_for_fallback(threat_summary: dict[str, Any], context: str) -> dict[str, list[str]]:
    return _merge_iocs(threat_summary.get("iocs", {}), _extract_iocs_from_text(context))


def _fallback_threat_summary(context: str, reason: Exception) -> dict[str, Any]:
    iocs = _extract_iocs_from_text(context)
    lower = context.lower()

    if "[critical]" in lower:
        severity = "Critical"
    elif "[high]" in lower:
        severity = "High"
    elif "[medium]" in lower:
        severity = "Medium"
    else:
        severity = "Low"

    if "macro" in lower:
        attack_vector = "Likely malicious Office macro execution"
    elif iocs["urls"] or iocs["domains"]:
        attack_vector = "Network-delivered or phishing-linked activity"
    elif "steg" in lower or "image" in lower:
        attack_vector = "Potential steganographic payload delivery"
    else:
        attack_vector = "Suspicious behavior identified by automated analyzers"

    return {
        "threat_name": "Automated Threat Detection",
        "threat_actor_type": "Unknown",
        "attack_vector": attack_vector,
        "attack_chain": [
            "Initial suspicious artifact or indicator identified",
            "Analyzer evidence correlated across pipeline passes",
            "Detection and triage actions recommended",
        ],
        "iocs": iocs,
        "mitre_ttps": [],
        "severity": severity,
        "confidence": "Medium",
        "reasoning": (
            "Primary AI threat-summary call failed, so a deterministic summary was "
            f"generated from extracted findings. Trigger: {_error_snippet(reason)}"
        ),
    }


def _escape_yara_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _build_yara_rule_text(
    rule_name: str,
    description: str,
    severity: str,
    literals: list[str],
    *,
    match_two_or_more: bool,
) -> str:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lines = [
        f"rule {rule_name} {{",
        "  meta:",
        f'    description = "{_escape_yara_string(description)}"',
        '    author = "SecFlow Fallback"',
        f'    date = "{today}"',
        f'    severity = "{severity.lower()}"',
        '    reference = "SecFlow deterministic fallback"',
        "  strings:",
    ]

    for idx, value in enumerate(literals, 1):
        lines.append(f'    $s{idx} = "{_escape_yara_string(value)}" nocase')

    lines.extend([
        "  condition:",
        "    2 of them" if match_two_or_more and len(literals) > 1 else "    any of them",
        "}",
    ])
    return "\n".join(lines)


def _fallback_yara_rules(
    threat_summary: dict[str, Any],
    context: str,
    reason: Exception,
) -> dict[str, Any]:
    iocs = _collect_iocs_for_fallback(threat_summary, context)
    lower = context.lower()

    ioc_literals = _dedupe(
        iocs["urls"] + iocs["domains"] + iocs["ips"] + iocs["file_names"],
        limit=7,
    )
    behavior_candidates = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
        "mshta",
        "autoopen",
        "frombase64string",
        "http://",
        "https://",
    ]
    behavior_literals = [token for token in behavior_candidates if token in lower]
    if len(behavior_literals) < 2:
        behavior_literals = _dedupe(behavior_literals + ["powershell", "cmd.exe", "http://"], limit=6)

    rules: list[dict[str, Any]] = []
    if ioc_literals:
        rules.append({
            "rule_name": "SecFlow_Fallback_IOCStrings",
            "description": "Detects high-confidence IOC strings extracted from SecFlow findings.",
            "reasoning": "Generated from extracted IOC values when AI-generated YARA was unavailable.",
            "tags": ["fallback", "ioc", "secflow"],
            "rule_text": _build_yara_rule_text(
                "SecFlow_Fallback_IOCStrings",
                "IOC string matcher generated from SecFlow findings",
                "high",
                ioc_literals,
                match_two_or_more=False,
            ),
        })

    rules.append({
        "rule_name": "SecFlow_Fallback_BehaviorKeywords",
        "description": "Detects suspicious execution and staging keywords from pipeline evidence.",
        "reasoning": "Keyword set derived from suspicious behavior markers in analyzer output.",
        "tags": ["fallback", "behavior", "secflow"],
        "rule_text": _build_yara_rule_text(
            "SecFlow_Fallback_BehaviorKeywords",
            "Behavior keyword matcher generated from SecFlow findings",
            "medium",
            behavior_literals,
            match_two_or_more=True,
        ),
    })

    return {
        "reasoning": (
            "AI YARA generation failed; deterministic fallback rules were generated "
            f"from observed indicators. Trigger: {_error_snippet(reason)}"
        ),
        "rules": rules,
        "total_rules": len(rules),
        "fallback": True,
    }


def _yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _fallback_sigma_process_rule(
    threat_summary: dict[str, Any],
    process_terms: list[str],
) -> dict[str, Any]:
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    mitre_tags: list[str] = ["attack.execution"]
    for ttp in threat_summary.get("mitre_ttps", []):
        if not isinstance(ttp, dict):
            continue
        tid = str(ttp.get("id") or "").lower().strip()
        if tid:
            mitre_tags.append(f"attack.{tid}")
        if len(mitre_tags) >= 3:
            break

    lines = [
        "title: Detect Suspicious Process Indicators (SecFlow Fallback)",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        "description: Detects suspicious process command-line patterns observed by SecFlow.",
        "author: SecFlow Fallback",
        f"date: {today}",
        f"modified: {today}",
        "tags:",
    ]
    for tag in _dedupe(mitre_tags, limit=4):
        lines.append(f"  - {tag}")
    lines.extend([
        "logsource:",
        "  category: process_creation",
        "  product: windows",
        "detection:",
        "  selection_cli:",
        "    CommandLine|contains:",
    ])
    for term in process_terms:
        lines.append(f"      - {_yaml_quote(term)}")
    lines.extend([
        "  condition: selection_cli",
        "falsepositives:",
        "  - Legitimate administrative scripts",
        "level: high",
    ])

    return {
        "rule_name": "detect_secflow_suspicious_process_indicators",
        "description": "Detects suspicious command-line activity related to observed threat behavior.",
        "log_source": "Sysmon",
        "reasoning": "Fallback process-creation rule based on suspicious execution tokens in findings.",
        "tags": _dedupe(mitre_tags, limit=4),
        "rule_text": "\n".join(lines),
    }


def _fallback_sigma_network_rule(
    domains: list[str],
    ips: list[str],
) -> dict[str, Any]:
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    lines = [
        "title: Detect Suspicious Network Indicators (SecFlow Fallback)",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        "description: Detects network connections to suspicious domains or IPs extracted by SecFlow.",
        "author: SecFlow Fallback",
        f"date: {today}",
        f"modified: {today}",
        "tags:",
        "  - attack.command_and_control",
        "  - attack.t1071",
        "logsource:",
        "  category: network_connection",
        "  product: windows",
        "detection:",
    ]

    conditions: list[str] = []
    if domains:
        lines.extend([
            "  selection_domain:",
            "    DestinationHostname|contains:",
        ])
        for domain in domains:
            lines.append(f"      - {_yaml_quote(domain)}")
        conditions.append("selection_domain")

    if ips:
        lines.extend([
            "  selection_ip:",
            "    DestinationIp:",
        ])
        for ip in ips:
            lines.append(f"      - {_yaml_quote(ip)}")
        conditions.append("selection_ip")

    lines.extend([
        f"  condition: {' or '.join(conditions) if conditions else 'selection_domain'}",
        "falsepositives:",
        "  - Approved third-party infrastructure",
        "level: high",
    ])

    return {
        "rule_name": "detect_secflow_network_iocs",
        "description": "Detects network telemetry matching suspicious IOC infrastructure.",
        "log_source": "Network",
        "reasoning": "Fallback network rule generated from IOC infrastructure extracted from findings.",
        "tags": ["fallback", "network", "secflow"],
        "rule_text": "\n".join(lines),
    }


def _fallback_sigma_file_rule(file_names: list[str]) -> dict[str, Any]:
    today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    patterns = file_names or ["payload.exe", "update.exe"]

    lines = [
        "title: Detect Suspicious File Drops (SecFlow Fallback)",
        f"id: {uuid.uuid4()}",
        "status: experimental",
        "description: Detects file write activity tied to suspicious filenames from SecFlow analysis.",
        "author: SecFlow Fallback",
        f"date: {today}",
        f"modified: {today}",
        "tags:",
        "  - attack.defense_evasion",
        "  - attack.t1036",
        "logsource:",
        "  category: file_event",
        "  product: windows",
        "detection:",
        "  selection_file:",
        "    TargetFilename|contains:",
    ]
    for pattern in _dedupe(patterns, limit=6):
        lines.append(f"      - {_yaml_quote(pattern)}")
    lines.extend([
        "  condition: selection_file",
        "falsepositives:",
        "  - Software installation activity",
        "level: medium",
    ])

    return {
        "rule_name": "detect_secflow_suspicious_file_drops",
        "description": "Detects suspicious file creation tied to extracted indicator filenames.",
        "log_source": "Windows Security",
        "reasoning": "Fallback file-event rule generated from suspicious filenames in findings.",
        "tags": ["fallback", "file-event", "secflow"],
        "rule_text": "\n".join(lines),
    }


def _fallback_sigma_rules(
    threat_summary: dict[str, Any],
    context: str,
    reason: Exception,
) -> dict[str, Any]:
    iocs = _collect_iocs_for_fallback(threat_summary, context)
    lower = context.lower()

    process_candidates = [
        "powershell",
        "cmd.exe",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
        "mshta",
        "bitsadmin",
        "frombase64string",
    ]
    process_terms = [token for token in process_candidates if token in lower]
    if not process_terms:
        process_terms = ["powershell", "cmd.exe", "http"]
    process_terms = _dedupe(process_terms, limit=6)

    domains = _dedupe(iocs["domains"], limit=6)
    ips = _dedupe(iocs["ips"], limit=6)

    rules = [_fallback_sigma_process_rule(threat_summary, process_terms)]
    if domains or ips:
        rules.append(_fallback_sigma_network_rule(domains, ips))
    else:
        rules.append(_fallback_sigma_file_rule(iocs["file_names"]))

    return {
        "reasoning": (
            "AI SIGMA generation failed; deterministic fallback rules were generated "
            f"from observed indicators. Trigger: {_error_snippet(reason)}"
        ),
        "rules": rules,
        "total_rules": len(rules),
        "fallback": True,
    }


def _call_model_json(prompt: str, max_tokens: int) -> dict[str, Any]:
    client = _get_client()
    resp = client.chat.completions.create(
        model=_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
        max_tokens=max_tokens,
    )
    raw = resp.choices[0].message.content or ""
    return json.loads(_clean_json(raw))


def _get_client() -> OpenAI:
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        _client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    return _client


def _clean_json(text: str) -> str:
    """Strip <think> blocks and markdown code fences from model output."""
    text = re.sub(r"<think>[\s\S]*?</think>", "", text).strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text).strip()
    return text


# ── Context builder ────────────────────────────────────────────────────────────

def _build_context(raw_findings: list[dict]) -> str:
    """
    Build a comprehensive, model-readable context string from all pipeline passes.

    Strategy:
    - Every finding from every pass is included: type, severity, detail, evidence.
    - decompilation / disassembly evidence is hard-capped at MAX_DECOMPILE_LINES
      lines so the Ghidra JVM output does not dominate the token budget.
    - All other evidence (VT JSON, IOC lists, recon results, olevba output) is
      included in full — these are typically small and highly signal-dense.
    - JSON evidence blobs are pretty-printed for the model to read more easily.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    parts: list[str] = [
        "SECFLOW AUTOMATED THREAT ANALYSIS — COMPLETE PIPELINE OUTPUT",
        f"Date: {today}",
        "=" * 70,
    ]

    for item in raw_findings:
        analyzer  = item.get("analyzer", "unknown").upper()
        pass_num  = item.get("pass", "?")
        risk      = item.get("risk_score", 0)
        input_val = item.get("input", "")

        parts.append(f"\n{'─' * 60}")
        parts.append(
            f"PASS {pass_num} | {analyzer} ANALYZER | "
            f"Risk Score: {risk}/10 | Target: {input_val}"
        )
        parts.append(f"{'─' * 60}")

        for f in item.get("findings", []):
            ftype    = f.get("type", "unknown")
            severity = (f.get("severity") or "info").upper()
            detail   = f.get("detail", "")

            parts.append(f"\n[{severity}] {ftype}")
            parts.append(f"  Detail: {detail}")

            ev = (f.get("evidence") or "").strip()
            if not ev:
                continue

            # Decompile / disassembly: hard cap at 1000 lines
            if ftype in ("decompilation", "disassembly"):
                lines = ev.split("\n")
                taken = min(len(lines), _MAX_DECOMPILE_LINES)
                ev_out = "\n".join(lines[:taken])
                if len(lines) > taken:
                    ev_out += (
                        f"\n[... {len(lines) - taken} additional lines truncated — "
                        f"Ghidra output capped at {_MAX_DECOMPILE_LINES} lines ...]"
                    )
                parts.append(f"  Code Output (first {taken} lines):\n{ev_out}")
                continue

            # JSON evidence — pretty-print for model readability
            if ev.startswith(("{", "[")):
                try:
                    ev = json.dumps(json.loads(ev), indent=2)
                except (json.JSONDecodeError, ValueError):
                    pass

            parts.append(f"  Evidence:\n{ev}")

    context = "\n".join(parts)
    log.info(
        f"[threat_intel] Context built — {len(raw_findings)} passes, "
        f"{len(context):,} chars"
    )
    return context


def _trim_context(context: str) -> str:
    """Truncate context to _MAX_CONTEXT_CHARS, keeping the last portion
    (most recent pass findings are most relevant for rule generation)."""
    if len(context) <= _MAX_CONTEXT_CHARS:
        return context
    kept = context[-_MAX_CONTEXT_CHARS:]
    header = f"[... context trimmed to last {_MAX_CONTEXT_CHARS:,} chars ...]\n"
    log.warning(
        f"[threat_intel] Context trimmed from {len(context):,} "
        f"to {_MAX_CONTEXT_CHARS:,} chars"
    )
    return header + kept


# ── Call 1: Threat Summary ─────────────────────────────────────────────────────

# Exact schema the model must return — shown verbatim in the prompt.
_THREAT_SUMMARY_SCHEMA = """{
  "threat_name": "Descriptive name for this specific threat (e.g. 'Macro-delivered AsyncRAT with Tor-based C2')",
  "threat_actor_type": "one of: APT | Cybercrime | Ransomware | Hacktivism | Script Kiddie | Unknown",
  "attack_vector": "Initial access method description",
  "attack_chain": [
    "Step 1: ...",
    "Step 2: ...",
    "Step N: ..."
  ],
  "iocs": {
    "hashes":     ["sha256 or md5 values found in analysis"],
    "ips":        ["malicious or suspicious IP addresses"],
    "domains":    ["malicious or suspicious domains"],
    "urls":       ["full malicious URLs"],
    "file_names": ["suspicious file names or paths"]
  },
  "mitre_ttps": [
    {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"}
  ],
  "severity":   "Critical | High | Medium | Low",
  "confidence": "High | Medium | Low",
  "reasoning":  "2-4 sentence paragraph explaining what was found, why it is classified this way, and any notable characteristics of this threat."
}"""


def _call_threat_summary(context: str) -> dict[str, Any]:
    """
    Call 1/3 — Generate a structured threat intelligence summary.

    Asks the model to:
    - Identify and name the threat
    - Classify the actor type
    - Extract all IOCs from the evidence
    - Map observed behaviors to MITRE ATT&CK TTPs
    - Provide a confidence-rated assessment with full reasoning
    """
<<<<<<< HEAD
    variants = _context_variants(context, _SUMMARY_CONTEXT_LIMITS)
    total_attempts = len(variants)
    last_exc: Exception | None = None
=======
    context = _trim_context(context)
    prompt = (
        "You are a Tier-3 SOC analyst at a CSIRT. You have just completed a "
        "multi-stage automated threat analysis. Your job is to produce a structured "
        "threat intelligence summary that will be sent to the security leadership team.\n\n"
        "Analyze the complete pipeline output below and respond ONLY with a single "
        "valid JSON object matching this exact schema — no other text:\n\n"
        f"{_THREAT_SUMMARY_SCHEMA}\n\n"
        "Requirements:\n"
        "- Extract EVERY IOC (IP, domain, URL, hash, filename) visible in the evidence.\n"
        "- Map EVERY identified behavior to a real MITRE ATT&CK TTP (use correct IDs).\n"
        "- If a field has no data, use an empty array [] or empty string \"\".\n"
        "- The reasoning field must be substantive (2-4 sentences minimum).\n"
        "- Do NOT wrap the JSON in markdown code fences.\n\n"
        "Complete Pipeline Analysis Output:\n"
        f"{context}"
    )
>>>>>>> 5718a184c23296fe00786f5b399b26b2f7182c36

    for attempt, ctx in enumerate(variants, 1):
        prompt = (
            "You are a Tier-3 SOC analyst at a CSIRT. You have just completed a "
            "multi-stage automated threat analysis. Your job is to produce a structured "
            "threat intelligence summary that will be sent to the security leadership team.\n\n"
            "Analyze the complete pipeline output below and respond ONLY with a single "
            "valid JSON object matching this exact schema — no other text:\n\n"
            f"{_THREAT_SUMMARY_SCHEMA}\n\n"
            "Requirements:\n"
            "- Extract EVERY IOC (IP, domain, URL, hash, filename) visible in the evidence.\n"
            "- Map EVERY identified behavior to a real MITRE ATT&CK TTP (use correct IDs).\n"
            "- If a field has no data, use an empty array [] or empty string \"\".\n"
            "- The reasoning field must be substantive (2-4 sentences minimum).\n"
            "- Do NOT wrap the JSON in markdown code fences.\n\n"
            "Complete Pipeline Analysis Output:\n"
            f"{ctx}"
        )

        log.info(
            f"[threat_intel] Call 1/3 — Threat Summary → {_MODEL} "
            f"(attempt {attempt}/{total_attempts}, context={len(ctx):,} chars)"
        )

        try:
            data = _call_model_json(prompt, max_tokens=1800)
            data = _normalize_threat_summary(data)
            log.info(
                f"[threat_intel] Call 1 complete — threat='{data.get('threat_name', '?')}', "
                f"confidence={data.get('confidence', '?')}"
            )
            return data
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_error(exc)
            log.warning(
                f"[threat_intel] Call 1 attempt {attempt}/{total_attempts} failed: "
                f"{_error_snippet(exc)}"
            )
            if attempt >= total_attempts or not retryable:
                raise

            delay = min(_RETRY_MAX_SECONDS, _RETRY_BASE_SECONDS * attempt)
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("Threat summary generation failed without explicit error")


# ── Call 2: YARA Rules ──────────────────────────────────────────────────────────

_YARA_SCHEMA = """{
  "reasoning": "Overall explanation of why these YARA rules were generated — which evidence drove them and what threats they collectively defend against.",
  "rules": [
    {
      "rule_name":   "SecFlow_ThreatCategory_IndicatorType",
      "description": "One sentence: what this rule detects",
      "reasoning":   "Why this specific rule — cite the exact evidence from the analysis that informed it (e.g. 'The string xyz was found in the Ghidra decompilation at line 42')",
      "tags":        ["malware", "apt", "relevant-tags"],
      "rule_text":   "rule SecFlow_ThreatCategory_IndicatorType {\\n  meta:\\n    description = \\\"...\\\"\\n    author = \\\"SecFlow AI\\\"\\n    date = \\\"YYYY-MM-DD\\\"\\n    severity = \\\"high\\\"\\n    reference = \\\"SecFlow automated analysis\\\"\\n  strings:\\n    $s1 = \\\"suspicious_string\\\"\\n    $b1 = { DE AD BE EF }\\n  condition:\\n    any of them\\n}"
    }
  ],
  "total_rules": 1
}"""


def _call_yara_rules(context: str, threat_summary: dict) -> dict[str, Any]:
    """
    Call 2/3 — Generate YARA detection rules.

    Uses the threat summary from Call 1 as additional context so the rules
    align with the identified threat actor type, TTPs, and IOC inventory.
    Asks for 2–5 rules each targeting a distinct indicator or behavior.
    """
    context = _trim_context(context)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    threat_ctx = json.dumps(threat_summary, indent=2)
    compact_context = _compact_context_for_rules(context)
    variants = _context_variants(compact_context, _RULE_CONTEXT_LIMITS)
    total_attempts = len(variants)
    last_exc: Exception | None = None

    for attempt, ctx in enumerate(variants, 1):
        prompt = (
            "You are an expert malware analyst and detection engineer specializing "
            "in YARA rule authoring. You have a completed threat intelligence summary "
            "and the full pipeline output from an automated security analysis.\n\n"
            "Generate practical YARA rules that a SOC team can deploy immediately to "
            "detect this threat in their file scanning infrastructure, EDR, or sandbox.\n\n"
            "Respond ONLY with a single valid JSON object matching this exact schema — no other text:\n\n"
            f"{_YARA_SCHEMA}\n\n"
            "YARA authoring requirements:\n"
            f"- Use today's date {today} in each rule's meta.date field.\n"
            "- Every rule MUST have valid YARA syntax (compilable with yara-python 4.x).\n"
            "- Use the meta: section: description, author, date, severity, reference.\n"
            "- Base strings/byte patterns on ACTUAL indicators from the analysis output "
            "(do not invent generic strings — use what you found).\n"
            "- Generate 2–5 rules, each targeting a DIFFERENT aspect:\n"
            "  * File signature / magic bytes\n"
            "  * Embedded strings (C2 URLs, mutex names, registry keys)\n"
            "  * VBA macro patterns (if Office documents were analyzed)\n"
            "  * Packed/obfuscated binary indicators\n"
            "  * Network IOC references in memory\n"
            "- Rule names MUST follow: SecFlow_[ThreatCategory]_[IndicatorType]\n"
            "- The 'reasoning' for each rule MUST cite the exact line/evidence from the analysis.\n"
            "- Do NOT wrap the JSON in markdown code fences.\n\n"
            f"Threat Intelligence Summary (from prior analysis):\n{threat_ctx}\n\n"
            f"Complete Pipeline Analysis Output:\n{ctx}"
        )

        log.info(
            f"[threat_intel] Call 2/3 — YARA Rules → {_MODEL} "
            f"(attempt {attempt}/{total_attempts}, context={len(ctx):,} chars)"
        )

        try:
            data = _call_model_json(prompt, max_tokens=2200)
            data = _normalize_detection_payload(data, "YARA")
            log.info(
                f"[threat_intel] Call 2 complete — "
                f"{data.get('total_rules', len(data.get('rules', [])))} YARA rules"
            )
            return data
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_error(exc)
            log.warning(
                f"[threat_intel] Call 2 attempt {attempt}/{total_attempts} failed: "
                f"{_error_snippet(exc)}"
            )
            if attempt >= total_attempts or not retryable:
                raise

            delay = min(_RETRY_MAX_SECONDS, _RETRY_BASE_SECONDS * attempt)
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("YARA generation failed without explicit error")


# ── Call 3: SIGMA Rules ─────────────────────────────────────────────────────────

_SIGMA_SCHEMA = """{
  "reasoning": "Overall explanation of why these SIGMA rules were generated — which log sources they cover and what SOC use-cases they address.",
  "rules": [
    {
      "rule_name":   "detect_threat_behavior_lowercase_underscores",
      "description": "One sentence: what log activity this rule detects",
      "log_source":  "Windows Security | Sysmon | Web Proxy | EDR | DNS | Network | Email",
      "reasoning":   "Why this specific rule — cite the observed behavior from the analysis that necessitates this log source and detection logic",
      "rule_text":   "title: Detect Suspicious Behavior\\nid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\\nstatus: experimental\\ndescription: Detects ...\\nauthor: SecFlow AI\\ndate: YYYY/MM/DD\\nmodified: YYYY/MM/DD\\ntags:\\n  - attack.execution\\n  - attack.t1059\\nlogsource:\\n  category: process_creation\\n  product: windows\\ndetection:\\n  selection:\\n    CommandLine|contains:\\n      - 'suspicious_string'\\n  condition: selection\\nfalsepositives:\\n  - Legitimate administrative scripts\\nlevel: high"
    }
  ],
  "total_rules": 1
}"""


def _call_sigma_rules(context: str, threat_summary: dict) -> dict[str, Any]:
    """
    Call 3/3 — Generate SIGMA detection rules for SIEM deployment.

    Uses the threat summary from Call 1 as context to ensure the SIGMA rules
    map to exactly the observed TTPs and can be imported into any SIGMA-compatible
    SIEM (Splunk, Elastic Security, Microsoft Sentinel, Chronicle, QRadar).
    """
    context = _trim_context(context)
    today_sigma = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    threat_ctx = json.dumps(threat_summary, indent=2)
    compact_context = _compact_context_for_rules(context)
    variants = _context_variants(compact_context, _RULE_CONTEXT_LIMITS)
    total_attempts = len(variants)
    last_exc: Exception | None = None

    for attempt, ctx in enumerate(variants, 1):
        prompt = (
            "You are an expert SIEM detection engineer specializing in SIGMA rule "
            "authoring for enterprise SOC teams. You have a completed threat intelligence "
            "summary and the full pipeline output from an automated security analysis.\n\n"
            "Generate practical SIGMA rules that a SOC team can immediately import into "
            "Splunk, Elastic Security, Microsoft Sentinel, or any SIGMA-compatible SIEM.\n\n"
            "Respond ONLY with a single valid JSON object matching this exact schema — no other text:\n\n"
            f"{_SIGMA_SCHEMA}\n\n"
            "SIGMA authoring requirements:\n"
            f"- Use today's date {today_sigma} in each rule's date and modified fields.\n"
            "- Every rule MUST have valid SIGMA syntax (compatible with sigma-cli 0.x and pySigma).\n"
            "- Include a valid UUID v4 in the 'id' field of each rule (generate a random one).\n"
            "- Use appropriate logsource categories:\n"
            "  * process_creation — command execution, suspicious child processes\n"
            "  * network_connection — outbound C2 traffic, suspicious IPs/domains\n"
            "  * file_event — dropper activity, suspicious file writes\n"
            "  * dns_query — malicious domain lookups\n"
            "  * registry_event — persistence mechanisms\n"
            "  * web — web proxy/WAF logs for URL-based threats\n"
            "- Generate 2–4 rules, each covering a DIFFERENT log source.\n"
            "- Tags MUST map to real MITRE ATT&CK tactics/techniques from the threat summary.\n"
            "- The 'reasoning' for each rule MUST cite the specific observed behavior.\n"
            "- Set appropriate levels: critical | high | medium | low.\n"
            "- Rule names must be lowercase with underscores.\n"
            "- Do NOT wrap the JSON in markdown code fences.\n\n"
            f"Threat Intelligence Summary (from prior analysis):\n{threat_ctx}\n\n"
            f"Complete Pipeline Analysis Output:\n{ctx}"
        )

        log.info(
            f"[threat_intel] Call 3/3 — SIGMA Rules → {_MODEL} "
            f"(attempt {attempt}/{total_attempts}, context={len(ctx):,} chars)"
        )

        try:
            data = _call_model_json(prompt, max_tokens=2200)
            data = _normalize_detection_payload(data, "SIGMA")
            log.info(
                f"[threat_intel] Call 3 complete — "
                f"{data.get('total_rules', len(data.get('rules', [])))} SIGMA rules"
            )
            return data
        except Exception as exc:
            last_exc = exc
            retryable = _is_retryable_error(exc)
            log.warning(
                f"[threat_intel] Call 3 attempt {attempt}/{total_attempts} failed: "
                f"{_error_snippet(exc)}"
            )
            if attempt >= total_attempts or not retryable:
                raise

            delay = min(_RETRY_MAX_SECONDS, _RETRY_BASE_SECONDS * attempt)
            time.sleep(delay)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("SIGMA generation failed without explicit error")


# ── Public entry point ─────────────────────────────────────────────────────────

def generate_threat_intel(raw_findings: list[dict]) -> dict[str, Any]:
    """
    Run three sequential AI calls to produce SOC-ready threat intelligence.

    This function must be called AFTER all pipeline passes complete so the
    model receives the full context from every analyzer.

    Args:
        raw_findings: list of SecFlow contract dicts from the Findings Store.

    Returns:
        {
            "model":          str,   # "llama-3.3-70b-versatile"
            "threat_summary": dict,  # Call 1 — threat name, TTPs, IOCs, reasoning
            "yara":           dict,  # Call 2 — rules[], total_rules, reasoning
            "sigma":          dict,  # Call 3 — rules[], total_rules, reasoning
            "error":          str | None,
        }
    """
    result: dict[str, Any] = {
        "model":          _MODEL,
        "threat_summary": {},
        "yara":           {"rules": [], "total_rules": 0, "reasoning": ""},
        "sigma":          {"rules": [], "total_rules": 0, "reasoning": ""},
        "error":          None,
    }

    context = _build_context(raw_findings)

    # ── Call 1: Threat Summary ─────────────────────────────────────────────────
    try:
        result["threat_summary"] = _call_threat_summary(context)
    except Exception as exc:
        log.warning(f"[threat_intel] Call 1 (threat summary) failed: {exc}")
        result["threat_summary"] = _fallback_threat_summary(context, exc)
        result["error"] = _append_error(result["error"], "threat_summary", exc)

    result["threat_summary"] = _normalize_threat_summary(result["threat_summary"])

    # ── Call 2: YARA Rules ─────────────────────────────────────────────────────
    try:
        result["yara"] = _call_yara_rules(context, result["threat_summary"])
    except Exception as exc:
        log.warning(f"[threat_intel] Call 2 (YARA) failed: {exc}")
        result["yara"] = _fallback_yara_rules(result["threat_summary"], context, exc)
        result["error"] = _append_error(result["error"], "yara", exc)

    # ── Call 3: SIGMA Rules ────────────────────────────────────────────────────
    try:
        result["sigma"] = _call_sigma_rules(context, result["threat_summary"])
    except Exception as exc:
        log.warning(f"[threat_intel] Call 3 (SIGMA) failed: {exc}")
        result["sigma"] = _fallback_sigma_rules(result["threat_summary"], context, exc)
        result["error"] = _append_error(result["error"], "sigma", exc)

    result["yara"]["total_rules"] = len(result["yara"].get("rules", []))
    result["sigma"]["total_rules"] = len(result["sigma"].get("rules", []))

    n_yara = result["yara"].get("total_rules", 0)
    n_sigma = result["sigma"].get("total_rules", 0)
    log.info(
        f"[threat_intel] Complete — {n_yara} YARA rule(s), "
        f"{n_sigma} SIGMA rule(s), model={_MODEL}"
    )
    return result
