"""
Pipeline Orchestrator — the core analysis loop.

Coordinates all analyzer services via HTTP, runs adapters to normalize
responses, accumulates findings, and drives the AI routing loop.

Key facts about each analyzer's real API (deviates from generic docs):

Malware-Analyzer (port 5000 internal / 5001 host):
  - TWO separate calls required:
    1. POST /api/malware-analyzer/file-analysis  (VirusTotal, 60s)
    2. POST /api/malware-analyzer/decompile      (Ghidra, 180s)
  - Both merged as {"vt": ..., "decompile": ...} before adapter

Steg-Analyzer (port 5002):
  - ASYNC — three steps:
    1. POST /api/steg-analyzer/upload   field="image" → {"submission_hash": "..."}
    2. Poll  GET  /api/steg-analyzer/status/<hash>  until completed/error
    3. GET   /api/steg-analyzer/result/<hash>       → {"results": {...}}

Recon-Analyzer (port 5000 internal / 5003 host):
  - POST /api/Recon-Analyzer/scan   {"query": "ip_or_domain"}
  - POST /api/Recon-Analyzer/footprint  {"query": "..."}
  - Key is "query", prefix capital R and A

Web-Analyzer (port 5000 internal / 5005 host):
  - 34 individual GET endpoints with ?url= param
  - No combined POST endpoint
  - Calls the security-critical subset and aggregates
"""

import logging
import os
import re
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

import requests

from app.classifier.classifier import classify, get_file_head
from app.ai.engine import decide_next
from app.store.findings_store import FindingsStore
from app.adapters import malware_adapter, steg_adapter, recon_adapter, url_adapter, web_adapter, macro_adapter

log = logging.getLogger("secflow.orchestrator")

# Docker-internal service base URLs (overridable via env vars)
_MALWARE_BASE = os.getenv("MALWARE_ANALYZER_URL", "http://malware-analyzer:5000/api/malware-analyzer")
_STEG_BASE    = os.getenv("STEG_ANALYZER_URL",    "http://steg-analyzer:5000/api/steg-analyzer")
_RECON_BASE   = os.getenv("RECON_ANALYZER_URL",   "http://recon-analyzer:5000/api/Recon-Analyzer")
_WEB_BASE     = os.getenv("WEB_ANALYZER_URL",     "http://web-analyzer:5000/api/web-analyzer")
_MACRO_BASE   = os.getenv("MACRO_ANALYZER_URL",   "http://macro-analyzer:5000/api/macro-analyzer")

# Steg-Analyzer async polling settings
_STEG_POLL_INTERVAL = 3   # seconds between status checks
_STEG_MAX_WAIT      = 300 # 5 minutes max


# ── Analyzer caller functions ──────────────────────────────────────────────────

def _call_malware(file_path: str, pass_number: int) -> dict[str, Any]:
    """Call malware-analyzer: two requests (VT + Ghidra), merge, then adapt."""
    vt_resp: dict = {}
    decomp_resp: dict = {}

    # Call 1 — VirusTotal file analysis
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_MALWARE_BASE}/file-analysis",
                files={"file": f},
                timeout=60,
            )
        r.raise_for_status()
        vt_resp = r.json()
        log.info(f"[malware] VT analysis complete for {file_path}")
    except Exception as e:
        log.error(f"[malware] VT call failed: {e}")
        vt_resp = {"success": False, "error": str(e)}

    # Call 2 — Ghidra decompile + objdump
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_MALWARE_BASE}/decompile",
                files={"file": f},
                timeout=180,
            )
        r.raise_for_status()
        decomp_resp = r.json()
        log.info(f"[malware] Decompile complete for {file_path}")
    except Exception as e:
        log.error(f"[malware] Decompile call failed: {e}")
        decomp_resp = {"success": False, "error": str(e)}

    return malware_adapter.adapt(
        {"vt": vt_resp, "decompile": decomp_resp},
        pass_number,
        file_path,
    )


def _call_steg(file_path: str, pass_number: int) -> dict[str, Any]:
    """Call steg-analyzer: async upload → poll → fetch result, then adapt."""
    # Step 1 — upload
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_STEG_BASE}/upload",
                files={"image": f},
                timeout=30,
            )
        r.raise_for_status()
        submission_hash = r.json().get("submission_hash")
        if not submission_hash:
            raise ValueError("No submission_hash in upload response")
        log.info(f"[steg] Upload queued, hash={submission_hash}")
    except Exception as e:
        log.error(f"[steg] Upload failed: {e}")
        return steg_adapter.adapt({}, pass_number, file_path)

    # Step 2 — poll status
    deadline = time.time() + _STEG_MAX_WAIT
    while time.time() < deadline:
        try:
            r = requests.get(f"{_STEG_BASE}/status/{submission_hash}", timeout=10)
            r.raise_for_status()
            status = r.json().get("status", "")
            log.debug(f"[steg] status={status}")
            if status == "completed":
                break
            if status == "error":
                log.error("[steg] Analysis errored out")
                return steg_adapter.adapt({}, pass_number, file_path)
        except Exception as e:
            log.warning(f"[steg] Status poll error: {e}")
        time.sleep(_STEG_POLL_INTERVAL)
    else:
        log.error("[steg] Polling timed out")
        return steg_adapter.adapt({}, pass_number, file_path)

    # Step 3 — fetch result
    try:
        r = requests.get(f"{_STEG_BASE}/result/{submission_hash}", timeout=30)
        r.raise_for_status()
        result_payload = r.json()
        log.info(f"[steg] Results fetched for hash={submission_hash}")
    except Exception as e:
        log.error(f"[steg] Result fetch failed: {e}")
        return steg_adapter.adapt({}, pass_number, file_path)

    return steg_adapter.adapt(result_payload, pass_number, file_path)


def _call_recon(query: str, pass_number: int) -> dict[str, Any]:
    """
    Call recon-analyzer /scan for IP/domain or /footprint for email/phone/username.
    Key is "query" (not "target").
    """
    # Determine which endpoint to use based on input format
    ip_re = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    domain_re = re.compile(
        r"^([a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$"
    )

    is_ip_or_domain = bool(ip_re.match(query)) or bool(domain_re.match(query))
    endpoint = "scan" if is_ip_or_domain else "footprint"

    try:
        r = requests.post(
            f"{_RECON_BASE}/{endpoint}",
            json={"query": query},
            timeout=60,
        )
        r.raise_for_status()
        raw = r.json()
        log.info(f"[recon] {endpoint} complete for {query}")
    except Exception as e:
        log.error(f"[recon] Call failed: {e}")
        raw = {}

    return recon_adapter.adapt(raw, pass_number, query)


def _call_macro(file_path: str, pass_number: int) -> dict[str, Any]:
    """Call macro-analyzer: POST /analyze with the uploaded file, then adapt."""
    try:
        with open(file_path, "rb") as f:
            r = requests.post(
                f"{_MACRO_BASE}/analyze",
                files={"file": f},
                timeout=60,
            )
        r.raise_for_status()
        raw = r.json()
        log.info(f"[macro] Analysis complete for {file_path}, risk_level={raw.get('risk_level')}")
    except Exception as e:
        log.error(f"[macro] Call failed: {e}")
        raw = {
            "success": False,
            "error": f"macro-analyzer call failed: {e}",
        }
    return macro_adapter.adapt(raw, pass_number, file_path)


# ── Download-and-analyze helpers ──────────────────────────────────────────────

_CONTENT_TYPE_TO_ANALYZER: dict[str, str] = {
    "application/x-executable":                                             "malware",
    "application/x-dosexec":                                                "malware",
    "application/x-msdos-program":                                          "malware",
    "application/x-elf":                                                    "malware",
    "application/vnd.microsoft.portable-executable":                        "malware",
    "application/octet-stream":                                             "malware",
    "application/x-sharedlib":                                              "malware",
    "application/x-pie-executable":                                         "malware",
    "application/msword":                                                   "macro",
    "application/vnd.ms-excel":                                             "macro",
    "application/vnd.ms-powerpoint":                                        "macro",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "macro",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":    "macro",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "macro",
    "application/vnd.ms-excel.sheet.macroEnabled.12":                       "macro",
    "application/rtf":                                                      "macro",
    "image/png":  "steg", "image/jpeg": "steg", "image/gif":  "steg",
    "image/bmp":  "steg", "image/webp": "steg", "image/tiff": "steg",
}

_URL_EXT_TO_ANALYZER: dict[str, str] = {
    ".exe": "malware", ".dll": "malware", ".elf": "malware", ".bin": "malware",
    ".so":  "malware", ".out": "malware", ".o":   "malware",
    ".doc": "macro",   ".docx": "macro",  ".xls": "macro",   ".xlsx": "macro",
    ".xlsm": "macro",  ".docm": "macro",  ".ppt": "macro",   ".pptx": "macro",
    ".pptm": "macro",  ".rtf":  "macro",
    ".png": "steg",    ".jpg":  "steg",   ".jpeg": "steg",
    ".gif": "steg",    ".bmp":  "steg",
}

# Content-types that indicate a web page, not a downloadable payload
_SKIP_CONTENT_TYPES = frozenset({
    "text/html", "text/plain", "text/css",
    "text/javascript", "application/javascript", "application/json",
})

_PAYLOAD_MAX_BYTES = 50 * 1024 * 1024  # 50 MB


def _download_payload(url: str) -> tuple[str, str]:
    """
    Stream-download *url* to a named temporary file.
    Returns (temp_file_path, content_type).
    Raises on HTTP error, timeout, or 50 MB cap.
    Caller is responsible for os.unlink() when done.
    """
    with requests.get(url, stream=True, timeout=30, allow_redirects=True) as r:
        r.raise_for_status()
        content_type = (
            r.headers.get("Content-Type", "application/octet-stream")
            .split(";")[0].strip().lower()
        )
        ext = os.path.splitext(urlparse(url).path)[-1].lower() or ".bin"
        tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
        try:
            downloaded = 0
            for chunk in r.iter_content(chunk_size=65_536):
                downloaded += len(chunk)
                if downloaded > _PAYLOAD_MAX_BYTES:
                    tmp.close()
                    os.unlink(tmp.name)
                    raise ValueError(
                        f"Download exceeded {_PAYLOAD_MAX_BYTES // (1024 * 1024)} MB cap"
                    )
                tmp.write(chunk)
        finally:
            tmp.close()
    return tmp.name, content_type


def _select_analyzer_for_download(url: str, content_type: str, file_path: str) -> str:
    """Pick best analyzer: content-type → URL extension → python-magic fallback."""
    ct = content_type.split(";")[0].strip().lower()
    if ct in _CONTENT_TYPE_TO_ANALYZER:
        return _CONTENT_TYPE_TO_ANALYZER[ct]
    ext = os.path.splitext(urlparse(url).path)[-1].lower()
    if ext in _URL_EXT_TO_ANALYZER:
        return _URL_EXT_TO_ANALYZER[ext]
    detected, _, _ = classify(file_path)
    return detected or "malware"


def _find_downloadable_urls(result: dict[str, Any], already_downloaded: set[str]) -> list[str]:
    """
    Extract HTTP/S URLs from *result* raw_output + findings evidence that
    haven't been downloaded yet.  URLs with known payload extensions come first.
    """
    text = result.get("raw_output", "") + "\n" + " ".join(
        str(f.get("evidence", ""))
        for f in result.get("findings", [])
        if f.get("evidence")
    )
    all_urls = list(dict.fromkeys(
        u.rstrip("/.,;)")
        for u in re.findall(r"https?://[^\s\"'<>\)\(,\\}]{4,}", text)
        if u not in already_downloaded
    ))
    known_ext = [
        u for u in all_urls
        if os.path.splitext(urlparse(u).path)[-1].lower() in _URL_EXT_TO_ANALYZER
    ]
    other = [u for u in all_urls if u not in known_ext]
    return known_ext + other


def _call_web(url: str, pass_number: int) -> dict[str, Any]:
    """
    Call the security-critical subset of Web-Analyzer GET endpoints.
    Aggregates results, then adapts.
    """
    params = {"url": url}
    aggregated: dict[str, Any] = {}

    # Prioritized list: (endpoint_name, route, timeout)
    endpoints = [
        ("status",           "status",           15),
        ("security_headers", "security-headers", 20),
        ("tls",              "tls",              20),
        ("ssl",              "ssl",              20),
        ("hsts",             "hsts",             15),
        ("firewall",         "firewall",         20),
        ("redirects",        "redirects",        20),
        ("headers",          "headers",          15),
        ("redirect_chain",   "redirect-chain",   30),
        ("malware_check",    "malware-check",    30),
        ("url_parse",        "url-parse",        10),
        ("dns",              "dns",              15),
    ]

    for key, route, timeout in endpoints:
        try:
            r = requests.get(
                f"{_WEB_BASE}/{route}",
                params=params,
                timeout=timeout,
            )
            if r.status_code == 200:
                aggregated[key] = r.json()
                log.debug(f"[web] /{route} OK")
            else:
                log.warning(f"[web] /{route} returned {r.status_code}")
        except requests.exceptions.Timeout:
            log.warning(f"[web] /{route} timed out")
        except Exception as e:
            log.warning(f"[web] /{route} error: {e}")

    return web_adapter.adapt(aggregated, pass_number, url)


# ── Main pipeline loop ─────────────────────────────────────────────────────────

_CALLER_MAP = {
    "malware": _call_malware,
    "steg":    _call_steg,
    "recon":   _call_recon,
    "web":     _call_web,
    "macro":   _call_macro,
}


def _normalize_target(tool: str, target: str) -> str | None:
    """
    Last-mile normalization before passing target to an analyzer.
    - recon: must be a bare IP or hostname (no scheme, no path)
    - web:   must be a full URL with http(s):// scheme
    Returns None if the target cannot be made valid.
    """
    target = target.strip().rstrip("/")
    if not target:
        return None

    if tool == "recon":
        try:
            host = urlparse(target if "://" in target else f"https://{target}").hostname or ""
        except Exception:
            host = ""
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[pipeline] Cannot normalize recon target: {target!r}")
            return None
        return host

    if tool == "web":
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        try:
            host = urlparse(target).hostname or ""
        except Exception:
            host = ""
        if not host or host.startswith(".") or "." not in host:
            log.warning(f"[pipeline] Cannot normalize web target: {target!r}")
            return None
        return target

    return target


def run_pipeline(user_input: str, max_passes: int = 3) -> FindingsStore:
    """
    Run the SecFlow analysis pipeline.

    Args:
        user_input: file path, URL, IP address, or domain name
        max_passes: maximum loop iterations (3, 4, or 5)

    Returns:
        Populated FindingsStore with one entry per completed pass.
    """
    store = FindingsStore()

    # ── Pass 1: Deterministic classification (no AI required) ─────────────────
    log.info(f"[pipeline] Pass 1 — classifying input: {user_input!r}")
    first_analyzer, mime_type, magic_output = classify(user_input)

    if first_analyzer is None:
        # AI fallback: unknown type — ask Gemini to classify
        log.info("[pipeline] Unknown type — using AI fallback for classification")
        file_head = get_file_head(user_input)
        synthetic: dict[str, Any] = {
            "analyzer": "classifier",
            "pass": 0,
            "input": user_input,
            "findings": [],
            "risk_score": 0.0,
            "raw_output": (
                f"MIME: {mime_type}\nmagic: {magic_output}\n"
                f"file head:\n{file_head}"
            ),
        }
        decision = decide_next(synthetic, pass_number=0, max_passes=max_passes, tools_run=[])
        first_analyzer = decision["next_tool"]
        log.info(f"[pipeline] AI chose first analyzer: {first_analyzer} — {decision['reasoning']}")

    if not first_analyzer:
        log.warning("[pipeline] Cannot determine first analyzer — aborting pipeline")
        return store

    # ── Analyzer loop ──────────────────────────────────────────────────────────
    current_tool  = first_analyzer
    current_input = user_input

    # Track executed (tool, target) pairs to avoid infinite loops
    tools_run: list[str] = []
    visited: set[tuple[str, str]] = set()

    # Download-and-analyze state (per run)
    downloaded_urls: set[str] = set()    # URLs already fetched this run
    temp_downloads:  list[str] = []      # temp file paths — cleaned up on exit
    pending_source_url: str | None = None  # provenance URL when current_input was downloaded

    for pass_num in range(1, max_passes + 1):
        # Deduplicate — never re-run the exact same (tool, input) pair
        visit_key = (current_tool, str(current_input))
        if visit_key in visited:
            log.warning(f"[pipeline] Skipping duplicate ({current_tool}, {current_input!r})")
            break
        visited.add(visit_key)

        log.info(f"[pipeline] Pass {pass_num}/{max_passes} — {current_tool} on {current_input!r}")

        caller_fn = _CALLER_MAP.get(current_tool)
        if not caller_fn:
            log.error(f"[pipeline] Unknown analyzer: {current_tool!r}")
            break

        try:
            result = caller_fn(current_input, pass_num)
        except Exception as e:
            log.exception(f"[pipeline] Analyzer {current_tool} raised exception: {e}")
            result = {
                "analyzer": current_tool,
                "pass": pass_num,
                "input": current_input,
                "findings": [{"type": "error", "detail": str(e), "severity": "low", "evidence": ""}],
                "risk_score": 0.0,
                "raw_output": str(e),
            }

        # If current_input is a downloaded payload, always prepend provenance finding
        if pending_source_url:
            result["findings"].insert(0, {
                "type":     "payload_downloaded",
                "detail":   (
                    f"File downloaded from: {pending_source_url}. "
                    "Treat as inherently suspicious regardless of analysis results."
                ),
                "severity": "high",
                "evidence": pending_source_url,
            })
            log.info(f"[pipeline] Injected payload_downloaded provenance (source: {pending_source_url!r})")
            pending_source_url = None

        store.append(result)
        tools_run.append(current_tool)
        log.info(
            f"[pipeline] Pass {pass_num} done — "
            f"{len(result['findings'])} findings, risk_score={result['risk_score']}"
        )

        if pass_num >= max_passes:
            log.info("[pipeline] Max passes reached — stopping loop")
            break

        # ── AI routing decision ────────────────────────────────────────────────
        decision = decide_next(
            result,
            pass_number=pass_num,
            max_passes=max_passes,
            tools_run=tools_run,
        )
        log.info(
            f"[pipeline] AI decision: next={decision['next_tool']!r} "
            f"target={decision['target']!r} — {decision['reasoning']}"
        )

        if not decision["next_tool"]:
            # Before stopping: try to download a payload from URLs found in this pass
            _continue_pipeline = False
            if pass_num < max_passes:
                candidates = _find_downloadable_urls(result, downloaded_urls)
                for dl_url in candidates:
                    try:
                        tmp_path, content_type = _download_payload(dl_url)
                        if content_type in _SKIP_CONTENT_TYPES:
                            log.debug(
                                f"[pipeline] Skipping {dl_url!r} — web content ({content_type})"
                            )
                            os.unlink(tmp_path)
                            continue
                        downloaded_urls.add(dl_url)
                        temp_downloads.append(tmp_path)
                        analyzer = _select_analyzer_for_download(dl_url, content_type, tmp_path)
                        pending_source_url = dl_url
                        current_tool  = analyzer
                        current_input = tmp_path
                        _continue_pipeline = True
                        log.info(
                            f"[pipeline] Downloaded payload from {dl_url!r} "
                            f"({content_type}) → running {analyzer}"
                        )
                        break
                    except Exception as exc:
                        log.warning(f"[pipeline] Payload download failed for {dl_url!r}: {exc}")
            if not _continue_pipeline:
                log.info("[pipeline] AI signalled termination — ending loop early")
                break
            continue  # skip target-normalisation; current_tool/current_input already set

        next_input = decision.get("target")
        if not next_input:
            log.warning("[pipeline] AI provided no target — stopping")
            break

        # Normalize target for the specific tool (safety net after AI validation)
        next_input = _normalize_target(decision["next_tool"], next_input)
        if not next_input:
            log.warning(f"[pipeline] Target normalization failed for tool={decision['next_tool']!r} — stopping")
            break

        # For file-based tools (steg/malware/macro), if the AI returned a bare filename
        # without a directory path, it can't know the actual temp path — use current file.
        if decision["next_tool"] in ("steg", "malware", "macro"):
            if not os.path.isabs(next_input) and not os.path.exists(next_input):
                log.warning(
                    f"[pipeline] AI returned unresolvable file target {next_input!r} "
                    f"for {decision['next_tool']} — using current input {current_input!r}"
                )
                next_input = current_input

        current_tool  = decision["next_tool"]
        current_input = next_input

    # Clean up temp files from downloaded payloads
    for tmp in temp_downloads:
        try:
            os.unlink(tmp)
            log.debug(f"[pipeline] Cleaned up temp download: {tmp}")
        except OSError:
            pass

    log.info(f"[pipeline] Completed — {len(store.get_all())} pass(es) recorded")
    return store
