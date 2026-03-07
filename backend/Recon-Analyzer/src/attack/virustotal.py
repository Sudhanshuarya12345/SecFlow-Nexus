"""
VirusTotal v3 threat-intel module for the Recon Analyzer.

Supports three target types:
  - IP address  → GET /api/v3/ip_addresses/{ip}
  - Domain      → GET /api/v3/domains/{domain}
  - URL         → POST /api/v3/urls  (submit)
                  GET  /api/v3/analyses/{id}  (poll until completed)

All functions return a normalised dict with the same top-level keys so the
orchestrator adapter can handle them uniformly regardless of target type.

Required env var: VIRUSTOTAL_API_KEY
  If absent every function returns {"found": False, "error": "VIRUSTOTAL_API_KEY not configured"}
"""

import logging
import os
import time

import requests

logger = logging.getLogger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_TIMEOUT = 20  # seconds per request
_URL_POLL_ATTEMPTS = 3
_URL_POLL_INTERVAL = 10  # seconds between polls


# ── Helpers ────────────────────────────────────────────────────────────────────

def _api_key() -> str:
    return os.getenv("VIRUSTOTAL_API_KEY", "")


def _headers() -> dict[str, str]:
    return {"x-apikey": _api_key()}


def _no_key() -> dict:
    return {"found": False, "error": "VIRUSTOTAL_API_KEY not configured"}


def _http_error(status_code: int) -> dict | None:
    """Return a standard error dict for common HTTP error codes, or None."""
    if status_code == 401:
        return {"found": False, "error": "Invalid VirusTotal API key"}
    if status_code == 403:
        return {"found": False, "error": "VirusTotal API key forbidden — check plan limits"}
    if status_code == 404:
        return {"found": False, "error": "Not found in VirusTotal database"}
    if status_code == 429:
        return {"found": False, "error": "VirusTotal rate limit exceeded"}
    return None


def _parse_attributes(attrs: dict, query: str, vt_type: str) -> dict:
    """
    Extract common analysis fields from a VT attributes dict.
    Returns a base output dict that callers can extend with type-specific fields.

    Field-name differences across endpoints:
      /ip_addresses, /domains  → last_analysis_stats / last_analysis_results
      /analyses/{id}           → stats / results
    """
    stats: dict = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    results: dict = attrs.get("last_analysis_results") or attrs.get("results") or {}

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)
    timeout    = stats.get("timeout", 0)
    total      = sum(stats.values()) if stats else 0

    # Collect up to 10 positive engine detections
    engines: list[dict] = []
    for name, det in results.items():
        if det.get("category") in ("malicious", "suspicious"):
            engines.append({
                "engine":   name,
                "category": det.get("category", ""),
                "result":   det.get("result") or det.get("method", ""),
            })
        if len(engines) >= 10:
            break

    return {
        "found":      True,
        "type":       vt_type,
        "query":      query,
        "malicious":  malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless":   harmless,
        "timeout":    timeout,
        "total":      total,
        "stats":      stats,
        "reputation": attrs.get("reputation", 0),
        "engines":    engines,
        "error":      None,
    }


# ── Public API ─────────────────────────────────────────────────────────────────

def virustotal_ip(ip: str) -> dict:
    """
    Query VirusTotal for an IPv4 address.

    Returns a dict with:
      found, type, query, malicious, suspicious, undetected, harmless, total,
      stats, reputation, engines[], country, as_owner, asn, network, error
    """
    if not _api_key():
        return _no_key()

    try:
        r = requests.get(
            f"{_VT_BASE}/ip_addresses/{ip}",
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        err = _http_error(r.status_code)
        if err:
            return err
        r.raise_for_status()

        attrs = r.json().get("data", {}).get("attributes", {})
        out = _parse_attributes(attrs, ip, "ip")
        out["country"]  = attrs.get("country", "")
        out["as_owner"] = attrs.get("as_owner", "")
        out["asn"]      = attrs.get("asn")
        out["network"]  = attrs.get("network", "")
        logger.info(
            f"[VT] IP {ip}: malicious={out['malicious']}, "
            f"suspicious={out['suspicious']}, total={out['total']}"
        )
        return out

    except requests.exceptions.Timeout:
        logger.warning(f"[VT] IP request timed out for {ip}")
        return {"found": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as exc:
        logger.error(f"[VT] IP request failed for {ip}: {exc}")
        return {"found": False, "error": str(exc)}
    except Exception as exc:
        logger.error(f"[VT] Unexpected error for IP {ip}: {exc}")
        return {"found": False, "error": str(exc)}


def virustotal_domain(domain: str) -> dict:
    """
    Query VirusTotal for a domain name.

    Returns a dict with:
      found, type, query, malicious, suspicious, undetected, harmless, total,
      stats, reputation, engines[], registrar, categories, creation_date,
      whois (truncated to 500 chars), error
    """
    if not _api_key():
        return _no_key()

    try:
        r = requests.get(
            f"{_VT_BASE}/domains/{domain}",
            headers=_headers(),
            timeout=_TIMEOUT,
        )
        err = _http_error(r.status_code)
        if err:
            return err
        r.raise_for_status()

        attrs = r.json().get("data", {}).get("attributes", {})
        out = _parse_attributes(attrs, domain, "domain")
        out["registrar"]     = attrs.get("registrar", "")
        out["categories"]    = attrs.get("categories", {})     # {vendor: category}
        out["creation_date"] = attrs.get("creation_date")      # epoch int or None
        out["whois"]         = (attrs.get("whois") or "")[:500]
        logger.info(
            f"[VT] Domain {domain}: malicious={out['malicious']}, "
            f"suspicious={out['suspicious']}, total={out['total']}"
        )
        return out

    except requests.exceptions.Timeout:
        logger.warning(f"[VT] Domain request timed out for {domain}")
        return {"found": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as exc:
        logger.error(f"[VT] Domain request failed for {domain}: {exc}")
        return {"found": False, "error": str(exc)}
    except Exception as exc:
        logger.error(f"[VT] Unexpected error for domain {domain}: {exc}")
        return {"found": False, "error": str(exc)}


def virustotal_url(url: str) -> dict:
    """
    Submit a URL to VirusTotal and poll for the completed analysis report.

    Step 1 — POST /api/v3/urls  (submit URL, get analysis ID)
    Step 2 — GET  /api/v3/analyses/{id}  (poll up to _URL_POLL_ATTEMPTS × _URL_POLL_INTERVAL s)

    Returns a dict with:
      found, type, query, malicious, suspicious, undetected, harmless, total,
      stats, reputation, engines[], final_url, error
    """
    if not _api_key():
        return _no_key()

    try:
        # Step 1: submit the URL
        r = requests.post(
            f"{_VT_BASE}/urls",
            headers=_headers(),
            data={"url": url},          # VT expects form data, not JSON
            timeout=_TIMEOUT,
        )
        err = _http_error(r.status_code)
        if err:
            return err
        r.raise_for_status()

        analysis_id = r.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {"found": False, "error": "VirusTotal did not return an analysis ID"}

        logger.info(f"[VT] URL submitted, analysis_id={analysis_id}")

        # Step 2: poll until completed
        for attempt in range(1, _URL_POLL_ATTEMPTS + 1):
            time.sleep(_URL_POLL_INTERVAL)
            logger.info(f"[VT] URL poll attempt {attempt}/{_URL_POLL_ATTEMPTS}")

            r2 = requests.get(
                f"{_VT_BASE}/analyses/{analysis_id}",
                headers=_headers(),
                timeout=_TIMEOUT,
            )
            if r2.status_code != 200:
                logger.warning(f"[VT] Poll returned {r2.status_code}")
                continue

            data   = r2.json().get("data", {})
            status = data.get("attributes", {}).get("status", "")
            if status != "completed":
                logger.info(f"[VT] Analysis status={status}, waiting...")
                continue

            attrs = data.get("attributes", {})
            out   = _parse_attributes(attrs, url, "url")

            # URL-specific: grab the final (possibly redirected) URL
            meta = data.get("meta", {}).get("url_info", {})
            out["final_url"] = meta.get("url", url)

            logger.info(
                f"[VT] URL {url}: malicious={out['malicious']}, "
                f"suspicious={out['suspicious']}, total={out['total']}"
            )
            return out

        # Analysis still pending
        return {
            "found": False,
            "error": (
                f"VirusTotal analysis still pending after {_URL_POLL_ATTEMPTS * _URL_POLL_INTERVAL}s "
                "— recheck manually on virustotal.com"
            ),
        }

    except requests.exceptions.Timeout:
        logger.warning(f"[VT] URL request timed out for {url}")
        return {"found": False, "error": "Request timed out"}
    except requests.exceptions.RequestException as exc:
        logger.error(f"[VT] URL request failed for {url}: {exc}")
        return {"found": False, "error": str(exc)}
    except Exception as exc:
        logger.error(f"[VT] Unexpected error for URL {url}: {exc}")
        return {"found": False, "error": str(exc)}
