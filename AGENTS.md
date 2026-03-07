# AGENTS.md — SecFlow

This file defines the agent architecture for SecFlow and provides instructions for AI coding assistants (GitHub Copilot, etc.) working in this repository.

---

## Project Context

**SecFlow** is a Python-based automated threat analysis pipeline. Its core is a loop-driven orchestrator that routes any input (file, URL, IP, domain, image) through specialized analyzers, guided by Gemini AI tool-calling, and produces PWNDoc reports.

The backend is the primary focus. The frontend is not yet under development.

---

## Agent Roles

SecFlow's runtime pipeline is composed of the following agents/workers:

---

### 1. Pipeline Orchestrator

**File location:** `backend/orchestrator/`
**Responsibility:**
- Receives the user's input and hands it to the Input Classifier for the first pass.
- After each analyzer pass, receives the analyzer output and routes it to the AI Decision Engine.
- Maintains loop state: current pass count, max passes, termination flags.
- Writes every pass's output to the Findings Store.
- Triggers Report Generation when the loop ends.

**Key behaviors:**
- Loop runs for a user-configured max (3, 4, or 5 passes).
- Terminates early if the AI Decision Engine signals no further analyzers are relevant.
- Must never call AI on the first pass if a deterministic rule applies.

---

### 2. Input Classifier

**File location:** `backend/classifier/`
**Responsibility:**
- Identifies the type of the user's input using the `file` system command and `python-magic`.
- Applies deterministic routing rules to select the first analyzer:
  - Image (PNG, JPG, BMP, GIF…) → Steganography Analyzer
  - Executable / PE / binary → Malware Analyzer
  - URL string → Web Vulnerability Analyzer
  - IP address / domain → Reconnaissance Analyzer
- Fallback: if file type is ambiguous or unknown, passes `file`/`python-magic` output + first 100 lines of the file to the AI Decision Engine for classification.

**Key behaviors:**
- No AI is invoked on the first pass when a deterministic rule matches.
- For unknown types, always include `head -100` of the input alongside `file`/`python-magic` output when calling AI.

---

### 3. AI Decision Engine

**File location:** `backend/ai/`
**Responsibility:**
- Wraps the Gemini API with tool-calling capability.
- Takes analyzer output (or classifier output for unknown types) and returns the name of the next analyzer to call (or a termination signal).
- Implements the keyword-grep fallback:
  - If Gemini's response lacks confidence → pass the full analyzer output.
  - If output is noisy → grep a predefined keyword list; pass matched snippets to Gemini.

**Key behaviors:**
- Must return a structured response containing: `next_tool` (string | null) and `reasoning` (string).
- `next_tool: null` = the loop should terminate.
- Keyword list for fallback grep is maintained in `backend/ai/keywords.txt`.

---

### 4. Malware Analyzer

**Service location:** `backend/malware-analyzer/`
**Docker service:** `malware-analyzer` — runs at `http://malware-analyzer:5001/api/malware-analyzer/`
**Responsibility:**
- Analyzes executables, PE binaries, and extracted payloads as an independent HTTP microservice.
- Performs static analysis: hash computation (MD5, SHA256), string extraction, YARA rule matching, PE header inspection.
- Returns its own native JSON response; the Orchestrator's `malware_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://malware-analyzer:5001/api/malware-analyzer/", files={"file": open(path, "rb")})
```
**Output contract (after adapter):** `{ "analyzer": "malware", "pass": N, "findings": [...], "risk_score": 0-10 }`

---

### 5. Steganography Analyzer

**Service location:** `backend/steg-analyzer/`
**Docker service:** `steg-analyzer` — runs at `http://steg-analyzer:5002/api/steg-analyzer/`
**Responsibility:**
- Analyzes image files for hidden/embedded data as an independent HTTP microservice.
- Attempts multiple steg-detection techniques (LSB analysis, metadata inspection, embedded file extraction).
- Returns its own native JSON response; the Orchestrator's `steg_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://steg-analyzer:5002/api/steg-analyzer/", files={"file": open(path, "rb")})
```
**Output contract (after adapter):** `{ "analyzer": "steg", "pass": N, "findings": [...], "extracted_files": [...], "risk_score": 0-10 }`

---

### 6. Reconnaissance Analyzer

**Service location:** `backend/Recon-Analyzer/` — source code under `src/`
**Docker service name:** `recon-analyzer`
**Container port:** `5000` (internal); mapped to host port `5003` in SecFlow `compose.yml`
**Internal Docker URL:** `http://recon-analyzer:5000/api/Recon-Analyzer/`
**Base image:** `python:3.12-slim`
**Production server:** `gunicorn` with 2 workers, 120s timeout
**API prefix:** `/api/Recon-Analyzer` (capital R and A — must be exact)

**Responsibility:**
- Performs threat intelligence and OSINT reconnaissance on IPs, domains, emails, phone numbers, and usernames as an independent HTTP microservice.
- Two distinct modes: **scan** (IP/domain threat intel) and **footprint** (email/phone/username OSINT).
- Returns its own native JSON; the Orchestrator's `recon_adapter.py` translates it to the SecFlow contract.

**Real API endpoints (all under `/api/Recon-Analyzer/`):**

| Method | Route | Purpose | Input |
|---|---|---|---|
| `GET` | `/health` | Health check | None |
| `POST` | `/scan` | IP/domain threat intel | `{"query": "ip_or_domain"}` |
| `POST` | `/footprint` | Email/phone/username OSINT | `{"query": "email_or_phone_or_username"}` |

> **The request body key is `query`, not `target`.** Generic docs assumed `{"target": "..."}` — the real service uses `{"query": "..."}`.

**How the Orchestrator calls it:**
```python
# For IP or domain
requests.post("http://recon-analyzer:5000/api/Recon-Analyzer/scan",
              json={"query": ip_or_domain}, timeout=60)

# For email/phone/username OSINT (secondary use)
requests.post("http://recon-analyzer:5000/api/Recon-Analyzer/footprint",
              json={"query": email_or_username}, timeout=60)
```

**Input auto-detection logic in `/scan`:**
- Valid IPv4 → runs IP-based checks directly
- Valid domain → resolves to IP via DNS, then runs both IP + domain checks
- Invalid format → returns `400`

**Analysis modules used internally:**

| Module | File | What it does |
|---|---|---|
| `ipapi` | `attack/ipapi.py` | IP geolocation (country, ISP, ASN, timezone) via `ip-api.com` batch API |
| `talos` | `attack/talos.py` | Checks IP against Cisco Talos IP blocklist (local file, auto-downloads from snort.org) |
| `tor` | `attack/tor.py` | Checks if IP is a known Tor exit node (local file, auto-downloads from torproject.org) |
| `tranco` | `attack/tranco.py` | Domain ranking lookup via Tranco list API (domains only) |
| `threatfox` | `attack/threatfox.py` | IOC lookup via ThreatFox/abuse.ch API (domains only) |
| `xposedornot` | `osint/xposedornot.py` | Email breach check via XposedOrNot API (footprint only) |
| `phone` | `osint/phone.py` | Phone number validation via NumVerify API (footprint only) |
| `username` | `osint/username.py` | Username search across social platforms using multithreaded scraping via Sagemode (footprint only) |

**`/scan` response shape:**
```json
{
  "query": "8.8.8.8",
  "ipapi":    { "ip_info": [...], "dns_info": {...} },
  "talos":    { "blacklisted": false },
  "tor":      { "is_tor_exit": false },
  "tranco":   { "found": true, "rank": 42 },       // domains only
  "threatfox": { "found": false }                   // domains only
}
```

**`/footprint` response shape (email):**
```json
{
  "query": "user@example.com",
  "type": "email",
  "email_scan": {
    "exposed": true,
    "breach_count": 3,
    "breaches": [...],
    "password_strength": [...],
    "risk": {...}
  }
}
```

**Required environment variables:**

| Variable | Used by | Required? |
|---|---|---|
| `NUMVERIFY_API_KEY` | `phone.py` — phone validation | Optional |
| `THREATFOX_API_KEY` | `threatfox.py` — IOC lookup | Optional (works without it, lower rate limit) |
| `ipAPI_KEY` | `ipapi.py` — IP geolocation | Optional (free tier works without it) |

**Local media files (auto-downloaded if missing):**
- `src/media/talos.txt` — Talos IP blocklist (downloaded from `snort.org/downloads/ip-block-list`)
- `src/media/tor.txt` — Tor exit node IPs (downloaded from `check.torproject.org/exit-addresses`)

**Classifier routing:** The orchestrator routes to `"recon"` when:
- Input matches IPv4 regex `^\d{1,3}(\.\d{1,3}){3}$`
- Input matches domain regex `^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$`

**Output contract (after adapter):** `{ "analyzer": "recon", "pass": N, "input": str, "findings": [...], "risk_score": 0.0–10.0, "raw_output": str }`

**Full integration details:** See [docs/Recon-Analyzer-Orchestration.md](docs/Recon-Analyzer-Orchestration.md) for the adapter pattern, compose config, and classifier rules.

---

### 7. Web Vulnerability Analyzer

**Service location:** `backend/web-analyzer/`
**Docker service:** `web-analyzer` — runs at `http://web-analyzer:5005/api/web-analyzer/`
**Responsibility:**
- Analyzes URLs and web endpoints for vulnerabilities and security misconfigurations as an independent HTTP microservice.
- Performs: HTTP response analysis, security header auditing, technology fingerprinting, basic vuln scanning.
- Returns its own native JSON response; the Orchestrator's `web_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://web-analyzer:5005/api/web-analyzer/", json={"url": target_url})
```
**Output contract (after adapter):** `{ "analyzer": "web", "pass": N, "findings": [...], "risk_score": 0-10 }`

---

### 8. Findings Store

**File location:** `backend/store/`
**Responsibility:**
- Persistent in-memory (and optionally on-disk) accumulator for all analyzer outputs across all loop passes.
- Appends new findings after every pass.
- Provides the full findings history to the Report Generator.

**Key behaviors:**
- Must preserve pass order and analyzer identity in every entry.
- Should expose a method to serialize findings to JSON for the report generator.

---

### 9. Report Generator

**File location:** `backend/reporter/`
**Responsibility:**
- Takes the full Findings Store contents and passes them to Gemini AI for formatting.
- Produces a PWNDoc-compatible report in three formats: JSON, PDF, HTML.
- The report includes: threat summary per analyzer, overall risk score, actionable recommendations, findings timeline.

**Key behaviors:**
- Pass the complete findings store as structured JSON to Gemini, not raw text.
- Validate the Gemini-formatted output against the PWNDoc schema before writing to file.

---

## Coding Conventions

### Language & Style
- **Python 3.11+** for all backend code.
- **Flask** for all HTTP service entrypoints.
- **Docker + Docker Compose** for service orchestration.
- Use **type hints** on all function signatures.
- Format with **black** and lint with **ruff**.
- Each analyzer service is its own Docker container with its own `Dockerfile` and `requirements.txt`.

### Analyzer Output Contract
Every analyzer must return a dict conforming to:
```python
{
    "analyzer": str,          # e.g. "malware", "steg", "recon", "web"
    "pass": int,              # loop iteration number (1-indexed)
    "input": str,             # what was passed to this analyzer
    "findings": list[dict],   # list of individual finding objects
    "risk_score": float,      # 0.0 – 10.0
    "raw_output": str         # raw tool/command output (for AI consumption)
}
```

### AI Decision Engine Contract
The AI Decision Engine must return:
```python
{
    "next_tool": str | None,  # "malware" | "steg" | "recon" | "web" | None
    "reasoning": str          # explanation of the decision
}
```

### Error Handling
- Analyzers must never crash the pipeline. Wrap tool calls in try/except and return an error entry in `findings` instead.
- The Orchestrator must log all loop decisions (pass number, tool chosen, reasoning) for audit.

### File Naming
```
backend/
  orchestrator/                    ← NEW Docker service (port 5000)
    app/
      __init__.py
      routes.py                      ← Flask: POST /api/smart-analyze
      orchestrator.py                ← Pipeline loop (calls analyzers via HTTP)
      classifier/
        classifier.py
        rules.py
      ai/
        engine.py
        keywords.txt
      adapters/                      ← Translate analyzer responses → SecFlow contract
        malware_adapter.py
        steg_adapter.py
        recon_adapter.py
        url_adapter.py
        web_adapter.py
      store/
        findings_store.py
      reporter/
        report_generator.py
        pwndoc_schema.json
    Dockerfile
    requirements.txt
    .env.example
  Malware-Analyzer/                  ← REAL SOURCE (Docker service, host port 5001, container port 5000)
  steg-analyzer/                     ← Analyzer microservice (Docker service, port 5002)
  Recon-Analyzer/                    ← REAL SOURCE (Docker service, host port 5003, container port 5000)
  url-analyzer/                      ← Analyzer microservice (Docker service, port 5004, internal)
  web-analyzer/                      ← Analyzer microservice (Docker service, port 5005)
  compose.yml                        ← Includes all 6 services
  .env.example
```

---

## What NOT to Do

- Do not call the AI Decision Engine on the first pass when a deterministic classifier rule matches.
- Do not skip writing to the Findings Store after any pass.
- Do not generate a report unless the loop has completed (either max passes or early termination).
- Do not hardcode the Gemini API key — use environment variables (`GEMINI_API_KEY`).
- Do not import analyzer code directly into the orchestrator — always call analyzers via HTTP using their service URLs.
- Do not modify analyzer service code to fit the SecFlow contract — use adapters in `orchestrator/app/adapters/` to translate responses.
- Do not expose the `url-analyzer` as a public API route — it is an internal service called only by the Orchestrator.
- Do not implement frontend features until explicitly instructed.

---

## References

- [ProjectDetails.md](ProjectDetails.md) — Full project specification
- [docs/migration.md](docs/migration.md) — Integration guide: analyzer services setup
- [docs/architecture.md](docs/architecture.md) — System architecture diagram (microservices)
- [docs/pipeline-flow.md](docs/pipeline-flow.md) — Pipeline loop logic
- [docs/analyzers.md](docs/analyzers.md) — Per-analyzer capability spec
- [docs/implementation-guide.md](docs/implementation-guide.md) — Hands-on implementation guide with code snippets
- [docs/Malware-Analyzer-Orchestration.md](docs/Malware-Analyzer-Orchestration.md) — Malware Analyzer integration details (real endpoints, adapter, compose config)
- [docs/Recon-Analyzer-Orchestration.md](docs/Recon-Analyzer-Orchestration.md) — Recon Analyzer integration details (real endpoints, adapter, compose config)
