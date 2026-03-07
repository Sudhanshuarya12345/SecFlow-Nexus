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

**Service location:** `backend/malware-analyzer/` (migrated from old project)
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

**Service location:** `backend/steg-analyzer/` (migrated from old project)
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

**Service location:** `backend/recon-analyzer/` (migrated from old project)
**Docker service:** `recon-analyzer` — runs at `http://recon-analyzer:5003/api/recon-analyzer/`
**Responsibility:**
- Performs OSINT and infrastructure reconnaissance on IPs, domains, and hostnames as an independent HTTP microservice.
- Collects: WHOIS data, DNS records, open ports, geolocation, ASN, reverse DNS, threat intel lookups.
- Returns its own native JSON response; the Orchestrator's `recon_adapter.py` translates it to the SecFlow contract.

**How the Orchestrator calls it:**
```python
requests.post("http://recon-analyzer:5003/api/recon-analyzer/", json={"target": ip_or_domain})
```
**Output contract (after adapter):** `{ "analyzer": "recon", "pass": N, "findings": [...], "risk_score": 0-10 }`

---

### 7. Web Vulnerability Analyzer

**Service location:** `backend/web-analyzer/` (migrated from old project)
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
      adapters/                      ← Translate old analyzer responses → SecFlow contract
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
  malware-analyzer/                  ← FROM OLD PROJECT (Docker service, port 5001)
  steg-analyzer/                     ← FROM OLD PROJECT (Docker service, port 5002)
  recon-analyzer/                    ← FROM OLD PROJECT (Docker service, port 5003)
  url-analyzer/                      ← FROM OLD PROJECT (Docker service, port 5004, internal)
  web-analyzer/                      ← FROM OLD PROJECT (Docker service, port 5005)
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
- [docs/migration.md](docs/migration.md) — Migration guide: incorporating old analyzer services
- [docs/architecture.md](docs/architecture.md) — System architecture diagram (microservices)
- [docs/pipeline-flow.md](docs/pipeline-flow.md) — Pipeline loop logic
- [docs/analyzers.md](docs/analyzers.md) — Per-analyzer capability spec
- [docs/implementation-guide.md](docs/implementation-guide.md) — Hands-on implementation guide with code snippets
