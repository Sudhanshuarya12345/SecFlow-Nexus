# SecFlow — Pipeline Flow

This document describes the precise logic of the SecFlow analysis pipeline from input submission to report generation.

---

## Pipeline Entry Point

The user submits one of:
- A **file** (any format: Office doc, PNG, EXE, ZIP, RTF, …)
- A **URL** string
- An **IP address** string
- A **domain** string

Together with an optional `passes` query param (default `3`, max `5`).

---

## Stage 1 — Input Classification (Pass 1 Only, No AI by default)

```
User Input
    │
    ▼
┌─────────────────────────────────────────────┐
│  python-magic + file command                 │
│  Produce: MIME type + magic string           │
└─────────────┬───────────────────────────────┘
             │
    ┌───────┴───────┐
    │ Deterministic │
    │ Rule Match?   │
    └───────┬───────┘
             │
    ┌───────┴──────────────┐
   Yes                      No (unknown type)
    │                        │
    ▼                        ▼
 Route to first           AI Fallback (Groq):
 analyzer by rule         Pass magic output +
 (see table below)        head-100 of file →
                          returns first_tool
```

### Routing Rules (Deterministic, First Match Wins)

| Priority | Condition | First Analyzer |
|---|---|---|
| 1 | MIME `image/*` or magic contains PNG/JPEG/GIF/BMP/TIFF/WEBP | **steg** |
| 2 | MIME is any MS Office / OLE2 / OpenXML / RTF type, or magic contains “Composite Document File V2”, “Microsoft Office”, “Office Open XML”, “Rich Text Format”; or ZIP with .docx/.xlsx/.pptx extension | **macro** |
| 3 | MIME `application/x-dosexec`, `x-elf`, `x-executable` etc. AND magic confirms PE32/ELF/Mach-O | **malware** |
| 4 | Raw input string matches `^https?://` | **web** |
| 5 | Raw input string matches IPv4 regex | **recon** |
| 6 | Raw input string matches domain regex | **recon** |
| 7 | None of the above | AI fallback (Groq) |

---

## Stage 2 — Analyzer Execution

The selected analyzer is called via HTTP. The orchestrator calls each service at its Docker-internal URL (all containers on port 5000 internally):

| Analyzer | Internal URL | request format |
|---|---|---|
| malware | `http://malware-analyzer:5000/api/malware-analyzer/` | `multipart/form-data` file |
| steg | `http://steg-analyzer:5000/api/steg-analyzer/upload` | `multipart/form-data` file (async: poll `/status`, `/result`) |
| recon | `http://recon-analyzer:5000/api/Recon-Analyzer/scan` | JSON `{"query": "ip_or_domain"}` |
| recon (OSINT) | `http://recon-analyzer:5000/api/Recon-Analyzer/footprint` | JSON `{"query": "email_or_phone_or_username"}` |
| web | `http://web-analyzer:5000/api/web-analyzer/` | JSON `{"url": "..."}` |
| macro | `http://macro-analyzer:5000/api/macro-analyzer/analyze` | `multipart/form-data` file |

The response is passed through the matching adapter and the result is appended to the Findings Store:

```python
{
    "analyzer": "malware",    # which analyzer ran
    "pass":     1,            # current pass number
    "input":    "sample.exe", # what was analyzed
    "findings": [...],        # normalised finding dicts
    "risk_score": 8.5,        # 0.0 – 10.0
    "raw_output": "...",      # full text output (AI reads this)
}
```

---

## Stage 3 — AI Routing Decision

```
raw_output (full text, NOT truncated)
    │
    ▼
┌─────────────────────────────────────────────┐
│  Regex artifact extraction (engine.py)    │
│  — URLs, IPv4 addresses, domain names    │
│  Noise-filter: glibc, pypi, localhost...  │
└───────────────┬──────────────────────────────┘
               │  focused context: artifacts + raw excerpt
               ▼
┌─────────────────────────────────────────────┐
│  Groq qwen/qwen3-32b                      │
│  system: "/no_think"                      │
│  Instruction: return JSON                 │
│  {next_tool, target, reasoning}           │
└───────────────┬──────────────────────────────┘
               │
    ┌─────────┴─────────────────┐
   JSON                        Non-JSON or empty
    │                              │
    │                    Keyword grep fallback:
    │                    scan raw_output vs keywords.txt
    │                    → rule-based routing decision
    │                              │
    └───────────────────────────┘
               │
    {"next_tool": "web" | "malware" | "steg" | "recon" | "macro" | null,
     "target":   "the exact value to pass to the next analyzer",
     "reasoning": "human-readable explanation"}
```

`next_tool: null` = the loop should consider terminating.

---

## Stage 4 — Loop Control

```
while pass_num <= max_passes:

    run analyzer(current_tool, current_input)
    append result → Findings Store
    AI decision → {next_tool, target}

    if next_tool is not null:
        if (next_tool, target) already visited: break  # cycle guard
        current_tool  = next_tool
        current_input = normalise(next_tool, target)
        continue

    # next_tool is null — try download-and-analyze before stopping
    if pass_num < max_passes:
        candidates = extract HTTP/S URLs from raw_output + findings
        for url in candidates (file-ext URLs first):
            download url (stream, 50 MB cap)
            if content-type is text/html or text/plain: skip
            analyzer = pick by content-type → extension → python-magic
            set current_tool = analyzer, current_input = tmp_file_path
            prepend payload_downloaded finding on next result
            continue outer loop

    # no download worked or max passes reached
    break

clean up temp download files
→ proceed to Report Generation
```

### Cycle Guard

The tuple `(tool, normalized_target)` is tracked in `visited`. If the AI tries to route to the same `(tool, target)` pair twice, the loop terminates to prevent infinite cycling.

### Early Termination Conditions

| Condition | Action |
|---|---|
| AI returns `null` and no downloadable payloads found | Break |
| Max passes reached | Break after current pass |
| `(tool, target)` already in `visited` | Break (cycle guard) |
| AI provides a target that fails normalization | Break with warning log |

---

## Stage 5 — Download-and-Analyze

When the AI has no next tool but loop budget remains:

1. Regex-scan `raw_output` + all finding `evidence` fields for `https?://` URLs not yet downloaded this run.
2. Sort: URLs with known payload extensions (`.exe`, `.dll`, `.docx`, `.png`, …) first, then generic URLs.
3. For each candidate URL:
   - Stream-download (30s timeout, 50 MB hard cap).
   - Check `Content-Type` response header. Skip `text/html`, `text/plain`, `text/css`, `application/json` etc. (web pages, not payloads).
   - Pick analyzer: `Content-Type` → URL file extension → python-magic on the temp file.
   - Set `pending_source_url` = the download URL.
   - On the next pass result, prepend a `payload_downloaded` finding (severity: `high`) with the source URL — this always appears in the report regardless of analysis results.
4. If a payload was successfully queued, `continue` the loop (skip target normalisation).
5. If no URL yields a payload, break normally.

---

## Stage 6 — Report Generation

```
Findings Store (all passes)
    │
    ▼
┌──────────────────────────────────────────┐
│  Report Generator                         │
│                                           │
│  1. Build base report from findings       │
│  2. Groq: generate executive summary      │
│     + actionable recommendations          │
│  3. Render PWNDoc HTML:                   │
│     - Risk score cards (per pass + total) │
│     - Per-pass collapsible findings table │
│       "Pass N — Analyzer Name"            │
│     - Evidence rendered by type:          │
│       VT stats tables, AV badge rows,     │
│       VBA code blocks, IOC chip lists,    │
│       amber payload-download banners      │
│  4. "Export PDF" button (window.print())  │
│  5. Write to /app/reports/<job_id>.html   │
└──────────────────────────────────────────┘
```

The report is a **self-contained HTML file** — no server needed to view. All CSS is inline. The "Export PDF" button calls `window.print()` after expanding all `<details>` so nothing is hidden in the PDF.

---

## Full Walk-Through Example

```
Input: invoice.xlsm   Max passes: 5

─── Pass 1 ────────────────────────────────────────────────────
Classifier: ZIP + .xlsm extension → macro rule → Macro Analyzer
Macro Analyzer output:
  olevba: risk=malicious, AutoExec+Suspicious flags
  IOC: http://evil.sh/drop.exe (found in macro code)
  VirusTotal: 12 / 70 engines flagged
Findings Store: [macro_pass1]

AI Decision: URL in IOCs → Web Analyzer on http://evil.sh/drop.exe

─── Pass 2 ────────────────────────────────────────────────────
Web Analyzer input: http://evil.sh/drop.exe
Web output: endpoint alive, 302 redirect to CDN, missing security headers
Findings Store: [macro_pass1, web_pass2]

AI Decision: null (no further tool identified from web scan)
→ Download-and-analyze fallback:
  URL http://evil.sh/drop.exe found in raw_output
  Content-Type: application/x-dosexec → malware analyzer
  Download: drop.exe (2.1 MB) → temp file
  pending_source_url = http://evil.sh/drop.exe

─── Pass 3 ────────────────────────────────────────────────────
Malware Analyzer input: /tmp/secflow_abc123.exe
Result prepended with payload_downloaded finding:
  severity: high, evidence: http://evil.sh/drop.exe
Ghidra: C2 callout to 185.220.101.50 in decompile
VirusTotal: 45 / 70 — Trojan.GenericKDZ, RAT, Downloader
Findings Store: [macro_pass1, web_pass2, malware_pass3]

AI Decision: IP found → Recon Analyzer on 185.220.101.50

─── Pass 4 ────────────────────────────────────────────────────
Recon input: 185.220.101.50
Talos: blacklisted, Tor: is exit node
ThreatFox: MintsLoader malware, confidence 100%
Findings Store: [macro_pass1, web_pass2, malware_pass3, recon_pass4]

AI Decision: null (no further signals)
→ No download candidates → break

─── Report Generation ──────────────────────────────────────
All 4 passes → Groq summary → PWNDoc HTML
Output: /app/reports/<job_id>.html (Export PDF button included)
```

```
User Input
    │
    ▼
┌─────────────────────────────────────────────┐
│  file command + python-magic                │
│  Determine: MIME type, file type string     │
└─────────────┬───────────────────────────────┘
              │
     ┌────────▼─────────┐
     │ Deterministic    │
     │ Rule Match?      │
     └────────┬─────────┘
              │
    ┌─────────┴────────────┐
   Yes                     No (unknown type)
    │                       │
    ▼                       ▼
Route to first          AI Fallback:
analyzer by rule        Pass to Gemini:
(see table below)       - file/magic output
                        - head -100 of file
                        → Gemini returns first_tool
```

### Routing Rules (Deterministic)

| Condition | First Analyzer |
|---|---|
| MIME type is `image/*` (PNG, JPG, BMP, GIF…) | Steganography Analyzer |
| MIME type is `application/x-executable`, `application/x-dosexec`, PE binary | Malware Analyzer |
| Input is a valid URL string | Web Vulnerability Analyzer |
| Input is a valid IP address or domain | Reconnaissance Analyzer |
| None of the above | AI Fallback (Gemini) |

---

## Stage 2 — Analyzer Execution

The selected analyzer runs on the input and produces a structured output object:

```python
{
    "analyzer": "steg",          # which analyzer ran
    "pass": 1,                   # current pass number
    "input": "suspicious.png",   # what was analyzed
    "findings": [...],           # list of finding dicts
    "risk_score": 7.5,           # 0.0 – 10.0
    "raw_output": "..."          # raw tool output (text)
}
```

This output is **immediately appended to the Findings Store**.

---

## Stage 3 — AI Routing Decision

After each analyzer run, the orchestrator submits the analyzer output to the AI Decision Engine:

```
Analyzer Output (raw_output)
    │
    ▼
┌────────────────────────────────────────────┐
│  AI Decision Engine (Gemini tool-calling)  │
│                                            │
│  Prompt includes:                          │
│  - Current analyzer name                  │
│  - raw_output of this pass                │
│  - Available tools: malware, steg,         │
│    recon, web (excluding current)          │
│  - Pass counter and max passes             │
└────────────┬───────────────────────────────┘
             │
    ┌────────▼──────────┐
    │  Gemini confident? │
    └────────┬──────────┘
             │
    ┌────────┴───────────────┐
   Yes                       No
    │                         │
    ▼                         ▼
Return next_tool        Fallback strategy:
                        1. If unclear → pass full output to Gemini
                        2. If noisy   → grep keywords.txt
                                        pass matched lines to Gemini
                        → return next_tool
```

### AI Response Contract

```python
{
    "next_tool": "malware" | "steg" | "recon" | "web" | None,
    "reasoning": "..."   # human-readable explanation
}
```

`next_tool: None` = terminate the loop now.

---

## Stage 4 — Loop Control

```
┌─────────────────────────────────────────────────────┐
│                  Orchestrator Loop                  │
│                                                     │
│  current_pass = 1                                   │
│  max_passes = N  (user-configured: 3, 4, or 5)      │
│                                                     │
│  while current_pass <= max_passes:                  │
│                                                     │
│    1. Run analyzer(current_tool, input)             │
│    2. Append output → Findings Store                │
│    3. AI Decision → next_tool                       │
│    4. If next_tool is None: BREAK (early exit)      │
│    5. current_tool = next_tool                      │
│    6. input = extract_relevant_input(last_findings) │
│    7. current_pass += 1                             │
│                                                     │
│  → Proceed to Report Generation                     │
└─────────────────────────────────────────────────────┘
```

### Early Termination Conditions

| Condition | Action |
|---|---|
| AI returns `next_tool: None` | Break loop immediately |
| Max passes reached | Break loop after completing current pass |
| Analyzer returns no findings (`findings: []`) | Optionally break (configurable) |

---

## Stage 5 — Report Generation

Once the loop ends:

```
Findings Store (all passes)
    │
    ▼
┌──────────────────────────────────────────┐
│  Report Generator                        │
│                                          │
│  1. Serialize Findings Store → JSON      │
│  2. Pass to Gemini with PWNDoc template  │
│  3. Validate output vs pwndoc_schema     │
│  4. Render output:                       │
│     - JSON (raw structured)              │
│     - PDF (rendered)                     │
│     - HTML (rendered)                    │
└──────────────────────────────────────────┘
```

### Report Contents

- **Threat summary** per analyzer with pass number
- **Overall risk score** (aggregated across all passes)
- **Findings timeline** (pass 1 → pass N)
- **Actionable recommendations** per finding
- **Metadata:** input file, total passes run, timestamp

---

## Full Walk-Through Example

```
Input: suspicious.png   Max passes: 5

─── Pass 1 ──────────────────────────────────────────
Classifier: image/png → Steg Analyzer
Steg Analyzer output: embedded EXE found (steg_payload.exe)
AI Decision: → Malware Analyzer (found an EXE payload)
Findings Store: [steg_pass1]

─── Pass 2 ──────────────────────────────────────────
Malware Analyzer input: steg_payload.exe
Malware Analyzer output: C2 callout to http://192.168.1.100/beacon
AI Decision: → Web Analyzer (found HTTP callout URL)
Findings Store: [steg_pass1, mal_pass2]

─── Pass 3 ──────────────────────────────────────────
Web Analyzer input: http://192.168.1.100/beacon
Web Analyzer output: endpoint alive, CVE-XXXX-XXXX found
AI Decision: → Recon Analyzer (found a live IP)
Findings Store: [steg_pass1, mal_pass2, web_pass3]

─── Pass 4 ──────────────────────────────────────────
Recon Analyzer input: 192.168.1.100
Recon Analyzer output: open ports, ASN data, threat intel match
AI Decision: → None (no further signals)
Findings Store: [steg_pass1, mal_pass2, web_pass3, recon_pass4]

EARLY EXIT at pass 4 (AI signalled no further analysis needed).

─── Report Generation ───────────────────────────────
All 4 pass findings → Gemini → PWNDoc
Output: report.json, report.pdf, report.html
```

---

## Input Extraction Between Passes

When the AI selects the next analyzer, the orchestrator must extract the appropriate input for that analyzer from the previous findings:

| Next Analyzer | Extract from Findings |
|---|---|
| Malware | File path of any extracted binary/executable |
| Steganography | File path of any extracted image |
| Reconnaissance | First IP address or domain found |
| Web | First URL or HTTP endpoint found |

If no extractable input is found, the pipeline logs a warning and ends the loop early.
