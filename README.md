# OWASP Risk Assessment — Intelligent Web Vulnerability Assessment & Risk Prioritization

An M.Sc. Cyber Security project (University of Mumbai). A local web application that **runs several security
scanners against an authorized website, merges what they find, maps every finding to the OWASP Top 10:2021,
ranks the findings with an explainable risk score, and produces a dashboard plus PDF/CSV reports.**

> ⚖️ **Authorized use only.** Scan only your own systems, local labs, or targets you have written permission to
> test. By default the app only allows `localhost`.

🎬 A 2-minute demo of a real scan is in [`IVA_Demo.mp4`](IVA_Demo.mp4).

---

## 1. What problem does it solve?

A real assessment uses several tools (ZAP, Nmap, Nikto …). Each one:

- writes results in its own format (JSON, XML, text),
- uses its own severity scale (Nikto has none),
- reports the same issue again and again (ZAP reports a missing header once **per page**),
- knows nothing about OWASP categories or whether the target is a lab or a production site.

This project sits **above** the scanners and turns that noise into a short, ranked, explained list.
In a real test against the bundled lab server, **71 raw tool results became 24 distinct findings**, 12 of them
confirmed by two or more independent tools.

## 2. Features

| Area | What you get |
|---|---|
| 🎯 Safe scanning | URL validation, DNS-checked authorization policy (cloud-metadata/link-local always blocked), review + "I am authorized" confirmation, background execution, cancel button |
| 🛠️ 4 assessment methods | Built-in passive HTTP checks (Python) · **OWASP ZAP** (spider + passive, active only if enabled) · **Nmap** (TCP connect) · **Nikto** (DoS tests excluded) |
| 🔗 Correlation | One finding per issue + site, with every affected URL kept as *locations* and every tool that confirmed it kept as *sources* |
| 🗂️ OWASP mapping | OWASP Top 10:2021, rules in `config/owasp_2021.json`; each mapping is **mapped / potential / unmapped** with its reason |
| 📊 Risk engine | 0–100 score with a factor-by-factor explanation; scanner severity shown separately from calculated priority |
| 🖥️ Dashboard | KPI cards, risk gauge, priority vs. severity charts, OWASP heat-grid, cross-tool agreement, trend, recent scans |
| 🔍 Findings | Search + filters, evidence, locations, "Why this priority?", remediation, references |
| 🕘 History | All scans, open / report / delete, **compare two scans** (new · resolved · persistent) |
| 📄 Reports | PDF assessment report and CSV export (spreadsheet-injection safe) |
| 🧪 Demo mode | Clearly labelled sample data to explore the UI without any scanner |

## 3. How it works (flow)

```
 You ──► New scan page
          │  target URL + methods + options
          ▼
 ┌─────────────────────────┐   rejected? → reason shown, nothing runs
 │ Target validation       │   (http/https only, no credentials, every DNS address checked
 │ + authorization policy  │    against the policy; localhost allowed by default)
 └────────────┬────────────┘
              ▼  review screen → tick "I am authorized" → Start
 ┌─────────────────────────┐
 │ ScanManager             │   background thread · live progress · cancel
 └────────────┬────────────┘
     ┌────────┼─────────┬──────────┐
     ▼        ▼         ▼          ▼
 Built-in   OWASP ZAP   Nmap      Nikto           each returns a ToolResult
 HTTP checks (API)      (process) (process)       (completed / failed / unavailable / timeout / cancelled)
     └────────┴────┬────┴──────────┘
                   ▼
 ┌──────────────────────────────────────────────────────────┐
 │ Processing pipeline                                      │
 │ 1. Normalise & sanitise (severity, confidence, text)     │
 │ 2. De-duplicate: fingerprint = issue + site + parameter  │
 │    → merge sources, locations, evidence                  │
 │ 3. OWASP mapping: scanner tag → project rule → CWE →     │
 │    title keyword (potential) → unmapped                  │
 │ 4. Risk engine: score, priority, rationale               │
 └────────────┬─────────────────────────────────────────────┘
              ▼
        SQLite (data/iva.db) ──► Dashboard · Findings · History/Compare · PDF/CSV
```

### Risk score in one line

```
score = base(severity or scanner CVSS×10) × confidence
        + OWASP category impact + exploit evidence + asset criticality + exposure + spread   → clamp 0..100
```

| Priority | Critical | High | Medium | Low | Informational |
|---|---|---|---|---|---|
| Score | ≥ 80 | ≥ 60 | ≥ 35 | ≥ 15 | < 15 |

A guardrail never lets priority go more than **one level above** what the scanner itself said, and CVSS is never
invented. Every finding shows exactly which factors changed its score.

## 4. Requirements

| Needed | Version tested | For |
|---|---|---|
| Python | 3.12 | everything |
| Nmap | 7.80 | Nmap method (optional) |
| Java 17+ and OWASP ZAP | Java 26, ZAP 2.17.0 | ZAP method (optional) |
| Perl (Git for Windows includes one) + Nikto | Nikto 2.6.1 | Nikto method (optional) |

Without the optional tools the built-in checks, dashboard, reports and demo mode still work; the app tells you
which tools are missing and why.

## 5. Install

```powershell
git clone https://github.com/shreya-CSS/owasp-risk-assessment.git
cd owasp-risk-assessment
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env          # then edit .env (see below)
python scripts\init_db.py       # creates data\iva.db (safe to re-run)
```

### Configure `.env`

| Variable | Meaning |
|---|---|
| `IVA_ALLOWED_TARGETS` | Extra hosts / IPs / CIDRs you are authorized to test (localhost is always allowed) |
| `IVA_ALLOW_PRIVATE_NETWORKS` | `true` to allow 10/8, 172.16/12, 192.168/16 (e.g. a lab VM) |
| `IVA_ALLOW_ACTIVE_SCAN` | `true` to allow ZAP **active** scanning (sends attack payloads) — labs only |
| `ZAP_HOME`, `ZAP_API_URL`, `ZAP_API_KEY` | ZAP folder, API address (localhost), API key — make one with `python -c "import secrets;print(secrets.token_urlsafe(32))"` |
| `NMAP_PATH` | Optional; default is PATH or `C:\Program Files (x86)\Nmap\nmap.exe` |
| `NIKTO_PATH`, `PERL_PATH`, `NIKTO_PERL_LIB` | `...\nikto\program\nikto.pl`, Perl executable, folder with extra Perl modules (auto-detects `nikto\perl-lib`) |

`.env` is git-ignored — never commit it.

## 6. Run

Open three terminals in the project folder:

```powershell
python lab\vulnerable_lab_server.py   # 1. intentionally insecure test site → http://127.0.0.1:8008/
python scripts\start_zap.py           # 2. ZAP daemon on 127.0.0.1:8090 (optional, keep open)
streamlit run app.py                  # 3. the application → http://localhost:8501
```

Then: **New scan** → `http://127.0.0.1:8008/` → tick methods → *Review scan* → tick *I am authorized* →
*Start scan* → **Findings** → **Reports**.

### 5-minute demo script

1. **System & method** – all tools green; show the policy and OWASP coverage.
2. **New scan** – enter `http://169.254.169.254/` → rejected (cloud metadata). Then the lab URL with Built-in +
   ZAP + Nmap (+ Nikto) → review → authorize → watch the live radar.
3. **Findings** – CORS issue ranked first; open it to show *Why this priority?*. Search "Content-Security" →
   one finding confirmed by 3 tools across 8 pages.
4. **Dashboard** – gauge, priority vs. severity, OWASP grid, cross-tool agreement.
5. **Scan history** – compare two scans. **Reports** – download the PDF.

`python scripts\record_demo.py` re-records the demo video (needs the app and ZAP running).

## 7. Tests

```powershell
python -m pytest                                                     # 140 tests, ~45 s, no tools needed
$env:IVA_LIVE_TOOLS=1; python -m pytest tests\test_live_tools.py -v  # real Nmap/Nikto/ZAP vs the lab (~3 min)
```

Covers target validation and SSRF-style rejections, risk scoring, OWASP mapping, de-duplication, database
(migrations, hostile input), reports (PDF content, CSV injection, path traversal), every scanner adapter
(missing tools, timeouts, bad API key, malformed XML, real Nikto output), complete/partial/failed/cancelled
scans, and a headless render of every UI page.

## 8. Project structure

```
app.py                     Streamlit entry point
config/                    settings.py (.env), owasp_2021.json (OWASP mapping rules)
modules/
  target_validation.py     URL rules + authorization policy
  scan_manager.py          background scans, cancel, status, demo scans
  http_checks.py           built-in passive checks
  zap_scanner.py nmap_scanner.py nikto_scanner.py   tool adapters
  process_runner.py        safe subprocess (no shell, timeouts)
  finding_normalizer.py    sanitise, fingerprint, merge
  owasp_mapper.py risk_engine.py                    mapping + scoring
  database.py              SQLite schema, migrations, queries
  report_generator.py scan_comparison.py            PDF/CSV, scan diff
ui/                        pages, charts, theme
lab/vulnerable_lab_server.py   local test target (127.0.0.1 only)
scripts/                   init_db.py, start_zap.py, record_demo.py
tests/                     pytest suite (+ fixtures from real tool output)
IVA_Demo.mp4               demo video
```

## 9. Security design (short)

- Only `http/https`; credentials in URLs, odd IP notations, link-local/metadata, multicast and reserved
  addresses are rejected; **every** resolved address must pass the policy.
- Scanners are started with argument lists (`shell=False`), hard timeouts and capped output; Nmap scans the
  validated IP so DNS cannot redirect it.
- The built-in checker follows redirects only within the same site (SSRF protection).
- Parameterised SQL, transactions, forward-only migrations.
- Scanner output is treated as untrusted: never rendered as HTML; CSV formula cells are escaped.
- ZAP API bound to localhost with an API key; a fresh ZAP session per scan so old alerts are never re-reported.

## 10. Important notes & limitations

- Uses **OWASP Top 10:2021** (stable CWE mapping). Another edition can be added as `config/owasp_<year>.json`.
- **Not covered:** injection (A03) unless ZAP active scan is enabled; authorization logic (IDOR); logged-in
  pages; TLS cipher analysis; CVE lookup of disclosed versions; A09 logging failures.
- Risk weights are a documented heuristic, not trained on data, and not yet validated by expert rankings.
- Issues that two tools describe with different names (e.g. stack-trace vs. "Application Error Disclosure")
  are not merged yet.
- One scan at a time; scans run inside the Streamlit process (stopping the app interrupts a scan).
- Nikto stops at the per-tool time limit, so its results can vary between runs.
- Demo-mode data is fake and always labelled **DEMO**.

## 11. Troubleshooting

| Problem | Fix |
|---|---|
| ZAP 🔴 "Cannot reach the ZAP API" | `python scripts\start_zap.py`; check `ZAP_HOME` / `ZAP_API_URL` |
| "ZAP rejected the API key" | Restart ZAP with the script so it uses the key from `.env` |
| Nikto: `Required module not found: XML::Writer` | Put `XML/Writer.pm` in `nikto\perl-lib` or set `NIKTO_PERL_LIB` |
| Nmap: "a required DLL is missing" | Install the VC++ 2013 x86 runtime or a newer Nmap |
| Target rejected as private network | Only if authorized: `IVA_ALLOW_PRIVATE_NETWORKS=true` or add it to `IVA_ALLOWED_TARGETS` |
| TLS error on a lab with self-signed cert | `IVA_VERIFY_TLS=false` (labs only) |

## 12. Tech stack

Python 3.12 · Streamlit · SQLite · pandas · Plotly · fpdf2 · requests · defusedxml · pytest · Playwright ·
OWASP ZAP · Nmap · Nikto

---

**Author:** Pardeshi Shreya Yogesh · M.Sc. Cyber Security, University Department of Information Technology,
University of Mumbai · Guide: Prof. Anupama
