# 🔍 Log Anomaly Agent — Detect anomalies from logs & auto-generate reports

An agent that reads application logs, **detects anomalies** using *rules +
statistics + LLM (Claude)*, then **produces a report** (HTML + JSON) with
**recommended actions**, and can **send it by email** automatically. It ships
with an **automated test flow** (self-simulated incident/normal logs) that
proves the agent catches the right failures without false alarms.

> DevOps interview task. The **entire core runs on the Python stdlib** — clone and run, nothing to install.

---

## 1. Quick start (30 seconds)

```bash
# No installation needed for the core:
python3 -m src.pipeline --scenario incident      # simulate an incident -> report
python3 -m src.pipeline --scenario normal        # healthy state -> zero anomalies

# Open the report:
open sample_output/report.html
```

Or via Makefile / Docker:

```bash
make demo            # = pipeline incident
make test            # run the automated tests
docker compose run --rm agent   # run in a container
```

Enable Claude-powered root-cause analysis (optional):

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 -m src.pipeline --scenario incident      # root causes now written by the LLM
```

Send the report by email (optional — needs SMTP config in `.env`):

```bash
python3 -m src.pipeline --scenario incident --email --to bon@thinksmartinsurance.com
```

---

## 2. End-to-end architecture

```
 ┌────────────┐   ┌──────────┐   ┌──────────────────────┐   ┌─────────────┐   ┌──────────┐
 │ simulator  │ → │  parser  │ → │       detector       │ → │ llm_analyzer│ → │  report  │ → ✉ emailer
 │ make logs  │   │ struct.  │   │ rules + statistics   │   │ Claude (opt)│   │ HTML+JSON│   (optional)
 └────────────┘   └──────────┘   └──────────────────────┘   └─────────────┘   └──────────┘
   normal/incident                z-score + thresholds +       root cause +      charts +
   (self-simulated)               critical patterns +          actions           actions
                                  episode grouping
```

| Module | Role |
|--------|------|
| `src/simulator.py` | Generate synthetic logs in `normal` / `incident` mode (injects deliberate failures). |
| `src/parser.py` | Parse a raw log line → structured record (timestamp, level, service, status, latency…). |
| `src/detector.py` | **Core**: detect anomalies via rules + statistics, with episode grouping. |
| `src/llm_analyzer.py` | (Optional) call Claude for root cause + actions; **falls back** to a static table without a key. |
| `src/report.py` | Emit HTML (inline SVG charts) + JSON + text summary. |
| `src/emailer.py` | (Optional) send the report over SMTP/Gmail. |
| `src/pipeline.py` | Orchestrator wiring the whole flow + CLI. |

---

## 3. What anomalies does it detect?

| Type (`type`) | Technique | Severity |
|---|---|---|
| `error_spike` | Robust z-score (median + MAD) on errors/window | P1/P2 |
| `latency_spike` | p95 latency over threshold + z-score | P2 |
| `http_5xx` | 5xx rate/window over threshold | P1/P2 |
| `auth_bruteforce` | Burst of 401/403 (suspected password-guessing) | P2 |
| `critical_pattern` | Regex for OOM / disk full / pool exhausted / panic | P1 |
| `new_error_signature` | A new error signature unseen in the baseline | P2 |
| `service_silence` | A service that stopped logging (dead/hung) | P1 |

**Why two tiers (statistics + LLM)?** Statistics/rules are cheap and
deterministic → fast filtering, no token cost, always available. The LLM is
just an *enrichment* layer (natural-language root cause and actions). If the
network or API key is missing, the agent still produces a full report thanks to
**graceful degradation**.

**Robust statistics (median + MAD)** instead of mean + std: the median is not
dragged by the spike itself, reducing misses. **Episode grouping** merges
adjacent same-type windows into one incident with a duration → clean,
non-noisy reports.

---

## 4. Automated test flow

```bash
make test           # or: python3 -m pytest -q
```

Testing principles (`tests/test_detector.py`):
- **Incident → must catch** each failure type (error spike, latency, 5xx, brute-force, OOM, silence) and produce ≥1 P1.
- **Normal → must have no P1** (false-positive control).
- **Stable across multiple random seeds** (1, 7, 99, 2026).

CI (`.github/workflows/ci.yml`) runs on every push: unit tests + pipeline smoke
test (using `--fail-on-p1` so incident exits 1 and normal exits 0) + uploads the
report as an artifact.

---

## 5. Report & recommended actions

Each run produces:
- `sample_output/report.html` — executive summary, overview cards (P1/P2),
  **error-rate & latency p95 charts** (inline SVG), and a detail table:
  *severity · issue · root cause · recommended action*.
- `sample_output/report.json` — machine-readable (feed into alerting/SIEM next).

Example recommendations (mapped by type, optionally refined by the LLM):
- **OOM** → increase heap / find the memory leak / controlled restart.
- **5xx right after a deploy** → consider rollback, check upstream health.
- **Brute-force 401** → enable rate-limit + lockout, block IPs at the WAF, enforce MFA.
- **Service silence** → check liveness/health, add an alert for missing logs.

---

## 6. Running periodically (production hint)

```bash
# cron every 5 minutes: scan real logs, email if any P1
*/5 * * * * cd /opt/anomaly-agent && python3 -m src.pipeline \
    --logfile /var/log/app/app.log --fail-on-p1 --email || true
```

`--fail-on-p1` returns exit code 1 on a P1 incident → easy to plug into
cron/CI/alert managers.

---

## 7. Directory layout

```
.
├── src/                 # simulator, parser, detector, llm_analyzer, report, emailer, pipeline
├── tests/               # automated tests (pytest)
├── sample_output/       # simulated logs + sample reports (HTML/JSON)
├── .github/workflows/   # CI
├── Dockerfile · docker-compose.yml · Makefile · requirements.txt · .env.example
└── README.md
```

## 8. Design decisions (summary)

1. **Zero-dependency core** → reproducible; the reviewer runs it immediately, no setup friction.
2. **LLM is an enhancement, not a hard dependency** → report is produced with or without a key.
3. **Controlled simulation + assertion tests** → proves the detector is correct, not just "seems to run".
4. **Exit code by severity** → ready to plug into a real DevOps pipeline.
