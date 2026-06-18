"""Log simulator.

Generates synthetic application logs (modeling a web/insurance system) in two modes:
- normal:   regular traffic, few errors, low latency.
- incident: injects deliberate failures (error spike, latency, 5xx, auth
            brute-force, OutOfMemory, service silence) to prove the detector
            catches them.

Log format (1 line = 1 event):
    2026-06-18T09:15:01.123Z [INFO] api - request handled method=GET path=/q status=200 duration_ms=42 trace_id=ab12cd
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Iterable

LEVELS_NORMAL = ["DEBUG", "INFO", "INFO", "INFO", "INFO", "WARN"]
SERVICES = ["api", "auth", "payment", "quote-engine", "policy"]
PATHS = ["/api/quote", "/api/policy", "/api/payment", "/api/login", "/health"]
METHODS = ["GET", "GET", "GET", "POST", "POST"]


def _fmt(ts: datetime, level: str, service: str, msg: str, **kv: object) -> str:
    stamp = ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"
    extra = " ".join(f"{k}={v}" for k, v in kv.items())
    return f"{stamp} [{level}] {service} - {msg} {extra}".rstrip()


def _normal_event(ts: datetime, rng: random.Random) -> str:
    service = rng.choice(SERVICES)
    level = rng.choice(LEVELS_NORMAL)
    method = rng.choice(METHODS)
    path = rng.choice(PATHS)
    # ~3% client errors during normal operation, rest 2xx.
    status = rng.choices([200, 201, 400, 404], weights=[80, 10, 5, 5])[0]
    duration = int(rng.gauss(60, 25))
    duration = max(5, duration)
    trace = "%06x" % rng.randrange(16**6)
    if level == "WARN":
        msg = "slow downstream call"
    else:
        msg = "request handled"
    return _fmt(ts, level, service, msg, method=method, path=path,
                status=status, duration_ms=duration, trace_id=trace)


def _incident_events(ts: datetime, rng: random.Random, scenario: str) -> Iterable[str]:
    """Emit events for a given failure scenario at timestamp ts."""
    trace = "%06x" % rng.randrange(16**6)
    if scenario == "error_spike":
        yield _fmt(ts, "ERROR", "payment",
                   "payment gateway timeout after 30000ms",
                   method="POST", path="/api/payment", status=502,
                   duration_ms=30000, trace_id=trace)
    elif scenario == "latency_spike":
        yield _fmt(ts, "WARN", "quote-engine",
                   "request handled (degraded)",
                   method="GET", path="/api/quote", status=200,
                   duration_ms=rng.randint(2500, 6000), trace_id=trace)
    elif scenario == "http_5xx":
        status = rng.choice([500, 503])
        yield _fmt(ts, "ERROR", "api",
                   "unhandled exception in request pipeline",
                   method="GET", path="/api/policy", status=status,
                   duration_ms=rng.randint(800, 2000), trace_id=trace)
    elif scenario == "auth_attack":
        ip = f"203.0.113.{rng.randint(1, 254)}"
        yield _fmt(ts, "WARN", "auth",
                   "invalid credentials",
                   method="POST", path="/api/login", status=401,
                   src_ip=ip, trace_id=trace)
    elif scenario == "oom":
        yield _fmt(ts, "FATAL", "quote-engine",
                   "java.lang.OutOfMemoryError: Java heap space",
                   trace_id=trace)
    elif scenario == "new_error":
        yield _fmt(ts, "ERROR", "policy",
                   "NullPointerException at PolicyMapper.toDto line 88",
                   method="GET", path="/api/policy", status=500,
                   duration_ms=120, trace_id=trace)


def generate(
    *,
    scenario: str = "normal",
    minutes: int = 30,
    rate_per_sec: int = 5,
    seed: int = 42,
    base_time: datetime | None = None,
) -> list[str]:
    """Build a list of log lines.

    scenario: "normal" or "incident".
    minutes:  timeline length.
    rate_per_sec: number of events/second under normal conditions.
    """
    rng = random.Random(seed)
    if base_time is None:
        base_time = datetime(2026, 6, 18, 9, 0, 0, tzinfo=timezone.utc)

    total_seconds = minutes * 60
    lines: list[str] = []

    # Incident windows: 45%-65% of timeline for the main failure cluster,
    # 80%-90% for the brute-force; the "policy" service goes silent from 70%.
    incident = scenario == "incident"
    main_lo, main_hi = int(total_seconds * 0.45), int(total_seconds * 0.65)
    auth_lo, auth_hi = int(total_seconds * 0.80), int(total_seconds * 0.90)
    silence_from = int(total_seconds * 0.70)

    for sec in range(total_seconds):
        ts = base_time + timedelta(seconds=sec)
        for _ in range(rate_per_sec):
            jitter = timedelta(milliseconds=rng.randint(0, 999))
            ev_ts = ts + jitter
            # "policy" goes silent after silence_from (simulated dead service).
            if incident and sec >= silence_from:
                line = _normal_event(ev_ts, rng)
                if " policy - " in line:
                    continue
                lines.append(line)
            else:
                lines.append(_normal_event(ev_ts, rng))

        if not incident:
            continue

        # Inject failures by time window.
        if main_lo <= sec <= main_hi:
            for scn in ("error_spike", "http_5xx"):
                for _ in range(rng.randint(2, 5)):
                    lines.extend(_incident_events(ts + timedelta(milliseconds=rng.randint(0, 999)), rng, scn))
            for _ in range(rng.randint(3, 6)):
                lines.extend(_incident_events(ts + timedelta(milliseconds=rng.randint(0, 999)), rng, "latency_spike"))
            if sec == (main_lo + main_hi) // 2:
                lines.extend(_incident_events(ts, rng, "oom"))
                lines.extend(_incident_events(ts, rng, "new_error"))

        if auth_lo <= sec <= auth_hi:
            for _ in range(rng.randint(8, 15)):
                lines.extend(_incident_events(ts + timedelta(milliseconds=rng.randint(0, 999)), rng, "auth_attack"))

    lines.sort(key=lambda ln: ln[:24])  # sort by timestamp prefix
    return lines


def write_log_file(path: str, **kwargs: object) -> int:
    lines = generate(**kwargs)  # type: ignore[arg-type]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Generate synthetic logs")
    ap.add_argument("--scenario", choices=["normal", "incident"], default="incident")
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--out", default="sample_output/app.log")
    args = ap.parse_args()
    n = write_log_file(args.out, scenario=args.scenario, minutes=args.minutes)
    print(f"Wrote {n} log lines -> {args.out} (scenario={args.scenario})")
