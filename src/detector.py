"""Anomaly detector: rules + statistics (no external libraries).

Two-tier strategy:
  1. Bucket logs into time windows (default 30s), compute per-window metrics.
  2. Apply:
     - Statistics: robust z-score (median + MAD) to catch error / latency spikes.
     - Threshold rules: 5xx rate, 401/403 brute-force, absolute latency.
     - Critical patterns: FATAL / OutOfMemory / pool exhausted -> P1.
     - New error signature: error signatures unseen in the baseline.
     - Silence: a service that stopped logging.

Each anomaly is a normalized object reused by the report and the LLM layer.
"""

from __future__ import annotations

import math
import re
from collections import defaultdict
from dataclasses import dataclass, field

from .parser import LogRecord

# ----- configurable thresholds -----
WINDOW_SECONDS = 30
ERROR_Z = 3.5
ERROR_MIN_ABS = 5          # at least N errors/window to count as a spike
LATENCY_P95_MS = 1000.0    # p95 above this -> anomaly
LATENCY_Z = 3.5
HTTP_5XX_MIN = 3           # >= N 5xx errors/window
AUTH_FAIL_MIN = 8          # >= N 401/403/window -> suspected brute-force
BASELINE_WINDOWS = 3       # first N windows treated as "known" for new-signature

SEVERITY_ORDER = {"P1": 0, "P2": 1, "P3": 2}

CRITICAL_PATTERNS = [
    (re.compile(r"outofmemory", re.I), "OutOfMemory"),
    (re.compile(r"disk (is )?full|no space left", re.I), "Disk full"),
    (re.compile(r"connection pool (is )?exhausted|pool exhausted", re.I), "Connection pool exhausted"),
    (re.compile(r"\bpanic\b|segmentation fault", re.I), "Process crash"),
]


@dataclass
class Anomaly:
    type: str
    severity: str            # P1 / P2 / P3
    title: str
    detail: str
    window_start: str        # ISO
    metric: dict = field(default_factory=dict)
    samples: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "window_start": self.window_start,
            "metric": self.metric,
            "samples": self.samples,
            "recommendation": self.recommendation,
        }


# ----- statistics helpers (pure python) -----
def _median(xs: list[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def _mad(xs: list[float], med: float) -> float:
    if not xs:
        return 0.0
    return _median([abs(x - med) for x in xs])


def _robust_z(x: float, med: float, mad: float) -> float:
    if mad == 0:
        return 0.0
    return 0.6745 * (x - med) / mad


def _p95(xs: list[float]) -> float:
    if not xs:
        return 0.0
    s = sorted(xs)
    idx = max(0, math.ceil(0.95 * len(s)) - 1)
    return s[idx]


def _signature(rec: LogRecord) -> str:
    """Normalize a message into a stable signature (strip numbers/hex/uuid)."""
    msg = rec.message.lower()
    msg = re.sub(r"0x[0-9a-f]+", "#", msg)
    msg = re.sub(r"\b[0-9a-f]{6,}\b", "#", msg)
    msg = re.sub(r"\d+", "#", msg)
    return f"{rec.service}:{msg.strip()[:80]}"


# ----- windowing -----
@dataclass
class Window:
    start_epoch: float
    error_count: int = 0
    total: int = 0
    http_5xx: int = 0
    auth_fail: int = 0
    durations: list[float] = field(default_factory=list)
    services: set[str] = field(default_factory=set)
    error_samples: list[str] = field(default_factory=list)

    @property
    def p95(self) -> float:
        return _p95(self.durations)


def _bucket(records: list[LogRecord], window_s: int) -> list[Window]:
    if not records:
        return []
    base = min(r.epoch for r in records)
    buckets: dict[int, Window] = {}
    for r in records:
        idx = int((r.epoch - base) // window_s)
        w = buckets.get(idx)
        if w is None:
            w = Window(start_epoch=base + idx * window_s)
            buckets[idx] = w
        w.total += 1
        w.services.add(r.service)
        if r.duration_ms is not None:
            w.durations.append(r.duration_ms)
        if r.level in ("ERROR", "FATAL"):
            w.error_count += 1
            if len(w.error_samples) < 3:
                w.error_samples.append(r.raw)
        st = r.status
        if st is not None and 500 <= st < 600:
            w.http_5xx += 1
        if st in (401, 403):
            w.auth_fail += 1
    return [buckets[i] for i in sorted(buckets)]


def _iso(epoch: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----- detection rules -----
def _detect_error_spike(windows: list[Window]) -> list[Anomaly]:
    counts = [float(w.error_count) for w in windows]
    med, mad = _median(counts), _mad(counts, _median(counts))
    out = []
    for w in windows:
        z = _robust_z(w.error_count, med, mad)
        if w.error_count >= ERROR_MIN_ABS and (z >= ERROR_Z or w.error_count >= max(ERROR_MIN_ABS * 3, med * 4)):
            sev = "P1" if w.error_count >= ERROR_MIN_ABS * 4 else "P2"
            out.append(Anomaly(
                type="error_spike",
                severity=sev,
                title=f"Error spike: {w.error_count} errors in {WINDOW_SECONDS}s",
                detail=f"Errors/window = {w.error_count} (baseline median={med:.1f}, robust z={z:.1f}).",
                window_start=_iso(w.start_epoch),
                metric={"error_count": w.error_count, "baseline_median": med, "z": round(z, 2)},
                samples=list(w.error_samples),
            ))
    return out


def _detect_latency(windows: list[Window]) -> list[Anomaly]:
    p95s = [w.p95 for w in windows]
    med, mad = _median(p95s), _mad(p95s, _median(p95s))
    out = []
    for w in windows:
        p = w.p95
        z = _robust_z(p, med, mad)
        if p >= LATENCY_P95_MS and (z >= LATENCY_Z or p >= LATENCY_P95_MS * 2):
            out.append(Anomaly(
                type="latency_spike",
                severity="P2",
                title=f"High latency: p95 = {p:.0f}ms",
                detail=f"p95 latency = {p:.0f}ms (baseline median={med:.0f}ms, z={z:.1f}).",
                window_start=_iso(w.start_epoch),
                metric={"p95_ms": round(p, 1), "baseline_median_ms": round(med, 1), "z": round(z, 2)},
            ))
    return out


def _detect_5xx(windows: list[Window]) -> list[Anomaly]:
    out = []
    for w in windows:
        if w.http_5xx >= HTTP_5XX_MIN:
            rate = (w.http_5xx / w.total * 100) if w.total else 0
            sev = "P1" if rate >= 20 else "P2"
            out.append(Anomaly(
                type="http_5xx",
                severity=sev,
                title=f"High 5xx rate: {w.http_5xx} requests ({rate:.0f}%)",
                detail=f"{w.http_5xx}/{w.total} requests returned 5xx in this window.",
                window_start=_iso(w.start_epoch),
                metric={"http_5xx": w.http_5xx, "total": w.total, "rate_pct": round(rate, 1)},
                samples=list(w.error_samples),
            ))
    return out


def _detect_auth(windows: list[Window]) -> list[Anomaly]:
    out = []
    for w in windows:
        if w.auth_fail >= AUTH_FAIL_MIN:
            out.append(Anomaly(
                type="auth_bruteforce",
                severity="P2",
                title=f"Suspected brute-force: {w.auth_fail} x 401/403",
                detail=f"{w.auth_fail} auth failures in {WINDOW_SECONDS}s — possible password-guessing attack.",
                window_start=_iso(w.start_epoch),
                metric={"auth_fail": w.auth_fail},
            ))
    return out


def _detect_critical_patterns(records: list[LogRecord]) -> list[Anomaly]:
    out = []
    seen: set[str] = set()
    for r in records:
        for rx, label in CRITICAL_PATTERNS:
            if rx.search(r.message) or rx.search(r.raw):
                key = f"{label}:{r.service}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(Anomaly(
                    type="critical_pattern",
                    severity="P1",
                    title=f"{label} in service '{r.service}'",
                    detail=f"Detected critical pattern '{label}'. This is typically a P1 needing immediate action.",
                    window_start=_iso(r.epoch),
                    metric={"pattern": label, "service": r.service},
                    samples=[r.raw],
                ))
    return out


def _detect_new_signatures(records: list[LogRecord], window_s: int) -> list[Anomaly]:
    if not records:
        return []
    base = min(r.epoch for r in records)
    baseline_cutoff = base + BASELINE_WINDOWS * window_s
    known: set[str] = set()
    for r in records:
        if r.epoch < baseline_cutoff and r.level in ("ERROR", "FATAL", "WARN"):
            known.add(_signature(r))
    out, reported = [], set()
    for r in records:
        if r.epoch < baseline_cutoff or r.level not in ("ERROR", "FATAL"):
            continue
        sig = _signature(r)
        if sig not in known and sig not in reported:
            reported.add(sig)
            out.append(Anomaly(
                type="new_error_signature",
                severity="P2",
                title=f"New unseen error in '{r.service}'",
                detail=f"A new error signature appeared (not in baseline): {r.message[:120]}",
                window_start=_iso(r.epoch),
                metric={"signature": sig},
                samples=[r.raw],
            ))
    return out


def _detect_silence(records: list[LogRecord], window_s: int) -> list[Anomaly]:
    if not records:
        return []
    base = min(r.epoch for r in records)
    end = max(r.epoch for r in records)
    span = end - base
    # A service is "known active" if it logged in the first half;
    # flag it as silent if it has NO logs in the final quarter of the timeline.
    early = {r.service for r in records if r.epoch < base + span * 0.5}
    last_quarter_start = base + span * 0.75
    recent = {r.service for r in records if r.epoch >= last_quarter_start}
    out = []
    for svc in sorted(early - recent):
        out.append(Anomaly(
            type="service_silence",
            severity="P1",
            title=f"Service '{svc}' stopped logging",
            detail=(f"Service '{svc}' logged earlier but went completely silent "
                    f"in the final quarter of the timeline — likely dead/hung."),
            window_start=_iso(last_quarter_start),
            metric={"service": svc},
        ))
    return out


def _collapse_episodes(anomalies: list[Anomaly], window_s: int) -> list[Anomaly]:
    """Merge same-type anomalies in adjacent windows into a single 'episode'.

    Avoids noisy reports (each 30s window re-reporting the same incident). The
    episode keeps the peak (worst severity), start time, and span (window count).
    """
    from datetime import datetime, timezone

    def _epoch(iso: str) -> float:
        return datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()

    by_type: dict[str, list[Anomaly]] = defaultdict(list)
    for a in anomalies:
        by_type[a.type].append(a)

    merged: list[Anomaly] = []
    for items in by_type.values():
        items.sort(key=lambda a: a.window_start)
        group: list[Anomaly] = []
        for a in items:
            if group and _epoch(a.window_start) - _epoch(group[-1].window_start) <= window_s * 1.5:
                group.append(a)
            else:
                if group:
                    merged.append(_merge_group(group, window_s))
                group = [a]
        if group:
            merged.append(_merge_group(group, window_s))
    merged.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.window_start))
    return merged


def _merge_group(group: list[Anomaly], window_s: int) -> Anomaly:
    if len(group) == 1:
        return group[0]
    # Pick the worst anomaly as representative (highest severity).
    peak = min(group, key=lambda a: SEVERITY_ORDER.get(a.severity, 9))
    span = len(group) * window_s
    return Anomaly(
        type=peak.type,
        severity=peak.severity,
        title=peak.title + f"  (sustained ~{span}s, {len(group)} windows)",
        detail=peak.detail + f" The incident persisted across {len(group)} windows (~{span}s).",
        window_start=group[0].window_start,
        metric={**peak.metric, "episode_windows": len(group), "duration_s": span},
        samples=peak.samples,
        recommendation=peak.recommendation,
    )


def detect(records: list[LogRecord], window_s: int = WINDOW_SECONDS,
           collapse: bool = True) -> list[Anomaly]:
    """Run all rules; return anomalies sorted by severity then time."""
    windows = _bucket(records, window_s)
    anomalies: list[Anomaly] = []
    anomalies += _detect_error_spike(windows)
    anomalies += _detect_latency(windows)
    anomalies += _detect_5xx(windows)
    anomalies += _detect_auth(windows)
    anomalies += _detect_critical_patterns(records)
    anomalies += _detect_new_signatures(records, window_s)
    anomalies += _detect_silence(records, window_s)
    if collapse:
        anomalies = _collapse_episodes(anomalies, window_s)
    anomalies.sort(key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), a.window_start))
    return anomalies


def build_timeseries(records: list[LogRecord], window_s: int = WINDOW_SECONDS) -> dict:
    """Series for the report charts: error_count & p95 per window."""
    windows = _bucket(records, window_s)
    return {
        "labels": [_iso(w.start_epoch)[11:19] for w in windows],
        "error_count": [w.error_count for w in windows],
        "p95_ms": [round(w.p95, 0) for w in windows],
        "total": [w.total for w in windows],
    }
