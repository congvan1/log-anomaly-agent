"""Automated test flow.

Principles for testing anomaly detection:
  - When simulating INCIDENT -> the detector MUST catch the right failure types.
  - When simulating NORMAL   -> the detector MUST NOT raise P1 (avoid false positives).

Run: pytest -q   (or: python -m pytest)
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import detector, parser, simulator  # noqa: E402


def _detect(scenario, seed=42, minutes=30):
    lines = simulator.generate(scenario=scenario, minutes=minutes, seed=seed)
    records = parser.parse_lines(lines)
    return records, detector.detect(records)


def _types(anomalies):
    return {a.type for a in anomalies}


# ---------- INCIDENT must be caught ----------
def test_incident_detects_error_spike():
    _, anomalies = _detect("incident")
    assert "error_spike" in _types(anomalies)


def test_incident_detects_latency():
    _, anomalies = _detect("incident")
    assert "latency_spike" in _types(anomalies)


def test_incident_detects_5xx():
    _, anomalies = _detect("incident")
    assert "http_5xx" in _types(anomalies)


def test_incident_detects_auth_bruteforce():
    _, anomalies = _detect("incident")
    assert "auth_bruteforce" in _types(anomalies)


def test_incident_detects_oom_as_p1():
    _, anomalies = _detect("incident")
    crit = [a for a in anomalies if a.type == "critical_pattern"]
    assert crit, "must catch a critical pattern (OOM)"
    assert all(a.severity == "P1" for a in crit)


def test_incident_detects_service_silence():
    _, anomalies = _detect("incident")
    assert "service_silence" in _types(anomalies)


def test_incident_has_at_least_one_p1():
    _, anomalies = _detect("incident")
    assert any(a.severity == "P1" for a in anomalies)


# ---------- NORMAL must not raise false alarms ----------
def test_normal_has_no_p1_false_positive():
    _, anomalies = _detect("normal")
    p1 = [a for a in anomalies if a.severity == "P1"]
    assert not p1, f"normal should have no P1, but found: {[a.type for a in p1]}"


def test_normal_no_critical_or_silence():
    _, anomalies = _detect("normal")
    bad = _types(anomalies) & {"critical_pattern", "service_silence", "auth_bruteforce"}
    assert not bad, f"normal should not have {bad}"


# ---------- stable across seeds ----------
def test_incident_stable_across_seeds():
    for seed in (1, 7, 99, 2026):
        _, anomalies = _detect("incident", seed=seed)
        assert any(a.severity == "P1" for a in anomalies), f"seed={seed} should have a P1"


# ---------- parser ----------
def test_parser_extracts_fields():
    line = ("2026-06-18T09:15:01.123Z [ERROR] payment - gateway timeout "
            "method=POST path=/api/payment status=502 duration_ms=30000 trace_id=ab12cd")
    rec = parser.parse_line(line)
    assert rec is not None
    assert rec.level == "ERROR"
    assert rec.service == "payment"
    assert rec.status == 502
    assert rec.duration_ms == 30000
