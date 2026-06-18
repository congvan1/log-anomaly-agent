"""LLM enrichment (optional).

Sends the detected anomalies to Claude to:
  - write an executive summary,
  - explain the likely root cause,
  - propose concrete, actionable remediations.

Designed for graceful degradation: if there is no ANTHROPIC_API_KEY or the
`anthropic` SDK is not installed, the system still runs and uses a static
recommendation table (fallback). The statistical/rule layer always works;
the LLM is purely an enhancement.
"""

from __future__ import annotations

import json
import os

# Static recommendation table — used when no LLM is available
# (and as a seed of suggestions for the LLM).
FALLBACK_ACTIONS = {
    "error_spike": "Isolate the service with rising errors; check the latest deploy/release and consider a rollback; inspect downstream logs (DB, gateway).",
    "latency_spike": "Check DB slow queries, connection pool, GC pauses; review CPU/mem dashboards; enable tracing to find the bottleneck.",
    "http_5xx": "Identify the failing endpoint; if it started right after a deploy -> rollback; check upstream dependency health.",
    "auth_bruteforce": "Enable rate-limiting & lockout on /login; block source IPs at the WAF/firewall; enforce MFA; audit access logs.",
    "critical_pattern": "Handle as P1 now: for OOM increase heap / find the memory leak; pool exhausted -> raise size / fix connection leaks; controlled restart.",
    "new_error_signature": "New class of error — assign an owner, open a ticket, check recent code/config changes that introduced this signature.",
    "service_silence": "Check the service liveness/health; see if it crashed/hung/deadlocked; restart and add an alert for missing logs.",
}

DEFAULT_MODEL = os.environ.get("ANOMALY_MODEL", "claude-haiku-4-5-20251001")

_SYSTEM = (
    "You are a seasoned SRE/DevOps engineer. You receive a list of anomalies "
    "already detected from application logs. Analyze them concisely, accurately, "
    "and action-oriented. Return ONLY a single valid JSON object, with no prose outside the JSON."
)


def _apply_fallback(anomalies: list[dict]) -> dict:
    for a in anomalies:
        a["recommendation"] = a.get("recommendation") or FALLBACK_ACTIONS.get(
            a["type"], "Investigate further and assign an owner."
        )
        a.setdefault("root_cause", "(LLM off) — see the static recommendation above.")
    p1 = sum(1 for a in anomalies if a["severity"] == "P1")
    summary = (
        f"Detected {len(anomalies)} anomalies ({p1} at P1). "
        "Recommendations generated from the static knowledge base (LLM disabled)."
        if anomalies else "No significant anomalies detected."
    )
    return {"summary": summary, "anomalies": anomalies, "llm_used": False}


def _build_prompt(anomalies: list[dict]) -> str:
    compact = []
    for i, a in enumerate(anomalies):
        compact.append({
            "id": i,
            "type": a["type"],
            "severity": a["severity"],
            "title": a["title"],
            "detail": a["detail"],
            "metric": a.get("metric", {}),
            "samples": a.get("samples", [])[:2],
        })
    schema = (
        '{"summary": "<2-3 sentence summary for management>", '
        '"anomalies": [{"id": <int>, "root_cause": "<likely cause>", '
        '"recommendation": "<concrete action that can be taken now>"}]}'
    )
    return (
        "Here are the anomalies (JSON):\n"
        + json.dumps(compact, ensure_ascii=False, indent=2)
        + "\n\nReturn JSON matching exactly this schema (in English):\n"
        + schema
    )


def analyze(anomalies_objs) -> dict:
    """anomalies_objs: list[Anomaly]. Returns {summary, anomalies(list[dict]), llm_used}."""
    anomalies = [a.to_dict() for a in anomalies_objs]
    if not anomalies:
        return {"summary": "No significant anomalies detected.", "anomalies": [], "llm_used": False}

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _apply_fallback(anomalies)
    try:
        import anthropic  # type: ignore
    except ImportError:
        return _apply_fallback(anomalies)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        resp = client.messages.create(
            model=DEFAULT_MODEL,
            max_tokens=1500,
            system=_SYSTEM,
            messages=[{"role": "user", "content": _build_prompt(anomalies)}],
        )
        text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text").strip()
        if text.startswith("```"):
            text = text.strip("`").split("\n", 1)[-1].rsplit("```", 1)[0]
        data = json.loads(text)
    except Exception as exc:  # noqa: BLE001 — always fall back safely for the demo
        result = _apply_fallback(anomalies)
        result["summary"] += f" [LLM error: {exc.__class__.__name__}, used fallback]"
        return result

    by_id = {item.get("id"): item for item in data.get("anomalies", [])}
    for i, a in enumerate(anomalies):
        enr = by_id.get(i, {})
        a["root_cause"] = enr.get("root_cause", "")
        a["recommendation"] = enr.get("recommendation") or FALLBACK_ACTIONS.get(a["type"], "")
    return {
        "summary": data.get("summary", ""),
        "anomalies": anomalies,
        "llm_used": True,
        "model": DEFAULT_MODEL,
    }
