"""Log parser: turn a raw log line into a structured record."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+\[(?P<level>\w+)\]\s+(?P<service>\S+)\s+-\s+(?P<msg>.*?)\s*$"
)
_KV_RE = re.compile(r"(\w+)=(\S+)")


@dataclass
class LogRecord:
    ts: datetime
    epoch: float
    level: str
    service: str
    message: str
    fields: dict[str, str] = field(default_factory=dict)
    raw: str = ""

    @property
    def status(self) -> int | None:
        v = self.fields.get("status")
        return int(v) if v and v.isdigit() else None

    @property
    def duration_ms(self) -> float | None:
        v = self.fields.get("duration_ms")
        try:
            return float(v) if v is not None else None
        except ValueError:
            return None


def _parse_ts(value: str) -> datetime:
    # Format: 2026-06-18T09:15:01.123Z
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def parse_line(line: str) -> LogRecord | None:
    m = _LINE_RE.match(line)
    if not m:
        return None
    msg_full = m.group("msg")
    fields = dict(_KV_RE.findall(msg_full))
    # The human-readable message is the part before the first key=value pair.
    kv_start = msg_full.find("=")
    if kv_start != -1:
        cut = msg_full.rfind(" ", 0, msg_full.find("=", 0))
        message = msg_full[:cut].strip() if cut > 0 else msg_full
    else:
        message = msg_full
    ts = _parse_ts(m.group("ts"))
    return LogRecord(
        ts=ts,
        epoch=ts.timestamp(),
        level=m.group("level").upper(),
        service=m.group("service"),
        message=message,
        fields=fields,
        raw=line,
    )


def parse_lines(lines: list[str]) -> list[LogRecord]:
    out = []
    for ln in lines:
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        rec = parse_line(ln)
        if rec is not None:
            out.append(rec)
    return out


def parse_file(path: str) -> list[LogRecord]:
    with open(path, encoding="utf-8") as fh:
        return parse_lines(fh.readlines())
