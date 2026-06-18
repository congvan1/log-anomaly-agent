"""End-to-end orchestrator.

    simulate (or read file) -> parse -> detect -> LLM analyze -> report -> [email]

Examples:
    python -m src.pipeline --scenario incident
    python -m src.pipeline --logfile sample_output/app.log
    python -m src.pipeline --scenario incident --email
"""

from __future__ import annotations

import argparse
import os
import sys

from . import detector, llm_analyzer, parser, report, simulator


def run(args: argparse.Namespace) -> int:
    os.makedirs(os.path.dirname(args.html) or ".", exist_ok=True)

    # 1) Log source: existing file or simulate.
    if args.logfile:
        records = parser.parse_file(args.logfile)
        scenario = f"file:{os.path.basename(args.logfile)}"
        print(f"[1/5] Read {len(records)} records from {args.logfile}")
    else:
        lines = simulator.generate(scenario=args.scenario, minutes=args.minutes)
        if args.save_log:
            with open(args.save_log, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            print(f"[1/5] Simulated {len(lines)} log lines (scenario={args.scenario}) -> {args.save_log}")
        else:
            print(f"[1/5] Simulated {len(lines)} log lines (scenario={args.scenario})")
        records = parser.parse_lines(lines)
        scenario = args.scenario

    if not records:
        print("No valid records to analyze.", file=sys.stderr)
        return 2

    # 2) Detect anomalies (rules + statistics).
    anomalies = detector.detect(records, window_s=args.window)
    print(f"[2/5] Detected {len(anomalies)} anomalies "
          f"(P1={sum(1 for a in anomalies if a.severity=='P1')}).")

    # 3) Enrich with LLM (optional, with fallback).
    analysis = llm_analyzer.analyze(anomalies)
    print(f"[3/5] Analysis: {'Claude LLM' if analysis['llm_used'] else 'fallback (LLM off)'}")

    # 4) Build reports.
    timeseries = detector.build_timeseries(records, window_s=args.window)
    meta = {
        "scenario": scenario,
        "log_lines": len(records),
        "window_seconds": args.window,
    }
    report.write_reports(analysis, timeseries, meta, args.html, args.json)
    print(f"[4/5] Report: {args.html} | {args.json}")
    print("\n" + report.build_text_summary(analysis, meta) + "\n")

    # 5) Email (optional).
    if args.email:
        from . import emailer
        p1 = sum(1 for a in analysis["anomalies"] if a["severity"] == "P1")
        subject = f"[Anomaly Report] {len(analysis['anomalies'])} issues ({p1} P1) — {scenario}"
        status = emailer.send_report(
            subject=subject,
            body_text=report.build_text_summary(analysis, meta),
            html_path=args.html,
            to_addr=args.to,
        )
        print(f"[5/5] Email: {status}")
    else:
        print("[5/5] Email: skipped (add --email to send).")

    # Non-zero exit code if any P1 -> handy for plugging into CI/cron alerts.
    return 1 if any(a.severity == "P1" for a in anomalies) and args.fail_on_p1 else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Log anomaly detection agent + auto report")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--scenario", choices=["normal", "incident"], default="incident",
                     help="Log simulation mode (default: incident)")
    src.add_argument("--logfile", help="Read logs from an existing file instead of simulating")
    ap.add_argument("--minutes", type=int, default=30, help="Simulated timeline length")
    ap.add_argument("--window", type=int, default=detector.WINDOW_SECONDS, help="Window size (seconds)")
    ap.add_argument("--save-log", help="Save simulated logs to a file")
    ap.add_argument("--html", default="sample_output/report.html", help="HTML report path")
    ap.add_argument("--json", default="sample_output/report.json", help="JSON report path")
    ap.add_argument("--email", action="store_true", help="Send the report by email (needs SMTP config)")
    ap.add_argument("--to", help="Recipient email (overrides EMAIL_TO)")
    ap.add_argument("--fail-on-p1", action="store_true", help="Exit code 1 if any P1 (for CI/cron)")
    return run(ap.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
