"""Command-line interface for EMAILRECON.

Subcommand: ``scan EMAIL`` produces a defensive OSINT/posture report.

Exit codes:
    0  clean run, no actionable findings (only info-level)
    1  unexpected error
    2  argparse usage error (argparse default)
    3  findings at LOW or above were reported
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import ReconReport, Severity, build_report


def _render_table(report: ReconReport) -> str:
    e = report.email
    d = report.domain
    lines: list[str] = []
    lines.append(f"== {report.tool} {report.version} ==")
    lines.append(f"email        : {e.normalized}")
    lines.append(f"valid syntax : {e.valid_syntax}")
    if e.valid_syntax:
        lines.append(f"local / domain: {e.local_part} / {e.domain}")
        flags = []
        if e.is_role_account:
            flags.append("role")
        if e.is_disposable:
            flags.append("disposable")
        if e.is_freemail:
            flags.append("freemail")
        if e.has_plus_tag:
            flags.append(f"+{e.plus_tag}")
        lines.append(f"flags        : {', '.join(flags) if flags else '(none)'}")
        lines.append("-- domain posture --")
        lines.append(f"lookups done : {d.lookups_performed}")
        lines.append(f"mx           : {', '.join(d.mx_records) if d.mx_records else '(none)'}")
        lines.append(f"spf          : {d.spf_policy or d.spf_record or '(none)'}")
        lines.append(f"dmarc        : {d.dmarc_policy or d.dmarc_record or '(none)'}")
        lines.append(f"mta-sts hint : {d.mta_sts_hint}")
        if report.breach_hints:
            lines.append("-- breach hints --")
            for h in report.breach_hints:
                lines.append(f"  ! {h}")
    lines.append("-- findings --")
    if report.findings:
        for fnd in report.findings:
            lines.append(f"  [{fnd.severity.value.upper():6}] {fnd.code}: {fnd.message}")
    else:
        lines.append("  (no findings)")
    lines.append(f"max severity : {report.max_severity.value}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Defensive email OSINT / posture aggregator (authorized use only).",
    )
    p.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Analyze an email address and its domain posture.")
    scan.add_argument("email", help="email address to analyze")
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--no-dns",
        action="store_true",
        help="skip all DNS lookups (fully offline posture)",
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="per-query DNS timeout in seconds (default: 3.0)",
    )
    scan.add_argument(
        "--breach-corpus",
        metavar="PATH",
        default=None,
        help="path to an offline newline-delimited breach corpus (domains/addresses)",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        try:
            report = build_report(
                args.email,
                do_lookups=not args.no_dns,
                timeout=args.timeout,
                breach_corpus_path=args.breach_corpus,
                tool=TOOL_NAME,
                version=TOOL_VERSION,
            )
        except Exception as exc:  # pragma: no cover - defensive
            print(f"error: {exc}", file=sys.stderr)
            return 1

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
        else:
            print(_render_table(report))

        # Non-zero exit when there is anything actionable (LOW or above).
        if report.max_severity.rank >= Severity.LOW.rank:
            return 3
        return 0

    parser.error("unknown command")  # pragma: no cover
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
