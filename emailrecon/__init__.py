"""EMAILRECON - Defensive email OSINT aggregation (analysis/triage/detection only).

This package performs *passive* and *authorized* posture analysis on an email
address and its domain:

  * Address normalization / validity / role-account & disposable detection
  * Domain DNS posture: MX presence, SPF, DMARC, DKIM-hint, MTA-STS hints
  * Heuristic breach-exposure hinting from a local, offline corpus (no network)

It deliberately contains NO unauthorized attack capability: it never attempts
to authenticate, enumerate accounts on third-party services, or send mail.
"""
from .core import (
    EmailFacts,
    DomainPosture,
    ReconReport,
    Finding,
    Severity,
    analyze_email,
    analyze_domain,
    build_report,
)

TOOL_NAME = "emailrecon"
TOOL_VERSION = "1.0.0"

__all__ = [
    "EmailFacts",
    "DomainPosture",
    "ReconReport",
    "Finding",
    "Severity",
    "analyze_email",
    "analyze_domain",
    "build_report",
    "TOOL_NAME",
    "TOOL_VERSION",
]
