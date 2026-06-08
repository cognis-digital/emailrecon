"""Core engine for EMAILRECON.

Real logic, standard library only. DNS lookups use the stdlib resolver where
available but always degrade gracefully (offline / no-network) so that callers
(and tests) can run deterministically without network access.
"""
from __future__ import annotations

import os
import re
import socket
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Iterable, Optional

# --------------------------------------------------------------------------
# Static reference data (offline, embedded)
# --------------------------------------------------------------------------

# A small but real set of common disposable / throwaway mail domains.
DISPOSABLE_DOMAINS = frozenset(
    {
        "mailinator.com",
        "guerrillamail.com",
        "10minutemail.com",
        "tempmail.com",
        "trashmail.com",
        "yopmail.com",
        "sharklasers.com",
        "getnada.com",
        "dispostable.com",
        "throwawaymail.com",
        "maildrop.cc",
        "fakeinbox.com",
    }
)

# Free / consumer webmail providers (not suspicious, but worth flagging for
# corporate-posture triage).
FREEMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "ymail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "aol.com",
        "icloud.com",
        "proton.me",
        "protonmail.com",
        "gmx.com",
        "zoho.com",
    }
)

# Role / functional local-parts that should not belong to a single human and
# are higher-value targets for phishing/abuse.
ROLE_LOCALPARTS = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "postmaster",
        "hostmaster",
        "webmaster",
        "abuse",
        "security",
        "noreply",
        "no-reply",
        "donotreply",
        "support",
        "info",
        "sales",
        "billing",
        "help",
        "contact",
        "office",
        "hr",
        "it",
    }
)

# RFC-5321-ish address regex (pragmatic, not exhaustive).
_EMAIL_RE = re.compile(
    r"^(?P<local>[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+)@"
    r"(?P<domain>(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63})$"
)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3}[self.value]


@dataclass
class Finding:
    code: str
    severity: Severity
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity.value, "message": self.message}


@dataclass
class EmailFacts:
    raw: str
    normalized: str
    valid_syntax: bool
    local_part: str = ""
    domain: str = ""
    is_role_account: bool = False
    is_disposable: bool = False
    is_freemail: bool = False
    has_plus_tag: bool = False
    plus_tag: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DomainPosture:
    domain: str
    resolved: bool = False
    mx_records: list[str] = field(default_factory=list)
    spf_record: Optional[str] = None
    spf_policy: Optional[str] = None  # e.g. -all / ~all / ?all / +all
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None  # none / quarantine / reject
    dkim_hint: bool = False
    mta_sts_hint: bool = False
    lookups_performed: bool = False  # False when offline / disabled

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReconReport:
    tool: str
    version: str
    email: EmailFacts
    domain: DomainPosture
    breach_hints: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "email": self.email.to_dict(),
            "domain": self.domain.to_dict(),
            "breach_hints": list(self.breach_hints),
            "findings": [f.to_dict() for f in self.findings],
            "max_severity": self.max_severity.value,
        }


# --------------------------------------------------------------------------
# Email analysis
# --------------------------------------------------------------------------


def analyze_email(raw: str) -> EmailFacts:
    """Normalize and classify an email address (no network)."""
    normalized = (raw or "").strip().lower()
    m = _EMAIL_RE.match(normalized)
    if not m:
        return EmailFacts(raw=raw, normalized=normalized, valid_syntax=False)

    local = m.group("local")
    domain = m.group("domain")

    plus_tag: Optional[str] = None
    base_local = local
    if "+" in local:
        base_local, _, plus_tag = local.partition("+")

    return EmailFacts(
        raw=raw,
        normalized=normalized,
        valid_syntax=True,
        local_part=local,
        domain=domain,
        is_role_account=base_local in ROLE_LOCALPARTS,
        is_disposable=domain in DISPOSABLE_DOMAINS,
        is_freemail=domain in FREEMAIL_DOMAINS,
        has_plus_tag=plus_tag is not None,
        plus_tag=plus_tag or None,
    )


# --------------------------------------------------------------------------
# Domain DNS posture
# --------------------------------------------------------------------------


def _query_txt(name: str, timeout: float) -> list[str]:
    """Best-effort TXT lookup using only the standard library.

    Python's stdlib has no DNS TXT resolver, so we issue a minimal DNS query
    over UDP ourselves. Returns [] on any failure (offline-safe).
    """
    try:
        return _dns_query(name, qtype=16, timeout=timeout)  # 16 = TXT
    except Exception:
        return []


def _query_mx(name: str, timeout: float) -> list[str]:
    try:
        return _dns_query(name, qtype=15, timeout=timeout)  # 15 = MX
    except Exception:
        return []


def _dns_query(name: str, qtype: int, timeout: float) -> list[str]:
    """Tiny DNS resolver (A/MX/TXT) using the system resolver address.

    Sends a single UDP query to a public-style resolver derived from the OS;
    falls back to 127.0.0.1 stub resolvers. Strictly read-only.
    """
    import struct
    import random

    server = os.environ.get("EMAILRECON_DNS", "1.1.1.1")
    txn = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txn, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        struct.pack("B", len(part)) + part.encode("ascii")
        for part in name.rstrip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    # Parse answers.
    ancount = struct.unpack(">H", data[6:8])[0]
    # Skip header + question.
    idx = 12
    idx = _skip_name(data, idx) + 4  # qname + qtype + qclass
    results: list[str] = []
    for _ in range(ancount):
        idx = _skip_name(data, idx)
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[idx : idx + 10])
        idx += 10
        rdata = data[idx : idx + rdlen]
        if rtype == 16:  # TXT
            results.append(_parse_txt(rdata))
        elif rtype == 15:  # MX
            pref = struct.unpack(">H", rdata[:2])[0]
            host = _read_name(data, idx + 2)[0]
            results.append(f"{pref} {host}")
        idx += rdlen
    return results


def _parse_txt(rdata: bytes) -> str:
    out = []
    i = 0
    while i < len(rdata):
        ln = rdata[i]
        out.append(rdata[i + 1 : i + 1 + ln].decode("utf-8", "replace"))
        i += 1 + ln
    return "".join(out)


def _skip_name(data: bytes, idx: int) -> int:
    while True:
        ln = data[idx]
        if ln == 0:
            return idx + 1
        if ln & 0xC0 == 0xC0:  # compression pointer
            return idx + 2
        idx += 1 + ln


def _read_name(data: bytes, idx: int) -> tuple[str, int]:
    labels = []
    jumped = False
    start_after = idx
    while True:
        ln = data[idx]
        if ln == 0:
            idx += 1
            break
        if ln & 0xC0 == 0xC0:
            import struct

            ptr = struct.unpack(">H", data[idx : idx + 2])[0] & 0x3FFF
            if not jumped:
                start_after = idx + 2
            idx = ptr
            jumped = True
            continue
        labels.append(data[idx + 1 : idx + 1 + ln].decode("ascii", "replace"))
        idx += 1 + ln
    if not jumped:
        start_after = idx
    return ".".join(labels), start_after


def analyze_domain(domain: str, do_lookups: bool = True, timeout: float = 3.0) -> DomainPosture:
    """Assess DNS email-security posture for a domain.

    When *do_lookups* is False (or lookups fail / time out), the posture is
    returned with ``lookups_performed=False`` so callers can distinguish
    'absent record' from 'not checked'.
    """
    posture = DomainPosture(domain=domain)
    if not domain or not do_lookups:
        return posture

    try:
        mx = _query_mx(domain, timeout)
        txt_root = _query_txt(domain, timeout)
        txt_dmarc = _query_txt(f"_dmarc.{domain}", timeout)
        txt_mtasts = _query_txt(f"_mta-sts.{domain}", timeout)
        # If we got literally nothing back from any query, assume offline.
        if not any([mx, txt_root, txt_dmarc, txt_mtasts]):
            return posture
        posture.lookups_performed = True
    except Exception:
        return posture

    posture.resolved = bool(mx) or bool(txt_root)
    posture.mx_records = [r for r in mx if r]

    for rec in txt_root:
        low = rec.lower()
        if low.startswith("v=spf1"):
            posture.spf_record = rec
            posture.spf_policy = _spf_all_policy(rec)

    for rec in txt_dmarc:
        if rec.lower().startswith("v=dmarc1"):
            posture.dmarc_record = rec
            posture.dmarc_policy = _dmarc_policy(rec)

    posture.mta_sts_hint = any("v=stsv1" in r.lower() for r in txt_mtasts)
    # DKIM uses selector-specific records we can't enumerate without a selector;
    # treat presence of a DMARC record as a weak "alignment configured" hint.
    posture.dkim_hint = posture.dmarc_record is not None
    return posture


def _spf_all_policy(record: str) -> Optional[str]:
    m = re.search(r"([-~?+])all\b", record.lower())
    return (m.group(1) + "all") if m else None


def _dmarc_policy(record: str) -> Optional[str]:
    m = re.search(r"\bp\s*=\s*(none|quarantine|reject)\b", record.lower())
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# Breach hinting (offline corpus)
# --------------------------------------------------------------------------


def load_breach_corpus(path: Optional[str]) -> set[str]:
    """Load a newline-delimited list of known-exposed domains/addresses.

    Lines beginning with '#' are comments. Entries are lowercased. Missing
    file yields an empty corpus (no error) so the tool stays offline-friendly.
    """
    corpus: set[str] = set()
    if not path:
        return corpus
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    corpus.add(line)
    except OSError:
        pass
    return corpus


def breach_hints(email: EmailFacts, corpus: Iterable[str]) -> list[str]:
    hints: list[str] = []
    corpus_set = set(corpus)
    if email.normalized in corpus_set:
        hints.append(f"address present in offline breach corpus: {email.normalized}")
    if email.domain and email.domain in corpus_set:
        hints.append(f"domain present in offline breach corpus: {email.domain}")
    return hints


# --------------------------------------------------------------------------
# Report assembly
# --------------------------------------------------------------------------


def build_report(
    raw_email: str,
    *,
    do_lookups: bool = True,
    timeout: float = 3.0,
    breach_corpus_path: Optional[str] = None,
    tool: str = "emailrecon",
    version: str = "1.0.0",
) -> ReconReport:
    email = analyze_email(raw_email)
    domain = analyze_domain(email.domain, do_lookups=do_lookups, timeout=timeout) if email.valid_syntax else DomainPosture(domain=email.domain)
    corpus = load_breach_corpus(breach_corpus_path)
    hints = breach_hints(email, corpus) if email.valid_syntax else []

    findings = _derive_findings(email, domain, hints)
    return ReconReport(
        tool=tool,
        version=version,
        email=email,
        domain=domain,
        breach_hints=hints,
        findings=findings,
    )


def _derive_findings(
    email: EmailFacts, domain: DomainPosture, hints: list[str]
) -> list[Finding]:
    f: list[Finding] = []

    if not email.valid_syntax:
        f.append(Finding("EMAIL_INVALID", Severity.HIGH, "email address failed syntax validation"))
        return f

    if email.is_disposable:
        f.append(Finding("DISPOSABLE_DOMAIN", Severity.MEDIUM, f"disposable mail domain: {email.domain}"))
    if email.is_role_account:
        f.append(Finding("ROLE_ACCOUNT", Severity.MEDIUM, "role/functional account (higher-value target)"))
    if email.is_freemail:
        f.append(Finding("FREEMAIL", Severity.INFO, f"consumer webmail provider: {email.domain}"))
    if email.has_plus_tag:
        f.append(Finding("PLUS_TAG", Severity.LOW, f"sub-addressing tag present: +{email.plus_tag}"))

    if hints:
        f.append(Finding("BREACH_HINT", Severity.HIGH, "; ".join(hints)))

    if domain.lookups_performed:
        if not domain.mx_records:
            f.append(Finding("NO_MX", Severity.MEDIUM, "no MX records (domain may not receive mail)"))
        if domain.spf_record is None:
            f.append(Finding("SPF_MISSING", Severity.MEDIUM, "no SPF record published"))
        elif domain.spf_policy in ("+all", "?all"):
            f.append(Finding("SPF_WEAK", Severity.HIGH, f"permissive SPF policy: {domain.spf_policy}"))
        elif domain.spf_policy == "~all":
            f.append(Finding("SPF_SOFTFAIL", Severity.LOW, "SPF softfail (~all) instead of hardfail (-all)"))

        if domain.dmarc_record is None:
            f.append(Finding("DMARC_MISSING", Severity.HIGH, "no DMARC record published (spoofable)"))
        elif domain.dmarc_policy == "none":
            f.append(Finding("DMARC_MONITOR", Severity.MEDIUM, "DMARC p=none (monitor-only, not enforcing)"))

        if not domain.mta_sts_hint:
            f.append(Finding("MTA_STS_MISSING", Severity.LOW, "no MTA-STS policy hint found"))
    else:
        f.append(Finding("DNS_NOT_CHECKED", Severity.INFO, "DNS posture not evaluated (offline or --no-dns)"))

    return f
