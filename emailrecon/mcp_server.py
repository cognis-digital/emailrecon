"""EMAILRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json
import sys

from emailrecon.core import build_report


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-emailrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(
            "Install the MCP extra: pip install 'cognis-emailrecon[mcp]'",
            file=sys.stderr,
        )
        return 1

    app = FastMCP("emailrecon")

    @app.tool()
    def emailrecon_scan(target: str, no_dns: bool = False, timeout: float = 3.0) -> str:
        """Aggregate email OSINT (breach hints, MX, SPF/DMARC posture). Returns JSON findings."""
        if not isinstance(target, str) or not target.strip():
            return json.dumps({"error": "target must be a non-empty string"})
        try:
            report = build_report(target, do_lookups=not no_dns, timeout=max(timeout, 0.1))
        except Exception as exc:  # pragma: no cover - MCP layer catches and returns
            return json.dumps({"error": str(exc)})
        return json.dumps(report.to_dict(), indent=2, sort_keys=True)

    app.run()
    return 0
