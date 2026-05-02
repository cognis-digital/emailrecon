"""EMAILRECON MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from emailrecon.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-emailrecon[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-emailrecon[mcp]'")
        return 1
    app = FastMCP("emailrecon")

    @app.tool()
    def emailrecon_scan(target: str) -> str:
        """Aggregate email OSINT (breach hints, MX, SPF/DMARC posture). Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
