"""AI Coding-Agent Config Auditor.

A defensive, read-only scanner that flags risky AI coding-agent files
(AGENTS.md, CLAUDE.md, .claude hooks, MCP server configs, VS Code tasks ...)
in a cloned repository *before* you open it with an AI assistant.

The scanner never executes, imports or installs anything from the scanned repo.
"""
from .models import Finding, ScanResult, Severity
from .scanner import scan_path

__all__ = ["Finding", "ScanResult", "Severity", "scan_path"]
__version__ = "1.0.0"
