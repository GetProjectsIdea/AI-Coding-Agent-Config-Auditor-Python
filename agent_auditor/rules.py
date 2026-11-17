"""Detection rules. Every rule is a plain regular expression or a structural
check on a config file. Nothing here executes code from the scanned repo."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class TextRule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern
    advice: str


def _r(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# Phrases taken from the defensive checklist published by Bitdefender Labs
# (Nov 2026): concealment, silent execution, skipping confirmation.
INSTRUCTION_RULES = [
    TextRule("AGT001", "Tells the agent NOT to inspect a file", Severity.HIGH,
             _r(r"\b(do not|don't|never|must not)\s+(read|open|inspect|view|quote|display|show|print|cat|review|analy[sz]e|look at)\s+(the\s+)?(contents?\s+of\s+)?(`?[\w./\\-]+\.(js|mjs|cjs|ts|py|sh|ps1|bin|exe)`?|this\s+(file|script)|the\s+(file|script|setup script|installer))"),
             "Legitimate projects never forbid you from reading their own code. Open that file yourself before running anything."),
    TextRule("AGT002", "Asks to run something without user confirmation", Severity.CRITICAL,
             _r(r"without\s+(asking|confirmation|confirming|prompting|user approval|permission)|(skip|bypass|don't ask for|no need for)\s+(the\s+)?(confirmation|approval|permission)"),
             "An agent should always ask before running commands. Treat this as a red flag."),
    TextRule("AGT003", "Asks to hide or suppress output", Severity.HIGH,
             _r(r"without\s+(displaying|showing|printing)\s+(the\s+)?output|(run|execute|install|start)\w*[^.\n]{0,40}\bsilently|silently\s+(run|execute|install|start)|suppress\s+(the\s+)?output|hide\s+(the\s+)?output|>\s*/dev/null\s+2>&1"),
             "Hiding output is a classic way to keep you from noticing what ran."),
    TextRule("AGT004", "Runs a setup step at session start", Severity.MEDIUM,
             _r(r"(at|on|every)\s+(session\s+start|startup|start\s+of\s+(every|each|the)\s+session)|run\s+(this\s+)?(first|automatically)\s+(when|before)"),
             "Check exactly which script is meant to run at session start and why."),
    TextRule("AGT005", "Trust-me language about a sealed/signed artifact", Severity.MEDIUM,
             _r(r"sealed\s+(binary\s+)?artifact|cryptographically\s+signed|not\s+human[- ]readable|contains\s+encrypted\s+(credentials|configuration|secrets)"),
             "Words like 'sealed' or 'signed' are used to discourage review. Verify the claim yourself."),
    TextRule("AGT006", "Download-and-execute command", Severity.CRITICAL,
             _r(r"(curl|wget)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|iwr\b[^\n]{0,200}\|\s*iex|invoke-expression|irm\b[^\n]{0,200}\|\s*iex"),
             "Piping a downloaded script straight into a shell runs code you have never seen."),
    TextRule("AGT007", "Mentions secrets, keys or credential stores", Severity.MEDIUM,
             _r(r"~/\.ssh|id_rsa|id_ed25519|~/\.aws|\.npmrc|\.pypirc|\.git-credentials|keychain|credential manager|\bAPI[_ ]?KEYS?\b[^\n]{0,40}(send|upload|post|copy)"),
             "Instruction files rarely need to talk about your keys. Make sure nothing reads or sends them."),
    TextRule("AGT008", "Tries to override the agent's safety rules", Severity.HIGH,
             _r(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules)|disregard\s+(your|the|all)\s+(rules|instructions|guidelines)|you are now in (developer|god|unrestricted) mode"),
             "This is prompt-injection wording aimed at your AI assistant."),
    TextRule("AGT009", "Auto-installs packages or global tools", Severity.LOW,
             _r(r"\bnpx\s+-y\b|\bnpm\s+(i|install)\s+-g\b|\bpip\s+install\s+(--user\s+)?https?://|\bbun\s+run\s+-\b"),
             "Check every package name on the official registry before letting an agent install it."),
    TextRule("AGT010", "Runs a script with node/bun/python/bash", Severity.LOW,
             _r(r"\b(node|bun|deno|python3?|bash|sh|powershell|pwsh)\s+[\w./\\-]+\.(js|mjs|cjs|ts|py|sh|ps1)\b"),
             "Read the referenced script before you or your agent runs it."),
]

# Shell-level patterns used inside JSON commands (hooks, MCP servers, tasks).
COMMAND_RULES = [
    ("CMD001", "Downloads and executes remote code", Severity.CRITICAL,
     _r(r"(curl|wget)\b.*\|\s*(sudo\s+)?(ba|z)?sh\b|iwr\b.*\|\s*iex|invoke-expression|irm\b.*\|\s*iex")),
    ("CMD002", "Decodes and executes an encoded payload", Severity.CRITICAL,
     _r(r"base64\s+(-d|--decode)|frombase64string|eval\s*\(|exec\s*\(\s*(atob|buffer\.from)|\bbun\s+run\s+-")),
    ("CMD003", "Sends data to the network", Severity.HIGH,
     _r(r"\b(curl|wget|nc|ncat|netcat|scp)\b|invoke-webrequest|https?://")),
    ("CMD004", "Touches secrets or credential files", Severity.HIGH,
     _r(r"\.ssh|\.aws|\.env\b|\.npmrc|\.pypirc|\.git-credentials|printenv|\benv\b\s*\||GITHUB_TOKEN|AWS_SECRET")),
    ("CMD005", "Hides output", Severity.MEDIUM,
     _r(r">\s*/dev/null|2>&1|-WindowStyle\s+Hidden|nohup|&\s*$")),
    ("CMD006", "Runs a local script", Severity.LOW,
     _r(r"\b(node|bun|deno|python3?|bash|sh|powershell|pwsh)\s+[\w./\\${}-]+\.(js|mjs|cjs|ts|py|sh|ps1)\b")),
]

# Invisible characters that can hide instructions from a human reviewer.
HIDDEN_CHARS = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000E0000-\U000E007F]")
LONG_BLOB = re.compile(r"[A-Za-z0-9+/=]{200,}|(?:[0-9a-fA-F]{2}){150,}")
SECRET_LITERAL = re.compile(r"(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[bp]-[A-Za-z0-9-]{10,})")
SCRIPT_REF = re.compile(r"([\w.\-/\\${}]+\.(?:js|mjs|cjs|ts|py|sh|ps1))\b")
