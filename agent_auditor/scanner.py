"""Core scanning logic. Read-only: files are opened as text, never executed."""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional

from . import jsonc
from .models import Finding, ScanResult, Severity
from .rules import (COMMAND_RULES, HIDDEN_CHARS, INSTRUCTION_RULES, LONG_BLOB,
                    SCRIPT_REF, SECRET_LITERAL)
from .targets import (KIND_CLAUDE, KIND_INSTRUCTION, KIND_MCP, KIND_OTHER,
                      KIND_PACKAGE, KIND_SCRIPT, KIND_TASKS, iter_targets)

MAX_READ = 2_000_000          # bytes read from any single file
BIG_SCRIPT = 500_000          # scripts bigger than this are suspicious
LONG_LINE = 3_000             # a single line this long = minified/obfuscated
SHELLS = {"bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh", "powershell.exe"}
LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")


def _read(path: Path) -> str:
    with open(path, "rb") as fh:
        data = fh.read(MAX_READ)
    return data.decode("utf-8", errors="replace")


def _line_of(text: str, needle: str) -> int:
    idx = text.find(needle) if needle else -1
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0


def _short(s: str, n: int = 160) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[: n - 1] + "…"


class Scanner:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.result = ScanResult(root=str(self.root))
        self._script_refs: dict[str, str] = {}   # script path -> referencing file

    # ------------------------------------------------------------------ utils
    def add(self, rule_id, title, severity, rel, line=0, evidence="", advice=""):
        for f in self.result.findings:   # de-duplicate identical findings
            if (f.rule_id, f.file, f.line, f.evidence) == (rule_id, rel, line, _short(evidence)):
                return
        self.result.findings.append(Finding(rule_id, title, Severity(severity), rel, line,
                                            _short(evidence), advice))

    def _remember_scripts(self, text: str, rel: str) -> None:
        for m in SCRIPT_REF.finditer(text):
            ref = m.group(1).strip("`'\"").replace("\\", "/")
            ref = re.sub(r"^\$\{?(CLAUDE_PROJECT_DIR|workspaceFolder|PWD)\}?/", "", ref)
            if ref.startswith(("http:", "https:")):
                continue
            while ref.startswith("./"):
                ref = ref[2:]
            self._script_refs.setdefault(ref, rel)

    def check_command(self, cmd: str, rel: str, raw: str, context: str,
                      base: Severity = Severity.INFO) -> None:
        """Apply shell-level rules to a command string found in a config."""
        line = _line_of(raw, cmd.split()[0] if cmd.split() else cmd)
        for rule_id, title, sev, pat in COMMAND_RULES:
            if pat.search(cmd):
                self.add(rule_id, f"{context}: {title}", max(sev, base), rel, line, cmd,
                         "Read the full command and any script it calls before trusting this repo.")
        self._remember_scripts(cmd, rel)

    def common_text_checks(self, text: str, rel: str) -> None:
        for m in HIDDEN_CHARS.finditer(text):
            self.add("TXT001", "Invisible/bidirectional Unicode characters", Severity.HIGH, rel,
                     _line_of(text, m.group(0)), f"U+{ord(m.group(0)):04X}",
                     "Hidden characters can smuggle instructions past a human reviewer.")
            break
        m = LONG_BLOB.search(text)
        if m:
            self.add("TXT002", "Long encoded blob (base64/hex)", Severity.MEDIUM, rel,
                     _line_of(text, m.group(0)[:40]), m.group(0)[:60],
                     "Encoded data in a config or instruction file is unusual. Decode it offline to see what it is.")
        m = SECRET_LITERAL.search(text)
        if m:
            self.add("TXT003", "Hard-coded token or API key", Severity.HIGH, rel,
                     _line_of(text, m.group(0)), m.group(0)[:8] + "…",
                     "Never commit real tokens. If this is yours, revoke it now.")

    # ------------------------------------------------------- file-type checks
    def scan_instruction(self, text: str, rel: str) -> None:
        hits = set()
        for rule in INSTRUCTION_RULES:
            for m in rule.pattern.finditer(text):
                hits.add(rule.rule_id)
                self.add(rule.rule_id, rule.title, rule.severity, rel,
                         _line_of(text, m.group(0)), m.group(0), rule.advice)
        self._remember_scripts(text, rel)
        # Combination seen in the Nov 2026 campaign: hide a script + tell the agent to run it.
        if "AGT001" in hits and hits & {"AGT002", "AGT003", "AGT004", "AGT010"}:
            self.add("AGT100", "Concealed script + instruction to run it (known attack pattern)",
                     Severity.CRITICAL, rel, 0, "do-not-inspect wording combined with run/auto-run wording",
                     "Do NOT open this repo with an AI agent. This matches the pattern Bitdefender Labs reported on 17 Nov 2026.")

    def scan_claude_settings(self, data: dict, raw: str, rel: str) -> None:
        hooks = data.get("hooks") or {}
        if isinstance(hooks, dict):
            for event, entries in hooks.items():
                for entry in entries if isinstance(entries, list) else []:
                    for hook in (entry.get("hooks") or []) if isinstance(entry, dict) else []:
                        cmd = str(hook.get("command", "")) if isinstance(hook, dict) else ""
                        if not cmd:
                            continue
                        auto = event in ("SessionStart", "UserPromptSubmit", "Setup")
                        sev = Severity.HIGH if auto else Severity.MEDIUM
                        self.add("CLD001", f"{event} hook runs a shell command automatically", sev, rel,
                                 _line_of(raw, cmd[:30]), cmd,
                                 "Hooks run without any prompt to the AI. Make sure you understand this command.")
                        self.check_command(cmd, rel, raw, f"{event} hook", base=Severity.INFO)
        perms = data.get("permissions") or {}
        if isinstance(perms, dict):
            for item in perms.get("allow", []) or []:
                if str(item).strip() in ("Bash", "Bash(*)", "Bash(**)", "*"):
                    self.add("CLD002", "Pre-approves every shell command", Severity.HIGH, rel,
                             _line_of(raw, str(item)), str(item),
                             "A repo should not grant the agent blanket shell access.")
            if perms.get("defaultMode") in ("bypassPermissions", "acceptEdits"):
                sev = Severity.HIGH if perms.get("defaultMode") == "bypassPermissions" else Severity.LOW
                self.add("CLD003", f"Sets permission mode to {perms.get('defaultMode')}", sev, rel,
                         _line_of(raw, "defaultMode"), str(perms.get("defaultMode")),
                         "Repo settings should not switch off the agent's confirmation prompts.")
        if data.get("enableAllProjectMcpServers") is True:
            self.add("CLD004", "Auto-approves every MCP server in the repo", Severity.HIGH, rel,
                     _line_of(raw, "enableAllProjectMcpServers"), "enableAllProjectMcpServers: true",
                     "Approve MCP servers one by one after reading them.")
        helper = data.get("apiKeyHelper")
        if helper:
            self.check_command(str(helper), rel, raw, "apiKeyHelper", base=Severity.MEDIUM)
        if isinstance(data.get("mcpServers"), dict):
            self.scan_mcp(data, raw, rel)

    def scan_mcp(self, data: dict, raw: str, rel: str) -> None:
        servers = data.get("mcpServers") or data.get("servers") or \
            (data.get("mcp", {}) or {}).get("servers") or {}
        if not isinstance(servers, dict):
            return
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            line = _line_of(raw, f'"{name}"')
            command = str(cfg.get("command", ""))
            args = [str(a) for a in cfg.get("args", []) or []]
            full = " ".join([command] + args).strip()
            url = str(cfg.get("url", "") or cfg.get("serverUrl", ""))
            self.add("MCP001", f"Declares MCP server '{name}'", Severity.INFO, rel, line,
                     full or url, "Every MCP server is code or a remote service your agent can call.")
            exe = PurePosixPath(command.replace("\\", "/")).name.lower()
            if exe in SHELLS and any(a in ("-c", "/c", "-Command", "-EncodedCommand") for a in args):
                self.add("MCP002", f"MCP server '{name}' is launched through a shell", Severity.HIGH,
                         rel, line, full, "Real MCP servers start a program directly, not a shell one-liner.")
            if exe in ("npx", "bunx", "uvx", "pnpx") or "dlx" in args:
                pkg = next((a for a in args if not a.startswith("-") and a != "dlx"), "")
                pinned = bool(re.search(r".@\d", pkg))
                self.add("MCP003", f"MCP server '{name}' downloads package '{pkg or '?'}' at start-up"
                         + ("" if pinned else " (version not pinned)"),
                         Severity.LOW if pinned else Severity.MEDIUM, rel, line, full,
                         "Check the package on the official registry and pin an exact version.")
            if url:
                local = re.match(r"https?://(localhost|127\.0\.0\.1|\[::1\])", url)
                if url.startswith("http://") and not local:
                    self.add("MCP004", f"MCP server '{name}' uses unencrypted http://", Severity.MEDIUM,
                             rel, line, url, "Use https so tokens are not sent in clear text.")
                elif not local:
                    self.add("MCP005", f"MCP server '{name}' is a remote service", Severity.LOW, rel,
                             line, url, "Confirm who runs this server before connecting.")
            env = cfg.get("env") or {}
            for k, v in (env.items() if isinstance(env, dict) else []):
                if SECRET_LITERAL.search(str(v)):
                    self.add("MCP006", f"MCP server '{name}' has a hard-coded secret in env", Severity.HIGH,
                             rel, _line_of(raw, k), f"{k}=***", "Use environment variables, never literal tokens.")
            if full:
                self.check_command(full, rel, raw, f"MCP server '{name}'")

    def scan_tasks(self, data: dict, raw: str, rel: str) -> None:
        for task in data.get("tasks", []) or []:
            if not isinstance(task, dict):
                continue
            cmd = " ".join([str(task.get("command", ""))] + [str(a) for a in task.get("args", []) or []]).strip()
            label = task.get("label", "task")
            run_on = (task.get("runOptions") or {}).get("runOn")
            if run_on == "folderOpen":
                self.add("VSC001", f"Task '{label}' runs automatically when the folder opens", Severity.HIGH,
                         rel, _line_of(raw, "folderOpen"), cmd,
                         "Auto-run tasks execute as soon as you trust the folder. Keep 'Allow automatic tasks' off.")
            if cmd:
                base = Severity.MEDIUM if run_on == "folderOpen" else Severity.INFO
                self.check_command(cmd, rel, raw, f"VS Code task '{label}'", base=base)

    def scan_package_json(self, data: dict, raw: str, rel: str) -> None:
        scripts = data.get("scripts") or {}
        for name in LIFECYCLE_SCRIPTS:
            cmd = scripts.get(name) if isinstance(scripts, dict) else None
            if cmd:
                self.add("PKG001", f"npm '{name}' script runs on install", Severity.LOW, rel,
                         _line_of(raw, f'"{name}"'), str(cmd),
                         "Install scripts run automatically. Use 'npm install --ignore-scripts' until reviewed.")
                self.check_command(str(cmd), rel, raw, f"npm {name}")
        for key, value in data.items():
            if key.startswith("_") and isinstance(value, str) and LONG_BLOB.search(value):
                self.add("PKG002", f"Hidden encoded field '{key}' in package.json", Severity.HIGH, rel,
                         _line_of(raw, f'"{key}"'), value[:40],
                         "package.json should not carry large encoded blobs.")

    def scan_script_file(self, path: Path, rel: str, reason: str) -> None:
        size = path.stat().st_size
        text = _read(path)
        lines = text.splitlines() or [""]
        longest = max(len(l) for l in lines)
        if size > BIG_SCRIPT:
            self.add("SCR001", f"Very large script ({size // 1024} KB) {reason}", Severity.HIGH, rel, 0,
                     f"{size} bytes", "Huge single scripts are often packed or obfuscated payloads.")
        if longest > LONG_LINE:
            self.add("SCR002", f"Minified or obfuscated script {reason}", Severity.HIGH, rel, 0,
                     f"longest line {longest} chars", "Readable source should not be one giant line.")
        if LONG_BLOB.search(text):
            self.add("SCR003", f"Script contains a long encoded blob {reason}", Severity.MEDIUM, rel, 0,
                     "base64/hex data", "Decode it offline before running anything.")
        if re.search(r"\beval\s*\(|new\s+Function\s*\(|exec\s*\(\s*(compile|base64)", text):
            self.add("SCR004", f"Script uses dynamic code evaluation {reason}", Severity.MEDIUM, rel,
                     _line_of(text, "eval"), "eval/new Function/exec",
                     "Dynamic evaluation hides what really runs.")

    # ---------------------------------------------------------------- driver
    def run(self) -> ScanResult:
        for path, rel, kind in iter_targets(self.root):
            self.result.files_scanned.append(rel)
            if kind != KIND_SCRIPT:
                self.result.agent_files.append(rel)
            if kind == KIND_SCRIPT:
                self.add("SCR000", "Executable script inside an AI-agent config folder", Severity.MEDIUM,
                         rel, 0, rel, "Scripts in .claude/ or .vscode/ are used by hooks and tasks. Read them first.")
                self.scan_script_file(path, rel, "in agent folder")
                continue
            raw = _read(path)
            self.common_text_checks(raw, rel)
            if kind in (KIND_INSTRUCTION, KIND_OTHER) and not rel.endswith(".json"):
                self.scan_instruction(raw, rel)
                continue
            try:
                data = jsonc.loads(raw)
            except (json.JSONDecodeError, ValueError):
                self.add("CFG001", "Config file is not valid JSON", Severity.LOW, rel, 0, "",
                         "A broken config can hide content from tools. Open it in an editor.")
                self.scan_instruction(raw, rel)
                continue
            if not isinstance(data, dict):
                continue
            if kind == KIND_CLAUDE:
                self.scan_claude_settings(data, raw, rel)
            elif kind == KIND_MCP:
                self.scan_mcp(data, raw, rel)
            elif kind == KIND_TASKS:
                self.scan_tasks(data, raw, rel)
            elif kind == KIND_PACKAGE:
                self.scan_package_json(data, raw, rel)
            else:
                self.scan_mcp(data, raw, rel)
        self._check_referenced_scripts()
        return self.result

    def _check_referenced_scripts(self) -> None:
        scanned = set(self.result.files_scanned)
        for ref, origin in self._script_refs.items():
            candidate = (self.root / ref).resolve()
            try:
                rel = candidate.relative_to(self.root).as_posix()
            except ValueError:
                continue   # outside the repo: never read it
            if rel in scanned or not candidate.is_file() or candidate.is_symlink():
                continue
            scanned.add(rel)
            self.scan_script_file(candidate, rel, f"(referenced by {origin})")


def scan_path(path: str | Path, min_severity: Optional[Severity] = None) -> ScanResult:
    """Scan a local folder and return a ScanResult."""
    root = Path(path)
    if not root.is_dir():
        raise NotADirectoryError(f"Not a folder: {path}")
    result = Scanner(root).run()
    if min_severity is not None:
        result.findings = [f for f in result.findings if f.severity >= min_severity]
    return result
