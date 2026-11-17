"""Which files in a repository can steer or trigger an AI coding agent."""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Iterator, Tuple

# Markdown / text instruction files that an agent reads into its context.
INSTRUCTION_PATTERNS = [
    "AGENTS.md", "AGENT.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md",
    ".cursorrules", ".windsurfrules", ".clinerules", ".roorules",
    ".cursor/rules/*", ".windsurf/rules/*", ".clinerules/*",
    ".github/copilot-instructions.md", ".github/instructions/*",
    ".claude/commands/*", ".claude/agents/*", ".claude/skills/*/SKILL.md",
    ".gemini/*.md", ".kiro/steering/*", ".continue/rules/*",
]

# JSON settings that can define hooks, permissions or tasks.
CLAUDE_SETTINGS = [".claude/settings.json", ".claude/settings.local.json"]
MCP_PATTERNS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json",
                ".gemini/settings.json", ".roo/mcp.json", ".kiro/settings/mcp.json",
                "mcp.json", ".continue/mcpServers/*.json"]
VSCODE_TASKS = [".vscode/tasks.json"]
OTHER_CONFIG = [".aider.conf.yml", ".continue/config.json", ".continue/config.yaml"]
PACKAGE_JSON = ["package.json"]

KIND_INSTRUCTION = "instruction"
KIND_CLAUDE = "claude-settings"
KIND_MCP = "mcp"
KIND_TASKS = "vscode-tasks"
KIND_OTHER = "agent-config"
KIND_PACKAGE = "package-json"
KIND_SCRIPT = "agent-folder-script"

AGENT_DIRS = (".claude/", ".vscode/", ".cursor/", ".gemini/", ".windsurf/", ".kiro/", ".continue/")
SCRIPT_EXTS = (".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".ps1", ".bat", ".cmd")

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


def _match(rel: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(rel, p) for p in patterns)


def classify(rel: str) -> str | None:
    """Return the target kind for a repo-relative POSIX path, or None.

    Nested folders count too (monorepos): `apps/web/.mcp.json` is checked
    as `.mcp.json`, `apps/web/.claude/settings.json` as `.claude/settings.json`.
    """
    parts = rel.split("/")
    for i in range(len(parts)):
        kind = _classify_one("/".join(parts[i:]))
        if kind:
            return kind
    return None


def _classify_one(rel: str) -> str | None:
    name = rel.rsplit("/", 1)[-1]
    if _match(rel, CLAUDE_SETTINGS):
        return KIND_CLAUDE
    if _match(rel, MCP_PATTERNS):
        return KIND_MCP
    if _match(rel, VSCODE_TASKS):
        return KIND_TASKS
    if _match(rel, OTHER_CONFIG):
        return KIND_OTHER
    if rel == "package.json":
        return KIND_PACKAGE
    if _match(rel, INSTRUCTION_PATTERNS) or name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md"}:
        return KIND_INSTRUCTION
    if rel.startswith(AGENT_DIRS) and rel.lower().endswith(SCRIPT_EXTS):
        return KIND_SCRIPT
    return None


def iter_targets(root: Path) -> Iterator[Tuple[Path, str, str]]:
    """Yield (absolute_path, relative_posix_path, kind) for agent files under root.

    Symlinks are never followed, so a malicious repo cannot point the
    scanner at files outside the project.
    """
    root = root.resolve()
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
                continue
            rel = entry.relative_to(root).as_posix()
            kind = classify(rel)
            if kind:
                yield entry, rel, kind
