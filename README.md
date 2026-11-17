# 🛡️ AI Coding-Agent Config Auditor (Python)

A **read-only security scanner** that checks a cloned repository for risky AI coding-agent files
**before** you open it with Claude Code, Cursor, Copilot, Gemini CLI, Codex or any other AI assistant.

It flags things like:

* `AGENTS.md` / `CLAUDE.md` / `.cursorrules` text that tells the agent **not to read a script** and to **run it silently**
* `.claude/settings.json` **SessionStart hooks**, blanket `Bash(*)` permissions and `bypassPermissions`
* MCP server configs (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`) launched through a shell, over plain `http://`, unpinned `npx -y` packages or hard-coded tokens
* VS Code tasks that run on `folderOpen`, npm `postinstall` scripts
* huge / single-line (obfuscated) scripts referenced by those files, hidden Unicode, long encoded blobs

📖 Full step-by-step tutorial: **https://getprojects.org/ai-coding-agent-security-scanner-python/**

> **Why now?** On 17 Nov 2026 Bitdefender Labs reported a GitHub malware campaign that abuses
> AGENTS.md, CLAUDE.md, session-start hooks and MCP configs to make AI coding agents run a hidden
> `setup.js` ([report](https://www.bitdefender.com/en-us/blog/labs/how-ai-agents-become-new-targets-in-github-malware-campaign)).
> Google Threat Intelligence (16 Nov 2026) also describes attackers modifying `.claude/settings.json`
> so a backdoor downloads when Claude Code starts
> ([report](https://cloud.google.com/blog/topics/threat-intelligence/agentic-threat-activity-crosses-a-significant-threshold/)).

**This tool is 100% defensive.** It never executes, imports or installs anything from the scanned
repository, never follows symlinks, and never reads files outside the repo. The "risky" demo
repo is **generated into a temp folder on demand** (`agent_auditor/demo.py`) and contains only
harmless placeholder text pointing at `example.invalid`, so no live risky AGENTS.md or hooks
are ever committed here for your own AI agent to pick up.

---

## Features

| | |
|---|---|
| 🔍 35+ detection rules | instruction-file wording, hooks, permissions, MCP servers, tasks, npm scripts, scripts |
| 📊 Risk score 0-100 + verdict | `LOOKS SAFE`, `REVIEW` or `DANGEROUS` |
| 🖥️ CLI | text (coloured), JSON or Markdown output, CI-friendly exit codes |
| 🌐 Optional Flask web UI | upload a `.zip`, zip-slip and zip-bomb protected |
| 🧬 Safe clone | `--clone URL` does a shallow clone with git hooks disabled, scans, deletes |
| ✅ Tested | 25 pytest tests, standard library only for the core |

## Quick start

```bash
git clone https://github.com/GetProjectsIdea/AI-Coding-Agent-Config-Auditor-Python.git
cd AI-Coding-Agent-Config-Auditor-Python
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt

# scan a repo you already cloned
python -m agent_auditor path/to/some-repo

# try the bundled examples
python -m agent_auditor --demo                 # builds a harmless risky demo repo in a temp folder
python -m agent_auditor examples/safe-repo
```

### More CLI options

```bash
python -m agent_auditor --clone https://github.com/user/repo     # safe shallow clone + scan
python -m agent_auditor some-repo -f json -o report.json         # JSON report
python -m agent_auditor some-repo -f markdown -o report.md       # Markdown report
python -m agent_auditor some-repo --min-severity medium          # hide low/info
python -m agent_auditor some-repo --fail-on critical             # CI gate
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = risky findings, `2` = usage error.

Install as a command: `pip install .` then run `agent-audit some-repo`.

### Web UI

```bash
python app.py        # open http://127.0.0.1:5000
```

## Sample output

```text
AI Coding-Agent Config Auditor
==============================
Scanned folder : demo:risky-repo
Agent files    : 6 (.mcp.json, AGENTS.md, CLAUDE.md, package.json, .vscode/tasks.json, .claude/settings.json)
Risk score     : 100/100
Verdict        : DANGEROUS
Findings       : Critical 4, High 11, Medium 9, Low 4, Info 3

[CRITICAL] AGT100 Concealed script + instruction to run it (known attack pattern)
           at  AGENTS.md
[CRITICAL] AGT002 Asks to run something without user confirmation
           at  AGENTS.md:6
[HIGH    ] CLD001 SessionStart hook runs a shell command automatically
           at  .claude/settings.json:6
[HIGH    ] VSC001 Task 'prepare' runs automatically when the folder opens
           at  .vscode/tasks.json:9
...
```

Full outputs: [`docs/sample-output-risky.txt`](docs/sample-output-risky.txt), [`docs/sample-output-safe.txt`](docs/sample-output-safe.txt).

## Screenshots

| Home | Risky report |
|---|---|
| ![Home](docs/screenshots/01-home.png) | ![Risky report](docs/screenshots/02-risky-report.png) |
| **Safe report** | **CLI** |
| ![Safe report](docs/screenshots/03-safe-report.png) | ![CLI output](docs/screenshots/05-cli-output.png) |

Mobile view: [`docs/screenshots/04-mobile-report.png`](docs/screenshots/04-mobile-report.png)

## Project structure

```text
agent_auditor/
  targets.py      which files can steer an AI agent (AGENTS.md, .claude/, .mcp.json ...)
  rules.py        regex detection rules (instruction wording + shell command patterns)
  scanner.py      reads files, parses JSON(C), applies rules, follows referenced scripts
  models.py       Finding / ScanResult, risk score and verdict
  report.py       text, Markdown and JSON reports + safe-cloning checklist
  safe_clone.py   shallow clone with hooks disabled (https GitHub/GitLab/Bitbucket only)
  cli.py          argparse command line
app.py            optional Flask web UI
  demo.py         builds the harmless risky demo repo in a temp folder
examples/         harmless safe-repo fixture
tests/            pytest suite
```

## Rule reference (short)

| ID | What it flags | Severity |
|---|---|---|
| AGT001 | "Do not read/inspect scripts/x.js" | High |
| AGT002 | run "without asking / without confirmation" | Critical |
| AGT003 | "without displaying output", run silently | High |
| AGT004 | run at session start | Medium |
| AGT005 | "sealed artifact", "cryptographically signed", "not human-readable" | Medium |
| AGT006 | `curl ... \| sh`, `iwr ... \| iex` | Critical |
| AGT008 | "ignore previous instructions" | High |
| AGT100 | concealment + execution in one file (campaign pattern) | Critical |
| CLD001 | hooks (SessionStart = High) | Medium/High |
| CLD002-004 | `Bash(*)`, `bypassPermissions`, `enableAllProjectMcpServers` | High |
| MCP002-006 | shell-launched, http://, unpinned npx, remote, literal secrets | Low-High |
| VSC001 | VS Code task with `runOn: folderOpen` | High |
| PKG001-002 | npm install scripts, hidden encoded `_field` | Low/High |
| SCR000-004 | scripts in agent folders, huge/minified/encoded/eval scripts | Medium/High |
| TXT001-003 | hidden Unicode, encoded blobs, hard-coded tokens | Medium/High |

## Safe-cloning checklist for students

1. Read `AGENTS.md`, `CLAUDE.md` and `.cursorrules` yourself before opening the repo with an AI agent.
2. Open `.claude/settings.json`, `.mcp.json`, `.cursor/mcp.json` and `.vscode/tasks.json` and read every command.
3. Open unknown repos in VS Code **Restricted Mode** (don't click "Trust" yet).
4. Install with `npm install --ignore-scripts` until you've reviewed `package.json`.
5. Never let an agent run a script it was told not to read.
6. Test unknown code in a fresh VM, container or Codespace with no personal tokens.

## Limitations

Pattern matching can miss new tricks and can occasionally flag harmless text. A clean report
means "no known red flags", not "guaranteed safe". Always read the files yourself.

## Ideas to extend (final-year project scope)

* SARIF output for GitHub code scanning
* a GitHub Action / pre-commit hook
* an ML classifier for instruction files trained on labelled examples
* a browser extension that scans a repo page before you clone

## License

MIT © 2026 Pardeep Patel / [GetProjects.org](https://getprojects.org/)
