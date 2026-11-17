# Example repos (100% harmless)

* `safe-repo/` - a normal project with a friendly AGENTS.md and a pinned MCP server.
* The **risky** demo is NOT stored here as real files. It is generated into a temp
  folder by `agent_auditor/demo.py` (`python -m agent_auditor --demo`), so an AI agent
  that opens this project never auto-loads a risky AGENTS.md, CLAUDE.md or hook.
  It imitates only the *shape* of the files described by Bitdefender Labs
  (17 Nov 2026); commands point to `example.invalid` and the script just prints a message.
