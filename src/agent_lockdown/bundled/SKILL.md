---
name: agent-lockdown
description: >-
  Audit a Linux/macOS computer and all installed AI coding agents for leaked API keys,
  malicious startup hooks, risky MCP servers, prompt injection, hidden Unicode smuggling,
  and supply-chain backdoors — and install or manage the global .env secret-file protection
  hook across all agents (Claude, Antigravity, Gemini, Cursor, Codex, Hermes, Pi, OpenCode,
  GitHub Copilot, Grok, Kiro). Use whenever the user asks to run a security check, audit AI
  agents, check for leaked keys, lock down .env files, or install/remove agent security hooks.
---

# Agent Lockdown Skill (`agent-lockdown` / `asa`)

You have access to `agent-lockdown` (also callable as `asa`), a zero-dependency, read-only security auditor and global `.env` secret-file protection hook manager for AI coding agents.

## 1. Golden Rules

1. **Do the terminal work for the user:** Run the commands yourself and summarize the results in friendly, plain English (ELI5).
2. **Audit is 100% read-only:** Always run the read-only scan first.
3. **Never print raw secrets:** `agent-lockdown` masks every secret match (`sk-or-…(73 chars)`). Never open `.env` files or print unmasked credentials into chat.
4. **Always ask permission before installing or removing hooks:** Never pass `--yes` to `--install-env-hook` or `--uninstall-env-hook` until you have shown the user which AI apps will be updated and the user has explicitly said **"Yes"**.

## 2. How to Run a Security Audit

```bash
# Fast 2-second AI-agent audit (hooks, MCP servers, leaked keys in chat/git history, rule files, supply-chain):
agent-lockdown --agents-only --format json --redact-paths

# Full 16-layer host + AI-agent audit (skipping slow virtualenv / deep git scans):
agent-lockdown --quick --format json --redact-paths
```

*(If `agent-lockdown` is not installed yet, install it with `uv tool install git+https://github.com/Mikehutu/agent-lockdown` or run `~/.local/bin/agent-lockdown`.)*

### Explaining Results to the User (ELI5 Style)

- **AI Apps Checked:** Name the AI tools detected on their machine.
- **Leaked API Keys (`agent-history` / `secrets`):** Point to the file path where a masked key was found and advise rotating the key in their provider dashboard.
- **Startup Hooks, MCP Servers & Rules (`agent-config` / `agent-rules` / `supply-chain`):** Flag any hook or extension that downloads/executes remote code or contains hidden Unicode / prompt-injection patterns.
- **`.env` Secret Protection Status (`agent-config`):** Report which installed AI agents are protected and which ones still lack the global `.env` lock.

## 3. How to Lock Down `.env` Files Globally (Permission-Gated)

### Step 1: Preview affected agents (read-only)
```bash
agent-lockdown --install-env-hook --dry-run
```

### Step 2: Ask the user for permission
Show the planned agent config paths and ask:
> *"Would you like me to install the global `.env` safety lock across these AI apps? You can choose **Block automatically** (recommended — blocks `.env` reads while allowing `.env.example`) or **Ask me every time** (prompts you for permission whenever `.env` is accessed)."*

### Step 3: Install after user confirmation
```bash
# Option 1: Block automatically (default)
agent-lockdown --install-env-hook --yes

# Option 2: Prompt user at runtime when .env is accessed
agent-lockdown --install-env-hook --hook-mode ask --yes

# Optional: also install this skill into every detected agent's global skills folder
agent-lockdown --install-skill
```

### Step 4: Verify
```bash
agent-lockdown --layer agent-config --show-ok
```

## 4. How to Remove the Global `.env` Lock (If Requested)

If the user asks to remove or undo the `.env` lock, ask for confirmation and run:
```bash
agent-lockdown --uninstall-env-hook --yes
```
