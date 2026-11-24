# AGENTS.md — AI Agent Runbook for `agent-lockdown` (`asa`)

If a user pasted the link `https://github.com/Mikehutu/agent-lockdown` into your chat (**Claude Desktop**, **Claude Code**, **Antigravity Desktop / IDE / CLI**, **Cursor**, **Codex**, **Hermes**, **Pi**, **OpenCode**, **Grok**, **GitHub Copilot**, **Kiro**), **you are in charge of running the check and guiding them in simple, non-technical plain English (ELI5).**

Assume the user may not know how to code or use a terminal. Handle all commands for them, explain everything simply, and **always ask their permission before changing any settings**.

---

## 1. Golden Rules for the Agent

1. **Do the terminal work for the user:** Never ask a non-technical user to run terminal commands themselves if you have a shell/command tool. Run the commands for them and summarize the results in friendly, plain English.
2. **Audit first (100% read-only):** Always run the read-only scan before proposing any changes.
3. **Never reveal raw secrets:** `agent-lockdown` (`asa`) masks every secret (`sk-or-…(73 chars)`). Never open `.env` files or print unmasked API keys into the chat.
4. **Always ask permission before installing hooks:** Never run `agent-lockdown --install-env-hook --yes` until you have explained in plain English which AI apps on their computer will be updated and the user has said **"Yes"**.

---

## 2. Step-by-Step Workflow When a User Shares This Repo

### Step 0: Self-Audit This Repository First (Prove to the User It Is Safe)

Because this is a security tool that installs global hooks, **never ask the user to trust it blindly**. Before installing or running anything:

1. Inspect the 4 source files in `src/agent_lockdown/` (`data.py`, `core.py`, `hooks.py`, `cli.py`), `hermes/__init__.py`, `skills/agent-lockdown/SKILL.md`, and `pyproject.toml`.
2. Verify for the user that:
   - `pyproject.toml` has `dependencies = []` (zero third-party supply-chain risk).
   - `src/agent_lockdown/hooks.py` imports **no networking modules** (`urllib`, `http`, `socket`) and never reads `.env` contents—it only inspects the target filename/command string and blocks access.
   - The only network call in `core.py` is the public `https://cve.now/stack` package-version lookup (which is not even called during `--agents-only` or `--offline`).
   - File writes only exist in `hooks.py` when `--install-env-hook`, `--uninstall-env-hook`, or `--install-skill` is explicitly invoked.
3. Briefly tell the user in plain English: *"I reviewed the `agent-lockdown` source code first: it has zero external dependencies, no hidden network calls in its hook, and never sends your files or secrets anywhere."*

### Step 1: Install `agent-lockdown` Automatically

Check if `agent-lockdown` / `asa` is already installed; if not, install it from GitHub so the global hook binary (`~/.local/bin/agent-lockdown` and `~/.local/bin/asa`) is available on the machine:

```bash
# If uv is available (preferred):
uv tool install --force git+https://github.com/Mikehutu/agent-lockdown

# Fallback if uv is not installed:
python3 -m pip install --user --upgrade git+https://github.com/Mikehutu/agent-lockdown
```

*(Note: Ensure `~/.local/bin` is used when running `agent-lockdown` / `asa`, e.g., `~/.local/bin/agent-lockdown` if `~/.local/bin` is not in `PATH`.)*

### Step 2: Run the Read-Only Security Audit

Run the fast AI-agent audit (takes ~2 seconds):

```bash
~/.local/bin/agent-lockdown --agents-only --format json --redact-paths
```

*(If the user also asked for a full computer check, run `~/.local/bin/agent-lockdown --quick --format json --redact-paths`.)*

### Step 3: Explain the Results to the User in Simple ELI5 Plain English

Translate the findings into a short, reassuring summary without technical jargon:

- **AI Apps Found:** Tell them which AI tools were detected on their computer (e.g., *"I found Claude, Antigravity, Cursor, Hermes, and Codex on your computer."*).
- **Leaked Keys (`agent-history` / `secrets`):** If any keys were found in old chat history or git commits, explain simply: *"I found an old API key saved in a chat log file (`path`). The key itself is hidden, but you should create a new key in your provider dashboard and delete the old one."*
- **Sneaky Startup Scripts or Plugins (`agent-config` / `supply-chain` / `agent-rules`):** Tell them if any startup hooks, MCP plugins, or rule files look risky.
- **Unprotected `.env` Secret Files (`agent-config`):** Check which of their AI apps don't have the `.env` lock installed yet by running:
  ```bash
  ~/.local/bin/agent-lockdown --install-env-hook --dry-run
  ```

### Step 4: Ask the User for Permission to Install the Global `.env` Lock & Skill

Ask the user in plain English:

> *"Right now, these AI apps on your computer can be protected with the global `.env` safety lock (and the `agent-lockdown` security skill): **[list of apps]**.*
>
> *Would you like me to turn on the global `.env` safety lock and install the skill for them? You can choose:*
> 1. ***Block automatically (Recommended):** None of your AI apps will be allowed to read `.env` secret files (safe example files like `.env.example` will still work).*
> 2. ***Ask me every time:** Your AI app will pop up and ask for your permission whenever it wants to read a `.env` file."*

### Step 5: Install the Hooks & Skill (Only After the User Says Yes)

Once the user confirms:

```bash
# If they chose option 1 (Block automatically — default):
~/.local/bin/agent-lockdown --install-env-hook --yes

# If they chose option 2 (Ask me every time):
~/.local/bin/agent-lockdown --install-env-hook --hook-mode ask --yes

# Also install the agent-lockdown SKILL.md into all detected agents' global skills folders:
~/.local/bin/agent-lockdown --install-skill
```

Then verify that every detected AI agent is now protected:

```bash
~/.local/bin/agent-lockdown --layer agent-config --show-ok
```

Report back to the user in plain English: *"All done! I've locked down `.env` files across all your AI apps, installed the `agent-lockdown` skill so you can ask any of your agents to run a check anytime, and verified that your existing settings were preserved."*

---

## 3. Reference: What `agent-lockdown` Installs

- **Global `.env` Hooks (`--install-env-hook`):**
  - **Claude (Desktop CLI & Code):** `~/.claude/settings.json` (`permissions.deny` + `hooks.PreToolUse`)
  - **Antigravity (Desktop / IDE / CLI) & Gemini:** `~/.gemini/config/hooks.json` (`asa-env-guard.PreToolUse`) + `~/.gemini/settings.json`
  - **Codex CLI:** `~/.codex/hooks.json` (`hooks.PreToolUse`)
  - **Grok CLI:** `~/.grok/hooks/asa-env-guard.json` (`hooks.PreToolUse`)
  - **GitHub Copilot:** `~/.copilot/hooks/asa-env-guard.json` (`hooks.PreToolUse`)
  - **Cursor:** `~/.cursor/hooks.json` (`beforeReadFile` + `beforeShellExecution`)
  - **Kiro CLI:** `~/.kiro/settings/hooks.json` (`hooks.preToolUse`)
  - **Hermes Agent:** `~/.hermes/plugins/agent-lockdown/` (native `pre_tool_call` hook + `agent_lockdown` tool, enabled in `~/.hermes/config.yaml`)
  - **Pi Coding Agent:** `~/.pi/agent/extensions/asa-env-guard.ts` (`pi.on("tool_call", ...)`)
  - **OpenCode:** `~/.config/opencode/plugins/asa-env-guard.js` (`"tool.execute.before"`)
  - **Factory / Qwen:** `~/.factory/settings.json`, `~/.qwen/settings.json` (`hooks.PreToolUse`)
- **Global Agent Skill (`--install-skill` or `npx skills add Mikehutu/agent-lockdown`):**
  - Installs `SKILL.md` into `~/.agents/skills/agent-lockdown/SKILL.md` plus `~/.claude/skills/`, `~/.hermes/skills/`, `~/.codex/skills/`, `~/.gemini/skills/`, `~/.copilot/skills/`, `~/.grok/skills/`, `~/.pi/agent/skills/`, `~/.config/opencode/skills/`, and `~/.kiro/skills/` for every installed agent on the host.
- **Uninstalling (`--uninstall-env-hook --yes`):**
  - Cleanly removes the `.env` hook entries while preserving all other user hooks (such as `herdr`).

---

## 4. Repository Development Guidelines (for Agents Editing This Repo)

- **Zero dependencies:** Python 3.8+ standard library only (`pyproject.toml` has `dependencies = []`).
- **Keep audit read-only:** `core.audit(ctx)` must never create, modify, or delete any file (`tests/test_smoke.py::AuditTests::test_audit_never_writes` enforces this).
- **Run tests before committing:**
  ```bash
  PYTHONPATH=src python3 -m unittest discover -s tests -v
  ```
