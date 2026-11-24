"""Multi-agent global .env protection hooks & skills: runtime handler, snippets, and installer.

Supports:
  * Claude Code        (~/.claude/settings.json: permissions.deny + hooks.PreToolUse)
  * Antigravity/Gemini (~/.gemini/config/hooks.json: asa-env-guard.PreToolUse + ~/.gemini/settings.json)
  * Codex CLI          (~/.codex/hooks.json: hooks.PreToolUse)
  * Grok CLI           (~/.grok/hooks/asa-env-guard.json: hooks.PreToolUse)
  * GitHub Copilot     (~/.copilot/hooks/asa-env-guard.json: hooks.PreToolUse)
  * Cursor             (~/.cursor/hooks.json: beforeReadFile + beforeShellExecution)
  * Kiro CLI           (~/.kiro/settings/hooks.json: hooks.preToolUse)
  * Hermes Agent       (~/.hermes/plugins/agent-lockdown: pre_tool_call hook + config.yaml)
  * Pi Coding Agent    (~/.pi/agent/extensions/asa-env-guard.ts: tool_call listener)
  * OpenCode           (~/.config/opencode/plugins/asa-env-guard.js: tool.execute.before)
  * Factory / Qwen     (~/.factory/settings.json, ~/.qwen/settings.json: hooks.PreToolUse)
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from typing import Any

HOOK_MARKER = "asa-env-guard"
RUN_HOOK_FLAG = "--run-env-hook"

SAFE_ENV_SUFFIXES = (
    ".example", ".sample", ".template", ".dist",
    ".defaults", ".schema", ".md", ".txt", ".rst",
)

CODE_ENV_IDENTIFIERS = frozenset({
    "process.env", "meta.env", "import.meta.env", "deno.env",
    "bun.env", "cypress.env", "window.env", "global.env",
    "globalthis.env", "os.env", "sys.env", "ctx.env", "self.env",
})

PATH_ARG_KEYS = (
    "file_path", "path", "filePath", "Path", "target_file", "TargetFile",
    "uri", "file", "filename", "source", "destination", "glob", "pattern",
    "include", "directory_path", "TargetDirectory",
)

MULTI_PATH_ARG_KEYS = ("paths", "files", "patterns", "targets", "includePatterns")

COMMAND_ARG_KEYS = ("command", "CommandLine", "cmd", "script", "code")

CLAUDE_DENY_RULES = [
    "Read(.env)",
    "Read(.env.*)",
    "Read(**/.env)",
    "Read(**/.env.*)",
]

# Regex extracting candidate .env file tokens from shell commands or inline scripts.
_ENV_TOKEN_RE = re.compile(
    r"""(?:^|[\s'"`(=:<|,])((?:[A-Za-z0-9_./~*-]*/)?(?:\.env(?:\.[A-Za-z0-9_.*-]+|\*)?|[A-Za-z0-9_.-]+\.env))(?=$|[\s'"`);>|,&])""",
    re.I,
)

# Safe housekeeping git / gh / asa commands that do not expose .env secret contents.
_SAFE_GIT_CMD_RE = re.compile(
    r"^\s*(?:git\s+(?:-[A-Za-z]\s+\S+\s+)*(?:check-ignore|rm\s+--cached|status|add\s+\.gitignore|commit|log)\b|gh\s+(?:repo|pr|issue|release)\b|(?:asa|agent-lockdown|agent-security-audit)\b)",
    re.I,
)
_SAFE_GITIGNORE_ECHO_RE = re.compile(
    r"""^\s*(?:echo|printf)\s+['"]?\.env(?:\.\*|\*)?['"]?\s*>>\s*(?:\S+/)?\.gitignore\s*$""",
    re.I,
)


def is_sensitive_env_path(raw_path: str, *, from_command: bool = False) -> bool:
    """True when raw_path points to a sensitive .env file rather than a safe template."""
    if not raw_path or not isinstance(raw_path, str):
        return False
    cleaned = raw_path.strip().strip("'\"`();,|&<>")
    if not cleaned:
        return False
    low_full = cleaned.replace("\\", "/").lower()
    if from_command and low_full in CODE_ENV_IDENTIFIERS:
        return False
    base = os.path.basename(low_full.rstrip("/"))
    if not base:
        return False
    if any(base.endswith(ext) for ext in SAFE_ENV_SUFFIXES):
        return False
    if base in (".env", ".env*", "*.env", ".env.*"):
        return True
    if base.startswith(".env."):
        return True
    if base.endswith(".env"):
        if from_command and "/" not in low_full and not base.startswith(
            ("secrets.", "secret.", "prod.", "production.", "local.", "dev.", "staging.", "credentials.", "auth.", "app.", "docker.")
        ):
            return False
        return True
    return False


def is_sensitive_env_command(cmd: str) -> str | None:
    """Return the matched sensitive .env token if a shell/code command accesses a .env file."""
    if not cmd or not isinstance(cmd, str):
        return None
    segments = re.split(r"(?:&&|\|\||;|\n)", cmd)
    for seg in segments:
        seg_str = seg.strip()
        if not seg_str:
            continue
        if _SAFE_GIT_CMD_RE.match(seg_str) or _SAFE_GITIGNORE_ECHO_RE.match(seg_str):
            continue
        for m in _ENV_TOKEN_RE.finditer(seg_str):
            token = m.group(1)
            if is_sensitive_env_path(token, from_command=True):
                return token
    return None


def check_tool_call(tool_name: str, tool_input: Any) -> str | None:
    """Inspect a tool call's name and arguments. Return a human-readable match reason or None."""
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except Exception:  # noqa: BLE001
            if is_sensitive_env_path(tool_input):
                return tool_input
            return is_sensitive_env_command(tool_input)

    if not isinstance(tool_input, dict):
        return None

    for key in PATH_ARG_KEYS:
        k = key.strip()
        val = tool_input.get(k)
        if isinstance(val, str) and is_sensitive_env_path(val):
            return "%s (%s=%s)" % (tool_name or "tool", k, val)

    for key in MULTI_PATH_ARG_KEYS:
        vals = tool_input.get(key)
        if isinstance(vals, (list, tuple)):
            for val in vals:
                if isinstance(val, str) and is_sensitive_env_path(val):
                    return "%s (%s=%s)" % (tool_name or "tool", key, val)

    for key in COMMAND_ARG_KEYS:
        val = tool_input.get(key)
        if isinstance(val, str):
            hit = is_sensitive_env_command(val)
            if hit:
                return "%s (%s references %s)" % (tool_name or "shell", key, hit)

    for nested_key in ("args", "input", "tool_input", "parameters"):
        nested = tool_input.get(nested_key)
        if isinstance(nested, dict) and nested is not tool_input:
            hit = check_tool_call(tool_name, nested)
            if hit:
                return hit

    return None


def run_env_hook(stdin_text: str, mode: str = "deny") -> tuple[int, str, str]:
    """Process a hook payload from stdin. Returns (exit_code, stdout, stderr).

    Fails open (exit 0) on malformed input so a hook error never bricks an agent session.
    """
    raw = (stdin_text or "").strip()
    if not raw:
        return 0, "", ""
    try:
        payload = json.loads(raw)
    except Exception:  # noqa: BLE001
        return 0, "", ""
    if not isinstance(payload, dict):
        return 0, "", ""

    # 1. Antigravity / Gemini CLI protocol (camelCase hookEventName / toolCall)
    if "hookEventName" in payload or "toolCall" in payload:
        tc = payload.get("toolCall") if isinstance(payload.get("toolCall"), dict) else {}
        tool_name = str(tc.get("name") or payload.get("toolName") or "")
        tool_args = tc.get("args") if isinstance(tc.get("args"), dict) else payload
        hit = check_tool_call(tool_name, tool_args)
        if hit:
            decision = "ask" if mode == "ask" else "deny"
            reason = (
                "agent-lockdown (%s): blocked access to secret .env file via %s. "
                "Use .env.example for templates." % (HOOK_MARKER, hit)
            )
            return 0, json.dumps({"decision": decision, "reason": reason}), ""
        if payload.get("hookEventName") == "PreToolUse":
            return 0, json.dumps({"decision": "allow"}), ""
        return 0, "{}", ""

    # 2. Cursor hook protocol (beforeReadFile / beforeShellExecution)
    event_name = str(payload.get("hook_event_name") or "")
    if "cursor_version" in payload or event_name in ("beforeReadFile", "beforeShellExecution", "beforeMCPExecution"):
        tool_name = event_name or str(payload.get("tool_name") or "cursor")
        tool_args = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else payload
        hit = check_tool_call(tool_name, tool_args)
        if hit:
            reason = (
                "agent-lockdown (%s): blocked access to secret .env file via %s." % (HOOK_MARKER, hit)
            )
            if mode == "ask":
                return 0, json.dumps({"permission": "ask", "user_message": reason, "agent_message": reason}), ""
            return 2, json.dumps({"permission": "deny", "user_message": reason, "agent_message": reason}), reason
        return 0, json.dumps({"permission": "allow"}), ""

    # 3. Hermes shell hook protocol (pre_tool_call)
    if event_name == "pre_tool_call":
        tool_name = str(payload.get("tool_name") or "")
        tool_args = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else (payload.get("args") or {})
        hit = check_tool_call(tool_name, tool_args)
        if hit:
            reason = (
                "agent-lockdown (%s): blocked access to secret .env file via %s." % (HOOK_MARKER, hit)
            )
            if mode == "ask":
                return 0, json.dumps({"action": "approve", "message": reason, "rule_key": "asa_env_guard"}), ""
            return 2, json.dumps({"action": "block", "message": reason}), reason
        return 0, "", ""

    # 4. Claude Code / Codex CLI / Grok CLI / Copilot / Factory / Qwen / Kiro (PreToolUse / preToolUse)
    tool_name = str(payload.get("tool_name") or payload.get("toolName") or event_name or "")
    tool_args = (
        payload.get("tool_input")
        if isinstance(payload.get("tool_input"), dict)
        else payload.get("toolInput")
        if isinstance(payload.get("toolInput"), dict)
        else payload.get("args")
        if isinstance(payload.get("args"), dict)
        else payload.get("input")
        if isinstance(payload.get("input"), dict)
        else payload
    )
    hit = check_tool_call(tool_name, tool_args)
    if hit:
        reason = (
            "agent-lockdown (%s): blocked access to secret .env file via %s. "
            "Use .env.example for templates." % (HOOK_MARKER, hit)
        )
        if mode == "ask":
            out = {
                "hookSpecificOutput": {
                    "hookEventName": event_name or "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": reason,
                }
            }
            return 0, json.dumps(out), ""
        return 2, "", reason

    return 0, "", ""


def resolve_hook_command(mode: str = "deny", portable: bool = False) -> str:
    """Return the shell command used in hook configs to invoke the .env guard."""
    suffix = " %s" % RUN_HOOK_FLAG
    if mode == "ask":
        suffix += " --hook-mode ask"
    if portable:
        return "asa" + suffix
    for local_bin in ("~/.local/bin/asa", "~/.local/bin/agent-lockdown"):
        home_local = os.path.expanduser(local_bin)
        if os.path.isfile(home_local) and os.access(home_local, os.X_OK):
            return home_local + suffix
    for name in ("asa", "agent-lockdown", "agent-security-audit"):
        found = shutil.which(name)
        if found:
            return found + suffix
    return "%s -m agent_lockdown%s" % (sys.executable, suffix)


PI_EXTENSION_TEMPLATE = """// installed by agent-lockdown (asa-env-guard)
// Blocks reading or leaking sensitive .env files while allowing .env.example / .sample / .template.
// @ts-nocheck

const SAFE_SUFFIXES = [".example", ".sample", ".template", ".dist", ".defaults", ".schema", ".md", ".txt"];
const CODE_IDS = new Set(["process.env", "meta.env", "import.meta.env", "deno.env", "bun.env", "window.env"]);
const ENV_TOKEN_RE = /(?:^|[\\s'"`(=:<|,])((?:[A-Za-z0-9_./~*-]*\\/)?(?:\\.env(?:\\.[A-Za-z0-9_.*-]+|\\*)?|[A-Za-z0-9_.-]+\\.env))(?=$|[\\s'"`);>|,&])/gi;

function isSensitiveEnvPath(raw, fromCmd = false) {
  if (typeof raw !== "string" || !raw.trim()) return false;
  const cleaned = raw.trim().replace(/^['"`();,|&<>]+|['"`();,|&<>]+$/g, "").replace(/\\\\/g, "/").toLowerCase();
  if (fromCmd && CODE_IDS.has(cleaned)) return false;
  const parts = cleaned.replace(/\\/+$/, "").split("/");
  const base = parts[parts.length - 1] || "";
  if (!base || SAFE_SUFFIXES.some((s) => base.endsWith(s))) return false;
  if (base === ".env" || base === ".env*" || base === "*.env" || base === ".env.*" || base.startsWith(".env.")) return true;
  if (base.endsWith(".env")) {
    if (fromCmd && !cleaned.includes("/") && !/^(secrets?|prod|production|local|dev|staging|credentials?|auth|app|docker)\\.env$/.test(base)) {
      return false;
    }
    return true;
  }
  return false;
}

function checkInput(input) {
  if (!input || typeof input !== "object") return null;
  for (const k of ["file_path", "path", "filePath", "Path", "target_file", "file", "glob", "pattern"]) {
    if (typeof input[k] === "string" && isSensitiveEnvPath(input[k])) return `${k}=${input[k]}`;
  }
  for (const k of ["command", "CommandLine", "cmd", "script", "code"]) {
    if (typeof input[k] === "string") {
      const cmd = input[k];
      if (/^\\s*git\\s+(?:check-ignore|rm\\s+--cached|status)\\b/i.test(cmd)) continue;
      ENV_TOKEN_RE.lastIndex = 0;
      let m;
      while ((m = ENV_TOKEN_RE.exec(cmd)) !== null) {
        if (isSensitiveEnvPath(m[1], true)) return `${k} references ${m[1]}`;
      }
    }
  }
  return null;
}

export default function (pi) {
  pi.on("tool_call", (event) => {
    const hit = checkInput(event?.input);
    if (hit) {
      return {
        block: true,
        reason: `agent-lockdown (asa-env-guard): blocked access to secret .env file (${hit}). Use .env.example for templates.`,
      };
    }
  });
}
"""

OPENCODE_PLUGIN_TEMPLATE = """// installed by agent-lockdown (asa-env-guard)
// Blocks reading or leaking sensitive .env files while allowing .env.example / .sample / .template.

const SAFE_SUFFIXES = [".example", ".sample", ".template", ".dist", ".defaults", ".schema", ".md", ".txt"];
const CODE_IDS = new Set(["process.env", "meta.env", "import.meta.env", "deno.env", "bun.env", "window.env"]);
const ENV_TOKEN_RE = /(?:^|[\\s'"`(=:<|,])((?:[A-Za-z0-9_./~*-]*\\/)?(?:\\.env(?:\\.[A-Za-z0-9_.*-]+|\\*)?|[A-Za-z0-9_.-]+\\.env))(?=$|[\\s'"`);>|,&])/gi;

function isSensitiveEnvPath(raw, fromCmd = false) {
  if (typeof raw !== "string" || !raw.trim()) return false;
  const cleaned = raw.trim().replace(/^['"`();,|&<>]+|['"`();,|&<>]+$/g, "").replace(/\\\\/g, "/").toLowerCase();
  if (fromCmd && CODE_IDS.has(cleaned)) return false;
  const parts = cleaned.replace(/\\/+$/, "").split("/");
  const base = parts[parts.length - 1] || "";
  if (!base || SAFE_SUFFIXES.some((s) => base.endsWith(s))) return false;
  if (base === ".env" || base === ".env*" || base === "*.env" || base === ".env.*" || base.startsWith(".env.")) return true;
  if (base.endsWith(".env")) {
    if (fromCmd && !cleaned.includes("/") && !/^(secrets?|prod|production|local|dev|staging|credentials?|auth|app|docker)\\.env$/.test(base)) {
      return false;
    }
    return true;
  }
  return false;
}

function checkArgs(args) {
  if (!args || typeof args !== "object") return null;
  for (const k of ["file_path", "path", "filePath", "Path", "target_file", "file", "glob", "pattern"]) {
    if (typeof args[k] === "string" && isSensitiveEnvPath(args[k])) return `${k}=${args[k]}`;
  }
  for (const k of ["command", "CommandLine", "cmd", "script", "code"]) {
    if (typeof args[k] === "string") {
      const cmd = args[k];
      if (/^\\s*git\\s+(?:check-ignore|rm\\s+--cached|status)\\b/i.test(cmd)) continue;
      ENV_TOKEN_RE.lastIndex = 0;
      let m;
      while ((m = ENV_TOKEN_RE.exec(cmd)) !== null) {
        if (isSensitiveEnvPath(m[1], true)) return `${k} references ${m[1]}`;
      }
    }
  }
  return null;
}

export const AsaEnvGuardPlugin = async () => {
  return {
    "tool.execute.before": async (input, output) => {
      const hit = checkArgs(output?.args ?? input);
      if (hit) {
        throw new Error(`agent-lockdown (asa-env-guard): blocked access to secret .env file (${hit}). Use .env.example for templates.`);
      }
    },
  };
};

export default AsaEnvGuardPlugin;
"""


def format_env_hook_snippets(agent: str = "all", mode: str = "deny") -> str:
    """Return copy-pasteable global hook configuration snippets for one or all agents."""
    cmd = resolve_hook_command(mode=mode, portable=True)
    sections = []

    if agent in ("all", "claude"):
        claude_cfg = {
            "permissions": {"deny": CLAUDE_DENY_RULES},
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Read|Edit|Write|MultiEdit|Bash|Grep",
                        "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
                    }
                ]
            },
        }
        sections.append(
            "# 1. Claude Code — ~/.claude/settings.json (or .claude/settings.json):\n"
            + json.dumps(claude_cfg, indent=2)
        )

    if agent in ("all", "gemini", "antigravity"):
        gemini_cfg = {
            HOOK_MARKER: {
                "PreToolUse": [
                    {
                        "matcher": "read_file|view_file|run_command|grep_search|edit_file|write_file|replace_file_content|multi_replace_file_content",
                        "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
                    }
                ]
            }
        }
        sections.append(
            "# 2. Antigravity / Gemini — ~/.gemini/config/hooks.json (or .agents/hooks.json):\n"
            + json.dumps(gemini_cfg, indent=2)
        )

    if agent in ("all", "codex", "grok", "copilot", "factory", "qwen"):
        std_cfg = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
                    }
                ]
            }
        }
        sections.append(
            "# 3. Codex (~/.codex/hooks.json), Grok (~/.grok/hooks/asa-env-guard.json),\n"
            "#    Copilot (~/.copilot/hooks/asa-env-guard.json), Factory (~/.factory/settings.json):\n"
            + json.dumps(std_cfg, indent=2)
        )

    if agent in ("all", "cursor"):
        cursor_cfg = {
            "version": 1,
            "hooks": {
                "beforeReadFile": [{"command": cmd}],
                "beforeShellExecution": [{"command": cmd}],
            },
        }
        sections.append(
            "# 4. Cursor — ~/.cursor/hooks.json:\n"
            + json.dumps(cursor_cfg, indent=2)
        )

    if agent in ("all", "hermes"):
        sections.append(
            "# 5. Hermes Agent — ~/.hermes/plugins/agent-lockdown (native pre_tool_call hook)\n"
            "#    or ~/.hermes/config.yaml shell hook:\n"
            "hooks:\n"
            "  pre_tool_call:\n"
            "    - command: %s" % cmd
        )

    if agent in ("all", "pi"):
        sections.append(
            "# 6. Pi Coding Agent — ~/.pi/agent/extensions/asa-env-guard.ts:\n"
            + PI_EXTENSION_TEMPLATE.strip()
        )

    if agent in ("all", "opencode"):
        sections.append(
            "# 7. OpenCode — ~/.config/opencode/plugins/asa-env-guard.js:\n"
            + OPENCODE_PLUGIN_TEMPLATE.strip()
        )

    return "\n\n".join(sections)


# ---------------------------------------------------------------- detection & installer

SUPPORTED_HOOK_AGENTS = (
    "claude", "gemini", "codex", "grok", "copilot",
    "cursor", "kiro", "hermes", "pi", "opencode",
    "factory", "qwen",
)


def _read_json_file(path: str) -> dict:
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
        if not raw:
            return {}
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _write_json_file(path: str, payload: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _write_text_file(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _has_asa_hook_in_groups(groups: Any) -> bool:
    if not isinstance(groups, list):
        return False
    for g in groups:
        if not isinstance(g, dict):
            continue
        cmd = str(g.get("command") or "")
        if RUN_HOOK_FLAG in cmd or HOOK_MARKER in cmd:
            return True
        for h in (g.get("hooks") or []):
            if isinstance(h, dict):
                hcmd = str(h.get("command") or "")
                if RUN_HOOK_FLAG in hcmd or HOOK_MARKER in hcmd:
                    return True
    return False


def _merge_pre_tool_use_group(
    cfg: dict,
    cmd: str,
    *,
    event_key: str = "PreToolUse",
    matcher: str | None = "*",
) -> dict:
    hooks_obj = cfg.get("hooks")
    if not isinstance(hooks_obj, dict):
        hooks_obj = {}
        cfg["hooks"] = hooks_obj
    groups = hooks_obj.get(event_key)
    if not isinstance(groups, list):
        groups = []
        hooks_obj[event_key] = groups

    for g in groups:
        if not isinstance(g, dict):
            continue
        for h in (g.get("hooks") or []):
            if isinstance(h, dict) and (RUN_HOOK_FLAG in str(h.get("command") or "") or HOOK_MARKER in str(h.get("command") or "")):
                h["command"] = cmd
                h["type"] = "command"
                h["timeout"] = 5
                if matcher is not None:
                    g["matcher"] = matcher
                return cfg

    entry: dict[str, Any] = {
        "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
    }
    if matcher is not None:
        entry["matcher"] = matcher
    groups.append(entry)
    return cfg


def _remove_asa_from_groups(groups: list) -> list:
    cleaned = []
    for g in groups:
        if not isinstance(g, dict):
            cleaned.append(g)
            continue
        cmd = str(g.get("command") or "")
        if RUN_HOOK_FLAG in cmd or HOOK_MARKER in cmd:
            continue
        inner = g.get("hooks")
        if isinstance(inner, list):
            kept_inner = [
                h for h in inner
                if not (isinstance(h, dict) and (RUN_HOOK_FLAG in str(h.get("command") or "") or HOOK_MARKER in str(h.get("command") or "")))
            ]
            if not kept_inner:
                continue
            g = dict(g)
            g["hooks"] = kept_inner
        cleaned.append(g)
    return cleaned


def detected_hook_agents(home: str) -> list[str]:
    """Return canonical names of hook-capable agents installed under home."""
    found = []
    checks = (
        ("claude", (".claude", ".claude.json")),
        ("gemini", (".gemini",)),
        ("codex", (".codex",)),
        ("grok", (".grok",)),
        ("copilot", (".copilot",)),
        ("cursor", (".cursor", ".cursor-server")),
        ("kiro", (".kiro",)),
        ("hermes", (".hermes",)),
        ("pi", (".pi",)),
        ("opencode", (".opencode", ".config/opencode")),
        ("factory", (".factory",)),
        ("qwen", (".qwen",)),
    )
    for name, rels in checks:
        if any(os.path.exists(os.path.join(home, r)) for r in rels):
            found.append(name)
    return found


def is_agent_env_protected(home: str, agent: str) -> bool:
    """True when the given installed agent has an active .env deny rule or pre-tool guard."""
    if agent == "claude":
        cfg = _read_json_file(os.path.join(home, ".claude", "settings.json"))
        deny = ((cfg.get("permissions") or {}).get("deny") or [])
        has_deny = any(".env" in str(x) for x in deny)
        has_hook = _has_asa_hook_in_groups((cfg.get("hooks") or {}).get("PreToolUse"))
        return has_deny and has_hook
    if agent == "gemini":
        hcfg = _read_json_file(os.path.join(home, ".gemini", "config", "hooks.json"))
        for val in hcfg.values():
            if isinstance(val, dict) and _has_asa_hook_in_groups(val.get("PreToolUse")):
                return True
        scfg = _read_json_file(os.path.join(home, ".gemini", "settings.json"))
        return _has_asa_hook_in_groups((scfg.get("hooks") or {}).get("PreToolUse"))
    if agent == "codex":
        cfg = _read_json_file(os.path.join(home, ".codex", "hooks.json"))
        return _has_asa_hook_in_groups((cfg.get("hooks") or {}).get("PreToolUse"))
    if agent == "grok":
        hdir = os.path.join(home, ".grok", "hooks")
        if os.path.isdir(hdir):
            for fn in os.listdir(hdir):
                if fn.endswith(".json"):
                    cfg = _read_json_file(os.path.join(hdir, fn))
                    if _has_asa_hook_in_groups((cfg.get("hooks") or {}).get("PreToolUse")):
                        return True
        return False
    if agent == "copilot":
        hdir = os.path.join(home, ".copilot", "hooks")
        if os.path.isdir(hdir):
            for fn in os.listdir(hdir):
                if fn.endswith(".json"):
                    cfg = _read_json_file(os.path.join(hdir, fn))
                    if _has_asa_hook_in_groups((cfg.get("hooks") or {}).get("PreToolUse")):
                        return True
        return False
    if agent == "cursor":
        cfg = _read_json_file(os.path.join(home, ".cursor", "hooks.json"))
        hooks_obj = cfg.get("hooks") or {}
        return _has_asa_hook_in_groups(hooks_obj.get("beforeReadFile"))
    if agent == "kiro":
        cfg = _read_json_file(os.path.join(home, ".kiro", "settings", "hooks.json"))
        hooks_obj = cfg.get("hooks") or {}
        return _has_asa_hook_in_groups(hooks_obj.get("preToolUse")) or _has_asa_hook_in_groups(hooks_obj.get("PreToolUse"))
    if agent == "hermes":
        for slug in ("agent-lockdown", "agent-security-audit"):
            p_init = os.path.join(home, ".hermes", "plugins", slug, "__init__.py")
            if os.path.isfile(p_init):
                try:
                    with open(p_init, "r", encoding="utf-8", errors="replace") as fh:
                        if "pre_tool_call" in fh.read():
                            return True
                except OSError:
                    pass
        cfg_yaml = os.path.join(home, ".hermes", "config.yaml")
        if os.path.isfile(cfg_yaml):
            try:
                with open(cfg_yaml, "r", encoding="utf-8", errors="replace") as fh:
                    txt = fh.read()
                if RUN_HOOK_FLAG in txt or HOOK_MARKER in txt:
                    return True
            except OSError:
                pass
        return False
    if agent == "pi":
        ext = os.path.join(home, ".pi", "agent", "extensions", "asa-env-guard.ts")
        return os.path.isfile(ext)
    if agent == "opencode":
        p1 = os.path.join(home, ".config", "opencode", "plugins", "asa-env-guard.js")
        p2 = os.path.join(home, ".opencode", "plugins", "asa-env-guard.js")
        return os.path.isfile(p1) or os.path.isfile(p2)
    if agent in ("factory", "qwen"):
        cfg = _read_json_file(os.path.join(home, "." + agent, "settings.json"))
        return _has_asa_hook_in_groups((cfg.get("hooks") or {}).get("PreToolUse"))
    return False


def agent_env_protection_status(home: str) -> tuple[list[str], list[str]]:
    """Return (protected_agents, unprotected_agents) among detected hook-capable agents."""
    protected, unprotected = [], []
    for agent in detected_hook_agents(home):
        if is_agent_env_protected(home, agent):
            protected.append(agent)
        else:
            unprotected.append(agent)
    return protected, unprotected


def _install_hermes_plugin(home: str, dry_run: bool = False) -> list[str]:
    """Install/update the Hermes agent-lockdown plugin with pre_tool_call .env guard."""
    modified = []
    plugin_dir = os.path.join(home, ".hermes", "plugins", "agent-lockdown")
    legacy_dir = os.path.join(home, ".hermes", "plugins", "agent-security-audit")
    init_path = os.path.join(plugin_dir, "__init__.py")
    yaml_path = os.path.join(plugin_dir, "plugin.yaml")

    repo_hermes = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "hermes"))
    src_init = os.path.join(repo_hermes, "__init__.py")
    src_yaml = os.path.join(repo_hermes, "plugin.yaml")

    if not dry_run:
        os.makedirs(plugin_dir, exist_ok=True)
        if os.path.isfile(src_init) and os.path.isfile(src_yaml):
            shutil.copyfile(src_init, init_path)
            shutil.copyfile(src_yaml, yaml_path)
        else:
            _write_text_file(init_path, _FALLBACK_HERMES_INIT)
            _write_text_file(yaml_path, _FALLBACK_HERMES_YAML)
        if os.path.isdir(legacy_dir):
            shutil.rmtree(legacy_dir, ignore_errors=True)
    modified.append(init_path)

    cfg_yaml = os.path.join(home, ".hermes", "config.yaml")
    if os.path.isfile(cfg_yaml):
        try:
            with open(cfg_yaml, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            new_content = content.replace("    - agent-security-audit\n", "    - agent-lockdown\n")
            if "    - agent-lockdown\n" not in new_content:
                m = re.search(r"(^plugins:\s*\n\s*enabled:\s*\n)", new_content, re.M)
                if m:
                    insert_pos = m.end()
                    new_content = (
                        new_content[:insert_pos]
                        + "    - agent-lockdown\n"
                        + new_content[insert_pos:]
                    )
            if new_content != content:
                if not dry_run:
                    with open(cfg_yaml, "w", encoding="utf-8") as fh:
                        fh.write(new_content)
                modified.append(cfg_yaml)
        except OSError:
            pass
    return modified


_FALLBACK_HERMES_YAML = """name: agent-lockdown
version: 0.4.0
description: Read-only security audit of the host and every AI coding agent installed on it, with pre_tool_call .env protection hook and permission-gated global hook installer.
author: Mike Huttunen
license: MIT
manifest_version: 2
requires_hermes: ">=0.21.5"
provides_tools:
  - agent_lockdown
provides_hooks:
  - pre_tool_call
tags: [security, audit, cve, agents, mcp, secrets, hooks]
"""

_FALLBACK_HERMES_INIT = '''"""Hermes plugin: expose agent-lockdown as a tool + native pre_tool_call .env guard.

Self-contained stdlib module so it loads cleanly inside Hermes's own Python environment
while invoking the installed `agent-lockdown` / `asa` binary for full audits.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

TOOL = "agent_lockdown"

VALID_LAYERS = frozenset({
    "host-python", "host-node", "docker-containers", "docker-images",
    "manifests", "ports", "os-packages", "ssh", "semgrep", "secrets",
    "venvs", "cve-now", "agent-config", "agent-history", "agent-rules",
    "supply-chain",
})

VALID_HOOK_MODES = frozenset({"deny", "ask"})

SAFE_ENV_SUFFIXES = (
    ".example", ".sample", ".template", ".dist",
    ".defaults", ".schema", ".md", ".txt", ".rst",
)
CODE_ENV_IDENTIFIERS = frozenset({
    "process.env", "meta.env", "import.meta.env", "deno.env",
    "bun.env", "cypress.env", "window.env", "global.env",
    "globalthis.env", "os.env", "sys.env", "ctx.env", "self.env",
})
_ENV_TOKEN_RE = re.compile(
    r"""(?:^|[\\s\'"`(=:<|,])((?:[A-Za-z0-9_./~*-]*/)?(?:\\.env(?:\\.[A-Za-z0-9_.*-]+|\\*)?|[A-Za-z0-9_.-]+\\.env))(?=$|[\\s\'"`);>|,&])""",
    re.I,
)
_SAFE_GIT_CMD_RE = re.compile(
    r"^\\s*(?:git\\s+(?:-[A-Za-z]\\s+\\S+\\s+)*(?:check-ignore|rm\\s+--cached|status|add\\s+\\.gitignore|commit|log)\\b|gh\\s+(?:repo|pr|issue|release)\\b|(?:asa|agent-lockdown|agent-security-audit)\\b)",
    re.I,
)

SCHEMA = {
    "name": TOOL,
    "description": (
        "Read-only security audit of the host and every AI coding agent installed "
        "(hooks, MCP servers, keys in agent history, prompt injection, supply chain). "
        "Returns JSON with findings and a summary. Never modifies anything during an audit. "
        "If unprotected agents are reported, ask the user for permission first, then call "
        "with install_env_hook=true and user_approved=true to install the global .env guard."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "root": {"type": "string", "description": "Project directory to scan. Defaults to the current directory."},
            "layer": {"type": "string", "enum": sorted(VALID_LAYERS), "description": "Run a single layer instead of all 16."},
            "agents_only": {"type": "boolean", "description": "Fast mode: run only the 4 AI-agent layers."},
            "quick": {"type": "boolean", "description": "Skip slow checks (venv audit, long git history)."},
            "offline": {"type": "boolean", "description": "Skip the cve.now network feed."},
            "redact_paths": {"type": "boolean", "description": "Replace $HOME with ~ and omit hostname in JSON output."},
            "install_env_hook": {"type": "boolean", "description": "Install the global .env protection hook across detected agents (MUST ask the user for permission first and set user_approved=true)."},
            "install_skill": {"type": "boolean", "description": "Install the agent-lockdown SKILL.md into every detected agent's global skills folder."},
            "user_approved": {"type": "boolean", "description": "Set to true ONLY after the user has explicitly granted permission to install global .env protection hooks."},
            "hook_agent": {"type": "string", "description": "Optional comma-separated agent names for install_env_hook (default: 'all')."},
            "hook_mode": {"type": "string", "enum": ["deny", "ask"], "description": "Hook behavior when a tool accesses .env: 'deny' or 'ask'."},
        },
        "additionalProperties": False,
    },
}


def _resolve_cli():
    for local_name in ("~/.local/bin/agent-lockdown", "~/.local/bin/asa"):
        home_local = os.path.expanduser(local_name)
        if os.path.isfile(home_local) and os.access(home_local, os.X_OK):
            return [home_local]
    for bin_name in ("agent-lockdown", "asa", "agent-security-audit"):
        found = shutil.which(bin_name)
        if found:
            return [found]
    return [sys.executable, "-m", "agent_lockdown"]


def _is_sensitive_env_path(raw_path: str, *, from_command: bool = False) -> bool:
    if not raw_path or not isinstance(raw_path, str):
        return False
    cleaned = raw_path.strip().strip("\'\\"`();,|&<>")
    if not cleaned:
        return False
    low_full = cleaned.replace("\\\\", "/").lower()
    if from_command and low_full in CODE_ENV_IDENTIFIERS:
        return False
    base = os.path.basename(low_full.rstrip("/"))
    if not base or any(base.endswith(ext) for ext in SAFE_ENV_SUFFIXES):
        return False
    if base in (".env", ".env*", "*.env", ".env.*") or base.startswith(".env."):
        return True
    if base.endswith(".env"):
        if from_command and "/" not in low_full and not base.startswith(
            ("secrets.", "secret.", "prod.", "production.", "local.", "dev.", "staging.", "credentials.", "auth.", "app.", "docker.")
        ):
            return False
        return True
    return False


def _check_hermes_tool_args(tool_name: str, args) -> str | None:
    if not isinstance(args, dict):
        return None
    for k in ("file_path", "path", "filePath", "Path", "target_file", "file", "glob", "pattern"):
        val = args.get(k)
        if isinstance(val, str) and _is_sensitive_env_path(val):
            return "%s (%s=%s)" % (tool_name or "tool", k, val)
    for k in ("command", "CommandLine", "cmd", "script", "code"):
        val = args.get(k)
        if isinstance(val, str):
            for seg in re.split(r"(?:&&|\\|\\||;|\\n)", val):
                seg_str = seg.strip()
                if not seg_str or _SAFE_GIT_CMD_RE.match(seg_str):
                    continue
                for m in _ENV_TOKEN_RE.finditer(seg_str):
                    tok = m.group(1)
                    if _is_sensitive_env_path(tok, from_command=True):
                        return "%s (%s references %s)" % (tool_name or "shell", k, tok)
    return None


def _on_pre_tool_call(tool_name: str = "", args=None, **_kwargs):
    if os.environ.get("ASA_ENV_GUARD_DISABLE", "").lower() in ("1", "true", "yes", "on"):
        return None
    hit = _check_hermes_tool_args(tool_name, args)
    if not hit:
        return None
    msg = (
        "agent-lockdown (asa-env-guard): blocked access to secret .env file via %s. "
        "Use .env.example for templates." % hit
    )
    if os.environ.get("ASA_ENV_GUARD_MODE", "").lower() == "ask":
        return {"action": "approve", "message": msg, "rule_key": "asa_env_guard"}
    return {"action": "block", "message": msg}


def _handler(args, **_kwargs):
    if args.get("install_skill"):
        cmd = _resolve_cli() + ["--install-skill"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"ok": False, "error": "skill install failed: %s" % exc})
        return json.dumps({"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": (proc.stdout or "").strip(), "stderr": (proc.stderr or "").strip()})

    if args.get("install_env_hook"):
        hook_mode = args.get("hook_mode") or "deny"
        if hook_mode not in VALID_HOOK_MODES:
            return json.dumps({"ok": False, "error": "invalid hook_mode %r; expected \'deny\' or \'ask\'" % hook_mode})
        hook_agent = args.get("hook_agent") or "all"
        if not args.get("user_approved"):
            cmd = _resolve_cli() + ["--install-env-hook", "--dry-run", "--hook-mode", hook_mode, "--hook-agent", hook_agent]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return json.dumps({
                "ok": False,
                "needs_user_permission": True,
                "error": "User permission is required before modifying global agent hook configs. Show the planned paths to the user, ask for confirmation, and call again with user_approved=true.",
                "planned_changes": (proc.stdout or "").strip(),
            })
        cmd = _resolve_cli() + ["--install-env-hook", "--yes", "--hook-mode", hook_mode, "--hook-agent", hook_agent]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"ok": False, "error": "hook install failed: %s" % exc})
        return json.dumps({"ok": proc.returncode == 0, "exit_code": proc.returncode, "output": (proc.stdout or "").strip(), "stderr": (proc.stderr or "").strip()})

    layer = args.get("layer") or ""
    if layer and layer not in VALID_LAYERS:
        return json.dumps({"ok": False, "error": "invalid layer %r; expected one of: %s" % (layer, ", ".join(sorted(VALID_LAYERS)))})

    root = os.path.abspath(os.path.expanduser(args.get("root") or os.getcwd()))
    cmd = _resolve_cli() + ["--root", root, "--format", "json"]
    if args.get("agents_only"):
        cmd.append("--agents-only")
    elif layer:
        cmd += ["--layer", layer]
    if args.get("quick"):
        cmd.append("--quick")
    if args.get("offline"):
        cmd.append("--offline")
    if args.get("redact_paths"):
        cmd.append("--redact-paths")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"ok": False, "error": "audit failed to start: %s" % exc})

    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:  # noqa: BLE001
        return json.dumps({"ok": False, "error": "audit produced no JSON", "stderr": (proc.stderr or "")[-800:]})

    payload["ok"] = "findings" in payload
    payload["exit_code"] = proc.returncode
    return json.dumps(payload)


def register(ctx):
    ctx.register_tool(name=TOOL, toolset="security", schema=SCHEMA, handler=_handler, description=SCHEMA["description"])
    if hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_tool_call", _on_pre_tool_call)
'''


def install_env_hooks(
    home: str,
    *,
    agents: tuple[str, ...] | list[str] = (),
    mode: str = "deny",
    dry_run: bool = False,
) -> list[tuple[str, str]]:
    """Install or merge the global .env protection hook into detected (or specified) agents.

    Returns a list of (agent_name, modified_path) pairs.
    """
    target_agents = list(agents) if agents else detected_hook_agents(home)
    cmd = resolve_hook_command(mode=mode, portable=False)
    results: list[tuple[str, str]] = []

    for agent in target_agents:
        if agent == "claude":
            path = os.path.join(home, ".claude", "settings.json")
            if not dry_run:
                cfg = _read_json_file(path)
                perms = cfg.get("permissions")
                if not isinstance(perms, dict):
                    perms = {}
                    cfg["permissions"] = perms
                deny = perms.get("deny")
                if not isinstance(deny, list):
                    deny = []
                    perms["deny"] = deny
                for rule in CLAUDE_DENY_RULES:
                    if rule not in deny:
                        deny.append(rule)
                _merge_pre_tool_use_group(
                    cfg, cmd,
                    event_key="PreToolUse",
                    matcher="Read|Edit|Write|MultiEdit|Bash|Grep",
                )
                _write_json_file(path, cfg)
            results.append(("claude", path))

        elif agent == "gemini":
            hpath = os.path.join(home, ".gemini", "config", "hooks.json")
            if not dry_run:
                hcfg = _read_json_file(hpath)
                hcfg[HOOK_MARKER] = {
                    "PreToolUse": [
                        {
                            "matcher": "read_file|view_file|run_command|grep_search|edit_file|write_file|replace_file_content|multi_replace_file_content",
                            "hooks": [{"type": "command", "command": cmd, "timeout": 5}],
                        }
                    ]
                }
                _write_json_file(hpath, hcfg)
            results.append(("gemini", hpath))

            spath = os.path.join(home, ".gemini", "settings.json")
            if os.path.isfile(spath):
                if not dry_run:
                    scfg = _read_json_file(spath)
                    perms = scfg.get("permissions")
                    if not isinstance(perms, dict):
                        perms = {}
                        scfg["permissions"] = perms
                    deny = perms.get("deny")
                    if not isinstance(deny, list):
                        deny = []
                        perms["deny"] = deny
                    for rule in CLAUDE_DENY_RULES:
                        if rule not in deny:
                            deny.append(rule)
                    _write_json_file(spath, scfg)
                results.append(("gemini", spath))

        elif agent == "codex":
            path = os.path.join(home, ".codex", "hooks.json")
            if not dry_run:
                cfg = _read_json_file(path)
                _merge_pre_tool_use_group(cfg, cmd, event_key="PreToolUse", matcher="*")
                _write_json_file(path, cfg)
            results.append(("codex", path))

        elif agent == "grok":
            path = os.path.join(home, ".grok", "hooks", "asa-env-guard.json")
            if not dry_run:
                cfg = _read_json_file(path)
                _merge_pre_tool_use_group(cfg, cmd, event_key="PreToolUse", matcher=None)
                _write_json_file(path, cfg)
            results.append(("grok", path))

        elif agent == "copilot":
            path = os.path.join(home, ".copilot", "hooks", "asa-env-guard.json")
            if not dry_run:
                cfg = _read_json_file(path)
                _merge_pre_tool_use_group(cfg, cmd, event_key="PreToolUse", matcher="*")
                _write_json_file(path, cfg)
            results.append(("copilot", path))

        elif agent == "cursor":
            path = os.path.join(home, ".cursor", "hooks.json")
            if not dry_run:
                cfg = _read_json_file(path)
                if "version" not in cfg:
                    cfg["version"] = 1
                hooks_obj = cfg.get("hooks")
                if not isinstance(hooks_obj, dict):
                    hooks_obj = {}
                    cfg["hooks"] = hooks_obj
                for ev in ("beforeReadFile", "beforeShellExecution"):
                    ev_list = hooks_obj.get(ev)
                    if not isinstance(ev_list, list):
                        ev_list = []
                        hooks_obj[ev] = ev_list
                    if not _has_asa_hook_in_groups(ev_list):
                        ev_list.append({"command": cmd})
                    else:
                        for item in ev_list:
                            if isinstance(item, dict) and (RUN_HOOK_FLAG in str(item.get("command") or "") or HOOK_MARKER in str(item.get("command") or "")):
                                item["command"] = cmd
                _write_json_file(path, cfg)
            results.append(("cursor", path))

        elif agent == "kiro":
            path = os.path.join(home, ".kiro", "settings", "hooks.json")
            if not dry_run:
                cfg = _read_json_file(path)
                _merge_pre_tool_use_group(cfg, cmd, event_key="preToolUse", matcher="*")
                _write_json_file(path, cfg)
            results.append(("kiro", path))

        elif agent == "hermes":
            for mod_path in _install_hermes_plugin(home, dry_run=dry_run):
                results.append(("hermes", mod_path))

        elif agent == "pi":
            path = os.path.join(home, ".pi", "agent", "extensions", "asa-env-guard.ts")
            if not dry_run:
                _write_text_file(path, PI_EXTENSION_TEMPLATE)
            results.append(("pi", path))

        elif agent == "opencode":
            targets = []
            if os.path.isdir(os.path.join(home, ".config", "opencode")) or not os.path.isdir(os.path.join(home, ".opencode")):
                targets.append(os.path.join(home, ".config", "opencode", "plugins", "asa-env-guard.js"))
            if os.path.isdir(os.path.join(home, ".opencode")):
                targets.append(os.path.join(home, ".opencode", "plugins", "asa-env-guard.js"))
            for path in targets:
                if not dry_run:
                    _write_text_file(path, OPENCODE_PLUGIN_TEMPLATE)
                results.append(("opencode", path))

        elif agent in ("factory", "qwen"):
            path = os.path.join(home, "." + agent, "settings.json")
            if not dry_run:
                cfg = _read_json_file(path)
                _merge_pre_tool_use_group(cfg, cmd, event_key="PreToolUse", matcher="*")
                _write_json_file(path, cfg)
            results.append((agent, path))

    return results


def uninstall_env_hooks(
    home: str,
    *,
    agents: tuple[str, ...] | list[str] = (),
    dry_run: bool = False,
) -> list[tuple[str, str]]:
    """Cleanly remove the agent-lockdown .env hook from detected (or specified) agents."""
    target_agents = list(agents) if agents else detected_hook_agents(home)
    removed: list[tuple[str, str]] = []

    for agent in target_agents:
        if agent == "claude":
            path = os.path.join(home, ".claude", "settings.json")
            if os.path.isfile(path):
                cfg = _read_json_file(path)
                hooks_obj = cfg.get("hooks")
                if isinstance(hooks_obj, dict) and isinstance(hooks_obj.get("PreToolUse"), list):
                    hooks_obj["PreToolUse"] = _remove_asa_from_groups(hooks_obj["PreToolUse"])
                    if not hooks_obj["PreToolUse"]:
                        hooks_obj.pop("PreToolUse", None)
                if not dry_run:
                    _write_json_file(path, cfg)
                removed.append(("claude", path))
        elif agent == "gemini":
            hpath = os.path.join(home, ".gemini", "config", "hooks.json")
            if os.path.isfile(hpath):
                hcfg = _read_json_file(hpath)
                if HOOK_MARKER in hcfg:
                    hcfg.pop(HOOK_MARKER, None)
                    if not dry_run:
                        _write_json_file(hpath, hcfg)
                    removed.append(("gemini", hpath))
        elif agent in ("codex", "kiro", "factory", "qwen"):
            rel = {
                "codex": (".codex", "hooks.json"),
                "kiro": (".kiro", "settings", "hooks.json"),
                "factory": (".factory", "settings.json"),
                "qwen": (".qwen", "settings.json"),
            }[agent]
            path = os.path.join(home, *rel)
            if os.path.isfile(path):
                cfg = _read_json_file(path)
                hooks_obj = cfg.get("hooks")
                if isinstance(hooks_obj, dict):
                    for ev in ("PreToolUse", "preToolUse"):
                        if isinstance(hooks_obj.get(ev), list):
                            hooks_obj[ev] = _remove_asa_from_groups(hooks_obj[ev])
                if not dry_run:
                    _write_json_file(path, cfg)
                removed.append((agent, path))
        elif agent in ("grok", "copilot"):
            path = os.path.join(home, "." + agent, "hooks", "asa-env-guard.json")
            if os.path.isfile(path):
                if not dry_run:
                    os.remove(path)
                removed.append((agent, path))
        elif agent == "cursor":
            path = os.path.join(home, ".cursor", "hooks.json")
            if os.path.isfile(path):
                cfg = _read_json_file(path)
                hooks_obj = cfg.get("hooks")
                if isinstance(hooks_obj, dict):
                    for ev in ("beforeReadFile", "beforeShellExecution"):
                        if isinstance(hooks_obj.get(ev), list):
                            hooks_obj[ev] = _remove_asa_from_groups(hooks_obj[ev])
                if not dry_run:
                    _write_json_file(path, cfg)
                removed.append(("cursor", path))
        elif agent == "pi":
            path = os.path.join(home, ".pi", "agent", "extensions", "asa-env-guard.ts")
            if os.path.isfile(path):
                if not dry_run:
                    os.remove(path)
                removed.append(("pi", path))
        elif agent == "opencode":
            for rel in ((".config", "opencode", "plugins", "asa-env-guard.js"), (".opencode", "plugins", "asa-env-guard.js")):
                path = os.path.join(home, *rel)
                if os.path.isfile(path):
                    if not dry_run:
                        os.remove(path)
                    removed.append(("opencode", path))
    return removed


SKILL_MARKDOWN_CONTENT = """---
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

## 3. How to Lock Down `.env` Files Globally (Permission-Gated)

1. Preview affected agents (read-only): `agent-lockdown --install-env-hook --dry-run`
2. Ask the user for permission (offering `deny` to block automatically or `ask` to prompt every time).
3. Only after user confirmation: `agent-lockdown --install-env-hook --yes` (or `--hook-mode ask --yes`).
4. Verify: `agent-lockdown --layer agent-config --show-ok`

## 4. How to Remove the Global `.env` Lock (If Requested)

Ask for confirmation, then run: `agent-lockdown --uninstall-env-hook --yes`
"""


def install_agent_skills(home: str, *, dry_run: bool = False) -> list[tuple[str, str]]:
    """Install the agent-lockdown SKILL.md into ~/.agents/skills and every detected agent's skills directory."""
    skill_roots = [
        ("agents", (".agents", "skills")),
        ("claude", (".claude", "skills")),
        ("gemini", (".gemini", "skills")),
        ("codex", (".codex", "skills")),
        ("hermes", (".hermes", "skills")),
        ("copilot", (".copilot", "skills")),
        ("grok", (".grok", "skills")),
        ("pi", (".pi", "agent", "skills")),
        ("opencode", (".config", "opencode", "skills")),
        ("kiro", (".kiro", "skills")),
    ]
    repo_skill = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "skills", "agent-lockdown", "SKILL.md"))
    content = SKILL_MARKDOWN_CONTENT
    if os.path.isfile(repo_skill):
        try:
            with open(repo_skill, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            pass

    installed: list[tuple[str, str]] = []
    for agent_name, rel_parts in skill_roots:
        parent_root = os.path.join(home, rel_parts[0])
        if agent_name != "agents" and not os.path.exists(parent_root):
            continue
        target = os.path.join(home, *rel_parts, "agent-lockdown", "SKILL.md")
        if not dry_run:
            _write_text_file(target, content)
        installed.append((agent_name, target))
    return installed
