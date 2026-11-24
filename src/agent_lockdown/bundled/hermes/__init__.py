"""Hermes plugin: expose agent-lockdown as a tool + native pre_tool_call .env guard.

The audit itself is 100% read-only. Installing the global .env protection hook into
other agents on the machine is opt-in and requires explicit user permission
(`install_env_hook=True` and `user_approved=True`).
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
    r"""(?:^|[\s'"`(=:<|,])((?:[A-Za-z0-9_./~*-]*/)?(?:\.env(?:\.[A-Za-z0-9_.*-]+|\*)?|[A-Za-z0-9_.-]+\.env))(?=$|[\s'"`);>|,&])""",
    re.I,
)
_SAFE_GIT_CMD_RE = re.compile(
    r"^\s*(?:git\s+(?:-[A-Za-z]\s+\S+\s+)*(?:check-ignore|rm\s+--cached|status|add\s+\.gitignore|commit|log)\b|gh\s+(?:repo|pr|issue|release)\b|(?:asa|agent-lockdown|agent-security-audit)\b)",
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
            "root": {
                "type": "string",
                "description": "Project directory to scan. Defaults to the current directory.",
            },
            "layer": {
                "type": "string",
                "enum": sorted(VALID_LAYERS),
                "description": "Run a single layer instead of all 16.",
            },
            "agents_only": {
                "type": "boolean",
                "description": "Fast mode: run only the 4 AI-agent layers (agent-config, agent-history, agent-rules, supply-chain).",
            },
            "quick": {
                "type": "boolean",
                "description": "Skip slow checks (venv audit, long git history).",
            },
            "offline": {
                "type": "boolean",
                "description": "Skip the cve.now network feed.",
            },
            "redact_paths": {
                "type": "boolean",
                "description": "Replace $HOME with ~ and omit hostname in JSON output.",
            },
            "install_env_hook": {
                "type": "boolean",
                "description": "Install the global .env protection hook across detected agents (MUST ask the user for permission first and set user_approved=true).",
            },
            "install_skill": {
                "type": "boolean",
                "description": "Install the agent-lockdown SKILL.md into every detected agent's global skills folder.",
            },
            "user_approved": {
                "type": "boolean",
                "description": "Set to true ONLY after the user has explicitly granted permission to install global .env protection hooks.",
            },
            "hook_agent": {
                "type": "string",
                "description": "Optional comma-separated agent names for install_env_hook (default: 'all').",
            },
            "hook_mode": {
                "type": "string",
                "enum": ["deny", "ask"],
                "description": "Hook behavior when a tool accesses .env: 'deny' (hard block, default) or 'ask' (prompt user).",
            },
        },
        "additionalProperties": False,
    },
}


def _resolve_cli():
    """Prefer installed CLI binary (works with uv tool / pipx), fall back to python -m."""
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
    cleaned = raw_path.strip().strip("'\"`();,|&<>")
    if not cleaned:
        return False
    low_full = cleaned.replace("\\", "/").lower()
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
            for seg in re.split(r"(?:&&|\|\||;|\n)", val):
                seg_str = seg.strip()
                if not seg_str or _SAFE_GIT_CMD_RE.match(seg_str):
                    continue
                for m in _ENV_TOKEN_RE.finditer(seg_str):
                    tok = m.group(1)
                    if _is_sensitive_env_path(tok, from_command=True):
                        return "%s (%s references %s)" % (tool_name or "shell", k, tok)
    return None


def _on_pre_tool_call(tool_name: str = "", args=None, **_kwargs):
    """Native Hermes pre_tool_call hook guarding sensitive .env files."""
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
        return json.dumps({
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        })

    if args.get("install_env_hook"):
        hook_mode = args.get("hook_mode") or "deny"
        if hook_mode not in VALID_HOOK_MODES:
            return json.dumps({"ok": False, "error": "invalid hook_mode %r; expected 'deny' or 'ask'" % hook_mode})
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
        return json.dumps({
            "ok": proc.returncode == 0,
            "exit_code": proc.returncode,
            "output": (proc.stdout or "").strip(),
            "stderr": (proc.stderr or "").strip(),
        })

    layer = args.get("layer") or ""
    if layer and layer not in VALID_LAYERS:
        return json.dumps({
            "ok": False,
            "error": "invalid layer %r; expected one of: %s" % (layer, ", ".join(sorted(VALID_LAYERS))),
        })

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
    except Exception as exc:  # noqa: BLE001 - a tool must return, not crash
        return json.dumps({"ok": False, "error": "audit failed to start: %s" % exc})

    try:
        payload = json.loads(proc.stdout or "{}")
    except Exception:  # noqa: BLE001
        return json.dumps({
            "ok": False,
            "error": "audit produced no JSON",
            "stderr": (proc.stderr or "")[-800:],
        })

    payload["ok"] = "findings" in payload
    payload["exit_code"] = proc.returncode
    return json.dumps(payload)


def register(ctx):
    ctx.register_tool(
        name=TOOL,
        toolset="security",
        schema=SCHEMA,
        handler=_handler,
        description=SCHEMA["description"],
    )
    if hasattr(ctx, "register_hook"):
        ctx.register_hook("pre_tool_call", _on_pre_tool_call)
