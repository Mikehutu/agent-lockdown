"""Command line interface for agent-lockdown (also callable as `asa`)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import socket
import sys
import time
from dataclasses import dataclass, field

from . import core, data, hooks as hook_mod

__version__ = "0.6.0"

COLORS = {
    "vuln": "\033[0;31m",
    "warn": "\033[1;33m",
    "info": "\033[0;36m",
    "ok": "\033[0;32m",
}
RESET = "\033[0m"
SYMBOLS = {"vuln": "✗", "warn": "!", "info": "ℹ", "ok": "✓"}


@dataclass
class Context:
    root: str
    home: str
    layer: str = ""
    layers: tuple = field(default_factory=tuple)
    quick: bool = False
    offline: bool = False


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-lockdown",
        description="Read-only security audit and 1-click global .env secret lock for a host and its AI coding agents.",
        epilog="Exit codes: 0 clean, 1 findings at or above --fail-on, 2 usage/permission error.",
    )
    p.add_argument("--root", default=os.getcwd(),
                   help="project directory to scan (default: current directory)")
    p.add_argument("--home", default=os.path.expanduser("~"),
                   help="base directory holding agent tool dirs (default: $HOME)")
    p.add_argument("--layer", default="", choices=[""] + list(core.LAYER_NAMES),
                   help="run a single layer")
    p.add_argument("--layers", default="",
                   help="comma-separated list of layers to run (e.g. agent-config,agent-history)")
    p.add_argument("--agents-only", action="store_true",
                   help="run only the 4 AI-agent layers (agent-config, agent-history, agent-rules, supply-chain)")
    p.add_argument("--list-layers", action="store_true",
                   help="list all available audit layers and exit")
    p.add_argument("--print-env-hook", action="store_true",
                   help="print copy-paste global .env protection hook snippets for your agents, then exit")
    p.add_argument("--run-env-hook", action="store_true",
                   help="internal PreToolUse hook handler: read tool call JSON from stdin and block/ask on .env access")
    p.add_argument("--install-env-hook", action="store_true",
                   help="install or merge the global .env protection hook into detected agents under --home (asks permission unless --yes)")
    p.add_argument("--uninstall-env-hook", action="store_true",
                   help="remove the global .env protection hook from detected agents under --home (asks permission unless --yes)")
    p.add_argument("--install-skill", action="store_true",
                   help="install the agent-lockdown SKILL.md into ~/.agents/skills and every detected agent's global skills folder")
    p.add_argument("--hook-agent", default="all",
                   help="comma-separated agent(s) for --print-env-hook / --install-env-hook (default: all detected; choices: all,%s)"
                        % ",".join(hook_mod.SUPPORTED_HOOK_AGENTS))
    p.add_argument("--hook-mode", default="deny", choices=["deny", "ask"],
                   help="hook action when a tool tries to access .env: 'deny' (hard block) or 'ask' (prompt user)")
    p.add_argument("--yes", "-y", action="store_true",
                   help="confirm installing/uninstalling hooks (use after obtaining user permission)")
    p.add_argument("--dry-run", action="store_true",
                   help="preview which agent configs/skills would be updated without writing files")
    p.add_argument("--quick", action="store_true",
                   help="skip slow checks (venv audit, long git history)")
    p.add_argument("--offline", action="store_true",
                   help="skip the cve.now network feed")
    p.add_argument("--format", default="text", choices=["text", "json", "sarif"],
                   help="output format (default: text)")
    p.add_argument("--fail-on", default="vuln", choices=["vuln", "warn", "never"],
                   help="exit non-zero at this severity (default: vuln)")
    p.add_argument("--redact-paths", action="store_true",
                   help="replace $HOME with ~ and omit hostname for safe sharing")
    p.add_argument("--show-ok", action="store_true", help="print passing checks too")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    p.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return p


def _redact(text: str, home: str, enabled: bool) -> str:
    if not enabled or not text or not home:
        return text
    return text.replace(home, "~")


def render_text(rep: core.Report, args, color: bool, home: str = "") -> str:
    redact = getattr(args, "redact_paths", False)
    out = []
    layers = []
    for f in rep.findings:
        if f.layer not in layers:
            layers.append(f.layer)
    for layer in layers:
        out.append("\n=== %s ===" % layer)
        for f in rep.findings:
            if f.layer != layer:
                continue
            if f.severity == "ok" and not args.show_ok:
                continue
            sym = SYMBOLS[f.severity]
            title = _redact(f.title, home, redact)
            path = _redact(f.path, home, redact)
            detail = _redact(f.detail, home, redact)
            line = "  %s %s" % (sym, title)
            if path:
                line += "  [%s]" % path
            if color:
                line = "  %s%s%s %s" % (COLORS[f.severity], sym, RESET, title)
                if path:
                    line += "  [%s]" % path
            out.append(line)
            if detail:
                out.append("      %s" % detail[:300])
            if f.remediation and f.severity in ("vuln", "warn"):
                out.append("      fix: %s" % f.remediation[:200])

    vulns, warns, infos = rep.count("vuln"), rep.count("warn"), rep.count("info")
    out.append("\n=== Summary ===")
    out.append("  layers run: %d" % rep.layers_run)
    out.append("  vulnerabilities: %d" % vulns)
    out.append("  warnings: %d" % warns)
    out.append("  info: %d" % infos)
    for s in rep.skipped:
        out.append("  skipped: %s" % _redact(s, home, redact))
    if vulns:
        out.append("\n  Action required: %d finding(s) need review." % vulns)
    elif warns:
        out.append("\n  No vulnerabilities; %d warning(s) to review." % warns)
    else:
        out.append("\n  Clean.")
    return "\n".join(out)


def render_json(rep: core.Report, args, home: str = "") -> str:
    redact = getattr(args, "redact_paths", False)
    findings = []
    for f in rep.findings:
        d = f.as_dict()
        if redact:
            d["title"] = _redact(d["title"], home, True)
            d["detail"] = _redact(d["detail"], home, True)
            d["path"] = _redact(d["path"], home, True)
        findings.append(d)
    payload = {
        "schema_version": 1,
        "tool": "agent-lockdown",
        "version": __version__,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": {
            "hostname": "<redacted>" if redact else socket.gethostname(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "root": _redact(os.path.abspath(args.root), home, redact),
        "home": "~" if redact else os.path.abspath(args.home),
        "summary": {
            "layers_run": rep.layers_run,
            "vulnerabilities": rep.count("vuln"),
            "warnings": rep.count("warn"),
            "info": rep.count("info"),
        },
        "findings": findings,
        "skipped": [_redact(s, home, redact) for s in rep.skipped],
    }
    return json.dumps(payload, indent=2)


def render_sarif(rep: core.Report, args, home: str = "") -> str:
    """Emit SARIF 2.1.0 JSON for GitHub Code Scanning / CI integration."""
    redact = getattr(args, "redact_paths", False)
    level_map = {"vuln": "error", "warn": "warning", "info": "note"}
    rules_seen = {}
    results = []
    for f in rep.findings:
        if f.severity == "ok":
            continue
        rule_id = "ASA/%s" % f.layer
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.layer,
                "shortDescription": {"text": "agent-lockdown layer: %s" % f.layer},
            }
        msg = _redact(f.title, home, redact)
        if f.detail:
            msg += " — " + _redact(f.detail, home, redact)
        if f.remediation:
            msg += " (fix: %s)" % f.remediation
        item = {
            "ruleId": rule_id,
            "level": level_map.get(f.severity, "note"),
            "message": {"text": msg},
        }
        if f.path:
            uri = _redact(f.path, home, redact)
            item["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                }
            }]
        results.append(item)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "agent-lockdown",
                    "version": __version__,
                    "informationUri": "https://github.com/Mikehutu/agent-lockdown",
                    "rules": list(rules_seen.values()),
                }
            },
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _resolve_target_agents(args, home: str):
    if args.hook_agent and args.hook_agent != "all":
        req = [a.strip().lower() for a in args.hook_agent.split(",") if a.strip()]
        bad = [a for a in req if a not in hook_mod.SUPPORTED_HOOK_AGENTS]
        if bad:
            print("error: unsupported --hook-agent %s (supported: %s)"
                  % (", ".join(bad), ", ".join(hook_mod.SUPPORTED_HOOK_AGENTS)), file=sys.stderr)
            return None
        return req
    return hook_mod.detected_hook_agents(home)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_layers:
        for name, desc in data.LAYER_DESCRIPTIONS:
            tag = " [agent]" if name in data.AGENT_LAYERS else ""
            print("%-18s %s%s" % (name, desc, tag))
        return 0

    if args.run_env_hook:
        stdin_text = sys.stdin.read() if not sys.stdin.isatty() else ""
        rc, out, err = hook_mod.run_env_hook(stdin_text, mode=args.hook_mode)
        if out:
            print(out)
        if err:
            print(err, file=sys.stderr)
        return rc

    if args.print_env_hook:
        print(hook_mod.format_env_hook_snippets(agent=args.hook_agent, mode=args.hook_mode))
        return 0

    if args.install_skill:
        home = os.path.abspath(os.path.expanduser(args.home))
        installed = hook_mod.install_agent_skills(home, dry_run=args.dry_run)
        prefix = "Dry run — would install" if args.dry_run else "Installed"
        print("%s agent-lockdown SKILL.md into %d skill folder(s):" % (prefix, len(installed)))
        for agent_name, spath in installed:
            print("  ✓ [%s] %s" % (agent_name, spath))
        return 0

    if args.uninstall_env_hook:
        home = os.path.abspath(os.path.expanduser(args.home))
        targets = _resolve_target_agents(args, home)
        if targets is None:
            return 2
        planned = hook_mod.uninstall_env_hooks(home, agents=targets, dry_run=True)
        if args.dry_run:
            print("Dry run — global .env protection hook would be removed from %d file(s):" % len(planned))
            for agent_name, cfg_path in planned:
                print("  [%s] %s" % (agent_name, cfg_path))
            return 0
        if not args.yes:
            if not sys.stdin.isatty():
                print("Permission required: ask the user first, then re-run with `--uninstall-env-hook --yes`.", file=sys.stderr)
                return 2
            try:
                ans = input("Remove global .env protection hook from %d file(s)? [y/N]: " % len(planned)).strip().lower()
            except EOFError:
                ans = ""
            if ans not in ("y", "yes"):
                print("Aborted — no files were modified.")
                return 1
        removed = hook_mod.uninstall_env_hooks(home, agents=targets, dry_run=False)
        print("Removed global .env protection hook from %d file(s):" % len(removed))
        for agent_name, cfg_path in removed:
            print("  ✓ [%s] %s" % (agent_name, cfg_path))
        return 0

    if args.install_env_hook:
        home = os.path.abspath(os.path.expanduser(args.home))
        targets = _resolve_target_agents(args, home)
        if targets is None:
            return 2
        if not targets:
            print("No supported hook-capable agents detected under %s." % home)
            return 0
        planned = hook_mod.install_env_hooks(home, agents=targets, mode=args.hook_mode, dry_run=True)
        if args.dry_run:
            print("Dry run — global .env protection hook (%s mode) would be installed into:" % args.hook_mode)
            for agent_name, cfg_path in planned:
                print("  [%s] %s" % (agent_name, cfg_path))
            return 0
        if not args.yes:
            print("Planned global .env protection hook (%s mode) updates:" % args.hook_mode)
            for agent_name, cfg_path in planned:
                print("  [%s] %s" % (agent_name, cfg_path))
            if not sys.stdin.isatty():
                print(
                    "\nPermission required: ask the user for confirmation before modifying global agent configs, "
                    "then re-run with `--install-env-hook --yes`.",
                    file=sys.stderr,
                )
                return 2
            try:
                ans = input("\nInstall global .env protection hook into these %d file(s)? [y/N]: " % len(planned)).strip().lower()
            except EOFError:
                ans = ""
            if ans not in ("y", "yes"):
                print("Aborted — no files were modified.")
                return 1
        applied = hook_mod.install_env_hooks(home, agents=targets, mode=args.hook_mode, dry_run=False)
        print("Installed global .env protection hook (%s mode) into %d file(s):" % (args.hook_mode, len(applied)))
        for agent_name, cfg_path in applied:
            print("  ✓ [%s] %s" % (agent_name, cfg_path))
        return 0

    selected_layers = ()
    if args.agents_only:
        selected_layers = data.AGENT_LAYERS
    elif args.layers:
        raw = [s.strip() for s in args.layers.split(",") if s.strip()]
        bad = [s for s in raw if s not in core.LAYER_NAMES]
        if bad:
            print("error: unknown layer(s): %s (run --list-layers)" % ", ".join(bad), file=sys.stderr)
            return 2
        selected_layers = tuple(raw)

    root = os.path.abspath(os.path.expanduser(args.root))
    home = os.path.abspath(os.path.expanduser(args.home))
    if not os.path.isdir(root):
        print("error: --root %s is not a directory" % root, file=sys.stderr)
        return 2

    ctx = Context(root=root, home=home, layer=args.layer, layers=selected_layers,
                  quick=args.quick, offline=args.offline)

    rep = core.audit(ctx)

    color = (not args.no_color) and sys.stdout.isatty() and args.format == "text"
    if args.format == "json":
        print(render_json(rep, args, home=home))
    elif args.format == "sarif":
        print(render_sarif(rep, args, home=home))
    else:
        print(render_text(rep, args, color, home=home))

    vulns, warns = rep.count("vuln"), rep.count("warn")
    if args.fail_on == "never":
        return 0
    if args.fail_on == "warn" and warns:
        return 1
    return 1 if vulns else 0


if __name__ == "__main__":
    raise SystemExit(main())
