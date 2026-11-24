"""Read-only security audit of a host and the AI agents running on it.

Design rules:
  * Read-only. Nothing is deleted, installed, upgraded or rewritten.
  * Never print secret values. Matches are reported as a 6-char prefix plus length.
  * Fail loud. A tool that cannot run is reported as UNKNOWN, never as "clean".
  * Stdlib only. Runs on any Linux with python3.8+, no third-party packages.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import data, hooks as hook_mod

MAX_READ = 2 * 1024 * 1024  # per-file read cap for text scans
MAX_HISTORY_FILE = 50 * 1024 * 1024


@dataclass
class Finding:
    layer: str
    severity: str  # vuln | warn | info | ok
    title: str
    detail: str = ""
    remediation: str = ""
    path: str = ""

    def as_dict(self) -> dict:
        return {
            "layer": self.layer,
            "severity": self.severity,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "path": self.path,
        }


@dataclass
class Report:
    findings: list = field(default_factory=list)
    layers_run: int = 0
    skipped: list = field(default_factory=list)

    def add(self, layer: str, severity: str, title: str, **kw) -> None:
        self.findings.append(Finding(layer, severity, title, **kw))

    def count(self, severity: str) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def has_vulns(self) -> bool:
        return self.count("vuln") > 0


# ---------------------------------------------------------------- helpers


def run(cmd, timeout=30, env=None):
    """Run a command without a shell. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env=env, errors="replace",
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except FileNotFoundError:
        return 127, "", "not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001 - a probe must never crash the audit
        return 1, "", str(exc)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def vtuple(v: str):
    parts = re.findall(r"\d+", v.split("+")[0].split("-")[0])
    return tuple(int(p) for p in parts[:6]) or (0,)


def vlt(a: str, b: str) -> bool:
    """True when version a < b. Falls back to numeric segments, never raises."""
    try:
        ta, tb = vtuple(a), vtuple(b)
        n = max(len(ta), len(tb))
        ta += (0,) * (n - len(ta))
        tb += (0,) * (n - len(tb))
        return ta < tb
    except Exception:  # noqa: BLE001
        return False


def read_text(path, limit=MAX_READ):
    try:
        if os.path.getsize(path) > limit:
            return ""
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def walk(root, max_depth=4, names=None):
    """Yield files under root, bounded depth, skipping known-noise dirs."""
    root = str(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        depth = dirpath.count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in data.SKIP_DIRS]
        for fn in filenames:
            if names is None:
                yield os.path.join(dirpath, fn)
                continue
            for pat in names:
                if fn == pat or fn.endswith(pat.lstrip("*")) and pat.startswith("*"):
                    yield os.path.join(dirpath, fn)
                    break


def git_repos(root, max_depth=4):
    """Yield directories that contain a .git entry (repos to inspect)."""
    root = str(root)
    base_depth = root.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, _ in os.walk(root, onerror=lambda e: None):
        depth = dirpath.count(os.sep) - base_depth
        if depth >= max_depth:
            dirnames[:] = []
        if ".git" in dirnames:
            yield dirpath
        dirnames[:] = [d for d in dirnames if d not in data.SKIP_DIRS]


def mask(value: str) -> str:
    """Never return a usable credential: short prefix + total length."""
    n = len(value)
    if n <= 12:
        keep = min(2, n)
    elif n <= 20:
        keep = 4
    else:
        keep = 6
    return "%s…(%d chars)" % (value[:keep], n)


_CMD_FLAG_SECRET_RE = re.compile(
    r"((?:--?(?:api[-_]?key|token|secret|password|passwd|auth[-_]?token|access[-_]?token|bearer|key))\s*(?:=|\s+))([^\s\"']+)",
    re.I,
)
_BEARER_RE = re.compile(r"(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})", re.I)
_URL_CRED_RE = re.compile(r"(https?://[^/\s:@]+:)([^/\s@]+)(@)", re.I)


def sanitize_command(cmd: str) -> str:
    """Mask any inline API keys, tokens, or URL passwords before logging a command."""
    if not cmd:
        return ""
    out = _CMD_FLAG_SECRET_RE.sub(lambda m: m.group(1) + mask(m.group(2)), cmd)
    out = _BEARER_RE.sub(lambda m: m.group(1) + mask(m.group(2)), out)
    out = _URL_CRED_RE.sub(lambda m: m.group(1) + mask(m.group(2)) + m.group(3), out)
    out = re.sub(KEY_PATTERN, lambda m: mask(m.group(0)), out)
    return out


def _should_run(ctx, layer: str) -> bool:
    layers = getattr(ctx, "layers", None)
    if layers:
        return layer in layers
    single = getattr(ctx, "layer", "")
    if single:
        return single == layer
    return True


def is_dummy(value: str) -> bool:
    if value in data.DUMMY_VALUES:
        return True
    low = value.lower()
    if any(low.startswith(p.lower()) for p in data.DUMMY_PREFIXES):
        return True
    if any(s in value for s in data.DUMMY_SUBSTRINGS):
        return True
    if "1234567890" in value:
        return True
    if re.search(r"(.)\1{6,}", value):
        return True
    return False


# ---------------------------------------------------------------- layers


def layer_host_python(rep: Report, ctx) -> None:
    layer = "host-python"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    try:
        import importlib.metadata as md
    except ImportError:
        rep.add(layer, "warn", "importlib.metadata unavailable", detail="python < 3.8?")
        return

    checked = 0
    for pkg, (min_v, cve, desc) in data.CVE_DB_PY.items():
        try:
            ver = md.version(pkg)
        except Exception:  # noqa: BLE001 - package not installed
            continue
        checked += 1
        if vlt(ver, min_v):
            rep.add(layer, "vuln", "%s %s — %s" % (pkg, ver, cve),
                    detail=desc, remediation="pip install %s==%s" % (pkg, min_v))
        else:
            rep.add(layer, "ok", "%s %s — patched (>=%s)" % (pkg, ver, min_v))
    if checked == 0:
        rep.add(layer, "info", "no CVE-tracked Python packages installed")


def layer_host_node(rep: Report, ctx) -> None:
    layer = "host-node"
    if not _should_run(ctx, layer):
        return
    if not have("npm"):
        rep.skipped.append("host-node: npm not found")
        return
    rep.layers_run += 1
    rc, out, _ = run(["npm", "list", "-g", "--depth=0", "--json"], timeout=60)
    try:
        deps = json.loads(out or "{}").get("dependencies") or {}
    except Exception:  # noqa: BLE001
        rep.add(layer, "warn", "npm global list unreadable", detail="state UNKNOWN")
        return
    for pkg, (min_v, cve, desc) in data.CVE_DB_NPM.items():
        ver = (deps.get(pkg) or {}).get("version")
        if not ver:
            continue
        if vlt(ver, min_v):
            rep.add(layer, "vuln", "%s %s (global) — %s" % (pkg, ver, cve),
                    detail=desc, remediation="npm install -g %s@%s" % (pkg, min_v))
        else:
            rep.add(layer, "ok", "%s %s (global) — patched" % (pkg, ver))


def layer_docker_containers(rep: Report, ctx) -> None:
    layer = "docker-containers"
    if not _should_run(ctx, layer):
        return
    if not have("docker"):
        rep.skipped.append("docker-containers: docker not found")
        return
    rep.layers_run += 1

    rc, out, _ = run(["docker", "info", "--format", "{{.Name}}|{{.DockerRootDir}}"])
    if rc != 0:
        rep.add(layer, "warn", "docker CLI cannot reach a daemon", detail="state UNKNOWN")
        return
    daemon, root = (out.strip().split("|") + ["?"])[:2]
    rep.add(layer, "info", "docker daemon: %s (root %s)" % (daemon, root))

    # A second dockerd (e.g. snap) is invisible to the CLI.
    if have("systemctl"):
        rc2, st, _ = run(["systemctl", "is-active", "snap.docker.dockerd"])
        if rc2 == 0 and st.strip() == "active" and "/var/snap/docker" not in root:
            rep.add(layer, "warn",
                    "second dockerd is running and NOT audited by the docker CLI",
                    detail="its containers escape this layer entirely",
                    remediation="audit it directly: sudo snap docker ps")

    rc, out, _ = run(["docker", "ps", "--format", "{{.Names}}"])
    names = [n for n in out.split() if n]
    if rc != 0 or not names:
        rep.add(layer, "info", "no running containers on the CLI daemon")
        return

    for name in names:
        probe = ["docker", "exec", name, "python3", "-c", "import sys"]
        rc, _, _ = run(probe, timeout=20)
        if rc != 0:
            rep.add(layer, "warn", "%s: no usable python3 — package CVE state UNKNOWN" % name)
        else:
            for pkg, (min_v, cve, desc) in data.CVE_DB_PY.items():
                rc2, ver, _ = run(["docker", "exec", name, "python3", "-c",
                                   "import importlib.metadata as m; print(m.version(%r))" % pkg],
                                  timeout=20)
                ver = ver.strip()
                if rc2 != 0 or not re.match(r"^\d", ver):
                    continue
                if vlt(ver, min_v):
                    rep.add(layer, "vuln", "%s: %s %s — %s" % (name, pkg, ver, cve),
                            detail=desc)

        rc, top, _ = run(["docker", "top", name, "-eo", "pid,user"], timeout=20)
        lines = top.splitlines()
        if len(lines) > 1:
            user = lines[1].split()[-1] if lines[1].split() else "?"
            if user in ("root", "0"):
                rep.add(layer, "warn", "%s: main process runs as root" % name,
                        remediation="add a USER directive to the image")

        rc, priv, _ = run(["docker", "inspect", name, "--format",
                           "{{.HostConfig.Privileged}}"], timeout=20)
        if priv.strip() == "true":
            rep.add(layer, "vuln", "%s: running privileged (full host access)" % name,
                    remediation="drop --privileged; add only the capabilities needed")


def layer_docker_images(rep: Report, ctx) -> None:
    layer = "docker-images"
    if not _should_run(ctx, layer):
        return
    if not have("docker"):
        rep.skipped.append("docker-images: docker not found")
        return
    rep.layers_run += 1
    rc, out, _ = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"])
    if rc != 0:
        rep.add(layer, "warn", "docker images unreadable — state UNKNOWN")
        return
    latest = [i for i in out.splitlines() if i.endswith(":latest")]
    for img in latest:
        rep.add(layer, "warn", "%s uses :latest" % img,
                remediation="pin a specific version or digest")
    if not latest:
        rep.add(layer, "ok", "no :latest image tags")


LOCK_BLOCK = re.compile(r"\[\[package\]\]\n(.*?)(?=\n\[\[package\]\]|\Z)", re.S)
LOCK_NAME = re.compile(r'^name\s*=\s*"([^"]+)"', re.M)
LOCK_VER = re.compile(r'^version\s*=\s*"([^"]+)"', re.M)


def layer_manifests(rep: Report, ctx) -> None:
    layer = "manifests"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1

    for path in walk(ctx.root, max_depth=6, names=("uv.lock", "poetry.lock")):
        text = read_text(path, limit=64 * 1024 * 1024)  # lockfiles are large
        if not text:
            continue
        versions = {}
        for block in LOCK_BLOCK.findall(text):
            m, v = LOCK_NAME.search(block), LOCK_VER.search(block)
            if m and v:
                versions.setdefault(m.group(1).lower(), set()).add(v.group(1))
        if not versions:
            continue
        for pkg, (min_v, cve, desc) in data.CVE_DB_PY.items():
            for ver in sorted(versions.get(pkg, ())):
                if vlt(ver, min_v):
                    rep.add(layer, "vuln", "%s: %s %s — %s" % (path, pkg, ver, cve),
                            detail=desc, path=path,
                            remediation="uv lock --upgrade-package %s (or poetry update %s)" % (pkg, pkg))
                else:
                    rep.add(layer, "ok", "%s: %s %s — patched" % (path, pkg, ver), path=path)

    unpinned_re = re.compile(
        r"^(fastapi|starlette|vllm|litellm|open-webui|django|flask|aiohttp|httpx|"
        r"requests|urllib3|pillow|pyyaml|cryptography|PyJWT|setuptools)\s*(?![=<>~!])",
        re.I)
    for path in walk(ctx.root, max_depth=6, names=("requirements.txt",)):
        text = read_text(path)
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            if unpinned_re.match(line.strip()):
                rep.add(layer, "warn", "%s: unpinned %s" % (path, line.strip()), path=path,
                        remediation="pin an exact version (==)")

    for path in walk(ctx.root, max_depth=6, names=("pyproject.toml",)):
        text = read_text(path)
        for pkg, (min_v, cve, desc) in data.CVE_DB_PY.items():
            m = re.search(r'^\s*%s\s*[=~<>]+\s*["\']?(\d[0-9.]*)' % re.escape(pkg),
                          text, re.M | re.I)
            if m and vlt(m.group(1), min_v):
                rep.add(layer, "vuln", "%s: %s floor %s < %s — %s" % (path, pkg, m.group(1), min_v, cve),
                        detail=desc, path=path)

    for path in walk(ctx.root, max_depth=6, names=("Dockerfile",)):
        text = read_text(path)
        for line in text.splitlines():
            if re.match(r"^\s*FROM\s+\S+:latest", line, re.I):
                rep.add(layer, "warn", "%s: :latest base image → %s" % (path, line.strip()),
                        path=path, remediation="pin the base image tag or digest")


def _listening_sockets():
    """Parse /proc/net/tcp{,6} — no ss/netstat needed, works on any Linux."""
    socks = []
    for fam, fn in (("ipv4", "/proc/net/tcp"), ("ipv6", "/proc/net/tcp6")):
        try:
            with open(fn, "r", encoding="utf-8") as fh:
                next(fh, None)
                for line in fh:
                    parts = line.split()
                    if len(parts) < 10 or parts[3] != "0A":
                        continue
                    addr, port = parts[1].split(":")
                    inode = parts[9]
                    socks.append((fam, addr, int(port, 16), inode))
        except OSError:
            continue
    return socks


def _socket_owner(inode: str) -> str:
    if not inode or inode == "0":
        return "unknown"
    target = "socket:[%s]" % inode
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            fd_dir = "/proc/%s/fd" % pid
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        if os.readlink(os.path.join(fd_dir, fd)) == target:
                            return read_text("/proc/%s/comm" % pid, 4096).strip() or pid
                    except OSError:
                        continue
            except OSError:
                continue
    except OSError:
        pass
    return "unknown"


def _fmt_ip(fam, addr):
    """Decode a /proc/net/tcp{,6} address into a readable IP."""
    if fam == "ipv4":
        try:
            return ".".join(str(b) for b in bytes.fromhex(addr)[::-1])
        except ValueError:
            return addr
    # IPv6 is four little-endian 32-bit words.
    try:
        import ipaddress
        words = [addr[i:i + 8] for i in range(0, 32, 8)]
        raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
        return str(ipaddress.IPv6Address(raw))
    except Exception:  # noqa: BLE001
        return addr


def _lsof_listening_sockets():
    """macOS / BSD fallback when /proc/net/tcp is unavailable."""
    rc, out, _ = run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"], timeout=20)
    if rc != 0:
        return []
    exposed, loopback = [], 0
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 9:
            continue
        owner = parts[0]
        name = parts[8]  # e.g. 127.0.0.1:8080 or *:3000 or [::1]:5432
        if ":" not in name:
            continue
        host, port_s = name.rsplit(":", 1)
        if not port_s.isdigit():
            continue
        host = host.strip("[]")
        if host in ("127.0.0.1", "::1", "localhost"):
            loopback += 1
        else:
            exposed.append((int(port_s), "0.0.0.0" if host == "*" else host, owner))
    return exposed, loopback


def layer_ports(rep: Report, ctx) -> None:
    layer = "ports"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    socks = _listening_sockets()
    exposed = []
    loopback = 0
    if socks:
        for fam, addr, port, inode in socks:
            ip = _fmt_ip(fam, addr)
            if ip in ("127.0.0.1", "::1"):
                loopback += 1
                continue
            exposed.append((port, ip, _socket_owner(inode)))
    elif not os.path.exists("/proc/net/tcp") and have("lsof"):
        res = _lsof_listening_sockets()
        if res:
            exposed, loopback = res
    if not exposed and not loopback:
        rep.add(layer, "info", "no listening TCP sockets found")
        return
    seen = set()
    for port, ip, owner in sorted(set(exposed)):
        if (port, ip) in seen:
            continue
        seen.add((port, ip))
        where = "0.0.0.0" if ip == "0.0.0.0" else ip
        rep.add(layer, "warn", "%s:%d (%s) — reachable beyond loopback" % (where, port, owner),
                remediation="bind 127.0.0.1 or put authentication in front")
    if loopback:
        rep.add(layer, "ok", "%d socket(s) bound to loopback only" % loopback)


def layer_os_packages(rep: Report, ctx) -> None:
    layer = "os-packages"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    if have("apt"):
        rc, out, _ = run(["apt", "list", "--upgradable"], timeout=120)
        if rc == 0:
            ups = [l for l in out.splitlines() if "upgradable from" in l]
            sec = [l for l in ups if re.search(r"[-/]security", l)]
            if sec:
                rep.add(layer, "warn", "%d security update(s) pending" % len(sec),
                        remediation="sudo apt upgrade")
            elif ups:
                rep.add(layer, "info", "%d package update(s) available (none security-tagged)" % len(ups))
            else:
                rep.add(layer, "ok", "no pending apt updates")
        else:
            rep.add(layer, "warn", "apt list failed — state UNKNOWN")
    elif have("dnf"):
        rc, out, _ = run(["dnf", "-q", "check-update"], timeout=180)
        rep.add(layer, "warn" if rc == 100 else "ok",
                "dnf reports pending updates" if rc == 100 else "dnf: no updates",
                remediation="sudo dnf upgrade --security")
    elif have("apk"):
        rc, out, _ = run(["apk", "version", "-l", "<"], timeout=60)
        rep.add(layer, "info", "apk upgrade available", detail=out.strip()[:400])
    else:
        rep.add(layer, "info", "no supported package manager found")

    if have("snap"):
        rc, out, _ = run(["snap", "refresh", "--list"], timeout=60)
        lines = out.strip().splitlines() if out.strip() else []
        if rc == 0 and len(lines) > 1:
            rep.add(layer, "warn", "snap packages need refresh", detail=out.strip()[:300],
                    remediation="sudo snap refresh")


def layer_ssh(rep: Report, ctx) -> None:
    layer = "ssh"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    running = False
    if have("systemctl"):
        for unit in ("ssh", "sshd"):
            rc, out, _ = run(["systemctl", "is-active", unit])
            if rc == 0 and out.strip() == "active":
                running = True
    if not running and have("pgrep"):
        running = run(["pgrep", "-x", "sshd"])[0] == 0
    if not running:
        rep.add(layer, "info", "sshd is not running — SSH hardening not applicable")
        return

    cfg = ""
    for path in ("/etc/ssh/sshd_config",):
        cfg += read_text(path, 512 * 1024)
    d = "/etc/ssh/sshd_config.d"
    if os.path.isdir(d):
        for fn in sorted(os.listdir(d)):
            cfg += read_text(os.path.join(d, fn), 256 * 1024)

    if not cfg:
        rep.add(layer, "info", "sshd config not readable — SSH hardening UNKNOWN")
    else:
        def setting(name):
            m = re.findall(r"^\s*%s\s+(\S+)" % name, cfg, re.M | re.I)
            return m[-1].lower() if m else ""

        pw = setting("PasswordAuthentication")
        root = setting("PermitRootLogin")
        if pw in ("yes", ""):
            rep.add(layer, "warn", "PasswordAuthentication not disabled",
                    remediation="set PasswordAuthentication no in sshd_config")
        else:
            rep.add(layer, "ok", "SSH password auth disabled")
        if root in ("yes", "prohibit-password", ""):
            rep.add(layer, "warn", "PermitRootLogin not restricted",
                    remediation="set PermitRootLogin no")
        else:
            rep.add(layer, "ok", "SSH root login restricted")

    if have("systemctl"):
        rc, _, _ = run(["systemctl", "is-active", "fail2ban"])
        if rc == 0:
            rep.add(layer, "ok", "fail2ban running")
        else:
            rep.add(layer, "info", "fail2ban not active")


def layer_semgrep(rep: Report, ctx) -> None:
    layer = "semgrep"
    if not _should_run(ctx, layer):
        return
    rules = []
    for base in ("security", ".security"):
        d = os.path.join(ctx.root, base)
        if not os.path.isdir(d):
            continue
        for dirpath, _, filenames in os.walk(d):
            if "semgrep.yml" in filenames:
                rules.append(os.path.join(dirpath, "semgrep.yml"))
    if not rules:
        rep.skipped.append("semgrep: no security/*/semgrep.yml rules under %s" % ctx.root)
        return
    if not have("semgrep"):
        rep.add(layer, "warn", "semgrep not installed — static rules NOT run",
                remediation="uv tool install semgrep")
        return
    rep.layers_run += 1
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    for rule in rules:
        rc, out, _ = run(["semgrep", "scan", "--config", rule, ctx.root,
                          "--no-git-ignore", "--json", "--quiet"], timeout=600, env=env)
        try:
            results = json.loads(out or "{}").get("results", [])
        except Exception:  # noqa: BLE001
            rep.add(layer, "warn", "%s: semgrep failed — state UNKNOWN" % rule)
            continue
        if not results:
            rep.add(layer, "ok", "%s: no matches" % os.path.basename(os.path.dirname(rule)))
            continue
        from collections import Counter
        rep.add(layer, "vuln", "%s: %d pattern(s)" % (rule, len(results)),
                detail="review before deploy")
        for path, n in Counter(r.get("path", "?") for r in results).most_common(15):
            rep.add(layer, "info", "%dx %s" % (n, path))


def layer_secrets(rep: Report, ctx) -> None:
    layer = "secrets"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    exts = (".py", ".ts", ".js", ".tsx", ".jsx", ".env", ".yaml", ".yml", ".json", ".toml", ".sh")
    skip_parts = ("/pytest-of-", "/test/", "/tests/", "/fixtures/", "/vendor/",
                  "/dist/", "/node_modules/", "/.venv/", "/site-packages/")
    found = 0
    for path in walk(ctx.root, max_depth=6):
        if not path.endswith(exts):
            continue
        if any(part in path for part in skip_parts):
            continue
        if path.endswith((".min.js", ".min.css", ".test.ts", ".test.js",
                          ".spec.ts", ".spec.js", "_test.py")):
            continue
        base = os.path.basename(path)
        if base.startswith(("test-", "test_")) or ".test." in base or ".spec." in base:
            continue
        try:
            if os.path.getsize(path) > 512 * 1024:  # bundles produce garbage matches
                continue
        except OSError:
            continue
        text = read_text(path)
        if not text:
            continue
        for pat in data.SECRET_PATTERNS:
            for m in re.finditer(pat, text, re.I):
                value = m.group(m.lastindex or 0) if m.lastindex else m.group(0)
                if value.startswith("$") or is_dummy(value):
                    continue
                rep.add(layer, "vuln", "possible hardcoded secret", path=path,
                        detail="%s: %s" % (pat[:40], mask(value)),
                        remediation="move to an env var / secret store; rotate if real")
                found += 1
                break
        if found >= 40:
            break

    for path in walk(ctx.root, max_depth=5, names=(".env",)):
        d = os.path.dirname(path)
        rc, _, _ = run(["git", "-C", d, "ls-files", "--error-unmatch", os.path.basename(path)])
        if rc == 0:
            rep.add(layer, "vuln", ".env tracked in git", path=path,
                    remediation="git rm --cached and add to .gitignore")
        else:
            rc_repo, _, _ = run(["git", "-C", d, "rev-parse", "--is-inside-work-tree"])
            if rc_repo == 0:
                rc_ign, _, _ = run(["git", "-C", d, "check-ignore", "-q", path])
                if rc_ign != 0:
                    rep.add(layer, "warn", ".env exists in git repo but is NOT in .gitignore",
                            path=path, remediation="add .env to .gitignore before committing")

    if not found:
        rep.add(layer, "ok", "no hardcoded secrets in source")


def layer_venvs(rep: Report, ctx) -> None:
    layer = "venvs"
    if not _should_run(ctx, layer):
        return
    if ctx.quick:
        rep.skipped.append("venvs: skipped in --quick")
        return
    rep.layers_run += 1
    seen = 0
    for dirpath, dirnames, filenames in os.walk(ctx.root, onerror=lambda e: None):
        if os.path.basename(dirpath) != "bin" or "python3" not in filenames:
            continue
        py = os.path.join(dirpath, "python3")
        seen += 1
        for pkg, (min_v, cve, desc) in data.CVE_DB_PY.items():
            rc, out, _ = run([py, "-c",
                              "import importlib.metadata as m; print(m.version(%r))" % pkg],
                             timeout=20)
            ver = out.strip()
            if rc == 0 and re.match(r"^\d", ver) and vlt(ver, min_v):
                rep.add(layer, "vuln", "%s: %s %s — %s" % (py, pkg, ver, cve), detail=desc)
        if seen > 80:
            rep.add(layer, "info", "venv scan capped at 80 environments")
            break
    if seen == 0:
        rep.add(layer, "info", "no virtual environments found under %s" % ctx.root)


def layer_cve_now(rep: Report, ctx) -> None:
    layer = "cve-now"
    if not _should_run(ctx, layer):
        return
    if ctx.offline:
        rep.skipped.append("cve-now: --offline")
        return
    rep.layers_run += 1

    parts, unknown = [], []
    try:
        import importlib.metadata as md
        for dist in md.distributions():
            name = (dist.metadata["Name"] or "").lower().replace("_", "-")
            ver = dist.version or ""
            if not name:
                continue
            if not ver or ver == "0.0.0":
                unknown.append("%s@%s" % (name, ver or "unknown"))
                continue
            parts.append("pypi:%s@%s" % (name, ver))
    except Exception:  # noqa: BLE001
        pass

    if have("npm"):
        rc, out, _ = run(["npm", "list", "-g", "--depth=0", "--json"], timeout=60)
        try:
            deps = json.loads(out or "{}").get("dependencies") or {}
        except Exception:  # noqa: BLE001
            deps = {}
        for name, info in deps.items():
            ver = (info or {}).get("version") or ""
            if not ver or ver == "0.0.0":
                unknown.append("npm:%s@%s" % (name, ver or "unknown"))
                continue
            parts.append("npm:%s@%s" % (name.lower().replace("_", "-"), ver))

    if unknown:
        rep.add(layer, "info", "%d package(s) report placeholder version 0.0.0 — NOT assessed"
                % len(unknown), detail=", ".join(unknown[:6]))
    if not parts:
        rep.add(layer, "warn", "no packages to check")
        return

    items, incomplete = [], False
    for i in range(0, len(parts), 25):
        chunk = parts[i:i + 25]
        q = urllib.parse.quote(",".join(chunk), safe="")
        url = "https://cve.now/stack?p=" + q
        status, body = None, ""
        for attempt in range(2):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "agent-lockdown"})
                with urllib.request.urlopen(req, timeout=90) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", "replace")
                break
            except urllib.error.HTTPError as exc:
                status = exc.code
            except Exception:  # noqa: BLE001 - network flake
                status = 0
            if attempt == 0:
                import time
                time.sleep(2)
        if status != 200:
            rep.add(layer, "warn", "feed batch failed (HTTP %s) — %d package(s) UNKNOWN"
                    % (status, len(chunk)), detail=chunk[0])
            incomplete = True
            continue
        for item in re.findall(r"<item>(.*?)</item>", body, re.S):
            title = re.search(r"<title>(.*?)</title>", item, re.S)
            desc = re.search(r"<description>(.*?)</description>", item, re.S)
            title = _unescape(title.group(1)).strip() if title else ""
            desc = _unescape(desc.group(1)) if desc else ""
            aff = re.search(r"Affects ([^ ]+ \([^)]+\))", desc)
            pkg = aff.group(1) if aff else "unknown"
            items.append((pkg, title.split(":")[0]))

    if incomplete:
        rep.add(layer, "warn", "feed check INCOMPLETE — unassessed batches are UNKNOWN, not clean")

    if not items:
        if not incomplete:
            rep.add(layer, "ok", "no known CVEs affect installed package versions")
        return

    from collections import defaultdict
    by = defaultdict(set)
    for pkg, cid in items:
        by[pkg].add(cid)
    rep.add(layer, "vuln", "%d CVE(s) across %d installed package(s)" % (len(items), len(by)),
            remediation="upgrade the listed packages, then re-run")
    for pkg, ids in sorted(by.items(), key=lambda kv: -len(kv[1])):
        ids = sorted(ids)
        shown = ", ".join(ids[:6]) + (" …" if len(ids) > 6 else "")
        rep.add(layer, "vuln", "%s — %d CVE(s)" % (pkg, len(ids)), detail=shown)


def _unescape(text: str) -> str:
    import html
    return html.unescape(text)


# ---------------------------------------------------------------- agent layers


def _agent_configs(ctx):
    """Yield (path, agent_root_name) for every config of every installed agent."""
    seen = set()
    for root in data.AGENT_ROOTS:
        base = os.path.join(ctx.home, root)
        if not os.path.exists(base):
            continue
        if os.path.isfile(base):
            if base not in seen:
                seen.add(base)
                yield base, root
            continue
        for dirpath, dirnames, filenames in os.walk(base, onerror=lambda e: None):
            depth = dirpath[len(base):].count(os.sep)
            if depth >= 3:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if d not in data.SKIP_DIRS]
            for fn in filenames:
                in_hooks_dir = os.path.basename(dirpath) == "hooks" and fn.endswith(".json")
                if fn in data.AGENT_CONFIG_NAMES or fn.endswith(".mcp.json") or in_hooks_dir:
                    path = os.path.join(dirpath, fn)
                    if path not in seen:
                        seen.add(path)
                        yield path, root
    for glob in data.AGENT_REPO_CONFIG_GLOBS:
        for path in walk(ctx.root, max_depth=5, names=(os.path.basename(glob),)):
            if glob.replace("\\", "/") in path.replace("\\", "/") and path not in seen:
                seen.add(path)
                yield path, "repo"


def _strip_jsonc(text):
    """Remove // and /* */ comments so JSONC configs parse (VS Code/Copilot)."""
    out, i, n = [], 0, len(text)
    in_str = False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_config(path):
    """Return (hooks, mcp_servers, deny_env) or None when unparseable."""
    raw = read_text(path)
    if not raw or not raw.strip():
        return {}, {}, False
    if path.endswith(".toml"):
        data_ = {}
        try:
            import tomllib  # py3.11+
            data_ = tomllib.loads(raw)
        except Exception:  # noqa: BLE001
            for m in re.finditer(r"\[mcp_servers\.([^\]]+)\](.*?)(?=\n\[|\Z)", raw, re.S):
                cm = re.search(r'^command\s*=\s*["\']([^"\']+)["\']', m.group(2), re.M)
                if cm:
                    data_.setdefault("mcp_servers", {})[m.group(1)] = {"command": cm.group(1)}
    else:
        try:
            data_ = json.loads(raw)
        except Exception:  # noqa: BLE001
            try:
                data_ = json.loads(_strip_jsonc(raw))
            except Exception:  # noqa: BLE001
                return None
    hooks = data_.get("hooks") or {}
    # Antigravity / Gemini hooks.json maps hook names at the top level to event dicts
    if not hooks and os.path.basename(path) == "hooks.json" and isinstance(data_, dict):
        merged_events = {}
        for val in data_.values():
            if isinstance(val, dict):
                for ev_name, ev_list in val.items():
                    if isinstance(ev_list, list):
                        merged_events.setdefault(ev_name, []).extend(ev_list)
        if merged_events:
            hooks = merged_events
    servers = data_.get("mcpServers") or data_.get("mcp_servers") or data_.get("servers") or {}
    deny = ((data_.get("permissions") or {}).get("deny") or [])
    has_env_deny = any(".env" in str(x) for x in deny)
    if not has_env_deny and isinstance(hooks, dict):
        for ev_groups in hooks.values():
            if hook_mod._has_asa_hook_in_groups(ev_groups):
                has_env_deny = True
                break
    return hooks, servers, has_env_deny


def detected_roots(ctx):
    """Every agent tool directory that actually exists under ctx.home."""
    return [r for r in data.AGENT_ROOTS if os.path.exists(os.path.join(ctx.home, r))]


def layer_agent_config(rep: Report, ctx) -> None:
    layer = "agent-config"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1

    cfgs = list(_agent_configs(ctx))
    if not cfgs:
        rep.add(layer, "info", "no agent config files found")
        return

    roots = detected_roots(ctx)
    rep.add(layer, "info", "agent roots detected: %s" % " ".join(roots))

    total_hooks = mcp_total = mcp_notable = env_blocked = 0
    for path, _root in cfgs:
        parsed = _parse_config(path)
        if parsed is None:
            rep.add(layer, "warn", "unparseable config (neither JSON nor TOML)", path=path)
            continue
        hooks, servers, deny_env = parsed
        if deny_env:
            env_blocked += 1

        if isinstance(hooks, dict):
            for event, groups in hooks.items():
                if not isinstance(groups, list):
                    continue
                for group in groups:
                    if not isinstance(group, dict):
                        continue
                    hook_items = group.get("hooks") if isinstance(group.get("hooks"), list) else [group]
                    for hook in hook_items:
                        if not isinstance(hook, dict):
                            continue
                        cmd = hook.get("command") or ""
                        if not cmd:
                            continue
                        total_hooks += 1
                        flags = _command_flags(cmd)
                        if "downloads/executes" in flags or "fetches remote" in flags:
                            rep.add(layer, "vuln", "%s hook %s" % (event, flags), path=path,
                                    detail=sanitize_command(cmd.replace("\n", " "))[:150],
                                    remediation="remove the hook unless you wrote it yourself")
                        elif flags:
                            rep.add(layer, "warn", "%s hook %s" % (event, flags), path=path,
                                    detail=sanitize_command(cmd.replace("\n", " "))[:150])

        if isinstance(servers, dict):
            for name, spec in servers.items():
                if not isinstance(spec, dict):
                    continue
                cmd = str(spec.get("command") or "")
                args = " ".join(str(a) for a in (spec.get("args") or []))
                url = str(spec.get("url") or spec.get("serverUrl") or "")
                full = (cmd + " " + args).strip()
                if not full and not url:
                    continue
                mcp_total += 1
                flags = _command_flags(full)
                if url:
                    flags = (flags + "; remote endpoint").strip("; ")
                if not flags:
                    continue
                mcp_notable += 1
                safe_detail = sanitize_command(full or url)[:140]
                if "downloads/executes" in flags:
                    rep.add(layer, "vuln", "MCP server '%s' %s" % (name, flags), path=path,
                            detail=safe_detail,
                            remediation="remove or replace the server; never pipe a download into a shell")
                else:
                    rep.add(layer, "warn", "MCP server '%s' %s" % (name, flags), path=path,
                            detail=safe_detail)

        if path.endswith("settings.local.json"):
            d = os.path.dirname(path)
            rc, _, _ = run(["git", "-C", d, "ls-files", "--error-unmatch", path])
            if rc == 0:
                rc2, origin, _ = run(["git", "-C", d, "remote", "get-url", "origin"])
                origin = origin.strip()
                rep.add(layer, "vuln", "settings.local.json tracked in git", path=path,
                        detail=("origin: %s" % origin) if origin else "tracked in local git repo",
                        remediation="git rm --cached it and add .claude/settings.local.json to .gitignore")
            else:
                rc_repo, _, _ = run(["git", "-C", d, "rev-parse", "--is-inside-work-tree"])
                if rc_repo == 0:
                    rc_ign, _, _ = run(["git", "-C", d, "check-ignore", "-q", path])
                    if rc_ign != 0:
                        rep.add(layer, "warn", "settings.local.json is NOT in .gitignore", path=path,
                                remediation="add .claude/settings.local.json to .gitignore")

    protected_agents, unprotected_agents = hook_mod.agent_env_protection_status(ctx.home)
    total_protected = max(env_blocked, len(protected_agents))
    rep.add(layer, "info", "hooks: %d · MCP servers: %d (%d notable) · configs: %d"
            % (total_hooks, mcp_total, mcp_notable, len(cfgs)))
    if total_protected == 0:
        rep.add(layer, "warn", "no config denies .env reads",
                remediation="add a permissions.deny entry or global PreToolUse hook (run `asa --install-env-hook` or `asa --print-env-hook`)")
    else:
        rep.add(layer, "ok", "%d config(s)/agent(s) deny .env reads" % total_protected)
        if unprotected_agents:
            rep.add(layer, "warn",
                    "detected agent(s) without global .env read protection: %s" % ", ".join(unprotected_agents),
                    remediation="ask user permission, then run `asa --install-env-hook --yes`")


def _command_flags(cmd: str) -> str:
    flags = []
    if re.search(data.SHELL_EXEC_PATTERN, cmd, re.I):
        flags.append("downloads/executes")
    if re.search(data.INLINE_CODE_PATTERN, cmd, re.I):
        flags.append("inline code")
    if re.search(data.REMOTE_PKG_PATTERN, cmd, re.I):
        flags.append("remote package")
    if re.search(data.URL_PATTERN, cmd, re.I):
        flags.append("fetches remote")
    return "; ".join(flags)


KEY_PATTERN = (
    r"(sk-ant-[A-Za-z0-9_-]{20,120}|sk-proj-[A-Za-z0-9_-]{20,160}"
    r"|sk-or-v1-[A-Za-z0-9]{40,80}|sk-[A-Za-z0-9]{20,64}"
    r"|sk_live_[A-Za-z0-9]{20,64}|gsk_[A-Za-z0-9]{20,64}"
    r"|AIza[0-9A-Za-z_-]{35}|hf_[A-Za-z0-9]{30,40}"
    r"|gh[pousr]_[A-Za-z0-9]{30,40}|xox[baprs]-[0-9A-Za-z-]{10,40}"
    r"|AKIA[0-9A-Z]{16})"
)


def layer_agent_history(rep: Report, ctx) -> None:
    layer = "agent-history"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1

    exts = (".jsonl", ".json", ".md", ".txt", ".db", ".log")
    hits = 0
    scanned = 0
    for root in data.AGENT_ROOTS:
        base = os.path.join(ctx.home, root)
        if not os.path.isdir(base):
            continue
        scanned += 1
        per_root = 0
        for path in walk(base, max_depth=6):
            if per_root >= 10:
                break
            if not path.endswith(exts):
                continue
            if any(part in path for part in ("/docs/", "/website/", "/bin/", "/plugins/", "/installs/")):
                continue
            try:
                if os.path.getsize(path) > MAX_HISTORY_FILE:
                    continue
            except OSError:
                continue
            text = read_text(path, MAX_HISTORY_FILE)
            if not text or not re.search(KEY_PATTERN, text):
                continue
            values = []
            for m in re.finditer(KEY_PATTERN, text):
                v = m.group(0)
                if is_dummy(v) or v in values:
                    continue
                values.append(v)
                if len(values) >= 3:
                    break
            if not values:
                continue
            rep.add(layer, "vuln", "credential in agent history", path=path,
                    detail=" ".join(mask(v) for v in values),
                    remediation="rotate the key at the provider, then purge the file")
            hits += 1
            per_root += 1
    rep.add(layer, "info", "agent history roots scanned: %d · files with keys: %d" % (scanned, hits))
    if hits == 0:
        rep.add(layer, "ok", "no provider keys found in agent history")

    # Git history: a key removed from HEAD still ships in every clone.
    repos = 0
    cap = 12 if ctx.quick else 25
    for repo in git_repos(ctx.root, max_depth=4):
        repos += 1
        if repos > cap:
            break
        rc, out, _ = run(["git", "-C", repo, "log", "-p", "--all", "--max-count=60"], timeout=120)
        vals = [v for v in re.findall(KEY_PATTERN, out or "") if not is_dummy(v)]
        if vals:
            rep.add(layer, "vuln", "credential in git history (%d match(es))" % len(vals), path=repo,
                    detail=" ".join(mask(v) for v in vals[:3]),
                    remediation="rotate the key; history rewrite needs approval")
    rep.add(layer, "info", "git history scanned: %d repo(s) (cap %d)" % (repos, cap))


def layer_agent_rules(rep: Report, ctx) -> None:
    layer = "agent-rules"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1
    count = 0
    hidden_hits = 0
    rule_paths = []
    for path in walk(ctx.root, max_depth=4):
        base = os.path.basename(path)
        if base in data.AGENT_RULE_NAMES or base == "SKILL.md" or path.endswith(".mdc"):
            rule_paths.append(path)
    for rel in data.SKILL_ROOTS:
        sdir = os.path.join(ctx.home, rel)
        if os.path.isdir(sdir):
            for path in walk(sdir, max_depth=3, names=("SKILL.md",)):
                rule_paths.append(path)

    for path in dict.fromkeys(rule_paths):
        text = read_text(path, 512 * 1024)
        if not text:
            continue
        inv = re.findall(data.INVISIBLE_UNICODE_RE, text)
        if inv:
            codes = ", ".join(sorted({"U+%04X" % ord(ch) for ch in inv})[:6])
            rep.add(layer, "vuln", "hidden Unicode characters in agent rule/skill (%d)" % len(inv),
                    path=path, detail="codepoints: %s (possible ASCII smuggling / invisible prompt injection)" % codes,
                    remediation="inspect raw bytes and strip zero-width/BiDi/tag characters")
            hidden_hits += 1
        for i, line in enumerate(text.splitlines(), 1):
            if re.search(data.INJECTION_PATTERN, line, re.I):
                rep.add(layer, "warn", "suspicious directive at line %d" % i, path=path,
                        detail=line.strip()[:150],
                        remediation="review; delete it if you did not write it")
                count += 1
                if count > 40:
                    break
    if count == 0 and hidden_hits == 0:
        rep.add(layer, "ok", "no injected-instruction or hidden-Unicode patterns in agent rules")


def _npm_package_jsons(root, cap):
    """package.json of installed npm packages (including @scope/pkg)."""
    count = 0
    for dirpath, dirnames, _ in os.walk(root, onerror=lambda e: None):
        if os.path.basename(dirpath) != "node_modules":
            continue
        for pkg in list(dirnames):
            pkg_dir = os.path.join(dirpath, pkg)
            if pkg.startswith("@"):
                try:
                    scoped = os.listdir(pkg_dir)
                except OSError:
                    scoped = []
                for sub in scoped:
                    pj = os.path.join(pkg_dir, sub, "package.json")
                    if os.path.isfile(pj):
                        yield pj
                        count += 1
                        if count >= cap:
                            return
                continue
            pj = os.path.join(pkg_dir, "package.json")
            if os.path.isfile(pj):
                yield pj
                count += 1
                if count >= cap:
                    return
        dirnames[:] = []  # do not descend into the packages themselves


def layer_supply_chain(rep: Report, ctx) -> None:
    layer = "supply-chain"
    if not _should_run(ctx, layer):
        return
    rep.layers_run += 1

    pth_scanned = pth_hits = 0
    for dirpath, dirnames, filenames in os.walk(ctx.root, onerror=lambda e: None):
        if os.path.basename(dirpath) != "site-packages":
            continue
        dirnames[:] = []
        for fn in filenames:
            if not fn.endswith(".pth"):
                continue
            pth_scanned += 1
            if fn in data.BENIGN_PTH or fn.startswith("__editable__"):
                continue
            text = read_text(os.path.join(dirpath, fn), 256 * 1024)
            if re.search(data.PTH_DANGEROUS, text):
                rep.add(layer, "vuln", "suspicious .pth executes code",
                        path=os.path.join(dirpath, fn),
                        remediation="inspect it; a compromised package can persist here")
                pth_hits += 1
    if pth_hits == 0:
        rep.add(layer, "ok", "no suspicious .pth files (%d scanned)" % pth_scanned)

    for path in walk(ctx.root, max_depth=7, names=("sitecustomize.py", "usercustomize.py")):
        rep.add(layer, "warn", "custom interpreter-start hook", path=path,
                remediation="verify it is intentional")

    npm_cap = 80 if ctx.quick else 200
    seen = 0
    for path in _npm_package_jsons(ctx.root, npm_cap):
        seen += 1
        try:
            pkg = json.loads(read_text(path))
        except Exception:  # noqa: BLE001
            continue
        scripts = pkg.get("scripts") or {}
        for key in ("preinstall", "install", "postinstall", "prepare"):
            cmd = scripts.get(key) or ""
            if cmd and re.search(data.SHELL_EXEC_PATTERN + "|" + data.INLINE_CODE_PATTERN, cmd, re.I):
                rep.add(layer, "vuln", "npm %s lifecycle hook" % key, path=path,
                        detail=cmd[:120],
                        remediation="remove the hook or pin a trusted version")
    rep.add(layer, "info", "npm package.json audited: %d (cap %d)" % (seen, npm_cap))

    # Skill scripts under $HOME: skills ship executable scripts, not just markdown.
    skill_scripts = skill_hits = 0
    script_exts = (".sh", ".py", ".js", ".mjs", ".ts")
    for rel in data.SKILL_ROOTS:
        sdir = os.path.join(ctx.home, rel)
        if not os.path.isdir(sdir):
            continue
        for path in walk(sdir, max_depth=4):
            if not path.endswith(script_exts):
                continue
            if path.endswith((".test.js", ".test.mjs", ".test.ts", "_test.py")) or "/tests/" in path:
                continue
            skill_scripts += 1
            text = read_text(path, 256 * 1024)
            if not text:
                continue
            m = re.search(data.SKILL_SCRIPT_DANGEROUS_PATTERN, text, re.I)
            if m:
                rep.add(layer, "vuln", "suspicious download/exfil pattern in skill script",
                        path=path, detail=sanitize_command(m.group(0).strip())[:120],
                        remediation="review the script; remove the skill if untrusted")
                skill_hits += 1
    if skill_scripts:
        rep.add(layer, "info", "skill scripts audited: %d · flagged: %d" % (skill_scripts, skill_hits))

    # Editor extensions (VS Code, Cursor, Windsurf): check for lifecycle install hooks.
    ext_scanned = ext_hits = 0
    for rel in data.EDITOR_EXT_DIRS:
        edir = os.path.join(ctx.home, rel)
        if not os.path.isdir(edir):
            continue
        try:
            entries = os.listdir(edir)
        except OSError:
            continue
        for entry in entries[:250]:
            pj = os.path.join(edir, entry, "package.json")
            if not os.path.isfile(pj):
                continue
            ext_scanned += 1
            try:
                pkg = json.loads(read_text(pj, 256 * 1024))
            except Exception:  # noqa: BLE001
                continue
            scripts = pkg.get("scripts") or {}
            for key in ("preinstall", "install", "postinstall"):
                cmd = scripts.get(key) or ""
                if cmd and re.search(data.SHELL_EXEC_PATTERN + "|" + data.INLINE_CODE_PATTERN, cmd, re.I):
                    rep.add(layer, "vuln", "editor extension %s lifecycle hook" % key,
                            path=pj, detail=sanitize_command(cmd)[:120],
                            remediation="uninstall the extension if you do not trust its publisher")
                    ext_hits += 1
    if ext_scanned:
        rep.add(layer, "info", "editor extensions audited: %d · flagged: %d" % (ext_scanned, ext_hits))


ALL_LAYERS = (
    layer_host_python, layer_host_node, layer_docker_containers, layer_docker_images,
    layer_manifests, layer_ports, layer_os_packages, layer_ssh, layer_semgrep,
    layer_secrets, layer_venvs, layer_cve_now, layer_agent_config,
    layer_agent_history, layer_agent_rules, layer_supply_chain,
)

LAYER_NAMES = (
    "host-python", "host-node", "docker-containers", "docker-images", "manifests",
    "ports", "os-packages", "ssh", "semgrep", "secrets", "venvs", "cve-now",
    "agent-config", "agent-history", "agent-rules", "supply-chain",
)


def audit(ctx) -> Report:
    rep = Report()
    for name, fn in zip(LAYER_NAMES, ALL_LAYERS):
        if not _should_run(ctx, name):
            continue
        try:
            fn(rep, ctx)
        except Exception as exc:  # noqa: BLE001 - one broken layer must not kill the audit
            rep.add("internal", "warn", "%s crashed: %s" % (fn.__name__, exc),
                    detail="state UNKNOWN for this layer")
    return rep
