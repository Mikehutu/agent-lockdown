"""Static data for the audit: CVE tables, agent registry, and detection patterns.

Everything here is data, not behaviour. Keeping it separate means a new CVE or a
new agent tool is a one-line change, and packagers can diff it easily.
"""

# Format: package -> (minimum safe version, CVE id, description)
# Note: For live up-to-date CVE coverage across all installed packages, layer 12 (`cve-now`)
# queries the public https://cve.now feed (unless --offline or --agents-only is set).
CVE_DB_PY = {
    "starlette": ("1.0.1", "CVE-2026-48710", "BadHost: Host header injection bypasses path-based auth"),
    "requests": ("2.33.0", "CVE-2026-25645", "HTTP header injection via proxy bypass"),
    "pyjwt": ("2.12.1", "CVE-2026-32597", "Algorithm confusion attack"),
    "urllib3": ("2.5.0", "CVE-2025-50581", "Request smuggling via chunked transfer"),
    "cryptography": ("44.0.0", "CVE-2025-1352", "Buffer overread in OpenSSL bindings"),
    "pillow": ("11.1.0", "CVE-2025-48379", "Image parsing DoS via crafted TIFF"),
    "pyyaml": ("6.0.2", "CVE-2025-47081", "Arbitrary code execution via unsafe load"),
    "setuptools": ("78.1.1", "CVE-2025-47273", "Package download path traversal"),
    "django": ("5.1.7", "CVE-2025-48382", "SQL injection in contrib.postgres"),
    "flask": ("3.1.0", "CVE-2025-48449", "Open redirect via malformed URL"),
    "aiohttp": ("3.11.14", "CVE-2025-48488", "HTTP request smuggling"),
    "httpx": ("0.28.1", "CVE-2025-48492", "Proxy auth header leak"),
    "jinja2": ("3.1.6", "CVE-2025-27516", "Sandbox breakout via attr filter"),
    "werkzeug": ("3.0.6", "CVE-2024-49766", "Path traversal via safe_join on Windows"),
    "tornado": ("6.4.2", "CVE-2024-52804", "Cookie parsing DoS"),
    "fastapi": ("0.115.0", "CVE-2024-24762", "ReDoS via python-multipart form boundary"),
    "langchain-core": ("0.3.28", "CVE-2024-46946", "Template / deserialization injection"),
    "gradio": ("5.6.0", "CVE-2024-47872", "Arbitrary file read / SSRF"),
}

CVE_DB_NPM = {
    "express": ("5.1.0", "CVE-2025-48501", "Open redirect via malformed path"),
    "next": ("15.3.2", "CVE-2025-48510", "SSRF in image optimization"),
    "axios": ("1.9.0", "CVE-2025-48515", "SSRF via absolute URL parsing"),
    "lodash": ("4.17.21", "CVE-2025-48520", "Prototype pollution in mergeWith"),
    "vite": ("6.2.4", "CVE-2025-31125", "Dev server fs.deny bypass"),
    "undici": ("6.21.1", "CVE-2025-22150", "Insufficiently random boundary values"),
    "tar": ("7.4.3", "CVE-2024-28863", "Denial of service via crafted archive"),
}

# Agent tools to audit. Presence is checked, never assumed. A tool that is not
# listed is invisible to layers 14-16, so adding one here is the extension point.
AGENT_ROOTS = (
    ".claude", ".claude.json", ".codex", ".copilot", ".cursor", ".cursor-server",
    ".gemini", ".pi", ".opencode", ".config/opencode", ".kiro", ".grok", ".openfang", ".agents",
    ".archon", ".aitk", ".aider", ".continue", ".cline", ".windsurf", ".zed",
    ".qwen", ".goose", ".amp", ".crush", ".factory", ".trae", ".roo", ".augment",
    ".tabnine", ".sourcegraph", ".hermes", ".bolt", ".devin",
)

# Config file names searched under each agent root (depth 3).
AGENT_CONFIG_NAMES = (
    "settings.json", "settings.local.json", "config.toml", "config.json",
    "config.yaml", "opencode.json", "mcp.json", "mcp-config.json",
    "mcp_config.json", "*.mcp.json", "hooks.json",
)

# Repo-level agent config globs, relative to the scanned root.
AGENT_REPO_CONFIG_GLOBS = (
    ".claude/settings.json", ".claude/settings.local.json", ".mcp.json",
    ".cursor/mcp.json", ".cursor/hooks.json", ".gemini/settings.json",
    ".agents/hooks.json", ".codex/hooks.json", ".kiro/settings/mcp.json",
)

# Rule files loaded into every session by the major tools.
AGENT_RULE_NAMES = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules",
                    ".clinerules", ".windsurfrules")

# Secret patterns. Key-shaped names only: a bare `token =` matches tokenizer
# parameters (pad_token=0) and produces pure noise.
SECRET_PATTERNS = (
    r"(api[_-]?key|apikey)\s*[=:]\s*[\"']([A-Za-z0-9_-]{16,})[\"']",
    r"(client[_-]?secret|secret[_-]?key)\s*[=:]\s*[\"']([A-Za-z0-9_-]{16,})[\"']",
    r"(password|passwd)\s*[=:]\s*[\"']([^\"'\s]{8,})[\"']",
    r"(access[_-]?token|auth[_-]?token)\s*[=:]\s*[\"']([A-Za-z0-9_.-]{16,})[\"']",
    r"AWS_SECRET_ACCESS_KEY\s*=\s*[\"']([A-Za-z0-9/+=]{32,})[\"']",
    r"sk-(?:ant-[A-Za-z0-9_-]{20,120}|proj-[A-Za-z0-9_-]{20,160}|or-v1-[A-Za-z0-9]{40,80}|[A-Za-z0-9]{20,64})",
    r"sk_live_[A-Za-z0-9]{20,64}",
    r"gsk_[A-Za-z0-9]{20,64}",
    r"AIza[0-9A-Za-z_-]{35}",
    r"gh[pousr]_[A-Za-z0-9]{30,40}",
    r"hf_[A-Za-z0-9]{30,40}",
    r"xox[baprs]-[0-9A-Za-z-]{10,40}",
    r"AKIA[0-9A-Z]{16}",
)

# Values that look like keys but are placeholders.
DUMMY_VALUES = ("mesh-llm-ci", "password", "refreshed-jwt", "synthetic-not-a-credential",
                "test", "changeme", "***")
DUMMY_PREFIXES = ("sk-test", "test-key", "synthetic-", "not-a-credential", "replace-me",
                  "change-me", "changeme", "your-", "CHANGE_ME", "example", "dummy",
                  "placeholder", "xxx", "phc_", "pk_", "pub_")
DUMMY_SUBSTRINGS = ("EXAMPLE", "example", "dummy", "fake", "your", "placeholder")

# Prompt-injection: instructions that STEER the agent against its user.
# Avoid bare words like "exfiltration" or "base64 -d" that appear in legitimate
# security/testing documentation; require imperative injection phrasing.
INJECTION_PATTERN = (
    r"(?<!['\"`])("
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|disregard\s+(the\s+)?(system|previous|above)\s+instructions"
    r"|do\s+not\s+(tell|inform|mention\s+this\s+to)\s+(the\s+)?(user|human|operator)\b(?!\s+to\s+run)"
    r"|disable\s+(all\s+)?(security|safety|guardrails|sandbox|approval|consent)\s+(checks|controls|prompts|hooks|mode)"
    r"|bypass\s+(the\s+)?(auth|approval|consent|sandbox)\s+(check|gate|prompt|policy)"
    r"|send\s+(the\s+)?(contents|secrets|keys|env|token|credentials)\s+to\s+https?://"
    r")"
)

# Hidden Unicode used in ASCII-smuggling / invisible prompt injection:
# zero-width chars, BiDi overrides, and Unicode Tag characters (U+E0000..U+E007F).
INVISIBLE_UNICODE_RE = r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]"

# Editor extension directories and AI skill directories under $HOME.
EDITOR_EXT_DIRS = (
    ".vscode/extensions", ".cursor/extensions", ".windsurf/extensions",
    ".vscode-server/extensions",
)
SKILL_ROOTS = (
    ".claude/skills", ".agents/skills", ".hermes/skills",
    ".codex/skills", ".copilot/skills",
)
# In multi-line skill scripts, normal HTTP calls are common; flag download-and-pipe-to-shell,
# reverse shells (/dev/tcp, ncat/nc -e), base64-decode-to-shell, or secret-file exfiltration.
SKILL_SCRIPT_DANGEROUS_PATTERN = (
    r"((?:curl|wget)\b[^\n|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|base64\s+(?:-d|--decode)\b[^\n|;&]*\|\s*(?:ba|z|da)?sh\b"
    r"|/dev/tcp/[0-9A-Za-z._-]+/\d+"
    r"|\b(?:nc|ncat|netcat)\s+[^\n]*-e\s+/bin/(?:ba)?sh"
    r"|(?:curl|wget|ncat|\bnc)\b[^\n]*(?:\.env\b|\.ssh/|id_rsa|\.aws/credentials)"
    r"|(?:\.env\b|\.ssh/id_rsa|\.aws/credentials)[^\n]*\|\s*(?:curl|wget|ncat|\bnc)\b)"
)

# Hooks / MCP commands that download-and-execute (note \b before nc!).
SHELL_EXEC_PATTERN = r"(\b(?:curl|wget|ncat|nc)\s|/dev/tcp|base64\s+-d|\|\s*(?:ba)?sh\b)"
INLINE_CODE_PATTERN = r"(eval\b|python[0-9.]*\s+-c|node\s+-e)"
REMOTE_PKG_PATTERN = r"\b(npx|pnpx|bunx|uvx|uv tool run)\b"
URL_PATTERN = r"(https?://|ftp://|git\+)"

# .pth files that legitimately execute code (editable installs, coverage shims).
BENIGN_PTH = {
    "distutils-precedence.pth", "_virtualenv.pth", "setuptools.pth",
    "easy-install.pth", "a1_coverage.pth", "pytest-cov.pth", "coloredlogs.pth",
}
PTH_DANGEROUS = r"(exec\(|eval\(|subprocess|os\.system|urllib|socket|base64|__import__)"

# Directories never worth descending into.
SKIP_DIRS = {
    "node_modules", ".git", ".venv", "venv", "__pycache__", ".cache",
    "site-packages", "dist", "build", ".tox", ".mypy_cache", ".ruff_cache",
    ".pytest_cache", "installs", "plugins", ".next", ".turbo", ".archive",
}

# Layers focused specifically on AI coding agents and their supply chain.
AGENT_LAYERS = ("agent-config", "agent-history", "agent-rules", "supply-chain")

# Human-readable layer catalog for --list-layers.
LAYER_DESCRIPTIONS = (
    ("host-python", "Installed Python packages checked against CVE table"),
    ("host-node", "Global npm packages checked against CVE table"),
    ("docker-containers", "Running containers: package CVEs, root user, privileged mode"),
    ("docker-images", "Docker images using mutable :latest tags"),
    ("manifests", "Lockfiles (uv.lock/poetry.lock), unpinned requirements, Dockerfiles"),
    ("ports", "Listening TCP sockets reachable beyond loopback (/proc)"),
    ("os-packages", "Pending OS security updates (apt/dnf/apk/snap)"),
    ("ssh", "sshd hardening (PasswordAuthentication, PermitRootLogin, fail2ban)"),
    ("semgrep", "Custom security/*/semgrep.yml static rules"),
    ("secrets", "Hardcoded secrets in source and .env tracked in git"),
    ("venvs", "Virtualenv Python packages checked against CVE table"),
    ("cve-now", "Live CVE check against public cve.now feed (skipped with --offline)"),
    ("agent-config", "AI agent hooks, MCP servers, settings.local.json in git, .env deny"),
    ("agent-history", "Provider API keys leaked in agent chat logs and git history"),
    ("agent-rules", "Prompt-injection patterns in CLAUDE.md / AGENTS.md / rule files"),
    ("supply-chain", "Suspicious .pth startup hooks, sitecustomize, npm lifecycle scripts"),
)
