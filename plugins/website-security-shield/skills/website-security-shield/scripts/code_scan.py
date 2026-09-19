#!/usr/bin/env python3
"""
code_scan.py - fast heuristic scan of a website's source code for leaked secrets and
risky patterns (injection sinks, unsafe deserialization, disabled TLS checks, debug
mode, weak crypto, permissive CORS, DOM XSS sinks, JWT verification disabled, ...).

Results are LEADS, not verdicts: read each flagged line and confirm whether untrusted
input really reaches it. Secrets are redacted in the output.

Standard library only. Python 3.8+.

Usage:
  python code_scan.py <path> [--json] [--max-findings 400]
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", "vendor", "venv", ".venv", "env", "__pycache__", "dist", "build",
             ".next", ".nuxt", "coverage", ".tox", ".mypy_cache", ".pytest_cache", "bower_components",
             "site-packages", ".idea", ".vscode", "target", "bin", "obj", ".terraform"}
CODE_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".php", ".rb", ".java", ".kt", ".go",
            ".cs", ".html", ".htm", ".vue", ".svelte", ".erb", ".twig", ".jinja", ".j2", ".ejs", ".hbs",
            ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties", ".tf",
            ".env", ".sh", ".ps1", ".sql", ".config", ".gradle"}
CONFIG_NAMES = {".env", ".env.local", ".env.production", ".env.prod", ".npmrc", ".pypirc", "dockerfile",
                "docker-compose.yml", "docker-compose.yaml", "web.config", "wp-config.php", "settings.py",
                ".htaccess", "nginx.conf"}
MAX_FILE_BYTES = 1_500_000

# (id, severity, category, regex, advice, flags)
SECRET_RULES = [
    ("aws-access-key", "CRITICAL", "Secret", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key. Rotate in IAM now, then move to a secret manager / IAM role."),
    ("private-key", "CRITICAL", "Secret", r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "Private key in source. Revoke/replace the key pair."),
    ("stripe-live", "CRITICAL", "Secret", r"\b[sr]k_live_[0-9a-zA-Z]{16,}\b", "Stripe live secret key. Roll it in the Stripe dashboard."),
    ("github-token", "CRITICAL", "Secret", r"\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{30,}\b|\bgithub_pat_[0-9A-Za-z_]{40,}\b", "GitHub token. Revoke it."),
    ("slack-token", "HIGH", "Secret", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "Slack token. Revoke it."),
    ("slack-webhook", "MEDIUM", "Secret", r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+", "Slack webhook URL. Regenerate it."),
    ("google-api-key", "HIGH", "Secret", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Google API key. Restrict or rotate it (check HTTP-referrer/API restrictions)."),
    ("openai-key", "CRITICAL", "Secret", r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b", "AI provider API key. Rotate it; never ship to frontend."),
    ("anthropic-key", "CRITICAL", "Secret", r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b", "Anthropic API key. Rotate it."),
    ("sendgrid-key", "HIGH", "Secret", r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b", "SendGrid key. Rotate it."),
    ("twilio-key", "HIGH", "Secret", r"\bSK[0-9a-fA-F]{32}\b", "Twilio API key. Rotate it."),
    ("db-url-with-password", "CRITICAL", "Secret", r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/'\"]+:[^@\s'\"]{3,}@", "Connection string with embedded password. Rotate DB password; load from env/secret manager."),
    ("generic-secret-assignment", "HIGH", "Secret",
     r"""(?i)\b(password|passwd|pwd|secret|secret_key|api_key|apikey|access_token|auth_token|client_secret|jwt_secret|private_key)\b\s*[:=]\s*['"][^'"\s]{8,}['"]""",
     "Hard-coded credential. Move to environment variables / secret manager and rotate."),
]

CODE_RULES = [
    # Injection
    ("sql-string-build", "HIGH", "SQL injection",
     r"""(?i)(execute|query|raw|exec|prepare)\s*\(\s*(f['"]|['"][^'"]*\b(select|insert|update|delete)\b[^'"]*['"]\s*(\+|%|\.format|\.))|['"]\s*(select|insert into|update|delete from)\b[^'"]*['"]\s*\.\s*\$_(get|post|request|cookie)""",
     "SQL built from strings. Use parameterized queries / ORM."),
    ("sql-fstring", "HIGH", "SQL injection", r"""(?i)f['"]\s*(select|insert\s+into|update|delete\s+from)\b[^'"]*\{""", "f-string SQL. Use parameters (%s / ?) instead."),
    ("sql-template-literal", "HIGH", "SQL injection", r"""(?i)`\s*(select|insert\s+into|update|delete\s+from)\b[^`]*\$\{""", "Template-literal SQL. Use placeholders ($1 / ?)."),
    ("php-superglobal-query", "CRITICAL", "SQL injection", r"""(?i)(mysqli?_query|->query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)""", "Request data in query. Use PDO prepared statements."),
    ("os-command", "HIGH", "Command injection", r"""\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output)\([^)]*shell\s*=\s*True|child_process\.exec(Sync)?\s*\(|\bexec\s*\(\s*[`'"][^)]*\$\{|shell_exec\s*\(|passthru\s*\(|proc_open\s*\(|Runtime\.getRuntime\(\)\.exec)""", "Shell execution. Use argument arrays, never pass user input to a shell."),
    ("php-system", "HIGH", "Command injection", r"""\b(system|exec|popen)\s*\(\s*\$""", "PHP command execution with a variable. Validate/allow-list or avoid."),
    ("eval", "HIGH", "Code injection", r"""(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*['"`]""", "Dynamic code evaluation. Remove; never evaluate user-influenced strings."),
    ("template-from-string", "HIGH", "Template injection", r"""render_template_string\s*\(|Template\s*\(\s*(request|req)\.|Environment\([^)]*\)\.from_string\(""", "Template compiled from a string. Pass user data as variables instead."),
    # Deserialization / XML
    ("pickle-loads", "HIGH", "Deserialization", r"""\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|\bdill\.loads?\s*\(""", "Unsafe deserialization if data is untrusted. Use JSON."),
    ("yaml-load", "HIGH", "Deserialization", r"""\byaml\.load\s*\((?![^)]*SafeLoader)""", "Use yaml.safe_load()."),
    ("php-unserialize", "HIGH", "Deserialization", r"""\bunserialize\s*\(\s*\$""", "Use json_decode for untrusted data."),
    ("java-deser", "MEDIUM", "Deserialization", r"""ObjectInputStream\s*\(|\.readObject\s*\(""", "Java native deserialization. Never on untrusted input."),
    ("xml-unsafe", "MEDIUM", "XXE", r"""\b(etree\.fromstring|etree\.parse|minidom\.parse(String)?|xml\.sax\.parse)\s*\(|resolve_entities\s*=\s*True|DocumentBuilderFactory\.newInstance\(\)|libxml_disable_entity_loader\s*\(\s*false""", "XML parsing. Disable DTD/external entities (use defusedxml in Python)."),
    # XSS / client side
    ("dom-xss-sink", "MEDIUM", "XSS", r"""\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|v-html\s*=|\{\{\{|\|\s*safe\b|\{!!|mark_safe\s*\(|Markup\s*\(|html_safe\b|\braw\s*\(""", "Raw HTML sink. Ensure input is sanitized (DOMPurify/bleach) or use text APIs."),
    ("open-redirect", "MEDIUM", "Open redirect", r"""(?i)redirect\s*\(\s*(request\.(args|GET|params|query)|req\.(query|params|body))|header\s*\(\s*['"]Location:\s*['"]\s*\.\s*\$_(GET|REQUEST)""", "Redirect to user-supplied URL. Allow-list or relative paths only."),
    ("ssrf-candidate", "MEDIUM", "SSRF", r"""(requests\.(get|post)|urllib\.request\.urlopen|httpx\.(get|post)|axios\.(get|post)|fetch|file_get_contents|curl_setopt\([^,]+,\s*CURLOPT_URL)\s*\(?\s*(request\.|req\.(query|body|params)|\$_(GET|POST|REQUEST))""", "Server fetches a user-supplied URL. Add allow-list + block private/metadata IPs."),
    ("path-traversal", "MEDIUM", "Path traversal", r"""(open|send_file|sendFile|readFile(Sync)?|file_get_contents|include|require(_once)?|fopen)\s*\(\s*[^)]*(request\.|req\.(query|params|body)|\$_(GET|POST|REQUEST))""", "File path from user input. Canonicalize and confine to a base directory."),
    # Config / crypto
    ("debug-on", "HIGH", "Misconfiguration", r"""(?i)^\s*(DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|app\.run\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|display_errors\s*=\s*(On|1)|WP_DEBUG'\s*,\s*true)""", "Debug mode enabled. Ensure it is off in production."),
    ("tls-verify-off", "HIGH", "Crypto", r"""verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|ServerCertificateValidationCallback""", "TLS certificate verification disabled. Re-enable."),
    ("weak-password-hash", "HIGH", "Crypto", r"""(?i)(md5|sha1)\s*\(\s*\$?\w*pass|hashlib\.(md5|sha1)\s*\([^)]*pass|createHash\(\s*['"](md5|sha1)['"]\s*\)[^;]*pass""", "Weak password hashing. Use Argon2id or bcrypt."),
    ("insecure-random-token", "MEDIUM", "Crypto", r"""(?i)(token|secret|otp|reset|nonce|session)\w*\s*=\s*[^;\n]*(Math\.random\(\)|random\.random\(\)|random\.randint\(|\brand\(|mt_rand\()""", "Predictable randomness for a security token. Use crypto.randomBytes / secrets module / random_bytes."),
    ("jwt-no-verify", "HIGH", "Authentication", r"""verify_signature['"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[\s*['"]none['"]|\bjwt\.decode\s*\(\s*\w+\s*\)""", "JWT not verified. Use jwt.verify / decode with key, pinned algorithms, iss/aud checks."),
    ("cors-wildcard-creds", "HIGH", "CORS", r"""origin\s*:\s*(true|['"]\*['"])[^}]*credentials\s*:\s*true|CORS_ALLOW_ALL_ORIGINS\s*=\s*True|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|allow_origins\s*=\s*\[\s*['"]\*['"]\s*\][^)]*allow_credentials\s*=\s*True""", "Overly permissive CORS. Use an explicit origin allow-list."),
    ("cors-wildcard", "LOW", "CORS", r"""Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*""", "Wildcard CORS. OK only for public, unauthenticated data."),
    ("csrf-disabled", "MEDIUM", "CSRF", r"""@csrf_exempt|skip_before_action\s*:verify_authenticity_token|csrf\(\)\.disable\(\)|WTF_CSRF_ENABLED\s*=\s*False""", "CSRF protection disabled. Justify (e.g. signed webhook) or re-enable."),
    ("mass-assignment", "MEDIUM", "Access control", r"""\$guarded\s*=\s*\[\s*\]|\.(update|create|save|insert)\(\s*req\.body\s*[,)]|Object\.assign\(\s*\w+\s*,\s*req\.body\s*\)|\*\*request\.(json|data|POST)|permit!""", "Request body bound directly to a model. Allow-list fields explicitly."),
    ("cookie-insecure", "LOW", "Session", r"""(?i)(SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE)\s*=\s*False|httpOnly\s*:\s*false|secure\s*:\s*false""", "Insecure cookie setting. Use Secure + HttpOnly + SameSite."),
    ("allowed-hosts-any", "MEDIUM", "Misconfiguration", r"""ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]""", "Any Host header accepted (password-reset poisoning risk)."),
    ("graphql-introspection", "LOW", "API", r"""introspection\s*:\s*true""", "GraphQL introspection enabled. Disable in production."),
    ("prototype-pollution", "LOW", "Prototype pollution", r"""\[\s*['"]__proto__['"]\s*\]|merge\([^)]*req\.body|_\.merge\([^)]*req\.""", "Deep merge of user input. Block __proto__/constructor keys."),
]


def compile_rules(rules):
    out = []
    for rid, sev, cat, rx, advice in rules:
        out.append((rid, sev, cat, re.compile(rx, re.MULTILINE), advice))
    return out


SECRETS = compile_rules(SECRET_RULES)
ENV_SECRET = re.compile(r"(?im)^\s*(export\s+)?[A-Z0-9_.]*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY)[A-Z0-9_.]*\s*[=:]\s*['\"]?([^\s#'\"]{6,})")
ENV_LIKE_EXT = {".env", ".ini", ".properties", ".cfg", ".conf", ".toml"}
CODE = compile_rules(CODE_RULES)
PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]?|xxx+|placeholder|dummy|sample|<.*>|\$\{|%\(|process\.env|os\.environ|getenv|env\(|config\[|settings\.|\*\*\*)")
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def redact(s):
    s = s.strip()
    return (s[:4] + "…[REDACTED]") if len(s) > 4 else "[REDACTED]"


def is_test_path(path):
    p = path.replace("\\", "/").lower()
    return any(t in p for t in ("/test/", "/tests/", "/__tests__/", "/spec/", "/fixtures/", "/mocks/", ".test.", ".spec.", "_test."))


def scan_file(path, rel, findings):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return
    if "\x00" in text[:2048]:
        return
    lines = text.splitlines()
    test = is_test_path(rel)
    minified = rel.endswith(".min.js") or (lines and max(len(l) for l in lines[:50]) > 2000)

    for rid, sev, cat, rx, advice in SECRETS:
        for m in rx.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            if rid == "generic-secret-assignment" and PLACEHOLDER.search(m.group(0)):
                continue
            findings.append({"file": rel, "line": line_no, "rule": rid, "severity": "MEDIUM" if test else sev,
                             "category": cat, "match": redact(m.group(0)), "advice": advice,
                             "note": "in test/fixture path" if test else ""})
    base = os.path.basename(rel).lower()
    if base.startswith(".env") or os.path.splitext(base)[1] in ENV_LIKE_EXT:
        for m in ENV_SECRET.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            if PLACEHOLDER.search(m.group(3)):
                continue
            findings.append({"file": rel, "line": line_no, "rule": "config-file-secret",
                             "severity": "MEDIUM" if (test or ".example" in base or ".sample" in base) else "HIGH",
                             "category": "Secret", "match": redact(m.group(0)),
                             "advice": "Secret in config file. Keep it out of git and the web root; use a secret manager; rotate if exposed.",
                             "note": ""})
    if minified:
        return
    for rid, sev, cat, rx, advice in CODE:
        for m in rx.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = lines[line_no - 1].strip() if line_no - 1 < len(lines) else ""
            if line.startswith(("#", "//", "*", "/*", "<!--")):
                continue
            findings.append({"file": rel, "line": line_no, "rule": rid, "severity": "LOW" if test else sev,
                             "category": cat, "match": line[:160], "advice": advice,
                             "note": "in test path" if test else ""})


def project_checks(root, findings):
    gi = os.path.join(root, ".gitignore")
    ignored = ""
    if os.path.exists(gi):
        with open(gi, encoding="utf-8", errors="ignore") as f:
            ignored = f.read()
    for name in (".env", ".env.production", ".env.prod", ".env.local"):
        if os.path.exists(os.path.join(root, name)) and ".env" not in ignored:
            findings.append({"file": name, "line": 0, "rule": "env-not-gitignored", "severity": "HIGH",
                             "category": "Secret", "match": "", "note": "",
                             "advice": "Add .env* to .gitignore; if it was ever committed, rotate every secret in it."})
    lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum"]
    manifests = ["package.json", "pyproject.toml", "Pipfile", "composer.json", "Gemfile", "go.mod"]
    if any(os.path.exists(os.path.join(root, m)) for m in manifests) and not any(os.path.exists(os.path.join(root, l)) for l in lockfiles):
        findings.append({"file": "(project)", "line": 0, "rule": "no-lockfile", "severity": "LOW", "category": "Supply chain",
                         "match": "", "note": "", "advice": "Commit a lockfile so builds use reviewed dependency versions."})
    wf = os.path.join(root, ".github", "workflows")
    if os.path.isdir(wf):
        for fn in os.listdir(wf):
            try:
                with open(os.path.join(wf, fn), encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            for i, line in enumerate(content.splitlines(), 1):
                m = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@([\w.-]+)", line)
                if m and not m.group(1).startswith(("actions/", "github/")) and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
                    findings.append({"file": f".github/workflows/{fn}", "line": i, "rule": "action-not-pinned", "severity": "LOW",
                                     "category": "Supply chain", "match": line.strip()[:160], "note": "",
                                     "advice": "Pin third-party GitHub Actions to a full commit SHA."})
            if "pull_request_target" in content and "actions/checkout" in content:
                findings.append({"file": f".github/workflows/{fn}", "line": 0, "rule": "pr-target-checkout", "severity": "MEDIUM",
                                 "category": "CI/CD", "match": "", "note": "",
                                 "advice": "pull_request_target + checkout can run untrusted fork code with secrets. Review carefully."})


def main():
    ap = argparse.ArgumentParser(description="Heuristic secret & risky-pattern scan for website source code.")
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--max-findings", type=int, default=400)
    a = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    root = os.path.abspath(a.path)
    if not os.path.isdir(root):
        print(f"Not a directory: {root}")
        sys.exit(2)

    findings, files = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            if ext in CODE_EXT or fn.lower() in CONFIG_NAMES or fn.lower().startswith(".env"):
                if fn.endswith((".lock", "-lock.json", ".map")) or fn in ("package-lock.json",):
                    continue
                full = os.path.join(dirpath, fn)
                files += 1
                scan_file(full, os.path.relpath(full, root), findings)
    project_checks(root, findings)

    seen, deduped = set(), []
    for f in sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9)):
        k = (f["file"], f["line"], f["category"]) if f["line"] else (f["file"], f["rule"])
        if k not in seen:
            seen.add(k)
            deduped.append(f)
    findings = deduped
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["category"], f["file"], f["line"]))
    total = len(findings)
    shown = findings[: a.max_findings]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}

    if a.json:
        print(json.dumps({"root": root, "files_scanned": files, "total_findings": total, "summary": counts,
                          "findings": shown}, indent=2, ensure_ascii=False))
        return

    print(f"\nCode security scan: {root}")
    print(f"Files scanned: {files}  |  Findings: {total}  |  " + "  ".join(f"{k}:{v}" for k, v in counts.items() if v))
    print("-" * 78)
    for f in shown:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        note = f" ({f['note']})" if f["note"] else ""
        print(f"[{f['severity']:<8}] {f['category']} · {f['rule']}{note}\n            {loc}")
        if f["match"]:
            print(f"            > {f['match']}")
        print(f"            {f['advice']}")
    if total > len(shown):
        print(f"... {total - len(shown)} more (use --max-findings or --json)")
    print("-" * 78)
    print("Heuristic leads only: confirm each by reading the code. This scan cannot find broken")
    print("access control (IDOR/BOLA), missing role checks, or business-logic flaws; review those manually.")


if __name__ == "__main__":
    main()
