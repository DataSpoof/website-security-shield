# Website Security Shield: a Claude skill

**Protect any website from getting hacked.** This skill makes Claude a defensive website-security assistant. It looks at your site the way an attacker would, then gives you a prioritized fix plan in plain language.

It's built on OWASP Top 10:2025, the OWASP API Security Top 10, OWASP Automated Threats, MITRE ATT&CK (T1190), CISA guidance, and the Verizon 2026 DBIR.

## What it does

| You ask | Claude does |
|---|---|
| "Check my website https://mysite.com, I own it" | Non-intrusive external health check: HTTPS/TLS, certificate expiry, security headers, cookies, CORS, leaked files (`.env`, `.git`, backups, `phpinfo`), verbose errors, directory listing |
| "Review my project's code before launch" | Scans for hard-coded secrets and risky code (SQL injection, command/template injection, unsafe deserialization, SSRF, XSS, weak crypto, JWT/CORS mistakes), then manually checks access control, business logic and CI/CD |
| "I'm not technical, how do I stop my WordPress site getting hacked?" | A plain-language, step-by-step checklist with where-to-click instructions (also covers Shopify, Wix, Squarespace and Webflow) |
| "Help! My site redirects to a spam site" | Incident response in the right order: contain, preserve evidence, change passwords (email first), find the way in, clean up, get the Google warning removed, legal duties |
| "We're adding an AI chatbot. What are the risks?" | Prompt injection (direct and indirect), agent/tool abuse, RAG poisoning, cross-tenant leaks, output exfiltration, cost abuse |
| "Give me a full security plan" | P0/P1 hardening checklist covering identity, authorization, AppSec, APIs, secrets, cloud, detection and backups, with exact config values |

Every report has the same parts: **bottom line**, **fix first** (Critical → Low), **attack chains**, **what's already good**, **what wasn't checked**, **how to verify each fix**, and **ongoing habits**.

## Install

### Claude Code (plugin marketplace)
```
/plugin marketplace add DataSpoof/website-security-shield
/plugin install website-security-shield@dataspoof-skills
```

### Claude app (claude.ai / desktop)
1. Download `website-security-shield.skill` from the [latest release](https://github.com/DataSpoof/website-security-shield/releases/latest).
2. Open it in the Claude app and click **Save skill**, or upload it under **Settings → Capabilities → Skills**.

### Manual (Claude Code personal skills)
```bash
git clone https://github.com/DataSpoof/website-security-shield.git
cp -r website-security-shield/plugins/website-security-shield/skills/website-security-shield ~/.claude/skills/
```

## Use it

Just ask in normal words. The skill triggers automatically on website-security questions. In Claude Code you can also call it directly with `/website-security-shield`.

The two bundled scripts need only Python 3.8+ and have no dependencies:
```bash
# External check. Only run it on sites you own or are authorized to test.
python scripts/site_check.py https://yoursite.com --authorized

# Code scan (secrets are redacted in the output)
python scripts/code_scan.py path/to/project
```
Add `--json` to either script for machine-readable output.

## What's inside
```
skills/website-security-shield/
├── SKILL.md                         # workflow, modes, prioritization, report format
├── references/
│   ├── attack-surface-catalog.md    # 70+ attack categories as threat → defense → verify
│   ├── hardening-checklist.md       # P0/P1 checklist with exact header/cookie/TLS values
│   ├── code-audit-guide.md          # insecure vs secure code patterns, framework settings, tools
│   ├── owner-quick-wins.md          # plain-language checklist for non-technical owners
│   ├── infrastructure-and-cloud.md  # DNS, CDN, cloud IAM, containers, K8s, CI/CD, DDoS
│   ├── ai-llm-security.md           # prompt injection, RAG, agents, tool permissions
│   └── incident-response.md         # "my site was hacked" playbook
└── scripts/
    ├── site_check.py                # non-intrusive external health check
    └── code_scan.py                 # secret and risky-pattern scanner
```

## Responsible use

- **Defensive use only.** Test only websites you own or have written permission to test. `site_check.py` refuses to run without `--authorized`.
- The scripts send ordinary requests only: no exploit payloads, no brute force, no load testing.
- The skill never asks for your passwords and redacts any secrets it finds.
- No tool can prove a site is "unhackable". For high-value sites, also get an authorized penetration test.

## License

MIT. See [LICENSE](LICENSE).
