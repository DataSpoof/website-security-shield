# Website Security Shield: a Claude skill

**Protect any website from getting hacked — and run authorized penetration tests.** This skill makes Claude a website-security assistant for two audiences: owners who want to defend their site in plain language, and authorized pentesters / bug-bounty hunters who want advanced offensive methodology with the fix and detection for every technique.

It's built on OWASP Top 10:2025, the OWASP API Security Top 10, the OWASP Web Security Testing Guide (WSTG), OWASP Automated Threats, MITRE ATT&CK (T1190), CISA guidance, PTES, and the Verizon 2026 DBIR.

> **Authorized use only.** The offensive material is gated behind a signed engagement-scope file (or a published bug-bounty scope). The skill won't help attack systems you don't own or aren't authorized to test, and every exploitation technique is paired with its remediation and detection signature. Testing systems without authorization is illegal (CFAA, UK CMA, India IT Act and equivalents) regardless of intent.

## What it does

| You ask | Claude does |
|---|---|
| "Check my website https://mysite.com, I own it" | Non-intrusive external health check: HTTPS/TLS, certificate expiry, security headers, cookies, CORS, leaked files (`.env`, `.git`, backups, `phpinfo`), verbose errors, directory listing |
| "Review my project's code before launch" | Scans for hard-coded secrets and risky code (SQL injection, command/template injection, unsafe deserialization, SSRF, XSS, weak crypto, JWT/CORS mistakes), then manually checks access control, business logic and CI/CD |
| "I'm not technical, how do I stop my WordPress site getting hacked?" | A plain-language, step-by-step checklist with where-to-click instructions (also covers Shopify, Wix, Squarespace and Webflow) |
| "Help! My site redirects to a spam site" | Incident response in the right order: contain, preserve evidence, change passwords (email first), find the way in, clean up, get the Google warning removed, legal duties |
| "We're adding an AI chatbot. What are the risks?" | Prompt injection (direct and indirect), agent/tool abuse, RAG poisoning, cross-tenant leaks, output exfiltration, cost abuse |
| "Give me a full security plan" | P0/P1 hardening checklist covering identity, authorization, AppSec, APIs, secrets, cloud, detection and backups, with exact config values |
| "Pentest this / how would an attacker find and exploit vulns here?" (authorized) | Full WSTG-mapped methodology: recon → discovery → validation with safe PoC → chaining → report — **after** a signed scope file is in place |

Every report has the same parts: **bottom line**, **fix first** (Critical → Low), **attack chains**, **what's already good**, **what wasn't checked**, **how to verify each fix**, and **ongoing habits**.

## Advanced: authorized penetration testing

For professional pentesters and bug-bounty hunters, the skill adds a full offensive methodology — always gated behind authorization:

- **Authorization gate** — a signed [`engagement-scope.template.md`](plugins/website-security-shield/skills/website-security-shield/assets/engagement-scope.template.md) or published bounty scope is required before any active testing.
- **Recon & discovery** — passive OSINT then authorized active enumeration of the real attack surface.
- **Exploitation methodology** — per bug class (SQLi, XSS, SSRF, SSTI, IDOR/BOLA, XXE, deserialization, request smuggling, CORS, API, prototype pollution): discover → validate with a **minimal safe proof-of-concept** → assess impact → **remediate** → **detect**.
- **WAF & filter evasion** — to prove a control is inadequate, then fix it properly.
- **Auth/session testing** — OAuth/OIDC, SAML, JWT, MFA, password-reset and session flaws.
- **Business logic & chaining** — the flaws scanners miss, and turning small bugs into critical impact.
- **Tooling & legal labs** — Burp, ffuf, nuclei, sqlmap, etc., and PortSwigger Academy / HackTheBox / bug-bounty programs to practise legally.
- `pentest_checklist.py` generates a WSTG-mapped test checklist (sends no traffic).

Every offensive technique ships with its remediation and detection signature, so a pentest ends as a security *improvement*.

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
├── SKILL.md                          # workflow, modes, authorization gate, report format
├── references/
│   ├── attack-surface-catalog.md     # 70+ attack categories as threat → defense → verify
│   ├── hardening-checklist.md        # P0/P1 checklist with exact header/cookie/TLS values
│   ├── code-audit-guide.md           # insecure vs secure code patterns, framework settings
│   ├── owner-quick-wins.md           # plain-language checklist for non-technical owners
│   ├── infrastructure-and-cloud.md   # DNS, CDN, cloud IAM, containers, K8s, CI/CD, DDoS
│   ├── ai-llm-security.md            # prompt injection, RAG, agents, tool permissions
│   ├── incident-response.md          # "my site was hacked" playbook
│   ├── pentest-methodology.md        # [pentest] master: phases, gate, WSTG/PTES, reporting
│   ├── recon-and-discovery.md        # [pentest] OSINT + authorized active enumeration
│   ├── exploitation-methodology.md   # [pentest] per bug class: discover→PoC→impact→fix→detect
│   ├── waf-and-filter-evasion.md     # [pentest] proving a control is inadequate
│   ├── auth-session-testing.md       # [pentest] OAuth/OIDC/SAML/JWT/MFA/session
│   ├── business-logic-and-chaining.md# [pentest] logic flaws + chaining
│   └── tooling-and-labs.md           # [pentest] toolchain + legal practice labs
├── assets/
│   └── engagement-scope.template.md  # [pentest] signed scope that gates active testing
└── scripts/
    ├── site_check.py                 # non-intrusive external health check
    ├── code_scan.py                  # secret and risky-pattern scanner
    └── pentest_checklist.py          # WSTG-mapped checklist generator (sends no traffic)
```

## Responsible use

- **Defensive use only.** Test only websites you own or have written permission to test. `site_check.py` refuses to run without `--authorized`.
- The scripts send ordinary requests only: no exploit payloads, no brute force, no load testing.
- The skill never asks for your passwords and redacts any secrets it finds.
- No tool can prove a site is "unhackable". For high-value sites, also get an authorized penetration test.

## License

MIT. See [LICENSE](LICENSE).
