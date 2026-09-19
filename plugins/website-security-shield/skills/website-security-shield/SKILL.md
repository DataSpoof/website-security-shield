---
name: website-security-shield
description: Protect a website from getting hacked, and run authorized penetration tests against your own or in-scope targets. Audits a live website, its source code, CMS (WordPress, Shopify, Wix, etc.), APIs, hosting, DNS and cloud setup against a full attacker's-eye catalogue (OWASP Top 10:2025, OWASP API Security Top 10, OWASP WSTG, MITRE ATT&CK, CISA guidance), then gives a prioritized fix plan. For authorized pentesters and bug-bounty hunters it adds advanced methodology: recon and attack-surface discovery, per-bug-class exploitation with safe proof-of-concept, WAF/filter-evasion, auth/session/OAuth/JWT/MFA testing, business-logic and vulnerability chaining, all gated behind a signed engagement-scope file. Use this skill whenever a website owner, founder, developer, admin, pentester or bug-bounty hunter wants to secure, harden, protect, audit, or (with authorization) penetration-test a site, web app, online store or API; asks "can my site be hacked?", "how would an attacker find and exploit vulnerabilities here?", or "is my website safe?"; wants a security checklist or WSTG test plan; mentions security headers, SSL/HTTPS, login or admin security, SQL injection, XSS, CSRF, SSRF, IDOR, SSTI, bots, spam, DDoS, leaked API keys, plugins or backups; is adding an AI chatbot to their site; or thinks their site has been hacked, defaced or infected. Use it even if the person never says the word "security".
---

# Website Security Shield

This skill helps any website owner stop attackers before they get in. That includes a small-business owner with a WordPress site and an engineering team running an API on Kubernetes.

The approach: **think like an attacker, then defend like an owner.** Real breaches are rarely one bug. They are *chains*: recon finds a forgotten subdomain, an old plugin gives initial access, a leaked key gives the database. Each link might look minor. The chain is what causes the damage. Your job is to find the weak links in *this* site and help the owner break the chain in as many places as possible, easiest and most dangerous first.

Why this matters now: the Verizon 2026 DBIR reports that exploiting vulnerabilities (31% of breaches) has overtaken stolen credentials as the top way attackers get in, and that attackers increasingly use AI to move faster. So **patching, removing exposure and strong login protection** give the biggest return for almost every site.

## Ground rules

- **Everything here is for defense and *authorized* testing.** Two modes of use:
  - **Defensive audit (default):** on sites the person owns or manages. Confirm ownership before checking a live URL. The bundled `site_check.py`/`code_scan.py` are non-intrusive (normal HTTP requests, no attack payloads).
  - **Authorized penetration testing / bug bounty (advanced):** active testing — crafted input, fuzzing, auth attacks, proof-of-concept exploitation — is allowed **only** against targets covered by a signed engagement-scope file (`assets/engagement-scope.template.md`) or a published bug-bounty scope, within the agreed window and rules. See the authorization gate below and `references/pentest-methodology.md`.
- **Never help attack systems the person isn't authorized to test**, and never provide turnkey exploitation aimed at arbitrary third-party targets, mass exploitation, or persistence/data-theft that goes beyond proof. If authorization isn't established, give only passive/defensive guidance and explain what's needed (a scope file or ownership confirmation). Keep every proof-of-concept minimal and benign — prove the flaw, don't cause damage or exfiltrate real data.
- **Every offensive technique is paired with its fix and its detection signature.** A finding without remediation is half the job. That is what keeps this a security tool.
- **Never ask for passwords, API keys or tokens.** If you find a secret in code or config, redact it in your output (show only the first 4 characters). Tell the owner it must be **rotated**. Deleting it from the file isn't enough, because it stays in git history and may already be copied.
- **Be honest about coverage.** Never declare a site "secure" or "unhackable". Say what you checked, what you didn't, and what needs a human or a specialist. Scanners miss business-logic and authorization flaws, which are among the most damaging.
- **Match the person's level.** A shop owner needs "turn on two-factor login in your WordPress admin under Users → Profile". A developer needs the exact code or config change. If unsure, lead with plain language and put technical detail underneath.

## Step 1: Understand the site

Infer as much as you can before asking. If source code is in the working directory, read it: `package.json`, `requirements.txt`, `composer.json`, framework config, Dockerfiles, IaC, CI files. Ask only for what you can't find, in one short message:

1. **What access do we have?** A URL only, source code, hosting or cloud console, or a CMS admin panel.
2. **What is it built on?** A CMS or site builder (WordPress, Shopify, Wix, Squarespace, Webflow), or custom code (framework and language). Where is it hosted (shared hosting, VPS, AWS/Azure/GCP, Vercel/Netlify)?
3. **What does it handle?** User logins, payments, file uploads, personal data, a public API, an AI chatbot or RAG, several customers or tenants.
4. **Why now?** A routine check, a launch, a compliance need, or a suspicion of compromise.

What the site handles decides what matters. A static brochure site mostly needs good hosting, DNS, CMS and account hygiene. A multi-tenant SaaS with an AI agent needs everything.

## Step 2: Pick the mode(s)

| Situation | Mode | Start with |
|---|---|---|
| "I think I've been hacked", or defacement, spam redirects, unknown admins, a hosting suspension or a blacklist warning | **Incident** (do this first, before anything else) | `references/incident-response.md` |
| Non-technical owner, CMS or site-builder site | **Owner quick wins** | `references/owner-quick-wins.md` |
| We have a URL | **External health check** | `scripts/site_check.py` (see below) |
| We have source code | **Code audit** | `scripts/code_scan.py`, then `references/code-audit-guide.md` |
| Hosting, cloud, containers, CI/CD, DNS, CDN | **Infrastructure review** | `references/infrastructure-and-cloud.md` |
| Site has AI, LLM, RAG or agent features | **AI security review** | `references/ai-llm-security.md` |
| "Give me a full plan" or "make my site secure" | **Hardening plan** | `references/hardening-checklist.md` |
| "How would someone attack this?" or threat modelling | **Attack-surface map** | `references/attack-surface-catalog.md` |
| **Authorized penetration test / bug bounty**: "pentest this", "find and exploit vulns", "how would an attacker break in and how do I prove it?" | **Pentest** (requires the authorization gate below) | `references/pentest-methodology.md` |

Modes combine. A typical full review is: external check → code scan → manual code audit of risky areas → infrastructure → prioritized plan. A pentest is: authorization gate → recon → discovery → validation with safe PoC → chaining → report with remediation + detection.

### Authorization gate (before ANY active/offensive testing)

Active testing means anything beyond passive OSINT and the non-intrusive bundled scripts: crafted input, fuzzing, injection, auth attacks, proof-of-concept exploitation. Before providing or performing it against a specific target:

1. **Require a signed, in-date engagement-scope file** (`assets/engagement-scope.template.md`) or a **published bug-bounty scope**. If the user doesn't have one, offer the template and help them fill it — even for their own assets (it sets the rules and window). Don't proceed on a bare verbal claim.
2. Confirm the specific host/path is **in scope** and not excluded, and you're **inside the testing window** and rate limits.
3. Honor the **impact limits**: minimal benign PoC, no DoS unless explicitly authorized, no bulk data exfiltration, no destructive actions, no untracked persistence; any real credentials/customer data found is a stop-and-report.

If any of these isn't met, give only passive/defensive guidance and say what's needed. This gate is not optional and applies no matter how the request is framed. Full detail: `references/pentest-methodology.md`.

### Generating a pentest checklist

Planning aid only; sends no traffic:
```bash
python scripts/pentest_checklist.py --scope web    # or api / auth / infra
python scripts/pentest_checklist.py --scope api --target in-scope.example --tester "Name" --json
```
It emits a WSTG-mapped checklist pointing at the deep-dive references.

### Running the external health check

Only after the person confirms they own or manage the site:

```bash
python scripts/site_check.py https://example.com --authorized
python scripts/site_check.py https://example.com --authorized --json   # machine-readable
```

It checks the HTTPS redirect, certificate expiry, old TLS versions, security headers, cookie flags, CORS origin reflection, version banners, verbose error pages, directory listing, and about 25 commonly leaked files (`.env`, `.git/`, backups, `phpinfo`, debug endpoints). Content signatures reduce false positives. It uses only the Python standard library.

### Running the code scan

```bash
python scripts/code_scan.py path/to/project
python scripts/code_scan.py path/to/project --json
```

It flags hard-coded secrets (redacted) and risky patterns: SQL built from strings, shell execution, `eval`, unsafe deserialization, disabled TLS verification, wildcard CORS, debug mode, `innerHTML`, weak hashing, and JWT verification turned off. **These are leads, not verdicts.** Open each flagged line, check whether untrusted input actually reaches it, and drop false positives before reporting. Then do the manual review in `references/code-audit-guide.md`, because the most serious bug classes can't be found with grep: broken access control (IDOR/BOLA), missing role checks, mass assignment, business-logic abuse and race conditions.

Also run the ecosystem's dependency audit if available (`npm audit`, `pip-audit`, `composer audit`, `bundle audit`, `osv-scanner`). Vulnerable dependencies fall under OWASP A03:2025 (Software Supply Chain Failures).

## Step 3: Walk the attacker's path

Use the attacker lifecycle as a lens. For each stage, ask what this site gives away:

1. **Recon.** What can an outsider discover? Subdomains (dev, staging, old, admin), exposed services, JS bundles, API docs, source maps, version banners.
2. **Initial access.** Unpatched CMS, plugins, frameworks or servers. Injection, file upload, SSRF. Default or reused passwords. Exposed admin panels.
3. **Account takeover.** Credential stuffing, weak password reset or email change, weak MFA recovery, long-lived or leaked sessions and tokens.
4. **Authorization bypass.** Changing an ID in `/api/orders/1002` shows someone else's order. Hidden admin endpoints with no server-side role check.
5. **Execution and escalation.** Command or template injection, deserialization, over-privileged database users, service accounts or IAM roles.
6. **Lateral movement and persistence.** Web server → database → cloud metadata → other workloads. Backdoor admin accounts, API keys, web shells, OAuth apps, tampered CI pipelines.
7. **Impact.** Data theft, payment fraud, ransomware, defacement. Without logs or alerts, nobody notices for months.

Then check the layer map. Every layer is attack surface: **DNS · CDN/cache · WAF · load balancer/proxy · web server · frontend · authentication · authorization · API · business logic · database · files/uploads · WebSockets · OAuth/SSO · cloud · containers/Kubernetes · CI/CD · dependencies · secrets · third-party integrations · people (phishing) · AI/LLM/RAG · monitoring · backups/recovery.** Skip layers that don't exist for this site. Say which ones you skipped and why.

When you find several weaknesses, **describe the chain they form**. "The staging subdomain runs an old plugin → that gives file upload → the uploaded file can read `.env` → `.env` holds the production database password." Owners understand chains and prioritize them correctly.

## Step 4: Prioritize

Rate each finding by how easily it can be exploited and what the damage would be:

- **Critical.** Exploitable now by anyone on the internet, with serious impact. Examples: exposed `.env` or `.git`, a known-exploited CVE, SQL injection, a public database or bucket, a live secret in a public repo, no auth on admin or API. *Fix today.*
- **High.** Serious, but needs some condition. Examples: IDOR on user data, no MFA on admin accounts, weak password reset, SSRF with cloud metadata reachable, a CORS policy that reflects any origin with credentials. *Fix this week.*
- **Medium.** Defense-in-depth gaps that make other attacks easier. Examples: missing CSP or HSTS, verbose errors, missing rate limits, cookies without `HttpOnly`/`Secure`/`SameSite`, a version banner. *Fix this month.*
- **Low / informational.** Hygiene. Examples: no `security.txt`, minor information leakage. *Schedule.*

Then group the work using the control groups from the source research, P0 first:

- **P0 Identity:** MFA, password security, sessions, OAuth/OIDC, account recovery, privileged accounts.
- **P0 Authorization:** RBAC/ABAC, object- and function-level checks (BOLA/BFLA), tenant isolation.
- **P0 Internet exposure:** asset inventory, patching, CVE monitoring, exposed services, forgotten subdomains.
- **P0 Application security:** injection, XSS, SSRF, CSRF, file upload, deserialization, business logic, race conditions.
- **P0 API security:** authn/authz, rate limits, schema validation, resource limits, API inventory and versions.
- **P0 Secrets:** no secrets in git, a secret manager, rotation, short-lived credentials.
- **P1 Cloud:** IAM least privilege, segmentation, storage permissions, containers and Kubernetes, metadata protection.
- **P1 Detection:** central logs, auth monitoring, alerts on admin actions, error spikes and export spikes.
- **P1 Resilience:** tested offline backups, incident plan, DDoS protection, a kill switch.

## Step 5: Report

Use this structure. Keep it scannable. The owner should know what to do first within 30 seconds.

```markdown
# Website Security Report: <site>
_Date · Scope checked · Access used (URL / code / console)_

## Bottom line
2–4 sentences in plain language: overall risk, the single most urgent issue, and what to do today.

## Fix first (Critical & High)
| # | Issue | Why it matters (attacker's view) | How to fix | Effort |
|---|---|---|---|---|

## Attack chains found
(Only if multiple findings combine. Show the chain in one line each.)

## Next (Medium & Low)
Short table or checklist.

## What's already good
Credit real strengths. It builds trust and shows what to keep doing.

## Not checked / needs a specialist
Be explicit: e.g. business logic, authenticated areas, cloud console, penetration test.

## Ongoing habits
3–6 routines tailored to this site (updates, backups, MFA review, log alerts, quarterly re-check).
```

For each fix, give the concrete action: the exact setting, header value, code diff or command. Also give **how to verify it worked**, for example "re-run `site_check.py`; the HSTS line should turn to PASS". If the person asks you to apply fixes to their code, make small, targeted changes and explain each one.

Offer to save the report as a file (e.g. `security-report-<site>-<date>.md`) so they can track progress and re-run later.

## Reference files

Read only what the current mode needs:

- `references/attack-surface-catalog.md`: every attack category from the source research, by layer, as threat → defense → how to verify. Use it for threat modelling and to make sure nothing important is missed.
- `references/hardening-checklist.md`: the P0/P1 checklist with concrete config values (headers, cookies, TLS, rate limits, password and MFA policy).
- `references/code-audit-guide.md`: secure vs insecure code patterns per bug class, what to look for in code review, and dependency and secret scanning tools.
- `references/owner-quick-wins.md`: a plain-language checklist for non-technical owners and CMS or site-builder sites (WordPress specifics included).
- `references/infrastructure-and-cloud.md`: DNS, CDN/cache, proxies, cloud IAM, containers, Kubernetes, CI/CD, supply chain, DDoS and bots.
- `references/ai-llm-security.md`: prompt injection, RAG and agent threats, tool permissions, data leakage, multi-tenant isolation.
- `references/incident-response.md`: what to do when the site is (or might be) hacked.

**Advanced — authorized penetration testing** (read only in Pentest mode, after the authorization gate):

- `references/pentest-methodology.md`: master guide — engagement phases, the authorization gate, WSTG/PTES coverage, scoring, the report template, retest.
- `references/recon-and-discovery.md`: passive OSINT and authorized active enumeration to map the real attack surface.
- `references/exploitation-methodology.md`: per bug class — discover → validate with a minimal safe PoC → assess/escalate within scope → remediate → detect.
- `references/waf-and-filter-evasion.md`: why filters/WAFs fail, to prove a control is inadequate (and fix it properly).
- `references/auth-session-testing.md`: authentication, session, OAuth/OIDC, SAML, JWT and MFA testing.
- `references/business-logic-and-chaining.md`: the flaws scanners miss, and chaining small bugs into critical impact.
- `references/tooling-and-labs.md`: the standard toolchain and legal practice labs to build skill safely.
- `assets/engagement-scope.template.md`: the scope/authorization file that gates all active testing.
