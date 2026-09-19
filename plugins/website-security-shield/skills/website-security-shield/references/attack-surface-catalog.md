# Attack-Surface Catalogue: Threat → Defense → Verify

Condensed from research using OWASP Top 10:2025, OWASP API Security Top 10 (2023), OWASP Automated Threats, MITRE ATT&CK (T1190 Exploit Public-Facing Application), CISA advisories, the Verizon 2026 DBIR, and PortSwigger Web Security Academy.

Each entry has three parts: **Threat** (what the attacker does), **Defend** (the control), and **Verify** (how the owner confirms the control works). The OWASP 2025 mapping is in brackets.

## Contents
1. Recon & exposure
2. Identity: authentication, sessions, MFA, account takeover
3. Authorization & access control
4. Injection & server-side execution
5. Request/response-level web attacks
6. Files & document processing
7. APIs
8. Business logic & race conditions
9. Client side / browser
10. Supply chain, CI/CD, secrets
11. Infrastructure: DNS, CDN, cache, proxies, TLS
12. Cloud, containers, Kubernetes, databases
13. Automated threats: bots, scraping, payment fraud, DoS
14. People & third parties
15. AI / LLM / RAG
16. Post-compromise: persistence, lateral movement, exfiltration, ransomware
17. Detection & exceptional conditions
18. Enterprise layer matrix

---

## 1. Recon & exposure [A02 Security Misconfiguration]

**Subdomain & asset discovery.** *Threat:* attackers enumerate `dev.`, `staging.`, `old.`, `admin.`, `api.`, `beta.`, `files.`, `internal.` hosts through certificate-transparency logs, DNS brute force and search engines. Forgotten environments run old code with default credentials. *Defend:* keep an asset inventory, decommission unused hosts, put non-production environments behind VPN/SSO/IP allow-lists, and never use production data in staging. *Verify:* search crt.sh for `%.yourdomain.com` and confirm every result is known, patched and owned.

**Technology fingerprinting.** *Threat:* banners (`Server: nginx/1.18.0`, `X-Powered-By: PHP/7.4`), meta generator tags, JS bundles and error pages reveal exact versions, which attackers match to CVEs. *Defend:* strip version headers and generator tags. Hiding versions only buys time, so patching is still the real fix. *Verify:* `site_check.py` "Information leakage" section.

**Vulnerability scanning by attackers.** *Threat:* automated scanners sweep the internet for known CVEs, default credentials, exposed debug interfaces, open directories, weak TLS and missing headers within hours of a CVE being published. *Defend:* patch fast (internet-facing criticals within days), enable auto-updates for CMS and plugins where safe, subscribe to vendor advisories and the CISA KEV catalogue, and use a WAF with managed rules. *Verify:* dependency audit tools, CMS update page, CISA KEV cross-check.

**Information disclosure.** *Threat:* stack traces, debug endpoints, source maps, backup files (`.bak`, `.zip`, `.sql`), `.git/`, `.env`, internal hostnames, monitoring endpoints (`/actuator`, `/server-status`, `/metrics`), public API docs. *Defend:* generic error pages in production, debug mode off, source maps not public, block dotfiles at the web server, keep backups outside the web root, and protect admin and monitoring endpoints behind auth. *Verify:* `site_check.py` sensitive-path and error-page checks.

**Security misconfiguration (A02:2025).** *Threat:* `DEBUG=True`, default passwords, public storage buckets, open admin panels, unused services, weak CORS, missing headers, verbose errors, old TLS. These need no sophisticated exploit. *Defend:* a hardened, repeatable config (IaC), a minimal install, and a config review in the release checklist. *Verify:* `site_check.py`, `code_scan.py`, cloud security posture tools.

## 2. Identity [A07 Authentication Failures]

**Password attacks.** *Threat:* brute force, dictionary, password spraying (one common password across many users), credential stuffing (breached username/password pairs), default passwords. *Defend:* rate limit and progressively delay logins per account and per IP, bot detection or CAPTCHA after failures, check passwords against breached lists (e.g. HIBP k-anonymity API), minimum length 12+ with no forced complexity rotation, MFA, and alerts on login failure spikes. *Verify:* try 10 wrong passwords on a test account and confirm throttling appears. Confirm "Password123" is rejected.

**Account takeover chains.** *Threat:* leaked credential → login → change email → change password → disable recovery. Attackers target password reset, email and phone change, MFA recovery, backup codes, security questions, OAuth links, API tokens. *Defend:* require re-authentication (password plus MFA) for email, phone, password and MFA changes. Notify the *old* email on changes. Use single-use, short-lived (≤30 min), high-entropy reset tokens. Build reset links from a configured base URL, never from the Host header. Use the same response whether or not the account exists. *Verify:* walk through each recovery flow as an attacker holding only the password.

**Session attacks.** *Threat:* predictable IDs, sessions that never expire, no rotation on login (session fixation), token leakage in URLs or logs, insecure cookies, incorrect JWT validation, weak signing keys. *Defend:* framework session management, rotate the session ID at login and privilege change, idle and absolute timeouts, server-side logout invalidation, and cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`). Never put tokens in URLs. *Verify:* `site_check.py` cookie section. Log out, replay the old cookie, and it must fail.

**MFA attacks.** *Threat:* MFA fatigue (push spam), OTP brute force, OTP reuse, SIM swap, backup-code theft, session hijack after MFA, weak recovery. *Strong password + weak recovery = weak authentication.* *Defend:* number-matching push, rate-limited single-use OTPs, prefer passkeys/WebAuthn or TOTP over SMS, recovery at least as strong as login, and alerts on MFA changes. *Verify:* review every "lost my phone" path.

**Authentication providers / SSO (Auth0, Okta, Entra, Cognito, SAML).** *Threat:* misconfigured federation, token validation gaps, account linking by unverified email, weak recovery at the IdP. *Defend:* validate issuer, audience, signature and expiry. Link accounts only on verified email. Harden the IdP admin with MFA. *Verify:* IdP configuration review.

## 3. Authorization [A01 Broken Access Control, the #1 risk]

**IDOR / BOLA.** *Threat:* user 456 changes `/api/users/123/profile` or `/api/orders/1002` and sees someone else's data. *Defend:* every request that references an object checks on the server that the current user owns it or may access it. Scope queries (`WHERE id = ? AND owner_id = ?`). Random IDs help but are **not** a control. *Verify:* use two test accounts. With A's session, request B's object IDs on every endpoint. Each must return 403/404.

**Privilege escalation / BFLA.** *Threat:* hidden admin endpoints, UI-only role checks, manipulated `role` fields, weak JWT claims, API/UI mismatch. *Defend:* deny by default, enforce roles on the server for every function, keep admin APIs on a separate path with central middleware, and never trust client-side role claims unless they come from a verified signed token. *Verify:* call admin endpoints with a normal user's token.

**Multi-tenant isolation.** *Threat:* cross-tenant database rows, shared cache keys, S3 prefixes, vector-DB namespaces, Redis keys, wrong tenant context. *Defend:* treat tenant isolation as a first-class security boundary. Derive the tenant from the authenticated session, never from the request body. Use DB row-level security or per-tenant schemas, tenant-prefixed cache and storage keys, and automated cross-tenant tests. *Verify:* run the two-tenant test suite in CI.

## 4. Injection & server-side execution [A05 Injection]

**SQL injection.** *Threat:* untrusted input concatenated into queries, which leads to data theft, modification, auth bypass or DB takeover. *Defend:* parameterized queries or ORM everywhere, allow-lists for dynamic identifiers (sort columns), and a least-privilege DB user. *Verify:* `code_scan.py` SQL rules plus code review.

**NoSQL injection.** *Threat:* operator injection (`{"$ne": null}`) in MongoDB and similar. *Defend:* validate types with a schema so strings stay strings, and reject `$` keys in user input.

**OS command injection.** *Threat:* input reaches a shell. *Defend:* avoid shelling out. Use argument arrays (`subprocess.run([...])` without `shell=True`, `execFile`) and allow-list inputs.

**Server-side template injection (Jinja, Twig, Freemarker, Velocity).** *Threat:* user input compiled *as a template*, which can lead to RCE. *Defend:* pass user data as template variables and never build template source from input (`render_template_string(user_input)` is the red flag). Sandbox if unavoidable.

**LDAP, XPath, Expression Language injection.** *Defend:* use parameterized or escaped APIs for each query language, and never evaluate expressions built from input.

**GraphQL abuse.** *Threat:* introspection mapping the schema, deep or nested queries (DoS), batching to bypass rate limits, field-level authorization gaps. *Defend:* disable introspection in production, limit depth, complexity and batching, and authorize at the resolver level.

**Deserialization.** *Threat:* `pickle`, Java native serialization, PHP `unserialize`, unsafe YAML on untrusted data, which leads to RCE or auth bypass. *Defend:* use JSON with schema validation, `yaml.safe_load`, and never deserialize untrusted native objects. Sign data if you must round-trip it.

**Prototype pollution (JavaScript).** *Threat:* `__proto__` or `constructor.prototype` keys merged into objects, chained to XSS or RCE. *Defend:* reject those keys, use `Object.create(null)` or `Map`, use safe merge libraries, and keep lodash and others patched.

## 5. Request / response-level web attacks

**XSS (stored, reflected, DOM).** *Threat:* attacker script runs in a victim's browser and steals sessions or performs actions. *Defend:* auto-escaping templates, avoid `innerHTML`, `dangerouslySetInnerHTML`, `v-html` and `document.write` with untrusted data, sanitize rich HTML with DOMPurify, set a strict CSP (nonces/hashes, no `unsafe-inline`), and `HttpOnly` cookies. *Verify:* CSP header present, code scan of DOM sinks.

**CSRF.** *Threat:* a victim's browser is tricked into changing email or password, transferring money, deleting the account or creating an API key. *Defend:* `SameSite` cookies, CSRF tokens on state-changing requests, `Origin`/`Referer` validation, and no state changes on GET.

**CORS misconfiguration.** *Threat:* the API reflects any `Origin` with `Access-Control-Allow-Credentials: true`, or trusts `null` or broad regexes, so evil sites read authenticated data. *Defend:* an explicit allow-list of exact origins, and never `*` with credentials. *Verify:* `site_check.py` CORS check.

**SSRF [API7].** *Threat:* the server fetches attacker-supplied URLs, reaching internal APIs, admin panels or cloud metadata (`169.254.169.254`), which leads to stolen cloud credentials. *Defend:* allow-list destinations, resolve DNS and block private, link-local and loopback ranges (recheck after redirects), use an egress proxy, and enforce IMDSv2 on AWS.

**XXE.** *Threat:* XML external entities lead to local file read, SSRF or DoS. *Defend:* disable DTDs and external entities in every XML parser (use `defusedxml` in Python).

**Path traversal.** *Threat:* `../../etc/passwd` or `..\\` in filenames, which exposes config, source or credentials. *Defend:* map IDs to files server-side, canonicalize and check the path stays inside the base directory, and never pass raw filenames through.

**HTTP request smuggling.** *Threat:* CDN, load balancer, proxy and app disagree on request boundaries (`Content-Length` vs `Transfer-Encoding`, HTTP/2 downgrade). *Defend:* HTTP/2 end-to-end where possible, normalize or reject ambiguous requests at the edge, and keep proxies patched.

**Web cache poisoning & deception.** *Threat:* unkeyed headers poison cached pages, or `/account/profile.css` tricks the cache into storing private pages. *Defend:* cache only static paths, set `Cache-Control: private, no-store` on authenticated responses, and don't reflect unkeyed headers.

**Host-header attacks.** *Threat:* password-reset poisoning, cache poisoning, bad URL generation. *Defend:* configure allowed hosts (e.g. Django `ALLOWED_HOSTS`) and build absolute URLs from config.

**Open redirects.** *Threat:* `?next=https://evil.com` used for phishing and OAuth token theft. *Defend:* allow only relative paths or an allow-list of destinations.

## 6. Files & document processing

**File upload.** *Threat:* dangerous types (`.php`, `.jsp`, `.svg` with script, `.html`), MIME spoofing, filename tricks (`shell.php.jpg`, null bytes), path traversal, overwriting files, executable upload directories, image-parser bugs, archive extraction. *Defend:* allow-list extensions *and* check content (magic bytes), rename to random names, store outside the web root or in object storage served from a separate cookieless domain, disable script execution in upload directories, cap sizes, re-encode images, and malware-scan.

**Document parsers (PDF, DOCX, XLSX, images, ZIP, XML, CSV, email).** *Threat:* parser CVEs, XXE, decompression bombs, macros, embedded scripts, zip-slip. *Defend:* patched libraries, sandboxed or isolated workers with time and memory limits, archive entry path validation, and limits on extracted size and file count.

**CSV / formula injection.** *Threat:* exported cells beginning with `=`, `+`, `-`, `@` run as formulas in Excel (CRM, finance, admin exports). *Defend:* prefix such cells with `'` on export.

## 7. APIs [OWASP API Security Top 10]

API1 BOLA · API2 Broken Authentication · API3 Broken Object *Property* Level Authorization (mass assignment and over-exposed fields) · API4 Unrestricted Resource Consumption · API5 Broken Function Level Authorization · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.

- **Enumeration & inventory.** Attackers find `/api/v1/admin`, `/api/internal/*` and old `/v1` endpoints through JS bundles, mobile apps, OpenAPI files and error messages. *Defend:* keep an API inventory, retire old versions, and make sure internal APIs aren't internet-routable.
- **Mass assignment.** Client sends `{"name":"A","role":"admin","balance":99999}`. *Defend:* explicit allow-listed DTOs/serializers per endpoint, and never bind raw request bodies to models.
- **Excessive data exposure.** Returning full DB objects and relying on the frontend to hide fields. *Defend:* response schemas that include only needed fields.
- **Resource exhaustion.** Huge payloads, big page sizes, deep GraphQL queries, bulk ops, report, PDF, image or AI generation, SMS or email sends (cost attacks). *Defend:* rate limits per user, key and IP, max body size, pagination caps, timeouts, quotas, and cost budgets and alerts on paid APIs.
- **Unsafe consumption of third-party APIs.** *Defend:* validate and sanitize their responses like user input, use TLS, apply timeouts, and don't follow redirects blindly.
- **WebSockets.** Missing auth on connect, no per-message authorization, cross-site WebSocket hijacking (check `Origin`), message injection, resource exhaustion.
- **OAuth.** Redirect URI must be an exact match, `state` required, PKCE for public clients, minimal scopes, no tokens in URLs, careful account linking.
- **JWT.** Pin the algorithm (reject `none` and alg confusion), use strong secrets or asymmetric keys, validate `iss`/`aud`/`exp`, keep tokens short-lived with refresh rotation, never trust unsigned claims, and use a revocation strategy.

## 8. Business logic & race conditions [A06 Insecure Design]

Scanners rarely find these. *Threat:* coupon stacking, refund after coupon, negative quantities, price in the request body, skipping checkout steps, loyalty, referral or free-trial abuse, subscription manipulation, inventory hoarding. Race conditions give double spending, duplicate coupons, multiple refunds and overselling. *Defend:* recompute prices and totals on the server, enforce workflow state machines, use DB transactions with row locks or atomic conditional updates (`UPDATE ... SET balance = balance - x WHERE balance >= x`), use idempotency keys and unique constraints for one-time actions, and apply limits per account, device and payment instrument. *Verify:* design abuse cases ("what if I send this 20 times in parallel?").

## 9. Client side / browser

XSS, DOM XSS, clickjacking, malicious third-party scripts (Magecart card skimming), malvertising, drive-by compromise. *Defend:* CSP (including `frame-ancestors 'self'` or `X-Frame-Options: DENY` against clickjacking), Subresource Integrity on CDN scripts, a minimal set of third-party tags, and monitoring for script changes on payment pages (PCI DSS 4.0 requires this).

## 10. Supply chain, CI/CD, secrets [A03 Software Supply Chain Failures, A08 Integrity Failures]

- **Dependencies.** Compromised or malicious packages, typosquatting, dependency confusion, hijacked maintainer accounts. *Defend:* lockfiles, audit in CI, pin versions, private registry scoping, reviewed update PRs (Dependabot/Renovate), SBOM.
- **CI/CD.** GitHub Actions, GitLab, Jenkins and build servers hold deploy credentials, so attacker → CI → production. *Defend:* pin actions to commit SHAs, least-privilege tokens, OIDC short-lived cloud credentials, protected branches with required reviews, and no secrets exposed to PRs from forks.
- **Secret exposure.** API keys, cloud keys, DB passwords, JWT secrets and private keys in git history, `.env` files, logs or CI variables. *Defend:* a secret manager, pre-commit secret scanning (gitleaks), GitHub push protection, rotation, and short-lived credentials. **A leaked secret must be rotated, not just deleted.**

## 11. Infrastructure: DNS, CDN, cache, TLS [A04 Cryptographic Failures]

- **DNS hijacking & registrar compromise.** *Defend:* registrar account with MFA, registrar lock / transfer lock, DNSSEC where supported, and monitoring for DNS changes.
- **Subdomain takeover.** `old.company.com` CNAMEs to a deleted cloud resource (S3, Heroku, Azure, GitHub Pages), the attacker claims it and serves content on your domain. *Defend:* delete DNS records *before* deleting resources, and audit dangling CNAMEs regularly.
- **TLS.** Expired certificates, TLS 1.0/1.1, weak ciphers, private-key exposure, hard-coded encryption keys, weak encryption at rest. *Defend:* TLS 1.2+ only (1.3 preferred), auto-renewing certificates, HSTS, keys in KMS or a secret manager, and modern password hashing (Argon2id or bcrypt; never MD5/SHA1 for passwords).

## 12. Cloud, containers, Kubernetes, databases

- **Cloud.** Over-permissive IAM, public buckets, exposed keys, open security groups, public databases, metadata access, weak service roles. *Defend:* least-privilege roles, block public access at the account level, IMDSv2, and CloudTrail or audit logs with alerts.
- **Containers.** Web bug → container → service account → Kubernetes API → other workloads. *Defend:* non-root, read-only filesystem, drop capabilities, no privileged containers, and minimal patched base images.
- **Kubernetes.** Exposed API or dashboard, over-broad RBAC, auto-mounted service-account tokens, plaintext secrets, no network policies, exposed etcd. *Too much privilege + too much exposure = large blast radius.*
- **Databases.** Never directly internet-reachable. Least-privilege app user, no default accounts, encrypted and access-controlled backups, admin tools (phpMyAdmin, Adminer) not public.

## 13. Automated threats [OWASP OAT]

Credential stuffing, scraping, scalping, fake account creation, card testing, ad fraud, account aggregation, token cracking, denial of inventory, vulnerability scanning. **DoS:** volumetric floods, HTTP floods, expensive endpoints, and CPU, memory, connection or queue exhaustion. **Payment fraud:** card testing, coupon, refund and gift-card abuse, payment manipulation, transaction replay. *Defend:* CDN/DDoS protection (Cloudflare, AWS Shield, etc.), WAF plus bot management, rate limits on login, signup, checkout, search and expensive endpoints, CAPTCHA on abuse signals, velocity rules on payments, and your payment provider's fraud tools (e.g. Stripe Radar).

## 14. People & third parties

- **Social engineering.** Phishing, spear phishing, BEC, smishing, vishing, fake support calls, MFA fatigue aimed at admins, developers, support and finance. *Defend:* phishing-resistant MFA (passkeys or security keys) for admins, callback verification for payment or credential changes, and training.
- **Insiders.** Employees, contractors or vendors stealing data or abusing privileges. *Defend:* least privilege, offboarding checklist, access reviews, audit logs.
- **Third-party integrations.** Payment, CRM, email, analytics and AI API providers can be the compromised link. *Defend:* minimal scopes, per-integration keys, vendor security review, and validating inbound webhooks (signatures).

## 15. AI / LLM / RAG

See `ai-llm-security.md`. Summary: direct and indirect prompt injection, system-prompt and secret exfiltration, RAG poisoning and cross-tenant retrieval, agent tool abuse. **The question isn't "can the model say something bad?" but "what can the model make the system do?"**

## 16. Post-compromise

- **Persistence.** New admin accounts, backdoors, API keys, OAuth apps, SSH keys, cron jobs, modified pipelines, web shells, persistent cloud identities.
- **Lateral movement.** Website → app server → database → internal APIs → cloud IAM → other workloads. *Defend:* network segmentation, least privilege, application isolation (MITRE's recommendations for T1190).
- **Exfiltration.** PII, financial data, credentials, source code, documents. *Defend:* egress filtering, data-export alerts, encryption, data minimization.
- **Ransomware & defacement.** *Defend:* offline or immutable backups tested by restore, admin access restricted, file integrity monitoring.

## 17. Detection & exceptional conditions [A09 Logging & Alerting, A10 Mishandling of Exceptional Conditions]

- **Log and alert on:** login failures and anomalies, MFA and password changes, permission and role changes, new admin users and API keys, 4xx/5xx spikes, API traffic spikes, unusual admin access, data-export spikes, unusual outbound traffic. Centralize logs and don't log secrets or full tokens. MITRE detection guidance: correlate abnormal HTTP requests + elevated errors + suspicious processes + outbound callbacks.
- **Exceptional conditions.** Fail-open behavior (auth service down = let everyone in), swallowed exceptions, null states, partial transaction failures, inconsistent authorization state. *Defend:* fail closed, atomic transactions, and tests for error paths.

## 18. Enterprise layer matrix

| Layer | Main attack categories |
|---|---|
| DNS | Hijacking, subdomain takeover |
| CDN | Cache poisoning, misconfiguration |
| WAF | Bypass, misconfiguration |
| Load balancer / proxy | Request smuggling, routing |
| Web server | CVEs, misconfiguration |
| Frontend | XSS, DOM attacks, clickjacking |
| Authentication | Brute force, stuffing, MFA attacks |
| Authorization | IDOR/BOLA, privilege escalation |
| API | BOLA, BFLA, mass assignment, resource abuse |
| Business logic | Fraud, workflow abuse, races |
| Database | Injection, exposure |
| Files | Upload, traversal, parser attacks |
| Cache | Poisoning, leakage |
| WebSockets | Auth and message attacks |
| OAuth | Redirect and token attacks |
| Cloud | IAM, metadata, public resources |
| Containers / K8s | Escape, privileged workloads, RBAC, secrets |
| CI/CD | Pipeline compromise |
| Dependencies | Supply chain |
| Secrets | Credential leakage |
| People | Phishing, social engineering |
| Third parties | Integration compromise |
| AI / LLM / RAG | Prompt injection, tool abuse, poisoning, retrieval leakage |
| Monitoring | Logging/alert gaps |
| Network | DDoS, lateral movement |
| Data | Exfiltration |
| Recovery | Backup and ransomware attacks |

**OWASP Top 10:2025:** A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging & Alerting Failures · A10 Mishandling of Exceptional Conditions.

**Hands-on learning:** PortSwigger Web Security Academy (free labs on every category above) for owners and developers who want to understand attacks safely.
