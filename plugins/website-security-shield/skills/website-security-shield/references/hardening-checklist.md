# Hardening Checklist (P0 → P1)

Work top to bottom. Tick only items that apply to this site. Mark the rest "N/A" and give a reason. Every item has a concrete target value so it can be verified.

## Contents
- P0 Internet exposure & patching
- P0 Identity
- P0 Authorization
- P0 Application security
- P0 API security
- P0 Secrets
- Transport & browser security (headers, cookies, TLS): exact values
- P1 Cloud & infrastructure
- P1 Detection
- P1 Resilience

---

## P0: Internet exposure & patching
- [ ] Asset inventory: every domain, subdomain, IP, API, admin panel and cloud endpoint, each with an owner.
- [ ] No forgotten dev, staging, old or beta hosts publicly reachable (or they sit behind SSO/VPN/IP allow-list).
- [ ] No dangling DNS records pointing at deleted cloud resources.
- [ ] CMS core, plugins, themes, frameworks, server OS, web server and runtime are all on supported, patched versions.
- [ ] Patch SLA: critical internet-facing issues within 72 hours (sooner if listed in CISA KEV), high within 14 days.
- [ ] Unused plugins, themes, services, ports and endpoints removed, not just disabled.
- [ ] Admin panels (`/wp-admin`, `/admin`, phpMyAdmin, dashboards) restricted by IP, VPN or SSO where possible.
- [ ] Only ports 80 and 443 open to the internet. SSH is key-only and restricted. Databases are never public.
- [ ] Debug mode off in production. Generic error pages. No stack traces.
- [ ] No public `.git/`, `.env`, backups, `phpinfo`, source maps, `/server-status`, `/actuator`.

## P0: Identity
- [ ] MFA on **every** admin, hosting, registrar, DNS, CDN, cloud, email, code-repo and payment-provider account. Passkeys or security keys for admins where possible.
- [ ] Passwords: minimum 12 characters (15+ for admins), checked against breached-password lists, no forced periodic rotation, no composition rules that encourage patterns (NIST SP 800-63B).
- [ ] Password storage uses Argon2id, bcrypt (cost ≥ 12) or scrypt. Never MD5, SHA-1 or unsalted SHA-256.
- [ ] Login throttling per account and per IP, CAPTCHA or bot challenge after repeated failures, alerts on spikes (stuffing or spraying).
- [ ] Generic login and reset errors ("invalid email or password") so account existence isn't revealed.
- [ ] Password reset: single-use token, ≥128-bit random, expires ≤ 30 min, link built from a configured base URL, and all sessions invalidated after reset.
- [ ] Re-authentication required for email, phone, password and MFA changes. Notification sent to the old email.
- [ ] MFA recovery is at least as strong as login. Backup codes are single-use and hashed.
- [ ] Session ID rotated on login and privilege change. Idle timeout (e.g. 30 min for sensitive apps), absolute timeout (e.g. 12–24 h). Logout invalidates on the server.
- [ ] Default and shared accounts removed. Every admin is a named individual. Offboarding removes access the same day.

## P0: Authorization
- [ ] Deny by default. Every route and endpoint has an explicit authorization rule.
- [ ] Object-level checks on every request that takes an ID (BOLA/IDOR). Queries are scoped to the current user or tenant.
- [ ] Function-level checks on every admin or privileged action, enforced on the server (not by hiding buttons).
- [ ] Role and permission fields can't be set by the client (mass-assignment protection).
- [ ] Tenant ID comes from the session, never from the request. Cross-tenant tests run in CI.
- [ ] Automated tests with two users and two roles that attempt cross-access on every endpoint.

## P0: Application security
- [ ] Parameterized queries or ORM everywhere. No string-built SQL, NoSQL, LDAP or XPath.
- [ ] No shell execution with user input. No `eval`. No templates built from user input.
- [ ] Output encoding via auto-escaping templates. Rich HTML sanitized (DOMPurify / bleach). CSP deployed.
- [ ] CSRF protection on all state-changing requests (tokens and/or SameSite plus Origin check).
- [ ] SSRF protection on any "fetch this URL" feature (allow-list, block private/metadata ranges, recheck after redirects).
- [ ] File uploads: extension allow-list plus content check, random filenames, stored outside the web root or served from a separate domain, no execution, size limits, malware scan.
- [ ] XML parsers have DTDs and external entities disabled. Archive extraction checks paths (zip-slip).
- [ ] No native deserialization of untrusted data. `yaml.safe_load`, not `yaml.load`.
- [ ] Redirect targets are allow-listed or relative only.
- [ ] Business rules enforced on the server: prices, totals, discounts, quantities, workflow state.
- [ ] One-time actions (coupon, refund, withdrawal, vote) are atomic and idempotent (unique constraints, row locks, idempotency keys).
- [ ] CSV/Excel exports neutralize cells starting with `= + - @`.
- [ ] Errors fail closed. An auth or permission service error means deny.

## P0: API security
- [ ] API inventory (OpenAPI spec) matches what's deployed. Old versions retired. Internal APIs not internet-routable.
- [ ] Authentication on every non-public endpoint. API keys scoped, rotatable, never in URLs.
- [ ] Request schema validation (types, lengths, enums). Unknown fields rejected.
- [ ] Response schemas return only the fields needed. No raw DB objects.
- [ ] Rate limits and quotas per user, key and IP. Max body size (e.g. 1 MB unless uploads). Pagination cap (e.g. ≤ 100). Timeouts.
- [ ] GraphQL: introspection off in production, depth and complexity limits, batching limits, resolver-level authorization.
- [ ] Cost controls on paid downstream calls (SMS, email, AI inference, PDF/image generation) with alerts.
- [ ] Webhooks verified by signature and timestamp (replay window).
- [ ] CORS: exact-origin allow-list. Never `*` with credentials. Never reflect arbitrary origins.
- [ ] JWT: algorithm pinned, `iss`/`aud`/`exp` validated, access tokens ≤ 15–60 min, refresh tokens rotated and revocable.
- [ ] OAuth: exact redirect URI match, `state` and PKCE, minimal scopes.

## P0: Secrets
- [ ] No secrets in source code, git history, frontend bundles, Docker images, logs or tickets.
- [ ] `.env` files are in `.gitignore` and never deployed into the web root.
- [ ] Secrets live in a secret manager (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager, Vault, Doppler, or the platform's env-var store).
- [ ] Secret scanning in pre-commit and CI (gitleaks / trufflehog). GitHub push protection on.
- [ ] Any secret that was ever exposed has been **rotated**.
- [ ] Short-lived credentials where possible (OIDC from CI to cloud, IAM roles instead of static keys).

## Transport & browser security: exact values

**TLS**
- TLS 1.2 and 1.3 only. TLS 1.0/1.1 and SSLv3 disabled.
- Certificate auto-renewal (Let's Encrypt / managed certificates), with an alert 14 days before expiry.
- HTTP → HTTPS 301 redirect on every host.

**Security headers (starting point, tune per site)**
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'; form-action 'self'; upgrade-insecure-requests
X-Content-Type-Options: nosniff
X-Frame-Options: DENY            (or SAMEORIGIN; CSP frame-ancestors supersedes it)
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cross-Origin-Opener-Policy: same-origin
```
- Roll out CSP with `Content-Security-Policy-Report-Only` first, fix violations, then enforce.
- Add `preload` to HSTS only once every subdomain supports HTTPS.
- Remove `Server` version details, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`.

**Cookies (session and auth)**
```
Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax; Path=/
```
- Use the `__Host-` prefix for session cookies where possible (requires `Secure`, `Path=/`, no `Domain`).
- `SameSite=Strict` for high-value apps. `None` only when truly cross-site, and always with `Secure`.

**Other**
- `/.well-known/security.txt` with a contact address for vulnerability reports.
- Subresource Integrity (`integrity="sha384-..."`) on third-party scripts loaded from CDNs.

## P1: Cloud & infrastructure
- [ ] IAM least privilege. No wildcard `*:*` policies. No long-lived root or admin keys. MFA on root.
- [ ] Storage "block public access" on at account level. Public files served intentionally through a CDN.
- [ ] Security groups and firewalls: databases, caches (Redis) and queues reachable only from app subnets.
- [ ] IMDSv2 enforced (AWS), metadata endpoints unreachable from user-controlled fetches.
- [ ] Containers run as non-root, read-only root filesystem, no privileged mode, minimal images, scanned.
- [ ] Kubernetes: API not public, RBAC least privilege, network policies, secrets encrypted, service-account tokens not auto-mounted unless needed.
- [ ] CI/CD: actions pinned to SHA, protected branches, required reviews, least-privilege deploy tokens, OIDC to cloud.
- [ ] Registrar: MFA, transfer lock, contact email on a domain you control. DNS change alerts.
- [ ] CDN/WAF in front of origin. Origin IP not directly reachable (firewall allows only CDN ranges).

## P1: Detection
- [ ] Central logs (app, web server, WAF, auth, cloud audit such as CloudTrail) retained ≥ 90 days.
- [ ] Alerts: login failure spikes, new admin or role change, MFA disabled, new API key, 5xx/4xx spikes, data-export spikes, unusual outbound traffic, file changes in the web root.
- [ ] Logs exclude passwords, tokens, full card numbers and secrets.
- [ ] Uptime and defacement monitoring. Google Search Console for malware or spam warnings.
- [ ] Someone is actually on the receiving end of alerts, with a clear on-call or owner.

## P1: Resilience
- [ ] Automated daily backups of files **and** database, with at least one offline or immutable copy (3-2-1 rule).
- [ ] Restore tested at least quarterly. An untested backup isn't a backup.
- [ ] Written incident-response plan: who to call, how to take the site offline, how to rotate credentials, legal and notification duties (see `incident-response.md`).
- [ ] DDoS protection at the edge. A "maintenance mode" kill switch.
- [ ] Payment-provider fraud tools on. Rate limits on checkout.
