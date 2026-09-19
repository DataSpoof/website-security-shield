# Recon & Attack-Surface Discovery (Authorized)

Mapping the real attack surface for an authorized engagement. **Passive** techniques (no packets to the target's own infrastructure beyond normal browsing) need no active-testing gate. **Active** enumeration (directed scanning, fuzzing, brute-forcing content) requires the target to be in scope and in-window — see `pentest-methodology.md`.

Goal: find every host, endpoint, parameter, technology and trust boundary *before* testing, because the bug is usually on the asset nobody remembered. Keep an inventory as you go; it drives the whole test.

## Passive OSINT (no active-gate needed)

- **Certificate transparency** — crt.sh, censys, to enumerate subdomains from issued certs. This is public log data.
- **DNS history & records** — SecurityTrails, DNSdumpster, `dig`/`nslookup` for A/AAAA/CNAME/MX/TXT/NS; look for dangling CNAMEs (subdomain-takeover candidates — see `../references/infrastructure-and-cloud.md`).
- **Search engines & dorking** — `site:`, `inurl:`, `filetype:` to find exposed docs, admin panels, index pages. Google/Bing only touch the target as a normal crawler would.
- **Public code & secrets** — GitHub/GitLab search for the org, leaked keys in public repos, `.git` on old mirrors, gists. Wayback Machine (web.archive.org) for old endpoints and JS.
- **Cloud footprint** — enumerate likely S3/GCS/Azure blob names from the brand; public buckets are a classic. (Only *read* what's public; don't write.)
- **Tech & third parties** — Wappalyzer, BuiltWith, response headers, favicon hashes (Shodan `http.favicon.hash`), to fingerprint stack, CDN, WAF, analytics, chat widgets, payment providers.
- **People & orgs** — for phishing-susceptibility *reporting only* (never actually phish unless the scope explicitly allows it): LinkedIn roles, email format, breach-corpus exposure (HaveIBeenPwned domain search).

## Active enumeration (gate required: in-scope + in-window)

- **Subdomain resolution & liveness** — resolve the passive list, probe which are live (httpx), note redirects, statuses, titles, tech per host. Respect rate limits.
- **Port/service discovery** — nmap against in-scope IPs only, at an authorized rate. Map non-web services (SSH, DBs, admin panels) that shouldn't be public.
- **Content discovery** — ffuf/feroxbuster with sensible wordlists (SecLists) for hidden paths, backups (`.bak`, `~`, `.old`, `.zip`), admin routes, VCS dirs, config files. Watch for soft-404s; calibrate against a random path first (the bundled `site_check.py` does this).
- **Parameter discovery** — Arjun/param-miner and JS analysis to find hidden GET/POST params (often where unvalidated input lives).
- **JavaScript analysis** — pull all JS bundles, run through LinkFinder/`grep` for endpoints, API paths, keys, feature flags, and source maps (`.map` files reconstruct original source — a goldmine and a finding in itself).
- **API surface** — hunt for `swagger.json`/`openapi.json`, GraphQL `/graphql` (introspection), mobile-app API bases, old versions (`/api/v1` when prod is v3). Import specs into Burp/Postman. See `exploitation-methodology.md` §API.
- **Virtual hosts & origins** — vhost fuzzing, and try to reach the **origin behind the CDN/WAF** (historical DNS, SSRF, misconfigured DNS) — hitting origin directly can bypass edge protections (report it; see `waf-and-filter-evasion.md`).
- **Auth surface** — locate every login, registration, reset, SSO, OAuth callback, API-key issuance, and admin entry point → `auth-session-testing.md`.

## What to record per asset

For each host/endpoint: URL, tech/version, auth required?, roles that can reach it, parameters, interesting responses, and a hypothesis ("this reset flow builds the link from the Host header → test host-header injection"). This inventory becomes your test plan and feeds the chaining analysis in `business-logic-and-chaining.md`.

## Fingerprint → known-CVE mapping

Once versions are known, map to CVEs (NVD, the vendor advisory, CISA KEV for actively-exploited). For an authorized test, **validate** the CVE applies to this build before claiming it — version banners lie, and back-ported patches are common. Prefer a safe version-confirmation over firing a public exploit at production.

## Detection note (for the defense half of the report)

Recon is noisy and detectable: spikes in NXDOMAIN/subdomain lookups, 404 floods from content discovery, unusual user-agents, scanning from one ASN, favicon/hash lookups. Recommend the client alert on 404 spikes, WAF scanner-signatures, and CT-log monitoring for their own domains. Attackers do this recon too — the client seeing it early is a win.
