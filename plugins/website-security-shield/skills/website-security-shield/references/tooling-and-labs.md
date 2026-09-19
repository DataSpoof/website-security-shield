# Tooling & Legal Practice Labs

The standard professional toolchain, and where to build and practice these skills **legally**. Use tools only against authorized targets (`pentest-methodology.md`).

## The web/API pentest toolchain

**Intercepting proxy (the core tool)**
- **Burp Suite** (Community/Pro) or **OWASP ZAP** (free): intercept, Repeater (manual testing), Intruder/fuzzing, Comparer, extensions (param-miner, Autorize for IDOR, JWT Editor, Collaborator for OOB). Turbo Intruder for race conditions.

**Recon & discovery**
- Subdomains: `subfinder`, `amass`, `crt.sh`. Liveness: `httpx`. Ports: `nmap`.
- Content/paths: `ffuf`, `feroxbuster`, `gobuster` + SecLists wordlists.
- Params: `Arjun`, param-miner. JS: `LinkFinder`, `getJS`, source-map extractors.
- Templated CVE checks: `nuclei` (community templates) — fast, low-noise, but validate hits.

**Class-specific**
- SQLi: `sqlmap` (use `--technique` and low risk/level on authorized targets; prefer boolean/time PoCs).
- XSS: `dalfox`, manual context analysis.
- OOB / interaction: Burp Collaborator, `interactsh`.
- JWT: `jwt_tool`, jwt.io. Directory/secret scanning of code: `trufflehog`, `gitleaks`, `semgrep`.
- API: Postman/Insomnia + imported OpenAPI; GraphQL: `graphql-cog`, InQL, introspection tools.
- TLS: `testssl.sh`, `sslyze`.

**Use nuclei/sqlmap/etc. carefully:** they're active. Respect rate limits and RoE, and confirm findings by hand before reporting — automated tools produce false positives and can cause load.

## Methodology references to read

- **OWASP Web Security Testing Guide (WSTG)** — the category-by-category test bible.
- **OWASP API Security Top 10**, **OWASP Top 10:2025**, **OWASP ASVS** (verification standard — great for structuring coverage), **OWASP Cheat Sheet Series** (defense).
- **PTES** (Penetration Testing Execution Standard), **NIST SP 800-115**.
- **PortSwigger Web Security Academy** — free, and the single best hands-on resource; its topic list *is* a curriculum.
- **HackTricks**, **PayloadsAllTheThings** — technique references (for authorized use).
- **Bug-bounty program policies** (HackerOne/Bugcrowd/Intigriti) — read scope & rules; they *are* your authorization for those targets.

## Legal practice labs (build skill without breaking the law)

Never practice on systems you don't own or aren't authorized for. Use these:

- **PortSwigger Web Security Academy** — free labs for every class here (SQLi, XSS, SSRF, SSTI, request smuggling, access control, auth, OAuth, JWT, GraphQL, prototype pollution, race conditions, WebSockets, CORS, XXE, host-header, deserialization, business logic, LLM attacks).
- **OWASP Juice Shop** — modern vulnerable app, self-host or use their instances.
- **DVWA**, **WebGoat**, **bWAPP**, **Mutillidae** — self-hosted classic vulnerable apps.
- **HackTheBox** / **TryHackMe** — guided and CTF-style machines; authorized by the platform.
- **VulnHub** — downloadable vulnerable VMs to run locally.
- **Bug-bounty programs** — real targets, legally, within published scope. Start with programs that have clear scope and a safe-harbor policy.
- **CTFs** (CTFtime) — time-boxed, authorized, and great for chaining practice.

## Building the skill responsibly

- Learn the **defense** for every attack you learn — that's what makes the finding valuable and keeps you on the right side.
- Always work from a **signed scope** or a **published bounty policy**. Keep evidence minimal and handle any real data you encounter as stop-and-report.
- Certifications that reinforce this methodology: OffSec **OSCP/OSWE**, **PortSwigger BSCP**, **PNPT**, **GWAPT**, **CEH**.
