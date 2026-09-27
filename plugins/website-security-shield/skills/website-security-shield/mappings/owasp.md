# OWASP & CWE Coverage

## OWASP Top 10:2025

| ID | Category | Coverage in this skill |
|---|---|---|
| A01 | Broken Access Control | `exploitation-methodology.md` §IDOR/BOLA; `code-audit-guide.md` §authorization; `attack-surface-catalog.md` §3 |
| A02 | Security Misconfiguration | `site_check.py`; `hardening-checklist.md`; `infrastructure-and-cloud.md` |
| A03 | Software Supply Chain Failures | `code-audit-guide.md` (deps); `infrastructure-and-cloud.md` §CI/CD & supply chain |
| A04 | Cryptographic Failures | `hardening-checklist.md` §TLS/crypto; `code-audit-guide.md` §crypto |
| A05 | Injection | `exploitation-methodology.md` §1–4; `code_scan.py` |
| A06 | Insecure Design | `business-logic-and-chaining.md`; `attack-surface-catalog.md` §8 |
| A07 | Authentication Failures | `auth-session-testing.md`; `attack-surface-catalog.md` §2 |
| A08 | Software or Data Integrity Failures | `exploitation-methodology.md` §deserialization; `infrastructure-and-cloud.md` §CI/CD |
| A09 | Security Logging & Alerting Failures | detection notes throughout; `hardening-checklist.md` §Detection |
| A10 | Mishandling of Exceptional Conditions | `attack-surface-catalog.md` §17; `code-audit-guide.md` (fail-closed) |

## OWASP API Security Top 10 (2023)

API1 BOLA · API2 Broken Authentication · API3 Broken Object Property Level Authorization (mass assignment) · API4 Unrestricted Resource Consumption · API5 BFLA · API6 Unrestricted Access to Sensitive Business Flows · API7 SSRF · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs — all in `attack-surface-catalog.md` §7 and `exploitation-methodology.md` §API.

## OWASP WSTG v4.2 (authorized-pentest test cases)

INFO · CONF · IDNT · ATHN · ATHZ · SESS · INPV · ERRH · CRYP · BUSL · CLNT · APIT — coverage matrix in `references/pentest-methodology.md`; generate a working checklist with `scripts/pentest_checklist.py`.

## CWE (root-cause weakness classes for findings)

| CWE | Weakness | Class ref |
|---|---|---|
| CWE-89 | SQL Injection | exploitation §1 |
| CWE-79 | Cross-site Scripting | exploitation §5 |
| CWE-78 | OS Command Injection | exploitation §3 |
| CWE-1336 | Server-Side Template Injection | exploitation §4 |
| CWE-918 | SSRF | exploitation §6 |
| CWE-639 / CWE-285 | Authorization Bypass / Improper Authorization | exploitation §7 |
| CWE-611 | XXE | exploitation §8 |
| CWE-502 | Deserialization of Untrusted Data | exploitation §9 |
| CWE-22 / CWE-434 | Path Traversal / Unrestricted Upload | exploitation §10 |
| CWE-444 | HTTP Request Smuggling | exploitation §11 |
| CWE-942 | Permissive CORS | exploitation §12 |
| CWE-352 | CSRF | auth-session §CSRF |
| CWE-798 / CWE-522 | Hard-coded / Insufficiently Protected Credentials | code-audit §secrets |
| CWE-287 / CWE-384 | Improper Authentication / Session Fixation | auth-session |
| CWE-20 | Improper Input Validation | exploitation (cross-cutting) |
| CWE-1321 | Prototype Pollution | exploitation §14 |
