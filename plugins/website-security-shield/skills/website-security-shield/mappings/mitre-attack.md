# MITRE ATT&CK & ATLAS Coverage

Adversary techniques this skill helps a tester **find/prove** (authorized) and a defender **prevent/detect**. Primary anchor for web is **T1190 Exploit Public-Facing Application**. Each row links to the skill content that covers it.

## ATT&CK Enterprise

| Technique | ID | Where in this skill |
|---|---|---|
| Active Scanning | T1595 | `references/recon-and-discovery.md` (active enumeration) |
| Gather Victim Host Information | T1592 | `references/recon-and-discovery.md` (fingerprinting) |
| Gather Victim Identity Information | T1589 | `references/recon-and-discovery.md` (OSINT) |
| Exploit Public-Facing Application | T1190 | `references/exploitation-methodology.md` (all injection/RCE classes) |
| Valid Accounts | T1078 | `references/auth-session-testing.md`; `references/attack-surface-catalog.md` §Identity (credential stuffing/ATO) |
| Brute Force | T1110 | `references/auth-session-testing.md` (lockout/throttling testing) |
| Modify Authentication Process | T1556 | `references/exploitation-methodology.md`, `auth-session-testing.md` (auth bypass) |
| Steal Web Session Cookie | T1539 | `references/auth-session-testing.md` (session/XSS) |
| Unsecured Credentials | T1552 | `references/code-audit-guide.md`; `scripts/code_scan.py` (secrets in code/.env) |
| Cloud Instance Metadata API | T1552.005 | `references/exploitation-methodology.md` §SSRF; `infrastructure-and-cloud.md` (IMDSv2) |
| Server Software Component: Web Shell | T1505.003 | `references/exploitation-methodology.md` §file upload; `attack-surface-catalog.md` §files |
| Supply Chain Compromise | T1195 | `references/code-audit-guide.md` (deps); `infrastructure-and-cloud.md` §CI/CD |
| Create Account | T1136 | `references/incident-response.md` (backdoor-admin persistence hunting) |
| Cloud Service Discovery | T1526 | `references/infrastructure-and-cloud.md` (cloud recon/posture) |
| Exfiltration Over Web Service | T1567 | `references/attack-surface-catalog.md` §exfiltration; detection notes |
| Endpoint Denial of Service | T1499 | `references/attack-surface-catalog.md` §DoS; `infrastructure-and-cloud.md` §DDoS |

MITRE recommends, for T1190: application isolation/sandboxing, network segmentation, least privilege, WAF, patching and vulnerability scanning — all reflected in `references/hardening-checklist.md` and `infrastructure-and-cloud.md`, and surfaced in each finding's **detection** note.

## MITRE ATLAS (AI/LLM)

| Technique | ID | Where |
|---|---|---|
| LLM Prompt Injection (direct & indirect) | AML.T0051 | `references/ai-llm-security.md` |
| LLM Data Leakage | AML.T0057 | `references/ai-llm-security.md` (system-prompt/secret/cross-tenant leakage) |

Related ATLAS concerns covered in `ai-llm-security.md`: excessive agency / tool abuse, RAG poisoning, and unbounded consumption.
