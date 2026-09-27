# NIST CSF 2.0 Coverage

How this skill supports the six NIST Cybersecurity Framework 2.0 functions. Useful for slotting findings and remediation into a client's existing program and for framing a report to a security-governance audience.

| Function | Category (examples) | Coverage in this skill |
|---|---|---|
| **GOVERN (GV)** | GV.OC (organizational context), GV.RM (risk management) | Authorized-testing scope & rules of engagement (`assets/engagement-scope.template.md`); prioritization by risk (`SKILL.md` §Prioritize) |
| **IDENTIFY (ID)** | ID.AM (asset management), ID.RA (risk assessment) | Asset inventory & external attack-surface discovery (`references/recon-and-discovery.md`, `hardening-checklist.md` P0 exposure); vulnerability discovery and CVSS scoring |
| **PROTECT (PR)** | PR.AA (identity & access control), PR.PS (platform security), PR.DS (data security) | `hardening-checklist.md` (headers, TLS, cookies, MFA, patching); `auth-session-testing.md`; secrets handling in `code-audit-guide.md` |
| **DETECT (DE)** | DE.CM (continuous monitoring), DE.AE (adverse event analysis) | Per-finding **detection signatures** throughout `exploitation-methodology.md`; `hardening-checklist.md` §Detection; log/alert guidance |
| **RESPOND (RS)** | RS.MA (incident management), RS.AN (analysis) | `references/incident-response.md` (contain → preserve → investigate → eradicate → notify) |
| **RECOVER (RC)** | RC.RP (recovery plan execution) | Backups, tested restores, resilience (`hardening-checklist.md` P1 Resilience; `incident-response.md`) |

Every offensive finding in this skill is paired with a PROTECT remediation and a DETECT signature — so an authorized test output maps directly onto CSF Protect/Detect improvements, not just Identify.
