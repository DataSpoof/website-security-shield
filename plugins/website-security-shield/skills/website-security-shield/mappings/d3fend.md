# MITRE D3FEND Coverage (Defensive Countermeasures)

D3FEND is MITRE's knowledge base of **defensive** techniques. Because every offensive technique in this skill is paired with a remediation, the skill maps cleanly onto D3FEND's tactics. This is the "blue-team" complement to the ATT&CK mapping in `mitre-attack.md`.

D3FEND tactics: **Model · Harden · Detect · Isolate · Deceive · Evict · Restore.** This skill concentrates on **Harden**, **Detect**, **Isolate** and **Restore**.

| D3FEND tactic | Defensive technique (this skill) | Where |
|---|---|---|
| **Harden** | Multi-factor Authentication | `hardening-checklist.md` §Identity; `auth-session-testing.md` |
| Harden | Strong Password Policy / Credential Hardening | `hardening-checklist.md` §Identity |
| Harden | Application Configuration Hardening (headers, cookies, debug off) | `hardening-checklist.md`; `site_check.py` |
| Harden | Message/Transport Hardening (TLS, HSTS) | `hardening-checklist.md` §TLS |
| Harden | Input Validation / output encoding | `code-audit-guide.md`; `exploitation-methodology.md` (fix column) |
| Harden | Session Termination (logout invalidation, rotation, timeouts) | `auth-session-testing.md` |
| **Isolate** | Inbound Traffic Filtering (WAF, allow-lists) | `infrastructure-and-cloud.md` §WAF; `waf-and-filter-evasion.md` (fix) |
| Isolate | Outbound Traffic Filtering (SSRF egress control, metadata block) | `exploitation-methodology.md` §SSRF; `infrastructure-and-cloud.md` |
| Isolate | Network/segmentation, least privilege (blast-radius) | `infrastructure-and-cloud.md`; `attack-surface-catalog.md` §16 |
| **Detect** | User Behavior Analysis / auth anomaly detection | detection notes throughout; `hardening-checklist.md` §Detection |
| Detect | Network/Application Traffic Analysis (WAF telemetry, log signals) | per-finding **detection** rows in `exploitation-methodology.md` |
| **Restore** | Backups, tested restore, recovery | `hardening-checklist.md` §Resilience; `incident-response.md` |

Use this table to phrase a pentest report's remediation section in D3FEND terms for a blue-team audience: each finding's fix is a D3FEND Harden/Isolate technique, and each detection signature is a D3FEND Detect technique.
