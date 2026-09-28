# ATT&CK / Framework Coverage Summary

A quick, honest coverage summary. This skill is **focused on the web/application attack surface** (anchored on MITRE ATT&CK **T1190 Exploit Public-Facing Application**), not a full-spectrum offensive/DFIR catalogue.

## MITRE ATT&CK (Enterprise) — 16 techniques
Recon (T1595, T1592, T1589) · Initial access (T1190) · Credential/auth (T1078, T1110, T1556, T1539, T1552, T1552.005) · Persistence (T1505.003, T1136) · Supply chain (T1195) · Cloud (T1526) · Exfiltration (T1567) · Impact (T1499).
Full detail + skill locations: [`mappings/mitre-attack.md`](plugins/website-security-shield/skills/website-security-shield/mappings/mitre-attack.md). Visual layer: [`attack-navigator-layer.json`](plugins/website-security-shield/skills/website-security-shield/mappings/attack-navigator-layer.json).

## MITRE ATLAS (AI/LLM)
LLM Prompt Injection (AML.T0051), LLM Data Leakage (AML.T0057), plus excessive agency / RAG poisoning / unbounded consumption — [`mappings/nist-ai-rmf.md`](plugins/website-security-shield/skills/website-security-shield/mappings/nist-ai-rmf.md) and `references/ai-llm-security.md`.

## Defensive (the other half of every finding)
- **MITRE D3FEND:** Harden / Isolate / Detect / Restore — [`mappings/d3fend.md`](plugins/website-security-shield/skills/website-security-shield/mappings/d3fend.md)
- **NIST CSF 2.0:** Govern / Identify / Protect / Detect / Respond / Recover — [`mappings/nist-csf.md`](plugins/website-security-shield/skills/website-security-shield/mappings/nist-csf.md)
- **NIST AI RMF 1.0:** Govern / Map / Measure / Manage

## OWASP
Top 10:2025 (A01–A10), API Security Top 10 (API1–API10), WSTG v4.2 (all categories), 20 CWE classes — [`mappings/owasp.md`](plugins/website-security-shield/skills/website-security-shield/mappings/owasp.md).

## Deliberately NOT covered
Endpoint/host malware reverse engineering, disk/memory forensics, Active Directory internal red-teaming, C2 framework internals, hardware/OT/ICS. Those are separate disciplines; this skill stays deep on **website + API + cloud-edge + AI-feature** security. If you need those, a broad multi-domain catalogue (e.g. large cybersecurity skill packs) is the better fit.
