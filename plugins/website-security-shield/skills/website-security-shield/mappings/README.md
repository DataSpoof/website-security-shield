# Framework Mappings

This skill maps its coverage to the industry frameworks pentesters, defenders and auditors use, so a finding can be tied to a recognised technique/control and slotted into a client's existing program. The machine-readable version lives in the skill frontmatter (`SKILL.md` → `frameworks:`) and in `../index.json`.

| Framework | What it's used for here | File |
|---|---|---|
| OWASP Top 10:2025 | Web app risk categories | `owasp.md` |
| OWASP API Security Top 10 (2023) | API-specific risks | `owasp.md` |
| OWASP WSTG v4.2 | Test-case coverage for authorized pentests | `owasp.md` |
| MITRE ATT&CK (Enterprise) | Adversary techniques the skill helps find/detect | `mitre-attack.md` |
| MITRE ATLAS | AI/LLM adversary techniques | `mitre-attack.md` |
| NIST CSF 2.0 | Governance/defense control functions | `nist-csf.md` |
| CWE | Root-cause weakness classes for findings | `owasp.md` |

Mappings are **coverage indicators**, not certification. They say "this skill has material that helps with technique/category X," and are derived from this skill's own content (not copied from any other project). Validate applicability per engagement.
