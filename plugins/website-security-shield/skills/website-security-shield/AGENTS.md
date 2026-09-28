# AGENTS.md — using this skill with any AI coding agent

This skill is authored for Claude (Claude Code / Claude app), but it's plain Markdown + standard-library Python, so it works with any agent that can read files and run scripts: **GitHub Copilot, Cursor, Codex CLI, Gemini CLI, Continue, Aider**, and others. This file is the portable entry point (the [agentskills.io](https://agentskills.io) `AGENTS.md` convention).

## Entry point
Start at [`SKILL.md`](SKILL.md). It defines the modes (defensive audit, owner quick-wins, code audit, infrastructure, AI/LLM, incident response, and — gated — authorized pentest), the workflow, prioritization, and the report format. Read only the `references/*.md` the current mode needs.

## The authorization rule (all agents must honor)
Defensive auditing of a site the user owns is open. **Active/offensive testing requires authorization**: a signed engagement-scope file (`assets/engagement-scope.template.md`) or a published bug-bounty scope, in-window, within rate/impact limits. Without it, give only passive/defensive guidance. See `SKILL.md` → "Authorization gate" and `mappings/`/`SCOPE`-level policy. Every offensive technique must be paired with its remediation and detection signature. Keep proofs-of-concept benign.

## Scripts (no dependencies beyond PyYAML for two of them)
```bash
python scripts/site_check.py https://yoursite.example --authorized   # non-intrusive external check (owner-authorized)
python scripts/code_scan.py path/to/project                          # secret + risky-pattern scan (offline)
python scripts/pentest_checklist.py --scope web                      # WSTG checklist (offline)
python scripts/build_index.py            # regenerate index.json (needs PyYAML)
python scripts/build_navigator_layer.py  # regenerate ATT&CK Navigator layer (needs PyYAML)
```

## Framework mappings
Machine-readable in `SKILL.md` frontmatter (`frameworks:`) and `index.json`. Human-readable in `mappings/` (OWASP, MITRE ATT&CK + ATLAS, D3FEND, NIST CSF 2.0, NIST AI RMF, CWE). The ATT&CK Navigator layer (`mappings/attack-navigator-layer.json`) loads at https://mitre-attack.github.io/attack-navigator/.

## Platform notes
- **Copilot:** see `.github/copilot-instructions.md` in the repo root (mirrors this file).
- **Cursor / Continue / Aider:** point the agent at `SKILL.md` as project context; it will follow the mode table.
- **Codex CLI / Gemini CLI:** load `SKILL.md`, then the relevant `references/*.md`.
