# Contributing

Thanks for helping improve Website Security Shield.

## What makes a good contribution
- **Defensive or authorized-testing only.** Every offensive technique must ship with its remediation and a detection signature. PoCs must be benign. Contributions that are purely weaponized exploitation, or aimed at unauthorized attacks, will be declined (see [SCOPE.md](SCOPE.md)).
- Accurate, current, and mapped to a framework where relevant (OWASP / MITRE ATT&CK / CWE / NIST CSF). Update `skills/website-security-shield/mappings/` and the frontmatter `frameworks:` block if you add coverage.
- Plain-language for owner-facing content; precise and technical for pentest content.

## Workflow
1. Fork and branch.
2. Edit the skill under `plugins/website-security-shield/skills/website-security-shield/`.
3. If you change frontmatter or add references/scripts, run:
   ```bash
   pip install pyyaml
   python tools/validate_skill.py
   cd plugins/website-security-shield/skills/website-security-shield && python scripts/build_index.py
   ```
4. Make sure `python scripts/*.py --help` / `--json` smoke tests pass and no secrets are committed.
5. Open a PR describing the change and its framework mapping.

## Style
- Keep `SKILL.md` under ~500 lines; put depth in `references/`.
- Scripts: standard library only where possible; no network calls except `site_check.py` (which must keep the `--authorized` gate).
