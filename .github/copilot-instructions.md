# Copilot / AI-agent instructions

This repository is a Claude skill that also works with other agents (Copilot, Cursor, Codex, Gemini). The skill lives at `plugins/website-security-shield/skills/website-security-shield/`.

- **Entry point:** read that folder's `SKILL.md`, then only the `references/*.md` the current task needs.
- **Authorization rule:** defensive auditing of a site the user owns is fine. **Active/offensive testing requires** a signed engagement-scope file (`assets/engagement-scope.template.md`) or a published bug-bounty scope, in-window. Otherwise give only passive/defensive guidance. Every offensive technique must include remediation + a detection signature. Keep PoCs benign. See `SCOPE.md`.
- **Scripts** are standard-library Python (two need PyYAML). `site_check.py` requires `--authorized`.
- **Framework mappings** are in `SKILL.md` frontmatter, `index.json`, and `mappings/`.
- Full portable guidance: `plugins/website-security-shield/skills/website-security-shield/AGENTS.md`.
