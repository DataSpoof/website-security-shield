# Security Policy

## Reporting a vulnerability in this project
This repo ships a Claude skill (Markdown + Python helper scripts that use only the standard library and send no traffic on their own). If you find a security issue in the scripts or guidance:

- Open a **private** report via GitHub Security Advisories ("Report a vulnerability" on the Security tab), or
- Email the maintainer listed in `CITATION.cff`.

Please do **not** open a public issue for a vulnerability. We aim to acknowledge within 7 days.

## Scope of the tools
- `scripts/site_check.py` performs a **non-intrusive** external check and refuses to run without `--authorized`.
- `scripts/code_scan.py`, `scripts/pentest_checklist.py`, `scripts/build_index.py` are local/offline and send no network traffic.
- Advanced/offensive **guidance** is gated behind an authorization scope file — see [SCOPE.md](SCOPE.md).

## Responsible use
Use only on assets you own or are authorized to test. See [SCOPE.md](SCOPE.md) for the full authorized-use policy.
