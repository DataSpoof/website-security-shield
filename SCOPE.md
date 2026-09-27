# Scope & Authorized-Use Policy

This project helps people **defend** websites and run **authorized** security testing. It is not an attack tool, and it is designed to refuse to act as one.

## In scope (what this skill is for)
- Defensive audits, hardening and incident response on sites you **own or operate**.
- **Authorized** penetration testing / red-teaming against targets covered by a **signed engagement-scope file** (`plugins/website-security-shield/skills/website-security-shield/assets/engagement-scope.template.md`).
- **Bug-bounty** testing strictly within a program's **published scope and rules**.
- Learning and practice on **legal targets**: PortSwigger Web Security Academy, OWASP Juice Shop, DVWA/WebGoat, HackTheBox/TryHackMe, VulnHub, CTFs.

## Out of scope (what it will not help with)
- Testing or attacking systems you don't own and aren't authorized to test.
- Turnkey / point-and-shoot exploitation of arbitrary third-party targets, mass exploitation, or automated attack campaigns.
- Persistence, real-data exfiltration, or destructive actions beyond a minimal proof-of-concept.
- Detection-evasion for the purpose of an actual intrusion, malware development, or DoS against third parties.

## How the guardrail works
- Active/offensive guidance is **gated** behind the authorization gate in `SKILL.md` and `references/pentest-methodology.md`: a signed scope file or a published bounty scope, in-window, within rate and impact limits.
- Every offensive technique is paired with its **remediation** and **detection** signature, so output improves security rather than only enabling access.
- Proofs-of-concept are deliberately **benign** (prove the flaw, don't cause harm or steal data).

## Legal note
Testing computer systems without authorization is illegal in most jurisdictions (e.g. US CFAA, UK Computer Misuse Act, India IT Act ss. 43/66) regardless of intent. You are responsible for having authorization before testing. When in doubt, don't.

Report security issues in this project itself per [SECURITY.md](SECURITY.md).
