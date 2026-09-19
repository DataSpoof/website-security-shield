# Authentication, Session, OAuth/OIDC, SAML, JWT & MFA Testing (Authorized)

Advanced testing of identity and session controls — WSTG ATHN/SESS/IDNT. **Gate:** in-scope, in-window, authorized targets only (`pentest-methodology.md`); test with **your own test accounts**, never real users' credentials. Any real credentials you discover are a stop-and-report, not a pivot.

## Authentication [WSTG-ATHN]
- **Credentials over the channel:** login/reset/register must be HTTPS-only; check for creds in URLs, logs, referrer.
- **Username/account enumeration:** do login, reset and registration reveal which accounts exist (different messages, status codes, or **timing**)? Report it — it enables targeted attacks.
- **Weak lockout / throttling:** confirm brute-force protection exists per-account **and** per-IP. Test with a *small* number of attempts against your own test account — do **not** run a real brute-force against real users; that's both harmful and usually out of RoE. Note credential-stuffing exposure conceptually.
- **Default/weak credentials:** check documented defaults on admin panels/devices in scope.
- **Authentication bypass:** forced browsing to post-auth pages, parameter tampering (`admin=true`, `role`), SQL/NoSQL auth bypass (see `exploitation-methodology.md`), response manipulation, skipping steps.
- **Password reset:** token entropy and lifetime, single-use, **host-header poisoning** (does the reset link build from the `Host` header?), token in referrer, account takeover via email/phone change without re-auth. This is one of the richest ATO areas — test each step.
- **Remember-me / persistent auth:** token strength, revocation on password change.

## Session management [WSTG-SESS]
- **Token generation:** unpredictable, high-entropy session IDs; no meaningful structure.
- **Cookie flags:** `Secure`, `HttpOnly`, `SameSite`; scope/domain/path; `__Host-` prefix.
- **Fixation:** does the session ID rotate on login and privilege change? Fix a value pre-auth and see if it survives authentication.
- **Lifecycle:** idle + absolute timeout; server-side invalidation on logout; concurrent-session handling; does logout actually kill the server session (replay the old cookie)?
- **CSRF [WSTG-SESS-05]:** state-changing requests need anti-CSRF tokens and/or `SameSite` + Origin checks. Build a PoC form from your test account; confirm the action executes cross-site.

## OAuth 2.0 / OIDC
- **`redirect_uri` validation:** exact-match? try appended paths, open-redirect chains, subdomain/`localhost` tricks → token/code theft.
- **`state` parameter:** present and validated? Missing `state` = CSRF on the OAuth flow / account linking.
- **PKCE:** enforced for public clients? downgrade possible?
- **Authorization-code handling:** code reuse, code leak via referrer, cross-client code use.
- **Scope & consent:** scope escalation, silent re-consent, account-linking by unverified email (pre-account-takeover).
- **Implicit-flow / token-in-URL** leakage where still used.

## SAML
- Signature validation: unsigned assertions accepted? signature wrapping (XSW)? comment-injection in `NameID`? Assertion replay (no `NotOnOrAfter`/`InResponseTo` checks)? IdP-initiated abuse. Test only against the in-scope SP/IdP with test identities.

## JWT
- **Algorithm attacks:** `alg:none` accepted? RS256→HS256 confusion (sign with the public key as HMAC secret)? Confirm the server actually *verifies*.
- **Key management:** weak/guessable HMAC secret (crack an *own* token offline), `jwk`/`jku`/`kid` header injection pointing at attacker keys, `kid` path traversal/SQLi.
- **Claims:** is `exp`/`nbf`/`iss`/`aud` validated? Are trust decisions made on client-controlled claims? Tamper `role`/`sub` in your own token and see if the server honors it.
- **Lifetime & revocation:** overly long tokens, no revocation, refresh-token rotation missing.

## MFA
- Bypass by skipping the MFA step (forced browsing to the post-MFA endpoint), OTP brute-force (rate limits?), OTP reuse, race conditions, backup-code weaknesses, "remember device" abuse, and recovery-flow weakness (the recovery path is often weaker than login). Also: is MFA enforced server-side on every request, or only at login (session then unprotected)?

## For every finding
PoC with your own test identities → CVSS → impact (account takeover of *which* users, privilege gained) → **remediation** (link `../references/hardening-checklist.md` Identity section) → **detection** (auth-failure spikes, impossible-travel, MFA-disable events, reset-flood, new-admin alerts). Account takeover chains are high severity — spell out the full path in the report.
