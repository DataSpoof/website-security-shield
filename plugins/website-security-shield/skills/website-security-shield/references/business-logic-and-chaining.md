# Business-Logic Testing & Vulnerability Chaining (Authorized)

The flaws automated scanners never find, and the art of turning small issues into critical impact. This is where advanced testers earn their keep. **Gate:** in-scope, in-window, authorized (`pentest-methodology.md`); use your own test accounts and benign proofs.

## Business-logic testing [WSTG-BUSL]

Scanners test *inputs*; logic flaws live in *workflows and rules*. You have to understand what the app is *for*, then ask "what if I don't play by the intended rules?"

- **Map the intended workflow** first (e.g. cart → coupon → pay → fulfil → refund). Then attack the assumptions:
  - **Step skipping / order:** jump straight to fulfilment or the post-payment endpoint without paying. Reach step 3 without step 2.
  - **Parameter/price tampering:** change price, quantity (negative? zero? huge?), currency, discount, or a `total` sent from the client. Confirm the server recomputes.
  - **Value manipulation:** stack coupons, reuse single-use codes, refund more than paid, refund to a different account, loyalty/referral/cashback abuse, free-trial farming.
  - **Limits & quotas:** are per-user/per-account limits enforced server-side? Bypass via multiple accounts, parallel requests, or a different endpoint.
  - **Race conditions [see below].**
  - **State abuse:** cancel-after-fulfil, edit-after-approval, replay a one-time action, use a resource after it should be locked.
- **How to test:** two test accounts, an intercepting proxy (Burp), and a habit of asking "who validates this, client or server?" Prove impact with your own accounts and benign amounts.

## Race conditions [WSTG-BUSL, CWE-362]

- **Where:** anything that checks-then-acts on a shared resource: balance/withdrawal, coupon/gift-card redemption, inventory, "one vote/claim/apply", rate limits, refund.
- **Test:** fire the same request many times **in parallel** (Burp Repeater "send group in parallel" / Turbo Intruder single-packet attack). If two+ succeed where one should, it's exploitable.
- **Impact:** double-spend, duplicate refunds/coupons, oversell, bypassed limits.
- **Fix:** atomic conditional updates (`UPDATE ... WHERE balance >= x`), row locks, unique constraints, idempotency keys. See `attack-surface-catalog.md` §race.
- **Detect:** bursts of identical requests, duplicate successful one-time actions, negative balances/inventory.

## Vulnerability chaining — the core of high-impact testing

Individually-minor issues combine into catastrophe. A great report tells the **attack narrative**, not just a bug list. Score the chain at the impact it achieves, not the weakest link.

**Classic chains to look for:**
- **Recon → forgotten API → BOLA → data:** old `/v1` endpoint in a JS bundle → no ownership check → all users' records.
- **Self-XSS + CSRF → stored XSS:** a "harmless" self-XSS becomes serious when a CSRF lets you set it in a victim's context.
- **Open redirect → OAuth token theft:** open redirect on an allowed `redirect_uri` host → steal the auth code → account takeover.
- **SSRF → cloud metadata → IAM creds → cloud takeover.** (Prove SSRF to a collaborator; treat any real creds as stop-and-report.)
- **IDOR (read) → info → password-reset abuse → ATO:** leak an email/token via one weak endpoint, use it to take an account.
- **Host-header injection → poisoned reset link → ATO.**
- **File upload (benign) → path/exec misconfig → web-served marker → RCE risk.**
- **Subdomain takeover → cookie scope / OAuth trust → session theft.**

**How to build a chain:**
1. Inventory every finding, however small (from recon + all the WSTG categories).
2. For each, ask "what does this *give* me, and what does it *unlock*?"
3. Look for a path from low-privilege/external to high-impact (data, funds, admin, other tenants).
4. Prove each hop with a minimal benign PoC; stop at the point impact is demonstrated — don't actually pillage.
5. Report the narrative end-to-end, with the CVSS of the *outcome*, and remediation at **every** breakable link (defense in depth: fixing any one hop breaks the chain).

## Why this matters in the report

Clients often dismiss Mediums. Showing that three Mediums chain into full account takeover of any customer changes the priority — and teaches their team to think in paths, not checklists. Always end with: which single fix most cheaply breaks the most chains.
