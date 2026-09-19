# Incident Response: "I Think My Site Was Hacked"

Stay calm and methodical. Speed matters, but acting in the wrong order (e.g. restoring a backup before closing the hole) leads to reinfection. Guide the owner through these phases. For businesses handling personal or payment data, recommend a professional incident-response firm or the host's security team early.

## Signs of compromise
Redirects to spam or scam sites (often only for mobile or search-engine visitors), "This site may be hacked" in Google, unknown pages or links (pharma, casino, crypto, Japanese keyword spam), unknown admin users, unfamiliar files in the web root (random PHP names, `.ico`/`.jpg` files containing code), modified `.htaccess`, new cron jobs, unexpected outbound email (spam), CPU spikes (cryptominers), customers reporting card fraud, homepage defacement, host suspension, blacklist warnings.

## Phase 1: Contain (first hour)
1. **Don't delete everything yet.** You need evidence to find how they got in.
2. Put the site in **maintenance mode** or take it offline if it's harming visitors (redirecting to malware, skimming cards).
3. **Change passwords and enable 2FA from a clean device**, in this order: email account → domain registrar → hosting/cloud → CMS admin → database → FTP/SFTP/SSH → payment provider → third-party integrations.
4. **Revoke sessions and keys:** log out all users, rotate API keys, cloud access keys, database passwords, CMS salts/secret keys (e.g. WordPress salts in `wp-config.php`), JWT signing keys, OAuth client secrets.
5. **Remove unknown admin accounts**, SSH keys, OAuth apps, API tokens and cron jobs (note them down first as evidence).
6. If payment data may be involved, notify your payment provider immediately.

## Phase 2: Preserve evidence
- Take a full copy of files, database and logs (web server access logs, error logs, CMS logs, hosting control-panel logs, cloud audit logs) **before** cleaning. Store it offline.
- Note the timeline: when it was first noticed, what changed, who has access.

## Phase 3: Investigate (find the way in)
Common entry points: an outdated plugin, theme or CMS, a stolen admin password (no 2FA), a vulnerable upload form, leaked credentials in a public repo, a compromised developer machine or FTP client, a vulnerable old copy of the site in a subfolder, a shared-hosting neighbor.
- Search access logs for POST requests to unusual files, requests to newly created files, admin logins from unknown IPs/countries, and spikes in requests to login endpoints.
- Compare site files against clean copies (CMS core checksums, e.g. `wp core verify-checksums`, and git).
- Look for recently modified files (`find . -type f -mtime -14` on Linux hosts) and suspicious code patterns (`base64_decode(`, `eval(`, `gzinflate(`, `str_rot13(`, `assert(` with variable input, `preg_replace` with `/e`).
- Scan with a reputable malware scanner (host's scanner, Wordfence/Sucuri for WordPress).
- Check the database for injected scripts or links (in posts, options and widgets tables) and unknown users.

## Phase 4: Eradicate & recover
- **Best option:** rebuild from a known-clean source (git repo or fresh CMS core plus clean plugin copies from official sources), then restore **content only** (database, uploads) after checking it for injected code. Or restore a backup from **before** the compromise, then patch immediately.
- Patch or remove the entry point you found. If you couldn't find it, assume the most likely one (outdated components, weak credentials) and fix all of them.
- Update everything, remove unused plugins and themes, apply `hardening-checklist.md` P0 items.
- Re-scan, then bring the site back online and monitor closely for 2–4 weeks (reinfection is common when a backdoor was missed).

## Phase 5: Clean up reputation
- Google Search Console: request a review once clean ("Security Issues" report).
- Check blacklists (Google Safe Browsing, Norton Safe Web, Sucuri SiteCheck) and request delisting.
- Check email-sending reputation if spam was sent.

## Phase 6: Notify (legal and trust)
If personal data may have been accessed, the owner may have **legal notification duties** with strict deadlines. Examples: GDPR (72 hours to the regulator), India's DPDP Act and CERT-In rules (6-hour reporting for certain incidents), US state breach laws, PCI DSS for card data. Recommend they consult a lawyer or their data-protection officer. Don't give definitive legal advice. Notify affected users honestly and promptly with what happened and what they should do (e.g. change passwords).

## Phase 7: Learn
Write a short post-incident note: timeline, root cause, what was affected, what was changed, and what will prevent recurrence (usually MFA, patching, backups, monitoring). Schedule a follow-up security review.
