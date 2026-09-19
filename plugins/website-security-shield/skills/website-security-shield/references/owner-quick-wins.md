# Owner Quick Wins: Plain-Language Checklist

For website owners who aren't developers: small businesses, bloggers, online shops, and sites on WordPress, Shopify, Wix, Squarespace, Webflow, Joomla or Drupal. Most real-world hacks of small sites come from a handful of causes: **stolen or weak passwords, outdated software and plugins, and no backups.** Fixing those stops most attacks.

When presenting this to a non-technical owner, give them the steps in order, one sentence of "why" each, and where to click. Skip anything that doesn't apply to their platform.

## The 10 most important things (in order)

1. **Turn on two-step login (2FA) everywhere that controls the site.** That means your website admin, hosting account, domain registrar (GoDaddy, Namecheap, etc.), email account, Cloudflare, payment provider, and Google/Facebook business accounts. *Why:* most break-ins use a stolen or guessed password, and 2FA blocks almost all of them. An authenticator app or passkey is better than SMS.
2. **Use a password manager and unique passwords.** Bitwarden, 1Password or the one built into your browser. Every account gets a different long password. *Why:* when some other site gets breached, attackers try the same email and password on yours ("credential stuffing").
3. **Update everything and turn on automatic updates.** CMS core, plugins, themes, and PHP version (ask your host). *Why:* attackers scan the whole internet for known holes in old versions within hours of them being published.
4. **Delete what you don't use.** Inactive plugins and themes, old admin users, old staging copies of the site, old subdomains. *Why:* unused software still gets hacked and nobody watches it.
5. **Set up automatic backups stored somewhere else.** Daily for shops, weekly for mostly static sites. Keep copies off the server (cloud storage) and **test restoring one**. *Why:* if the worst happens, a clean backup gets you back online in hours instead of weeks.
6. **Put a protective service in front of the site.** Cloudflare (free plan is fine) or your host's firewall/WAF. *Why:* it blocks bots, common attacks and floods before they reach your site.
7. **Make sure the site is HTTPS everywhere.** The padlock shows on every page, `http://` redirects to `https://`, and the certificate renews automatically. *Why:* protects logins and payments, and browsers warn visitors away from sites without it.
8. **Lock your domain.** At your registrar, turn on "domain lock / transfer lock", 2FA, and auto-renew, and keep the contact email on an address you check. *Why:* if someone takes your domain, they take your website and email with it.
9. **Limit who has admin access.** Give staff and freelancers their own accounts with the lowest role they need (Editor, not Administrator), and remove them when the work ends. *Why:* every admin account is a door in, and shared logins can't be traced or revoked.
10. **Watch for trouble.** Add the site to Google Search Console (it warns you about malware or hacked-content flags), set up a free uptime monitor (UptimeRobot, Better Stack), and read any security emails from your host. *Why:* the sooner you know, the less damage.

## WordPress specifics
- Only install plugins and themes from wordpress.org or reputable vendors. Avoid "nulled" (pirated) premium plugins, which often contain backdoors.
- Choose plugins that are actively maintained (updated in the last few months, many active installs).
- Install one reputable security plugin (e.g. Wordfence, Solid Security or Sucuri) for firewall, login protection and malware scanning. Don't stack several.
- Limit login attempts and add 2FA (many security plugins do both).
- Change the default `admin` username if it exists (create a new admin, move content over, then delete the old one).
- Disable the in-dashboard file editor: add `define('DISALLOW_FILE_EDIT', true);` to `wp-config.php`.
- Disable XML-RPC if you don't use the mobile app or Jetpack (often abused for brute-force).
- Keep the PHP version supported (8.1+ at the time of writing). Your host's control panel usually has a switcher.
- Make sure `wp-config.php` isn't publicly readable and that there are no backup copies like `wp-config.php.bak` in the site folder.
- Turn off directory browsing (`Options -Indexes` in `.htaccess` on Apache hosts).

## Shopify, Wix, Squarespace, Webflow (hosted platforms)
The platform handles servers, patching and HTTPS. Your job is **accounts, apps and integrations**:
- 2FA on the store owner account and every staff account. Remove ex-staff.
- Review installed apps and integrations: remove unused ones, and check what permissions each has.
- Be careful with custom code snippets and third-party scripts added to the theme. They run on your checkout and product pages.
- Turn on the platform's fraud analysis and require CVV/3-D Secure for card payments.
- Watch for phishing emails pretending to be the platform ("your store will be suspended, log in here").

## E-commerce & payments
- Never store card numbers yourself. Use Stripe, PayPal, Razorpay or your platform's payment system.
- Turn on your payment provider's fraud tools (e.g. Stripe Radar) to stop **card testing** (bots trying stolen cards with tiny purchases).
- Add bot protection or CAPTCHA to checkout, signup and login if you see a flood of fake orders or accounts.
- Set sensible limits on coupons (one per customer, expiry dates) and review refunds manually above a threshold.

## Hosting account & email
- 2FA on the hosting control panel (cPanel, Plesk, hosting dashboard).
- Use SFTP/SSH instead of plain FTP.
- Don't reuse the hosting password anywhere else.
- Your email account can reset every other password, so it needs the strongest protection.
- Set up SPF, DKIM and DMARC for your domain (your host or email provider has a guide) so scammers can't easily send email pretending to be you.

## People & phishing
- Most attacks on small businesses start with an email or message. Be suspicious of urgent "your account will be closed" messages, unexpected invoices, and "please change the bank details" requests.
- Verify any request to change payment details or share login codes by calling a known number.
- Never share 2FA codes with anyone, including people claiming to be "support".

## If you have a developer or agency
Ask them these questions. Good answers are a good sign:
1. "How and when do you apply security updates?"
2. "Where are our backups, and when did you last test a restore?"
3. "Who has admin access to the site, hosting and domain, and do they all have 2FA?"
4. "Are any passwords or API keys stored in the code or shared by email or chat?"
5. "What happens, and who do I call, if the site gets hacked?"
6. "Do we own the domain, hosting and code accounts in our business's name?"

## Signs your site may already be hacked
Go straight to `incident-response.md` if you see any of these: visitors redirected to spam or scam sites, Google showing "This site may be hacked", strange new pages or links (often pharmacy, casino or crypto), unknown admin users, your host suspending the account for malware or spam, a sudden drop in search traffic, customers reporting card fraud after buying from you, or your homepage changed.
