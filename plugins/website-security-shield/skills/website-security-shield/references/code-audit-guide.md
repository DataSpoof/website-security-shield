# Code Audit Guide

How to review a website's source code for the bug classes attackers exploit. Run `scripts/code_scan.py` first for quick leads, then use this guide for the manual review. The scan can't find the most damaging bugs, which are authorization and business logic, so the manual part matters most.

## Contents
1. Where to look first
2. Authorization (the #1 risk): manual review
3. Insecure → secure patterns by bug class
4. Framework-specific settings
5. Dependency & secret scanning tools
6. Writing up code findings

---

## 1. Where to look first

Attackers go where untrusted input meets something powerful. Map these first:

- **Entry points:** routes and controllers, API handlers, GraphQL resolvers, WebSocket handlers, webhooks, queue consumers, file-upload handlers, cron jobs that process user data.
- **Powerful sinks:** DB queries, shell commands, file-system paths, outbound HTTP requests, template rendering, deserializers, XML parsers, redirects, HTML output, `eval`.
- **Security-critical flows:** login, signup, password reset, email change, MFA, OAuth callback, checkout, refunds, coupons, admin actions, data export, API key creation.
- **Config:** production settings, CORS, session and cookie config, CSP, debug flags, IaC, Dockerfiles, CI workflows.

Trace each piece of untrusted input (body, query, headers, cookies, uploaded files, third-party API responses, LLM output) to each sink.

## 2. Authorization: manual review

For **every** endpoint, answer three questions:
1. Who can call it? Is authentication enforced by middleware or a decorator, not just remembered by the developer?
2. Which role or permission is required, and is that checked **on the server**?
3. If it takes an object ID, is ownership or tenancy checked **before** reading or writing?

Red flags:
```python
# BAD: any logged-in user can read any order (IDOR/BOLA)
order = Order.objects.get(id=order_id)

# GOOD: scoped to the current user
order = Order.objects.get(id=order_id, owner=request.user)
```
```js
// BAD: mass assignment. The client can send {role: "admin"}
await User.update(req.body, { where: { id: req.user.id } });

// GOOD: explicit allow-list
const { name, bio } = req.body;
await User.update({ name, bio }, { where: { id: req.user.id } });
```
- Admin routes protected only because "the link isn't shown in the UI".
- `tenant_id` / `org_id` / `user_id` read from the request body or query instead of the session.
- Role checks done in frontend code only.
- Endpoints added later (v2, export, bulk, search) that skip the middleware the original ones use.
- GraphQL resolvers that check auth on the top-level query but not on nested fields.

## 3. Insecure → secure patterns by bug class

### SQL / NoSQL injection
```python
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")      # BAD
cur.execute("SELECT * FROM users WHERE email = %s", (email,))     # GOOD
```
```js
db.query("SELECT * FROM users WHERE id = " + req.params.id)       // BAD
db.query("SELECT * FROM users WHERE id = $1", [req.params.id])    // GOOD
User.find({ email: req.body.email })  // BAD if body.email can be {"$ne": null}; validate it's a string
```
```php
$db->query("SELECT * FROM users WHERE id = " . $_GET['id']);      // BAD
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?"); $stmt->execute([$_GET['id']]); // GOOD
```
Dynamic `ORDER BY` or column names can't be parameterized, so map them through an allow-list.

### Command injection
```python
os.system("convert " + filename)                         # BAD
subprocess.run(f"ping {host}", shell=True)               # BAD
subprocess.run(["ping", "-c", "1", host], check=True)    # GOOD (and validate host)
```
```js
exec(`git log ${branch}`)                // BAD
execFile("git", ["log", branch])         // GOOD
```

### Template injection
```python
render_template_string("Hello " + name)               # BAD: input becomes template code
render_template("hello.html", name=name)              # GOOD
```

### XSS
```js
el.innerHTML = userComment;                       // BAD
el.textContent = userComment;                     // GOOD
<div dangerouslySetInnerHTML={{__html: bio}} />   // BAD unless sanitized with DOMPurify
```
Also: `v-html`, `document.write`, `{{{ }}}` / `|safe` / `{!! !!}` / `raw` in templates, `href={userUrl}` (allows `javascript:` URLs, so validate the scheme).

### SSRF
```python
requests.get(request.args["url"])   # BAD: can hit 169.254.169.254, localhost, internal APIs
```
GOOD: parse the URL, require https, match the host against an allow-list, resolve DNS and reject private, loopback and link-local IPs, disable redirects or re-validate each hop, and route through an egress proxy.

### Path traversal & file upload
```python
open(os.path.join(UPLOAD_DIR, request.args["file"]))           # BAD: ../../etc/passwd
path = (BASE / name).resolve()
if not path.is_relative_to(BASE.resolve()): abort(400)          # GOOD
```
Uploads: allow-list extensions plus magic-byte check, `secure_filename` or a random UUID name, store outside the web root or in S3 with a private ACL, serve from a separate domain with `Content-Disposition: attachment`, and cap sizes.

### Deserialization & XML
```python
pickle.loads(data)          # BAD on untrusted data
yaml.load(s)                # BAD; use yaml.safe_load(s)
lxml.etree.fromstring(x)    # risky; use defusedxml
```
```php
unserialize($_COOKIE['cart']);   // BAD; use json_decode
```
Java: `ObjectInputStream.readObject` on untrusted input is BAD. `DocumentBuilderFactory` must disable DTDs.

### Crypto & secrets
- `md5(password)`, `sha1(password)`, `hashlib.sha256(password)` for password storage is BAD. Use Argon2id or bcrypt.
- `Math.random()` / `random.random()` for tokens is BAD. Use `crypto.randomBytes` / `secrets.token_urlsafe`.
- `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true` disable TLS checks. BAD.
- Hard-coded keys and secrets are BAD. Load them from the environment or a secret manager.

### JWT
```js
jwt.decode(token)                                   // BAD for auth: does not verify
jwt.verify(token, secret)                           // better
jwt.verify(token, key, { algorithms: ["RS256"], issuer, audience })  // GOOD
```
```python
jwt.decode(t, options={"verify_signature": False})  # BAD
jwt.decode(t, key, algorithms=["HS256"], audience=AUD, issuer=ISS)  # GOOD
```

### CORS & CSRF
```js
app.use(cors({ origin: true, credentials: true }))          // BAD: reflects any origin
app.use(cors({ origin: ["https://app.example.com"], credentials: true }))  // GOOD
```
Django `@csrf_exempt`, Rails `skip_before_action :verify_authenticity_token`, and Laravel CSRF `$except` entries all need a justification (e.g. a signed webhook).

### Open redirect
```python
return redirect(request.args["next"])      # BAD
nxt = request.args.get("next", "/")
if not nxt.startswith("/") or nxt.startswith("//"): nxt = "/"
return redirect(nxt)                        # GOOD
```

### Race conditions & business logic
```python
if user.balance >= amount:           # BAD: two parallel requests both pass
    user.balance -= amount; user.save()
# GOOD: atomic conditional update
updated = User.objects.filter(id=uid, balance__gte=amount).update(balance=F("balance") - amount)
if not updated: raise InsufficientFunds
```
Coupons and refunds: unique DB constraint on (user, coupon), idempotency keys, recompute totals on the server, and never trust a price from the client.

### Error handling (fail closed)
```python
try:
    allowed = authz.check(user, resource)
except Exception:
    allowed = True        # BAD: fail-open
```
Production error responses must not include stack traces, SQL or internal paths.

## 4. Framework-specific settings

| Framework | Check |
|---|---|
| Django | `DEBUG=False`, `ALLOWED_HOSTS` set, `SECRET_KEY` from env, `SESSION_COOKIE_SECURE/HTTPONLY`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT`; run `python manage.py check --deploy` |
| Flask | `debug=False`, `SECRET_KEY` from env, `SESSION_COOKIE_SECURE/HTTPONLY/SAMESITE`, Flask-WTF CSRF, Talisman for headers |
| FastAPI | CORS allow-list, auth dependency on every router, Pydantic models with `extra="forbid"`, docs (`/docs`) disabled or protected in prod if sensitive |
| Express / Node | `helmet()`, `express-rate-limit`, `cors` allow-list, `app.disable('x-powered-by')`, body size limits, `cookie: {secure, httpOnly, sameSite}` |
| Next.js | server actions and API routes check auth, no secrets in `NEXT_PUBLIC_*`, headers set in `next.config.js`, middleware covers all protected paths |
| Laravel | `APP_DEBUG=false`, `APP_KEY` secret, `$fillable` (not `$guarded = []`), policies and gates on every controller action |
| Rails | `config.force_ssl`, strong parameters, `protect_from_forgery`, Brakeman scan |
| Spring | Spring Security on all routes, actuator endpoints restricted, CSRF on, no `permitAll` on sensitive paths |
| ASP.NET | `[Authorize]` by default, anti-forgery tokens, custom errors on, `UseHsts`, `UseHttpsRedirection` |
| WordPress (custom code) | `current_user_can()` + `check_admin_referer()`/nonces on every action, `$wpdb->prepare`, `esc_html/esc_attr/esc_url` on output, `sanitize_*` on input |

## 5. Dependency & secret scanning tools

| Ecosystem | Command |
|---|---|
| Node | `npm audit --omit=dev` / `pnpm audit` / `yarn npm audit` |
| Python | `pip-audit` (or `pip-audit -r requirements.txt`) |
| PHP | `composer audit` |
| Ruby | `bundle audit check --update` |
| Go | `govulncheck ./...` |
| Java | OWASP Dependency-Check, `mvn org.owasp:dependency-check-maven:check` |
| .NET | `dotnet list package --vulnerable` |
| Any | `osv-scanner -r .`, `trivy fs .` (also scans IaC and containers) |
| Secrets | `gitleaks detect` (scans git history), `trufflehog git file://.` |
| SAST | `semgrep --config auto`, Bandit (Python), Brakeman (Rails), CodeQL |

Only run tools that are installed, or ones the user agrees to install. Don't install packages without asking.

## 6. Writing up code findings

For each confirmed issue include: file:line, bug class, OWASP mapping, attacker scenario (one sentence, concrete), fix (diff or code), and how to test the fix. Group false positives from the scanner into one line ("12 scanner hits reviewed and dismissed: test fixtures, sanitized inputs") so the owner knows they were checked.
