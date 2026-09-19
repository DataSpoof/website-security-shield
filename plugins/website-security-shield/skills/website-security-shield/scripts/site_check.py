#!/usr/bin/env python3
"""
site_check.py - non-intrusive external security health check for a website you own.

Sends roughly 30-40 ordinary HTTP(S) GET requests (no attack payloads, no brute force,
no load) and reports on:
  * HTTPS redirect, TLS certificate expiry, legacy TLS versions accepted
  * Security headers (HSTS, CSP, X-Frame-Options/frame-ancestors, nosniff, Referrer-Policy, ...)
  * Cookie flags (Secure, HttpOnly, SameSite)
  * CORS origin reflection
  * Version / technology leakage in headers
  * Verbose error pages (stack traces) and directory listing
  * Commonly leaked sensitive files (.env, .git, backups, phpinfo, debug endpoints)
  * security.txt presence

Only use on sites you own or are explicitly authorized to test.
Standard library only. Python 3.8+.

Usage:
  python site_check.py https://example.com --authorized [--json] [--skip-paths] [--timeout 10]
"""
import argparse
import datetime as dt
import http.client
import json
import random
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

UA = "website-security-shield/1.0 (owner-authorized health check)"
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}

# path, severity, human label, content signature check (lowercased body -> bool)
SENSITIVE_PATHS = [
    ("/.env", "CRITICAL", "Environment file (often holds DB passwords / API keys)",
     lambda b: any(k in b for k in ("app_key=", "db_password", "database_url", "secret", "api_key", "aws_")) and "=" in b and "<html" not in b),
    ("/.git/HEAD", "CRITICAL", "Git repository exposed (full source code + history downloadable)",
     lambda b: b.startswith("ref:") or (len(b.strip()) == 40 and all(c in "0123456789abcdef" for c in b.strip()))),
    ("/.git/config", "CRITICAL", "Git config exposed", lambda b: "[core]" in b),
    ("/.svn/entries", "HIGH", "Subversion metadata exposed", lambda b: b[:3].strip().isdigit() or "svn" in b),
    ("/.hg/requires", "HIGH", "Mercurial metadata exposed", lambda b: "revlog" in b or "store" in b),
    ("/.DS_Store", "LOW", ".DS_Store file (leaks file names)", lambda b: "bud1" in b),
    ("/wp-config.php.bak", "CRITICAL", "WordPress config backup", lambda b: "db_password" in b or "define(" in b),
    ("/wp-config.php~", "CRITICAL", "WordPress config editor backup", lambda b: "db_password" in b or "define(" in b),
    ("/wp-config.php.save", "CRITICAL", "WordPress config backup", lambda b: "db_password" in b or "define(" in b),
    ("/config.php.bak", "CRITICAL", "PHP config backup", lambda b: "<?php" in b or "password" in b),
    ("/.aws/credentials", "CRITICAL", "AWS credentials file", lambda b: "aws_access_key_id" in b),
    ("/backup.zip", "HIGH", "Site backup archive", None),
    ("/backup.sql", "CRITICAL", "Database dump", lambda b: "create table" in b or "insert into" in b),
    ("/dump.sql", "CRITICAL", "Database dump", lambda b: "create table" in b or "insert into" in b),
    ("/database.sql", "CRITICAL", "Database dump", lambda b: "create table" in b or "insert into" in b),
    ("/site.tar.gz", "HIGH", "Site backup archive", None),
    ("/phpinfo.php", "HIGH", "phpinfo() page (full server configuration)", lambda b: "phpinfo()" in b or "php version" in b),
    ("/info.php", "HIGH", "phpinfo() page", lambda b: "phpinfo()" in b or "php version" in b),
    ("/server-status", "MEDIUM", "Apache server-status (live requests, client IPs)", lambda b: "apache server status" in b),
    ("/actuator/env", "CRITICAL", "Spring Boot actuator env (config + secrets)", lambda b: "propertysources" in b or "activeprofiles" in b),
    ("/actuator/heapdump", "CRITICAL", "Spring Boot heap dump (memory incl. secrets)", None),
    ("/actuator", "MEDIUM", "Spring Boot actuator index", lambda b: "_links" in b),
    ("/debug/vars", "MEDIUM", "Go expvar debug endpoint", lambda b: "memstats" in b),
    ("/docker-compose.yml", "HIGH", "docker-compose file (service layout, sometimes secrets)", lambda b: "services:" in b),
    ("/config.json", "MEDIUM", "Config JSON", lambda b: b.strip().startswith("{") and any(k in b for k in ("password", "secret", "token", "key"))),
    ("/.npmrc", "HIGH", ".npmrc (may contain registry tokens)", lambda b: "registry" in b or "_auth" in b),
    ("/adminer.php", "HIGH", "Adminer database admin tool publicly reachable", lambda b: "adminer" in b),
    ("/phpmyadmin/", "HIGH", "phpMyAdmin publicly reachable", lambda b: "phpmyadmin" in b),
    ("/elmah.axd", "HIGH", "ELMAH error log (.NET)", lambda b: "error log" in b),
    ("/trace.axd", "HIGH", "ASP.NET trace", lambda b: "application trace" in b),
    ("/swagger.json", "INFO", "Public API specification (confirm this is intended)", lambda b: "swagger" in b or "openapi" in b),
    ("/openapi.json", "INFO", "Public API specification (confirm this is intended)", lambda b: "openapi" in b),
]

ERROR_SIGNATURES = [
    "traceback (most recent call last)", "stack trace:", "at java.", "at org.springframework",
    "exception in thread", "werkzeug debugger", "whoops! there was an error", "laravel",
    "django.core", "you're seeing this error because you have debug = true",
    "system.web.httpexception", "server error in '/' application", "fatal error</b>:",
    "warning</b>:", "on line <b>", "sqlstate[", "mysql_fetch", "pg_query(", "ora-0",
    "node_modules/", "at object.<anonymous>", "uncaught exception",
]

LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator",
                 "x-drupal-cache", "x-runtime", "x-version"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def make_opener(follow_redirects=True):
    ctx = ssl.create_default_context()
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if not follow_redirects:
        handlers.append(NoRedirect())
    return urllib.request.build_opener(*handlers)


def fetch(url, timeout, follow=True, headers=None, max_bytes=65536):
    """Return dict(status, headers(list of tuples), body(str lower), url) or dict(error=...)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        resp = make_opener(follow).open(req, timeout=timeout)
        status, hdrs, final = resp.status, resp.getheaders(), resp.geturl()
        body = resp.read(max_bytes)
    except urllib.error.HTTPError as e:
        status, hdrs, final = e.code, list(e.headers.items()) if e.headers else [], url
        try:
            body = e.read(max_bytes)
        except Exception:
            body = b""
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ConnectionError, http.client.HTTPException) as e:
        return {"error": str(getattr(e, "reason", e))}
    return {"status": status, "headers": hdrs, "body": body.decode("utf-8", "replace").lower(),
            "raw_len": len(body), "url": final}


def hget(headers, name):
    vals = [v for k, v in headers if k.lower() == name.lower()]
    return vals[0] if vals else None


def hall(headers, name):
    return [v for k, v in headers if k.lower() == name.lower()]


class Report:
    def __init__(self):
        self.items = []

    def add(self, sev, area, title, detail="", fix=""):
        self.items.append({"severity": sev, "area": area, "title": title, "detail": detail, "fix": fix})


def check_tls(host, port, timeout, rep):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
        not_after = dt.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days = (not_after - dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)).days
        if days < 0:
            rep.add("CRITICAL", "TLS", "Certificate has EXPIRED", f"Expired {-days} days ago", "Renew the certificate and enable auto-renewal.")
        elif days < 14:
            rep.add("HIGH", "TLS", f"Certificate expires in {days} days", cert["notAfter"], "Renew now and enable auto-renewal (e.g. Let's Encrypt / managed certs).")
        elif days < 30:
            rep.add("MEDIUM", "TLS", f"Certificate expires in {days} days", cert["notAfter"], "Confirm auto-renewal is working.")
        else:
            rep.add("PASS", "TLS", f"Valid certificate, {days} days left", f"Negotiated {proto}")
    except ssl.SSLCertVerificationError as e:
        rep.add("CRITICAL", "TLS", "Certificate is not trusted / hostname mismatch", str(e), "Install a valid certificate for this hostname (full chain).")
        return
    except Exception as e:
        rep.add("HIGH", "TLS", "Could not complete TLS handshake", str(e), "Ensure HTTPS is served on port 443 with a valid certificate.")
        return

    # Legacy protocol probe (a normal handshake capped at TLS 1.1)
    for label, ver in (("TLS 1.0", "TLSv1"), ("TLS 1.1", "TLSv1_1")):
        tv = getattr(ssl.TLSVersion, ver, None)
        if tv is None:
            continue
        try:
            c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
            c.minimum_version = tv
            c.maximum_version = tv
            try:
                c.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with c.wrap_socket(sock, server_hostname=host) as ls:
                    if ls.version() not in ("TLSv1", "TLSv1.1"):
                        continue
                    rep.add("MEDIUM", "TLS", f"Server accepts legacy {label}", "",
                            "Disable TLS 1.0/1.1; allow only TLS 1.2 and 1.3.")
        except (ssl.SSLError, OSError, ValueError):
            pass  # rejected (good) or unsupported by local OpenSSL - either way nothing to report


def check_headers(resp, is_https, rep):
    h = resp["headers"]
    hsts = hget(h, "strict-transport-security")
    if is_https:
        if not hsts:
            rep.add("MEDIUM", "Headers", "Missing Strict-Transport-Security (HSTS)", "",
                    "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        else:
            try:
                age = int([p.split("=")[1] for p in hsts.replace(" ", "").split(";") if p.lower().startswith("max-age")][0])
            except Exception:
                age = 0
            if age < 15552000:
                rep.add("LOW", "Headers", "HSTS max-age is short", hsts, "Use max-age of at least 15552000 (180 days), ideally 31536000.")
            else:
                rep.add("PASS", "Headers", "HSTS enabled", hsts)

    csp = hget(h, "content-security-policy")
    csp_ro = hget(h, "content-security-policy-report-only")
    if not csp:
        rep.add("MEDIUM", "Headers", "Missing Content-Security-Policy",
                "Report-only CSP present" if csp_ro else "",
                "Add a CSP (start in Report-Only mode). Main defense-in-depth against XSS and card skimmers.")
    else:
        weak = [w for w in ("'unsafe-inline'", "'unsafe-eval'", " *", "data:") if w in csp and "script-src" in csp]
        if weak and "nonce-" not in csp and "strict-dynamic" not in csp:
            rep.add("LOW", "Headers", "CSP present but weak for scripts", f"Contains {', '.join(weak)}",
                    "Move to nonce- or hash-based script-src and drop 'unsafe-inline'/'unsafe-eval'.")
        else:
            rep.add("PASS", "Headers", "Content-Security-Policy present")

    xfo = hget(h, "x-frame-options")
    if not xfo and not (csp and "frame-ancestors" in csp):
        rep.add("MEDIUM", "Headers", "No clickjacking protection",
                "Neither X-Frame-Options nor CSP frame-ancestors set",
                "Add CSP frame-ancestors 'self' (or X-Frame-Options: DENY).")
    else:
        rep.add("PASS", "Headers", "Clickjacking protection present")

    if (hget(h, "x-content-type-options") or "").lower() != "nosniff":
        rep.add("LOW", "Headers", "Missing X-Content-Type-Options: nosniff", "", "Add: X-Content-Type-Options: nosniff")
    else:
        rep.add("PASS", "Headers", "X-Content-Type-Options: nosniff")

    if not hget(h, "referrer-policy"):
        rep.add("LOW", "Headers", "Missing Referrer-Policy", "", "Add: Referrer-Policy: strict-origin-when-cross-origin")
    if not hget(h, "permissions-policy"):
        rep.add("INFO", "Headers", "No Permissions-Policy", "", "Optionally add: Permissions-Policy: camera=(), microphone=(), geolocation=()")

    for name in LEAKY_HEADERS:
        v = hget(h, name)
        if v and (any(ch.isdigit() for ch in v) or name != "server"):
            rep.add("LOW", "Info leakage", f"Header reveals technology/version: {name}", v,
                    "Remove or genericize this header (hide versions). Patching is still the real fix.")


def check_cookies(resp, is_https, rep):
    cookies = hall(resp["headers"], "set-cookie")
    if not cookies:
        rep.add("INFO", "Cookies", "No cookies set on the homepage", "", "Re-run against a login page to check session cookies (pass that URL).")
        return
    for c in cookies:
        name = c.split("=", 1)[0].strip()
        low = c.lower()
        missing = []
        if is_https and "secure" not in [p.strip() for p in low.split(";")]:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            sessionish = any(k in name.lower() for k in ("sess", "sid", "auth", "token", "login", "jwt", "remember"))
            rep.add("MEDIUM" if sessionish else "LOW", "Cookies", f"Cookie '{name}' missing {', '.join(missing)}", "",
                    "Set Secure; HttpOnly; SameSite=Lax on session/auth cookies.")
        else:
            rep.add("PASS", "Cookies", f"Cookie '{name}' has Secure/HttpOnly/SameSite")


def check_cors(url, timeout, rep):
    evil = "https://cors-check.invalid"
    r = fetch(url, timeout, headers={"Origin": evil})
    if "error" in r:
        return
    acao = hget(r["headers"], "access-control-allow-origin")
    acac = (hget(r["headers"], "access-control-allow-credentials") or "").lower() == "true"
    if acao == evil and acac:
        rep.add("HIGH", "CORS", "CORS reflects any Origin WITH credentials",
                "Any website can read authenticated responses from this origin.",
                "Use an explicit allow-list of trusted origins; never reflect the request Origin.")
    elif acao == evil:
        rep.add("MEDIUM", "CORS", "CORS reflects arbitrary Origin", "", "Replace reflection with an explicit origin allow-list.")
    elif acao == "*" and acac:
        rep.add("HIGH", "CORS", "CORS '*' combined with credentials", "", "Never combine wildcard origin with credentials.")
    elif acao == "*":
        rep.add("INFO", "CORS", "CORS allows all origins (*)", "", "Fine for truly public, non-authenticated content only.")


def rand_path():
    return "/" + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(16)) + ".html"


def check_paths(base, timeout, rep, delay):
    # soft-404 baseline: many sites answer 200 for every path
    baseline = fetch(base + rand_path(), timeout)
    base_len = baseline.get("raw_len", -1) if "error" not in baseline else -1
    base_status = baseline.get("status")

    # verbose error page check using the random-path response
    if "error" not in baseline:
        hits = [s for s in ERROR_SIGNATURES if s in baseline["body"]]
        if hits:
            rep.add("MEDIUM", "Info leakage", "Error page reveals internal details",
                    f"Signatures: {', '.join(hits[:3])}", "Disable debug mode; show generic error pages in production.")

    found_any = False
    for path, sev, label, sig in SENSITIVE_PATHS:
        time.sleep(delay)
        r = fetch(base + path, timeout, follow=False)
        if "error" in r or r["status"] != 200:
            continue
        body = r["body"]
        if sig is not None:
            if not sig(body):
                continue
        else:
            # binary artifacts: require non-HTML content that differs from soft-404 baseline
            ctype = (hget(r["headers"], "content-type") or "").lower()
            if "html" in ctype or (base_status == 200 and abs(r["raw_len"] - base_len) < 64):
                continue
        found_any = True
        rep.add(sev, "Exposed files", f"{path} is publicly accessible", label,
                "Remove it from the web root / block it at the web server, and rotate any secrets it contained.")
    if not found_any:
        rep.add("PASS", "Exposed files", f"None of {len(SENSITIVE_PATHS)} commonly leaked files found")

    # directory listing on common folders
    for d in ("/uploads/", "/wp-content/uploads/", "/images/", "/files/", "/backup/", "/static/"):
        time.sleep(delay)
        r = fetch(base + d, timeout, follow=False)
        if "error" not in r and r["status"] == 200 and ("<title>index of" in r["body"] or "directory listing for" in r["body"]):
            rep.add("MEDIUM", "Exposed files", f"Directory listing enabled at {d}", "",
                    "Disable autoindex (Apache: Options -Indexes; nginx: autoindex off).")

    # security.txt
    r = fetch(base + "/.well-known/security.txt", timeout)
    if "error" in r or r.get("status") != 200 or "contact:" not in r.get("body", ""):
        rep.add("INFO", "Hygiene", "No /.well-known/security.txt", "",
                "Publish one with a Contact: line so researchers can report issues to you (securitytxt.org).")
    else:
        rep.add("PASS", "Hygiene", "security.txt present")


def main():
    ap = argparse.ArgumentParser(description="Non-intrusive website security health check (owner-authorized).")
    ap.add_argument("url")
    ap.add_argument("--authorized", action="store_true",
                    help="Confirm you own this site or have written permission to test it.")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--skip-paths", action="store_true", help="Skip the sensitive-file and directory checks.")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--delay", type=float, default=0.2, help="Seconds between path requests (be gentle).")
    a = ap.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if not a.authorized:
        print("Refusing to run: pass --authorized to confirm you own this site or have permission to test it.")
        sys.exit(2)

    url = a.url if "://" in a.url else "https://" + a.url
    p = urllib.parse.urlparse(url)
    host = p.hostname
    base = f"{p.scheme}://{p.netloc}"
    rep = Report()

    # 1. HTTP -> HTTPS redirect
    if p.scheme == "https":
        r = fetch(f"http://{p.netloc}/", a.timeout, follow=False)
        if "error" not in r:
            loc = hget(r["headers"], "location") or ""
            if r["status"] in (301, 302, 307, 308) and loc.lower().startswith("https://"):
                rep.add("PASS", "HTTPS", f"HTTP redirects to HTTPS ({r['status']})")
            else:
                rep.add("HIGH", "HTTPS", "HTTP does not redirect to HTTPS",
                        f"http:// returned {r['status']}", "Redirect all HTTP traffic to HTTPS with a 301.")
        check_tls(host, p.port or 443, a.timeout, rep)
    else:
        rep.add("HIGH", "HTTPS", "Site checked over plain HTTP", "", "Serve the site over HTTPS only.")

    # 2. Main page
    main_resp = fetch(url, a.timeout)
    if "error" in main_resp:
        rep.add("HIGH", "Availability", "Could not fetch the site", main_resp["error"])
    else:
        is_https = main_resp["url"].startswith("https://")
        check_headers(main_resp, is_https, rep)
        check_cookies(main_resp, is_https, rep)
        body = main_resp["body"]
        if "<title>index of /" in body or "<title>directory listing for /" in body:
            rep.add("MEDIUM", "Exposed files", "Directory listing on the site root", "", "Disable autoindex.")
        if 'name="generator"' in body:
            rep.add("LOW", "Info leakage", "HTML meta generator tag reveals CMS/version", "",
                    "Remove the generator meta tag (and keep the CMS updated).")
        if is_https and "src=\"http://" in body:
            rep.add("LOW", "HTTPS", "Mixed content: resources loaded over http://", "", "Load all resources over HTTPS.")
        check_cors(url, a.timeout, rep)

    if not a.skip_paths:
        check_paths(base, a.timeout, rep, a.delay)

    items = sorted(rep.items, key=lambda i: SEV_ORDER[i["severity"]])
    counts = {s: sum(1 for i in items if i["severity"] == s) for s in SEV_ORDER}

    if a.json:
        print(json.dumps({"target": url, "checked_at": dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
                          "summary": counts, "findings": items}, indent=2))
        return

    print(f"\nWebsite security health check: {url}")
    print(f"Checked at {dt.datetime.now(dt.timezone.utc).replace(tzinfo=None):%Y-%m-%d %H:%M} UTC  |  " +
          "  ".join(f"{k}:{v}" for k, v in counts.items() if v))
    print("-" * 78)
    for i in items:
        print(f"[{i['severity']:<8}] {i['area']}: {i['title']}")
        if i["detail"]:
            print(f"            {i['detail']}")
        if i["fix"] and i["severity"] != "PASS":
            print(f"            Fix: {i['fix']}")
    print("-" * 78)
    print("Scope: external, unauthenticated, non-intrusive. Does NOT test logins, access control,")
    print("business logic, injection, or anything behind authentication. Absence of findings != secure.")


if __name__ == "__main__":
    main()
