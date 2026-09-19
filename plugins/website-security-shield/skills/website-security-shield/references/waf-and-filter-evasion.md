# WAF & Input-Filter Evasion (Authorized Testing)

Why blocklists and WAFs get bypassed, so an authorized tester can **prove a control is inadequate** and a defender can fix it properly. The lesson for the report is always the same: **a WAF is a speed bump, not a fix.** The real remediation is parameterized queries, output encoding, allow-list validation and server-side authorization — the WAF buys time, nothing more.

**Gate:** active testing only, in scope, in window (`pentest-methodology.md`). Keep payloads benign — the point is to show the filter can be evaded, not to do damage through it.

## Why filters fail (the root causes)

- **Parser differential.** The WAF and the app parse the request differently (URL/Unicode/UTF-8 overlong encoding, mixed case, comments, whitespace variants, duplicate params, `charset` tricks, multipart quirks). The WAF sees something benign; the app sees the payload.
- **Blocklist incompleteness.** Blocking `<script>` misses `<svg onload=>`, `<img onerror=>`, `javascript:`, event handlers, `<iframe srcdoc>`. Blocklists enumerate badness and always miss cases; allow-lists enumerate goodness and don't.
- **Context blindness.** The filter doesn't know the output context (HTML attr vs JS vs URL), so it can't neutralize the right characters.
- **Normalization gaps.** Double-encoding (`%253C`), Unicode normalization, case folding, null bytes, and nested encodings that get decoded *after* the WAF check.
- **Coverage gaps.** Origin reachable directly (bypassing the CDN/WAF entirely — see recon), unfiltered methods/headers/paths, JSON/XML bodies the WAF doesn't inspect, size limits above which it stops scanning.

## Techniques (to demonstrate inadequacy, benignly)

- **Encoding:** URL, double-URL, HTML-entity, Unicode escapes, hex/octal, base64 where the app decodes it.
- **Case & whitespace:** `SeLeCt`, tabs/newlines/comments (`/**/`, `--`, `#`) inside SQL; `<Svg OnLoad>`.
- **Alternative payloads:** for XSS, event-handler and tag variety; for SQLi, logical/`UNION` alternatives, out-of-band; for command injection, `${IFS}`, brace/quote splitting.
- **Request-shape tricks:** parameter pollution (`?id=1&id=payload`), moving input to a body/header/JSON field the WAF ignores, oversize padding, `Content-Type` confusion.
- **Origin bypass:** hit the origin IP directly, or a non-proxied subdomain, so the WAF is never in path.

## What to put in the report

- The specific bypass that worked, as a **benign PoC** (e.g. an SSTI `{{7*7}}` that the WAF passed, a marker XSS that fired).
- The root cause (parser differential / blocklist gap / origin exposed).
- **Remediation, ordered:** (1) fix the underlying vuln (parameterization/encoding/allow-list/authz) so the WAF being bypassed doesn't matter; (2) lock the origin so only the CDN/WAF can reach it; (3) tune the WAF to normalize before inspecting and to inspect all body types; (4) prefer positive-security (allow-list) WAF rules where feasible.
- **Detection:** the client should alert on requests that reach the origin bypassing the edge, on encoded-payload patterns, and on WAF blocks (a spike means someone's probing).

## Framing for the client

Finding a WAF bypass is not "the WAF is worthless" — it's "the WAF cannot be your only control for this input." Every bypass finding pairs with the code-level fix. That's the difference between a scare and a security improvement.
