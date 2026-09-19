# Engagement Scope & Authorization

Fill this in **before** any active testing. The tester and an authorized signatory of the target organization both keep a copy. Active testing without a signed, in-date authorization is a crime in most jurisdictions (e.g. US CFAA, UK Computer Misuse Act, India IT Act s.43/66) regardless of intent. Bug-bounty participants: paste the program's scope/rules instead of a signature — the published policy is your authorization, and it binds you to its limits.

## 1. Parties
- **Testing organization / tester name:**
- **Client / target organization:**
- **Authorizing signatory (name, title):** _must have authority to grant access to the systems below_
- **Emergency contact during testing (name, phone, email):**

## 2. Authorization statement
> _[Client]_ authorizes _[Tester]_ to perform security testing against the in-scope targets listed below, for the window listed below, using the permitted techniques listed below. This authorization is granted by a person with authority to do so. _[Client]_ understands testing carries inherent risk to availability and data.

- **Signature / date:**
- **For a bug-bounty engagement instead:** program name, URL, and the exact scope + rules-of-engagement text: __________

## 3. In-scope targets (ONLY these)
List exact hosts, domains, IP ranges, apps, and API base paths. Anything not listed is out of scope.
- Domains / subdomains:
- IP addresses / CIDR ranges:
- Applications / URLs:
- APIs (base paths, versions):
- Mobile apps / thick clients:
- Cloud accounts / tenants (IDs):

## 4. Explicitly OUT of scope
- Third-party/SaaS the client doesn't own (payment processors, CDNs, identity providers, hosting control panels) — you may **observe** but not attack these.
- Production data exfiltration beyond proof (see §6).
- Named hosts/paths to avoid:
- Social engineering of staff/customers: **allowed / not allowed** (default: not allowed)
- Physical access: **allowed / not allowed** (default: not allowed)

## 5. Testing window & rate limits
- **Start:** ______  **End:** ______  (testing outside this window is unauthorized)
- Permitted hours (to avoid business impact):
- Max request rate / concurrency:
- Change freeze / maintenance windows to avoid:

## 6. Rules of engagement (impact limits)
- **No denial of service / load testing** unless explicitly authorized here: ______
- **No destructive actions:** no deleting/modifying production data, no ransomware simulation, no persistence that isn't cleaned up.
- **Proof-of-concept only:** demonstrate impact with the *minimum* necessary. For data access, retrieve a single benign record or a row count — never bulk-exfiltrate real PII. For RCE, run a harmless marker command (e.g. `id`, `whoami`) — nothing that alters the system.
- **Credentials provided (if any):** test accounts, roles, API keys — listed separately, never in this file.
- **Discovered secrets/credentials:** report them; do not use them to pivot beyond scope; recommend rotation.
- **Third-party/customer data:** if you encounter it, stop, do not copy it, and report immediately.

## 7. Handling of findings & data
- Where evidence/screenshots are stored, and how they're encrypted:
- Deliverable format and deadline:
- Retest included: yes / no
- Data destruction after the engagement: date/method

## 8. Incident & stop conditions
- If you find an **active compromise by a real attacker**, or cause an outage: stop, contact the emergency contact immediately.
- Client "stop testing" contact and channel:

---
_Keep this file next to the engagement notes. The skill will not provide active-testing steps for a target until an entry here (or a matching bug-bounty scope) covers it, is signed, and is within the testing window._
