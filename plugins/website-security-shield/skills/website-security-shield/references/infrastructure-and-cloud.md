# Infrastructure & Cloud Review

The web application is only one part of the attack surface. A web bug can escalate like this: container → service account → Kubernetes API → cloud IAM → every other workload and database. This file covers the layers around the application.

## Contents
1. DNS & domain
2. CDN, WAF, cache, proxies
3. Servers & network
4. Cloud (AWS / Azure / GCP)
5. Containers & Kubernetes
6. CI/CD & supply chain
7. DDoS & bots
8. Quick commands for owners who have console access

---

## 1. DNS & domain
- **Registrar account:** MFA, registrar/transfer lock, auto-renew, recovery email on a *different* domain.
- **Subdomain takeover:** list all CNAME/ALIAS records. For each target (S3 bucket, Azure app, Heroku, GitHub Pages, Netlify, Shopify, Zendesk…), confirm the resource still exists and you own it. Remove records **before** deleting cloud resources.
- **Discovery:** check certificate-transparency logs (crt.sh `%.example.com`) for subdomains you forgot.
- **DNSSEC** where your registrar and DNS host support it. Monitor DNS changes.
- **Email authentication:** SPF, DKIM, and DMARC (`p=quarantine` or `reject` once aligned) to stop domain spoofing for phishing.
- **CAA record** to restrict which certificate authorities can issue for your domain.

## 2. CDN, WAF, cache, proxies
- WAF with managed rulesets (OWASP core rules) in blocking mode after a tuning period in log mode.
- **Origin protection:** the origin server accepts traffic only from CDN IP ranges (or through an authenticated tunnel), otherwise attackers bypass the WAF by hitting the origin IP directly.
- **Cache safety:** cache only static assets by path/extension. Authenticated or personalized responses send `Cache-Control: private, no-store`. Don't vary cached content on unkeyed headers (`X-Forwarded-Host`, etc.). This prevents cache poisoning and cache deception.
- **Request smuggling:** use HTTP/2 end-to-end where possible, keep proxies and load balancers patched, and configure the edge to reject requests with both `Content-Length` and `Transfer-Encoding`.
- **Host header:** the app only accepts configured host names.

## 3. Servers & network
- Only 80/443 public. SSH key-only, no root login, restricted by IP or through a bastion or SSM/IAP. Fail2ban or similar.
- Databases, Redis, Elasticsearch, message queues, admin UIs (phpMyAdmin, Kibana, RabbitMQ): **never public**.
- Automatic OS security updates (`unattended-upgrades`, etc.).
- Web server runs as an unprivileged user. Web root isn't writable by the web server except specific upload directories (which must not execute scripts).
- Segment the network: web tier → app tier → data tier, each only reaching what it needs. Restrict egress so a compromised server can't freely call out.

## 4. Cloud (AWS / Azure / GCP)
- **Identity:** MFA on root/global admin, no root access keys, SSO for humans, roles instead of long-lived keys for workloads, least-privilege policies (no `Action: "*"`, `Resource: "*"`). Review unused permissions (IAM Access Analyzer / Recommender).
- **Storage:** account-level "Block Public Access" on. Buckets private by default. Signed URLs for user downloads.
- **Metadata:** enforce IMDSv2 (AWS) and block metadata IPs from SSRF-prone services.
- **Secrets:** Secrets Manager / Key Vault / Secret Manager, KMS encryption, rotation.
- **Databases:** in private subnets, encrypted at rest, automated backups with separate-account or immutable copies, IAM auth where possible.
- **Logging:** CloudTrail (all regions) / Azure Activity Log / GCP Audit Logs to a locked-down bucket. GuardDuty / Defender for Cloud / Security Command Center on.
- **Posture:** AWS Security Hub, Azure Defender, GCP SCC, or open-source Prowler/ScoutSuite for misconfiguration scans (with the owner's approval and read-only credentials).
- **Serverless:** least-privilege function roles, no secrets in plain environment variables where a secret manager is available, input validation (events are untrusted input too).

## 5. Containers & Kubernetes
**Containers**
- Minimal, patched base images (distroless/alpine/slim), image scanning (Trivy/Grype) in CI.
- Run as non-root, `readOnlyRootFilesystem: true`, drop all capabilities, no `privileged: true`, no host mounts of `/var/run/docker.sock`.
- No secrets baked into images or build args.

**Kubernetes**
- API server not public (or restricted and authenticated). No exposed dashboard. etcd never exposed and encrypted.
- RBAC least privilege. No `cluster-admin` for apps. `automountServiceAccountToken: false` unless needed.
- NetworkPolicies default-deny, then allow required flows.
- Pod Security Standards "restricted" via admission control.
- Secrets encrypted at rest, or external secret operator.
- Ingress: TLS, WAF, rate limiting.

## 6. CI/CD & supply chain
- **Source control:** MFA required for the org, protected main branch, required reviews, signed commits for sensitive repos, secret scanning plus push protection.
- **GitHub Actions / GitLab CI:** pin third-party actions to full commit SHA, `permissions:` minimized per workflow, no secrets for `pull_request` from forks, avoid `pull_request_target` with checkout of untrusted code, use OIDC to cloud instead of static keys.
- **Build integrity:** lockfiles committed, reproducible builds, SBOM generation, artifact signing (Sigstore/cosign) for containers.
- **Dependencies:** Dependabot/Renovate with review, audit in CI, scoped private registry names to prevent dependency confusion, watch for typosquats.
- **Deploy credentials:** scoped per environment, rotated, and only usable from CI.

## 7. DDoS & bots
- Edge DDoS protection (Cloudflare, AWS Shield/CloudFront, Azure Front Door, Google Cloud Armor, Akamai).
- Rate limits on: login, signup, password reset, OTP verification, search, checkout, contact forms, expensive API endpoints, AI endpoints.
- Bot management or challenges on abuse signals. Block known bad ASNs only if needed.
- App-level protection: timeouts, request size limits, pagination caps, query complexity limits, background queues for heavy jobs, autoscaling with **budget alerts** (so an attack doesn't become a huge bill).
- Scraping protection for valuable data: auth for sensitive listings, rate limits, no over-exposed API fields.

## 8. Quick commands (read-only) for owners with access
Only suggest these when the owner has the relevant CLI configured and agrees.
```bash
# AWS: public buckets & account public-access block
aws s3control get-public-access-block --account-id <ID>
aws s3api list-buckets --query "Buckets[].Name"
# AWS: IAM users with access keys (look for old/unused keys)
aws iam generate-credential-report && aws iam get-credential-report --query Content --output text | base64 -d
# Kubernetes: who can do everything?
kubectl get clusterrolebindings -o wide | grep cluster-admin
# Containers & IaC scan
trivy fs .      # dependencies, secrets, IaC misconfig
trivy image <image:tag>
```
