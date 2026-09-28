# NIST AI RMF 1.0 Coverage (AI/LLM features)

For websites with AI/LLM/RAG/agent features, this skill's `references/ai-llm-security.md` maps to the four functions of the **NIST AI Risk Management Framework 1.0**. (Complements the MITRE ATLAS mapping in `mitre-attack.md`.)

| Function | What it means | Coverage in this skill |
|---|---|---|
| **GOVERN** | Policies, accountability, roles for AI risk | Authorized-testing scope for AI features; keeping secrets/policy out of prompts; vendor/DPA and data-retention guidance in `ai-llm-security.md` |
| **MAP** | Establish context, identify AI risks | Threat model of the LLM/RAG/agent surface: direct & indirect prompt injection, tool/agent abuse, RAG poisoning, cross-tenant leakage, output exfiltration (`ai-llm-security.md`) |
| **MEASURE** | Analyze, assess, benchmark, test | Adversarial/red-team test set (injection prompts, two-tenant tests, markdown-exfil), run in CI before release (`ai-llm-security.md` §test plan) |
| **MANAGE** | Prioritize and act on risks; monitor | Tools act with end-user permissions, human confirmation on side effects, rate/token/cost limits, tenant-filtered retrieval, tool-call logging & alerts, kill switch (`ai-llm-security.md`) |

The central principle in `ai-llm-security.md` — *treat the model as untrusted and enforce security in code around it* — is how the MANAGE function is realized for an agentic web feature.
