---
name: defensive-ai-security
description: "Securing LLM applications and AI agents: OWASP Top 10 for LLM Applications 2025 (prompt injection, sensitive information disclosure, supply chain, data and model poisoning, improper output handling, excessive agency, system prompt leakage, vector and embedding weaknesses, misinformation, unbounded consumption), OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10: goal hijack, tool misuse, identity and privilege abuse, agentic supply chain, unexpected code execution, memory and context poisoning, insecure inter-agent communication, cascading failures, human-agent trust exploitation, rogue agents), indirect prompt injection defenses, MCP server/tool security, RAG access control, guardrails, logging and detection for AI usage, MITRE ATLAS, and NIST AI RMF. Use when reviewing or monitoring AI features, agents, or AI-assisted SOC tooling."
---

# AI / LLM & Agent Security

Treat model output as untrusted and model input as attacker-reachable. The highest risks come from what an LLM or agent is **allowed to do** (tools, data, credentials) when its instructions can be hijacked by content it reads.

## Quick Workflow

1. Inventory AI features, agents, models, tools/MCP servers, data sources (AIBOM)
2. Threat model with OWASP LLM + Agentic Top 10 and MITRE ATLAS
3. Minimize agency: least-privilege tools, scoped credentials, human approval for impactful actions
4. Isolate untrusted content; validate outputs before use
5. Enforce data access at retrieval (RAG authorization), not in prompts
6. Log prompts/tool calls; detect abuse; red-team regularly

---

## 1. OWASP Top 10 for LLM Applications (2025)

| ID | Risk | Primary controls |
|---|---|---|
| LLM01 | Prompt Injection (direct & indirect) | Separate trusted instructions from untrusted content; least-privilege tools; human approval; output validation; injection classifiers as one layer |
| LLM02 | Sensitive Information Disclosure | Data minimization; DLP on inputs/outputs; no secrets in prompts/context |
| LLM03 | Supply Chain | Vetted models/datasets/plugins; signatures; SBOM/AIBOM |
| LLM04 | Data and Model Poisoning | Provenance for training/fine-tune data; evaluation; anomaly checks |
| LLM05 | Improper Output Handling | Encode/sanitize before rendering (XSS), never pass to shell/SQL/eval without validation |
| LLM06 | Excessive Agency | Minimal tools/permissions; confirmation steps; rate limits |
| LLM07 | System Prompt Leakage | Assume prompts are public; no secrets/authz logic in prompts |
| LLM08 | Vector and Embedding Weaknesses | Per-tenant indexes or ACL-filtered retrieval; poisoning checks |
| LLM09 | Misinformation | Grounding, citations, human review for high-stakes output |
| LLM10 | Unbounded Consumption | Quotas, token/time limits, cost alerts |

---

## 2. OWASP Top 10 for Agentic Applications (2026, published Dec 2025)

| ID | Risk | Controls |
|---|---|---|
| ASI01 | Agent Goal Hijack | Treat retrieved content/emails/tickets/web as data; instruction hierarchy; goal confirmation for sensitive tasks |
| ASI02 | Tool Misuse | Tool allowlists per task; parameter validation; dry-run modes |
| ASI03 | Identity & Privilege Abuse | Per-agent identities; short-lived scoped tokens; no shared admin creds; on-behalf-of with user consent |
| ASI04 | Agentic Supply Chain | Vet MCP servers/tools/plugins; pin versions; signed packages |
| ASI05 | Unexpected Code Execution | Sandboxed code execution (no network/secrets by default); resource limits |
| ASI06 | Memory & Context Poisoning | Validate what's written to memory; provenance; expiry; per-user memory isolation |
| ASI07 | Insecure Inter-Agent Communication | Authenticated, integrity-protected messages; don't trust peer agents blindly |
| ASI08 | Cascading Failures | Circuit breakers, rate limits, blast-radius limits across agent chains |
| ASI09 | Human-Agent Trust Exploitation | Clear provenance of agent actions; avoid persuasive framing for approvals; show diffs |
| ASI10 | Rogue Agents | Behavioral monitoring, kill switches, anomaly detection on agent actions |

---

## 3. Indirect Prompt Injection Defense

```text
- Never give one agent both (a) access to untrusted content and (b) high-impact tools + sensitive data
  without a human approval step ("lethal trifecta": private data + untrusted content + exfil channel)
- Strip/neutralize active content (markdown images/links → exfil via URL params); block rendering of
  external images in AI outputs
- Constrain outbound: egress allowlists for agent HTTP tools; no arbitrary URL fetch with secrets
- Output schemas (JSON with enums) for downstream automation; reject free-form commands
- Detection classifiers help but are bypassable — design assuming injection succeeds
```

---

## 4. MCP / Tool Servers

```text
[ ] Install only reviewed MCP servers; pin versions; verify source
[ ] Run servers with least privilege (separate OS user/container; scoped API tokens)
[ ] Tool descriptions are attacker-controllable for third-party servers (tool poisoning) — review them
[ ] Require user confirmation for write/delete/send/purchase actions
[ ] Log every tool call (who, which agent, params, result) to SIEM
[ ] OAuth for remote MCP with per-user consent; no token passthrough to downstream APIs
```

---

## 5. RAG Security

- Enforce document ACLs at retrieval using the requesting user's identity
- Separate indexes per tenant/classification
- Scan ingested documents for injection payloads and secrets
- Record source citations for every answer; allow users to verify

---

## 6. Monitoring & Detection

| Signal | Source |
|---|---|
| Prompt injection markers in inputs/retrieved docs | App logs, guardrail classifier verdicts |
| Unusual tool call patterns (new tools, high frequency, sensitive params) | Agent/tool logs |
| Data egress via agent (URLs with encoded data, emails to external) | Proxy, email logs |
| Token/cost spikes | Provider usage APIs |
| Shadow AI usage | CASB/SWG logs for AI SaaS domains; DLP on uploads |
| Model/API key leakage | Secret scanning; provider anomaly alerts |

AI in the SOC: attacker-controlled fields in alerts (filenames, subjects, command lines) can carry injections into AI triage — keep AI verdicts advisory, require deterministic evidence for closure, and never let AI auto-execute containment.

---

## 7. Frameworks

| Framework | Use |
|---|---|
| MITRE ATLAS | Adversarial ML tactics/techniques and case studies |
| NIST AI RMF 1.0 + Generative AI Profile (NIST AI 600-1) | Governance (Govern, Map, Measure, Manage) |
| ISO/IEC 42001 | AI management system |
| EU AI Act | Risk-based obligations (phased application) |
| OWASP AI Exchange / GenAI Security Project | Controls guidance, red-teaming guides |

---

## Engagement Cheatsheet

```text
AIBOM → threat model (LLM Top 10 + ASI01–10 + ATLAS) → least agency + scoped identities → untrusted-content isolation
→ output validation + egress control → RAG ACLs → MCP vetting → logging + detections → red-team → governance (AI RMF)
```

---

## Key References

- OWASP Top 10 for LLM Applications 2025; OWASP Top 10 for Agentic Applications 2026 (genai.owasp.org)
- MITRE ATLAS — https://atlas.mitre.org ; NIST AI RMF & AI 600-1
- Model Context Protocol security best practices
- Related: `defensive-soar-automation`, `defensive-api-security`, `defensive-secure-code-review`
