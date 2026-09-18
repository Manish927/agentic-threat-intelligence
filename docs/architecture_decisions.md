# Architecture Decisions

- **Python-only Agentic Platform:** reuse the working ML/security foundation and reduce friction around agent/MCP/model integration.
- **Specialists, not wrappers:** only reasoning-heavy tasks become agents.
- **Deterministic authority:** agent recommendations are advisory; final policy is deterministic.
- **MCP for tools/context:** MCP is not the internal message bus.
- **Typed contracts:** no undocumented cross-agent dictionaries.
- **Scoped immutable case views:** minimum necessary information per agent.
- **Orchestrated communication:** collaboration passes through a mediator to preserve auditability and loop control.
- **Provider-neutral model boundary:** Gemini and future providers are adapters.
- **Cloud-neutral security principals:** AWS IAM, GCP workload identity and OIDC users map into one domain identity model.
- **Deny-by-default tool authorization:** discovering an MCP tool does not grant permission to call it.
- **Human approval for destructive actions:** agents may propose destructive actions but cannot execute them without explicit approval.
- **External content is always untrusted data:** email and tool output cannot become control instructions.
