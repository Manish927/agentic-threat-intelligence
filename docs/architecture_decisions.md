# Architecture Decisions
- **Python-only Agentic Platform:** reuse the working ML/security foundation and reduce friction around agent/MCP/model integration.
- **Specialists, not wrappers:** only reasoning-heavy tasks become agents.
- **Deterministic authority:** agent recommendations are advisory; final policy is deterministic.
- **MCP for tools/context:** MCP is not the internal message bus.
- **Typed contracts:** no undocumented cross-agent dictionaries.
- **Scoped immutable case views:** minimum necessary information per agent.
- **Orchestrated communication:** collaboration passes through a mediator to preserve auditability and loop control.
- **Provider-neutral model boundary:** Gemini and future providers are adapters.
