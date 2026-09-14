# Contract Rules
1. Every cross-agent message uses `AgentEnvelope`.
2. Every payload has a named/versioned contract.
3. Breaking changes create a new major contract version.
4. Evidence and inference are separate.
5. Errors are typed and structured.
6. Correlation ID spans the interaction; causation ID points to the triggering message.
7. Secrets are never domain payloads.
8. Disclosure filtering occurs before dispatch.
