# Security Model
- Agent output is untrusted until schema/policy validation.
- External MCP results are untrusted until validated.
- Credentials never appear in envelopes.
- Minimum-necessary allow-list disclosure is mandatory.
- Correlation/causation IDs, hop limits and invocation budgets prevent uncontrolled loops.
- Production additions: mTLS/workload identity, signed envelopes, OAuth/OIDC scoped tokens, field encryption, DLP/PII redaction, retention controls and policy-as-code.
