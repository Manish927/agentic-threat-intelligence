## Agent Identity, Tool Authorization and Prompt-Injection Boundary

The platform treats agent identity and tool execution as explicit deterministic security boundaries.

```mermaid
flowchart LR
    A["Specialized Agent"] --> I["Authenticated Principal"]
    I --> C["Capability Resolution"]
    C --> P["Deny-by-default Tool Authorization"]
    P -->|Allowed| S["Secured MCP Adapter"]
    P -->|Denied| D["Audit + Deny"]
    S --> M["MCP Server / Tool"]

    E["Email / External Content"] --> B["Prompt/Data Trust Boundary"]
    B --> A
```

Key rules:

- an agent discovering a tool does not imply permission to execute it
- every tool call requires an authenticated principal
- scopes and tool-specific argument policy are deterministic
- destructive actions can require explicit human approval
- email bodies and external tool output are treated as untrusted data
- prompt-injection detection is telemetry, not the primary control
- authorization and final disposition remain outside LLM reasoning
- every tool authorization and execution can be audited

For AWS/GCP portability, the security principal is cloud-neutral and can be backed by AWS IAM, GCP workload identity, or OIDC without changing agent business logic.
