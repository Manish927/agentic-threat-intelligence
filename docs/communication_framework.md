# Communication Framework

## Core flow

```mermaid
flowchart LR
    O[Orchestrator / Agent] --> B[Communication Bus]
    B --> A[Specialist Agent]
    A --> M[MCP Adapter]
    M --> S[MCP Server]
    S --> T[External Tool]
    A -->|Response / Event| B
    B -->|Response / Event| O
    R[Capability Registry] --> B
    A --> R
```

## Patterns

- Mediator — communication bus controls collaboration.
- Registry — dynamic capability discovery.
- Command — typed requests represent work.
- Observer / Pub-Sub — events and progress updates.
- Adapter — MCP and model-provider integration.
- Strategy — disclosure and routing policy.
- Circuit Breaker — remote dependency isolation.

## Transport evolution

```mermaid
flowchart LR
    I[AgentBus Interface] --> M[In-memory Reference]
    I --> K[Kafka]
    I --> N[NATS]
    I --> R[Redis Streams]
    I --> G[Google Pub/Sub]
    I --> A[AWS EventBridge / SQS]
```
