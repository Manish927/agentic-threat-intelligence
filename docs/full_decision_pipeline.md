# Full Agentic Decision Pipeline

## Architecture

```mermaid
flowchart TD
    START["Incoming Case"] --> SA["Specialist Analysis"]
    SA --> MI["Message Intelligence"]
    SA --> TI["Threat Intelligence + Secured MCP"]
    MI --> JOIN["Evidence Join"]
    TI --> JOIN
    JOIN --> R["Risk / Triage Agent"]
    R --> P["Policy / Response Agent"]
    P --> DP["Deterministic Policy Engine"]
    DP --> X["Explainability Agent"]
    X --> END["Final Decision Artifact"]
```

## Authority boundary

The agentic stages are advisory. `DeterministicPolicyEngine` is the final authority.

A model may increase scrutiny under explicit deterministic confidence thresholds, but it cannot downgrade deterministic controls. A high-confidence model recommendation to quarantine from a low/medium deterministic baseline is converted into `HUMAN_REVIEW`, not direct quarantine.

```mermaid
flowchart LR
    AR["Agent Recommendation"] --> RULES["Deterministic Rules"]
    DE["Deterministic Evidence"] --> RULES
    RULES --> FINAL["Final Disposition"]
    FINAL --> EXP["Post-decision Explanation"]
```

## Human review

`HUMAN_REVIEW` is now represented explicitly in the returned decision artifact. This phase deliberately does not pause/resume the graph with an in-memory checkpointer.

For the 100+ user cloud deployment, durable human approval should use a shared production checkpointer, preferably PostgreSQL-backed:

- AWS: Aurora/RDS PostgreSQL
- GCP: Cloud SQL PostgreSQL

That avoids process-local state and permits horizontal scaling.

## Explainability

Explainability runs only after the final deterministic decision. It cannot change the disposition and its `AgentResult.recommendation` is always `None`.
