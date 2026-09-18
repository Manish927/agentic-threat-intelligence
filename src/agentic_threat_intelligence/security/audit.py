from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


@dataclass(frozen=True)
class SecurityAuditEvent:
    event_type: str
    principal_id: str
    action: str
    resource: str
    allowed: bool
    reason: str
    case_id: str
    trace_id: str
    timestamp_iso: str

    @classmethod
    def create(
        cls,
        *,
        event_type: str,
        principal_id: str,
        action: str,
        resource: str,
        allowed: bool,
        reason: str,
        case_id: str,
        trace_id: str,
    ) -> "SecurityAuditEvent":
        return cls(
            event_type=event_type,
            principal_id=principal_id,
            action=action,
            resource=resource,
            allowed=allowed,
            reason=reason,
            case_id=case_id,
            trace_id=trace_id,
            timestamp_iso=datetime.now(timezone.utc).isoformat(),
        )


class SecurityAuditSink(Protocol):
    async def write(self, event: SecurityAuditEvent) -> None:
        ...


class NullSecurityAuditSink:
    async def write(self, event: SecurityAuditEvent) -> None:
        return None


class InMemorySecurityAuditSink:
    """Test/dev sink. Production adapters can target CloudWatch or GCP Logging."""

    def __init__(self) -> None:
        self.events: list[SecurityAuditEvent] = []

    async def write(self, event: SecurityAuditEvent) -> None:
        self.events.append(event)
