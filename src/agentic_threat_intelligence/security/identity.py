from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Mapping


class PrincipalType(StrEnum):
    USER = "USER"
    AGENT = "AGENT"
    SERVICE = "SERVICE"


@dataclass(frozen=True)
class SecurityPrincipal:
    """Cloud-neutral authenticated identity.

    `subject_id` can map to an AWS IAM principal, GCP service account,
    OIDC subject, or logical agent identity without leaking cloud details
    into the domain layer.
    """

    subject_id: str
    principal_type: PrincipalType
    tenant_id: str | None = None
    scopes: frozenset[str] = field(default_factory=frozenset)
    authenticated: bool = True
    attributes: Mapping[str, str] = field(default_factory=dict)

    def has_scopes(self, required: frozenset[str]) -> bool:
        return required.issubset(self.scopes)
