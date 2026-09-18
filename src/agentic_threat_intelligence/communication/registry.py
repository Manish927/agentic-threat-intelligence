from __future__ import annotations

from collections.abc import Iterable

from .capability import AgentCapability


class CapabilityNotFound(LookupError):
    pass


class CapabilityRegistry:
    def __init__(self) -> None:
        self._items: dict[str, AgentCapability] = {}

    def register(self, capability: AgentCapability) -> None:
        self._items[
            f"{capability.agent_name}:{capability.version}"
        ] = capability

    def unregister(self, name: str, version: str) -> None:
        self._items.pop(f"{name}:{version}", None)

    def list(self) -> list[AgentCapability]:
        return list(self._items.values())

    def find_by_task(self, task: str) -> list[AgentCapability]:
        return sorted(
            [
                capability
                for capability in self._items.values()
                if task in capability.supported_tasks
            ],
            key=lambda capability: capability.priority,
        )

    def find_by_task_for_scopes(
        self,
        task: str,
        scopes: Iterable[str],
    ) -> list[AgentCapability]:
        granted = frozenset(scopes)
        return [
            capability
            for capability in self.find_by_task(task)
            if capability.required_scopes.issubset(granted)
        ]

    def resolve(self, task: str) -> AgentCapability:
        matches = self.find_by_task(task)
        if not matches:
            raise CapabilityNotFound(f"No agent supports task: {task}")
        return matches[0]

    def resolve_for_scopes(
        self,
        task: str,
        scopes: Iterable[str],
    ) -> AgentCapability:
        matches = self.find_by_task_for_scopes(task, scopes)
        if not matches:
            raise CapabilityNotFound(
                f"No authorized agent supports task: {task}"
            )
        return matches[0]
