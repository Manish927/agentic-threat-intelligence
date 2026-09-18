from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from mcp import Client


class MCPRemoteToolError(RuntimeError):
    """Raised when an MCP server reports a tool-level error."""


class MCPStructuredResultError(RuntimeError):
    """Raised when a tool does not return application-readable JSON."""


@dataclass(frozen=True)
class StreamableHTTPMCPClient:
    """Official MCP Python SDK v2 Streamable HTTP client adapter.

    This implements the project's `MCPClient` protocol. It deliberately
    returns only `structured_content`; model-readable text blocks from remote
    tools are not promoted directly into the trusted application path.

    A Client lifecycle is scoped to one call. For high-volume production
    deployments, place this adapter behind the horizontally scalable MCP
    service layer and enforce provider quotas/caching there.
    """

    endpoint: str

    async def call_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        async with Client(self.endpoint) as client:
            result = await client.call_tool(
                tool_name,
                dict(arguments),
            )

        return self.structured_result(
            tool_name=tool_name,
            result=result,
        )

    @staticmethod
    def structured_result(
        *,
        tool_name: str,
        result: Any,
    ) -> Mapping[str, Any]:
        if bool(getattr(result, "is_error", False)):
            # Do not propagate arbitrary remote error text into the trusted
            # application channel.
            raise MCPRemoteToolError(
                f"MCP tool reported an error: {tool_name}"
            )

        structured = getattr(
            result,
            "structured_content",
            None,
        )
        if not isinstance(structured, Mapping):
            raise MCPStructuredResultError(
                f"MCP tool did not return structured content: {tool_name}"
            )

        return dict(structured)
