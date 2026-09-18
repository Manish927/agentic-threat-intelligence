import pytest

from agentic_threat_intelligence.mcp.python_sdk_client import (
    MCPRemoteToolError,
    MCPStructuredResultError,
    StreamableHTTPMCPClient,
)


class FakeResult:
    def __init__(
        self,
        *,
        structured_content=None,
        is_error=False,
    ):
        self.structured_content = structured_content
        self.is_error = is_error


def test_official_mcp_adapter_accepts_structured_content():
    result = StreamableHTTPMCPClient.structured_result(
        tool_name="threat_intel.domain.lookup",
        result=FakeResult(
            structured_content={
                "verdict": "malicious",
                "confidence": 0.95,
                "provider": "test",
            }
        ),
    )

    assert result["verdict"] == "malicious"


def test_official_mcp_adapter_rejects_remote_tool_error():
    with pytest.raises(
        MCPRemoteToolError,
        match="reported an error",
    ):
        StreamableHTTPMCPClient.structured_result(
            tool_name="threat_intel.domain.lookup",
            result=FakeResult(
                structured_content=None,
                is_error=True,
            ),
        )


def test_official_mcp_adapter_requires_structured_content():
    with pytest.raises(
        MCPStructuredResultError,
        match="structured content",
    ):
        StreamableHTTPMCPClient.structured_result(
            tool_name="threat_intel.domain.lookup",
            result=FakeResult(
                structured_content=None,
                is_error=False,
            ),
        )
