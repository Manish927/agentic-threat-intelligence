from dataclasses import dataclass
from typing import Any, Mapping, Protocol
class MCPClient(Protocol):
    async def call_tool(self,tool_name:str,arguments:Mapping[str,Any])->Mapping[str,Any]: ...
@dataclass
class MCPToolAdapter:
    client:MCPClient
    async def invoke(self, *, tool_name, arguments): return await self.client.call_tool(tool_name,arguments)
