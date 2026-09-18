import asyncio
from agentic_threat_intelligence.communication.bus import InMemoryAgentBus
from agentic_threat_intelligence.communication.envelope import AgentEnvelope
from agentic_threat_intelligence.communication.security import DEFAULT_DISCLOSURE_POLICY
async def handler(m):
    return m.reply(sender='threat-intelligence',payload={'status':'complete','url_count':len(m.payload.get('urls',[]))})
async def main():
    bus=InMemoryAgentBus(DEFAULT_DISCLOSURE_POLICY); bus.register_handler('threat-intelligence',handler)
    req=AgentEnvelope.request(case_id='case-123',sender='orchestrator',recipient='threat-intelligence',schema_version='IndicatorRequest/v1',trace_id='trace-abc',payload={'subject':'secret','sanitized_body':'hidden','urls':['https://example.xyz/verify'],'domains':['example.xyz']})
    print(await bus.request(req))
if __name__=='__main__': asyncio.run(main())
