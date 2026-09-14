import asyncio
from dataclasses import dataclass
@dataclass(frozen=True)
class RetryPolicy: attempts:int=3; base_delay_seconds:float=.2
async def retry_async(operation,policy=RetryPolicy()):
    err=None
    for i in range(policy.attempts):
        try: return await operation()
        except Exception as exc:
            err=exc
            if i<policy.attempts-1: await asyncio.sleep(policy.base_delay_seconds*(2**i))
    raise err
