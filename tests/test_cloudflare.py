import os
os.environ.setdefault('JWT_SECRET','x'*80)
from cryptography.fernet import Fernet
os.environ.setdefault('ENCRYPTION_KEY',Fernet.generate_key().decode())
import pytest, httpx
from app.services.cloudflare import CloudflareClient

@pytest.mark.asyncio
async def test_cloudflare_zone_list():
    async def handler(request):
        assert request.headers['Authorization']=='Bearer token'
        return httpx.Response(200,json={'success':True,'result':[{'id':'z1','name':'example.com'}]})
    client=CloudflareClient('token')
    import app.services.cloudflare as cf
    original=httpx.AsyncClient
    class MockAsyncClient:
        def __init__(self,*a,**k): self.client=original(transport=httpx.MockTransport(handler),base_url=client.base)
        async def __aenter__(self): return self.client
        async def __aexit__(self,*a): await self.client.aclose()
    cf.httpx.AsyncClient=MockAsyncClient
    try:
        result=await client.zones()
        assert result[0]['id']=='z1'
    finally: cf.httpx.AsyncClient=original


@pytest.mark.asyncio
async def test_cloudflare_graphql_security_events():
    import httpx
    async def handler(request):
        assert request.url.path.endswith('/graphql')
        payload=request.content.decode()
        assert 'firewallEventsAdaptive' in payload
        return httpx.Response(200,json={'data':{'viewer':{'zones':[{'firewallEventsAdaptive':[{'action':'block','datetime':'2026-10-06T10:00:00Z'}]}]}}})
    client=CloudflareClient('token')
    import app.services.cloudflare as cf
    original=httpx.AsyncClient
    class MockAsyncClient:
        def __init__(self,*a,**k): self.client=original(transport=httpx.MockTransport(handler),base_url=client.base)
        async def __aenter__(self): return self.client
        async def __aexit__(self,*a): await self.client.aclose()
    cf.httpx.AsyncClient=MockAsyncClient
    try:
        out=await client.security_events('z1',1,50); assert out['returned']==1; assert out['events'][0]['action']=='block'
    finally: cf.httpx.AsyncClient=original
