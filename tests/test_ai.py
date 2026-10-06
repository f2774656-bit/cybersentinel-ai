import os, httpx, pytest
os.environ.setdefault('JWT_SECRET','x'*80)
from cryptography.fernet import Fernet
os.environ.setdefault('ENCRYPTION_KEY',Fernet.generate_key().decode())
os.environ['CLOUDFLARE_ACCOUNT_ID']='acct'
os.environ['CLOUDFLARE_AI_TOKEN']='token'
from app.services.ai import CloudflareWorkersAIProvider

@pytest.mark.asyncio
async def test_workers_ai_payload_and_json_response():
    seen={}
    async def handler(request):
        import json
        seen['url']=str(request.url); seen['auth']=request.headers.get('authorization'); seen['body']=json.loads(request.content)
        return httpx.Response(200,json={'success':True,'result':{'response':'{"summary":"ok","technical_analysis":"evidence","impact":"impact","risk_reasoning":"reason","remediation":"fix","verification":"verify","confidence":0.9}'}})
    provider=CloudflareWorkersAIProvider()
    import app.services.ai as ai
    old=httpx.AsyncClient
    class MockAsyncClient:
        def __init__(self,*a,**k): self.client=old(transport=httpx.MockTransport(handler))
        async def __aenter__(self): return self.client
        async def __aexit__(self,*a): await self.client.aclose()
    ai.httpx.AsyncClient=MockAsyncClient
    try:
        out=await provider.analyze({'target':'mriranfa.site','finding':{'severity':'LOW'}})
        assert out['summary']=='ok'; assert seen['auth']=='Bearer token'; assert '/accounts/acct/ai/run/' in seen['url']
        assert 'INPUT' in seen['body']['prompt']
    finally: ai.httpx.AsyncClient=old
