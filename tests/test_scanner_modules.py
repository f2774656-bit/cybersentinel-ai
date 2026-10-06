import os, asyncio
os.environ.setdefault('JWT_SECRET','x'*80)
from cryptography.fernet import Fernet
os.environ.setdefault('ENCRYPTION_KEY',Fernet.generate_key().decode())
from scanner.modules import http_module, cookie_module, cors_module, behavior_module, dns_module, tls_module
from scanner.http_client import SafeHTTPClient

class FakeResponseClient:
    def __init__(self): self.calls=[]
    async def get(self, url, headers=None, allow_redirects=True):
        self.calls.append((url,headers,allow_redirects))
        return {"url":url,"status":200,"headers":{"server":"origin","content-type":"text/html","access-control-allow-origin":"*"},"body":b'<html><head><meta name="generator" content="ExampleCMS"></head></html>',"content_type":"text/html","cookies":[]}
    async def head_options(self,url):
        return {"HEAD":{"status":200,"headers":{}},"OPTIONS":{"status":200,"headers":{},"allow":"GET,POST,OPTIONS,TRACE"}}

class CookieClient:
    async def get(self,*args,**kwargs):
        return {"url":args[0],"status":200,"headers":{},"body":b"","content_type":"text/html","cookies":["sid=abc; Path=/"]}

class CorsClient:
    def __init__(self): self.n=0
    async def get(self,url,headers=None,allow_redirects=True):
        self.n+=1
        origin=headers.get('Origin') if headers else None
        h={'content-type':'text/html'}
        if origin: h['access-control-allow-origin']=origin
        return {"url":url,"status":200,"headers":h,"body":b"","content_type":"text/html","cookies":[]}

async def fake_dns():
    import scanner.modules as m
    original=m.dns.asyncresolver.Resolver
    class R:
        async def resolve(self, host, typ, lifetime=5):
            class X:
                def to_text(self): return 'value.example'
            return [X()]
    m.dns.asyncresolver.Resolver=lambda: R()
    try:
        out=await dns_module('example.com'); assert out['A']==['value.example']; assert out['DNSSEC']['dnskey_present']
    finally: m.dns.asyncresolver.Resolver=original

def test_http_header_and_technology_checks():
    r=asyncio.run(http_module(FakeResponseClient(),'https://example.com'))
    resp, findings, tech=r
    titles={x['title'] for x in findings}
    assert 'Content-Security-Policy is missing' in titles
    assert any(x['confidence']=='CONFIRMED' for x in tech)

def test_cookie_security_checks():
    findings=asyncio.run(cookie_module(CookieClient(),'https://example.com'))
    assert {x['category'] for x in findings}=={'cookies'}
    assert len(findings)>=3

def test_cors_reflection_check_is_evidence_backed():
    findings=asyncio.run(cors_module(CorsClient(),'https://example.com'))
    assert any('reflects arbitrary Origin' in x['title'] for x in findings)

def test_http_behavior_methods():
    findings=asyncio.run(behavior_module(FakeResponseClient(),'https://example.com'))
    assert any('unsafe HTTP methods' in x['title'] for x in findings)

def test_dns_module_with_mocked_resolver():
    asyncio.run(fake_dns())

def test_tls_scanner_fails_closed():
    result, findings=asyncio.run(tls_module('not-a-real-authorized-host.invalid'))
    assert 'error' in result or 'verification_error' in result or 'certificate_inspection_error' in result
    assert isinstance(findings,list)

def test_safe_http_client_requires_scope_callback():
    client=SafeHTTPClient(allow_url=lambda _: False)
    try:
        asyncio.run(client.get('https://example.com'))
    except Exception as exc:
        assert 'outside authorized scope' in str(exc)
    else:
        raise AssertionError('scope callback must reject URL')
