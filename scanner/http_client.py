from __future__ import annotations
import asyncio
from urllib.parse import urlsplit
import aiohttp
from aiohttp.abc import AbstractResolver
from app.services.scope import resolve_public, normalized_url, ScopeViolation

class PinnedResolver(AbstractResolver):
    def __init__(self, ips): self.ips=ips
    async def resolve(self, host, port=0, family=0):
        out=[]
        for ip in self.ips:
            fam=2 if ":" not in ip else 10
            out.append({"hostname":host,"host":ip,"port":port,"family":fam,"proto":0,"flags":0})
        return out
    async def close(self): pass

class SafeHTTPClient:
    def __init__(self, timeout=12, max_redirects=5, max_body=2_000_000, delay=0.6, allow_url=None):
        self.timeout=aiohttp.ClientTimeout(total=timeout, connect=5, sock_read=timeout)
        self.max_redirects=max_redirects; self.max_body=max_body; self.delay=delay; self.allow_url=allow_url

    async def get(self, url: str, headers=None, allow_redirects=True):
        current=normalized_url(url)
        hops=0; history=[]
        while True:
            parsed=urlsplit(current); host=parsed.hostname
            if not host: raise ScopeViolation("Missing host")
            if self.allow_url and not self.allow_url(current): raise ScopeViolation(f"URL outside authorized scope: {current}")
            ips=resolve_public(host)
            resolver=PinnedResolver(ips)
            connector=aiohttp.TCPConnector(resolver=resolver, ssl=__import__("ssl").create_default_context(), limit=2, ttl_dns_cache=0)
            await asyncio.sleep(self.delay)
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector, cookie_jar=aiohttp.DummyCookieJar()) as session:
                async with session.get(current, headers=headers or {"User-Agent":"CyberSentinel-AI/1.0 authorized-audit"}, allow_redirects=False, max_redirects=0) as resp:
                    body=bytearray()
                    async for chunk in resp.content.iter_chunked(65536):
                        body.extend(chunk)
                        if len(body)>self.max_body: break
                    result={"url":current,"status":resp.status,"headers":dict(resp.headers),"body":bytes(body[:self.max_body]),"content_type":resp.headers.get("content-type"),"cookies":resp.headers.getall("set-cookie",[]) if "set-cookie" in resp.headers else []}
                    loc=resp.headers.get("location")
                    history.append({"url":current,"status":resp.status,"location":loc})
                    if allow_redirects and loc and resp.status in {301,302,303,307,308}:
                        if hops>=self.max_redirects: result["redirect_limit_reached"]=True; result["redirect_history"]=history; return result
                        from urllib.parse import urljoin
                        nxt=normalized_url(urljoin(current,loc))
                        hops+=1; current=nxt; continue
                    result["redirect_history"]=history; return result

    async def head_options(self,url):
        current=normalized_url(url); parsed=urlsplit(current); ips=resolve_public(parsed.hostname)
        resolver=PinnedResolver(ips); connector=aiohttp.TCPConnector(resolver=resolver,ssl=False,limit=2,ttl_dns_cache=0)
        async with aiohttp.ClientSession(timeout=self.timeout,connector=connector,cookie_jar=aiohttp.DummyCookieJar()) as session:
            out={}
            for method in ("HEAD","OPTIONS"):
                try:
                    async with session.request(method,current,allow_redirects=False,headers={"User-Agent":"CyberSentinel-AI/1.0"}) as r:
                        out[method]={"status":r.status,"headers":dict(r.headers),"allow":r.headers.get("allow")}
                except Exception as exc: out[method]={"error":str(exc)}
            return out
