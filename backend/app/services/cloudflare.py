from __future__ import annotations
import httpx
from app.core.config import get_settings

class CloudflareError(RuntimeError): pass

class CloudflareClient:
    def __init__(self, token: str, base: str|None=None):
        self.token=token; self.base=(base or get_settings().cloudflare_api_base).rstrip("/")
    async def request(self, method:str, path:str, params:dict|None=None):
        async with httpx.AsyncClient(timeout=15) as c:
            r=await c.request(method,self.base+path,params=params,headers={"Authorization":f"Bearer {self.token}","Content-Type":"application/json","User-Agent":"CyberSentinel-AI/1.0"})
        try: data=r.json()
        except ValueError: raise CloudflareError(f"Cloudflare returned non-JSON status {r.status_code}")
        if r.status_code>=400 or not data.get("success",False):
            msg="; ".join(x.get("message","unknown") for x in data.get("errors",[])) or f"HTTP {r.status_code}"
            raise CloudflareError(msg)
        return data
    async def accounts(self): return (await self.request("GET","/accounts",{"per_page":50}))["result"]
    async def account(self, account_id): return (await self.request("GET",f"/accounts/{account_id}"))["result"]
    async def zones(self, name=None): return (await self.request("GET","/zones",{"name":name,"per_page":50} if name else {"per_page":50}))["result"]
    async def zone(self, zone_id): return (await self.request("GET",f"/zones/{zone_id}"))["result"]
    async def dns(self, zone_id): return (await self.request("GET",f"/zones/{zone_id}/dns_records",{"per_page":100}))["result"]
    async def settings(self, zone_id): return (await self.request("GET",f"/zones/{zone_id}/settings"))["result"]
    async def rulesets(self, zone_id): return (await self.request("GET",f"/zones/{zone_id}/rulesets",{"per_page":50}))["result"]
    async def security_posture(self, zone_id):
        zone,dns,settings,rulesets=await self.zone(zone_id),await self.dns(zone_id),await self.settings(zone_id),await self.rulesets(zone_id)
        sm={x.get("id"):x.get("value") for x in settings if isinstance(x,dict)}
        waf=[x for x in rulesets if x.get("phase") in {"http_request_firewall_managed","http_request_firewall_custom"}]
        return {"zone":zone,"dns":dns,"settings":settings,"rulesets":rulesets,"posture":{"always_use_https":sm.get("always_use_https"),"ssl_mode":sm.get("ssl"),"min_tls_version":sm.get("min_tls_version"),"tls_1_3":sm.get("tls_1_3"),"waf_ruleset_count":len(waf),"dns_record_count":len(dns),"proxied_dns_records":sum(1 for x in dns if x.get("proxied") is True)}}
    async def graphql(self, query: str, variables: dict):
        async with httpx.AsyncClient(timeout=20) as c:
            r=await c.post(self.base.rsplit('/client/v4',1)[0] + '/client/v4/graphql', headers={"Authorization":f"Bearer {self.token}","Content-Type":"application/json","Accept":"application/json"}, json={"query":query,"variables":variables})
        try: data=r.json()
        except ValueError: raise CloudflareError(f"Cloudflare GraphQL returned non-JSON status {r.status_code}")
        if r.status_code>=400 or data.get("errors"):
            errors=data.get("errors") or []
            msg="; ".join(x.get("message","unknown") for x in errors if isinstance(x,dict)) or f"HTTP {r.status_code}"
            raise CloudflareError(msg)
        return data.get("data")

    async def security_events(self, zone_tag: str, hours: int = 1, limit: int = 50):
        hours=max(1,min(int(hours),24)); limit=max(1,min(int(limit),100))
        from datetime import datetime, timedelta, timezone
        end=datetime.now(timezone.utc); start=end-timedelta(hours=hours)
        query="""query FirewallEvents($zoneTag: string, $filter: FirewallEventsAdaptiveFilter_InputObject) { viewer { zones(filter: { zoneTag: $zoneTag }) { firewallEventsAdaptive(filter: $filter, limit: 100, orderBy: [datetime_DESC]) { action clientAsn clientCountryName clientIP clientRequestPath clientRequestQuery datetime source userAgent } } } }"""
        data=await self.graphql(query,{"zoneTag":zone_tag,"filter":{"datetime_geq":start.isoformat().replace("+00:00","Z"),"datetime_leq":end.isoformat().replace("+00:00","Z")}})
        zones=(data or {}).get("viewer",{}).get("zones",[])
        events=zones[0].get("firewallEventsAdaptive",[]) if zones else []
        return {"hours":hours,"returned":len(events[:limit]),"events":events[:limit]}

    async def test(self, account_id=None, zone_id=None):
        if zone_id: result=await self.zone(zone_id)
        elif account_id: result=await self.account(account_id)
        else: result=await self.accounts()
        return {"ok":True,"resource":result}
