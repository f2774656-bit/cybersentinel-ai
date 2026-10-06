from __future__ import annotations
from .http_client import SafeHTTPClient
from .modules import dns_module,http_module,cookie_module,cors_module,behavior_module,robots_sitemap_module,tls_module
from app.services.scope import ScopeRules, normalized_url, resolve_public, ScopeViolation

PROFILES={
    "Quick Audit":["dns","http","headers","cookies","cors","behavior","tls"],
    "Full Web Audit":["dns","http","headers","cookies","cors","behavior","tls","robots"],
    "Passive Recon":["dns","http","tls","robots"],
    "Cloudflare Audit":["dns","http","tls"],
}

async def run_scan(root_domain: str, scopes: dict, profile: str, emit):
    rules=ScopeRules(root_domain=normalized_url(root_domain).split("://",1)[-1].split("/")[0],allowed_hosts=tuple(scopes.get("allowed_hosts",[])),allowed_paths=tuple(scopes.get("allowed_paths",[])),excluded_hosts=tuple(scopes.get("excluded_hosts",[])),excluded_paths=tuple(scopes.get("excluded_paths",[])))
    host=rules.root_domain; resolve_public(host)
    base="https://"+host; rules.allows_url(base)
    client=SafeHTTPClient(delay=0.6,allow_url=rules.allows_url); all_findings=[]; data={}
    modules=PROFILES.get(profile,PROFILES["Quick Audit"])
    if "dns" in modules: await emit("dns","RUNNING"); data["dns"]=await dns_module(host); await emit("dns","COMPLETED")
    if any(x in modules for x in ("http","headers")): await emit("http","RUNNING"); r,f,tech=await http_module(client,base); data["http"]={"status":r["status"],"url":r["url"],"headers":r["headers"],"content_type":r["content_type"],"redirects":r["redirect_history"]}; data["technology"]=tech; all_findings.extend(f); await emit("http","COMPLETED")
    if "cookies" in modules: await emit("cookies","RUNNING"); all_findings.extend(await cookie_module(client,base)); await emit("cookies","COMPLETED")
    if "cors" in modules: await emit("cors","RUNNING"); all_findings.extend(await cors_module(client,base)); await emit("cors","COMPLETED")
    if "behavior" in modules: await emit("behavior","RUNNING"); all_findings.extend(await behavior_module(client,base)); await emit("behavior","COMPLETED")
    if "tls" in modules: await emit("tls","RUNNING"); data["tls"],tls_findings=await tls_module(host); all_findings.extend(tls_findings); await emit("tls","COMPLETED")
    if "robots" in modules: await emit("robots","RUNNING"); data["discovery"]=await robots_sitemap_module(client,base); await emit("robots","COMPLETED")
    return data,all_findings
