from __future__ import annotations
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import socket
from urllib.parse import urlsplit, urlunsplit
import idna

BLOCKED_NETWORKS = [
    ip_network("127.0.0.0/8"), ip_network("10.0.0.0/8"), ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"), ip_network("169.254.0.0/16"), ip_network("100.64.0.0/10"),
    ip_network("::1/128"), ip_network("fc00::/7"), ip_network("fe80::/10"), ip_network("::ffff:127.0.0.0/104"),
    ip_network("::ffff:10.0.0.0/104"), ip_network("::ffff:172.16.0.0/108"), ip_network("::ffff:192.168.0.0/112"),
]
METADATA_HOSTS={"169.254.169.254","metadata.google.internal","metadata.azure.internal","instance-data.ec2.internal"}

class ScopeViolation(ValueError): pass

def normalize_domain(value: str) -> str:
    value=value.strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        raise ScopeViolation("Target must be a hostname, not a URL")
    try:
        value=idna.encode(value).decode("ascii")
    except idna.IDNAError as exc:
        raise ScopeViolation("Invalid hostname") from exc
    if len(value)>253 or not value or ".." in value or any(len(p)>63 or not p for p in value.split(".")):
        raise ScopeViolation("Invalid hostname")
    allowed=set("abcdefghijklmnopqrstuvwxyz0123456789.-")
    if any(c not in allowed for c in value): raise ScopeViolation("Invalid hostname")
    return value

def validate_ip_not_private(ip: str) -> None:
    parsed=ip_address(ip)
    if any(parsed in n for n in BLOCKED_NETWORKS) or parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast:
        raise ScopeViolation(f"Resolved address is not permitted: {ip}")

def resolve_public(host: str) -> list[str]:
    host=normalize_domain(host)
    if host in METADATA_HOSTS: raise ScopeViolation("Metadata endpoint blocked")
    seen=set(); ips=[]
    for fam,_,_,_,sockaddr in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM):
        ip=sockaddr[0]
        if ip not in seen:
            validate_ip_not_private(ip); seen.add(ip); ips.append(ip)
    if not ips: raise ScopeViolation("Host did not resolve to a permitted address")
    return ips

def normalized_url(url: str, default_scheme="https") -> str:
    raw=url.strip()
    if "://" not in raw: raw=f"{default_scheme}://{raw}"
    p=urlsplit(raw)
    if p.scheme not in {"http","https"} or not p.hostname: raise ScopeViolation("Only http/https targets are permitted")
    host=normalize_domain(p.hostname)
    port=p.port
    if port not in (None,80,443): raise ScopeViolation("Only standard HTTP(S) ports are permitted")
    path=p.path or "/"
    return urlunsplit((p.scheme, f"{host}:{port}" if port else host, path, p.query, ""))

def host_matches_scope(host: str, root: str, patterns: list[str]) -> bool:
    host=normalize_domain(host); root=normalize_domain(root)
    if host==root or host.endswith("."+root):
        if not patterns: return host==root
    for p in patterns:
        p=normalize_domain(p.replace("*.",""))
        if host==p or host.endswith("."+p): return True
    return False

@dataclass(frozen=True)
class ScopeRules:
    root_domain: str
    allowed_hosts: tuple[str,...]
    allowed_paths: tuple[str,...]
    excluded_hosts: tuple[str,...]
    excluded_paths: tuple[str,...]

    def allows_url(self, url: str) -> bool:
        u=normalized_url(url); p=urlsplit(u); host=p.hostname or ""
        if any(host==h or host.endswith("."+h) for h in self.excluded_hosts): return False
        if not host_matches_scope(host,self.root_domain,list(self.allowed_hosts)): return False
        if self.allowed_paths and not any(p.path.startswith(x) for x in self.allowed_paths): return False
        if any(p.path.startswith(x) for x in self.excluded_paths): return False
        resolve_public(host)
        return True
