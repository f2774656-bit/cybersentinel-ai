from __future__ import annotations
import re, ssl, socket
from datetime import datetime, timezone
from urllib.parse import urljoin
import dns.asyncresolver
from .http_client import SafeHTTPClient
from app.services.scope import normalize_domain, normalized_url, resolve_public

SEC_HEADERS={
    "content-security-policy":("MEDIUM","Content-Security-Policy is missing", "CWE-693","A05:2021"),
    "strict-transport-security":("MEDIUM","Strict-Transport-Security is missing on HTTPS", "CWE-319","A02:2021"),
    "x-content-type-options":("LOW","X-Content-Type-Options is missing", "CWE-693","A05:2021"),
    "referrer-policy":("LOW","Referrer-Policy is missing", "CWE-200","A05:2021"),
    "permissions-policy":("LOW","Permissions-Policy is missing", "CWE-693","A05:2021"),
    "x-frame-options":("LOW","Frame protection header is missing", "CWE-1021","A05:2021"),
}

def finding(title,category,severity,confidence,description,evidence,url,impact,remediation,cwe=None,owasp=None,refs=None):
    return dict(title=title,category=category,severity=severity,confidence=confidence,cwe=cwe,owasp_category=owasp,description=description,evidence=evidence,affected_url=url,impact=impact,remediation=remediation,references=refs or [])

async def dns_module(host):
    r=dns.asyncresolver.Resolver(); data={}
    for typ in ("A","AAAA","CNAME","NS","MX","TXT","CAA"):
        try:
            ans=await r.resolve(host,typ,lifetime=5)
            data[typ]=[x.to_text() for x in ans]
        except Exception: data[typ]=[]
    try:
        ans=await r.resolve(host,"DNSKEY",lifetime=5); data["DNSSEC"]={"dnskey_present":bool(ans)}
    except Exception: data["DNSSEC"]={"dnskey_present":False}
    return data

def tech_detect(headers:dict, body:bytes):
    text=body[:300_000].decode("utf-8","ignore").lower(); h={k.lower():v for k,v in headers.items()}; out=[]
    def add(name,conf,evidence): out.append({"name":name,"confidence":conf,"evidence":evidence})
    if "cloudflare" in h.get("server","").lower() or "cf-ray" in h: add("Cloudflare","CONFIRMED","server/cf-ray header")
    if "wp-content" in text or "wp-includes" in text: add("WordPress","LIKELY","WordPress asset path observed")
    m=re.search(r'<meta[^>]+name=[\"\']generator[\"\'][^>]+content=[\"\']([^\"\']+)',text,re.I)
    if m: add(m.group(1),"CONFIRMED","generator meta tag")
    if "next/static/" in text: add("Next.js","LIKELY","/_next/static asset path")
    if "react" in text and "data-reactroot" in text: add("React","POSSIBLE","React marker")
    return out

async def http_module(client: SafeHTTPClient, base_url: str):
    r=await client.get(base_url)
    headers={k.lower():v for k,v in r["headers"].items()}
    checks=[]
    for key,(sev,title,cwe,owasp) in SEC_HEADERS.items():
        if key not in headers and not (key=="strict-transport-security" and not base_url.startswith("https://")):
            checks.append(finding(title,"security-headers",sev,"HIGH",f"Response from {r['url']} did not include {key}.",{"header_present":False,"headers":r["headers"]},r["url"],"Browsers may lack an important defense-in-depth control.",f"Configure an appropriate {key} header at the edge/origin.",cwe,owasp))
    if base_url.startswith("http://") and r["status"] in {200,201,204,301,302,307,308}:
        loc=r["headers"].get("location","")
        if not loc.startswith("https://"):
            checks.append(finding("HTTP endpoint does not clearly redirect to HTTPS","transport","MEDIUM","HIGH","The HTTP endpoint did not return an HTTPS Location header.",{"status":r["status"],"location":loc},base_url,"Users can reach the service over plaintext HTTP.","Redirect HTTP to HTTPS for all public application routes.","CWE-319","A02:2021"))
    tech=tech_detect(r["headers"],r["body"])
    for k in ("server","x-powered-by","x-runtime","x-debug"):
        if k in headers and headers[k]:
            checks.append(finding(f"Information disclosure via {k} header","information-disclosure","LOW","HIGH",f"Response exposes {k}={headers[k]}.",{"header":k,"value":headers[k]},r["url"],"Implementation details can aid fingerprinting.",f"Remove or minimize unnecessary {k} response header."))
    return r,checks,tech

async def cookie_module(client: SafeHTTPClient, url: str):
    r=await client.get(url,allow_redirects=False); finds=[]
    for raw in r["cookies"]:
        parts=[p.strip() for p in raw.split(";")]; name=parts[0].split("=",1)[0].strip(); attrs={p.split("=",1)[0].lower():p.split("=",1)[1] if "=" in p else True for p in parts[1:]}
        if not url.startswith("https://"): continue
        if "secure" not in attrs: finds.append(finding(f"Cookie {name} missing Secure attribute","cookies","MEDIUM","HIGH","A cookie set over HTTPS lacks Secure.",{"cookie":name,"attributes":attrs},url,"The cookie could be sent over plaintext HTTP if reachable.","Set Secure on session and sensitive cookies.","CWE-614","A05:2021"))
        if "httponly" not in attrs: finds.append(finding(f"Cookie {name} missing HttpOnly attribute","cookies","LOW","HIGH","A cookie lacks HttpOnly.",{"cookie":name,"attributes":attrs},url,"Client-side script can read the cookie.","Set HttpOnly for session/authentication cookies where appropriate.","CWE-1004","A05:2021"))
        if "samesite" not in attrs: finds.append(finding(f"Cookie {name} missing SameSite attribute","cookies","LOW","HIGH","A cookie lacks SameSite policy.",{"cookie":name,"attributes":attrs},url,"Cross-site request leakage risk may increase.","Set SameSite=Lax/Strict or None; Secure when justified.","CWE-1275","A07:2021"))
        domain=attrs.get("domain")
        if domain and str(domain).startswith("."): finds.append(finding(f"Cookie {name} has broad Domain scope","cookies","LOW","MEDIUM","Cookie Domain is scoped to a parent domain.",{"cookie":name,"domain":domain},url,"Subdomains may receive the cookie.","Narrow Domain scope when cross-subdomain sharing is not required.","CWE-1004","A05:2021"))
    return finds

async def cors_module(client: SafeHTTPClient, url: str):
    r=await client.get(url,allow_redirects=False); h={k.lower():v for k,v in r["headers"].items()}; f=[]
    acao=h.get("access-control-allow-origin"); acc=h.get("access-control-allow-credentials")
    if acao=="*": f.append(finding("CORS allows any origin","cors","MEDIUM","HIGH","Access-Control-Allow-Origin is wildcard.",{"allow_origin":acao,"allow_credentials":acc},url,"Cross-origin reads may be broader than intended.","Allow only documented origins and review credentialed requests.","CWE-942","A05:2021"))
    probe="https://cybersentinel.invalid"
    try:
        probe_r=await client.get(url,headers={"User-Agent":"CyberSentinel-AI/1.0","Origin":probe},allow_redirects=False)
        probe_h={k.lower():v for k,v in probe_r["headers"].items()}
        if probe_h.get("access-control-allow-origin")==probe:
            f.append(finding("CORS reflects arbitrary Origin","cors","HIGH","HIGH","A benign cross-origin probe was reflected in Access-Control-Allow-Origin.",{"probe_origin":probe,"allow_origin":probe_h.get("access-control-allow-origin"),"allow_credentials":probe_h.get("access-control-allow-credentials")},url,"Untrusted origins may be granted cross-origin access.","Use an explicit origin allowlist and validate Origin before sending CORS headers.","CWE-942","A05:2021"))
    except Exception:
        pass
    if acao=="*" and str(acc).lower()=="true": f.append(finding("CORS combines wildcard origin with credentials","cors","HIGH","HIGH","Wildcard ACAO was observed alongside credentials.",{"allow_origin":acao,"allow_credentials":acc},url,"This is an unsafe combination for credentialed CORS.","Never combine wildcard ACAO with credentials; use an explicit allowlist.","CWE-942","A05:2021"))
    return f

async def behavior_module(client: SafeHTTPClient, url: str):
    o=await client.head_options(url); f=[]
    opt=o.get("OPTIONS",{}); allow=(opt.get("allow") or "").upper()
    dangerous=sorted(set(allow.split(",")) & {"TRACE","CONNECT"})
    if dangerous: f.append(finding("Potentially unsafe HTTP methods advertised","http-behavior","LOW","MEDIUM","OPTIONS advertises TRACE/CONNECT.",{"allow":allow,"methods":dangerous},url,"Unexpected methods may expand attack surface.","Disable unneeded methods at the reverse proxy/application.","CWE-749","A05:2021"))
    return f

async def robots_sitemap_module(client: SafeHTTPClient, base_url: str):
    out={}
    for path in ("/robots.txt","/sitemap.xml"):
        try:
            r=await client.get(urljoin(base_url,path),allow_redirects=False)
            out[path]={"status":r["status"],"content_type":r["content_type"],"body":r["body"].decode("utf-8","replace")[:100000]}
        except Exception as exc: out[path]={"error":str(exc)}
    return out

async def tls_module(host: str):
    result={"host":host}; finds=[]
    verified_error=None
    ctx=ssl.create_default_context()
    try:
        with socket.create_connection((host,443),timeout=6) as sock:
            with ctx.wrap_socket(sock,server_hostname=host) as ss:
                cert=ss.getpeercert(); result.update({"tls_version":ss.version(),"cipher":ss.cipher()[0] if ss.cipher() else None,"not_after":cert.get("notAfter"),"subject":cert.get("subject"),"issuer":cert.get("issuer")})
    except ssl.SSLCertVerificationError as exc:
        verified_error=str(exc); result["verification_error"]=verified_error
    except Exception as exc:
        verified_error=str(exc); result["error"]=verified_error

    # Retrieve the presented certificate without trusting it, solely for evidence inspection.
    try:
        insecure=ssl._create_unverified_context()
        with socket.create_connection((host,443),timeout=6) as sock:
            with insecure.wrap_socket(sock,server_hostname=host) as ss:
                der=ss.getpeercert(binary_form=True)
                if der:
                    from cryptography import x509
                    cert_obj=x509.load_der_x509_certificate(der)
                    result["subject_dn"]="CN=" + next((a.value for a in cert_obj.subject if a.oid.dotted_string=="2.5.4.3"), "")
                    result["issuer_dn"]="CN=" + next((a.value for a in cert_obj.issuer if a.oid.dotted_string=="2.5.4.3"), "")
                    result["not_before"]=cert_obj.not_valid_before_utc.isoformat()
                    result["expires_at"]=cert_obj.not_valid_after_utc.isoformat()
                    result["days_remaining"]=(cert_obj.not_valid_after_utc-datetime.now(timezone.utc)).days
                    san=[]
                    try:
                        san=[x.value for x in cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
                    except Exception: pass
                    result["subject_alt_names"]=san[:100]
                    result["expired"]=result["days_remaining"]<0
                    result["expiring_soon"]=0<=result["days_remaining"]<14
    except Exception as exc:
        result.setdefault("certificate_inspection_error",str(exc))

    url=f"https://{host}/"
    if result.get("expired"):
        finds.append(finding("TLS certificate is expired","tls","HIGH","HIGH","The presented server certificate is outside its validity period.",{"expires_at":result.get("expires_at"),"days_remaining":result.get("days_remaining")},url,"Clients may reject HTTPS connections or users may see certificate warnings.","Renew the certificate and ensure the full chain is deployed.","CWE-295","A07:2021"))
    elif result.get("expiring_soon"):
        finds.append(finding("TLS certificate expires soon","tls","MEDIUM","HIGH","The presented certificate expires in less than 14 days.",{"expires_at":result.get("expires_at"),"days_remaining":result.get("days_remaining")},url,"An upcoming expiry can cause service disruption if renewal is missed.","Renew before expiration and automate certificate monitoring."))
    if verified_error:
        low=verified_error.lower()
        if "hostname" in low or "doesn't match" in low or "does not match" in low:
            title="TLS certificate hostname validation failed"
            sev="HIGH"
            conf="HIGH"
        else:
            title="TLS certificate validation failed"
            sev="HIGH"
            conf="MEDIUM"
        finds.append(finding(title,"tls",sev,conf,"A standard certificate-verifying TLS handshake failed.",{"verification_error":verified_error,"certificate":{k:result.get(k) for k in ("subject_dn","issuer_dn","expires_at","subject_alt_names")}},url,"Clients may reject the HTTPS connection or the certificate may not provide a valid authenticated channel.","Install a valid certificate for the hostname, with a complete trusted chain and current validity period.","CWE-295","A07:2021"))
    if result.get("tls_version") and result["tls_version"] not in {"TLSv1.2","TLSv1.3"}:
        finds.append(finding("Legacy TLS protocol negotiated","tls","MEDIUM","HIGH","The negotiated TLS version is below TLS 1.2.",{"tls_version":result["tls_version"]},url,"Legacy protocols have weaker security properties.","Prefer TLS 1.2+ and disable obsolete protocol versions where safe."))
    return result, finds

