from __future__ import annotations
import csv, io, json, html, os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from app.services.scoring import breakdown

def build_report(scan, findings, ai_output=None, fmt="json", cloudflare_analysis=None):
    score=breakdown(findings)
    payload={"executive_summary":f"Security assessment of {scan.target.root_domain}. Deterministic score: {score['overall']}/100.","scope":scan.scope_snapshot,"authorization":scan.target.authorization_status,"methodology":"Passive reconnaissance and non-destructive HTTP/TLS configuration auditing.","target":{"domain":scan.target.root_domain},"security_score":score,"findings":[{"id":str(f.id),"title":f.title,"severity":f.severity.value,"confidence":f.confidence.value,"category":f.category,"cwe":f.cwe,"owasp":f.owasp_category,"description":f.description,"evidence":f.evidence,"affected_url":f.affected_url,"impact":f.impact,"remediation":f.remediation,"references":f.references} for f in findings],"cloudflare_analysis":cloudflare_analysis,"ai_analysis":ai_output,"scan_timeline":[{"created_at":e.created_at.isoformat(),"level":e.level,"message":e.message} for e in scan.events]}
    if fmt=="json": return json.dumps(payload,ensure_ascii=False,indent=2)
    if fmt=="csv":
        buf=io.StringIO(); w=csv.writer(buf); w.writerow(["id","title","severity","confidence","category","cwe","owasp","affected_url","impact","remediation"])
        for f in findings: w.writerow([f.id,f.title,f.severity.value,f.confidence.value,f.category,f.cwe,f.owasp_category,f.affected_url,f.impact,f.remediation])
        return buf.getvalue()
    if fmt=="html":
        rows="".join(f"<tr><td>{html.escape(f.severity.value)}</td><td>{html.escape(f.title)}</td><td>{html.escape(f.confidence.value)}</td><td>{html.escape(f.description)}</td><td>{html.escape(f.remediation)}</td></tr>" for f in findings)
        return f"<!doctype html><html lang='en'><meta charset='utf-8'><title>CYBERSENTINEL AI Report</title><style>body{{font-family:Arial;background:#0b0e0d;color:#e8fff4;padding:32px}}table{{width:100%;border-collapse:collapse}}td,th{{border:1px solid #1c352a;padding:10px}}h1{{color:#00ff88}}</style><h1>CYBERSENTINEL AI</h1><h2>{html.escape(scan.target.root_domain)}</h2><p>Security score: {score['overall']}/100</p><table><tr><th>Severity</th><th>Finding</th><th>Confidence</th><th>Description</th><th>Remediation</th></tr>{rows}</table></html>"
    if fmt=="pdf":
        buf=io.BytesIO(); doc=SimpleDocTemplate(buf,pagesize=A4); styles=getSampleStyleSheet(); story=[Paragraph("CYBERSENTINEL AI Security Assessment",styles["Title"]),Spacer(1,12),Paragraph(f"Target: {html.escape(scan.target.root_domain)}",styles["Heading2"]),Paragraph(f"Score: {score['overall']}/100",styles["Normal"]),Spacer(1,12)]
        data=[["Severity","Finding","Confidence"]]+[[f.severity.value,f.title,f.confidence.value] for f in findings]
        t=Table(data,repeatRows=1); t.setStyle(TableStyle([("GRID",(0,0),(-1,-1),0.4,colors.grey),("BACKGROUND",(0,0),(-1,0),colors.lightgrey)])); story.append(t); doc.build(story); return buf.getvalue()
    raise ValueError("Unsupported report format")
