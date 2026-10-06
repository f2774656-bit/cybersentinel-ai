from __future__ import annotations
import json
import re
import httpx
from app.core.config import get_settings

class AIProvider:
    async def analyze(self, structured_evidence: dict) -> dict: raise NotImplementedError

class CloudflareWorkersAIProvider(AIProvider):
    def __init__(self, token=None, account_id=None, model=None):
        s=get_settings(); self.token=token or s.cloudflare_ai_token; self.account_id=account_id or s.cloudflare_account_id; self.model=model or s.cloudflare_ai_model; self.base=s.cloudflare_api_base.rstrip("/")
        if not self.token or not self.account_id: raise RuntimeError("Workers AI is not configured")
    async def analyze(self, structured_evidence: dict) -> dict:
        system=("You are a defensive cybersecurity analyst. Only use supplied evidence. "
                "Separate EVIDENCE, INFERENCE, and RECOMMENDATION. Never invent facts. "
                "Return strict JSON with keys summary, technical_analysis, impact, risk_reasoning, remediation, verification, confidence, grouped_findings, duplicate_candidates, false_positive_candidates, prioritization.")
        prompt=system+"\nINPUT:\n"+json.dumps(structured_evidence,ensure_ascii=False)[:100000]
        body={"prompt":prompt}
        url=f"{self.base}/accounts/{self.account_id}/ai/run/{self.model}"
        async with httpx.AsyncClient(timeout=45) as c:
            r=await c.post(url,headers={"Authorization":f"Bearer {self.token}","Content-Type":"application/json"},json=body)
        r.raise_for_status(); data=r.json()
        raw=data.get("result",{}).get("response")
        if not raw: raise RuntimeError("Workers AI returned no response")
        m=re.search(r"\{.*\}",raw,re.S)
        if not m: return {"summary":raw,"technical_analysis":"","impact":"","risk_reasoning":"","remediation":"","verification":"","confidence":0.0,"raw_response":raw}
        return json.loads(m.group(0))
