from collections import Counter
from app.models.all import Severity, Confidence

SEV_PENALTY={Severity.CRITICAL:35, Severity.HIGH:20, Severity.MEDIUM:10, Severity.LOW:4, Severity.INFO:1}
CONF_MULT={Confidence.HIGH:1.0, Confidence.MEDIUM:0.7, Confidence.LOW:0.4}

def calculate_score(findings) -> float:
    penalty=sum(SEV_PENALTY[f.severity]*CONF_MULT[f.confidence] for f in findings)
    category_factor=min(12, len({f.category for f in findings})*1.2)
    affected_factor=min(8, len({f.affected_url for f in findings if f.affected_url})*0.5)
    raw=100-penalty-category_factor-affected_factor
    return round(max(0.0,min(100.0,raw)),2)

def breakdown(findings):
    c=Counter(f.severity.value for f in findings)
    return {"overall":calculate_score(findings),"critical":c["CRITICAL"],"high":c["HIGH"],"medium":c["MEDIUM"],"low":c["LOW"],"info":c["INFO"]}
