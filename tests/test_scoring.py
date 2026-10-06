from types import SimpleNamespace
from app.models.all import Severity,Confidence
from app.services.scoring import calculate_score,breakdown

def f(s,c,cat='a',url='https://example.com/'):
    return SimpleNamespace(severity=Severity[s],confidence=Confidence[c],category=cat,affected_url=url)

def test_score_monotonic():
    clean=calculate_score([]); high=calculate_score([f('HIGH','HIGH')]); critical=calculate_score([f('CRITICAL','HIGH')]); assert clean==100 and high<100 and critical<high

def test_breakdown_counts():
    x=breakdown([f('HIGH','HIGH'),f('LOW','MEDIUM'),f('INFO','LOW')]); assert x['high']==1 and x['low']==1 and x['info']==1
