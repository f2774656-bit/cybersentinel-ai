import os, uuid
os.environ.setdefault('JWT_SECRET','x'*80)
from cryptography.fernet import Fernet
os.environ.setdefault('ENCRYPTION_KEY',Fernet.generate_key().decode())
from types import SimpleNamespace
from datetime import datetime,timezone
from app.models.all import Severity,Confidence
from app.services.reports import build_report

def test_json_report():
    scan=SimpleNamespace(target=SimpleNamespace(root_domain='example.com',authorization_status='AUTHORIZED'),scope_snapshot={},events=[])
    finding=SimpleNamespace(id=uuid.uuid4(),title='Missing header',severity=Severity.LOW,confidence=Confidence.HIGH,category='security-headers',cwe='CWE-693',owasp_category='A05:2021',description='test',evidence={'x':1},affected_url='https://example.com/',impact='impact',remediation='fix',references=[],detected_at=datetime.now(timezone.utc))
    out=build_report(scan,[finding],None,'json'); assert 'example.com' in out and 'Missing header' in out
