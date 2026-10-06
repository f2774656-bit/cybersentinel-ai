import os
os.environ.setdefault('JWT_SECRET','test-secret-'+'x'*64)
from cryptography.fernet import Fernet
os.environ.setdefault('ENCRYPTION_KEY',Fernet.generate_key().decode())
from app.core.security import hash_password,verify_password,create_access_token,decode_token,encrypt_secret,decrypt_secret
from app.services.scope import normalize_domain,resolve_public,ScopeViolation

def test_password_roundtrip():
    h=hash_password('correct horse battery staple 123!')
    assert h!= 'correct horse battery staple 123!'
    assert verify_password('correct horse battery staple 123!',h)
    assert not verify_password('wrong',h)

def test_jwt_roundtrip():
    t=create_access_token('abc','ANALYST'); p=decode_token(t,'access'); assert p['sub']=='abc'

def test_secret_encryption_roundtrip():
    assert decrypt_secret(encrypt_secret('top-secret'))=='top-secret'

def test_scope_normalization():
    assert normalize_domain(' Example.COM. ')=='example.com'
    try: resolve_public('localhost')
    except ScopeViolation: pass
    else: raise AssertionError('localhost must be blocked')

def test_metadata_host_block():
    try: resolve_public('169.254.169.254')
    except ScopeViolation: pass
    else: raise AssertionError('metadata must be blocked')
