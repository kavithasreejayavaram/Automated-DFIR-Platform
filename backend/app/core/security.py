import bcrypt
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
import jwt
from app.core.config import settings

def _hash_secret(password: str) -> bytes:
    # Pre-hash with SHA256 to allow arbitrary length passwords safely before bcrypt 72-byte limit
    return hashlib.sha256(password.encode('utf-8')).hexdigest().encode('utf-8')

def get_password_hash(password: str) -> str:
    pwd_bytes = _hash_secret(password)
    salt = bcrypt.gensalt(12)
    hashed = bcrypt.hashpw(pwd_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = _hash_secret(plain_password)
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
