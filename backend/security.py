"""
security.py — QueryCast Security Utilities
JWT auth (HS256), thread-safe rate limiting, constant-time comparison,
request-ID generation, and structured audit logging.
"""
import hmac
import os
import threading
import time
import uuid
import logging

import jwt


# ── Configuration ──
JWT_SECRET        = os.environ.get('JWT_SECRET') or os.urandom(32).hex()
JWT_TTL           = int(os.environ.get('JWT_TTL_SECONDS', '86400'))
JWT_ALG           = 'HS256'

LOGIN_RATE_MAX    = int(os.environ.get('LOGIN_RATE_MAX', '5'))
LOGIN_RATE_WINDOW = int(os.environ.get('LOGIN_RATE_WINDOW', '900'))


# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)s %(levelname)s %(message)s',
)
audit_logger = logging.getLogger('querycast.audit')


# ── Thread-safe Rate Limiter ──
_attempts: dict = {}
_lock = threading.Lock()


def check_rate_limit(
    identifier: str,
    max_attempts: int = LOGIN_RATE_MAX,
    window: int = LOGIN_RATE_WINDOW,
) -> bool:
    """Return True if within limit; False if exceeded. Thread-safe bucket counter."""
    with _lock:
        current_window = int(time.time() // window)
        key = f"{identifier}:{current_window}"
        _attempts[key] = _attempts.get(key, 0) + 1

        # Prune entries older than 2 windows to prevent unbounded memory growth
        stale = [k for k in list(_attempts) if int(k.rsplit(':', 1)[-1]) < current_window - 1]
        for k in stale:
            del _attempts[k]

        return _attempts[key] <= max_attempts


# ── JWT Utilities ──
def issue_token(subject: str, extra_claims: dict | None = None) -> str:
    """Sign and return an HS256 JWT for *subject*."""
    now = int(time.time())
    payload: dict = {
        'sub': subject,
        'iat': now,
        'exp': now + JWT_TTL,
        'jti': str(uuid.uuid4()),
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(token: str) -> dict:
    """Decode and verify a JWT. Raises jwt.PyJWTError on any failure."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


# ── Request ID ──
def new_request_id() -> str:
    return str(uuid.uuid4())


# ── Constant-time Comparison ──
def secure_compare(a: str, b: str) -> bool:
    """Timing-attack-safe string comparison."""
    return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))


# ── Audit Logging ──
def audit(event: str, request_id: str, ip: str, user: str = '-', **kwargs) -> None:
    """Emit a structured JSON-formatted audit log entry."""
    extra = ''.join(f', "{k}": "{v}"' for k, v in kwargs.items())
    audit_logger.info(
        '{"event": "%s", "request_id": "%s", "ip": "%s", "user": "%s"%s}',
        event, request_id, ip, user, extra,
    )
