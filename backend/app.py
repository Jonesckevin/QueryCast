"""
app.py — QueryCast Flask API Backend
Provides: JWT auth, rate limiting, CORS, Socket.io WebSocket hardening,
file-upload security, proxy/HTTPS trust, and structured audit logging.
"""
import functools
import logging
import os
import time
import uuid
from pathlib import Path

import jwt as pyjwt
from flask import Flask, abort, g, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, disconnect

from security import (
    JWT_TTL,
    audit,
    check_rate_limit,
    issue_token,
    new_request_id,
    secure_compare,
    verify_token,
)


# ── Configuration ──
CORS_ORIGINS         = os.environ.get('CORS_ALLOWED_ORIGINS', 'http://localhost:9013').split(',')
TRUST_PROXY          = os.environ.get('TRUST_PROXY', 'false').lower() == 'true'
UPLOAD_MAX_BYTES     = int(os.environ.get('UPLOAD_MAX_BYTES', str(5 * 1024 * 1024)))   # 5 MB
UPLOAD_ALLOWED_EXT   = {'txt', 'log', 'csv', 'json', 'yml', 'yaml', 'xml', 'conf', 'sigma'}
UPLOAD_DIR           = Path(os.environ.get('UPLOAD_DIR', '/data/uploads'))
SOCKET_PING_TIMEOUT  = int(os.environ.get('SOCKET_PING_TIMEOUT', '20'))
SOCKET_PING_INTERVAL = int(os.environ.get('SOCKET_PING_INTERVAL', '25'))

app_log = logging.getLogger('querycast.app')


# ── Flask Application ──
app = Flask(__name__)
app.config.update(
    MAX_CONTENT_LENGTH=UPLOAD_MAX_BYTES,
    # Independently generated secret so Flask sessions are also protected
    SECRET_KEY=os.environ.get('FLASK_SECRET_KEY') or os.urandom(32).hex(),
    PROPAGATE_EXCEPTIONS=True,
)

# Honour X-Forwarded-* headers only when explicitly opted in (prevents IP spoofing)
if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

CORS(
    app,
    origins=CORS_ORIGINS,
    supports_credentials=True,
    methods=['GET', 'POST', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Request-ID'],
)

# Socket.io with hardened timeouts and message-size cap
socketio = SocketIO(
    app,
    cors_allowed_origins=CORS_ORIGINS,
    ping_timeout=SOCKET_PING_TIMEOUT,
    ping_interval=SOCKET_PING_INTERVAL,
    max_http_buffer_size=1_048_576,   # 1 MB per message
    async_mode='eventlet',
)


# ── Request / Response Lifecycle ──
@app.before_request
def attach_context() -> None:
    g.request_id = request.headers.get('X-Request-ID') or new_request_id()
    g.start_time = time.time()
    # remote_addr is rewritten by ProxyFix when TRUST_PROXY=true
    g.remote_ip  = request.remote_addr


@app.after_request
def add_security_headers(response):
    rid     = getattr(g, 'request_id', '-')
    elapsed = int((time.time() - getattr(g, 'start_time', time.time())) * 1000)

    # Per-response security headers (complements nginx-level headers for direct access)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options']         = 'DENY'
    response.headers['Referrer-Policy']         = 'strict-origin-when-cross-origin'
    response.headers['X-Request-ID']            = rid

    audit(
        event='http_response',
        request_id=rid,
        ip=getattr(g, 'remote_ip', '-'),
        method=request.method,
        path=request.path,
        status=str(response.status_code),
        ms=str(elapsed),
    )
    return response


# ── JWT Auth Decorator ──
def require_jwt(f):
    """Route decorator — enforces a valid Bearer JWT in the Authorization header."""
    @functools.wraps(f)
    def _wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            abort(401)
        token = auth.split(' ', 1)[1]
        try:
            g.jwt_claims = verify_token(token)
        except pyjwt.ExpiredSignatureError:
            abort(401)
        except pyjwt.PyJWTError:
            abort(403)
        return f(*args, **kwargs)
    return _wrapper


# ── File Upload Helpers ──
def _allowed_extension(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in UPLOAD_ALLOWED_EXT


# ── Routes ──
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'timestamp': int(time.time())})


@app.route('/api/auth/login', methods=['POST'])
def login():
    """Rate-limited login endpoint; issues a JWT on success."""
    ip = g.remote_ip

    if not check_rate_limit(ip):
        audit('rate_limit_exceeded', g.request_id, ip)
        return jsonify({'error': 'Too many attempts. Try again later.'}), 429

    data    = request.get_json(silent=True) or {}
    api_key = data.get('api_key', '')

    expected = os.environ.get('API_KEY', '')
    if not expected or not secure_compare(api_key, expected):
        audit('login_failure', g.request_id, ip)
        return jsonify({'error': 'Invalid credentials.'}), 401

    token = issue_token(subject='api_user')
    audit('login_success', g.request_id, ip)
    return jsonify({'token': token, 'expires_in': JWT_TTL})


@app.route('/api/auth/verify', methods=['GET'])
@require_jwt
def verify():
    """Returns token validity and subject claim."""
    return jsonify({'valid': True, 'sub': g.jwt_claims.get('sub')})


@app.route('/api/upload', methods=['POST'])
@require_jwt
def upload_file():
    """
    Accepts a single file upload.
    Security: JWT required, extension allow-list, path-traversal prevention,
    random UUID prefix on stored filename, MAX_CONTENT_LENGTH enforced by Flask.
    """
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request.'}), 400

    f = request.files['file']
    if not f.filename:
        return jsonify({'error': 'Empty filename.'}), 400

    # Strip any directory component to prevent path traversal
    safe_name = Path(f.filename).name
    if not safe_name or not _allowed_extension(safe_name):
        return jsonify({'error': 'File type not permitted.'}), 415

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"
    f.save(str(dest))

    audit('file_upload', g.request_id, g.remote_ip, filename=safe_name)
    return jsonify({'uploaded': safe_name}), 201


# ── WebSocket Events ──
@socketio.on('connect')
def ws_connect():
    """Reject connections without a valid JWT in the query string."""
    token = (request.args.get('token') or '').strip()
    try:
        verify_token(token)
    except pyjwt.PyJWTError:
        audit('ws_auth_failure', new_request_id(), request.remote_addr)
        disconnect()
        return False
    audit('ws_connect', new_request_id(), request.remote_addr)


@socketio.on('disconnect')
def ws_disconnect():
    audit('ws_disconnect', new_request_id(), request.remote_addr)


@socketio.on_error_default
def ws_error(e):
    app_log.error('WebSocket error: %s', e)


# ── Error Handlers ──
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request.'}), 400


@app.errorhandler(401)
def unauthorized(e):
    return jsonify({'error': 'Authentication required.'}), 401


@app.errorhandler(403)
def forbidden(e):
    return jsonify({'error': 'Forbidden.'}), 403


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found.'}), 404


@app.errorhandler(413)
def request_too_large(e):
    return jsonify({'error': f'Payload too large. Max {UPLOAD_MAX_BYTES // 1_048_576} MB.'}), 413


# ── Entry Point ──
if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', '5000'))
    socketio.run(app, host='0.0.0.0', port=port, use_reloader=False)
