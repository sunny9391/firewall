import logging
import os
import time
from collections import defaultdict, deque

from flask import Blueprint, jsonify, request

from src.hybrid_waf.utils.signature_checker import check_signature
from src.hybrid_waf.utils.preprocessor import extract_features, FEATURE_NAMES
from src.hybrid_waf.utils.ml_checker import check_ml_prediction

# ─── logging setup ────────────────────────────────────────────────────────────
LOG_FILE_PATH = os.path.join('logs', 'detections.log')
os.makedirs('logs', exist_ok=True)

waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)
if not waf_logger.handlers:
    fh = logging.FileHandler(LOG_FILE_PATH)
    fh.setFormatter(logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    waf_logger.addHandler(fh)

# ─── in-memory rate limiter ───────────────────────────────────────────────────
_RATE_WINDOW = 60
_RATE_LIMIT  = 30
_ip_history: dict[str, deque] = defaultdict(deque)


def _is_rate_limited(ip: str) -> bool:
    now = time.time()
    dq  = _ip_history[ip]
    while dq and now - dq[0] > _RATE_WINDOW:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return True
    dq.append(now)
    return False


proxy_bp = Blueprint('proxy', __name__)


def _log_sig(ip: str, uri: str, get_data: str, post_data: str) -> str:
    g = (get_data  or '-').strip().replace('\n', ' ')
    p = (post_data or '-').strip().replace('\n', ' ')
    return f'IP:{ip} URI:{uri or "/"} GET:{g} POST:{p}'


@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json(silent=True) or {}

    user_input = data.get('user_request', '')
    uri        = data.get('uri', user_input)
    get_data   = data.get('get_data', '')
    post_data  = data.get('post_data', '')
    ip = (
        request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
        .split(',')[0].strip()
    )

    sig = _log_sig(ip, uri, get_data, post_data)

    # Rate limiting
    if _is_rate_limited(ip):
        waf_logger.warning('%s - rate_limited', sig)
        return jsonify({
            'status':  'blocked',
            'reason':  'rate_limit',
            'message': '🚦 Too many requests. Please slow down and try again later.',
        }), 429

    # Signature check
    sig_result = check_signature(user_input)

    if sig_result == 'valid':
        waf_logger.info('%s - valid(signature)', sig)
        return jsonify({
            'status':  'valid',
            'reason':  'signature',
            'message': 'All Clear! Your request passed our security checks with flying colors. ✨',
        })

    if sig_result == 'malicious':
        waf_logger.info('%s - malicious(signature)', sig)
        return jsonify({
            'status':  'malicious',
            'reason':  'signature',
            'message': 'Critical Alert! Malicious pattern detected in your request. Access Denied! 🔒',
        })

    # ML check (sig_result == 'obfuscated')
    features   = extract_features(uri, get_data, post_data)
    prediction = check_ml_prediction(features)

    if prediction == -1:
        waf_logger.warning('%s - suspicious(no_model)', sig)
        return jsonify({
            'status':  'suspicious',
            'reason':  'ml_unavailable',
            'message': '⚠️ Suspicious patterns detected. ML model unavailable for deep analysis.',
            'features': dict(zip(FEATURE_NAMES, features)),
        })

    final_status = 'malicious' if prediction == 1 else 'valid'
    waf_logger.info('%s - %s(ML)', sig, final_status)

    return jsonify({
        'status':  final_status,
        'reason':  'ml',
        'message': 'Advanced AI analysis completed.',
        'ml_verdict': (
            '🚨 Threat Confirmed! AI Defense System blocked suspicious activity. 🔒'
            if final_status == 'malicious'
            else '✅ Advanced AI scan complete: Request verified safe ✨'
        ),
        'features': dict(zip(FEATURE_NAMES, features)),
    })


@proxy_bp.route('/api/rate_status', methods=['GET'])
def rate_status():
    now = time.time()
    active = {
        ip: len([t for t in dq if now - t <= _RATE_WINDOW])
        for ip, dq in _ip_history.items()
    }
    return jsonify({
        'rate_window_seconds': _RATE_WINDOW,
        'limit':               _RATE_LIMIT,
        'active_ips':          active,
    })