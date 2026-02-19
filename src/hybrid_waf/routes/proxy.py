import logging
import os

from flask import Blueprint, jsonify, request

from src.hybrid_waf.utils.signature_checker import check_signature
from src.hybrid_waf.utils.preprocessor import extract_features
from src.hybrid_waf.utils.ml_checker import check_ml_prediction

LOG_FILE_PATH = os.path.join('logs', 'detections.log')
os.makedirs('logs', exist_ok=True)

waf_logger = logging.getLogger('waf_detections')
waf_logger.setLevel(logging.INFO)

if not waf_logger.handlers:
    file_handler = logging.FileHandler(LOG_FILE_PATH)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    file_handler.setFormatter(formatter)
    waf_logger.addHandler(file_handler)

proxy_bp = Blueprint('proxy', __name__)


def _build_request_signature(uri: str, get_data: str, post_data: str) -> str:
    compact_get = get_data.strip().replace('\n', ' ') if get_data else '-'
    compact_post = post_data.strip().replace('\n', ' ') if post_data else '-'
    return f'URI:{uri or "/"} GET:{compact_get} POST:{compact_post}'


@proxy_bp.route('/check_request', methods=['POST'])
def check_request():
    data = request.get_json(silent=True) or {}

    user_input = data.get('user_request', '')
    uri = data.get('uri', user_input)
    get_data = data.get('get_data', '')
    post_data = data.get('post_data', '')

    request_signature = _build_request_signature(uri, get_data, post_data)
    signature_result = check_signature(user_input)

    if signature_result == 'valid':
        waf_logger.info('%s - valid(signature)', request_signature)
        return jsonify({
            'status': 'valid',
            'reason': 'signature',
            'message': 'All Clear! Your request passed our security checks with flying colors.✨'
        })

    if signature_result == 'malicious':
        waf_logger.info('%s - malicious(signature)', request_signature)
        return jsonify({
            'status': 'malicious',
            'reason': 'signature',
            'message': 'Critical Alert! Malicious pattern detected in your request.<br>Access Denied!🔒'
        })

    features = extract_features(uri, get_data, post_data)
    prediction = check_ml_prediction(features)
    final_status = 'malicious' if prediction == 1 else 'valid'

    waf_logger.info('%s - %s(ML)', request_signature, final_status)

    return jsonify({
        'status': final_status,
        'reason': 'ml',
        'message': 'Suspicious pattern detected. Advanced AI analysis completed.',
        'ml_verdict': (
            '🚨 Threat Confirmed! AI Defense System blocked suspicious activity.🔒'
            if final_status == 'malicious'
            else '✅ Advanced AI scan complete: Request verified safe ✨'
        ),
        'features': features
    })
