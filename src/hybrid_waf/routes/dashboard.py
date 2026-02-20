from collections import Counter

from flask import Blueprint, jsonify, render_template

from .data_processor import get_all_waf_logs

dashboard_bp = Blueprint(
    'dashboard', __name__,
    template_folder='../../templates',
    static_folder='../../static',
)


@dashboard_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@dashboard_bp.route('/api/dashboard_data')
def get_dashboard_data():
    all_logs = get_all_waf_logs()

    total_requests   = len(all_logs)
    blocked_requests = sum(1 for log in all_logs if log['status'] == 'malicious')
    ml_anomalies     = sum(1 for log in all_logs if log['reason'] == 'ML')
    valid_requests   = sum(1 for log in all_logs if log['status'] == 'valid')

    block_rate = round((blocked_requests / total_requests * 100), 1) if total_requests else 0

    ip_counts  = Counter(log.get('ip', 'N/A') for log in all_logs if log['status'] == 'malicious')
    url_counts = Counter(log.get('path', 'N/A') for log in all_logs)
    attack_type_counts = Counter(
        log.get('attack_type', 'Unknown')
        for log in all_logs
        if log['status'] == 'malicious' and log.get('attack_type', 'N/A') != 'N/A'
    )

    # Timeline: group malicious requests by date
    timeline: dict[str, int] = {}
    for log in all_logs:
        if log['status'] == 'malicious':
            date = log['timestamp'][:10]  # YYYY-MM-DD
            timeline[date] = timeline.get(date, 0) + 1

    return jsonify({
        'totalRequests':   total_requests,
        'blockedRequests': blocked_requests,
        'validRequests':   valid_requests,
        'mlAnomalies':     ml_anomalies,
        'blockRate':       block_rate,
        'topIps':   [{'ip': ip, 'count': c} for ip, c in ip_counts.most_common(5)],
        'topUrls':  [{'url': url, 'count': c} for url, c in url_counts.most_common(5)],
        'attackTypes': [{'type': t, 'count': c} for t, c in attack_type_counts.most_common()],
        'timeline': [{'date': d, 'count': c} for d, c in sorted(timeline.items())[-14:]],
        'liveLogs': all_logs[-15:],
    })