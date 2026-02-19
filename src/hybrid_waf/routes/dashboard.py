from flask import Blueprint, render_template, jsonify
from .data_processor import get_all_waf_logs

dashboard_bp = Blueprint('dashboard', __name__, template_folder='../../templates', static_folder='../../static')

@dashboard_bp.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard_data')
def get_dashboard_data():
    all_logs = get_all_waf_logs()
    
    # Process the logs to get summary stats
    total_requests = len(all_logs)
    blocked_requests = sum(1 for log in all_logs if log['status'] == 'malicious')
    ml_anomalies = sum(1 for log in all_logs if log['reason'] == 'ML')
    
    # Process the logs to get top attacking IPs and URLs
    ip_counts = {}
    url_counts = {}
    for log in all_logs:
        ip = log.get('ip', 'N/A')
        url = log.get('path', 'N/A')
        
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
        url_counts[url] = url_counts.get(url, 0) + 1
    
    top_ips = sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    top_urls = sorted(url_counts.items(), key=lambda item: item[1], reverse=True)[:5]
    
    # Get the last 10 log entries for the live stream
    live_logs = all_logs[-10:]
    
    data = {
        'totalRequests': total_requests,
        'blockedRequests': blocked_requests,
        'mlAnomalies': ml_anomalies,
        'topIps': [{'ip': ip, 'count': count} for ip, count in top_ips],
        'topUrls': [{'url': url, 'count': count} for url, count in top_urls],
        'liveLogs': live_logs
    }
    
    return jsonify(data)