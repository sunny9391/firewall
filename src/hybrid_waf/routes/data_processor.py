import os
import re

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'logs', 'detections.txt')

def parse_log_entry(line):
    # Regex to capture timestamp, a complex middle section, and the final decision
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s-\s(.*?)\s-\s(.*?)$")
    match = pattern.search(line)

    if match:
        timestamp, request_info, decision_info = match.groups()

        # Split the decision info to separate status and reason
        decision_match = re.search(r"(\S+)(?:\((.*?)\))?", decision_info)
        status = decision_match.group(1) if decision_match else 'N/A'
        reason = decision_match.group(2) if decision_match and decision_match.group(2) else 'N/A'

        # Split the request_info to get the method and path
        request_parts = request_info.strip().split(' ', 2)
        if len(request_parts) > 1 and request_parts[0] in ['GET', 'POST']:
            method = request_parts[0]
            path = request_parts[1]
        else:
            method = 'N/A'
            path = request_info.strip()

        # Extract IP address from the Host header or use a placeholder
        ip = 'N/A'
        host_match = re.search(r"Host:\s(\S+)", request_info)
        if host_match:
            ip = host_match.group(1)

        return {
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "status": status.strip(),
            "reason": reason.strip(),
            "ip": ip
        }
    return None

def get_all_waf_logs():
    logs = []
    print(f"Looking for log file at: {LOG_FILE_PATH}")
    try:
        with open(LOG_FILE_PATH, 'r') as f:
            for line in f:
                parsed_log = parse_log_entry(line)
                if parsed_log:
                    logs.append(parsed_log)
    except FileNotFoundError:
        print(f"Log file not found at: {LOG_FILE_PATH}")
    return logs