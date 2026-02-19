import os
import re

LOG_FILE_PATH = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'logs', 'detections.log')


def parse_log_entry(line):
    pattern = re.compile(r"(\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s-\s(.*?)\s-\s(.*?)$")
    match = pattern.search(line)

    if not match:
        return None

    timestamp, request_info, decision_info = match.groups()

    decision_match = re.search(r'(\S+)(?:\((.*?)\))?', decision_info)
    status = decision_match.group(1) if decision_match else 'N/A'
    reason = decision_match.group(2) if decision_match and decision_match.group(2) else 'N/A'

    uri_match = re.search(r'URI:(\S+)', request_info)
    get_match = re.search(r'GET:(.*?)\sPOST:', request_info)

    path = uri_match.group(1) if uri_match else request_info.strip()
    method = 'GET' if get_match and get_match.group(1).strip() not in ['', '-'] else 'POST'

    ip = 'N/A'

    return {
        'timestamp': timestamp,
        'method': method,
        'path': path,
        'status': status.strip(),
        'reason': reason.strip().upper(),
        'ip': ip
    }


def get_all_waf_logs():
    logs = []
    try:
        with open(LOG_FILE_PATH, 'r', encoding='utf-8') as file:
            for line in file:
                parsed_log = parse_log_entry(line)
                if parsed_log:
                    logs.append(parsed_log)
    except FileNotFoundError:
        return []
    return logs
