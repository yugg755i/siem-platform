import re

def apache_parser(logs):
    pattern = re.compile(
            r'(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3}) '
            r'\S+ \S+ '
            r'\[(?P<timestamp>[^\]]+)\] '
            r'"(?P<method>\w+) (?P<path>\S+) HTTP/\d\.\d" '
            r'(?P<status>\d{3})'
            )

    events = []

    for line in logs:

        match = pattern.search(line)

        if match:

            log_data = {
                "timestamp": match.group("timestamp"),
                "source": "apache",
                "event_type": "web_request",
                "username": None,
                "source_ip": match.group("src_ip"),
                "port": None,
                "path": match.group("path"),
                "method": match.group("method"),
                "http_status": int(match.group("status")),
                "event_id": None,
                "raw_log": line.strip()
            }

            events.append(log_data)
    return events
