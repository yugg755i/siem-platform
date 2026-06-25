import re

def auth_parser(logs):

    pattern = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+\d+\:\d+\:\d+)'
        r'.*?(?P<event_type>[A-Za-z ]+?) for (?:invalid user )?(?P<user>\S+)'
        r'.*?(?P<src_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) '
        r'port (?P<port>\d+)'
        )

    events = []

    for line in logs:

        match = pattern.search(line)

        if match:

            EVENT_MAP = {
                "Failed password": "failed_login",
                "Accepted password": "successful_login"
            }

            event_type = EVENT_MAP.get(
                match.group("event_type").strip(),
                "unknown"
            )

            log_data = {
                "timestamp": match.group("timestamp"),
                "source": "auth",
                "event_type": event_type,
                "username": match.group("user"),
                "source_ip": match.group("src_ip"),
                "port": match.group("port"),
                "path": None,
                "method": None,
                "http_status": None,
                "event_id": None,
                "raw_log": line.strip()
            }

            events.append(log_data)
    return events


