import json

EVENT_MAP = {
    4624: "successful_login",
    4625: "failed_login",
    4720: "account_created",
    4726: "account_deleted",
    4732: "privileged_group_added"
}

def windows_parser(logs):

    events = []

    for line in logs:

        try:

            event = json.loads(line)

            event_id = int(event["winlog"]["event_id"])
            event_data = event["winlog"].get("event_data", {})
            username = (
                event_data.get("TargetUserName")
                or event_data.get("SubjectUserName")
                or "unknown"
            )
            source_ip = event_data.get("IpAddress", "unknown")

            log_data = {
                "timestamp": event["@timestamp"],
                "source": "windows",
                "event_type": EVENT_MAP.get(event_id, "unknown"), 
                "username": username,
                "source_ip": source_ip,
                "port": None,
                "path": None,
                "method": None,
                "http_status": None,
                "event_id": event_id,
                "raw_log": line.strip()
            }

            events.append(log_data)

        except (json.JSONDecodeError, KeyError, ValueError):
            continue

    return events

