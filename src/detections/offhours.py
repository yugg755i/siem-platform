from datetime import datetime

def off_hours_login(events):

    start_hour = 8
    end_hour = 18

    admin_users = ["root", "admin", "administrator"]

    alerts = []

    for event in events:

        if event["event_type"] != "successful_login":
            continue

        timestamp = datetime.strptime(
            event["timestamp"],
            "%b %d %H:%M:%S"
        ).replace(year=datetime.now().year)

        hour = timestamp.hour

        if hour < start_hour or hour >= end_hour:

            severity = (
                "HIGH"
                if event["username"] in admin_users
                else "MEDIUM"
            )

            alerts.append({
                "title": "Off-Hours Login Detected",
                "severity": severity,
                "source_ip":  event["source_ip"],
                "username": event["username"],
                "port": None,
                "status": "NEW",
                "mitre_id": "T1078",
                "created_at": event["timestamp"],
                "event_ids": [event["id"]],
                "login_time": timestamp.strftime("%Y-%m-%d %H:%M:%S")
                })

    return alerts
