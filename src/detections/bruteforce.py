def bruteforce_detection(events):

    failed_by_ip = {}
    alerts = []

    for event in events:

        if event["event_type"] != "failed_login":
            continue

        ip = event["source_ip"]

        if ip not in failed_by_ip:
            failed_by_ip[ip] = {
                "event_ids": [],
                "port": event["port"],
                "timestamp": event["timestamp"]
            }
        failed_by_ip[ip]["event_ids"].append(event["id"])

    for ip, data in failed_by_ip.items():

        if len(data["event_ids"]) >= 5:

            alerts.append({
                "title": "SSH Brute Force Detected",
                "severity": "HIGH",
                "source_ip": ip,
                "port": data["port"],
                "status": "NEW",
                "mitre_id": "T1110",
                "created_at": data["timestamp"],
                "event_ids": data["event_ids"],
                "evidence": {
                    "attempts": len(data["event_ids"]),
                    "source_ip": ip,
                    "port": data["port"]
                    }
            })

    return alerts
