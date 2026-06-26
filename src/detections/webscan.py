def webscan_detection(events):

    ip_data = {}
    suspicious = {}
    alerts = []


    SCAN_PATHS = [ "/admin", "/wp-admin", "/phpmyadmin", "/.env", "/config.php", "/server-status", ]

    for event in events:

        ip = event["source_ip"]

        if ip not in ip_data:
            ip_data[ip] = {
                "paths": set(),
                "event_ids": [],
                "scanner_hits": 0,
                "created_at": event["timestamp"]
                }

        ip_data[ip]["paths"].add(event["path"])
        ip_data[ip]["event_ids"].append(event["id"])

        if event["path"] in SCAN_PATHS:
            ip_data[ip]["scanner_hits"] += 1


    for ip, data in ip_data.items():

        if len(data["paths"]) >= 10 or data["scanner_hits"] >= 3:

            alerts.append({
                "title": "Web Scanning Activity Detected",
                "severity": "MEDIUM",
                "source_ip": ip,
                "port": None,
                "status": "NEW",
                "mitre_id": "T1595",
                "created_at": data["created_at"],
                "event_ids": data["event_ids"],
                "evidence": {
                    "unique_paths": len(data["paths"]),
                    "scanner_hits": data["scanner_hits"],
                    "requested_paths": list(data["paths"])
                    }
            })

    return alerts
