import ipaddress
import json
import requests
from pathlib import Path

def check_abuseipdb(ip, api_key):
    try:

        params = {"ipAddress": ip, "maxAgeInDays": 90}

        headers = {"Key": api_key, "Accept": "application/json"}

        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params=params,
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()

        return response.json()["data"]

    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e}")

        if e.response is not None:
            print(e.response.text)
        return None

    except requests.exceptions.RequestException as e:
        print(f"error: {e}")
        return None

def is_public_ip(ip):
    return not ipaddress.ip_address(ip).is_private

def malicious_ip_detection(events, api_key):

    alerts = []

    checked_ips = {}

    for event in events:

        ip = event["source_ip"]

        if not is_public_ip(ip):
            continue

        if ip not in checked_ips:
            checked_ips[ip] = check_abuseipdb(ip, api_key)

        ip_data = checked_ips[ip]

        if ip_data and ip_data["abuseConfidenceScore"] >= 75:

            alerts.append({
                "title": "Malicious IP Detected",
                "severity": "HIGH",
                "source_ip": ip,
                "username": None,
                "port": event["port"],
                "status": "NEW",
                "mitre_id": "N/A",
                "created_at": event["timestamp"],
                "event_ids": [event["id"]],
                "evidence": {
                    "source_ip": ip,
                    "abuse_score": ip_data["abuseConfidenceScore"]
                    }
            })

    return alerts
