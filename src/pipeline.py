from src.database.database import (
    get_all_events,
    create_database,
    create_events,
    create_alerts,
    clear_events,
    clear_alerts,
)
from src.ingestion.ingest_log import ingest_log
from src.parsers.auth_parser import auth_parser
from src.parsers.apache_parser import apache_parser
from src.parsers.windows_parser import windows_parser

from src.detections.bruteforce import bruteforce_detection
from src.detections.offhours import off_hours_login
from src.detections.webscan import webscan_detection

def ingest_logs():

    create_database()

    apache_logs = ingest_log("logs/apache.log")
    auth_logs = ingest_log("logs/auth.log")
    windows_logs = ingest_log("logs/windows.log")

    apache_events = apache_parser(apache_logs)
    auth_events = auth_parser(auth_logs)
    windows_events = windows_parser(windows_logs)

    events = (
        auth_events +
        apache_events +
        windows_events
    )

    clear_events()
    create_events(events)


def get_events_by_source(source):

    events = get_all_events()

    return [
        event
        for event in events
        if event["source"] == source
    ]

def run_detections():

    clear_alerts()

    alerts = []

    apache_events = get_events_by_source("apache")
    auth_events = get_events_by_source("auth")
    windows_events = get_events_by_source("windows")

    alerts.extend(bruteforce_detection(auth_events))
    alerts.extend(off_hours_login(auth_events))
    alerts.extend(webscan_detection(apache_events))

    clear_alerts()
    create_alerts(alerts)

    return alerts

def process_logs():

    ingest_logs()
    alerts = run_detections()

    return alerts
