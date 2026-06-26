from datetime import datetime 
from src.database.database import ( get_cases, create_case, update_case_status, update_alert_status )

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def open_case(alert_id):

    existing = get_cases(alert_id)

    if existing:
        return existing[0]["id"]

    case_id = create_case(
        alert_id,
        verdict="PENDING",
        status="NEW",
        created_at=current_time()
    )

    update_alert_status(
            alert_id,
            "INVESTIGATING"
        )

    return case_id

def alter_case_status(case_id, new_status, alert_id=None):

    update_case_status(case_id, new_status)

    if new_status == "CLOSED" and alert_id:
        update_case_status(alert_id, "CLOSED")

    elif new_status == "INVESTIGATING" and alert_id:
        update_alert_status(alert_id, "INVESTIGATING")

def close_case(case_id, alert_id=None):

    update_case_status(
        case_id,
        "CLOSED"
    )

    if alert_id:
        update_alert_status(alert_id, "CLOSED")
