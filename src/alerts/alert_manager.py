from src.database.database import ( update_alert_status,  )

def investigate_alert(alert_id):

    update_alert_status(
        alert_id, "INVESTIGATING"
    )

def escalate_alert(alert_id):

    update_alert_status(
        alert_id, "ESCALATED"
    )

def close_alert(alert_id):

    update_alert_status(
        alert_id, "CLOSED"
    )

def reopen_alert(alert_id):

    update_alert_status(
        alert_id, "INVESTIGATING"
    )
