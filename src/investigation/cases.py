from datetime import datetime from src.database.database import ( create_case, update_case_status )

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def open_case(alert_id):

    case_id = create_case(
        alert_id,
        verdict=None,
        status="NEW",
        created_at=current_time()
    )

    update_case_status(
            case_id,
            "INVESTIGATING"
        )

def close_case(case_id):

    update_case_status(
        case_id,
        "CLOSED"
    )
