from datetime import datetime
from src.database.database import create_note

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def add_investigation_note(case_id, note):

    create_note(
        case_id,
        note,
        created_at=current_time()
    )
