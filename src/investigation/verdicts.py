from src.database.database import update_case_verdict

PENDING = "PENDING"
TRUE_POSITIVE = "TRUE_POSITIVE"
FALSE_POSITIVE = "FALSE_POSITIVE"
BENIGN = "BENIGN"

def set_verdict(case_id, verdict_string):

    update_case_verdict(
        case_id,
        verdict_string
    )

