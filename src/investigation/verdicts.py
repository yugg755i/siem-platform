from src.database.database import update_case_verdict

TRUE_POSITIVE = "TRUE POSITIVE"
FALSE_POSITIVE = "FALSE POSITIVE"
BENIGN = "BENIGN"

def set_verdict(case_id, verdict):

    update_case_verdict(
        case_id,
        verdict
    )

