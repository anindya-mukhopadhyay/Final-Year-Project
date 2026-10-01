import hashlib
import json
from typing import Dict, Any


# ============================================================
# GENERATE MARKSHEET
# ============================================================

def generate_marksheet(
    student_id: str,
    student_name: str,
    university: str,
    exam_name: str,
    answer_script_id: str,
    result_id: str,
    evaluation_id: str,
    final_marks: float,
    max_marks: float
) -> Dict[str, Any]:

    percentage = 0.0

    if max_marks > 0:

        percentage = (
            float(final_marks)
            / float(max_marks)
        ) * 100

    marksheet = {

        "student_id":
            student_id,

        "student_name":
            student_name,

        "university":
            university,

        "exam_name":
            exam_name,

        "answer_script_id":
            answer_script_id,

        "result_id":
            result_id,

        "evaluation_id":
            evaluation_id,

        "final_marks":
            float(final_marks),

        "max_marks":
            float(max_marks),

        "percentage":
            round(
                percentage,
                2
            ),

        "status":
            "GENERATED"

    }

    return marksheet


# ============================================================
# CANONICAL MARKSHEET
# ============================================================

def canonicalize_marksheet(
    marksheet: Dict[str, Any]
) -> str:

    return json.dumps(
        marksheet,
        sort_keys=True,
        separators=(
            ",",
            ":"
        )
    )


# ============================================================
# MARKSHEET SHA-256
# ============================================================

def calculate_marksheet_hash(
    marksheet: Dict[str, Any]
) -> str:

    canonical_data = canonicalize_marksheet(
        marksheet
    )

    return hashlib.sha256(
        canonical_data.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# VERIFY MARKSHEET HASH
# ============================================================

def verify_marksheet_hash(
    marksheet: Dict[str, Any],
    expected_hash: str
) -> bool:

    calculated_hash = calculate_marksheet_hash(
        marksheet
    )

    return calculated_hash == expected_hash