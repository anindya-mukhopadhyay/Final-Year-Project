import hashlib
import json
from typing import Any, Dict


def generate_marksheet(
    student_id: str,
    student_name: str,
    university: str,
    exam_name: str,
    answer_script_id: str,
    result_id: str,
    evaluation_id: str,
    final_marks: float,
    max_marks: float,
) -> Dict[str, Any]:
    """Build the canonical logical marksheet payload."""
    final_marks_value = float(final_marks)
    max_marks_value = float(max_marks)

    percentage = 0.0
    if max_marks_value > 0:
        percentage = (final_marks_value / max_marks_value) * 100.0

    return {
        "student_id": student_id,
        "student_name": student_name,
        "university": university,
        "exam_name": exam_name,
        "answer_script_id": answer_script_id,
        "result_id": result_id,
        "evaluation_id": evaluation_id,
        "final_marks": final_marks_value,
        "max_marks": max_marks_value,
        "percentage": round(percentage, 2),
        "status": "GENERATED",
    }


def canonicalize_marksheet(marksheet: Dict[str, Any]) -> str:
    """Return a stable JSON representation for hashing."""
    return json.dumps(
        marksheet,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def calculate_marksheet_hash(marksheet: Dict[str, Any]) -> str:
    """Calculate SHA-256 for the logical marksheet payload."""
    canonical_data = canonicalize_marksheet(marksheet)

    return hashlib.sha256(
        canonical_data.encode("utf-8")
    ).hexdigest()


def verify_marksheet_hash(
    marksheet: Dict[str, Any],
    expected_hash: str,
) -> bool:
    """Verify a logical marksheet against a previously stored hash."""
    return calculate_marksheet_hash(marksheet) == expected_hash