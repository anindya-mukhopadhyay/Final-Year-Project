from dataclasses import dataclass, asdict
from typing import Any, Dict


@dataclass
class Marksheet:
    marksheet_id: str
    student_id: str
    student_name: str
    university: str
    exam_name: str

    answer_script_id: str
    result_id: str
    evaluation_id: str

    final_marks: float
    max_marks: float

    marksheet_hash: str = ""

    status: str = "GENERATED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)