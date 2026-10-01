from dataclasses import asdict, dataclass
from typing import Any, Dict


@dataclass
class Marksheet:
    """Application-level representation of a generated marksheet."""

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

    percentage: float

    marksheet_hash: str = ""

    marksheet_pdf_hash: str = ""

    pdf_filename: str = ""

    status: str = "GENERATED"

    def to_dict(
        self,
    ) -> Dict[str, Any]:

        return asdict(self)