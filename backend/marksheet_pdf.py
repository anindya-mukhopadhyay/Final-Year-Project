import hashlib
import os
from typing import Any, Dict

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

GENERATED_DIR = os.path.join(
    BASE_DIR,
    "generated",
    "marksheets",
)

os.makedirs(
    GENERATED_DIR,
    exist_ok=True,
)


def generate_marksheet_pdf(
    marksheet: Dict[str, Any],
    marksheet_id: str,
) -> Dict[str, str]:
    """
    Generate an official-looking PDF marksheet.

    The PDF hash is calculated only after the complete PDF
    has been written to disk.

    The PDF does NOT contain its own final PDF hash because
    that would create a circular hashing dependency.
    """

    filename = f"{marksheet_id}.pdf"

    pdf_path = os.path.join(
        GENERATED_DIR,
        filename,
    )

    document = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
        title=f"Marksheet {marksheet_id}",
        author="AnswerChain",
    )

    styles = getSampleStyleSheet()

    university_style = ParagraphStyle(
        "UniversityStyle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        fontSize=20,
        leading=24,
        spaceAfter=8,
    )

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Heading2"],
        alignment=TA_CENTER,
        fontSize=15,
        leading=20,
        spaceAfter=18,
    )

    normal_style = ParagraphStyle(
        "MarksheetNormal",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
    )

    small_style = ParagraphStyle(
        "MarksheetSmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
    )

    story = []

    story.append(
        Paragraph(
            str(marksheet["university"]),
            university_style,
        )
    )

    story.append(
        Paragraph(
            "OFFICIAL MARKSHEET",
            title_style,
        )
    )

    # ========================================================
    # STUDENT INFORMATION
    # ========================================================

    student_table = Table(
        [
            [
                Paragraph(
                    "<b>Student ID</b>",
                    normal_style,
                ),
                str(
                    marksheet["student_id"]
                ),
            ],
            [
                Paragraph(
                    "<b>Student Name</b>",
                    normal_style,
                ),
                str(
                    marksheet["student_name"]
                ),
            ],
            [
                Paragraph(
                    "<b>Examination</b>",
                    normal_style,
                ),
                str(
                    marksheet["exam_name"]
                ),
            ],
            [
                Paragraph(
                    "<b>Answer Script ID</b>",
                    normal_style,
                ),
                str(
                    marksheet["answer_script_id"]
                ),
            ],
        ],
        colWidths=[
            45 * mm,
            115 * mm,
        ],
    )

    student_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.black,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
            ]
        )
    )

    story.append(student_table)
    story.append(
        Spacer(
            1,
            18,
        )
    )

    # ========================================================
    # RESULT INFORMATION
    # ========================================================

    result_table = Table(
        [
            [
                Paragraph(
                    "<b>Marks Obtained</b>",
                    normal_style,
                ),
                Paragraph(
                    "<b>Maximum Marks</b>",
                    normal_style,
                ),
                Paragraph(
                    "<b>Percentage</b>",
                    normal_style,
                ),
            ],
            [
                str(
                    marksheet["final_marks"]
                ),
                str(
                    marksheet["max_marks"]
                ),
                f'{marksheet["percentage"]}%',
            ],
        ],
        colWidths=[
            53 * mm,
            53 * mm,
            53 * mm,
        ],
    )

    result_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.black,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.lightgrey,
                ),
                (
                    "ALIGN",
                    (0, 0),
                    (-1, -1),
                    "CENTER",
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    10,
                ),
            ]
        )
    )

    story.append(result_table)
    story.append(
        Spacer(
            1,
            20,
        )
    )

    # ========================================================
    # BLOCKCHAIN REFERENCE
    # ========================================================

    blockchain_table = Table(
        [
            [
                Paragraph(
                    "<b>Marksheet ID</b>",
                    normal_style,
                ),
                str(
                    marksheet_id
                ),
            ],
            [
                Paragraph(
                    "<b>Result ID</b>",
                    normal_style,
                ),
                str(
                    marksheet["result_id"]
                ),
            ],
            [
                Paragraph(
                    "<b>Evaluation ID</b>",
                    normal_style,
                ),
                str(
                    marksheet["evaluation_id"]
                ),
            ],
            [
                Paragraph(
                    "<b>Document Status</b>",
                    normal_style,
                ),
                "BLOCKCHAIN-BACKED",
            ],
        ],
        colWidths=[
            45 * mm,
            115 * mm,
        ],
    )

    blockchain_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.black,
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.lightgrey,
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "MIDDLE",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    8,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(blockchain_table)
    story.append(
        Spacer(
            1,
            20,
        )
    )

    story.append(
        Paragraph(
            "<b>Blockchain Verification</b>",
            normal_style,
        )
    )

    story.append(
        Spacer(
            1,
            5,
        )
    )

    story.append(
        Paragraph(
            "This document is generated from a finalized "
            "academic result. Its document hash is stored "
            "with the AnswerChain blockchain record for "
            "integrity verification.",
            small_style,
        )
    )

    story.append(
        Spacer(
            1,
            8,
        )
    )

    story.append(
        Paragraph(
            "Document integrity uses SHA-256. Keep the "
            "original PDF bytes unchanged for successful "
            "verification.",
            small_style,
        )
    )

    document.build(story)

    # ========================================================
    # HASH FINAL PDF
    # ========================================================

    with open(
        pdf_path,
        "rb",
    ) as pdf_file:
        pdf_bytes = pdf_file.read()

    pdf_hash = hashlib.sha256(
        pdf_bytes
    ).hexdigest()

    return {
        "pdf_path": pdf_path,
        "pdf_filename": filename,
        "pdf_hash": pdf_hash,
    }


def calculate_pdf_hash(
    pdf_path: str,
) -> str:
    """
    Calculate SHA-256 of a PDF file.
    """

    with open(
        pdf_path,
        "rb",
    ) as pdf_file:
        return hashlib.sha256(
            pdf_file.read()
        ).hexdigest()


def verify_pdf_hash(
    pdf_path: str,
    expected_hash: str,
) -> bool:
    """
    Verify a PDF against a stored SHA-256 hash.
    """

    if not os.path.isfile(pdf_path):
        return False

    return (
        calculate_pdf_hash(pdf_path)
        == expected_hash
    )