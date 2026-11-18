import hashlib
import io
import logging
import os
from typing import Any, Dict, Optional, Tuple

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

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.stamp import TextStampStyle
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.sign import signers, fields
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko.sign.general import load_certs_from_pemder
from pyhanko_certvalidator import ValidationContext

logger = logging.getLogger(__name__)


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
    # DIGITAL SIGNATURE (pyHanko Institutional Signature)
    # ========================================================
    # Apply official cryptographic signature before hashing
    sign_marksheet_pdf(pdf_path)

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


def sign_marksheet_pdf(
    pdf_path: str,
    key_file: Optional[str] = None,
    cert_file: Optional[str] = None,
) -> bool:
    """
    Apply a cryptographic PAdES digital signature to the generated marksheet PDF.

    Uses pyHanko with the institutional X.509 private key and certificate.
    Creates an official signature field 'AnswerChainInstitutionalSignature'
    with standard signature metadata (Signer, Date, Reason, Location).
    Compatible PDF viewers (Adobe Acrobat, Foxit) will validate this signature natively.
    Does NOT bake decorative fake green tick images into the document stream.
    """
    key_file = key_file or os.path.join(BASE_DIR, "keys", "authority_pdf_key.pem")
    cert_file = cert_file or os.path.join(BASE_DIR, "keys", "authority_pdf_cert.pem")

    if not (os.path.isfile(key_file) and os.path.isfile(cert_file)):
        logger.warning(
            "Institutional PDF signing keys not found (%s, %s). Marksheet generated without digital signature.",
            key_file,
            cert_file,
        )
        return False

    try:
        signer = signers.SimpleSigner.load(
            key_file=key_file,
            cert_file=cert_file,
        )

        with open(pdf_path, "rb") as inf:
            pdf_data = inf.read()

        w = IncrementalPdfFileWriter(io.BytesIO(pdf_data))
        stamp_style = TextStampStyle(
            stamp_text=(
                "Digitally certified by AnswerChain Authorized Institution\n"
                "Signer: AnswerChain Examination Authority\n"
                "Reason: Official Academic Marksheet Certification\n"
                "Location: Kolkata, India\n"
                "Date: %(ts)s"
            ),
            border_width=1,
            text_box_style=TextBoxStyle(font_size=7),
        )

        pdf_signer = signers.PdfSigner(
            signature_meta=signers.PdfSignatureMetadata(
                field_name="AnswerChainInstitutionalSignature",
                reason="Official Academic Marksheet Certification",
                location="Kolkata, India",
            ),
            signer=signer,
            stamp_style=stamp_style,
            new_field_spec=fields.SigFieldSpec(
                sig_field_name="AnswerChainInstitutionalSignature",
                box=(330, 25, 555, 75),
            ),
        )

        out_buf = io.BytesIO()
        pdf_signer.sign_pdf(w, output=out_buf)
        signed_bytes = out_buf.getvalue()

        with open(pdf_path, "wb") as outf:
            outf.write(signed_bytes)

        logger.info("Successfully applied pyHanko digital signature to marksheet: %s", pdf_path)
        return True

    except Exception as e:
        logger.error("Failed to apply digital signature to PDF %s: %s", pdf_path, e)
        return False


def verify_pdf_digital_signature(
    pdf_bytes: bytes,
    ca_cert_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Cryptographically verify embedded digital signatures in a PDF byte payload.

    Returns detailed diagnostic results distinguishing:
      - Intact & Trusted signature (chaining to AnswerChain Root CA)
      - Tampered / Invalid signature (bytes altered after signing)
      - Untrusted issuer (valid crypto structure but unknown / rogue issuer)
      - Unsigned document (no digital signature present)
    """
    ca_cert_file = ca_cert_file or os.path.join(BASE_DIR, "keys", "answerchain_ca_cert.pem")

    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        signatures = reader.embedded_signatures

        if not signatures:
            return {
                "has_signature": False,
                "intact": False,
                "valid": False,
                "trusted": False,
                "signer_name": None,
                "issuer_name": None,
                "organization": None,
                "signing_time": None,
                "status": "UNSIGNED",
                "explanation": "No embedded digital signatures found in this document. It is an unsigned copy.",
            }

        sig = signatures[0]

        trust_roots = []
        if os.path.isfile(ca_cert_file):
            trust_roots = list(load_certs_from_pemder([ca_cert_file]))

        vc = ValidationContext(trust_roots=trust_roots, allow_fetching=False)
        sig_status = validate_pdf_signature(sig, signer_validation_context=vc)

        signer_name = "Unknown Signer"
        issuer_name = "Unknown Issuer"
        org_name = "Unknown Organization"

        if sig_status.signing_cert:
            signer_name = sig_status.signing_cert.subject.human_friendly
            issuer_name = sig_status.signing_cert.issuer.human_friendly
            try:
                for rdn in sig_status.signing_cert.subject.native.get("organization_name", []):
                    org_name = rdn
                    break
            except Exception:
                org_name = issuer_name

        signing_time = str(sig_status.signer_reported_dt) if sig_status.signer_reported_dt else None

        # Check 1: Cryptographic Byte Integrity (Rule 5: Altered after signing)
        if not sig_status.intact:
            return {
                "has_signature": True,
                "intact": False,
                "valid": False,
                "trusted": False,
                "signer_name": signer_name,
                "issuer_name": issuer_name,
                "organization": org_name,
                "signing_time": signing_time,
                "status": "TAMPERED_INVALID",
                "explanation": "Document cryptographic integrity check failed. Bytes were modified or altered after signing.",
            }

        # Check 2: Trust Chain / Issuer (Rule 6: Untrusted Issuer)
        if not sig_status.trusted:
            return {
                "has_signature": True,
                "intact": True,
                "valid": sig_status.valid,
                "trusted": False,
                "signer_name": signer_name,
                "issuer_name": issuer_name,
                "organization": org_name,
                "signing_time": signing_time,
                "status": "UNTRUSTED_ISSUER",
                "explanation": "The signing certificate is from an unknown or untrusted issuer not chained to the official AnswerChain Root Certificate Authority.",
            }

        # Check 3: Valid and Trusted
        return {
            "has_signature": True,
            "intact": True,
            "valid": sig_status.valid,
            "trusted": True,
            "signer_name": signer_name,
            "issuer_name": issuer_name,
            "organization": org_name,
            "signing_time": signing_time,
            "status": "VERIFIED_TRUSTED",
            "explanation": "Document is digitally signed by an officially trusted AnswerChain institutional authority with intact cryptographic integrity.",
        }

    except Exception as e:
        logger.error("Error inspecting PDF digital signature: %s", e)
        return {
            "has_signature": False,
            "intact": False,
            "valid": False,
            "trusted": False,
            "signer_name": None,
            "issuer_name": None,
            "organization": None,
            "signing_time": None,
            "status": "PARSE_ERROR",
            "explanation": f"Unable to parse digital signature structure: {str(e)}",
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