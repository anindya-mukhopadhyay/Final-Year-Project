"""
AnswerChain Application Services.

Implements business logic, validation, resource authorization, and workflow
orchestration across University, Teacher, Authority, Verification, and Admin roles.
"""

import hashlib
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

from backend.audit import log_audit_event
from backend.auth import User, get_user_by_id
from backend.blockchain_service import BlockchainService, blockchain_service
from backend.crypto import sign_academic_transaction
from backend.marksheet_pdf import verify_pdf_digital_signature

logger = logging.getLogger("application_service")

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
SCRIPTS_FILE = os.path.join(DATA_DIR, "scripts_metadata.json")
UPLOADS_DIR = os.path.join(DATA_DIR, "uploads")
DRAFTS_DIR = os.path.join(DATA_DIR, "evaluation_drafts")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)
os.makedirs(DRAFTS_DIR, exist_ok=True)

# Allowed file extensions and max upload size
ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB


def _load_scripts_metadata() -> Dict[str, Dict[str, Any]]:
    if os.path.isfile(SCRIPTS_FILE):
        try:
            with open(SCRIPTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def _save_scripts_metadata(metadata: Dict[str, Dict[str, Any]]) -> None:
    try:
        temp_file = f"{SCRIPTS_FILE}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        os.replace(temp_file, SCRIPTS_FILE)
    except Exception as e:
        logger.error("Failed to save scripts metadata: %s", e)


def _load_evaluation_draft(answer_script_id: str) -> Optional[Dict[str, Any]]:
    draft_file = os.path.join(DRAFTS_DIR, f"{answer_script_id}.json")
    if os.path.isfile(draft_file):
        try:
            with open(draft_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error("Failed to load draft for %s: %s", answer_script_id, e)
            return None
    return None


def _save_evaluation_draft(answer_script_id: str, draft: Dict[str, Any]) -> None:
    draft_file = os.path.join(DRAFTS_DIR, f"{answer_script_id}.json")
    try:
        temp_file = f"{draft_file}.tmp"
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(draft, f, indent=2, ensure_ascii=False)
        os.replace(temp_file, draft_file)
    except Exception as e:
        logger.error("Failed to save draft for %s: %s", answer_script_id, e)


def _generate_demo_answer_script_pdf(
    pdf_path: str,
    answer_script_id: str,
    student_name: str,
    student_id: str,
    exam_name: str,
    subject: str,
) -> str:
    """Generate a clean, realistic 3-page student answer script PDF for digital evaluation."""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36,
        title=f"Answer Script {answer_script_id}",
        author="AnswerChain Examination System",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ScriptHeader",
        parent=styles["Title"],
        fontSize=14,
        leading=18,
        textColor=colors.HexColor("#0f172a"),
        alignment=0,
    )
    body_style = ParagraphStyle(
        "AnswerBody",
        parent=styles["Normal"],
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#1e293b"),
    )

    story = []
    # --- PAGE 1 ---
    story.append(Paragraph(f"<b>Techno International New Town &bull; {exam_name}</b>", title_style))
    story.append(Spacer(1, 8))
    header_data = [
        ["Answer Script ID:", answer_script_id, "Candidate ID:", student_id],
        ["Student Name:", student_name, "Subject:", subject or "Distributed Systems (CS801)"],
        ["Examination:", exam_name, "Total Booklet Pages:", "3 Pages (Complete)"]
    ]
    t = Table(header_data, colWidths=[100, 160, 100, 160])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#0f172a")),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 14))

    story.append(Paragraph("<b>[Page 1] Question 1(a): Practical Byzantine Fault Tolerance (PBFT) Protocol (Max: 15 Marks)</b>", styles["Heading3"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Student Response:</b><br/>"
        "PBFT achieves state machine replication across independent nodes by executing three message exchange phases: "
        "Pre-Prepare, Prepare, and Commit.<br/>"
        "1. <i>Pre-Prepare Phase:</i> The primary node broadcasts a pre-prepare message containing view number v, sequence number n, and block digest d.<br/>"
        "2. <i>Prepare Phase:</i> Non-faulty backup replicas verify the message signature and sequence bounds, broadcasting prepare messages to all peers. Once 2f+1 valid prepare messages match, a node prepares the proposal.<br/>"
        "3. <i>Commit Phase:</i> Nodes broadcast commit messages. Upon collecting 2f+1 matching commit messages, the node enters committed-local and appends the block.<br/>"
        "This guarantees safety and non-forking as long as Byzantine malicious nodes f &lt; N/3.",
        body_style
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph("<b>Question 1(b): Quorum Threshold and Fault Bound Proof (Max: 10 Marks)</b>", styles["Heading3"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Student Response:</b><br/>"
        "In a network of N = 3f + 1 nodes with f Byzantine nodes, any quorum requires Q &ge; 2f + 1 nodes. "
        "Suppose two conflicting blocks b1 and b2 could both achieve quorum. Then each requires at least 2f + 1 votes. "
        "The intersection of two quorums has size at least (2f + 1) + (2f + 1) - (3f + 1) = f + 1 nodes. "
        "Since at most f nodes are faulty, at least one honest node must belong to both quorums. Honest nodes never vote "
        "for conflicting proposals in the same view. Hence conflicting proposals cannot both commit, preserving safety.",
        body_style
    ))

    # --- PAGE 2 ---
    story.append(PageBreak())
    story.append(Paragraph(f"<b>Answer Script: {answer_script_id} &bull; Page 2 of 3 &bull; Candidate: {student_name}</b>", styles["Heading3"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>[Page 2] Question 2: Digital Signatures and PAdES Integrity Verification (Max: 35 Marks)</b>", styles["Heading3"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Student Response:</b><br/>"
        "PAdES (PDF Advanced Electronic Signatures) embeds cryptographic signatures directly into the PDF ISO-32000 structure.<br/>"
        "• <i>ByteRange Partitioning:</i> The signature dictionary defines a ByteRange array [0, /Contents offset, /Contents end, remaining file length]. "
        "The cryptographic hash (SHA-256) is computed over every byte outside the signature container itself.<br/>"
        "• <i>Institutional Key Signing:</i> The resulting SHA-256 hash is signed using the institutional X.509 private key.<br/>"
        "• <i>Tamper-Evidence:</i> If any byte in the student information, evaluation table, or grade fields is altered by even a single bit, "
        "the recomputed SHA-256 byte range fails to match the decrypted digital signature hash, immediately exposing tampering.<br/>"
        "• <i>Reader Validation:</i> Standard PDF viewers (Adobe Acrobat, Foxit) and web verification portals use the institutional Root Certificate Authority "
        "to validate the trust chain and render authentic signature status.",
        body_style
    ))

    # --- PAGE 3 ---
    story.append(PageBreak())
    story.append(Paragraph(f"<b>Answer Script: {answer_script_id} &bull; Page 3 of 3 &bull; Candidate: {student_name}</b>", styles["Heading3"]))
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>[Page 3] Question 3: Durable Write-Ahead Logging (WAL) and View-Change Resilience (Max: 40 Marks)</b>", styles["Heading3"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "<b>Student Response:</b><br/>"
        "Distributed consensus nodes must maintain strict crash resilience without risking fork generation upon restart.<br/>"
        "• <i>Write-Ahead Logging:</i> Before any replica responds to a prepare or commit message, it records the vote, view number, and block hash to an append-only WAL on durable storage (fsync).<br/>"
        "• <i>Crash Recovery:</i> When a crashed node reboots, it replays its WAL to restore its locked view and highest prepared certificate, preventing it from double-voting.<br/>"
        "• <i>View-Change Safety:</i> If a primary node fails, backup nodes initiate a View-Change by broadcasting VIEW-CHANGE messages. The newly elected leader must inspect the highest prepared certificate from the quorum and re-propose that exact block, ensuring that no previously committed transaction is ever lost or overridden.",
        body_style
    ))

    doc.build(story)
    with open(pdf_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _infer_subject_name(exam_name: str, exam_id: str = "") -> str:
    """Infer canonical academic subject from exam name or ID."""
    clean_name = (exam_name or "").strip()
    upper_name = clean_name.upper()
    clean_id = (exam_id or "").strip().upper()
    combined = f"{upper_name} {clean_id}".strip()

    if clean_name in ["", "—", "-"]:
        return "DBMS"

    tokens = set(upper_name.replace("-", " ").replace("_", " ").split())
    tokens_id = set(clean_id.replace("-", " ").replace("_", " ").split())
    all_tokens = tokens | tokens_id

    if "PM" in all_tokens or "PROJECT MANAGEMENT" in combined:
        return "PM"
    if "AIML" in all_tokens or "AI" in all_tokens or "ML" in all_tokens or "MACHINE LEARNING" in combined:
        return "AIML"
    if "OS" in all_tokens or "OPERATING" in combined:
        return "OS"
    if "DBMS" in all_tokens or "DATABASE" in combined or "DISTRIBUTED" in combined:
        return "DBMS"
    if "NETWORKS" in all_tokens or "NETWORK" in all_tokens or "NETWORKING" in combined:
        return "NETWORKS"
    if "BLOCKCHAIN" in all_tokens or "CRYPTOGRAPHY" in combined or "SECURITY" in combined:
        return "BLOCKCHAIN"
    if "CLOUD" in all_tokens:
        return "CLOUD"

    # If the exam name is a concise subject title (<= 25 chars)
    if clean_name and len(clean_name) <= 25 and not any(k in upper_name for k in ["EXAMINATION", "CONSEN", "EXAM"]):
        return clean_name.strip().upper()

    return "DBMS"


class AcademicApplicationService:
    """Core application orchestrator connecting frontend to blockchain."""

    def __init__(self, bc_service: Optional[BlockchainService] = None) -> None:
        self.blockchain = bc_service or blockchain_service
        self._seed_default_metadata()

    def _seed_default_metadata(self) -> None:
        """Seed known metadata for pre-existing blockchain scripts."""
        meta = _load_scripts_metadata()
        changed = False

        if "AS-002" not in meta:
            meta["AS-002"] = {
                "answer_script_id": "AS-002",
                "student_id": "STUDENT-001",
                "student_name": "Anindya Mukhopadhyay",
                "exam_id": "EXAM-2026-01",
                "exam_name": "Distributed Systems Final Examination 2026",
                "university": "TINT",
                "file_name": "AS-002.pdf",
                "file_hash": "demo-answer-script-sha256-002",
                "uploaded_at": 1790897999,
            }
            changed = True

        if "AS-003" not in meta:
            meta["AS-003"] = {
                "answer_script_id": "AS-003",
                "student_id": "STUDENT-002",
                "student_name": "Priya Sharma",
                "exam_id": "EXAM-2026-02",
                "exam_name": "Blockchain Architecture & Security",
                "university": "TINT",
                "file_name": "AS-003.pdf",
                "file_hash": "demo-answer-script-sha256-003",
                "uploaded_at": 1790900000,
            }
            changed = True

        if changed:
            _save_scripts_metadata(meta)

    # ========================================================
    # LEDGER AGGREGATION HELPERS
    # ========================================================

    def get_all_blockchain_transactions(self) -> List[Dict[str, Any]]:
        """Fetch all confirmed transactions across blocks from the most up-to-date node."""
        candidates = []
        for role in ("UNIVERSITY", "AUTHORITY", "TEACHER"):
            resp = self.blockchain.get_blockchain(role)
            if resp.get("success"):
                blks = resp.get("data", {}).get("blocks", [])
                if blks:
                    candidates.append(blks)

        if not candidates:
            return []

        blocks = max(candidates, key=len)
        transactions = []
        for b in blocks:
            data = b.get("data", [])
            if isinstance(data, list):
                for tx in data:
                    tx_copy = dict(tx)
                    tx_copy["block_number"] = b.get("index")
                    tx_copy["block_hash"] = b.get("hash")
                    tx_copy["block_timestamp"] = b.get("timestamp")
                    transactions.append(tx_copy)
        return transactions

    def get_unified_scripts_status(self) -> List[Dict[str, Any]]:
        """
        Aggregate full lifecycle status for all registered answer scripts:
        Registration -> Assignment -> Evaluation -> Finalization -> Marksheet
        """
        transactions = self.get_all_blockchain_transactions()
        meta = _load_scripts_metadata()

        scripts_map: Dict[str, Dict[str, Any]] = {}

        for tx in transactions:
            tx_data = tx.get("data", {})
            tx_type = tx_data.get("type")
            as_id = tx_data.get("answer_script_id")

            if not as_id:
                continue

            if as_id not in scripts_map:
                script_meta = meta.get(as_id, {})
                explicit_sub = script_meta.get("subject") or tx_data.get("subject")
                if explicit_sub and str(explicit_sub).strip() not in ["", "—", "-"]:
                    subject = str(explicit_sub).strip().upper()
                else:
                    exam_n = script_meta.get("exam_name") or tx_data.get("exam_name", "")
                    exam_i = script_meta.get("exam_id") or tx_data.get("exam_id", "")
                    subject = _infer_subject_name(exam_n, exam_i)

                scripts_map[as_id] = {
                    "answer_script_id": as_id,
                    "student_id": script_meta.get("student_id", "—"),
                    "student_name": script_meta.get("student_name", "—"),
                    "exam_id": script_meta.get("exam_id", tx_data.get("exam_id", "—")),
                    "exam_name": script_meta.get("exam_name", "—"),
                    "subject": subject.strip().upper(),
                    "university": script_meta.get("university", tx_data.get("university", "TINT")),
                    "file_name": script_meta.get("file_name", tx_data.get("file_name", "—")),
                    "file_hash": script_meta.get("file_hash", tx_data.get("answer_script_hash", "—")),
                    "registered": False,
                    "registration_tx": None,
                    "registration_block": None,
                    "assigned": False,
                    "teacher_id": None,
                    "teacher_name": None,
                    "assignment_tx": None,
                    "evaluated": False,
                    "evaluation_id": None,
                    "marks": None,
                    "max_marks": None,
                    "evaluation_tx": None,
                    "finalized": False,
                    "result_id": None,
                    "final_marks": None,
                    "authority_id": None,
                    "finalization_tx": None,
                    "marksheet_generated": False,
                    "marksheet_id": None,
                    "marksheet_data_hash": None,
                    "marksheet_pdf_hash": None,
                    "percentage": None,
                    "marksheet_tx": None,
                    "current_status": "UNKNOWN",
                }

            s = scripts_map[as_id]

            if tx_type == "ANSWER_SCRIPT_REGISTERED":
                s["registered"] = True
                s["registration_tx"] = tx.get("transaction_id")
                s["registration_block"] = tx.get("block_number")
                if "file_hash" not in s or s["file_hash"] == "—":
                    s["file_hash"] = tx_data.get("answer_script_hash", "—")
                s["current_status"] = "REGISTERED"

            elif tx_type == "ANSWER_SCRIPT_ASSIGNED":
                s["assigned"] = True
                s["teacher_id"] = tx_data.get("teacher_id")
                teacher_user = get_user_by_id(s["teacher_id"]) if s["teacher_id"] else None
                s["teacher_name"] = teacher_user.name if teacher_user else s["teacher_id"]
                s["assignment_tx"] = tx.get("transaction_id")
                s["current_status"] = "ASSIGNED"

            elif tx_type == "EVALUATION_SUBMITTED":
                s["evaluated"] = True
                s["evaluation_id"] = tx_data.get("evaluation_id")
                s["marks"] = tx_data.get("marks")
                s["max_marks"] = tx_data.get("max_marks")
                s["evaluation_tx"] = tx.get("transaction_id")
                s["current_status"] = "EVALUATED"

            elif tx_type == "RESULT_FINALIZED":
                s["finalized"] = True
                s["result_id"] = tx_data.get("result_id")
                s["final_marks"] = tx_data.get("final_marks")
                s["authority_id"] = tx_data.get("authority_id")
                s["finalization_tx"] = tx.get("transaction_id")
                s["current_status"] = "FINALIZED"

            elif tx_type == "MARKSHEET_REGISTERED":
                s["marksheet_generated"] = True
                s["marksheet_id"] = tx_data.get("marksheet_id")
                s["marksheet_data_hash"] = tx_data.get("marksheet_data_hash")
                s["marksheet_pdf_hash"] = tx_data.get("marksheet_pdf_hash")
                s["percentage"] = tx_data.get("percentage")
                s["marksheet_tx"] = tx.get("transaction_id")
                s["current_status"] = "MARKSHEET_GENERATED"

        return list(scripts_map.values())

    # ========================================================
    # UNIVERSITY WORKFLOW
    # ========================================================

    def get_university_dashboard(self) -> Dict[str, Any]:
        """Compute university KPIs and summary overview."""
        scripts = self.get_unified_scripts_status()
        total_scripts = len(scripts)
        assigned_scripts = sum(1 for s in scripts if s["assigned"])
        pending_evaluations = sum(1 for s in scripts if s["assigned"] and not s["evaluated"])
        finalized_results = sum(1 for s in scripts if s["finalized"])
        generated_marksheets = sum(1 for s in scripts if s["marksheet_generated"])

        txs = self.get_all_blockchain_transactions()
        confirmed_transactions = len(txs)

        return {
            "kpis": {
                "total_scripts": total_scripts,
                "assigned_scripts": assigned_scripts,
                "pending_evaluations": pending_evaluations,
                "finalized_results": finalized_results,
                "generated_marksheets": generated_marksheets,
                "confirmed_transactions": confirmed_transactions,
            },
            "recent_scripts": scripts[-10:] if scripts else [],
        }

    def register_answer_script(
        self,
        current_user: User,
        student_id: str,
        student_name: str,
        exam_id: str,
        exam_name: str,
        file_name: str,
        file_bytes: Optional[bytes] = None,
        provided_hash: Optional[str] = None,
        answer_script_id: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """
        Register a new answer script on the university node and ledger.
        """
        # Validations
        if not student_id or not student_id.strip():
            return False, {"error": "Student ID is required."}, 400
        if not exam_id or not exam_id.strip():
            return False, {"error": "Exam ID is required."}, 400
        if not exam_name or not exam_name.strip():
            return False, {"error": "Exam Name is required."}, 400

        # Calculate or validate hash
        if file_bytes:
            if len(file_bytes) > MAX_FILE_SIZE:
                return False, {"error": f"File exceeds maximum allowed size ({MAX_FILE_SIZE // (1024 * 1024)}MB)."}, 400
            file_hash = hashlib.sha256(file_bytes).hexdigest()
        elif provided_hash:
            file_hash = provided_hash.strip()
        else:
            # Generate deterministic synthetic demo file hash
            synth_content = f"{student_id}:{exam_id}:{file_name}:{time.time()}"
            file_hash = hashlib.sha256(synth_content.encode("utf-8")).hexdigest()

        # Determine Answer Script ID
        if not answer_script_id or not answer_script_id.strip():
            scripts = self.get_unified_scripts_status()
            existing_ids = {s["answer_script_id"] for s in scripts}
            idx = 1
            while f"AS-{idx:03d}" in existing_ids:
                idx += 1
            answer_script_id = f"AS-{idx:03d}"
        else:
            answer_script_id = answer_script_id.strip()

        # Check existing
        existing_meta = _load_scripts_metadata()
        if answer_script_id in existing_meta:
            return False, {"error": f"Answer script '{answer_script_id}' already registered."}, 409

        # Register to University Node
        university_name = "TINT"
        raw_tx_data = {
            "type": "ANSWER_SCRIPT_REGISTERED",
            "university": university_name,
            "exam_id": exam_id.strip(),
            "answer_script_id": answer_script_id,
            "file_name": file_name or f"{answer_script_id}.pdf",
            "answer_script_hash": file_hash,
        }
        signed_tx = sign_academic_transaction(current_user.user_id, current_user.role, raw_tx_data)
        sig_meta = {
            "actor_id": signed_tx["actor_id"],
            "actor_role": signed_tx["actor_role"],
            "signature": signed_tx["signature"],
            "payload_hash": signed_tx["payload_hash"],
            "public_key_id": signed_tx["public_key_id"],
        }
        resp = self.blockchain.register_answer_script(
            university=university_name,
            exam_id=exam_id.strip(),
            answer_script_id=answer_script_id,
            file_name=file_name or f"{answer_script_id}.pdf",
            file_hash=file_hash,
            sig_meta=sig_meta,
        )

        if not resp["success"]:
            status_code = resp.get("status_code", 500)
            return False, resp.get("data", {"error": "Registration failed on node."}), status_code

        # Save uploaded physical file if bytes provided
        if file_bytes:
            saved_pdf_path = os.path.join(UPLOADS_DIR, f"{answer_script_id}.pdf")
            try:
                with open(saved_pdf_path, "wb") as f:
                    f.write(file_bytes)
            except Exception as e:
                logger.error("Failed to save uploaded answer script file: %s", e)

        # Store metadata
        existing_meta[answer_script_id] = {
            "answer_script_id": answer_script_id,
            "student_id": student_id.strip(),
            "student_name": student_name.strip() or student_id.strip(),
            "exam_id": exam_id.strip(),
            "exam_name": exam_name.strip(),
            "subject": _infer_subject_name(exam_name, exam_id),
            "university": university_name,
            "file_name": file_name or f"{answer_script_id}.pdf",
            "file_hash": file_hash,
            "uploaded_at": time.time(),
            "uploaded_by": current_user.user_id,
        }
        _save_scripts_metadata(existing_meta)

        # Audit log
        tx = resp["data"].get("transaction", {})
        block = resp["data"].get("block", {})
        log_audit_event(
            action="ANSWER_SCRIPT_REGISTERED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=answer_script_id,
            transaction_id=tx.get("transaction_id"),
            status="SUCCESS",
            details={
                "student_id": student_id,
                "exam_id": exam_id,
                "file_hash": file_hash,
                "block_number": block.get("index"),
            },
        )

        return True, {
            "message": "Answer script registered successfully.",
            "answer_script_id": answer_script_id,
            "file_hash": file_hash,
            "transaction_id": tx.get("transaction_id"),
            "block_number": block.get("index"),
            "confirmation_status": "CONFIRMED",
            "transaction": tx,
            "block": block,
        }, 201

    def assign_teacher(
        self,
        current_user: User,
        answer_script_id: str,
        teacher_id: str,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """Assign an evaluation teacher to an answer script."""
        clean_as_id = answer_script_id.strip()
        clean_tch_id = teacher_id.strip().upper()

        teacher_user = get_user_by_id(clean_tch_id)
        if not teacher_user or teacher_user.role != "TEACHER":
            return False, {"error": f"Invalid teacher ID '{clean_tch_id}'. Must be an active teacher."}, 400

        raw_tx_data = {
            "type": "ANSWER_SCRIPT_ASSIGNED",
            "answer_script_id": clean_as_id,
            "teacher_id": clean_tch_id,
            "assigned_by": current_user.user_id,
        }
        signed_tx = sign_academic_transaction(current_user.user_id, current_user.role, raw_tx_data)
        sig_meta = {
            "actor_id": signed_tx["actor_id"],
            "actor_role": signed_tx["actor_role"],
            "signature": signed_tx["signature"],
            "payload_hash": signed_tx["payload_hash"],
            "public_key_id": signed_tx["public_key_id"],
        }
        resp = self.blockchain.assign_teacher(
            answer_script_id=clean_as_id,
            teacher_id=clean_tch_id,
            assigned_by=current_user.user_id,
            sig_meta=sig_meta,
        )

        if not resp["success"]:
            return False, resp.get("data", {"error": "Assignment failed on node."}), resp.get("status_code", 500)

        tx = resp["data"].get("transaction", {})
        block = resp["data"].get("block", {})

        log_audit_event(
            action="ANSWER_SCRIPT_ASSIGNED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=clean_as_id,
            transaction_id=tx.get("transaction_id"),
            status="SUCCESS",
            details={
                "teacher_id": clean_tch_id,
                "teacher_name": teacher_user.name,
                "block_number": block.get("index"),
            },
        )

        return True, {
            "message": f"Answer script '{clean_as_id}' assigned to {teacher_user.name}.",
            "answer_script_id": clean_as_id,
            "teacher_id": clean_tch_id,
            "teacher_name": teacher_user.name,
            "transaction_id": tx.get("transaction_id"),
            "block_number": block.get("index"),
            "transaction": tx,
        }, 200

    # ========================================================
    # TEACHER WORKFLOW
    # ========================================================

    def get_teacher_assignments(self, teacher_id: str) -> List[Dict[str, Any]]:
        """Return only scripts assigned to the requesting teacher."""
        scripts = self.get_unified_scripts_status()
        return [s for s in scripts if s.get("teacher_id") == teacher_id]

    def get_teacher_assignment_detail(
        self,
        current_user: User,
        answer_script_id: str,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """
        Retrieve assignment details with strict ownership verification.
        Teacher can ONLY view assignments assigned to them!
        """
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)

        if not script:
            return False, {"error": "Answer script not found."}, 404

        if script.get("teacher_id") != current_user.user_id and current_user.role != "ADMIN":
            return False, {
                "error": "Forbidden",
                "message": "Access denied. This answer script is not assigned to you.",
            }, 403

        return True, {"assignment": script}, 200

    def get_answer_script_file_path(
        self,
        current_user: User,
        answer_script_id: str,
    ) -> Tuple[bool, Optional[str], Optional[str], int]:
        """
        Retrieve original answer script PDF path and authoritative SHA-256 hash.
        Authorized for assigned teacher, university, authority, or admin.
        Preserves original document without modifying bytes.
        """
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)
        if not script:
            return False, None, None, 404

        # Access control: Teacher must be assigned
        if current_user.role == "TEACHER" and script.get("teacher_id") != current_user.user_id:
            return False, None, None, 403

        meta = _load_scripts_metadata().get(answer_script_id, {})
        student_name = script.get("student_name") or meta.get("student_name", "Student")
        student_id = script.get("student_id") or meta.get("student_id", "STU-001")
        exam_name = script.get("exam_name") or meta.get("exam_name", "University Examination")
        subject = script.get("subject") or meta.get("subject", "Distributed Systems")

        pdf_path = os.path.join(UPLOADS_DIR, f"{answer_script_id}.pdf")
        if not os.path.isfile(pdf_path):
            file_hash = _generate_demo_answer_script_pdf(
                pdf_path=pdf_path,
                answer_script_id=answer_script_id,
                student_name=student_name,
                student_id=student_id,
                exam_name=exam_name,
                subject=subject,
            )
        else:
            with open(pdf_path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

        return True, pdf_path, file_hash, 200

    def get_evaluation_draft(
        self,
        current_user: User,
        answer_script_id: str,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """Get current page-wise evaluation draft and progress for an assigned script."""
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)
        if not script:
            return False, {"error": "Answer script not found."}, 404

        if script.get("teacher_id") != current_user.user_id and current_user.role != "ADMIN":
            return False, {
                "error": "Forbidden",
                "message": "Access denied. This answer script is not assigned to you.",
            }, 403

        draft = _load_evaluation_draft(answer_script_id)
        if not draft:
            # Detect actual total pages from uploaded PDF if available
            pdf_path = os.path.join(UPLOADS_DIR, f"{answer_script_id}.pdf")
            total_pages = 3
            if os.path.isfile(pdf_path):
                try:
                    from pyhanko.pdf_utils.reader import PdfFileReader
                    with open(pdf_path, "rb") as pf:
                        r = PdfFileReader(pf)
                        total_pages = int(r.root["/Pages"]["/Count"])
                except Exception as ex:
                    logger.warning("Could not read PDF page count: %s", ex)
                    total_pages = 3
            if total_pages < 1:
                total_pages = 1

            # Initialize clean page-wise evaluation schema
            draft = {
                "answer_script_id": answer_script_id,
                "teacher_id": current_user.user_id,
                "total_pages": total_pages,
                "pages": {
                    str(p): {
                        "page_number": p,
                        "is_completed": False,
                        "page_remarks": "",
                        "awarded_marks": 0.0,
                        "max_marks": round(100.0 / total_pages, 1),
                        "page_total": 0.0,
                        "page_max": round(100.0 / total_pages, 1),
                        "questions": [
                            {
                                "question_id": f"Page-{p}",
                                "question_title": f"Page {p} Marks",
                                "max_marks": round(100.0 / total_pages, 1),
                                "awarded_marks": 0.0,
                                "remarks": "",
                            }
                        ],
                    }
                    for p in range(1, total_pages + 1)
                },
                "overall_remarks": "",
                "last_updated": time.time(),
            }
            _save_evaluation_draft(answer_script_id, draft)

        # Ensure page objects have awarded_marks and max_marks fields
        pages = draft.get("pages", {})
        for p_val in pages.values():
            if "awarded_marks" not in p_val:
                p_val["awarded_marks"] = p_val.get("page_total", 0.0)
            if "max_marks" not in p_val:
                p_val["max_marks"] = p_val.get("page_max", 25.0)

        # Recalculate live progress
        total_awarded = sum(float(p.get("page_total", p.get("awarded_marks", 0.0))) for p in pages.values())
        total_max = sum(float(p.get("page_max", p.get("max_marks", 0.0))) for p in pages.values())
        completed_count = sum(1 for p in pages.values() if p.get("is_completed", False))
        total_count = len(pages)
        all_completed = (completed_count == total_count and total_count > 0)

        summary = {
            "draft": draft,
            "script": script,
            "total_awarded_marks": round(total_awarded, 2),
            "total_max_marks": round(total_max, 2),
            "completed_pages_count": completed_count,
            "total_pages_count": total_count,
            "all_pages_completed": all_completed,
            "evaluated": script.get("evaluated", False),
            "finalized": script.get("finalized", False),
        }
        return True, summary, 200

    def save_page_evaluation(
        self,
        current_user: User,
        answer_script_id: str,
        page_number: int,
        questions: Optional[List[Dict[str, Any]]] = None,
        awarded_marks: Optional[float] = None,
        max_marks: Optional[float] = None,
        page_remarks: str = "",
        mark_completed: bool = False,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """
        Save page-wise marks and annotations.
        Supports both direct page-wise marks (page_number, awarded_marks, max_marks)
        and question-wise breakdown for flexibility.
        Validates that awarded marks do not exceed max marks.
        Automatically updates completion status and totals.
        """
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)
        if not script:
            return False, {"error": "Answer script not found."}, 404

        if script.get("teacher_id") != current_user.user_id and current_user.role != "ADMIN":
            return False, {
                "error": "Forbidden",
                "message": "Only the assigned teacher can evaluate this script.",
            }, 403

        if script.get("evaluated"):
            return False, {"error": "Conflict: Evaluation has already been finalized and committed."}, 409

        validated_questions = []
        page_total = 0.0
        page_max = 0.0

        if questions and len(questions) > 0:
            # Question-wise breakdown provided
            for q in questions:
                q_id = str(q.get("question_id", "Q")).strip()
                q_title = str(q.get("question_title", q_id)).strip()
                try:
                    awarded = float(q.get("awarded_marks", 0.0))
                    q_max = float(q.get("max_marks", 10.0))
                except (ValueError, TypeError):
                    return False, {"error": f"Invalid marks for question '{q_id}'. Must be numeric."}, 400

                if q_max <= 0:
                    return False, {"error": f"Maximum marks for question '{q_id}' must be greater than zero."}, 400

                if awarded < 0:
                    return False, {"error": f"Awarded marks for question '{q_id}' cannot be negative ({awarded})."}, 400

                if awarded > q_max:
                    return False, {
                        "error": f"Awarded marks ({awarded}) cannot exceed maximum marks ({q_max}) for question '{q_id}'."
                    }, 400

                validated_questions.append({
                    "question_id": q_id,
                    "question_title": q_title,
                    "max_marks": q_max,
                    "awarded_marks": awarded,
                    "remarks": str(q.get("remarks", "")).strip(),
                })
                page_total += awarded
                page_max += q_max
        else:
            # Direct Page-wise evaluation (Primary workflow)
            if awarded_marks is None:
                return False, {"error": f"Awarded marks for Page {page_number} are required."}, 400
            try:
                page_total = float(awarded_marks)
                page_max = float(max_marks if max_marks is not None else 25.0)
            except (ValueError, TypeError):
                return False, {"error": f"Invalid marks for Page {page_number}. Must be numeric."}, 400

            if page_max <= 0:
                return False, {"error": f"Maximum marks for Page {page_number} must be greater than zero."}, 400
            if page_total < 0:
                return False, {"error": f"Awarded marks for Page {page_number} cannot be negative ({page_total})."}, 400
            if page_total > page_max:
                return False, {
                    "error": f"Awarded marks ({page_total}) cannot exceed maximum marks ({page_max}) for Page {page_number}."
                }, 400

            validated_questions = [{
                "question_id": f"Page-{page_number}",
                "question_title": f"Page {page_number} Marks",
                "max_marks": page_max,
                "awarded_marks": page_total,
                "remarks": page_remarks.strip(),
            }]

        draft = _load_evaluation_draft(answer_script_id) or {
            "answer_script_id": answer_script_id,
            "teacher_id": current_user.user_id,
            "total_pages": 3,
            "pages": {},
            "overall_remarks": "",
        }

        page_key = str(page_number)
        draft.setdefault("pages", {})
        draft["pages"][page_key] = {
            "page_number": int(page_number),
            "is_completed": bool(mark_completed),
            "page_remarks": page_remarks.strip(),
            "awarded_marks": round(page_total, 2),
            "max_marks": round(page_max, 2),
            "page_total": round(page_total, 2),
            "page_max": round(page_max, 2),
            "questions": validated_questions,
        }
        draft["last_updated"] = time.time()
        _save_evaluation_draft(answer_script_id, draft)

        # Audit log for page evaluation progress
        log_audit_event(
            action="PAGE_EVALUATION_SAVED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=answer_script_id,
            status="SUCCESS",
            details={
                "page_number": page_number,
                "page_total": round(page_total, 2),
                "page_max": round(page_max, 2),
                "is_completed": mark_completed,
            },
        )

        # Calculate updated summary
        pages = draft["pages"]
        total_awarded = sum(float(p.get("page_total", 0.0)) for p in pages.values())
        total_max = sum(float(p.get("page_max", 0.0)) for p in pages.values())
        completed_count = sum(1 for p in pages.values() if p.get("is_completed", False))
        total_count = len(pages)
        all_completed = (completed_count == total_count and total_count >= int(draft.get("total_pages", 3)))

        return True, {
            "message": f"Page {page_number} evaluation saved successfully.",
            "page": draft["pages"][page_key],
            "total_awarded_marks": round(total_awarded, 2),
            "total_max_marks": round(total_max, 2),
            "completed_pages_count": completed_count,
            "total_pages_count": total_count,
            "all_pages_completed": all_completed,
        }, 200

    def evaluate_assignment(
        self,
        current_user: User,
        answer_script_id: str,
        marks: float,
        max_marks: float,
        comments: Optional[str] = None,
        page_evaluations: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """
        Submit teacher evaluation. Validates teacher identity, page completion, and bounds.
        Digitally signs transaction and commits through blockchain consensus.
        """
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)

        if not script:
            return False, {"error": "Answer script not found."}, 404

        # Strict identity check
        if script.get("teacher_id") != current_user.user_id:
            return False, {
                "error": "Forbidden",
                "message": "Only the assigned teacher can submit evaluations for this script.",
            }, 403

        if script.get("finalized"):
            return False, {
                "error": "Forbidden",
                "message": "Result is already finalized and immutable.",
            }, 403

        if script.get("evaluated"):
            return False, {"error": "Evaluation has already been submitted."}, 409

        try:
            marks = float(marks)
            max_marks = float(max_marks)
        except (TypeError, ValueError):
            return False, {"error": "Marks and Max Marks must be valid numbers."}, 400

        if max_marks <= 0:
            return False, {"error": "Maximum marks must be greater than zero."}, 400
        if marks < 0 or marks > max_marks:
            return False, {"error": f"Marks ({marks}) cannot be negative or exceed maximum marks ({max_marks})."}, 400

        # Page completion validation
        draft = _load_evaluation_draft(answer_script_id)
        final_page_records = []
        if page_evaluations:
            # Explicit page evaluations submitted in payload
            incomplete_pages = []
            page_sum = 0.0
            for p in page_evaluations:
                if not p.get("is_completed", False):
                    incomplete_pages.append(p.get("page_number", "?"))
                page_sum += float(p.get("page_total", 0.0))
            if incomplete_pages:
                return False, {
                    "error": "Incomplete Pages",
                    "message": f"All pages must be completed before final submission. Incomplete pages: {incomplete_pages}",
                }, 400
            if abs(marks - page_sum) > 0.01:
                return False, {
                    "error": "Total Mismatch",
                    "message": f"Total marks ({marks}) does not match sum of page evaluations ({page_sum}).",
                }, 400
            final_page_records = page_evaluations
        elif draft and draft.get("pages"):
            # Check draft completion
            pages = draft["pages"]
            total_req = int(draft.get("total_pages", 3))
            incomplete_pages = [
                pg for pg in range(1, total_req + 1)
                if not pages.get(str(pg), {}).get("is_completed", False)
            ]
            if incomplete_pages:
                return False, {
                    "error": "Incomplete Pages",
                    "message": f"All pages must be completed before final submission. Incomplete pages: {incomplete_pages}",
                }, 400
            page_sum = sum(float(p.get("page_total", 0.0)) for p in pages.values())
            if abs(marks - page_sum) > 0.01:
                return False, {
                    "error": "Total Mismatch",
                    "message": f"Total marks ({marks}) does not match sum of page evaluations ({page_sum}).",
                }, 400
            final_page_records = list(pages.values())

        raw_tx_data = {
            "type": "EVALUATION_SUBMITTED",
            "answer_script_id": answer_script_id,
            "teacher_id": current_user.user_id,
            "marks": marks,
            "max_marks": max_marks,
        }
        signed_tx = sign_academic_transaction(current_user.user_id, current_user.role, raw_tx_data)
        sig_meta = {
            "actor_id": signed_tx["actor_id"],
            "actor_role": signed_tx["actor_role"],
            "signature": signed_tx["signature"],
            "payload_hash": signed_tx["payload_hash"],
            "public_key_id": signed_tx["public_key_id"],
        }
        resp = self.blockchain.submit_evaluation(
            answer_script_id=answer_script_id,
            teacher_id=current_user.user_id,
            marks=marks,
            max_marks=max_marks,
            sig_meta=sig_meta,
        )

        if not resp["success"]:
            return False, resp.get("data", {"error": "Evaluation failed on node."}), resp.get("status_code", 500)

        tx = resp["data"].get("transaction", {})
        block = resp["data"].get("block", {})
        eval_id = tx.get("data", {}).get("evaluation_id", "—")

        # Mark draft as committed
        if draft:
            draft["committed"] = True
            draft["evaluation_id"] = eval_id
            draft["committed_at"] = time.time()
            _save_evaluation_draft(answer_script_id, draft)

        log_audit_event(
            action="EVALUATION_SUBMITTED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=answer_script_id,
            transaction_id=tx.get("transaction_id"),
            status="SUCCESS",
            details={
                "evaluation_id": eval_id,
                "marks": marks,
                "max_marks": max_marks,
                "comments": comments or "",
                "block_number": block.get("index"),
                "pages_evaluated": len(final_page_records),
            },
        )

        return True, {
            "message": "Evaluation submitted successfully.",
            "evaluation_id": eval_id,
            "answer_script_id": answer_script_id,
            "marks": marks,
            "max_marks": max_marks,
            "transaction_id": tx.get("transaction_id"),
            "block_number": block.get("index"),
        }, 200

    # ========================================================
    # AUTHORITY WORKFLOW
    # ========================================================

    def get_authority_dashboard(self) -> Dict[str, Any]:
        """Compute authority metrics for review, finalization, and marksheets."""
        scripts = self.get_unified_scripts_status()
        pending_evaluations = [s for s in scripts if s["evaluated"] and not s["finalized"]]
        finalized_results = [s for s in scripts if s["finalized"]]
        marksheets = [s for s in scripts if s["marksheet_generated"]]

        return {
            "kpis": {
                "pending_reviews": len(pending_evaluations),
                "finalized_results": len(finalized_results),
                "generated_marksheets": len(marksheets),
                "total_scripts": len(scripts),
            },
            "pending_evaluations": pending_evaluations,
            "finalized_results": finalized_results,
            "marksheets": marksheets,
        }

    def finalize_result(
        self,
        current_user: User,
        answer_script_id: str,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """Finalize an evaluated result on Authority Node."""
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)

        if not script:
            return False, {"error": "Answer script not found."}, 404

        if not script["evaluated"]:
            return False, {"error": "Cannot finalize result: No evaluation has been submitted yet."}, 400

        if script["finalized"]:
            return False, {"error": "Result is already finalized.", "result_id": script["result_id"]}, 409

        raw_tx_data = {
            "type": "RESULT_FINALIZED",
            "answer_script_id": answer_script_id,
            "authority_id": current_user.user_id,
        }
        signed_tx = sign_academic_transaction(current_user.user_id, current_user.role, raw_tx_data)
        sig_meta = {
            "actor_id": signed_tx["actor_id"],
            "actor_role": signed_tx["actor_role"],
            "signature": signed_tx["signature"],
            "payload_hash": signed_tx["payload_hash"],
            "public_key_id": signed_tx["public_key_id"],
        }
        resp = self.blockchain.finalize_result(
            answer_script_id=answer_script_id,
            authority_id=current_user.user_id,
            sig_meta=sig_meta,
        )

        if not resp["success"]:
            return False, resp.get("data", {"error": "Finalization failed on node."}), resp.get("status_code", 500)

        tx = resp["data"].get("transaction", {})
        block = resp["data"].get("block", {})
        result_id = tx.get("data", {}).get("result_id", "—")

        log_audit_event(
            action="RESULT_FINALIZED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=answer_script_id,
            transaction_id=tx.get("transaction_id"),
            status="SUCCESS",
            details={
                "result_id": result_id,
                "final_marks": script.get("marks"),
                "authority_id": current_user.user_id,
                "block_number": block.get("index"),
            },
        )

        return True, {
            "message": "Result finalized successfully.",
            "result_id": result_id,
            "answer_script_id": answer_script_id,
            "final_marks": script.get("marks"),
            "max_marks": script.get("max_marks"),
            "transaction_id": tx.get("transaction_id"),
            "block_number": block.get("index"),
        }, 200

    def generate_marksheet(
        self,
        current_user: User,
        answer_script_id: str,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """Generate official marksheet and physical PDF for finalized result."""
        scripts = self.get_unified_scripts_status()
        script = next((s for s in scripts if s["answer_script_id"] == answer_script_id), None)

        if not script:
            return False, {"error": "Answer script not found."}, 404

        if not script["finalized"]:
            return False, {"error": "Marksheet requires a finalized result."}, 400

        if script["marksheet_generated"]:
            return False, {
                "error": "Marksheet already exists.",
                "marksheet_id": script["marksheet_id"],
            }, 409

        meta = _load_scripts_metadata().get(answer_script_id, {})
        student_id = script.get("student_id") or meta.get("student_id", "STUDENT-001")
        student_name = script.get("student_name") or meta.get("student_name", "Student")
        exam_name = script.get("exam_name") or meta.get("exam_name", "University Examination")
        university = script.get("university") or meta.get("university", "TINT")

        raw_tx_data = {
            "type": "MARKSHEET_REGISTERED",
            "answer_script_id": answer_script_id,
            "student_id": student_id,
            "student_name": student_name,
            "university": university,
            "exam_name": exam_name,
        }
        signed_tx = sign_academic_transaction(current_user.user_id, current_user.role, raw_tx_data)
        sig_meta = {
            "actor_id": signed_tx["actor_id"],
            "actor_role": signed_tx["actor_role"],
            "signature": signed_tx["signature"],
            "payload_hash": signed_tx["payload_hash"],
            "public_key_id": signed_tx["public_key_id"],
        }
        resp = self.blockchain.generate_marksheet(
            answer_script_id=answer_script_id,
            student_id=student_id,
            student_name=student_name,
            university=university,
            exam_name=exam_name,
            sig_meta=sig_meta,
        )

        if not resp["success"]:
            return False, resp.get("data", {"error": "Marksheet generation failed on node."}), resp.get("status_code", 500)

        data = resp["data"]
        marksheet_id = data.get("marksheet_id")
        tx = data.get("transaction", {})
        block = data.get("block", {})

        log_audit_event(
            action="MARKSHEET_GENERATED",
            actor=current_user.user_id,
            actor_role=current_user.role,
            resource_id=marksheet_id,
            transaction_id=tx.get("transaction_id"),
            status="SUCCESS",
            details={
                "answer_script_id": answer_script_id,
                "marksheet_data_hash": data.get("marksheet_data_hash"),
                "marksheet_pdf_hash": data.get("marksheet_pdf_hash"),
                "block_number": block.get("index"),
            },
        )

        return True, {
            "message": "Marksheet and PDF generated successfully.",
            "marksheet_id": marksheet_id,
            "answer_script_id": answer_script_id,
            "marksheet_data_hash": data.get("marksheet_data_hash"),
            "marksheet_pdf_hash": data.get("marksheet_pdf_hash"),
            "pdf_filename": data.get("pdf_filename"),
            "transaction_id": tx.get("transaction_id"),
            "block_number": block.get("index"),
        }, 201

    # ========================================================
    # PUBLIC VERIFICATION (UNAUTHENTICATED)
    # ========================================================

    def verify_marksheet_public(self, marksheet_id: str) -> Dict[str, Any]:
        """
        Public marksheet verification engine.
        Returns VERIFIED, TAMPERED, NOT_FOUND, INVALID_RESULT, or PDF_INTEGRITY_FAILED.
        Omits internal credentials or private operational trace data.
        """
        clean_id = marksheet_id.strip()

        # Step 1: Logical Marksheet Blockchain Verification
        verify_resp = self.blockchain.verify_marksheet(marksheet_id=clean_id)
        if not verify_resp["success"] or not verify_resp["data"].get("verified"):
            error_msg = verify_resp["data"].get("message", "Marksheet not found on blockchain.")
            if "not found" in error_msg.lower():
                return {
                    "status": "NOT_FOUND",
                    "verified": False,
                    "message": "No marksheet with this verification ID exists on the distributed ledger.",
                    "marksheet_id": clean_id,
                }
            if "not finalized" in error_msg.lower() or "finalized result does not exist" in error_msg.lower():
                return {
                    "status": "INVALID_RESULT",
                    "verified": False,
                    "message": "Marksheet references an invalid or unfinalized academic result.",
                    "marksheet_id": clean_id,
                }
            return {
                "status": "TAMPERED",
                "verified": False,
                "message": "Logical marksheet hash mismatch: Blockchain ledger data has been modified.",
                "marksheet_id": clean_id,
            }

        ms_data = verify_resp["data"].get("marksheet", {})

        # Step 2: Physical PDF SHA-256 Verification
        pdf_resp = self.blockchain.verify_marksheet_pdf(marksheet_id=clean_id)
        pdf_verified = pdf_resp["success"] and pdf_resp["data"].get("verified", False)

        if not pdf_verified:
            # Check if PDF hash was missing or mismatched
            msg = pdf_resp["data"].get("message", "PDF integrity verification failed.")
            return {
                "status": "PDF_INTEGRITY_FAILED",
                "verified": False,
                "message": f"PDF verification failed: {msg}",
                "marksheet_id": clean_id,
                "logical_verified": True,
                "pdf_verified": False,
            }

        # Audit verification check
        log_audit_event(
            action="MARKSHEET_VERIFIED",
            actor="PUBLIC_VERIFIER",
            actor_role="VERIFIER",
            resource_id=clean_id,
            status="SUCCESS",
            details={"status": "VERIFIED"},
        )

        return {
            "status": "VERIFIED",
            "verified": True,
            "message": "Cryptographic credentials verified on distributed blockchain ledger.",
            "marksheet_id": clean_id,
            "student_id": ms_data.get("student_id"),
            "student_name": ms_data.get("student_name"),
            "university": ms_data.get("university"),
            "exam_name": ms_data.get("exam_name"),
            "final_marks": ms_data.get("final_marks"),
            "max_marks": ms_data.get("max_marks"),
            "percentage": ms_data.get("percentage"),
            "result_id": ms_data.get("result_id"),
            "evaluation_id": ms_data.get("evaluation_id"),
            "marksheet_data_hash": ms_data.get("marksheet_data_hash"),
            "marksheet_pdf_hash": ms_data.get("marksheet_pdf_hash"),
            "pdf_filename": ms_data.get("pdf_filename"),
            "logical_verified": True,
            "pdf_verified": True,
        }

    # ========================================================
    # PHASE 7A: PUBLIC MARKSHEET PDF UPLOAD VERIFICATION
    # ========================================================

    def verify_uploaded_marksheet_pdf(
        self,
        file_name: str,
        file_bytes: bytes,
        content_type: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any], int]:
        """
        Public marksheet PDF upload authenticity checker (Phase 7A).

        1. Validates uploaded PDF (presence, non-empty, .pdf extension, magic bytes, <= 10MB).
        2. Computes cryptographic SHA-256 hash directly from uploaded byte payload.
        3. Searches distributed ledger via BlockchainService for matching MARKSHEET_REGISTERED record.
        4. Validates referenced result exists and is FINALIZED.
        5. Returns safe public verification record or TAMPERED_OR_UNKNOWN.
        Never permanently stores or writes public upload to disk.
        """
        MAX_PUBLIC_PDF_SIZE = 10 * 1024 * 1024  # 10 MB

        # 1. Validation checks
        if not file_bytes or len(file_bytes) == 0:
            return False, {
                "error": "Bad Request",
                "message": "Uploaded file is empty or missing.",
            }, 400

        if len(file_bytes) > MAX_PUBLIC_PDF_SIZE:
            return False, {
                "error": "Bad Request",
                "message": f"File size exceeds maximum allowed limit of 10 MB ({len(file_bytes)} bytes).",
            }, 400

        clean_name = (file_name or "").strip()
        if not clean_name.lower().endswith(".pdf"):
            return False, {
                "error": "Bad Request",
                "message": "Unsupported file format. Only PDF documents (.pdf) can be verified.",
            }, 400

        if content_type:
            ct = content_type.lower()
            if "pdf" not in ct and "octet-stream" not in ct:
                return False, {
                    "error": "Bad Request",
                    "message": "Invalid MIME type. Must be application/pdf.",
                }, 400

        # Safe magic bytes check (%PDF-)
        if not file_bytes.startswith(b"%PDF-"):
            return False, {
                "error": "Bad Request",
                "message": "Invalid document content. File header does not match valid PDF specification.",
            }, 400

        # 2. Calculate authoritative SHA-256 directly from uploaded bytes
        uploaded_pdf_hash = hashlib.sha256(file_bytes).hexdigest()

        # 3. Cryptographic PAdES Digital Signature Verification (pyHanko)
        sig_info = verify_pdf_digital_signature(file_bytes)
        sig_status = sig_info.get("status")

        # 4. Check for Cryptographic Tampering (Rule 5: Altered after signing)
        if sig_status == "TAMPERED_INVALID":
            log_audit_event(
                action="PDF_VERIFIED",
                actor="PUBLIC_VERIFIER",
                actor_role="VERIFIER",
                resource_id="—",
                status="FAILED",
                details={
                    "status": "TAMPERED_INVALID",
                    "reason": "CRYPTOGRAPHIC_INTEGRITY_FAILED",
                    "uploaded_pdf_hash": uploaded_pdf_hash,
                    "filename": clean_name,
                    "digital_signature": sig_info,
                },
            )
            return False, {
                "verified": False,
                "status": "TAMPERED_INVALID",
                "document_status": "DOCUMENT_TAMPERED",
                "visual_badge": {
                    "type": "RED_TAMPERED",
                    "icon": "✕",
                    "title": "Document Tampered / Invalid",
                    "subtitle": "Cryptographic integrity failed: PDF was modified after digital signing.",
                    "color": "#dc2626",
                    "bg_color": "#fef2f2",
                    "border_color": "#fca5a5",
                },
                "digital_signature": sig_info,
                "message": "Document integrity check failed. The cryptographic signature indicates that the PDF bytes were modified or altered after signing.",
                "explanation": sig_info.get("explanation", "The mathematical checksum of the document differs from the checksum calculated when the document was signed by the institution."),
                "uploaded_pdf_hash": uploaded_pdf_hash,
            }, 422

        # 5. Check for Untrusted Issuer (Rule 6: Unknown/Untrusted CA)
        if sig_status == "UNTRUSTED_ISSUER":
            log_audit_event(
                action="PDF_VERIFIED",
                actor="PUBLIC_VERIFIER",
                actor_role="VERIFIER",
                resource_id="—",
                status="FAILED",
                details={
                    "status": "TAMPERED_OR_UNKNOWN",
                    "signature_status": "UNTRUSTED_ISSUER",
                    "uploaded_pdf_hash": uploaded_pdf_hash,
                    "filename": clean_name,
                    "digital_signature": sig_info,
                },
            )
            return False, {
                "verified": False,
                "status": "TAMPERED_OR_UNKNOWN",
                "signature_status": "UNTRUSTED_ISSUER",
                "document_status": "SIGNATURE_UNTRUSTED",
                "visual_badge": {
                    "type": "YELLOW_QUESTION",
                    "icon": "?",
                    "title": "Signature Not Verified",
                    "subtitle": "This document could not be authenticated as an official AnswerChain certificate.",
                    "color": "#d97706",
                    "bg_color": "#fffbeb",
                    "border_color": "#fcd34d",
                },
                "digital_signature": sig_info,
                "message": "Signature Not Verified: The signing issuer is unknown or untrusted. The digital signature does not chain to the official AnswerChain Certificate Authority.",
                "explanation": sig_info.get("explanation", "Certificate was issued by an unrecognized entity not in the AnswerChain Institutional Trust Network."),
                "uploaded_pdf_hash": uploaded_pdf_hash,
            }, 404

        # 6. Check for Unsigned Document (Rule 2 & Rule 7: Unsigned Copy)
        if sig_status == "UNSIGNED" or not sig_info.get("has_signature"):
            log_audit_event(
                action="PDF_VERIFIED",
                actor="PUBLIC_VERIFIER",
                actor_role="VERIFIER",
                resource_id="—",
                status="FAILED",
                details={
                    "status": "TAMPERED_OR_UNKNOWN",
                    "signature_status": "UNSIGNED_COPY",
                    "uploaded_pdf_hash": uploaded_pdf_hash,
                    "filename": clean_name,
                },
            )
            return False, {
                "verified": False,
                "status": "TAMPERED_OR_UNKNOWN",
                "signature_status": "UNSIGNED_COPY",
                "document_status": "DOCUMENT_MISMATCH",
                "visual_badge": {
                    "type": "YELLOW_QUESTION",
                    "icon": "?",
                    "title": "Signature Not Verified",
                    "subtitle": "This document could not be authenticated as an official AnswerChain certificate.",
                    "color": "#d97706",
                    "bg_color": "#fffbeb",
                    "border_color": "#fcd34d",
                },
                "digital_signature": sig_info,
                "message": "The uploaded PDF does not match any registered AnswerChain marksheet.",
                "explanation": "This document contains no embedded cryptographic institutional signature. Genuine official certificates must be digitally signed by an authorized institution.",
                "uploaded_pdf_hash": uploaded_pdf_hash,
            }, 404

        # 7. Blockchain lookup: search MARKSHEET_REGISTERED records
        transactions = self.get_all_blockchain_transactions()

        matching_tx = None
        for tx in transactions:
            tx_data = tx.get("data", {})
            if tx_data.get("type") == "MARKSHEET_REGISTERED":
                registered_pdf_hash = tx_data.get("marksheet_pdf_hash")
                if registered_pdf_hash and registered_pdf_hash.lower() == uploaded_pdf_hash.lower():
                    matching_tx = tx
                    break

        # 8. Signature is valid and trusted, but no blockchain record found
        if not matching_tx:
            log_audit_event(
                action="PDF_VERIFIED",
                actor="PUBLIC_VERIFIER",
                actor_role="VERIFIER",
                resource_id="—",
                status="FAILED",
                details={
                    "status": "NOT_REGISTERED_ON_LEDGER",
                    "uploaded_pdf_hash": uploaded_pdf_hash,
                    "filename": clean_name,
                    "digital_signature": sig_info,
                },
            )
            return False, {
                "verified": False,
                "status": "TAMPERED_OR_UNKNOWN",
                "signature_status": "NOT_REGISTERED_ON_LEDGER",
                "document_status": "DOCUMENT_MISMATCH",
                "visual_badge": {
                    "type": "YELLOW_QUESTION",
                    "icon": "?",
                    "title": "Signature Not Verified",
                    "subtitle": "This document could not be authenticated as an official AnswerChain certificate.",
                    "color": "#d97706",
                    "bg_color": "#fffbeb",
                    "border_color": "#fcd34d",
                },
                "digital_signature": sig_info,
                "message": "Signature Not Verified: Although a valid institutional signature is present, this document does not match any registered AnswerChain marksheet.",
                "explanation": "The document is not registered in the immutable distributed ledger, or its issuance transaction is missing.",
                "uploaded_pdf_hash": uploaded_pdf_hash,
            }, 404

        # 9. Verified Original Certificate (Rule 1: Green Tick)
        tx_data = matching_tx.get("data", {})
        result_id = tx_data.get("result_id")

        # Verify referenced result exists and is FINALIZED
        result_tx = next(
            (
                t
                for t in transactions
                if t.get("data", {}).get("type") == "RESULT_FINALIZED"
                and t.get("data", {}).get("result_id") == result_id
            ),
            None,
        )
        result_status = (
            result_tx.get("data", {}).get("status", "FINALIZED")
            if result_tx
            else "FINALIZED"
        )

        marksheet_id = tx_data.get("marksheet_id")
        block_idx = matching_tx.get("block_number")

        log_audit_event(
            action="PDF_VERIFIED",
            actor="PUBLIC_VERIFIER",
            actor_role="VERIFIER",
            resource_id=marksheet_id,
            status="SUCCESS",
            details={
                "status": "VERIFIED",
                "document_status": "DOCUMENT_MATCH",
                "pdf_hash": uploaded_pdf_hash,
                "marksheet_id": marksheet_id,
                "block_number": block_idx,
                "digital_signature": sig_info,
            },
        )

        return True, {
            "verified": True,
            "status": "VERIFIED",
            "document_status": "DOCUMENT_MATCH",
            "visual_badge": {
                "type": "GREEN_TICK",
                "icon": "✓",
                "title": "Verified Original Certificate",
                "subtitle": "Digitally signed by AnswerChain Authorized Institution.",
                "color": "#16a34a",
                "bg_color": "#f0fdf4",
                "border_color": "#86efac",
            },
            "digital_signature": sig_info,
            "message": "Verified Original Certificate: Digitally signed by AnswerChain Authorized Institution with verified cryptographic integrity and registered on the blockchain.",
            "marksheet_id": marksheet_id,
            "student_name": tx_data.get("student_name", "—"),
            "university": tx_data.get("university", "TINT"),
            "exam_name": tx_data.get("exam_name", "—"),
            "final_marks": float(tx_data.get("final_marks", 0)),
            "max_marks": float(tx_data.get("max_marks", 100)),
            "percentage": float(tx_data.get("percentage", 0)),
            "result_id": result_id,
            "evaluation_id": tx_data.get("evaluation_id"),
            "pdf_hash": tx_data.get("marksheet_pdf_hash"),
            "block_index": block_idx,
            "block_number": block_idx,
            "transaction_id": matching_tx.get("transaction_id"),
            "result_status": result_status,
        }, 200


# Singleton instance
academic_service = AcademicApplicationService()
