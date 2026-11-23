"""
AnswerChain Relational Database Layer.

Provides SQLite persistence for Users, Subjects, Teacher-Subject Assignments,
Answer Scripts, and Operational Audit Logs. Automatically seeds initial schema
and administrative credentials on first run.
"""

import hashlib
import json
import logging
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("database")

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DEFAULT_DB_PATH = os.path.join(DATA_DIR, "answerchain.db")
DB_PATH = os.environ.get("ANSWERCHAIN_DB_PATH", DEFAULT_DB_PATH)

PASSWORD_SALT = os.environ.get("AUTH_PASSWORD_SALT", "answerchain_salt_2026")


def hash_password(password: str, salt: str = PASSWORD_SALT) -> str:
    """Hash a plain text password with SHA-256 and cryptographic salt."""
    return hashlib.sha256(f"{salt}:{password}".encode("utf-8")).hexdigest()


def get_db_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Return an active connection to the SQLite database with row factory enabled."""
    target_path = db_path or DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    conn = sqlite3.connect(target_path, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    """
    Initialize SQLite database schema and seed default subjects and users.
    Idempotent: safe to run multiple times.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            # 1. Subjects Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subjects (
                    subject_code TEXT PRIMARY KEY,
                    subject_name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)

            # 2. Users Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    department TEXT DEFAULT '',
                    email TEXT DEFAULT '',
                    assigned_subject TEXT,
                    password_hash TEXT NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (assigned_subject) REFERENCES subjects(subject_code)
                        ON UPDATE CASCADE ON DELETE SET NULL
                );
            """)

            # 3. Teacher-Subject Mapping Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS teacher_subjects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    teacher_id TEXT NOT NULL,
                    subject_code TEXT NOT NULL,
                    assigned_at REAL NOT NULL,
                    active INTEGER NOT NULL DEFAULT 1,
                    FOREIGN KEY (teacher_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (subject_code) REFERENCES subjects(subject_code)
                        ON UPDATE CASCADE ON DELETE CASCADE,
                    UNIQUE (teacher_id, subject_code)
                );
            """)

            # 4. Answer Scripts Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS answer_scripts (
                    answer_script_id TEXT PRIMARY KEY,
                    student_id TEXT NOT NULL,
                    student_name TEXT NOT NULL,
                    exam_id TEXT NOT NULL,
                    exam_name TEXT NOT NULL,
                    subject_code TEXT,
                    subject_name TEXT,
                    file_name TEXT,
                    file_hash TEXT NOT NULL,
                    assigned_teacher_id TEXT,
                    status TEXT DEFAULT 'REGISTERED',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (subject_code) REFERENCES subjects(subject_code)
                        ON UPDATE CASCADE ON DELETE SET NULL,
                    FOREIGN KEY (assigned_teacher_id) REFERENCES users(user_id)
                        ON DELETE SET NULL
                );
            """)

            # 5. Operational Audit Logs Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    action TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    actor_role TEXT,
                    resource_id TEXT,
                    transaction_id TEXT,
                    status TEXT NOT NULL,
                    reason TEXT,
                    details_json TEXT
                );
            """)

            # Indexes for high performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_assigned_subject ON users(assigned_subject);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subjects_active ON subjects(active);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scripts_teacher ON answer_scripts(assigned_teacher_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scripts_subject ON answer_scripts(subject_code);")

            # Seed default data if empty
            _seed_default_data(conn)
    finally:
        conn.close()


def _seed_default_data(conn: sqlite3.Connection) -> None:
    """Seed default subjects and core users if not already present."""
    now = time.time()

    # Seed Default Subjects
    cursor = conn.execute("SELECT COUNT(*) as count FROM subjects")
    subject_count = cursor.fetchone()["count"]
    if subject_count == 0:
        default_subjects = [
            ("DBMS", "Database Management Systems", "Relational database modeling, SQL, ACID transactions, and indexing."),
            ("OS", "Operating Systems", "Process scheduling, memory virtualization, concurrency, and file systems."),
            ("AIML", "Artificial Intelligence & Machine Learning", "Neural networks, supervised learning, and algorithmic intelligence."),
            ("PM", "Project Management", "Agile methodologies, software engineering lifecycle, and project governance."),
            ("CYS", "Cyber Security", "Applied cryptography, network defense, penetration testing, and access controls."),
            ("CLOUD", "Cloud Computing & Distributed Networks", "Virtualization, distributed cloud architectures, and container orchestration."),
            ("ENGLISH", "English Communication", "Professional communication, technical documentation, and verbal skills."),
            ("DISTRIB", "Distributed Systems & Advanced Consensus", "BFT consensus, Byzantine fault tolerance, and blockchain architectures."),
        ]
        conn.executemany("""
            INSERT INTO subjects (subject_code, subject_name, description, active, created_at, updated_at)
            VALUES (?, ?, ?, 1, ?, ?)
        """, [(s[0], s[1], s[2], now, now) for s in default_subjects])
        logger.info("Seeded %d default subjects into database", len(default_subjects))

    # Seed Default Users
    cursor = conn.execute("SELECT COUNT(*) as count FROM users")
    user_count = cursor.fetchone()["count"]
    if user_count == 0:
        # Default Admin password from environment variable if provided
        admin_pass = os.environ.get("ANSWERCHAIN_ADMIN_PASSWORD", "admin123")
        default_users = [
            (
                "ADMIN-001",
                "AnswerChain System Admin",
                "ADMIN",
                "Network & Security Operations",
                "admin@answerchain.internal",
                None,
                hash_password(admin_pass),
                1,
                now,
                now,
            ),
            (
                "UNIV-001",
                "Techno International New Town (TINT) University",
                "UNIVERSITY",
                "Registrar & Exam Branch",
                "registrar@tint.edu.in",
                None,
                hash_password("university123"),
                1,
                now,
                now,
            ),
            (
                "TCH-001",
                "Prof. Alex Mercer",
                "TEACHER",
                "Computer Science & Engineering",
                "a.mercer@tint.edu.in",
                "DBMS",
                hash_password("teacher123"),
                1,
                now,
                now,
            ),
            (
                "TCH-002",
                "Prof. Sarah Jenkins",
                "TEACHER",
                "Information Technology",
                "s.jenkins@tint.edu.in",
                "OS",
                hash_password("teacher123"),
                1,
                now,
                now,
            ),
            (
                "TCH-003",
                "Prof. Ramesh Guha",
                "TEACHER",
                "Electronics & Comm. Engg",
                "r.guha@tint.edu.in",
                "AIML",
                hash_password("teacher123"),
                1,
                now,
                now,
            ),
            (
                "TCH-004",
                "Prof. David K.",
                "TEACHER",
                "Computer Science & Engineering",
                "d.k@tint.edu.in",
                "DISTRIB",
                hash_password("teacher123"),
                1,
                now,
                now,
            ),
            (
                "TCH-005",
                "Prof. Elena Rostova",
                "TEACHER",
                "Computer Science & Engineering",
                "e.rostova@tint.edu.in",
                "CLOUD",
                hash_password("teacher123"),
                1,
                now,
                now,
            ),
            (
                "NODE-001",
                "Examiner Node 1",
                "NODE",
                "Examiner Cluster",
                "node1@answerchain.internal",
                "DBMS",
                hash_password("node123"),
                1,
                now,
                now,
            ),
            (
                "NODE-002",
                "Examiner Node 2",
                "NODE",
                "Examiner Cluster",
                "node2@answerchain.internal",
                "OS",
                hash_password("node123"),
                1,
                now,
                now,
            ),
            (
                "NODE-003",
                "Examiner Node 3",
                "NODE",
                "Examiner Cluster",
                "node3@answerchain.internal",
                "AIML",
                hash_password("node123"),
                1,
                now,
                now,
            ),
            (
                "NODE-004",
                "Examiner Node 4",
                "NODE",
                "Examiner Cluster",
                "node4@answerchain.internal",
                "DISTRIB",
                hash_password("node123"),
                1,
                now,
                now,
            ),
            (
                "NODE-005",
                "Examiner Node 5",
                "NODE",
                "Examiner Cluster",
                "node5@answerchain.internal",
                "CLOUD",
                hash_password("node123"),
                1,
                now,
                now,
            ),
            (
                "AUTH-001",
                "Dr. S. K. Mukherjee",
                "AUTHORITY",
                "Office of Controller of Examinations",
                "coe@tint.edu.in",
                None,
                hash_password("authority123"),
                1,
                now,
                now,
            ),
            (
                "VERIFY-001",
                "Public Credential Verifier",
                "VERIFIER",
                "Academic Verification Agency",
                "verify@credential-check.org",
                None,
                hash_password("verify123"),
                1,
                now,
                now,
            ),
        ]
        conn.executemany("""
            INSERT INTO users (
                user_id, name, role, department, email, assigned_subject, password_hash, active, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_users)

        # Seed initial teacher-subject assignments
        teacher_subject_pairs = [
            ("TCH-001", "DBMS"),
            ("TCH-002", "OS"),
            ("TCH-003", "AIML"),
            ("TCH-004", "DISTRIB"),
            ("TCH-005", "CLOUD"),
        ]
        conn.executemany("""
            INSERT OR IGNORE INTO teacher_subjects (teacher_id, subject_code, assigned_at, active)
            VALUES (?, ?, ?, 1)
        """, [(t[0], t[1], now) for t in teacher_subject_pairs])
        logger.info("Seeded %d default users and teacher mappings into database", len(default_users))


# ============================================================
# SUBJECT OPERATIONS
# ============================================================

def list_subjects(active_only: bool = False) -> List[Dict[str, Any]]:
    """Return all subjects, optionally filtered by active status."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT s.subject_code, s.subject_name, s.description, s.active, s.created_at, s.updated_at,
                   COUNT(DISTINCT u.user_id) AS teacher_count
            FROM subjects s
            LEFT JOIN users u ON u.assigned_subject = s.subject_code AND u.role = 'TEACHER' AND u.active = 1
        """
        if active_only:
            sql += " WHERE s.active = 1"
        sql += " GROUP BY s.subject_code ORDER BY s.subject_name ASC"
        cursor = conn.execute(sql)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def get_subject(subject_code: str) -> Optional[Dict[str, Any]]:
    """Retrieve a single subject by its code."""
    if not subject_code:
        return None
    clean_code = subject_code.strip().upper()
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "SELECT * FROM subjects WHERE subject_code = ?",
            (clean_code,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_subject(
    subject_code: str,
    subject_name: str,
    description: str = "",
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Create a new subject in the database.
    Returns (success, subject_dict, error_message).
    """
    clean_code = (subject_code or "").strip().upper()
    clean_name = (subject_name or "").strip()
    clean_desc = (description or "").strip()

    if not clean_code:
        return False, None, "Subject code is required."
    if not clean_name:
        return False, None, "Subject name is required."

    conn = get_db_connection()
    try:
        now = time.time()
        with conn:
            # Check unique
            cursor = conn.execute("SELECT subject_code FROM subjects WHERE subject_code = ?", (clean_code,))
            if cursor.fetchone():
                return False, None, f"Subject with code '{clean_code}' already exists."

            conn.execute("""
                INSERT INTO subjects (subject_code, subject_name, description, active, created_at, updated_at)
                VALUES (?, ?, ?, 1, ?, ?)
            """, (clean_code, clean_name, clean_desc, now, now))

        created = get_subject(clean_code)
        return True, created, None
    except sqlite3.IntegrityError:
        return False, None, f"Subject with code '{clean_code}' already exists."
    except Exception as e:
        logger.error("Error creating subject: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def update_subject(
    subject_code: str,
    subject_name: Optional[str] = None,
    description: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Update details of an existing subject."""
    clean_code = (subject_code or "").strip().upper()
    sub = get_subject(clean_code)
    if not sub:
        return False, None, f"Subject '{clean_code}' not found."

    new_name = subject_name.strip() if subject_name is not None else sub["subject_name"]
    new_desc = description.strip() if description is not None else sub["description"]
    now = time.time()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE subjects
                SET subject_name = ?, description = ?, updated_at = ?
                WHERE subject_code = ?
            """, (new_name, new_desc, now, clean_code))
        updated = get_subject(clean_code)
        return True, updated, None
    except Exception as e:
        logger.error("Error updating subject: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def toggle_subject_status(subject_code: str, active: bool) -> Tuple[bool, Optional[str]]:
    """Activate or deactivate a subject."""
    clean_code = (subject_code or "").strip().upper()
    sub = get_subject(clean_code)
    if not sub:
        return False, f"Subject '{clean_code}' not found."

    conn = get_db_connection()
    try:
        now = time.time()
        with conn:
            conn.execute("""
                UPDATE subjects
                SET active = ?, updated_at = ?
                WHERE subject_code = ?
            """, (1 if active else 0, now, clean_code))
        return True, None
    except Exception as e:
        logger.error("Error toggling subject status: %s", e)
        return False, str(e)
    finally:
        conn.close()


# ============================================================
# USER & TEACHER OPERATIONS
# ============================================================

def get_user(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve public profile of a user by user_id or institutional email."""
    if not identifier:
        return None
    clean_id = identifier.strip()
    conn = get_db_connection()
    try:
        cursor = conn.execute("""
            SELECT u.user_id, u.name, u.role, u.department, u.email,
                   u.assigned_subject, u.active, u.created_at, u.updated_at,
                   s.subject_name AS assigned_subject_name
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            WHERE UPPER(u.user_id) = UPPER(?) OR (u.email != '' AND LOWER(u.email) = LOWER(?))
        """, (clean_id, clean_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_auth(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve user credentials and auth payload by user_id or institutional email."""
    if not identifier:
        return None
    clean_id = identifier.strip()
    conn = get_db_connection()
    try:
        cursor = conn.execute("""
            SELECT u.user_id, u.name, u.role, u.department, u.email,
                   u.assigned_subject, u.password_hash, u.active,
                   s.subject_name AS assigned_subject_name
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            WHERE UPPER(u.user_id) = UPPER(?) OR (u.email != '' AND LOWER(u.email) = LOWER(?))
        """, (clean_id, clean_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_users(role: Optional[str] = None, active_only: bool = False) -> List[Dict[str, Any]]:
    """List users filtered by role or active status."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT u.user_id, u.name, u.role, u.department, u.email,
                   u.assigned_subject, u.active, u.created_at, u.updated_at,
                   s.subject_name AS assigned_subject_name
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            WHERE 1=1
        """
        params = []
        if role:
            sql += " AND u.role = ?"
            params.append(role.strip().upper())
        if active_only:
            sql += " AND u.active = 1"
        sql += " ORDER BY u.user_id ASC"
        cursor = conn.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def list_teachers(subject_code: Optional[str] = None, active_only: bool = False) -> List[Dict[str, Any]]:
    """List teachers, optionally filtered by assigned subject or active status."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT u.user_id, u.name, u.role, u.department, u.email,
                   u.assigned_subject, u.active, u.created_at, u.updated_at,
                   s.subject_name AS assigned_subject_name
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            WHERE u.role = 'TEACHER'
        """
        params = []
        if active_only:
            sql += " AND u.active = 1"
        if subject_code:
            clean_sub = subject_code.strip().upper()
            sql += " AND (u.assigned_subject = ? OR s.subject_name LIKE ?)"
            params.extend([clean_sub, f"%{clean_sub}%"])
        sql += " ORDER BY u.name ASC"
        cursor = conn.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def create_teacher(
    user_id: str,
    name: str,
    assigned_subject: str,
    password: str,
    department: str = "Academic Faculty",
    email: str = "",
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Create a new teacher account with securely hashed credentials.
    Returns (success, teacher_dict, error_message).
    """
    clean_id = (user_id or "").strip().upper()
    clean_name = (name or "").strip()
    clean_sub = (assigned_subject or "").strip().upper()
    clean_dept = (department or "Academic Faculty").strip()
    clean_email = (email or f"{clean_id.lower()}@tint.edu.in").strip()

    if not clean_id:
        return False, None, "User ID is required."
    if not clean_name:
        return False, None, "Teacher name is required."
    if not clean_sub:
        return False, None, "Assigned subject is required."
    if not password or len(password) < 6:
        return False, None, "Password must be at least 6 characters long."

    # Verify that the subject exists
    sub = get_subject(clean_sub)
    if not sub:
        return False, None, f"Subject '{clean_sub}' does not exist. Please create the subject first."

    # Check unique user_id
    if get_user(clean_id):
        return False, None, f"User ID '{clean_id}' already exists."

    pwd_hash = hash_password(password)
    now = time.time()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO users (
                    user_id, name, role, department, email, assigned_subject,
                    password_hash, active, created_at, updated_at
                ) VALUES (?, ?, 'TEACHER', ?, ?, ?, ?, 1, ?, ?)
            """, (clean_id, clean_name, clean_dept, clean_email, clean_sub, pwd_hash, now, now))

            conn.execute("""
                INSERT OR REPLACE INTO teacher_subjects (teacher_id, subject_code, assigned_at, active)
                VALUES (?, ?, ?, 1)
            """, (clean_id, clean_sub, now))

        created = get_user(clean_id)
        return True, created, None
    except Exception as e:
        logger.error("Error creating teacher: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def update_teacher(
    user_id: str,
    name: Optional[str] = None,
    assigned_subject: Optional[str] = None,
    department: Optional[str] = None,
    email: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Update details of an existing teacher."""
    clean_id = (user_id or "").strip().upper()
    user = get_user(clean_id)
    if not user or user["role"] != "TEACHER":
        return False, None, f"Teacher with ID '{clean_id}' not found."

    new_name = name.strip() if name is not None else user["name"]
    new_dept = department.strip() if department is not None else user["department"]
    new_email = email.strip() if email is not None else user["email"]
    new_sub = assigned_subject.strip().upper() if assigned_subject is not None else user["assigned_subject"]

    if new_sub:
        sub = get_subject(new_sub)
        if not sub:
            return False, None, f"Subject '{new_sub}' does not exist."

    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET name = ?, department = ?, email = ?, assigned_subject = ?, updated_at = ?
                WHERE user_id = ?
            """, (new_name, new_dept, new_email, new_sub, now, clean_id))

            if new_sub:
                conn.execute("""
                    INSERT OR REPLACE INTO teacher_subjects (teacher_id, subject_code, assigned_at, active)
                    VALUES (?, ?, ?, 1)
                """, (clean_id, new_sub, now))

        updated = get_user(clean_id)
        return True, updated, None
    except Exception as e:
        logger.error("Error updating teacher: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def reset_teacher_password(user_id: str, new_password: str) -> Tuple[bool, Optional[str]]:
    """Reset a teacher's password."""
    clean_id = (user_id or "").strip().upper()
    user = get_user(clean_id)
    if not user or user["role"] != "TEACHER":
        return False, f"Teacher with ID '{clean_id}' not found."

    if not new_password or len(new_password) < 6:
        return False, "Password must be at least 6 characters long."

    pwd_hash = hash_password(new_password)
    now = time.time()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET password_hash = ?, updated_at = ?
                WHERE user_id = ?
            """, (pwd_hash, now, clean_id))
        return True, None
    except Exception as e:
        logger.error("Error resetting teacher password: %s", e)
        return False, str(e)
    finally:
        conn.close()


def toggle_teacher_status(user_id: str, active: bool) -> Tuple[bool, Optional[str]]:
    """Activate or deactivate a teacher's account."""
    clean_id = (user_id or "").strip().upper()
    user = get_user(clean_id)
    if not user or user["role"] != "TEACHER":
        return False, f"Teacher with ID '{clean_id}' not found."

    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET active = ?, updated_at = ?
                WHERE user_id = ?
            """, (1 if active else 0, now, clean_id))
        return True, None
    except Exception as e:
        logger.error("Error toggling teacher status: %s", e)
        return False, str(e)
    finally:
        conn.close()


# ============================================================
# ANSWER SCRIPT DATABASE SYNC
# ============================================================

def sync_answer_script_to_db(
    answer_script_id: str,
    student_id: str,
    student_name: str,
    exam_id: str,
    exam_name: str,
    file_name: str,
    file_hash: str,
    subject_code: Optional[str] = None,
    subject_name: Optional[str] = None,
    assigned_teacher_id: Optional[str] = None,
    status: str = "REGISTERED",
) -> None:
    """Insert or update answer script metadata in SQLite database."""
    conn = get_db_connection()
    try:
        now = time.time()
        with conn:
            conn.execute("""
                INSERT INTO answer_scripts (
                    answer_script_id, student_id, student_name, exam_id, exam_name,
                    subject_code, subject_name, file_name, file_hash,
                    assigned_teacher_id, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(answer_script_id) DO UPDATE SET
                    assigned_teacher_id = COALESCE(excluded.assigned_teacher_id, answer_scripts.assigned_teacher_id),
                    status = COALESCE(excluded.status, answer_scripts.status),
                    subject_code = COALESCE(excluded.subject_code, answer_scripts.subject_code),
                    subject_name = COALESCE(excluded.subject_name, answer_scripts.subject_name)
            """, (
                answer_script_id, student_id, student_name, exam_id, exam_name,
                subject_code, subject_name, file_name, file_hash,
                assigned_teacher_id, status, now
            ))
    except Exception as e:
        logger.error("Failed to sync answer script %s to DB: %s", answer_script_id, e)
    finally:
        conn.close()


# ============================================================
# AUDIT LOG DATABASE SYNC
# ============================================================

def insert_audit_log_to_db(
    action: str,
    actor: str,
    actor_role: str,
    status: str,
    resource_id: Optional[str] = None,
    transaction_id: Optional[str] = None,
    reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist an operational audit record into SQLite database."""
    conn = get_db_connection()
    try:
        now = time.time()
        details_str = json.dumps(details) if details else None
        with conn:
            conn.execute("""
                INSERT INTO audit_logs (
                    timestamp, action, actor, actor_role, resource_id,
                    transaction_id, status, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now, action, actor, actor_role, resource_id, transaction_id, status, reason, details_str))
    except Exception as e:
        logger.error("Failed to insert audit log to DB: %s", e)
    finally:
        conn.close()


# Auto-initialize database on module import
init_db()
