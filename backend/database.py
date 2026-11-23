"""
AnswerChain Relational Database Layer.

Provides SQLite persistence for Users, Subjects, Teacher-Subject Assignments,
Answer Scripts, and Operational Audit Logs. Automatically seeds initial schema
and administrative credentials on first run.
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
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
                    college_id TEXT,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (assigned_subject) REFERENCES subjects(subject_code)
                        ON UPDATE CASCADE ON DELETE SET NULL
                );
            """)

            # Schema migration for existing users table
            user_cols = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "college_id" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN college_id TEXT;")
            if "must_change_password" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;")

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

            # 6. Colleges Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS colleges (
                    id TEXT PRIMARY KEY,
                    college_code TEXT UNIQUE NOT NULL,
                    college_name TEXT NOT NULL,
                    affiliated_university TEXT NOT NULL,
                    address TEXT NOT NULL,
                    state TEXT NOT NULL,
                    district TEXT NOT NULL,
                    official_email TEXT NOT NULL,
                    contact_number TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)

            # 7. Departments Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS departments (
                    id TEXT PRIMARY KEY,
                    college_id TEXT NOT NULL,
                    dept_code TEXT NOT NULL,
                    dept_name TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE CASCADE,
                    UNIQUE(college_id, dept_code)
                );
            """)

            # 8. Courses Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS courses (
                    id TEXT PRIMARY KEY,
                    college_id TEXT NOT NULL,
                    course_code TEXT NOT NULL,
                    course_name TEXT NOT NULL,
                    duration_years INTEGER NOT NULL DEFAULT 4,
                    total_semesters INTEGER NOT NULL DEFAULT 8,
                    created_at REAL NOT NULL,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE CASCADE,
                    UNIQUE(college_id, course_code)
                );
            """)

            # 9. Students Table (No public registration; created exclusively by College Admin)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS students (
                    student_id TEXT PRIMARY KEY,
                    user_id TEXT UNIQUE NOT NULL,
                    college_id TEXT NOT NULL,
                    roll_number TEXT NOT NULL,
                    registration_number TEXT NOT NULL,
                    college_roll TEXT DEFAULT '',
                    full_name TEXT NOT NULL,
                    father_name TEXT DEFAULT '',
                    mother_name TEXT DEFAULT '',
                    dob TEXT DEFAULT '',
                    gender TEXT DEFAULT 'Male',
                    blood_group TEXT DEFAULT '',
                    category TEXT DEFAULT 'General',
                    email TEXT NOT NULL,
                    mobile TEXT DEFAULT '',
                    permanent_address TEXT DEFAULT '',
                    current_address TEXT DEFAULT '',
                    department TEXT NOT NULL,
                    course TEXT NOT NULL,
                    admission_year INTEGER NOT NULL,
                    current_semester INTEGER NOT NULL DEFAULT 1,
                    academic_session TEXT NOT NULL,
                    enrollment_date TEXT NOT NULL,
                    profile_photo_url TEXT DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE RESTRICT,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                );
            """)

            # 10. Academic Results (Semester-wise Results)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS academic_results (
                    id TEXT PRIMARY KEY,
                    student_id TEXT NOT NULL,
                    college_id TEXT NOT NULL,
                    semester INTEGER NOT NULL,
                    academic_session TEXT NOT NULL,
                    total_marks_obtained REAL NOT NULL DEFAULT 0.0,
                    total_max_marks REAL NOT NULL DEFAULT 0.0,
                    percentage REAL NOT NULL DEFAULT 0.0,
                    sgpa REAL NOT NULL DEFAULT 0.0,
                    cgpa REAL NOT NULL DEFAULT 0.0,
                    total_credits REAL NOT NULL DEFAULT 0.0,
                    credits_earned REAL NOT NULL DEFAULT 0.0,
                    result_status TEXT NOT NULL DEFAULT 'PASS',
                    is_published INTEGER NOT NULL DEFAULT 0,
                    published_at REAL,
                    published_by TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE CASCADE,
                    UNIQUE(student_id, semester)
                );
            """)

            # 11. Subject Marks Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS subject_marks (
                    id TEXT PRIMARY KEY,
                    result_id TEXT NOT NULL,
                    student_id TEXT NOT NULL,
                    subject_code TEXT NOT NULL,
                    subject_name TEXT NOT NULL,
                    internal_marks REAL NOT NULL DEFAULT 0.0,
                    external_marks REAL NOT NULL DEFAULT 0.0,
                    practical_marks REAL NOT NULL DEFAULT 0.0,
                    total_marks REAL NOT NULL DEFAULT 0.0,
                    max_marks REAL NOT NULL DEFAULT 100.0,
                    grade TEXT NOT NULL DEFAULT 'A',
                    grade_point REAL NOT NULL DEFAULT 8.0,
                    credits REAL NOT NULL DEFAULT 4.0,
                    result_status TEXT NOT NULL DEFAULT 'PASS',
                    created_at REAL NOT NULL,
                    FOREIGN KEY (result_id) REFERENCES academic_results(id) ON DELETE CASCADE,
                    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE
                );
            """)

            # 12. Marksheets Table (Official Downloadable Documents)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS marksheets (
                    id TEXT PRIMARY KEY,
                    student_id TEXT NOT NULL,
                    college_id TEXT NOT NULL,
                    semester INTEGER,
                    academic_session TEXT NOT NULL,
                    is_consolidated INTEGER NOT NULL DEFAULT 0,
                    file_path TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    qr_code_path TEXT NOT NULL,
                    verification_url TEXT NOT NULL,
                    is_revoked INTEGER NOT NULL DEFAULT 0,
                    digilocker_uri TEXT DEFAULT '',
                    digilocker_status TEXT DEFAULT 'ISSUED',
                    certificate_type TEXT DEFAULT 'MARKSHEET',
                    generated_at REAL NOT NULL,
                    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE CASCADE
                );
            """)

            # Ensure DigiLocker columns exist if table was already created
            try:
                col_names = [r["name"] for r in conn.execute("PRAGMA table_info(marksheets)").fetchall()]
                if "digilocker_uri" not in col_names:
                    conn.execute("ALTER TABLE marksheets ADD COLUMN digilocker_uri TEXT DEFAULT ''")
                if "digilocker_status" not in col_names:
                    conn.execute("ALTER TABLE marksheets ADD COLUMN digilocker_status TEXT DEFAULT 'ISSUED'")
                if "certificate_type" not in col_names:
                    conn.execute("ALTER TABLE marksheets ADD COLUMN certificate_type TEXT DEFAULT 'MARKSHEET'")
            except Exception as e:
                logger.debug("Table info check error: %s", e)

            # 13. Profile Correction Requests Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS profile_correction_requests (
                    id TEXT PRIMARY KEY,
                    student_id TEXT NOT NULL,
                    college_id TEXT NOT NULL,
                    field_name TEXT NOT NULL,
                    current_value TEXT NOT NULL,
                    requested_value TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    reviewed_by TEXT,
                    reviewed_at REAL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    FOREIGN KEY (student_id) REFERENCES students(student_id) ON DELETE CASCADE,
                    FOREIGN KEY (college_id) REFERENCES colleges(id) ON DELETE CASCADE
                );
            """)

            # Indexes for high performance
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_assigned_subject ON users(assigned_subject);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_college ON users(college_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subjects_active ON subjects(active);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scripts_teacher ON answer_scripts(assigned_teacher_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scripts_subject ON answer_scripts(subject_code);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_colleges_code ON colleges(college_code);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_colleges_status ON colleges(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_students_college ON students(college_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_students_roll ON students(roll_number);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_students_reg ON students(registration_number);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_student ON academic_results(student_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_college ON academic_results(college_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_published ON academic_results(is_published);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_subject_marks_result ON subject_marks(result_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_marksheets_student ON marksheets(student_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_marksheets_college ON marksheets(college_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_profile_corrections_college ON profile_correction_requests(college_id);")

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

    # Seed Default College and Student System
    cur = conn.execute("SELECT COUNT(*) as count FROM colleges")
    if cur.fetchone()["count"] == 0:
        conn.execute("""
            INSERT INTO colleges (
                id, college_code, college_name, affiliated_university, address,
                state, district, official_email, contact_number, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
        """, (
            "COL-TINT", "TINT", "Techno International New Town",
            "Maulana Abul Kalam Azad University of Technology (MAKAUT)",
            "Block - DG 1/1, Action Area 1, New Town, Rajarhat, Kolkata - 700156",
            "West Bengal", "North 24 Parganas", "principal@tint.edu.in", "+91-33-23242050",
            now, now
        ))

        # Seed College Admin User
        conn.execute("""
            INSERT OR IGNORE INTO users (
                user_id, name, role, department, email, assigned_subject,
                password_hash, active, college_id, must_change_password, created_at, updated_at
            ) VALUES (?, ?, 'COLLEGE_ADMIN', 'College Administration', ?, NULL, ?, 1, 'COL-TINT', 0, ?, ?)
        """, (
            "COL-TINT-ADMIN", "TINT College Administrator", "admin@tint.edu.in",
            hash_password("college123"), now, now
        ))

        # Seed Departments
        depts = [
            ("DEP-CSE", "COL-TINT", "CSE", "Computer Science & Engineering"),
            ("DEP-IT", "COL-TINT", "IT", "Information Technology"),
            ("DEP-ECE", "COL-TINT", "ECE", "Electronics & Communication Engineering"),
        ]
        conn.executemany("""
            INSERT OR IGNORE INTO departments (id, college_id, dept_code, dept_name, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, [(d[0], d[1], d[2], d[3], now) for d in depts])

        # Seed Courses
        courses = [
            ("CRS-BCSE", "COL-TINT", "BTECH-CSE", "Bachelor of Technology in Computer Science & Engineering", 4, 8),
            ("CRS-BIT", "COL-TINT", "BTECH-IT", "Bachelor of Technology in Information Technology", 4, 8),
        ]
        conn.executemany("""
            INSERT OR IGNORE INTO courses (id, college_id, course_code, course_name, duration_years, total_semesters, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, [(c[0], c[1], c[2], c[3], c[4], c[5], now) for c in courses])

        # Seed Sample Student: Asmit Mondal
        conn.execute("""
            INSERT OR IGNORE INTO users (
                user_id, name, role, department, email, assigned_subject,
                password_hash, active, college_id, must_change_password, created_at, updated_at
            ) VALUES (?, ?, 'STUDENT', 'Computer Science & Engineering', ?, NULL, ?, 1, 'COL-TINT', 0, ?, ?)
        """, (
            "111", "Asmit Mondal", "asmit.mondal@tint.edu.in",
            hash_password("student123"), now, now
        ))

        conn.execute("""
            INSERT OR IGNORE INTO students (
                student_id, user_id, college_id, roll_number, registration_number,
                college_roll, full_name, father_name, mother_name, dob, gender,
                blood_group, category, email, mobile, permanent_address, current_address,
                department, course, admission_year, current_semester, academic_session,
                enrollment_date, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
        """, (
            "STU-111", "111", "COL-TINT", "11100123001", "REG-2023-111001",
            "CSE-23-01", "Asmit Mondal", "Debabrata Mondal", "Mita Mondal", "2003-08-15", "Male",
            "B+", "General", "asmit.mondal@tint.edu.in", "+91-9876543210", "Kolkata, West Bengal", "New Town, Kolkata",
            "Computer Science & Engineering", "Bachelor of Technology in Computer Science & Engineering",
            2023, 3, "2023-24", "2023-08-01", now, now
        ))

        # Seed Semester 1 Academic Result
        conn.execute("""
            INSERT OR IGNORE INTO academic_results (
                id, student_id, college_id, semester, academic_session,
                total_marks_obtained, total_max_marks, percentage, sgpa, cgpa,
                total_credits, credits_earned, result_status, is_published, published_at, published_by,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PASS', 1, ?, 'COL-TINT-ADMIN', ?, ?)
        """, (
            "RES-STU111-SEM1", "STU-111", "COL-TINT", 1, "2023-24",
            255.0, 300.0, 85.0, 8.40, 8.40, 10.0, 10.0, now, now, now
        ))

        # Seed Semester 1 Subject Marks
        sem1_marks = [
            ("MRK-111-S1-1", "RES-STU111-SEM1", "STU-111", "DBMS", "Database Management Systems", 27.0, 62.0, 0.0, 89.0, 100.0, "A+", 9.0, 4.0, "PASS", now),
            ("MRK-111-S1-2", "RES-STU111-SEM1", "STU-111", "ENGLISH", "English Communication", 28.0, 58.0, 0.0, 86.0, 100.0, "A", 8.0, 3.0, "PASS", now),
            ("MRK-111-S1-3", "RES-STU111-SEM1", "STU-111", "PM", "Project Management", 25.0, 55.0, 0.0, 80.0, 100.0, "A", 8.0, 3.0, "PASS", now),
        ]
        conn.executemany("""
            INSERT OR IGNORE INTO subject_marks (
                id, result_id, student_id, subject_code, subject_name,
                internal_marks, external_marks, practical_marks, total_marks, max_marks,
                grade, grade_point, credits, result_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sem1_marks)

        # Seed Semester 2 Academic Result
        conn.execute("""
            INSERT OR IGNORE INTO academic_results (
                id, student_id, college_id, semester, academic_session,
                total_marks_obtained, total_max_marks, percentage, sgpa, cgpa,
                total_credits, credits_earned, result_status, is_published, published_at, published_by,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PASS', 1, ?, 'COL-TINT-ADMIN', ?, ?)
        """, (
            "RES-STU111-SEM2", "STU-111", "COL-TINT", 2, "2023-24",
            259.0, 300.0, 86.33, 8.73, 8.57, 11.0, 11.0, now, now, now
        ))

        # Seed Semester 2 Subject Marks
        sem2_marks = [
            ("MRK-111-S2-1", "RES-STU111-SEM2", "STU-111", "OS", "Operating Systems", 26.0, 60.0, 0.0, 86.0, 100.0, "A", 8.0, 4.0, "PASS", now),
            ("MRK-111-S2-2", "RES-STU111-SEM2", "STU-111", "AIML", "Artificial Intelligence & Machine Learning", 28.0, 64.0, 0.0, 92.0, 100.0, "O", 10.0, 4.0, "PASS", now),
            ("MRK-111-S2-3", "RES-STU111-SEM2", "STU-111", "CYS", "Cyber Security", 24.0, 57.0, 0.0, 81.0, 100.0, "A", 8.0, 3.0, "PASS", now),
        ]
        conn.executemany("""
            INSERT OR IGNORE INTO subject_marks (
                id, result_id, student_id, subject_code, subject_name,
                internal_marks, external_marks, practical_marks, total_marks, max_marks,
                grade, grade_point, credits, result_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, sem2_marks)
        logger.info("Seeded default college COL-TINT, college admin, departments, and sample student STU-111 with results")


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
                   u.assigned_subject, u.active, u.college_id, u.must_change_password,
                   u.created_at, u.updated_at,
                   s.subject_name AS assigned_subject_name,
                   c.college_name, c.college_code
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            LEFT JOIN colleges c ON c.id = u.college_id
            WHERE UPPER(u.user_id) = UPPER(?) OR (u.email != '' AND LOWER(u.email) = LOWER(?))
        """, (clean_id, clean_id))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_auth(identifier: str) -> Optional[Dict[str, Any]]:
    """Retrieve user credentials and auth payload by user_id, institutional email, student roll, or registration."""
    if not identifier:
        return None
    clean_id = identifier.strip()
    conn = get_db_connection()
    try:
        cursor = conn.execute("""
            SELECT u.user_id, u.name, u.role, u.department, u.email,
                   u.assigned_subject, u.password_hash, u.active,
                   u.college_id, u.must_change_password,
                   s.subject_name AS assigned_subject_name,
                   c.college_name, c.college_code,
                   st.student_id, st.roll_number, st.registration_number
            FROM users u
            LEFT JOIN subjects s ON s.subject_code = u.assigned_subject
            LEFT JOIN colleges c ON c.id = u.college_id
            LEFT JOIN students st ON st.user_id = u.user_id
            WHERE UPPER(u.user_id) = UPPER(?)
               OR (u.email != '' AND LOWER(u.email) = LOWER(?))
               OR (st.roll_number IS NOT NULL AND UPPER(st.roll_number) = UPPER(?))
               OR (st.registration_number IS NOT NULL AND UPPER(st.registration_number) = UPPER(?))
        """, (clean_id, clean_id, clean_id, clean_id))
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


# ============================================================
# MULTI-COLLEGE ACADEMIC MANAGEMENT OPERATIONS
# ============================================================

# --- College Management ---

def create_college(
    college_code: str,
    college_name: str,
    affiliated_university: str,
    address: str,
    state: str,
    district: str,
    official_email: str,
    contact_number: str,
    admin_name: str,
    admin_email: str,
    username: str,
    password: str,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Super Admin creates a new college and its primary administrator account.
    Returns (success, college_dict, error_message).
    """
    clean_code = (college_code or "").strip().upper()
    clean_name = (college_name or "").strip()
    clean_univ = (affiliated_university or "").strip()
    clean_addr = (address or "").strip()
    clean_state = (state or "").strip()
    clean_dist = (district or "").strip()
    clean_email = (official_email or "").strip().lower()
    clean_contact = (contact_number or "").strip()
    clean_admin_name = (admin_name or "").strip()
    clean_admin_email = (admin_email or "").strip().lower()
    clean_username = (username or f"{clean_code.lower()}_admin").strip().upper()

    if not clean_code or not clean_name:
        return False, None, "College Code and College Name are required."
    if not clean_univ:
        return False, None, "Affiliated University is required."
    if not clean_email or not clean_contact:
        return False, None, "Official Email and Contact Number are required."
    if not clean_admin_name or not clean_admin_email:
        return False, None, "Administrator Name and Administrator Email are required."
    if not password or len(password) < 6:
        return False, None, "Temporary password must be at least 6 characters long."

    college_id = f"COL-{clean_code}"
    conn = get_db_connection()
    try:
        # Check duplicate college code
        cur = conn.execute("SELECT id FROM colleges WHERE college_code = ? OR id = ?", (clean_code, college_id))
        if cur.fetchone():
            return False, None, f"College with code '{clean_code}' already exists."

        # Check duplicate username
        if get_user(clean_username):
            return False, None, f"Username '{clean_username}' already exists. Choose another."

        now = time.time()
        pwd_hash = hash_password(password)

        with conn:
            # 1. Insert College
            conn.execute("""
                INSERT INTO colleges (
                    id, college_code, college_name, affiliated_university, address,
                    state, district, official_email, contact_number, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """, (
                college_id, clean_code, clean_name, clean_univ, clean_addr,
                clean_state, clean_dist, clean_email, clean_contact, now, now
            ))

            # 2. Insert College Admin User (forced password change on first login)
            conn.execute("""
                INSERT INTO users (
                    user_id, name, role, department, email, assigned_subject,
                    password_hash, active, college_id, must_change_password, created_at, updated_at
                ) VALUES (?, ?, 'COLLEGE_ADMIN', 'College Administration', ?, NULL, ?, 1, ?, 1, ?, ?)
            """, (
                clean_username, clean_admin_name, clean_admin_email,
                pwd_hash, college_id, now, now
            ))

            # 3. Seed starter departments
            default_depts = [
                (f"DEP-{clean_code}-CSE", college_id, "CSE", "Computer Science & Engineering"),
                (f"DEP-{clean_code}-IT", college_id, "IT", "Information Technology"),
                (f"DEP-{clean_code}-ECE", college_id, "ECE", "Electronics & Communication Engineering"),
            ]
            conn.executemany("""
                INSERT OR IGNORE INTO departments (id, college_id, dept_code, dept_name, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, [(d[0], d[1], d[2], d[3], now) for d in default_depts])

            # 4. Seed starter course
            conn.execute("""
                INSERT OR IGNORE INTO courses (id, college_id, course_code, course_name, duration_years, total_semesters, created_at)
                VALUES (?, ?, 'BTECH', 'Bachelor of Technology', 4, 8, ?)
            """, (f"CRS-{clean_code}-BTECH", college_id, now))

        college = get_college(college_id)
        return True, college, None
    except Exception as e:
        logger.error("Error creating college: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def get_college(college_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a college by ID or Code."""
    if not college_id:
        return None
    clean_id = college_id.strip()
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            SELECT c.*,
                   COUNT(DISTINCT s.student_id) AS total_students,
                   SUM(CASE WHEN s.status = 'ACTIVE' THEN 1 ELSE 0 END) AS active_students,
                   COUNT(DISTINCT m.id) AS total_marksheets,
                   COUNT(DISTINCT d.id) AS total_departments
            FROM colleges c
            LEFT JOIN students s ON s.college_id = c.id
            LEFT JOIN marksheets m ON m.college_id = c.id
            LEFT JOIN departments d ON d.college_id = c.id
            WHERE c.id = ? OR UPPER(c.college_code) = UPPER(?)
            GROUP BY c.id
        """, (clean_id, clean_id))
        row = cur.fetchone()
        if not row:
            return None
        res = dict(row)

        # Get Admin User Details
        admin_cur = conn.execute("""
            SELECT user_id, name, email, must_change_password, active, updated_at
            FROM users
            WHERE college_id = ? AND role = 'COLLEGE_ADMIN'
            LIMIT 1
        """, (res["id"],))
        admin_row = admin_cur.fetchone()
        res["admin"] = dict(admin_row) if admin_row else None
        res["code"] = res.get("college_code")
        res["name"] = res.get("college_name")
        res["college_id"] = res.get("id")
        res["university"] = res.get("affiliated_university")
        return res
    finally:
        conn.close()


def list_colleges(search_query: Optional[str] = None, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all registered colleges with student counts and administrative status."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT c.*,
                   COUNT(DISTINCT s.student_id) AS total_students,
                   SUM(CASE WHEN s.status = 'ACTIVE' THEN 1 ELSE 0 END) AS active_students,
                   COUNT(DISTINCT m.id) AS total_marksheets,
                   u.name AS admin_name,
                   u.email AS admin_email,
                   u.user_id AS admin_username
            FROM colleges c
            LEFT JOIN students s ON s.college_id = c.id
            LEFT JOIN marksheets m ON m.college_id = c.id
            LEFT JOIN users u ON u.college_id = c.id AND u.role = 'COLLEGE_ADMIN'
            WHERE 1=1
        """
        params = []
        if status and status.upper() != "ALL":
            sql += " AND UPPER(c.status) = ?"
            params.append(status.strip().upper())
        if search_query:
            term = f"%{search_query.strip().lower()}%"
            sql += " AND (LOWER(c.college_name) LIKE ? OR LOWER(c.college_code) LIKE ? OR LOWER(c.affiliated_university) LIKE ? OR LOWER(c.district) LIKE ?)"
            params.extend([term, term, term, term])

        sql += " GROUP BY c.id ORDER BY c.created_at DESC"
        cursor = conn.execute(sql, params)
        rows = cursor.fetchall()
        colleges = []
        for r in rows:
            cd = dict(r)
            cd["code"] = cd.get("college_code")
            cd["name"] = cd.get("college_name")
            cd["college_id"] = cd.get("id")
            cd["university"] = cd.get("affiliated_university")
            colleges.append(cd)
        return colleges
    finally:
        conn.close()


def update_college(
    college_id: str,
    college_name: Optional[str] = None,
    affiliated_university: Optional[str] = None,
    address: Optional[str] = None,
    state: Optional[str] = None,
    district: Optional[str] = None,
    official_email: Optional[str] = None,
    contact_number: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Update profile and contact information for an existing college."""
    col = get_college(college_id)
    if not col:
        return False, None, f"College '{college_id}' not found."

    clean_name = college_name.strip() if college_name is not None else col["college_name"]
    clean_univ = affiliated_university.strip() if affiliated_university is not None else col["affiliated_university"]
    clean_addr = address.strip() if address is not None else col["address"]
    clean_state = state.strip() if state is not None else col["state"]
    clean_dist = district.strip() if district is not None else col["district"]
    clean_email = official_email.strip().lower() if official_email is not None else col["official_email"]
    clean_contact = contact_number.strip() if contact_number is not None else col["contact_number"]
    now = time.time()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE colleges
                SET college_name = ?, affiliated_university = ?, address = ?,
                    state = ?, district = ?, official_email = ?, contact_number = ?, updated_at = ?
                WHERE id = ?
            """, (clean_name, clean_univ, clean_addr, clean_state, clean_dist, clean_email, clean_contact, now, col["id"]))
        return True, get_college(col["id"]), None
    except Exception as e:
        logger.error("Error updating college: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def set_college_status(college_id: str, status: str) -> Tuple[bool, Optional[str]]:
    """Set college operational status ('ACTIVE', 'DEACTIVATED', 'SUSPENDED', 'ARCHIVED')."""
    valid_statuses = {"ACTIVE", "DEACTIVATED", "SUSPENDED", "ARCHIVED"}
    clean_status = (status or "").strip().upper()
    if clean_status not in valid_statuses:
        return False, f"Invalid status '{status}'. Must be one of {valid_statuses}."

    col = get_college(college_id)
    if not col:
        return False, f"College '{college_id}' not found."

    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE colleges
                SET status = ?, updated_at = ?
                WHERE id = ?
            """, (clean_status, now, col["id"]))

            # If deactivated/suspended, deactivate admin accounts
            if clean_status in ("DEACTIVATED", "SUSPENDED", "ARCHIVED"):
                conn.execute("UPDATE users SET active = 0, updated_at = ? WHERE college_id = ?", (now, col["id"]))
            elif clean_status == "ACTIVE":
                conn.execute("UPDATE users SET active = 1, updated_at = ? WHERE college_id = ?", (now, col["id"]))
        return True, None
    except Exception as e:
        logger.error("Error changing college status: %s", e)
        return False, str(e)
    finally:
        conn.close()


def reset_college_admin_password(college_id: str, new_password: str) -> Tuple[bool, Optional[str]]:
    """Reset administrator credentials for a college and force password update on next login."""
    if not new_password or len(new_password) < 6:
        return False, "Password must be at least 6 characters long."

    col = get_college(college_id)
    if not col:
        return False, f"College '{college_id}' not found."

    now = time.time()
    pwd_hash = hash_password(new_password)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET password_hash = ?, must_change_password = 1, updated_at = ?
                WHERE college_id = ? AND role = 'COLLEGE_ADMIN'
            """, (pwd_hash, now, col["id"]))
        return True, None
    except Exception as e:
        logger.error("Error resetting college admin password: %s", e)
        return False, str(e)
    finally:
        conn.close()


def get_global_analytics() -> Dict[str, Any]:
    """Retrieve multi-college global platform analytics for Super Admin."""
    conn = get_db_connection()
    try:
        total_colleges = conn.execute("SELECT COUNT(*) as count FROM colleges").fetchone()["count"]
        active_colleges = conn.execute("SELECT COUNT(*) as count FROM colleges WHERE status = 'ACTIVE'").fetchone()["count"]
        suspended_colleges = conn.execute("SELECT COUNT(*) as count FROM colleges WHERE status IN ('SUSPENDED', 'DEACTIVATED')").fetchone()["count"]
        total_students = conn.execute("SELECT COUNT(*) as count FROM students").fetchone()["count"]
        active_students = conn.execute("SELECT COUNT(*) as count FROM students WHERE status = 'ACTIVE'").fetchone()["count"]
        total_results = conn.execute("SELECT COUNT(*) as count FROM academic_results").fetchone()["count"]
        total_marksheets = conn.execute("SELECT COUNT(*) as count FROM marksheets").fetchone()["count"]

        # College-wise distribution
        col_dist = conn.execute("""
            SELECT c.id, c.college_code, c.college_name,
                   COUNT(s.student_id) as student_count,
                   COUNT(m.id) as marksheet_count
            FROM colleges c
            LEFT JOIN students s ON s.college_id = c.id
            LEFT JOIN marksheets m ON m.college_id = c.id
            GROUP BY c.id
            ORDER BY student_count DESC
            LIMIT 10
        """).fetchall()

        # Recent activities
        recent_logs = conn.execute("""
            SELECT id, timestamp, action, actor, actor_role, resource_id, status, details_json
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 8
        """).fetchall()

        return {
            "total_colleges": total_colleges,
            "active_colleges": active_colleges,
            "suspended_colleges": suspended_colleges,
            "total_students": total_students,
            "active_students": active_students,
            "total_academic_records": total_results,
            "total_marksheets_generated": total_marksheets,
            "college_distribution": [dict(r) for r in col_dist],
            "recent_activities": [dict(r) for r in recent_logs],
        }
    finally:
        conn.close()


# --- Departments & Courses ---

def list_departments(college_id: str) -> List[Dict[str, Any]]:
    """List departments for a specific college."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM departments WHERE college_id = ? ORDER BY dept_code ASC", (college_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def create_department(college_id: str, dept_code: str, dept_name: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Add a new academic department under a college."""
    clean_code = (dept_code or "").strip().upper()
    clean_name = (dept_name or "").strip()
    if not clean_code or not clean_name:
        return False, None, "Department Code and Name are required."

    dept_id = f"DEP-{college_id}-{clean_code}"
    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO departments (id, college_id, dept_code, dept_name, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (dept_id, college_id, clean_code, clean_name, now))
        return True, {"id": dept_id, "college_id": college_id, "dept_code": clean_code, "dept_name": clean_name}, None
    except Exception as e:
        return False, None, str(e)
    finally:
        conn.close()


def list_courses(college_id: str) -> List[Dict[str, Any]]:
    """List degree courses for a specific college."""
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM courses WHERE college_id = ? ORDER BY course_code ASC", (college_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def create_course(college_id: str, course_code: str, course_name: str, duration_years: int = 4, total_semesters: int = 8) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Add a new academic degree course under a college."""
    clean_code = (course_code or "").strip().upper()
    clean_name = (course_name or "").strip()
    if not clean_code or not clean_name:
        return False, None, "Course Code and Course Name are required."

    course_id = f"CRS-{college_id}-{clean_code}"
    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO courses (id, college_id, course_code, course_name, duration_years, total_semesters, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (course_id, college_id, clean_code, clean_name, duration_years, total_semesters, now))
        return True, {"id": course_id, "college_id": college_id, "course_code": clean_code, "course_name": clean_name}, None
    except Exception as e:
        return False, None, str(e)
    finally:
        conn.close()


# --- Student Registration & Management (Strictly College-Isolated) ---

def create_student(
    college_id: str,
    data: Dict[str, Any],
    password: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], Optional[str]]:
    """
    College Administrator registers a new student profile and generates login credentials.
    Students CANNOT self-register.
    Returns (success, student_dict, generated_password, error_message).
    """
    col = get_college(college_id)
    if not col:
        return False, None, None, f"College '{college_id}' not found."

    roll_number = str(data.get("roll_number", "")).strip()
    reg_number = str(data.get("registration_number", "")).strip()
    full_name = str(data.get("full_name") or data.get("name") or "").strip()
    email = str(data.get("email", "")).strip().lower()
    department = str(data.get("department", "")).strip()
    course = str(data.get("course", "Bachelor of Technology")).strip()
    current_sem = int(data.get("current_semester", 1))
    admission_year = int(data.get("admission_year", time.localtime().tm_year))
    academic_session = str(data.get("academic_session", f"{admission_year}-{str(admission_year+1)[-2:]}")).strip()

    if not roll_number:
        return False, None, None, "University Roll Number is required."
    if not reg_number:
        return False, None, None, "University Registration Number is required."
    if not full_name:
        return False, None, None, "Student Full Name is required."
    if not email:
        return False, None, None, "Student Email Address is required."
    if not department:
        return False, None, None, "Academic Department is required."

    # Username: user specified or default to roll_number
    username = str(data.get("username") or roll_number).strip().upper()

    # Generate secure temporary password if not provided
    generated_pwd = password.strip() if password and len(password.strip()) >= 6 else secrets.token_urlsafe(8)

    conn = get_db_connection()
    try:
        # Check duplicate roll number
        dup_roll = conn.execute("SELECT student_id FROM students WHERE roll_number = ?", (roll_number,)).fetchone()
        if dup_roll:
            return False, None, None, f"Student with Roll Number '{roll_number}' is already registered."

        # Check duplicate registration number
        dup_reg = conn.execute("SELECT student_id FROM students WHERE registration_number = ?", (reg_number,)).fetchone()
        if dup_reg:
            return False, None, None, f"Student with Registration Number '{reg_number}' is already registered."

        # Check duplicate user ID or email in users table
        dup_user = get_user(username)
        if dup_user:
            return False, None, None, f"User account with identifier '{username}' already exists."

        dup_email_user = get_user(email)
        if dup_email_user:
            return False, None, None, f"An account with email '{email}' already exists."

        # Generate unique Student ID
        cur_count = conn.execute("SELECT COUNT(*) as count FROM students WHERE college_id = ?", (col["id"],)).fetchone()["count"]
        student_id = f"STU-{col['college_code']}-{admission_year}-{cur_count + 1:04d}"

        now = time.time()
        pwd_hash = hash_password(generated_pwd)

        with conn:
            # 1. Create authentication user account
            conn.execute("""
                INSERT INTO users (
                    user_id, name, role, department, email, assigned_subject,
                    password_hash, active, college_id, must_change_password, created_at, updated_at
                ) VALUES (?, ?, 'STUDENT', ?, ?, NULL, ?, 1, ?, 1, ?, ?)
            """, (username, full_name, department, email, pwd_hash, col["id"], now, now))

            # 2. Create student record
            conn.execute("""
                INSERT INTO students (
                    student_id, user_id, college_id, roll_number, registration_number,
                    college_roll, full_name, father_name, mother_name, dob, gender,
                    blood_group, category, email, mobile, permanent_address, current_address,
                    department, course, admission_year, current_semester, academic_session,
                    enrollment_date, profile_photo_url, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
            """, (
                student_id, username, col["id"], roll_number, reg_number,
                str(data.get("college_roll", "")).strip(), full_name,
                str(data.get("father_name", "")).strip(), str(data.get("mother_name", "")).strip(),
                str(data.get("dob", "")).strip(), str(data.get("gender", "Male")).strip(),
                str(data.get("blood_group", "")).strip(), str(data.get("category", "General")).strip(),
                email, str(data.get("mobile", "")).strip(),
                str(data.get("permanent_address", "")).strip(), str(data.get("current_address", "")).strip(),
                department, course, admission_year, current_sem, academic_session,
                str(data.get("enrollment_date", time.strftime("%Y-%m-%d"))).strip(),
                str(data.get("profile_photo_url", "")).strip(), now, now
            ))

        student = get_student(student_id)
        return True, student, generated_pwd, None
    except Exception as e:
        logger.error("Error registering student: %s", e)
        return False, None, None, str(e)
    finally:
        conn.close()


def get_student(student_id: str, college_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieve full student profile with college-isolation verification."""
    if not student_id:
        return None
    clean_id = student_id.strip()
    conn = get_db_connection()
    try:
        sql = """
            SELECT s.*,
                   c.college_name, c.college_code, c.affiliated_university,
                   u.active as account_active, u.must_change_password
            FROM students s
            JOIN colleges c ON c.id = s.college_id
            JOIN users u ON u.user_id = s.user_id
            WHERE s.student_id = ? OR s.user_id = ? OR s.roll_number = ?
        """
        params = [clean_id, clean_id, clean_id]
        if college_id:
            sql += " AND s.college_id = ?"
            params.append(college_id.strip())

        cur = conn.execute(sql, params)
        row = cur.fetchone()
        if not row:
            return None
        res = dict(row)
        res["name"] = res.get("full_name")
        res["mobile_number"] = res.get("mobile")
        return res
    finally:
        conn.close()


def get_student_by_user_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve student profile by their authentication user_id."""
    return get_student(user_id)


def update_student(student_id: str, college_id: str, update_data: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Update student profile details, enforcing college-level isolation."""
    student = get_student(student_id, college_id=college_id)
    if not student:
        return False, None, f"Student '{student_id}' not found in your college."

    full_name = str(update_data.get("full_name") or student["full_name"]).strip()
    father_name = str(update_data.get("father_name") if update_data.get("father_name") is not None else student["father_name"]).strip()
    mother_name = str(update_data.get("mother_name") if update_data.get("mother_name") is not None else student["mother_name"]).strip()
    dob = str(update_data.get("dob") if update_data.get("dob") is not None else student["dob"]).strip()
    gender = str(update_data.get("gender") if update_data.get("gender") is not None else student["gender"]).strip()
    blood_group = str(update_data.get("blood_group") if update_data.get("blood_group") is not None else student["blood_group"]).strip()
    mobile = str(update_data.get("mobile") if update_data.get("mobile") is not None else student["mobile"]).strip()
    perm_addr = str(update_data.get("permanent_address") if update_data.get("permanent_address") is not None else student["permanent_address"]).strip()
    curr_addr = str(update_data.get("current_address") if update_data.get("current_address") is not None else student["current_address"]).strip()
    current_sem = int(update_data.get("current_semester", student["current_semester"]))

    now = time.time()
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE students
                SET full_name = ?, father_name = ?, mother_name = ?, dob = ?,
                    gender = ?, blood_group = ?, mobile = ?, permanent_address = ?,
                    current_address = ?, current_semester = ?, updated_at = ?
                WHERE student_id = ? AND college_id = ?
            """, (full_name, father_name, mother_name, dob, gender, blood_group, mobile, perm_addr, curr_addr, current_sem, now, student["student_id"], college_id))

            conn.execute("""
                UPDATE users SET name = ?, updated_at = ? WHERE user_id = ?
            """, (full_name, now, student["user_id"]))
        return True, get_student(student["student_id"], college_id=college_id), None
    except Exception as e:
        logger.error("Error updating student: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def set_student_status(student_id: str, college_id: str, status: str) -> Tuple[bool, Optional[str]]:
    """Activate, deactivate, or suspend a student account."""
    clean_status = (status or "").strip().upper()
    valid_statuses = {"ACTIVE", "INACTIVE", "SUSPENDED"}
    if clean_status not in valid_statuses:
        return False, f"Invalid status '{status}'. Must be one of {valid_statuses}."

    student = get_student(student_id, college_id=college_id)
    if not student:
        return False, f"Student '{student_id}' not found in your college."

    now = time.time()
    is_active = 1 if clean_status == "ACTIVE" else 0
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE students SET status = ?, updated_at = ?
                WHERE student_id = ? AND college_id = ?
            """, (clean_status, now, student["student_id"], college_id))

            conn.execute("""
                UPDATE users SET active = ?, updated_at = ?
                WHERE user_id = ?
            """, (is_active, now, student["user_id"]))
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def reset_student_password(student_id: str, college_id: str, new_password: str) -> Tuple[bool, Optional[str]]:
    """Reset a student's login password (by authorized College Admin)."""
    if not new_password or len(new_password) < 6:
        return False, "Password must be at least 6 characters long."

    student = get_student(student_id, college_id=college_id)
    if not student:
        return False, f"Student '{student_id}' not found in your college."

    now = time.time()
    pwd_hash = hash_password(new_password)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET password_hash = ?, must_change_password = 1, updated_at = ?
                WHERE user_id = ?
            """, (pwd_hash, now, student["user_id"]))
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def list_students(
    college_id: Optional[str] = None,
    search: Optional[str] = None,
    department: Optional[str] = None,
    semester: Optional[int] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List students, optionally isolated by college, with filtering and search."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT s.*,
                   c.college_name, c.college_code,
                   COUNT(DISTINCT r.id) AS total_semesters_recorded,
                   COUNT(DISTINCT m.id) AS total_marksheets
            FROM students s
            JOIN colleges c ON c.id = s.college_id
            LEFT JOIN academic_results r ON r.student_id = s.student_id
            LEFT JOIN marksheets m ON m.student_id = s.student_id
            WHERE 1=1
        """
        params = []
        if college_id:
            sql += " AND s.college_id = ?"
            params.append(college_id.strip())
        if department and department.upper() != "ALL":
            sql += " AND s.department = ?"
            params.append(department.strip())
        if semester and semester > 0:
            sql += " AND s.current_semester = ?"
            params.append(int(semester))
        if status and status.upper() != "ALL":
            sql += " AND UPPER(s.status) = ?"
            params.append(status.strip().upper())
        if search:
            term = f"%{search.strip().lower()}%"
            sql += " AND (LOWER(s.full_name) LIKE ? OR LOWER(s.roll_number) LIKE ? OR LOWER(s.registration_number) LIKE ? OR LOWER(s.email) LIKE ? OR LOWER(s.student_id) LIKE ?)"
            params.extend([term, term, term, term, term])

        sql += " GROUP BY s.student_id ORDER BY s.created_at DESC"
        cur = conn.execute(sql, params)
        students = []
        for r in cur.fetchall():
            sd = dict(r)
            sd["name"] = sd.get("full_name")
            sd["mobile_number"] = sd.get("mobile")
            students.append(sd)
        return students
    finally:
        conn.close()


def get_college_dashboard_stats(college_id: str) -> Dict[str, Any]:
    """Calculate isolated academic metrics and distributions for a college."""
    conn = get_db_connection()
    try:
        col = get_college(college_id)
        if not col:
            return {}

        total_students = conn.execute("SELECT COUNT(*) as count FROM students WHERE college_id = ?", (college_id,)).fetchone()["count"]
        active_students = conn.execute("SELECT COUNT(*) as count FROM students WHERE college_id = ? AND status = 'ACTIVE'", (college_id,)).fetchone()["count"]
        inactive_students = total_students - active_students

        # Department distribution
        dept_dist = conn.execute("""
            SELECT department, COUNT(*) as count
            FROM students WHERE college_id = ?
            GROUP BY department ORDER BY count DESC
        """, (college_id,)).fetchall()

        # Semester distribution
        sem_dist = conn.execute("""
            SELECT current_semester, COUNT(*) as count
            FROM students WHERE college_id = ?
            GROUP BY current_semester ORDER BY current_semester ASC
        """, (college_id,)).fetchall()

        total_results = conn.execute("SELECT COUNT(*) as count FROM academic_results WHERE college_id = ?", (college_id,)).fetchone()["count"]
        total_marksheets = conn.execute("SELECT COUNT(*) as count FROM marksheets WHERE college_id = ?", (college_id,)).fetchone()["count"]

        # Recent students
        recent_students = conn.execute("""
            SELECT student_id, user_id, roll_number, full_name, department, current_semester, created_at, status
            FROM students WHERE college_id = ?
            ORDER BY created_at DESC LIMIT 6
        """, (college_id,)).fetchall()

        return {
            "college": col,
            "total_students": total_students,
            "active_students": active_students,
            "inactive_students": inactive_students,
            "total_academic_records": total_results,
            "total_marksheets": total_marksheets,
            "department_distribution": [dict(r) for r in dept_dist],
            "semester_distribution": [dict(r) for r in sem_dist],
            "recent_students": [dict(r) for r in recent_students],
        }
    finally:
        conn.close()


# --- Academic Results & Subject Marks ---

def save_semester_result(
    college_id: str,
    student_id: str,
    semester: int,
    academic_session: str,
    subject_marks_list: List[Dict[str, Any]],
    is_published: bool = False,
    published_by: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Save or update a semester academic record with its subject-wise marks.
    Calculates total marks, percentage, SGPA, and grade points according to standard academic formulas.
    """
    student = get_student(student_id, college_id=college_id)
    if not student:
        return False, None, f"Student '{student_id}' not found in your college."

    if not subject_marks_list:
        return False, None, "At least one subject mark record is required."

    now = time.time()
    result_id = f"RES-{student['student_id']}-SEM{semester}"

    # Calculate aggregations
    total_obtained = 0.0
    total_max = 0.0
    total_credits = 0.0
    weighted_grade_points = 0.0
    has_backlog = False

    processed_marks = []
    for idx, item in enumerate(subject_marks_list):
        sub_code = str(item.get("subject_code", f"SUB{idx+1}")).strip().upper()
        sub_name = str(item.get("subject_name", sub_code)).strip()
        internal = float(item.get("internal_marks", 0.0))
        external = float(item.get("external_marks", 0.0))
        practical = float(item.get("practical_marks", 0.0))
        max_marks = float(item.get("max_marks", 100.0))
        tot = internal + external + practical
        credits = float(item.get("credits", 4.0))

        # Academic grade calculation
        pct = (tot / max_marks) * 100.0 if max_marks > 0 else 0.0
        if pct >= 90:
            grade, gp = "O", 10.0
        elif pct >= 80:
            grade, gp = "A+", 9.0
        elif pct >= 70:
            grade, gp = "A", 8.0
        elif pct >= 60:
            grade, gp = "B+", 7.0
        elif pct >= 50:
            grade, gp = "B", 6.0
        elif pct >= 40:
            grade, gp = "C", 5.0
        else:
            grade, gp = "F", 0.0
            has_backlog = True

        status = "PASS" if gp >= 5.0 else "BACKLOG"
        total_obtained += tot
        total_max += max_marks
        total_credits += credits
        weighted_grade_points += (gp * credits)

        mark_id = f"MRK-{result_id}-{sub_code}"
        processed_marks.append((
            mark_id, result_id, student["student_id"], sub_code, sub_name,
            internal, external, practical, tot, max_marks,
            grade, gp, credits, status, now
        ))

    overall_percentage = round((total_obtained / total_max) * 100.0, 2) if total_max > 0 else 0.0
    sgpa = round(weighted_grade_points / total_credits, 2) if total_credits > 0 else 0.0
    result_status = "BACKLOG" if has_backlog else "PASS"

    conn = get_db_connection()
    try:
        with conn:
            # 1. Insert or Replace Academic Result
            conn.execute("""
                INSERT INTO academic_results (
                    id, student_id, college_id, semester, academic_session,
                    total_marks_obtained, total_max_marks, percentage, sgpa, cgpa,
                    total_credits, credits_earned, result_status, is_published, published_at, published_by,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(student_id, semester) DO UPDATE SET
                    academic_session = excluded.academic_session,
                    total_marks_obtained = excluded.total_marks_obtained,
                    total_max_marks = excluded.total_max_marks,
                    percentage = excluded.percentage,
                    sgpa = excluded.sgpa,
                    total_credits = excluded.total_credits,
                    credits_earned = excluded.credits_earned,
                    result_status = excluded.result_status,
                    is_published = excluded.is_published,
                    published_at = COALESCE(excluded.published_at, academic_results.published_at),
                    published_by = COALESCE(excluded.published_by, academic_results.published_by),
                    updated_at = excluded.updated_at
            """, (
                result_id, student["student_id"], college_id, semester, academic_session,
                round(total_obtained, 2), round(total_max, 2), overall_percentage, sgpa, sgpa,
                total_credits, total_credits if not has_backlog else (total_credits - 4.0),
                result_status, 1 if is_published else 0,
                now if is_published else None, published_by if is_published else None,
                now, now
            ))

            # 2. Refresh Subject Marks
            conn.execute("DELETE FROM subject_marks WHERE result_id = ?", (result_id,))
            conn.executemany("""
                INSERT INTO subject_marks (
                    id, result_id, student_id, subject_code, subject_name,
                    internal_marks, external_marks, practical_marks, total_marks, max_marks,
                    grade, grade_point, credits, result_status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, processed_marks)

            # 3. Recalculate CGPA across all recorded semesters
            all_sems = conn.execute("""
                SELECT sgpa, total_credits FROM academic_results
                WHERE student_id = ?
            """, (student["student_id"],)).fetchall()
            total_weighted = sum(r["sgpa"] * r["total_credits"] for r in all_sems)
            sum_credits = sum(r["total_credits"] for r in all_sems)
            cgpa = round(total_weighted / sum_credits, 2) if sum_credits > 0 else sgpa

            conn.execute("UPDATE academic_results SET cgpa = ? WHERE student_id = ?", (cgpa, student["student_id"]))

        results = get_student_semester_results(student["student_id"], college_id=college_id)
        res_ret = next((r for r in results if r["semester"] == semester), None)
        if res_ret and "result_id" not in res_ret:
            res_ret["result_id"] = res_ret.get("id")
        return True, res_ret, None
    except Exception as e:
        logger.error("Error saving semester result: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def publish_semester_result(college_id: str, result_id: str, publisher_id: str) -> Tuple[bool, Optional[str]]:
    """Publish an academic semester result making it official and accessible to the student."""
    now = time.time()
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM academic_results WHERE id = ? AND college_id = ?", (result_id, college_id))
        row = cur.fetchone()
        if not row:
            return False, f"Academic result '{result_id}' not found in your college."

        with conn:
            conn.execute("""
                UPDATE academic_results
                SET is_published = 1, published_at = ?, published_by = ?, updated_at = ?
                WHERE id = ?
            """, (now, publisher_id, now, result_id))
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def get_student_semester_results(student_id: str, college_id: Optional[str] = None, published_only: bool = False) -> List[Dict[str, Any]]:
    """Retrieve all semester results and subject marks for a student."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT r.*,
                   c.college_name, c.college_code, c.affiliated_university,
                   s.full_name, s.roll_number, s.registration_number, s.department, s.course
            FROM academic_results r
            JOIN students s ON s.student_id = r.student_id
            JOIN colleges c ON c.id = r.college_id
            WHERE (r.student_id = ? OR s.user_id = ? OR s.roll_number = ?)
        """
        params = [student_id, student_id, student_id]
        if college_id:
            sql += " AND r.college_id = ?"
            params.append(college_id)
        if published_only:
            sql += " AND r.is_published = 1"

        sql += " ORDER BY r.semester ASC"
        results_rows = conn.execute(sql, params).fetchall()

        results = []
        for r in results_rows:
            r_dict = dict(r)
            r_dict["result_id"] = r_dict.get("id")
            r_dict["name"] = r_dict.get("full_name")
            # Fetch subject marks
            marks_cur = conn.execute("""
                SELECT * FROM subject_marks WHERE result_id = ? ORDER BY subject_code ASC
            """, (r_dict["id"],))
            r_dict["subjects"] = [dict(m) for m in marks_cur.fetchall()]
            results.append(r_dict)
        return results
    finally:
        conn.close()


def get_student_academic_summary(student_id: str, college_id: Optional[str] = None) -> Dict[str, Any]:
    """Calculate overall academic performance, CGPA progression, and passed/backlog counts."""
    student = get_student(student_id, college_id=college_id)
    if not student:
        return {}

    results = get_student_semester_results(student["student_id"], college_id=college_id, published_only=True)
    if not results:
        return {
            "student": student,
            "total_semesters_published": 0,
            "overall_cgpa": 0.0,
            "overall_percentage": 0.0,
            "total_credits_earned": 0.0,
            "total_subjects": 0,
            "passed_subjects": 0,
            "backlog_subjects": 0,
            "semesters": [],
        }

    total_subjects = 0
    passed_subjects = 0
    backlog_subjects = 0
    total_credits = 0.0
    weighted_sgpa = 0.0
    total_obtained = 0.0
    total_max = 0.0

    for res in results:
        total_obtained += res["total_marks_obtained"]
        total_max += res["total_max_marks"]
        total_credits += res["total_credits"]
        weighted_sgpa += (res["sgpa"] * res["total_credits"])
        for sub in res.get("subjects", []):
            total_subjects += 1
            if sub["result_status"] == "PASS":
                passed_subjects += 1
            else:
                backlog_subjects += 1

    overall_cgpa = round(weighted_sgpa / total_credits, 2) if total_credits > 0 else 0.0
    overall_pct = round((total_obtained / total_max) * 100.0, 2) if total_max > 0 else 0.0

    return {
        "student": student,
        "total_semesters_published": len(results),
        "overall_cgpa": overall_cgpa,
        "overall_percentage": overall_pct,
        "total_credits_earned": total_credits,
        "total_subjects": total_subjects,
        "passed_subjects": passed_subjects,
        "backlog_subjects": backlog_subjects,
        "semesters": results,
    }


# --- Marksheet Operations & Verification ---

def save_marksheet_record(
    marksheet_id: str,
    student_id: str,
    college_id: str,
    semester: Optional[int],
    academic_session: str,
    file_path: str,
    file_hash: str,
    qr_code_path: str,
    verification_url: str,
    is_consolidated: bool = False,
    digilocker_uri: Optional[str] = None,
    digilocker_status: str = "ISSUED",
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Save an official printable marksheet document record."""
    now = time.time()
    conn = get_db_connection()
    try:
        uri = digilocker_uri or ""
        with conn:
            conn.execute("""
                INSERT OR REPLACE INTO marksheets (
                    id, student_id, college_id, semester, academic_session,
                    is_consolidated, file_path, file_hash, qr_code_path,
                    verification_url, is_revoked, digilocker_uri, digilocker_status, generated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
            """, (
                marksheet_id, student_id, college_id, semester, academic_session,
                1 if is_consolidated else 0, file_path, file_hash, qr_code_path,
                verification_url, uri, digilocker_status, now
            ))
        record = get_marksheet_by_id(marksheet_id)
        return True, record, None
    except Exception as e:
        logger.error("Error saving marksheet record: %s", e)
        return False, None, str(e)
    finally:
        conn.close()


def get_marksheet_by_id(marksheet_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve marksheet record and public verification payload by Marksheet ID."""
    if not marksheet_id:
        return None
    clean_id = marksheet_id.strip()
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            SELECT m.*,
                   s.full_name as student_name, s.roll_number, s.registration_number,
                   s.department, s.course,
                   c.college_name, c.college_code, c.affiliated_university,
                   r.total_marks_obtained, r.total_max_marks, r.percentage,
                   r.sgpa, r.cgpa, r.result_status
            FROM marksheets m
            JOIN students s ON s.student_id = m.student_id
            JOIN colleges c ON c.id = m.college_id
            LEFT JOIN academic_results r ON r.student_id = m.student_id AND r.semester = m.semester
            WHERE m.id = ?
        """, (clean_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_student_marksheets(student_id: str, college_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all official marksheets generated for a student."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT m.*,
                   s.full_name as student_name, s.roll_number,
                   c.college_name, c.college_code
            FROM marksheets m
            JOIN students s ON s.student_id = m.student_id
            JOIN colleges c ON c.id = m.college_id
            WHERE (m.student_id = ? OR s.user_id = ? OR s.roll_number = ?)
        """
        params = [student_id, student_id, student_id]
        if college_id:
            sql += " AND m.college_id = ?"
            params.append(college_id)
        sql += " ORDER BY m.semester ASC, m.generated_at DESC"
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def list_college_marksheets(college_id: str) -> List[Dict[str, Any]]:
    """List all marksheets generated across a college."""
    conn = get_db_connection()
    try:
        cur = conn.execute("""
            SELECT m.*, s.full_name as student_name, s.roll_number, s.department
            FROM marksheets m
            JOIN students s ON s.student_id = m.student_id
            WHERE m.college_id = ?
            ORDER BY m.generated_at DESC
        """, (college_id,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


# --- Profile Correction Requests ---

def submit_profile_correction(
    student_id: str,
    college_id: str,
    field_name: str,
    current_value: str,
    requested_value: str,
    reason: str,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """Students submit a formal profile correction request to their college administrator."""
    clean_field = (field_name or "").strip()
    clean_req = (requested_value or "").strip()
    clean_reason = (reason or "").strip()

    if not clean_field or not clean_req or not clean_reason:
        return False, None, "Field name, requested correction, and reason are required."

    now = time.time()
    req_id = f"PCR-{student_id}-{int(now)}"
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                INSERT INTO profile_correction_requests (
                    id, student_id, college_id, field_name, current_value,
                    requested_value, reason, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
            """, (req_id, student_id, college_id, clean_field, current_value, clean_req, clean_reason, now, now))
        return True, {"id": req_id, "status": "PENDING", "field_name": clean_field, "requested_value": clean_req}, None
    except Exception as e:
        return False, None, str(e)
    finally:
        conn.close()


def list_profile_corrections(
    college_id: Optional[str] = None,
    student_id: Optional[str] = None,
    status: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """List profile correction requests for a college administrator or student."""
    conn = get_db_connection()
    try:
        sql = """
            SELECT p.*, s.full_name as student_name, s.roll_number, s.department
            FROM profile_correction_requests p
            JOIN students s ON s.student_id = p.student_id
            WHERE 1=1
        """
        params = []
        if college_id:
            sql += " AND p.college_id = ?"
            params.append(college_id)
        if student_id:
            sql += " AND p.student_id = ?"
            params.append(student_id)
        if status and status.upper() != "ALL":
            sql += " AND p.status = ?"
            params.append(status.strip().upper())
        sql += " ORDER BY p.created_at DESC"
        cur = conn.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def review_profile_correction(request_id: str, college_id: str, status: str, reviewer_id: str) -> Tuple[bool, Optional[str]]:
    """College administrator approves or rejects a profile correction request."""
    clean_status = (status or "").strip().upper()
    if clean_status not in ("APPROVED", "REJECTED"):
        return False, "Status must be 'APPROVED' or 'REJECTED'."

    now = time.time()
    conn = get_db_connection()
    try:
        cur = conn.execute("SELECT * FROM profile_correction_requests WHERE id = ? AND college_id = ?", (request_id, college_id))
        row = cur.fetchone()
        if not row:
            return False, f"Request '{request_id}' not found."

        with conn:
            conn.execute("""
                UPDATE profile_correction_requests
                SET status = ?, reviewed_by = ?, reviewed_at = ?, updated_at = ?
                WHERE id = ?
            """, (clean_status, reviewer_id, now, now, request_id))

            # If approved, apply the update to the students table
            if clean_status == "APPROVED":
                allowed_fields = {"full_name", "father_name", "mother_name", "dob", "gender", "blood_group", "mobile", "permanent_address", "current_address"}
                field_name = row["field_name"]
                if field_name in allowed_fields:
                    conn.execute(f"UPDATE students SET {field_name} = ?, updated_at = ? WHERE student_id = ?", (row["requested_value"], now, row["student_id"]))
                    if field_name == "full_name":
                        conn.execute("UPDATE users SET name = ?, updated_at = ? WHERE user_id = (SELECT user_id FROM students WHERE student_id = ?)", (row["requested_value"], now, row["student_id"]))
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


# --- User Password Management ---

def change_user_password(user_id: str, old_password: str, new_password: str) -> Tuple[bool, Optional[str]]:
    """Verify old password and set a new password, resetting must_change_password flag to 0."""
    if not new_password or len(new_password) < 6:
        return False, "New password must be at least 6 characters long."

    user_auth = get_user_auth(user_id)
    if not user_auth:
        return False, "User not found."

    expected_hash = user_auth.get("password_hash")
    if not expected_hash or not hmac.compare_digest(expected_hash, hash_password(old_password)):
        return False, "Current password does not match."

    now = time.time()
    new_hash = hash_password(new_password)
    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
                UPDATE users
                SET password_hash = ?, must_change_password = 0, updated_at = ?
                WHERE user_id = ?
            """, (new_hash, now, user_auth["user_id"]))
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


# Auto-initialize database on module import
init_db()
