import sqlite3
import secrets
import string
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "hrms.db"

# Database connection helpers
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS companies (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            code        TEXT NOT NULL,          -- e.g. "OI" for "Odoo India"
            logo_path   TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS users (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id          INTEGER NOT NULL,
            login_id            TEXT UNIQUE NOT NULL,   -- e.g. OIJODO20220001
            first_name          TEXT NOT NULL,
            last_name           TEXT NOT NULL,
            email               TEXT UNIQUE NOT NULL,
            phone               TEXT,
            password_hash       TEXT NOT NULL,
            role                TEXT NOT NULL CHECK(role IN ('HR', 'Employee')),
            year_joined         INTEGER NOT NULL,
            serial_no           INTEGER NOT NULL,
            must_change_password INTEGER NOT NULL DEFAULT 0,
            email_verified      INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT NOT NULL,
            FOREIGN KEY (company_id) REFERENCES companies (id)
        );
        """
    )
    conn.commit()
    conn.close()

# Login ID generation:  [CompanyCode][Initials][Year][Serial]
def generate_company_code(company_name: str) -> str:
    """
    Turns a company name into a short code, e.g. "Odoo India" -> "OI".
    Falls back to the first two letters of a single-word name.
    """
    words = [w for w in company_name.strip().split() if w]
    if len(words) >= 2:
        code = "".join(w[0] for w in words[:2])
    elif words:
        code = words[0][:2]
    else:
        code = "CO"
    return code.upper()


def _name_initials(first_name: str, last_name: str) -> str:
    """First 2 letters of first name + first 2 letters of last name."""
    f = (first_name or "").strip()
    l = (last_name or "").strip()
    f2 = (f[:2] if len(f) >= 2 else (f + "X" * 2)[:2]).upper()
    l2 = (l[:2] if len(l) >= 2 else (l + "X" * 2)[:2]).upper()
    return f2 + l2


def next_serial_for_year(conn, company_id: int, year: int) -> int:
    """
    Finds the next serial number for a given company + year of joining.
    Serial numbers restart at 1 for each new year, per company.
    """
    row = conn.execute(
        "SELECT MAX(serial_no) AS max_serial FROM users "
        "WHERE company_id = ? AND year_joined = ?",
        (company_id, year),
    ).fetchone()
    max_serial = row["max_serial"] if row and row["max_serial"] else 0
    return max_serial + 1


def generate_login_id(conn, company_code: str, first_name: str,
                       last_name: str, company_id: int, year: int = None):
    """
    Builds a login ID like OIJODO20220001 and returns
    (login_id, year, serial_no).
    """
    year = year or datetime.now().year
    serial = next_serial_for_year(conn, company_id, year)
    login_id = f"{company_code}{_name_initials(first_name, last_name)}{year}{serial:04d}"
    return login_id, year, serial

# Auto password generation (for employees created by HR/Admin)
def generate_temp_password(length: int = 10) -> str:
    """
    Generates a readable-but-secure temporary password containing
    upper/lower letters, digits and one symbol, per common password
    security rules.
    """
    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%"
    pool = letters + digits
    pwd = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(digits),
        secrets.choice(symbols),
    ]
    pwd += [secrets.choice(pool) for _ in range(length - len(pwd))]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

# Password policy (per spec 3.1.1: "Password must follow security rules")
def validate_password_strength(password: str) -> (bool, str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    if not any(c in string.punctuation for c in password):
        return False, "Password must contain at least one special character."
    return True, ""

# User / Company data access
def create_company_and_hr(company_name, admin_first, admin_last, email,
                           phone, password, logo_path=None):
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            return None, "An account with this email already exists."

        ok, msg = validate_password_strength(password)
        if not ok:
            return None, msg

        code = generate_company_code(company_name)
        now = datetime.now().isoformat()

        cur = conn.execute(
            "INSERT INTO companies (name, code, logo_path, created_at) "
            "VALUES (?, ?, ?, ?)",
            (company_name, code, logo_path, now),
        )
        company_id = cur.lastrowid

        login_id, year, serial = generate_login_id(
            conn, code, admin_first, admin_last, company_id
        )
        pwd_hash = generate_password_hash(password)

        conn.execute(
            """INSERT INTO users
               (company_id, login_id, first_name, last_name, email, phone,
                password_hash, role, year_joined, serial_no,
                must_change_password, email_verified, created_at)""",
            (company_id, login_id, admin_first, admin_last, email, phone,
             pwd_hash, year, serial, now),
        )
        conn.commit()
        return login_id, None
    finally:
        conn.close()


def create_employee(company_id, first_name, last_name, email, phone,
                     role="Employee"):
    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            return None, None, "An account with this email already exists."

        company = conn.execute(
            "SELECT * FROM companies WHERE id = ?", (company_id,)
        ).fetchone()
        if not company:
            return None, None, "Company not found."

        now = datetime.now().isoformat()
        login_id, year, serial = generate_login_id(
            conn, company["code"], first_name, last_name, company_id
        )
        temp_password = generate_temp_password()
        pwd_hash = generate_password_hash(temp_password)

        conn.execute(
            """INSERT INTO users
               (company_id, login_id, first_name, last_name, email, phone,
                password_hash, role, year_joined, serial_no,
                must_change_password, email_verified, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)""",
            (company_id, login_id, first_name, last_name, email, phone,
             pwd_hash, role, year, serial, now),
        )
        conn.commit()
        return login_id, temp_password, None
    finally:
        conn.close()


def find_user_by_login(identifier: str):
    """Users can sign in with either their Login ID or their Email."""
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE login_id = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()
        return user
    finally:
        conn.close()


def verify_login(identifier: str, password: str):
    """
    Returns (user_row, error_message). error_message is None on success.
    """
    user = find_user_by_login(identifier)
    if not user:
        return None, "Incorrect Login ID/Email or password."
    if not check_password_hash(user["password_hash"], password):
        return None, "Incorrect Login ID/Email or password."
    return user, None


def change_password(user_id: int, new_password: str):
    ok, msg = validate_password_strength(new_password)
    if not ok:
        return False, msg
    conn = get_db()
    try:
        pwd_hash = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = 0 "
            "WHERE id = ?",
            (pwd_hash, user_id),
        )
        conn.commit()
        return True, ""
    finally:
        conn.close()
