import sqlite3
import secrets
import string
from datetime import datetime, date, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = "hrms.db"

# ----------------------------------------------------------------------
# Database connection helpers
# ----------------------------------------------------------------------
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
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            company_id            INTEGER NOT NULL,
            login_id              TEXT UNIQUE NOT NULL,   -- e.g. OIJODO20220001
            first_name            TEXT NOT NULL,
            last_name             TEXT NOT NULL,
            email                 TEXT UNIQUE NOT NULL,
            phone                 TEXT,
            password_hash         TEXT NOT NULL,
            role                  TEXT NOT NULL CHECK(role IN ('HR', 'Employee')),
            year_joined           INTEGER NOT NULL,
            serial_no             INTEGER NOT NULL,
            must_change_password  INTEGER NOT NULL DEFAULT 0,
            email_verified        INTEGER NOT NULL DEFAULT 0,
            created_at            TEXT NOT NULL,

            -- org info shown on the employee card / profile header
            department            TEXT DEFAULT 'General',
            designation           TEXT DEFAULT 'Employee',
            manager               TEXT,
            location              TEXT DEFAULT 'Head Office',

            -- attendance / presence
            checked_in            INTEGER NOT NULL DEFAULT 0,
            check_in_time         TEXT,

            -- private info tab
            date_of_birth         TEXT,
            gender                TEXT,
            marital_status        TEXT,
            date_of_joining       TEXT,
            reporting_address     TEXT,
            nationality           TEXT,
            personal_email        TEXT,
            bank_name             TEXT,
            account_number        TEXT,
            ifsc_code             TEXT,
            pan                   TEXT,
            uan_id                TEXT,
            esic_code             TEXT,
            about                 TEXT DEFAULT '',

            -- salary info tab (admin-only)
            wage_monthly          REAL NOT NULL DEFAULT 0,
            working_days_per_week INTEGER NOT NULL DEFAULT 5,
            working_hours         REAL NOT NULL DEFAULT 8,

            -- time off
            leave_balance         INTEGER NOT NULL DEFAULT 12,

            FOREIGN KEY (company_id) REFERENCES companies (id)
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            date        TEXT NOT NULL,
            check_in    TEXT NOT NULL,
            check_out   TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS leave_requests (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            from_date   TEXT NOT NULL,
            to_date     TEXT NOT NULL,
            reason      TEXT,
            status      TEXT NOT NULL DEFAULT 'pending'
                        CHECK(status IN ('pending', 'approved', 'rejected')),
            created_at  TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    conn.commit()
    conn.close()
    _migrate_db()


def _migrate_db():
    """
    Additive migrations for the Attendance List + Time Off features.
    Uses ALTER TABLE ... ADD COLUMN, which SQLite supports; each is
    wrapped so re-running against an already-migrated database is a
    harmless no-op.
    """
    conn = get_db()
    try:
        migrations = [
            "ALTER TABLE users ADD COLUMN paid_leave_balance INTEGER NOT NULL DEFAULT 24",
            "ALTER TABLE users ADD COLUMN sick_leave_balance INTEGER NOT NULL DEFAULT 7",
            "ALTER TABLE leave_requests ADD COLUMN leave_type TEXT NOT NULL DEFAULT 'Paid Time Off'",
            "ALTER TABLE leave_requests ADD COLUMN attachment_path TEXT",
            "ALTER TABLE users ADD COLUMN profile_picture TEXT",
        ]
        for stmt in migrations:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError:
                pass  # column already exists
        conn.commit()
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Login ID generation:  [CompanyCode][Initials][Year][Serial]
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Auto password generation (for employees created by HR/Admin)
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Password policy (per spec 3.1.1: "Password must follow security rules")
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# User / Company data access
# ----------------------------------------------------------------------
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
        today = date.today().isoformat()

        conn.execute(
            """INSERT INTO users
               (company_id, login_id, first_name, last_name, email, phone,
                password_hash, role, year_joined, serial_no,
                must_change_password, email_verified, created_at,
                designation, date_of_joining, wage_monthly, profile_picture)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'HR', ?, ?, 0, 0, ?,
                       'HR / Admin', ?, 0, ?)""",
            (company_id, login_id, admin_first, admin_last, email, phone,
             pwd_hash, year, serial, now, today, logo_path),
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
        today = date.today().isoformat()
        login_id, year, serial = generate_login_id(
            conn, company["code"], first_name, last_name, company_id
        )
        temp_password = generate_temp_password()
        pwd_hash = generate_password_hash(temp_password)
        designation = "HR / Admin" if role == "HR" else "Employee"

        conn.execute(
            """INSERT INTO users
               (company_id, login_id, first_name, last_name, email, phone,
                password_hash, role, year_joined, serial_no,
                must_change_password, email_verified, created_at,
                designation, date_of_joining)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?, ?)""",
            (company_id, login_id, first_name, last_name, email, phone,
             pwd_hash, role, year, serial, now, designation, today),
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


def change_password(user_id: int, new_password: str, force_change: bool = False):
    """Sets a new password for user_id. When force_change is True (used
    when HR/Admin resets someone else's password), the user is required
    to set their own password again on their next login — mirroring the
    system-generated temp-password flow used at account creation."""
    ok, msg = validate_password_strength(new_password)
    if not ok:
        return False, msg
    conn = get_db()
    try:
        pwd_hash = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password_hash = ?, must_change_password = ? "
            "WHERE id = ?",
            (pwd_hash, 1 if force_change else 0, user_id),
        )
        conn.commit()
        return True, ""
    finally:
        conn.close()


def update_profile_picture(user_id: int, picture_path: str):
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET profile_picture = ? WHERE id = ?",
            (picture_path, user_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def get_user(user_id: int):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Employee directory (Admin dashboard)
# ----------------------------------------------------------------------
def _employee_status(conn, user_row, today: str) -> str:
    """present / leave / absent, per the wireframe's status-dot legend."""
    on_leave = conn.execute(
        "SELECT 1 FROM leave_requests WHERE user_id = ? AND status = 'approved' "
        "AND from_date <= ? AND to_date >= ?",
        (user_row["id"], today, today),
    ).fetchone()
    if on_leave:
        return "leave"
    if user_row["checked_in"]:
        return "present"
    return "absent"


def list_employees(company_id: int, query: str = ""):
    conn = get_db()
    try:
        today = date.today().isoformat()
        rows = conn.execute(
            "SELECT * FROM users WHERE company_id = ? ORDER BY first_name",
            (company_id,),
        ).fetchall()
        results = []
        q = (query or "").strip().lower()
        for r in rows:
            name = f"{r['first_name']} {r['last_name']}".strip()
            if q and q not in name.lower() and q not in (r["department"] or "").lower():
                continue
            results.append({
                "id": r["id"],
                "name": name,
                "designation": r["designation"] or ("HR / Admin" if r["role"] == "HR" else "Employee"),
                "department": r["department"] or "General",
                "status": _employee_status(conn, r, today),
            })
        return results
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Attendance
# ----------------------------------------------------------------------
STANDARD_SHIFT_HOURS = 8  # per the wireframe: hours beyond this count as "Extra hours"


def _parse_clock(time_str):
    """Parses a '%I:%M %p' string (e.g. '10:00 AM') into a datetime.time."""
    if not time_str:
        return None
    return datetime.strptime(time_str.strip(), "%I:%M %p").time()


def _fmt_hm(hours: float) -> str:
    """Formats a fractional hour count as HH:MM, e.g. 9.5 -> '09:30'."""
    if hours is None or hours < 0:
        return "—"
    total_minutes = round(hours * 60)
    h, m = divmod(total_minutes, 60)
    return f"{h:02d}:{m:02d}"


def _work_extra_hours(check_in, check_out, standard_hours=STANDARD_SHIFT_HOURS):
    """Returns (work_hours_str, extra_hours_str) for a check-in/out pair.
    Work Hours = total time worked. Extra hours = time worked beyond the
    standard shift length, per the wireframe."""
    if not check_in or not check_out:
        return "—", "—"
    t_in, t_out = _parse_clock(check_in), _parse_clock(check_out)
    if not t_in or not t_out:
        return "—", "—"
    minutes = (t_out.hour * 60 + t_out.minute) - (t_in.hour * 60 + t_in.minute)
    if minutes < 0:
        minutes += 24 * 60  # overnight shift, just in case
    total_hours = minutes / 60
    extra = max(0.0, total_hours - standard_hours)
    return _fmt_hm(total_hours), _fmt_hm(extra)


def check_in(user_id: int):
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user["checked_in"]:
            return False, "Already checked in."
        now = datetime.now()
        today = now.date().isoformat()
        time_str = now.strftime("%I:%M %p")
        conn.execute(
            "INSERT INTO attendance (user_id, date, check_in) VALUES (?, ?, ?)",
            (user_id, today, time_str),
        )
        conn.execute(
            "UPDATE users SET checked_in = 1, check_in_time = ? WHERE id = ?",
            (time_str, user_id),
        )
        conn.commit()
        return True, time_str
    finally:
        conn.close()


def check_out(user_id: int):
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user["checked_in"]:
            return False, "Not checked in."
        now = datetime.now()
        today = now.date().isoformat()
        time_str = now.strftime("%I:%M %p")
        conn.execute(
            "UPDATE attendance SET check_out = ? WHERE user_id = ? AND date = ? "
            "AND check_out IS NULL",
            (time_str, user_id, today),
        )
        conn.execute(
            "UPDATE users SET checked_in = 0, check_in_time = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        return True, time_str
    finally:
        conn.close()


def get_recent_attendance(user_id: int, limit: int = 5):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM attendance WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def _row_with_hours(row, standard_hours=STANDARD_SHIFT_HOURS):
    d = dict(row)
    work, extra = _work_extra_hours(d.get("check_in"), d.get("check_out"), standard_hours)
    d["work_hours"] = work
    d["extra_hours"] = extra
    return d


def get_attendance_for_user(user_id: int):
    """Full history for an employee's own Attendance page (used as a
    fallback / by other callers that don't need month-scoping)."""
    conn = get_db()
    try:
        user = conn.execute("SELECT working_hours FROM users WHERE id = ?", (user_id,)).fetchone()
        standard = (user["working_hours"] if user else None) or STANDARD_SHIFT_HOURS
        rows = conn.execute(
            "SELECT * FROM attendance WHERE user_id = ? ORDER BY date DESC",
            (user_id,),
        ).fetchall()
        return [_row_with_hours(r, standard) | {"emp_id": user_id} for r in rows]
    finally:
        conn.close()


def get_attendance_for_month(user_id: int, year: int, month: int):
    """Day-wise attendance for one employee, scoped to a calendar month —
    'On the Attendance page, users should see a day-wise attendance ...
    for ongoing month' per the wireframe note."""
    conn = get_db()
    try:
        user = conn.execute("SELECT working_hours FROM users WHERE id = ?", (user_id,)).fetchone()
        standard = (user["working_hours"] if user else None) or STANDARD_SHIFT_HOURS
        prefix = f"{year:04d}-{month:02d}"
        rows = conn.execute(
            "SELECT * FROM attendance WHERE user_id = ? AND date LIKE ? ORDER BY date DESC",
            (user_id, f"{prefix}%"),
        ).fetchall()
        return [_row_with_hours(r, standard) | {"emp_id": user_id} for r in rows]
    finally:
        conn.close()


def get_month_attendance_stats(user_id: int, year: int, month: int):
    """Backs the 'Count of days present / Leaves count / Total working
    days' chips on the employee Attendance page."""
    import calendar as _cal
    conn = get_db()
    try:
        prefix = f"{year:04d}-{month:02d}"
        present = conn.execute(
            "SELECT COUNT(DISTINCT date) AS c FROM attendance WHERE user_id = ? AND date LIKE ?",
            (user_id, f"{prefix}%"),
        ).fetchone()["c"]

        days_in_month = _cal.monthrange(year, month)[1]
        month_start = date(year, month, 1).isoformat()
        month_end = date(year, month, days_in_month).isoformat()

        leave_rows = conn.execute(
            "SELECT from_date, to_date FROM leave_requests WHERE user_id = ? "
            "AND status = 'approved' AND from_date <= ? AND to_date >= ?",
            (user_id, month_end, month_start),
        ).fetchall()
        leaves_count = 0
        for r in leave_rows:
            start = max(date.fromisoformat(r["from_date"]), date(year, month, 1))
            end = min(date.fromisoformat(r["to_date"]), date(year, month, days_in_month))
            if end >= start:
                leaves_count += (end - start).days + 1

        working_days = sum(
            1 for d in range(1, days_in_month + 1)
            if date(year, month, d).weekday() < 5  # Mon–Fri
        )

        return {"present": present, "leaves": leaves_count, "working_days": working_days}
    finally:
        conn.close()


def get_month_calendar(user_id: int, year: int, month: int):
    """Day-by-day status for one employee's Physical Calendar view.

    Returns one dict per calendar day of the month:
      {day, date, status, checked_in_time, checked_out_time}
    status is one of: 'present', 'absent', 'leave', 'weekend', 'future'.
    'weekend' / 'future' are just muted, non-working-day markers — the
    Present/Absent/Leave colouring only applies to actual past/today
    working days, per the wireframe's day-wise attendance rules.
    """
    import calendar as _cal
    conn = get_db()
    try:
        days_in_month = _cal.monthrange(year, month)[1]
        today = date.today()
        prefix = f"{year:04d}-{month:02d}"

        att_rows = conn.execute(
            "SELECT date, check_in, check_out FROM attendance "
            "WHERE user_id = ? AND date LIKE ?",
            (user_id, f"{prefix}%"),
        ).fetchall()
        attendance_by_date = {r["date"]: r for r in att_rows}

        month_start = date(year, month, 1).isoformat()
        month_end = date(year, month, days_in_month).isoformat()
        leave_rows = conn.execute(
            "SELECT from_date, to_date FROM leave_requests WHERE user_id = ? "
            "AND status = 'approved' AND from_date <= ? AND to_date >= ?",
            (user_id, month_end, month_start),
        ).fetchall()
        leave_dates = set()
        for r in leave_rows:
            start = max(date.fromisoformat(r["from_date"]), date(year, month, 1))
            end = min(date.fromisoformat(r["to_date"]), date(year, month, days_in_month))
            d = start
            while d <= end:
                leave_dates.add(d.isoformat())
                d += timedelta(days=1)

        days = []
        for day_num in range(1, days_in_month + 1):
            d = date(year, month, day_num)
            d_str = d.isoformat()
            att = attendance_by_date.get(d_str)

            if att:
                status = "present"
            elif d_str in leave_dates:
                status = "leave"
            elif d > today:
                status = "future"
            elif d.weekday() >= 5:
                status = "weekend"
            else:
                status = "absent"

            days.append({
                "day": day_num,
                "date": d_str,
                "status": status,
                "check_in": att["check_in"] if att else None,
                "check_out": att["check_out"] if att else None,
            })
        return days
    finally:
        conn.close()


def get_all_attendance(company_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT a.*, u.working_hours AS standard_hours,
                      (u.first_name || ' ' || u.last_name) AS emp_name
               FROM attendance a
               JOIN users u ON u.id = a.user_id
               WHERE u.company_id = ? ORDER BY a.date DESC, a.id DESC""",
            (company_id,),
        ).fetchall()
        out = []
        for r in rows:
            d = _row_with_hours(r, r["standard_hours"] or STANDARD_SHIFT_HOURS)
            d["emp_id"] = r["user_id"]
            d["emp_name"] = r["emp_name"]
            out.append(d)
        return out
    finally:
        conn.close()


def get_attendance_for_date(company_id: int, date_str: str, query: str = ""):
    """Day-view for HR/Admin: 'Admins/Time off officers can see attendance
    of all employees present on the current day', with an employee
    searchbar per the wireframe."""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT a.*, u.working_hours AS standard_hours,
                      (u.first_name || ' ' || u.last_name) AS emp_name
               FROM attendance a
               JOIN users u ON u.id = a.user_id
               WHERE u.company_id = ? AND a.date = ?
               ORDER BY u.first_name""",
            (company_id, date_str),
        ).fetchall()
        q = (query or "").strip().lower()
        out = []
        for r in rows:
            if q and q not in (r["emp_name"] or "").lower():
                continue
            d = _row_with_hours(r, r["standard_hours"] or STANDARD_SHIFT_HOURS)
            d["emp_id"] = r["user_id"]
            d["emp_name"] = r["emp_name"]
            out.append(d)
        return out
    finally:
        conn.close()


def employees_by_id(company_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT id, first_name, last_name FROM users WHERE company_id = ?",
            (company_id,),
        ).fetchall()
        return {
            r["id"]: {"name": f"{r['first_name']} {r['last_name']}".strip()}
            for r in rows
        }
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Leave requests (Time Off)
# ----------------------------------------------------------------------
LEAVE_TYPES = ["Paid Time Off", "Sick Leave", "Unpaid Leaves"]

# Sample public holidays shown on the Time Off year calendar. Static
# placeholder data per the wireframe — a real deployment would source
# these from a company calendar / HR settings.
PUBLIC_HOLIDAYS_BY_YEAR = {
    2026: [
        ("2026-01-14", "Kite Festival"),
        ("2026-01-26", "Republic Day"),
        ("2026-03-04", "Dhuleti"),
        ("2026-08-15", "Independence Day"),
        ("2026-08-28", "Rakhi"),
        ("2026-10-02", "Gandhi Jayanti"),
        ("2026-11-08", "Diwali"),
        ("2026-11-10", "New Year"),
        ("2026-11-11", "Bhai Duj"),
    ],
}


def get_public_holidays(year: int):
    return PUBLIC_HOLIDAYS_BY_YEAR.get(year, [])


def get_year_leave_calendar(user_id: int, year: int):
    """Full-year, month-by-month Time Off calendar for one employee —
    mirrors the wireframe's 'Validated / To Approve / Refused' legend
    plus public holidays. Returns 12 month dicts:
      {month, label, weeks: [[{day, date, in_month, status,
                                is_holiday, holiday_name, is_today}, ...]]}
    """
    import calendar as _cal
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT from_date, to_date, status FROM leave_requests WHERE user_id = ?",
            (user_id,),
        ).fetchall()

        status_priority = {"approved": 3, "pending": 2, "rejected": 1}
        status_label = {"approved": "validated", "pending": "to_approve", "rejected": "refused"}
        day_status = {}
        for r in rows:
            try:
                start = date.fromisoformat(r["from_date"])
                end = date.fromisoformat(r["to_date"])
            except ValueError:
                continue
            if end < start:
                continue
            d = start
            while d <= end:
                if d.year == year:
                    ds = d.isoformat()
                    cur = day_status.get(ds)
                    if not cur or status_priority[r["status"]] > status_priority[cur]:
                        day_status[ds] = r["status"]
                d += timedelta(days=1)

        holidays = dict(get_public_holidays(year))
        today = date.today()
        cal = _cal.Calendar(firstweekday=6)  # weeks start Sunday, per wireframe (S M T W T F S)

        months = []
        for month in range(1, 13):
            weeks = []
            for week in cal.monthdatescalendar(year, month):
                week_cells = []
                for d in week:
                    in_month = d.month == month
                    d_str = d.isoformat()
                    week_cells.append({
                        "day": d.day,
                        "date": d_str,
                        "in_month": in_month,
                        "status": status_label.get(day_status.get(d_str)) if in_month else None,
                        "is_holiday": in_month and d_str in holidays,
                        "holiday_name": holidays.get(d_str) if in_month else None,
                        "is_today": in_month and d == today,
                    })
                weeks.append(week_cells)
            months.append({"month": month, "label": _cal.month_name[month], "weeks": weeks})
        return months
    finally:
        conn.close()


def get_leave_balances(user_id: int):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT paid_leave_balance, sick_leave_balance FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        return {
            "paid": row["paid_leave_balance"] if row else 0,
            "sick": row["sick_leave_balance"] if row else 0,
        }
    finally:
        conn.close()


def create_leave_request(user_id: int, leave_type: str, from_date: str,
                          to_date: str, reason: str, attachment_path: str = None):
    if leave_type not in LEAVE_TYPES:
        leave_type = "Paid Time Off"
    conn = get_db()
    try:
        now = datetime.now().isoformat()
        conn.execute(
            """INSERT INTO leave_requests
               (user_id, from_date, to_date, reason, status, created_at,
                leave_type, attachment_path)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)""",
            (user_id, from_date, to_date, reason, now, leave_type, attachment_path),
        )
        conn.commit()
        return True, None
    finally:
        conn.close()


def _leave_row_to_dict(r):
    return {
        "id": r["id"], "emp_id": r["user_id"],
        "name": r["emp_name"] if "emp_name" in r.keys() else None,
        "from": r["from_date"], "to": r["to_date"],
        "reason": r["reason"], "status": r["status"],
        "leave_type": r["leave_type"] if "leave_type" in r.keys() else "Paid Time Off",
        "attachment_path": r["attachment_path"] if "attachment_path" in r.keys() else None,
    }


def get_leave_requests_for_user(user_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT lr.*, (u.first_name || ' ' || u.last_name) AS emp_name
               FROM leave_requests lr JOIN users u ON u.id = lr.user_id
               WHERE lr.user_id = ? ORDER BY lr.id DESC""",
            (user_id,),
        ).fetchall()
        return [_leave_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def get_all_leave_requests(company_id: int):
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT lr.*, (u.first_name || ' ' || u.last_name) AS emp_name
               FROM leave_requests lr
               JOIN users u ON u.id = lr.user_id
               WHERE u.company_id = ? ORDER BY lr.id DESC""",
            (company_id,),
        ).fetchall()
        return [_leave_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def leave_action(req_id: int, action: str):
    """Approve or reject a leave request. Only ever called from a route
    guarded by @hr_required, so approving/rejecting is Admin/HR-only."""
    status = "approved" if action == "approve" else "rejected"
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM leave_requests WHERE id = ?", (req_id,)
        ).fetchone()
        if not row:
            return False, "Leave request not found."
        if row["status"] != "pending":
            return False, "This request has already been reviewed."

        conn.execute(
            "UPDATE leave_requests SET status = ? WHERE id = ?", (status, req_id)
        )
        if status == "approved":
            days = (date.fromisoformat(row["to_date"]) - date.fromisoformat(row["from_date"])).days + 1
            leave_type = row["leave_type"] if "leave_type" in row.keys() else "Paid Time Off"
            if leave_type == "Sick Leave":
                conn.execute(
                    "UPDATE users SET sick_leave_balance = MAX(0, sick_leave_balance - ?) WHERE id = ?",
                    (days, row["user_id"]),
                )
            elif leave_type == "Paid Time Off":
                conn.execute(
                    "UPDATE users SET paid_leave_balance = MAX(0, paid_leave_balance - ?) WHERE id = ?",
                    (days, row["user_id"]),
                )
            # Unpaid Leaves: no balance to deduct from.
        conn.commit()
        return True, None
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Salary (Admin-only tab) — computed from a single "Monthly Wage" input,
# per the wireframe's automatic-calculation note.
# ----------------------------------------------------------------------
def update_salary(user_id: int, wage_monthly: float, working_days_per_week: int,
                   working_hours: float):
    """HR/Admin-only edit of an employee's salary inputs; salary components
    themselves stay auto-computed from these via compute_salary()."""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET wage_monthly = ?, working_days_per_week = ?, "
            "working_hours = ? WHERE id = ?",
            (max(0.0, wage_monthly), max(1, working_days_per_week),
             max(0.0, working_hours), user_id),
        )
        conn.commit()
        return True
    finally:
        conn.close()


PF_RATE = 0.12          # 12% of Basic, per wireframe
PROFESSIONAL_TAX = 200  # flat, per wireframe

def compute_salary(wage_monthly: float):
    wage = wage_monthly or 0
    basic = round(wage * 0.50, 2)
    hra = round(basic * 0.50, 2)
    standard_allowance = round(wage * 0.10, 2)
    performance_bonus = round(wage * 0.05, 2)
    leave_travel_allowance = round(wage * 0.05, 2)
    fixed_allowance = round(max(0.0, wage - (basic + hra + standard_allowance
                                              + performance_bonus + leave_travel_allowance)), 2)

    pf_employee = round(basic * PF_RATE, 2)
    pf_employer = round(basic * PF_RATE, 2)

    components = [
        {"label": "Basic", "value": basic, "note": "50% of wage"},
        {"label": "House Rent Allowance (HRA)", "value": hra, "note": "50% of Basic"},
        {"label": "Standard Allowance", "value": standard_allowance, "note": "10% of wage"},
        {"label": "Performance Bonus", "value": performance_bonus, "note": "5% of wage"},
        {"label": "Leave Travel Allowance", "value": leave_travel_allowance, "note": "5% of wage"},
        {"label": "Fixed Allowance", "value": fixed_allowance, "note": "Remainder of wage"},
    ]

    return {
        "yearly_wage": wage * 12,
        "components": components,
        "pf": {"rate": f"{int(PF_RATE * 100)}%", "employee": pf_employee, "employer": pf_employer},
        "professional_tax": PROFESSIONAL_TAX,
    }
