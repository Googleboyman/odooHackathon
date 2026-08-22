import os
import secrets as _secrets
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash, jsonify
)
from werkzeug.utils import secure_filename

import models

app = Flask(__name__)
# Generate a fresh secret key on every process start unless one is pinned
# via HRMS_SECRET_KEY. This means every server restart invalidates any
# session cookies left over in a browser from a previous run — no stale
# "still logged in" cookies surviving between test sessions.
app.secret_key = os.environ.get("HRMS_SECRET_KEY") or _secrets.token_hex(32)

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_LOGO_EXT = {"png", "jpg", "jpeg", "gif", "svg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Initialize (and migrate) the database at import time rather than only
# under `if __name__ == "__main__"`. That guard never runs when the app
# is launched any other way (e.g. `flask run`, gunicorn, most hosting
# platforms), which left the users/companies/etc. tables never created —
# every sign up, employee creation, and login would silently fail against
# a database with no tables. init_db()/its migrations are idempotent
# (CREATE TABLE IF NOT EXISTS, ALTER TABLE guarded against duplicate
# columns), so it's safe to run on every import.
models.init_db()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_LOGO_EXT
    )


@app.route("/")
def index():
    """Root URL: send signed-in users straight to their dashboard, and
    everyone else to sign in (which links to Sign up for new companies).
    Without this, http://127.0.0.1:5000/ 404s and only /signup works."""
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("signin"))


@app.context_processor
def inject_current_user_picture():
    # Makes the signed-in user's profile picture available to every
    # template (used by the avatar button in the top nav), without
    # bloating the session cookie with a file path.
    picture = None
    if "user_id" in session:
        row = models.get_user(session["user_id"])
        if row:
            picture = row["profile_picture"]
    return {"current_user_picture": picture}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "error")
            return redirect(url_for("signin"))
        return view(*args, **kwargs)
    return wrapped


def hr_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("role") != "HR":
            flash("Only HR/Admin can perform that action.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def add_no_cache_headers(response):
    # Prevents the browser's back/forward cache from ever re-displaying a
    # protected page (Employees, Attendance, Leave, Profile, ...) after
    # the user has logged out.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


# ----------------------------------------------------------------------
# Sign up / Sign in / Sign out
# ----------------------------------------------------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        full_name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not all([company_name, full_name, email, phone, password]):
            flash("Please fill in all fields.", "error")
            return render_template("signup.html", form=request.form)

        if password != confirm_password:
            flash("Password and Confirm Password do not match.", "error")
            return render_template("signup.html", form=request.form)

        name_parts = full_name.split(maxsplit=1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        logo_path = None
        logo_file = request.files.get("logo")
        if logo_file and logo_file.filename:
            if allowed_file(logo_file.filename):
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
                filename = secure_filename(logo_file.filename)
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                logo_file.save(save_path)
                logo_path = f"uploads/{filename}"
            else:
                flash("Logo must be an image file (png, jpg, jpeg, gif, svg).",
                      "error")
                return render_template("signup.html", form=request.form)

        login_id, error = models.create_company_and_hr(
            company_name, first_name, last_name, email, phone,
            password, logo_path,
        )

        if error:
            flash(error, "error")
            return render_template("signup.html", form=request.form)

        flash(
            f"Account created! Your system-generated Login ID is "
            f"{login_id}. Please sign in.",
            "success",
        )
        return redirect(url_for("signin"))

    return render_template("signup.html", form={})


@app.route("/signin", methods=["GET", "POST"])
def signin():
    # Always show the Sign In page itself, exactly as designed — no
    # silent redirect away from it, even if a session already exists.
    if request.method == "POST":
        identifier = request.form.get("login_id", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter your Login ID/Email and Password.", "error")
            return render_template("signin.html")

        user, error = models.verify_login(identifier, password)
        if error:
            # Per spec 3.1.2: "Incorrect credentials should display error
            # messages."
            flash(error, "error")
            return render_template("signin.html")

        session["user_id"] = user["id"]
        session["login_id"] = user["login_id"]
        session["name"] = f"{user['first_name']} {user['last_name']}".strip()
        session["role"] = user["role"]
        session["company_id"] = user["company_id"]

        if user["must_change_password"]:
            flash(
                "This is your first login with a system-generated "
                "password. Please set a new password.",
                "info",
            )
            return redirect(url_for("change_password"))

        # Per spec 3.1.2: "Successful login redirects to the dashboard" —
        # HR/Admin lands on the Employees dashboard, everyone else on
        # their own personal dashboard.
        return redirect(url_for("dashboard"))

    return render_template("signin.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("signin"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("change_password.html", target=None)

        ok, msg = models.change_password(session["user_id"], new_password)
        if not ok:
            flash(msg, "error")
            return render_template("change_password.html", target=None)

        flash("Password updated successfully. Please sign in again.",
              "success")
        session.clear()
        return redirect(url_for("signin"))

    return render_template("change_password.html", target=None)


@app.route("/profile/<int:emp_id>/change-password", methods=["GET", "POST"])
@login_required
@hr_required
def admin_change_password(emp_id):
    row = models.get_user(emp_id)
    if not row or row["company_id"] != session["company_id"]:
        flash("Employee not found.", "error")
        return redirect(url_for("admin_dashboard"))

    target = {
        "id": row["id"],
        "name": f"{row['first_name']} {row['last_name']}".strip(),
    }

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("change_password.html", target=target)

        # force_change=True: the employee must set their own password
        # again on next login, same as a freshly-created account.
        ok, msg = models.change_password(row["id"], new_password, force_change=True)
        if not ok:
            flash(msg, "error")
            return render_template("change_password.html", target=target)

        flash(f"Password reset for {target['name']}. They'll be asked to "
              f"set their own on next login.", "success")
        return redirect(url_for("profile", emp_id=row["id"]))

    return render_template("change_password.html", target=target)


# ----------------------------------------------------------------------
# Dashboard — splits into the two wireframed views:
#   HR/Admin    -> employee directory grid  (admin_dashboard.html)
#   Employee    -> personal dashboard        (employee_dashboard.html)
# ----------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "HR":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("employee_dashboard"))


@app.route("/dashboard/employees")
@login_required
@hr_required
def admin_dashboard():
    query = request.args.get("q", "")
    employees = models.list_employees(session["company_id"], query)
    return render_template("admin_dashboard.html", employees=employees, query=query)


@app.route("/dashboard/me")
@login_required
def employee_dashboard():
    row = models.get_user(session["user_id"])
    user = {
        "id": row["id"],
        "name": f"{row['first_name']} {row['last_name']}".strip(),
        "checked_in": bool(row["checked_in"]),
        "check_in_time": row["check_in_time"],
        "leave_balance": row["leave_balance"],
    }
    recent = models.get_recent_attendance(row["id"])
    return render_template("employee_dashboard.html", user=user, recent=recent)


# ----------------------------------------------------------------------
# Check in / Check out (used by both dashboards' avatar/card actions)
# ----------------------------------------------------------------------
@app.route("/attendance/checkin", methods=["POST"])
@login_required
def attendance_checkin():
    ok, result = models.check_in(session["user_id"])
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify(ok=ok, time=result if ok else None, error=None if ok else result)
    if not ok:
        flash(result, "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/attendance/checkout", methods=["POST"])
@login_required
def attendance_checkout():
    ok, result = models.check_out(session["user_id"])
    if request.headers.get("X-Requested-With") == "fetch":
        return jsonify(ok=ok, time=result if ok else None, error=None if ok else result)
    if not ok:
        flash(result, "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/attendance")
@login_required
def attendance():
    from datetime import date, timedelta
    import calendar as _cal

    if session["role"] == "HR":
        q = request.args.get("q", "")
        try:
            selected_date = date.fromisoformat(request.args.get("date", ""))
        except ValueError:
            selected_date = date.today()
        records = models.get_attendance_for_date(session["company_id"], selected_date.isoformat(), q)

        # --- Physical Calendar: HR/Admin picks any employee to view ---
        today = date.today()
        employees_map = models.employees_by_id(session["company_id"])
        employees = sorted(
            ({"id": eid, "name": info["name"]} for eid, info in employees_map.items()),
            key=lambda e: e["name"].lower(),
        )

        cal_emp_id = request.args.get("emp_id", type=int)
        if cal_emp_id not in employees_map:
            cal_emp_id = employees[0]["id"] if employees else None

        try:
            cal_year = int(request.args.get("cal_year", today.year))
            cal_month = int(request.args.get("cal_month", today.month))
        except ValueError:
            cal_year, cal_month = today.year, today.month

        calendar_days = models.get_month_calendar(cal_emp_id, cal_year, cal_month) if cal_emp_id else []
        leading_blanks = (date(cal_year, cal_month, 1).weekday() + 1) % 7  # Sun-first offset
        cal_prev_month, cal_prev_year = (12, cal_year - 1) if cal_month == 1 else (cal_month - 1, cal_year)
        cal_next_month, cal_next_year = (1, cal_year + 1) if cal_month == 12 else (cal_month + 1, cal_year)

        return render_template(
            "attendance.html",
            is_admin=True,
            records=records,
            query=q,
            selected_date=selected_date,
            prev_date=(selected_date - timedelta(days=1)).isoformat(),
            next_date=(selected_date + timedelta(days=1)).isoformat(),
            employees=employees,
            cal_emp_id=cal_emp_id,
            cal_emp_name=employees_map[cal_emp_id]["name"] if cal_emp_id in employees_map else "",
            cal_year=cal_year,
            cal_month=cal_month,
            cal_month_label=f"{_cal.month_name[cal_month]} {cal_year}",
            cal_prev_year=cal_prev_year, cal_prev_month=cal_prev_month,
            cal_next_year=cal_next_year, cal_next_month=cal_next_month,
            calendar_days=calendar_days,
            leading_blanks=leading_blanks,
        )

    today = date.today()
    try:
        year = int(request.args.get("year", today.year))
        month = int(request.args.get("month", today.month))
    except ValueError:
        year, month = today.year, today.month

    records = models.get_attendance_for_month(session["user_id"], year, month)
    stats = models.get_month_attendance_stats(session["user_id"], year, month)
    prev_month, prev_year = (12, year - 1) if month == 1 else (month - 1, year)
    next_month, next_year = (1, year + 1) if month == 12 else (month + 1, year)
    calendar_days = models.get_month_calendar(session["user_id"], year, month)
    leading_blanks = (date(year, month, 1).weekday() + 1) % 7  # Sun-first offset

    return render_template(
        "attendance.html",
        is_admin=False,
        records=records,
        stats=stats,
        month_label=f"{_cal.month_name[month]} {year}",
        prev_year=prev_year, prev_month=prev_month,
        next_year=next_year, next_month=next_month,
        calendar_days=calendar_days,
        leading_blanks=leading_blanks,
        cal_month_label=f"{_cal.month_name[month]} {year}",
    )


# ----------------------------------------------------------------------
# Leave requests (Time Off)
# ----------------------------------------------------------------------
ALLOWED_ATTACHMENT_EXT = {"png", "jpg", "jpeg", "gif", "pdf"}


def _allowed_attachment(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_ATTACHMENT_EXT


@app.route("/leave", methods=["GET", "POST"])
@login_required
def leave():
    from datetime import date
    if request.method == "POST":
        if session["role"] == "HR":
            flash("HR/Admin reviews requests here rather than filing new ones.", "error")
            return redirect(url_for("leave"))

        leave_type = request.form.get("leave_type", "Paid Time Off")
        from_date = request.form.get("from_date", "")
        to_date = request.form.get("to_date", "")
        reason = request.form.get("reason", "")

        if not from_date or not to_date:
            flash("Please choose both a start and end date.", "error")
            return redirect(url_for("leave"))

        attachment_path = None
        attachment_file = request.files.get("attachment")
        if attachment_file and attachment_file.filename:
            if not _allowed_attachment(attachment_file.filename):
                flash("Attachment must be an image or PDF.", "error")
                return redirect(url_for("leave"))
            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
            filename = secure_filename(f"leave_{session['user_id']}_{_secrets.token_hex(4)}_{attachment_file.filename}")
            attachment_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            attachment_path = f"uploads/{filename}"
        elif leave_type == "Sick Leave":
            flash("Please attach a sick leave certificate.", "error")
            return redirect(url_for("leave"))

        models.create_leave_request(session["user_id"], leave_type, from_date, to_date, reason, attachment_path)
        flash("Time off request submitted.", "success")
        return redirect(url_for("leave"))

    is_admin = session["role"] == "HR"
    if is_admin:
        requests_ = models.get_all_leave_requests(session["company_id"])
        balances = None
        year_calendar = None
        cal_year = None
        holidays = None
    else:
        requests_ = models.get_leave_requests_for_user(session["user_id"])
        balances = models.get_leave_balances(session["user_id"])
        try:
            cal_year = int(request.args.get("year", date.today().year))
        except ValueError:
            cal_year = date.today().year
        year_calendar = models.get_year_leave_calendar(session["user_id"], cal_year)
        holidays = models.get_public_holidays(cal_year)

    return render_template(
        "leave.html",
        requests=requests_,
        is_admin=is_admin,
        balances=balances,
        leave_types=models.LEAVE_TYPES,
        year_calendar=year_calendar,
        cal_year=cal_year,
        holidays=holidays,
    )


@app.route("/leave/<int:req_id>/<action>", methods=["POST"])
@login_required
@hr_required
def leave_action(req_id, action):
    if action not in ("approve", "reject"):
        flash("Unknown action.", "error")
        return redirect(url_for("leave"))
    ok, error = models.leave_action(req_id, action)
    if not ok:
        flash(error, "error")
    else:
        flash(f"Leave request {action}d.", "success")
    return redirect(url_for("leave"))


# ----------------------------------------------------------------------
# Profile — own profile, or (HR only) a read-only view of any employee
# ----------------------------------------------------------------------
@app.route("/profile")
@app.route("/profile/<int:emp_id>")
@login_required
def profile(emp_id=None):
    target_id = emp_id or session["user_id"]
    if target_id != session["user_id"] and session["role"] != "HR":
        flash("You can only view your own profile.", "error")
        return redirect(url_for("dashboard"))

    row = models.get_user(target_id)
    if not row or row["company_id"] != session["company_id"]:
        flash("Employee not found.", "error")
        return redirect(url_for("dashboard"))

    is_self = target_id == session["user_id"]
    view_only = not is_self  # HR viewing someone else's profile: read-only
    show_salary_tab = session["role"] == "HR"  # per wireframe: admin-only tab

    target = dict(row)
    target["name"] = f"{row['first_name']} {row['last_name']}".strip()
    target["mobile"] = row["phone"]  # profile.html field name

    salary = models.compute_salary(row["wage_monthly"]) if show_salary_tab else None

    return render_template(
        "profile.html",
        target=target,
        is_self=is_self,
        view_only=view_only,
        show_salary_tab=show_salary_tab,
        salary=salary,
    )


@app.route("/profile/<int:emp_id>/salary", methods=["POST"])
@login_required
@hr_required
def update_salary(emp_id):
    target = models.get_user(emp_id)
    if not target or target["company_id"] != session["company_id"]:
        flash("Employee not found.", "error")
        return redirect(url_for("admin_dashboard"))

    try:
        wage_monthly = float(request.form.get("wage_monthly", "0") or 0)
        working_days_per_week = int(request.form.get("working_days_per_week", "5") or 5)
        working_hours = float(request.form.get("working_hours", "8") or 8)
    except ValueError:
        flash("Please enter valid numbers for salary fields.", "error")
        return redirect(url_for("profile", emp_id=emp_id))

    if wage_monthly < 0 or working_hours <= 0 or not (1 <= working_days_per_week <= 7):
        flash("Salary values are out of range.", "error")
        return redirect(url_for("profile", emp_id=emp_id))

    models.update_salary(emp_id, wage_monthly, working_days_per_week, working_hours)
    flash("Salary updated.", "success")
    return redirect(url_for("profile", emp_id=emp_id))


@app.route("/profile/picture", methods=["POST"])
@login_required
def update_profile_picture():
    picture_file = request.files.get("profile_picture")
    if not picture_file or not picture_file.filename:
        flash("Please choose an image to upload.", "error")
        return redirect(url_for("profile"))

    if not allowed_file(picture_file.filename):
        flash("Profile picture must be an image file (png, jpg, jpeg, gif, svg).",
              "error")
        return redirect(url_for("profile"))

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    filename = secure_filename(
        f"avatar_{session['user_id']}_{_secrets.token_hex(4)}_{picture_file.filename}"
    )
    picture_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    picture_path = f"uploads/{filename}"

    models.update_profile_picture(session["user_id"], picture_path)
    flash("Profile picture updated.", "success")
    return redirect(url_for("profile"))


# ----------------------------------------------------------------------
# HR creates a new Employee (auto Login ID + auto temp password)
# ----------------------------------------------------------------------
@app.route("/employees/new", methods=["GET", "POST"])
@login_required
@hr_required
def new_employee():
    created = None
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        role = request.form.get("role", "Employee")

        if not all([first_name, email]):
            flash("First name and email are required.", "error")
            return render_template("new_employee.html", created=None)

        login_id, temp_password, error = models.create_employee(
            session["company_id"], first_name, last_name, email, phone, role
        )
        if error:
            flash(error, "error")
            return render_template("new_employee.html", created=None)

        created = {
            "login_id": login_id,
            "temp_password": temp_password,
            "email": email,
        }

    return render_template("new_employee.html", created=created)


if __name__ == "__main__":
    app.run(debug=True)
