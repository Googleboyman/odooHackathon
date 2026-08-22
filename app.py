import os
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, session, flash
)
from werkzeug.utils import secure_filename

import models

app = Flask(__name__)
app.secret_key = os.environ.get("HRMS_SECRET_KEY", "dev-secret-change-me")

UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
ALLOWED_LOGO_EXT = {"png", "jpg", "jpeg", "gif", "svg"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_LOGO_EXT
    )

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

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip()
        full_name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- basic field validation ---
        if not all([company_name, full_name, email, phone, password]):
            flash("Please fill in all fields.", "error")
            return render_template("signup.html", form=request.form)

        if password != confirm_password:
            flash("Password and Confirm Password do not match.", "error")
            return render_template("signup.html", form=request.form)

        name_parts = full_name.split(maxsplit=1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        # --- optional logo upload ---
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

# Sign In
@app.route("/signin", methods=["GET", "POST"])
def signin():
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

        # Per spec 3.1.2: "Successful login redirects to the dashboard."
        return redirect(url_for("dashboard"))

    return render_template("signin.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("signin"))

# Forced password change (for system-auto-generated passwords)
@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("change_password.html")

        ok, msg = models.change_password(session["user_id"], new_password)
        if not ok:
            flash(msg, "error")
            return render_template("change_password.html")

        flash("Password updated successfully. Please sign in again.",
              "success")
        session.clear()
        return redirect(url_for("signin"))

    return render_template("change_password.html")

# Dashboard (placeholder landing page after login)
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template(
        "dashboard.html",
        name=session.get("name"),
        login_id=session.get("login_id"),
        role=session.get("role"),
    )

# HR creates a new Employee (auto Login ID + auto temp password)
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
    models.init_db()
    app.run(debug=True)
