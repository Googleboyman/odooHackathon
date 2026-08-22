# HR Management System — Sign In / Sign Up

A Flask app implementing the Sign In / Sign Up flow from your wireframe
and SRS excerpt.

## Setup

```bash
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000/signin**

The SQLite database (`hrms.db`) is created automatically on first run.

## What's implemented

**Sign Up page** (`/signup`) — matches your wireframe field order:
Company Name + logo upload → Name → Email → Phone → Password → Confirm
Password. This registers the **Company** and its first **HR/Admin**
account (self-service). Per your note, ordinary users can't register
themselves beyond this — every other account is created *by* HR from
inside the system.

**Sign In page** (`/signin`) — Login ID/Email → Password → Sign In.
Accepts either the auto-generated Login ID or the user's email.
Incorrect credentials show an error message; success redirects to the
dashboard (SRS 3.1.2).

**Login ID auto-generation** (`models.py`) — implements your exact rule:

```
[Company Code][First 2 letters of first + last name][Year of joining][Serial]
Example: OIJODO20260001
```

- Company code is derived from the company name (e.g. "Odoo India" → "OI").
- Serial numbers restart at 1 each year, per company.
- Used both at Sign Up (for the HR admin) and when HR creates an
  employee (`/employees/new`), exactly as your note specifies.

**Auto-generated passwords** — when HR creates an employee, the system
generates a temporary password. The employee is forced to `/change-password`
on their first login, per your note ("They can login and change the
system generated password").

**Password rules** — 8+ characters, upper/lower/number/symbol, enforced
on both Sign Up and Change Password.

## Files

```
app.py                        Flask routes
models.py                     DB schema + ID/password generation logic
templates/signin.html         Sign In page
templates/signup.html         Sign Up page
templates/change_password.html
templates/dashboard.html
templates/new_employee.html   HR-only: create employee
static/style.css              Dark theme matching your wireframe
```

## Extending it

This covers Sign In/Sign Up only, as requested. Natural next steps per
your SRS: email verification on signup, leave/attendance modules for
Employee and HR roles, and payroll views for HR.
