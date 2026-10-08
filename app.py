import os
import csv
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from Laboratorysystem import DatabaseManager, AuthSystem, InventoryManager, AuthController

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "campus_inventory_secret_key_123")

import smtplib
import random
from email.mime.text import MIMEText

# --- BREVO SMTP CONFIGURATION ---
SMTP_SERVER = "smtp-relay.brevo.com"
SMTP_PORT = 587
# TODO: Replace these with your actual Brevo SMTP Login and Master Password
SMTP_LOGIN = "bd2e52001@smtp-brevo.com"       
SMTP_PASSWORD = "bskiMPbwNPRyOyb"  

def send_otp_email(receiver_email, otp, intent):
    """Sends a 6-digit OTP using Brevo SMTP."""
    msg = MIMEText(f"Your {intent} One-Time Password (OTP) is: {otp}\n\nPlease enter this code to proceed. Do not share this code with anyone.")
    msg['Subject'] = f"Laboratory System - {intent} OTP"
    msg['From'] = "your-actual-email@gmail.com"  # Replace with your verified Brevo email
    msg['To'] = receiver_email
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_LOGIN, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

db_mgr = DatabaseManager()
auth_sys = AuthSystem(db_mgr)
inv_mgr = InventoryManager(db_mgr)


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        success, msg, user = auth_sys.authenticate(username, password)
        if success:
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Welcome back!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash(msg, "error")
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "USER").strip().upper()
    if not username or not email or not password:
        flash("All registration fields are required.", "danger")
        return redirect(url_for("register"))
    # Generate OTP and save to session
    otp = str(random.randint(100000, 999999))
    session['pending_user'] = {'username': username, 'email': email, 'password': password, 'role': role, 'otp': otp}
    
    if send_otp_email(email, otp, intent="Account Registration"):
        flash("We sent a 6-digit code to your email. Please verify.", "info")
        return redirect(url_for("verify_otp", action="register"))
    else:
        flash("Failed to send OTP email. Please try again.", "danger")
        return redirect(url_for("register"))

@app.route("/reset-request", methods=["GET", "POST"])
def reset_request():
    if request.method == "GET":
        return render_template("reset.html")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    if not username or not email or not new_password or not confirm_password:
        flash("All reset fields are required.", "danger")
        return redirect(url_for("reset_request"))
    if new_password != confirm_password:
        flash("New passwords do not match.", "danger")
        return redirect(url_for("reset_request"))
    # Generate OTP and save to session
    otp = str(random.randint(100000, 999999))
    session['pending_reset'] = {'username': username, 'email': email, 'new_password': new_password, 'otp': otp}
    
    if send_otp_email(email, otp, intent="Password Reset"):
        flash("We sent a 6-digit code to your email. Please verify.", "info")
        return redirect(url_for("verify_otp", action="reset"))
    else:
        flash("Failed to send OTP email. Please try again.", "danger")
        return redirect(url_for("reset_request"))

@app.route("/verify-otp/<action>", methods=["GET", "POST"])
def verify_otp(action):
    # Determine which session data to use
    session_key = 'pending_user' if action == "register" else 'pending_reset'
        
    if session_key not in session:
        flash("Session expired. Please try again.", "warning")
        return redirect(url_for("login"))
        
    if request.method == "POST":
        user_otp = request.form.get("otp_code", "").strip()
        data = session[session_key]
        
        if user_otp == data['otp']:
            if action == "register":
                # OTP matches, create the user
                ok, msg = AuthController.register_user(data['username'], data['email'], data['password'], role=data['role'])
                session.pop(session_key, None)
                flash("Account successfully verified and created!", "success" if ok else "warning")
                return redirect(url_for("login"))
                
            elif action == "reset":
                # OTP matches, submit the reset request to Admin
                ok, msg = AuthController.submit_password_reset_request(data['username'], data['email'], data['new_password'])
                session.pop(session_key, None)
                flash("Email verified! Your password reset request has been submitted.", "success" if ok else "danger")
                return redirect(url_for("login"))
        else:
            flash("Invalid OTP code. Try again.", "danger")
            
    return render_template("otp_verify.html", action_url=url_for('verify_otp', action=action))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "")
    category = request.args.get("category", "ALL")
    status = request.args.get("status", "ALL")

    p = db_mgr.is_postgres
    query = "SELECT * FROM hardware WHERE 1=1"
    params = []

    if search:
        query += " AND item_name ILIKE %s" if p else " AND item_name LIKE ?"
        params.append(f"%{search}%")
    if category != "ALL":
        query += " AND category = %s" if p else " AND category = ?"
        params.append(category)
    if status != "ALL":
        query += " AND status = %s" if p else " AND status = ?"
        params.append(status)

    query += " ORDER BY item_id ASC"
    hardware_list = db_mgr.query_all(query, tuple(params))

    if session["role"] == "ADMIN":
        borrow_query = "SELECT * FROM loans ORDER BY loan_id DESC"
        borrow_requests = db_mgr.query_all(borrow_query)
    else:
        borrow_query = "SELECT * FROM loans WHERE username = %s ORDER BY loan_id DESC" if p else "SELECT * FROM loans WHERE username = ? ORDER BY loan_id DESC"
        borrow_requests = db_mgr.query_all(borrow_query, (session["username"],))

    return render_template("dashboard.html", 
                           user=session["username"], 
                           role=session["role"],
                           hardware=hardware_list,
                           borrow_requests=borrow_requests,
                           search=search, category=category, status=status)


@app.route("/add_hardware", methods=["POST"])
def add_hardware():
    if session.get("role") != "ADMIN":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    item_name = request.form.get("item_name")
    category = request.form.get("category")
    quantity = int(request.form.get("quantity", 0))
    unit_price = float(request.form.get("unit_price", 0.0))

    inv_mgr.add_item(item_name, category, quantity, unit_price)
    flash("Hardware item added successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/edit_hardware/<int:item_id>", methods=["POST"])
def edit_hardware(item_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    item_name = request.form.get("item_name")
    category = request.form.get("category")
    quantity = int(request.form.get("quantity", 0))
    unit_price = float(request.form.get("unit_price", 0.0))

    inv_mgr.update_item(item_id, item_name, category, quantity, unit_price)
    flash("Hardware item updated successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/delete_hardware/<int:item_id>", methods=["POST"])
def delete_hardware(item_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    inv_mgr.delete_item(item_id)
    flash("Hardware item deleted successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/request_borrow", methods=["POST"])
def request_borrow():
    if "username" not in session:
        return redirect(url_for("login"))

    item_id = int(request.form.get("item_id"))
    qty = int(request.form.get("quantity", 1))

    p = db_mgr.is_postgres
    item = db_mgr.query_one("SELECT * FROM hardware WHERE item_id = %s" if p else "SELECT * FROM hardware WHERE item_id = ?", (item_id,))

    if not item or item["quantity"] < qty:
        flash("Requested quantity unavailable.", "error")
        return redirect(url_for("dashboard"))

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    q = "INSERT INTO loans (username, item_id, item_name, borrow_date, quantity, status) VALUES (%s, %s, %s, %s, %s, %s)" if p else "INSERT INTO loans (username, item_id, item_name, borrow_date, quantity, status) VALUES (?, ?, ?, ?, ?, ?)"
    db_mgr.execute(q, (session["username"], item_id, item["item_name"], now, qty, "PENDING"))

    flash("Borrow request submitted.", "success")
    return redirect(url_for("dashboard"))


@app.route("/approve_borrow/<int:borrow_id>", methods=["POST"])
def approve_borrow(borrow_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    p = db_mgr.is_postgres
    loan = db_mgr.query_one("SELECT * FROM loans WHERE loan_id = %s" if p else "SELECT * FROM loans WHERE loan_id = ?", (borrow_id,))

    if loan and loan["status"] == "PENDING":
        item = db_mgr.query_one("SELECT * FROM hardware WHERE item_id = %s" if p else "SELECT * FROM hardware WHERE item_id = ?", (loan["item_id"],))
        if item and item["quantity"] >= loan["quantity"]:
            new_qty = item["quantity"] - loan["quantity"]
            inv_mgr.update_item(item["item_id"], item["item_name"], item["category"], new_qty, item["unit_price"])

            q = "UPDATE loans SET status = 'APPROVED' WHERE loan_id = %s" if p else "UPDATE loans SET status = 'APPROVED' WHERE loan_id = ?"
            db_mgr.execute(q, (borrow_id,))
            flash("Borrow request approved.", "success")
        else:
            flash("Insufficient stock to approve request.", "error")
    return redirect(url_for("dashboard"))


@app.route("/reject_borrow/<int:borrow_id>", methods=["POST"])
def reject_borrow(borrow_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    p = db_mgr.is_postgres
    q = "UPDATE loans SET status = 'REJECTED' WHERE loan_id = %s" if p else "UPDATE loans SET status = 'REJECTED' WHERE loan_id = ?"
    db_mgr.execute(q, (borrow_id,))
    flash("Borrow request rejected.", "info")
    return redirect(url_for("dashboard"))


@app.route("/request_return/<int:borrow_id>", methods=["POST"])
def request_return(borrow_id):
    if "username" not in session:
        return redirect(url_for("login"))

    p = db_mgr.is_postgres
    q = "UPDATE loans SET status = 'RETURN_PENDING' WHERE loan_id = %s AND username = %s" if p else "UPDATE loans SET status = 'RETURN_PENDING' WHERE loan_id = ? AND username = ?"
    db_mgr.execute(q, (borrow_id, session["username"]))
    flash("Return request submitted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/approve_return/<int:borrow_id>", methods=["POST"])
def approve_return(borrow_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    p = db_mgr.is_postgres
    loan = db_mgr.query_one("SELECT * FROM loans WHERE loan_id = %s" if p else "SELECT * FROM loans WHERE loan_id = ?", (borrow_id,))

    if loan and loan["status"] == "RETURN_PENDING":
        item = db_mgr.query_one("SELECT * FROM hardware WHERE item_id = %s" if p else "SELECT * FROM hardware WHERE item_id = ?", (loan["item_id"],))
        if item:
            new_qty = item["quantity"] + loan["quantity"]
            inv_mgr.update_item(item["item_id"], item["item_name"], item["category"], new_qty, item["unit_price"])

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        q = "UPDATE loans SET status = 'RETURNED', return_date = %s WHERE loan_id = %s" if p else "UPDATE loans SET status = 'RETURNED', return_date = ? WHERE loan_id = ?"
        db_mgr.execute(q, (now, borrow_id))
        flash("Return confirmed and stock updated.", "success")

    return redirect(url_for("dashboard"))


@app.route("/admin_approvals")
def admin_approvals():
    if session.get("role") != "ADMIN":
        flash("Unauthorized access.", "error")
        return redirect(url_for("dashboard"))

    requests = db_mgr.query_all("SELECT * FROM password_resets ORDER BY request_id DESC")
    return render_template("dashboard.html", 
                           user=session["username"], 
                           role=session["role"],
                           show_approvals=True, 
                           requests=requests)


@app.route("/approve_request/<int:req_id>", methods=["POST"])
def approve_request(req_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    p = db_mgr.is_postgres
    req_data = db_mgr.query_one("SELECT * FROM password_resets WHERE request_id = %s" if p else "SELECT * FROM password_resets WHERE request_id = ?", (req_id,))

    if req_data and req_data["status"] == "PENDING":
        up_usr = "UPDATE users SET password_hash = %s, failed_attempts = 0, is_locked = 0 WHERE username = %s" if p else "UPDATE users SET password_hash = ?, failed_attempts = 0, is_locked = 0 WHERE username = ?"
        db_mgr.execute(up_usr, (req_data["new_password_hash"], req_data["username"]))

        up_req = "UPDATE password_resets SET status = 'APPROVED' WHERE request_id = %s" if p else "UPDATE password_resets SET status = 'APPROVED' WHERE request_id = ?"
        db_mgr.execute(up_req, (req_id,))

        flash(f"Password reset approved for {req_data['username']}.", "success")

    return redirect(url_for("admin_approvals"))


@app.route("/reject_request/<int:req_id>", methods=["POST"])
def reject_request(req_id):
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    p = db_mgr.is_postgres
    q = "UPDATE password_resets SET status = 'REJECTED' WHERE request_id = %s" if p else "UPDATE password_resets SET status = 'REJECTED' WHERE request_id = ?"
    db_mgr.execute(q, (req_id,))

    flash("Password reset request rejected.", "info")
    return redirect(url_for("admin_approvals"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "username" not in session:
        return redirect(url_for("login"))

    p = db_mgr.is_postgres
    user_info = db_mgr.query_one("SELECT * FROM users WHERE username = %s" if p else "SELECT * FROM users WHERE username = ?", (session["username"],))

    if request.method == "POST":
        current_pw = request.form.get("current_password")
        new_pw = request.form.get("new_password")
        confirm_pw = request.form.get("confirm_password")

        if not auth_sys.verify_password(current_pw, user_info["password_hash"]):
            flash("Current password incorrect.", "error")
        elif new_pw != confirm_pw:
            flash("New passwords do not match.", "error")
        else:
            new_hash = auth_sys.hash_password(new_pw)
            q = "UPDATE users SET password_hash = %s WHERE username = %s" if p else "UPDATE users SET password_hash = ? WHERE username = ?"
            db_mgr.execute(q, (new_hash, session["username"]))
            flash("Password updated successfully.", "success")

    return render_template("dashboard.html", user=session["username"], role=session["role"], show_profile=True, user_info=user_info)


@app.route("/export_csv")
def export_csv():
    if session.get("role") != "ADMIN":
        flash("Unauthorized.", "error")
        return redirect(url_for("dashboard"))

    hardware_list = inv_mgr.get_all_hardware()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Item Name", "Category", "Quantity", "Unit Price (PHP)", "Status"])

    for item in hardware_list:
        writer.writerow([item["item_id"], item["item_name"], item["category"], item["quantity"], item["unit_price"], item["status"]])

    response = Response(output.getvalue(), mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=hardware_inventory_report.csv"
    return response


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)