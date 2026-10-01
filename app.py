import os
import csv
import io
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from Laboratorysystem import DatabaseManager, AuthSystem, InventoryManager

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "campus_inventory_secret_key_123")

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
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_pw = request.form.get("confirm_password")
        role = request.form.get("role", "USER")

        if password != confirm_pw:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        success, msg = auth_sys.register_user(username, email, password, role)
        if success:
            flash("Registration successful. Please login.", "success")
            return redirect(url_for("login"))
        else:
            flash(msg, "error")
    return render_template("register.html")


@app.route("/reset", methods=["GET", "POST"])
def reset_request():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        new_password = request.form.get("new_password")
        
        pw_hash = auth_sys.hash_password(new_password)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        p = db_mgr.is_postgres
        q = "INSERT INTO password_resets (username, email, new_password_hash, request_time, status) VALUES (%s, %s, %s, %s, %s)" if p else "INSERT INTO password_resets (username, email, new_password_hash, request_time, status) VALUES (?, ?, ?, ?, ?)"
        db_mgr.execute(q, (username, email, pw_hash, now, "PENDING"))

        flash("Password reset request submitted. Awaiting Admin Approval.", "info")
        return redirect(url_for("login"))
    return render_template("reset.html")


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