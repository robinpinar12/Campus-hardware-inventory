import os
import re
import csv
import sqlite3
import logging
import smtplib
import bcrypt
from email.message import EmailMessage
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, ValidationError

DB_FILE = "Database.db"

# Logging setup
LOG_DIR = "app_logging"
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "app.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("HardwareApp")

# Pydantic Schema
class HardwareSchema(BaseModel):
    item_name: str = Field(..., min_length=2, max_length=100)
    category: str = Field(..., min_length=1)
    quantity: int = Field(..., ge=0)

# Database Utilities
def get_db_connection():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def column_exists(conn, table_name, column_name):
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [row[1] for row in cursor.fetchall()]
    return column_name in columns

def determine_status(quantity):
    if quantity > 5:
        return "In Stock"
    elif quantity >= 1:
        return "Low Stock"
    return "Out of Stock"

def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'USER',
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                is_locked INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hardware (
                item_id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS equipment_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                item_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL,
                start_time TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'PENDING',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (item_id) REFERENCES hardware(item_id) ON DELETE CASCADE
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_reset_requests (
                request_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TIMESTAMP,
                reviewed_by TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

# Validation & Password Helpers
def validate_password_complexity(password):
    pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
    return bool(re.match(pattern, password))

def validate_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return bool(re.match(pattern, email))

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password, password_hash):
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False

# Controller Classes for Flask Integration
class AuthController:
    @staticmethod
    def login_user(username, password):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, password_hash, role, failed_attempts, is_locked, email FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if not user:
                return False, "Invalid username or password.", None, False, None
            user_id, db_user, pass_hash, role, failed, is_locked, email = user
            if is_locked:
                return False, "Account locked due to 3 failed attempts.", None, True, email
            if verify_password(password, pass_hash):
                cursor.execute("UPDATE users SET failed_attempts = 0 WHERE id = ?", (user_id,))
                conn.commit()
                return True, f"Welcome back, {db_user}!", role, False, email
            else:
                attempts = failed + 1
                locked = 1 if attempts >= 3 else 0
                cursor.execute("UPDATE users SET failed_attempts = ?, is_locked = ? WHERE id = ?", (attempts, locked, user_id))
                conn.commit()
                if locked:
                    return False, "Account locked due to 3 failed attempts.", None, True, email
                return False, f"Invalid credentials. Attempts left: {max(0, 3 - attempts)}", None, False, email

    @staticmethod
    def register_user(username, email, password, role="USER"):
        if len(username) < 3 or not validate_email(email) or not validate_password_complexity(password):
            return False, "Validation failed. Check password requirements and email format."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
            if cursor.fetchone():
                return False, "Username or Email already registered."
            cursor.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                           (username, email, hash_password(password), role))
            conn.commit()
        return True, "Account registered successfully."

    @staticmethod
    def submit_password_reset_request(username, email, new_password):
        if not validate_email(email) or not validate_password_complexity(new_password):
            return False, "Invalid email or password complexity standard not met."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ? AND email = ?", (username, email))
            user = cursor.fetchone()
            if not user:
                return False, "No matching account found with that username and email."
            user_id = user[0]
            cursor.execute("SELECT request_id FROM password_reset_requests WHERE user_id = ? AND status = 'PENDING'", (user_id,))
            if cursor.fetchone():
                return False, "A password reset request is already pending."
            cursor.execute("INSERT INTO password_reset_requests (user_id, email, status) VALUES (?, ?, 'PENDING')", (user_id, email))
            conn.commit()
        return True, "Password reset request submitted for Admin approval."

    @staticmethod
    def get_pending_resets():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, u.username, r.email, r.requested_at 
                FROM password_reset_requests r 
                JOIN users u ON r.user_id = u.id 
                WHERE r.status = 'PENDING'
            """)
            return cursor.fetchall()

    @staticmethod
    def process_bulk_resets(request_ids, approve=True):
        if not request_ids:
            return False, "No reset requests selected."
        status_val = "APPROVED" if approve else "REJECTED"
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for r_id in request_ids:
                cursor.execute("UPDATE password_reset_requests SET status = ?, reviewed_at = CURRENT_TIMESTAMP WHERE request_id = ?", (status_val, r_id))
            conn.commit()
        return True, f"Reset requests {status_val.lower()} successfully."

    @staticmethod
    def change_password_direct(username, email, old_password, new_password):
        if not validate_password_complexity(new_password):
            return False, "New password does not meet complexity standards."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row or not verify_password(old_password, row[1]):
                return False, "Incorrect current password."
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), row[0]))
            conn.commit()
        return True, "Password updated successfully."

class InventoryController:
    @staticmethod
    def get_all_items(search_text="", category="ALL"):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT item_id, item_name, category, quantity, status FROM hardware WHERE 1=1"
            params = []
            if search_text:
                query += " AND (item_name LIKE ? OR category LIKE ?)"
                params.extend([f"%{search_text}%", f"%{search_text}%"])
            if category and category != "ALL":
                query += " AND category = ?"
                params.append(category)
            cursor.execute(query, params)
            return cursor.fetchall()

    @staticmethod
    def get_categories():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT DISTINCT category FROM hardware")
            return [row[0] for row in cursor.fetchall()]

    @staticmethod
    def borrow_item(username, item_id, quantity):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            if not user:
                return False, "User account not found."
            user_id = user[0]

            cursor.execute("SELECT quantity FROM hardware WHERE item_id = ?", (item_id,))
            item = cursor.fetchone()
            if not item:
                return False, "Item not found."
            avail_qty = item[0]

            if quantity > avail_qty:
                return False, f"Requested quantity ({quantity}) exceeds available stock ({avail_qty})."

            cursor.execute("""
                INSERT INTO equipment_requests (user_id, item_id, quantity, start_time, status)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'PENDING')
            """, (user_id, item_id, quantity))
            conn.commit()
        return True, "Borrow request submitted successfully and is pending Admin approval."

    @staticmethod
    def get_user_active_loans(username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, h.item_name, r.quantity, r.start_time 
                FROM equipment_requests r
                JOIN hardware h ON r.item_id = h.item_id
                JOIN users u ON r.user_id = u.id
                WHERE u.username = ? AND r.status IN ('APPROVED', 'BORROWED')
            """, (username,))
            return cursor.fetchall()

    @staticmethod
    def get_user_pending_borrows(username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, h.item_name, r.quantity, r.requested_at 
                FROM equipment_requests r
                JOIN hardware h ON r.item_id = h.item_id
                JOIN users u ON r.user_id = u.id
                WHERE u.username = ? AND r.status = 'PENDING'
            """, (username,))
            return cursor.fetchall()

    @staticmethod
    def get_user_loan_history(username):
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, h.item_name, r.quantity, r.start_time, r.end_time, r.status 
                FROM equipment_requests r
                JOIN hardware h ON r.item_id = h.item_id
                JOIN users u ON r.user_id = u.id
                WHERE u.username = ?
                ORDER BY r.request_id DESC
            """, (username,))
            return cursor.fetchall()

    @staticmethod
    def request_bulk_item_returns(loan_ids):
        if not loan_ids:
            return False, "No borrowed items selected for return."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for l_id in loan_ids:
                cursor.execute("UPDATE equipment_requests SET status = 'RETURN_PENDING' WHERE request_id = ? AND status IN ('APPROVED', 'BORROWED')", (l_id,))
            conn.commit()
        return True, "Return request submitted for Admin approval."

    @staticmethod
    def get_pending_borrows():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, u.username, h.item_name, r.quantity, r.requested_at 
                FROM equipment_requests r
                JOIN users u ON r.user_id = u.id
                JOIN hardware h ON r.item_id = h.item_id
                WHERE r.status = 'PENDING'
            """)
            return cursor.fetchall()

    @staticmethod
    def get_pending_returns():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, u.username, h.item_name, r.quantity, r.start_time 
                FROM equipment_requests r
                JOIN users u ON r.user_id = u.id
                JOIN hardware h ON r.item_id = h.item_id
                WHERE r.status = 'RETURN_PENDING'
            """)
            return cursor.fetchall()

    @staticmethod
    def process_bulk_borrows(loan_ids, approve=True):
        if not loan_ids:
            return False, "No borrow requests selected."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for l_id in loan_ids:
                cursor.execute("SELECT item_id, quantity, status FROM equipment_requests WHERE request_id = ?", (l_id,))
                req = cursor.fetchone()
                if req and req[2] == "PENDING":
                    item_id, req_qty, _ = req
                    if approve:
                        cursor.execute("SELECT quantity FROM hardware WHERE item_id = ?", (item_id,))
                        stock = cursor.fetchone()[0]
                        if req_qty > stock:
                            continue
                        new_qty = stock - req_qty
                        cursor.execute("UPDATE hardware SET quantity = ?, status = ? WHERE item_id = ?", (new_qty, determine_status(new_qty), item_id))
                        cursor.execute("UPDATE equipment_requests SET status = 'BORROWED', reviewed_at = CURRENT_TIMESTAMP WHERE request_id = ?", (l_id,))
                    else:
                        cursor.execute("UPDATE equipment_requests SET status = 'REJECTED', reviewed_at = CURRENT_TIMESTAMP WHERE request_id = ?", (l_id,))
            conn.commit()
        return True, "Borrow requests processed successfully."

    @staticmethod
    def process_bulk_returns(loan_ids, approve=True):
        if not loan_ids:
            return False, "No return requests selected."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for l_id in loan_ids:
                cursor.execute("SELECT item_id, quantity, status FROM equipment_requests WHERE request_id = ?", (l_id,))
                req = cursor.fetchone()
                if req and req[2] == "RETURN_PENDING":
                    item_id, req_qty, _ = req
                    if approve:
                        cursor.execute("SELECT quantity FROM hardware WHERE item_id = ?", (item_id,))
                        stock = cursor.fetchone()[0]
                        new_qty = stock + req_qty
                        cursor.execute("UPDATE hardware SET quantity = ?, status = ? WHERE item_id = ?", (new_qty, determine_status(new_qty), item_id))
                        cursor.execute("UPDATE equipment_requests SET status = 'RETURNED', end_time = CURRENT_TIMESTAMP WHERE request_id = ?", (l_id,))
                    else:
                        cursor.execute("UPDATE equipment_requests SET status = 'BORROWED' WHERE request_id = ?", (l_id,))
            conn.commit()
        return True, "Return requests processed successfully."

    @staticmethod
    def get_all_loans_history():
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.request_id, u.username, h.item_name, r.quantity, r.start_time, r.end_time, r.status 
                FROM equipment_requests r
                JOIN users u ON r.user_id = u.id
                JOIN hardware h ON r.item_id = h.item_id
                ORDER BY r.request_id DESC
            """)
            return cursor.fetchall()

    @staticmethod
    def add_item(name, category, quantity, unit_price=0.0):
        try:
            item_data = HardwareSchema(item_name=name, category=category, quantity=quantity)
        except ValidationError as ve:
            return False, f"Validation error: {ve}"
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT item_id FROM hardware WHERE LOWER(item_name) = LOWER(?)", (item_data.item_name,))
            if cursor.fetchone():
                return False, "An item with this name already exists."
            cursor.execute("INSERT INTO hardware (item_name, category, quantity, status) VALUES (?, ?, ?, ?)",
                           (item_data.item_name, item_data.category, item_data.quantity, determine_status(item_data.quantity)))
            conn.commit()
        return True, "Equipment added successfully."

    @staticmethod
    def delete_bulk_items(item_ids):
        if not item_ids:
            return False, "No equipment selected for deletion."
        with get_db_connection() as conn:
            cursor = conn.cursor()
            for item_id in item_ids:
                cursor.execute("DELETE FROM hardware WHERE item_id = ?", (item_id,))
            conn.commit()
        return True, "Selected equipment deleted successfully."

    @staticmethod
    def export_to_csv(username):
        filename = "inventory_report.csv"
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT item_id, item_name, category, quantity, status FROM hardware")
                rows = cursor.fetchall()
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Item ID", "Name", "Category", "Quantity", "Status"])
                writer.writerows(rows)
            return True, "Report generated."
        except Exception as e:
            return False, str(e)

# ISOLATE TKINTER INTERFACE (DESKTOP ONLY - Retained for original desktop version)
"""
if __name__ == '__main__':
    root = tk.Tk()
    init_db()
    show_login_window()
    root.mainloop()
"""