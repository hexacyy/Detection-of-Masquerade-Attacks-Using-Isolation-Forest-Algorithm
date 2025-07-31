# routes/user.py - NEW FILE
"""
Enhanced User Management Routes
Self-service password changes and security features
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import check_password_hash, generate_password_hash
import sqlite3
import secrets
import string
from datetime import datetime, timedelta
from utils import login_required, is_strong_password
from config import DB_FILE

user_bp = Blueprint('user', __name__, url_prefix='/user')

def log_security_event(user_id, username, action, details, success=True, ip_address=None):
    """Log security events to audit table"""
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""INSERT INTO security_audit_log 
                     (user_id, username, action, details, success, ip_address, timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                 (user_id, username, action, details, int(success), 
                  ip_address or request.remote_addr, datetime.now().isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERROR] Failed to log security event: {e}")

def check_password_history(user_id, new_password_hash, history_limit=5):
    """Check if password was used recently"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""SELECT password_hash FROM password_history 
                 WHERE user_id = ? ORDER BY created_at DESC LIMIT ?""",
              (user_id, history_limit))
    recent_passwords = c.fetchall()
    conn.close()
    
    for (old_hash,) in recent_passwords:
        if check_password_hash(old_hash, new_password_hash):
            return False  # Password was used recently
    return True

def save_password_to_history(user_id, password_hash):
    """Save password to history table"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)""",
              (user_id, password_hash))
    
    # Keep only last 10 passwords
    c.execute("""DELETE FROM password_history WHERE user_id = ? AND id NOT IN (
                 SELECT id FROM password_history WHERE user_id = ? 
                 ORDER BY created_at DESC LIMIT 10)""",
              (user_id, user_id))
    conn.commit()
    conn.close()

@user_bp.route('/change_password', methods=['GET', 'POST'])
@login_required()
def change_password():
    """Self-service password change"""
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        user_id = session.get('user_id')
        username = session.get('username')
        
        # Validate new password
        if new_password != confirm_password:
            flash("❌ New passwords don't match.", "danger")
            log_security_event(user_id, username, "PASSWORD_CHANGE_FAILED", 
                             "Passwords don't match", False)
            return render_template("change_password.html")
            
        if not is_strong_password(new_password):
            flash("❌ Password must be at least 12 characters and include uppercase, lowercase, numbers, and symbols.", "danger")
            log_security_event(user_id, username, "PASSWORD_CHANGE_FAILED", 
                             "Weak password", False)
            return render_template("change_password.html")
        
        # Verify current password
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        
        if not user or not check_password_hash(user[1], current_password):
            flash("❌ Current password is incorrect.", "danger")
            log_security_event(user_id, username, "PASSWORD_CHANGE_FAILED", 
                             "Incorrect current password", False)
            conn.close()
            return render_template("change_password.html")
        
        # Check password history (prevent reuse)
        new_password_hash = generate_password_hash(new_password)
        if not check_password_history(user[0], new_password):
            flash("❌ You cannot reuse a recent password. Please choose a different password.", "danger")
            log_security_event(user_id, username, "PASSWORD_CHANGE_FAILED", 
                             "Password reuse attempt", False)
            conn.close()
            return render_template("change_password.html")
        
        # Update password
        current_time = datetime.now().isoformat()
        c.execute("""UPDATE users SET 
                     password_hash = ?, 
                     password_changed_at = ?,
                     must_change_password = 0,
                     temp_password_expires = NULL
                     WHERE id = ?""", 
                 (new_password_hash, current_time, user[0]))
        conn.commit()
        conn.close()
        
        # Save to password history
        save_password_to_history(user[0], new_password_hash)
        
        flash("✅ Password changed successfully!", "success")
        log_security_event(user_id, username, "PASSWORD_CHANGED", 
                         "User changed their own password", True)
        
        return redirect(url_for('dashboard.dashboard'))
    
    return render_template("change_password.html")

@user_bp.route('/profile')
@login_required()
def user_profile():
    """User profile page with security information"""
    username = session.get('username')
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Get user info
    c.execute("""SELECT id, username, role, created_at, password_changed_at, 
                        last_login_at, last_login_ip, failed_login_attempts
                 FROM users WHERE username = ?""", (username,))
    user_info = c.fetchone()
    
    # Get recent security events
    c.execute("""SELECT action, details, timestamp, success, ip_address
                 FROM security_audit_log 
                 WHERE username = ? 
                 ORDER BY timestamp DESC LIMIT 10""", (username,))
    recent_activity = c.fetchall()
    
    # Get active sessions (if any)
    c.execute("""SELECT created_at, last_activity, ip_address, user_agent
                 FROM user_sessions 
                 WHERE username = ? AND is_active = 1
                 ORDER BY last_activity DESC""", (username,))
    active_sessions = c.fetchall()
    
    conn.close()
    
    return render_template("user_profile.html", 
                         user_info=user_info,
                         recent_activity=recent_activity,
                         active_sessions=active_sessions)

# Add these routes to your existing routes/admin.py file

def generate_secure_temp_password(length=16):
    """Generate a secure temporary password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Ensure at least one character from each category
    categories = [
        string.ascii_lowercase,
        string.ascii_uppercase, 
        string.digits,
        "!@#$%^&*"
    ]
    
    password = []
    for category in categories:
        password.append(secrets.choice(category))
    
    # Fill the rest randomly
    for _ in range(length - len(categories)):
        password.append(secrets.choice(alphabet))
    
    # Shuffle the password
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)

