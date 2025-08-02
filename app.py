from flask import Flask, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
import os
from logging_config import setup_logging

# Load environment variables and setup logging
load_dotenv("webhook.env")
setup_logging()

def ensure_current_database():
    """Ensure current month database exists on startup"""
    try:
        # Import here to avoid circular imports
        from utils import get_monthly_db_path
        
        db_path = get_monthly_db_path()
        print(f"[STARTUP] Current database: {db_path}")
        
        # Test a simple query to make sure table exists
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM prediction_logs")
            count = cursor.fetchone()[0]
            print(f"[STARTUP] ✅ Database ready with {count} records")
            
    except Exception as e:
        print(f"[STARTUP] ⚠️ Database issue detected: {e}")
        print(f"[STARTUP] 🔧 Auto-fixing...")
        # Try to create manually if import fails
        try:
            import sqlite3
            from datetime import datetime, timezone
            
            current_month = datetime.now(timezone.utc).strftime('%Y%m')
            db_path = f"prediction_logs_{current_month}.db"
            
            if not os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute('''CREATE TABLE prediction_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    log_month TEXT,
                    anomaly INTEGER,
                    explanation TEXT,
                    network_packet_size REAL,
                    login_attempts INTEGER,
                    session_duration REAL,
                    ip_reputation_score REAL,
                    failed_logins INTEGER,
                    unusual_time_access INTEGER,
                    protocol_type_ICMP INTEGER DEFAULT 0,
                    protocol_type_TCP INTEGER DEFAULT 1,
                    protocol_type_UDP INTEGER DEFAULT 0,
                    encryption_used_AES INTEGER DEFAULT 1,
                    encryption_used_DES INTEGER DEFAULT 0,
                    browser_type_Chrome INTEGER DEFAULT 0,
                    browser_type_Edge INTEGER DEFAULT 0,
                    browser_type_Firefox INTEGER DEFAULT 0,
                    browser_type_Safari INTEGER DEFAULT 0,
                    browser_type_Unknown INTEGER DEFAULT 0,
                    risk_score REAL,
                    anomaly_score REAL,
                    profile_used TEXT,
                    user_role TEXT,
                    confidence TEXT,
                    method_used TEXT,
                    baseline_used INTEGER DEFAULT 1
                )''')
                conn.commit()
                conn.close()
                print(f"[STARTUP] ✅ Emergency database created: {db_path}")
        except Exception as emergency_e:
            print(f"[STARTUP] ❌ Emergency fix failed: {emergency_e}")

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["SECRET_KEY"]
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.prediction import prediction_bp
    from routes.dashboard import dashboard_bp
    from routes.admin import admin_bp
    from routes.data_feeds import data_feeds_bp
    from routes.ml_performance import ml_performance_bp  # ADD THIS LINE
    from routes.user import user_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(data_feeds_bp)
    app.register_blueprint(ml_performance_bp)  # ADD THIS LINE
    app.register_blueprint(user_bp)
    
    # Context processor for template variables
    @app.context_processor
    def inject_environment():
        return dict(is_azure='azurewebsites.net' in request.host)
    
    # Root route redirect
    @app.route('/')
    def index():
        if 'username' in session:
            return redirect(url_for('dashboard.dashboard'))
        else:
            return redirect(url_for('auth.login'))
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {"status": "healthy", "service": "anomaly_detection"}, 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "Not Found", 
            "message": "The requested resource was not found on this server.",
            "status_code": 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred on the server.",
            "status_code": 500
        }), 500
    
    return app

if __name__ == '__main__':
    import sqlite3  # Add this import
    
    # Ensure database is ready before starting
    ensure_current_database()
    
    app = create_app()
    
    # Development server configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    
    print(f"Starting Flask application on {host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, debug=debug_mode)