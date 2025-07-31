#!/usr/bin/env python3
"""
Migration script to create historical_logs table
Run this once to fix the "no such table: historical_logs" error
"""

import sqlite3
import os
from datetime import datetime

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def migrate_database():
    """Create historical_logs table in current database"""
    
    db_path = get_monthly_db_path()
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        print("Please run database_setup.py first")
        return False
    
    print(f"🔧 Migrating database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Check if historical_logs table exists
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='historical_logs'")
        if c.fetchone():
            print("✅ historical_logs table already exists")
            conn.close()
            return True
        
        # Create historical_logs table
        print("🔨 Creating historical_logs table...")
        c.execute('''CREATE TABLE historical_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            log_month TEXT,
            anomaly INTEGER,
            explanation TEXT,
            network_packet_size INTEGER,
            login_attempts INTEGER,
            session_duration REAL,
            ip_reputation_score REAL,
            failed_logins INTEGER,
            unusual_time_access INTEGER,
            protocol_type_ICMP INTEGER,
            protocol_type_TCP INTEGER,
            protocol_type_UDP INTEGER,
            encryption_used_AES INTEGER,
            encryption_used_DES INTEGER,
            browser_type_Chrome INTEGER,
            browser_type_Edge INTEGER,
            browser_type_Firefox INTEGER,
            browser_type_Safari INTEGER,
            browser_type_Unknown INTEGER,
            risk_score REAL,
            anomaly_score REAL,
            profile_used TEXT,
            user_role TEXT,
            archived_at TEXT
        )''')
        
        conn.commit()
        conn.close()
        
        print("✅ historical_logs table created successfully!")
        print("🎯 You can now use the Static Report without errors")
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False

if __name__ == '__main__':
    print("🚀 Starting database migration...")
    success = migrate_database()
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("\nNext steps:")
        print("1. Restart your Flask application")
        print("2. Visit /report - it should work now")
        print("3. Use 'Clear Predictions' - data will be preserved in Static Report")
    else:
        print("\n❌ Migration failed!")
        print("Please check the error messages above")