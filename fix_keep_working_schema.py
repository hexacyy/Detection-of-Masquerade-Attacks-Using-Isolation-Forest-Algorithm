#!/usr/bin/env python3
"""
fix_keep_working_schema.py - Fix database while keeping the working schema structure
"""

import sqlite3
import os
from datetime import datetime

def get_current_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime("%Y%m")
    return f"prediction_logs_{current_month}.db"

def fix_prediction_logs_table():
    """Fix the table to match the working schema you showed"""
    db_path = get_current_db_path()
    
    # Backup current database
    if os.path.exists(db_path):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{db_path}.backup_{timestamp}"
        import shutil
        shutil.copy2(db_path, backup_path)
        print(f"📦 Backed up to: {backup_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check current table structure
    cursor.execute("PRAGMA table_info(prediction_logs)")
    current_columns = [col[1] for col in cursor.fetchall()]
    print(f"📋 Current columns: {len(current_columns)}")
    
    # The WORKING schema from your old table
    working_schema_columns = [
        'id INTEGER PRIMARY KEY AUTOINCREMENT',
        'timestamp TEXT',
        'log_month TEXT',
        'anomaly INTEGER',
        'explanation TEXT',
        'network_packet_size REAL',
        'login_attempts INTEGER',
        'session_duration REAL',
        'ip_reputation_score REAL',
        'failed_logins INTEGER',
        'unusual_time_access INTEGER',
        'protocol_type_ICMP INTEGER DEFAULT 0',
        'protocol_type_TCP INTEGER DEFAULT 1',
        'protocol_type_UDP INTEGER DEFAULT 0',
        'encryption_used_AES INTEGER DEFAULT 1',
        'encryption_used_DES INTEGER DEFAULT 0',
        'browser_type_Chrome INTEGER DEFAULT 0',
        'browser_type_Edge INTEGER DEFAULT 0',
        'browser_type_Firefox INTEGER DEFAULT 0',
        'browser_type_Safari INTEGER DEFAULT 0',
        'browser_type_Unknown INTEGER DEFAULT 0',
        'risk_score REAL',
        'anomaly_score REAL',
        'profile_used TEXT',
        'user_role TEXT',
        # Add the missing columns that were causing errors
        'input_data TEXT',
        'confidence TEXT',
        'method_used TEXT',
        'baseline_used INTEGER DEFAULT 1'
    ]
    
    # Drop the messy table and recreate with working schema
    print("🗑️ Dropping messy table...")
    cursor.execute("DROP TABLE IF EXISTS prediction_logs")
    
    # Create the working table structure
    create_table_sql = f"CREATE TABLE prediction_logs ({', '.join(working_schema_columns)})"
    cursor.execute(create_table_sql)
    
    print("✅ Created table with working schema")
    
    # Verify the new structure
    cursor.execute("PRAGMA table_info(prediction_logs)")
    new_columns = cursor.fetchall()
    print(f"📋 New schema ({len(new_columns)} columns):")
    for i, col in enumerate(new_columns, 1):
        print(f"  {i:2d}. {col[1]} ({col[2]})")
    
    conn.commit()
    conn.close()
    print(f"✅ Fixed database: {db_path}")

if __name__ == "__main__":
    print("🔧 Fixing Database - Keeping Working Schema")
    print("=" * 50)
    fix_prediction_logs_table()
    print("\n🎉 Database fix completed!")
    print("Your prediction route should now work with the proper schema.")