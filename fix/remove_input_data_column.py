#!/usr/bin/env python3
"""
remove_input_data_column.py - Remove the redundant input_data column
"""

import sqlite3
import os
from datetime import datetime

def get_current_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime("%Y%m")
    return f"prediction_logs_{current_month}.db"

def remove_input_data_column():
    """Remove the redundant input_data column from prediction_logs table"""
    db_path = get_current_db_path()
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return
    
    # Backup first
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = f"{db_path}.backup_before_cleanup_{timestamp}"
    import shutil
    shutil.copy2(db_path, backup_path)
    print(f"📦 Backed up to: {backup_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check current columns
    cursor.execute("PRAGMA table_info(prediction_logs)")
    current_columns = [(col[1], col[2]) for col in cursor.fetchall()]
    print(f"📋 Current columns: {len(current_columns)}")
    
    # Define clean schema WITHOUT input_data
    clean_columns = [
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
        # Keep these useful meta columns
        'confidence TEXT',
        'method_used TEXT',
        'baseline_used INTEGER DEFAULT 1'
    ]
    
    print("🔄 Recreating table without input_data...")
    
    # Create new table with clean schema
    cursor.execute("BEGIN TRANSACTION")
    
    try:
        # Create new table
        create_sql = f"CREATE TABLE prediction_logs_new ({', '.join(clean_columns)})"
        cursor.execute(create_sql)
        
        # Copy data (excluding input_data column)
        copy_columns = [
            'timestamp', 'log_month', 'anomaly', 'explanation', 'network_packet_size',
            'login_attempts', 'session_duration', 'ip_reputation_score', 'failed_logins',
            'unusual_time_access', 'protocol_type_ICMP', 'protocol_type_TCP', 'protocol_type_UDP',
            'encryption_used_AES', 'encryption_used_DES', 'browser_type_Chrome', 'browser_type_Edge',
            'browser_type_Firefox', 'browser_type_Safari', 'browser_type_Unknown',
            'risk_score', 'anomaly_score', 'profile_used', 'user_role',
            'confidence', 'method_used', 'baseline_used'
        ]
        
        # Check which columns actually exist
        existing_columns = [col[0] for col in current_columns]
        available_columns = [col for col in copy_columns if col in existing_columns]
        
        if available_columns:
            copy_sql = f"""
                INSERT INTO prediction_logs_new ({', '.join(available_columns)})
                SELECT {', '.join(available_columns)} FROM prediction_logs
            """
            cursor.execute(copy_sql)
            
            # Get count of copied records
            cursor.execute("SELECT COUNT(*) FROM prediction_logs_new")
            copied_count = cursor.fetchone()[0]
            print(f"📊 Copied {copied_count} records")
        
        # Drop old table and rename new one
        cursor.execute("DROP TABLE prediction_logs")
        cursor.execute("ALTER TABLE prediction_logs_new RENAME TO prediction_logs")
        
        cursor.execute("COMMIT")
        print("✅ Successfully removed input_data column")
        
        # Verify new structure
        cursor.execute("PRAGMA table_info(prediction_logs)")
        new_columns = cursor.fetchall()
        print(f"📋 New schema ({len(new_columns)} columns):")
        for i, col in enumerate(new_columns, 1):
            print(f"  {i:2d}. {col[1]} ({col[2]})")
        
    except Exception as e:
        cursor.execute("ROLLBACK")
        print(f"❌ Error: {e}")
        raise
    
    conn.close()

if __name__ == "__main__":
    print("🧹 Removing Redundant input_data Column")
    print("=" * 50)
    remove_input_data_column()
    print("\n🎉 Cleanup completed!")
    print("Your dashboard table will now be much cleaner and easier to read.")