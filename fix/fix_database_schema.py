#!/usr/bin/env python3
"""
fix_database_schema.py - Fix database schema issues for prediction logs
"""

import sqlite3
import os
from datetime import datetime

def get_current_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime("%Y%m")
    return f"prediction_logs_{current_month}.db"

def check_and_fix_prediction_logs_table():
    """Check and fix the prediction_logs table schema"""
    db_path = get_current_db_path()
    print(f"🔍 Checking database: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        print("Creating new database...")
        create_prediction_logs_table(db_path)
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check current table structure
    cursor.execute("PRAGMA table_info(prediction_logs)")
    columns_info = cursor.fetchall()
    existing_columns = [col[1] for col in columns_info]
    
    print(f"📋 Current columns ({len(existing_columns)}):")
    for col in existing_columns:
        print(f"  - {col}")
    
    # Required columns for the updated system
    required_columns = {
        'id': 'INTEGER PRIMARY KEY AUTOINCREMENT',
        'timestamp': 'TEXT',
        'input_data': 'TEXT',  # This is the missing column!
        'prediction_result': 'INTEGER',
        'confidence': 'TEXT',
        'method_used': 'TEXT',
        'baseline_used': 'INTEGER DEFAULT 0',
        'explanation': 'TEXT',
        'anomaly_score': 'REAL',
        'log_month': 'TEXT',
        'anomaly': 'INTEGER',
        'profile_used': 'TEXT',
        'user_role': 'TEXT',
        'business_impact': 'TEXT',
        'estimated_cost': 'INTEGER',
        'rule_based_detection': 'INTEGER',
        'ml_detection': 'INTEGER',
        'risk_score': 'REAL',
        'detection_method': 'TEXT',
        'network_packet_size': 'REAL',
        'login_attempts': 'INTEGER',
        'session_duration': 'REAL',
        'ip_reputation_score': 'REAL',
        'failed_logins': 'INTEGER',
        'unusual_time_access': 'INTEGER',
        'protocol_type_ICMP': 'INTEGER',
        'protocol_type_TCP': 'INTEGER',
        'protocol_type_UDP': 'INTEGER',
        'encryption_used_AES': 'INTEGER',
        'encryption_used_DES': 'INTEGER',
        'browser_type_Chrome': 'INTEGER',
        'browser_type_Edge': 'INTEGER',
        'browser_type_Firefox': 'INTEGER',
        'browser_type_Safari': 'INTEGER',
        'browser_type_Unknown': 'INTEGER'
    }
    
    # Find missing columns
    missing_columns = [col for col in required_columns.keys() if col not in existing_columns]
    
    if missing_columns:
        print(f"\n⚠️ Missing columns ({len(missing_columns)}):")
        for col in missing_columns:
            print(f"  - {col}")
        
        print("\n🔧 Adding missing columns...")
        for col in missing_columns:
            try:
                cursor.execute(f"ALTER TABLE prediction_logs ADD COLUMN {col} {required_columns[col]}")
                print(f"  ✅ Added: {col}")
            except sqlite3.Error as e:
                print(f"  ❌ Failed to add {col}: {e}")
    else:
        print("\n✅ All required columns present!")
    
    conn.commit()
    conn.close()
    print(f"\n✅ Database schema updated: {db_path}")

def create_prediction_logs_table(db_path):
    """Create a new prediction_logs table with correct schema"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS prediction_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        input_data TEXT,
        prediction_result INTEGER,
        confidence TEXT,
        method_used TEXT,
        baseline_used INTEGER DEFAULT 0,
        explanation TEXT,
        anomaly_score REAL,
        log_month TEXT,
        anomaly INTEGER,
        profile_used TEXT,
        user_role TEXT,
        business_impact TEXT,
        estimated_cost INTEGER,
        rule_based_detection INTEGER,
        ml_detection INTEGER,
        risk_score REAL,
        detection_method TEXT,
        network_packet_size REAL,
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
        browser_type_Unknown INTEGER
    )''')
    
    conn.commit()
    conn.close()
    print(f"✅ Created new prediction_logs table in {db_path}")

if __name__ == "__main__":
    print("🛠️ Fixing Database Schema Issues")
    print("=" * 40)
    check_and_fix_prediction_logs_table()
    print("\n🎉 Database schema fix completed!")