#!/usr/bin/env python3
"""
fix_month_transition.py - Handle the new month database creation
"""

import sqlite3
import os
from datetime import datetime

def get_current_month_db():
    """Get current month's database path"""
    current_month = datetime.now().strftime("%Y%m")
    return f"prediction_logs_{current_month}.db"

def get_previous_month_db():
    """Get previous month's database path"""
    now = datetime.now()
    if now.month == 1:
        # January -> December of previous year
        prev_month = f"{now.year - 1}12"
    else:
        # Just go back one month
        prev_month = f"{now.year}{now.month - 1:02d}"
    return f"prediction_logs_{prev_month}.db"

def create_current_month_database():
    """Create the current month's database with proper schema"""
    
    current_db = get_current_month_db()
    previous_db = get_previous_month_db()
    
    print(f"Current month database: {current_db}")
    print(f"Previous month database: {previous_db}")
    
    # Check if current month DB already exists
    if os.path.exists(current_db):
        print(f"✅ {current_db} already exists")
        return
    
    print(f"🔧 Creating {current_db}...")
    
    # Create new database with clean schema
    conn = sqlite3.connect(current_db)
    cursor = conn.cursor()
    
    # Create prediction_logs table with the working schema
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
    
    print(f"✅ Created {current_db} with proper schema")
    
    # Optional: Copy some sample data from previous month for continuity
    if os.path.exists(previous_db):
        copy_sample_data(previous_db, current_db)

def copy_sample_data(source_db, target_db):
    """Copy a few sample records from previous month for continuity"""
    try:
        # Connect to both databases
        source_conn = sqlite3.connect(source_db)
        target_conn = sqlite3.connect(target_db)
        
        source_cursor = source_conn.cursor()
        target_cursor = target_conn.cursor()
        
        # Get last 5 records from previous month
        source_cursor.execute("""
            SELECT timestamp, log_month, anomaly, explanation, network_packet_size,
                   login_attempts, session_duration, ip_reputation_score, failed_logins,
                   unusual_time_access, protocol_type_ICMP, protocol_type_TCP, protocol_type_UDP,
                   encryption_used_AES, encryption_used_DES, browser_type_Chrome, browser_type_Edge,
                   browser_type_Firefox, browser_type_Safari, browser_type_Unknown,
                   risk_score, anomaly_score, profile_used, user_role,
                   confidence, method_used, baseline_used
            FROM prediction_logs 
            ORDER BY timestamp DESC 
            LIMIT 3
        """)
        
        sample_records = source_cursor.fetchall()
        
        if sample_records:
            # Update timestamps to current month and insert
            current_month = datetime.now().strftime('%Y-%m')
            
            for record in sample_records:
                # Update the log_month and timestamp for the new records
                updated_record = list(record)
                updated_record[0] = datetime.now().isoformat()  # timestamp
                updated_record[1] = current_month  # log_month
                
                target_cursor.execute("""
                    INSERT INTO prediction_logs 
                    (timestamp, log_month, anomaly, explanation, network_packet_size,
                     login_attempts, session_duration, ip_reputation_score, failed_logins,
                     unusual_time_access, protocol_type_ICMP, protocol_type_TCP, protocol_type_UDP,
                     encryption_used_AES, encryption_used_DES, browser_type_Chrome, browser_type_Edge,
                     browser_type_Firefox, browser_type_Safari, browser_type_Unknown,
                     risk_score, anomaly_score, profile_used, user_role,
                     confidence, method_used, baseline_used)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, updated_record)
            
            target_conn.commit()
            print(f"📊 Copied {len(sample_records)} sample records for continuity")
        
        source_conn.close()
        target_conn.close()
        
    except Exception as e:
        print(f"⚠️ Could not copy sample data: {e}")

def check_database_status():
    """Check status of all database files"""
    print("\n📋 Database Status Check:")
    print("=" * 40)
    
    # List all prediction database files
    db_files = [f for f in os.listdir('.') if f.startswith('prediction_logs_') and f.endswith('.db')]
    
    for db_file in sorted(db_files):
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM prediction_logs")
            count = cursor.fetchone()[0]
            conn.close()
            
            # Determine if this is current month
            current_month = datetime.now().strftime("%Y%m")
            is_current = current_month in db_file
            status = "📍 CURRENT" if is_current else "📁 ARCHIVED"
            
            print(f"  {status} {db_file}: {count} records")
            
        except Exception as e:
            print(f"  ❌ ERROR {db_file}: {e}")

if __name__ == "__main__":
    print("🗓️ Handling Month Transition")
    print("=" * 40)
    
    # Create current month database
    create_current_month_database()
    
    # Check all database status
    check_database_status()
    
    print("\n🎉 Month transition completed!")
    print("\nNext steps:")
    print("1. 🔄 Restart your Flask application")
    print("2. 🧪 Test a prediction submission")
    print("3. 📊 Check your dashboard")
    print("4. 📱 Verify data feeds are working")