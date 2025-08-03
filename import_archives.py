#!/usr/bin/env python3
"""
import_archives.py - Import May and June CSV archives into historical_logs table
"""

import pandas as pd
import sqlite3
import os
from datetime import datetime

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def import_archived_data():
    """Import May and June CSV data into historical_logs table"""
    
    db_path = get_monthly_db_path()
    archives_dir = "archives"
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        return False
    
    if not os.path.exists(archives_dir):
        print(f"❌ Archives directory {archives_dir} does not exist!")
        return False
    
    # Find the archive CSV files
    may_csv = f"{archives_dir}/prediction_logs_2025-05_20250531_120000.csv"
    june_csv = f"{archives_dir}/prediction_logs_2025-06_20250630_120000.csv"
    
    print(f"🔍 Looking for archive files...")
    print(f"   May: {may_csv} - {'✅ Found' if os.path.exists(may_csv) else '❌ Missing'}")
    print(f"   June: {june_csv} - {'✅ Found' if os.path.exists(june_csv) else '❌ Missing'}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if historical_logs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='historical_logs'")
        if not cursor.fetchone():
            print("❌ historical_logs table does not exist! Creating it...")
            create_historical_logs_table(cursor)
        
        total_imported = 0
        
        # Import May data
        if os.path.exists(may_csv):
            may_count = import_csv_to_historical_logs(may_csv, "2025-05", cursor)
            total_imported += may_count
            print(f"✅ Imported {may_count} May 2025 records")
        
        # Import June data  
        if os.path.exists(june_csv):
            june_count = import_csv_to_historical_logs(june_csv, "2025-06", cursor)
            total_imported += june_count
            print(f"✅ Imported {june_count} June 2025 records")
        
        conn.commit()
        conn.close()
        
        print(f"\n🎉 Successfully imported {total_imported} total records to historical_logs!")
        print("📊 Your May and June data should now show in the Static Report")
        
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_historical_logs_table(cursor):
    """Create historical_logs table if it doesn't exist"""
    cursor.execute('''CREATE TABLE IF NOT EXISTS historical_logs (
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

def import_csv_to_historical_logs(csv_path, month, cursor):
    """Import a specific CSV file to historical_logs table"""
    
    print(f"📥 Importing {csv_path}...")
    
    # Read the CSV
    df = pd.read_csv(csv_path)
    print(f"   Read {len(df)} records from CSV")
    
    # Add archived_at timestamp
    archived_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Check if data already exists for this month
    cursor.execute("SELECT COUNT(*) FROM historical_logs WHERE log_month = ?", (month,))
    existing_count = cursor.fetchone()[0]
    
    if existing_count > 0:
        print(f"   ⚠️ {existing_count} records already exist for {month}, skipping...")
        return 0
    
    imported_count = 0
    
    # Insert each record
    for _, row in df.iterrows():
        try:
            # Prepare the data - handle missing columns gracefully
            record = {
                'timestamp': row.get('timestamp', ''),
                'log_month': month,
                'anomaly': int(row.get('anomaly', 0)),
                'explanation': row.get('explanation', 'Imported from archive'),
                'network_packet_size': int(row.get('network_packet_size', 0)),
                'login_attempts': int(row.get('login_attempts', 1)),
                'session_duration': float(row.get('session_duration', 0.0)),
                'ip_reputation_score': float(row.get('ip_reputation_score', 0.0)),
                'failed_logins': int(row.get('failed_logins', 0)),
                'unusual_time_access': int(row.get('unusual_time_access', 0)),
                'protocol_type_ICMP': int(row.get('protocol_type_ICMP', 0)),
                'protocol_type_TCP': int(row.get('protocol_type_TCP', 1)),
                'protocol_type_UDP': int(row.get('protocol_type_UDP', 0)),
                'encryption_used_AES': int(row.get('encryption_used_AES', 1)),
                'encryption_used_DES': int(row.get('encryption_used_DES', 0)),
                'browser_type_Chrome': int(row.get('browser_type_Chrome', 1)),
                'browser_type_Edge': int(row.get('browser_type_Edge', 0)),
                'browser_type_Firefox': int(row.get('browser_type_Firefox', 0)),
                'browser_type_Safari': int(row.get('browser_type_Safari', 0)),
                'browser_type_Unknown': int(row.get('browser_type_Unknown', 0)),
                'risk_score': float(row.get('risk_score', 0.0)),
                'anomaly_score': float(row.get('anomaly_score', 0.0)),
                'profile_used': row.get('profile_used', 'Archived'),
                'user_role': row.get('user_role', 'archived_user'),
                'archived_at': archived_at
            }
            
            # Insert the record
            columns = ', '.join(record.keys())
            placeholders = ', '.join('?' for _ in record)
            cursor.execute(f"""
                INSERT INTO historical_logs ({columns}) 
                VALUES ({placeholders})
            """, tuple(record.values()))
            
            imported_count += 1
            
        except Exception as e:
            print(f"   ⚠️ Error importing record {len(df) - imported_count}: {e}")
            continue
    
    return imported_count

def verify_import():
    """Verify the import was successful"""
    print("\n🔍 VERIFYING IMPORT:")
    
    db_path = get_monthly_db_path()
    conn = sqlite3.connect(db_path)
    
    # Check historical_logs counts
    df = pd.read_sql_query("""
        SELECT log_month, COUNT(*) as count 
        FROM historical_logs 
        GROUP BY log_month 
        ORDER BY log_month
    """, conn)
    
    print("📊 Historical logs by month:")
    for _, row in df.iterrows():
        print(f"   {row['log_month']}: {row['count']} records")
    
    # Check available months for dropdown
    months_df = pd.read_sql_query("""
        SELECT DISTINCT log_month 
        FROM (
            SELECT log_month FROM historical_logs 
            UNION 
            SELECT log_month FROM prediction_logs
        ) 
        ORDER BY log_month DESC
    """, conn)
    
    print(f"🗓️ Available months for dropdown: {months_df['log_month'].tolist()}")
    
    conn.close()

if __name__ == "__main__":
    print("📥 IMPORTING ARCHIVED DATA TO DATABASE")
    print("=" * 50)
    
    success = import_archived_data()
    
    if success:
        verify_import()
        print("\n✅ Import completed!")
        print("\n🎯 Next steps:")
        print("1. Restart your Flask application")
        print("2. Go to /report page")
        print("3. Use the dropdown to select '2025-05' or '2025-06'")
        print("4. You should now see your May and June data!")
    else:
        print("\n❌ Import failed!")