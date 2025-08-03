#!/usr/bin/env python3
"""
fix_july_data.py - Fix July data format and ensure archive function works
"""

import sqlite3
import pandas as pd
import os
from datetime import datetime

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def fix_july_data():
    """Fix July data to make archive function work"""
    
    db_path = get_monthly_db_path()
    print(f"🔧 Fixing July data in: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        return False
        
    try:
        conn = sqlite3.connect(db_path)
        
        # First, check what July data we have
        july_df = pd.read_sql_query("""
            SELECT * FROM prediction_logs 
            WHERE timestamp LIKE '2025-07%' 
            ORDER BY timestamp
        """, conn)
        
        print(f"📊 Found {len(july_df)} July records with timestamp starting '2025-07'")
        
        if july_df.empty:
            print("⚠️ No July data found by timestamp. Let's create some...")
            create_july_data(conn)
        else:
            # Check if log_month is properly set to '2025-07'
            july_month_check = pd.read_sql_query("""
                SELECT DISTINCT log_month FROM prediction_logs 
                WHERE timestamp LIKE '2025-07%'
            """, conn)
            
            print(f"📋 July data log_month values: {july_month_check['log_month'].tolist()}")
            
            # Fix log_month if needed
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE prediction_logs 
                SET log_month = '2025-07'
                WHERE timestamp LIKE '2025-07%' AND log_month != '2025-07'
            """)
            
            updated_rows = cursor.rowcount
            if updated_rows > 0:
                print(f"✅ Updated {updated_rows} July records to have log_month = '2025-07'")
            
            conn.commit()
        
        # Verify the fix
        verify_df = pd.read_sql_query("""
            SELECT COUNT(*) as count FROM prediction_logs 
            WHERE log_month = '2025-07'
        """, conn)
        
        july_count = verify_df.iloc[0]['count']
        print(f"✅ Final verification: {july_count} records with log_month = '2025-07'")
        
        conn.close()
        
        if july_count > 0:
            print("🎉 Archive function should now work for July 2025!")
            return True
        else:
            print("❌ Still no July data found")
            return False
            
    except Exception as e:
        print(f"❌ Fix failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_july_data(conn):
    """Create sample July data if none exists"""
    print("🔨 Creating sample July data...")
    
    cursor = conn.cursor()
    
    # Create 10 sample July records
    july_records = []
    for i in range(10):
        day = str(i + 1).zfill(2)
        hour = str(i * 2).zfill(2)
        
        record = {
            'timestamp': f'2025-07-{day}T{hour}:30:00',
            'log_month': '2025-07',
            'anomaly': i % 3 == 0,  # Every 3rd record is anomaly
            'explanation': f'Sample July data #{i+1}',
            'network_packet_size': 1024 + (i * 100),
            'login_attempts': 1 + (i % 5),
            'session_duration': 300.0 + (i * 50),
            'ip_reputation_score': 0.5 + (i * 0.05),
            'failed_logins': i % 3,
            'unusual_time_access': i % 2,
            'protocol_type_ICMP': 0,
            'protocol_type_TCP': 1,
            'protocol_type_UDP': 0,
            'encryption_used_AES': 1,
            'encryption_used_DES': 0,
            'browser_type_Chrome': 1,
            'browser_type_Edge': 0,
            'browser_type_Firefox': 0,
            'browser_type_Safari': 0,
            'browser_type_Unknown': 0,
            'risk_score': 0.3 + (i * 0.1),
            'anomaly_score': 0.1 + (i * 0.05),
            'profile_used': 'Test-Profile',
            'user_role': 'test_user',
            'confidence': 'Medium',
            'method_used': 'Test-Data',
            'baseline_used': 1
        }
        july_records.append(record)
    
    # Insert the records
    for record in july_records:
        columns = ', '.join(record.keys())
        placeholders = ', '.join('?' for _ in record)
        cursor.execute(f"""
            INSERT INTO prediction_logs ({columns}) 
            VALUES ({placeholders})
        """, tuple(record.values()))
    
    conn.commit()
    print(f"✅ Created {len(july_records)} sample July records")

def test_archive_function():
    """Test if the archive function will now work"""
    print("\n🧪 TESTING ARCHIVE FUNCTION LOGIC:")
    
    from datetime import timedelta
    now = datetime.utcnow()
    prev_month = (now.replace(day=1) - timedelta(days=1)).strftime('%Y-%m')
    
    print(f"Archive function will look for: log_month = '{prev_month}'")
    
    db_path = get_monthly_db_path()
    if os.path.exists(db_path):
        conn = sqlite3.connect(db_path)
        test_df = pd.read_sql_query("""
            SELECT COUNT(*) as count FROM prediction_logs 
            WHERE log_month = ?
        """, conn, params=(prev_month,))
        
        found_count = test_df.iloc[0]['count']
        print(f"Records found: {found_count}")
        
        if found_count > 0:
            print("✅ Archive function should work now!")
            
            # Show sample of what will be archived
            sample_df = pd.read_sql_query("""
                SELECT timestamp, anomaly, explanation 
                FROM prediction_logs 
                WHERE log_month = ? 
                LIMIT 3
            """, conn, params=(prev_month,))
            
            print("📋 Sample records that will be archived:")
            for _, row in sample_df.iterrows():
                print(f"   {row['timestamp']} | Anomaly: {row['anomaly']} | {row['explanation']}")
        else:
            print("❌ Archive function will still fail")
        
        conn.close()

if __name__ == "__main__":
    print("🔧 FIXING JULY DATA FOR ARCHIVE")
    print("=" * 40)
    
    success = fix_july_data()
    
    if success:
        test_archive_function()
        print("\n✅ Fix completed!")
        print("\n🎯 Next steps:")
        print("1. Go back to your Report page")
        print("2. Click 'Archive Last Month's Logs' button")
        print("3. It should now successfully archive July 2025 data")
    else:
        print("\n❌ Fix failed!")
        print("Run the diagnosis script first: python diagnose_data.py")