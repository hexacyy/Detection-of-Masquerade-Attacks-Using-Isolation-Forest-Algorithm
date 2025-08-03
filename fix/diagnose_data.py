#!/usr/bin/env python3
"""
diagnose_data.py - Check what data exists in your databases
"""

import sqlite3
import pandas as pd
import os
from datetime import datetime

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def diagnose_database():
    """Check what data actually exists"""
    
    db_path = get_monthly_db_path()
    print(f"🔍 Diagnosing database: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        return
        
    try:
        conn = sqlite3.connect(db_path)
        
        # Check what tables exist
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"📋 Tables found: {tables}")
        
        # Check prediction_logs data
        if 'prediction_logs' in tables:
            print("\n📊 PREDICTION_LOGS TABLE:")
            
            # Count total records
            df = pd.read_sql_query("SELECT COUNT(*) as count FROM prediction_logs", conn)
            total_count = df.iloc[0]['count']
            print(f"   Total records: {total_count}")
            
            if total_count > 0:
                # Check log_month formats
                month_df = pd.read_sql_query("SELECT DISTINCT log_month FROM prediction_logs ORDER BY log_month", conn)
                print(f"   Available months: {month_df['log_month'].tolist()}")
                
                # Check timestamp range
                time_df = pd.read_sql_query("SELECT MIN(timestamp) as min_time, MAX(timestamp) as max_time FROM prediction_logs", conn)
                print(f"   Time range: {time_df.iloc[0]['min_time']} to {time_df.iloc[0]['max_time']}")
                
                # Count by month
                count_df = pd.read_sql_query("SELECT log_month, COUNT(*) as count FROM prediction_logs GROUP BY log_month ORDER BY log_month", conn)
                print("   Records per month:")
                for _, row in count_df.iterrows():
                    print(f"     {row['log_month']}: {row['count']} records")
        
        # Check historical_logs data
        if 'historical_logs' in tables:
            print("\n📚 HISTORICAL_LOGS TABLE:")
            
            # Count total records
            df = pd.read_sql_query("SELECT COUNT(*) as count FROM historical_logs", conn)
            total_count = df.iloc[0]['count']
            print(f"   Total records: {total_count}")
            
            if total_count > 0:
                # Check log_month formats
                month_df = pd.read_sql_query("SELECT DISTINCT log_month FROM historical_logs ORDER BY log_month", conn)
                print(f"   Available months: {month_df['log_month'].tolist()}")
                
                # Count by month
                count_df = pd.read_sql_query("SELECT log_month, COUNT(*) as count FROM historical_logs GROUP BY log_month ORDER BY log_month", conn)
                print("   Records per month:")
                for _, row in count_df.iterrows():
                    print(f"     {row['log_month']}: {row['count']} records")
        
        conn.close()
        
        # Check what the archive function is looking for
        print("\n🎯 ARCHIVE FUNCTION ANALYSIS:")
        now = datetime.utcnow()
        current_month = now.strftime('%Y-%m')
        from datetime import timedelta
        prev_month = (now.replace(day=1) - timedelta(days=1)).strftime('%Y-%m')
        
        print(f"   Current month calculated: {current_month}")
        print(f"   Previous month calculated: {prev_month}")
        print(f"   Archive function looks for: log_month = '{prev_month}'")
        
        # Check if we have that exact data
        if 'prediction_logs' in tables:
            conn = sqlite3.connect(db_path)
            search_df = pd.read_sql_query("SELECT COUNT(*) as count FROM prediction_logs WHERE log_month = ?", conn, params=(prev_month,))
            found_count = search_df.iloc[0]['count']
            print(f"   Records found for '{prev_month}': {found_count}")
            conn.close()
            
            if found_count == 0:
                print(f"   ❌ This is why archive failed - no data for '{prev_month}'")
        
        print("\n💡 RECOMMENDATIONS:")
        print("1. Check if your data has log_month in format '2025-07' vs '2025-7' vs '202507'")
        print("2. Verify if July data exists but with different format")
        print("3. Consider if July data was already archived")
        
    except Exception as e:
        print(f"❌ Diagnosis failed: {e}")
        import traceback
        traceback.print_exc()

def check_archive_files():
    """Check what archive files exist"""
    print("\n📁 CHECKING ARCHIVE FILES:")
    
    archives_dir = "archives"
    if os.path.exists(archives_dir):
        archive_files = [f for f in os.listdir(archives_dir) if f.endswith('.csv')]
        if archive_files:
            print(f"   Found {len(archive_files)} archive files:")
            for file in sorted(archive_files):
                file_path = os.path.join(archives_dir, file)
                print(f"     {file} ({os.path.getsize(file_path)} bytes)")
        else:
            print("   No archive files found")
    else:
        print("   No archives directory found")
    
    # Check backup files
    backup_files = [f for f in os.listdir('.') if f.startswith('prediction_logs_backup') and f.endswith('.csv')]
    if backup_files:
        print(f"\n💾 Found {len(backup_files)} backup files:")
        for file in sorted(backup_files):
            print(f"     {file} ({os.path.getsize(file)} bytes)")

if __name__ == "__main__":
    print("🔍 DATABASE DATA DIAGNOSTIC")
    print("=" * 50)
    
    diagnose_database()
    check_archive_files()
    
    print("\n✅ Diagnosis completed!")