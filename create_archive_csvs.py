#!/usr/bin/env python3
"""
Create archive CSV files for May and June 2025
This simulates what the "Archive Last Month's Logs" button would create
"""

import pandas as pd
import sqlite3
import os
from datetime import datetime

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def export_to_archive_csvs():
    """Export May and June data to archive CSV files"""
    
    print("📁 Creating archive CSV files for testing...")
    
    # Create archives directory
    archives_dir = "archives"
    if not os.path.exists(archives_dir):
        os.makedirs(archives_dir)
        print(f"📂 Created archives directory: {archives_dir}")
    
    db_path = get_monthly_db_path()
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        
        # Export May 2025 data
        print("📊 Exporting May 2025 data...")
        may_df = pd.read_sql_query(
            "SELECT * FROM historical_logs WHERE log_month = '2025-05' ORDER BY timestamp", 
            conn
        )
        
        if not may_df.empty:
            # Remove archived_at column for cleaner CSV
            if 'archived_at' in may_df.columns:
                may_df = may_df.drop(columns=['archived_at'])
            
            may_csv_path = f"{archives_dir}/prediction_logs_2025-05_20250531_120000.csv"
            may_df.to_csv(may_csv_path, index=False)
            print(f"✅ May 2025: {len(may_df)} records exported to {may_csv_path}")
        else:
            print("⚠️  No May 2025 data found in historical_logs")
        
        # Export June 2025 data
        print("📊 Exporting June 2025 data...")
        june_df = pd.read_sql_query(
            "SELECT * FROM historical_logs WHERE log_month = '2025-06' ORDER BY timestamp", 
            conn
        )
        
        if not june_df.empty:
            # Remove archived_at column for cleaner CSV
            if 'archived_at' in june_df.columns:
                june_df = june_df.drop(columns=['archived_at'])
                
            june_csv_path = f"{archives_dir}/prediction_logs_2025-06_20250630_120000.csv"
            june_df.to_csv(june_csv_path, index=False)
            print(f"✅ June 2025: {len(june_df)} records exported to {june_csv_path}")
        else:
            print("⚠️  No June 2025 data found in historical_logs")
        
        conn.close()
        
        # Create summary reports
        if not may_df.empty:
            create_summary_report(may_df, "2025-05", archives_dir)
        if not june_df.empty:
            create_summary_report(june_df, "2025-06", archives_dir)
        
        print("\n✅ Archive CSV files created successfully!")
        print(f"📁 Files saved in: {archives_dir}/")
        print("\n🎯 These files simulate what the 'Archive Last Month's Logs' button creates")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating archive CSVs: {e}")
        return False

def create_summary_report(df, month, archives_dir):
    """Create a summary report for the month"""
    
    total = len(df)
    anomalies = df['anomaly'].sum() if 'anomaly' in df.columns else 0
    normal = total - anomalies
    anomaly_rate = round((anomalies / total) * 100, 2) if total > 0 else 0
    
    avg_risk_score = df['risk_score'].mean() if 'risk_score' in df.columns else 0
    high_risk_sessions = len(df[df['risk_score'] > 0.8]) if 'risk_score' in df.columns else 0
    
    # User role breakdown
    user_role_breakdown = df['user_role'].value_counts().to_dict() if 'user_role' in df.columns else {}
    
    # Time range
    first_entry = df['timestamp'].min() if not df.empty else 'N/A'
    last_entry = df['timestamp'].max() if not df.empty else 'N/A'
    
    summary = {
        "month": month,
        "total_sessions": total,
        "anomalies_detected": int(anomalies),
        "normal_sessions": int(normal),
        "anomaly_rate_percent": anomaly_rate,
        "average_risk_score": round(float(avg_risk_score), 3) if avg_risk_score else 0,
        "high_risk_sessions": int(high_risk_sessions),
        "user_role_breakdown": str(user_role_breakdown),
        "first_entry_time": first_entry,
        "last_entry_time": last_entry,
        "archived_at": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        "archived_by": "system_dummy_data",
        "total_records_archived": total
    }
    
    # Save summary report
    summary_path = f"{archives_dir}/summary_report_{month}_20250731_120000.csv"
    
    import csv
    with open(summary_path, "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)
    
    print(f"📋 Summary report for {month}: {summary_path}")

if __name__ == '__main__':
    print("📦 STEP 2: Creating archive CSV files for testing...")
    print("This script exports the dummy data to CSV files (run after generate_dummy_data.py)")
    print("-" * 70)
    success = export_to_archive_csvs()
    
    if success:
        print("\n🎉 Archive files ready!")
        print("\n📋 What you can test now:")
        print("1. Static Report should show May/June data")
        print("2. Download buttons should work")
        print("3. Archive button functionality is demonstrated")
        print("4. Clear predictions won't affect this archived data")
    else:
        print("\n❌ Failed to create archive files!")
        print("Make sure you've run generate_dummy_data.py first.")