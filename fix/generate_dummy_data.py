#!/usr/bin/env python3
"""
Generate dummy cybersecurity data for May and June 2025
This creates realistic intrusion detection logs for testing the Static Report
"""

import pandas as pd
import numpy as np
import sqlite3
import os
from datetime import datetime, timedelta
import random
from datetime import timezone

def get_monthly_db_path():
    """Get current month's database path"""
    current_month = datetime.now().strftime('%Y%m')
    return f"prediction_logs_{current_month}.db"

def generate_dummy_session_data(start_date, end_date, num_records=500):
    """Generate realistic cybersecurity session data"""
    
    # Set random seed for reproducible results
    np.random.seed(42)
    random.seed(42)
    
    data = []
    current_date = start_date
    
    # Define realistic value ranges based on your CSV structure
    protocols = ['TCP', 'UDP', 'ICMP']
    encryptions = ['AES', 'DES', 'None']
    browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Unknown']
    user_roles = ['admin', 'user', 'guest', 'developer']
    profiles = ['Profile_A', 'Profile_B', 'Profile_C', 'Profile_D']
    
    for i in range(num_records):
        # Generate timestamp within the month
        days_in_period = (end_date - start_date).days
        random_day = random.randint(0, days_in_period)
        random_hour = random.randint(0, 23)
        random_minute = random.randint(0, 59)
        random_second = random.randint(0, 59)
        
        timestamp = start_date + timedelta(
            days=random_day, 
            hours=random_hour, 
            minutes=random_minute, 
            seconds=random_second
        )
        
        # Generate base session characteristics
        network_packet_size = random.randint(64, 65535)
        login_attempts = random.randint(1, 10)
        session_duration = round(random.uniform(30.0, 7200.0), 2)  # 30s to 2 hours
        ip_reputation_score = round(random.uniform(0.1, 1.0), 3)
        failed_logins = random.randint(0, min(login_attempts, 5))
        
        # Determine if this should be an anomaly (20% chance)
        is_anomaly = random.random() < 0.2
        
        # Adjust characteristics for anomalies
        if is_anomaly:
            # Anomalous sessions have suspicious characteristics
            login_attempts = random.randint(5, 15)  # More login attempts
            failed_logins = random.randint(3, login_attempts)  # More failures
            ip_reputation_score = round(random.uniform(0.1, 0.4), 3)  # Lower reputation
            unusual_time_access = 1 if random.random() < 0.7 else 0  # Often unusual times
            session_duration = round(random.uniform(1.0, 300.0), 2)  # Shorter sessions
            risk_score = round(random.uniform(0.6, 1.0), 3)  # High risk
            anomaly_score = round(random.uniform(-1.0, -0.3), 3)  # Negative anomaly score
            
            explanations = [
                "High failed login ratio detected",
                "Unusual access time pattern",
                "Low IP reputation score",
                "Suspicious session duration",
                "Multiple failed authentication attempts",
                "Anomalous network packet patterns"
            ]
            explanation = random.choice(explanations)
        else:
            # Normal sessions
            unusual_time_access = 1 if random.random() < 0.1 else 0  # Rarely unusual
            risk_score = round(random.uniform(0.0, 0.5), 3)  # Low risk
            anomaly_score = round(random.uniform(-0.2, 0.3), 3)  # Normal range
            explanation = "Normal session behavior"
        
        # Protocol selection (one-hot encoded)
        protocol = random.choice(protocols)
        protocol_icmp = 1 if protocol == 'ICMP' else 0
        protocol_tcp = 1 if protocol == 'TCP' else 0
        protocol_udp = 1 if protocol == 'UDP' else 0
        
        # Encryption selection (one-hot encoded)
        encryption = random.choice(encryptions)
        encryption_aes = 1 if encryption == 'AES' else 0
        encryption_des = 1 if encryption == 'DES' else 0
        
        # Browser selection (one-hot encoded)
        browser = random.choice(browsers)
        browser_chrome = 1 if browser == 'Chrome' else 0
        browser_edge = 1 if browser == 'Edge' else 0
        browser_firefox = 1 if browser == 'Firefox' else 0
        browser_safari = 1 if browser == 'Safari' else 0
        browser_unknown = 1 if browser == 'Unknown' else 0
        
        # Other fields
        user_role = random.choice(user_roles)
        profile_used = random.choice(profiles)
        log_month = timestamp.strftime('%Y-%m')
        
        record = {
            'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'log_month': log_month,
            'anomaly': 1 if is_anomaly else 0,
            'explanation': explanation,
            'network_packet_size': network_packet_size,
            'login_attempts': login_attempts,
            'session_duration': session_duration,
            'ip_reputation_score': ip_reputation_score,
            'failed_logins': failed_logins,
            'unusual_time_access': unusual_time_access,
            'protocol_type_ICMP': protocol_icmp,
            'protocol_type_TCP': protocol_tcp,
            'protocol_type_UDP': protocol_udp,
            'encryption_used_AES': encryption_aes,
            'encryption_used_DES': encryption_des,
            'browser_type_Chrome': browser_chrome,
            'browser_type_Edge': browser_edge,
            'browser_type_Firefox': browser_firefox,
            'browser_type_Safari': browser_safari,
            'browser_type_Unknown': browser_unknown,
            'risk_score': risk_score,
            'anomaly_score': anomaly_score,
            'profile_used': profile_used,
            'user_role': user_role
        }
        
        data.append(record)
    
    return data

def insert_dummy_data():
    """Insert dummy data into the historical_logs table"""
    
    print("🚀 Generating dummy data for May and June 2025...")
    
    # Define date ranges
    may_start = datetime(2025, 5, 1)
    may_end = datetime(2025, 5, 31)
    june_start = datetime(2025, 6, 1)  
    june_end = datetime(2025, 6, 30)
    
    # Generate data for both months
    print("📊 Generating May 2025 data...")
    may_data = generate_dummy_session_data(may_start, may_end, 300)
    
    print("📊 Generating June 2025 data...")
    june_data = generate_dummy_session_data(june_start, june_end, 350)
    
    all_data = may_data + june_data
    
    print(f"✅ Generated {len(all_data)} total records")
    print(f"   - May 2025: {len(may_data)} records")
    print(f"   - June 2025: {len(june_data)} records")
    
    # Get database connection
    db_path = get_monthly_db_path()
    
    if not os.path.exists(db_path):
        print(f"❌ Database {db_path} does not exist!")
        print("Please run database_setup.py first")
        return False
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        # Create historical_logs table if it doesn't exist
        c.execute('''CREATE TABLE IF NOT EXISTS historical_logs (
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
        
        # Insert dummy data
        archived_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        
        print("💾 Inserting data into historical_logs table...")
        
        for record in all_data:
            c.execute("""
                INSERT INTO historical_logs 
                (timestamp, log_month, anomaly, explanation, network_packet_size,
                 login_attempts, session_duration, ip_reputation_score, failed_logins,
                 unusual_time_access, protocol_type_ICMP, protocol_type_TCP, protocol_type_UDP,
                 encryption_used_AES, encryption_used_DES, browser_type_Chrome, browser_type_Edge,
                 browser_type_Firefox, browser_type_Safari, browser_type_Unknown,
                 risk_score, anomaly_score, profile_used, user_role, archived_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record['timestamp'], record['log_month'], record['anomaly'], record['explanation'],
                record['network_packet_size'], record['login_attempts'], record['session_duration'],
                record['ip_reputation_score'], record['failed_logins'], record['unusual_time_access'],
                record['protocol_type_ICMP'], record['protocol_type_TCP'], record['protocol_type_UDP'],
                record['encryption_used_AES'], record['encryption_used_DES'], record['browser_type_Chrome'],
                record['browser_type_Edge'], record['browser_type_Firefox'], record['browser_type_Safari'],
                record['browser_type_Unknown'], record['risk_score'], record['anomaly_score'],
                record['profile_used'], record['user_role'], archived_at
            ))
        
        conn.commit()
        conn.close()
        
        # Generate summary statistics
        df = pd.DataFrame(all_data)
        may_anomalies = len([r for r in may_data if r['anomaly'] == 1])
        june_anomalies = len([r for r in june_data if r['anomaly'] == 1])
        
        print("\n📈 Data Summary:")
        print(f"   May 2025:  {len(may_data)} records, {may_anomalies} anomalies ({(may_anomalies/len(may_data)*100):.1f}%)")
        print(f"   June 2025: {len(june_data)} records, {june_anomalies} anomalies ({(june_anomalies/len(june_data)*100):.1f}%)")
        print(f"   Total:     {len(all_data)} records, {may_anomalies + june_anomalies} anomalies")
        
        print("\n✅ Dummy data inserted successfully!")
        print("\n🎯 Next steps:")
        print("1. Go to /report (Static Report page)")
        print("2. Use the month dropdown to select '2025-05' or '2025-06'")
        print("3. You should see the dummy data displayed")
        print("4. Test clearing predictions from dashboard - this data should remain!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error inserting dummy data: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    print("🔧 STEP 1: Creating dummy cybersecurity data for testing...")
    print("This script generates May & June 2025 data and inserts it into the database")
    print("-" * 60)
    success = insert_dummy_data()
    
    if not success:
        print("\n❌ Failed to create dummy data!")
        print("Make sure your database exists and try again.")
    else:
        print("\n🎉 All done! Your Static Report now has historical data to display.")
        print("\nRun this next: python3 create_archive_csvs.py")