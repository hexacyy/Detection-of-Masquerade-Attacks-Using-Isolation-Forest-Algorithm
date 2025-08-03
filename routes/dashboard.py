from flask import Blueprint, render_template, request, send_file, jsonify
import pandas as pd
import sqlite3
import os
import csv
from datetime import datetime, timezone
from utils import login_required, get_monthly_db_path
import numpy as np

dashboard_bp = Blueprint('dashboard', __name__)


def clean_dataframe_for_json(df):
    """Clean DataFrame to make it JSON serializable - FIXED VERSION"""
    if df is None or df.empty:
        return []
    
    df_clean = df.copy()
    
    # Handle datetime columns and NaT values more robustly
    for col in df_clean.columns:
        if df_clean[col].dtype == 'datetime64[ns]':
            # Convert datetime to string, handling NaT values properly
            df_clean[col] = df_clean[col].apply(
                lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if pd.notna(x) else None
            )
        elif df_clean[col].dtype == 'object':
            # Handle any object columns that might contain datetime-like objects
            df_clean[col] = df_clean[col].apply(
                lambda x: str(x) if pd.notna(x) and x != 'NaT' else None
            )
    
    # Replace all NaN, NaT, and inf values with None (which becomes null in JSON)
    df_clean = df_clean.replace({
        pd.NaT: None,
        pd.NA: None,
        float('inf'): None,
        float('-inf'): None
    })
    
    # Replace remaining NaN with None
    df_clean = df_clean.where(pd.notna(df_clean), None)
    
    # Convert to records (list of dictionaries)
    return df_clean.to_dict(orient='records')

def generate_summary_internal(selected_month=None):
    """Generate internal summary data for dashboard - FIXED VERSION"""
    
    # Default summary structure
    summary = {
        'total': 0,
        'anomalies': 0,
        'normal': 0,
        'anomaly_rate': 0.0,
        'last_updated': 'N/A',
        'df_tail': [],
        'timestamps': [],
        'anomaly_flags': [],
        'available_months': []
    }
    
    try:
        db_path = get_monthly_db_path()
        print(f"[DEBUG] Accessing database: {db_path}")
        
        if not os.path.exists(db_path):
            print(f"[WARNING] Database {db_path} does not exist")
            return summary
            
        with sqlite3.connect(db_path) as conn:
            # Check if prediction_logs table exists
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='prediction_logs'")
            if not cursor.fetchone():
                print("[ERROR] prediction_logs table does not exist!")
                return summary
            
            # Base query - always use prediction_logs
            if selected_month:
                query = "SELECT * FROM prediction_logs WHERE log_month = ? ORDER BY timestamp DESC"
                params = (selected_month,)
                print(f"[DEBUG] Querying specific month: {selected_month}")
            else:
                query = "SELECT * FROM prediction_logs ORDER BY timestamp DESC"
                params = None
                print(f"[DEBUG] Querying all data")
                
            print(f"[DEBUG] Executing query: {query}")
            
            # Execute the query safely
            if params:
                df = pd.read_sql_query(query, conn, params=params)
            else:
                df = pd.read_sql_query(query, conn)
                
            print(f"[DEBUG] Query returned {len(df)} records")
            
            if not df.empty:
                # Calculate summary statistics
                summary['total'] = len(df)
                summary['anomalies'] = int(df['anomaly'].sum()) if 'anomaly' in df.columns else 0
                summary['normal'] = summary['total'] - summary['anomalies']
                summary['anomaly_rate'] = (summary['anomalies'] / summary['total'] * 100) if summary['total'] > 0 else 0
                
                # Handle timestamps SAFELY
                if 'timestamp' in df.columns:
                    # Convert to datetime and handle errors gracefully
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                    
                    # Remove any NaT values for processing
                    valid_timestamps = df['timestamp'].dropna()
                    
                    if not valid_timestamps.empty:
                        max_timestamp = valid_timestamps.max()
                        summary['last_updated'] = max_timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        
                        # Create timestamps list for charts (only valid timestamps)
                        summary['timestamps'] = [
                            ts.strftime('%Y-%m-%d %H:%M:%S') 
                            for ts in valid_timestamps 
                            if pd.notna(ts)
                        ]
                    else:
                        summary['last_updated'] = 'N/A'
                        summary['timestamps'] = []
                
                # Get recent records for display - CLEAN THEM PROPERLY
                recent_df = df.head(100)
                summary['df_tail'] = clean_dataframe_for_json(recent_df)
                
                # Anomaly flags for charts
                summary['anomaly_flags'] = df['anomaly'].tolist() if 'anomaly' in df.columns else []
                
            # Get available months
            try:
                available_months_query = "SELECT DISTINCT log_month FROM prediction_logs ORDER BY log_month DESC"
                available_months = [row[0] for row in conn.execute(available_months_query).fetchall()]
                summary['available_months'] = available_months
            except Exception as e:
                print(f"[WARNING] Could not get available months: {e}")
                summary['available_months'] = []
                
        print(f"[DEBUG] Summary generated: {summary['total']} total, {summary['anomalies']} anomalies")
        return summary
        
    except Exception as e:
        print(f"[ERROR] Summary generation failed: {e}")
        import traceback
        traceback.print_exc()
        return summary

@dashboard_bp.route('/dashboard')
@login_required()
def dashboard():
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Generate base summary
    summary = generate_summary_internal()
    
    # Handle date filtering
    if start_date or end_date:
        try:
            db_path = get_monthly_db_path()
            with sqlite3.connect(db_path) as conn:
                df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
                
                if not df.empty:
                    # Ensure timestamp is datetime
                    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                    
                    # Apply filters
                    if start_date:
                        df = df[df['timestamp'] >= start_date]
                    if end_date:
                        df = df[df['timestamp'] <= end_date]
                    
                    # Update summary with filtered data
                    summary['total'] = len(df)
                    summary['anomalies'] = int(df['anomaly'].sum()) if not df.empty and 'anomaly' in df.columns else 0
                    summary['normal'] = summary['total'] - summary['anomalies']
                    summary['anomaly_rate'] = (summary['anomalies'] / summary['total'] * 100) if summary['total'] > 0 else 0
                    
                    # CRITICAL: Update df_tail with filtered data
                    df_tail_filtered = df.head(100) if not df.empty else pd.DataFrame()
                    summary['df_tail'] = clean_dataframe_for_json(df_tail_filtered)
                    
                    # Handle last_updated for filtered data
                    if not df.empty and 'timestamp' in df.columns:
                        max_timestamp = df['timestamp'].max()
                        summary['last_updated'] = max_timestamp.strftime('%Y-%m-%d %H:%M:%S') if pd.notna(max_timestamp) else 'N/A'
                    else:
                        summary['last_updated'] = 'N/A'
                    
                    # Handle timestamps and anomaly flags for filtered data
                    if not df.empty:
                        summary['timestamps'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                            pd.notna(df['timestamp']), 'N/A'
                        ).tolist()
                        summary['anomaly_flags'] = df['anomaly'].tolist() if 'anomaly' in df.columns else []
                    else:
                        summary['timestamps'] = []
                        summary['anomaly_flags'] = []
                        
        except Exception as e:
            print(f"[ERROR] Error filtering data: {e}")
            # Keep original summary data if filtering fails
            # Ensure df_tail exists even on error
            if 'df_tail' not in summary:
                summary['df_tail'] = []
    
    # Ensure df_tail always exists
    if 'df_tail' not in summary:
        summary['df_tail'] = []
    
    print(f"[DEBUG] Dashboard rendering with {len(summary.get('df_tail', []))} records in df_tail")
    
    return render_template("dashboard_v5.html", summary=summary, start_date=start_date, end_date=end_date, active_page='dashboard')

# Replace the report route in routes/dashboard.py
# Make sure you have this import at the top of the file:
# from flask import render_template, request, flash

@dashboard_bp.route('/report')
@login_required()
def report():
    selected_month = request.args.get('month')
    
    # Default summary structure
    summary = {
        'available_months': [],
        'df_tail': [],
        'total': 0,
        'anomalies': 0,
        'normal': 0,
        'last_updated': 'N/A',
        'timestamps': [],
        'anomaly_flags': []
    }
    
    try:
        db_path = get_monthly_db_path()
        conn = sqlite3.connect(db_path)
        
        # Check if historical_logs table exists, create if not
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='historical_logs'")
        if not c.fetchone():
            print("[INFO] Creating historical_logs table...")
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
            conn.commit()
            print("[SUCCESS] historical_logs table created")
        
        # Get available months from both tables
        try:
            available_months_query = """
                SELECT DISTINCT log_month 
                FROM (
                    SELECT log_month FROM historical_logs 
                    UNION 
                    SELECT log_month FROM prediction_logs
                ) 
                ORDER BY log_month DESC
            """
            available_months = [row[0] for row in conn.execute(available_months_query).fetchall()]
        except Exception as e:
            print(f"[WARNING] Error getting available months: {e}")
            # Fallback: get months from prediction_logs only
            available_months = [row[0] for row in conn.execute(
                "SELECT DISTINCT log_month FROM prediction_logs ORDER BY log_month DESC"
            ).fetchall()]
        
        summary['available_months'] = available_months
        
        if selected_month:
            # Load specific month's data
            try:
                df_historical = pd.read_sql_query(
                    "SELECT * FROM historical_logs WHERE log_month = ? ORDER BY timestamp DESC", 
                    conn, 
                    params=(selected_month,)
                )
            except Exception as e:
                print(f"[WARNING] Could not load from historical_logs: {e}")
                df_historical = pd.DataFrame()
            
            df_current = pd.read_sql_query(
                "SELECT * FROM prediction_logs WHERE log_month = ? ORDER BY timestamp DESC", 
                conn, 
                params=(selected_month,)
            )
            
            # Combine data
            if not df_historical.empty and not df_current.empty:
                # Remove archived_at column if it exists to match schemas
                if 'archived_at' in df_historical.columns:
                    df_historical = df_historical.drop(columns=['archived_at'])
                df = pd.concat([df_historical, df_current], ignore_index=True)
            elif not df_historical.empty:
                if 'archived_at' in df_historical.columns:
                    df_historical = df_historical.drop(columns=['archived_at'])
                df = df_historical
            elif not df_current.empty:
                df = df_current
            else:
                df = pd.DataFrame()
                
        else:
            # No month selected - show recent data from both tables
            try:
                df_historical = pd.read_sql_query(
                    "SELECT * FROM historical_logs ORDER BY timestamp DESC LIMIT 500", 
                    conn
                )
                if not df_historical.empty and 'archived_at' in df_historical.columns:
                    df_historical = df_historical.drop(columns=['archived_at'])
            except Exception as e:
                print(f"[WARNING] Could not load from historical_logs: {e}")
                df_historical = pd.DataFrame()
                
            df_current = pd.read_sql_query(
                "SELECT * FROM prediction_logs ORDER BY timestamp DESC LIMIT 500", 
                conn
            )
            
            if not df_historical.empty and not df_current.empty:
                df = pd.concat([df_historical, df_current], ignore_index=True)
            elif not df_historical.empty:
                df = df_historical
            elif not df_current.empty:
                df = df_current
            else:
                df = pd.DataFrame()
        
        conn.close()
        
        # Generate summary from data
        if not df.empty:
            # Convert timestamp with proper timezone handling
            if 'timestamp' in df.columns:
                try:
                    # Try standard format first
                    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S')
                except ValueError:
                    try:
                        # Try with mixed formats and UTC handling
                        df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed', utc=True)
                        # Convert to local timezone (remove timezone info for consistency)
                        df['timestamp'] = df['timestamp'].dt.tz_localize(None)
                    except ValueError:
                        # Last resort - let pandas infer and normalize timezone
                        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
                        df['timestamp'] = df['timestamp'].dt.tz_localize(None)
                        print("[WARNING] Some timestamps could not be parsed")
                
                # Remove any remaining timezone info to avoid comparison issues
                if df['timestamp'].dt.tz is not None:
                    df['timestamp'] = df['timestamp'].dt.tz_localize(None)
                
                df = df.sort_values('timestamp', ascending=False)
            
            summary['total'] = len(df)
            summary['anomalies'] = int(df['anomaly'].sum()) if 'anomaly' in df.columns else 0
            summary['normal'] = summary['total'] - summary['anomalies']
            
            if 'timestamp' in df.columns and not df.empty:
                summary['last_updated'] = df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
            
            # Get most recent 100 records for display
            recent_df = df.head(100)
            summary['df_tail'] = recent_df.to_dict('records')
            
            # For charts
            if 'timestamp' in df.columns:
                summary['timestamps'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').tolist()
            summary['anomaly_flags'] = df['anomaly'].tolist() if 'anomaly' in df.columns else []
        
        print(f"[DEBUG] Static Report loaded: {summary['total']} total records, {len(summary['df_tail'])} displayed")
        
    except Exception as e:
        print(f"[ERROR] Error loading report data: {e}")
        import traceback
        traceback.print_exc()
        try:
            from flask import flash
            flash(f"❌ Error loading report data: {str(e)}", "danger")
        except:
            print(f"[ERROR] Could not flash error message: {e}")
    
    return render_template("report.html", summary=summary, selected_month=selected_month)

@dashboard_bp.route('/generate_summary')
@login_required(role='admin')
def generate_summary():
    try:
        selected_month = request.args.get("month")
        summary_data = generate_summary_internal(selected_month)

        # Convert numpy types to Python types
        summary_data = {
            k: int(v) if isinstance(v, (np.int64, np.int32))
            else float(v) if isinstance(v, (np.float64, np.float32))
            else v for k, v in summary_data.items()
        }

        return jsonify({"message": "Summary generated successfully.", "summary": summary_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@dashboard_bp.route('/download/log')
@login_required()
def download_log():
    selected_month = request.args.get("month")
    db_path = f"prediction_logs_{selected_month.replace('-', '')}.db" if selected_month else get_monthly_db_path()
    try:
        with sqlite3.connect(db_path) as conn:
            df = pd.read_sql_query("SELECT * FROM prediction_logs", conn)
        if df.empty:
            return "No data available for download.", 404
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        csv_path = f"prediction_logs_backup_{selected_month or 'current'}_{timestamp}.csv"
        df.to_csv(csv_path, index=False)
        return send_file(csv_path, as_attachment=True)
    except Exception as e:
        return f"Failed to generate download: {str(e)}", 500

@dashboard_bp.route('/download/summary')
@login_required()
def download_summary():
    selected_month = request.args.get("month")
    summary = generate_summary_internal(selected_month)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    csv_path = f"prediction_summary_report_{selected_month or 'current'}_{timestamp}.csv"
    with open(csv_path, "w", newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=summary.keys())
        writer.writeheader()
        writer.writerow(summary)
    return send_file(csv_path, as_attachment=True)