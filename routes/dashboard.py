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
    """Clean DataFrame to make it JSON serializable"""
    if df is None or df.empty:
        return []
    
    df_clean = df.copy()
    
    # Handle datetime columns and NaT values
    for col in df_clean.columns:
        if df_clean[col].dtype == 'datetime64[ns]':
            # Convert datetime to string, handling NaT values
            df_clean[col] = df_clean[col].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                pd.notna(df_clean[col]), None
            )
    
    # Replace NaN with None (which becomes null in JSON)
    df_clean = df_clean.where(pd.notna(df_clean), None)
    
    # Convert to records (list of dictionaries)
    return df_clean.to_dict(orient='records')



# Replace your generate_summary_internal function in routes/dashboard.py with this:

def clean_dataframe_for_json(df):
    """Clean DataFrame to make it JSON serializable"""
    if df is None or df.empty:
        return []
    
    df_clean = df.copy()
    
    # Handle datetime columns and NaT values
    for col in df_clean.columns:
        if df_clean[col].dtype == 'datetime64[ns]':
            # Convert datetime to string, handling NaT values
            df_clean[col] = df_clean[col].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                pd.notna(df_clean[col]), None
            )
    
    # Replace NaN with None (which becomes null in JSON)
    df_clean = df_clean.where(pd.notna(df_clean), None)
    
    # Convert to records (list of dictionaries)
    return df_clean.to_dict(orient='records')

def generate_summary_internal(selected_month=None):
    """
    Enhanced summary generation with df_tail for dashboard template
    """
    try:
        db_path = get_monthly_db_path()
        
        if not os.path.exists(db_path):
            return {
                'total': 0,
                'anomalies': 0,
                'normal': 0,
                'anomaly_rate': 0.0,
                'last_updated': 'No data',
                'available_months': [],
                'timestamps': [],
                'anomaly_flags': [],
                'df_tail': []  # Add empty df_tail
            }

        with sqlite3.connect(db_path) as conn:
            # First, get all available months for the dropdown
            try:
                available_months_df = pd.read_sql_query(
                    "SELECT DISTINCT log_month FROM prediction_logs WHERE log_month IS NOT NULL ORDER BY log_month DESC", 
                    conn
                )
                available_months = available_months_df['log_month'].tolist()
            except:
                available_months = []

            # Build the main query based on selected month
            if selected_month:
                query = "SELECT * FROM prediction_logs WHERE log_month = ? ORDER BY timestamp DESC"
                params = (selected_month,)
                print(f"[DEBUG] Filtering by month: {selected_month}")
            else:
                # Show all data when no month is selected
                query = "SELECT * FROM prediction_logs ORDER BY timestamp DESC"
                params = ()
                print(f"[DEBUG] Showing all months")

            df = pd.read_sql_query(query, conn, params=params)

        if df.empty:
            return {
                'total': 0,
                'anomalies': 0,
                'normal': 0,
                'anomaly_rate': 0.0,
                'last_updated': 'No data',
                'available_months': available_months,
                'timestamps': [],
                'anomaly_flags': [],
                'df_tail': [],  # Add empty df_tail
                'selected_month_summary': f"No data found for {selected_month}" if selected_month else "No data available"
            }

        # Convert timestamp column to datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

        # Calculate summary statistics
        total = len(df)
        anomalies = df['anomaly'].sum() if 'anomaly' in df.columns else 0
        normal = total - anomalies
        anomaly_rate = (anomalies / total * 100) if total > 0 else 0.0

        # Get last updated timestamp
        if not df.empty and 'timestamp' in df.columns:
            valid_timestamps = df['timestamp'].dropna()
            if not valid_timestamps.empty:
                last_updated = valid_timestamps.max().strftime('%Y-%m-%d %H:%M:%S')
            else:
                last_updated = 'Unknown'
        else:
            last_updated = 'No timestamps'

        # Prepare timeline data
        timestamps = []
        anomaly_flags = []
        
        if not df.empty and 'timestamp' in df.columns:
            # Limit to recent 1000 records for performance
            recent_df = df.head(1000)
            
            timestamps = recent_df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S').where(
                pd.notna(recent_df['timestamp']), 'N/A'
            ).tolist()
            
            anomaly_flags = recent_df['anomaly'].tolist() if 'anomaly' in recent_df.columns else [0] * len(recent_df)

        # CRITICAL: Add df_tail for dashboard template
        # Get recent records for the table display (limit to 100 for performance)
        df_tail_records = df.head(100) if not df.empty else pd.DataFrame()
        df_tail_clean = clean_dataframe_for_json(df_tail_records)

        # Add month-specific summary
        month_summary = f"Showing data for {selected_month}" if selected_month else f"Showing all {len(available_months)} months"
        if selected_month:
            month_summary += f" ({total} sessions, {anomalies} anomalies, {anomaly_rate:.1f}% anomaly rate)"

        summary = {
            'total': int(total),
            'anomalies': int(anomalies),
            'normal': int(normal),
            'anomaly_rate': round(float(anomaly_rate), 2),
            'last_updated': last_updated,
            'available_months': available_months,
            'timestamps': timestamps,
            'anomaly_flags': anomaly_flags,
            'df_tail': df_tail_clean,  # CRITICAL: Add this field for dashboard template
            'selected_month_summary': month_summary,
            'data_source': f"Database: {os.path.basename(db_path)}",
            'query_month': selected_month or 'All months'
        }

        print(f"[DEBUG] Summary generated: {total} total, {anomalies} anomalies, {len(df_tail_clean)} records in df_tail")
        return summary

    except Exception as e:
        print(f"[ERROR] Summary generation failed: {e}")
        import traceback
        traceback.print_exc()
        
        return {
            'total': 0,
            'anomalies': 0, 
            'normal': 0,
            'anomaly_rate': 0.0,
            'last_updated': f'Error: {str(e)}',
            'available_months': [],
            'timestamps': [],
            'anomaly_flags': [],
            'df_tail': [],  # CRITICAL: Add this field even for errors
            'error': str(e)
        }

# Replace your dashboard route in routes/dashboard.py with this:

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

@dashboard_bp.route('/report')
@login_required()
def report():
    selected_month = request.args.get('month')
    summary = generate_summary_internal(selected_month)
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