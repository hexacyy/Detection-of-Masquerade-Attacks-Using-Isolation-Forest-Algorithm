#!/usr/bin/env python3
"""
Quick fix for timestamp format issue in Static Report
This updates the report route to handle different timestamp formats
"""

import os
import re

def fix_timestamp_parsing():
    """Fix the timestamp parsing issue in routes/dashboard.py"""
    
    dashboard_file = "routes/dashboard.py"
    
    if not os.path.exists(dashboard_file):
        print(f"❌ File not found: {dashboard_file}")
        return False
    
    try:
        # Read the file
        with open(dashboard_file, 'r') as f:
            content = f.read()
        
        # Find and replace the problematic timestamp conversion
        old_pattern = r"df\['timestamp'\] = pd\.to_datetime\(df\['timestamp'\]\)"
        
        new_code = """try:
                    # Try standard format first
                    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S')
                except ValueError:
                    try:
                        # Try with mixed formats
                        df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed')
                    except ValueError:
                        # Last resort - let pandas infer
                        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
                        print("[WARNING] Some timestamps could not be parsed")"""
        
        # Replace the problematic line
        if old_pattern in content:
            content = re.sub(old_pattern, new_code, content)
            
            # Write back to file
            with open(dashboard_file, 'w') as f:
                f.write(content)
            
            print("✅ Fixed timestamp parsing in routes/dashboard.py")
            print("🔄 Restart your Flask app to apply the fix")
            return True
        else:
            print("⚠️  Pattern not found - file may already be fixed or different")
            return False
            
    except Exception as e:
        print(f"❌ Error fixing file: {e}")
        return False

def alternative_fix():
    """Alternative: Add the fix manually to your routes/dashboard.py"""
    
    print("\n📝 MANUAL FIX INSTRUCTIONS:")
    print("=" * 50)
    print("In routes/dashboard.py, find this line:")
    print("   df['timestamp'] = pd.to_datetime(df['timestamp'])")
    print("\nReplace it with:")
    print("""
try:
    # Try standard format first
    df['timestamp'] = pd.to_datetime(df['timestamp'], format='%Y-%m-%d %H:%M:%S')
except ValueError:
    try:
        # Try with mixed formats
        df['timestamp'] = pd.to_datetime(df['timestamp'], format='mixed')
    except ValueError:
        # Last resort - let pandas infer
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        print("[WARNING] Some timestamps could not be parsed")
""")
    print("\nThen restart your Flask app.")

if __name__ == '__main__':
    print("🔧 FIXING TIMESTAMP FORMAT ISSUE")
    print("=" * 40)
    
    success = fix_timestamp_parsing()
    
    if not success:
        alternative_fix()
    
    print("\n🎯 After fixing:")
    print("1. Restart your Flask app")
    print("2. Go to /report")
    print("3. Select '2025-06' from dropdown")
    print("4. Data should display without timestamp errors!")