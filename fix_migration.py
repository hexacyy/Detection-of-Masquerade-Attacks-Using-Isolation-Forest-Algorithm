#!/usr/bin/env python3
"""
Fix Migration Script - Handle the password_changed_at column issue
Run this to complete the migration
"""

import sqlite3
import os
from datetime import datetime
from config import DB_FILE

def fix_password_changed_at_column():
    """Fix the password_changed_at column issue"""
    print("🔧 Fixing password_changed_at column...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    try:
        # Add the column without a default value first
        c.execute("ALTER TABLE users ADD COLUMN password_changed_at TEXT")
        print("  ✅ Added password_changed_at column")
        
        # Update existing users with current timestamp
        current_time = datetime.now().isoformat()
        c.execute("UPDATE users SET password_changed_at = ? WHERE password_changed_at IS NULL", (current_time,))
        updated_rows = c.rowcount
        print(f"  ✅ Updated {updated_rows} existing users with current timestamp")
        
        conn.commit()
        
    except sqlite3.Error as e:
        if "duplicate column name" in str(e).lower():
            print("  ⏭️  Column password_changed_at already exists")
            # Just update NULL values
            current_time = datetime.now().isoformat()
            c.execute("UPDATE users SET password_changed_at = ? WHERE password_changed_at IS NULL", (current_time,))
            updated_rows = c.rowcount
            if updated_rows > 0:
                print(f"  ✅ Updated {updated_rows} users with missing timestamps")
            conn.commit()
        else:
            print(f"  ❌ Error: {e}")
    
    conn.close()

def verify_complete_migration():
    """Final verification that everything is working"""
    print("🔍 Final verification...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check users table structure
    c.execute("PRAGMA table_info(users)")
    columns_info = c.fetchall()
    user_columns = [column[1] for column in columns_info]
    
    print(f"  📋 Users table columns ({len(user_columns)}):")
    for i, col_info in enumerate(columns_info, 1):
        print(f"    {i:2d}. {col_info[1]} ({col_info[2]})")
    
    # Check for required security columns
    required_security_columns = [
        'must_change_password', 'temp_password_expires', 'password_changed_at',
        'failed_login_attempts', 'account_locked_until', 'last_login_at', 'last_login_ip'
    ]
    
    missing_columns = [col for col in required_security_columns if col not in user_columns]
    if missing_columns:
        print(f"  ❌ Still missing columns: {missing_columns}")
        return False
    else:
        print(f"  ✅ All security columns present!")
    
    # Check new tables
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [table[0] for table in c.fetchall()]
    
    required_tables = ['password_history', 'security_audit_log', 'user_sessions']
    missing_tables = [table for table in required_tables if table not in tables]
    
    if missing_tables:
        print(f"  ❌ Missing tables: {missing_tables}")
        return False
    else:
        print(f"  ✅ All security tables present: {required_tables}")
    
    # Check existing users
    c.execute("SELECT id, username, role, password_changed_at FROM users")
    users = c.fetchall()
    print(f"  👥 Existing users ({len(users)}):")
    for user in users:
        print(f"    - {user[1]} ({user[2]}) - Last changed: {user[3] or 'Not set'}")
    
    conn.close()
    return True

def main():
    """Main fix function"""
    print("🔧 Fixing Migration Issues")
    print("=" * 40)
    
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file not found: {DB_FILE}")
        return False
    
    # Fix the column issue
    fix_password_changed_at_column()
    
    # Final verification
    if verify_complete_migration():
        print("\n" + "=" * 40)
        print("🎉 Migration fix completed successfully!")
        print("\n✅ Your database is now ready for enhanced security features!")
        print("\nNext steps:")
        print("1. ✅ Database migration complete")
        print("2. 🔄 Update Flask routes with new security features")
        print("3. 📄 Add new templates for password management")
        print("4. 🧪 Test the system")
        return True
    else:
        print("\n❌ Migration fix failed!")
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)