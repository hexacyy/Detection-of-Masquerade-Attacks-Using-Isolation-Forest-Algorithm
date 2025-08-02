#!/usr/bin/env python3
"""
Database Migration Script - Enhanced Security Features
Run this script to add new security columns and tables to your existing database
"""

import sqlite3
import os
from datetime import datetime
from config import DB_FILE

def backup_database():
    """Create a backup of the current database before migration"""
    if os.path.exists(DB_FILE):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"{DB_FILE}.backup_{timestamp}"
        
        print(f"📦 Creating backup: {backup_file}")
        
        # Simple file copy for SQLite
        import shutil
        shutil.copy2(DB_FILE, backup_file)
        print(f"✅ Backup created successfully!")
        return backup_file
    return None

def check_column_exists(cursor, table_name, column_name):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = [column[1] for column in cursor.fetchall()]
    return column_name in columns

def migrate_users_table():
    """Add new security columns to the users table"""
    print("🔧 Migrating users table...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # List of new columns to add
    new_columns = [
        ("must_change_password", "INTEGER DEFAULT 0"),
        ("temp_password_expires", "TEXT"),
        ("password_changed_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("failed_login_attempts", "INTEGER DEFAULT 0"),
        ("account_locked_until", "TEXT"),
        ("last_login_at", "TIMESTAMP"),
        ("last_login_ip", "TEXT")
    ]
    
    for column_name, column_definition in new_columns:
        if not check_column_exists(c, 'users', column_name):
            try:
                c.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_definition}")
                print(f"  ✅ Added column: {column_name}")
            except sqlite3.Error as e:
                print(f"  ❌ Failed to add {column_name}: {e}")
        else:
            print(f"  ⏭️  Column {column_name} already exists")
    
    conn.commit()
    conn.close()
    print("✅ Users table migration completed!")

def create_password_history_table():
    """Create password history table"""
    print("🔧 Creating password_history table...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    
    # Create index for better performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id)')
    
    conn.commit()
    conn.close()
    print("✅ Password history table created!")

def create_security_audit_log_table():
    """Create security audit log table"""
    print("🔧 Creating security_audit_log table...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS security_audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        username TEXT,
        action TEXT NOT NULL,
        details TEXT,
        ip_address TEXT,
        user_agent TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER DEFAULT 1
    )''')
    
    # Create indexes for better performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_user_id ON security_audit_log(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON security_audit_log(timestamp)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_audit_action ON security_audit_log(action)')
    
    conn.commit()
    conn.close()
    print("✅ Security audit log table created!")

def create_user_sessions_table():
    """Create user sessions table for better session management"""
    print("🔧 Creating user_sessions table...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS user_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        is_active INTEGER DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )''')
    
    # Create indexes for better performance
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON user_sessions(session_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at)')
    
    conn.commit()
    conn.close()
    print("✅ User sessions table created!")

def verify_migration():
    """Verify that all tables and columns were created successfully"""
    print("🔍 Verifying migration...")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Check users table columns
    c.execute("PRAGMA table_info(users)")
    user_columns = [column[1] for column in c.fetchall()]
    
    required_columns = [
        'id', 'username', 'password_hash', 'role', 'created_at',
        'must_change_password', 'temp_password_expires', 'password_changed_at',
        'failed_login_attempts', 'account_locked_until', 'last_login_at', 'last_login_ip'
    ]
    
    missing_columns = [col for col in required_columns if col not in user_columns]
    if missing_columns:
        print(f"  ❌ Missing columns in users table: {missing_columns}")
        return False
    else:
        print(f"  ✅ Users table has all required columns ({len(user_columns)} total)")
    
    # Check if new tables exist
    c.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [table[0] for table in c.fetchall()]
    
    required_tables = ['users', 'password_history', 'security_audit_log', 'user_sessions']
    missing_tables = [table for table in required_tables if table not in tables]
    
    if missing_tables:
        print(f"  ❌ Missing tables: {missing_tables}")
        return False
    else:
        print(f"  ✅ All required tables exist: {required_tables}")
    
    conn.close()
    return True

def main():
    """Main migration function"""
    print("🚀 Starting Enhanced Security Database Migration")
    print("=" * 50)
    
    # Check if database exists
    if not os.path.exists(DB_FILE):
        print(f"❌ Database file not found: {DB_FILE}")
        print("Please run database_setup.py first!")
        return False
    
    # Create backup
    backup_file = backup_database()
    
    try:
        # Run migrations
        migrate_users_table()
        create_password_history_table()
        create_security_audit_log_table()
        create_user_sessions_table()
        
        # Verify migration
        if verify_migration():
            print("\n" + "=" * 50)
            print("🎉 Migration completed successfully!")
            print("\nNext steps:")
            print("1. Update your Flask routes with new security features")
            print("2. Add the new templates for password management")
            print("3. Test the enhanced user management system")
            if backup_file:
                print(f"\n📦 Backup file created: {backup_file}")
            return True
        else:
            print("\n❌ Migration verification failed!")
            return False
            
    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        if backup_file:
            print(f"You can restore from backup: {backup_file}")
        return False

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)