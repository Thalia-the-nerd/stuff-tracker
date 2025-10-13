# =================================================================
# MBSH Robotics - User Management Script (Interactive CLI Version)
# =================================================================
# Author: Thalia
# Description: An interactive command-line tool to manage users in
#              the inventory tracker's SQLite database.
#
# Requirements:
# - Python 3
# - bcrypt library (pip install bcrypt)
#
# Usage:
# python3 manage_users.py
# > Then follow the on-screen menu.
# =================================================================

import sqlite3
import bcrypt
from getpass import getpass

DB_FILE = './mbs_robotics_inventory.db'

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as e:
        print(f"\n[Error] Database connection error: {e}")
        exit(1)

def check_and_update_schema():
    """Checks the database schema and adds missing columns to the users table if necessary."""
    print("Checking database schema...")
    conn = get_db_connection()
    if not conn:
        return
    try:
        cur = conn.cursor()
        # Check for 'status' and 'timeout_until' columns in users table
        columns = cur.execute("PRAGMA table_info(users)").fetchall()
        column_names = [col['name'] for col in columns]

        if 'status' not in column_names:
            print("  -> 'status' column missing. Adding it now...")
            # Added CHECK constraint to match the Node.js app schema
            cur.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'timed_out', 'banned'))")
            print("     ... 'status' column added.")

        if 'timeout_until' not in column_names:
            print("  -> 'timeout_until' column missing. Adding it now...")
            cur.execute("ALTER TABLE users ADD COLUMN timeout_until DATETIME")
            print("     ... 'timeout_until' column added.")
        
        conn.commit()
        print("Schema check complete.")
    except sqlite3.Error as e:
        # If the users table doesn't exist at all, this will fail. That's okay.
        if "no such table: users" not in str(e):
             print(f"\n[Error] An error occurred during schema check: {e}")
    finally:
        if conn:
            conn.close()


def list_users():
    """Lists all users in the database."""
    print("\n--- All Users ---")
    conn = get_db_connection()
    try:
        users = conn.execute('SELECT id, name, student_id, role, status FROM users ORDER BY name').fetchall()
        print(f"{'ID':<5} {'Name':<25} {'Student ID':<20} {'Role':<10} {'Status':<10}")
        print("-" * 75)
        if not users:
            print("No users found.")
        else:
            for user in users:
                print(f"{user['id']:<5} {user['name']:<25} {user['student_id']:<20} {user['role']:<10} {user['status']:<10}")
    except sqlite3.Error as e:
        print(f"\n[Error] An error occurred: {e}")
    finally:
        conn.close()

def add_user():
    """Prompts for and adds a new user to the database."""
    print("\n--- Add New User ---")
    name = input("Enter user's full name: ")
    student_id = input("Enter user's student ID: ")
    password = getpass("Enter password for user: ")
    role = input("Enter role (user, manager, admin) [default: user]: ").lower() or 'user'

    if not all([name, student_id, password]):
        print("\n[Error] Name, Student ID, and Password cannot be empty.")
        return

    if role not in ['user', 'manager', 'admin']:
        print("\n[Error] Invalid role. Please choose 'user', 'manager', or 'admin'.")
        return

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO users (name, student_id, password, role) VALUES (?, ?, ?, ?)',
            (name, student_id, hashed_password.decode('utf-8'), role)
        )
        conn.commit()
        print(f"\n[Success] Added user '{name}' with student ID '{student_id}'.")
    except sqlite3.IntegrityError:
        print(f"\n[Error] A user with student ID '{student_id}' already exists.")
    except sqlite3.Error as e:
        print(f"\n[Error] An error occurred: {e}")
    finally:
        conn.close()

def set_user_role():
    """Prompts for and updates the role of an existing user."""
    print("\n--- Change User Role ---")
    student_id = input("Enter the student ID of the user to modify: ")
    role = input("Enter the new role (user, manager, admin): ").lower()
    
    if role not in ['user', 'manager', 'admin']:
        print("\n[Error] Invalid role. Please choose 'user', 'manager', or 'admin'.")
        return
        
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET role = ? WHERE student_id = ?", (role, student_id))
        if cur.rowcount == 0:
            print(f"\n[Error] No user found with student ID '{student_id}'.")
        else:
            conn.commit()
            print(f"\n[Success] Updated role for '{student_id}' to '{role}'.")
    except sqlite3.Error as e:
        print(f"\n[Error] An error occurred: {e}")
    finally:
        conn.close()

def reset_password():
    """Prompts for and resets a user's password."""
    print("\n--- Reset User Password ---")
    student_id = input("Enter the student ID of the user: ")
    new_password = getpass("Enter the new password: ")

    if not new_password:
        print("\n[Error] Password cannot be empty.")
        return

    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password = ? WHERE student_id = ?", (hashed_password.decode('utf-8'), student_id))
        if cur.rowcount == 0:
            print(f"\n[Error] No user found with student ID '{student_id}'.")
        else:
            conn.commit()
            print(f"\n[Success] Reset password for '{student_id}'.")
    except sqlite3.Error as e:
        print(f"\n[Error] An error occurred: {e}")
    finally:
        conn.close()

def delete_user():
    """Prompts for and deletes a user from the database."""
    print("\n--- Delete User ---")
    student_id = input("Enter the student ID of the user to delete: ")

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        user = cur.execute("SELECT role FROM users WHERE student_id = ?", (student_id,)).fetchone()
        if not user:
             print(f"\n[Error] No user found with student ID '{student_id}'.")
             return
        if user['role'] == 'admin':
            print("\n[Error] Cannot delete an administrator account.")
            return

        confirm = input(f"Are you sure you want to permanently delete user '{student_id}'? This cannot be undone. (yes/no): ")
        if confirm.lower() != 'yes':
            print("Deletion cancelled.")
            return
            
        cur.execute("DELETE FROM users WHERE student_id = ?", (student_id,))
        conn.commit()
        print(f"\n[Success] Deleted user '{student_id}'.")
    except sqlite3.Error as e:
        print(f"\n[Error] An error occurred: {e}")
    finally:
        conn.close()

def main_menu():
    """Displays the main menu and handles user input."""
    while True:
        print("\n=============================================")
        print("  MBSH Robotics Inventory - User Management")
        print("=============================================")
        print("1. List all users")
        print("2. Add a new user")
        print("3. Change a user's role")
        print("4. Reset a user's password")
        print("5. Delete a user")
        print("6. Exit")
        
        choice = input("\nPlease select an option (1-6): ")
        
        if choice == '1':
            list_users()
        elif choice == '2':
            add_user()
        elif choice == '3':
            set_user_role()
        elif choice == '4':
            reset_password()
        elif choice == '5':
            delete_user()
        elif choice == '6':
            print("Exiting...")
            break
        else:
            print("\n[Error] Invalid option. Please try again.")
            
        input("\nPress Enter to return to the menu...")

if __name__ == '__main__':
    check_and_update_schema()
    main_menu()


