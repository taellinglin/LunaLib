import sqlite3
import os
from lunalib.utils.console import print_info, print_error
import sqlite3
import os

# Example script to inspect wallets.db and print table names and first few rows

def inspect_wallets_db(db_path):
    if not os.path.exists(db_path):
        print_error(f"File not found: {db_path}")
        return
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    print_info("Tables in wallets.db:")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    for (table_name,) in tables:
        print_info(f"\nTable: {table_name}")
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        print_info("Columns: " + str([col[1] for col in columns]))
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 5")
        rows = cursor.fetchall()
        for row in rows:
            print_info(row)
    conn.close()

if __name__ == "__main__":
    print_info("Usage: python inspect_wallets_db.py <path_to_wallets.db>")
    inspect_wallets_db(os.path.expanduser("~/.lunawallet/wallets.db"))
