import sqlite3

conn = sqlite3.connect("cve_database.db")
cursor = conn.cursor()

# Get all tables
cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
tables = cursor.fetchall()

print("Connected! Tables in the database:")
for table in tables:
    print(f" - {table[0]}")

conn.close()
