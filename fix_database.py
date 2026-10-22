
import sqlite3
import shutil
from pathlib import Path
from datetime import datetime

db_path = Path("instance/socialfix.db")

if not db_path.exists():
    print("ERROR: Database not found:", db_path.resolve())
    raise SystemExit(1)

backup_path = db_path.with_name(
    f"socialfix_backup_{datetime.now():%Y%m%d_%H%M%S}.db"
)

shutil.copy2(db_path, backup_path)
print("Backup created:", backup_path)

connection = sqlite3.connect(db_path)

try:
    cursor = connection.cursor()
    cursor.execute('PRAGMA table_info("case")')
    columns = {row[1] for row in cursor.fetchall()}

    if not columns:
        print('ERROR: "case" table not found.')
        raise SystemExit(1)

    if "issue" not in columns:
        cursor.execute(
            'ALTER TABLE "case" ADD COLUMN issue VARCHAR(200)'
        )
        print("Added missing issue column.")
    else:
        print("The issue column already exists.")

    connection.commit()
    print("Database fixed successfully.")

except Exception:
    connection.rollback()
    raise

finally:
    connection.close()
