import os
import sys

# Ensure root is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database.database import engine, Base
from app.database.models import User, Resource, Permission, Session, ActivityLog, Alert

def init_database():
    print("[*] Initializing Prism Network SQLite Database...")
    data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
    os.makedirs(data_dir, exist_ok=True)

    Base.metadata.create_all(bind=engine)
    print("[+] Database tables successfully created:")
    for table_name in Base.metadata.tables.keys():
        print(f"    - {table_name}")

if __name__ == "__main__":
    init_database()
