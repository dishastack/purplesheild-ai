import sqlite3
from pathlib import Path

# Database configuration
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

DATA_DIR.mkdir(exist_ok=True)

DATABASE_PATH = DATA_DIR / "purpleshield.db"


def get_connection():
    """Create a database connection."""

    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create the security events table."""

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            event_type TEXT NOT NULL,

            source TEXT,

            severity TEXT NOT NULL,

            description TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

        )
    """)

    connection.commit()
    connection.close()

    print("PurpleShield AI database initialized.")


def add_security_event(event_type, source, severity, description):

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events
        (event_type, source, severity, description)

        VALUES (?, ?, ?, ?)
    """, (
        event_type,
        source,
        severity,
        description
    ))

    connection.commit()

    event_id = cursor.lastrowid

    connection.close()

    return event_id


def get_security_events():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM security_events
        ORDER BY created_at DESC
    """)

    events = cursor.fetchall()

    connection.close()

    return events