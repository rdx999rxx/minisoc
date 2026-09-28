import hashlib
import sqlite3
from pathlib import Path

DB_PATH = Path("minisoc.db")


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            fingerprint TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


def _fingerprint(alert_type, severity, source_ip, description):
    value = f"{alert_type}|{severity}|{source_ip}|{description}"
    return hashlib.sha256(value.encode()).hexdigest()


def add_alert(alert_type, severity, source_ip, description):
    fingerprint = _fingerprint(
        alert_type,
        severity,
        source_ip,
        description,
    )

    connection = get_connection()

    connection.execute(
        """
        INSERT OR IGNORE INTO alerts
        (alert_type, severity, source_ip, description, fingerprint)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            alert_type,
            severity,
            source_ip,
            description,
            fingerprint,
        ),
    )

    connection.commit()
    connection.close()


def get_alerts():
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT id, alert_type, severity, source_ip,
               description, status, created_at
        FROM alerts
        ORDER BY created_at DESC
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def update_alert_status(alert_id, status):
    connection = get_connection()

    connection.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE id = ?
        """,
        (status, alert_id),
    )

    connection.commit()
    connection.close()


def clear_alerts():
    connection = get_connection()
    connection.execute("DELETE FROM alerts")
    connection.commit()
    connection.close()
