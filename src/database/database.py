import csv
import sqlite3

DB_PATH = "data/alerts.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def create_database():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        severity TEXT CHECK(
            severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
            ),
        source_ip TEXT,
        port TEXT,
        status TEXT CHECK(
            status IN ('NEW', 'INVESTIGATING', 'ESCALATED', 'CLOSED')
            ),
        mitre_id TEXT,
        created_at TEXT
    );
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        verdict TEXT CHECK(
            verdict IN ('TRUE POSITIVE', 'FALSE POSITIVE', 'BENIGN')
            ),
        status TEXT CHECK(
            status IN ('NEW', 'INVESTIGATING', 'ESCALATED', 'CLOSED')
            ),
        created_at TEXT,
        FOREIGN KEY(alert_id) 
            REFERENCES alerts(id)
            ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id INTEGER,
        note TEXT,
        created_at TEXT,
        FOREIGN KEY(case_id)
            REFERENCES cases(id)
            ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        event_type TEXT,
        username TEXT,
        source_ip TEXT,
        port TEXT,
        path TEXT,
        method TEXT,
        http_status TEXT,
        event_id INTEGER,
        raw_log TEXT
    );
    CREATE TABLE IF NOT EXISTS alert_events (
        alert_id INTEGER,
        event_id INTEGER,

        PRIMARY KEY(alert_id, event_id),

        FOREIGN KEY(alert_id)
            REFERENCES alerts(id)
            ON DELETE CASCADE,

        FOREIGN KEY(event_id)
            REFERENCES events(id)
            ON DELETE CASCADE
    );
    """)

    conn.commit()
    conn.close()

# events:

def create_events(events):

    conn = get_connection()

    cursor = conn.cursor()

    for event in events:
        cursor.execute(
            """
            INSERT INTO events (
            timestamp,
            source, 
            event_type, 
            username,
            source_ip,
            port, 
            path,
            method,
            http_status,
            event_id,
            raw_log
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
        (
            event["timestamp"],
            event["source"],
            event["event_type"],
            event["username"],
            event["source_ip"],
            event["port"],
            event["path"],
            event["method"],
            event["http_status"],
            event["event_id"],
            event["raw_log"]
        ),
            )

    conn.commit()
    conn.close()

def get_event(event_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM events WHERE id = ?
        """,
        (event_id,)
    )

    row = cursor.fetchone()

    conn.close()

    return dict(row) if row else None

def get_all_events():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM events
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_events_for_alert(alert_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT events.* FROM events
        JOIN alert_events ON events.id = alert_events.event_id
        WHERE alert_id = ?
        """,
        ( alert_id, )
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def clear_events():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM events")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='events'")

    conn.commit()
    conn.close()

# alerts:

def create_alerts(alerts):

    conn = get_connection()

    cursor = conn.cursor()

    for alert in alerts:
        cursor.execute(
                """
            INSERT INTO alerts (
                title,
                severity,
                source_ip,
                port,
                status,
                mitre_id,
                created_at
                )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                alert["title"],
                alert["severity"],
                alert["source_ip"],
                alert["port"],
                alert["status"],
                alert["mitre_id"],
                alert["created_at"]
            )
        )

        alert_id = cursor.lastrowid

        for event_id in alert["event_ids"]:
            cursor.execute(
                """
                INSERT INTO alert_events(alert_id, event_id)
                VALUES (?, ?)
                """,
                (alert_id, event_id)
            )

    conn.commit()
    conn.close()

def get_alert(alert_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM alerts WHERE id = ?
        """,
        (alert_id,)
    )

    row = cursor.fetchone()

    conn.close()

    return row

def get_all_alerts():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM alerts
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def clear_alerts():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM alerts")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='alerts'")

    conn.commit()
    conn.close()

def update_alert_status(alert_id, status):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE alerts SET status = ? WHERE id = ?
        """,
        (status, alert_id)
    )

    conn.commit()
    conn.close()

def get_alert_count_by_status(status):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*) FROM alerts WHERE status = ?
        """,
        (status,)
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

# cases:

def create_case(alert_id, verdict, status, created_at):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT into cases (alert_id, verdict, status, created_at) VALUES(?, ?, ?, ?)
        """,
        (alert_id, verdict, status, created_at)
        )

    conn.commit()
    conn.close()

def get_case(case_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM cases WHERE id = ?
        """,
        (case_id,)
    )

    row = cursor.fetchone()

    conn.close()

    return row

def get_cases(alert_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM cases WHERE alert_id = ?
        """,
        (alert_id,)
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_all_cases():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM cases
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def clear_cases():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM cases")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='cases'")

    conn.commit()
    conn.close()

def update_case_status(case_id, status):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE cases SET status = ? WHERE id = ?
        """,
        (status, case_id)
    )

    conn.commit()
    conn.close()

def update_case_verdict(case_id, verdict):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE cases SET verdict = ? WHERE id = ?
        """,
        (verdict, case_id)
    )

    conn.commit()
    conn.close()

# notes:

def create_note(case_id, note, created_at):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO notes (case_id, note, created_at) VALUES(?, ?, ?)
        """,
        (case_id, note, created_at)
        )

    conn.commit()
    conn.close()

def get_notes(case_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM notes WHERE case_id = ?
        """,
        (case_id,)
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def get_all_notes():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT * FROM notes
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return rows

def clear_notes():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("DELETE FROM notes")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='notes'")

    conn.commit()
    conn.close()
