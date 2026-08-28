import sqlite3

DATABASE = "security.db"


def get_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_tables():
    conn = get_connection()

    # 1. Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT,
            department TEXT,
            baseline_metadata TEXT
        )
    """)

    # 2. Activity logs table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            action_type TEXT,
            resource_accessed TEXT,
            ip_address TEXT,
            session_info TEXT,

            FOREIGN KEY (user_id)
                REFERENCES users(user_id)
        )
    """)

    # 3. Model results table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS model_results (
            result_id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER NOT NULL,
            anomaly_score REAL,
            is_anomaly INTEGER,
            model_version TEXT,
            scored_at TEXT,

            FOREIGN KEY (log_id)
                REFERENCES activity_logs(log_id)
        )
    """)

    # 4. Alerts table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            log_id INTEGER NOT NULL,
            risk_score REAL,
            severity_bucket TEXT,
            triggered_features TEXT,
            explanation_text TEXT,
            status TEXT DEFAULT 'open',
            created_at TEXT,

            FOREIGN KEY (user_id)
                REFERENCES users(user_id),

            FOREIGN KEY (log_id)
                REFERENCES activity_logs(log_id)
        )
    """)

    conn.commit()
    conn.close()


create_tables()

def insert_user(name, role, department, baseline_metadata=None):
    conn = get_connection()

    cursor = conn.execute("""
        INSERT INTO users (
            name,
            role,
            department,
            baseline_metadata
        )
        VALUES (?, ?, ?, ?)
    """, (name, role, department, baseline_metadata))

    conn.commit()

    user_id = cursor.lastrowid

    conn.close()

    return user_id

def insert_activity_log(
    user_id,
    timestamp,
    action_type,
    resource_accessed=None,
    ip_address=None,
    session_info=None
):
    conn = get_connection()

    cursor = conn.execute("""
        INSERT INTO activity_logs (
            user_id,
            timestamp,
            action_type,
            resource_accessed,
            ip_address,
            session_info
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        timestamp,
        action_type,
        resource_accessed,
        ip_address,
        session_info
    ))

    conn.commit()

    log_id = cursor.lastrowid

    conn.close()

    return log_id

def insert_model_result(
    log_id,
    anomaly_score,
    is_anomaly,
    model_version,
    scored_at
):
    conn = get_connection()

    cursor = conn.execute("""
        INSERT INTO model_results (
            log_id,
            anomaly_score,
            is_anomaly,
            model_version,
            scored_at
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        log_id,
        anomaly_score,
        is_anomaly,
        model_version,
        scored_at
    ))

    conn.commit()

    result_id = cursor.lastrowid

    conn.close()

    return result_id

def insert_alert(
    user_id,
    log_id,
    risk_score,
    severity_bucket,
    triggered_features,
    explanation_text,
    status="open",
    created_at=None
):
    conn = get_connection()

    cursor = conn.execute("""
        INSERT INTO alerts (
            user_id,
            log_id,
            risk_score,
            severity_bucket,
            triggered_features,
            explanation_text,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        log_id,
        risk_score,
        severity_bucket,
        triggered_features,
        explanation_text,
        status,
        created_at
    ))

    conn.commit()

    alert_id = cursor.lastrowid

    conn.close()

    return alert_id

def get_alerts_by_user(user_id):
    conn = get_connection()

    rows = conn.execute("""
        SELECT *
        FROM alerts
        WHERE user_id = ?
        ORDER BY created_at DESC
    """, (user_id,)).fetchall()

    conn.close()

    return rows

def get_recent_activity(limit=20):
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            activity_logs.*,
            users.name
        FROM activity_logs
        JOIN users
            ON activity_logs.user_id = users.user_id
        ORDER BY activity_logs.timestamp DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()

    return rows

def get_recent_alerts(limit=20):
    conn = get_connection()

    rows = conn.execute("""
        SELECT
            alerts.*,
            users.name
        FROM alerts
        JOIN users
            ON alerts.user_id = users.user_id
        ORDER BY alerts.created_at DESC
        LIMIT ?
    """, (limit,)).fetchall()

    conn.close()

    return rows

def get_user_count():
    conn = get_connection()

    row = conn.execute("""
        SELECT COUNT(*) AS count
        FROM users
    """).fetchone()

    conn.close()

    return row["count"]


def get_activity_count():
    conn = get_connection()

    row = conn.execute("""
        SELECT COUNT(*) AS count
        FROM activity_logs
    """).fetchone()

    conn.close()

    return row["count"]


def get_anomaly_count():
    conn = get_connection()

    row = conn.execute("""
        SELECT COUNT(*) AS count
        FROM model_results
        WHERE is_anomaly = 1
    """).fetchone()

    conn.close()

    return row["count"]


def get_open_alert_count():
    conn = get_connection()

    row = conn.execute("""
        SELECT COUNT(*) AS count
        FROM alerts
        WHERE status = 'open'
    """).fetchone()

    conn.close()

    return row["count"]

def update_alert_status(alert_id, status):
    allowed_statuses = {"open", "reviewed", "dismissed"}

    if status not in allowed_statuses:
        raise ValueError(
            "Status must be open, reviewed, or dismissed"
        )

    conn = get_connection()

    cursor = conn.execute("""
        UPDATE alerts
        SET status = ?
        WHERE alert_id = ?
    """, (status, alert_id))

    conn.commit()

    updated = cursor.rowcount

    conn.close()

    return updated

if __name__ == "__main__":
    create_tables()
    print("Database tables created successfully!")
