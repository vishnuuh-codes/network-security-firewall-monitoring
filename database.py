
# DATABASE MANAGEMENT MODULE

import sqlite3

DB_NAME = "firewall_security.db"


def get_connection():
    return sqlite3.connect(DB_NAME)


def initialize_database():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        destination_ip TEXT,
        port INTEGER,
        protocol TEXT,
        traffic_type TEXT,
        access_status TEXT,
        firewall_rule TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_ip TEXT,
        blocked_attempts INTEGER,
        severity TEXT,
        alert_message TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()


def save_traffic(log):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO traffic_logs
    (source_ip, destination_ip, port, protocol,
     traffic_type, access_status, firewall_rule)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        log["Source IP"],
        log["Destination IP"],
        log["Port"],
        log["Protocol"],
        log["Traffic Type"],
        log["Access Status"],
        log["Firewall Rule"]
    ))

    conn.commit()
    conn.close()


def get_traffic_logs():

    conn = get_connection()

    import pandas as pd
    df = pd.read_sql_query(
        "SELECT * FROM traffic_logs ORDER BY id DESC",
        conn
    )

    conn.close()
    return df


def get_suspicious_ips(threshold=3):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT source_ip, COUNT(*) AS attempts
    FROM traffic_logs
    WHERE access_status = 'BLOCKED'
    GROUP BY source_ip
    HAVING COUNT(*) >= ?
    """, (threshold,))

    results = cursor.fetchall()
    conn.close()

    return results


def save_alert(source_ip, attempts):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT COUNT(*) FROM security_alerts
    WHERE source_ip = ? AND alert_message = ?
    """, (source_ip, "Repeated unauthorized access"))

    exists = cursor.fetchone()[0]

    if not exists:
        cursor.execute("""
        INSERT INTO security_alerts
        (source_ip, blocked_attempts, severity, alert_message)
        VALUES (?, ?, ?, ?)
        """, (
            source_ip,
            attempts,
            "HIGH",
            "Repeated unauthorized access"
        ))

    conn.commit()
    conn.close()


def get_alerts():

    conn = get_connection()
    import pandas as pd

    df = pd.read_sql_query(
        "SELECT * FROM security_alerts ORDER BY id DESC",
        conn
    )

    conn.close()
    return df


initialize_database()
print("Database Module Loaded Successfully")
