"""
seed.py — Populate database with realistic demo data
Run this once to fill your dashboard with sample detections:
    cd api/
    python seed.py
"""
import sqlite3
from datetime import datetime, timedelta
import random

DB_PATH = "detections.db"

PHISHING_URLS = [
    "http://paypal-secure-login-verify.com/account/update",
    "http://amaz0n-prime-reward.net/claim?user=12345",
    "http://192.168.1.1/secure/bank-login.php",
    "http://verify-bank-account.top/update-now",
    "http://instagram-login-verify.ru/confirm",
    "http://bit.ly/3xR4mPh-login",
    "http://secure-paypal-verify.xyz/signin",
    "http://apple-id-locked.suspicious.com/unlock",
    "http://microsoft-account-suspended.net/verify",
    "http://netflix-billing-update.top/payment",
]

LEGIT_URLS = [
    "https://google.com",
    "https://github.com",
    "https://stackoverflow.com",
    "https://amazon.com",
    "https://microsoft.com",
    "https://apple.com",
    "https://youtube.com",
    "https://linkedin.com",
    "https://wikipedia.org",
    "https://python.org",
    # Yenepoya University portals
    "https://yenepoya.edu.in",
    "https://student.yenepoya.edu.in/",
    "https://ytincubator.com/",
    "https://yengage.yenepoya.edu.in/",
    "https://vidyen.yenepoya.in/",
    "https://www.ydc.yenepoya.edu.in/",
]

SOURCES = ["extension", "dashboard", "popup_manual", "batch", "api"]

def seed():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0,
            timestamp  TEXT NOT NULL,
            source     TEXT DEFAULT 'api'
        )
    """)
    # Add risk_score column if upgrading an old DB
    try:
        conn.execute("ALTER TABLE detections ADD COLUMN risk_score REAL NOT NULL DEFAULT 0")
    except Exception:
        pass

    existing = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
    if existing > 0:
        print(f"[!] Database already has {existing} records. Skipping seed.")
        print("    Delete detections.db first if you want to reseed.")
        conn.close()
        return

    count = 0
    for i in range(60):
        days_ago   = random.randint(0, 6)
        hours_ago  = random.randint(0, 23)
        mins_ago   = random.randint(0, 59)
        ts = (datetime.utcnow()
              - timedelta(days=days_ago, hours=hours_ago, minutes=mins_ago)
              ).isoformat()

        is_phishing = random.random() < 0.45  # 45% phishing rate
        if is_phishing:
            url  = random.choice(PHISHING_URLS)
            pred = "phishing"
            conf = round(random.uniform(0.78, 0.99), 4)
        else:
            url  = random.choice(LEGIT_URLS)
            pred = "legitimate"
            conf = round(random.uniform(0.82, 0.99), 4)

        source = random.choice(SOURCES)
        risk = conf if pred == "phishing" else round(1.0 - conf, 4)
        conn.execute(
            "INSERT INTO detections (url,prediction,confidence,risk_score,timestamp,source) VALUES(?,?,?,?,?,?)",
            (url, pred, conf, risk, ts, source)
        )
        count += 1

    conn.commit()
    conn.close()
    print(f"[✓] Seeded {count} demo detections into {DB_PATH}")
    print("    Now open http://127.0.0.1:5000 to see the dashboard!")

if __name__ == "__main__":
    seed()
