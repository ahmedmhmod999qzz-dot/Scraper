"""core/storage.py — SQLite لمنع التنبيهات المكررة"""
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path

from config.settings import settings
from utils.logger import logger


class Storage:
    def __init__(self, db_path: Path | None = None):
        self.db_path = db_path or settings.DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """ينشئ الجداول إن لم تكن موجودة."""
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                hash TEXT PRIMARY KEY,
                source TEXT,
                repo TEXT,
                rule_id TEXT,
                file TEXT,
                line INTEGER,
                secret_preview TEXT,
                verified INTEGER,
                cvss REAL,
                first_seen TEXT,
                last_seen TEXT
            );

            CREATE TABLE IF NOT EXISTS scanned_repos (
                full_name TEXT PRIMARY KEY,
                scanned_at TEXT,
                findings_count INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_cvss ON findings(cvss);
            CREATE INDEX IF NOT EXISTS idx_repo ON findings(repo);
        """)
        conn.commit()
        conn.close()

    @staticmethod
    def _hash_finding(finding: dict) -> str:
        """بصمة فريدة لكل سر — نفس المفتاح في مستودعين = نفس البصمة."""
        key = f"{finding.get('rule_id','')}:{finding.get('secret_preview','')}"
        return hashlib.sha256(key.encode()).hexdigest()

    def is_new(self, finding: dict) -> bool:
        """هل هذا السر جديد؟ (لم نرسله سابقًا)"""
        h = self._hash_finding(finding)
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT 1 FROM findings WHERE hash=?", (h,)).fetchone()
        conn.close()
        return row is None

    def save(self, finding: dict, cvss: float):
        """يحفظ سرًا في قاعدة البيانات."""
        h = self._hash_finding(finding)
        now = datetime.utcnow().isoformat()

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            INSERT OR REPLACE INTO findings
            (hash, source, repo, rule_id, file, line, secret_preview, verified, cvss, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT first_seen FROM findings WHERE hash=?), ?), ?)
        """, (
            h,
            finding.get("source", ""),
            finding.get("repo", ""),
            finding.get("rule_id", ""),
            finding.get("file", ""),
            finding.get("line", 0),
            finding.get("secret_preview", ""),
            1 if finding.get("verified") else 0,
            cvss,
            h, now,
            now,
        ))
        conn.commit()
        conn.close()

    def mark_repo_scanned(self, full_name: str, findings_count: int):
        """يسجّل أن مستودعًا فُحص، لمنع إعادة فحصه."""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO scanned_repos VALUES (?, ?, ?)",
            (full_name, datetime.utcnow().isoformat(), findings_count),
        )
        conn.commit()
        conn.close()

    def was_scanned(self, full_name: str, max_age_hours: int = 24) -> bool:
        """هل فُحص هذا المستودع خلال آخر N ساعة؟"""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT scanned_at FROM scanned_repos WHERE full_name=?",
            (full_name,),
        ).fetchone()
        conn.close()

        if not row:
            return False
        try:
            scanned = datetime.fromisoformat(row[0])
            age = (datetime.utcnow() - scanned).total_seconds() / 3600
            return age < max_age_hours
        except Exception:
            return False

    def stats(self) -> dict:
        """إحصائيات سريعة."""
        conn = sqlite3.connect(self.db_path)
        total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM findings WHERE cvss >= 9.0").fetchone()[0]
        verified = conn.execute("SELECT COUNT(*) FROM findings WHERE verified=1").fetchone()[0]
        repos = conn.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0]
        conn.close()
        return {
            "total_findings": total,
            "critical": critical,
            "verified": verified,
            "repos_scanned": repos,
        }


storage = Storage()
