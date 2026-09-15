"""config/settings.py"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


class Settings:
    GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
    TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
    TELEGRAM_CHAT_ID: str = os.getenv("TELEGRAM_CHAT_ID", "")

    RECENT_DAYS: int = int(os.getenv("RECENT_DAYS", "1"))
    MAX_REPOS_PER_CYCLE: int = int(os.getenv("MAX_REPOS_PER_CYCLE", "10"))  # ← 20 → 10
    MAX_COMMITS_PER_REPO: int = int(os.getenv("MAX_COMMITS_PER_REPO", "5"))

    ROOT_DIR: Path = Path(__file__).resolve().parent.parent
    DATA_DIR: Path = ROOT_DIR / "data"
    LOGS_DIR: Path = ROOT_DIR / "logs"
    DB_PATH: Path = DATA_DIR / "hunter.db"

    ALERT_VALID: bool = os.getenv("ALERT_VALID", "true").lower() == "true"
    ALERT_INVALID: bool = os.getenv("ALERT_INVALID", "false").lower() == "true"
    ALERT_UNVERIFIED: bool = os.getenv("ALERT_UNVERIFIED", "false").lower() == "true"
    HEARTBEAT_MINUTES: int = int(os.getenv("HEARTBEAT_MINUTES", "30"))

    REQUEST_TIMEOUT: int = int(os.getenv("REQUEST_TIMEOUT", "10"))
    RETRY_ATTEMPTS: int = int(os.getenv("RETRY_ATTEMPTS", "3"))
    CONCURRENCY: int = int(os.getenv("CONCURRENCY", "1"))  # ← 2 → 1

    @classmethod
    def validate(cls) -> None:
        errors = []
        if not cls.GITHUB_TOKEN:
            errors.append("GITHUB_TOKEN مطلوب")
        if not cls.TELEGRAM_BOT_TOKEN:
            errors.append("TELEGRAM_BOT_TOKEN مطلوب")
        if not cls.TELEGRAM_CHAT_ID:
            errors.append("TELEGRAM_CHAT_ID مطلوب")
        if errors:
            raise ValueError("❌ إعدادات ناقصة:\n  - " + "\n  - ".join(errors))
        cls.DATA_DIR.mkdir(parents=True, exist_ok=True)
        cls.LOGS_DIR.mkdir(parents=True, exist_ok=True)


settings = Settings()
