"""utils/logger.py — تسجيل موحد لكل الوحدات"""
import logging
import sys
from config.settings import settings


def setup_logger(name: str = "hunter", level: int = logging.INFO) -> logging.Logger:
    """ينشئ Logger موحدًا يكتب في stdout (Render) وفي ملف."""
    logger = logging.getLogger(name)
    if logger.handlers:          # تجنب إضافة معالجات مكررة
        return logger

    logger.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)-15s │ %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # stdout — يظهر مباشرة في لوحة Render
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # ملف — يبقى حتى لو أُعيد تشغيل الخدمة
    fh = logging.FileHandler(settings.LOGS_DIR / f"{name}.log", encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


logger = setup_logger()
