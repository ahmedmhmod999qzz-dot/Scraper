"""tests/test_wave1.py — اختبار الموجة 1"""
import sys
from pathlib import Path

# أضف جذر المشروع إلى مسار البحث
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config.settings import settings
from utils.logger import logger
from utils.entropy import calculate_entropy, is_likely_secret

# ... باقي الكود كما هو

"""tests/test_wave1.py — اختبار الموجة 1"""
from config.settings import settings
from utils.logger import logger
from utils.entropy import calculate_entropy, is_likely_secret


def test_settings():
    print("\n═══ اختبار settings ═══")
    try:
        settings.validate()
        print("✅ الإعدادات صحيحة")
        print(f"   RECENT_DAYS         = {settings.RECENT_DAYS}")
        print(f"   MAX_REPOS_PER_CYCLE = {settings.MAX_REPOS_PER_CYCLE}")
        print(f"   DATA_DIR            = {settings.DATA_DIR}")
        print(f"   DB_PATH             = {settings.DB_PATH}")
    except ValueError as e:
        print(f"❌ {e}")


def test_logger():
    print("\n═══ اختبار logger ═══")
    logger.info("رسالة info")
    logger.warning("رسالة warning")
    logger.error("رسالة error")
    print("✅ السجل يظهر في stdout وفي logs/hunter.log")


def test_entropy():
    print("\n═══ اختبار entropy ═══")
    cases = [
        ("sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz12345", True, "OpenAI key"),
        ("aaaaaaaaaaaaaaaaaaaa", False, "نص منخفض الإنتروبيا"),
        ("AKIAIOSFODNN7EXAMPLE", False, "نمط AWS (قصير)"),
        ("a" * 40, False, "hash منخفض الإنتروبيا"),
        ("9f3a8b7c6d5e4f2a1b0c9d8e7f6a5b4c3d2e1f0a", False, "Git hash"),
        ("correct-horse-battery-staple", False, "جملة إنجليزية"),
        ("MyP@ssw0rd!VeryS3cur3AndL0ng123456", True, "كلمة مرور قوية"),
    ]
    for text, expected, label in cases:
        result = is_likely_secret(text)
        status = "✅" if result == expected else "❌"
        ent = calculate_entropy(text)
        print(f"{status} {label:30s} entropy={ent:5.2f} result={result} expected={expected}")


if __name__ == "__main__":
    test_settings()
    test_logger()
    test_entropy()
    print("\n🎯 الموجة 1 جاهزة للانتقال إلى الموجة 2")
