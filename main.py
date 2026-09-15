"""main.py — نقطة دخول The Hunter"""
import asyncio
import signal
import sys

from config.settings import settings
from utils.logger import logger
from core.orchestrator import Orchestrator
from core.notifier import send_message
from core.storage import storage


CYCLE_INTERVAL_SECONDS = 600  # 10 دقائق بين الدورات


async def _graceful_shutdown(signame: str):
    logger.info(f"[Main] استقبلت {signame} — إيقاف نظيف")
    sys.exit(0)


async def main():
    logger.info("╔" + "═" * 60 + "╗")
    logger.info("║           The Hunter — GitHub Secret Scanner            ║")
    logger.info("╚" + "═" * 60 + "╝")

    # تحقق من الإعدادات
    try:
        settings.validate()
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # إشعار البدء
    stats = storage.stats()
    await send_message(
        f"🟢 *The Hunter استُبدئ*\n\n"
        f"📦 مستودعات مفحوصة سابقًا: `{stats['repos_scanned']}`\n"
        f"🔑 نتائج مخزنة: `{stats['total_findings']}`\n"
        f"🕒 `{__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
    )

    orchestrator = Orchestrator()

    # حلقة لا نهائية
    while True:
        try:
            logger.info("[Main] بدء دورة جديدة...")
            new_findings = await orchestrator.scan_cycle()
            logger.info(f"[Main] الدورة انتهت ({new_findings} جديدة). انتظار {CYCLE_INTERVAL_SECONDS}s...")
        except Exception as e:
            logger.exception(f"[Main] استثناء في الدورة: {e}")
            await send_message(f"⚠️ *خطأ في الدورة الرئيسية*\n```\n{str(e)[:500]}\n```")

        await asyncio.sleep(CYCLE_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[Main] إيقاف يدوي")
