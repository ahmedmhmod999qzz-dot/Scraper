
"""main.py — نقطة دخول The Hunter"""
import asyncio
import sys

from config.settings import settings
from utils.logger import logger
from core.orchestrator import Orchestrator
from core.bot_handler import bot
from core.storage import storage


CYCLE_INTERVAL_SECONDS = 300


async def scanner_loop():
    """حلقة الفحص في الخلفية."""
    orchestrator = Orchestrator()
    while True:
        try:
            logger.info("[Main] بدء دورة جديدة...")
            new = await orchestrator.scan_cycle()
            logger.info(f"[Main] الدورة انتهت ({new} جديدة). انتظار {CYCLE_INTERVAL_SECONDS}s...")
        except Exception as e:
            logger.exception(f"[Main] خطأ في الدورة: {e}")
        await asyncio.sleep(CYCLE_INTERVAL_SECONDS)


async def main():
    logger.info("╔" + "═" * 60 + "╗")
    logger.info("║           The Hunter — GitHub Secret Scanner            ║")
    logger.info("╚" + "═" * 60 + "╝")

    try:
        settings.validate()
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    # شغّل الفحص والبوت معًا
    await asyncio.gather(
        scanner_loop(),
        bot.poll_loop(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("[Main] إيقاف يدوي")
