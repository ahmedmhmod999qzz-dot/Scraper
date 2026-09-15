"""main.py — نقطة دخول The Hunter (خفيف على الذاكرة)"""
import asyncio
import os
import sys
import threading

from config.settings import settings
from utils.logger import logger
from core.orchestrator import Orchestrator
from core.bot_handler import bot
from core.storage import storage
from core.notifier import send_message
from web import run_web


CYCLE_INTERVAL_SECONDS = int(os.environ.get("CYCLE_INTERVAL", "300"))


async def scanner_loop():
    orchestrator = Orchestrator()
    # إشعار بدء
    try:
        stats = storage.stats()
        await send_message(
            f"🟢 *The Hunter استُبدئ*\n\n"
            f"📦 مستودعات سابقة: `{stats['repos_scanned']}`\n"
            f"🔑 نتائج مخزنة: `{stats['total_findings']}`"
        )
    except Exception:
        pass

    while True:
        try:
            logger.info("[Main] بدء دورة جديدة...")
            new = await orchestrator.scan_cycle()
            logger.info(f"[Main] الدورة انتهت ({new} جديدة)")
        except Exception as e:
            logger.exception(f"[Main] خطأ في الدورة: {e}")
        await asyncio.sleep(CYCLE_INTERVAL_SECONDS)


async def async_main():
    logger.info("╔" + "═" * 60 + "╗")
    logger.info("║           The Hunter — GitHub Secret Scanner            ║")
    logger.info("╚" + "═" * 60 + "╝")

    try:
        settings.validate()
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    await asyncio.gather(
        scanner_loop(),
        bot.poll_loop(),
    )


def run_async_in_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(async_main())


if __name__ == "__main__":
    worker = threading.Thread(target=run_async_in_thread, daemon=True)
    worker.start()
    logger.info("[Main] بدء خادم الويب...")
    run_web()
