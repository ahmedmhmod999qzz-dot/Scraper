
"""core/notifier.py — إرسال تنبيهات Telegram منسقة مع المفتاح الكامل"""
import asyncio
import aiohttp
from datetime import datetime

from config.settings import settings
from utils.logger import logger


TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


async def send_message(text: str, markdown: bool = True, keyboard: dict | None = None) -> bool:
    """يرسل رسالة نصية إلى Telegram."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.warning("[Telegram] التوكن أو Chat ID مفقود")
        return False

    url = TELEGRAM_API.format(token=settings.TELEGRAM_BOT_TOKEN)
    payload = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": text[:4000],
        "disable_web_page_preview": True,
    }
    if markdown:
        payload["parse_mode"] = "Markdown"
    if keyboard:
        payload["reply_markup"] = keyboard

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(f"[Telegram] HTTP {resp.status}: {body[:200]}")
                    return False
                return True
    except Exception as e:
        logger.exception(f"[Telegram] استثناء: {e}")
        return False


async def notify_finding(finding: dict, cvss: float, severity: str, emoji: str):
    """يرسل تنبيها منسقًا لسر مكتشف مع المفتاح الكامل."""
    repo = finding.get("repo", "?")
    rule = finding.get("rule_id", "?")
    file_path = finding.get("file", "?")
    line = finding.get("line", 0)
    preview = finding.get("secret_raw", "") or finding.get("secret_preview", "")
    verified = finding.get("verified", False)
    source = finding.get("source", "?")
    commit = finding.get("commit", "")
    entropy = finding.get("entropy", 0.0)

    status_icon = "✅ *مُتحقق*" if verified else "❓ *غير مُتحقق*"
    verified_badge = "🔥 *VERIFIED* 🔥\n" if verified else ""

    if commit and len(commit) >= 7:
        commit_link = f"[`{commit[:7]}`](https://github.com/{repo}/commit/{commit})"
    else:
        commit_link = "_غير متاح_"

    # ═══ الرسالة الرئيسية ═══
    text = (
        f"{emoji} *{severity}* — CVSS `{cvss:.1f}`\n"
        f"{verified_badge}\n"
        f"🔑 *النوع:* `{rule}`\n"
        f"📦 *المستودع:* `{repo}`\n"
        f"📄 *الملف:* `{file_path}`"
        f"{f' (سطر {line})' if line else ''}\n"
        f"🔍 *الكاشف:* `{source}`\n"
        f"🔒 *الحالة:* {status_icon}\n"
        f"📊 *Entropy:* `{entropy:.2f}`\n"
        f"🌿 *Commit:* {commit_link}\n"
        f"⏰ `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
    )
    await send_message(text)

    # ═══ رسالة منفصلة: المفتاح الكامل (في code block للنسخ) ═══
    if preview:
        secret_msg = (
            f"🔐 *المفتاح الكامل* — `{repo}`\n"
            f"`{rule}`\n\n"
            f"```\n{preview}\n```\n"
            f"👇 اضغط مطولًا للنسخ"
        )
        await send_message(secret_msg)
