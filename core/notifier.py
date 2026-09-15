"""core/notifier.py — إرسال تنبيهات Telegram منسقة"""
import asyncio
import aiohttp
from datetime import datetime

from config.settings import settings
from utils.logger import logger


TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


def _escape_md(text: str) -> str:
    """يهرب الأحرف الخاصة في MarkdownV2."""
    if not text:
        return ""
    for ch in r"_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


async def send_message(text: str, markdown: bool = True) -> bool:
    """يرسل رسالة نصية إلى Telegram."""
    if not settings.TELEGRAM_BOT_TOKEN or not settings.TELEGRAM_CHAT_ID:
        logger.warning("[Telegram] التوكن أو Chat ID مفقود")
        return False

    url = TELEGRAM_API.format(token=settings.TELEGRAM_BOT_TOKEN)
    payload = {
        "chat_id": settings.TELEGRAM_CHAT_ID,
        "text": text[:4000],  # حد Telegram
        "disable_web_page_preview": True,
    }
    if markdown:
        payload["parse_mode"] = "Markdown"

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
    """يرسل تنبيها منسقًا لسر مكتشف."""
    repo = finding.get("repo", "?")
    rule = finding.get("rule_id", "?")
    file_path = finding.get("file", "?")
    line = finding.get("line", 0)
    preview = finding.get("secret_preview", "")
    verified = finding.get("verified", False)
    source = finding.get("source", "?")
    commit = finding.get("commit", "")

    status_icon = "✅ *مُتحقق*" if verified else "❓ *غير مُتحقق*"
    verified_badge = "🔥 *VERIFIED* 🔥" if verified else ""

    # رابط مباشر للـ commit إن أمكن
    if commit and len(commit) >= 7:
        commit_link = f"[`{commit[:7]}`](https://github.com/{repo}/commit/{commit})"
    else:
        commit_link = "_غير متاح_"

    text = (
        f"{emoji} *{severity}* — CVSS `{cvss:.1f}`\n"
        f"{verified_badge}\n\n"
        f"🔑 *النوع:* `{rule}`\n"
        f"📦 *المستودع:* `{repo}`\n"
        f"📄 *الملف:* `{file_path}`"
        f"{f' (سطر {line})' if line else ''}\n"
        f"🔍 *الكاشف:* `{source}`\n"
        f"🔒 *الحالة:* {status_icon}\n"
        f"🌿 *Commit:* {commit_link}\n"
        f"🎯 *المقتطف:* `{preview}`\n"
        f"⏰ `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
    )
    await send_message(text)


async def notify_heartbeat(stats: dict, cycle_duration: float = 0.0):
    """يرسل نبضة دورية."""
    text = (
        f"💓 *Heartbeat*\n\n"
        f"📊 *النتائج المخزنة:* `{stats.get('total_findings', 0)}`\n"
        f"🔴 *حرجة:* `{stats.get('critical', 0)}`\n"
        f"✅ *مُتحقق منها:* `{stats.get('verified', 0)}`\n"
        f"📦 *المستودعات المفحوصة:* `{stats.get('repos_scanned', 0)}`\n"
        f"⏱ *الدورة الأخيرة:* `{cycle_duration:.1f}s`\n"
        f"🕒 `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
    )
    await send_message(text)


async def notify_error(module: str, error: str):
    """يرسل إشعارًا بخطأ."""
    text = (
        f"⚠️ *خطأ في الوحدة:* `{module}`\n\n"
        f"```\n{error[:500]}\n```\n"
        f"⏰ `{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}`"
    )
    await send_message(text)
