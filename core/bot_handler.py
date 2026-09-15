"""core/bot_handler.py — بوت Telegram تفاعلي مع أزرار"""
import asyncio
import aiohttp
import sqlite3
from datetime import datetime, timedelta

from config.settings import settings
from utils.logger import logger
from core.storage import storage


TELEGRAM_API = "https://api.telegram.org/bot{token}"
MAX_MSG = 4000


class BotHandler:
    def __init__(self):
        self.token = settings.TELEGRAM_BOT_TOKEN
        self.chat_id = str(settings.TELEGRAM_CHAT_ID)
        self.offset = 0
        self.base = TELEGRAM_API.format(token=self.token)

    # ═══ إرسال رسائل ═══
    async def send(self, text: str, keyboard: dict | None = None):
        payload = {
            "chat_id": self.chat_id,
            "text": text[:MAX_MSG],
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if keyboard:
            payload["reply_markup"] = keyboard
        async with aiohttp.ClientSession() as s:
            try:
                async with s.post(f"{self.base}/sendMessage", json=payload,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    return await r.json()
            except Exception as e:
                logger.error(f"[Bot] send failed: {e}")

    async def edit(self, message_id: int, text: str, keyboard: dict | None = None):
        payload = {
            "chat_id": self.chat_id,
            "message_id": message_id,
            "text": text[:MAX_MSG],
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        if keyboard:
            payload["reply_markup"] = keyboard
        async with aiohttp.ClientSession() as s:
            try:
                async with s.post(f"{self.base}/editMessageText", json=payload,
                                  timeout=aiohttp.ClientTimeout(total=10)) as r:
                    return await r.json()
            except Exception as e:
                logger.error(f"[Bot] edit failed: {e}")

    async def answer_callback(self, callback_id: str):
        async with aiohttp.ClientSession() as s:
            try:
                await s.post(f"{self.base}/answerCallbackQuery",
                             json={"callback_query_id": callback_id},
                             timeout=aiohttp.ClientTimeout(total=5))
            except Exception:
                pass

    # ═══ لوحات المفاتيح ═══
    @staticmethod
    def main_menu():
        return {"inline_keyboard": [
            [{"text": "📊 الإحصائيات", "callback_data": "stats"}],
            [{"text": "📦 المستودعات المُصَابة", "callback_data": "repos:0"}],
            [{"text": "🔑 أنواع التسريبات", "callback_data": "types"}],
            [{"text": "🔴 الحرجة فقط", "callback_data": "critical:0"}],
            [{"text": "🔄 تحديث", "callback_data": "refresh"}],
        ]}

    @staticmethod
    def back_menu():
        return {"inline_keyboard": [
            [{"text": "🔙 القائمة الرئيسية", "callback_data": "menu"}],
        ]}

    # ═══ الإحصائيات ═══
    def get_stats(self) -> dict:
        conn = sqlite3.connect(storage.db_path)
        c = conn.cursor()
        total_repos = c.execute("SELECT COUNT(*) FROM scanned_repos").fetchone()[0]
        total_findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        repos_with_findings = c.execute(
            "SELECT COUNT(DISTINCT repo) FROM findings"
        ).fetchone()[0]
        critical = c.execute(
            "SELECT COUNT(*) FROM findings WHERE cvss >= 9.0"
        ).fetchone()[0]
        high = c.execute(
            "SELECT COUNT(*) FROM findings WHERE cvss >= 7.0 AND cvss < 9.0"
        ).fetchone()[0]
        verified = c.execute(
            "SELECT COUNT(*) FROM findings WHERE verified=1"
        ).fetchone()[0]
        # آخر 24 ساعة
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat()
        last24 = c.execute(
            "SELECT COUNT(*) FROM findings WHERE first_seen > ?", (since,)
        ).fetchone()[0]
        conn.close()
        return {
            "total_repos": total_repos,
            "total_findings": total_findings,
            "repos_with_findings": repos_with_findings,
            "critical": critical,
            "high": high,
            "verified": verified,
            "last24": last24,
        }

    async def show_stats(self, message_id: int | None = None):
        s = self.get_stats()
        text = (
            f"📊 *الإحصائيات الكاملة*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📦 *المستودعات المفحوصة:* `{s['total_repos']}`\n"
            f"🎯 *مستودعات فيها تسريبات:* `{s['repos_with_findings']}`\n"
            f"🔑 *إجمالي التسريبات:* `{s['total_findings']}`\n\n"
            f"🔴 *حرجة (CVSS ≥ 9):* `{s['critical']}`\n"
            f"🟠 *عالية (7-9):* `{s['high']}`\n"
            f"✅ *مُتحقق منها:* `{s['verified']}`\n"
            f"🕐 *آخر 24 ساعة:* `{s['last24']}`\n\n"
            f"⏰ `{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}`"
        )
        kb = {"inline_keyboard": [
            [{"text": "🔄 تحديث", "callback_data": "stats"}],
            [{"text": "🔙 القائمة الرئيسية", "callback_data": "menu"}],
        ]}
        if message_id:
            await self.edit(message_id, text, kb)
        else:
            await self.send(text, kb)

    # ═══ المستودعات المُصَابة ═══
    async def show_repos(self, page: int = 0, message_id: int | None = None):
        conn = sqlite3.connect(storage.db_path)
        rows = conn.execute("""
            SELECT repo, COUNT(*) as cnt, MAX(cvss) as max_cvss
            FROM findings GROUP BY repo ORDER BY max_cvss DESC, cnt DESC
        """).fetchall()
        conn.close()

        if not rows:
            text = "📭 *لا توجد مستودعات فيها تسريبات بعد*"
            kb = self.back_menu()
            if message_id:
                return await self.edit(message_id, text, kb)
            return await self.send(text, kb)

        per_page = 8
        total_pages = (len(rows) + per_page - 1) // per_page
        page = max(0, min(page, total_pages - 1))
        chunk = rows[page * per_page:(page + 1) * per_page]

        text = (
            f"📦 *المستودعات المُصَابة* ({len(rows)})\n"
            f"صفحة {page + 1}/{total_pages}\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
        )
        buttons = []
        for repo, cnt, max_cvss in chunk:
            emoji = "🔴" if max_cvss >= 9 else "🟠" if max_cvss >= 7 else "🟡"
            short = repo if len(repo) <= 32 else repo[:29] + "..."
            buttons.append([{
                "text": f"{emoji} {short} ({cnt})",
                "callback_data": f"repo:{repo[:40]}",
            }])

        # التنقل
        nav = []
        if page > 0:
            nav.append({"text": "⬅️ السابق", "callback_data": f"repos:{page-1}"})
        if page < total_pages - 1:
            nav.append({"text": "التالي ➡️", "callback_data": f"repos:{page+1}"})
        if nav:
            buttons.append(nav)
        buttons.append([{"text": "🔙 القائمة", "callback_data": "menu"}])

        kb = {"inline_keyboard": buttons}
        if message_id:
            await self.edit(message_id, text, kb)
        else:
            await self.send(text, kb)

    async def show_repo_detail(self, repo: str, message_id: int | None = None):
        conn = sqlite3.connect(storage.db_path)
        rows = conn.execute("""
            SELECT rule_id, file, cvss, verified, secret_preview, source
            FROM findings WHERE repo=? ORDER BY cvss DESC
        """, (repo,)).fetchall()
        conn.close()

        if not rows:
            return await self.edit(message_id, "❌ لم يُعثر على نتائج", self.back_menu())

        text = f"📦 *{repo}*\n`{len(rows)} تسريب`\n━━━━━━━━━━━━━━━━━━━━\n"
        for rule, file, cvss, verified, preview, source in rows[:10]:
            emoji = "🔴" if cvss >= 9 else "🟠" if cvss >= 7 else "🟡"
            v = " ✅" if verified else ""
            text += (
                f"\n{emoji} *{rule}*{v}\n"
                f"  CVSS: `{cvss:.1f}` | الكاشف: `{source}`\n"
                f"  📄 `{file[:50]}`\n"
                f"  🔒 `{preview}`\n"
            )

        if len(rows) > 10:
            text += f"\n_... و {len(rows) - 10} أخرى_"

        kb = {"inline_keyboard": [
            [{"text": "🔙 المستودعات", "callback_data": "repos:0"}],
            [{"text": "🏠 القائمة", "callback_data": "menu"}],
        ]}
        await self.edit(message_id, text, kb)

    # ═══ الأنواع ═══
    async def show_types(self, message_id: int | None = None):
        conn = sqlite3.connect(storage.db_path)
        rows = conn.execute("""
            SELECT rule_id, COUNT(*) as cnt, MAX(cvss) as max_cvss
            FROM findings GROUP BY rule_id ORDER BY cnt DESC
        """).fetchall()
        conn.close()

        if not rows:
            return await self.edit(message_id, "📭 لا توجد نتائج بعد", self.back_menu())

        text = f"🔑 *أنواع التسريبات* ({len(rows)})\n━━━━━━━━━━━━━━━━━━━━\n\n"
        for rule, cnt, cvss in rows[:20]:
            emoji = "🔴" if cvss >= 9 else "🟠" if cvss >= 7 else "🟡"
            text += f"{emoji} `{rule}` → *{cnt}*\n"

        kb = {"inline_keyboard": [
            [{"text": "🔙 القائمة", "callback_data": "menu"}],
        ]}
        await self.edit(message_id, text, kb)

    # ═══ الحرجة ═══
    async def show_critical(self, page: int = 0, message_id: int | None = None):
        conn = sqlite3.connect(storage.db_path)
        rows = conn.execute("""
            SELECT repo, rule_id, cvss, file, secret_preview
            FROM findings WHERE cvss >= 9.0
            ORDER BY cvss DESC LIMIT 20
        """).fetchall()
        conn.close()

        if not rows:
            return await self.edit(message_id, "✅ *لا توجد تسريبات حرجة*", self.back_menu())

        text = f"🔴 *تسريبات حرجة* ({len(rows)})\n━━━━━━━━━━━━━━━━━━━━\n"
        for repo, rule, cvss, file, preview in rows[:8]:
            text += (
                f"\n🔴 *{rule}* `{cvss:.1f}`\n"
                f"  📦 `{repo}`\n"
                f"  📄 `{file[:40]}`\n"
                f"  🔒 `{preview}`\n"
            )

        kb = {"inline_keyboard": [
            [{"text": "🔙 القائمة", "callback_data": "menu"}],
        ]}
        await self.edit(message_id, text, kb)

    # ═══ معالجة الأزرار ═══
    async def handle_callback(self, cb: dict):
        data = cb.get("data", "")
        msg_id = cb["message"]["message_id"]
        await self.answer_callback(cb["id"])

        if data == "menu" or data == "refresh":
            await self.edit(msg_id, "🏠 *القائمة الرئيسية*", self.main_menu())
        elif data == "stats":
            await self.show_stats(msg_id)
        elif data.startswith("repos:"):
            page = int(data.split(":")[1])
            await self.show_repos(page, msg_id)
        elif data.startswith("repo:"):
            await self.show_repo_detail(data.split(":", 1)[1], msg_id)
        elif data == "types":
            await self.show_types(msg_id)
        elif data.startswith("critical:"):
            page = int(data.split(":")[1])
            await self.show_critical(page, msg_id)

    # ═══ حلقة الاستماع ═══
    async def poll_loop(self):
        """يعمل في الخلفية، يستمع للأزرار والأوامر."""
        logger.info("[Bot] بدء الاستماع لأوامر Telegram")
        # أرسل القائمة الرئيسية عند البدء
        await self.send("🏠 *القائمة الرئيسية*\nاختر من الأسفل:", self.main_menu())

        while True:
            try:
                async with aiohttp.ClientSession() as s:
                    params = {"timeout": 25, "offset": self.offset}
                    async with s.get(
                        f"{self.base}/getUpdates",
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as r:
                        if r.status != 200:
                            await asyncio.sleep(5)
                            continue
                        data = await r.json()
                        for upd in data.get("result", []):
                            self.offset = upd["update_id"] + 1
                            if "callback_query" in upd:
                                try:
                                    await self.handle_callback(upd["callback_query"])
                                except Exception as e:
                                    logger.error(f"[Bot] callback error: {e}")
                            elif "message" in upd:
                                text = upd["message"].get("text", "").strip()
                                if text in ("/start", "/menu"):
                                    await self.send("🏠 *القائمة الرئيسية*", self.main_menu())
                                elif text == "/stats":
                                    await self.show_stats()
                                elif text == "/repos":
                                    await self.show_repos(0)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"[Bot] poll error: {e}")
                await asyncio.sleep(5)


bot = BotHandler()
