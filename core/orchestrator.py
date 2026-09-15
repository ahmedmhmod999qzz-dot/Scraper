"""core/orchestrator.py — العقل المنسّق بين كل الوحدات"""
import asyncio
import time
from datetime import datetime

from config.settings import settings
from utils.logger import logger
from utils.entropy import is_likely_secret

from core.github_client import search_recent_repos
from core.gitleaks_runner import scan_repo_with_gitleaks
from core.trufflehog_runner import scan_repo_with_trufflehog
from core.cvss import score_of, severity_label, severity_emoji
from core.storage import storage
from core.notifier import notify_finding, notify_heartbeat


class Orchestrator:
    def __init__(self):
        self.last_heartbeat = time.time()

    async def _scan_one_repo(self, repo: dict) -> int:
        """يفحص مستودعًا واحدًا بالكامل. يعيد عدد الاكتشافات الجديدة."""
        full_name = repo["full_name"]
        clone_url = repo["clone_url"]
        size_kb = repo.get("size_kb", 0)
        language = repo.get("language", "?")
        stars = repo.get("stars", 0)

        # ═══ فلترة spam ═══
        if size_kb < 10:
            logger.debug(f"[Orch] {full_name} → حجم صغير ({size_kb}KB)، تخطٍّ")
            return 0

        # تجاوز إذا فُحص حديثًا
        if storage.was_scanned(full_name, max_age_hours=24):
            logger.debug(f"[Orch] {full_name} → فُحص مؤخرًا، تخطٍّ")
            return 0

        logger.info(f"[Orch] ▶ فحص {full_name} ({size_kb}KB, {language}, ⭐{stars})")

        # ═══ 1. شغّل Gitleaks و TruffleHog بالتوازي ═══
        gl_task = asyncio.create_task(scan_repo_with_gitleaks(clone_url, full_name))
        th_task = asyncio.create_task(
            scan_repo_with_trufflehog(clone_url, full_name, only_verified=True)
        )

        gitleaks_findings, trufflehog_findings = await asyncio.gather(
            gl_task, th_task, return_exceptions=True
        )

        if isinstance(gitleaks_findings, Exception):
            logger.error(f"[Orch] Gitleaks فشل على {full_name}: {gitleaks_findings}")
            gitleaks_findings = []
        if isinstance(trufflehog_findings, Exception):
            logger.error(f"[Orch] TruffleHog فشل على {full_name}: {trufflehog_findings}")
            trufflehog_findings = []

        all_findings = list(gitleaks_findings) + list(trufflehog_findings)

        # ═══ 2. فلترة + حفظ + تنبيهات ═══
        new_count = 0
        for f in all_findings:
            preview = f.get("secret_preview", "")
            if not is_likely_secret(preview):
                logger.debug(f"[Orch] استُبعد بـ entropy: {f.get('rule_id', '?')}")
                continue

            if not storage.is_new(f):
                logger.debug(f"[Orch] مكرر: {f.get('rule_id', '?')}")
                continue

            cvss = score_of(f.get("rule_id", ""), verified=f.get("verified", False))
            severity = severity_label(cvss)
            emoji = severity_emoji(cvss)

            # احفظ أولًا (حتى لو فشل Telegram)
            storage.save(f, cvss)
            new_count += 1

            # أرسل تنبيه
            try:
                await notify_finding(f, cvss, severity, emoji)
                await asyncio.sleep(1.2)  # تجنب flood limits في Telegram
            except Exception as e:
                logger.error(f"[Orch] فشل إرسال التنبيه: {e}")

        storage.mark_repo_scanned(full_name, len(all_findings))
        logger.info(
            f"[Orch] ✓ {full_name} → {len(all_findings)} نتيجة ({new_count} جديدة)"
        )
        return new_count

    async def scan_cycle(self) -> int:
        """دورة فحص واحدة."""
        cycle_start = time.time()

        # ═══ 1. ابحث عن مستودعات حديثة ═══
        repos = await search_recent_repos(
            days=settings.RECENT_DAYS,
            max_results=settings.MAX_REPOS_PER_CYCLE,
        )
        if not repos:
            logger.info("[Orch] لا مستودعات جديدة في هذه الدورة")
            return 0

        # ═══ 2. فلترة أولية للمستودعات (spam) ═══
        filtered = [r for r in repos if r.get("size_kb", 0) >= 10]
        skipped = len(repos) - len(filtered)
        if skipped:
            logger.info(f"[Orch] استُبعد {skipped} مستودع spam صغير الحجم")

        if not filtered:
            logger.info("[Orch] كل المستودعات spam — لا شيء لفحصه")
            return 0

        # ═══ 3. افحص بالتوازي المحدود ═══
        sem = asyncio.Semaphore(settings.CONCURRENCY)

        async def _limited(r):
            async with sem:
                try:
                    return await self._scan_one_repo(r)
                except Exception as e:
                    logger.exception(f"[Orch] استثناء في {r['full_name']}: {e}")
                    return 0

        results = await asyncio.gather(*[_limited(r) for r in filtered])
        total_new = sum(results)

        cycle_duration = time.time() - cycle_start
        logger.info(
            f"[Orch] ═══ الدورة انتهت ═══ "
            f"مستودعات={len(filtered)} (+{skipped} spam)، "
            f"جديدة={total_new}، مدة={cycle_duration:.1f}s"
        )

        # ═══ 4. Heartbeat دوري ═══
        if time.time() - self.last_heartbeat >= settings.HEARTBEAT_MINUTES * 60:
            stats = storage.stats()
            try:
                await notify_heartbeat(stats, cycle_duration)
            except Exception as e:
                logger.error(f"[Orch] Heartbeat فشل: {e}")
            self.last_heartbeat = time.time()

        return total_new
