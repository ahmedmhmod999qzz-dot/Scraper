
"""core/orchestrator.py — العقل المنسّق بين كل الوحدات"""
import asyncio
import time

from config.settings import settings
from utils.logger import logger
from utils.entropy import is_likely_secret

from core.github_client import search_recent_repos
from core.gitleaks_runner import scan_repo_with_gitleaks
from core.trufflehog_runner import scan_repo_with_trufflehog
from core.cvss import score_of, severity_label, severity_emoji
from core.storage import storage
from core.notifier import notify_finding


MIN_SIZE_KB = 10
MAX_SIZE_KB = 50_000


class Orchestrator:
    def __init__(self):
        self.last_heartbeat = time.time()

    @staticmethod
    def _is_scannable(repo: dict) -> tuple[bool, str]:
        size = repo.get("size_kb", 0)
        if size < MIN_SIZE_KB:
            return False, f"صغير ({size}KB)"
        if size > MAX_SIZE_KB:
            return False, f"كبير ({size}KB)"
        return True, ""

    async def _scan_one_repo(self, repo: dict) -> int:
        full_name = repo["full_name"]
        clone_url = repo["clone_url"]
        size_kb = repo.get("size_kb", 0)
        language = repo.get("language", "?")
        stars = repo.get("stars", 0)

        if storage.was_scanned(full_name, max_age_hours=24):
            logger.debug(f"[Orch] {full_name} → فُحص مؤخرًا، تخطٍّ")
            return 0

        logger.info(f"[Orch] ▶ فحص {full_name} ({size_kb/1024:.1f}MB, {language}, ⭐{stars})")

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

        new_count = 0
        for f in all_findings:
            preview = f.get("secret_raw", "") or f.get("secret_preview", "")
            source = f.get("source", "")

            if source == "gitleaks":
                if len(preview) < 8:
                    logger.debug(f"[Orch] استُبعد (قصير): {f.get('rule_id', '?')}")
                    continue
            else:
                if not is_likely_secret(preview):
                    logger.debug(f"[Orch] استُبعد بـ entropy: {f.get('rule_id', '?')}")
                    continue

            if not storage.is_new(f):
                logger.debug(f"[Orch] مكرر: {f.get('rule_id', '?')}")
                continue

            cvss = score_of(f.get("rule_id", ""), verified=f.get("verified", False))
            severity = severity_label(cvss)
            emoji = severity_emoji(cvss)

            storage.save(f, cvss)
            new_count += 1

            try:
                await notify_finding(f, cvss, severity, emoji)
                await asyncio.sleep(1.2)
            except Exception as e:
                logger.error(f"[Orch] فشل إرسال التنبيه: {e}")

        storage.mark_repo_scanned(full_name, len(all_findings))
        logger.info(f"[Orch] ✓ {full_name} → {len(all_findings)} نتيجة ({new_count} جديدة)")
        return new_count

    async def scan_cycle(self) -> int:
        cycle_start = time.time()

        repos = await search_recent_repos(
            days=settings.RECENT_DAYS,
            max_results=settings.MAX_REPOS_PER_CYCLE,
        )
        if not repos:
            logger.info("[Orch] لا مستودعات جديدة")
            return 0

        filtered = []
        rejected_small = 0
        rejected_big = 0
        for r in repos:
            ok, reason = self._is_scannable(r)
            if ok:
                filtered.append(r)
            elif "صغير" in reason:
                rejected_small += 1
            else:
                rejected_big += 1

        logger.info(
            f"[Orch] الفلترة: {len(filtered)} مقبول، "
            f"{rejected_small} spam صغير، {rejected_big} كبير"
        )

        if not filtered:
            return 0

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
            f"مفحوص={len(filtered)}، جديدة={total_new}، مدة={cycle_duration:.1f}s"
        )
        return total_new
