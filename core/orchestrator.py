"""core/orchestrator.py — فلترة صارمة + استهلاك ذاكرة منخفض"""
import asyncio
import re
import time

from config.settings import settings
from utils.logger import logger
from utils.entropy import is_likely_secret, calculate_entropy

from core.github_client import search_recent_repos
from core.gitleaks_runner import scan_repo_with_gitleaks
from core.trufflehog_runner import scan_repo_with_trufflehog
from core.cvss import score_of, severity_label, severity_emoji
from core.storage import storage
from core.notifier import notify_finding


MIN_SIZE_KB = 10
MAX_SIZE_KB = 30_000  # ← خُفّض من 50MB إلى 30MB

# ═══ مسارات نتجاهلها كليًا ═══
_IGNORED_PATH_PATTERNS = [
    re.compile(r"(^|/)tests?/", re.I),
    re.compile(r"(^|/)examples?/", re.I),
    re.compile(r"(^|/)samples?/", re.I),
    re.compile(r"(^|/)fixtures?/", re.I),
    re.compile(r"(^|/)docs?/", re.I),
    re.compile(r"\.md$", re.I),
    re.compile(r"README", re.I),
    re.compile(r"\.env\.example$", re.I),
    re.compile(r"\.sample$", re.I),
    re.compile(r"\.template$", re.I),
    re.compile(r"\.lock$", re.I),        # package-lock.json, yarn.lock
    re.compile(r"\.yaml$|\.yml$", re.I), # ← VPN configs, k8s configs
    re.compile(r"clash|surge|v2ray|shadowsocks|trojan", re.I),
    re.compile(r"\.json$", re.I),        # أغلبها configs
    re.compile(r"\.min\.(js|css)$", re.I),
    re.compile(r"\.map$", re.I),
]

# ═══ placeholders ═══
_PLACEHOLDER_REGEX = re.compile(
    r"(abc123|xyz|123456|test|demo|sample|example|dummy|fake|mock|"
    r"placeholder|your[_-]|changeme|replace[_-]me|insert[_-]here|"
    r"xxx+|yyy+|zzz+|foobar|foo_bar|redacted|"
    r"api[_-]?key[_-]?here|secret[_-]?key[_-]?here)",
    re.I,
)

# ═══ معرّفات ═══
_CONTEXT_IDENTIFIERS = re.compile(
    r"(dashboard|student|project|module|component|variable|const|"
    r"label|title|route|path|index|placeholder|sample|demo)",
    re.I,
)

_STRUCTURAL_FP = [
    re.compile(r"^[a-z][a-z0-9_]*_v\d+(\.\d+)*$", re.I),
    re.compile(r"_v\d+(\.\d+)*$", re.I),
    re.compile(r"^[a-z]+_[a-z]+_[a-z]+$", re.I),
    re.compile(r"^[a-z]+$"),
    re.compile(r"^[A-Z_]+$"),
    re.compile(r"^[A-Za-z0-9+/=]+$"),  # ← base64 مضاد
]

# ═══ قواعد صارمة للأنماط العامة ═══
GENERIC_RULES = {"generic-api-key", "generic-api-token", "generic-secret", "generic-password"}
GENERIC_MIN_LEN = 24       # ← رُفع من 20
GENERIC_MIN_ENTROPY = 4.5  # ← رُفع من 4.0


def is_ignored_path(file_path: str) -> bool:
    if not file_path:
        return False
    return any(p.search(file_path) for p in _IGNORED_PATH_PATTERNS)


def is_false_positive(secret: str, rule_id: str, file_path: str = "") -> bool:
    if not secret:
        return True

    if is_ignored_path(file_path):
        return True

    s = secret.strip()
    rule = (rule_id or "").lower()

    if _PLACEHOLDER_REGEX.search(s):
        return True

    for pat in _STRUCTURAL_FP:
        if pat.search(s):
            return True

    if _CONTEXT_IDENTIFIERS.search(s) and "_" in s and s.count("_") >= 2:
        return True

    if rule in GENERIC_RULES:
        if len(s) < GENERIC_MIN_LEN:
            return True
        ent = calculate_entropy(s)
        if ent < GENERIC_MIN_ENTROPY:
            return True
        # كله uppercase وحروف فقط = base64 مشبوه
        if s.isupper() and s.isalpha():
            return True

    return False


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

        if storage.was_scanned(full_name, max_age_hours=24):
            return 0

        logger.info(f"[Orch] ▶ فحص {full_name} ({size_kb/1024:.1f}MB, {language})")

        # ═══ تسلسلي بدل متوازي (تخفيف ذاكرة) ═══
        try:
            gitleaks_findings = await scan_repo_with_gitleaks(clone_url, full_name)
        except Exception as e:
            logger.error(f"[Orch] Gitleaks فشل: {e}")
            gitleaks_findings = []

        try:
            trufflehog_findings = await scan_repo_with_trufflehog(
                clone_url, full_name, only_verified=True
            )
        except Exception as e:
            logger.error(f"[Orch] TruffleHog فشل: {e}")
            trufflehog_findings = []

        all_findings = list(gitleaks_findings) + list(trufflehog_findings)

        new_count = 0
        rejected_fp = 0
        for f in all_findings:
            secret = f.get("secret_raw", "") or f.get("secret_preview", "")
            rule_id = f.get("rule_id", "")
            source = f.get("source", "")
            file_path = f.get("file", "")

            if is_false_positive(secret, rule_id, file_path):
                rejected_fp += 1
                continue

            if source == "gitleaks" and len(secret) < 8:
                continue
            if source != "gitleaks" and not is_likely_secret(secret):
                continue

            if not storage.is_new(f):
                continue

            cvss = score_of(rule_id, verified=f.get("verified", False))
            severity = severity_label(cvss)
            emoji = severity_emoji(cvss)

            storage.save(f, cvss)
            new_count += 1

            # ═══ أرسل فقط MEDIUM وما فوق ═══
            if cvss >= 5.0:
                try:
                    await notify_finding(f, cvss, severity, emoji)
                    await asyncio.sleep(1.5)
                except Exception as e:
                    logger.error(f"[Orch] فشل التنبيه: {e}")

        storage.mark_repo_scanned(full_name, len(all_findings))
        logger.info(
            f"[Orch] ✓ {full_name} → {len(all_findings)} اكتشاف، "
            f"{rejected_fp} FP، {new_count} جديد"
        )
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
            ok, _ = self._is_scannable(r)
            if ok:
                filtered.append(r)
            else:
                if r.get("size_kb", 0) < MIN_SIZE_KB:
                    rejected_small += 1
                else:
                    rejected_big += 1

        logger.info(
            f"[Orch] الفلترة: {len(filtered)} مقبول، "
            f"{rejected_small} صغير، {rejected_big} كبير"
        )

        if not filtered:
            return 0

        # ═══ تسلسلي تام (تخفيف ذاكرة) ═══
        total_new = 0
        for r in filtered:
            try:
                total_new += await self._scan_one_repo(r)
            except Exception as e:
                logger.exception(f"[Orch] استثناء: {e}")

        cycle_duration = time.time() - cycle_start
        logger.info(
            f"[Orch] ═══ الدورة انتهت ═══ "
            f"مفحوص={len(filtered)}، جديدة={total_new}، مدة={cycle_duration:.1f}s"
        )
        return total_new
