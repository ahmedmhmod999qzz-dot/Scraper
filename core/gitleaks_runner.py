
"""core/gitleaks_runner.py — تشغيل Gitleaks وقراءة نتائجه"""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from utils.logger import logger


async def _run_cmd(cmd: list[str], cwd: str | None = None, timeout: int = 120):
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode
    except asyncio.TimeoutError:
        proc.kill()
        return "", "TIMEOUT", -1


async def _clone_repo(clone_url: str, dest: str) -> bool:
    stdout, stderr, code = await _run_cmd(
        ["git", "clone", "--depth", "1", "--quiet", clone_url, dest],
        timeout=90,
    )
    if code != 0:
        logger.warning(f"[Clone] فشل: {clone_url} → {stderr[:150]}")
        return False
    return True


async def scan_repo_with_gitleaks(clone_url: str, repo_name: str) -> list[dict]:
    """يستنسخ، يشغّل Gitleaks، يعيد نتائج موحدة مع المفتاح الكامل."""
    tmpdir = tempfile.mkdtemp(prefix="hunter_gl_")
    repo_path = Path(tmpdir) / "repo"
    report_path = Path(tmpdir) / "report.json"

    try:
        if not await _clone_repo(clone_url, str(repo_path)):
            return []

        # ═══ أمر Gitleaks — بدون إخفاء ═══
        cmd = [
            "gitleaks", "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
            "--no-redact",           # ← المفتاح! يمنع الإخفاء
            "--exit-code", "0",
        ]
        stdout, stderr, code = await _run_cmd(cmd, timeout=180)

        # إذا رفض الإصدار --no-redact، جرب بدونها
        if code not in (0, 1) and "no-redact" in stderr.lower():
            logger.warning("[Gitleaks] --no-redact غير مدعوم، محاولة بدونه")
            cmd = [c for c in cmd if c != "--no-redact"]
            stdout, stderr, code = await _run_cmd(cmd, timeout=180)

        if code not in (0, 1):
            logger.warning(f"[Gitleaks] {repo_name} → exit={code}: {stderr[:200]}")
            return []

        if not report_path.exists():
            logger.info(f"[Gitleaks] {repo_name} → لا توجد نتائج")
            return []

        with open(report_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        findings = []
        for item in raw:
            secret = item.get("Secret", "") or item.get("Match", "")
            findings.append({
                "source": "gitleaks",
                "repo": repo_name,
                "rule_id": item.get("RuleID", "unknown"),
                "description": item.get("Description", ""),
                "file": item.get("File", ""),
                "line": item.get("StartLine", 0),
                "secret_raw": secret,                # ← القيمة الكاملة
                "secret_preview": secret,            # للتوافق
                "secret_len": len(secret),
                "commit": item.get("Commit", ""),
                "author": item.get("Author", ""),
                "entropy": item.get("Entropy", 0.0),
                "verified": False,
            })

        logger.info(f"[Gitleaks] {repo_name} → {len(findings)} اكتشاف")
        return findings

    except Exception as e:
        logger.exception(f"[Gitleaks] {repo_name} → استثناء: {e}")
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
