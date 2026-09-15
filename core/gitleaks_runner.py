"""core/gitleaks_runner.py — تشغيل Gitleaks مع إعدادات مخصصة"""
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
    """يستنسخ، يشغّل Gitleaks مع إعدادات مخصصة، يعيد نتائج موحدة."""
    tmpdir = tempfile.mkdtemp(prefix="hunter_gl_")
    repo_path = Path(tmpdir) / "repo"
    report_path = Path(tmpdir) / "report.json"

    try:
        if not await _clone_repo(clone_url, str(repo_path)):
            return []

        cmd = [
            "gitleaks", "detect",
            "--source", str(repo_path),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--no-banner",
            "--exit-code", "0",
        ]

        # ═══ استخدم الإعدادات المخصصة إن وُجدت ═══
        config_path = Path("/app/.gitleaks.toml")
        if config_path.exists():
            cmd.extend(["--config", str(config_path)])
            logger.debug(f"[Gitleaks] استخدام {config_path}")

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
                "secret_raw": secret,
                "secret_preview": secret,
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
