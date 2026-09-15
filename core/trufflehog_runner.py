"""core/trufflehog_runner.py — تشغيل TruffleHog مع التحقق الفعلي"""
import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from utils.logger import logger


async def _run_cmd(cmd: list[str], timeout: int = 180):
    proc = await asyncio.create_subprocess_exec(
        *cmd,
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
    """يستنسخ بعمق كامل (TruffleHog يحتاج التاريخ كاملًا)."""
    stdout, stderr, code = await _run_cmd(
        ["git", "clone", "--quiet", clone_url, dest],
        timeout=120,
    )
    return code == 0


async def scan_repo_with_trufflehog(
    clone_url: str,
    repo_name: str,
    only_verified: bool = True,
) -> list[dict]:
    """
    يستنسخ المستودع، يشغّل TruffleHog، يعيد نتائج موحدة.
    only_verified=True → يعيد فقط المفاتيح التي تحقق منها TruffleHog فعليًا.
    """
    tmpdir = tempfile.mkdtemp(prefix="hunter_th_")
    repo_path = Path(tmpdir) / "repo"

    try:
        if not await _clone_repo(clone_url, str(repo_path)):
            return []

        cmd = [
            "trufflehog", "git",
            f"file://{repo_path}",
            "--json",
            "--no-update",
            "--concurrency", "4",
        ]
        if only_verified:
            cmd.append("--only-verified")

        stdout, stderr, code = await _run_cmd(cmd, timeout=240)

        findings = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            # استخرج البيانات بحذر
            det = item.get("DetectorName", "unknown")
            ver = item.get("Verified", False)
            raw = item.get("Raw", "")
            meta = item.get("SourceMetadata", {}).get("Data", {})

            # معلومات الموقع
            git_info = meta.get("Git", {})
            file_path = git_info.get("file", "")
            commit_sha = git_info.get("commit", "")
            author = git_info.get("email", "")

            findings.append({
                "source": "trufflehog",
                "repo": repo_name,
                "rule_id": det,
                "description": f"TruffleHog: {det}",
                "file": file_path,
                "line": 0,
                "secret_preview": raw[:40] if isinstance(raw, str) else "",
                "commit": commit_sha,
                "author": author,
                "entropy": 0.0,
                "verified": bool(ver),
            })

        verified_count = sum(1 for f in findings if f["verified"])
        logger.info(
            f"[TruffleHog] {repo_name} → {len(findings)} اكتشاف "
            f"({verified_count} مُتحقق)"
        )
        return findings

    except Exception as e:
        logger.exception(f"[TruffleHog] {repo_name} → استثناء: {e}")
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
