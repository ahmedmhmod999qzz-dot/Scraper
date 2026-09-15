"""core/github_client.py — البحث عن المستودعات الحديثة على GitHub"""
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Optional

from config.settings import settings
from utils.logger import logger


GITHUB_API = "https://api.github.com"
HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if settings.GITHUB_TOKEN:
    HEADERS["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"


async def search_recent_repos(
    days: int = 1,
    max_results: int = 50,
    languages: Optional[list[str]] = None,
) -> list[dict]:
    """
    يبحث عن مستودعات أُنشئت أو حُدّثت خلال آخر N أيام.
    يعيد قائمة موحدة من dicts.
    """
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")

    queries = [
        f"created:>{since} sort:updated",
        f"pushed:>{since} sort:updated",
    ]

    if languages:
        queries = [f"{q} language:{lang}" for q in queries for lang in languages]

    results: dict[str, dict] = {}

    async with aiohttp.ClientSession(headers=HEADERS) as session:
        for query in queries:
            params = {"q": query, "per_page": min(max_results, 100), "sort": "updated"}
            try:
                async with session.get(
                    f"{GITHUB_API}/search/repositories",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    # سجّل حالة Rate Limit
                    remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                    logger.info(f"[GitHub] query='{query[:60]}' → HTTP {resp.status}, remaining={remaining}")

                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get("items", []):
                            fn = item["full_name"]
                            if fn not in results:
                                results[fn] = {
                                    "full_name": fn,
                                    "clone_url": item["clone_url"],
                                    "html_url": item["html_url"],
                                    "language": item.get("language"),
                                    "stars": item.get("stargazers_count", 0),
                                    "created_at": item.get("created_at"),
                                    "updated_at": item.get("updated_at"),
                                    "size_kb": item.get("size", 0),
                                }
                    elif resp.status == 403:
                        logger.warning("[GitHub] Rate limit reached. Waiting 60s...")
                        await asyncio.sleep(60)
                    elif resp.status == 422:
                        logger.warning(f"[GitHub] Invalid query: {query[:80]}")
                    else:
                        body = await resp.text()
                        logger.error(f"[GitHub] HTTP {resp.status}: {body[:200]}")
            except asyncio.TimeoutError:
                logger.error(f"[GitHub] Timeout on query: {query[:60]}")
            except Exception as e:
                logger.exception(f"[GitHub] Exception: {e}")

    repos = list(results.values())
    logger.info(f"[GitHub] إجمالي المستودعات الفريدة: {len(repos)}")
    return repos[:max_results]
