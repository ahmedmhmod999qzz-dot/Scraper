"""utils/entropy.py — حساب Shannon Entropy لفلترة المفاتيح"""
import re
from math import log2

# هاشات Git ليست مفاتيح سرية
_GIT_HASH = re.compile(r"^[a-f0-9]{40,64}$")

# سياق يشير إلى hash وليس مفتاح
_HASH_CONTEXT = re.compile(
    r"(commit|sha|hash|tree|blob|oid|digest)[\s=:\"']+[a-f0-9]{40,64}",
    re.IGNORECASE,
)


def calculate_entropy(text: str) -> float:
    """Shannon Entropy بالـ bits لكل رمز (0 إلى ~8)."""
    if not text or len(text) < 8:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def is_likely_secret(text: str, min_entropy: float = 3.2) -> bool:
    """يرفض الهاشات والنصوص قصيرة الإنتروبيا."""
    if len(text) < 16:
        return False
    if _GIT_HASH.match(text):
        return False
    if _HASH_CONTEXT.search(text):
        return False
    if calculate_entropy(text) < min_entropy:
        return False
    return True
