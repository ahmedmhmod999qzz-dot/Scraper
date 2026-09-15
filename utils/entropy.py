"""utils/entropy.py — حساب Shannon Entropy وفلترة المفاتيح"""
import re
from math import log2

# هاشات Git ليست مفاتيح سرية
_GIT_HASH = re.compile(r"^[a-f0-9]{40,64}$")

# سياق يشير إلى hash وليس مفتاح
_HASH_CONTEXT = re.compile(
    r"(commit|sha|hash|tree|blob|oid|digest)[\s=:\"']+[a-f0-9]{40,64}",
    re.IGNORECASE,
)

# كلمات تشير إلى قيم تجريبية أو placeholders
_PLACEHOLDER_WORDS = re.compile(
    r"(example|sample|test|dummy|placeholder|your_|xxxx|aaaa|fake|demo|mock)",
    re.IGNORECASE,
)

# كلمات إنجليزية شائعة تدل على نص بشري
_COMMON_WORDS = re.compile(
    r"(password|secret|token|key|api|auth|bearer|correct|horse|battery|staple)",
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


def is_placeholder(text: str) -> bool:
    """يكشف الأنماط التي تشير إلى قيمة تجريبية أو placeholder."""
    return bool(_PLACEHOLDER_WORDS.search(text))


def is_readable_text(text: str) -> bool:
    """يكشف النصوص الإنجليزية القابلة للقراءة (كلمات مفصولة بشرطات)."""
    # إذا كان النص يحتوي على 3 شرطات أو أكثر، وكلماته قصيرة، فهو نص بشري
    if text.count("-") >= 3 and len(text.split("-")) >= 4:
        return True
    return False


def is_likely_secret(text: str, min_entropy: float = 3.2) -> bool:
    """يرفض الهاشات، النصوص قصيرة الإنتروبيا، والقيم التجريبية.

    الطبقات:
        1. الطول (16 حرفًا على الأقل)
        2. Git hash (40-64 hex)
        3. سياق hash
        4. Shannon Entropy
        5. Placeholders (example, test, dummy...)
        6. نص إنجليزي قابل للقراءة
    """
    if len(text) < 16:
        return False
    if _GIT_HASH.match(text):
        return False
    if _HASH_CONTEXT.search(text):
        return False
    if calculate_entropy(text) < min_entropy:
        return False
    if is_placeholder(text):
        return False
    if is_readable_text(text):
        return False
    return True
