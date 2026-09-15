"""core/cvss.py — تقييم CVSS لكل نوع سر"""
from typing import Optional


# خريطة rule_id → CVSS
# مأخوذة من قاعدة بيانات Gitleaks + خبرة الصناعة
CVSS_MAP: dict[str, float] = {
    # الذكاء الاصطناعي
    "openai-api-key": 8.0,
    "anthropic-api-key": 8.0,
    # GitHub
    "github-pat": 9.0,
    "github-oauth": 8.5,
    "github-app-token": 8.5,
    # السحابة
    "aws-access-token": 7.0,
    "google-api-key": 7.5,
    "digitalocean-token": 8.5,
    # المدفوعات
    "stripe-access-token": 9.5,
    # التواصل
    "slack-bot-token": 7.5,
    "slack-user-token": 8.5,
    "sendgrid-api-token": 7.0,
    "twilio-api-key": 6.5,
    # قواعد البيانات
    "postgres-uri": 9.0,
    "mongodb-uri": 9.0,
    "mysql-uri": 9.0,
    "redis-uri": 8.0,
    # المفاتيح الخاصة
    "private-key": 9.5,
    "rsa-private-key": 9.5,
    "openssh-private-key": 9.5,
    "pgp-private-key": 8.5,
    # أخرى
    "npm-token": 7.5,
    "dockerhub-token": 7.0,
    "jwt": 6.0,
    "generic-api-key": 5.0,
}


def score_of(rule_id: str, verified: bool = False) -> float:
    """
    يعيد CVSS لسر معين.
    إذا كان مُتحقق منه، نرفع الدرجة قليلًا (لأن الخطورة مؤكدة).
    """
    rule = (rule_id or "").lower().replace("_", "-")

    # ابحث عن تطابق مباشر
    if rule in CVSS_MAP:
        base = CVSS_MAP[rule]
    else:
        # ابحث عن تطابق جزئي
        base = 5.0
        for key, val in CVSS_MAP.items():
            if key in rule or rule in key:
                base = val
                break

    # تعزيز الدرجة إن كان مُتحققًا
    if verified:
        base = min(10.0, base + 1.0)

    return base


def severity_label(cvss: float) -> str:
    """يعيد تصنيفًا نصيًا حسب معيار CVSS v3.1"""
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    if cvss > 0.0:
        return "LOW"
    return "INFO"


def severity_emoji(cvss: float) -> str:
    """إيموجي للتصنيف"""
    if cvss >= 9.0:
        return "🔴"
    if cvss >= 7.0:
        return "🟠"
    if cvss >= 4.0:
        return "🟡"
    if cvss > 0.0:
        return "🟢"
    return "⚪"
