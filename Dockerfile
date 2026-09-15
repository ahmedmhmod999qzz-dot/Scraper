FROM python:3.12-slim

# ═══ أدوات النظام ═══
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ═══ Gitleaks ═══
ARG GITLEAKS_VERSION=8.28.0
RUN curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o /tmp/gitleaks.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

# ═══ TruffleHog ═══
ARG TRUFFLEHOG_VERSION=3.82.5
RUN curl -sSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz" \
    -o /tmp/th.tar.gz \
    && tar -xzf /tmp/th.tar.gz -C /usr/local/bin/ trufflehog \
    && chmod +x /usr/local/bin/trufflehog \
    && rm /tmp/th.tar.gz

# ═══ العمل داخل /app ═══
WORKDIR /app

# 1. ثبّت المتطلبات أولًا (طبقة منفصلة — أسرع في إعادة البناء)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. انسخ الكود كاملًا
COPY . .

# 3. تحقق اختياري من وجود .gitleaks.toml (بدون فشل البناء)
RUN if [ -f /app/.gitleaks.toml ]; then echo "✅ .gitleaks.toml موجود"; else echo "⚠️ .gitleaks.toml مفقود"; fi

EXPOSE 8080
CMD ["python", "-u", "main.py"]
