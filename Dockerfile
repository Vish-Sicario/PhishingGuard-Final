FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TF_CPP_MIN_LOG_LEVEL=2

WORKDIR /app

# Recover the exact verified PhishingGuard baseline from the known-good commit.
# Pinning the commit prevents later changes in the old repository from changing this build.
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates tar \
    && curl -fsSL "https://github.com/Vish-Sicario/PhishingGuard/archive/99bb368691442fe3443b9a0cb35ab08302743078.tar.gz" -o /tmp/phishingguard.tar.gz \
    && mkdir -p /tmp/phishingguard \
    && tar -xzf /tmp/phishingguard.tar.gz -C /tmp/phishingguard --strip-components=1 \
    && cp /tmp/phishingguard/app.py /app/app.py \
    && cp /tmp/phishingguard/phishing_url_detector.keras /app/phishing_url_detector.keras \
    && cp /tmp/phishingguard/requirements.txt /app/requirements.txt \
    && rm -rf /tmp/phishingguard /tmp/phishingguard.tar.gz \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && apt-get purge -y curl tar \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Files in PhishingGuard-Final are copied last so the final UI/entrypoint can evolve
# without changing the protected baseline model/scanner.
COPY . /app/

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}"]
