# detonation container - visits phishing urls in isolated chromium
FROM python:3.11-slim-bookworm

# system deps for chromium (changes rarely, cached aggressively)
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    gnupg \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# deps layer (only rebuilds when requirements change)
COPY docker_requirements.txt .
RUN pip install --no-cache-dir -r docker_requirements.txt

# browser install (only rebuilds when playwright version changes)
RUN playwright install chromium && playwright install-deps

# script layer (rebuilds on code changes only, everything above is cached)
COPY detonate_url.py .

CMD ["python", "detonate_url.py"]
