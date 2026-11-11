# QueryCast API Backend
# Python 3.12-slim base — minimal attack surface
FROM python:3.12-slim

# Create non-root user/group (UID 1000, GID 1000)
RUN groupadd -g 1000 appgroup && \
    useradd  -u 1000 -g appgroup -m -s /sbin/nologin appuser

WORKDIR /app

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies as root before dropping privileges
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY app.py security.py ./

# Create persistent data directory and set ownership
RUN mkdir -p /data/uploads && \
    chown -R appuser:appgroup /data /app

# Drop to non-root
USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c \
        "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/health')" \
        || exit 1

CMD ["python", "app.py"]
