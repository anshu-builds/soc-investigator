FROM python:3.11-slim

WORKDIR /app

# Install system deps for chromadb and sentence-transformers
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY backend /app/backend
COPY detection /app/detection
COPY correlation /app/correlation
COPY ai /app/ai
COPY rag /app/rag
COPY reports /app/reports
COPY knowledge /app/knowledge
COPY alembic.ini /app/alembic.ini
COPY alembic /app/alembic

WORKDIR /app

ENV PYTHONPATH=/app

# Create dedicated non-root user and assign permissions
RUN groupadd -r soc && useradd -r -g soc -s /sbin/nologin -d /app soc \
    && mkdir -p /app/generated_reports \
    && chown -R soc:soc /app

USER soc

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
