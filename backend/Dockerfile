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

WORKDIR /app

ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
