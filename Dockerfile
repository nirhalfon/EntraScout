# Multi-stage build: frontend (Node) → backend (Python)

# Stage 1: Build React frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Python runtime
FROM python:3.12-slim
WORKDIR /app

# Install system deps for dnspython/httpx
RUN apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e "."

# Copy application code
COPY entrascout/ ./entrascout/
COPY tests/ ./tests/
COPY LICENSE README.md ./

# Copy built frontend into the web static folder
COPY --from=frontend-builder /app/frontend/dist ./entrascout/web/static

# Create data directory for SQLite
RUN mkdir -p /app/data

ENV ENTRASCOUT_DB=/app/data/entrascout.db
ENV ENTRASCOUT_OUTPUT=/app/data/output
ENV PORT=8000

EXPOSE 8000

CMD ["uvicorn", "entrascout.web.api:app", "--host", "0.0.0.0", "--port", "8000"]
