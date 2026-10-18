# ---- Stage 1: build (install deps + train the model) ----
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY phishguard ./phishguard
RUN python -m phishguard.train --out /build/models

# ---- Stage 2: runtime (small, non-root, no build tools) ----
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" MODEL_DIR=/app/models
RUN groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/models ./models
COPY phishguard ./phishguard
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -m phishguard.healthcheck
CMD ["uvicorn", "phishguard.app:app", "--host", "0.0.0.0", "--port", "8000"]
