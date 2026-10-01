# --- build the React front end ---
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# --- Python API serving the built front end ---
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TRIAGE_CACHE_DIR=/cache
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY triage/ ./triage/
COPY --from=web /web/dist ./web/dist
RUN useradd --create-home app && mkdir -p /cache && chown app /cache
USER app
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health')"
CMD ["uvicorn", "triage.server:app", "--host", "0.0.0.0", "--port", "8000"]
