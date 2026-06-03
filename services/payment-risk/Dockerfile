# DEMO: python:3.8-alpine has known critical CVEs — triggers Gate 2. Restore to 3.11-alpine for green build.
FROM python:3.8-alpine
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
RUN adduser -D appuser && chown -R appuser /app
USER appuser
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
