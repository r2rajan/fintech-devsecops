FROM python:3.12-alpine
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
RUN adduser -D appuser && chown -R appuser /app
USER appuser
CMD exec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}
