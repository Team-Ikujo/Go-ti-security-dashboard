FROM python:3.13-slim

WORKDIR /app

RUN useradd -u 1000 -m appuser

COPY requirements-server.txt .
RUN pip install --no-cache-dir -r requirements-server.txt

COPY server.py .
COPY utils/ utils/

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8100

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/health')"

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8100"]
