# syntax=docker/dockerfile:1.7
FROM python:3.12-alpine

RUN pip install --no-cache-dir \
      "fastapi==0.115.*" \
      "httpx==0.27.*" \
      "uvicorn[standard]==0.32.*"

WORKDIR /app
COPY gateway.py .

# Non-root
RUN adduser -D -u 10001 app
USER app

EXPOSE 8080
ENTRYPOINT ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8080", \
            "--no-access-log", "--workers", "2"]
