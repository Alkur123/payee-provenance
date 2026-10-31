# Payee-provenance gate as a service. Standard library only: no third-party packages in the image.
# Build:  docker build -t payee-provenance .
# Run:    docker run -p 8080:8080 -e PP_BANK_KEY=<hex> -e PP_GATE_KEY=<hex> -e PP_RECEIPT_KEY=<hex> -e PP_APP_KEY=<hex> \
#           -v pp-receipts:/data payee-provenance
# Keys come from the bank's secret store (each at least 32 bytes, hex); the service refuses to start without them.
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 gate && mkdir -p /data && chown gate /data
WORKDIR /app
COPY payee_provenance/ /app/payee_provenance/
USER gate
ENV PP_RECEIPTS_PATH=/data/receipts.jsonl PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2)"
CMD ["python", "-m", "payee_provenance.server", "--host", "0.0.0.0", "--port", "8080"]
