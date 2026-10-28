# Build context is the PROJECT ROOT (see docker-compose.yml's
# `build.context: .`). This same image is also reused, with its CMD
# overridden, as the one-shot `cert-init` service in docker-compose.yml --
# that's why `deployment/gen_dev_certs.py` is copied in too, even though
# tcp_server.py itself never imports it.
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server/ ./server/
COPY deployment/gen_dev_certs.py ./deployment/gen_dev_certs.py

WORKDIR /app/server

EXPOSE 8443

CMD ["python", "tcp_server.py"]
