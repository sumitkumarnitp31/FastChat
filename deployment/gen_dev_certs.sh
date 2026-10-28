#!/usr/bin/env bash
# Generates a self-signed cert for LOCAL DEVELOPMENT ONLY.
# In production, use a CA-signed cert (Let's Encrypt via certbot, or your
# org's internal CA) -- self-signed certs mean clients must explicitly
# trust them out-of-band, which doesn't scale past testing.
set -euo pipefail

mkdir -p ../server/certs

openssl req -x509 -newkey rsa:4096 \
    -keyout ../server/certs/server.key \
    -out ../server/certs/server.crt \
    -days 365 -nodes \
    -subj "/CN=localhost"

echo "Generated ../server/certs/server.key and ../server/certs/server.crt"
echo "Point CERT_FILE / KEY_FILE in tcp_server.py at these, and CA_CERT_FILE in client.py at server.crt."
