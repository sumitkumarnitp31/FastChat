# Build context is the PROJECT ROOT (see docker-compose.yml's
# `build.context: .`), not this directory -- that's why the requirements
# file and the api/ folder are both copied relative to root paths below.
FROM python:3.12-slim

WORKDIR /app

# Install dependencies first, separately from app code, so Docker's layer
# cache reuses this (slow) step on every rebuild unless requirements.txt
# itself actually changed.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/

WORKDIR /app/api

EXPOSE 5000

# No --reload here (that's a dev-only uvicorn feature); production-style
# invocation. Scale workers via `--workers N` if we need more than one
# process per container -- for local/demo purposes, one is plenty.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]
