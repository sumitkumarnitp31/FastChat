
# FastChat: High-Throughput Real-Time Messaging

FastChat is a TLS-encrypted, asyncio-based chat system with a FastAPI auth
API, PostgreSQL persistence, end-to-end encrypted messages, and Redis-based
fan-out for multi-instance socket deployments. It's designed to support
roughly 1000 concurrent clients per asyncio process, and to scale
horizontally across multiple processes behind a load balancer.

## Project layout

```text
fastchat/
├── .env                        # local secrets/config (gitignored, auto-loaded by both processes)
├── .env.example                # safe template for .env, committed
├── .gitignore
├── .dockerignore
├── docker-compose.yml           # "everything in Docker" orchestration (recommended)
├── BENCHMARKING.md              # how to actually measure throughput/latency
├── api/
│   ├── main.py                  # FastAPI auth API: /register, /login, /logout,
│   │                             # GET+PATCH /users/.../public_key, /health
│   └── Dockerfile
├── db/
│   └── schema.sql               # PostgreSQL schema and indexes (auto-applied by Docker on first run)
├── deployment/
│   ├── gen_dev_certs.py         # Python helper to generate a local self-signed cert (no openssl needed)
│   ├── gen_dev_certs.sh         # Bash/openssl equivalent
│   ├── nginx.conf               # Nginx TCP load balancer example (bare-metal, placeholder IPs)
│   └── nginx.docker.conf        # Same, wired to Docker Compose service names
├── scripts/
│   └── load_test.py             # real throughput/latency measurement, see BENCHMARKING.md
├── server/
│   ├── client.py                 # TLS client with automatic E2E key exchange (runs on your HOST, not in Docker)
│   ├── e2e_crypto.py             # X25519 + AES-GCM end-to-end encryption primitives
│   ├── identity_store.py         # Persists each client's identity + peer keys to disk
│   ├── tcp_server.py             # Async TLS socket server, JWT session validation, Redis fan-out
│   └── Dockerfile
└── requirements.txt
```

---

## Running FastChat

There are two ways to run this. **Docker is recommended** — one command
brings up the database, cache, both application tiers, and a load
balancer, all correctly wired together, with the schema applied
automatically. The manual path is there for when you want to run pieces
individually (e.g. debugging one service, or you don't have Docker
available).

### Option 1: Everything in Docker (recommended)

Your entire backend — FastAPI, the socket server (as **two** separate
instances), Redis, PostgreSQL, and an Nginx TCP load balancer — runs
inside an isolated virtual network created by Docker Compose. Only
`client.py` runs outside Docker, on your host machine, since it's an
interactive terminal program.

**Why this is worth using over running four+ terminals manually:**

1. **One command instead of five terminals.** Postgres, Redis, the API,
   and the socket server(s) all start in the correct order automatically:
   ```bash
   docker compose up --build
   ```
2. **Isolated, disposable database.** No native Postgres install, no
   version conflicts, no background service lingering on your machine.
   Want to wipe all data and start over? `docker compose down -v` deletes
   the volume; the schema reapplies automatically on the next `up`.
3. **No "works on my machine."** Cloning the repo and running
   `docker compose up --build` reproduces the exact same environment
   anywhere Docker runs — useful if we ever need to demo this to someone
   else without spending 20 minutes on their dependency setup.
4. **Proves multi-instance scaling actually works, not just in theory.**
   This compose file runs **two** socket-server instances
   (`socket-server-1`, `socket-server-2`) behind Nginx, sharing one Redis.
   You can watch a message sent by a client on instance A actually get
   relayed to a client connected to instance B — the exact scenario
   described in Phase 4.

#### Prerequisites

- Docker and Docker Compose (Docker Desktop on Windows/Mac, or
  `docker` + the `compose` plugin on Linux)
- Nothing else — no local Python, Postgres, or Redis install needed for
  the containers themselves. You do still need Python locally to run
  `client.py`, since it's not containerized.

#### 1) Unzip and bring the stack up

```bash
unzip fastchat.zip
cd fastchat
docker compose up --build
```

This builds and starts all seven containers:

| Service | What it is | Host port |
|---|---|---|
| `postgres` | Database, schema auto-applied on first run | `5432` |
| `redis` | Cross-instance message fan-out | `6379` |
| `cert-init` | One-shot: generates the shared dev TLS cert, then exits | — |
| `api` | FastAPI auth service | `5000` |
| `socket-server-1` | Chat server, instance 1 (direct access, bypassing the LB) | `8444` |
| `socket-server-2` | Chat server, instance 2 (direct access, bypassing the LB) | `8445` |
| `nginx` | TCP load balancer in front of both instances | `8443` |

Wait for the logs to settle — `postgres` and `redis` report healthy,
`cert-init` exits with status 0, then `api`, `socket-server-1`,
`socket-server-2`, and `nginx` all start.

`FASTCHAT_JWT_SECRET` is pulled automatically from the `.env` file
already at the project root — Docker Compose loads it for `${...}`
substitution in `docker-compose.yml`. You don't need a separate
Docker-specific secrets file.

#### 2) Set up your local Python environment for the client

The client isn't containerized (it needs an interactive terminal), so it
still runs natively:

```bash
python3.12 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

`cert-init` writes the shared dev certificate to `./server/certs/` on
your **host** filesystem (bind-mounted, not a Docker-only volume) —
`client.py` reads it from that same path, so no manual cert copying is
needed.

#### 3) Register users and log in

Exactly the same as the manual setup — the API is reachable at
`http://localhost:5000` regardless of how it's running:

```bash
curl -X POST http://localhost:5000/register -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"password123"}'

curl -X POST http://localhost:5000/register -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@example.com","password":"password123"}'

curl -X POST http://localhost:5000/login -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

Copy the JWT token from the response — you'll paste it into the client next.


#### 4) Connect clients — through the load balancer

`client.py`'s default `SERVER_PORT` is `8443`, which is exactly the port
Nginx exposes — so clients connect through the load balancer
transparently, with no code changes:

```bash
cd server
python3.12 client.py
```

Paste Alice's JWT. Repeat in another terminal for Bob. Send a message the
usual way:

```text
2 hey bob!
```

You have no way of knowing (or needing to know) which of the two
socket-server instances either client actually landed on — Nginx's
`least_conn` balancing decided that. That's the point.

#### 5) Prove the multi-instance Redis fan-out is actually working

This is the interesting part — force two clients onto **different**
instances and confirm a message still gets delivered in real time.

```bash
# Terminal A: connect directly to instance 1, bypassing the load balancer
cd server
python3.12 -c "
import client
client.SERVER_PORT = 8444
import asyncio
asyncio.run(client.main())
"
# paste Alice's JWT

# Terminal B: connect directly to instance 2
cd server
python3.12 -c "
import client
client.SERVER_PORT = 8445
import asyncio
asyncio.run(client.main())
"
# paste Bob's JWT
```

Now send a message from Alice (on instance 1) to Bob (on instance 2):
```text
2 can you see this from the other instance?
```

Watch the logs — `docker compose logs -f socket-server-1
socket-server-2 redis` — you'll see instance 1 publish to Redis (no local
writer for user 2) and instance 2's `redis_subscriber_loop` receive and
deliver it. Bob's terminal shows the decrypted message exactly as if both
clients had been on the same instance.

#### 6) Tear down / reset

```bash
docker compose down          # stop and remove containers, keep data
docker compose down -v       # also delete the Postgres volume (full reset)
```

---

### Option 2: Manual / native setup (no Docker)

#### Prerequisites

- Python 3.11+
- PostgreSQL running locally, or Docker (for just the database)
- Redis is optional; the server runs in single-instance mode without it
- OpenSSL is optional — `gen_dev_certs.py` needs nothing extra, which
  matters on Windows since `openssl` usually isn't on PATH there by
  default

#### 1) Unzip and create a virtual environment

```bash
unzip fastchat.zip
cd fastchat
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

#### 2) Set up PostgreSQL

**Option A: Local PostgreSQL on WSL/Ubuntu**

```bash
sudo apt update
sudo apt install postgresql postgresql-client
sudo -u postgres createuser fastchat --pwprompt
sudo -u postgres createdb fastchat -O fastchat
```

When prompted, set the password to `fastchat` (or update `.env` to match
whatever you choose). Then load the schema:

```bash
psql -U fastchat -d fastchat -h 127.0.0.1 -f db/schema.sql
```

**Option B: Docker, just for Postgres**

```bash
docker run --name fastchat-pg \
  -e POSTGRES_USER=fastchat \
  -e POSTGRES_PASSWORD=fastchat \
  -e POSTGRES_DB=fastchat \
  -p 5432:5432 \
  -d postgres:16

psql -U fastchat -d fastchat -h 127.0.0.1 -f db/schema.sql
```

#### 3) Create a local TLS certificate

```bash
python3.12 deployment/gen_dev_certs.py
```

Creates `server/certs/server.crt` and `server/certs/server.key`.
Re-running this is safe — it skips regeneration if the files already exist.

#### 4) Configure environment variables

A `.env` file already exists at the project root with a real generated
`FASTCHAT_JWT_SECRET` and the default DSN — you don't need to export
anything manually. Both `api/main.py` and `server/tcp_server.py` load
`.env` automatically (via `python-dotenv`).

```env
FASTCHAT_JWT_SECRET=<a long random value, already generated>
FASTCHAT_DB_DSN=postgresql://fastchat:fastchat@127.0.0.1:5432/fastchat
```

Only edit `FASTCHAT_DB_DSN` if your Postgres credentials differ.
`.env.example` is the safe, secret-free template committed to version
control — `.env` itself is gitignored.

Optional — only needed if you want a non-default port or a second local
instance for testing:

```env
FASTCHAT_PORT=8443
FASTCHAT_REDIS_URL=redis://localhost:6379/0
FASTCHAT_REDIS_CHANNEL_PREFIX=fastchat:user
```

#### 5) Start the FastAPI auth service

Terminal 1:

```bash
cd api
uvicorn main:app --reload --port 5000
```

Visit `http://localhost:5000/docs` for Swagger UI, or
`http://localhost:5000/health` for a DB-backed health check.

#### 6) Start the socket server

Terminal 2:

```bash
cd server
python3.12 tcp_server.py
```

You should see `FastChat TLS server listening on ...`.

To run a **second** instance locally (to test Redis fan-out without
Docker), start Redis (`redis-server`), then in another terminal:

```bash
cd server
FASTCHAT_PORT=8444 python3.12 tcp_server.py
```

Both instances will connect to the same `FASTCHAT_REDIS_URL` and relay
messages to each other for users connected to the other instance.

#### 7) Register users and log in

Terminal 3:

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"password123"}'

curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"bob","email":"bob@example.com","password":"password123"}'

curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}'
```

Copy the returned JWT.

#### 8) Connect two clients

Terminal 4:

```bash
cd server
python3.12 client.py
```

Paste Alice's JWT. The client loads (or creates) a persistent identity
keypair, publishes its public key to the API, and prints it for
reference.

Terminal 5 — repeat for Bob.

#### 9) Send a message

```text
2 hey bob!
```

No manual key exchange needed — the client auto-fetches Bob's public key
from the API. If that fails (API unreachable, peer never logged in yet),
fall back to:

```text
/addkey <their_user_id> <their_public_key_b64>
```

Either way, the resulting shared key is saved to disk and reused in
future sessions.

---

## Benchmarking

"It's built on asyncio" is an architecture choice, not a performance
measurement. `scripts/load_test.py` actually measures throughput and
latency against a real running instance -- concurrent connections,
messages/sec, and a full p50/p95/p99/max latency distribution, not just
an average. See `BENCHMARKING.md` for how to run it, what it measures
(and deliberately doesn't), and a real bug it caught on its first run
(bcrypt blocking the FastAPI event loop -- since fixed in `api/main.py`).

```bash
pip install aiohttp   # only needed for this script
python3.12 scripts/load_test.py --users 100 --messages-per-user 20
```

## How it works

1. The FastAPI service issues a JWT on `/login` and records a matching row in `sessions`.
2. The socket server verifies the JWT's signature and independently checks the `sessions` row on every new connection — this is what makes `/logout` able to kill a session before its token naturally expires.
3. On login, the client publishes its persistent X25519 public key to the API (`PATCH /users/me/public_key`).
4. When messaging someone new, the client fetches their public key automatically (`GET /users/{id}/public_key`) and derives a shared AES key via X25519 Diffie-Hellman — no key ever crosses the wire.
5. Messages are AES-GCM encrypted client-side, sent over TLS, and stored in PostgreSQL as ciphertext the server itself cannot read.
6. If the recipient is connected to a *different* socket-server instance, the sending instance publishes the ciphertext to Redis (`FASTCHAT_REDIS_CHANNEL_PREFIX:<user_id>`); the instance holding that user's connection is subscribed and relays it in real time.
7. If the recipient is offline entirely, the ciphertext waits in the `messages` table and is delivered the moment they reconnect.

## Database schema at a glance

Full definitions and indexes are in `db/schema.sql`.

### `users`
- `id`, `username` (unique), `email` (unique)
- `password_hash` (bcrypt)
- `public_key` (X25519 public key, published via the API for auto key exchange)
- `is_active`, `created_at`, `last_seen`

### `sessions`
One row per issued login token.
- `user_id`, `token_jti` (unique, indexed for fast socket-auth lookups)
- `issued_at`, `expires_at`, `revoked`
- `ip_address`, `user_agent`

### `messages`
- `sender_id`, `receiver_id` (or `room_id` for group/broadcast flows)
- `ciphertext`, `nonce`
- `sent_at`, `delivered`

## Notes

- Redis is optional in the manual setup; without it, each socket-server instance runs standalone. The Docker setup always includes it, since it runs two instances by design.
- The included cert is self-signed, for local development only — use a CA-signed cert in production.
- `server/.fastchat_identities/` holds each client's persisted identity and peer keys as plaintext JSON — fine for local dev, but a production client should encrypt this at rest with a passphrase (see the note at the top of `identity_store.py`).
- Windows note: `tcp_server.py`'s shutdown handling falls back automatically on Windows, since `asyncio`'s `SIGTERM` handling is POSIX-only.
- The Docker Nginx config (`nginx.docker.conf`) does **not** terminate TLS — it routes based on the TLS ClientHello via `ssl_preread`, and each socket-server instance terminates its own TLS individually, using the shared cert from the bind-mounted `server/certs/` directory.
- For real production deployments beyond this local/demo setup: CA-signed certificates, a proper secrets manager instead of a checked-in `.env`, rate limiting on `/register` and `/login`, and structured metrics (Prometheus) for connection counts, message throughput, and DB pool saturation.
