"""
tcp_server.py
=============
FastChat's core network layer.

CONCURRENCY MODEL
------------------
We use asyncio instead of thread-per-connection. At ~1000 concurrent clients,
a thread-per-connection model means 1000 OS threads: several hundred MB of
stack memory alone, plus the kernel scheduler doing constant context switches
between mostly-idle threads (a chat client spends 99% of its time waiting on
I/O, not computing). asyncio's event loop uses epoll (on Linux) under the
hood: ONE OS thread services all 1000 sockets, waking up only when a socket
actually has data ready. That's the difference between "1000 threads mostly
sleeping" and "1 thread + epoll telling it exactly who's ready." It scales
far better for I/O-bound workloads like this one.

We still use a small ThreadPoolExecutor for anything that isn't
asyncio-native and would otherwise block the event loop (e.g. a CPU-bound
bcrypt hashing operation, though here password hashing is delegated to the
FastAPI auth API, and DB calls all go through asyncpg's native async
driver, so nothing here should actually block -- the executor is kept as a
safety net).

SSL/TLS HANDSHAKE
------------------
`asyncio.start_server(..., ssl=ssl_context)` wraps every accepted socket in
a TLS handshake BEFORE our `handle_client` coroutine ever sees it. Sequence:
  1. TCP 3-way handshake completes (SYN, SYN-ACK, ACK).
  2. Client sends ClientHello (supported TLS versions/ciphers).
  3. Server responds ServerHello + its certificate + chosen cipher suite.
  4. Client verifies the certificate, both sides derive a shared symmetric
     session key via ECDHE key exchange (perfect forward secrecy).
  5. Both sides send "Finished" once the record layer is encrypted.
  6. Only THEN does asyncio invoke `handle_client(reader, writer)`.
This is transport-level encryption; see server/e2e_crypto.py for true
end-to-end (server-can't-read-it) encryption of message payloads.

APPLICATION-LEVEL AUTH
------------------
TLS proves "you're talking to the real server," not "you're a valid user."
Immediately after connecting, the client must send a JWT (issued by the
FastAPI auth API on login) as its first framed message. We verify the JWT
signature AND cross-check it against the `sessions` table (so a token can
be force-revoked server-side even before it naturally expires). Only after
that does the connection get promoted to an authenticated session capable
of sending/receiving chat messages.

WIRE FORMAT
------------------
Simple length-prefixed framing to avoid TCP message-boundary ambiguity:
    [4 bytes: big-endian uint32 length][N bytes: UTF-8 JSON payload]
"""

import asyncio
import ssl
import json
import struct
import logging
import signal
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import os
import asyncpg
import jwt  # PyJWT
from dotenv import load_dotenv, find_dotenv

# Auto-load a .env file from the project root -- searches the current
# directory and upward, so this works whether you run this script from
# fastchat/, fastchat/server/, or anywhere else inside the project. This
# means you set FASTCHAT_JWT_SECRET / FASTCHAT_DB_DSN ONCE in .env instead
# of re-exporting them in every terminal you open.
load_dotenv(find_dotenv())

# --------------------------------------------------------------------------
# Configuration. JWT_SECRET and DB_DSN are read from the SAME environment
# variables main.py (the FastAPI service) uses -- FASTCHAT_JWT_SECRET and
# FASTCHAT_DB_DSN. This is not optional: if these two processes ever use
# different secrets, every login will produce a JWT this server can't
# verify, and every client will get "authentication failed" with no
# indication of why other than the server log. Set both env vars before
# starting either process.
# --------------------------------------------------------------------------
HOST = "0.0.0.0"
PORT = int(os.environ.get("FASTCHAT_PORT", "8443"))
JWT_SECRET = os.environ.get("FASTCHAT_JWT_SECRET", "CHANGE_ME_TO_A_LONG_RANDOM_SECRET")
JWT_ALGORITHM = "HS256"
DB_DSN = os.environ.get("FASTCHAT_DB_DSN", "postgresql://fastchat:fastchat@localhost:5432/fastchat")
CERT_FILE = os.environ.get("FASTCHAT_CERT_FILE", "certs/server.crt")
KEY_FILE = os.environ.get("FASTCHAT_KEY_FILE", "certs/server.key")
MAX_FRAME_BYTES = 64 * 1024   # 64KB per message cap -- prevents a malicious
                              # client from claiming a multi-GB frame length
                              # and exhausting server memory.

# Multi-instance fan-out (see Phase 4 / README "Everything in Docker"
# setup). REDIS_URL points every instance at the SAME Redis, so a message
# received by one instance can reach a recipient connected to another.
# REDIS_CHANNEL_PREFIX must also match across instances -- it's the
# namespace for per-user pub/sub channels (each user gets a channel named
# "<prefix>:<user_id>"). Both are configurable per-deployment so multiple
# unrelated FastChat clusters could share one Redis without colliding, by
# giving each cluster a different prefix.
REDIS_URL = os.environ.get("FASTCHAT_REDIS_URL", "redis://localhost:6379/0")
REDIS_CHANNEL_PREFIX = os.environ.get("FASTCHAT_REDIS_CHANNEL_PREFIX", "fastchat:user")

# DB pool size. The original hardcoded default here (min=10, max=30) was
# never load-tested and turned out to be a real bottleneck: at 500
# concurrent clients all persisting messages, only `max_size` inserts can
# ever be in flight at once -- everyone else queues, and because a single
# connection's messages are processed strictly one-at-a-time (see the
# `while True` loop in handle_client -- it fully awaits handle_chat_message
# before reading that connection's next frame), a small pool under high
# concurrency produces exactly the runaway latency this was built to catch.
# Tune this to your actual Postgres instance's real capacity -- there's no
# universally "right" number, it depends on Postgres's own max_connections,
# available cores, and disk I/O characteristics. See BENCHMARKING.md.
DB_POOL_MIN_SIZE = int(os.environ.get("FASTCHAT_DB_POOL_MIN_SIZE", "10"))
DB_POOL_MAX_SIZE = int(os.environ.get("FASTCHAT_DB_POOL_MAX_SIZE", "50"))


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("fastchat.server")

# Small executor reserved for any accidental blocking call; asyncpg/asyncio
# itself never needs this, kept purely as a defensive safety net.
executor = ThreadPoolExecutor(max_workers=8)


# --------------------------------------------------------------------------
# Connection registry: maps authenticated user_id -> StreamWriter.
# Single-threaded event loop means no risk of two coroutines mutating this
# dict truly simultaneously, but we still guard with a Lock because a
# coroutine CAN be suspended mid-mutation at an `await` point, and we want
# register/unregister to be atomic with respect to each other.
# --------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self._connections: dict[int, asyncio.StreamWriter] = {}
        self._lock = asyncio.Lock()

    async def register(self, user_id: int, writer: asyncio.StreamWriter):
        async with self._lock:
            # If the same user reconnects (e.g. new device/tab), close the
            # stale connection rather than silently leaking it.
            old = self._connections.get(user_id)
            if old is not None and not old.is_closing():
                old.close()
            self._connections[user_id] = writer

    async def unregister(self, user_id: int):
        async with self._lock:
            self._connections.pop(user_id, None)

    def get_writer(self, user_id: int) -> asyncio.StreamWriter | None:
        return self._connections.get(user_id)

    def online_count(self) -> int:
        return len(self._connections)


conn_manager = ConnectionManager()


# --------------------------------------------------------------------------
# Framing helpers
# --------------------------------------------------------------------------
async def send_frame(writer: asyncio.StreamWriter, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()   # respects backpressure -- pauses us if the
                            # client's TCP receive buffer is full, instead
                            # of buffering unbounded data in our own memory.


async def read_frame(reader: asyncio.StreamReader) -> dict | None:
    """Returns None cleanly on EOF/disconnect instead of raising."""
    try:
        length_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None   # client disconnected between messages -- normal, not an error

    (length,) = struct.unpack(">I", length_bytes)
    if length > MAX_FRAME_BYTES:
        raise ValueError(f"Frame of {length} bytes exceeds max {MAX_FRAME_BYTES}")

    try:
        data = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None   # client disconnected mid-frame

    return json.loads(data.decode("utf-8"))


# --------------------------------------------------------------------------
# Auth: verify JWT signature + confirm the session is still active in DB.
# --------------------------------------------------------------------------
async def authenticate(db_pool: asyncpg.Pool, token: str) -> dict | None:
    try:
        claims = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        log.info("auth rejected: token expired")
        return None
    except jwt.InvalidTokenError as e:
        log.info("auth rejected: invalid token (%s)", e)
        return None

    jti = claims.get("jti")
    user_id = claims.get("user_id")
    if not jti or not user_id:
        return None

    # Hot-path query -- served by the partial unique index on (token_jti)
    # WHERE revoked = false, so this is an index-only lookup even under load.
    row = await db_pool.fetchrow(
        """
        SELECT s.user_id, u.username
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_jti = $1
          AND s.revoked = FALSE
          AND s.expires_at > now()
        """,
        jti,
    )
    if row is None:
        log.info("auth rejected: session revoked/expired/not found for jti=%s", jti)
        return None

    return {"user_id": row["user_id"], "username": row["username"]}


# --------------------------------------------------------------------------
# Per-connection handler
# --------------------------------------------------------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         db_pool: asyncpg.Pool, redis_client=None):
    peer = writer.get_extra_info("peername")
    log.info("connection opened from %s", peer)
    user_id = None
    username = None

    try:
        # ---- Step 1: require an auth frame within 10 seconds ----
        try:
            first_frame = await asyncio.wait_for(read_frame(reader), timeout=10.0)
        except asyncio.TimeoutError:
            await send_frame(writer, {"type": "error", "message": "auth timeout"})
            return

        if first_frame is None or first_frame.get("type") != "auth":
            await send_frame(writer, {"type": "error", "message": "expected auth frame first"})
            return

        identity = await authenticate(db_pool, first_frame.get("token", ""))
        if identity is None:
            await send_frame(writer, {"type": "error", "message": "authentication failed"})
            return

        user_id, username = identity["user_id"], identity["username"]
        await conn_manager.register(user_id, writer)
        await send_frame(writer, {"type": "auth_ok", "user_id": user_id, "username": username})
        log.info("user %s (id=%s) authenticated from %s", username, user_id, peer)

        # Flush any messages that arrived while this user was offline.
        await deliver_pending_messages(db_pool, writer, user_id)

        # ---- Step 2: main receive loop ----
        while True:
            frame = await read_frame(reader)
            if frame is None:
                break   # client disconnected -- exit loop, fall to `finally`

            msg_type = frame.get("type")
            if msg_type == "message":
                await handle_chat_message(db_pool, redis_client, user_id, frame)
            elif msg_type == "ping":
                await send_frame(writer, {"type": "pong"})
            else:
                await send_frame(writer, {"type": "error", "message": f"unknown frame type '{msg_type}'"})

    except ValueError as e:
        # Raised by read_frame on an oversized/malformed frame -- treat as
        # a misbehaving client, not a server fault.
        log.warning("protocol violation from %s: %s", peer, e)
        try:
            await send_frame(writer, {"type": "error", "message": str(e)})
        except Exception:
            pass
    except (ConnectionResetError, BrokenPipeError):
        # Client vanished (crashed, lost network, killed process). Normal in
        # a system with 1000 concurrent clients -- log at info, not error.
        log.info("connection reset by peer %s", peer)
    except Exception:
        log.exception("unexpected error handling client %s", peer)
    finally:
        if user_id is not None:
            await conn_manager.unregister(user_id)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        log.info("connection closed for %s (user_id=%s)", peer, user_id)


async def deliver_pending_messages(db_pool: asyncpg.Pool, writer: asyncio.StreamWriter, user_id: int):
    rows = await db_pool.fetch(
        """
        SELECT id, sender_id, ciphertext, nonce, sent_at
        FROM messages
        WHERE receiver_id = $1 AND delivered = FALSE
        ORDER BY sent_at ASC
        LIMIT 500
        """,
        user_id,
    )
    if not rows:
        return

    for row in rows:
        await send_frame(writer, {
            "type": "message",
            "from": row["sender_id"],
            "ciphertext": row["ciphertext"].hex(),
            "nonce": row["nonce"].hex() if row["nonce"] else None,
            "sent_at": row["sent_at"].isoformat(),
        })

    ids = [r["id"] for r in rows]
    await db_pool.execute("UPDATE messages SET delivered = TRUE WHERE id = ANY($1::bigint[])", ids)


async def handle_chat_message(db_pool: asyncpg.Pool, redis_client, sender_id: int, frame: dict):
    """
    frame = {
        "type": "message",
        "to": <receiver_user_id>,
        "ciphertext": "<hex>",   # already E2E-encrypted client-side, see e2e_crypto.py
        "nonce": "<hex>"
    }
    """
    receiver_id = frame.get("to")
    ciphertext = bytes.fromhex(frame["ciphertext"])
    nonce = bytes.fromhex(frame["nonce"]) if frame.get("nonce") else None

    # Persist first (durability), then attempt real-time delivery.
    row = await db_pool.fetchrow(
        """
        INSERT INTO messages (sender_id, receiver_id, ciphertext, nonce, delivered)
        VALUES ($1, $2, $3, $4, FALSE)
        RETURNING id, sent_at
        """,
        sender_id, receiver_id, ciphertext, nonce,
    )

    payload = {
        "type": "message",
        "from": sender_id,
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex() if nonce else None,
        "sent_at": row["sent_at"].isoformat(),
    }

    target_writer = conn_manager.get_writer(receiver_id)
    if target_writer is not None:
        # Recipient is connected to THIS server instance -- deliver locally,
        # no Redis round-trip needed.
        await send_frame(target_writer, payload)
        await db_pool.execute("UPDATE messages SET delivered = TRUE WHERE id = $1", row["id"])
    elif redis_client is not None:
        # Recipient may be connected to a DIFFERENT server instance behind
        # the load balancer (see Phase 4 / README "Everything in Docker"
        # setup). Publish so whichever instance owns that user's socket can
        # deliver it -- REDIS_CHANNEL_PREFIX must match across all
        # instances sharing this Redis for this to work.
        await redis_client.publish(f"{REDIS_CHANNEL_PREFIX}:{receiver_id}", json.dumps(payload))
    # else: recipient is fully offline -- it'll be delivered from the DB
    # via deliver_pending_messages() next time they connect.


# --------------------------------------------------------------------------
# Redis subscriber: listens for messages destined for users connected to
# OTHER server instances but whose delivery got routed to us via Pub/Sub
# (only relevant once you're running more than one server process --
# see Phase 4). Safe to run even with a single instance; it just never
# receives anything of interest to itself in that case.
# --------------------------------------------------------------------------
async def redis_subscriber_loop(redis_client):
    pubsub = redis_client.pubsub()
    pattern = f"{REDIS_CHANNEL_PREFIX}:*"
    await pubsub.psubscribe(pattern)
    log.info("subscribed to Redis fan-out pattern '%s'", pattern)
    try:
        async for message in pubsub.listen():
            if message["type"] != "pmessage":
                continue
            try:
                channel = message["channel"].decode() if isinstance(message["channel"], bytes) else message["channel"]
                user_id = int(channel.rsplit(":", 1)[-1])
                payload = json.loads(message["data"])
            except Exception:
                log.exception("malformed pubsub message")
                continue

            writer = conn_manager.get_writer(user_id)
            if writer is not None:
                await send_frame(writer, payload)
    except asyncio.CancelledError:
        # Expected on graceful shutdown -- unsubscribe and let it propagate
        # so main() knows the task actually finished, not just abandoned it.
        await pubsub.punsubscribe(pattern)
        raise


# --------------------------------------------------------------------------
# SSL context setup
# --------------------------------------------------------------------------
def build_ssl_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    context.minimum_version = ssl.TLSVersion.TLSv1_2   # reject legacy/broken TLS
    context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5:!DSS")
    return context


# --------------------------------------------------------------------------
# Entrypoint
# --------------------------------------------------------------------------
async def main():
    ssl_context = build_ssl_context()

    # asyncpg pool: a SMALL number of real Postgres connections shared by
    # ALL 1000 client sockets. This is the key to scaling -- we are not
    # opening one DB connection per chat client.
    db_pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=DB_POOL_MIN_SIZE, max_size=DB_POOL_MAX_SIZE)

    redis_client = None
    try:
        import redis.asyncio as aioredis
        redis_client = aioredis.from_url(REDIS_URL)
        await redis_client.ping()
        log.info("connected to Redis at %s for cross-instance fan-out", REDIS_URL)
    except Exception as e:
        log.warning("Redis unavailable at %s, running in single-instance mode: %s", REDIS_URL, e)
        redis_client = None

    async def client_connected_cb(reader, writer):
        await handle_client(reader, writer, db_pool, redis_client)

    server = await asyncio.start_server(client_connected_cb, HOST, PORT, ssl=ssl_context)

    subscriber_task = None
    if redis_client is not None:
        subscriber_task = asyncio.create_task(redis_subscriber_loop(redis_client))

    addr = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    log.info("FastChat TLS server listening on %s", addr)

    # Graceful shutdown on SIGTERM/SIGINT -- important under a process
    # manager (systemd, supervisord, k8s) so in-flight messages get a
    # chance to flush instead of connections being hard-killed.
    #
    # NOTE: `loop.add_signal_handler()` is POSIX-only -- it raises
    # NotImplementedError on Windows's asyncio event loop. We fall back to
    # plain `signal.signal()` there, which still lets Ctrl+C (SIGINT)
    # trigger a clean shutdown on Windows; it just can't catch SIGTERM
    # (Windows doesn't really have an equivalent process-manager signal
    # anyway).
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_shutdown(*_args):
        loop.call_soon_threadsafe(stop_event.set)

    try:
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop_event.set)
    except NotImplementedError:
        # Windows: register with the standard library instead.
        signal.signal(signal.SIGINT, _request_shutdown)
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, _request_shutdown)

    async with server:
        await stop_event.wait()
        log.info("shutdown signal received, closing server...")

    if subscriber_task:
        subscriber_task.cancel()
        try:
            await subscriber_task
        except asyncio.CancelledError:
            pass
    if redis_client is not None:
        await redis_client.aclose()
        log.info("Redis connection closed")
    await db_pool.close()
    executor.shutdown(wait=True)
    log.info("clean shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Extra safety net on Windows if Ctrl+C arrives before the signal
        # handler above is registered (e.g. during startup).
        log.info("interrupted, exiting")
