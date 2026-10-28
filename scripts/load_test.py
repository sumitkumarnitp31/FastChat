"""
load_test.py
============
Actually measures FastChat's throughput and latency instead of assuming
"it's asyncio, so it's fast." Produces the kind of numbers worth citing:

    500 concurrent clients
    50,000 messages exchanged
    connect time:  1.8s  (277 conn/s)
    throughput:    3,412 msg/s
    latency (ms):  p50=8.2  p95=19.4  p99=31.0  max=88.1

WHAT THIS MEASURES (and what it deliberately does NOT)
--------------------------------------------------------
This benchmarks the socket server's connection handling, JWT/session
auth, message framing, and DB persistence path -- the actual bottleneck
candidates in tcp_server.py. It sends fixed-size dummy "ciphertext"
payloads rather than doing real X25519/AES-GCM per message, because:
  (a) real E2E crypto adds a small, easily-separately-measured constant
      per-message CPU cost (client-side, not server-side -- the server
      never decrypts anyway), and
  (b) establishing O(n^2) real pairwise shared keys for n simulated users
      would benchmark key-exchange setup cost, not the message relay path
      this tool is actually trying to measure.
If you want end-to-end numbers INCLUDING real crypto overhead, that's a
worthwhile separate benchmark -- ask, and it can be added as a flag.

METHODOLOGY
--------------------------------------------------------
1. SETUP: register N test users via the API (idempotent -- reuses
   existing ones on repeat runs), then log all of them in concurrently.
2. CONNECT: open N concurrent TLS connections to the socket server and
   authenticate each one. This phase's wall-clock time is reported
   separately from message throughput, since "how fast can 1000 clients
   all connect at once" and "how fast can already-connected clients
   exchange messages" are different questions with different bottlenecks
   (the former stresses the TLS handshake + DB session lookup; the
   latter stresses the event loop's message-relay path).
3. EXCHANGE: each connected client sends MESSAGES_PER_USER messages to a
   randomly chosen OTHER connected user. Every message embeds a
   monotonic send timestamp; the receiving client computes
   receive_time - send_time as that message's latency the instant it
   arrives. This is real one-way latency as experienced by a receiving
   client, not a synthetic ping/pong RTT.
4. REPORT: aggregate throughput (total messages / wall-clock exchange
   duration) and a latency distribution (p50/p95/p99/max), not just an
   average -- a single average hides tail latency, which is usually what
   actually matters for a chat system's "does this feel real-time" claim.

USAGE
--------------------------------------------------------
    pip install aiohttp   # only needed for this script, not the app itself
    python3.12 scripts/load_test.py --users 100 --messages-per-user 20

    # Scale up once the small run looks healthy:
    python3.12 scripts/load_test.py --users 500 --messages-per-user 100
"""

import argparse
import asyncio
import json
import ssl
import struct
import time
import random
import statistics
from pathlib import Path

import aiohttp

# --------------------------------------------------------------------------
# Config -- mirrors server/client.py's defaults so this talks to the same
# local dev stack by default. Override via CLI flags for other setups
# (e.g. pointing --host at an Nginx load balancer for a multi-instance run).
# --------------------------------------------------------------------------
DEFAULT_API_BASE_URL = "http://localhost:5000"
DEFAULT_SERVER_HOST = "localhost"
DEFAULT_SERVER_PORT = 8443
DEFAULT_CERT_FILE = str(Path(__file__).resolve().parent.parent / "server" / "certs" / "server.crt")
MAX_FRAME_BYTES = 64 * 1024

# IMPORTANT: tcp_server.py's handle_chat_message() rebuilds the outgoing
# frame from scratch (type/from/ciphertext/nonce/sent_at) -- it does NOT
# echo back arbitrary extra fields a client sends. So a naive top-level
# "sent_ts" field would be silently dropped server-side, and latency could
# never be measured. Instead, the send timestamp is packed into the FIRST
# 8 bytes of the (dummy) ciphertext payload itself -- ciphertext bytes are
# opaque to the server (it never inspects, only stores/relays them), so
# this rides through completely unmodified and comes back out the other
# side intact.
_TIMESTAMP_STRUCT = struct.Struct("d")   # 8-byte IEEE-754 double
_DUMMY_PAYLOAD_TOTAL_BYTES = 64          # rest is padding to a realistic message size


# --------------------------------------------------------------------------
# Wire protocol -- identical framing to server/client.py, duplicated here
# on purpose so this script has zero import dependency on the app's client
# module and can be dropped into a separate machine for real load
# generation without carrying the rest of the project along.
# --------------------------------------------------------------------------
async def send_frame(writer: asyncio.StreamWriter, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    writer.write(struct.pack(">I", len(data)) + data)
    await writer.drain()


async def read_frame(reader: asyncio.StreamReader) -> dict | None:
    try:
        length_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", length_bytes)
    if length > MAX_FRAME_BYTES:
        return None
    try:
        data = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(data.decode("utf-8"))


# --------------------------------------------------------------------------
# Phase 1: SETUP -- register + log in N test users via the API, concurrently.
# --------------------------------------------------------------------------
async def register_and_login_user(session: aiohttp.ClientSession, api_base: str, index: int, run_id: str) -> dict | None:
    # IMPORTANT: run_id makes usernames unique PER INVOCATION of this
    # script, not just per user index. Earlier versions used a fixed
    # "loadtest_user_{index}" scheme, which reused the SAME identities
    # across every run. Combined with tcp_server.py's offline-message
    # delivery (any undelivered message is flushed to a user the instant
    # they reconnect, regardless of how long ago it was sent), that meant
    # a user who reconnected under the same username in a LATER run would
    # immediately receive leftover undelivered messages from an EARLIER
    # run -- each still carrying its original send timestamp. The computed
    # "latency" for those messages was actually just wall-clock time
    # between two unrelated test runs (sometimes minutes), not real
    # message latency -- and it compounded, since each overloaded run left
    # more backlog than the last. This is what produced impossible
    # "received > sent" percentages and wildly inflated latency stats.
    # Unique usernames per run eliminate this at the source: there is
    # never a pre-existing identity to inherit backlog from.
    username = f"loadtest_{run_id}_user_{index:05d}"
    email = f"{username}@loadtestdomain.com"
    password = "loadtest_password_123"

    # Idempotent: a 409 (already registered) from a previous run is fine,
    # we just proceed straight to login.
    try:
        async with session.post(f"{api_base}/register", json={
            "username": username, "email": email, "password": password,
        }) as resp:
            if resp.status not in (201, 409):
                text = await resp.text()
                print(f"[!] register failed for {username}: {resp.status} {text}")
                return None
    except Exception as e:
        print(f"[!] register error for {username}: {e}")
        return None

    try:
        async with session.post(f"{api_base}/login", json={
            "username": username, "password": password,
        }) as resp:
            if resp.status != 200:
                text = await resp.text()
                print(f"[!] login failed for {username}: {resp.status} {text}")
                return None
            data = await resp.json()
            return {"username": username, "token": data["token"]}
    except Exception as e:
        print(f"[!] login error for {username}: {e}")
        return None


async def setup_users(api_base: str, num_users: int) -> list[dict]:
    # Unique per invocation -- see the long comment in
    # register_and_login_user() for why this matters. Millisecond
    # precision + a short random suffix so even two runs started in the
    # same second (e.g. a quick automated ramp-up script) get distinct IDs.
    run_id = f"{int(time.time() * 1000)}_{random.randint(1000, 9999)}"
    print(f"[setup] run_id={run_id} (unique per invocation -- prevents stale backlog from prior runs)")
    print(f"[setup] registering + logging in {num_users} test users via {api_base} ...")
    start = time.monotonic()
    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[
            register_and_login_user(session, api_base, i, run_id) for i in range(num_users)
        ])
    users = [u for u in results if u is not None]
    elapsed = time.monotonic() - start
    print(f"[setup] {len(users)}/{num_users} users ready in {elapsed:.2f}s")
    if len(users) < num_users:
        print(f"[!] {num_users - len(users)} users failed setup -- check the API is running and reachable")
    return users


# --------------------------------------------------------------------------
# Phase 2 + 3: a single simulated client's lifecycle -- connect,
# authenticate, then concurrently send its share of messages while
# listening for (and timing) incoming ones.
# --------------------------------------------------------------------------
class SimulatedClient:
    def __init__(self, user: dict, host: str, port: int, ssl_context: ssl.SSLContext):
        self.user = user
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.reader = None
        self.writer = None
        self.user_id = None
        self.latencies_ms: list[float] = []
        self.received_count = 0

    async def connect_and_auth(self) -> bool:
        try:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=self.ssl_context
            )
            await send_frame(self.writer, {"type": "auth", "token": self.user["token"]})
            resp = await asyncio.wait_for(read_frame(self.reader), timeout=10.0)
            if resp is None or resp.get("type") != "auth_ok":
                print(f"[!] auth failed for {self.user['username']}: {resp}")
                return False
            self.user_id = resp["user_id"]
            return True
        except Exception as e:
            print(f"[!] connect/auth error for {self.user['username']}: {e}")
            return False

    async def listen(self, stop_event: asyncio.Event):
        """Runs for the whole exchange phase, timing every message received."""
        while not stop_event.is_set():
            try:
                frame = await asyncio.wait_for(read_frame(self.reader), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except Exception:
                break
            if frame is None:
                break
            if frame.get("type") == "message" and frame.get("ciphertext"):
                try:
                    payload_bytes = bytes.fromhex(frame["ciphertext"])
                    sent_ts = _TIMESTAMP_STRUCT.unpack(payload_bytes[:8])[0]
                    latency_ms = (time.monotonic() - sent_ts) * 1000
                    self.latencies_ms.append(latency_ms)
                    self.received_count += 1
                except (ValueError, struct.error):
                    pass  # not one of our load-test payloads (e.g. leftover real message) -- ignore

    async def send_messages(self, all_user_ids: list[int], count: int):
        others = [uid for uid in all_user_ids if uid != self.user_id]
        if not others:
            return
        for _ in range(count):
            target = random.choice(others)
            payload_bytes = _TIMESTAMP_STRUCT.pack(time.monotonic())
            payload_bytes += b"\xaa" * (_DUMMY_PAYLOAD_TOTAL_BYTES - len(payload_bytes))
            await send_frame(self.writer, {
                "type": "message",
                "to": target,
                "ciphertext": payload_bytes.hex(),
                "nonce": "bb" * 12,
            })

    async def close(self):
        if self.writer:
            self.writer.close()
            try:
                await self.writer.wait_closed()
            except Exception:
                pass


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
async def run_load_test(args):
    users = await setup_users(args.api_url, args.users)
    if len(users) < 2:
        print("[!] need at least 2 successfully-authenticated users to exchange messages -- aborting")
        return

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.load_verify_locations(args.cert)
    ssl_context.check_hostname = False

    clients = [SimulatedClient(u, args.host, args.port, ssl_context) for u in users]

    # ---- Phase 2: CONNECT ----
    print(f"[connect] opening {len(clients)} concurrent TLS connections to {args.host}:{args.port} ...")
    start = time.monotonic()
    results = await asyncio.gather(*[c.connect_and_auth() for c in clients])
    connect_elapsed = time.monotonic() - start
    connected = [c for c, ok in zip(clients, results) if ok]
    print(f"[connect] {len(connected)}/{len(clients)} connected + authenticated in "
          f"{connect_elapsed:.2f}s ({len(connected) / connect_elapsed:.0f} conn/s)")

    if len(connected) < 2:
        print("[!] fewer than 2 clients connected successfully -- aborting exchange phase")
        for c in clients:
            await c.close()
        return

    all_user_ids = [c.user_id for c in connected]

    # ---- Phase 3: EXCHANGE ----
    stop_event = asyncio.Event()
    listen_tasks = [asyncio.create_task(c.listen(stop_event)) for c in connected]

    total_messages_planned = len(connected) * args.messages_per_user
    print(f"[exchange] sending {args.messages_per_user} messages per client "
          f"({total_messages_planned} total) ...")

    start = time.monotonic()
    await asyncio.gather(*[c.send_messages(all_user_ids, args.messages_per_user) for c in connected])
    # Give in-flight messages time to actually arrive and be timed before
    # stopping the listeners -- without this, the last wave of sends would
    # be unfairly excluded from the latency/throughput numbers.
    await asyncio.sleep(args.drain_seconds)
    exchange_elapsed = time.monotonic() - start

    stop_event.set()
    await asyncio.gather(*listen_tasks, return_exceptions=True)

    for c in connected:
        await c.close()

    # ---- Phase 4: REPORT ----
    all_latencies = [lat for c in connected for lat in c.latencies_ms]
    total_received = sum(c.received_count for c in connected)

    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"Concurrent clients:     {len(connected)}")
    print(f"Connect time:           {connect_elapsed:.2f}s ({len(connected) / connect_elapsed:.0f} conn/s)")
    print(f"Messages sent:          {total_messages_planned}")
    print(f"Messages received:      {total_received} "
          f"({100 * total_received / total_messages_planned:.1f}% delivered within drain window)")
    print(f"Exchange wall time:     {exchange_elapsed:.2f}s")
    if exchange_elapsed > 0:
        print(f"Throughput:             {total_received / exchange_elapsed:.0f} msg/s")
    if all_latencies:
        sorted_lat = sorted(all_latencies)
        print(f"Latency (ms):           "
              f"p50={statistics.median(sorted_lat):.1f}  "
              f"p95={sorted_lat[int(len(sorted_lat) * 0.95)]:.1f}  "
              f"p99={sorted_lat[int(len(sorted_lat) * 0.99)]:.1f}  "
              f"max={sorted_lat[-1]:.1f}")
    else:
        print("Latency (ms):           no messages received -- check server logs")
    print("=" * 60)

    if args.csv:
        with open(args.csv, "w") as f:
            f.write("latency_ms\n")
            for lat in all_latencies:
                f.write(f"{lat}\n")
        print(f"\nRaw per-message latencies written to {args.csv}")


def main():
    parser = argparse.ArgumentParser(description="FastChat load test: real throughput and latency numbers.")
    parser.add_argument("--users", type=int, default=50, help="number of concurrent simulated clients")
    parser.add_argument("--messages-per-user", type=int, default=10, help="messages each client sends")
    parser.add_argument("--host", default=DEFAULT_SERVER_HOST, help="socket server host")
    parser.add_argument("--port", type=int, default=DEFAULT_SERVER_PORT, help="socket server port")
    parser.add_argument("--api-url", default=DEFAULT_API_BASE_URL, help="FastAPI base URL")
    parser.add_argument("--cert", default=DEFAULT_CERT_FILE, help="path to server.crt for TLS verification")
    parser.add_argument("--drain-seconds", type=float, default=3.0,
                         help="how long to wait after sending for in-flight messages to arrive")
    parser.add_argument("--csv", default=None, help="optional path to write raw per-message latencies")
    args = parser.parse_args()

    asyncio.run(run_load_test(args))


if __name__ == "__main__":
    main()
