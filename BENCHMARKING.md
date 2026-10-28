# Benchmarking FastChat

"It's built on asyncio" is an architecture choice, not a performance
measurement. This document is about actually measuring throughput and
latency with `scripts/load_test.py`, instead of asserting them.

## What the tool measures

`scripts/load_test.py`:
1. Registers and logs in N test users via the real API.
2. Opens N concurrent TLS connections to the real socket server and
   authenticates each one (measured separately from message throughput --
   connection setup and message relay stress different parts of the
   system).
3. Has every connected client send a configurable number of messages to
   random other connected clients, with each message carrying a
   monotonic send timestamp embedded in its payload bytes (the server
   rebuilds the outgoing frame from scratch and doesn't echo back
   arbitrary client fields, so the timestamp has to ride inside the
   ciphertext payload itself to survive the round trip).
4. Reports real numbers: connections/sec, messages/sec, and a full
   latency **distribution** (p50/p95/p99/max) -- not just an average,
   since an average hides the tail latency that actually determines
   whether a chat system feels real-time.

It intentionally sends dummy fixed-size payloads rather than doing real
per-message X25519/AES-GCM, so it isolates the server's connection
handling, auth, message framing, and DB persistence path -- the actual
bottleneck candidates in `tcp_server.py` -- from client-side crypto cost,
which is a separate, easily-estimated constant per message.

## Running it

```bash
pip install aiohttp   # only needed for this script
python3.12 deployment/gen_dev_certs.py   # if you haven't already
# start api/main.py and server/tcp_server.py, then:
python3.12 scripts/load_test.py --users 100 --messages-per-user 20
```

Useful flags:
```
--users N               concurrent simulated clients
--messages-per-user N   messages each client sends
--host / --port         socket server address (point at an Nginx LB for multi-instance runs)
--api-url               FastAPI base URL
--drain-seconds N        how long to wait for in-flight messages after sending stops
--csv path.csv          write raw per-message latencies for your own analysis/plotting
```

Start small (20-50 users) to confirm everything's wired up correctly
before scaling toward your real target (e.g. 500-1000).

## A real bug this caught, on the first real run

Running this against the actual stack immediately surfaced a genuine
problem, not a hypothetical one: **`bcrypt.hashpw()` and
`bcrypt.checkpw()` were being called directly inside async FastAPI route
handlers.** bcrypt is deliberately slow (that's the whole point --
brute-force resistance), which means calling it directly blocks
FastAPI's *entire* event loop for its full duration. Measured directly:

```
unrelated request got to START running after 275ms   (bcrypt called directly)
unrelated request got to START running after 2ms     (via asyncio.to_thread)
```

While one user's password was being hashed, every *other* concurrent
request -- another user's login, a `/health` check, anything -- was
stalled behind it. At real concurrency (hundreds of simultaneous
logins), this would have serialized auth throughput badly and been
nearly invisible in casual testing with 1-2 users.

The fix (already applied in `api/main.py`): wrap both calls in
`asyncio.to_thread(...)`, moving the blocking work off the event loop
onto a worker thread. This is exactly the kind of bug that "it's built
on asyncio" claims paper over, and exactly why load testing against the
real stack -- not just reading the code -- matters.

## A second real bug: DB pool exhaustion at real concurrency

Jumping straight to `--users 500 --messages-per-user 100` (50,000
messages) on a first real run produced average latency over 110
**seconds** and max latency over 17 **minutes**. That is not "slow" --
it's queue collapse: messages arriving far faster than they can be
processed, so a backlog builds and later messages wait behind an
ever-growing queue. The max being roughly 10x the average is the
signature of exactly that (uniform slowness would keep average and max
much closer together).

Two compounding root causes, found by reading the actual code path
those 50,000 messages went through:

1. **`asyncpg.create_pool(..., max_size=30)` was hardcoded** in
   `tcp_server.py`, never load-tested. With 500 concurrent clients all
   persisting messages at once, only 30 database inserts can ever be in
   flight simultaneously -- everyone else queues for a free connection.
2. **A single connection's messages are processed strictly one at a
   time.** `handle_client`'s main loop fully `await`s
   `handle_chat_message()` -- including the database write -- before
   reading that same connection's *next* frame. There's no pipelining
   within a connection, so slow writes serialize each sender's own
   message stream on top of the pool contention above.

The fix: `DB_POOL_MIN_SIZE`/`DB_POOL_MAX_SIZE` are now configurable via
`FASTCHAT_DB_POOL_MIN_SIZE`/`FASTCHAT_DB_POOL_MAX_SIZE` (raised default:
10/50, up from a hardcoded 10/30), and Postgres's own `max_connections`
is raised to 200 in `docker-compose.yml` (the default 100 would have
been exceeded anyway once two socket-server instances at 50 each plus
the API's pool of 20 are all accounted for -- that combination would
have produced a *different* failure, "too many connections," once the
first bottleneck was fixed).

**There is no universally "correct" pool size** -- it depends on your
actual Postgres instance's cores, memory, and disk I/O. Tune it and
re-measure; don't just copy a bigger number and assume it's fixed.

## Recommended methodology: ramp up, don't jump to your target

Jumping straight to a target scale (say 500 users) with no smaller runs
first tells you the system falls over somewhere at or below that number
-- but not *where*, which is the more useful thing to know when you're
trying to fix it. Ramp up instead:

```bash
python3.12 scripts/load_test.py --users 25  --messages-per-user 20
python3.12 scripts/load_test.py --users 50  --messages-per-user 20
python3.12 scripts/load_test.py --users 100 --messages-per-user 20
python3.12 scripts/load_test.py --users 250 --messages-per-user 20
python3.12 scripts/load_test.py --users 500 --messages-per-user 20
```

Watch p50/p95/p99 at each step. Healthy scaling looks like latency
staying roughly flat (or growing slowly) as user count rises. A cliff --
latency suddenly jumping 10-50x between two steps -- tells you almost
exactly where a resource limit (pool size, `max_connections`, CPU cap in
`docker-compose.bench.yml`, disk I/O) got saturated, which is far faster
to diagnose than staring at one blown-up number from a single run at
full scale.

## A third real bug: stale backlog inflating latency across runs

Running the ramp-up methodology above (25 → 50 → 100 → 500 users)
produced a suspicious symptom in the raw output:

```
Messages received: 620 (124.0% delivered within drain window)
```

**Receiving more messages than were sent is not possible for a clean
run.** The cause: `load_test.py` originally generated deterministic
usernames (`loadtest_user_00000`, `loadtest_user_00001`, ...) -- the
*same* usernames on every invocation. Combined with
`deliver_pending_messages()` in `tcp_server.py` (which flushes *any*
undelivered message to a user the instant they reconnect, regardless of
how long ago it was originally sent), this meant:

1. An early, smaller run (say 25 users) gets overwhelmed within its
   drain window and leaves some messages undelivered in Postgres.
2. A later run (say 50 users) reconnects using the *same first 25
   usernames* and immediately receives that leftover backlog --
   messages still carrying their **original** send timestamp from the
   earlier run.
3. `(now) - (an earlier run's timestamp)` computes as a "latency" of
   however long ago that run happened -- sometimes minutes -- which is
   not real message latency at all, just wall-clock time between two
   unrelated test invocations.
4. It compounds: an overloaded run leaves more backlog than it clears,
   so each subsequent run inherits a larger contaminated pool than the
   last. By the time a 500-user run comes around, it can be flushing
   backlog accumulated from every smaller run that preceded it.

This is *why* the ramp-up run showed p95/p99/max climbing into the
hundreds of thousands of milliseconds, and why the 500-user run's p50
came out around 400 seconds -- those numbers were measuring stale
backlog contamination, not real current-run latency.

**The fix** (already applied): each invocation now generates a unique
`run_id` (millisecond timestamp + random suffix) and uses it in every
username for that run (`loadtest_{run_id}_user_{index}`). Since
`deliver_pending_messages()` looks up backlog by `receiver_id`, and
different runs now always produce different user IDs, there is no
possible way for one run's leftovers to reach another run's users --
this is a structural guarantee, not just an empirical fix. Verified
directly: a clean run with the fix in place produced 100.0% delivery
(not >100%) and realistic double-digit millisecond latency, with zero
undelivered rows left in the `messages` table afterward.

**Practical consequence: any ramp-up results gathered before this fix
are not trustworthy and should be re-run.** The earlier `--users 500`
numbers referenced elsewhere in this document predate the fix and
reflect this exact contamination, not real system behavior at 500
concurrent users.

One remaining housekeeping note, not a correctness issue: since every
run now creates brand-new users, the `users` table grows indefinitely
across repeated test runs. Periodically truncate between benchmarking
sessions if you're running this a lot:
```bash
psql -h localhost -U fastchat -d fastchat -c \
  "TRUNCATE messages, sessions, users RESTART IDENTITY CASCADE;"
```

## Honest results from this sandbox (not a production claim)

The sandbox this project was developed in has **a single CPU core**,
which matters for interpreting these numbers -- `asyncio.to_thread`
prevents *blocking other requests* (proven above) regardless of core
count, but it can't provide *parallel speedup* for CPU-bound work like
bcrypt hashing without multiple cores to actually run threads on
simultaneously. A real multi-core server would see faster wall-clock
setup times too, not just non-blocking behavior.

Two real runs, small-scale (chosen to fit sandbox constraints, not as a
target number):

```
15 concurrent clients, 75 messages exchanged
connect:    0.24s (63 conn/s)
throughput: 37 msg/s
latency:    p50=57ms  p95=90ms  p99=92ms  max=92ms
```

```
20 concurrent clients, 200 messages exchanged
connect:    0.48s (42 conn/s)
throughput: 99 msg/s
latency:    p50=136ms  p95=230ms  p99=235ms  max=235ms
```

**Do not cite these specific numbers as FastChat's real capacity.** They
reflect a single shared CPU core in a sandbox, not target hardware. What
*is* worth taking from these runs:
- 100% message delivery in both runs -- no dropped messages under this load.
- Latency is dominated by the database write: every message does a
  synchronous `INSERT ... RETURNING id, sent_at` **before** attempting
  delivery (durability-first, by design -- see `handle_chat_message` in
  `tcp_server.py`). On real hardware with a properly-provisioned Postgres
  instance, this write should be single-digit milliseconds, not the
  50-100ms+ seen here on constrained shared hardware.
- The tool itself works end to end and produces a real, reproducible
  measurement methodology -- that's what to actually take away and rerun
  on real hardware.

## Getting a real 500-user number

Run this on your actual target hardware (a real machine or a cloud
instance with multiple cores), against Postgres running locally or on
the same network segment (not this sandbox):

```bash
python3.12 scripts/load_test.py --users 500 --messages-per-user 100 --csv results_500.csv
```

Then report the real output: connect rate, messages/sec, and the full
p50/p95/p99/max latency line the script prints -- that's a claim you can
actually defend, because you'll have the methodology and raw CSV to back
it up if asked.

## Running on a shared local machine (WSL2, no Docker Desktop)

A real second machine (or two cloud instances) is the cleanest setup,
since the server and the load generator never compete for the same CPU
at all. If that's not available, a multi-core laptop -- Docker installed
natively inside WSL2, not Docker Desktop -- is a reasonable substitute,
with one caveat: **both the server and the load generator are on the
same physical cores**, so without any isolation, a busy server will
starve the load generator (and vice versa), skewing results in ways that
don't reflect a real distributed deployment.

`docker-compose.bench.yml` addresses this by capping how many CPU cores
Docker's containers can use in total, deliberately leaving some cores
free for the load-test process running natively alongside them. It's an
additive override, not a replacement -- normal development still uses
the plain `docker-compose.yml` unconstrained.

```bash
# In your WSL2 Ubuntu terminal (Docker installed there directly, no
# Docker Desktop needed):
cd fastchat
docker compose -f docker-compose.yml -f docker-compose.bench.yml up --build -d
docker compose ps   # confirm all services are healthy

# Everything runs inside the same WSL2 filesystem -- no need to copy
# certs across a Windows/WSL boundary, unlike the Docker Desktop path.
python3.12 -m venv venv
source venv/bin/activate
pip install aiohttp

python3.12 scripts/load_test.py \
  --users 500 --messages-per-user 100 \
  --host localhost --port 8443 \
  --api-url http://localhost:5000 \
  --cert server/certs/server.crt \
  --csv results_500.csv
```

Adjust the `cpus:` values in `docker-compose.bench.yml` to your own core
count -- the defaults assume roughly 12 cores and leave about 4 free.
Rule of thumb: total the `deploy.resources.limits.cpus` values across
services to (your core count minus 3-4), so the load generator and the
OS itself aren't starved.

While it's running, watch `docker stats` in a second WSL2 terminal --
per-container CPU/memory -- and Task Manager on the Windows side as a
sanity check that the whole machine isn't pinned. If one container is
maxed out while its `cpus:` limit clearly hasn't been hit, that's a
different bottleneck (likely I/O, not CPU) worth investigating on its
own.

**This is still not equivalent to two separate machines.** The
containers are CPU-limited via cgroups, but they're still physically
sharing cache, memory bandwidth, and the same cores under the hood in a
way two real separate boxes wouldn't be. Treat numbers from this setup
as directionally useful (does a fix help, where's the bottleneck, does
throughput scale with more users) rather than a hard capacity number
you'd cite externally -- for that, the two-cloud-instance approach
earlier in this document is still the more defensible version.
