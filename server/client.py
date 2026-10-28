"""
client.py
=========
Connects over TLS to tcp_server.py, authenticates with a JWT (obtained from
the FastAPI auth API's /login endpoint beforehand), then runs two concurrent
coroutines for the lifetime of the session:

  - `listen_loop`  : continuously reads incoming frames from the server
                     and prints them, so messages can arrive at any time.
  - `input_loop`   : reads the user's typed input and sends it, without
                     blocking the listen loop.

Both run under the same asyncio event loop via `asyncio.gather`, which is
how a single-threaded client can "listen and type at the same time" --
stdin reads are handed to a thread executor (`loop.run_in_executor`) so the
blocking `input()` call doesn't stall message delivery.

PERSISTENT IDENTITY (see identity_store.py): your E2E keypair is generated
ONCE per username and reused across every future run, and every shared key
you derive with a peer is saved to disk too.

AUTOMATIC KEY EXCHANGE: on login, this client PUBLISHES its own
public key to the API (`PATCH /users/me/public_key`), and when you message
someone for the first time, it AUTO-FETCHES their public key
(`GET /users/{id}/public_key`) instead of requiring you to paste it in
manually. This means:
  - Sending a message is just `<recipient_user_id> <message text>` --
    no public key needed in the command at all, first time or otherwise.
  - `/addkey <user_id> <public_key_b64>` still exists as a manual fallback
    for when the API is unreachable, or the peer hasn't logged in with
    this client yet (so has never published a key) and you already have
    their key through some other channel.
"""

import asyncio
import ssl
import json
import struct
import sys
import urllib.request
import urllib.error

from e2e_crypto import derive_shared_key, encrypt_message, decrypt_message, b64, unb64
from identity_store import load_or_create_identity, load_peer_keys, save_peer_key

SERVER_HOST = "localhost"
SERVER_PORT = 8443
CA_CERT_FILE = "certs/server.crt"   # for a self-signed cert; use system CA bundle in production
MAX_FRAME_BYTES = 64 * 1024


# Base URL of the FastAPI auth service -- used only for the automatic
# public-key publish/fetch calls below. Uses plain stdlib `urllib` (no new
# dependency) run through `loop.run_in_executor` so these brief blocking
# HTTP calls never stall the event loop.
API_BASE_URL = "http://localhost:5000"


def _http_publish_public_key_sync(jwt_token: str, public_key_b64: str) -> bool:
    """Runs in a worker thread. Returns True on success, False on any failure."""
    req = urllib.request.Request(
        f"{API_BASE_URL}/users/me/public_key",
        data=json.dumps({"public_key": public_key_b64}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {jwt_token}"},
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, timeout=5):
            return True
    except (urllib.error.URLError, urllib.error.HTTPError):
        return False


def _http_fetch_public_key_sync(user_id: int) -> str | None:
    """Runs in a worker thread. Returns the peer's base64 public key, or None if unavailable."""
    try:
        with urllib.request.urlopen(f"{API_BASE_URL}/users/{user_id}/public_key", timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("public_key")
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError):
        return None


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
        raise ValueError("server sent an oversized frame -- aborting for safety")
    try:
        data = await reader.readexactly(length)
    except asyncio.IncompleteReadError:
        return None
    return json.loads(data.decode("utf-8"))


async def listen_loop(reader: asyncio.StreamReader, peer_keys: dict):
    """Runs forever, printing whatever the server sends us."""
    while True:
        try:
            frame = await read_frame(reader)
        except ValueError as e:
            print(f"\n[!] {e}")
            break

        if frame is None:
            print("\n[!] Server closed the connection.")
            break

        msg_type = frame.get("type")
        if msg_type == "message":
            sender_id = frame["from"]
            shared_key = peer_keys.get(sender_id)
            if shared_key and frame.get("nonce"):
                try:
                    plaintext = decrypt_message(
                        shared_key,
                        bytes.fromhex(frame["ciphertext"]),
                        bytes.fromhex(frame["nonce"]),
                    )
                    print(f"\n[user {sender_id}] {plaintext}\n> ", end="", flush=True)
                except Exception:
                    print(f"\n[user {sender_id}] <unable to decrypt: key mismatch>\n> ", end="", flush=True)
            else:
                print(f"\n[user {sender_id}] <encrypted message, no shared key yet -- "
                      f"reply to them and it'll auto-fetch their key, or run "
                      f"/addkey {sender_id} <their_public_key_b64>>\n> ", end="", flush=True)
        elif msg_type == "error":
            print(f"\n[server error] {frame.get('message')}\n> ", end="", flush=True)
        elif msg_type == "pong":
            pass  # heartbeat ack, nothing to show
        else:
            print(f"\n[server] {frame}\n> ", end="", flush=True)


async def input_loop(writer: asyncio.StreamWriter, my_private_key: bytes, peer_keys: dict, username: str):
    """
    Reads stdin in a background thread (so it never blocks the event loop,
    and therefore never blocks incoming-message delivery) and sends chat
    frames.

    Commands:
        /addkey <user_id> <their_public_key_b64>
            MANUAL fallback: derive, cache, and persist a shared key
            without going through the API. Useful if the API is down, or
            the peer has never published a key (hasn't logged in via this
            client yet) but you have their key some other way.

        /quit
            Disconnect.

        <recipient_user_id> <message text>
            Send an encrypted message. If no shared key is cached yet for
            this recipient, their public key is fetched AUTOMATICALLY from
            the API, the shared key is derived, cached, and persisted --
            no manual key-passing needed.
    """
    loop = asyncio.get_running_loop()
    while True:
        line = await loop.run_in_executor(None, input, "> ")
        if not line.strip():
            continue
        if line.strip() == "/quit":
            writer.close()
            await writer.wait_closed()
            sys.exit(0)

        if line.strip().startswith("/addkey"):
            parts = line.strip().split(" ")
            if len(parts) != 3:
                print("usage: /addkey <user_id> <their_public_key_b64>")
                continue
            try:
                peer_id = int(parts[1])
                shared_key = derive_shared_key(my_private_key, unb64(parts[2]))
                peer_keys[peer_id] = shared_key
                save_peer_key(username, peer_id, shared_key)
                print(f"[+] Shared key established and saved for user {peer_id}.")
            except Exception as e:
                print(f"[!] Failed to derive key: {e}")
            continue

        try:
            recipient_id_str, text = line.split(" ", 1)
            recipient_id = int(recipient_id_str)
        except ValueError:
            print("usage: <recipient_user_id> <message>   (or /addkey <user_id> <public_key_b64>)")
            continue

        shared_key = peer_keys.get(recipient_id)
        if shared_key is None:
            # First message to this peer in this key-store: fetch their
            # public key from the API automatically instead of requiring
            # it typed in every time.
            peer_pub_b64 = await loop.run_in_executor(None, _http_fetch_public_key_sync, recipient_id)
            if peer_pub_b64 is None:
                print(f"[!] Couldn't fetch a public key for user {recipient_id} from the API "
                      f"(they may not have logged in yet, or the API is unreachable).")
                print(f"    If you already have their key another way, run: "
                      f"/addkey {recipient_id} <their_public_key_b64>")
                continue
            shared_key = derive_shared_key(my_private_key, unb64(peer_pub_b64))
            peer_keys[recipient_id] = shared_key
            save_peer_key(username, recipient_id, shared_key)
            print(f"[+] Auto-fetched user {recipient_id}'s public key and established a shared key.")

        ciphertext, nonce = encrypt_message(shared_key, text)
        await send_frame(writer, {
            "type": "message",
            "to": recipient_id,
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
        })


async def main():
    jwt_token = input("Paste your JWT (from /login): ").strip()

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # In production with a CA-signed cert, drop these two lines and just use
    # the system default verification. They're here because a local
    # self-signed dev cert won't validate against a public CA.
    ssl_context.load_verify_locations(CA_CERT_FILE)
    ssl_context.check_hostname = False

    reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT, ssl=ssl_context)
    print("[+] TLS connection established.")

    await send_frame(writer, {"type": "auth", "token": jwt_token})
    auth_response = await read_frame(reader)
    if auth_response is None or auth_response.get("type") != "auth_ok":
        print(f"[!] Authentication failed: {auth_response}")
        return

    username = auth_response["username"]
    print(f"[+] Authenticated as {username} (id={auth_response['user_id']})")

    # Load (or create, on first-ever run for this username) a PERSISTENT
    # identity keypair, and load any peer shared keys already established
    # in previous sessions -- both happen synchronously here, BEFORE
    # listen_loop starts consuming frames, so any offline messages the
    # server flushes to us immediately after auth can already decrypt
    # correctly using keys from prior sessions.
    my_private_key, my_public_key, is_new_identity = load_or_create_identity(username)
    peer_keys: dict[int, bytes] = load_peer_keys(username)

    # Publish our public key to the API so PEERS can auto-fetch it. This is
    # idempotent -- safe to call every login even if unchanged.
    loop = asyncio.get_running_loop()
    published = await loop.run_in_executor(None, _http_publish_public_key_sync, jwt_token, b64(my_public_key))

    print(f"[i] Your public key: {b64(my_public_key)}")
    if published:
        print("[i] Published to the API -- others can now message you without needing this pasted in.")
    else:
        print("[i] Could NOT publish to the API (unreachable?) -- peers will need /addkey with this "
              "key manually until it's published.")
    if is_new_identity:
        print("[i] New identity created for this username -- it will be reused on every future run.")
    else:
        print(f"[i] Loaded existing identity + {len(peer_keys)} saved peer key(s) from previous sessions.")
    print("[i] To message someone: just type   <their_user_id> <message>   -- their key is fetched automatically.")

    try:
        await asyncio.gather(
            listen_loop(reader, peer_keys),
            input_loop(writer, my_private_key, peer_keys, username),
        )
    except (ConnectionResetError, asyncio.CancelledError):
        print("\n[!] Disconnected from server.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[+] Client exiting.")
