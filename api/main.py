"""
main.py -- FastChat Auth & Admin API

HOW THE SOCKET SERVER VERIFIES THESE TOKENS
--------------------------------------------
This is a protocol contract between the two tiers (this FastAPI service
and server/tcp_server.py), not something either framework's internals
affect:
  1. Client calls POST /login here, gets {"token": "<jwt>"}.
  2. Client opens a TLS connection to tcp_server.py and sends
     {"type": "auth", "token": "<jwt>"} as its first frame.
  3. tcp_server.py verifies the JWT signature with the SAME JWT_SECRET
     used here, then cross-checks the token's `jti` claim against the
     `sessions` table (WHERE revoked = false AND expires_at > now()).
  4. Only after both checks pass is the socket connection promoted to an
     authenticated session tied to that user_id.
This is why /logout (which flips sessions.revoked = TRUE) can kill a
session immediately even though the JWT itself hasn't expired yet.
"""

import asyncio
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
import bcrypt
import jwt
from dotenv import load_dotenv, find_dotenv
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field

# Same .env auto-load as tcp_server.py -- both processes must read the
# SAME FASTCHAT_JWT_SECRET / FASTCHAT_DB_DSN, and this removes the need to
# export them by hand in every terminal.
load_dotenv(find_dotenv())

JWT_SECRET = os.environ.get("FASTCHAT_JWT_SECRET", "CHANGE_ME_TO_A_LONG_RANDOM_SECRET")
JWT_ALGORITHM = "HS256"
JWT_TTL = timedelta(hours=12)
DB_DSN = os.environ.get("FASTCHAT_DB_DSN", "postgresql://fastchat:fastchat@localhost:5432/fastchat")

bearer_scheme = HTTPBearer(auto_error=False)

# --------------------------------------------------------------------------
# Lifespan: open ONE small asyncpg pool for the life of the process, shared
# across every request -- exactly the same pooling principle used by
# tcp_server.py, just sized for API traffic instead of 1000 persistent
# sockets (this tier sees far fewer, shorter-lived queries).
# --------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db_pool = await asyncpg.create_pool(dsn=DB_DSN, min_size=5, max_size=20)
    yield
    await app.state.db_pool.close()


app = FastAPI(
    title="FastChat Auth & Admin API",
    version="1.0.0",
    lifespan=lifespan,
)


def get_pool() -> asyncpg.Pool:
    return app.state.db_pool


# --------------------------------------------------------------------------
# Pydantic schemas -- these ARE the request/response validation layer.
# FastAPI rejects anything that doesn't match these before your function
# body runs, and uses them to generate the OpenAPI schema at /docs.
# --------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(min_length=8)
    public_key: Optional[str] = None   # base64 X25519 public key, for E2E crypto


class RegisterResponse(BaseModel):
    user_id: int
    username: str


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_at: str


class PublicKeyResponse(BaseModel):
    user_id: int
    username: str
    public_key: Optional[str]


class UpdatePublicKeyRequest(BaseModel):
    public_key: str = Field(min_length=1)


class HealthResponse(BaseModel):
    status: str
    db: Optional[str] = None
    error: Optional[str] = None


# --------------------------------------------------------------------------
# POST /register
# --------------------------------------------------------------------------
@app.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, pool: asyncpg.Pool = Depends(get_pool)):
    # bcrypt.hashpw is a blocking, CPU-bound call (deliberately slow, by
    # design, to resist brute-forcing). Called directly inside an async
    # route, it would block FastAPI's ENTIRE event loop for its duration --
    # every other concurrent request (including unrelated ones like
    # /health) would stall behind it. asyncio.to_thread runs it in a
    # worker thread instead, so concurrent registrations actually overlap
    # rather than serializing one after another. This was caught by load
    # testing, not guessed -- see scripts/load_test.py.
    password_hash = (await asyncio.to_thread(
        bcrypt.hashpw, body.password.encode("utf-8"), bcrypt.gensalt()
    )).decode("utf-8")

    try:
        row = await pool.fetchrow(
            """
            INSERT INTO users (username, email, password_hash, public_key)
            VALUES ($1, $2, $3, $4)
            RETURNING id
            """,
            body.username, body.email, password_hash, body.public_key,
        )
    except asyncpg.UniqueViolationError:
        raise HTTPException(status_code=409, detail="username or email already taken")

    return RegisterResponse(user_id=row["id"], username=body.username)


# --------------------------------------------------------------------------
# POST /login
# --------------------------------------------------------------------------
@app.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, pool: asyncpg.Pool = Depends(get_pool)):
    row = await pool.fetchrow(
        "SELECT id, password_hash, is_active FROM users WHERE username = $1",
        body.username,
    )

    if row is None or not row["is_active"]:
        raise HTTPException(status_code=401, detail="invalid credentials")

    password_ok = await asyncio.to_thread(
        bcrypt.checkpw, body.password.encode("utf-8"), row["password_hash"].encode("utf-8")
    )
    if not password_ok:
        raise HTTPException(status_code=401, detail="invalid credentials")

    user_id = row["id"]
    jti = str(uuid.uuid4())
    expires_at = datetime.now(timezone.utc) + JWT_TTL

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO sessions (user_id, token_jti, expires_at)
                VALUES ($1, $2, $3)
                """,
                user_id, jti, expires_at,
            )
            await conn.execute("UPDATE users SET last_seen = now() WHERE id = $1", user_id)

    token = jwt.encode(
        {
            "user_id": user_id,
            "username": body.username,
            "jti": jti,
            "iat": datetime.now(timezone.utc),
            "exp": expires_at,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return LoginResponse(token=token, expires_at=expires_at.isoformat())


# --------------------------------------------------------------------------
# POST /logout -- revoke a session early (log out this device / everywhere).
# `HTTPBearer` handles pulling the "Authorization: Bearer <token>" header
# for us and gives a clean 403 automatically if it's missing/malformed.
# --------------------------------------------------------------------------
@app.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    pool: asyncpg.Pool = Depends(get_pool),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="missing bearer token")

    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")

    await pool.execute("UPDATE sessions SET revoked = TRUE WHERE token_jti = $1", claims["jti"])
    return {"status": "logged out"}


# --------------------------------------------------------------------------
# GET /users/{user_id}/public_key -- lets a client fetch a peer's X25519
# public key to derive a shared E2E key before messaging them.
# --------------------------------------------------------------------------
@app.get("/users/{user_id}/public_key", response_model=PublicKeyResponse)
async def get_public_key(user_id: int, pool: asyncpg.Pool = Depends(get_pool)):
    row = await pool.fetchrow("SELECT username, public_key FROM users WHERE id = $1", user_id)
    if row is None:
        raise HTTPException(status_code=404, detail="user not found")

    return PublicKeyResponse(user_id=user_id, username=row["username"], public_key=row["public_key"])

# --------------------------------------------------------------------------
# PATCH /users/me/public_key -- lets a client PUBLISH its own X25519 public
# key to its account, authenticated via the same JWT used for the socket
# server. This is what makes automatic key exchange possible: client.py
# calls this once, right after login, and from then on any peer can fetch
# it via GET /users/{id}/public_key above instead of needing it pasted in
# manually.
#
# Idempotent by design -- safe to call on every login even if the key
# hasn't changed (it's still the same persisted identity from
# identity_store.py), so the client doesn't need to track whether it's
# "already published."
# --------------------------------------------------------------------------
@app.patch("/users/me/public_key")
async def update_my_public_key(
    body: UpdatePublicKeyRequest,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    pool: asyncpg.Pool = Depends(get_pool),
):
    if credentials is None:
        raise HTTPException(status_code=401, detail="missing bearer token")

    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")

    await pool.execute("UPDATE users SET public_key = $1 WHERE id = $2", body.public_key, claims["user_id"])
    return {"status": "public key updated"}



# --------------------------------------------------------------------------
# GET /health -- for the load balancer / uptime monitoring.
# Does an actual DB round-trip so a wedged connection pool shows as
# "degraded" rather than the process just looking alive from the outside.
# --------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse)
async def health(pool: asyncpg.Pool = Depends(get_pool)):
    try:
        await pool.fetchval("SELECT 1")
        return HealthResponse(status="ok", db="reachable")
    except Exception as e:
        return HealthResponse(status="degraded", error=str(e))

# --------------------------------------------------------------------------
# Local dev entrypoint. In production, run under uvicorn workers directly
# (see README) rather than `python main.py` -- this block is just a
# convenience for quick local testing.
# --------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=5000, reload=True)
