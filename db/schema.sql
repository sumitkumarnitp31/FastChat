-- ============================================================================
-- FastChat Database Schema
-- Design goals: fast auth lookups, cheap session validation on every socket
-- connect, and high-throughput message writes/reads without full table scans.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto; -- for gen_random_uuid()

-- ----------------------------------------------------------------------------
-- USERS
-- ----------------------------------------------------------------------------
CREATE TABLE users (
    id              BIGSERIAL PRIMARY KEY,
    username        VARCHAR(64)  NOT NULL UNIQUE,
    email           VARCHAR(255) NOT NULL UNIQUE,
    password_hash   VARCHAR(255) NOT NULL,        -- bcrypt hash, never plaintext
    public_key      TEXT,                          -- client's X25519 public key (base64) for E2E crypto
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ
);

-- Login is by username; keep it as a unique btree (already implied by UNIQUE,
-- but declared explicitly so intent is documented).
CREATE UNIQUE INDEX idx_users_username ON users (username);
CREATE UNIQUE INDEX idx_users_email    ON users (email);

-- ----------------------------------------------------------------------------
-- SESSIONS  (one row per issued JWT / login)
-- The socket server hits this table on every new TCP connection to confirm
-- the token hasn't been revoked/expired server-side (JWTs are otherwise
-- stateless, so this is what lets us force-logout / kill a session early).
-- ----------------------------------------------------------------------------
CREATE TABLE sessions (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_jti       UUID   NOT NULL DEFAULT gen_random_uuid() UNIQUE, -- JWT "jti" claim
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN NOT NULL DEFAULT FALSE,
    ip_address      INET,
    user_agent      TEXT
);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);
-- This is the hot-path lookup: "SELECT ... WHERE token_jti = $1 AND revoked = false"
CREATE UNIQUE INDEX idx_sessions_jti_active ON sessions (token_jti) WHERE revoked = FALSE;
-- Partial index to make the periodic expiry-cleanup job cheap.
CREATE INDEX idx_sessions_expiry ON sessions (expires_at) WHERE revoked = FALSE;

-- ----------------------------------------------------------------------------
-- MESSAGES
-- Content is stored as BYTEA because, depending on the crypto mode chosen
-- (see server/e2e_crypto.py), it may be AES-GCM ciphertext the server itself
-- cannot decrypt. Never store plaintext message bodies here.
-- ----------------------------------------------------------------------------
CREATE TABLE messages (
    id              BIGSERIAL PRIMARY KEY,
    sender_id       BIGINT REFERENCES users(id),
    receiver_id     BIGINT REFERENCES users(id),   -- NULL for room/broadcast messages
    room_id         VARCHAR(64),                    -- NULL for direct messages
    ciphertext      BYTEA NOT NULL,
    nonce           BYTEA,                           -- AES-GCM nonce, if E2E crypto mode is on
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered       BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (receiver_id IS NOT NULL OR room_id IS NOT NULL)
);

-- Message history for a 1:1 conversation, newest first.
CREATE INDEX idx_messages_receiver_sent ON messages (receiver_id, sent_at DESC);
-- Room/broadcast history, newest first.
CREATE INDEX idx_messages_room_sent ON messages (room_id, sent_at DESC) WHERE room_id IS NOT NULL;
-- Offline-delivery queue: "give me everything still undelivered for this user".
CREATE INDEX idx_messages_undelivered ON messages (receiver_id) WHERE delivered = FALSE;

-- ----------------------------------------------------------------------------
-- SCALING NOTE (read before going to production):
-- At real high volume, partition `messages` by month (PARTITION BY RANGE on
-- sent_at) so old partitions can be dropped/archived cheaply and the hot
-- partition stays small enough to keep entirely in shared_buffers. Example:
--
--   CREATE TABLE messages (...) PARTITION BY RANGE (sent_at);
--   CREATE TABLE messages_2026_07 PARTITION OF messages
--       FOR VALUES FROM ('2026-07-01') TO ('2026-08-01');
--
-- Also consider connection pooling at the DB tier (PgBouncer in transaction
-- mode) since 1000 concurrent app-level clients should NOT map to 1000 raw
-- Postgres backends -- Postgres backends are expensive (~10MB+ RAM each,
-- context-switch overhead). Route through PgBouncer or asyncpg's own pool
-- (small pool, e.g. 20-50 connections, shared across all client sessions).
-- ----------------------------------------------------------------------------
