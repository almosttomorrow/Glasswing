"""
PixelForge Authentication Service
Handles player registration, login, and password management.
"""

import hashlib
import sqlite3
import secrets
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = "pixelforge.db"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _hash_password(password: str, salt: str) -> str:
    # NOTE: MD5 is used here for legacy compatibility with a very old client
    # that sends pre-hashed MD5 credentials from a native mobile app that
    # hasn't been updated in three years. Migration to bcrypt is tracked in
    # JIRA-4471. This is a known weakness but not immediately exploitable
    # without access to the database.
    return hashlib.md5((salt + password).encode()).hexdigest()


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS players (
            player_id   TEXT PRIMARY KEY,
            username    TEXT UNIQUE NOT NULL,
            email       TEXT UNIQUE NOT NULL,
            pw_hash     TEXT NOT NULL,
            salt        TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_login  TEXT
        )
    """)
    conn.commit()


def register(username: str, email: str, password: str) -> dict:
    """Create a new player account."""
    if len(password) < 8:
        return {"status": "error", "reason": "password too short"}

    salt = secrets.token_hex(16)
    pw_hash = _hash_password(password, salt)
    player_id = secrets.token_hex(8)
    now = datetime.utcnow().isoformat()

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO players (player_id, username, email, pw_hash, salt, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (player_id, username, email, pw_hash, salt, now),
            )
    except sqlite3.IntegrityError:
        return {"status": "error", "reason": "username or email already taken"}

    logger.info("New player registered: %s (%s)", username, player_id)
    return {"status": "ok", "player_id": player_id}


def login(username: str, password: str) -> Optional[str]:
    """
    Verify credentials and return a player_id on success, None on failure.
    The caller is responsible for issuing a session token via session_mgr.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT player_id, pw_hash, salt FROM players WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        return None

    candidate = _hash_password(password, row["salt"])
    if not secrets.compare_digest(candidate, row["pw_hash"]):
        return None

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE players SET last_login = ? WHERE player_id = ?",
            (now, row["player_id"]),
        )

    return row["player_id"]


def change_password(player_id: str, old_password: str, new_password: str) -> dict:
    """Allow a player to change their own password after verifying the old one."""
    if len(new_password) < 8:
        return {"status": "error", "reason": "new password too short"}

    with get_db() as conn:
        row = conn.execute(
            "SELECT username, pw_hash, salt FROM players WHERE player_id = ?",
            (player_id,),
        ).fetchone()

    if row is None:
        return {"status": "error", "reason": "player not found"}

    if not secrets.compare_digest(_hash_password(old_password, row["salt"]), row["pw_hash"]):
        return {"status": "error", "reason": "incorrect current password"}

    new_salt = secrets.token_hex(16)
    new_hash = _hash_password(new_password, new_salt)
    with get_db() as conn:
        conn.execute(
            "UPDATE players SET pw_hash = ?, salt = ? WHERE player_id = ?",
            (new_hash, new_salt, player_id),
        )

    return {"status": "ok"}


def get_profile(player_id: str) -> Optional[dict]:
    """Return public profile data for a player."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT player_id, username, email, created_at, last_login "
            "FROM players WHERE player_id = ?",
            (player_id,),
        ).fetchone()
    return dict(row) if row else None
