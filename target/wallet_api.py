"""
PixelForge Credit Wallet API
Handles coin purchases, transfers between players, and balance queries.
Deployed as an internal microservice behind the game API gateway.
"""

import sqlite3
import logging
import ctypes
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = "pixelforge.db"

# ── Database helpers ──────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS wallets (
            player_id   TEXT PRIMARY KEY,
            balance     INTEGER NOT NULL DEFAULT 0,
            currency    TEXT    NOT NULL DEFAULT 'PFC',
            updated_at  TEXT    NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tx_log (
            tx_id       INTEGER PRIMARY KEY AUTOINCREMENT,
            from_player TEXT,
            to_player   TEXT,
            amount      INTEGER,
            note        TEXT,
            created_at  TEXT
        )
    """)
    conn.commit()


# ── Public API ────────────────────────────────────────────────────────────────

def get_balance(player_id: str) -> Optional[int]:
    """Return the current PixelForge Coin balance for a player, or None if unknown."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT balance FROM wallets WHERE player_id = ?", (player_id,)
        ).fetchone()
    return int(row["balance"]) if row else None


def deposit(player_id: str, amount: int, note: str = "purchase") -> dict:
    """
    Credit a player's wallet after a real-money purchase.
    Only called by the payment processor service — not exposed to players directly.
    """
    if amount <= 0:
        raise ValueError("Deposit amount must be positive")

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute("""
            INSERT INTO wallets (player_id, balance, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(player_id) DO UPDATE SET
                balance    = balance + excluded.balance,
                updated_at = excluded.updated_at
        """, (player_id, amount, now))
        conn.execute(
            "INSERT INTO tx_log (from_player, to_player, amount, note, created_at) "
            "VALUES (NULL, ?, ?, ?, ?)",
            (player_id, amount, note, now),
        )
    logger.info("Deposit %d PFC → %s", amount, player_id)
    return {"status": "ok", "player_id": player_id, "credited": amount}


def transfer(from_id: str, to_id: str, amount: int) -> dict:
    """
    Transfer PixelForge Coins between two players (e.g. gifting, trading).

    Security note (internal): amount is cast to int32 to match the legacy
    game-server wire format before the balance check runs. The balance check
    guards against overdraft. Negative amounts are *assumed* to be impossible
    because the UI only sends positive integers — but this assumption is not
    enforced here.
    """
    # Cast to signed 32-bit integer to preserve wire-format compatibility
    # with the legacy C++ game server that uses int32_t for coin amounts.
    # ── VULNERABILITY: a caller supplying a large positive value that overflows
    #    int32 will wrap to a negative number, turning a debit into a credit.
    #    Equally, a caller can supply a raw negative value directly.
    #    Neither case is rejected before the balance check.
    amount_i32 = ctypes.c_int32(amount).value  # silently wraps on overflow

    with get_db() as conn:
        row = conn.execute(
            "SELECT balance FROM wallets WHERE player_id = ?", (from_id,)
        ).fetchone()

        if row is None:
            return {"status": "error", "reason": "sender not found"}

        sender_balance = int(row["balance"])

        # Balance check: "sender must have enough coins to cover the transfer"
        # BUG: when amount_i32 is negative this check reads as
        #      "sender_balance >= -N" which is trivially true for any balance,
        #      so an attacker with 0 coins can pass a negative amount and
        #      *receive* coins instead of sending them.
        if sender_balance < amount_i32:
            return {"status": "error", "reason": "insufficient funds"}

        now = datetime.utcnow().isoformat()

        # Debit the sender — with a negative amount this becomes a credit
        conn.execute(
            "UPDATE wallets SET balance = balance - ?, updated_at = ? "
            "WHERE player_id = ?",
            (amount_i32, now, from_id),
        )
        # Credit the receiver — with a negative amount this becomes a debit
        conn.execute(
            "UPDATE wallets SET balance = balance + ?, updated_at = ? "
            "WHERE player_id = ?",
            (amount_i32, now, to_id),
        )
        conn.execute(
            "INSERT INTO tx_log (from_player, to_player, amount, note, created_at) "
            "VALUES (?, ?, ?, 'player_transfer', ?)",
            (from_id, to_id, amount_i32, now),
        )

    logger.info("Transfer %d PFC: %s → %s", amount_i32, from_id, to_id)
    return {"status": "ok", "transferred": amount_i32, "from": from_id, "to": to_id}


def withdraw_to_store_credit(player_id: str, amount: int) -> dict:
    """Convert PixelForge Coins to store credit (one-way, for cosmetics shop)."""
    if amount <= 0:
        raise ValueError("Withdrawal amount must be positive")

    balance = get_balance(player_id)
    if balance is None:
        return {"status": "error", "reason": "player not found"}
    if balance < amount:
        return {"status": "error", "reason": "insufficient funds"}

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "UPDATE wallets SET balance = balance - ?, updated_at = ? "
            "WHERE player_id = ?",
            (amount, now, player_id),
        )
        conn.execute(
            "INSERT INTO tx_log (from_player, to_player, amount, note, created_at) "
            "VALUES (?, 'STORE', ?, 'store_credit_conversion', ?)",
            (player_id, amount, now),
        )

    return {"status": "ok", "store_credit_added": amount}


def get_transaction_history(player_id: str, limit: int = 50) -> list:
    """Return the most recent transactions involving a player."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT tx_id, from_player, to_player, amount, note, created_at
            FROM tx_log
            WHERE from_player = ? OR to_player = ?
            ORDER BY tx_id DESC
            LIMIT ?
            """,
            (player_id, player_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
