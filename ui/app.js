/**
 * Project Glasswing Demo — Browser Orchestrator
 *
 * Runs the three-wave vulnerability hunting pipeline entirely in the browser.
 * Calls the Anthropic API directly using the official JS SDK (loaded from CDN).
 * The user's API key is kept in sessionStorage only — never sent to any server.
 *
 * Wave 1 — Triage:   Score every file 1-5 for vulnerability likelihood.
 * Wave 2 — Hunt:     Deep-scan files scoring ≥ 4 with dedicated agents (sequential in browser).
 * Wave 3 — Validate: Senior reviewer confirms which findings are real and critical.
 */

// ── SDK (no build step — loaded via CDN ES module) ────────────────────────
import Anthropic from 'https://esm.sh/@anthropic-ai/sdk@0.52.0';

// ── Configuration ─────────────────────────────────────────────────────────
const MODEL          = 'claude-opus-4-5';
const HUNT_THRESHOLD = 4;   // files scoring this or above go to Wave 2
const PREVIEW_CHARS  = 200; // characters sent per file in Wave 1 triage

// ── Target files (full source, identical to target/ directory) ────────────
// Embedded so the demo works as a pure static site with no backend.
const TARGET_METADATA = {
  'wallet_api.py':   { tag: 'target', label: '★ Contains planted vulnerability' },
  'auth_service.py': { tag: 'minor',  label: 'Weak hashing (MD5)' },
  'session_mgr.py':  { tag: 'minor',  label: 'Weak entropy (random)' },
  'inventory_db.py': { tag: 'clean',  label: 'Clean' },
  'store_api.py':    { tag: 'clean',  label: 'Clean' },
};

// Embedded target files — identical to target/ directory in this repo
const TARGET_FILES = {
  "wallet_api.py": `"""
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
`,
  "auth_service.py": `"""
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
`,
  "session_mgr.py": `"""
PixelForge Session Manager
Issues and validates session tokens for authenticated players.
Tokens are stored in an in-process dict (suitable for single-instance deployment).
For multi-instance deployments, swap _sessions for a Redis-backed store.
"""

import random
import string
import logging
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# In-memory session store: token → {player_id, expires_at}
_sessions: dict = {}

# Session lifetime in minutes
SESSION_LIFETIME_MINUTES = 60


def _generate_token(length: int = 32) -> str:
    # NOTE: random.randint / random.choice is NOT cryptographically secure.
    # This was written before the secrets module was available (Python 3.5 era)
    # and never updated. An attacker who can observe a few tokens could predict
    # future ones if they know the RNG seed. Should be replaced with
    # secrets.token_urlsafe(). Tracked in JIRA-3892.
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def create_session(player_id: str) -> str:
    """Issue a new session token for a player. Returns the token string."""
    token = _generate_token()
    expires_at = datetime.utcnow() + timedelta(minutes=SESSION_LIFETIME_MINUTES)
    _sessions[token] = {"player_id": player_id, "expires_at": expires_at}
    logger.debug("Session created for %s, expires %s", player_id, expires_at.isoformat())
    return token


def validate_session(token: str) -> Optional[str]:
    """
    Check whether a token is valid and not expired.
    Returns the associated player_id, or None if invalid/expired.
    """
    entry = _sessions.get(token)
    if entry is None:
        return None
    if datetime.utcnow() > entry["expires_at"]:
        del _sessions[token]
        logger.debug("Expired session evicted: %s", token[:8] + "…")
        return None
    return entry["player_id"]


def refresh_session(token: str) -> Optional[str]:
    """Extend a valid session by another SESSION_LIFETIME_MINUTES. Returns new expiry ISO string."""
    player_id = validate_session(token)
    if player_id is None:
        return None
    new_expiry = datetime.utcnow() + timedelta(minutes=SESSION_LIFETIME_MINUTES)
    _sessions[token]["expires_at"] = new_expiry
    return new_expiry.isoformat()


def invalidate_session(token: str) -> bool:
    """Destroy a session (logout). Returns True if a session was removed."""
    existed = token in _sessions
    _sessions.pop(token, None)
    return existed


def purge_expired() -> int:
    """Remove all expired sessions. Returns the count of removed entries."""
    now = datetime.utcnow()
    expired = [t for t, v in _sessions.items() if now > v["expires_at"]]
    for t in expired:
        del _sessions[t]
    if expired:
        logger.info("Purged %d expired sessions", len(expired))
    return len(expired)


def active_session_count() -> int:
    """Return the number of currently active (non-expired) sessions."""
    purge_expired()
    return len(_sessions)
`,
  "inventory_db.py": `"""
PixelForge Inventory Database
Read-only access layer for the item catalogue and player inventory lookups.
Writes go through the store_api (purchases) or admin tooling.
"""

import sqlite3
import logging
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = "pixelforge.db"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS items (
            item_id     TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            category    TEXT NOT NULL,
            price_pfc   INTEGER NOT NULL,
            description TEXT,
            is_limited  INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS player_inventory (
            player_id   TEXT NOT NULL,
            item_id     TEXT NOT NULL,
            acquired_at TEXT NOT NULL,
            PRIMARY KEY (player_id, item_id)
        )
    """)
    conn.commit()


def get_item(item_id: str) -> Optional[dict]:
    """Look up a single item by its ID. Returns None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT item_id, name, category, price_pfc, description, is_limited "
            "FROM items WHERE item_id = ?",
            (item_id,),
        ).fetchone()
    return dict(row) if row else None


def list_items(category: Optional[str] = None, limit: int = 100, offset: int = 0) -> list:
    """
    Return items from the catalogue, optionally filtered by category.
    Results are paginated — use limit and offset for large catalogues.
    """
    with get_db() as conn:
        if category:
            rows = conn.execute(
                "SELECT item_id, name, category, price_pfc, is_limited "
                "FROM items WHERE category = ? ORDER BY name LIMIT ? OFFSET ?",
                (category, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT item_id, name, category, price_pfc, is_limited "
                "FROM items ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]


def get_player_inventory(player_id: str) -> list:
    """Return all items owned by a player, joined with item details."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT i.item_id, i.name, i.category, i.description, pi.acquired_at
            FROM player_inventory pi
            JOIN items i ON i.item_id = pi.item_id
            WHERE pi.player_id = ?
            ORDER BY pi.acquired_at DESC
            """,
            (player_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def player_owns_item(player_id: str, item_id: str) -> bool:
    """Quick ownership check — used by the game server before applying cosmetics."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT 1 FROM player_inventory WHERE player_id = ? AND item_id = ?",
            (player_id, item_id),
        ).fetchone()
    return row is not None


def search_items(query: str, limit: int = 20) -> list:
    """Full-text search against item names and descriptions."""
    pattern = f"%{query}%"
    with get_db() as conn:
        rows = conn.execute(
            "SELECT item_id, name, category, price_pfc "
            "FROM items WHERE name LIKE ? OR description LIKE ? "
            "ORDER BY name LIMIT ?",
            (pattern, pattern, limit),
        ).fetchall()
    return [dict(r) for r in rows]
`,
  "store_api.py": `"""
PixelForge Store API
Handles purchasing items from the cosmetics store using PixelForge Coins.
This module is the authoritative purchase path — all coin deductions go through here.
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional

import wallet_api
import inventory_db

logger = logging.getLogger(__name__)

DB_PATH = "pixelforge.db"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def purchase_item(player_id: str, item_id: str) -> dict:
    """
    Allow a player to buy an item from the store.

    Steps:
      1. Verify the item exists and is available.
      2. Check the player does not already own it.
      3. Check the player has enough coins.
      4. Deduct coins from the wallet (via wallet_api).
      5. Record ownership in the inventory.

    Returns a dict with status and relevant detail.
    """
    item = inventory_db.get_item(item_id)
    if item is None:
        return {"status": "error", "reason": "item not found"}

    if inventory_db.player_owns_item(player_id, item_id):
        return {"status": "error", "reason": "already owned"}

    price = item["price_pfc"]
    balance = wallet_api.get_balance(player_id)
    if balance is None:
        return {"status": "error", "reason": "player wallet not found"}

    if balance < price:
        return {
            "status": "error",
            "reason": "insufficient funds",
            "balance": balance,
            "price": price,
        }

    # Deduct coins — this is the only place store purchases deduct coins,
    # so it is the right place to validate item prices against the wallet.
    deduction = wallet_api.withdraw_to_store_credit(player_id, price)
    if deduction.get("status") != "ok":
        logger.error("Wallet deduction failed for %s buying %s: %s", player_id, item_id, deduction)
        return {"status": "error", "reason": "payment failed"}

    now = datetime.utcnow().isoformat()
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO player_inventory (player_id, item_id, acquired_at) VALUES (?, ?, ?)",
                (player_id, item_id, now),
            )
    except sqlite3.IntegrityError:
        # Race condition: another request granted ownership between our check and insert.
        # Coins already deducted — issue a refund and surface the duplicate.
        logger.warning("Race condition on purchase %s/%s — issuing refund", player_id, item_id)
        wallet_api.deposit(player_id, price, note="purchase_race_refund")
        return {"status": "error", "reason": "already owned (race condition)"}

    logger.info("Purchase: %s bought %s for %d PFC", player_id, item_id, price)
    return {
        "status": "ok",
        "item_id": item_id,
        "item_name": item["name"],
        "paid_pfc": price,
        "acquired_at": now,
    }


def get_store_listing(category: Optional[str] = None) -> list:
    """
    Return purchasable items, annotated with availability.
    Items the player already owns are excluded — call with player_id to filter.
    """
    return inventory_db.list_items(category=category)


def gift_item(sender_id: str, recipient_id: str, item_id: str) -> dict:
    """
    Gift an item to another player. The sender pays; the recipient receives ownership.
    The sender must not already own the item (gifts are purchases on behalf of another).
    """
    item = inventory_db.get_item(item_id)
    if item is None:
        return {"status": "error", "reason": "item not found"}

    if inventory_db.player_owns_item(recipient_id, item_id):
        return {"status": "error", "reason": "recipient already owns this item"}

    price = item["price_pfc"]
    sender_balance = wallet_api.get_balance(sender_id)
    if sender_balance is None or sender_balance < price:
        return {"status": "error", "reason": "insufficient funds"}

    deduction = wallet_api.withdraw_to_store_credit(sender_id, price)
    if deduction.get("status") != "ok":
        return {"status": "error", "reason": "payment failed"}

    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO player_inventory (player_id, item_id, acquired_at) VALUES (?, ?, ?)",
            (recipient_id, item_id, now),
        )

    logger.info("Gift: %s → %s, item %s (%d PFC)", sender_id, recipient_id, item_id, price)
    return {"status": "ok", "gifted_to": recipient_id, "item_id": item_id, "paid_pfc": price}
`,
};
// ── Prompts (kept identical to orchestrator.py) ───────────────────────────

const TRIAGE_SYSTEM =
  'You are a security triage analyst. You will be given a list of source files ' +
  'with short previews. Score each file from 1 to 5 for how likely it is to ' +
  'contain a critical security vulnerability, where 1 = almost certainly clean ' +
  'and 5 = almost certainly vulnerable. Reply ONLY with a JSON array of objects, ' +
  'each with keys: "file" (string) and "score" (integer 1-5). No prose, no markdown.';

const HUNT_SYSTEM =
  'You are a security researcher performing a thorough code audit. ' +
  'Analyse the provided source file for critical security vulnerabilities. ' +
  'If you find one or more critical vulnerabilities, return a JSON object with these keys: ' +
  'found (boolean), file (string), type (string), description (string), ' +
  'exploit_example (string), severity (string: critical|high|medium|low). ' +
  'If no critical vulnerability is found, return: {"found": false, "file": "<name>"}. ' +
  'Reply ONLY with the JSON object. No prose, no markdown code fences.';

const VALIDATE_SYSTEM =
  'You are a senior security engineer performing a final validation pass. ' +
  'You will receive a list of potential vulnerability findings from junior researchers. ' +
  'For each finding, assess whether it is a real, exploitable, critical issue or a false positive. ' +
  'Return a JSON array of objects, each with keys: ' +
  'confirmed (boolean), file (string), verdict (string), impact (string). ' +
  'Reply ONLY with the JSON array. No prose, no markdown code fences.';

// Used in the plain-English reveal — this is a live model call, not hardcoded text.
const EXPLAIN_SYSTEM =
  'You are explaining a confirmed security vulnerability to a non-technical executive audience. ' +
  'Write 4 short paragraphs in plain English — no jargon, no bullet points, no markdown, no headers. ' +
  'Paragraph 1: what does the vulnerable code do in normal use? ' +
  'Paragraph 2: what is the exact bug, in simple terms? ' +
  'Paragraph 3: what would an attacker actually do, step by step, to exploit it? ' +
  'Paragraph 4: why did this bug survive code review — what made it hard to spot? ' +
  'Be concrete and use plain language a non-programmer can follow. ' +
  'Separate paragraphs with a blank line. Output only the four paragraphs, nothing else.';

// ── Runtime state ─────────────────────────────────────────────────────────
let client  = null;
const state = { scores: [], findings: [], verdicts: [] };

// ── Helpers ───────────────────────────────────────────────────────────────

/** Strip accidental markdown fences from model JSON responses. */
function stripFences(text) {
  return text.replace(/^```[a-z]*\n?/gm, '').replace(/```$/gm, '').trim();
}

/** Safely parse JSON; return null on failure. */
function tryParse(text) {
  try { return JSON.parse(stripFences(text)); } catch { return null; }
}

/** Append text to a streaming element and auto-scroll. */
function appendStream(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent += text;
  el.scrollTop = el.scrollHeight;
}

/** Set the timer label for a wave. */
function setTimer(waveNum, text) {
  const el = document.getElementById(`wave${waveNum}-timer`);
  if (el) el.textContent = text;
}

/** Activate a pipeline step circle. */
function setPipeState(num, state /* 'active'|'done' */) {
  const el = document.getElementById(`pipe${num}`);
  if (!el) return;
  el.classList.remove('active', 'done');
  if (state) el.classList.add(state);
}

/** Unlock and activate a wave section. */
function activateWave(num) {
  const sec = document.getElementById(`wave${num}-section`);
  if (!sec) return;
  sec.classList.remove('wave-locked');
  sec.classList.add('wave-active');
  sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function doneWave(num) {
  const sec = document.getElementById(`wave${num}-section`);
  if (sec) { sec.classList.remove('wave-active'); sec.classList.add('wave-done'); }
}

/** Score bar colour based on score value. */
function scoreColor(score) {
  if (score >= 4) return 'var(--red)';
  if (score === 3) return 'var(--amber)';
  return 'var(--green)';
}

// ── Intro: populate file list before pipeline runs ────────────────────────

function renderIntroFileList() {
  const el = document.getElementById('fileList');
  if (!el) return;
  el.innerHTML = '';
  for (const [name, meta] of Object.entries(TARGET_METADATA)) {
    const tagClass = { target: 'ftag-target', minor: 'ftag-minor', clean: 'ftag-clean' }[meta.tag];
    el.insertAdjacentHTML('beforeend', `
      <div class="file-list-item">
        <span class="fname">${name}</span>
        <span class="ftag ${tagClass}">${meta.label}</span>
      </div>`);
  }
}

// ── Wave 1 — Triage ───────────────────────────────────────────────────────

function buildTriagePrompt() {
  return Object.entries(TARGET_FILES).map(([name, content]) => {
    const preview = content.slice(0, PREVIEW_CHARS).replace(/\n/g, ' ').trim();
    return `FILE: ${name}\nPREVIEW: ${preview}`;
  }).join('\n\n');
}

function renderScoreCards(scores) {
  const grid = document.getElementById('fileGrid');
  grid.innerHTML = '';

  for (const entry of scores) {
    const { file, score } = entry;
    const riskClass = score >= 4 ? 'risk-high' : score === 3 ? 'risk-medium' : 'risk-low';
    const tag = score >= HUNT_THRESHOLD
      ? `<div class="score-tag">⚡ Queued for deep scan</div>` : '';

    grid.insertAdjacentHTML('beforeend', `
      <div class="score-card ${riskClass}">
        <div class="score-filename">${file}</div>
        <div class="score-bar-row">
          <div class="score-bar-track">
            <div class="score-bar-fill" id="bar-${file.replace('.','_')}"
                 style="background:${scoreColor(score)}"></div>
          </div>
          <div class="score-val">${score}/5</div>
        </div>
        ${tag}
      </div>`);

    // Animate bar width after a short delay so the transition fires
    setTimeout(() => {
      const bar = document.getElementById(`bar-${file.replace('.','_')}`);
      if (bar) bar.style.width = `${(score / 5) * 100}%`;
    }, 80);
  }
}

async function runWave1() {
  activateWave(1);
  setPipeState(1, 'active');
  const t0 = Date.now();

  // Clear waiting message
  document.getElementById('wave1-waiting')?.remove();

  // Open the raw-response drawer so the audience sees streaming immediately
  const drawer = document.querySelector('#wave1-section .raw-drawer');
  if (drawer) drawer.open = true;

  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 512,
    system: TRIAGE_SYSTEM,
    messages: [{ role: 'user', content: buildTriagePrompt() }],
  });

  let full = '';
  for await (const ev of stream) {
    if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') {
      full += ev.delta.text;
      appendStream('wave1-terminal', ev.delta.text);
    }
  }

  const scores = tryParse(full);
  if (!scores) throw new Error('Wave 1: could not parse model response as JSON');

  scores.sort((a, b) => b.score - a.score);
  state.scores = scores;

  renderScoreCards(scores);
  setTimer(1, `✓ ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  setPipeState(1, 'done');
  doneWave(1);

  return scores.filter(s => s.score >= HUNT_THRESHOLD).map(s => s.file);
}

// ── Wave 2 — Hunt ─────────────────────────────────────────────────────────

function createAgentCard(filename) {
  const safeId = filename.replace('.', '_');
  document.getElementById('wave2-waiting')?.remove();

  document.getElementById('agentList').insertAdjacentHTML('beforeend', `
    <div class="agent-card agent-active" id="agent-${safeId}">
      <div class="agent-header">
        <div class="agent-dot dot-scanning" id="dot-${safeId}"></div>
        <div class="agent-fname">${filename}</div>
        <div class="agent-status" id="status-${safeId}">
          <span class="spinner"></span>&nbsp;Scanning…
        </div>
      </div>
      <div class="agent-stream" id="stream-${safeId}"></div>
    </div>`);
}

function finaliseAgentCard(filename, finding) {
  const safeId  = filename.replace('.', '_');
  const dot     = document.getElementById(`dot-${safeId}`);
  const status  = document.getElementById(`status-${safeId}`);
  const card    = document.getElementById(`agent-${safeId}`);

  if (finding?.found) {
    dot.className    = 'agent-dot dot-found';
    status.textContent = '⚠ Finding detected';
    card.classList.replace('agent-active', 'agent-found');

    card.insertAdjacentHTML('beforeend', `
      <div class="agent-finding-chip">
        <div class="chip-label">Finding</div>
        <div class="chip-type">${finding.type || 'Unknown'}</div>
        <div class="chip-desc">${finding.description || ''}</div>
      </div>`);
  } else {
    dot.className    = 'agent-dot dot-clean';
    status.textContent = '✓ No critical issues';
    card.classList.replace('agent-active', 'agent-clean');
  }
}

async function huntFile(filename) {
  createAgentCard(filename);
  const safeId  = filename.replace('.', '_');
  const content = TARGET_FILES[filename];

  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 1024,
    system: HUNT_SYSTEM,
    messages: [{
      role: 'user',
      content: `File: ${filename}\n\n\`\`\`python\n${content}\n\`\`\``,
    }],
  });

  let full = '';
  for await (const ev of stream) {
    if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') {
      full += ev.delta.text;
      appendStream(`stream-${safeId}`, ev.delta.text);
    }
  }

  const finding = tryParse(full) ?? { found: false, file: filename };
  finding.file  = filename;
  finaliseAgentCard(filename, finding);
  return finding;
}

async function runWave2(highRiskFiles) {
  activateWave(2);
  setPipeState(2, 'active');
  const t0 = Date.now();

  // Browser can't parallelise; run sequentially — educational note already in HTML
  for (const filename of highRiskFiles) {
    const finding = await huntFile(filename);
    state.findings.push(finding);
  }

  setTimer(2, `✓ ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  setPipeState(2, 'done');
  doneWave(2);
}

// ── Wave 3 — Validate ─────────────────────────────────────────────────────

async function runWave3() {
  activateWave(3);
  setPipeState(3, 'active');
  const t0 = Date.now();

  document.getElementById('wave3-waiting')?.remove();

  const positives = state.findings.filter(f => f.found);

  if (positives.length === 0) {
    document.getElementById('validationArea').innerHTML =
      '<p style="padding:24px 28px;color:var(--text-dim);font-size:13px">No findings from Wave 2 — nothing to validate.</p>';
    setPipeState(3, 'done');
    doneWave(3);
    return [];
  }

  // Build validator UI
  document.getElementById('validationArea').innerHTML = `
    <div class="validator-card">
      <div class="validator-header">
        <div class="agent-dot dot-scanning" id="vdot"></div>
        <div class="validator-label">
          Senior AI Reviewer — validating ${positives.length} finding(s)…
        </div>
      </div>
      <div class="validator-stream" id="val-stream"></div>
    </div>`;

  // Open the raw drawer so audience sees streaming
  const drawer = document.querySelector('#wave3-section .raw-drawer');
  if (drawer) drawer.open = true;

  const cleanFindings = positives.map(({ file, type, description, exploit_example, severity, found }) =>
    ({ found, file, type, description, exploit_example, severity })
  );

  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 1024,
    system: VALIDATE_SYSTEM,
    messages: [{ role: 'user', content: JSON.stringify(cleanFindings, null, 2) }],
  });

  let full = '';
  for await (const ev of stream) {
    if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') {
      full += ev.delta.text;
      appendStream('val-stream', ev.delta.text);
      appendStream('wave3-terminal', ev.delta.text);
    }
  }

  const verdicts = tryParse(full) ?? [];
  state.verdicts = verdicts;

  // Update dot colour
  const vdot = document.getElementById('vdot');
  if (vdot) vdot.className = 'agent-dot ' + (verdicts.some(v => v.confirmed) ? 'dot-found' : 'dot-clean');

  setTimer(3, `✓ ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  setPipeState(3, 'done');
  doneWave(3);

  return verdicts;
}

// ── Final reveal ──────────────────────────────────────────────────────────

async function showReveal(verdicts) {
  const confirmed = verdicts.filter(v => v.confirmed);

  if (confirmed.length === 0) {
    document.getElementById('cleanSection').hidden = false;
    document.getElementById('cleanSection').scrollIntoView({ behavior: 'smooth' });
    return;
  }

  const verdict = confirmed[0];
  const finding = state.findings.find(f => f.file === verdict.file) ?? {};

  // Structured finding table — populated from the real model response
  const rows = [
    ['File',        finding.file || verdict.file,                   'prose'],
    ['Type',        finding.type || 'Logic Error',                  'prose'],
    ['Severity',    (finding.severity || 'critical').toUpperCase(), 'sev-critical'],
    ['Description', finding.description || verdict.verdict,         'prose'],
    ['Exploit',     finding.exploit_example || '—',                 ''],
    ['AI Verdict',  verdict.verdict,                                'prose'],
    ['Impact',      verdict.impact,                                 'prose'],
  ];

  document.getElementById('findingTable').innerHTML = rows.map(([k, v, cls]) => `
    <div class="finding-row">
      <div class="finding-key">${k}</div>
      <div class="finding-val ${cls}">${v}</div>
    </div>`).join('');

  // Show the reveal section immediately with a loading state for the explanation
  const peEl = document.getElementById('plainEnglish');
  peEl.innerHTML = `
    <div class="explain-loading">
      <span class="spinner"></span>&nbsp; AI is writing a plain-English explanation…
    </div>
    <div class="explain-stream" id="explain-stream"></div>`;

  const sec = document.getElementById('revealSection');
  sec.hidden = false;
  setTimeout(() => sec.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);

  // Live API call — stream the explanation directly into the reveal panel
  const context =
    `File: ${finding.file}\n` +
    `Vulnerability type: ${finding.type}\n` +
    `Description: ${finding.description}\n` +
    `Exploit example: ${finding.exploit_example}\n` +
    `Severity: ${finding.severity}\n` +
    `Validator verdict: ${verdict.verdict}\n` +
    `Impact: ${verdict.impact}`;

  const stream = client.messages.stream({
    model: MODEL,
    max_tokens: 600,
    system: EXPLAIN_SYSTEM,
    messages: [{ role: 'user', content: context }],
  });

  let fullExplanation = '';
  const streamEl = document.getElementById('explain-stream');

  for await (const ev of stream) {
    if (ev.type === 'content_block_delta' && ev.delta.type === 'text_delta') {
      fullExplanation += ev.delta.text;
      // Stream raw text so the audience sees the model writing in real time
      streamEl.textContent = fullExplanation;
    }
  }

  // Once complete, remove the loading indicator and render as proper paragraphs
  peEl.innerHTML = fullExplanation
    .split(/\n\n+/)
    .filter(p => p.trim())
    .map(p => `<p>${p.trim()}</p>`)
    .join('');
}

// ── Main pipeline ─────────────────────────────────────────────────────────

async function runPipeline() {
  const btn = document.getElementById('runBtn');
  btn.disabled   = true;
  btn.textContent = '⟳  Running…';

  // Reset any previous run state
  state.scores   = [];
  state.findings = [];
  state.verdicts = [];
  document.getElementById('revealSection').hidden  = true;
  document.getElementById('cleanSection').hidden   = true;
  ['wave1-terminal', 'wave3-terminal'].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = '';
  });
  document.getElementById('agentList').innerHTML =
    '<div class="waiting-msg" id="wave2-waiting">Waiting for Wave 1 to complete…</div>';
  document.getElementById('validationArea').innerHTML =
    '<div class="waiting-msg" id="wave3-waiting">Waiting for Wave 2 to complete…</div>';

  // Re-lock waves 2 & 3
  ['wave2-section','wave3-section'].forEach(id => {
    const s = document.getElementById(id);
    s.classList.remove('wave-active','wave-done');
    s.classList.add('wave-locked');
  });
  [1,2,3].forEach(n => setPipeState(n, null));

  try {
    const highRisk = await runWave1();

    if (highRisk.length > 0) {
      await runWave2(highRisk);
    } else {
      // Skip Wave 2, unlock Wave 3 anyway
      doneWave(2);
    }

    const verdicts = await runWave3();
    await showReveal(verdicts);

    btn.textContent = '↺  Run Again';
    btn.disabled    = false;
  } catch (err) {
    console.error('[Glasswing]', err);
    btn.textContent = '✗  Error — check console';
    btn.style.background = 'var(--red)';
    btn.style.color      = '#fff';
    btn.disabled = false;
  }
}

// ── Initialisation ────────────────────────────────────────────────────────

const apiKeyInput = document.getElementById('apiKey');
const runBtn      = document.getElementById('runBtn');

// Populate the intro file list on page load (no API needed)
renderIntroFileList();

// Restore key from sessionStorage (session-only; cleared when tab closes)
const saved = sessionStorage.getItem('gw_api_key');
if (saved) {
  apiKeyInput.value = saved;
  runBtn.disabled   = false;
}

apiKeyInput.addEventListener('input', () => {
  const key = apiKeyInput.value.trim();
  runBtn.disabled = !key;
  if (key) sessionStorage.setItem('gw_api_key', key);
  else     sessionStorage.removeItem('gw_api_key');
});

runBtn.addEventListener('click', () => {
  const key = apiKeyInput.value.trim();
  if (!key) return;
  client = new Anthropic({ apiKey: key, dangerouslyAllowBrowser: true });
  runPipeline();
});
