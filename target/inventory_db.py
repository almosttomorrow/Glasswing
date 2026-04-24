"""
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
