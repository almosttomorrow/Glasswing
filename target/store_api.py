"""
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
