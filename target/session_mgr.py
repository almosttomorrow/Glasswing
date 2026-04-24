"""
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
