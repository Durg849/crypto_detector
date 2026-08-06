"""
db.py — MongoDB connection + atomic API key operations for Injecto.

Replaces the old api_keys.json / users.json flat-file storage
(load_keys/save_keys/load_users/save_users in server.py), which had a
read-modify-write race condition: two concurrent requests could both
read requests=41 and both write back 42, silently losing a count.
It also didn't survive Render's ephemeral filesystem across deploys.

Every function below does its check + update as ONE MongoDB call,
so MongoDB's own document-level atomicity prevents that race —
no explicit transactions needed.
"""

import os
import datetime
import secrets
from pymongo import MongoClient, ReturnDocument

MONGODB_URI = os.environ.get("MONGODB_URI", "")
MONGODB_DB_NAME = os.environ.get("MONGODB_DB_NAME", "injecto")

if not MONGODB_URI:
    raise RuntimeError("MONGODB_URI is not set — add it in Render's environment variables")

_client = MongoClient(MONGODB_URI)
_db = _client[MONGODB_DB_NAME]
_keys = _db["api_keys"]
_users = _db["users"]

# Unique index — makes duplicate emails impossible at the DB level,
# instead of a separate "does this exist?" check-then-insert (which is
# itself a race condition).
_keys.create_index("email", unique=True)
_keys.create_index("api_key", unique=True)


def generate_api_key() -> str:
    return "inj_" + secrets.token_hex(24)


def create_api_key(email: str, plan: str = "starter") -> str:
    """
    Create a new key for an email. Returns the plain key string.
    Raises ValueError if the email already has a key.
    """
    key = generate_api_key()
    doc = {
        "email": email,
        "api_key": key,
        "plan": plan,
        "requests": 0,
        "created_at": datetime.datetime.now().isoformat(),
        "last_used": None,
    }
    try:
        _keys.insert_one(doc)
    except Exception as e:
        if "duplicate key" in str(e).lower():
            raise ValueError("An API key already exists for this email")
        raise
    return key


def verify_and_count_api_key(key: str):
    """
    Atomic replacement for the old verify_api_key():
    looks up the key AND increments its request counter in a single
    findOneAndUpdate call — no separate load/modify/save file steps,
    so concurrent requests can't clobber each other's counts.

    Returns the updated key document, or None if the key doesn't exist.
    """
    return _keys.find_one_and_update(
        {"api_key": key},
        {
            "$inc": {"requests": 1},
            "$set": {"last_used": datetime.datetime.now().isoformat()},
        },
        return_document=ReturnDocument.AFTER,
    )


def get_key_stats(key: str):
    """Read-only lookup — used by /api/stats, does not bump the counter."""
    return _keys.find_one({"api_key": key}, {"_id": 0})
