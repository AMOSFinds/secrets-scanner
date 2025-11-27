# app/payments.py
import os, json, httpx, hmac, hashlib
from typing import Optional

PAYSTACK_SECRET = os.getenv("PAYSTACK_SECRET_KEY", "")
PAYSTACK_PUBLIC = os.getenv("PAYSTACK_PUBLIC_KEY", "")
PRICE_CENTS = int(os.getenv("PRO_PRICE_CENTS", "10000"))  # R100 by default
CURRENCY = os.getenv("PRO_CURRENCY", "ZAR")
CALLBACK_URL = os.getenv("PRO_CALLBACK_URL", "")

# --- Key pool from PRO_KEYS_JSON ---
_raw = os.getenv("PRO_KEYS_JSON", '{"keys": []}')
try:
    parsed = json.loads(_raw)
    POOL = parsed.get("keys", [])
except Exception as e:
    print("WARNING: PRO_KEYS_JSON is not valid JSON:", repr(_raw), "error:", e)
    POOL = []

# in-memory issued map: email -> key dict
ISSUED: dict[str, dict] = {}


def next_available_key() -> Optional[dict]:
    """Return the next unused key from the pool."""
    used = {v.get("key") for v in ISSUED.values()}
    for k in POOL:
        kk = k.get("key")
        if kk and kk not in used:
            return k
    return None


def assign_key_to_email(email: str) -> Optional[dict]:
    """Idempotent: same email always gets the same key while the process lives."""
    if email in ISSUED:
        return ISSUED[email]
    k = next_available_key()
    if not k:
        return None
    ISSUED[email] = k
    return k


# --- Paystack helpers ---
BASE = "https://api.paystack.co"


def paystack_headers() -> dict:
    if not PAYSTACK_SECRET:
        raise RuntimeError("PAYSTACK_SECRET_KEY is not set")
    return {
        "Authorization": f"Bearer {PAYSTACK_SECRET}",
        "Content-Type": "application/json",
    }


async def init_transaction(email: str) -> dict:
    """
    Returns {"authorization_url": "...", "reference": "..."}
    """
    payload = {
        "email": email,
        "amount": PRICE_CENTS,  # cents
        "currency": CURRENCY,
        "callback_url": CALLBACK_URL or None,
    }
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            f"{BASE}/transaction/initialize",
            json=payload,
            headers=paystack_headers(),
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("status"):
            raise RuntimeError(data.get("message", "Paystack init failed"))
        return data["data"]


async def verify_transaction(reference: str) -> dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(
            f"{BASE}/transaction/verify/{reference}",
            headers=paystack_headers(),
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("status"):
            raise RuntimeError(data.get("message", "Paystack verify failed"))
        return data["data"]  # includes customer, amount, status, etc.


def verify_webhook_signature(body: bytes, signature: str | None) -> bool:
    # Paystack docs: HMAC SHA512 of raw body with your secret key
    if not (signature and PAYSTACK_SECRET):
        return False
    digest = hmac.new(PAYSTACK_SECRET.encode(), body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(digest, signature)
