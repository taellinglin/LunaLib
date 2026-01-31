"""Tolken assets (NFT-like) for LunaLib."""

from typing import Any, Dict, Optional, Tuple
from lunalib.utils.validation import is_valid_address, is_valid_tx_hash, sanitize_memo

ALLOWED_TOLKEN_TYPES = {"midi", "ogg", "png", "svg"}


def normalize_tolken_type(value: Optional[str]) -> str:
    return str(value or "").strip().lower()


def is_valid_tolken_type(value: Optional[str]) -> bool:
    return normalize_tolken_type(value) in ALLOWED_TOLKEN_TYPES


def is_valid_asset_hash(value: Optional[str]) -> bool:
    return is_valid_tx_hash(value)


def calculate_tolken_fee(price: float) -> float:
    try:
        price_val = float(price)
    except Exception:
        return 0.0
    return max(0.0, price_val * 0.0001)


def validate_tolken_payload(transaction: Any) -> Tuple[bool, str]:
    if not isinstance(transaction, dict):
        return False, "Tolken payload must be an object"

    tx_type = normalize_tolken_type(transaction.get("type"))
    if tx_type != "tolkens":
        return False, "Invalid tolken type"

    if not is_valid_address(transaction.get("from")):
        return False, "Invalid from address"
    if not is_valid_address(transaction.get("to")):
        return False, "Invalid to address"

    try:
        price = float(transaction.get("price", 0))
    except Exception:
        return False, "Invalid price"
    if price <= 0:
        return False, "Price must be positive"

    asset_type = normalize_tolken_type(transaction.get("asset_type"))
    if asset_type not in ALLOWED_TOLKEN_TYPES:
        return False, "Invalid asset_type"

    asset_hash = transaction.get("asset_hash")
    if not is_valid_asset_hash(asset_hash):
        return False, "Invalid asset_hash"

    fee = transaction.get("fee", None)
    if fee is None:
        return False, "Missing fee"

    if "memo" in transaction:
        transaction["memo"] = sanitize_memo(transaction.get("memo"))

    return True, "OK"
