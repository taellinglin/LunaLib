"""
SM3 wrapper utilities with optional accelerated backend.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List

from lunalib.core.sm2 import SM3Hash

try:  # Optional fast backend
    from gmssl import sm3 as gmssl_sm3  # type: ignore
    from gmssl import func as gmssl_func  # type: ignore
    _HAS_GMSSL = True
except Exception:  # pragma: no cover - optional
    _HAS_GMSSL = False


def sm3_digest(data: bytes) -> bytes:
    if _HAS_GMSSL:
        return bytes.fromhex(gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(data)))
    return SM3Hash.hash(data)


def sm3_hex(data: bytes) -> str:
    return sm3_digest(data).hex()


def sm3_batch(data_items: Iterable[bytes], max_workers: int = 0) -> List[bytes]:
    """Batch SM3 hashing with optional threading."""
    items = list(data_items)
    if not items:
        return []
    if max_workers and max_workers > 1:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            return list(pool.map(sm3_digest, items))
    return [sm3_digest(item) for item in items]
