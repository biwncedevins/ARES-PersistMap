"""File hashing with caching and size caps.

SHA256 is the primary hash. Hashing is never mandatory - callers decide.
Within one scan the same file (path + size + mtime) is hashed at most once.
"""

from __future__ import annotations

import hashlib
import os
import threading
from typing import Optional

from config import MAX_HASH_FILE_SIZE


class HashCache:
    """In-memory per-scan hash cache keyed by (path, size, mtime)."""

    def __init__(self, max_size: int = MAX_HASH_FILE_SIZE) -> None:
        self.max_size = max_size
        self._cache: dict[tuple, str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(path: str) -> Optional[tuple]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (os.path.normcase(path), st.st_size, int(st.st_mtime))

    def sha256_of(self, path: str) -> str:
        """Return hex sha256 or empty string if unavailable/oversized."""
        key = self._key(path)
        if key is None:
            return ""
        with self._lock:
            value = self._cache.get(key)
        if value is not None:
            return value
        digest = self._compute(path)
        if digest:
            with self._lock:
                # store under the full key (path may have changed)
                self._cache[(os.path.normcase(path), key[1], key[2])] = digest
                self._cache[key] = digest
        return digest

    def _compute(self, path: str) -> str:
        try:
            size = os.path.getsize(path)
            if size > self.max_size:
                return ""
            h = hashlib.sha256()
            with open(path, "rb") as fh:
                while True:
                    block = fh.read(1024 * 1024)
                    if not block:
                        break
                    h.update(block)
            return h.hexdigest()
        except OSError:
            return ""

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()