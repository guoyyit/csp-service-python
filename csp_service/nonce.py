"""Per-response nonce generation and HTML injection."""
from __future__ import annotations

import re
import secrets
import threading
from collections import deque

NONCE_ATTR = "nonce"
_NONCE_BYTES = 16
_HISTORY_LIMIT = 4096

# <script ...> / <style ...> opening tags (case-insensitive), excluding
# self-closing fragments. Attribute text is matched without '>' so the
# regex stays simple for well-formed HTML.
_TAG_RE = re.compile(
    r"<(?P<tag>script|style)(?P<attrs>\s[^>]*)?>",
    re.IGNORECASE,
)
_SRC_RE = re.compile(r"(^|\s)src\s*=", re.IGNORECASE)
_NONCE_RE = re.compile(r"(^|\s)nonce\s*=", re.IGNORECASE)


class NonceGenerator:
    """Thread-safe one-time random nonce generator.

    A bounded history guards against (astronomically unlikely) collisions,
    guaranteeing that nonces returned to successive responses differ even
    under concurrency.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._history: set[str] = set()
        self._order: deque[str] = deque()

    def generate(self) -> str:
        with self._lock:
            value = secrets.token_urlsafe(_NONCE_BYTES)
            while value in self._history:
                value = secrets.token_urlsafe(_NONCE_BYTES)
            self._history.add(value)
            self._order.append(value)
            if len(self._order) > _HISTORY_LIMIT:
                self._history.discard(self._order.popleft())
            return value


def inject_nonce(html: str, nonce: str) -> str:
    """Inject *nonce* into inline ``<script>``/``<style>`` tags lacking one.

    External scripts (with ``src``) and tags already carrying a nonce are
    left untouched. The same *nonce* is inserted everywhere, so the header
    and page content always agree.
    """

    def _add(match: re.Match[str]) -> str:
        tag = match.group("tag")
        attrs = (match.group("attrs") or "").strip()
        if _NONCE_RE.search(attrs):
            return match.group(0)
        if tag.lower() == "script" and _SRC_RE.search(attrs):
            return match.group(0)
        pieces = [tag]
        if attrs:
            pieces.append(attrs)
        pieces.append(f'nonce="{nonce}"')
        return "<" + " ".join(pieces) + ">"

    return _TAG_RE.sub(_add, html)
