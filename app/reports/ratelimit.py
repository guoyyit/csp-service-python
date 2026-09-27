"""基于滑动窗口的内存限流器，跟踪字典大小有界。"""
from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowRateLimiter:
    """按 key 维护时间戳队列，超过窗口上限即拒绝。

    为防止恶意刷量构造海量不同 key 导致内存无界增长，
    空闲 key 会被惰性清理，且 key 数量设有硬上限。
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        max_requests: int = 10,
        *,
        max_tracked_keys: int = 10000,
    ) -> None:
        if window_seconds <= 0 or max_requests <= 0:
            raise ValueError("窗口长度与请求上限必须为正数")
        self.window = float(window_seconds)
        self.max_requests = max_requests
        self.max_tracked_keys = max_tracked_keys
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        """同一 key 在时间窗内超过上限则拒绝（拒绝不记录新时间戳）。"""
        current = time.monotonic() if now is None else now
        cutoff = current - self.window
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque()
                self._buckets[key] = bucket
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                return False
            bucket.append(current)
            self._evict_if_needed(cutoff)
            return True

    def _evict_if_needed(self, cutoff: float) -> None:
        # 先清理所有已完全过期的 key
        stale = [k for k, b in self._buckets.items() if not b or b[-1] <= cutoff]
        for k in stale:
            del self._buckets[k]
        # 仍然超限时，丢弃最近活动时间最旧的 key（流量最小原则）
        if len(self._buckets) > self.max_tracked_keys:
            overflow = len(self._buckets) - self.max_tracked_keys
            for k in sorted(self._buckets, key=lambda x: self._buckets[x][-1])[
                :overflow
            ]:
                del self._buckets[k]

    def size(self) -> int:
        with self._lock:
            return len(self._buckets)
