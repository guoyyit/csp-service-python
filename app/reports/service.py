"""违规上报处理服务：去重、限速、有界存储、查询聚合。"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.reports.ratelimit import SlidingWindowRateLimiter
from app.reports.store import ReportStore

# 单条原始上报体积上限，防止超大 payload 刷爆磁盘
MAX_RAW_BYTES = 16 * 1024


@dataclass(frozen=True)
class IngestResult:
    accepted: bool
    reason: str
    id: int | None = None
    count: int = 0
    duplicate: bool = False
    pruned: int = 0


class ReportService:
    """组合限流器与存储，对外提供上报接收与查询能力。"""

    def __init__(
        self,
        store: ReportStore,
        *,
        rate_window_seconds: float = 60.0,
        rate_max_requests: int = 10,
        max_events: int = 10000,
        max_raw_bytes: int = MAX_RAW_BYTES,
    ) -> None:
        self.store = store
        self.max_events = max_events
        self.max_raw_bytes = max_raw_bytes
        self._limiter = SlidingWindowRateLimiter(
            rate_window_seconds, rate_max_requests
        )

    def ingest(self, payload: dict[str, Any]) -> IngestResult:
        """接收一条浏览器 CSP 违规上报。

        流程：体积校验 → 字段归一化 → 去重键限速 → 容量裁剪 → 去重落库。
        限速按“去重键”计数：同一类违规高频重复才会被限流，
        不同类型事件互不影响；超过容量只删除最旧记录，存储始终有界。
        """
        if not isinstance(payload, dict):
            return IngestResult(accepted=False, reason="invalid_payload")

        raw = payload.get("csp-report", payload)
        if not isinstance(raw, dict):
            return IngestResult(accepted=False, reason="invalid_payload")
        if len(json.dumps(payload, ensure_ascii=False).encode("utf-8")) > self.max_raw_bytes:
            return IngestResult(accepted=False, reason="payload_too_large")

        document_uri = str(raw.get("document-uri", ""))
        violated_directive = self._directive_name(
            str(raw.get("violated-directive", ""))
        )
        blocked_uri = str(raw.get("blocked-uri", ""))
        source_file = str(raw.get("source-file", ""))
        line_number = int(raw.get("line-number") or 0)
        column_number = int(raw.get("column-number") or 0)

        dedup_key = self._dedup_key(
            document_uri=document_uri,
            violated_directive=violated_directive,
            blocked_uri=blocked_uri,
            source_file=source_file,
            line_number=line_number,
            column_number=column_number,
        )

        if not self._limiter.allow(dedup_key):
            return IngestResult(accepted=False, reason="rate_limited")

        # 限速通过后，先裁剪到 max_events - 1 再插入，
        # 保证即使新事件落库后总量也不超过容量硬上限
        pruned = self.store.prune(self.max_events - 1)
        report_id, count, created = self.store.upsert(
            dedup_key=dedup_key,
            document_uri=document_uri,
            violated_directive=violated_directive,
            blocked_uri=blocked_uri,
            source_file=source_file,
            line_number=line_number,
            column_number=column_number,
            raw=payload,
        )
        return IngestResult(
            accepted=True,
            reason="stored",
            id=report_id,
            count=count,
            duplicate=not created,
            pruned=pruned,
        )

    def list_reports(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return self.store.list_reports(status=status, limit=limit, offset=offset)

    def set_status(self, report_id: int, status: str) -> bool:
        return self.store.set_status(report_id, status)

    def aggregate(self) -> list[dict[str, Any]]:
        return self.store.aggregate()

    def counts(self) -> dict[str, int]:
        return self.store.counts()

    def close(self) -> None:
        self.store.close()

    @staticmethod
    def _directive_name(violated_directive: str) -> str:
        """``script-src 'self'`` → ``script-src``，便于去重与聚合。"""
        return violated_directive.split(" ", 1)[0]

    @staticmethod
    def _dedup_key(
        *,
        document_uri: str,
        violated_directive: str,
        blocked_uri: str,
        source_file: str,
        line_number: int,
        column_number: int,
    ) -> str:
        material = "|".join(
            (
                document_uri,
                violated_directive,
                blocked_uri,
                source_file,
                str(line_number),
                str(column_number),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()
