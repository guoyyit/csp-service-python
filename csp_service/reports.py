"""Violation report collection: dedup, rate limiting, bounded persistence."""
from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class ReportStatus(str, Enum):
    OPEN = "open"
    HANDLED = "handled"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


@dataclass
class ViolationEvent:
    """A deduplicated violation record stored by the service."""

    fingerprint: str
    document_uri: str = ""
    violated_directive: str = ""
    blocked_uri: str = ""
    source_file: str = ""
    line_number: int = 0
    first_seen: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)
    count: int = 1
    status: ReportStatus = ReportStatus.OPEN

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "document_uri": self.document_uri,
            "violated_directive": self.violated_directive,
            "blocked_uri": self.blocked_uri,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "count": self.count,
            "status": self.status.value,
        }


@dataclass(frozen=True)
class RateLimitConfig:
    """Sliding-window rate limit and storage cap."""

    window_seconds: float = 60.0
    max_events_per_window: int = 100
    max_records: int = 10000


# Accepted reasons returned by ReportStore.add.
ACCEPTED = "accepted"
DUPLICATE = "duplicate"
RATE_LIMITED = "rate_limited"
STORAGE_FULL = "storage_full"


def normalize_report(payload: Any) -> dict[str, Any]:
    """Normalize legacy report-uri and Reporting-API payloads.

    Accepted shapes:
    * ``{"csp-report": {...}}``                 (legacy report-uri)
    * ``[{"type": "csp-violation", "body": {}}]`` (Reporting-API batch)
    * ``{"type": "csp-violation", "body": {}}``  (single Reporting-API item)
    * a bare ``{...}`` report body
    """
    data = payload
    # Reporting API: list of {type, body}
    if isinstance(payload, list):
        if not payload:
            return {}
        item = payload[0]
        data = item.get("body", item) if isinstance(item, Mapping) else {}
    elif isinstance(payload, Mapping) and "csp-report" in payload:
        data = payload["csp-report"]
    elif isinstance(payload, Mapping) and isinstance(payload.get("body"), Mapping):
        data = payload["body"]
    if not isinstance(data, Mapping):
        return {}

    def pick(*names: str) -> Any:
        for name in names:
            if name in data and data[name] is not None:
                return data[name]
        return ""

    violated = str(pick("effective-directive", "violated-directive", "violatedDirective"))
    # "script-src 'self'" -> "script-src"
    directive = violated.split(" ", 1)[0] if violated else ""
    line = pick("line-number", "lineNumber") or 0

    return {
        "document_uri": str(pick("document-uri", "documentURL", "document_uri")),
        "violated_directive": directive,
        "blocked_uri": str(pick("blocked-uri", "blockedURL", "blocked_uri")),
        "source_file": str(pick("source-file", "sourceFile", "source_file")),
        "line_number": int(line) if str(line).isdigit() else 0,
    }


def fingerprint_of(fields: Mapping[str, Any]) -> str:
    basis = "|".join(
        str(fields.get(k, ""))
        for k in (
            "document_uri",
            "violated_directive",
            "blocked_uri",
            "source_file",
            "line_number",
        )
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class ReportStore:
    """Thread-safe, persisted, de-duplicated and rate-limited report store."""

    def __init__(
        self,
        path: str | None = None,
        limit: RateLimitConfig | None = None,
    ) -> None:
        self.limit = limit or RateLimitConfig()
        self._lock = threading.RLock()
        self._path = path or ":memory:"
        if self._path != ":memory:":
            parent = os.path.dirname(os.path.abspath(self._path))
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        # sliding window of submission timestamps (monotonic seconds)
        self._window: deque[float] = deque()
        self._clock = _utcnow

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                fingerprint TEXT PRIMARY KEY,
                document_uri TEXT NOT NULL DEFAULT '',
                violated_directive TEXT NOT NULL DEFAULT '',
                blocked_uri TEXT NOT NULL DEFAULT '',
                source_file TEXT NOT NULL DEFAULT '',
                line_number INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                count INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'open'
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_reports_directive "
            "ON reports(violated_directive)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    def add(self, payload: Any) -> tuple[ViolationEvent | None, str]:
        """Add a browser report.

        Returns ``(event, reason)``. Duplicates bump the existing record's
        counter and ``last_seen``; floods are rejected by the sliding-window
        rate limiter and the hard record cap, keeping storage bounded.
        """
        fields = normalize_report(payload)
        fp = fingerprint_of(fields)
        now = self._clock()

        with self._lock:
            self._prune_window(now)
            if len(self._window) >= self.limit.max_events_per_window:
                return None, RATE_LIMITED
            self._window.append(now.timestamp())

            row = self._conn.execute(
                "SELECT * FROM reports WHERE fingerprint = ?", (fp,)
            ).fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE reports SET count = count + 1, last_seen = ? "
                    "WHERE fingerprint = ?",
                    (_iso(now), fp),
                )
                self._conn.commit()
                event = self._row_to_event(row)
                event.count += 1
                event.last_seen = now
                return event, DUPLICATE

            count = self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            if count >= self.limit.max_records:
                return None, STORAGE_FULL

            self._conn.execute(
                """
                INSERT INTO reports (fingerprint, document_uri, violated_directive,
                    blocked_uri, source_file, line_number, first_seen, last_seen,
                    count, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'open')
                """,
                (
                    fp,
                    fields["document_uri"],
                    fields["violated_directive"],
                    fields["blocked_uri"],
                    fields["source_file"],
                    fields["line_number"],
                    _iso(now),
                    _iso(now),
                ),
            )
            self._conn.commit()
            return (
                ViolationEvent(
                    fingerprint=fp,
                    document_uri=fields["document_uri"],
                    violated_directive=fields["violated_directive"],
                    blocked_uri=fields["blocked_uri"],
                    source_file=fields["source_file"],
                    line_number=fields["line_number"],
                    first_seen=now,
                    last_seen=now,
                ),
                ACCEPTED,
            )

    def _prune_window(self, now: datetime) -> None:
        cutoff = now.timestamp() - self.limit.window_seconds
        while self._window and self._window[0] <= cutoff:
            self._window.popleft()

    # ------------------------------------------------------------------
    def query(
        self,
        status: ReportStatus | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ViolationEvent]:
        with self._lock:
            if status is not None:
                rows = self._conn.execute(
                    "SELECT * FROM reports WHERE status = ? "
                    "ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                    (status.value, limit, offset),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM reports ORDER BY last_seen DESC "
                    "LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
            return [self._row_to_event(r) for r in rows]

    def aggregate(self) -> dict[str, dict[str, Any]]:
        """Aggregate counts grouped by violated directive."""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT violated_directive,
                       COUNT(*) AS event_count,
                       SUM(count) AS report_count,
                       SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count
                FROM reports
                GROUP BY violated_directive
                ORDER BY report_count DESC
                """
            ).fetchall()
        return {
            r["violated_directive"]: {
                "event_count": r["event_count"],
                "report_count": r["report_count"],
                "open_count": r["open_count"],
            }
            for r in rows
        }

    def mark_handled(self, fingerprint: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE reports SET status = ? WHERE fingerprint = ?",
                (ReportStatus.HANDLED.value, fingerprint),
            )
            self._conn.commit()
            return cur.rowcount == 1

    def total_records(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> ViolationEvent:
        return ViolationEvent(
            fingerprint=row["fingerprint"],
            document_uri=row["document_uri"],
            violated_directive=row["violated_directive"],
            blocked_uri=row["blocked_uri"],
            source_file=row["source_file"],
            line_number=row["line_number"],
            first_seen=_parse_iso(row["first_seen"]),
            last_seen=_parse_iso(row["last_seen"]),
            count=row["count"],
            status=ReportStatus(row["status"]),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()
