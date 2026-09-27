"""违规事件 SQLite 持久化存储。

线程安全策略：单一连接（``check_same_thread=False``）+ 进程内锁，
所有写操作在锁内完成并立即 commit，保证服务重启后记录不丢失。
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

VALID_STATUS = ("open", "resolved")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    document_uri TEXT NOT NULL DEFAULT '',
    violated_directive TEXT NOT NULL DEFAULT '',
    blocked_uri TEXT NOT NULL DEFAULT '',
    source_file TEXT NOT NULL DEFAULT '',
    line_number INTEGER NOT NULL DEFAULT 0,
    column_number INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',
    count INTEGER NOT NULL DEFAULT 1,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_last_seen ON reports(last_seen);
"""


class ReportStore:
    def __init__(self, db_path: str | Path = "data/csp_reports.db") -> None:
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            str(path), check_same_thread=False, timeout=30.0
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def upsert(
        self,
        *,
        dedup_key: str,
        document_uri: str,
        violated_directive: str,
        blocked_uri: str,
        source_file: str,
        line_number: int,
        column_number: int,
        raw: dict[str, Any],
    ) -> tuple[int, int, bool]:
        """插入新事件或对重复事件计数 +1，返回 ``(id, count, created)``。"""
        now = time.time()
        raw_json = json.dumps(raw, ensure_ascii=False)
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, count FROM reports WHERE dedup_key = ?", (dedup_key,)
            )
            row = cur.fetchone()
            if row is not None:
                self._conn.execute(
                    "UPDATE reports SET count = count + 1, last_seen = ? WHERE id = ?",
                    (now, row["id"]),
                )
                self._conn.commit()
                return row["id"], row["count"] + 1, False
            cur = self._conn.execute(
                """
                INSERT INTO reports (
                    dedup_key, document_uri, violated_directive, blocked_uri,
                    source_file, line_number, column_number, raw,
                    first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dedup_key,
                    document_uri,
                    violated_directive,
                    blocked_uri,
                    source_file,
                    line_number,
                    column_number,
                    raw_json,
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return cur.lastrowid, 1, True

    def list_reports(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(limit, 500))
        offset = max(0, offset)
        with self._lock:
            if status is not None:
                if status not in VALID_STATUS:
                    raise ValueError(f"非法状态: {status!r}")
                rows = self._conn.execute(
                    "SELECT * FROM reports WHERE status = ? "
                    "ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                    (status, limit, offset),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM reports ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def set_status(self, report_id: int, status: str) -> bool:
        """更新处理状态（可在 open/resolved 间反复切换），返回是否命中记录。"""
        if status not in VALID_STATUS:
            raise ValueError(f"非法状态: {status!r}")
        with self._lock:
            cur = self._conn.execute(
                "UPDATE reports SET status = ? WHERE id = ?", (status, report_id)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def aggregate(self) -> list[dict[str, Any]]:
        """按 (违规指令, 被拦截资源) 聚合出现次数与处理进度。"""
        with self._lock:
            rows = self._conn.execute(
                """
                SELECT violated_directive,
                       blocked_uri,
                       COUNT(*) AS signatures,
                       COALESCE(SUM(count), 0) AS total_occurrences,
                       COALESCE(SUM(CASE WHEN status = 'open' THEN count ELSE 0 END), 0)
                           AS open_occurrences,
                       MIN(first_seen) AS first_seen,
                       MAX(last_seen) AS last_seen
                FROM reports
                GROUP BY violated_directive, blocked_uri
                ORDER BY total_occurrences DESC
                """
            ).fetchall()
        return [dict(r) for r in rows]

    def prune(self, max_rows: int) -> int:
        """超过容量上限时按最旧优先删除，返回删除条数，保证存储有界。"""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
            excess = total - max_rows
            if excess <= 0:
                return 0
            self._conn.execute(
                """
                DELETE FROM reports WHERE id IN (
                    SELECT id FROM reports ORDER BY id ASC LIMIT ?
                )
                """,
                (excess,),
            )
            self._conn.commit()
            return excess

    def counts(self) -> dict[str, int]:
        with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*) AS signatures,
                       COALESCE(SUM(count), 0) AS occurrences,
                       COALESCE(SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END), 0)
                           AS open_signatures,
                       COALESCE(SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END), 0)
                           AS resolved_signatures
                FROM reports
                """
            ).fetchone()
        return dict(row)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["raw"] = json.loads(data["raw"])
        return data

    def close(self) -> None:
        with self._lock:
            self._conn.close()
