"""策略快照管理：默认策略、继承覆盖、原子热更新与持久化。"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from app.models import CSPMode, PolicySnapshot, RouteRule

DEFAULT_REPORT_URI = "/csp/report"


def default_rules() -> list[dict[str, Any]]:
    """内置默认策略：未配置任何路由时使用。"""
    return [
        {
            "path": "/",
            "directives": {
                "default-src": ["'self'"],
                "img-src": ["'self'", "data:"],
                "script-src": ["'self'"],
                "style-src": ["'self'"],
                "object-src": ["'none'"],
                "base-uri": ["'self'"],
                "frame-ancestors": ["'none'"],
            },
        }
    ]


class PolicyManager:
    """持有当前生效的不可变 :class:`PolicySnapshot`，并支持原子热更新。"""

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        default_report_uri: str = DEFAULT_REPORT_URI,
    ) -> None:
        self._lock = threading.RLock()
        self._config_path = Path(config_path) if config_path else None
        self._snapshot: PolicySnapshot
        if self._config_path and self._config_path.exists():
            data = json.loads(self._config_path.read_text(encoding="utf-8"))
            self._snapshot = self._build_snapshot(
                data.get("rules", default_rules()),
                mode=data.get("mode", CSPMode.ENFORCE.value),
                report_uri=data.get("report_uri", default_report_uri),
                version=data.get("version", 1),
            )
        else:
            self._snapshot = self._build_snapshot(
                default_rules(),
                mode=CSPMode.ENFORCE.value,
                report_uri=default_report_uri,
                version=1,
            )
            self._persist_locked()

    # ---- 对外接口 --------------------------------------------------------

    def snapshot(self) -> PolicySnapshot:
        """获取当前生效快照（锁保护下的原子引用读取）。"""
        with self._lock:
            return self._snapshot

    def update(
        self,
        rules: list[dict[str, Any]],
        *,
        mode: str = CSPMode.ENFORCE.value,
        report_uri: str | None = None,
    ) -> PolicySnapshot:
        """原子热更新。

        先在锁外完成解析与校验，再在锁内整体替换快照：
        任何在途请求持有的仍是旧快照引用，计算结果不受影响。
        """
        new_snapshot = self._build_snapshot(
            rules,
            mode=mode,
            report_uri=report_uri or self._snapshot.report_uri,
            version=self._snapshot.version + 1,
        )
        with self._lock:
            self._snapshot = new_snapshot
            self._persist_locked()
            return new_snapshot

    def current_config(self) -> dict[str, Any]:
        """导出当前配置（可用于查询与持久化）。"""
        snap = self.snapshot()
        return {
            "version": snap.version,
            "mode": snap.mode.value,
            "report_uri": snap.report_uri,
            "generated_at": snap.generated_at,
            "rules": [
                {
                    "path": r.path,
                    "directives": {k: list(v) for k, v in r.directives.items()},
                    **({"mode": r.mode.value} if r.mode is not None else {}),
                }
                for r in snap.rules
            ],
        }

    def close(self) -> None:
        """无后台资源，保留接口以便统一生命周期管理。"""

    # ---- 内部实现 --------------------------------------------------------

    @staticmethod
    def _build_snapshot(
        raw_rules: list[dict[str, Any]],
        *,
        mode: str,
        report_uri: str,
        version: int,
    ) -> PolicySnapshot:
        if not isinstance(raw_rules, list):
            raise ValueError("rules 必须是数组")
        parsed: list[RouteRule] = []
        seen: set[str] = set()
        for item in raw_rules:
            rule = RouteRule.from_dict(item)
            if rule.path in seen:
                raise ValueError(f"路由 {rule.path} 存在重复配置")
            seen.add(rule.path)
            parsed.append(rule)
        # 继承链必须有根；未显式配置时补一个空根规则
        if not any(r.path == "/" for r in parsed):
            parsed.insert(0, RouteRule(path="/"))
        parsed.sort(key=lambda r: (r.path.count("/"), r.path))
        return PolicySnapshot(
            version=version,
            mode=CSPMode.parse(mode),
            report_uri=report_uri,
            rules=tuple(parsed),
        )

    def _persist_locked(self) -> None:
        if not self._config_path:
            return
        path = self._config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        data = self.current_config()
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, path)
