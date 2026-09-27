"""内容安全策略相关数据模型与类型定义。"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_DIRECTIVE_RE = re.compile(r"^[a-z][a-z0-9-]*$")


class CSPMode(str, Enum):
    """CSP 工作模式：强制执行 / 仅报告。"""

    ENFORCE = "enforce"
    REPORT_ONLY = "report-only"

    @classmethod
    def parse(cls, value: str) -> "CSPMode":
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"非法模式 {value!r}，仅支持 'enforce' 或 'report-only'"
            ) from None


def normalize_path(path: str) -> str:
    """规范化路由范围路径：必须以 ``/`` 开头，去掉末尾多余 ``/``。"""
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError(f"路由路径必须以 '/' 开头: {path!r}")
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


def path_matches(rule_path: str, request_path: str) -> bool:
    """判断规则路径是否覆盖请求路径（按路径段边界匹配）。"""
    if rule_path == "/":
        return True
    return request_path == rule_path or request_path.startswith(rule_path + "/")


@dataclass(frozen=True)
class RouteRule:
    """单个路由范围的策略配置，路径以 ``/`` 前缀匹配，子路由继承。

    ``directives`` 中指令名到源列表的映射；子范围同名指令整体覆盖父范围，
    不同名指令则与父范围合并。``mode=None`` 表示继承更外层（或全局）模式。
    """

    path: str
    directives: dict[str, tuple[str, ...]] = field(default_factory=dict)
    mode: CSPMode | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RouteRule":
        if not isinstance(data, dict):
            raise ValueError("路由规则必须是对象")
        path = normalize_path(data.get("path", ""))
        raw_directives = data.get("directives", {})
        if not isinstance(raw_directives, dict):
            raise ValueError(f"规则 {path} 的 directives 必须是对象")
        directives: dict[str, tuple[str, ...]] = {}
        for name, sources in raw_directives.items():
            if not _DIRECTIVE_RE.match(name):
                raise ValueError(f"非法指令名: {name!r}")
            if name in ("report-uri", "report-to"):
                raise ValueError(
                    f"指令 {name!r} 由服务统一管理，不允许在规则中配置"
                )
            if isinstance(sources, str):
                sources = [sources]
            if not isinstance(sources, (list, tuple)) or not all(
                isinstance(s, str) for s in sources
            ):
                raise ValueError(f"指令 {name} 的源列表必须是字符串数组")
            directives[name] = tuple(sources)
        mode = data.get("mode")
        return cls(
            path=path,
            directives=directives,
            mode=CSPMode.parse(mode) if mode is not None else None,
        )


@dataclass(frozen=True)
class PolicySnapshot:
    """某一时刻生效的不可变策略快照。

    热更新会整体替换快照；在途请求持有旧快照引用，
    因此配置更新不影响在途请求的策略计算结果。
    """

    version: int
    mode: CSPMode
    report_uri: str
    rules: tuple[RouteRule, ...]
    generated_at: float = field(default_factory=time.time)

    def resolve(self, path: str) -> tuple[RouteRule, list[RouteRule]]:
        """返回路径命中的最深层规则与继承链（根在前，叶子在后）。

        快照中必然包含 ``/`` 根规则，因此总能命中。
        """
        chain = [r for r in self.rules if path_matches(r.path, path)]
        chain.sort(key=lambda r: r.path.count("/"))
        if not chain:  # 防御：快照缺少根规则时退回空规则
            fallback = RouteRule(path="/")
            return fallback, [fallback]
        return chain[-1], chain

    def effective_directives(self, path: str) -> dict[str, tuple[str, ...]]:
        """计算指定路径的生效指令：沿继承链合并，子范围覆盖父范围同名指令。"""
        _, chain = self.resolve(path)
        merged: dict[str, tuple[str, ...]] = {}
        for rule in chain:
            merged.update(rule.directives)
        return merged

    def effective_mode(self, path: str) -> CSPMode:
        """计算指定路径的生效模式：取继承链上最深层显式设置，缺省用全局模式。"""
        _, chain = self.resolve(path)
        for rule in reversed(chain):
            if rule.mode is not None:
                return rule.mode
        return self.mode
