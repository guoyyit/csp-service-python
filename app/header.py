"""CSP 响应头构建。"""
from __future__ import annotations

from app.models import CSPMode

ENFORCE_HEADER = "Content-Security-Policy"
REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only"

# 需要注入一次性随机数的指令
_NONCE_DIRECTIVES = ("script-src", "style-src")


def header_name_for(mode: CSPMode) -> str:
    """根据模式返回对应的响应头名称。

    两种模式下策略计算完全相同，仅写入的响应头不同：
    仅报告模式浏览器只上报不拦截，因此不会中断正常响应。
    """
    if mode is CSPMode.REPORT_ONLY:
        return REPORT_ONLY_HEADER
    return ENFORCE_HEADER


def _with_nonce(
    directives: dict[str, tuple[str, ...]], name: str, nonce: str
) -> tuple[str, ...]:
    """为指定指令追加 nonce；指令缺失时按 default-src 兜底。"""
    if name in directives:
        sources = list(directives[name])
    elif "default-src" in directives:
        sources = list(directives["default-src"])
    else:
        sources = []
    token = f"'nonce-{nonce}'"
    if token not in sources:
        sources.append(token)
    return tuple(sources)


def build_policy_header(
    directives: dict[str, tuple[str, ...]],
    *,
    nonce: str | None = None,
    report_uri: str | None = None,
) -> str:
    """把指令集合序列化为 CSP 头值。

    提供 ``nonce`` 时同时向 ``script-src`` 与 ``style-src`` 注入随机数
    （缺失则按 ``default-src`` 兜底），保证响应头与页面内容使用同一值。
    """
    merged: dict[str, tuple[str, ...]] = dict(directives)
    if nonce:
        for name in _NONCE_DIRECTIVES:
            merged[name] = _with_nonce(merged, name, nonce)
    if report_uri:
        merged["report-uri"] = (report_uri,)

    parts = [f"{name} {' '.join(sources)}".rstrip() for name, sources in merged.items()]
    return "; ".join(parts)
