"""CSP 注入中间件：策略计算、随机数注入、模式处理。

关键语义：
- 请求进入时立即获取策略快照引用；后续即使配置热更新，本请求仍按旧快照计算
  （在途请求保持旧策略，结果可通过 ``X-CSP-Policy-Version`` 解释）。
- 每个响应生成一个独立 nonce，同时写入 CSP 响应头与页面 HTML，
  同一响应内一致，不同响应互不相同。
- enforce / report-only 只改变响应头名称，策略计算完全相同；
  report-only 模式绝不拦截或中断正常响应。
"""
from __future__ import annotations

import re

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.header import build_policy_header, header_name_for
from app.nonce import generate_nonce

_INLINE_TAG_RE = re.compile(rb"(<(?:script|style)\b)([^>]*>)", re.IGNORECASE)
_NONCE_ATTR_RE = re.compile(rb"""\snonce\s*=\s*("[^"]*"|'[^']*')""", re.IGNORECASE)


def inject_nonce_into_html(body: bytes, nonce: str) -> bytes:
    """为 HTML 中未带 nonce 的 ``<script>/<style>`` 开标签注入 nonce 属性。"""
    token = f' nonce="{nonce}"'.encode("ascii")

    def repl(match: re.Match[bytes]) -> bytes:
        open_tag, rest = match.group(1), match.group(2)
        if _NONCE_ATTR_RE.search(rest):
            # 已显式声明 nonce 的标签保持原值，避免覆盖
            return match.group(0)
        return open_tag + token + rest

    return _INLINE_TAG_RE.sub(repl, body)


class CSPMiddleware:
    """为每个 HTTP 响应计算策略并注入 CSP 头与内联资源随机数。"""

    def __init__(
        self,
        app: ASGIApp,
        manager,
        *,
        inject_into_html: bool = True,
    ) -> None:
        self.app = app
        self.manager = manager
        self.inject_into_html = inject_into_html

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 在请求处理开始的瞬间固定快照，整个请求使用同一版本策略
        snapshot = self.manager.snapshot()
        request_path = scope.get("path", "/")
        directives = snapshot.effective_directives(request_path)
        mode = snapshot.effective_mode(request_path)
        nonce = generate_nonce()
        csp_header = header_name_for(mode)
        csp_value = build_policy_header(
            directives, nonce=nonce, report_uri=snapshot.report_uri
        )

        start_message: Message | None = None
        content_type = ""
        body_chunks: list[bytes] = []

        async def send_wrapper(message: Message) -> None:
            nonlocal start_message, content_type

            if message["type"] == "http.response.start":
                # 暂缓发送 start，待拿到完整 body 后统一改写
                start_message = message
                content_type = Headers(scope=message).get("content-type", "")
                return

            if message["type"] == "http.response.body":
                if message.get("body"):
                    body_chunks.append(bytes(message["body"]))
                if message.get("more_body", False):
                    return
                assert start_message is not None  # ASGI 保证 start 先于 body
                body = b"".join(body_chunks)

                headers = MutableHeaders(scope=start_message)
                headers.__delitem__("Content-Security-Policy")
                headers.__delitem__("Content-Security-Policy-Report-Only")
                headers.append(csp_header, csp_value)
                headers.append("X-CSP-Policy-Version", str(snapshot.version))

                is_html = "text/html" in content_type
                if self.inject_into_html and is_html and body:
                    body = inject_nonce_into_html(body, nonce)
                    # body 长度已变化，同步修正 content-length
                    headers.__delitem__("content-length")
                    headers.append("content-length", str(len(body)))

                await send(start_message)
                await send(
                    {"type": "http.response.body", "body": body, "more_body": False}
                )
                return

            # 其余消息类型（如 trailing headers）原样转发
            await send(message)

        await self.app(scope, receive, send_wrapper)
