"""HTTP 路由：演示页面、策略管理、违规上报与查询。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

DEMO_HTML = """<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>CSP 演示页</title>
<style>body{font-family:sans-serif;margin:2rem}</style>
</head>
<body>
<h1>内容安全策略演示</h1>
<p>本页内联脚本与样式均由中间件注入一次性 nonce，响应头与页面内容一致。</p>
<script>document.addEventListener('DOMContentLoaded',function(){
  document.getElementById('ok').textContent='内联脚本已被 CSP 放行';
});</script>
<p id="ok"></p>
</body></html>"""


class PolicyUpdateIn(BaseModel):
    rules: list[dict[str, Any]] = Field(default_factory=list)
    mode: str = "enforce"
    report_uri: str | None = None


class StatusUpdateIn(BaseModel):
    status: str


def create_router(manager, reports) -> APIRouter:
    router = APIRouter()

    @router.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @router.get("/", response_class=None)
    def demo_page() -> bytes:
        # 返回原始 HTML，由 CSP 中间件注入 nonce
        from fastapi import Response

        return Response(content=DEMO_HTML, media_type="text/html")

    # ---- 策略管理 --------------------------------------------------------

    @router.get("/csp/config")
    def get_config() -> dict[str, Any]:
        return manager.current_config()

    @router.put("/csp/config")
    def put_config(body: PolicyUpdateIn) -> dict[str, Any]:
        try:
            snapshot = manager.update(
                body.rules, mode=body.mode, report_uri=body.report_uri
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "updated": True,
            "version": snapshot.version,
            "config": manager.current_config(),
        }

    # ---- 违规上报 --------------------------------------------------------

    @router.post("/csp/report", status_code=202)
    async def receive_report(request: Request) -> dict[str, Any]:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid_json") from None
        result = reports.ingest(payload)
        return {
            "accepted": result.accepted,
            "reason": result.reason,
            "id": result.id,
            "count": result.count,
            "duplicate": result.duplicate,
            "pruned": result.pruned,
        }

    @router.get("/csp/reports")
    def list_reports(
        status: str | None = None, limit: int = 100, offset: int = 0
    ) -> dict[str, Any]:
        try:
            items = reports.list_reports(
                status=status, limit=limit, offset=offset
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"items": items, "count": len(items)}

    @router.get("/csp/reports/aggregate")
    def aggregate_reports() -> dict[str, Any]:
        return {"groups": reports.aggregate()}

    @router.get("/csp/reports/counts")
    def report_counts() -> dict[str, int]:
        return reports.counts()

    @router.patch("/csp/reports/{report_id}")
    def update_report_status(report_id: int, body: StatusUpdateIn) -> dict[str, Any]:
        try:
            updated = reports.set_status(report_id, body.status)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not updated:
            raise HTTPException(status_code=404, detail="report_not_found")
        return {"id": report_id, "status": body.status}

    return router
