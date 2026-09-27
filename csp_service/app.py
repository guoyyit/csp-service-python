"""FastAPI application wiring: CSP middleware, report and admin APIs."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

from .config import (
    ConfigError,
    PolicyConfig,
    PolicyMode,
    PolicyStore,
    ScopePolicy,
    parse_config,
)
from .nonce import NonceGenerator, inject_nonce
from .policy import render_header, resolve_policy
from .reports import (
    ACCEPTED,
    DUPLICATE,
    RATE_LIMITED,
    STORAGE_FULL,
    RateLimitConfig,
    ReportStatus,
    ReportStore,
)

REPORT_PATH = "/csp/report"
DEFAULT_DB_PATH = "data/csp-reports.db"

_INDEX_HTML = """<!doctype html>
<html>
<head>
  <title>CSP demo</title>
  <style>body { font-family: sans-serif; }</style>
</head>
<body>
  <h1>CSP service</h1>
  <p id="ok">loading...</p>
  <script>document.getElementById('ok').textContent = 'inline script allowed by nonce';</script>
  <script src="/static/app.js"></script>
  <p><a href="/admin">admin scope</a></p>
</body>
</html>
"""

_ADMIN_HTML = """<!doctype html>
<html>
<head><style>h1 { color: navy; }</style></head>
<body>
  <h1>Admin scope</h1>
  <script>console.log('admin inline script');</script>
</body>
</html>
"""


def default_config() -> PolicyConfig:
    """Default demo configuration."""
    return parse_config(
        {
            "default": {
                "prefix": "/",
                "directives": {
                    "default-src": ["'self'"],
                    "img-src": ["'self'", "data:"],
                },
                "mode": PolicyMode.ENFORCE.value,
                "report_uri": REPORT_PATH,
            },
            "scopes": [
                {
                    "prefix": "/admin",
                    "directives": {
                        "script-src": ["'self'"],
                        "style-src": ["'self'"],
                    },
                }
            ],
        }
    )


def config_to_dict(config: PolicyConfig) -> dict[str, Any]:
    data = asdict(config)
    # directives become lists in JSON form
    default = data["default"]
    default["directives"] = dict(default["directives"])
    for scope in data["scopes"]:
        scope["directives"] = dict(scope["directives"])
    return data


def create_app(
    store: PolicyStore | None = None,
    reports: ReportStore | None = None,
    report_db_path: str | None = DEFAULT_DB_PATH,
) -> FastAPI:
    """Build the FastAPI application.

    *store* holds the hot-reloadable policy config; *reports* is the
    persisted violation store. Tests may inject either component.
    """
    app = FastAPI(title="csp-service", version="0.1.0")
    app.state.policy_store = store or PolicyStore(default_config())
    app.state.nonce_generator = NonceGenerator()
    app.state.report_store = reports or ReportStore(report_db_path)

    # ---------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return _INDEX_HTML

    @app.get("/admin", response_class=HTMLResponse)
    def admin() -> str:
        return _ADMIN_HTML

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # -------------------------------------------------------- CSP middleware
    @app.middleware("http")
    async def csp_middleware(request: Request, call_next):
        # Snapshot ONCE per request: a concurrent config update changes only
        # later requests; this response is computed entirely from the frozen
        # snapshot it started with.
        config = request.app.state.policy_store.snapshot()
        resolved = resolve_policy(config, request.url.path)
        nonce = request.app.state.nonce_generator.generate()
        header_value = render_header(resolved, nonce)

        response: Response = await call_next(request)

        if resolved.mode is PolicyMode.ENFORCE:
            response.headers["Content-Security-Policy"] = header_value
        else:
            # report-only never blocks; policy computation is identical
            response.headers["Content-Security-Policy-Report-Only"] = header_value
        response.headers["X-CSP-Config-Version"] = str(resolved.config_version)
        response.headers["X-CSP-Matched-Prefix"] = resolved.matched_prefix
        response.headers["X-CSP-Mode"] = resolved.mode.value

        content_type = response.headers.get("content-type", "")
        if content_type.startswith("text/html"):
            body = b"".join([chunk async for chunk in response.body_iterator])
            html = body.decode(response.charset or "utf-8")
            injected = inject_nonce(html, nonce)
            return _rebuild(response, injected.encode("utf-8"))

        return response

    # ------------------------------------------------------- report ingest
    @app.post(REPORT_PATH)
    async def receive_report(request: Request) -> JSONResponse:
        try:
            payload = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="invalid JSON body")

        entries = payload if isinstance(payload, list) else [payload]
        results: list[dict[str, Any]] = []
        worst = 202
        for entry in entries:
            event, reason = request.app.state.report_store.add(entry)
            status_code = {
                ACCEPTED: 202,
                DUPLICATE: 202,
                RATE_LIMITED: 429,
                STORAGE_FULL: 507,
            }[reason]
            worst = max(worst, status_code)
            results.append(
                {
                    "reason": reason,
                    "fingerprint": event.fingerprint if event else None,
                    "count": event.count if event else None,
                }
            )
        return JSONResponse(
            {"results": results if len(results) > 1 else results[0]},
            status_code=worst,
        )

    # ------------------------------------------------------ report queries
    @app.get("/csp/reports")
    def list_reports(
        request: Request,
        status: str | None = Query(default=None, pattern="^(open|handled)$"),
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        st = ReportStatus(status) if status else None
        events = request.app.state.report_store.query(st, limit, offset)
        return {"reports": [e.to_dict() for e in events], "limit": limit, "offset": offset}

    @app.get("/csp/reports/aggregate")
    def aggregate_reports(request: Request) -> dict[str, Any]:
        return {"groups": request.app.state.report_store.aggregate()}

    @app.post("/csp/reports/{fingerprint}/handled")
    def mark_handled(fingerprint: str, request: Request) -> dict[str, str]:
        if not request.app.state.report_store.mark_handled(fingerprint):
            raise HTTPException(status_code=404, detail="unknown fingerprint")
        return {"fingerprint": fingerprint, "status": ReportStatus.HANDLED.value}

    # ------------------------------------------------------- config admin
    @app.get("/csp/config")
    def get_config(request: Request) -> dict[str, Any]:
        return config_to_dict(request.app.state.policy_store.snapshot())

    @app.put("/csp/config")
    async def put_config(request: Request) -> dict[str, Any]:
        try:
            payload = await request.json()
            new_config = parse_config(payload)
        except ConfigError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        old = request.app.state.policy_store.update(new_config)
        current = request.app.state.policy_store.snapshot()
        return {
            "updated": True,
            "previous_version": old.version,
            "config": config_to_dict(current),
        }

    return app


def _rebuild(response: Response, body: bytes) -> Response:
    """Recreate a response with a replaced body, preserving headers/status."""
    headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
    return Response(
        content=body,
        status_code=response.status_code,
        headers=headers,
        media_type=response.media_type,
    )
