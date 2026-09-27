"""应用装配。"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI

from app import routes as routes_mod
from app.middleware import CSPMiddleware
from app.policy_manager import PolicyManager
from app.reports.service import ReportService
from app.reports.store import ReportStore


def create_app(
    *,
    config_path: str | Path | None = None,
    db_path: str | Path | None = None,
    report_store: ReportStore | None = None,
    report_service: ReportService | None = None,
    title: str = "CSP Service",
) -> FastAPI:
    """创建 FastAPI 应用。

    默认路径可通过环境变量覆盖，便于本地验证与测试隔离：
    ``CSP_CONFIG_PATH`` / ``CSP_DB_PATH``；显式传参优先。
    """
    config_path = config_path or os.getenv("CSP_CONFIG_PATH", "data/csp_policy.json")
    db_path = db_path or os.getenv("CSP_DB_PATH", "data/csp_reports.db")

    manager = PolicyManager(config_path)
    if report_service is not None:
        reports = report_service
    else:
        store = report_store or ReportStore(db_path)
        reports = ReportService(store)

    app = FastAPI(title=title)
    app.state.manager = manager
    app.state.reports = reports
    app.add_middleware(CSPMiddleware, manager=manager)
    app.include_router(routes_mod.create_router(manager, reports))
    return app


app = create_app()
