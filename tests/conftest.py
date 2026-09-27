"""测试共享夹具：每个用例使用独立临时目录，避免污染默认 data/。"""
from __future__ import annotations

import pytest

from app.app import create_app


@pytest.fixture()
def app_factory(tmp_path):
    def _factory(**overrides):
        config_path = tmp_path / "policy.json"
        db_path = tmp_path / "reports.db"
        return create_app(
            config_path=overrides.pop("config_path", config_path),
            db_path=overrides.pop("db_path", db_path),
            **overrides,
        )

    return _factory


@pytest.fixture()
def client(app_factory):
    from starlette.testclient import TestClient

    app = app_factory()
    with TestClient(app) as c:
        c.app = app
        yield c
