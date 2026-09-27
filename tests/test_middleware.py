"""nonce 生成、头构建以及中间件注入行为。"""
from __future__ import annotations

from app.header import (
    ENFORCE_HEADER,
    REPORT_ONLY_HEADER,
    build_policy_header,
    header_name_for,
)
from app.middleware import inject_nonce_into_html
from app.models import CSPMode
from app.nonce import generate_nonce


def test_nonce_unique_per_response():
    values = {generate_nonce() for _ in range(500)}
    assert len(values) == 500
    assert all(len(v) >= 24 for v in values)


def test_header_modes():
    assert header_name_for(CSPMode.ENFORCE) == ENFORCE_HEADER
    assert header_name_for(CSPMode.REPORT_ONLY) == REPORT_ONLY_HEADER


def test_header_contains_nonce_for_script_and_style():
    header = build_policy_header(
        {"default-src": ("'self'",)}, nonce="abc", report_uri="/csp/report"
    )
    assert "script-src 'self' 'nonce-abc'" in header
    assert "style-src 'self' 'nonce-abc'" in header
    assert header.endswith("report-uri /csp/report")


def test_inject_nonce_skips_existing():
    html = b'<script nonce="keep">a</script><style>b</style>'
    out = inject_nonce_into_html(html, "N")
    assert b'nonce="keep"' in out
    assert b'<style nonce="N">' in out
    assert out.count(b'nonce=') == 2


def test_page_nonce_matches_header(client):
    r = client.get("/")
    assert r.status_code == 200
    csp = r.headers.get("content-security-policy")
    assert "'nonce-" in csp
    # 从响应头取出 nonce，页面内所有内联标签必须使用同一值
    import re

    nonce = re.search(r"'nonce-([^']+)'", csp).group(1)
    body_nonces = set(re.findall(rb'nonce="([^"]+)"', r.content))
    assert body_nonces == {nonce.encode()}


def test_different_responses_have_different_nonces(client):
    import re

    def nonce_of():
        r = client.get("/")
        return re.search(rb"'nonce-([^']+)'", r.headers.get(
            "content-security-policy").encode()).group(1)

    assert nonce_of() != nonce_of()


def test_report_only_uses_report_only_header(client, app_factory):
    from starlette.testclient import TestClient

    app = app_factory()
    app.state.manager.update(
        [{"path": "/", "directives": {"default-src": ["'self'"]}}],
        mode="report-only",
    )
    with TestClient(app) as c:
        r = c.get("/")
        assert r.status_code == 200  # 仅报告模式不中断正常响应
        assert r.headers.get("content-security-policy-report-only")
        assert not r.headers.get("content-security-policy")


def test_per_route_mixed_modes(client):
    manager = client.app.state.manager
    manager.update(
        [
            {"path": "/", "directives": {"default-src": ["'self'"]}},
            {
                "path": "/admin",
                "directives": {"script-src": ["'self'"]},
                "mode": "report-only",
            },
        ]
    )
    admin = client.get("/admin")
    other = client.get("/other")
    assert admin.headers.get("content-security-policy-report-only")
    assert other.headers.get("content-security-policy")
    # 版本头可解释请求命中了哪个策略版本
    assert admin.headers["x-csp-policy-version"] == str(manager.snapshot().version)


def test_non_html_responses_get_header_only(client):
    r = client.get("/healthz")
    assert r.headers.get("content-security-policy")
    assert b"nonce=" not in r.content
