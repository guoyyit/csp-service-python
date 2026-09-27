"""违规上报的去重、限速、容量裁剪、持久化与查询聚合。"""
from __future__ import annotations

from app.reports.ratelimit import SlidingWindowRateLimiter
from app.reports.service import ReportService
from app.reports.store import ReportStore

REPORT = {
    "csp-report": {
        "document-uri": "http://test/page",
        "violated-directive": "script-src 'self'",
        "blocked-uri": "http://evil/a.js",
        "source-file": "",
        "line-number": 3,
        "column-number": 8,
    }
}


def make_service(tmp_path, **kw):
    defaults = dict(rate_window_seconds=60, rate_max_requests=5, max_events=10)
    defaults.update(kw)
    return ReportService(ReportStore(tmp_path / "r.db"), **defaults)


def variant(blocked="http://evil/a.js", line=3):
    p = {"csp-report": dict(REPORT["csp-report"])}
    p["csp-report"]["blocked-uri"] = blocked
    p["csp-report"]["line-number"] = line
    return p


def test_dedup_increments_count(tmp_path):
    svc = make_service(tmp_path)
    r1 = svc.ingest(REPORT)
    r2 = svc.ingest(REPORT)
    assert r1.accepted and not r1.duplicate
    assert r2.duplicate and r2.id == r1.id and r2.count == 2
    assert svc.counts()["signatures"] == 1
    assert svc.counts()["occurrences"] == 2


def test_rate_limit_same_signature(tmp_path):
    svc = make_service(tmp_path, rate_max_requests=2)
    accepted = [svc.ingest(REPORT).accepted for _ in range(4)]
    assert accepted == [True, True, False, False]


def test_rate_limit_isolated_by_signature(tmp_path):
    svc = make_service(tmp_path, rate_max_requests=1)
    assert svc.ingest(variant(blocked="http://a/1")).accepted
    assert svc.ingest(variant(blocked="http://a/1")).reason == "rate_limited"
    # 不同违规签名互不影响
    assert svc.ingest(variant(blocked="http://a/2")).accepted


def test_sliding_window_recovers():
    rl = SlidingWindowRateLimiter(window_seconds=10, max_requests=1)
    assert rl.allow("k", now=0)
    assert not rl.allow("k", now=9)
    assert rl.allow("k", now=11)


def test_limiter_tracking_is_bounded():
    rl = SlidingWindowRateLimiter(
        window_seconds=1000, max_requests=1, max_tracked_keys=5
    )
    for i in range(50):
        rl.allow(f"k{i}", now=i)
    assert rl.size() <= 5


def test_storage_bounded_against_flood(tmp_path):
    svc = make_service(tmp_path, rate_max_requests=100, max_events=5)
    for i in range(30):
        svc.ingest(variant(blocked=f"http://evil/{i}.js", line=i))
    counts = svc.counts()
    assert counts["signatures"] <= 5


def test_invalid_payloads_rejected(tmp_path):
    svc = make_service(tmp_path)
    assert not svc.ingest("not-a-dict").accepted
    assert not svc.ingest({"csp-report": [1, 2]}).accepted
    huge = {"csp-report": dict(REPORT["csp-report"]), "blob": "x" * 20000}
    result = svc.ingest(huge)
    assert not result.accepted and result.reason == "payload_too_large"


def test_status_flow_and_filter(tmp_path):
    svc = make_service(tmp_path)
    rid = svc.ingest(REPORT).id
    assert svc.list_reports(status="open")[0]["id"] == rid
    assert svc.set_status(rid, "resolved")
    assert svc.list_reports(status="resolved")[0]["status"] == "resolved"
    assert svc.list_reports(status="open") == []
    # 允许重新打开
    assert svc.set_status(rid, "open")
    assert svc.list_reports(status="open")[0]["id"] == rid
    assert not svc.set_status(9999, "resolved")


def test_aggregate_groups(tmp_path):
    svc = make_service(tmp_path, rate_max_requests=100)
    svc.ingest(REPORT)
    svc.ingest(REPORT)
    svc.ingest(variant(blocked="http://evil/b.js"))
    groups = svc.aggregate()
    assert len(groups) == 2
    top = groups[0]
    assert top["violated_directive"] == "script-src"
    assert top["total_occurrences"] == 2


def test_reports_survive_restart(tmp_path):
    db = tmp_path / "r.db"
    svc1 = make_service(tmp_path)
    rid = svc1.ingest(REPORT).id
    svc1.ingest(REPORT)
    svc1.set_status(rid, "resolved")
    svc1.close()

    svc2 = ReportService(ReportStore(db))
    counts = svc2.counts()
    assert counts["signatures"] == 1
    assert counts["occurrences"] == 2
    assert counts["resolved_signatures"] == 1
    assert svc2.list_reports()[0]["raw"]["csp-report"]["blocked-uri"] == (
        "http://evil/a.js"
    )


# ---- HTTP 层 -------------------------------------------------------------

def post_report(client, payload=None):
    return client.post("/csp/report", json=payload if payload is not None else REPORT)


def test_report_http_and_dedup(client):
    r1 = post_report(client)
    r2 = post_report(client)
    assert r1.status_code == 202 and r1.json()["accepted"]
    assert r2.json()["duplicate"] is True
    listed = client.get("/csp/reports").json()
    assert listed["count"] == 1
    assert listed["items"][0]["count"] == 2


def test_report_rate_limited_http(client):
    app = client.app
    app.state.reports._limiter = SlidingWindowRateLimiter(60, 1)
    assert post_report(client).json()["accepted"]
    body = post_report(client).json()
    assert body["accepted"] is False and body["reason"] == "rate_limited"


def test_status_endpoint_http(client):
    rid = post_report(client).json()["id"]
    assert client.patch(f"/csp/reports/{rid}", json={"status": "resolved"}).status_code == 200
    assert client.get("/csp/reports?status=resolved").json()["count"] == 1
    assert client.patch("/csp/reports/9999", json={"status": "open"}).status_code == 404


def test_restart_via_http(tmp_path, app_factory):
    from starlette.testclient import TestClient

    app1 = app_factory(db_path=tmp_path / "r.db", config_path=tmp_path / "p.json")
    with TestClient(app1) as c:
        c.post("/csp/report", json=REPORT)
    # 用相同数据路径重新装配应用，模拟重启
    app2 = app_factory(db_path=tmp_path / "r.db", config_path=tmp_path / "p2.json")
    with TestClient(app2) as c:
        items = c.get("/csp/reports").json()["items"]
        assert len(items) == 1 and items[0]["count"] == 1
