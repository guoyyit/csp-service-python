"""HTTP-level tests: nonce consistency, modes, reports, hot reload."""
import re

import pytest
from fastapi.testclient import TestClient

from csp_service.app import create_app
from csp_service.config import PolicyStore, parse_config
from csp_service.reports import RateLimitConfig, ReportStore


@pytest.fixture
def client(tmp_path):
    reports = ReportStore(str(tmp_path / "reports.db"), RateLimitConfig(max_events_per_window=1000))
    application = create_app(reports=reports, report_db_path=None)
    with TestClient(application) as c:
        yield c
    reports.close()


NONCE_RE = re.compile(r'nonce="([^"]+)"')


# --------------------------------------------------------------- nonce
def test_header_and_body_share_single_nonce(client):
    response = client.get("/")
    assert response.status_code == 200
    nonces = set(NONCE_RE.findall(response.text))
    assert len(nonces) == 1
    nonce = next(iter(nonces))
    assert f"'nonce-{nonce}'" in response.headers["content-security-policy"]


def test_different_responses_get_different_nonces(client):
    n1 = NONCE_RE.findall(client.get("/").text)
    n2 = NONCE_RE.findall(client.get("/").text)
    assert set(n1).isdisjoint(set(n2))


def test_non_html_response_has_header_but_unchanged_body(client):
    response = client.get("/healthz")
    assert "content-security-policy" in response.headers
    assert "nonce" not in response.text


# -------------------------------------------------------------- modes
def test_enforce_header_used_by_default(client):
    response = client.get("/")
    assert "content-security-policy" in response.headers
    assert "content-security-policy-Report-Only".lower() not in {
        k.lower() for k in response.headers
    }
    assert response.headers["x-csp-mode"] == "enforce"


def test_report_only_mode_never_sends_enforce_header(client):
    client.put(
        "/csp/config",
        json={
            "default": {
                "directives": {"default-src": ["'self'"]},
                "mode": "report-only",
                "report_uri": "/csp/report",
            }
        },
    )
    response = client.get("/")
    assert response.status_code == 200  # page still served normally
    assert "content-security-policy-report-only" in response.headers
    assert "content-security-policy" not in response.headers
    assert response.headers["x-csp-mode"] == "report-only"


def test_mode_switch_does_not_change_policy(client):
    def policy_header():
        r = client.get("/")
        return (
            r.headers.get("content-security-policy")
            or r.headers.get("content-security-policy-report-only")
        )

    enforce_value = policy_header()
    client.put(
        "/csp/config",
        json={
            "default": {
                "directives": {"default-src": ["'self'"], "img-src": ["'self'", "data:"]},
                "mode": "report-only",
                "report_uri": "/csp/report",
            }
        },
    )
    report_only_value = policy_header()
    assert enforce_value.replace("'nonce-" + re.search(r"'nonce-([^']+)'", enforce_value).group(1),
                                 "'nonce-X'") == report_only_value.replace(
        "'nonce-" + re.search(r"'nonce-([^']+)'", report_only_value).group(1), "'nonce-X'")


def test_scope_mode_override(client):
    client.put(
        "/csp/config",
        json={
            "default": {
                "directives": {"default-src": ["'self'"]},
                "mode": "enforce",
                "report_uri": "/csp/report",
            },
            "scopes": [{"prefix": "/admin", "mode": "report-only"}],
        },
    )
    root = client.get("/")
    admin = client.get("/admin")
    assert "content-security-policy" in root.headers
    assert "content-security-policy-report-only" in admin.headers
    assert admin.headers["x-csp-matched-prefix"] == "/admin"


# ------------------------------------------------------- report endpoints
def test_report_lifecycle_over_http(client):
    payload = {
        "csp-report": {
            "document-uri": "http://app/",
            "violated-directive": "script-src 'self'",
            "blocked-uri": "http://evil/a.js",
        }
    }
    assert client.post("/csp/report", json=payload).status_code == 202
    dup = client.post("/csp/report", json=payload)
    assert dup.status_code == 202
    assert dup.json()["results"]["reason"] == "duplicate"

    listing = client.get("/csp/reports").json()["reports"]
    assert len(listing) == 1 and listing[0]["count"] == 2

    fingerprint = listing[0]["fingerprint"]
    assert client.post(f"/csp/reports/{fingerprint}/handled").status_code == 200
    assert (
        client.post("/csp/reports/unknown/handled").status_code == 404
    )
    handled = client.get("/csp/reports", params={"status": "handled"}).json()["reports"]
    assert len(handled) == 1
    assert len(client.get("/csp/reports", params={"status": "open"}).json()["reports"]) == 0

    aggregate = client.get("/csp/reports/aggregate").json()["groups"]
    assert aggregate["script-src"]["report_count"] == 2


def test_report_endpoint_accepts_reporting_api_batch(client):
    batch = [
        {
            "type": "csp-violation",
            "body": {
                "documentURL": "http://app/batch",
                "effective-directive": "img-src",
                "blockedURL": "http://evil/img.png",
            },
        }
    ]
    response = client.post("/csp/report", json=batch)
    assert response.status_code == 202
    assert response.json()["results"]["reason"] == "accepted"


def test_invalid_report_body_rejected(client):
    response = client.post("/csp/report", content=b"not-json",
                           headers={"content-type": "application/json"})
    assert response.status_code == 400


# ------------------------------------------------------------- hot reload
def test_config_get_and_update(client):
    before = client.get("/csp/config").json()
    assert before["version"] >= 1

    update = {
        "default": {
            "directives": {"default-src": ["'none'"]},
            "mode": "enforce",
        }
    }
    result = client.put("/csp/config", json=update).json()
    assert result["updated"] is True
    assert result["config"]["version"] == before["version"] + 1

    header = client.get("/").headers["content-security-policy"]
    assert "default-src 'none'" in header


def test_invalid_config_rejected_without_replacing_active_policy(client):
    active_before = client.get("/csp/config").json()
    response = client.put("/csp/config", json={"scopes": [{"prefix": "/x"}, {"prefix": "/x"}]})
    assert response.status_code == 400
    assert client.get("/csp/config").json()["version"] == active_before["version"]
    # page still served with old policy
    assert client.get("/").status_code == 200


# ----------------------------------------------------------- concurrency
def test_concurrent_requests_each_get_consistent_nonce(client):
    import threading

    errors: list[Exception] = []
    used_nonces: list[str] = []
    lock = threading.Lock()

    def worker():
        try:
            for _ in range(20):
                response = client.get("/")
                nonces = set(NONCE_RE.findall(response.text))
                assert len(nonces) == 1
                nonce = next(iter(nonces))
                assert f"'nonce-{nonce}'" in response.headers["content-security-policy"]
                with lock:
                    used_nonces.append(nonce)
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(used_nonces) == 160
    assert len(set(used_nonces)) == 160
