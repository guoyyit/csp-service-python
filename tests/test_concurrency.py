"""Concurrency: safe nonce allocation and hot config updates under load."""
import threading
import time

from fastapi.testclient import TestClient

from csp_service.app import create_app
from csp_service.config import PolicyStore, parse_config
from csp_service.nonce import NonceGenerator
from csp_service.policy import resolve_policy
from csp_service.reports import RateLimitConfig, ReportStore


def test_snapshot_taken_before_update_resolves_to_old_version():
    """An in-flight request that snapshotted before an update keeps the
    old policy even if resolution happens afterwards (result explainable
    via X-CSP-Config-Version)."""
    store = PolicyStore(
        parse_config({"default": {"directives": {"default-src": ["'self'"]}}})
    )
    in_flight = store.snapshot()
    initial_version = in_flight.version

    store.update(parse_config({"default": {"directives": {"default-src": ["'none'"]}}}))
    assert store.version() == initial_version + 1

    resolved = resolve_policy(in_flight, "/anything")
    assert resolved.config_version == initial_version
    assert resolved.directives["default-src"] == ("'self'",)


def test_concurrent_reads_while_config_updated():
    store = PolicyStore(
        parse_config({"default": {"directives": {"default-src": ["'self'"]}}})
    )
    errors: list[Exception] = []
    seen_versions: set[int] = set()
    stop = threading.Event()

    def reader():
        try:
            while not stop.is_set():
                snapshot = store.snapshot()
                resolved = resolve_policy(snapshot, "/admin/page")
                # every resolution must be internally consistent
                assert resolved.config_version == snapshot.version
                assert "default-src" in resolved.directives
                seen_versions.add(snapshot.version)
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    readers = [threading.Thread(target=reader) for _ in range(8)]
    for t in readers:
        t.start()

    for i in range(1, 31):
        store.update(
            parse_config(
                {"default": {"directives": {"default-src": [f"'self' v{i}"]}}}
            )
        )

    # let readers observe the final snapshot before stopping
    deadline = time.monotonic() + 2.0
    while 31 not in seen_versions and time.monotonic() < deadline:
        time.sleep(0.005)

    stop.set()
    for t in readers:
        t.join()
    assert errors == []
    assert store.version() == 31
    # readers must have observed both old and new snapshots
    assert 1 in seen_versions and 31 in seen_versions


def test_http_traffic_during_config_update_stays_consistent(tmp_path):
    reports = ReportStore(str(tmp_path / "c.db"), RateLimitConfig(max_events_per_window=1_000_000))
    client = TestClient(create_app(reports=reports))
    errors: list[Exception] = []
    stop = threading.Event()
    lock = threading.Lock()

    def traffic():
        try:
            while not stop.is_set():
                response = client.get("/")
                # whole response computed under exactly one config version
                assert response.headers["x-csp-config-version"].isdigit()
                assert response.headers["x-csp-mode"] in ("enforce", "report-only")
        except Exception as exc:  # pragma: no cover
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=traffic) for _ in range(4)]
    for t in threads:
        t.start()
    for i in range(20):
        mode = "report-only" if i % 2 else "enforce"
        response = client.put(
            "/csp/config",
            json={
                "default": {
                    "directives": {"default-src": [f"'self' http://cdn{i}.example.com"]},
                    "mode": mode,
                    "report_uri": "/csp/report",
                }
            },
        )
        assert response.status_code == 200

    stop.set()
    for t in threads:
        t.join()
    assert errors == []
    # final config is the last update and new requests use it
    final = client.get("/")
    assert final.headers["x-csp-config-version"] == str(21)
    assert "cdn19.example.com" in final.headers.get(
        "content-security-policy", ""
    ) or "cdn19.example.com" in final.headers.get(
        "content-security-policy-report-only", ""
    )
    reports.close()
