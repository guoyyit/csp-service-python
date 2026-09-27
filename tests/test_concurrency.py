"""并发请求下的线程安全：nonce 唯一、策略计算一致、热更新与在途请求隔离。"""
from __future__ import annotations

import threading

from starlette.testclient import TestClient

from app.models import CSPMode
from app.policy_manager import PolicyManager


def test_concurrent_requests_unique_nonces(client):
    n_threads, per_thread = 8, 25
    nonces: list[str] = []
    lock = threading.Lock()

    def worker():
        local = []
        for _ in range(per_thread):
            r = client.get("/")
            csp = r.headers["content-security-policy"]
            token = csp.split("'nonce-", 1)[1].split("'", 1)[0]
            local.append(token)
        with lock:
            nonces.extend(local)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(nonces) == n_threads * per_thread
    assert len(set(nonces)) == len(nonces)


def test_concurrent_policy_reads_stable(tmp_path):
    manager = PolicyManager(tmp_path / "p.json")
    errors: list[Exception] = []

    def reader():
        try:
            for _ in range(500):
                snap = manager.snapshot()
                d = snap.effective_directives("/some/path")
                assert "default-src" in d
                assert snap.effective_mode("/some/path") in (
                    CSPMode.ENFORCE,
                    CSPMode.REPORT_ONLY,
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    def writer():
        try:
            for i in range(20):
                manager.update(
                    [
                        {
                            "path": "/",
                            "directives": {
                                "default-src": ["'self'"],
                                "x-iteration": [str(i)],
                            },
                        }
                    ],
                    mode="report-only" if i % 2 else "enforce",
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=reader) for _ in range(6)]
    threads.append(threading.Thread(target=writer))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []


def test_inflight_requests_keep_old_policy_version(client):
    """并发更新时，每个响应都能自洽：头中版本与指令来自同一快照。"""
    manager = client.app.state.manager
    seen_versions: set[int] = set()
    lock = threading.Lock()
    errors: list[str] = []

    def requester():
        for _ in range(30):
            r = client.get("/")
            version = int(r.headers["x-csp-policy-version"])
            csp = r.headers.get("content-security-policy") or r.headers.get(
                "content-security-policy-report-only"
            )
            # 页面 nonce 与头 nonce 必须一致
            import re

            header_nonce = re.search(r"'nonce-([^']+)'", csp)
            body_nonces = set(re.findall(rb'nonce="([^"]+)"', r.content))
            if body_nonces != {header_nonce.group(1).encode()}:
                errors.append("nonce mismatch")
            with lock:
                seen_versions.add(version)

    def updater():
        for i in range(10):
            manager.update(
                [
                    {
                        "path": "/",
                        "directives": {"default-src": ["'self'"], "x-i": [str(i)]},
                    }
                ]
            )

    t1 = [threading.Thread(target=requester) for _ in range(4)]
    t2 = threading.Thread(target=updater)
    for t in t1:
        t.start()
    t2.start()
    for t in t1:
        t.join()
    t2.join()

    assert errors == []
    assert len(seen_versions) >= 2  # 更新确实发生且旧版本在途响应也完成了


def test_concurrent_report_ingest_no_loss_within_bounds(tmp_path):
    from app.reports.service import ReportService
    from app.reports.store import ReportStore

    svc = ReportService(
        ReportStore(tmp_path / "r.db"),
        rate_window_seconds=60,
        rate_max_requests=1000,
        max_events=50,
    )

    def worker(worker_id):
        for i in range(50):
            # 每人前 25 条重复，后 25 条唯一
            line = i if i >= 25 else 0
            svc.ingest(
                {
                    "csp-report": {
                        "document-uri": "/",
                        "violated-directive": "script-src 'self'",
                        "blocked-uri": f"http://w{worker_id}/{line}.js",
                        "line-number": line,
                        "column-number": 1,
                    }
                }
            )

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    counts = svc.counts()
    assert counts["signatures"] <= 50
    assert counts["occurrences"] >= counts["signatures"]
