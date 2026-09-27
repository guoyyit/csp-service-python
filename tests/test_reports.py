"""Deduplication, rate limiting, aggregation and status tests."""
import pytest

from csp_service.reports import (
    ACCEPTED,
    DUPLICATE,
    RATE_LIMITED,
    STORAGE_FULL,
    RateLimitConfig,
    ReportStatus,
    ReportStore,
    fingerprint_of,
    normalize_report,
)

LEGACY = {
    "csp-report": {
        "document-uri": "http://app/page",
        "violated-directive": "script-src 'self'",
        "blocked-uri": "http://evil/a.js",
        "source-file": "http://app/page",
        "line-number": 12,
    }
}

REPORTING_API = [
    {
        "type": "csp-violation",
        "body": {
            "documentURL": "http://app/page",
            "effective-directive": "script-src",
            "blockedURL": "http://evil/a.js",
            "sourceFile": "http://app/page",
            "lineNumber": 12,
        },
    }
]


@pytest.fixture
def store():
    s = ReportStore(None, RateLimitConfig(window_seconds=60, max_events_per_window=5, max_records=10))
    yield s
    s.close()


def test_legacy_and_reporting_api_normalize_to_same_fingerprint():
    a = normalize_report(LEGACY)
    b = normalize_report(REPORTING_API)
    assert fingerprint_of(a) == fingerprint_of(b)
    assert a["violated_directive"] == "script-src"


def test_single_reporting_api_item_shape():
    single = {
        "type": "csp-violation",
        "body": {
            "documentURL": "http://app/page",
            "effective-directive": "script-src",
            "blockedURL": "http://evil/a.js",
            "sourceFile": "http://app/page",
            "lineNumber": 12,
        },
    }
    fields = normalize_report(single)
    assert fields["document_uri"] == "http://app/page"
    assert fields["violated_directive"] == "script-src"
    assert fields["blocked_uri"] == "http://evil/a.js"
    assert fields["line_number"] == 12
    # same violation in any of the three shapes shares one fingerprint
    assert fingerprint_of(fields) == fingerprint_of(normalize_report(LEGACY))


def test_first_report_accepted_then_duplicate(store):
    event, reason = store.add(LEGACY)
    assert reason is ACCEPTED
    assert event.count == 1
    event2, reason2 = store.add(LEGACY)
    assert reason2 is DUPLICATE
    assert event2.count == 2
    assert len(store.query()) == 1
    assert store.query()[0].count == 2


def test_rate_limiter_rejects_flood(store):
    for i in range(5):
        _, reason = store.add(
            {"csp-report": {"document-uri": f"http://app/{i}", "violated-directive": "img-src"}}
        )
        assert reason is ACCEPTED
    # 6th within the window is rate-limited even if unique
    _, reason = store.add({"csp-report": {"document-uri": "http://app/flood"}})
    assert reason is RATE_LIMITED
    # rejected submission creates no record
    assert store.total_records() == 5


def test_rate_limit_window_reopens(store):
    from datetime import datetime, timedelta, timezone

    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    store._clock = lambda: base
    for i in range(5):
        store.add({"csp-report": {"document-uri": f"http://app/{i}"}})
    assert store.add({"csp-report": {"document-uri": "http://new"}})[1] is RATE_LIMITED
    store._clock = lambda: base + timedelta(seconds=61)
    assert store.add({"csp-report": {"document-uri": "http://new"}})[1] is ACCEPTED


def test_storage_cap_bounds_growth(store):
    # cap max_records=10; limit window is 5/min, so widen it for this test
    store.limit = RateLimitConfig(window_seconds=60, max_events_per_window=10_000, max_records=10)
    for i in range(10):
        assert store.add({"csp-report": {"document-uri": f"http://app/{i}"}})[1] is ACCEPTED
    _, reason = store.add({"csp-report": {"document-uri": "http://overflow"}})
    assert reason is STORAGE_FULL
    assert store.total_records() == 10


def test_duplicates_of_existing_records_never_grow_storage(store):
    store.limit = RateLimitConfig(window_seconds=60, max_events_per_window=10_000, max_records=10)
    store.add(LEGACY)
    for _ in range(20):
        _, reason = store.add(LEGACY)
        assert reason is DUPLICATE
    assert store.total_records() == 1


def test_aggregate_groups_by_directive(store):
    store.add({"csp-report": {"document-uri": "a", "violated-directive": "script-src"}})
    store.add({"csp-report": {"document-uri": "a", "violated-directive": "script-src"}})
    store.add({"csp-report": {"document-uri": "b", "violated-directive": "style-src"}})
    groups = store.aggregate()
    assert groups["script-src"] == {"event_count": 1, "report_count": 2, "open_count": 1}
    assert groups["style-src"]["event_count"] == 1


def test_mark_handled_and_status_filter(store):
    event, _ = store.add(LEGACY)
    assert store.query(status=ReportStatus.OPEN)[0].fingerprint == event.fingerprint
    assert store.mark_handled(event.fingerprint) is True
    assert store.mark_handled(event.fingerprint) is True
    assert store.query(status=ReportStatus.OPEN) == []
    handled = store.query(status=ReportStatus.HANDLED)
    assert len(handled) == 1 and handled[0].status is ReportStatus.HANDLED
    assert store.mark_handled("nonexistent") is False


def test_query_pagination(store):
    store.limit = RateLimitConfig(window_seconds=60, max_events_per_window=10_000, max_records=100)
    for i in range(5):
        store.add({"csp-report": {"document-uri": f"http://app/{i}"}})
    assert len(store.query(limit=2, offset=0)) == 2
    assert len(store.query(limit=2, offset=4)) == 1


def test_concurrent_adds_are_safe():
    import threading

    s = ReportStore(None, RateLimitConfig(window_seconds=60, max_events_per_window=100_000))
    errors = []

    def worker(worker_id):
        try:
            for i in range(50):
                s.add(
                    {
                        "csp-report": {
                            "document-uri": f"http://app/w{worker_id}-{i}",
                            "violated-directive": "script-src",
                        }
                    }
                )
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert s.total_records() == 500
    s.close()
