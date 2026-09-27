"""Report records survive service restart; status is preserved."""
from csp_service.reports import RateLimitConfig, ReportStatus, ReportStore

PAYLOAD_A = {
    "csp-report": {
        "document-uri": "http://app/a",
        "violated-directive": "script-src 'self'",
        "blocked-uri": "http://evil/x.js",
        "line-number": 3,
    }
}
PAYLOAD_B = {
    "csp-report": {
        "document-uri": "http://app/b",
        "violated-directive": "img-src",
        "blocked-uri": "http://evil/p.png",
    }
}


def test_records_survive_restart(tmp_path):
    db_path = str(tmp_path / "reports.db")
    store = ReportStore(db_path)
    event_a, _ = store.add(PAYLOAD_A)
    store.add(PAYLOAD_B)
    store.add(PAYLOAD_A)  # duplicate bump
    store.mark_handled(event_a.fingerprint)
    store.close()

    reopened = ReportStore(db_path)
    rows = {e.fingerprint: e for e in reopened.query()}
    assert len(rows) == 2

    restored_a = rows[event_a.fingerprint]
    assert restored_a.count == 2
    assert restored_a.status is ReportStatus.HANDLED
    assert restored_a.violated_directive == "script-src"

    open_events = reopened.query(status=ReportStatus.OPEN)
    assert len(open_events) == 1
    assert open_events[0].violated_directive == "img-src"

    aggregate = reopened.aggregate()
    assert aggregate["script-src"]["report_count"] == 2
    assert aggregate["script-src"]["open_count"] == 0
    reopened.close()


def test_aggregation_and_handled_marking_persist_after_second_restart(tmp_path):
    db_path = str(tmp_path / "reports2.db")
    first = ReportStore(db_path)
    event, _ = first.add(PAYLOAD_A)
    first.mark_handled(event.fingerprint)
    first.close()

    second = ReportStore(db_path)
    assert second.query(status=ReportStatus.HANDLED)[0].fingerprint == event.fingerprint
    second.close()
