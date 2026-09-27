"""Nonce generation and HTML injection tests."""
import threading

import pytest

from csp_service.nonce import NonceGenerator, inject_nonce


def test_nonce_unique_across_responses():
    gen = NonceGenerator()
    values = {gen.generate() for _ in range(500)}
    assert len(values) == 500


def test_nonce_urlsafe_and_long_enough():
    value = NonceGenerator().generate()
    assert value.isascii()
    assert len(value) >= 20


def test_nonce_thread_safe_uniqueness():
    gen = NonceGenerator()
    results: list[str] = []
    lock = threading.Lock()

    def worker():
        values = [gen.generate() for _ in range(100)]
        with lock:
            results.extend(values)

    threads = [threading.Thread(target=worker) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 2000
    assert len(set(results)) == 2000


@pytest.mark.parametrize(
    "html,expected",
    [
        ("<script>a</script>", "<script nonce=\"N\">a</script>"),
        ("<style>x{}</style>", "<style nonce=\"N\">x{}</style>"),
        ("<SCRIPT>a</SCRIPT>", "<SCRIPT nonce=\"N\">a</SCRIPT>"),
        ("<script type=\"text/javascript\">a</script>",
         "<script type=\"text/javascript\" nonce=\"N\">a</script>"),
        ("<script   >a</script>", "<script nonce=\"N\">a</script>"),
    ],
)
def test_inject_adds_nonce_to_inline_tags(html, expected):
    assert inject_nonce(html, "N") == expected


def test_inject_skips_external_scripts():
    html = "<script src=\"/a.js\"></script>"
    assert inject_nonce(html, "N") == html


def test_inject_keeps_existing_nonce():
    html = "<script nonce=\"preexisting\">a</script>"
    assert inject_nonce(html, "N") == html


def test_inject_uses_same_nonce_everywhere():
    html = "<script>a</script><style>x</style><script>b</script>"
    out = inject_nonce(html, "SAME")
    assert out.count("nonce=\"SAME\"") == 3
