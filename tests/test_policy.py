"""Policy inheritance, override and rendering tests."""
from csp_service.config import PolicyConfig, PolicyMode, PolicyStore, ScopePolicy, parse_config
from csp_service.policy import render_header, resolve_policy


def make_config():
    return parse_config(
        {
            "default": {
                "directives": {
                    "default-src": ["'self'"],
                    "img-src": ["*"],
                },
                "mode": "enforce",
                "report_uri": "/csp/report",
            },
            "scopes": [
                {
                    "prefix": "/admin",
                    "directives": {"script-src": ["'self'", "cdn.example.com"]},
                },
                {
                    "prefix": "/admin/panel",
                    "mode": "report-only",
                    "directives": {"style-src": ["'self'"]},
                },
                {
                    "prefix": "/static",
                    "mode": "report-only",
                },
            ],
        }
    )


def test_default_policy_used_for_root():
    resolved = resolve_policy(make_config(), "/home")
    assert resolved.matched_prefix == "/"
    assert resolved.mode is PolicyMode.ENFORCE
    assert dict(resolved.directives)["default-src"] == ("'self'",)


def test_scope_inherits_default_directives():
    resolved = resolve_policy(make_config(), "/admin/users")
    assert resolved.matched_prefix == "/admin"
    # inherited directives
    assert resolved.directives["default-src"] == ("'self'",)
    assert resolved.directives["img-src"] == ("*",)
    # overridden directive is replaced wholesale
    assert resolved.directives["script-src"] == ("'self'", "cdn.example.com")
    assert resolved.mode is PolicyMode.ENFORCE


def test_nested_scope_inherits_parent_and_overrides_mode():
    resolved = resolve_policy(make_config(), "/admin/panel/x")
    assert resolved.matched_prefix == "/admin/panel"
    assert resolved.mode is PolicyMode.REPORT_ONLY
    assert resolved.directives["script-src"] == ("'self'", "cdn.example.com")
    assert resolved.directives["style-src"] == ("'self'",)
    assert resolved.directives["img-src"] == ("*",)
    assert resolved.report_uri == "/csp/report"


def test_prefix_matching_requires_segment_boundary():
    cfg = make_config()
    assert resolve_policy(cfg, "/administrator").matched_prefix == "/"
    assert resolve_policy(cfg, "/static/app.js").matched_prefix == "/static"
    assert resolve_policy(cfg, "/staticx").matched_prefix == "/"


def test_mode_override_without_directives():
    resolved = resolve_policy(make_config(), "/static/x.css")
    assert resolved.mode is PolicyMode.REPORT_ONLY
    assert resolved.directives["default-src"] == ("'self'",)


def test_render_header_basic():
    resolved = resolve_policy(make_config(), "/")
    header = render_header(resolved)
    assert "default-src 'self'" in header
    assert "report-uri /csp/report" in header


def test_render_header_nonce_added_to_script_and_style():
    resolved = resolve_policy(make_config(), "/")
    header = render_header(resolved, "abc")
    assert "'nonce-abc'" in header
    assert "script-src 'self' 'nonce-abc'" in header
    # style-src falls back to default-src sources
    assert "style-src 'self' 'nonce-abc'" in header
    # nonce appears exactly once per directive
    assert header.count("'nonce-abc'") == 2


def test_render_header_no_nonce_by_default():
    header = render_header(resolve_policy(make_config(), "/"))
    assert "nonce" not in header


def test_resolve_carries_config_version():
    store = PolicyStore(make_config())
    v1 = resolve_policy(store.snapshot(), "/admin")
    old_snapshot = store.snapshot()
    store.update(
        parse_config(
            {"default": {"directives": {"default-src": ["'none'"]}}}
        )
    )
    # in-flight snapshot remains on old version
    assert resolve_policy(old_snapshot, "/admin").config_version == v1.config_version
    assert resolve_policy(store.snapshot(), "/admin").directives["default-src"] == (
        "'none'",
    )
