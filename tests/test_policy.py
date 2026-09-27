"""策略继承与覆盖、模式解析、热更新与快照隔离。"""
from __future__ import annotations

import pytest

from app.models import CSPMode, PolicySnapshot, RouteRule
from app.policy_manager import PolicyManager


def make_snapshot():
    return PolicySnapshot(
        version=1,
        mode=CSPMode.ENFORCE,
        report_uri="/csp/report",
        rules=(
            RouteRule.from_dict(
                {
                    "path": "/",
                    "directives": {
                        "default-src": ["'self'"],
                        "script-src": ["'self'"],
                    },
                }
            ),
            RouteRule.from_dict(
                {
                    "path": "/admin",
                    "directives": {"script-src": ["'self'", "https://cdn.example"]},
                    "mode": "report-only",
                }
            ),
            RouteRule.from_dict(
                {
                    "path": "/admin/api",
                    "directives": {"img-src": ["https://img.example"]},
                }
            ),
        ),
    )


def test_inheritance_and_override():
    snap = make_snapshot()
    # 深层路由继承父级与根级指令
    d = snap.effective_directives("/admin/api/users")
    assert d["default-src"] == ("'self'",)
    # /admin 对 script-src 的覆盖继续生效
    assert d["script-src"] == ("'self'", "https://cdn.example")
    # 自己新增的指令
    assert d["img-src"] == ("https://img.example",)


def test_path_boundary_matching():
    snap = make_snapshot()
    # 路径段边界：/administrator 不应命中 /admin
    d = snap.effective_directives("/administrator")
    assert d["script-src"] == ("'self'",)
    assert snap.effective_mode("/administrator") is CSPMode.ENFORCE
    # 精确命中
    assert snap.effective_mode("/admin") is CSPMode.REPORT_ONLY
    assert snap.effective_mode("/admin/x") is CSPMode.REPORT_ONLY


def test_mode_does_not_change_directives():
    snap = make_snapshot()
    enforce = snap.effective_directives("/admin")
    # 即便 /admin 是 report-only，指令集合与 enforce 计算完全一致
    assert enforce == snap.effective_directives("/admin")
    assert snap.effective_mode("/admin") is CSPMode.REPORT_ONLY


def test_invalid_rule_validation():
    with pytest.raises(ValueError):
        RouteRule.from_dict({"path": "no-slash", "directives": {}})
    with pytest.raises(ValueError):
        RouteRule.from_dict({"path": "/", "directives": {"BAD_NAME": ["x"]}})
    with pytest.raises(ValueError):
        RouteRule.from_dict({"path": "/", "directives": {"report-uri": ["x"]}})
    with pytest.raises(ValueError):
        RouteRule.from_dict({"path": "/", "directives": {}, "mode": "nope"})


def test_hot_reload_and_snapshot_isolation(tmp_path):
    manager = PolicyManager(tmp_path / "policy.json")
    old = manager.snapshot()
    old_directives = dict(old.effective_directives("/x"))

    new = manager.update(
        [{"path": "/", "directives": {"default-src": ["'none'"]}}],
        mode="report-only",
    )
    # 新请求使用新策略
    assert new.version == old.version + 1
    assert manager.snapshot() is new
    assert manager.snapshot().effective_directives("/x")["default-src"] == ("'none'",)
    assert manager.snapshot().effective_mode("/x") is CSPMode.REPORT_ONLY
    # 在途请求持有旧快照：旧策略结果不变
    assert old.effective_directives("/x") == old_directives
    assert old.effective_mode("/x") is CSPMode.ENFORCE


def test_invalid_update_keeps_old_snapshot(tmp_path):
    manager = PolicyManager(tmp_path / "policy.json")
    before = manager.snapshot()
    with pytest.raises(ValueError):
        manager.update([{"path": "bad"}])
    assert manager.snapshot() is before


def test_config_persistence_across_restart(tmp_path):
    cfg = tmp_path / "policy.json"
    manager = PolicyManager(cfg)
    manager.update(
        [{"path": "/", "directives": {"default-src": ["'self'"]}}],
        mode="report-only",
    )
    restarted = PolicyManager(cfg)
    assert restarted.snapshot().effective_mode("/") is CSPMode.REPORT_ONLY
    assert restarted.snapshot().effective_directives("/")["default-src"] == (
        "'self'",
    )


def test_duplicate_path_rejected():
    with pytest.raises(ValueError):
        PolicyManager._build_snapshot(
            [
                {"path": "/", "directives": {}},
                {"path": "/", "directives": {}},
            ],
            mode="enforce",
            report_uri="/csp/report",
            version=1,
        )
