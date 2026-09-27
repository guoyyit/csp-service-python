"""CSP policy resolution: inheritance, override and header rendering."""
from __future__ import annotations

from dataclasses import dataclass

from .config import PolicyConfig, PolicyMode, ScopePolicy

# Directives that receive the per-response nonce.
NONCED_DIRECTIVES = ("script-src", "style-src")
# Fallback directive used by browsers when the specific one is absent.
_FALLBACK_SRC = "default-src"


@dataclass(frozen=True)
class ResolvedPolicy:
    """Result of resolving a policy for one request."""

    directives: dict[str, tuple[str, ...]]
    mode: PolicyMode
    report_uri: str | None
    config_version: int
    matched_prefix: str


def merge_directives(
    base: dict[str, tuple[str, ...]],
    override: dict[str, tuple[str, ...]],
) -> dict[str, tuple[str, ...]]:
    """Merge two directive maps.

    Directives present in *override* replace the base directive wholesale
    (per CSP there is no per-source inheritance); other directives are
    inherited unchanged from *base*.
    """
    merged = dict(base)
    merged.update(override)
    return merged


def _matches(path: str, prefix: str) -> bool:
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def resolve_policy(config: PolicyConfig, path: str) -> ResolvedPolicy:
    """Resolve the effective policy for *path* using longest-prefix match.

    Scopes form an inheritance chain ordered by prefix length: the default
    policy is the root, and each matching scope inherits from the closest
    shorter-prefix match. Directives, mode and report-uri are overridden
    per-key by the child scope.
    """
    chain = [s for s in config.scopes if _matches(path, s.prefix)]
    chain.sort(key=lambda s: len(s.prefix))

    directives: dict[str, tuple[str, ...]] = dict(config.default.directives)
    mode = config.default.mode or PolicyMode.ENFORCE
    report_uri = config.default.report_uri
    matched = "/"
    for scope in chain:
        directives = merge_directives(directives, dict(scope.directives))
        if scope.mode is not None:
            mode = scope.mode
        if scope.report_uri is not None:
            report_uri = scope.report_uri
        matched = scope.prefix

    return ResolvedPolicy(
        directives=directives,
        mode=mode,
        report_uri=report_uri,
        config_version=config.version,
        matched_prefix=matched,
    )


def _with_nonce(
    directives: dict[str, tuple[str, ...]], nonce: str
) -> dict[str, tuple[str, ...]]:
    result = dict(directives)
    token = f"'nonce-{nonce}'"
    for name in NONCED_DIRECTIVES:
        sources = result.get(name)
        if sources is None:
            # fall back to default-src sources so nonced inline tags work
            sources = result.get(_FALLBACK_SRC, ())
        if token not in sources:
            sources = (*sources, token)
        result[name] = sources
    return result


def render_header(policy: ResolvedPolicy, nonce: str | None = None) -> str:
    """Render the CSP header value, injecting *nonce* where applicable."""
    directives = dict(policy.directives)
    if nonce:
        directives = _with_nonce(directives, nonce)
    if policy.report_uri and "report-uri" not in directives:
        directives["report-uri"] = (policy.report_uri,)

    parts: list[str] = []
    for name, sources in directives.items():
        if sources:
            parts.append(f"{name} {' '.join(sources)}")
        else:
            parts.append(name)
    return "; ".join(parts)
