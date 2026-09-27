"""CSP policy configuration models and hot-reloadable store."""
from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping


class PolicyMode(str, Enum):
    ENFORCE = "enforce"
    REPORT_ONLY = "report-only"

    @classmethod
    def parse(cls, value: str | PolicyMode | None) -> PolicyMode | None:
        if value is None or isinstance(value, PolicyMode):
            return value
        try:
            return cls(str(value).strip().lower())
        except ValueError:
            raise ConfigError(f"unknown policy mode: {value!r}")


@dataclass(frozen=True)
class ScopePolicy:
    """Policy for a route scope (prefix match)."""

    prefix: str = "/"
    directives: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    mode: PolicyMode | None = None
    report_uri: str | None = None

    def __post_init__(self) -> None:
        # normalise mutable containers into immutable ones
        norm: dict[str, tuple[str, ...]] = {}
        for name, sources in dict(self.directives).items():
            key = _validate_directive_name(name)
            norm[key] = tuple(str(s) for s in sources)
        object.__setattr__(self, "directives", norm)
        prefix = self.prefix if self.prefix.startswith("/") else "/" + self.prefix
        if len(prefix) > 1 and prefix.endswith("/"):
            prefix = prefix.rstrip("/")
        object.__setattr__(self, "prefix", prefix)
        if self.mode is not None and not isinstance(self.mode, PolicyMode):
            object.__setattr__(self, "mode", PolicyMode.parse(self.mode))


@dataclass(frozen=True)
class PolicyConfig:
    """Full configuration: default policy plus scoped overrides."""

    default: ScopePolicy = field(default_factory=lambda: ScopePolicy("/"))
    scopes: tuple[ScopePolicy, ...] = ()
    version: int = 0


class ConfigError(ValueError):
    """Raised when a policy configuration payload is invalid."""


_DIRECTIVE_RE = re.compile(r"^[a-zA-Z-]+$")


def _validate_directive_name(name: str) -> str:
    key = str(name).strip().lower()
    if not _DIRECTIVE_RE.match(key):
        raise ConfigError(f"invalid directive name: {name!r}")
    return key


def _parse_scope(data: Mapping[str, Any]) -> ScopePolicy:
    if not isinstance(data, Mapping):
        raise ConfigError("scope must be an object")
    directives = data.get("directives", {})
    if not isinstance(directives, Mapping):
        raise ConfigError("directives must be an object of arrays")
    return ScopePolicy(
        prefix=str(data.get("prefix", "/")),
        directives={k: list(v) for k, v in directives.items()},
        mode=PolicyMode.parse(data.get("mode")),
        report_uri=(str(data["report_uri"]) if data.get("report_uri") else None),
    )


def parse_config(payload: Mapping[str, Any]) -> PolicyConfig:
    """Validate and build a PolicyConfig from a JSON-like payload."""
    if not isinstance(payload, Mapping):
        raise ConfigError("config payload must be an object")

    default_data = payload.get("default")
    if default_data is not None:
        if not isinstance(default_data, Mapping):
            raise ConfigError("default must be an object")
        default_data = {**default_data, "prefix": "/"}
        default = _parse_scope(default_data)
    else:
        default = ScopePolicy("/")

    raw_scopes = payload.get("scopes", [])
    if not isinstance(raw_scopes, list):
        raise ConfigError("scopes must be an array")
    scopes = tuple(_parse_scope(s) for s in raw_scopes)

    seen: set[str] = {"/"}
    for s in scopes:
        if s.prefix == "/":
            raise ConfigError("scope prefix '/' is reserved for the default policy")
        if s.prefix in seen:
            raise ConfigError(f"duplicate scope prefix: {s.prefix!r}")
        seen.add(s.prefix)

    return PolicyConfig(default=default, scopes=scopes)


class PolicyStore:
    """Thread-safe store holding an immutable config snapshot.

    Updates replace the whole snapshot atomically; in-flight requests that
    obtained an older snapshot keep using it because PolicyConfig is frozen.
    """

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self._lock = threading.Lock()
        config = config or PolicyConfig()
        self._config = (
            config if config.version > 0 else replace(config, version=1)
        )

    def snapshot(self) -> PolicyConfig:
        # frozen object => safe to hand out without copying
        return self._config

    def update(self, config: PolicyConfig) -> PolicyConfig:
        with self._lock:
            new_version = replace(config, version=self._config.version + 1)
            old = self._config
            self._config = new_version
            return old

    def version(self) -> int:
        return self._config.version
