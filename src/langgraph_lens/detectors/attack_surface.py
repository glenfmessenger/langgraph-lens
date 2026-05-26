"""Startup attack-surface scan.

Looks at runtime / configuration the operator has surfaced to the lens
and emits a detection for each known-risky combination. Runs once, at
boot, before the first node is invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import AttackSurfaceConfig
from ..events import Detection, Severity


@dataclass(slots=True)
class RuntimeInfo:
    """Snapshot of the runtime surface the lens is being asked to monitor.

    Populated by `Lens.scan_attack_surface(...)` callers. Every field is
    optional — the detector only flags signals it has evidence for.
    """

    checkpoint_saver: str | None = None  # e.g. "PostgresSaver"
    checkpoint_serializer: str | None = None  # e.g. "JsonPlusSerializer"
    prompt_registry_url: str | None = None
    prompt_registry_signature_required: bool = True
    template_formats_in_use: list[str] = field(default_factory=list)
    recursion_limit: int | None = None
    server_mode: bool = False
    server_auth_configured: bool = False


_PICKLE_BACKED_SERIALIZERS = {
    "JsonPlusSerializer",
    "PickleSerializer",
    "JsonPlusPickleSerializer",
}


class AttackSurfaceDetector:
    def __init__(self, config: AttackSurfaceConfig) -> None:
        self.config = config

    def scan(self, info: RuntimeInfo) -> list[Detection]:
        if not self.config.enabled:
            return []
        out: list[Detection] = []
        rules = set(self.config.rules)

        if (
            "pickle_checkpoint_backend" in rules
            and info.checkpoint_serializer in _PICKLE_BACKED_SERIALIZERS
            and info.checkpoint_saver
            and info.checkpoint_saver not in ("MemorySaver", "InMemorySaver")
        ):
            out.append(
                Detection(
                    detector="attack_surface",
                    rule="pickle_checkpoint_backend",
                    severity=Severity.HIGH,
                    extra={
                        "saver": info.checkpoint_saver,
                        "serializer": info.checkpoint_serializer,
                        "advisory": "CVE-2026-27794/28277 affects pickle-fallback serializers in multi-tenant deployments.",
                    },
                )
            )

        if (
            "unsigned_prompt_registry" in rules
            and info.prompt_registry_url
            and not info.prompt_registry_signature_required
        ):
            out.append(
                Detection(
                    detector="attack_surface",
                    rule="unsigned_prompt_registry",
                    severity=Severity.HIGH,
                    extra={"prompt_registry_url": info.prompt_registry_url},
                )
            )

        if "jinja2_template_format" in rules and "jinja2" in info.template_formats_in_use:
            out.append(
                Detection(
                    detector="attack_surface",
                    rule="jinja2_template_format",
                    severity=Severity.MEDIUM,
                    extra={
                        "advisory": "Jinja2 template_format on user-controllable inputs is the CVE-2026-34070 attack surface.",
                    },
                )
            )

        if (
            "permissive_recursion_limit" in rules
            and isinstance(info.recursion_limit, int)
            and info.recursion_limit > 100
        ):
            out.append(
                Detection(
                    detector="attack_surface",
                    rule="permissive_recursion_limit",
                    severity=Severity.LOW,
                    extra={"recursion_limit": info.recursion_limit},
                )
            )

        if (
            "server_without_auth" in rules
            and info.server_mode
            and not info.server_auth_configured
        ):
            out.append(
                Detection(
                    detector="attack_surface",
                    rule="server_without_auth",
                    severity=Severity.CRITICAL,
                    extra={
                        "advisory": "LangGraph Server is bound without auth — any client can resume any thread_id."
                    },
                )
            )

        return out
