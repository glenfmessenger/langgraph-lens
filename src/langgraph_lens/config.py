"""Configuration schema for langgraph-lens.

Every detector defaults to enabled. The whole point of the project is that
`LANGGRAPH_LENS=1` is enough; this module is just for tuning, not for turning
things on.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class AttackSurfaceConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "pickle_checkpoint_backend",
            "unsigned_prompt_registry",
            "jinja2_template_format",
            "permissive_recursion_limit",
            "server_without_auth",
        ]
    )


class CheckpointConfig(BaseModel):
    enabled: bool = True
    scan_on_write: bool = True
    scan_on_read: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "unsafe_pickle_opcode",
            "unknown_serializer_kind",
            "missing_thread_id",
            "schema_drift",
            "oversized_blob",
        ]
    )
    max_blob_bytes: int = 10 * 1024 * 1024  # 10 MiB


class SupplyChainConfig(BaseModel):
    enabled: bool = True
    scan_on_load: bool = True
    formats: list[str] = Field(
        default_factory=lambda: ["jinja2", "f_string", "mustache", "prompt_dir"]
    )
    rules: list[str] = Field(
        default_factory=lambda: [
            "jinja_ssti",
            "path_traversal",
            "unsafe_chat_template",
            "unsigned_hub_pull",
        ]
    )


class ToolConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "shell_metachar",
            "ssrf_pattern",
            "out_of_allowlist",
            "enumeration",
            "oversized_args",
        ]
    )
    enumeration_window_seconds: int = 30
    enumeration_threshold: int = 8
    max_arg_bytes: int = 65536


class MemoryConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "system_prompt_override",
            "oversized_entry",
            "cross_tenant_key",
        ]
    )
    max_entry_bytes: int = 32768


class PIIPattern(BaseModel):
    """One PII pattern.

    Either set `type` to a built-in name (ssn, email, etc.) or provide a
    `name` + `regex` pair for a custom pattern.
    """

    type: str | None = None
    name: str | None = None
    regex: str | None = None

    @field_validator("regex")
    @classmethod
    def _custom_requires_name(cls, v: str | None, info: object) -> str | None:
        return v


class PIIConfig(BaseModel):
    enabled: bool = True
    scan_ingress: bool = True
    scan_egress: bool = True
    scan_checkpoints: bool = True
    patterns: list[PIIPattern] = Field(
        default_factory=lambda: [
            PIIPattern(type="ssn"),
            PIIPattern(type="credit_card"),
            PIIPattern(type="phone_us"),
            PIIPattern(type="phone_intl"),
            PIIPattern(type="email"),
            PIIPattern(type="ip_address"),
        ]
    )
    custom_patterns: list[PIIPattern] = Field(default_factory=list)


class GoalHijackConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "system_prompt_drift",
            "tool_call_drift",
            "off_topic_subgoal",
        ]
    )
    user_intent_similarity_threshold: float = 0.35
    watch_substrings: list[str] = Field(
        default_factory=lambda: [
            "transfer funds",
            "send money",
            "delete account",
            "exfiltrate",
            "curl http",
            "wget http",
        ]
    )


class CommsConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "undeclared_edge",
            "recursion_exceeded",
            "send_to_undeclared_target",
            "oversized_state_growth",
        ]
    )
    state_growth_multiplier: float = 10.0


class SQLInjectionConfig(BaseModel):
    enabled: bool = True
    rules: list[str] = Field(
        default_factory=lambda: [
            "union_select",
            "comment_terminator",
            "stacked_query",
            "metadata_escape",
        ]
    )
    fields: list[str] = Field(
        default_factory=lambda: ["thread_id", "checkpoint_ns", "checkpoint_id"]
    )


class PrometheusConfig(BaseModel):
    enabled: bool = True
    port: int = 9092


class LoggingConfig(BaseModel):
    enabled: bool = True
    destination: Literal["stderr", "file"] = "stderr"
    file_path: str = "/var/log/langgraph-lens.jsonl"
    format: Literal["json", "text"] = "json"
    include_match_text: bool = False


class AlertsConfig(BaseModel):
    enabled: bool = False
    slack_webhook: str = ""
    cooldown_seconds: int = 300
    alert_on: list[str] = Field(
        default_factory=lambda: [
            "supply_chain",
            "attack_surface",
            "checkpoint",
            "goal_hijack",
        ]
    )


class OtelConfig(BaseModel):
    enabled: bool = False
    endpoint: str = "http://localhost:4318"
    service_name: str = "langgraph-agent"
    export_traces: bool = True
    export_metrics: bool = True


# ---------------------------------------------------------------------------
# Tier 2 — interventions. All `enabled: False` by default. Nothing here does
# anything unless you explicitly turn it on.
# ---------------------------------------------------------------------------


class PIIRedactionConfig(BaseModel):
    enabled: bool = False
    mode: Literal["redact", "block"] = "redact"
    patterns: list[PIIPattern] = Field(
        default_factory=lambda: [
            PIIPattern(type="ssn"),
            PIIPattern(type="credit_card"),
            PIIPattern(type="email"),
            PIIPattern(type="phone_us"),
            PIIPattern(type="phone_intl"),
            PIIPattern(type="ip_address"),
        ]
    )
    custom_patterns: list[PIIPattern] = Field(default_factory=list)


class ToolAllowlistConfig(BaseModel):
    enabled: bool = False
    mode: Literal["block", "log"] = "block"
    allowed_tools: list[str] | None = None
    block_on_rules: list[str] = Field(
        default_factory=lambda: ["shell_metachar", "ssrf_pattern", "oversized_args"]
    )


class CheckpointProtectorConfig(BaseModel):
    enabled: bool = False
    mode: Literal["enforce", "log"] = "enforce"
    block_on_rules: list[str] = Field(
        default_factory=lambda: ["unsafe_pickle_opcode"]
    )
    require_hmac: bool = False
    signing_key: str = ""


class GoalGuardConfig(BaseModel):
    enabled: bool = False
    mode: Literal["block", "log"] = "block"
    block_on_rules: list[str] = Field(
        default_factory=lambda: ["system_prompt_drift", "tool_call_drift"]
    )


class RateLimitConfig(BaseModel):
    enabled: bool = False
    mode: Literal["throttle", "block"] = "throttle"
    capacity: float = 60.0
    refill_per_second: float = 1.0
    size_divisor: int = 1000  # chars of args per extra token of cost
    key_by_tenant: bool = True
    key_by_thread: bool = True
    key_by_tool: bool = False


class CircuitBreakerConfig(BaseModel):
    enabled: bool = False
    window_seconds: int = 30
    min_samples: int = 20
    error_rate_threshold: float = 0.5  # 0..1
    cooldown_seconds: int = 30

    fail_closed_on_attack: bool = False
    fail_closed_min_severity: Literal["low", "medium", "high", "critical"] = "high"
    fail_closed_attack_window_seconds: int = 60
    fail_closed_min_attack_signals: int = 5


class AuditSignalingConfig(BaseModel):
    enabled: bool = False
    triggered_header: str = "X-Lens-Triggered"
    reason_header: str = "X-Lens-Reason"
    action_header: str = "X-Lens-Action"
    stamp_state: bool = False


class Tier2Config(BaseModel):
    pii_redaction: PIIRedactionConfig = Field(default_factory=PIIRedactionConfig)
    tool_allowlist: ToolAllowlistConfig = Field(default_factory=ToolAllowlistConfig)
    checkpoint_protector: CheckpointProtectorConfig = Field(
        default_factory=CheckpointProtectorConfig
    )
    goal_guard: GoalGuardConfig = Field(default_factory=GoalGuardConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    circuit_breaker: CircuitBreakerConfig = Field(default_factory=CircuitBreakerConfig)
    audit_signaling: AuditSignalingConfig = Field(default_factory=AuditSignalingConfig)

    @property
    def any_enabled(self) -> bool:
        return any(
            (
                self.pii_redaction.enabled,
                self.tool_allowlist.enabled,
                self.checkpoint_protector.enabled,
                self.goal_guard.enabled,
                self.rate_limit.enabled,
                self.circuit_breaker.enabled,
            )
        )


class LensConfig(BaseModel):
    attack_surface: AttackSurfaceConfig = Field(default_factory=AttackSurfaceConfig)
    checkpoint: CheckpointConfig = Field(default_factory=CheckpointConfig)
    supply_chain: SupplyChainConfig = Field(default_factory=SupplyChainConfig)
    tool: ToolConfig = Field(default_factory=ToolConfig)
    memory: MemoryConfig = Field(default_factory=MemoryConfig)
    pii: PIIConfig = Field(default_factory=PIIConfig)
    goal_hijack: GoalHijackConfig = Field(default_factory=GoalHijackConfig)
    comms: CommsConfig = Field(default_factory=CommsConfig)
    sql_injection: SQLInjectionConfig = Field(default_factory=SQLInjectionConfig)
    prometheus: PrometheusConfig = Field(default_factory=PrometheusConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)
    otel: OtelConfig = Field(default_factory=OtelConfig)
    tier2: Tier2Config = Field(default_factory=Tier2Config)

    @classmethod
    def default(cls) -> LensConfig:
        return cls()

    @classmethod
    def from_yaml(cls, path: str | Path) -> LensConfig:
        with open(path) as fh:
            data = yaml.safe_load(fh) or {}
        return cls.model_validate(data)

    @classmethod
    def from_env(cls) -> LensConfig:
        """Resolve config from the standard env vars.

        - `LANGGRAPH_LENS_CONFIG` -> path to YAML file
        - otherwise -> defaults (everything enabled)
        """
        path = os.environ.get("LANGGRAPH_LENS_CONFIG")
        if path:
            return cls.from_yaml(path)
        return cls.default()
