"""Pydantic 模型：脱敏策略、API 请求与响应结构。"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .detectors import DETECTOR_NAMES

ActionType = Literal["delete", "mask", "tokenize"]
InputFormat = Literal["json", "ndjson"]

_RULE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")


class MatchSpec(BaseModel):
    """规则的命中条件。

    各维度之间是 AND；同一维度内多个值是 OR。

    * 含字段/键名维度、但不含 value_patterns/detectors 的规则为**整字段规则**，
      动作作用于整个标量值。
    * 含 value_patterns/detectors 的规则为**内容规则**，动作只替换字符串中
      命中的片段，可用字段/键名维度缩小作用范围。
    """

    field_paths: list[str] = Field(
        default_factory=list,
        description="JSONPath 风格路径通配，如 $.user.email、**.ip、*.phone",
    )
    key_names: list[str] = Field(
        default_factory=list, description="按键名精确匹配，如 password、id_card"
    )
    key_globs: list[str] = Field(
        default_factory=list, description="键名通配，如 *_token、*secret*"
    )
    key_patterns: list[str] = Field(
        default_factory=list, description="键名正则（任一命中即可）"
    )
    value_patterns: list[str] = Field(
        default_factory=list, description="对字符串值生效的内容正则"
    )
    detectors: list[str] = Field(
        default_factory=list,
        description=f"内置敏感信息识别器，可选：{', '.join(sorted(DETECTOR_NAMES))}",
    )

    @field_validator("detectors")
    @classmethod
    def _check_detectors(cls, v: list[str]) -> list[str]:
        unknown = [d for d in v if d not in DETECTOR_NAMES]
        if unknown:
            raise ValueError(f"未知识别器: {unknown}，可选: {sorted(DETECTOR_NAMES)}")
        return v

    @field_validator("key_patterns", "value_patterns")
    @classmethod
    def _check_regex(cls, v: list[str]) -> list[str]:
        for p in v:
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"非法正则 {p!r}: {exc}") from exc
        return v

    def has_field_dimension(self) -> bool:
        return bool(
            self.field_paths or self.key_names or self.key_globs or self.key_patterns
        )

    def has_content_dimension(self) -> bool:
        return bool(self.value_patterns or self.detectors)


class Rule(BaseModel):
    id: str = Field(description="规则唯一标识，将作为令牌化命名空间")
    name: str = Field(description="人类可读名称")
    description: str = ""
    enabled: bool = True
    match: MatchSpec
    action: ActionType
    mask_char: str = Field(default="*", description="mask 动作的替换字符")
    keep_prefix: int = Field(default=0, ge=0, description="mask 时保留的前缀长度")
    keep_suffix: int = Field(default=0, ge=0, description="mask 时保留的后缀长度")
    token_namespace: str | None = Field(
        default=None, description="tokenize 的命名空间，默认取规则 id"
    )

    @field_validator("id")
    @classmethod
    def _check_id(cls, v: str) -> str:
        if not _RULE_ID.match(v):
            raise ValueError("规则 id 只能包含小写字母、数字、下划线、连字符（1-64 位，且以字母或数字开头）")
        return v

    @field_validator("mask_char")
    @classmethod
    def _check_mask_char(cls, v: str) -> str:
        if len(v) != 1:
            raise ValueError("mask_char 必须是单个字符")
        return v

    @model_validator(mode="after")
    def _check_match_nonempty(self) -> "Rule":
        m = self.match
        if not (
            m.field_paths
            or m.key_names
            or m.key_globs
            or m.key_patterns
            or m.value_patterns
            or m.detectors
        ):
            raise ValueError(f"规则 {self.id} 至少需要一个匹配维度")
        if self.keep_prefix + self.keep_suffix > 0 and self.action == "tokenize":
            raise ValueError("keep_prefix/keep_suffix 仅对 mask 动作有效")
        return self


class Strategy(BaseModel):
    name: str
    version: str = "1"
    description: str = ""
    rules: list[Rule]
    risk_detectors: list[str] = Field(
        default_factory=lambda: ["email", "phone", "ipv4", "access_token",
                                 "id_card", "bank_card"],
        description="处理后仍命中这些识别器的内容会被标记为需复核",
    )

    @field_validator("risk_detectors")
    @classmethod
    def _check_risk_detectors(cls, v: list[str]) -> list[str]:
        unknown = [d for d in v if d not in DETECTOR_NAMES]
        if unknown:
            raise ValueError(f"未知识别器: {unknown}")
        return v

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "Strategy":
        ids = [r.id for r in self.rules]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"规则 id 重复: {sorted(dup)}")
        return self


# ---------- 请求 ----------


class BatchPayload(BaseModel):
    format: InputFormat = Field(default="json", description="json 为对象或数组，ndjson 每行一个对象")
    content: str = Field(description="原始日志文本；禁止随请求提交额外密钥")
    strategy: Strategy


class DryRunRequest(BatchPayload):
    pass


class CreateJobRequest(BatchPayload):
    pass


# ---------- 响应 ----------


class AuditEntry(BaseModel):
    """审计清单中的一条。按设计不含任何原始值。"""

    record_index: int = Field(description="记录在批次中的序号（从 0 开始）")
    line_no: int | None = Field(default=None, description="NDJSON 输入时的行号（从 1 开始）")
    field_path: str
    key_name: str | None = None
    rule_id: str
    rule_name: str
    action: ActionType
    match_type: Literal["field", "content"]
    hit_by: list[str] = Field(description="命中维度/识别器/正则名称")
    occurrences: int = Field(default=1, description="该位置内容动作的替换次数")


class RiskFinding(BaseModel):
    """处理后仍残留的高风险内容（只记录位置与类型，不记录原值）。"""

    record_index: int
    line_no: int | None = None
    field_path: str
    detector: str
    length: int = Field(description="命中片段长度，便于人工判断")


class ActionStat(BaseModel):
    rule_id: str
    action: ActionType
    count: int


class RunStats(BaseModel):
    records_in: int
    fields_scanned: int
    audit_entries: int
    risk_findings: int
    by_action: dict[str, int]
    by_rule: dict[str, int]


class RunResult(BaseModel):
    records: list[Any]
    audit: list[AuditEntry]
    risks: list[RiskFinding]
    stats: RunStats
    needs_review: bool
    key_fingerprint: str


class JobModel(BaseModel):
    id: str
    idempotency_key: str | None
    created_at: str
    format: str
    strategy_name: str
    strategy_version: str
    record_count: int
    needs_review: bool
    stats: RunStats
    output_filename: str
    key_fingerprint: str


class JobDetail(JobModel):
    audit: list[AuditEntry]
    risks: list[RiskFinding]


class JobSummary(BaseModel):
    id: str
    created_at: str
    strategy_name: str
    record_count: int
    needs_review: bool
    risk_findings: int


class JobList(BaseModel):
    items: list[JobSummary]
    total: int
