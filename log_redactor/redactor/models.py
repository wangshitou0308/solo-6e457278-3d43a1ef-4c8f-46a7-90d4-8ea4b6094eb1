"""Pydantic 模型：脱敏策略、API 请求与响应结构。"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .crypto import MAX_TOKEN_CONTEXT
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
    token_context: str | None = Field(
        default=None,
        max_length=MAX_TOKEN_CONTEXT,
        description=(
            "令牌关联域上下文（最长 128 字符）。传入后令牌化在该上下文专属的"
            "隔离域内进行：同一主密钥下，相同上下文与原值恒为同一替身，"
            "不同上下文必为不同替身；服务只持久化不可逆域标识（域指纹），"
            "不保存本字段原文。未传（或纯空白）时沿用全局映射；"
            "对 delete/mask 动作无影响。"
        ),
    )

    @field_validator("token_context")
    @classmethod
    def _normalize_token_context(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class DryRunRequest(BatchPayload):
    pass


class CreateJobRequest(BatchPayload):
    pass


# ---------- 策略变更对照（baseline vs candidate） ----------


class StrategyDiffLimits(BaseModel):
    """CI 放行门槛；字段为 None 表示该项不设限（恒通过）。"""

    max_new_risks: int | None = Field(
        default=None, ge=0, description="候选策略新增残留风险条数上限"
    )
    max_lost_coverage: int | None = Field(
        default=None, ge=0, description="候选策略失去处理的覆盖条数上限"
    )
    max_type_changes: int | None = Field(
        default=None, ge=0, description="输出值 JSON 类型变化处数上限"
    )


class StrategyDiffRequest(BaseModel):
    """同一批日志上对照基线与候选策略（同一主密钥执行，不落库、不生成文件）。"""

    format: InputFormat = Field(
        default="json", description="json 为对象或数组，ndjson 每行一个对象（空行占行号）"
    )
    content: str = Field(description="原始日志文本；禁止随请求提交额外密钥")
    baseline: Strategy = Field(description="基线策略（当前线上版本）")
    candidate: Strategy = Field(description="候选策略（待放行版本）")
    limits: StrategyDiffLimits = Field(default_factory=StrategyDiffLimits)
    token_context: str | None = Field(
        default=None,
        max_length=MAX_TOKEN_CONTEXT,
        description=(
            "令牌关联域上下文（最长 128 字符）。基线与候选**共用同一关联域**"
            "执行，避免两侧仅因域隔离产生伪差异；未传时基线与候选共用全局域。"
            "服务只持久化不可逆域标识（域指纹），不保存本字段原文。"
        ),
    )

    @field_validator("token_context")
    @classmethod
    def _normalize_token_context(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip()
        return v or None


class DiffLocation(BaseModel):
    """差异位置：记录序号、NDJSON 行号、字段路径与内容命中位置（原文内字符偏移）。

    ``span_start``/``span_end`` 仅对内容命中存在；整字段（整值）差异为 null。
    偏移基于原始文本坐标，基线与候选两侧可直接对齐。
    """

    record_index: int = Field(description="记录在批次中的序号（从 0 开始）")
    line_no: int | None = Field(default=None, description="NDJSON 输入时的物理行号（从 1 开始，空行占号）")
    field_path: str = Field(description="字段路径，如 $.user.email")
    span_start: int | None = Field(default=None, description="内容命中起点（原文内偏移）")
    span_end: int | None = Field(default=None, description="内容命中终点（原文内偏移，开区间）")


class CoverageDiffItem(BaseModel):
    """一处覆盖增减（只含位置、规则、动作、识别器与计数，绝不含值）。"""

    location: DiffLocation
    action: ActionType = Field(description="该位置的处理动作")
    rule_id: str
    rule_name: str
    hit_by: list[str] = Field(description="命中维度/识别器标签（detector:<名称> 等）")
    count: int = Field(default=1, description="该差异项合并的命中段数")


class ActionChangeItem(BaseModel):
    """同一位置两侧均被处理、但动作不同。"""

    location: DiffLocation
    from_action: ActionType
    to_action: ActionType
    from_rule_id: str
    from_rule_name: str
    to_rule_id: str
    to_rule_name: str
    count: int = Field(default=1, description="该差异项合并的命中段数")


class WinnerChangeItem(BaseModel):
    """同一位置动作一致、但胜出规则 id 不同（含规则换名重写）。"""

    location: DiffLocation
    action: ActionType = Field(description="两侧一致的处理动作")
    from_rule_id: str
    from_rule_name: str
    to_rule_id: str
    to_rule_name: str
    count: int = Field(default=1, description="该差异项合并的命中段数")


class TypeChangeItem(BaseModel):
    """同一叶子输出值的 JSON 类型变化（只记录类型名，不记录值）。"""

    location: DiffLocation
    from_type: str = Field(description="基线输出的 JSON 类型（null/boolean/number/string/array/object）")
    to_type: str = Field(description="候选输出的 JSON 类型")
    count: int = Field(default=1)


class RiskDiffItem(BaseModel):
    """残留风险增减（按记录/行号/字段路径/识别器聚合，只含计数）。"""

    location: DiffLocation
    detector: str = Field(description="命中识别器名称")
    count: int = Field(description="该位置该识别器新增/解除的残留风险条数")


class DiffCheck(BaseModel):
    """一项放行门槛的核对结果。"""

    name: str = Field(description="门槛名称：new_risks / lost_coverage / type_changes")
    limit: int | None = Field(description="上限；null 表示未设限（恒通过）")
    actual: int = Field(description="实际数量")
    passed: bool


class StrategyDiffSummary(BaseModel):
    """各项差异的总数（不受返回列表截断影响）。"""

    coverage_gained: int = Field(description="候选新增覆盖条数")
    coverage_lost: int = Field(description="候选失去覆盖条数")
    action_changes: int = Field(description="动作变化条数")
    winner_changes: int = Field(description="胜出规则变化条数（动作一致）")
    type_changes: int = Field(description="输出 JSON 类型变化处数")
    risks_new: int = Field(description="候选新增残留风险条数")
    risks_resolved: int = Field(description="候选解除的残留风险条数")


class StrategyDiffResponse(BaseModel):
    """策略变更对照结果。所有差异项均不含原始值、正则文本或处理后仍含敏感信息的值。"""

    passed: bool = Field(description="全部已设限门槛通过时为 true，供 CI 放行判定")
    checks: list[DiffCheck] = Field(description="逐项门槛依据")
    summary: StrategyDiffSummary
    coverage_gained: list[CoverageDiffItem]
    coverage_lost: list[CoverageDiffItem]
    action_changes: list[ActionChangeItem]
    winner_changes: list[WinnerChangeItem]
    type_changes: list[TypeChangeItem]
    risks_new: list[RiskDiffItem]
    risks_resolved: list[RiskDiffItem]
    truncated: list[str] = Field(
        default_factory=list,
        description="因超过单类返回上限而被截断的差异类目名（summary 计数仍为全量）",
    )
    key_fingerprint: str = Field(description="执行对照的主密钥指纹（两侧相同）")
    domain_fingerprint: str = Field(
        default="global",
        description="基线与候选共用的令牌关联域指纹：global=全局域；dom:<hex>=隔离域",
    )


# ---------- 响应 ----------


class AuditEntry(BaseModel):
    """审计清单中的一条。按设计不含任何原始值。"""

    record_index: int = Field(description="记录在批次/来源文件中的序号（从 0 开始）")
    line_no: int | None = Field(default=None, description="NDJSON/文本输入时的行号（从 1 开始）")
    field_path: str
    key_name: str | None = None
    rule_id: str
    rule_name: str
    action: ActionType
    match_type: Literal["field", "content"]
    hit_by: list[str] = Field(description="命中维度/识别器/正则名称")
    occurrences: int = Field(default=1, description="该位置内容动作的替换次数")
    source_path: str | None = Field(
        default=None, description="诊断包作业中来源文件在压缩包内的相对路径"
    )


class RiskFinding(BaseModel):
    """处理后仍残留的高风险内容（只记录位置与类型，不记录原值）。"""

    record_index: int
    line_no: int | None = None
    field_path: str
    detector: str
    length: int = Field(description="命中片段长度，便于人工判断")
    source_path: str | None = Field(
        default=None, description="诊断包作业中来源文件在压缩包内的相对路径"
    )


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
    domain_fingerprint: str = Field(
        default="global",
        description="令牌关联域指纹：global=全局映射；dom:<hex>=隔离域（不可逆推上下文原文）",
    )


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
    top_level_is_array: bool
    key_fingerprint: str
    domain_fingerprint: str = Field(
        default="global",
        description="令牌关联域指纹：global=全局映射；dom:<hex>=隔离域",
    )
    receipt_url: str = Field(
        default="", description="完整性凭证查询地址（成功发布的作业必有凭证）"
    )


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


# ---------- 大批量 NDJSON 流式作业 ----------

StreamJobStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]


class StreamProgress(BaseModel):
    """流式作业的实时进度（全部为累计计数）。"""

    bytes_total: int = Field(description="上传文件总字节数")
    bytes_processed: int = Field(description="已安全检查点处理的输入字节数")
    records_processed: int = Field(description="已脱敏并检查点的记录数")
    audit_count: int = Field(description="已落库的审计条目数")
    risk_count: int = Field(description="已落库的残留风险数")
    last_line_no: int = Field(default=0, description="最近处理到的 NDJSON 行号（物理行）")
    updated_at: str | None = None


class StreamJobModel(BaseModel):
    id: str
    idempotency_key: str | None = None
    created_at: str
    updated_at: str | None = None
    status: StreamJobStatus
    format: str = "ndjson"
    strategy_name: str
    strategy_version: str
    source_filename: str = Field(description="上传时的原始文件名（仅展示用）")
    bytes_total: int = 0
    bytes_processed: int = 0
    records_processed: int = 0
    audit_count: int = 0
    risk_count: int = 0
    fields_scanned: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    last_line_no: int = 0
    error_line: int | None = Field(default=None, description="格式错误行号；失败时填入")
    error_message: str | None = None
    output_filename: str | None = Field(default=None, description="成功发布后的文件名")
    output_bytes: int = 0
    key_fingerprint: str
    domain_fingerprint: str = Field(
        default="global",
        description="令牌关联域指纹：global=全局映射；dom:<hex>=隔离域",
    )
    content_sha256: str = Field(description="上传内容 SHA-256，用于幂等冲突判定，不可逆推内容")
    strategy_sha256: str = Field(default="", description="规范化策略 SHA-256，参与幂等一致性判定")
    progress_pct: float = 0.0
    download_url: str | None = None
    receipt_url: str | None = Field(
        default=None, description="完整性凭证查询地址；仅 succeeded 作业可用"
    )


class StreamJobSummary(BaseModel):
    id: str
    created_at: str
    status: StreamJobStatus
    strategy_name: str
    bytes_total: int
    records_processed: int
    risk_count: int
    progress_pct: float


class StreamJobList(BaseModel):
    items: list[StreamJobSummary]
    total: int


class AuditPage(BaseModel):
    job_id: str
    total: int
    limit: int
    offset: int
    items: list[AuditEntry]


class RiskPage(BaseModel):
    job_id: str
    total: int
    limit: int
    offset: int
    items: list[RiskFinding]


# ---------- 诊断包（ZIP）作业 ----------

BundleJobStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]

# 诊断包内可处理的文件类型（按扩展名归类）
BundleFileFormat = Literal["json", "ndjson", "text"]


class BundleFileInfo(BaseModel):
    """清单中单个来源文件的处理结果（不含任何原始内容）。"""

    path: str = Field(description="来源文件在压缩包内的相对路径")
    status: Literal["redacted", "skipped", "failed"] = Field(
        description="redacted=已脱敏并写入结果；skipped=按策略不处理（二进制/不支持类型/"
                    "保留名冲突）；failed=处理失败（如 JSON 解析错误）"
    )
    reason: str | None = Field(default=None, description="skipped/failed 的原因（不含原值）")
    format: BundleFileFormat | None = Field(default=None, description="识别出的文件类型")
    records: int = Field(default=0, description="结构化文件的记录数")
    lines: int = Field(default=0, description="文本/NDJSON 文件的物理行数")
    audit_entries: int = 0
    risk_findings: int = 0
    output_path: str | None = Field(
        default=None, description="结果 ZIP 内的相对路径（skipped/failed 为 null）"
    )
    size_in: int = Field(default=0, description="来源文件解压后字节数")
    size_out: int = Field(default=0, description="脱敏输出字节数")


class BundleManifest(BaseModel):
    """结果 ZIP 内的清单（redaction-manifest.json），同样不含任何原始值。"""

    job_id: str
    created_at: str
    completed_at: str | None = None
    strategy_name: str
    strategy_version: str
    source_filename: str
    source_sha256: str = Field(description="上传压缩包的 SHA-256，不可逆推内容")
    key_fingerprint: str
    domain_fingerprint: str = Field(
        default="global",
        description="令牌关联域指纹：global=全局映射；dom:<hex>=隔离域",
    )
    stats: dict[str, Any] = Field(description="汇总统计（文件/记录/审计/风险计数）")
    files: list[BundleFileInfo]


class BundleJobModel(BaseModel):
    id: str
    idempotency_key: str | None = None
    created_at: str
    updated_at: str | None = None
    status: BundleJobStatus
    strategy_name: str
    strategy_version: str
    source_filename: str = Field(description="上传时的原始文件名（仅展示用）")
    bytes_total: int = Field(default=0, description="上传压缩包字节数（压缩态）")
    files_total: int = Field(default=0, description="压缩包内文件条目数（不含目录）")
    files_processed: int = Field(default=0, description="已完成处理（含跳过）的文件数")
    records_processed: int = 0
    audit_count: int = 0
    risk_count: int = 0
    fields_scanned: int = 0
    by_action: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)
    current_file: str | None = Field(default=None, description="正在处理的包内相对路径")
    error_message: str | None = None
    output_filename: str | None = Field(default=None, description="成功发布后的文件名")
    output_bytes: int = 0
    key_fingerprint: str
    domain_fingerprint: str = Field(
        default="global",
        description="令牌关联域指纹：global=全局映射；dom:<hex>=隔离域",
    )
    content_sha256: str = Field(description="上传压缩包 SHA-256，用于幂等冲突判定")
    strategy_sha256: str = Field(default="", description="规范化策略 SHA-256，参与幂等一致性判定")
    progress_pct: float = 0.0
    download_url: str | None = None
    receipt_url: str | None = Field(
        default=None, description="完整性凭证查询地址；仅 succeeded 作业可用"
    )


class BundleJobSummary(BaseModel):
    id: str
    created_at: str
    status: BundleJobStatus
    strategy_name: str
    files_total: int
    files_processed: int
    records_processed: int
    risk_count: int
    progress_pct: float


class BundleJobList(BaseModel):
    items: list[BundleJobSummary]
    total: int


# ---------- 脱敏结果完整性凭证 ----------

ReceiptVerdict = Literal[
    "ok",
    "unsupported_format",
    "key_mismatch",
    "receipt_tampered",
    "job_mismatch",
    "result_missing",
    "content_mismatch",
]


class ReceiptVerifyResponse(BaseModel):
    """凭证校验结论。HTTP 恒为 200，结论看 ``verdict``；不返回任何文件内容。"""

    job_id: str
    job_kind: Literal["batch", "stream", "bundle"]
    ok: bool = Field(description="凭证标签与结果摘要均一致时为 true")
    verdict: ReceiptVerdict = Field(
        description="ok=一致；unsupported_format=格式不支持；key_mismatch=密钥不匹配；"
                    "receipt_tampered=凭证被改动；job_mismatch=凭证与本作业不对应；"
                    "result_missing=结果缺失；content_mismatch=内容不符"
    )
    detail: str = Field(description="结论说明（不含原始值/处理后值）")
    checks: dict[str, str] = Field(
        description="各校验阶段结果（ok/failed/skipped）：format/binding/structure/"
                    "key/tag/result/content"
    )


# ---------- 本地数据保留与安全清理 ----------

RetentionJobKind = Literal["batch", "stream", "bundle"]
# 终态：batch 只有成功终态；异步作业还包括失败/取消
RetentionTerminalStatus = Literal["succeeded", "failed", "cancelled"]
# 规则键中的“是否需复核”维度：true/false 精确匹配，any=两者皆适用
ReviewScope = Literal["true", "false", "any"]
CleanupPlanStatus = Literal["pending", "running", "succeeded", "partial", "failed"]
LockState = Literal["active", "expired", "released"]
FileOutcome = Literal["deleted", "missing", "symlink_refused", "path_refused", "failed"]


class RetentionRuleModel(BaseModel):
    """单条保留期限规则：(作业类型, 终态, 需复核) 三元组唯一。"""

    job_kind: RetentionJobKind
    terminal_status: RetentionTerminalStatus
    needs_review: ReviewScope = Field(
        description="true/false=仅匹配对应复核状态；any=两者皆适用"
    )
    retention_days: float | None = Field(
        ge=0,
        description="自终态时间起的保留天数（小数可用，如 0.5=12 小时）；null=永久保留",
    )
    builtin: bool = Field(default=False, description="内置默认规则不可删除，只能覆盖")
    updated_at: str


class RetentionPolicyResponse(BaseModel):
    """生效中的保留策略：内置默认规则 + 调用方覆盖（含永久保留）。"""

    rules: list[RetentionRuleModel]


class UpsertRetentionRuleRequest(BaseModel):
    job_kind: RetentionJobKind
    terminal_status: RetentionTerminalStatus
    needs_review: ReviewScope = "any"
    retention_days: float | None = Field(
        default=None, ge=0, description="保留天数；null=永久保留（覆盖内置期限）"
    )


class RetentionLockModel(BaseModel):
    """作业保留锁：带原因与到期时间；到期前该作业不得被清理。"""

    job_kind: RetentionJobKind
    job_id: str
    reason: str = Field(min_length=1, max_length=512, description="加锁原因（不含敏感值）")
    expires_at: datetime = Field(description="到期时间（UTC ISO 8601）；到期后自动失效")
    created_at: str
    state: LockState = Field(description="active=生效中；expired=已到期；released=已释放")


class CreateRetentionLockRequest(BaseModel):
    job_kind: RetentionJobKind
    job_id: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=512)
    expires_at: datetime


class RetentionLockList(BaseModel):
    total: int
    items: list[RetentionLockModel]


class PreviewFileEntry(BaseModel):
    """预览中的单个待删文件类别条目（只有相对路径/类别/大小，绝不读取内容）。"""

    category: str = Field(
        description="result/receipt/raw_input/partial_output/bundle_staging 等类别"
    )
    path: str = Field(description="相对数据目录的路径（仅用于核对，不返回任何日志内容）")
    bytes: int
    status: Literal["present", "missing"] = Field(
        default="present",
        description="present=现存（计释放空间）；missing=规范集合中本应存在但已缺失，"
                    "执行时记录为 missing，不影响关联记录删除",
    )
    note: str | None = Field(
        default=None,
        description="symlink=该路径是符号链接（执行时拒绝）；out_of_tree=越界路径；"
                    "contains_symlink=暂存目录内含符号链接；null=普通文件",
    )


class PreviewItem(BaseModel):
    """预览中的单个待删作业（不含日志内容、审计内容）。"""

    job_kind: RetentionJobKind
    job_id: str
    terminal_status: RetentionTerminalStatus
    needs_review: bool
    completed_at: str
    retention_days: float | None
    rule_source: Literal["builtin", "custom"] = Field(
        description="命中的期限规则来源；null 期限表示永久保留，不会出现在预览中"
    )
    expired: bool
    files: list[PreviewFileEntry]
    bytes_total: int = Field(description="预计释放字节数（现存文件大小之和）")


class CleanupPreviewRequest(BaseModel):
    """清理预览请求；不传任何过滤即按当前策略扫描全部终态作业。"""

    job_kinds: list[RetentionJobKind] | None = Field(
        default=None, description="仅预览这些作业类型；null=全部三类"
    )
    now: datetime | None = Field(
        default=None,
        description="评估用当前时间（UTC ISO 8601），默认服务当前时间；便于复测期限",
    )


class CleanupPreviewResponse(BaseModel):
    """清理预览：待删作业、文件类别与预计释放空间；不读取或返回任何日志内容。"""

    preview_id: str = Field(description="本次预览的稳定标识（内容指纹，重复预览幂等）")
    generated_at: str
    target_fingerprint: str = Field(
        description="待删目标摘要：作业三元组 + 文件(类别,路径,大小) 规范化哈希"
    )
    items: list[PreviewItem]
    job_count: int
    file_count: int
    bytes_total: int = Field(description="预计释放字节数合计")
    by_category: dict[str, int] = Field(description="各文件类别的预计释放字节数")
    blocked: dict[str, int] = Field(
        description="未入选计数：locked=保留锁拦截；retained=期限未满；"
                    "running=仍在运行；permanent=命中永久保留规则",
    )


class CleanupExecuteRequest(BaseModel):
    """执行清理必须回传预览摘要；目标发生变化时拒绝执行（409）。"""

    preview_id: str = Field(description="预览接口返回的 preview_id（等于 target_fingerprint）")
    target_fingerprint: str = Field(description="预览接口返回的目标指纹")
    job_count: int = Field(ge=0)
    file_count: int = Field(ge=0)
    bytes_total: int = Field(ge=0)
    job_kinds: list[RetentionJobKind] | None = Field(
        default=None,
        description="预览时使用的作业类型过滤；必须与预览一致，默认全部三类",
    )
    now: datetime | None = Field(
        default=None,
        description="评估用当前时间；与预览一致时目标判定才可复现，默认服务当前时间",
    )


class PlanItemModel(BaseModel):
    """清理计划中单个作业项的执行结果（计划先持久化，删除逐项推进、可重试）。"""

    job_kind: RetentionJobKind
    job_id: str
    status: Literal["pending", "done", "failed", "skipped"]
    planned_files: list[PreviewFileEntry]
    processed: int = 0
    deleted_bytes: int = 0
    outcomes: list[dict[str, Any]] = Field(
        default_factory=list,
        description="逐文件结果：category/path/outcome(deleted|missing|symlink_refused|"
                    "path_refused|failed)/bytes/error",
    )


class CleanupPlanModel(BaseModel):
    """清理作业（持久化的计划 + 执行进度 + 结果）。"""

    plan_id: str
    idempotency_key: str | None = None
    status: CleanupPlanStatus
    created_at: str
    updated_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    target_fingerprint: str
    submitted_preview: dict[str, Any]
    jobs_total: int
    jobs_done: int = 0
    jobs_failed: int = 0
    files_processed: int = 0
    bytes_deleted: int = 0
    error: str | None = None
    items: list[PlanItemModel] = Field(default_factory=list)


class CleanupPlanList(BaseModel):
    total: int
    items: list[CleanupPlanModel]


class RetentionAuditEntry(BaseModel):
    """保留/清理审计条目（只含动作、目标与计数，绝不含日志内容）。"""

    id: int
    ts: str
    action: str = Field(
        description="policy.rule.set / policy.rule.deleted / lock.created / "
                    "lock.released / cleanup.plan.created / cleanup.plan.started / "
                    "cleanup.item.done / cleanup.item.failed / cleanup.plan.finished / "
                    "cleanup.plan.retried"
    )
    job_kind: str | None = None
    job_id: str | None = None
    plan_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class RetentionAuditPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[RetentionAuditEntry]
