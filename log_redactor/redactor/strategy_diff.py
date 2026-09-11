"""策略变更对照：同一批次上对齐基线与候选策略的处理结果。

对齐原则
--------
* 同一主密钥分别执行两份策略（纯内存，不落库、不生成文件）；
* 覆盖事件按 ``(record_index, line_no, field_path)`` 分组，内容命中再按
  **原始文本坐标**的命中区间对齐：把两侧区间边界切成基本段后逐段比较，
  因此规则顺序变化导致的重叠命中也能稳定对齐，不会把同一区域重复计为
  「失去 + 新增」；
* 覆盖增减只看「是否被处理、以什么动作处理」，与规则身份无关——仅规则
  改名（id/名称变化）而处理一致时记为胜出规则变化，**不算覆盖改善**；
* 残留风险按 ``(record_index, line_no, field_path, detector)`` 聚合计数
  （两侧输出文本坐标不可比，不按偏移对齐）；
* 输出类型变化按叶子路径比较两侧输出的 JSON 类型名。

差异项只含位置、规则、动作、识别器与计数，绝不回显原始值、正则文本或
处理后仍含敏感信息的值。
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .crypto import MasterKey, key_fingerprint
from .engine import CoverageEvent, RedactionEngine, display_path
from .models import (
    ActionChangeItem,
    CoverageDiffItem,
    DiffCheck,
    DiffLocation,
    RiskDiffItem,
    RiskFinding,
    Strategy,
    StrategyDiffLimits,
    StrategyDiffResponse,
    StrategyDiffSummary,
    TypeChangeItem,
    WinnerChangeItem,
)

MAX_DIFF_ITEMS = 500  # 每类差异项的返回上限（与引擎 MAX_RISK_FINDINGS 对齐）

# 差异类目名（用于 truncated 标注）
_CATEGORIES = (
    "coverage_gained", "coverage_lost", "action_changes", "winner_changes",
    "type_changes", "risks_new", "risks_resolved",
)


@dataclass
class _TraceRun:
    """一份策略在批次上的内存执行轨迹。"""

    records: list[Any]
    coverage: list[CoverageEvent]
    risks: list[RiskFinding]


def _trace_run(strategy: Strategy, records: list[Any], line_nos: list[int | None],
               key: MasterKey, is_ndjson: bool,
               domain_fingerprint: str = "global") -> _TraceRun:
    engine = RedactionEngine(
        strategy, key, is_ndjson=is_ndjson, collect_coverage=True,
        domain_fingerprint=domain_fingerprint,
    )
    out: list[Any] = []
    for idx, record in enumerate(records):
        # NDJSON 传物理行号（空行占号）；JSON 传 None（审计/风险本就不带行号）
        line_no = line_nos[idx] if is_ndjson else None
        out.append(engine.process_record(record, idx, line_no=line_no))
    return _TraceRun(records=out, coverage=engine.coverage, risks=list(engine.risks))


# ---------- 覆盖对齐 ----------


def _loc(ev: CoverageEvent, span: tuple[int, int] | None) -> DiffLocation:
    return DiffLocation(
        record_index=ev.record_index,
        line_no=ev.line_no,
        field_path=ev.field_path,
        span_start=span[0] if span else None,
        span_end=span[1] if span else None,
    )


def _classify(
    base: CoverageEvent | None,
    cand: CoverageEvent | None,
    span: tuple[int, int] | None,
    gained: list[CoverageDiffItem],
    lost: list[CoverageDiffItem],
    action_changes: list[ActionChangeItem],
    winner_changes: list[WinnerChangeItem],
) -> None:
    """比较同一位置同一区间两侧的处理结果并归类。"""
    if base is None and cand is None:
        return
    if cand is None:
        assert base is not None
        lost.append(CoverageDiffItem(
            location=_loc(base, span), action=base.action,  # type: ignore[arg-type]
            rule_id=base.rule_id, rule_name=base.rule_name,
            hit_by=list(base.hit_by),
        ))
        return
    if base is None:
        gained.append(CoverageDiffItem(
            location=_loc(cand, span), action=cand.action,  # type: ignore[arg-type]
            rule_id=cand.rule_id, rule_name=cand.rule_name,
            hit_by=list(cand.hit_by),
        ))
        return
    if base.action != cand.action:
        action_changes.append(ActionChangeItem(
            location=_loc(base, span),
            from_action=base.action, to_action=cand.action,  # type: ignore[arg-type]
            from_rule_id=base.rule_id, from_rule_name=base.rule_name,
            to_rule_id=cand.rule_id, to_rule_name=cand.rule_name,
        ))
    elif base.rule_id != cand.rule_id:
        # 处理一致（同动作同区间）但胜出规则不同：规则重写/换名，不算覆盖改善
        winner_changes.append(WinnerChangeItem(
            location=_loc(base, span),
            action=base.action,  # type: ignore[arg-type]
            from_rule_id=base.rule_id, from_rule_name=base.rule_name,
            to_rule_id=cand.rule_id, to_rule_name=cand.rule_name,
        ))
    # 同规则同动作：无差异（仅规则名称变化且处理一致时同样落入此处）


def _merge_adjacent(items: list) -> list:
    """合并同一位置相邻且属性完全一致的差异项，count 累计段数。"""

    def key_of(item) -> tuple:
        loc = item.location
        attrs = item.model_dump_json(exclude={"location", "count"})
        return (loc.record_index, loc.line_no, loc.field_path, attrs)

    out: list = []
    for item in items:
        if out:
            prev = out[-1]
            if (key_of(prev) == key_of(item)
                    and prev.location.span_end is not None
                    and prev.location.span_end == item.location.span_start):
                prev.location.span_end = item.location.span_end
                prev.count += 1
                continue
        out.append(item)
    return out


def _diff_coverage(base: _TraceRun, cand: _TraceRun) -> tuple[
    list[CoverageDiffItem], list[CoverageDiffItem],
    list[ActionChangeItem], list[WinnerChangeItem],
]:
    gained: list[CoverageDiffItem] = []
    lost: list[CoverageDiffItem] = []
    action_changes: list[ActionChangeItem] = []
    winner_changes: list[WinnerChangeItem] = []

    def group(events: list[CoverageEvent]) -> dict[tuple, list[CoverageEvent]]:
        g: dict[tuple, list[CoverageEvent]] = {}
        for ev in events:
            g.setdefault((ev.record_index, ev.line_no, ev.field_path), []).append(ev)
        return g

    base_by_pos = group(base.coverage)
    cand_by_pos = group(cand.coverage)

    for pos in sorted(set(base_by_pos) | set(cand_by_pos)):
        b_events = base_by_pos.get(pos, [])
        c_events = cand_by_pos.get(pos, [])

        # 非字符串标量的整字段命中（span=None）：叶子只可能是整字段事件或
        # 无事件（内容规则不作用于非字符串），两侧按整体单元比较
        b_whole = next((e for e in b_events if e.span is None), None)
        c_whole = next((e for e in c_events if e.span is None), None)
        if b_whole is not None or c_whole is not None:
            _classify(b_whole, c_whole, None, gained, lost,
                      action_changes, winner_changes)
            continue

        # 字符串：把两侧命中区间边界切成基本段，逐段归属后比较。
        # 单侧一次运行内区间互不重叠（先定义规则消费片段），故每段在每侧
        # 至多归属一个事件；整字段命中字符串时已记为 (0, len) 同坐标比较。
        b_spans = [(e.span[0], e.span[1], e) for e in b_events]  # type: ignore[index]
        c_spans = [(e.span[0], e.span[1], e) for e in c_events]  # type: ignore[index]
        bounds = sorted({s for s, _, _ in b_spans + c_spans}
                        | {e for _, e, _ in b_spans + c_spans})

        def owner(spans: list, s: int, e: int) -> CoverageEvent | None:
            for ts, te, ev in spans:
                if ts <= s and e <= te:
                    return ev
            return None

        for s, e in zip(bounds, bounds[1:]):
            if s >= e:
                continue
            _classify(owner(b_spans, s, e), owner(c_spans, s, e), (s, e),
                      gained, lost, action_changes, winner_changes)

    # 相邻基本段属性一致时合并（规则重排造成的碎片段），计数为段数
    gained = _merge_adjacent(gained)
    lost = _merge_adjacent(lost)
    action_changes = _merge_adjacent(action_changes)
    winner_changes = _merge_adjacent(winner_changes)
    return gained, lost, action_changes, winner_changes


# ---------- 残留风险对齐 ----------


def _diff_risks(base: _TraceRun, cand: _TraceRun
                ) -> tuple[list[RiskDiffItem], list[RiskDiffItem]]:
    def group(risks: list[RiskFinding]) -> dict[tuple, int]:
        g: dict[tuple, int] = {}
        for r in risks:
            key = (r.record_index, r.line_no, r.field_path, r.detector)
            g[key] = g.get(key, 0) + 1
        return g

    base_g, cand_g = group(base.risks), group(cand.risks)
    new: list[RiskDiffItem] = []
    resolved: list[RiskDiffItem] = []
    for key in sorted(set(base_g) | set(cand_g)):
        record_index, line_no, field_path, detector = key
        delta = cand_g.get(key, 0) - base_g.get(key, 0)
        if delta == 0:
            continue
        item = RiskDiffItem(
            location=DiffLocation(record_index=record_index, line_no=line_no,
                                  field_path=field_path),
            detector=detector,
            count=abs(delta),
        )
        (new if delta > 0 else resolved).append(item)
    return new, resolved


# ---------- 输出类型对齐 ----------


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _type_map(records: list[Any]) -> dict[tuple[int, str], str]:
    """``(record_index, 字段路径)`` -> 输出值的 JSON 类型名。"""
    out: dict[tuple[int, str], str] = {}

    def walk(node: Any, idx: int, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, idx, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, idx, f"{path}[{i}]")
        else:
            out[(idx, display_path(path))] = _json_type(node)

    for idx, record in enumerate(records):
        if isinstance(record, (dict, list)):
            walk(record, idx, "")
        else:
            out[(idx, "$")] = _json_type(record)
    return out


def _diff_types(base: _TraceRun, cand: _TraceRun,
                line_nos: list[int | None], is_ndjson: bool
                ) -> list[TypeChangeItem]:
    base_t = _type_map(base.records)
    cand_t = _type_map(cand.records)
    items: list[TypeChangeItem] = []
    for key in sorted(set(base_t) | set(cand_t)):
        bt = base_t.get(key, "absent")
        ct = cand_t.get(key, "absent")
        if bt == ct:
            continue
        idx, path = key
        items.append(TypeChangeItem(
            location=DiffLocation(
                record_index=idx,
                line_no=line_nos[idx] if is_ndjson else None,
                field_path=path,
            ),
            from_type=bt,
            to_type=ct,
        ))
    return items


# ---------- 汇总与门槛 ----------


def _cap(items: list, category: str, truncated: list[str]) -> list:
    if len(items) > MAX_DIFF_ITEMS:
        truncated.append(category)
        return items[:MAX_DIFF_ITEMS]
    return items


def run_strategy_diff(
    records: list[Any],
    line_nos: list[int | None],
    is_ndjson: bool,
    baseline: Strategy,
    candidate: Strategy,
    limits: StrategyDiffLimits,
    key: MasterKey,
    *,
    master_key: MasterKey | None = None,
    domain_fingerprint: str = "global",
) -> StrategyDiffResponse:
    """在同一批记录上对照基线与候选策略（纯内存，不落库、不生成文件）。

    ``key`` 为生效密钥（全局域即主密钥，隔离域为派生子密钥）；
    ``master_key`` 给定时用于报告主密钥指纹（隔离域下 ``key`` 是子密钥）。
    基线与候选共用同一关联域，避免仅因域隔离产生伪差异。
    """
    base = _trace_run(baseline, records, line_nos, key, is_ndjson,
                      domain_fingerprint)
    cand = _trace_run(candidate, records, line_nos, key, is_ndjson,
                      domain_fingerprint)

    gained, lost, action_changes, winner_changes = _diff_coverage(base, cand)
    risks_new, risks_resolved = _diff_risks(base, cand)
    type_changes = _diff_types(base, cand, line_nos, is_ndjson)

    summary = StrategyDiffSummary(
        coverage_gained=sum(i.count for i in gained),
        coverage_lost=sum(i.count for i in lost),
        action_changes=sum(i.count for i in action_changes),
        winner_changes=sum(i.count for i in winner_changes),
        type_changes=sum(i.count for i in type_changes),
        risks_new=sum(i.count for i in risks_new),
        risks_resolved=sum(i.count for i in risks_resolved),
    )

    def check(name: str, limit: int | None, actual: int) -> DiffCheck:
        return DiffCheck(name=name, limit=limit, actual=actual,
                         passed=limit is None or actual <= limit)

    checks = [
        check("new_risks", limits.max_new_risks, summary.risks_new),
        check("lost_coverage", limits.max_lost_coverage, summary.coverage_lost),
        check("type_changes", limits.max_type_changes, summary.type_changes),
    ]

    truncated: list[str] = []
    return StrategyDiffResponse(
        passed=all(c.passed for c in checks),
        checks=checks,
        summary=summary,
        coverage_gained=_cap(gained, "coverage_gained", truncated),
        coverage_lost=_cap(lost, "coverage_lost", truncated),
        action_changes=_cap(action_changes, "action_changes", truncated),
        winner_changes=_cap(winner_changes, "winner_changes", truncated),
        type_changes=_cap(type_changes, "type_changes", truncated),
        risks_new=_cap(risks_new, "risks_new", truncated),
        risks_resolved=_cap(risks_resolved, "risks_resolved", truncated),
        truncated=truncated,
        key_fingerprint=key_fingerprint(master_key or key),
        domain_fingerprint=domain_fingerprint,
    )
